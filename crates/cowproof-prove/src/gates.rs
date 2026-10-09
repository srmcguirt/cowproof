//! Proof gates: mechanical checks over the lane patch.
//!
//! Gates load configuration from the base revision, never the patched tree.
//! This prevents a patch from weakening its own checks.

use crate::flaws::{RuleFile, check_rule, parse_patch};
use anyhow::{Context, Result, bail};
use cowproof_core::{glob_matches, outside_ownership, removed_lines};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

/// Configuration for a single gate execution.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GatePacket {
    /// Paths the patch is allowed to touch.
    pub owns: Vec<String>,
    /// Per-path, the maximum number of lines allowed to be removed.
    pub append_only: BTreeMap<String, usize>,
    /// Additional protected paths beyond the default set.
    pub protected: Vec<String>,
    /// If true, a patch without held-out checks fails the gate.
    pub require_heldout: bool,
}

/// A single gate result.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GateResult {
    pub name: String,
    pub passed: bool,
    pub warned: bool,
    pub evidence: Vec<String>,
}

/// Report from all gates.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GateReport {
    pub gates: Vec<GateResult>,
    pub any_failed: bool,
}

/// Run all gates on a patch. Loads configuration from the base revision.
pub fn run_gates(
    base_repo: &Path,
    base_commit: &str,
    lane_patch: &str,
    packet: &GatePacket,
) -> Result<GateReport> {
    let mut gates = Vec::new();

    // Gate 1: Ownership
    let ownership_result = check_ownership(lane_patch, packet)?;
    gates.push(ownership_result);

    // Gate 2: Append-only
    let append_only_result = check_append_only(lane_patch, packet)?;
    gates.push(append_only_result);

    // Gate 3: Protected paths (load from base)
    let protected_result = check_protected_paths(base_repo, base_commit, lane_patch, packet)?;
    gates.push(protected_result);

    // Gate 4: Held-out checks
    let heldout_result = check_heldout(packet);
    gates.push(heldout_result);

    // Gate 5: Flaw rules (load from base)
    let flaw_result = check_flaws(base_repo, base_commit, lane_patch)?;
    gates.push(flaw_result);

    let any_failed = gates.iter().any(|g| !g.passed);

    Ok(GateReport { gates, any_failed })
}

/// Gate 1: Ownership - files outside `owns` fail.
fn check_ownership(lane_patch: &str, packet: &GatePacket) -> Result<GateResult> {
    let deltas = parse_patch(lane_patch);
    let files: Vec<String> = deltas.iter().map(|d| d.path.clone()).collect();

    // Always protected by default
    let always_protected = vec![
        ".env".into(),
        ".env.*".into(),
        "**/.env".into(),
        "**/.env.*".into(),
    ];

    let outside = outside_ownership(&files, &packet.owns, &always_protected);

    let passed = outside.is_empty();
    let mut evidence = Vec::new();
    if !passed {
        evidence.push(format!("Files outside owns globs: {}", outside.join(", ")));
    }

    Ok(GateResult {
        name: "ownership".to_string(),
        passed,
        warned: false,
        evidence,
    })
}

/// Gate 2: Append-only - removed lines must not exceed allowed per path.
fn check_append_only(lane_patch: &str, packet: &GatePacket) -> Result<GateResult> {
    let deltas = parse_patch(lane_patch);
    let mut violations = Vec::new();

    for (path, allowed) in &packet.append_only {
        for delta in &deltas {
            if glob_matches(path, &delta.path) {
                let removed_count = removed_lines(lane_patch, &delta.path);
                if removed_count > *allowed {
                    violations.push(format!(
                        "{}: removed {} lines, max allowed {}",
                        delta.path, removed_count, allowed
                    ));
                }
            }
        }
    }

    let passed = violations.is_empty();

    Ok(GateResult {
        name: "append_only".to_string(),
        passed,
        warned: false,
        evidence: violations,
    })
}

/// Gate 3: Protected paths - must not be touched unless explicitly owned.
fn check_protected_paths(
    base_repo: &Path,
    base_commit: &str,
    lane_patch: &str,
    packet: &GatePacket,
) -> Result<GateResult> {
    // Load protected list from repo config
    let (repo_protected, _) = cowproof_core::repo_rules(base_repo);

    // Build complete protected list
    let mut protected = Vec::new();
    protected.extend(
        cowproof_core::ALWAYS_PROTECTED
            .iter()
            .map(|s| s.to_string()),
    );
    protected.extend(repo_protected);
    protected.extend(packet.protected.clone());

    // Add defaults from design
    protected.extend(vec![
        "Cargo.toml".into(),
        "package.json".into(),
        "Cargo.lock".into(),
        "**/Cargo.lock".into(),
        "**/package-lock.json".into(),
        ".github/**".into(),
        "Makefile".into(),
        "justfile".into(),
        "cowproof.toml".into(),
        "cowproof/**".into(),
    ]);

    // Try to get flaw pack paths from base
    if let Ok(config_content) = run_git_show(base_repo, base_commit, "cowproof.toml")
        && let Ok(config) = toml::from_str::<toml::Table>(&config_content)
        && let Some(proof) = config.get("proof").and_then(|p| p.as_table())
        && let Some(packs) = proof.get("packs").and_then(|p| p.as_array())
    {
        for pack_path in packs {
            if let Some(s) = pack_path.as_str() {
                protected.push(s.to_string());
            }
        }
    }

    let deltas = parse_patch(lane_patch);
    let files: Vec<String> = deltas.iter().map(|d| d.path.clone()).collect();

    let mut protected_violations = Vec::new();
    let mut protected_warnings = Vec::new();

    for file in &files {
        let is_protected = protected.iter().any(|g| glob_matches(g, file));
        if !is_protected {
            continue;
        }

        let is_owned = packet.owns.iter().any(|g| glob_matches(g, file));
        if is_owned {
            protected_warnings.push(format!("{}: check harness changed", file));
        } else {
            protected_violations.push(file.clone());
        }
    }

    let passed = protected_violations.is_empty();
    let warned = !protected_warnings.is_empty();

    let mut evidence = Vec::new();
    if !passed {
        evidence.push(format!(
            "Protected paths touched: {}",
            protected_violations.join(", ")
        ));
    }
    evidence.extend(protected_warnings);

    Ok(GateResult {
        name: "protected_paths".to_string(),
        passed,
        warned,
        evidence,
    })
}

/// Gate 4: Held-out checks - packet without held-out checks gets a warning.
fn check_heldout(packet: &GatePacket) -> GateResult {
    let has_heldout = false;

    let passed = !packet.require_heldout || has_heldout;
    let warned = !has_heldout && !packet.require_heldout;

    let mut evidence = Vec::new();
    if !has_heldout {
        if packet.require_heldout {
            evidence.push("Held-out checks required but not provided".to_string());
        } else {
            evidence.push("No held-out checks provided".to_string());
        }
    }

    GateResult {
        name: "held_out".to_string(),
        passed,
        warned,
        evidence,
    }
}

/// Gate 5: Flaw rules - run flaw pack rules over added lines.
/// Loads the flaw pack from the base commit, never the working tree.
fn check_flaws(base_repo: &Path, base_commit: &str, lane_patch: &str) -> Result<GateResult> {
    let deltas = parse_patch(lane_patch);

    // Load flaw rules from base revision
    let flaw_content = match run_git_show(
        base_repo,
        base_commit,
        "crates/cowproof-report/rules/flaws.toml",
    ) {
        Ok(content) => content,
        Err(_) => {
            // Flaw pack optional; return clean if not found
            return Ok(GateResult {
                name: "flaws".to_string(),
                passed: true,
                warned: false,
                evidence: vec!["Flaw pack not found in base".to_string()],
            });
        }
    };

    let rule_file: RuleFile = toml::from_str(&flaw_content)
        .ok()
        .unwrap_or_else(|| RuleFile { rules: vec![] });

    let mut findings = Vec::new();
    let mut compilation_errors = Vec::new();

    for delta in &deltas {
        for rule in &rule_file.rules {
            match check_rule(rule, delta) {
                Ok(mut deltas_findings) => {
                    findings.append(&mut deltas_findings);
                }
                Err(err) => {
                    // Pattern compilation error MUST FAIL the gate
                    compilation_errors.push(format!("Rule error: {}", err));
                }
            }
        }
    }

    let passed = findings.is_empty() && compilation_errors.is_empty();

    let mut evidence: Vec<String> = compilation_errors;
    evidence.extend(findings.iter().map(|f| {
        if let Some(line) = f.line {
            format!("{}:{}: {} ({})", f.file, line, f.explanation, f.pattern)
        } else {
            format!("{}: {} ({})", f.file, f.explanation, f.pattern)
        }
    }));

    Ok(GateResult {
        name: "flaws".to_string(),
        passed,
        warned: false,
        evidence,
    })
}

/// Run `git show` in a repository to read a file from a commit.
fn run_git_show(repo: &Path, commit: &str, path: &str) -> Result<String> {
    let output = Command::new("git")
        .current_dir(repo)
        .args(["show", &format!("{}:{}", commit, path)])
        .output()
        .context("git show command failed")?;

    if !output.status.success() {
        bail!("git show {}:{} failed", commit, path);
    }

    String::from_utf8(output.stdout).context("git show output was not valid UTF-8")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn setup_test_repo() -> Result<(TempDir, String)> {
        let dir = TempDir::new()?;
        let repo = dir.path();

        let _ = Command::new("git")
            .args(["init"])
            .current_dir(repo)
            .output()?;

        let _ = Command::new("git")
            .args(["config", "user.email", "test@test.local"])
            .current_dir(repo)
            .output()?;

        let _ = Command::new("git")
            .args(["config", "user.name", "Test"])
            .current_dir(repo)
            .output()?;

        fs::write(repo.join("README.md"), "# Test")?;
        let _ = Command::new("git")
            .args(["add", "README.md"])
            .current_dir(repo)
            .output()?;

        let _ = Command::new("git")
            .args(["commit", "-m", "initial"])
            .current_dir(repo)
            .output()?;

        let commit_output = Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(repo)
            .output()?;

        let commit = String::from_utf8(commit_output.stdout)?.trim().to_string();

        Ok((dir, commit))
    }

    #[test]
    fn ownership_detects_files_outside_owns() -> Result<()> {
        let patch = r#"diff --git a/src/allowed.rs b/src/allowed.rs
--- a/src/allowed.rs
+++ b/src/allowed.rs
@@ -1 +1,2 @@
 // old
+// new
diff --git a/AGENTS.md b/AGENTS.md
--- a/AGENTS.md
+++ b/AGENTS.md
@@ -1 +1,2 @@
 # old
+# new
"#;

        let packet = GatePacket {
            owns: vec!["src/**".into()],
            append_only: BTreeMap::new(),
            protected: vec![],
            require_heldout: false,
        };

        let result = check_ownership(patch, &packet)?;
        assert!(!result.passed);
        assert!(result.evidence.iter().any(|e| e.contains("AGENTS.md")));
        Ok(())
    }

    #[test]
    fn ownership_passes_when_all_owned() -> Result<()> {
        let patch = r#"diff --git a/src/a.rs b/src/a.rs
--- a/src/a.rs
+++ b/src/a.rs
@@ -1 +1,2 @@
 // old
+// new
"#;

        let packet = GatePacket {
            owns: vec!["src/**".into()],
            append_only: BTreeMap::new(),
            protected: vec![],
            require_heldout: false,
        };

        let result = check_ownership(patch, &packet)?;
        assert!(result.passed);
        Ok(())
    }

    #[test]
    fn append_only_detects_removed_lines() -> Result<()> {
        let patch = r#"diff --git a/test.rs b/test.rs
--- a/test.rs
+++ b/test.rs
@@ -1,3 +1,2 @@
 fn test() {
-    assert!(x);
-    assert!(y);
+    assert!(z);
"#;

        let mut append_only_map = BTreeMap::new();
        append_only_map.insert("test.rs".into(), 1);

        let packet = GatePacket {
            owns: vec!["test.rs".into()],
            append_only: append_only_map,
            protected: vec![],
            require_heldout: false,
        };

        let result = check_append_only(patch, &packet)?;
        assert!(!result.passed);
        assert!(result.evidence.iter().any(|e| e.contains("2 lines")));
        Ok(())
    }

    #[test]
    fn append_only_passes_within_limit() -> Result<()> {
        let patch = r#"diff --git a/test.rs b/test.rs
--- a/test.rs
+++ b/test.rs
@@ -1,3 +1,2 @@
 fn test() {
-    assert!(x);
+    assert!(z);
"#;

        let mut append_only_map = BTreeMap::new();
        append_only_map.insert("test.rs".into(), 1);

        let packet = GatePacket {
            owns: vec!["test.rs".into()],
            append_only: append_only_map,
            protected: vec![],
            require_heldout: false,
        };

        let result = check_append_only(patch, &packet)?;
        assert!(result.passed);
        Ok(())
    }

    #[test]
    fn protected_paths_fails_when_touched_without_ownership() -> Result<()> {
        let patch = r#"diff --git a/Cargo.toml b/Cargo.toml
--- a/Cargo.toml
+++ b/Cargo.toml
@@ -1 +1,2 @@
 [package]
+name = "test"
"#;

        let (dir, commit) = setup_test_repo()?;
        let repo = dir.path();

        let packet = GatePacket {
            owns: vec!["src/**".into()],
            append_only: BTreeMap::new(),
            protected: vec![],
            require_heldout: false,
        };

        let result = check_protected_paths(repo, &commit, patch, &packet)?;
        assert!(!result.passed);
        assert!(result.evidence.iter().any(|e| e.contains("Cargo.toml")));
        Ok(())
    }

    #[test]
    fn protected_paths_warns_when_owned_but_protected() -> Result<()> {
        let patch = r#"diff --git a/Cargo.toml b/Cargo.toml
--- a/Cargo.toml
+++ b/Cargo.toml
@@ -1 +1,2 @@
 [package]
+name = "test"
"#;

        let (dir, commit) = setup_test_repo()?;
        let repo = dir.path();

        let packet = GatePacket {
            owns: vec!["Cargo.toml".into()],
            append_only: BTreeMap::new(),
            protected: vec![],
            require_heldout: false,
        };

        let result = check_protected_paths(repo, &commit, patch, &packet)?;
        assert!(result.passed);
        assert!(result.warned);
        assert!(result.evidence.iter().any(|e| e.contains("harness")));
        Ok(())
    }

    #[test]
    fn heldout_warns_when_not_provided() {
        let packet = GatePacket {
            owns: vec!["src/**".into()],
            append_only: BTreeMap::new(),
            protected: vec![],
            require_heldout: false,
        };

        let result = check_heldout(&packet);
        assert!(result.passed);
        assert!(result.warned);
    }

    #[test]
    fn heldout_fails_when_required_and_not_provided() {
        let packet = GatePacket {
            owns: vec!["src/**".into()],
            append_only: BTreeMap::new(),
            protected: vec![],
            require_heldout: true,
        };

        let result = check_heldout(&packet);
        assert!(!result.passed);
    }

    #[test]
    fn flaws_detects_pattern_in_added_lines() -> Result<()> {
        let patch = r#"diff --git a/test.rs b/test.rs
--- a/test.rs
+++ b/test.rs
@@ -0,0 +1 @@
+    EXCEPTION WHEN OTHERS THEN NULL;
"#;

        let (dir, _commit) = setup_test_repo()?;
        let repo = dir.path();

        let rules_dir = repo.join("crates/cowproof-report/rules");
        fs::create_dir_all(&rules_dir)?;
        fs::write(
            rules_dir.join("flaws.toml"),
            r#"[[rules]]
pattern = "(?i)EXCEPTION\\s+WHEN\\s+OTHERS"
files = ["**/*"]
explanation = "This catches and can swallow every exception."
"#,
        )?;

        let _ = Command::new("git")
            .args(["add", "-A"])
            .current_dir(repo)
            .output()?;
        let _ = Command::new("git")
            .args(["commit", "-m", "add rules"])
            .current_dir(repo)
            .output()?;

        let result = check_flaws(repo, "HEAD", patch)?;
        assert!(!result.passed);
        assert!(!result.evidence.is_empty());
        Ok(())
    }

    #[test]
    fn flaws_loaded_from_base_not_patched_tree() -> Result<()> {
        let patch = r#"diff --git a/test.rs b/test.rs
--- a/test.rs
+++ b/test.rs
@@ -0,0 +1 @@
+    EXCEPTION WHEN OTHERS THEN NULL;
diff --git a/crates/cowproof-report/rules/flaws.toml b/crates/cowproof-report/rules/flaws.toml
--- a/crates/cowproof-report/rules/flaws.toml
+++ b/crates/cowproof-report/rules/flaws.toml
@@ -1,3 +0,0 @@
-[[rules]]
-pattern = "(?i)EXCEPTION\\s+WHEN\\s+OTHERS"
-files = ["**/*"]
"#;

        let (dir, _commit) = setup_test_repo()?;
        let repo = dir.path();

        let rules_dir = repo.join("crates/cowproof-report/rules");
        fs::create_dir_all(&rules_dir)?;
        fs::write(
            rules_dir.join("flaws.toml"),
            r#"[[rules]]
pattern = "(?i)EXCEPTION\\s+WHEN\\s+OTHERS"
files = ["**/*"]
explanation = "This catches and can swallow every exception."
"#,
        )?;

        let _ = Command::new("git")
            .args(["add", "-A"])
            .current_dir(repo)
            .output()?;
        let _ = Command::new("git")
            .args(["commit", "-m", "add rules"])
            .current_dir(repo)
            .output()?;

        // Flaw gate should fail (rules loaded from base)
        let result = check_flaws(repo, "HEAD", patch)?;
        assert!(!result.passed);
        assert!(result.evidence.iter().any(|e| e.contains("EXCEPTION")));

        // Protected-path gate should also fail for the flaw pack
        let packet = GatePacket {
            owns: vec!["test.rs".into()],
            append_only: BTreeMap::new(),
            protected: vec![],
            require_heldout: false,
        };

        let protected_result = check_protected_paths(repo, "HEAD", patch, &packet)?;
        assert!(!protected_result.passed);
        assert!(
            protected_result
                .evidence
                .iter()
                .any(|e| e.contains("flaws.toml"))
        );

        Ok(())
    }

    #[test]
    fn flaws_gate_fails_on_pattern_compilation_error() -> Result<()> {
        let patch = r#"diff --git a/test.rs b/test.rs
--- a/test.rs
+++ b/test.rs
@@ -0,0 +1 @@
+some code
"#;

        let (dir, _commit) = setup_test_repo()?;
        let repo = dir.path();

        let rules_dir = repo.join("crates/cowproof-report/rules");
        fs::create_dir_all(&rules_dir)?;
        fs::write(
            rules_dir.join("flaws.toml"),
            r#"[[rules]]
pattern = "[invalid(regex"
files = ["**/*"]
explanation = "This has a broken pattern."
"#,
        )?;

        let _ = Command::new("git")
            .args(["add", "-A"])
            .current_dir(repo)
            .output()?;
        let _ = Command::new("git")
            .args(["commit", "-m", "add broken rules"])
            .current_dir(repo)
            .output()?;

        let result = check_flaws(repo, "HEAD", patch)?;
        assert!(!result.passed, "Gate must FAIL on invalid pattern");
        assert!(
            result
                .evidence
                .iter()
                .any(|e| e.contains("Invalid pattern"))
        );
        Ok(())
    }
}
