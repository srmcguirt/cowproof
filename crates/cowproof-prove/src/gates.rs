//! Proof gates: mechanical checks over the lane patch.
//!
//! Gates load configuration from the base revision, never the patched tree.
//! This prevents a patch from weakening its own checks.

use crate::flaws::{check_rules, parse_patch, parse_rules};
use anyhow::{Context, Result, bail};
use cowproof_core::{glob_matches, outside_ownership, removed_lines};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Where the default flaw pack lives in the base revision. It is loaded from
/// the base and protected by default.
pub const DEFAULT_FLAW_PACK: &str = "crates/cowproof-report/rules/flaws.toml";

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
    /// Optional path to a held-out checks file. Resolved outside the repository.
    /// The gate loads this file to count checks and report evidence.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub heldout_path: Option<PathBuf>,
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
    verify_commit(base_repo, base_commit)?;

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
    let heldout_result = check_heldout(packet, base_repo);
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

    // The default pack and every pack named in the base `cowproof.toml`
    // `[proof] packs` are gate inputs, so a patch may not touch them.
    protected.push(DEFAULT_FLAW_PACK.to_string());
    protected.extend(configured_packs(base_repo, base_commit)?);

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

/// Gate 4: Held-out checks - verifies that held-out checks are present and valid.
///
/// - No held-out path → warn (unless require_heldout is true, then fail)
/// - Valid held-out file with ≥1 check → pass with evidence naming the number of checks
///   (the checks themselves are RUN by the verifier, not here)
/// - Empty held-out file → fail
/// - Held-out path inside the repository or invalid → fail naming the path/problem
/// - Invalid TOML or other load errors → fail naming the problem
fn check_heldout(packet: &GatePacket, base_repo: &Path) -> GateResult {
    let (passed, warned, evidence) = match &packet.heldout_path {
        None => {
            // No held-out path provided
            if packet.require_heldout {
                (
                    false,
                    false,
                    vec!["Held-out checks required but not provided".to_string()],
                )
            } else {
                (true, true, vec!["No held-out checks provided".to_string()])
            }
        }
        Some(path) => {
            // Resolve and validate the path using the core library function.
            // Pass base_repo as both repo_root and cwd (relative paths resolve against repo root).
            match cowproof_core::heldout::resolve_outside_repo(path, base_repo, base_repo) {
                Ok(path_canonical) => {
                    // Path is validated; now try to load the checks
                    match cowproof_core::heldout::load(&path_canonical) {
                        Ok(heldout) => {
                            let check_count = heldout.check.len();
                            if check_count == 0 {
                                (
                                    false,
                                    false,
                                    vec!["Held-out checks file is empty".to_string()],
                                )
                            } else {
                                let evidence = vec![format!(
                                    "Held-out checks present: {} check{}",
                                    check_count,
                                    if check_count == 1 { "" } else { "s" }
                                )];
                                (true, false, evidence)
                            }
                        }
                        Err(e) => (
                            false,
                            false,
                            vec![format!(
                                "Failed to load held-out checks from {}: {}",
                                path_canonical.display(),
                                e
                            )],
                        ),
                    }
                }
                Err(e) => {
                    // Path resolution failed (inside repo, invalid, contains .., etc.)
                    (false, false, vec![e.to_string()])
                }
            }
        }
    };

    GateResult {
        name: "held_out".to_string(),
        passed,
        warned,
        evidence,
    }
}

/// Gate 5: Flaw rules - run flaw pack rules over the patch.
///
/// Packs are read with `git show <base>:<path>`, never from the working tree:
/// the default pack (optional) plus every path named in the base
/// `cowproof.toml` `[proof] packs` (required). A pack that is missing,
/// malformed or holds a rule whose pattern does not compile FAILS the gate.
fn check_flaws(base_repo: &Path, base_commit: &str, lane_patch: &str) -> Result<GateResult> {
    let deltas = parse_patch(lane_patch);
    let mut evidence = Vec::new();
    let mut failed = false;

    let mut rules = Vec::new();
    let mut loaded = 0usize;
    let configured = configured_packs(base_repo, base_commit)?;
    let mut sources: Vec<(String, bool)> = vec![(DEFAULT_FLAW_PACK.to_string(), false)];
    sources.extend(
        configured
            .into_iter()
            .filter(|p| p != DEFAULT_FLAW_PACK)
            .map(|p| (p, true)),
    );
    for (path, required) in sources {
        match git_show_optional(base_repo, base_commit, &path)? {
            None if required => {
                failed = true;
                evidence.push(format!(
                    "Flaw pack {path} is named in cowproof.toml but missing from the base"
                ));
            }
            None => {}
            Some(text) => match parse_rules(&text) {
                Ok(file) => {
                    loaded += 1;
                    rules.extend(file.rules);
                }
                Err(e) => {
                    failed = true;
                    evidence.push(format!("Flaw pack {path}: {e}"));
                }
            },
        }
    }

    if loaded == 0 && !failed {
        evidence.push("No flaw pack found in base".to_string());
    }

    let (findings, errors) = check_rules(&rules, &deltas, None);
    failed |= !errors.is_empty() || !findings.is_empty();
    evidence.extend(errors.into_iter().map(|e| format!("Rule error: {e}")));
    evidence.extend(findings.iter().map(|f| match f.line {
        Some(line) => format!(
            "{}:{}: [{}] {} ({})",
            f.file, line, f.rule, f.explanation, f.pattern
        ),
        None => format!("{}: [{}] {} ({})", f.file, f.rule, f.explanation, f.pattern),
    }));

    Ok(GateResult {
        name: "flaws".to_string(),
        passed: !failed,
        warned: false,
        evidence,
    })
}

/// Fail early when `base_commit` is not a commit in `repo`, so a bad revision
/// can never read as "file missing from base".
fn verify_commit(repo: &Path, commit: &str) -> Result<()> {
    let status = Command::new("git")
        .current_dir(repo)
        .args(["rev-parse", "--verify", "--quiet", "--end-of-options"])
        .arg(format!("{commit}^{{commit}}"))
        .output()
        .context("git rev-parse failed to start")?;
    if !status.status.success() {
        bail!(
            "base revision {commit} is not a commit in {}",
            repo.display()
        );
    }
    Ok(())
}

/// Pack paths named in the base `cowproof.toml` `[proof] packs`, normalized
/// (leading `./` removed). `generic` is the built-in pack and has no path.
/// A missing `cowproof.toml` means no packs; a malformed one is an error.
fn configured_packs(repo: &Path, commit: &str) -> Result<Vec<String>> {
    let Some(text) = git_show_optional(repo, commit, "cowproof.toml")? else {
        return Ok(Vec::new());
    };
    let config: toml::Table =
        toml::from_str(&text).context("cowproof.toml in the base does not parse")?;
    let packs = config
        .get("proof")
        .and_then(|p| p.as_table())
        .and_then(|p| p.get("packs"))
        .and_then(|p| p.as_array());
    Ok(packs
        .into_iter()
        .flatten()
        .filter_map(|p| p.as_str())
        .filter(|p| *p != "generic")
        .map(|p| p.trim_start_matches("./").to_string())
        .collect())
}

/// `git show <commit>:<path>`; `Ok(None)` when the path is not in the commit.
fn git_show_optional(repo: &Path, commit: &str, path: &str) -> Result<Option<String>> {
    let spec = format!("{commit}:{path}");
    let exists = Command::new("git")
        .current_dir(repo)
        .args(["cat-file", "-e", &spec])
        .output()
        .context("git cat-file failed to start")?;
    if !exists.status.success() {
        return Ok(None);
    }
    run_git_show(repo, commit, path).map(Some)
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

    const SWALLOW_PACK: &str = r#"[[rules]]
id = "swallow-exceptions"
pattern = "(?i)EXCEPTION\\s+WHEN\\s+OTHERS"
files = ["**/*"]
explanation = "This catches and can swallow every exception."
"#;

    const OFFENDING: &str = "    EXCEPTION WHEN OTHERS THEN NULL;\n";

    /// A real temporary git repository. The base is a commit; the patch under
    /// test is whatever `git diff` reports for the working tree against it.
    struct TestRepo {
        dir: TempDir,
        base: String,
    }

    fn git(repo: &Path, args: &[&str]) -> Result<String> {
        let out = Command::new("git")
            .current_dir(repo)
            .args(["-c", "commit.gpgsign=false", "-c", "core.autocrlf=false"])
            .args(args)
            .output()?;
        if !out.status.success() {
            bail!(
                "git {:?} failed: {}",
                args,
                String::from_utf8_lossy(&out.stderr)
            );
        }
        Ok(String::from_utf8(out.stdout)?)
    }

    impl TestRepo {
        /// Commit `files` as the base revision.
        fn new(files: &[(&str, &str)]) -> Result<Self> {
            let dir = TempDir::new()?;
            let repo = dir.path();
            git(repo, &["init", "-q"])?;
            git(repo, &["config", "user.email", "test@test.local"])?;
            git(repo, &["config", "user.name", "Test"])?;
            let r = TestRepo {
                dir,
                base: String::new(),
            };
            fs::write(r.path().join("README.md"), "# Test\n")?;
            for (path, content) in files {
                r.write(path, content)?;
            }
            git(r.path(), &["add", "-A"])?;
            git(r.path(), &["commit", "-q", "-m", "base"])?;
            let base = git(r.path(), &["rev-parse", "HEAD"])?.trim().to_string();
            Ok(TestRepo { base, ..r })
        }

        fn path(&self) -> &Path {
            self.dir.path()
        }

        /// Change the working tree only; the base commit is untouched.
        fn write(&self, path: &str, content: &str) -> Result<()> {
            let full = self.path().join(path);
            if let Some(parent) = full.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(full, content)?;
            Ok(())
        }

        fn remove(&self, path: &str) -> Result<()> {
            fs::remove_file(self.path().join(path))?;
            Ok(())
        }

        /// The real patch: `git diff` of the working tree against the base.
        fn patch(&self) -> Result<String> {
            git(self.path(), &["add", "-A"])?;
            git(
                self.path(),
                &[
                    "-c",
                    "diff.noprefix=false",
                    "-c",
                    "diff.mnemonicPrefix=false",
                    "diff",
                    "--cached",
                    "--no-color",
                    "--no-ext-diff",
                    &self.base,
                ],
            )
        }
    }

    fn packet(owns: &[&str]) -> GatePacket {
        GatePacket {
            owns: owns.iter().map(|s| s.to_string()).collect(),
            append_only: BTreeMap::new(),
            protected: vec![],
            require_heldout: false,
            heldout_path: None,
        }
    }

    fn gate<'a>(report: &'a GateReport, name: &str) -> &'a GateResult {
        report
            .gates
            .iter()
            .find(|g| g.name == name)
            .unwrap_or_else(|| panic!("no gate named {name}"))
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

        let result = check_ownership(patch, &packet(&["src/**"]))?;
        assert!(!result.passed);
        assert_eq!(result.evidence.len(), 1);
        assert!(result.evidence[0].contains("AGENTS.md"));
        assert!(!result.evidence[0].contains("src/allowed.rs"));
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

        let result = check_ownership(patch, &packet(&["src/**"]))?;
        assert!(result.passed);
        assert!(result.evidence.is_empty());
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

        let mut p = packet(&["test.rs"]);
        p.append_only.insert("test.rs".into(), 1);

        let result = check_append_only(patch, &p)?;
        assert!(!result.passed);
        assert_eq!(
            result.evidence,
            vec!["test.rs: removed 2 lines, max allowed 1".to_string()]
        );
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

        let mut p = packet(&["test.rs"]);
        p.append_only.insert("test.rs".into(), 1);

        let result = check_append_only(patch, &p)?;
        assert!(result.passed);
        assert!(result.evidence.is_empty());
        Ok(())
    }

    #[test]
    fn protected_paths_fails_when_touched_without_ownership() -> Result<()> {
        let repo = TestRepo::new(&[("Cargo.toml", "[package]\n")])?;
        repo.write("Cargo.toml", "[package]\nname = \"test\"\n")?;
        let patch = repo.patch()?;

        let result = check_protected_paths(repo.path(), &repo.base, &patch, &packet(&["src/**"]))?;
        assert!(!result.passed);
        assert_eq!(
            result.evidence,
            vec!["Protected paths touched: Cargo.toml".to_string()]
        );
        Ok(())
    }

    #[test]
    fn protected_paths_warns_when_owned_but_protected() -> Result<()> {
        let repo = TestRepo::new(&[("Cargo.toml", "[package]\n")])?;
        repo.write("Cargo.toml", "[package]\nname = \"test\"\n")?;
        let patch = repo.patch()?;

        let result =
            check_protected_paths(repo.path(), &repo.base, &patch, &packet(&["Cargo.toml"]))?;
        assert!(result.passed);
        assert!(result.warned);
        assert_eq!(
            result.evidence,
            vec!["Cargo.toml: check harness changed".to_string()]
        );
        Ok(())
    }

    #[test]
    fn protected_paths_covers_packs_named_in_base_cowproof_toml() -> Result<()> {
        // `./cowproof/flaws.toml` must protect `cowproof/flaws.toml`; the
        // leading `./` is normalized, and an out-of-tree pack name is covered
        // even though no default glob names it.
        let repo = TestRepo::new(&[(
            "cowproof.toml",
            "[proof]\npacks = [\"generic\", \"./rules/extra.toml\"]\n",
        )])?;
        repo.write("rules/extra.toml", SWALLOW_PACK)?;
        let patch = repo.patch()?;

        let result = check_protected_paths(repo.path(), &repo.base, &patch, &packet(&["src/**"]))?;
        assert!(!result.passed);
        assert!(
            result.evidence[0].contains("rules/extra.toml"),
            "{:?}",
            result.evidence
        );
        Ok(())
    }

    #[test]
    fn heldout_warns_when_not_provided() -> Result<()> {
        let repo = TestRepo::new(&[])?;
        let result = check_heldout(&packet(&["src/**"]), repo.path());
        assert!(result.passed);
        assert!(result.warned);
        assert_eq!(
            result.evidence,
            vec!["No held-out checks provided".to_string()]
        );
        Ok(())
    }

    #[test]
    fn heldout_fails_when_required_and_not_provided() -> Result<()> {
        let repo = TestRepo::new(&[])?;
        let mut p = packet(&["src/**"]);
        p.require_heldout = true;

        let result = check_heldout(&p, repo.path());
        assert!(!result.passed);
        assert!(!result.warned);
        assert_eq!(
            result.evidence,
            vec!["Held-out checks required but not provided".to_string()]
        );
        Ok(())
    }

    #[test]
    fn heldout_passes_with_valid_file_outside_repo() -> Result<()> {
        let repo = TestRepo::new(&[])?;
        let temp = TempDir::new()?;
        let heldout_path = temp.path().join("checks.toml");

        // Create a valid held-out checks file with 2 checks
        let content = r#"[[check]]
id = "check-1"
command = "echo test1"

[[check]]
id = "check-2"
command = "echo test2"
"#;
        std::fs::write(&heldout_path, content)?;

        let mut p = packet(&["src/**"]);
        p.heldout_path = Some(heldout_path);

        let result = check_heldout(&p, repo.path());
        assert!(result.passed);
        assert!(!result.warned);
        assert_eq!(result.evidence.len(), 1);
        assert_eq!(
            result.evidence[0],
            "Held-out checks present: 2 checks".to_string()
        );
        Ok(())
    }

    #[test]
    fn heldout_fails_with_empty_file() -> Result<()> {
        let repo = TestRepo::new(&[])?;
        let temp = TempDir::new()?;
        let heldout_path = temp.path().join("checks.toml");

        // Create an empty file
        std::fs::write(&heldout_path, "")?;

        let mut p = packet(&["src/**"]);
        p.heldout_path = Some(heldout_path);

        let result = check_heldout(&p, repo.path());
        assert!(!result.passed);
        assert!(!result.warned);
        assert_eq!(
            result.evidence,
            vec!["Held-out checks file is empty".to_string()]
        );
        Ok(())
    }

    #[test]
    fn heldout_fails_with_file_inside_repo() -> Result<()> {
        let repo = TestRepo::new(&[])?;
        let heldout_path = repo.path().join("checks.toml");

        let mut p = packet(&["src/**"]);
        p.heldout_path = Some(heldout_path.clone());

        let result = check_heldout(&p, repo.path());
        assert!(!result.passed);
        assert!(!result.warned);
        assert!(result.evidence[0].contains("inside the repository"));
        Ok(())
    }

    #[test]
    fn heldout_fails_with_invalid_toml() -> Result<()> {
        let repo = TestRepo::new(&[])?;
        let temp = TempDir::new()?;
        let heldout_path = temp.path().join("checks.toml");

        // Create an invalid TOML file
        std::fs::write(&heldout_path, "[[check]\nid = ")?;

        let mut p = packet(&["src/**"]);
        p.heldout_path = Some(heldout_path);

        let result = check_heldout(&p, repo.path());
        assert!(!result.passed);
        assert!(!result.warned);
        assert!(result.evidence[0].contains("Failed to load held-out checks"));
        Ok(())
    }

    #[test]
    fn heldout_fails_with_relative_path() -> Result<()> {
        let repo = TestRepo::new(&[])?;
        // A relative path x.heldout.toml resolves against cwd (repo.path())
        // making it inside the repo, which should be rejected
        let mut p = packet(&["src/**"]);
        p.heldout_path = Some(PathBuf::from("x.heldout.toml"));

        let result = check_heldout(&p, repo.path());
        assert!(!result.passed);
        assert!(!result.warned);
        assert!(result.evidence[0].contains("inside the repository"));
        Ok(())
    }

    #[test]
    fn heldout_fails_with_dotdot_in_path() -> Result<()> {
        let repo = TestRepo::new(&[])?;
        // Create a path with .. that doesn't exist yet, which tries to escape the repo
        let escaped_path = repo
            .path()
            .join("subdir")
            .join("..")
            .join("..")
            .join("escape.toml");

        let mut p = packet(&["src/**"]);
        p.heldout_path = Some(escaped_path);

        let result = check_heldout(&p, repo.path());
        assert!(!result.passed);
        assert!(!result.warned);
        // The `..` rule refuses it; both messages print the path, so match the
        // rule's own wording.
        assert!(
            result.evidence[0].contains("path contains ..:"),
            "{:?}",
            result.evidence
        );
        Ok(())
    }

    #[test]
    fn flaws_detects_pattern_in_added_lines() -> Result<()> {
        let repo = TestRepo::new(&[(DEFAULT_FLAW_PACK, SWALLOW_PACK)])?;
        repo.write("test.rs", OFFENDING)?;
        let patch = repo.patch()?;
        assert!(patch.contains("+    EXCEPTION WHEN OTHERS"), "{patch}");

        let result = check_flaws(repo.path(), &repo.base, &patch)?;
        assert!(!result.passed);
        assert_eq!(result.evidence.len(), 1, "{:?}", result.evidence);
        assert!(result.evidence[0].starts_with("test.rs:1: [swallow-exceptions] "));
        assert!(result.evidence[0].contains("This catches and can swallow every exception."));
        Ok(())
    }

    #[test]
    fn flaws_passes_a_clean_patch_and_says_which_pack_ran() -> Result<()> {
        let repo = TestRepo::new(&[(DEFAULT_FLAW_PACK, SWALLOW_PACK)])?;
        repo.write("test.rs", "fn ok() {}\n")?;
        let patch = repo.patch()?;

        let result = check_flaws(repo.path(), &repo.base, &patch)?;
        assert!(result.passed, "{:?}", result.evidence);
        assert!(result.evidence.is_empty());
        Ok(())
    }

    #[test]
    fn flaws_sees_added_lines_that_start_with_plus_signs() -> Result<()> {
        let repo = TestRepo::new(&[(DEFAULT_FLAW_PACK, SWALLOW_PACK)])?;
        repo.write("test.sql", "++ EXCEPTION WHEN OTHERS\n")?;
        let patch = repo.patch()?;
        assert!(patch.contains("\n+++ EXCEPTION WHEN OTHERS"), "{patch}");

        let result = check_flaws(repo.path(), &repo.base, &patch)?;
        assert!(!result.passed, "an added `++` line evaded the flaw gate");
        Ok(())
    }

    #[test]
    fn flaws_loaded_from_base_not_patched_tree() -> Result<()> {
        // The patch adds a violation AND deletes the rule that would catch it.
        let repo = TestRepo::new(&[(DEFAULT_FLAW_PACK, SWALLOW_PACK)])?;
        repo.write("test.rs", OFFENDING)?;
        repo.remove(DEFAULT_FLAW_PACK)?;
        let patch = repo.patch()?;
        assert!(
            patch.contains("deleted file mode"),
            "the patch must delete the pack: {patch}"
        );
        assert!(!repo.path().join(DEFAULT_FLAW_PACK).exists());

        // The flaw gate fails, naming the rule that only the base still has.
        let flaws = check_flaws(repo.path(), &repo.base, &patch)?;
        assert!(!flaws.passed, "{:?}", flaws.evidence);
        assert!(
            flaws
                .evidence
                .iter()
                .any(|e| e.starts_with("test.rs:1: [swallow-exceptions] ")),
            "{:?}",
            flaws.evidence
        );

        // The protected-path gate also fails, for the pack path itself.
        let protected =
            check_protected_paths(repo.path(), &repo.base, &patch, &packet(&["test.rs"]))?;
        assert!(!protected.passed);
        assert_eq!(
            protected.evidence,
            vec![format!("Protected paths touched: {DEFAULT_FLAW_PACK}")]
        );

        // Through the public entry point both gates fail and the report fails.
        let report = run_gates(repo.path(), &repo.base, &patch, &packet(&["test.rs"]))?;
        assert!(report.any_failed);
        assert!(!gate(&report, "flaws").passed);
        assert!(!gate(&report, "protected_paths").passed);
        assert!(!gate(&report, "ownership").passed);
        Ok(())
    }

    #[test]
    fn flaws_weakened_in_patched_tree_still_catches_with_base_rules() -> Result<()> {
        let repo = TestRepo::new(&[(DEFAULT_FLAW_PACK, SWALLOW_PACK)])?;
        repo.write("test.rs", OFFENDING)?;
        repo.write(
            DEFAULT_FLAW_PACK,
            &SWALLOW_PACK.replace("EXCEPTION", "NEVER_MATCHES"),
        )?;
        let patch = repo.patch()?;

        let flaws = check_flaws(repo.path(), &repo.base, &patch)?;
        assert!(!flaws.passed);
        assert!(
            flaws
                .evidence
                .iter()
                .any(|e| e.contains("swallow-exceptions"))
        );
        Ok(())
    }

    #[test]
    fn flaws_gate_fails_on_pattern_compilation_error() -> Result<()> {
        let repo = TestRepo::new(&[(
            DEFAULT_FLAW_PACK,
            r#"[[rules]]
id = "broken-rule"
pattern = "[invalid(regex"
files = ["**/*"]
explanation = "This has a broken pattern."
"#,
        )])?;
        // A clean patch: the failure is the broken rule, not a finding.
        repo.write("test.rs", "fn ok() {}\n")?;
        let patch = repo.patch()?;

        let result = check_flaws(repo.path(), &repo.base, &patch)?;
        assert!(!result.passed, "Gate must FAIL on invalid pattern");
        assert_eq!(result.evidence.len(), 1, "{:?}", result.evidence);
        assert!(result.evidence[0].starts_with("Rule error: broken-rule: "));
        assert!(result.evidence[0].contains("does not compile"));
        Ok(())
    }

    #[test]
    fn flaws_gate_names_rules_without_an_id_by_position() -> Result<()> {
        let repo = TestRepo::new(&[(
            DEFAULT_FLAW_PACK,
            "[[rules]]\npattern = \"fine\"\nfiles = [\"**/*\"]\nexplanation = \"x\"\n\n[[rules]]\npattern = \"(\"\nfiles = [\"**/*\"]\nexplanation = \"y\"\n",
        )])?;
        repo.write("test.rs", "x\n")?;
        let patch = repo.patch()?;

        let result = check_flaws(repo.path(), &repo.base, &patch)?;
        assert!(!result.passed);
        assert!(
            result.evidence[0].contains("rule #2"),
            "{:?}",
            result.evidence
        );
        Ok(())
    }

    #[test]
    fn flaws_gate_fails_on_malformed_pack() -> Result<()> {
        let repo = TestRepo::new(&[(DEFAULT_FLAW_PACK, "[[rules]]\npattern = \n")])?;
        repo.write("test.rs", OFFENDING)?;
        let patch = repo.patch()?;

        let result = check_flaws(repo.path(), &repo.base, &patch)?;
        assert!(!result.passed, "a malformed pack must not read as no rules");
        assert!(result.evidence[0].contains(DEFAULT_FLAW_PACK));
        Ok(())
    }

    #[test]
    fn flaws_gate_loads_packs_named_in_base_cowproof_toml() -> Result<()> {
        let repo = TestRepo::new(&[
            (
                "cowproof.toml",
                "[proof]\npacks = [\"generic\", \"./cowproof/flaws.toml\"]\n",
            ),
            ("cowproof/flaws.toml", SWALLOW_PACK),
        ])?;
        repo.write("test.rs", OFFENDING)?;
        repo.remove("cowproof/flaws.toml")?;
        let patch = repo.patch()?;

        let flaws = check_flaws(repo.path(), &repo.base, &patch)?;
        assert!(!flaws.passed);
        assert!(
            flaws
                .evidence
                .iter()
                .any(|e| e.contains("[swallow-exceptions]"))
        );

        let protected =
            check_protected_paths(repo.path(), &repo.base, &patch, &packet(&["test.rs"]))?;
        assert!(!protected.passed);
        assert!(protected.evidence[0].contains("cowproof/flaws.toml"));
        Ok(())
    }

    #[test]
    fn flaws_gate_fails_when_a_named_pack_is_missing_from_base() -> Result<()> {
        let repo = TestRepo::new(&[(
            "cowproof.toml",
            "[proof]\npacks = [\"./cowproof/flaws.toml\"]\n",
        )])?;
        repo.write("test.rs", "fn ok() {}\n")?;
        let patch = repo.patch()?;

        let result = check_flaws(repo.path(), &repo.base, &patch)?;
        assert!(!result.passed);
        assert!(result.evidence[0].contains("cowproof/flaws.toml"));
        assert!(result.evidence[0].contains("missing from the base"));
        Ok(())
    }

    #[test]
    fn flaws_gate_passes_with_a_note_when_no_pack_exists() -> Result<()> {
        let repo = TestRepo::new(&[])?;
        repo.write("test.rs", OFFENDING)?;
        let patch = repo.patch()?;

        let result = check_flaws(repo.path(), &repo.base, &patch)?;
        assert!(result.passed);
        assert_eq!(
            result.evidence,
            vec!["No flaw pack found in base".to_string()]
        );
        Ok(())
    }

    #[test]
    fn run_gates_rejects_a_base_that_is_not_a_commit() -> Result<()> {
        let repo = TestRepo::new(&[(DEFAULT_FLAW_PACK, SWALLOW_PACK)])?;
        repo.write("test.rs", OFFENDING)?;
        let patch = repo.patch()?;

        let err = run_gates(
            repo.path(),
            "no-such-revision",
            &patch,
            &packet(&["test.rs"]),
        )
        .unwrap_err();
        assert!(err.to_string().contains("not a commit"), "{err}");
        Ok(())
    }
}
