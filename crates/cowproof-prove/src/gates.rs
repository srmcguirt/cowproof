//! Proof gates: mechanical checks over the lane patch.
//!
//! Gates load configuration from the base revision, never the patched tree.
//! This prevents a patch from weakening its own checks.

use crate::flaws::{
    BaseCommitFiles, check_rules, configured_packs, load_flaw_packs, pack_file_paths,
};
use crate::port::PortOutcome;
use crate::verify::HeldOutOutcome;
use anyhow::{Context, Result, bail};
use cowproof_core::{
    git_show_optional, glob_matches, outside_ownership, parse_patch, removed_lines,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Configuration for a single gate execution.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GatePacket {
    /// The lane's id. A new file under the base commit's handoff directory whose name
    /// carries it as a whole token is accepted without being owned (see `handoff_accepted`). Empty means
    /// no such allowance.
    #[serde(default)]
    pub lane_id: String,
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
    let ownership_result = check_ownership(base_repo, base_commit, lane_patch, packet)?;
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

/// Write what the verifier found into the gate report, so `gates.json` alone tells the truth.
///
/// `run_gates` runs before the tree is rebuilt, so its `held_out` gate can only say the
/// checks are present. Once `verify` has run them, each held-out check's pass or fail is
/// added to that gate's evidence and the gate fails if any check did; the port packet's
/// held-out cases are recorded the same way (a skipped one warns, or fails the gate when
/// `require_heldout` is set: the base `cowproof.toml` asked for held-out evidence and the
/// skipped cases gave none). A `kind: port` capsule
/// also gets a `port_replay` gate. `any_failed` is recomputed. `verdict.json` is not built
/// from this: it keeps listing held-out failures under `heldOutFailed`.
pub fn record_verify_results(
    report: &mut GateReport,
    heldout: &[HeldOutOutcome],
    port: Option<&PortOutcome>,
    require_heldout: bool,
) {
    if let Some(gate) = report.gates.iter_mut().find(|g| g.name == "held_out") {
        for outcome in heldout {
            gate.evidence.push(format!(
                "held-out check {:?}: {}",
                outcome.check_id,
                if outcome.passed { "passed" } else { "failed" }
            ));
            gate.passed &= outcome.passed;
        }
        if let Some(port) = port {
            let held = &port.result.held_out;
            match held.state.as_str() {
                "passed" => gate.evidence.push(format!(
                    "held-out port cases: {} captured against the reference, all passed",
                    held.cases
                )),
                "failed" => {
                    gate.evidence.push(format!(
                        "held-out port cases: failed ({})",
                        held.reason.as_deref().unwrap_or("see the capsule")
                    ));
                    gate.passed = false;
                }
                "skipped" => {
                    gate.evidence.push(format!(
                        "held-out: skipped ({})",
                        held.reason.as_deref().unwrap_or("no reason")
                    ));
                    if require_heldout {
                        gate.evidence.push(
                            "held-out port cases skipped but [proof] require_heldout is set"
                                .to_string(),
                        );
                        gate.passed = false;
                    } else {
                        gate.warned = true;
                    }
                }
                _ => {}
            }
        }
    }
    if let Some(port) = port {
        let result = &port.result;
        let evidence = if result.success {
            let other = result
                .surfaces
                .values()
                .map(|s| s.other_platform)
                .max()
                .unwrap_or(0);
            let skipped = if other > 0 {
                format!(
                    "; {other} fixture(s) tagged for other platforms were not replayed and are not counted as passed"
                )
            } else {
                String::new()
            };
            vec![format!(
                "replayed {} fixture file(s) on the direct and mcp surfaces; fixture set sha256 {}{skipped}",
                result.fixture_count, result.fixture_hash
            )]
        } else {
            result.failures.clone()
        };
        report.gates.push(GateResult {
            name: "port_replay".to_string(),
            passed: result.success,
            warned: false,
            evidence,
        });
    }
    report.any_failed = report.gates.iter().any(|g| !g.passed);
}

/// The evidence line that says the old config file contributed protected globs.
const LANES_CONFIG_NOTE: &str =
    "protected globs read from lanes.config.json; move them to [proof] protected in cowproof.toml";

/// The repository rules at `base_commit`, from the base only, never the working tree: a
/// patch could edit that. The two config files go through `cowproof_core::repo_rules_from_texts`,
/// the one parser the report uses as well. Protected globs are the union of the base
/// `cowproof.toml` `[proof] protected` and `lanes.config.json` `protected`, so a rename
/// never shrinks protection. A value that is not a list of strings, or a file that does
/// not parse, is an error, never "no globs".
fn load_rules_from_base(base_repo: &Path, base_commit: &str) -> Result<cowproof_core::RepoRules> {
    let lanes = git_show_optional(base_repo, base_commit, "lanes.config.json")?;
    let toml = git_show_optional(base_repo, base_commit, "cowproof.toml")?;
    cowproof_core::repo_rules_from_texts(lanes.as_deref(), toml.as_deref())
        .context("reading the config files at the base")
}

/// Whether the base `cowproof.toml` sets `[proof] require_heldout = true`: a lane
/// without held-out checks then fails the held-out gate instead of only warning. Read
/// from the base commit, so a patch cannot switch it off. A missing file or key means
/// false; a file that does not parse is an error.
pub fn base_requires_heldout(repo: &Path, commit: &str) -> Result<bool> {
    verify_commit(repo, commit)?;
    let Some(text) = git_show_optional(repo, commit, "cowproof.toml")? else {
        return Ok(false);
    };
    let config: toml::Table =
        toml::from_str(&text).context("cowproof.toml in the base does not parse")?;
    Ok(config
        .get("proof")
        .and_then(|p| p.as_table())
        .and_then(|p| p.get("require_heldout"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false))
}

/// The migration baseline declared in the base `cowproof.toml`, `[proof] migration_baseline`:
/// the file name of the last applied migration. A migration that sorts at or before it
/// (see `flaws::migration_order`) is applied, and the `applied_migration` flaw rules fire
/// on a patch that edits or deletes one. Read from the base commit, so a patch cannot move
/// it (and `cowproof.toml` is protected, so editing it is flagged as well). A missing file
/// or key means no baseline; a value that is not a non-empty string, or a file that does
/// not parse, is an error.
pub fn base_migration_baseline(repo: &Path, commit: &str) -> Result<Option<String>> {
    verify_commit(repo, commit)?;
    let Some(text) = git_show_optional(repo, commit, "cowproof.toml")? else {
        return Ok(None);
    };
    let config: toml::Table =
        toml::from_str(&text).context("cowproof.toml in the base does not parse")?;
    let Some(value) = config
        .get("proof")
        .and_then(|p| p.as_table())
        .and_then(|p| p.get("migration_baseline"))
    else {
        return Ok(None);
    };
    match value.as_str().map(str::trim) {
        Some(name) if !name.is_empty() => Ok(Some(name.to_string())),
        _ => {
            bail!("[proof] migration_baseline in the base cowproof.toml must be a non-empty string")
        }
    }
}

/// Whether `name` holds `lane_id` as a whole token: the characters before it are the start of
/// the name or a separator (`-`, `_`, `.`), and so are the ones after it. `notes` is a token of
/// `notes.md`, `release-notes.md` and `notes-v2.md`, not of `footnotes.md` or `notesy.md`, and
/// `t-run-1` is one of `t-run-1.md`, not of `t-run-10.md`.
fn has_id_token(name: &str, lane_id: &str) -> bool {
    let is_sep = |c: char| matches!(c, '-' | '_' | '.');
    name.match_indices(lane_id).any(|(at, _)| {
        name[..at].chars().next_back().is_none_or(is_sep)
            && name[at + lane_id.len()..].chars().next().is_none_or(is_sep)
    })
}

/// Whether `path` is a handoff file the ownership gate accepts without `owns`: under
/// `handoff_dir` at any depth, and a file name that carries the lane id as a whole token
/// (`has_id_token`). `handoff_dir` comes from the base commit (a patch cannot move it). A
/// directory that is empty, absolute or has a `.`/`..`/empty component names no handoff
/// directory (`.` would otherwise be the whole repository), and a lane id that
/// `validate_lane_id` refuses (empty included) matches nothing.
fn handoff_accepted(path: &str, handoff_dir: &str, lane_id: &str) -> bool {
    let plain = |p: &str| p.split('/').all(|c| !matches!(c, "" | "." | ".."));
    let dir = handoff_dir.trim_end_matches('/');
    if cowproof_run::lane::validate_lane_id(lane_id).is_err() || dir.is_empty() || !plain(dir) {
        return false;
    }
    let Some(rest) = path
        .strip_prefix(dir)
        .and_then(|rest| rest.strip_prefix('/'))
    else {
        return false;
    };
    plain(rest)
        && rest
            .rsplit('/')
            .next()
            .is_some_and(|name| has_id_token(name, lane_id))
}

/// Gate 1: Ownership - files outside `owns` fail.
///
/// One allowance: a regular file the patch **creates** under the base commit's handoff
/// directory, named for the lane (`handoff_accepted`), needs no `owns`, so the handoff the
/// builder preamble asks for passes without the director naming it. Editing, deleting or
/// renaming a file that already exists there (another lane's handoff), a symlink, and a
/// path the always-protected globs name all stay outside. The evidence names each file
/// accepted this way.
fn check_ownership(
    base_repo: &Path,
    base_commit: &str,
    lane_patch: &str,
    packet: &GatePacket,
) -> Result<GateResult> {
    let deltas = parse_patch(lane_patch);
    let files: Vec<String> = deltas.iter().map(|d| d.path.clone()).collect();

    // Always protected by default
    let always_protected = vec![
        ".env".into(),
        ".env.*".into(),
        "**/.env".into(),
        "**/.env.*".into(),
    ];

    let mut outside = outside_ownership(&files, &packet.owns, &always_protected);

    // The handoff directory is the base commit's, never the patched tree's.
    let mut accepted = Vec::new();
    if !outside.is_empty() && !packet.lane_id.is_empty() {
        let handoff_dir = load_rules_from_base(base_repo, base_commit)?.handoff_dir;
        outside.retain(|file| {
            let creates_regular_file = deltas.iter().any(|d| {
                d.path == *file && matches!(d.new_file_mode.as_deref(), Some("100644" | "100755"))
            });
            let protected = always_protected.iter().any(|g| glob_matches(g, file));
            let ok = creates_regular_file
                && !protected
                && handoff_accepted(file, &handoff_dir, &packet.lane_id);
            if ok {
                accepted.push(file.clone());
            }
            !ok
        });
    }

    let passed = outside.is_empty();
    let mut evidence = Vec::new();
    if !passed {
        evidence.push(format!("Files outside owns globs: {}", outside.join(", ")));
    }
    for file in accepted {
        evidence.push(format!("handoff file accepted outside owns: {file}"));
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
    // Load protected list from repo config in the base commit, not the working tree
    let base_rules = load_rules_from_base(base_repo, base_commit)?;

    // Build complete protected list
    let mut protected = Vec::new();
    protected.extend(
        cowproof_core::ALWAYS_PROTECTED
            .iter()
            .map(|s| s.to_string()),
    );
    protected.extend(base_rules.protected.clone());
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
        // Both config files are gate inputs, whatever list `lanes.config.json` names.
        "lanes.config.json".into(),
        "cowproof/**".into(),
    ]);

    // Registry configuration (D14): the dependency fetch and the cache key read it
    // from the base only, and a builder never chooses where its dependencies come
    // from. The one list lives in cowproof-run, beside the key that hashes it; a
    // nested copy (a workspace member's own `.cargo/config.toml`) counts too, and
    // `.yarnrc*` covers every yarn rc file.
    for name in cowproof_run::REGISTRY_CONFIGS {
        protected.push((*name).to_string());
        protected.push(format!("**/{name}"));
    }
    protected.extend([".yarnrc*".to_string(), "**/.yarnrc*".to_string()]);

    // Every pack file named in the base `cowproof.toml` `[proof] packs` is a gate input, so
    // a patch may not touch it. Built-in names are embedded and have no path.
    let base_files = BaseCommitFiles {
        repo: base_repo,
        commit: base_commit,
    };
    protected.extend(pack_file_paths(&configured_packs(&base_files)?));

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
    if base_rules.protected_from_lanes_config {
        evidence.push(LANES_CONFIG_NOTE.to_string());
    }

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
                            if heldout.is_empty() {
                                (
                                    false,
                                    false,
                                    vec!["Held-out checks file is empty".to_string()],
                                )
                            } else {
                                let mut evidence = Vec::new();
                                if check_count > 0 {
                                    evidence.push(format!(
                                        "Held-out checks present: {} check{}",
                                        check_count,
                                        if check_count == 1 { "" } else { "s" }
                                    ));
                                }
                                if heldout.port.is_some() {
                                    evidence.push("Held-out port cases present".to_string());
                                }
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
/// The embedded generic pack always runs, plus every pack named in the base
/// `cowproof.toml` `[proof] packs`. Named files are read with `git show <base>:<path>`,
/// never from the working tree, through the loader the report shares. A pack that is
/// missing, escapes the repository, is malformed or holds a rule whose pattern does not
/// compile FAILS the gate.
fn check_flaws(base_repo: &Path, base_commit: &str, lane_patch: &str) -> Result<GateResult> {
    let deltas = parse_patch(lane_patch);
    let mut evidence = Vec::new();
    let mut failed = false;

    // The generic pack is embedded and always runs; the packs the base `cowproof.toml`
    // names come from the base commit. One loader, shared with `cowproof report handback`.
    let base_files = BaseCommitFiles {
        repo: base_repo,
        commit: base_commit,
    };
    let configured = configured_packs(&base_files)?;
    let rules = match load_flaw_packs(&base_files, &configured) {
        Ok(loaded) => loaded.rules,
        Err(e) => {
            return Ok(GateResult {
                name: "flaws".to_string(),
                passed: false,
                warned: false,
                evidence: vec![format!("Flaw pack error: {e:#}")],
            });
        }
    };

    // The migration baseline is a gate input like the packs: base commit only. When a loaded
    // rule needs it and the base declares none, the gate says so rather than passing quietly.
    let baseline = base_migration_baseline(base_repo, base_commit)?;
    let mut warned = false;
    if rules.iter().any(|r| r.applied_migration) {
        match &baseline {
            Some(name) => evidence.push(format!(
                "applied_migration rules checked against [proof] migration_baseline {name} \
                 (from the base cowproof.toml)"
            )),
            None => {
                // Warn only when it matters: the patch touches a migration that an
                // `applied_migration` rule covers. A patch that touches none passes quietly.
                let touched: Vec<&str> = deltas
                    .iter()
                    .filter(|d| {
                        crate::flaws::migration_file_name(&d.path).is_some()
                            && rules
                                .iter()
                                .filter(|r| r.applied_migration)
                                .any(|r| r.files.iter().any(|g| glob_matches(g, &d.path)))
                    })
                    .map(|d| d.path.as_str())
                    .collect();
                if !touched.is_empty() {
                    warned = true;
                    evidence.push(format!(
                        "applied_migration rules skipped for {}: the base cowproof.toml sets no \
                         [proof] migration_baseline",
                        touched.join(", ")
                    ));
                }
            }
        }
    }
    let (findings, errors) = check_rules(&rules, &deltas, baseline.as_deref());
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
        warned,
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    /// A project pack with one rule the embedded generic pack does not have, so a test
    /// can tell which pack a finding came from.
    const SWALLOW_PACK: &str = r#"[[rules]]
id = "swallow-exceptions"
pattern = "SWALLOWED_ERROR"
files = ["**/*"]
explanation = "This catches and can swallow every exception."
"#;

    const OFFENDING: &str = "    SWALLOWED_ERROR THEN NULL;\n";

    /// Where the tests keep their project pack, and the base `cowproof.toml` that names it.
    const TEST_PACK: &str = "cowproof/flaws.toml";
    const TEST_PACK_CONFIG: &str = "[proof]\npacks = [\"./cowproof/flaws.toml\"]\n";

    /// A base commit holding `pack` at `TEST_PACK`, named by its `cowproof.toml`.
    fn named_pack(pack: &str) -> [(&str, &str); 2] {
        [("cowproof.toml", TEST_PACK_CONFIG), (TEST_PACK, pack)]
    }

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
            let dir = TempDir::new_in("/var/tmp")?;
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

        /// Create a new repo with a cowproof.toml config that lists the given packs.
        fn with_config(packs: &[&str]) -> Result<Self> {
            let dir = TempDir::new()?;
            let repo = dir.path();
            git(repo, &["init", "-q"])?;
            git(repo, &["config", "user.email", "test@test.local"])?;
            git(repo, &["config", "user.name", "Test"])?;
            let packs_list = packs
                .iter()
                .map(|p| format!("\"{}\"", p))
                .collect::<Vec<_>>()
                .join(", ");
            let config = format!("[proof]\npacks = [{}]\n", packs_list);
            fs::write(repo.join("cowproof.toml"), &config)?;
            fs::write(repo.join("README.md"), "# Test\n")?;
            git(repo, &["add", "-A"])?;
            git(repo, &["commit", "-q", "-m", "base"])?;
            let base = git(repo, &["rev-parse", "HEAD"])?.trim().to_string();
            Ok(TestRepo { dir, base })
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
            lane_id: String::new(),
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

        let repo = TestRepo::new(&[])?;
        let result = check_ownership(repo.path(), &repo.base, patch, &packet(&["src/**"]))?;
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

        let repo = TestRepo::new(&[])?;
        let result = check_ownership(repo.path(), &repo.base, patch, &packet(&["src/**"]))?;
        assert!(result.passed);
        assert!(result.evidence.is_empty());
        Ok(())
    }

    /// A packet for lane `lane-hd` that owns only `src/**`.
    fn lane_packet() -> GatePacket {
        GatePacket {
            lane_id: "lane-hd".into(),
            ..packet(&["src/**"])
        }
    }

    /// The ownership gate over a real `git diff` of `repo`'s working tree.
    fn ownership_of(repo: &TestRepo, packet: &GatePacket) -> Result<GateResult> {
        check_ownership(repo.path(), &repo.base, &repo.patch()?, packet)
    }

    #[test]
    fn a_new_handoff_named_for_the_lane_passes_without_owns_and_the_evidence_names_it() -> Result<()>
    {
        let repo = TestRepo::new(&[])?;
        repo.write("docs/handoffs/lane-hd.md", "# handoff\n")?;
        repo.write("docs/handoffs/2026-10-12-lane-hd-notes.md", "notes\n")?;
        repo.write("docs/handoffs/deep/er/lane-hd.md", "deep\n")?;
        repo.write("src/a.rs", "// a\n")?;
        let result = ownership_of(&repo, &lane_packet())?;
        assert!(result.passed, "{:?}", result.evidence);
        assert_eq!(
            result.evidence,
            vec![
                "handoff file accepted outside owns: docs/handoffs/2026-10-12-lane-hd-notes.md",
                "handoff file accepted outside owns: docs/handoffs/deep/er/lane-hd.md",
                "handoff file accepted outside owns: docs/handoffs/lane-hd.md",
            ]
        );
        // Through the whole gate run, too.
        let report = run_gates(repo.path(), &repo.base, &repo.patch()?, &lane_packet())?;
        assert!(gate(&report, "ownership").passed);
        Ok(())
    }

    #[test]
    fn a_new_handoff_without_the_lane_id_in_its_name_still_needs_owns() -> Result<()> {
        let repo = TestRepo::new(&[])?;
        repo.write("docs/handoffs/notes.md", "notes\n")?;
        // The lane id in a directory name is not a file name.
        repo.write("docs/handoffs/lane-hd/notes.md", "notes\n")?;
        let result = ownership_of(&repo, &lane_packet())?;
        assert!(!result.passed);
        assert_eq!(
            result.evidence,
            vec![
                "Files outside owns globs: docs/handoffs/lane-hd/notes.md, docs/handoffs/notes.md"
            ]
        );
        // A packet with no lane id (an older caller) gets no allowance either.
        let repo = TestRepo::new(&[])?;
        repo.write("docs/handoffs/lane-hd.md", "# handoff\n")?;
        assert!(!ownership_of(&repo, &packet(&["src/**"]))?.passed);
        Ok(())
    }

    #[test]
    fn a_handoff_that_holds_the_lane_id_inside_a_longer_word_still_needs_owns() -> Result<()> {
        let repo = TestRepo::new(&[])?;
        repo.write("docs/handoffs/release-notes.md", "ok\n")?;
        repo.write("docs/handoffs/footnotes.md", "no\n")?;
        repo.write("docs/handoffs/notesy.md", "no\n")?;
        let packet = GatePacket {
            lane_id: "notes".into(),
            ..packet(&["src/**"])
        };
        let result = ownership_of(&repo, &packet)?;
        assert!(!result.passed);
        assert_eq!(
            result.evidence,
            vec![
                "Files outside owns globs: docs/handoffs/footnotes.md, docs/handoffs/notesy.md",
                "handoff file accepted outside owns: docs/handoffs/release-notes.md",
            ]
        );
        Ok(())
    }

    #[test]
    fn modifying_an_existing_handoff_still_needs_owns_even_with_the_lane_id() -> Result<()> {
        let repo = TestRepo::new(&[("docs/handoffs/lane-hd.md", "# old\n")])?;
        repo.write("docs/handoffs/lane-hd.md", "# rewritten\n")?;
        let result = ownership_of(&repo, &lane_packet())?;
        assert!(!result.passed);
        assert_eq!(
            result.evidence,
            vec!["Files outside owns globs: docs/handoffs/lane-hd.md"]
        );
        Ok(())
    }

    #[test]
    fn deleting_an_existing_handoff_still_needs_owns() -> Result<()> {
        let repo = TestRepo::new(&[("docs/handoffs/lane-hd.md", "# old\n")])?;
        repo.remove("docs/handoffs/lane-hd.md")?;
        let result = ownership_of(&repo, &lane_packet())?;
        assert!(!result.passed);
        assert_eq!(
            result.evidence,
            vec!["Files outside owns globs: docs/handoffs/lane-hd.md"]
        );
        Ok(())
    }

    #[test]
    fn renaming_a_handoff_to_a_lane_named_one_still_needs_owns() -> Result<()> {
        // Another lane's handoff, moved to a name that carries this lane's id: the new
        // path is not a created file (git reports a rename), so it is not accepted.
        let repo = TestRepo::new(&[("docs/handoffs/other.md", "# other lane's handoff\n")])?;
        git(
            repo.path(),
            &["mv", "docs/handoffs/other.md", "docs/handoffs/lane-hd.md"],
        )?;
        let result = ownership_of(&repo, &lane_packet())?;
        assert!(!result.passed, "{:?}", result.evidence);
        assert_eq!(
            result.evidence,
            vec!["Files outside owns globs: docs/handoffs/lane-hd.md"]
        );
        Ok(())
    }

    #[test]
    fn moving_the_handoff_dir_in_the_patch_gains_nothing() -> Result<()> {
        let repo = TestRepo::new(&[("cowproof.toml", "[paths]\nhandoffs = \"docs/handoffs\"\n")])?;
        repo.write("cowproof.toml", "[paths]\nhandoffs = \"src\"\n")?;
        repo.write("src/lane-hd.rs", "fn main() {}\n")?;
        // Not owned (the packet owns docs only), and `src` is the patched tree's handoff dir.
        let packet = GatePacket {
            lane_id: "lane-hd".into(),
            ..packet(&["docs/**"])
        };
        let result = ownership_of(&repo, &packet)?;
        assert!(!result.passed);
        assert_eq!(
            result.evidence,
            vec!["Files outside owns globs: cowproof.toml, src/lane-hd.rs"]
        );
        Ok(())
    }

    #[test]
    fn the_base_handoff_dir_from_cowproof_toml_is_the_one_used() -> Result<()> {
        let repo =
            TestRepo::new(&[("cowproof.toml", "[paths]\nhandoffs = \"notes/handoffs/\"\n")])?;
        repo.write("notes/handoffs/lane-hd.md", "# handoff\n")?;
        // The default directory is not the base's, so a file there needs owns.
        repo.write("docs/handoffs/lane-hd.md", "# handoff\n")?;
        let packet = GatePacket {
            lane_id: "lane-hd".into(),
            ..packet(&["cowproof.toml"])
        };
        let result = ownership_of(&repo, &packet)?;
        assert!(!result.passed);
        assert_eq!(
            result.evidence,
            vec![
                "Files outside owns globs: docs/handoffs/lane-hd.md",
                "handoff file accepted outside owns: notes/handoffs/lane-hd.md",
            ]
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_added_under_the_handoff_dir_is_not_accepted() -> Result<()> {
        let repo = TestRepo::new(&[])?;
        fs::create_dir_all(repo.path().join("docs/handoffs"))?;
        std::os::unix::fs::symlink(
            "../../src/secret.rs",
            repo.path().join("docs/handoffs/lane-hd.md"),
        )?;
        let result = ownership_of(&repo, &lane_packet())?;
        assert!(!result.passed);
        assert_eq!(
            result.evidence,
            vec!["Files outside owns globs: docs/handoffs/lane-hd.md"]
        );
        Ok(())
    }

    #[test]
    fn a_protected_path_is_not_accepted_as_a_handoff() -> Result<()> {
        // A base whose handoff directory is the repository root would accept `.env`.
        let repo = TestRepo::new(&[("cowproof.toml", "[paths]\nhandoffs = \"cfg\"\n")])?;
        repo.write("cfg/.env.lane-hd", "SECRET=1\n")?;
        repo.write("cfg/.env", "SECRET=1\n")?;
        let result = ownership_of(&repo, &lane_packet())?;
        assert!(!result.passed);
        assert_eq!(
            result.evidence,
            vec!["Files outside owns globs: cfg/.env, cfg/.env.lane-hd"]
        );
        Ok(())
    }

    #[test]
    fn handoff_accepted_matches_the_directory_and_the_file_name_only() {
        let ok = |p: &str, d: &str, id: &str| handoff_accepted(p, d, id);
        assert!(ok("docs/handoffs/x-lane-a.md", "docs/handoffs", "lane-a"));
        // Boundaries: a separator or an end on each side, never part of a longer word.
        for name in [
            "notes.md",
            "2026-10-12-notes.md",
            "notes-v2.md",
            "release-notes.md",
            "a_notes_b",
            "notes",
        ] {
            assert!(
                ok(&format!("docs/handoffs/{name}"), "docs/handoffs", "notes"),
                "{name}"
            );
        }
        for name in [
            "footnotes.md",
            "notesy.md",
            "annotes.md",
            "xnotesx.md",
            "notes2.md",
        ] {
            assert!(
                !ok(&format!("docs/handoffs/{name}"), "docs/handoffs", "notes"),
                "{name}"
            );
        }
        // A later occurrence counts when an earlier one is inside a word.
        assert!(ok(
            "docs/handoffs/footnotes-notes.md",
            "docs/handoffs",
            "notes"
        ));
        // A short id does not match every name that holds the letter.
        assert!(!ok("docs/handoffs/x.md", "docs/handoffs", "xx"));
        assert!(!ok("docs/handoffs/index.md", "docs/handoffs", "x"));
        assert!(ok("docs/handoffs/x.md", "docs/handoffs", "x"));
        // An id with separators of its own is one token: `t-run-1` is not `t-run-10`.
        assert!(ok("docs/handoffs/t-run-1.md", "docs/handoffs", "t-run-1"));
        assert!(ok(
            "docs/handoffs/2026-t-run-1-notes.md",
            "docs/handoffs",
            "t-run-1"
        ));
        assert!(!ok("docs/handoffs/t-run-10.md", "docs/handoffs", "t-run-1"));
        assert!(!ok(
            "docs/handoffs/t-run-10-notes.md",
            "docs/handoffs",
            "t-run-1"
        ));
        // An id the lane-id validator refuses accepts nothing.
        for id in ["", ".", "..", "a/b", "a b", "a*", &"a".repeat(65)] {
            assert!(!ok("docs/handoffs/a.md", "docs/handoffs", id), "{id:?}");
            assert!(
                !ok(&format!("docs/handoffs/{id}"), "docs/handoffs", id),
                "{id:?}"
            );
        }
        assert!(ok("docs/handoffs/a/b/lane-a", "docs/handoffs/", "lane-a"));
        // A sibling that merely shares the prefix, the directory itself, another name.
        assert!(!ok(
            "docs/handoffs-old/lane-a.md",
            "docs/handoffs",
            "lane-a"
        ));
        assert!(!ok("docs/handoffs", "docs/handoffs", "lane-a"));
        assert!(!ok("docs/handoffs/lane-b.md", "docs/handoffs", "lane-a"));
        assert!(!ok(
            "docs/handoffs/lane-a/readme.md",
            "docs/handoffs",
            "lane-a"
        ));
        // No lane id, or a directory that is not one.
        assert!(!ok("docs/handoffs/lane-a.md", "docs/handoffs", ""));
        for dir in [
            "",
            ".",
            "/",
            "/docs",
            "docs/../src",
            "docs//handoffs",
            "./docs",
        ] {
            assert!(!ok("src/lane-a.rs", dir, "lane-a"), "{dir:?}");
            assert!(!ok("docs/handoffs/lane-a.md", dir, "lane-a"), "{dir:?}");
        }
        assert!(!ok(
            "docs/handoffs/../src/lane-a.rs",
            "docs/handoffs",
            "lane-a"
        ));
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

    /// A hand-written patch touching `path`, so the test controls the paths and the
    /// repository's working tree stays out of the patch.
    fn touching(path: &str) -> String {
        format!(
            "diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n@@ -1 +1,2 @@\n old\n+new\n"
        )
    }

    const PROTECT_SECRET: &str = "{\"protected\": [\"secret/**\"]}";

    #[test]
    fn a_protected_rule_committed_in_the_base_applies() -> Result<()> {
        let repo = TestRepo::new(&[("lanes.config.json", PROTECT_SECRET)])?;
        let result = check_protected_paths(
            repo.path(),
            &repo.base,
            &touching("secret/key.txt"),
            &packet(&["docs/**"]),
        )?;
        assert!(!result.passed);
        assert_eq!(
            result.evidence,
            vec![
                "Protected paths touched: secret/key.txt".to_string(),
                LANES_CONFIG_NOTE.to_string(),
            ]
        );
        assert!(
            LANES_CONFIG_NOTE.contains("lanes.config.json")
                && LANES_CONFIG_NOTE.contains("[proof] protected in cowproof.toml")
        );
        assert!(!result.warned, "the note is not a warning");
        Ok(())
    }

    const TOML_PROTECT_SECRET: &str = "[proof]\nprotected = [\"secret/**\"]\n";

    /// A hand-written patch touching every path in `paths`.
    fn touching_all(paths: &[&str]) -> String {
        paths.iter().map(|p| touching(p)).collect()
    }

    #[test]
    fn a_protected_rule_in_cowproof_toml_applies_without_a_note() -> Result<()> {
        let repo = TestRepo::new(&[("cowproof.toml", TOML_PROTECT_SECRET)])?;
        let result = check_protected_paths(
            repo.path(),
            &repo.base,
            &touching("secret/key.txt"),
            &packet(&["docs/**"]),
        )?;
        assert!(!result.passed);
        assert_eq!(
            result.evidence,
            vec!["Protected paths touched: secret/key.txt".to_string()]
        );
        // The extra globs add to the defaults: they do not replace them.
        let defaults = check_protected_paths(
            repo.path(),
            &repo.base,
            &touching("AGENTS.md"),
            &packet(&["**"]),
        )?;
        assert!(
            defaults.passed && defaults.warned,
            "{:?}",
            defaults.evidence
        );
        let outside = check_protected_paths(
            repo.path(),
            &repo.base,
            &touching("AGENTS.md"),
            &packet(&["docs/**"]),
        )?;
        assert!(!outside.passed);
        Ok(())
    }

    #[test]
    fn both_config_files_protect_the_union() -> Result<()> {
        let repo = TestRepo::new(&[
            ("cowproof.toml", "[proof]\nprotected = [\"from_toml/**\"]\n"),
            ("lanes.config.json", "{\"protected\": [\"from_json/**\"]}"),
        ])?;
        let result = check_protected_paths(
            repo.path(),
            &repo.base,
            &touching_all(&["from_toml/a.txt", "from_json/b.txt", "free/c.txt"]),
            &packet(&["docs/**"]),
        )?;
        assert!(!result.passed);
        // Protected files are violations; the unprotected one is not this gate's concern.
        assert_eq!(
            result.evidence[0],
            "Protected paths touched: from_toml/a.txt, from_json/b.txt"
        );
        // Each glob alone protects.
        for path in ["from_toml/a.txt", "from_json/b.txt"] {
            let only = check_protected_paths(
                repo.path(),
                &repo.base,
                &touching(path),
                &packet(&["docs/**"]),
            )?;
            assert!(!only.passed, "{path} must be protected");
        }
        // Owned, so the only thing left is the protected-path warning: both globs fire.
        let owned = check_protected_paths(
            repo.path(),
            &repo.base,
            &touching_all(&["from_toml/a.txt", "from_json/b.txt"]),
            &packet(&["from_toml/**", "from_json/**"]),
        )?;
        assert!(owned.passed && owned.warned);
        assert_eq!(
            owned
                .evidence
                .iter()
                .filter(|l| l.contains("check harness changed"))
                .count(),
            2,
            "{:?}",
            owned.evidence
        );
        assert_eq!(
            owned
                .evidence
                .iter()
                .filter(|l| *l == LANES_CONFIG_NOTE)
                .count(),
            1,
            "the note appears once: {:?}",
            owned.evidence
        );
        Ok(())
    }

    #[test]
    fn a_patch_that_drops_a_glob_from_cowproof_toml_is_judged_by_the_base() -> Result<()> {
        let repo = TestRepo::new(&[("cowproof.toml", TOML_PROTECT_SECRET)])?;
        // The lane empties the list in its working tree and touches a file it protected.
        repo.write("cowproof.toml", "[proof]\nprotected = []\n")?;
        let result = check_protected_paths(
            repo.path(),
            &repo.base,
            &touching_all(&["cowproof.toml", "secret/key.txt"]),
            &packet(&["docs/**"]),
        )?;
        assert!(!result.passed);
        assert_eq!(
            result.evidence,
            vec!["Protected paths touched: cowproof.toml, secret/key.txt".to_string()]
        );
        Ok(())
    }

    #[test]
    fn both_config_files_are_protected_even_when_a_list_omits_them() -> Result<()> {
        let repo = TestRepo::new(&[("lanes.config.json", "{\"protected\": [\"secret/**\"]}")])?;
        for path in ["lanes.config.json", "cowproof.toml"] {
            let result = check_protected_paths(
                repo.path(),
                &repo.base,
                &touching(path),
                &packet(&["docs/**"]),
            )?;
            assert!(!result.passed, "{path} must be protected");
        }
        Ok(())
    }

    #[test]
    fn a_malformed_protected_value_is_an_error_not_no_globs() -> Result<()> {
        let cases: [(&str, &str, &str); 6] = [
            (
                "cowproof.toml",
                "[proof]\nprotected = \"secret/**\"\n",
                "list of strings",
            ),
            (
                "cowproof.toml",
                "[proof]\nprotected = [1]\n",
                "list of strings",
            ),
            ("cowproof.toml", "proof = \"x\"\n", "must be a table"),
            (
                "lanes.config.json",
                "{\"protected\": \"secret/**\"}",
                "list of strings",
            ),
            (
                "lanes.config.json",
                "{\"protected\": [\"a\", 2]}",
                "list of strings",
            ),
            ("lanes.config.json", "{not json", "does not parse"),
        ];
        for (file, text, expect) in cases {
            let repo = TestRepo::new(&[(file, text)])?;
            let err = check_protected_paths(
                repo.path(),
                &repo.base,
                &touching("secret/key.txt"),
                &packet(&["docs/**"]),
            )
            .expect_err(&format!("{file}: {text}"));
            let message = format!("{err:#}");
            assert!(message.contains(expect), "{file}: {message}");
        }
        Ok(())
    }

    #[test]
    fn a_protected_rule_only_in_the_working_tree_has_no_effect() -> Result<()> {
        // The base commit has no lanes.config.json. The director's working tree gains one
        // that protects `secret/**`, uncommitted: the gate must not see it.
        let repo = TestRepo::new(&[])?;
        repo.write("lanes.config.json", PROTECT_SECRET)?;
        let result = check_protected_paths(
            repo.path(),
            &repo.base,
            &touching("secret/key.txt"),
            &packet(&["docs/**"]),
        )?;
        assert!(result.passed, "{:?}", result.evidence);
        assert!(result.evidence.is_empty());
        Ok(())
    }

    #[test]
    fn a_committed_protected_rule_edited_away_in_the_working_tree_still_applies() -> Result<()> {
        let repo = TestRepo::new(&[("lanes.config.json", PROTECT_SECRET)])?;
        repo.write("lanes.config.json", "{\"protected\": [\"other/**\"]}")?;
        let result = check_protected_paths(
            repo.path(),
            &repo.base,
            &touching("secret/key.txt"),
            &packet(&["docs/**"]),
        )?;
        assert!(!result.passed);
        assert!(result.evidence[0].contains("secret/key.txt"));
        Ok(())
    }

    #[test]
    fn registry_config_is_protected_by_default() -> Result<()> {
        // Registry configs are protected: a builder cannot modify them, and fetch
        // always uses the base commit's config (D14).
        let repo = TestRepo::new(&[])?;
        for config_file in &[
            ".cargo/config.toml",
            ".cargo/config",
            ".npmrc",
            ".yarnrc",
            ".yarnrc.yml",
            "crates/member/.cargo/config.toml",
            "web/.npmrc",
            ".yarnrc.local",
        ] {
            let result = check_protected_paths(
                repo.path(),
                &repo.base,
                &touching(config_file),
                &packet(&["docs/**"]),
            )?;
            assert!(!result.passed, "{} should be protected", config_file);
            assert!(
                result.evidence[0].contains(config_file),
                "evidence should name {}",
                config_file
            );
        }
        Ok(())
    }

    #[test]
    fn require_heldout_is_read_from_the_base_cowproof_toml() -> Result<()> {
        let on = TestRepo::new(&[("cowproof.toml", "[proof]\nrequire_heldout = true\n")])?;
        assert!(base_requires_heldout(on.path(), &on.base)?);
        let off = TestRepo::new(&[("cowproof.toml", "[proof]\npacks = []\n")])?;
        assert!(!base_requires_heldout(off.path(), &off.base)?);
        let none = TestRepo::new(&[])?;
        assert!(!none.path().join("cowproof.toml").exists());
        assert!(!base_requires_heldout(none.path(), &none.base)?);
        // Only the base counts: switching it on in the working tree does nothing.
        none.write("cowproof.toml", "[proof]\nrequire_heldout = true\n")?;
        assert!(!base_requires_heldout(none.path(), &none.base)?);
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
        let repo = TestRepo::new(&named_pack(SWALLOW_PACK))?;
        repo.write("test.rs", OFFENDING)?;
        let patch = repo.patch()?;
        assert!(patch.contains("+    SWALLOWED_ERROR"), "{patch}");

        let result = check_flaws(repo.path(), &repo.base, &patch)?;
        assert!(!result.passed);
        assert_eq!(result.evidence.len(), 1, "{:?}", result.evidence);
        assert!(result.evidence[0].starts_with("test.rs:1: [swallow-exceptions] "));
        assert!(result.evidence[0].contains("This catches and can swallow every exception."));
        Ok(())
    }

    #[test]
    fn flaws_passes_a_clean_patch_and_says_which_pack_ran() -> Result<()> {
        let repo = TestRepo::new(&named_pack(SWALLOW_PACK))?;
        repo.write("test.rs", "fn ok() {}\n")?;
        let patch = repo.patch()?;

        let result = check_flaws(repo.path(), &repo.base, &patch)?;
        assert!(result.passed, "{:?}", result.evidence);
        assert!(result.evidence.is_empty());
        Ok(())
    }

    #[test]
    fn flaws_sees_added_lines_that_start_with_plus_signs() -> Result<()> {
        let repo = TestRepo::new(&named_pack(SWALLOW_PACK))?;
        repo.write("test.sql", "++ SWALLOWED_ERROR\n")?;
        let patch = repo.patch()?;
        assert!(patch.contains("\n+++ SWALLOWED_ERROR"), "{patch}");

        let result = check_flaws(repo.path(), &repo.base, &patch)?;
        assert!(!result.passed, "an added `++` line evaded the flaw gate");
        Ok(())
    }

    #[test]
    fn flaws_loaded_from_base_not_patched_tree() -> Result<()> {
        // The patch adds a violation AND deletes the rule that would catch it.
        let repo = TestRepo::new(&named_pack(SWALLOW_PACK))?;
        repo.write("test.rs", OFFENDING)?;
        repo.remove(TEST_PACK)?;
        let patch = repo.patch()?;
        assert!(
            patch.contains("deleted file mode"),
            "the patch must delete the pack: {patch}"
        );
        assert!(!repo.path().join(TEST_PACK).exists());

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
            vec![format!("Protected paths touched: {TEST_PACK}")]
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
        let repo = TestRepo::new(&named_pack(SWALLOW_PACK))?;
        repo.write("test.rs", OFFENDING)?;
        repo.write(
            TEST_PACK,
            &SWALLOW_PACK.replace("SWALLOWED_ERROR", "NEVER_MATCHES"),
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
        let repo = TestRepo::new(&named_pack(
            r#"[[rules]]
id = "broken-rule"
pattern = "[invalid(regex"
files = ["**/*"]
explanation = "This has a broken pattern."
"#,
        ))?;
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
        let repo = TestRepo::new(&named_pack(
            "[[rules]]\npattern = \"fine\"\nfiles = [\"**/*\"]\nexplanation = \"x\"\n\n[[rules]]\npattern = \"(\"\nfiles = [\"**/*\"]\nexplanation = \"y\"\n",
        ))?;
        repo.write("test.rs", "x\n")?;
        let patch = repo.patch()?;

        let result = check_flaws(repo.path(), &repo.base, &patch)?;
        assert!(!result.passed);
        // The generic pack's five rules load first, so the broken one is the seventh.
        assert!(
            result.evidence[0].contains("rule #7"),
            "{:?}",
            result.evidence
        );
        Ok(())
    }

    #[test]
    fn flaws_gate_fails_on_malformed_pack() -> Result<()> {
        let repo = TestRepo::new(&named_pack("[[rules]]\npattern = \n"))?;
        repo.write("test.rs", OFFENDING)?;
        let patch = repo.patch()?;

        let result = check_flaws(repo.path(), &repo.base, &patch)?;
        assert!(!result.passed, "a malformed pack must not read as no rules");
        assert!(result.evidence[0].contains(TEST_PACK));
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
    fn flaws_gate_runs_the_generic_rules_on_a_repository_with_no_pack_files_at_all() -> Result<()> {
        // No cowproof.toml, no pack file: the embedded generic pack still runs.
        let repo = TestRepo::new(&[])?;
        repo.write("test.sql", "    EXCEPTION WHEN OTHERS THEN NULL;\n")?;
        let patch = repo.patch()?;

        let result = check_flaws(repo.path(), &repo.base, &patch)?;
        assert!(!result.passed, "{:?}", result.evidence);
        assert_eq!(result.evidence.len(), 1, "{:?}", result.evidence);
        assert!(
            result.evidence[0].starts_with("test.sql:1: [rule #1] "),
            "{:?}",
            result.evidence
        );

        // A clean patch passes quietly: no note about a missing pack.
        let clean = TestRepo::new(&[])?;
        clean.write("test.rs", "fn ok() {}\n")?;
        let result = check_flaws(clean.path(), &clean.base, &clean.patch()?)?;
        assert!(result.passed && !result.warned, "{:?}", result.evidence);
        assert!(result.evidence.is_empty(), "{:?}", result.evidence);
        Ok(())
    }

    #[test]
    fn a_built_in_name_in_packs_loads_its_embedded_pack() -> Result<()> {
        let repo = TestRepo::new(&[(
            "cowproof.toml",
            "[proof]\npacks = [\"generic\", \"example-supabase\"]\n",
        )])?;
        repo.write("test.sql", "create policy p using (true);\n")?;
        let patch = repo.patch()?;
        let result = check_flaws(repo.path(), &repo.base, &patch)?;
        assert!(!result.passed, "{:?}", result.evidence);
        assert!(
            result
                .evidence
                .iter()
                .any(|e| e.contains("Placeholder or public policy")),
            "{:?}",
            result.evidence
        );
        // Built-in names are not repository paths, so they are not protected globs.
        let protected =
            check_protected_paths(repo.path(), &repo.base, &touching("generic"), &packet(&[]))?;
        assert!(protected.passed, "{:?}", protected.evidence);
        Ok(())
    }

    #[test]
    fn a_pack_path_that_escapes_the_repository_fails_the_gate() -> Result<()> {
        // Outside the repository, where a pack would parse if the loader followed the path.
        let outside = tempfile::tempdir_in("/var/tmp")?;
        let secret = outside.path().join("outside.toml");
        fs::write(&secret, SWALLOW_PACK)?;
        let absolute = secret.to_str().unwrap().to_string();
        for named in ["../outside.toml", "cowproof/../../outside.toml", &absolute] {
            let repo =
                TestRepo::new(&[("cowproof.toml", &format!("[proof]\npacks = [{named:?}]\n"))])?;
            repo.write("test.rs", OFFENDING)?;
            let patch = repo.patch()?;

            let result = check_flaws(repo.path(), &repo.base, &patch)?;
            assert!(!result.passed, "{named}: {:?}", result.evidence);
            assert!(
                result.evidence[0].contains("inside the repository"),
                "{named}: {:?}",
                result.evidence
            );
            // The outside pack's rule did not run.
            assert!(
                result
                    .evidence
                    .iter()
                    .all(|e| !e.contains("swallow-exceptions")),
                "{named}: {:?}",
                result.evidence
            );
        }
        Ok(())
    }

    #[test]
    fn a_pack_that_is_a_symlink_in_the_base_fails_the_gate() -> Result<()> {
        let outside = tempfile::tempdir_in("/var/tmp")?;
        let secret = outside.path().join("secret.toml");
        fs::write(&secret, "not = [toml\n")?;
        let repo = TestRepo::new(&[("cowproof.toml", TEST_PACK_CONFIG)])?;
        fs::create_dir_all(repo.path().join("cowproof"))?;
        std::os::unix::fs::symlink(&secret, repo.path().join(TEST_PACK))?;
        git(repo.path(), &["add", "-A"])?;
        git(repo.path(), &["commit", "-q", "-m", "link"])?;
        let base = git(repo.path(), &["rev-parse", "HEAD"])?.trim().to_string();

        let result = check_flaws(repo.path(), &base, &touching("test.rs"))?;
        assert!(!result.passed, "{:?}", result.evidence);
        assert!(
            result.evidence[0].contains("not a regular file"),
            "{:?}",
            result.evidence
        );
        // The target's text is not quoted into the evidence.
        assert!(!result.evidence[0].contains("not = [toml"));
        Ok(())
    }

    #[test]
    fn a_malformed_packs_value_is_an_error_not_no_packs() -> Result<()> {
        for text in ["[proof]\npacks = \"generic\"\n", "[proof]\npacks = [1]\n"] {
            let repo = TestRepo::new(&[("cowproof.toml", text)])?;
            repo.write("test.rs", "fn ok() {}\n")?;
            let err = check_flaws(repo.path(), &repo.base, &repo.patch()?).expect_err(text);
            assert!(
                format!("{err:#}").contains("list of strings"),
                "{text}: {err:#}"
            );
        }
        Ok(())
    }

    #[test]
    fn a_pack_in_the_working_tree_but_not_the_base_has_no_effect() -> Result<()> {
        // The patch adds a pack and names it in cowproof.toml; the base names none. The gate
        // reads the base, so the new pack's rule does not run and the patch is not judged by it.
        let repo = TestRepo::new(&[])?;
        repo.write("cowproof.toml", TEST_PACK_CONFIG)?;
        repo.write(TEST_PACK, SWALLOW_PACK)?;
        repo.write("test.rs", OFFENDING)?;
        let patch = repo.patch()?;
        let result = check_flaws(repo.path(), &repo.base, &patch)?;
        assert!(result.passed, "{:?}", result.evidence);
        // But the gate also refuses the patch's edit to cowproof.toml.
        let protected =
            check_protected_paths(repo.path(), &repo.base, &patch, &packet(&["test.rs"]))?;
        assert!(!protected.passed);
        assert!(protected.evidence[0].contains("cowproof.toml"));
        Ok(())
    }

    /// A base commit that names the generic pack and a migration baseline, with applied
    /// migrations `001`, `002` and `010`.
    fn migration_repo(baseline: &str) -> Result<TestRepo> {
        TestRepo::new(&[
            (
                "cowproof.toml",
                &format!("[proof]\npacks = [\"generic\"]\nmigration_baseline = \"{baseline}\"\n"),
            ),
            ("db/migrations/001_init.sql", "create table a (id int);\n"),
            ("db/migrations/002_more.sql", "create table b (id int);\n"),
            ("db/migrations/010_late.sql", "create table c (id int);\n"),
        ])
    }

    #[test]
    fn migration_baseline_is_read_from_the_base_cowproof_toml() -> Result<()> {
        let with = migration_repo("010_late.sql")?;
        assert_eq!(
            base_migration_baseline(with.path(), &with.base)?.as_deref(),
            Some("010_late.sql")
        );
        let without = TestRepo::new(&[("cowproof.toml", "[proof]\npacks = []\n")])?;
        assert_eq!(
            base_migration_baseline(without.path(), &without.base)?,
            None
        );
        let no_file = TestRepo::new(&[])?;
        assert_eq!(
            base_migration_baseline(no_file.path(), &no_file.base)?,
            None
        );
        // A baseline that is not a non-empty string is refused, never read as "none".
        for bad in ["migration_baseline = 10", "migration_baseline = \"\""] {
            let repo = TestRepo::new(&[("cowproof.toml", &format!("[proof]\n{bad}\n"))])?;
            let err = base_migration_baseline(repo.path(), &repo.base).unwrap_err();
            assert!(err.to_string().contains("migration_baseline"), "{err}");
        }
        Ok(())
    }

    #[test]
    fn flaws_gate_fails_a_patch_that_edits_an_applied_migration_naming_file_and_baseline()
    -> Result<()> {
        let repo = migration_repo("010_late.sql")?;
        repo.write(
            "db/migrations/002_more.sql",
            "create table b (id bigint);\n",
        )?;
        let patch = repo.patch()?;

        let report = run_gates(repo.path(), &repo.base, &patch, &packet(&["db/**"]))?;
        let flaws = gate(&report, "flaws");
        assert!(!flaws.passed, "{:?}", flaws.evidence);
        assert!(report.any_failed);
        let line = flaws
            .evidence
            .iter()
            .find(|e| e.contains("db/migrations/002_more.sql"))
            .unwrap_or_else(|| panic!("no finding names the file: {:?}", flaws.evidence));
        assert!(line.contains("010_late.sql"), "{line}");
        assert!(line.contains("baseline"), "{line}");
        Ok(())
    }

    #[test]
    fn flaws_gate_fails_a_patch_that_deletes_an_applied_migration() -> Result<()> {
        let repo = migration_repo("010_late.sql")?;
        repo.remove("db/migrations/001_init.sql")?;
        let patch = repo.patch()?;

        let result = check_flaws(repo.path(), &repo.base, &patch)?;
        assert!(!result.passed, "{:?}", result.evidence);
        assert!(
            result
                .evidence
                .iter()
                .any(|e| e.contains("db/migrations/001_init.sql") && e.contains("010_late.sql")),
            "{:?}",
            result.evidence
        );
        Ok(())
    }

    #[test]
    fn flaws_gate_passes_a_new_migration_after_the_baseline() -> Result<()> {
        let repo = migration_repo("010_late.sql")?;
        repo.write("db/migrations/011_new.sql", "create table d (id int);\n")?;
        let patch = repo.patch()?;

        let result = check_flaws(repo.path(), &repo.base, &patch)?;
        assert!(result.passed, "{:?}", result.evidence);
        assert!(!result.warned);
        // It still says the rule ran and against what, so the gate is not silent.
        assert!(
            result
                .evidence
                .iter()
                .any(|e| e.contains("checked against")
                    && e.contains("migration_baseline 010_late.sql")),
            "{:?}",
            result.evidence
        );
        Ok(())
    }

    #[test]
    fn flaws_gate_orders_migrations_by_number_not_by_string() -> Result<()> {
        // As strings "9_a.sql" sorts after "10_b.sql", which would let this edit through.
        let repo = TestRepo::new(&[
            (
                "cowproof.toml",
                "[proof]\npacks = [\"generic\"]\nmigration_baseline = \"10_b.sql\"\n",
            ),
            ("db/migrations/9_a.sql", "select 1;\n"),
            ("db/migrations/10_b.sql", "select 2;\n"),
        ])?;
        repo.write("db/migrations/9_a.sql", "select 3;\n")?;
        let patch = repo.patch()?;
        let result = check_flaws(repo.path(), &repo.base, &patch)?;
        assert!(!result.passed, "{:?}", result.evidence);
        assert!(
            result
                .evidence
                .iter()
                .any(|e| e.contains("db/migrations/9_a.sql"))
        );
        Ok(())
    }

    #[test]
    fn flaws_gate_says_the_migration_rule_was_skipped_when_the_base_has_no_baseline() -> Result<()>
    {
        let repo = TestRepo::with_config(&["generic"])?;
        repo.write("db/migrations/001_init.sql", "select 1;\n")?;
        let patch = repo.patch()?;

        let result = check_flaws(repo.path(), &repo.base, &patch)?;
        assert!(result.passed, "{:?}", result.evidence);
        assert!(
            result.warned,
            "a skipped rule is a warning, not a silent pass"
        );
        assert!(
            result
                .evidence
                .iter()
                .any(|e| e.contains("applied_migration rules skipped")
                    && e.contains("db/migrations/001_init.sql")
                    && e.contains("migration_baseline")),
            "{:?}",
            result.evidence
        );
        // A pack with no migration rule says nothing about migrations.
        let quiet = TestRepo::new(&named_pack(SWALLOW_PACK))?;
        quiet.write("test.rs", "fn ok() {}\n")?;
        let result = check_flaws(quiet.path(), &quiet.base, &quiet.patch()?)?;
        assert!(result.evidence.is_empty() && !result.warned);
        Ok(())
    }

    #[test]
    fn no_baseline_and_no_migration_in_the_patch_passes_without_a_warning() -> Result<()> {
        // The generic pack's migration rule matches every path (`**/*`), but the patch
        // touches no file under a `migrations/` directory, so there is nothing to warn about.
        let repo = TestRepo::with_config(&["generic"])?;
        repo.write("src/lib.rs", "fn ok() {}\n")?;
        repo.write("docs/migrations.md", "notes\n")?;
        let patch = repo.patch()?;

        let result = check_flaws(repo.path(), &repo.base, &patch)?;
        assert!(result.passed, "{:?}", result.evidence);
        assert!(!result.warned, "{:?}", result.evidence);
        assert!(result.evidence.is_empty(), "{:?}", result.evidence);
        // And through the whole gate run.
        let report = run_gates(
            repo.path(),
            &repo.base,
            &patch,
            &packet(&["src/**", "docs/**"]),
        )?;
        let flaws = gate(&report, "flaws");
        assert!(flaws.passed && !flaws.warned && flaws.evidence.is_empty());
        Ok(())
    }

    #[test]
    fn a_patch_cannot_move_the_baseline_and_is_flagged_for_trying() -> Result<()> {
        // The patch edits applied migration 002 and rewrites the baseline in cowproof.toml
        // to one before it. The gate still uses the base's baseline, and the protected
        // path gate flags the cowproof.toml edit.
        let repo = migration_repo("010_late.sql")?;
        repo.write(
            "db/migrations/002_more.sql",
            "create table b (id bigint);\n",
        )?;
        repo.write(
            "cowproof.toml",
            "[proof]\npacks = [\"generic\"]\nmigration_baseline = \"001_init.sql\"\n",
        )?;
        let patch = repo.patch()?;

        let report = run_gates(
            repo.path(),
            &repo.base,
            &patch,
            &packet(&["db/**", "cowproof.toml"]),
        )?;
        let flaws = gate(&report, "flaws");
        assert!(
            !flaws.passed,
            "the patched baseline was used: {:?}",
            flaws.evidence
        );
        assert!(flaws.evidence.iter().any(|e| e.contains("010_late.sql")));
        assert!(!flaws.evidence.iter().any(|e| e.contains("001_init.sql ")));
        // Owned, so the protected gate passes but warns that the harness changed.
        let protected = gate(&report, "protected_paths");
        assert!(protected.warned, "{:?}", protected.evidence);
        assert!(
            protected
                .evidence
                .iter()
                .any(|e| e.contains("cowproof.toml"))
        );
        // Not owned: it fails.
        let report = run_gates(repo.path(), &repo.base, &patch, &packet(&["db/**"]))?;
        let protected = gate(&report, "protected_paths");
        assert!(!protected.passed);
        assert!(protected.evidence[0].contains("cowproof.toml"));
        Ok(())
    }

    #[test]
    fn a_baseline_added_only_by_the_patch_does_not_enable_the_rule() -> Result<()> {
        let repo = TestRepo::with_config(&["generic"])?;
        repo.write("db/migrations/001_init.sql", "select 1;\n")?;
        repo.write(
            "cowproof.toml",
            "[proof]\npacks = [\"generic\"]\nmigration_baseline = \"001_init.sql\"\n",
        )?;
        let patch = repo.patch()?;
        let result = check_flaws(repo.path(), &repo.base, &patch)?;
        assert!(result.warned, "{:?}", result.evidence);
        assert!(
            result.evidence.iter().any(|e| e.contains("skipped")),
            "{:?}",
            result.evidence
        );
        Ok(())
    }

    #[test]
    fn run_gates_rejects_a_base_that_is_not_a_commit() -> Result<()> {
        let repo = TestRepo::new(&named_pack(SWALLOW_PACK))?;
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

    #[test]
    fn generic_pack_loads_when_named() -> Result<()> {
        let repo = TestRepo::with_config(&["generic"])?;
        // Generic pack has #[ignore] rule, not USING(true)
        repo.write("test.rs", "#[ignore]\nfn test() {}")?;
        let patch = repo.patch()?;

        let report = run_gates(repo.path(), "HEAD", &patch, &packet(&["test.rs"]))?;
        let flaws_gate = gate(&report, "flaws");
        assert!(!flaws_gate.passed, "generic pack should catch #[ignore]");
        Ok(())
    }

    #[test]
    fn stack_specific_rules_not_in_generic() -> Result<()> {
        let repo = TestRepo::with_config(&["generic"])?;
        // USING(true) is Postgres-specific, not in generic pack
        repo.write("policy.sql", "POLICY x AS (USING (true))")?;
        let patch = repo.patch()?;

        let report = run_gates(repo.path(), "HEAD", &patch, &packet(&["policy.sql"]))?;
        let flaws = gate(&report, "flaws");
        // Should pass because USING(true) is not in generic pack
        assert!(
            flaws.passed,
            "USING(true) should not be in generic pack: {:?}",
            flaws.evidence
        );
        Ok(())
    }

    #[test]
    fn unknown_pack_name_fails_the_gate() -> Result<()> {
        let repo = TestRepo::with_config(&["nope"])?;
        repo.write("test.rs", "fn foo() {}")?;
        let patch = repo.patch()?;

        let report = run_gates(repo.path(), "HEAD", &patch, &packet(&["test.rs"]))?;
        let flaws = gate(&report, "flaws");
        assert!(
            !flaws.passed,
            "unknown pack should fail the gate: {:?}",
            flaws.evidence
        );
        assert!(
            flaws
                .evidence
                .iter()
                .any(|e| e.contains("nope") && e.contains("missing from the base")),
            "should report pack as missing: {:?}",
            flaws.evidence
        );
        Ok(())
    }

    #[test]
    fn an_empty_packs_list_still_runs_the_generic_pack() -> Result<()> {
        let repo = TestRepo::with_config(&[])?;
        repo.write("test.rs", "#[ignore]fn ok() {}")?;
        let patch = repo.patch()?;

        let report = run_gates(repo.path(), "HEAD", &patch, &packet(&["test.rs"]))?;
        let flaws = gate(&report, "flaws");
        // The generic pack is not optional: an empty list does not switch it off.
        assert!(!flaws.passed, "{:?}", flaws.evidence);
        assert!(
            flaws
                .evidence
                .iter()
                .any(|e| e.contains("An ignored Rust test")),
            "{:?}",
            flaws.evidence
        );
        Ok(())
    }

    #[test]
    fn removed_lines_agrees_with_parse_patch() -> Result<()> {
        let tmpdir = tempfile::TempDir::new()?;
        let repo = tmpdir.path();

        // Initialize repo with two files
        git(repo, &["init", "-q"])?;
        git(repo, &["config", "user.email", "test@test.local"])?;
        git(repo, &["config", "user.name", "Test"])?;
        std::fs::write(repo.join("file1.txt"), "line1\nline2\nline3\n")?;
        std::fs::write(repo.join("file2.txt"), "alpha\nbeta\ngamma\n")?;
        git(repo, &["add", "-A"])?;
        git(repo, &["commit", "-q", "-m", "base"])?;

        // Modify both files: remove a line from each
        std::fs::write(repo.join("file1.txt"), "line1\nline3\n")?; // removed line2
        std::fs::write(repo.join("file2.txt"), "alpha\ngamma\n")?; // removed beta

        // Generate diff
        git(repo, &["add", "-A"])?;
        let patch = git(
            repo,
            &[
                "-c",
                "diff.noprefix=false",
                "-c",
                "diff.mnemonicPrefix=false",
                "diff",
                "--cached",
                "--no-color",
                "--no-ext-diff",
            ],
        )?;

        // Check agreement
        let deltas = parse_patch(&patch);
        assert_eq!(
            removed_lines(&patch, "file1.txt"),
            deltas
                .iter()
                .find(|d| d.path == "file1.txt")
                .map(|d| d.removed.len())
                .unwrap_or(0),
            "removed_lines should match parse_patch for file1.txt"
        );
        assert_eq!(
            removed_lines(&patch, "file2.txt"),
            deltas
                .iter()
                .find(|d| d.path == "file2.txt")
                .map(|d| d.removed.len())
                .unwrap_or(0),
            "removed_lines should match parse_patch for file2.txt"
        );
        Ok(())
    }
}
