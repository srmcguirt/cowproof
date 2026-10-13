use crate::capsule::{
    Capsule, CapsuleError, CheckResult, HELDOUT_FILE, VerifierRun, read_packet_versions,
};
use crate::port::{PortOutcome, PortRun, run_port};
use crate::runner::{CheckRunner, acquire_slot};
use cowproof_core::{MAX_CHECK_TIMEOUT, MIN_CHECK_TIMEOUT, get_slot_dir, parse_header};
use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::process::Command;

/// How `verify` holds the machine's class slots and bounds its checks.
pub struct VerifyOptions {
    /// Directory holding the machine-wide slots, shared with the builders.
    pub slot_dir: PathBuf,
    /// The class of the lane being verified (`rust`, `pg`, `light`). The verifier holds a
    /// slot of this class while it runs (D12): its own, or the one in `held_slot_path`.
    pub slot_class: String,
    /// The class's limit.
    pub slot_limit: usize,
    /// The time limit of a check whose capsule record carries none (a capsule from before
    /// the limit was recorded), of the held-out checks and of the port replay. A check whose
    /// record has `timeout_ms` is replayed under that limit instead.
    pub default_timeout: Duration,
    /// The directory of a slot of `slot_class` the caller already holds and keeps holding
    /// until `verify` returns. The verifier then acquires none. `cowproof run` sets it to
    /// the builder's slot, so the verifier never waits on a slot its own run holds.
    pub held_slot_path: Option<PathBuf>,
    /// Replay a capsule marked `unsandboxed` instead of refusing it. Only `cowproof run`
    /// sets it, to check a lane it just built with `--unsandboxed` before the lane can end
    /// `finished` (the replay itself is sandboxed as always). It is false by default, so
    /// `cowproof verify` refuses such a capsule: one from a builder that ran unconfined is
    /// not a proof to hand to someone else.
    pub allow_unsandboxed: bool,
    /// The `cowproof` executable whose `pk port replay` the verifier runs for a `kind: port`
    /// capsule. `None` is the running executable (`std::env::current_exe`). It must be
    /// reachable inside the verifier's sandbox (`SandboxedRunner::with_executable`).
    pub pk_exe: Option<PathBuf>,
    /// The runtime directories the caller granted the runner (`--runtime-dir`), as text. The
    /// capsule records the ones its proof had; a held-out skip names those the caller lacks.
    pub runtime_dirs: Vec<String>,
}

impl Default for VerifyOptions {
    /// The machine-wide slot directory, the `rust` class at its usual limit of two, and
    /// a 20 minute limit per check. No held slot is assumed (standalone verify).
    fn default() -> Self {
        Self {
            slot_dir: get_slot_dir(),
            slot_class: "rust".to_string(),
            slot_limit: 2,
            default_timeout: Duration::from_secs(20 * 60),
            held_slot_path: None,
            allow_unsandboxed: false,
            pk_exe: None,
            runtime_dirs: Vec::new(),
        }
    }
}

#[derive(Error, Debug)]
pub enum VerifyError {
    #[error("Infrastructure error during verification: {0}")]
    Infrastructure(String),

    #[error("Verification failed: capsule is marked unsandboxed and cannot be proved")]
    UnsandboxedNotProved,

    #[error("Capsule rejected: {0}")]
    Capsule(#[from] CapsuleError),

    /// A check's recorded time limit is not the one the packet header declares, or is out of
    /// range. The header is what was proved, so the capsule is refused before anything runs.
    #[error("Capsule refused: {0}")]
    CheckLimitMismatch(String),
}

#[derive(Debug, Clone)]
pub struct CheckMatch {
    pub check_id: String,
    pub passed: bool,
    pub matched_capsule: bool,
    pub capsule_exit_status: i32,
    pub actual_exit_status: i32,
    /// This replay's own run of the check (the last attempt, for a flaky check). `cowproof run`
    /// writes it into the capsule beside the builder's record; `cowproof verify` writes nothing.
    pub run: VerifierRun,
    /// The builder's recorded output hash, when the capsule has one (empty for a capsule from
    /// before runs were recorded).
    pub builder_output_sha256: String,
}

impl CheckMatch {
    /// A note, never a failure: this replay's output is not byte-identical to the builder's.
    /// `None` when the hashes agree or the capsule recorded no builder hash to compare with.
    /// Outputs legitimately differ between runs (a timestamp, a path, a test order), and only
    /// pass or fail decides the verdict.
    pub fn output_note(&self) -> Option<String> {
        if self.builder_output_sha256.is_empty()
            || self.builder_output_sha256 == self.run.output_sha256
        {
            return None;
        }
        Some(format!(
            "check {:?}: the verifier's output is not byte-identical to the builder's (builder \
             sha256 {}, verifier sha256 {}); only pass or fail was compared",
            self.check_id,
            short_hash(&self.builder_output_sha256),
            short_hash(&self.run.output_sha256),
        ))
    }
}

fn short_hash(hash: &str) -> &str {
    hash.get(..12).unwrap_or(hash)
}

/// A held-out check run on the rebuilt tree. It has no recorded result to match: it
/// passes or it fails.
#[derive(Debug, Clone)]
pub struct HeldOutOutcome {
    pub check_id: String,
    pub passed: bool,
}

#[derive(Debug)]
pub enum VerifyResult {
    /// Every recorded check matched and every held-out check passed.
    Reproduced,
    /// A recorded check's pass or fail differs from the capsule's.
    Diverged { check_ids: Vec<String> },
    /// Every recorded check matched, but a held-out check failed on the rebuilt tree.
    HeldOutFailed { check_ids: Vec<String> },
    /// Checks and held-out checks passed, but the `port_replay` gate of a `kind: port` capsule
    /// failed: a fixture differs, a tool is not ported, a base fixture was altered, an accepted
    /// difference has no ruling, or a held-out port case failed. One line each.
    PortFailed { failures: Vec<String> },
}

#[derive(Debug)]
pub struct VerifyReport {
    pub result: VerifyResult,
    pub checks: Vec<CheckMatch>,
    /// The held-out checks, in file order. Empty when the capsule holds none. Filled
    /// even when a recorded check diverged, so a refutation names every failure.
    pub heldout: Vec<HeldOutOutcome>,
    /// What the replay of a `kind: port` capsule found. `None` for every other capsule.
    pub port: Option<PortOutcome>,
}

const FLAKY_ATTEMPTS: u32 = 3;

/// Verify a capsule by rebuilding the tree from `source_repo` and re-running checks.
///
/// Before it builds anything, `verify` holds a slot of `opts.slot_class` until it returns,
/// on every path: success, divergence, error or check timeout (D12). It waits for one, unless
/// `opts.held_slot_path` names a slot the caller already holds.
/// A capsule marked `unsandboxed` is refused (`VerifyError::UnsandboxedNotProved`) before
/// anything is built, unless `opts.allow_unsandboxed` is set.
/// Every check runs under the time limit its record carries (`CheckResult::timeout_ms`), else
/// under `opts.default_timeout`; one that overruns is an infrastructure error naming the
/// check, never a divergence. Before anything is built, a recorded limit that differs from
/// the one the capsule's last packet header declares for that check is refused
/// (`VerifyError::CheckLimitMismatch`): the header is what was proved.
///
/// The tree is always built the same way, into `workdir/tree` (which must not exist):
/// 1. Clone `source_repo` and check out the capsule's base commit (its tree hash must
///    match the capsule's `base_tree_hash`).
/// 2. Apply `base.patch` (when present and non-empty).
/// 3. Replay the launch baseline by deleting the paths in `capsule.launch_removed` (D13/R10).
/// 4. Apply `lane.patch`.
/// 5. Run each recorded check's command through the `CheckRunner`. The checks are the
///    sealed `checks/<id>.json` files named in `capsule.json`; a file the seal does not
///    list is refused by `Capsule::read` before this point, never run.
/// 6. Compare pass or fail per check id; durations and output hashes are never compared. Each
///    check's own run (exit, duration, output hash and length) comes back in its `CheckMatch`,
///    and `CheckMatch::output_note` says when its output differs from the builder's.
/// 7. Run the held-out checks in `packets/heldout.toml` (when the capsule has one) on the
///    same tree, after the recorded checks. They have no recorded result: one that fails
///    refutes the lane (`HeldOutFailed`), naming the check. A held-out file that cannot be
///    read is an infrastructure error.
///
/// Checks marked flaky in the capsule are retried up to three times. Any failure to
/// rebuild the tree, apply a patch, replay the baseline or run a check is `VerifyError::Infrastructure`,
/// never a divergence (F-1).
pub async fn verify(
    capsule_dir: &Path,
    source_repo: &Path,
    workdir: &Path,
    runner: &dyn CheckRunner,
    opts: VerifyOptions,
) -> Result<VerifyReport, VerifyError> {
    let capsule = Capsule::read(capsule_dir)?;

    if capsule.unsandboxed && !opts.allow_unsandboxed {
        return Err(VerifyError::UnsandboxedNotProved);
    }

    // A caller that already holds a slot of the lane's class (`cowproof run` holds the
    // builder's; `cowproof verify` takes its own before it builds the runner, which needs
    // the slot's port block) says so in `held_slot_path`, and the verifier takes no
    // second one: at a limit of one it would wait forever on itself. Otherwise it waits
    // for a slot here and holds it until it returns (D12).
    let _slot = match &opts.held_slot_path {
        Some(held) => {
            if !held.is_dir() {
                return Err(infra(format!(
                    "the slot the caller says it holds is gone: {}",
                    held.display()
                )));
            }
            None
        }
        None => Some(
            acquire_slot(&opts.slot_class, opts.slot_limit, &opts.slot_dir)
                .await
                .map_err(|e| infra(format!("could not acquire a {} slot: {e}", opts.slot_class)))?,
        ),
    };

    let recorded = load_checks(capsule_dir, &capsule)?;
    refuse_limit_mismatch(capsule_dir, &recorded)?;

    let tree = workdir.join("tree");
    if tree.exists() {
        return Err(infra(format!(
            "refusing to reuse existing tree at {}",
            tree.display()
        )));
    }
    std::fs::create_dir_all(workdir).map_err(|e| infra(format!("workdir: {e}")))?;
    clone_at_commit(source_repo, &capsule.base_commit, &tree).await?;

    let actual_tree_hash = git(&tree, &["rev-parse", "HEAD^{tree}"]).await?;
    if actual_tree_hash.trim() != capsule.base_tree_hash {
        return Err(infra(format!(
            "base tree hash mismatch: capsule has {}, rebuilt tree has {}",
            capsule.base_tree_hash,
            actual_tree_hash.trim()
        )));
    }

    // The builder's lane started from base.patch, then the launch baseline; lane.patch
    // is computed against that, so this is the only order it applies in.
    apply_patch_file(&tree, &capsule_dir.join("base.patch"), "base.patch").await?;
    replay_launch_baseline(&tree, &capsule.launch_removed).await?;
    apply_patch_file(&tree, &capsule_dir.join("lane.patch"), "lane.patch").await?;

    let mut check_matches = Vec::new();
    let mut diverged_ids = Vec::new();

    for (check_id, check) in recorded {
        let max_attempts = if capsule.flaky_checks.contains(&check_id) {
            FLAKY_ATTEMPTS
        } else {
            1
        };

        let limit = check
            .timeout_ms
            .map_or(opts.default_timeout, Duration::from_millis);
        let mut actual_exit = -1;
        let mut run = None;
        for _ in 0..max_attempts {
            let started = Instant::now();
            let outcome = runner
                .run(&tree, &check.command, limit)
                .await
                .map_err(|e| infra(format!("check {check_id}: {e}")))?;
            run = Some(VerifierRun {
                exit_status: outcome.exit_status,
                end: outcome.end,
                duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                output_sha256: Capsule::hash_bytes(outcome.output.as_bytes()),
                output_len: outcome.output.len() as u64,
            });
            actual_exit = outcome.exit_status;
            if actual_exit == 0 {
                break;
            }
        }
        let run = run.ok_or_else(|| infra(format!("check {check_id}: no attempt was made")))?;

        let matched = (check.exit_status == 0) == (actual_exit == 0);
        if !matched {
            diverged_ids.push(check_id.clone());
        }

        check_matches.push(CheckMatch {
            check_id,
            passed: actual_exit == 0,
            matched_capsule: matched,
            capsule_exit_status: check.exit_status,
            actual_exit_status: actual_exit,
            run,
            builder_output_sha256: check.output_sha256.clone(),
        });
    }

    let heldout_file = load_heldout(capsule_dir)?;
    let mut heldout_outcomes = Vec::new();
    for check in heldout_file.check.iter().cloned() {
        let outcome = runner
            .run(&tree, &check.command, opts.default_timeout)
            .await
            .map_err(|e| infra(format!("held-out check {}: {e}", check.id)))?;
        heldout_outcomes.push(HeldOutOutcome {
            check_id: check.id,
            passed: outcome.exit_status == 0,
        });
    }
    let heldout_failed: Vec<String> = heldout_outcomes
        .iter()
        .filter(|o| !o.passed)
        .map(|o| o.check_id.clone())
        .collect();

    // A port capsule: portkit's replay of the fixtures and of the director's held-out cases,
    // after the checks, in the same tree.
    let port = match &capsule.port {
        None => None,
        Some(spec) => {
            let pk_exe = match &opts.pk_exe {
                Some(exe) => exe.clone(),
                None => std::env::current_exe()
                    .map_err(|e| infra(format!("cannot find the cowproof executable: {e}")))?,
            };
            Some(
                run_port(PortRun {
                    capsule_dir,
                    capsule: &capsule,
                    spec,
                    heldout: &heldout_file,
                    tree: &tree,
                    workdir,
                    pk_exe: &pk_exe,
                    runner,
                    timeout: opts.default_timeout,
                    runtime_dirs: &opts.runtime_dirs,
                })
                .await?,
            )
        }
    };

    let result = if !diverged_ids.is_empty() {
        VerifyResult::Diverged {
            check_ids: diverged_ids,
        }
    } else if !heldout_failed.is_empty() {
        VerifyResult::HeldOutFailed {
            check_ids: heldout_failed,
        }
    } else if let Some(port) = port.as_ref().filter(|p| !p.passed()) {
        VerifyResult::PortFailed {
            failures: port.result.failures.clone(),
        }
    } else {
        VerifyResult::Reproduced
    };

    Ok(VerifyReport {
        result,
        checks: check_matches,
        heldout: heldout_outcomes,
        port,
    })
}

pub(crate) fn infra(msg: String) -> VerifyError {
    VerifyError::Infrastructure(msg)
}

/// The recorded checks, taken from the sealed list and never from the directory: a
/// check is `checks/<id>.json` for each such key of `capsule.file_hashes`. `Capsule::read`
/// has already hashed every one of those files and refused any other file in `checks/`, so
/// a check that is loaded here is a check that was sealed. A key that would name a path
/// outside `checks/` is refused.
pub(crate) fn load_checks(
    capsule_dir: &Path,
    capsule: &Capsule,
) -> Result<BTreeMap<String, CheckResult>, VerifyError> {
    let mut checks = BTreeMap::new();
    for key in capsule.file_hashes.keys() {
        let Some(file) = key.strip_prefix("checks/") else {
            continue;
        };
        let Some(id) = file.strip_suffix(".json") else {
            continue;
        };
        if id.is_empty() || id.contains('/') {
            return Err(infra(format!("{key}: not a valid check file name")));
        }
        let content = std::fs::read_to_string(capsule_dir.join(key))
            .map_err(|e| infra(format!("checks/{id}.json: {e}")))?;
        let check: CheckResult =
            serde_json::from_str(&content).map_err(|e| infra(format!("checks/{id}.json: {e}")))?;
        checks.insert(id.to_string(), check);
    }
    Ok(checks)
}

/// Refuse a capsule whose recorded check limits are not the ones the packet header declares.
///
/// A recorded `timeout_ms` must lie between the shortest and the longest limit a header may
/// declare. For each check the last packet version (the one the lane was proved against)
/// declares a limit for, the record must carry exactly that limit: a record with another limit
/// or none is refused. A check with no declared limit may record whatever default the builder's
/// runner used. A capsule with no packet versions (from before they were written), or whose
/// last version holds no readable header, has nothing to compare and is left to the other checks.
fn refuse_limit_mismatch(
    capsule_dir: &Path,
    recorded: &BTreeMap<String, CheckResult>,
) -> Result<(), VerifyError> {
    for (id, check) in recorded {
        if let Some(ms) = check.timeout_ms
            && !(MIN_CHECK_TIMEOUT.as_millis()..=MAX_CHECK_TIMEOUT.as_millis())
                .contains(&u128::from(ms))
        {
            return Err(VerifyError::CheckLimitMismatch(format!(
                "check {id:?}: the recorded time limit of {ms} ms is outside the allowed range of 1 s to 6 h"
            )));
        }
    }
    let versions = read_packet_versions(capsule_dir)?;
    let Some((version, text)) = versions.last() else {
        return Ok(());
    };
    let Ok(header) = parse_header(text) else {
        return Ok(());
    };
    for declared in &header.checks {
        let limit = declared.time_limit().map_err(|why| {
            VerifyError::CheckLimitMismatch(format!(
                "check {:?}: the packet header ({}) has an invalid timeout: {why}",
                declared.id, version.file
            ))
        })?;
        let (Some(limit), Some(check)) = (limit, recorded.get(&declared.id)) else {
            continue;
        };
        let want = u64::try_from(limit.as_millis()).unwrap_or(u64::MAX);
        if check.timeout_ms != Some(want) {
            let had = check
                .timeout_ms
                .map_or_else(|| "none".to_string(), |ms| format!("{ms} ms"));
            return Err(VerifyError::CheckLimitMismatch(format!(
                "check {:?}: the capsule recorded a time limit of {had}, but the packet header \
                 ({}) declares {want} ms; the header is what was proved",
                declared.id, version.file
            )));
        }
    }
    Ok(())
}

/// The held-out file the capsule carries (its checks in file order, and the `[port]` table);
/// empty when it has no `packets/heldout.toml`. The file is hashed, so `Capsule::read` has
/// already proved it is the one the lane was gated on.
fn load_heldout(capsule_dir: &Path) -> Result<cowproof_core::heldout::HeldOut, VerifyError> {
    let path = capsule_dir.join(HELDOUT_FILE);
    if !path.exists() {
        return Ok(cowproof_core::heldout::HeldOut::default());
    }
    cowproof_core::heldout::load(&path).map_err(|e| infra(format!("{HELDOUT_FILE}: {e:#}")))
}

pub(crate) async fn git(dir: &Path, args: &[&str]) -> Result<String, VerifyError> {
    let output = Command::new("git")
        .args(["-c", "core.hooksPath=/dev/null", "-C"])
        .arg(dir)
        .args(args)
        .output()
        .await
        .map_err(|e| infra(format!("failed to run git: {e}")))?;
    if !output.status.success() {
        return Err(infra(format!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

async fn clone_at_commit(
    source_repo: &Path,
    commit: &str,
    target: &Path,
) -> Result<(), VerifyError> {
    let output = Command::new("git")
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "clone",
            "--quiet",
            "--no-checkout",
            "--",
        ])
        .arg(source_repo)
        .arg(target)
        .output()
        .await
        .map_err(|e| infra(format!("failed to run git clone: {e}")))?;
    if !output.status.success() {
        return Err(infra(format!(
            "git clone of {} failed: {}",
            source_repo.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    git(target, &["checkout", "--quiet", "--detach", commit]).await?;
    Ok(())
}

async fn apply_patch_file(tree: &Path, patch: &Path, name: &str) -> Result<(), VerifyError> {
    if !patch.exists() {
        return Ok(());
    }
    let content = std::fs::read(patch).map_err(|e| infra(format!("{name}: {e}")))?;
    if content.iter().all(u8::is_ascii_whitespace) {
        return Ok(());
    }
    let output = Command::new("git")
        .args(["-c", "core.hooksPath=/dev/null", "-C"])
        .arg(tree)
        .arg("apply")
        .arg(patch)
        .output()
        .await
        .map_err(|e| infra(format!("{name}: failed to run git apply: {e}")))?;
    if !output.status.success() {
        return Err(infra(format!(
            "{name} did not apply: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}

/// Replay the launch baseline (D13/R10): delete exactly the capsule's `launch_removed`
/// paths from the rebuilt tree, then commit, so `lane.patch` applies on the same
/// tree the builder started from.
///
/// The list comes from the capsule, which is untrusted input, and this deletes files, so
/// every path is validated against the tree before any is deleted; one bad path means
/// nothing is deleted. A path is accepted only when it is relative, has no empty, `.`,
/// `..` or `.git` component, passes through no symlink, and ends in an existing file or
/// symlink. Deletion unlinks; it never follows a symlink.
async fn replay_launch_baseline(tree: &Path, removed_paths: &[String]) -> Result<(), VerifyError> {
    remove_launch_paths(tree, removed_paths)?;
    git(tree, &["add", "-A"])
        .await
        .map_err(|e| infra(format!("launch baseline: {e}")))?;
    git(
        tree,
        &[
            "-c",
            "user.name=cowproof",
            "-c",
            "user.email=cowproof@localhost",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-q",
            "--allow-empty",
            "--no-verify",
            "-m",
            "cowproof: replay launch baseline",
        ],
    )
    .await
    .map_err(|e| infra(format!("launch baseline: {e}")))?;
    Ok(())
}

/// Validate every path, then delete them all. Never deletes anything unless all pass.
/// Remove the launch baseline paths: delete exactly the paths in `removed_paths` from the
/// tree, validating each before any is deleted.
///
/// The list comes from the capsule (untrusted input), and this deletes files, so every
/// path is validated first; one bad path means nothing is deleted. A path is accepted
/// only when it is relative, has no empty, `.`, `..` or `.git` component, passes through
/// no symlink, and ends in an existing file or symlink. Deletion unlinks; it never
/// follows a symlink at the end of the path.
pub fn remove_launch_paths(tree: &Path, removed_paths: &[String]) -> Result<(), VerifyError> {
    let mut seen = HashSet::new();
    let mut targets = Vec::new();
    for rel in removed_paths {
        if !seen.insert(rel.as_str()) {
            return Err(infra(format!("launch baseline: duplicate path: {rel}")));
        }
        targets.push(validate_launch_path(tree, rel)?);
    }
    for (rel, path) in removed_paths.iter().zip(&targets) {
        // `remove_file` unlinks a symlink itself and never follows it.
        std::fs::remove_file(path)
            .map_err(|e| infra(format!("launch baseline: cannot remove {rel}: {e}")))?;
        // Leave no empty directory behind, as the lane did (git does not track them).
        let mut parent = path.parent();
        while let Some(dir) = parent {
            if dir == tree || std::fs::remove_dir(dir).is_err() {
                break;
            }
            parent = dir.parent();
        }
    }
    Ok(())
}

/// The full path of `rel` inside `tree`, or an infrastructure error naming `rel`.
fn validate_launch_path(tree: &Path, rel: &str) -> Result<PathBuf, VerifyError> {
    let refuse = |why: &str| infra(format!("launch baseline: {why}: {rel}"));
    let components: Vec<&str> = rel.split('/').collect();
    if components[0].is_empty() && components.len() > 1 {
        return Err(refuse("absolute path not allowed"));
    }
    for c in &components {
        match *c {
            "" => return Err(refuse("empty path component")),
            "." | ".." => return Err(refuse("`.` or `..` component not allowed")),
            _ if c.eq_ignore_ascii_case(".git") => {
                return Err(refuse("`.git` component not allowed"));
            }
            _ if c.contains('\0') => return Err(refuse("NUL in path")),
            _ => {}
        }
    }
    let mut current = tree.to_path_buf();
    for (i, c) in components.iter().enumerate() {
        current.push(c);
        let md = match std::fs::symlink_metadata(&current) {
            Ok(md) => md,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(refuse("path does not exist"));
            }
            Err(e) => return Err(refuse(&format!("cannot inspect ({e})"))),
        };
        let last = i + 1 == components.len();
        if last {
            // A file or a symlink (the lane removes both); never a directory.
            if md.is_dir() {
                return Err(refuse("a directory is not a recorded removal"));
            }
        } else if md.file_type().is_symlink() {
            return Err(refuse("path passes through a symlink"));
        } else if !md.is_dir() {
            return Err(refuse("path passes through a non-directory"));
        }
    }
    Ok(current)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cowproof_run::tools::CheckEnd;

    fn matched(builder: &str, verifier: &str) -> CheckMatch {
        CheckMatch {
            check_id: "unit".to_string(),
            passed: true,
            matched_capsule: true,
            capsule_exit_status: 0,
            actual_exit_status: 0,
            run: VerifierRun {
                exit_status: 0,
                end: CheckEnd::Exited { code: 0 },
                duration_ms: 5,
                output_sha256: verifier.to_string(),
                output_len: 1,
            },
            builder_output_sha256: builder.to_string(),
        }
    }

    #[test]
    fn the_output_note_names_a_check_whose_hashes_differ() {
        let note = matched(&"a".repeat(64), &"b".repeat(64))
            .output_note()
            .expect("different hashes are noted");
        assert!(note.contains("\"unit\""), "{note}");
        assert!(note.contains("not byte-identical"), "{note}");
        assert!(
            note.contains(&"a".repeat(12)) && note.contains(&"b".repeat(12)),
            "{note}"
        );
    }

    #[test]
    fn there_is_no_output_note_for_equal_hashes_or_a_builder_without_one() {
        assert_eq!(
            matched(&"a".repeat(64), &"a".repeat(64)).output_note(),
            None
        );
        // A capsule from before runs were recorded has an empty builder hash: nothing to compare.
        assert_eq!(matched("", &"b".repeat(64)).output_note(), None);
    }

    #[test]
    fn a_launch_removed_symlink_is_unlinked_and_its_target_is_left_alone() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join("AGENTS.md"), "rules").unwrap();
        std::os::unix::fs::symlink("AGENTS.md", dir.path().join("CLAUDE.md")).unwrap();
        remove_launch_paths(dir.path(), &["CLAUDE.md".to_string()]).unwrap();
        assert!(std::fs::symlink_metadata(dir.path().join("CLAUDE.md")).is_err());
        assert_eq!(
            std::fs::read_to_string(dir.path().join("AGENTS.md")).unwrap(),
            "rules"
        );
    }

    #[test]
    fn a_path_through_a_symlinked_directory_is_still_refused() {
        let dir = tempfile::TempDir::new().unwrap();
        let outside = tempfile::TempDir::new().unwrap();
        std::fs::write(outside.path().join("CLAUDE.md"), "precious").unwrap();
        std::os::unix::fs::symlink(outside.path(), dir.path().join("sub")).unwrap();
        let err = remove_launch_paths(dir.path(), &["sub/CLAUDE.md".to_string()]).unwrap_err();
        assert!(
            err.to_string().contains("path passes through a symlink"),
            "{err}"
        );
        assert_eq!(
            std::fs::read_to_string(outside.path().join("CLAUDE.md")).unwrap(),
            "precious"
        );
    }
}
