use crate::capsule::{Capsule, CapsuleError, CheckResult};
use crate::runner::{CheckRunner, acquire_slot};
use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::Duration;
use thiserror::Error;
use tokio::process::Command;

/// How `verify` holds the machine's class slots and bounds its checks.
pub struct VerifyOptions {
    /// Directory holding the machine-wide slots, shared with the builders.
    pub slot_dir: PathBuf,
    /// The class of the lane being verified (`rust`, `pg`, `light`). The verifier takes a
    /// slot of this class after the builder has released its own (D12).
    pub slot_class: String,
    /// The class's limit.
    pub slot_limit: usize,
    /// Per-check time limit. A recorded check carries no limit of its own yet, so this
    /// applies to every check.
    pub default_timeout: Duration,
}

impl Default for VerifyOptions {
    /// The machine-wide slot directory, the `rust` class at its usual limit of two, and
    /// a 20 minute limit per check.
    fn default() -> Self {
        Self {
            slot_dir: PathBuf::from(cowproof_core::SLOT_DIR),
            slot_class: "rust".to_string(),
            slot_limit: 2,
            default_timeout: Duration::from_secs(20 * 60),
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
}

#[derive(Debug, Clone)]
pub struct CheckMatch {
    pub check_id: String,
    pub passed: bool,
    pub matched_capsule: bool,
    pub capsule_exit_status: i32,
    pub actual_exit_status: i32,
}

#[derive(Debug)]
pub enum VerifyResult {
    Reproduced,
    Diverged { check_ids: Vec<String> },
}

#[derive(Debug)]
pub struct VerifyReport {
    pub result: VerifyResult,
    pub checks: Vec<CheckMatch>,
}

const FLAKY_ATTEMPTS: u32 = 3;

/// Verify a capsule by rebuilding the tree from `source_repo` and re-running checks.
///
/// Before it builds anything, `verify` waits for a slot of `opts.slot_class` and holds it
/// until it returns, on every path: success, divergence, error or check timeout (D12).
/// Every check runs under `opts.default_timeout`; one that overruns is an
/// infrastructure error naming the check, never a divergence.
///
/// The tree is always built the same way, into `workdir/tree` (which must not exist):
/// 1. Clone `source_repo` and check out the capsule's base commit (its tree hash must
///    match the capsule's `base_tree_hash`).
/// 2. Apply `base.patch` (when present and non-empty).
/// 3. Replay the launch baseline by deleting the paths in `capsule.launch_removed` (D13/R10).
/// 4. Apply `lane.patch`.
/// 5. Run each recorded check's command through the `CheckRunner`.
/// 6. Compare pass or fail per check id; durations and output hashes are never compared.
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

    if capsule.unsandboxed {
        return Err(VerifyError::UnsandboxedNotProved);
    }

    let _slot = acquire_slot(&opts.slot_class, opts.slot_limit, &opts.slot_dir)
        .await
        .map_err(|e| infra(format!("could not acquire a {} slot: {e}", opts.slot_class)))?;

    let recorded = load_checks(capsule_dir)?;

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

        let mut actual_exit = -1;
        for _ in 0..max_attempts {
            let outcome = runner
                .run(&tree, &check.command, opts.default_timeout)
                .await
                .map_err(|e| infra(format!("check {check_id}: {e}")))?;
            actual_exit = outcome.exit_status;
            if actual_exit == 0 {
                break;
            }
        }

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
        });
    }

    let result = if diverged_ids.is_empty() {
        VerifyResult::Reproduced
    } else {
        VerifyResult::Diverged {
            check_ids: diverged_ids,
        }
    };

    Ok(VerifyReport {
        result,
        checks: check_matches,
    })
}

fn infra(msg: String) -> VerifyError {
    VerifyError::Infrastructure(msg)
}

fn load_checks(capsule_dir: &Path) -> Result<BTreeMap<String, CheckResult>, VerifyError> {
    let mut checks = BTreeMap::new();
    let checks_dir = capsule_dir.join("checks");
    if !checks_dir.exists() {
        return Ok(checks);
    }
    let entries = std::fs::read_dir(&checks_dir).map_err(|e| infra(format!("checks/: {e}")))?;
    for entry in entries {
        let path = entry.map_err(|e| infra(format!("checks/: {e}")))?.path();
        if path.extension().is_none_or(|ext| ext != "json") {
            continue;
        }
        let id = path
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| infra("check file name is not UTF-8".to_string()))?
            .to_string();
        let content =
            std::fs::read_to_string(&path).map_err(|e| infra(format!("checks/{id}.json: {e}")))?;
        let check: CheckResult =
            serde_json::from_str(&content).map_err(|e| infra(format!("checks/{id}.json: {e}")))?;
        checks.insert(id, check);
    }
    Ok(checks)
}

async fn git(dir: &Path, args: &[&str]) -> Result<String, VerifyError> {
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
fn remove_launch_paths(tree: &Path, removed_paths: &[String]) -> Result<(), VerifyError> {
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
