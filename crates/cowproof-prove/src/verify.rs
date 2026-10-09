use crate::capsule::{Capsule, CapsuleError, CheckResult};
use crate::runner::CheckRunner;
use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;
use thiserror::Error;

/// Errors that can occur during verification.
///
/// None of these is a refutation (design Note F-1): a verifier that cannot rebuild
/// the tree or run a check says nothing about the lane's work.
#[derive(Error, Debug)]
pub enum VerifyError {
    /// The verifier could not do its job: tree rebuild, patch apply or runner failure.
    #[error("Infrastructure error during verification: {0}")]
    Infrastructure(String),

    #[error("Verification failed: capsule is marked unsandboxed and cannot be proved")]
    UnsandboxedNotProved,

    /// The capsule itself is unreadable or fails its hash check. Nothing was run.
    #[error("Capsule rejected: {0}")]
    Capsule(#[from] CapsuleError),
}

/// Per-check verification result.
#[derive(Debug, Clone)]
pub struct CheckMatch {
    pub check_id: String,
    pub passed: bool,
    pub matched_capsule: bool,
    pub capsule_exit_status: i32,
    pub actual_exit_status: i32,
}

/// Enum for overall verification result.
#[derive(Debug)]
pub enum VerifyResult {
    /// All checks reproduced successfully.
    Reproduced,

    /// Some checks diverged from the capsule.
    Diverged { check_ids: Vec<String> },
}

/// Report from verifying a capsule.
#[derive(Debug)]
pub struct VerifyReport {
    pub result: VerifyResult,
    pub checks: Vec<CheckMatch>,
}

/// Type alias for Reproduced for backwards compatibility.
pub type Reproduced = ();

/// Type alias for Diverged for backwards compatibility.
pub type Diverged = Vec<String>;

/// Maximum attempts for a check marked flaky in the capsule.
const FLAKY_ATTEMPTS: u32 = 3;

/// Verify a capsule by rebuilding the tree from `source_repo` and re-running checks.
///
/// The tree is always built the same way, into `workdir/tree` (which must not exist):
/// 1. Clone `source_repo` and check out the capsule's base commit (its tree hash must
///    match the capsule's `base_tree_hash`).
/// 2. Apply `base.patch` (when present and non-empty).
/// 3. Apply `launch.patch` (D13/R10: the pre-launch baseline the builder started from).
/// 4. Apply `lane.patch`.
/// 5. Run each recorded check's command through the `CheckRunner`.
/// 6. Compare pass or fail per check id; durations and output hashes are never compared.
///
/// Checks marked flaky in the capsule are retried up to three times. Any failure to
/// rebuild the tree, apply a patch or run a check is `VerifyError::Infrastructure`,
/// never a divergence (F-1).
pub async fn verify(
    capsule_dir: &Path,
    source_repo: &Path,
    workdir: &Path,
    runner: &dyn CheckRunner,
) -> Result<VerifyReport, VerifyError> {
    let capsule = Capsule::read(capsule_dir)?;

    if capsule.unsandboxed {
        return Err(VerifyError::UnsandboxedNotProved);
    }

    let recorded = load_checks(capsule_dir)?;

    let tree = workdir.join("tree");
    if tree.exists() {
        return Err(infra(format!(
            "refusing to reuse existing tree at {}",
            tree.display()
        )));
    }
    std::fs::create_dir_all(workdir).map_err(|e| infra(format!("workdir: {e}")))?;
    clone_at_commit(source_repo, &capsule.base_commit, &tree)?;

    let actual_tree_hash = git(&tree, &["rev-parse", "HEAD^{tree}"])?;
    if actual_tree_hash.trim() != capsule.base_tree_hash {
        return Err(infra(format!(
            "base tree hash mismatch: capsule has {}, rebuilt tree has {}",
            capsule.base_tree_hash,
            actual_tree_hash.trim()
        )));
    }

    for name in ["base.patch", "launch.patch", "lane.patch"] {
        apply_patch_file(&tree, &capsule_dir.join(name), name)?;
    }

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
                .run(&tree, &check.command)
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

/// Load `checks/<id>.json` files, keyed by check id (the file stem), in id order.
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

/// Run git in `dir` with hooks disabled; return stdout.
fn git(dir: &Path, args: &[&str]) -> Result<String, VerifyError> {
    let output = Command::new("git")
        .args(["-c", "core.hooksPath=/dev/null", "-C"])
        .arg(dir)
        .args(args)
        .output()
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

/// Clone `source_repo` into `target` and check out `commit` detached.
fn clone_at_commit(source_repo: &Path, commit: &str, target: &Path) -> Result<(), VerifyError> {
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
        .map_err(|e| infra(format!("failed to run git clone: {e}")))?;
    if !output.status.success() {
        return Err(infra(format!(
            "git clone of {} failed: {}",
            source_repo.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    git(target, &["checkout", "--quiet", "--detach", commit])?;
    Ok(())
}

/// Apply one capsule patch to the tree. A missing or blank patch is skipped; a patch
/// that does not apply is an infrastructure error naming the patch (F-1).
fn apply_patch_file(tree: &Path, patch: &Path, name: &str) -> Result<(), VerifyError> {
    if !patch.exists() {
        return Ok(());
    }
    let content = std::fs::read(patch).map_err(|e| infra(format!("{name}: {e}")))?;
    if content.iter().all(u8::is_ascii_whitespace) {
        return Ok(());
    }
    // Plain `git apply`: exact context only, no three-way fallback, so a replay
    // never silently succeeds on a tree other than the one the patch was made on.
    let output = Command::new("git")
        .args(["-c", "core.hooksPath=/dev/null", "-C"])
        .arg(tree)
        .arg("apply")
        .arg(patch)
        .output()
        .map_err(|e| infra(format!("{name}: failed to run git apply: {e}")))?;
    if !output.status.success() {
        return Err(infra(format!(
            "{name} did not apply: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}
