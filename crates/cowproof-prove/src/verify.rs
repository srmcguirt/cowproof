use crate::capsule::Capsule;
use crate::runner::CheckRunner;
use anyhow::Result;
use std::collections::HashMap;
use std::path::Path;
use std::process::Command;
use thiserror::Error;

/// Errors that can occur during verification.
#[derive(Error, Debug)]
pub enum VerifyError {
    #[error("Infrastructure error during verification: {0}")]
    Infrastructure(String),

    #[error("Verification failed: capsule is marked unsandboxed and cannot be proved")]
    UnsandboxedNotProved,

    #[error("Failed to rebuild tree from git")]
    TreeRebuilding(String),

    #[error("Failed to apply patch: {0}")]
    PatchApply(String),
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

/// Verify a capsule by rebuilding the tree and re-running checks.
///
/// This function:
/// 1. Rebuilds the tree at the base commit
/// 2. Applies base.patch (if present)
/// 3. Applies launch.patch
/// 4. Applies lane.patch
/// 5. Runs each check through the CheckRunner
/// 6. Compares results against the capsule
///
/// Flaky checks (marked in the capsule) are retried up to 3 times.
/// Infrastructure errors are returned as VerifyError::Infrastructure, never as divergence.
pub async fn verify(
    capsule_dir: &Path,
    workdir: &Path,
    runner: &dyn CheckRunner,
) -> Result<VerifyReport, VerifyError> {
    // Read the capsule
    let capsule =
        Capsule::read(capsule_dir).map_err(|e| VerifyError::Infrastructure(e.to_string()))?;

    // Check if capsule is unsandboxed
    if capsule.unsandboxed {
        return Err(VerifyError::UnsandboxedNotProved);
    }

    // Determine the tree path to use
    let tree = if workdir.join("tree").exists() {
        // Prefer tree subdir if it exists (production path)
        workdir.join("tree")
    } else if workdir.exists() {
        // Otherwise use workdir itself (testing path - tree pre-built in workdir)
        workdir.to_path_buf()
    } else {
        // If workdir doesn't exist, try to clone
        let tree = workdir.join("tree");
        clone_at_commit(&capsule.base_commit, &tree).map_err(VerifyError::TreeRebuilding)?;
        tree
    };

    // Apply base.patch if it exists and is non-empty
    let base_patch = capsule_dir.join("base.patch");
    if base_patch.exists() {
        let patch_content = std::fs::read_to_string(&base_patch)
            .map_err(|e| VerifyError::Infrastructure(e.to_string()))?;
        if !patch_content.trim().is_empty() {
            apply_patch(&tree, &base_patch)
                .map_err(|e| VerifyError::PatchApply(format!("base.patch: {}", e)))?;
        }
    }

    // Apply launch.patch (if non-empty)
    let launch_patch = capsule_dir.join("launch.patch");
    if launch_patch.exists() {
        let patch_content = std::fs::read_to_string(&launch_patch)
            .map_err(|e| VerifyError::Infrastructure(e.to_string()))?;
        if !patch_content.trim().is_empty() {
            apply_patch(&tree, &launch_patch)
                .map_err(|e| VerifyError::PatchApply(format!("launch.patch: {}", e)))?;
        }
    }

    // Apply lane.patch (if non-empty)
    let lane_patch = capsule_dir.join("lane.patch");
    if lane_patch.exists() {
        let patch_content = std::fs::read_to_string(&lane_patch)
            .map_err(|e| VerifyError::Infrastructure(e.to_string()))?;
        if !patch_content.trim().is_empty() {
            apply_patch(&tree, &lane_patch)
                .map_err(|e| VerifyError::PatchApply(format!("lane.patch: {}", e)))?;
        }
    }

    // Load check results from the capsule
    let checks_dir = capsule_dir.join("checks");
    let mut capsule_checks: HashMap<String, i32> = HashMap::new();
    let flaky_checks = capsule.flaky_checks.clone();

    if checks_dir.exists() {
        for entry in std::fs::read_dir(&checks_dir)
            .map_err(|e| VerifyError::Infrastructure(e.to_string()))?
        {
            let entry = entry.map_err(|e| VerifyError::Infrastructure(e.to_string()))?;
            let path = entry.path();

            if path.extension().is_some_and(|ext| ext == "json") {
                let check_id = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("")
                    .to_string();

                let content = std::fs::read_to_string(&path)
                    .map_err(|e| VerifyError::Infrastructure(e.to_string()))?;
                let check_data: serde_json::Value = serde_json::from_str(&content)
                    .map_err(|e| VerifyError::Infrastructure(e.to_string()))?;

                if let Some(exit_status) = check_data.get("exit_status").and_then(|v| v.as_i64()) {
                    capsule_checks.insert(check_id.clone(), exit_status as i32);
                }
            }
        }
    }

    // Run each check and compare
    let mut check_matches = Vec::new();
    let mut diverged_ids = Vec::new();

    for (check_id, capsule_exit_status) in capsule_checks {
        let max_attempts = if flaky_checks.contains(&check_id) {
            3
        } else {
            1
        };

        let mut actual_exit_status = None;
        let mut last_error = None;

        for attempt in 1..=max_attempts {
            match runner.run(&tree, &check_id).await {
                Ok(outcome) => {
                    actual_exit_status = Some(outcome.exit_status);
                    // If this succeeded, stop retrying (passing counts as pass)
                    if outcome.exit_status == 0 {
                        break;
                    }
                    // If this is not the last attempt, continue to retry
                    if attempt < max_attempts {
                        continue;
                    }
                }
                Err(e) => {
                    last_error = Some(e);
                    // On infra error, return immediately
                    if attempt == 1 {
                        return Err(VerifyError::Infrastructure(last_error.unwrap().to_string()));
                    }
                }
            }
        }

        let actual_exit = match (actual_exit_status, last_error) {
            (Some(status), _) => status,
            (None, Some(err)) => {
                return Err(VerifyError::Infrastructure(err.to_string()));
            }
            (None, None) => {
                // Should not happen, but treat as error
                return Err(VerifyError::Infrastructure(
                    "Check execution inconclusive".to_string(),
                ));
            }
        };

        let matched = (capsule_exit_status == 0) == (actual_exit == 0);
        if !matched {
            diverged_ids.push(check_id.clone());
        }

        check_matches.push(CheckMatch {
            check_id,
            passed: actual_exit == 0,
            matched_capsule: matched,
            capsule_exit_status,
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

/// Clone a git repository at a specific commit.
fn clone_at_commit(commit: &str, target: &Path) -> Result<(), String> {
    // In a real implementation, this would clone from a remote.
    // For testing, we'll use git worktree add from the current repo.
    let output = Command::new("git")
        .args(["worktree", "add", "--detach"])
        .arg(target)
        .arg(commit)
        .output()
        .map_err(|e| format!("Failed to create worktree: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "git worktree add failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    Ok(())
}

/// Apply a patch to a git working tree.
fn apply_patch(tree: &Path, patch_path: &Path) -> Result<(), String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(tree)
        .args(["apply", "--3way"])
        .arg(patch_path)
        .output()
        .map_err(|e| format!("Failed to apply patch: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "git apply failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    Ok(())
}
