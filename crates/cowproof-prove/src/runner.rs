use anyhow::Result;
use async_trait::async_trait;
use std::path::Path;
use std::process::Command;
use thiserror::Error;

/// Infrastructure errors when running checks.
#[derive(Error, Debug, Clone)]
pub enum InfraError {
    #[error("Check process failed to start: {0}")]
    SpawnError(String),

    #[error("Check process was interrupted: {0}")]
    Interrupted(String),

    #[error("Check working directory not accessible: {0}")]
    WorkdirError(String),

    #[error("Timeout waiting for check to complete")]
    Timeout,
}

/// The outcome of running a single check.
#[derive(Debug, Clone)]
pub struct CheckOutcome {
    pub exit_status: i32,
    pub output: String,
    pub attempts: u32,
}

/// Trait for executing checks. Implementations must run checks in isolation.
///
/// For `ProcessRunner`, this is a fresh sandbox with:
/// - write access to the clone and scratch only
/// - no read/write access to lane/control/ or the real tree
/// - no credentials
/// - no network
#[async_trait]
pub trait CheckRunner: Send + Sync {
    /// Run a check command in the tree at the given path.
    /// Returns the exit status and output, or an infrastructure error.
    async fn run(&self, tree: &Path, command: &str) -> Result<CheckOutcome, InfraError>;
}

/// ProcessRunner executes checks by running `sh -c <command>` in the tree.
///
/// **This is a stopgap until the verifier sandbox (SandboxPolicy::verifier) is wired.**
/// It runs with NO sandbox, which means:
/// - The builder's clone is accessible (including test config, build scripts, etc.)
/// - Commands can reach the network (unless separately firewalled)
/// - Commands can access credentials (if present in the environment)
///
/// This implementation is clearly documented as unsandboxed and is intended only
/// for testing and local verification. The production verifier must run in a
/// restricted sandbox per the design.
pub struct ProcessRunner {
    /// Maximum attempts to retry a check (for flaky checks)
    max_attempts: u32,
}

impl ProcessRunner {
    /// Create a new ProcessRunner.
    pub fn new(max_attempts: u32) -> Self {
        Self { max_attempts }
    }
}

#[async_trait]
impl CheckRunner for ProcessRunner {
    async fn run(&self, tree: &Path, command: &str) -> Result<CheckOutcome, InfraError> {
        let mut attempts = 0u32;

        loop {
            attempts += 1;

            let output_result = Command::new("sh")
                .arg("-c")
                .arg(command)
                .current_dir(tree)
                .output()
                .map_err(|e| InfraError::SpawnError(e.to_string()))?;

            let mut output = String::from_utf8_lossy(&output_result.stdout).to_string();
            if !output_result.stderr.is_empty() {
                output.push_str(&String::from_utf8_lossy(&output_result.stderr));
            }

            // Return on success or if this was the last attempt
            if output_result.status.success() || attempts >= self.max_attempts {
                return Ok(CheckOutcome {
                    exit_status: output_result.status.code().unwrap_or(-1),
                    output,
                    attempts,
                });
            }
        }
    }
}

#[cfg(test)]
pub mod test_doubles {
    use super::*;

    /// Mock CheckRunner for testing.
    pub struct MockCheckRunner {
        pub results: std::sync::Mutex<std::collections::HashMap<String, CheckOutcome>>,
    }

    impl MockCheckRunner {
        pub fn new() -> Self {
            Self {
                results: std::sync::Mutex::new(std::collections::HashMap::new()),
            }
        }
    }

    impl Default for MockCheckRunner {
        fn default() -> Self {
            Self::new()
        }
    }

    impl MockCheckRunner {
        pub fn set_result(&self, command: String, outcome: CheckOutcome) {
            self.results.lock().unwrap().insert(command, outcome);
        }
    }

    #[async_trait]
    impl CheckRunner for MockCheckRunner {
        async fn run(&self, _tree: &Path, command: &str) -> Result<CheckOutcome, InfraError> {
            self.results
                .lock()
                .unwrap()
                .get(command)
                .cloned()
                .ok_or_else(|| InfraError::SpawnError("not mocked".to_string()))
        }
    }
}
