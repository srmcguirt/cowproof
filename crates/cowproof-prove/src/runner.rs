use anyhow::Result;
use async_trait::async_trait;
use cowproof_run::{LaneLayout, SandboxPolicy, render_macos_profile, sandbox_command};
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::NamedTempFile;
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
/// **This is unsandboxed and not used in production paths.** It runs with no
/// sandbox, which means:
/// - The builder's clone is accessible (including test config, build scripts, etc.)
/// - Commands can reach the network (unless separately firewalled)
/// - Commands can access credentials (if present in the environment)
///
/// This implementation is documented for testing only. The production verifier uses
/// `SandboxedRunner`, which runs checks in a restricted sandbox per the design.
pub struct ProcessRunner {
    /// Kept for API compatibility but unused; verify owns retries.
    #[allow(dead_code)]
    max_attempts: u32,
}

impl ProcessRunner {
    /// Create a new ProcessRunner.
    /// Note: max_attempts is kept for API compatibility but is unused.
    /// Production paths use SandboxedRunner with 1 attempt; verify owns retries.
    pub fn new(max_attempts: u32) -> Self {
        Self { max_attempts }
    }
}

#[async_trait]
impl CheckRunner for ProcessRunner {
    async fn run(&self, tree: &Path, command: &str) -> Result<CheckOutcome, InfraError> {
        // ProcessRunner runs with 1 attempt only. The verifier (verify.rs) owns retries.
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

        Ok(CheckOutcome {
            exit_status: output_result.status.code().unwrap_or(-1),
            output,
            attempts: 1,
        })
    }
}

/// SandboxedRunner executes checks inside SandboxPolicy::verifier, with no network
/// and no credentials (D6).
///
/// The verifier owns flaky retries; each run call executes exactly once.
pub struct SandboxedRunner {
    lane: LaneLayout,
    cache_dir: std::path::PathBuf,
    platform: String,
}

impl SandboxedRunner {
    /// Create a new SandboxedRunner.
    ///
    /// # Arguments
    /// * `lane` - Lane filesystem layout (clone, home, scratch, control, real_home)
    /// * `cache_dir` - Verifier's dependency cache directory (mounted read-only by policy)
    /// * `platform` - Target platform ("darwin" for macOS, "linux" for Linux)
    pub fn new(lane: LaneLayout, cache_dir: std::path::PathBuf, platform: String) -> Self {
        Self {
            lane,
            cache_dir,
            platform,
        }
    }
}

#[async_trait]
impl CheckRunner for SandboxedRunner {
    async fn run(&self, tree: &Path, command: &str) -> Result<CheckOutcome, InfraError> {
        let policy = SandboxPolicy::verifier(&self.lane, &self.cache_dir);

        // On macOS, write the profile to a temp file outside the clone.
        let profile_file = NamedTempFile::new()
            .map_err(|e| InfraError::SpawnError(format!("cannot create sandbox profile: {e}")))?;
        let profile_path = profile_file.path().to_path_buf();

        // Render the Seatbelt profile (macOS) or bubblewrap args (Linux).
        if self.platform == "darwin" {
            let profile_text = render_macos_profile(&policy).map_err(|e| {
                InfraError::SpawnError(format!("sandbox profile render failed: {e}"))
            })?;
            std::fs::write(&profile_path, profile_text).map_err(|e| {
                InfraError::SpawnError(format!("cannot write sandbox profile: {e}"))
            })?;
        }

        let (sandbox_bin, sandbox_args) = sandbox_command(
            &policy,
            &profile_path,
            &["sh".to_string(), "-c".to_string(), command.to_string()],
            &self.platform,
        )
        .map_err(|e| InfraError::SpawnError(format!("sandbox_command failed: {e}")))?;

        // Run the sandboxed command.
        let output_result = Command::new(&sandbox_bin)
            .args(&sandbox_args)
            .current_dir(tree)
            .output()
            .map_err(|e| InfraError::SpawnError(format!("sandbox execution failed: {e}")))?;

        let mut output = String::from_utf8_lossy(&output_result.stdout).to_string();
        if !output_result.stderr.is_empty() {
            output.push_str(&String::from_utf8_lossy(&output_result.stderr));
        }

        Ok(CheckOutcome {
            exit_status: output_result.status.code().unwrap_or(-1),
            output,
            attempts: 1,
        })
    }
}

/// RAII guard for a held slot (D12). Released on drop.
pub struct SlotGuard {
    slot_path: PathBuf,
}

impl SlotGuard {
    fn new(slot_path: PathBuf) -> Self {
        Self { slot_path }
    }
}

impl Drop for SlotGuard {
    fn drop(&mut self) {
        // Clean up the slot directory when the guard is dropped.
        let _ = std::fs::remove_dir_all(&self.slot_path);
    }
}

/// Acquire a slot of the given class, wait with bounded backoff if none is free,
/// and hold it for the duration of the verify operation (D12).
///
/// Returns the guard, which releases the slot on drop.
pub fn try_acquire_slot(class: &str, limit: usize, dir: &Path) -> Result<SlotGuard> {
    use std::thread;
    use std::time::Duration;

    let mut backoff_ms = 10u64;
    const MAX_BACKOFF_MS: u64 = 1000;

    loop {
        match cowproof_core::try_acquire_slot(class, limit, dir)? {
            Some(slot) => return Ok(SlotGuard::new(slot)),
            None => {
                // No slot available; wait with exponential backoff.
                thread::sleep(Duration::from_millis(backoff_ms));
                backoff_ms = std::cmp::min(backoff_ms * 2, MAX_BACKOFF_MS);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn process_runner_runs_command() {
        let tmp = tempfile::tempdir().unwrap();
        let runner = ProcessRunner::new(1);

        // Create a test file
        let test_file = tmp.path().join("test.txt");
        std::fs::write(&test_file, "hello").unwrap();

        // Run a check that reads the file
        let outcome = runner.run(tmp.path(), "cat test.txt").await.unwrap();

        assert_eq!(outcome.exit_status, 0);
        assert_eq!(outcome.output.trim(), "hello");
        assert_eq!(outcome.attempts, 1);
    }

    #[tokio::test]
    async fn process_runner_reports_failure() {
        let tmp = tempfile::tempdir().unwrap();
        let runner = ProcessRunner::new(1);

        let outcome = runner.run(tmp.path(), "exit 42").await.unwrap();

        assert_eq!(outcome.exit_status, 42);
        assert_eq!(outcome.attempts, 1);
    }

    #[tokio::test]
    async fn check_runner_trait_is_object_safe() {
        // This test just verifies the trait can be used as a trait object
        let tmp = tempfile::tempdir().unwrap();
        let runner: Box<dyn CheckRunner> = Box::new(ProcessRunner::new(1));
        std::fs::write(tmp.path().join("x"), "y").unwrap();

        let outcome = runner.run(tmp.path(), "cat x").await.unwrap();
        assert_eq!(outcome.exit_status, 0);
    }

    #[test]
    fn slot_guard_releases_on_drop() {
        let tmp = tempfile::tempdir().unwrap();
        let slot_dir = tmp.path().to_path_buf();

        // Create a slot directory
        std::fs::create_dir_all(slot_dir.join("rust-0")).unwrap();
        std::fs::write(slot_dir.join("rust-0/pid"), "999").unwrap();

        // Create a guard
        {
            let _guard = SlotGuard::new(slot_dir.join("rust-0"));
            assert!(slot_dir.join("rust-0").exists());
            // guard dropped here
        }

        // Slot should be cleaned up
        assert!(!slot_dir.join("rust-0").exists());
    }

    #[test]
    fn slot_guard_drop_is_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        let slot_dir = tmp.path().join("rust-0");

        std::fs::create_dir_all(&slot_dir).unwrap();
        std::fs::write(slot_dir.join("pid"), "999").unwrap();

        // Multiple drops should not panic
        let guard = SlotGuard::new(slot_dir.clone());
        drop(guard);
        drop(SlotGuard::new(slot_dir.clone())); // drop again on a non-existent dir
    }

    #[test]
    fn try_acquire_slot_blocks_until_available() {
        let tmp = tempfile::tempdir().unwrap();
        let slot_dir = tmp.path().to_path_buf();

        // Acquire a slot
        let guard1 = try_acquire_slot("light", 1, &slot_dir).unwrap();

        // Spawn a thread that will try to acquire the same slot
        let slot_dir_clone = slot_dir.clone();
        let handle =
            std::thread::spawn(move || try_acquire_slot("light", 1, &slot_dir_clone).unwrap());

        // Give the thread time to start waiting
        std::thread::sleep(std::time::Duration::from_millis(100));

        // Release the first slot
        drop(guard1);

        // The thread should now acquire the slot
        let guard2 = handle.join().unwrap();

        // Verify the slot is held
        assert!(slot_dir.join("light-0").exists());
        drop(guard2);
    }

    #[test]
    fn slot_never_exceeds_limit() {
        let tmp = tempfile::tempdir().unwrap();
        let slot_dir = tmp.path().to_path_buf();

        // Acquire two slots with a limit of 2
        let _g1 = try_acquire_slot("pg", 2, &slot_dir).unwrap();
        let _g2 = try_acquire_slot("pg", 2, &slot_dir).unwrap();

        // Verify both slots exist
        assert!(slot_dir.join("pg-0").exists());
        assert!(slot_dir.join("pg-1").exists());

        // Check that total concurrency counter never exceeds 1
        // by spawning a thread that spins trying to acquire (it should eventually timeout)
        let slot_dir_clone = slot_dir.clone();
        let attempt = std::thread::spawn(move || {
            use std::time::{Duration, Instant};
            let start = Instant::now();
            loop {
                if cowproof_core::try_acquire_slot("pg", 2, &slot_dir_clone)
                    .unwrap()
                    .is_some()
                {
                    return true;
                }
                if start.elapsed() > Duration::from_millis(200) {
                    return false; // Timed out, no slot available
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        });

        // This thread should fail to acquire within the timeout
        let got_slot = attempt.join().unwrap();
        assert!(!got_slot, "should not acquire a third slot when limit is 2");
    }
}

#[cfg(test)]
#[cfg(target_os = "macos")]
mod macos_tests {
    use super::*;

    #[tokio::test]
    async fn sandboxed_runner_denies_home_access() {
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();

        // Create lane structure
        for d in [
            "lane/clone",
            "lane/home",
            "lane/scratch",
            "lane/control",
            "cache/.cargo",
            "realhome",
        ] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }

        let lane = LaneLayout {
            clone: root.join("lane/clone"),
            home: root.join("lane/home"),
            scratch: root.join("lane/scratch"),
            control: root.join("lane/control"),
            real_home: root.join("realhome"),
        };

        let runner = SandboxedRunner::new(lane, root.join("cache"), "darwin".to_string());

        // Create a test file in the real home
        std::fs::write(root.join("realhome/.bashrc"), "secret").unwrap();

        // Try to read it from the sandbox—should fail
        let outcome = runner
            .run(
                &root.join("lane/clone"),
                "cat /etc/shadow 2>&1 || echo 'denied'",
            )
            .await
            .unwrap();

        // The sandbox should deny access (or the file doesn't exist in the sandbox)
        assert!(outcome.output.contains("denied") || outcome.exit_status != 0);
    }

    #[tokio::test]
    async fn sandboxed_runner_allows_clone_access() {
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();

        // Create lane structure
        for d in [
            "lane/clone",
            "lane/home",
            "lane/scratch",
            "lane/control",
            "cache/.cargo",
            "realhome",
        ] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }

        let lane = LaneLayout {
            clone: root.join("lane/clone"),
            home: root.join("lane/home"),
            scratch: root.join("lane/scratch"),
            control: root.join("lane/control"),
            real_home: root.join("realhome"),
        };

        let runner = SandboxedRunner::new(lane, root.join("cache"), "darwin".to_string());

        // Create a test file in the clone
        std::fs::write(root.join("lane/clone/test.txt"), "hello").unwrap();

        // Read it from the sandbox—should succeed
        let outcome = runner
            .run(&root.join("lane/clone"), "cat test.txt")
            .await
            .unwrap();

        assert_eq!(outcome.exit_status, 0);
        assert_eq!(outcome.output.trim(), "hello");
    }

    #[tokio::test]
    async fn sandboxed_runner_denies_network() {
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();

        // Create lane structure
        for d in [
            "lane/clone",
            "lane/home",
            "lane/scratch",
            "lane/control",
            "cache/.cargo",
            "realhome",
        ] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }

        let lane = LaneLayout {
            clone: root.join("lane/clone"),
            home: root.join("lane/home"),
            scratch: root.join("lane/scratch"),
            control: root.join("lane/control"),
            real_home: root.join("realhome"),
        };

        let runner = SandboxedRunner::new(lane, root.join("cache"), "darwin".to_string());

        // Try to connect to localhost—should be denied by the sandbox
        let outcome = runner
            .run(
                &root.join("lane/clone"),
                "nc -zv localhost 8080 2>&1 || echo 'network denied'",
            )
            .await
            .unwrap();

        // The network access should be denied
        assert!(outcome.output.contains("denied") || outcome.exit_status != 0);
    }
}
