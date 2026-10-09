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

/// Trait for executing checks.
///
/// `SandboxedRunner` is the production implementation: write access to the tree and
/// scratch only, no access to `lane/control/` or the real home, no credentials, no
/// network. `ProcessRunner` gives none of that and exists for tests.
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
        // The rebuilt tree is the verifier's clone: it is the one writable tree, so
        // the policy is built around it, not around the lane's own clone.
        let mut lane = self.lane.clone();
        lane.clone = tree.to_path_buf();
        let policy = SandboxPolicy::verifier(&lane, &self.cache_dir);

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

        // No credentials (D6): the check starts from an empty environment holding only
        // PATH and what the policy sets (the verifier's CARGO_HOME), never the
        // caller's environment, which may carry API keys.
        let mut env = vec![(
            "PATH".to_string(),
            std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".to_string()),
        )];
        policy.apply_env(&mut env);

        let output_result = Command::new(&sandbox_bin)
            .args(&sandbox_args)
            .current_dir(tree)
            .env_clear()
            .envs(env)
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

/// The platform string `SandboxedRunner::new` expects for the machine running this code.
pub fn host_platform() -> &'static str {
    if cfg!(target_os = "macos") {
        "darwin"
    } else {
        "linux"
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
        cowproof_core::release_slot(Some(&self.slot_path));
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

        // Give the thread time to start waiting: it must still be blocked while the
        // first guard is held.
        std::thread::sleep(std::time::Duration::from_millis(100));
        assert!(!handle.is_finished(), "waiter got a slot that was held");

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

        // A third attempt, spinning for 200 ms, must never get a slot while both are held.
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

/// Whether this host can create the sandbox. macOS always can; Linux needs bubblewrap and
/// user namespaces. With `COWPROOF_REQUIRE_SANDBOX=1` (set in CI) an unavailable sandbox
/// panics instead of skipping, so a runner that cannot sandbox never reports these tests
/// as passing.
#[cfg(test)]
pub(crate) fn sandbox_available() -> bool {
    if cfg!(target_os = "macos") {
        return true;
    }
    let reason = match Command::new("bwrap")
        .args(["--ro-bind", "/", "/", "true"])
        .output()
    {
        Ok(o) if o.status.success() => return true,
        Ok(o) => format!(
            "bwrap cannot create a sandbox here: {}",
            String::from_utf8_lossy(&o.stderr).trim()
        ),
        Err(e) => format!("bwrap is not installed: {e}"),
    };
    if std::env::var_os("COWPROOF_REQUIRE_SANDBOX").is_some_and(|v| v == "1") {
        panic!("COWPROOF_REQUIRE_SANDBOX=1 but {reason}");
    }
    eprintln!("SKIP: {reason}");
    false
}

/// A lane layout, a verifier cache and a fake real home, all under one temp dir.
#[cfg(test)]
pub(crate) struct SandboxFixture {
    _tmp: tempfile::TempDir,
    pub root: PathBuf,
    pub lane: LaneLayout,
}

#[cfg(test)]
impl SandboxFixture {
    pub(crate) fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
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
        Self {
            _tmp: tmp,
            root,
            lane,
        }
    }

    pub(crate) fn runner(&self) -> SandboxedRunner {
        SandboxedRunner::new(
            self.lane.clone(),
            self.root.join("cache"),
            host_platform().to_string(),
        )
    }
}

#[cfg(test)]
mod sandbox_tests {
    use super::*;
    use std::net::TcpListener;

    /// What the sandbox says when it refuses a read of the hidden home: Seatbelt denies
    /// the open, bubblewrap replaces the home with an empty tmpfs.
    const HOME_DENIED: &str = if cfg!(target_os = "macos") {
        "Operation not permitted"
    } else {
        "No such file or directory"
    };

    #[tokio::test]
    async fn sandboxed_runner_reads_and_writes_the_tree() {
        if !sandbox_available() {
            return;
        }
        let fx = SandboxFixture::new();
        let tree = &fx.lane.clone;
        std::fs::write(tree.join("in.txt"), "from-host").unwrap();

        let outcome = fx
            .runner()
            .run(tree, "cat in.txt && echo from-sandbox > out.txt")
            .await
            .unwrap();

        assert_eq!(outcome.exit_status, 0, "{}", outcome.output);
        assert_eq!(outcome.output.trim(), "from-host");
        assert_eq!(outcome.attempts, 1);
        assert_eq!(
            std::fs::read_to_string(tree.join("out.txt"))
                .unwrap()
                .trim(),
            "from-sandbox"
        );
    }

    /// The same read that works unsandboxed fails under the sandbox, and fails because
    /// the home is hidden: the denial message is asserted, and the secret never appears.
    #[tokio::test]
    async fn sandboxed_runner_hides_the_real_home() {
        if !sandbox_available() {
            return;
        }
        let fx = SandboxFixture::new();
        let secret = fx.root.join("realhome/.bashrc");
        std::fs::write(&secret, "SECRET_CREDENTIAL").unwrap();
        let cmd = format!("cat {}", secret.display());

        // Control: the path is valid and readable without the sandbox.
        let open = ProcessRunner::new(1)
            .run(&fx.lane.clone, &cmd)
            .await
            .unwrap();
        assert_eq!(open.exit_status, 0, "{}", open.output);
        assert_eq!(open.output.trim(), "SECRET_CREDENTIAL");

        // The sandbox itself works: a read inside the tree succeeds.
        std::fs::write(fx.lane.clone.join("allowed.txt"), "allowed").unwrap();
        let ok = fx
            .runner()
            .run(&fx.lane.clone, "cat allowed.txt")
            .await
            .unwrap();
        assert_eq!(ok.exit_status, 0, "{}", ok.output);
        assert_eq!(ok.output.trim(), "allowed");

        let denied = fx.runner().run(&fx.lane.clone, &cmd).await.unwrap();
        assert_eq!(denied.exit_status, 1, "{}", denied.output);
        assert!(
            denied.output.contains(HOME_DENIED),
            "expected {HOME_DENIED:?}, got {:?}",
            denied.output
        );
        assert!(!denied.output.contains("SECRET_CREDENTIAL"));
    }

    /// `lane/control` (held-out checks) is unreadable even though it is a sibling of
    /// the tree.
    #[tokio::test]
    async fn sandboxed_runner_hides_lane_control() {
        if !sandbox_available() {
            return;
        }
        let fx = SandboxFixture::new();
        let held_out = fx.lane.control.join("heldout");
        std::fs::write(&held_out, "HELD_OUT_CHECK").unwrap();
        let cmd = format!("cat {}", held_out.display());

        let open = ProcessRunner::new(1)
            .run(&fx.lane.clone, &cmd)
            .await
            .unwrap();
        assert_eq!(open.output.trim(), "HELD_OUT_CHECK");

        let denied = fx.runner().run(&fx.lane.clone, &cmd).await.unwrap();
        assert_eq!(denied.exit_status, 1, "{}", denied.output);
        assert!(!denied.output.contains("HELD_OUT_CHECK"));
        assert!(denied.output.contains(HOME_DENIED), "{}", denied.output);
    }

    /// A TCP connect to a local listener succeeds unsandboxed and is refused by the
    /// sandbox: the listener accepts one connection in the first case and none in the
    /// second.
    #[tokio::test]
    async fn sandboxed_runner_blocks_network() {
        if !sandbox_available() {
            return;
        }
        let fx = SandboxFixture::new();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let cmd = format!("echo STARTED; exec /bin/bash -c 'exec 3<>/dev/tcp/127.0.0.1/{port}'");

        // Control: the same command connects without the sandbox.
        let open = ProcessRunner::new(1)
            .run(&fx.lane.clone, &cmd)
            .await
            .unwrap();
        assert_eq!(open.exit_status, 0, "{}", open.output);
        assert!(
            listener.accept().is_ok(),
            "unsandboxed connect never reached the listener"
        );

        let blocked = fx.runner().run(&fx.lane.clone, &cmd).await.unwrap();
        assert!(
            blocked.output.contains("STARTED"),
            "the sandbox did not start the command: {}",
            blocked.output
        );
        assert_eq!(blocked.exit_status, 1, "{}", blocked.output);
        let refused = listener.accept().unwrap_err();
        assert_eq!(
            refused.kind(),
            std::io::ErrorKind::WouldBlock,
            "the sandboxed check reached the listener"
        );
    }

    /// No credentials (D6): the caller's environment does not reach the check. cargo
    /// sets CARGO_MANIFEST_DIR for this test process, standing in for an API key.
    #[tokio::test]
    async fn sandboxed_runner_does_not_inherit_the_environment() {
        if !sandbox_available() {
            return;
        }
        let fx = SandboxFixture::new();
        assert!(std::env::var_os("CARGO_MANIFEST_DIR").is_some());

        let open = ProcessRunner::new(1)
            .run(&fx.lane.clone, "env")
            .await
            .unwrap();
        assert!(open.output.contains("CARGO_MANIFEST_DIR="), "control");

        let sandboxed = fx.runner().run(&fx.lane.clone, "env").await.unwrap();
        assert_eq!(sandboxed.exit_status, 0, "{}", sandboxed.output);
        assert!(
            !sandboxed.output.contains("CARGO_MANIFEST_DIR="),
            "{}",
            sandboxed.output
        );
        // What the verifier policy sets is present.
        let cargo_home = format!("CARGO_HOME={}", fx.root.join("cache/.cargo").display());
        assert!(
            sandboxed.output.contains(&cargo_home),
            "{}",
            sandboxed.output
        );
    }
}
