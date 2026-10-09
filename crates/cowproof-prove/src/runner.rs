use anyhow::{Result, anyhow};
use async_trait::async_trait;
use cowproof_run::{LaneLayout, SandboxPolicy, render_macos_profile, sandbox_command};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tempfile::NamedTempFile;
use thiserror::Error;
use tokio::io::AsyncReadExt;
use tokio::process::Command;

/// Infrastructure errors when running checks.
#[derive(Error, Debug, Clone)]
pub enum InfraError {
    #[error("Check process failed to start: {0}")]
    SpawnError(String),

    #[error("Check process was interrupted: {0}")]
    Interrupted(String),

    #[error("Check working directory not accessible: {0}")]
    WorkdirError(String),

    /// The check did not finish within its limit and its whole process group was
    /// killed. Carries the check's command and the limit.
    #[error("Timeout waiting for check to complete: {0}")]
    Timeout(String),
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
/// network. `ProcessRunner` gives none of that, exists for tests and is compiled only
/// in test builds.
#[async_trait]
pub trait CheckRunner: Send + Sync {
    /// Run a check command in the tree at the given path. If it has not finished within
    /// `timeout`, its whole process group is killed and `InfraError::Timeout` is
    /// returned.
    async fn run(
        &self,
        tree: &Path,
        command: &str,
        timeout: Duration,
    ) -> Result<CheckOutcome, InfraError>;
}

/// Spawn `cmd` as the leader of its own process group, collect its output and wait for
/// it, all on tokio (nothing blocks the executor).
///
/// On expiry the whole group gets SIGKILL, not only the direct child: a check that
/// backgrounds work (`sleep 30 &`, a test server) must not outlive its limit. The child
/// is then awaited, so no zombie is left, and `InfraError::Timeout` names `command`.
async fn run_with_timeout(
    mut cmd: Command,
    command: &str,
    timeout: Duration,
) -> Result<CheckOutcome, InfraError> {
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .kill_on_drop(true);
    let mut child = cmd
        .spawn()
        .map_err(|e| InfraError::SpawnError(format!("spawn failed: {e}")))?;
    // process_group(0) makes the child its own group leader, so its pid is the pgid.
    let pgid = child
        .id()
        .ok_or_else(|| InfraError::SpawnError("could not get child process ID".to_string()))?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| InfraError::SpawnError("child stdout was not piped".to_string()))?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| InfraError::SpawnError("child stderr was not piped".to_string()))?;
    let (mut out, mut err) = (Vec::new(), Vec::new());

    let finished = tokio::time::timeout(timeout, async {
        let (o, e, status) = tokio::join!(
            stdout.read_to_end(&mut out),
            stderr.read_to_end(&mut err),
            child.wait()
        );
        o?;
        e?;
        status
    })
    .await;

    match finished {
        Ok(Ok(status)) => {
            let mut output = String::from_utf8_lossy(&out).to_string();
            output.push_str(&String::from_utf8_lossy(&err));
            Ok(CheckOutcome {
                exit_status: status.code().unwrap_or(-1),
                output,
                attempts: 1,
            })
        }
        Ok(Err(e)) => Err(InfraError::Interrupted(format!(
            "waiting for the check failed: {e}"
        ))),
        Err(_) => {
            kill_process_group(pgid);
            let _ = child.wait().await;
            Err(InfraError::Timeout(format!(
                "'{command}' after {:.1}s",
                timeout.as_secs_f64()
            )))
        }
    }
}

/// SIGKILL every process in the group `pgid` (a negative pid addresses the group).
fn kill_process_group(pgid: u32) {
    // SAFETY: `kill(2)` takes two integers and touches no memory.
    unsafe {
        libc::kill(-(pgid as libc::pid_t), libc::SIGKILL);
    }
}

/// ProcessRunner executes checks by running `sh -c <command>` in the tree.
///
/// **Test-only: this type is not compiled into release builds**, so no production path
/// can reach it. It runs with no sandbox: the builder's clone is accessible, commands
/// can reach the network and see the caller's environment. It shares the timeout and
/// process-group kill with the production runner.
#[cfg(test)]
#[derive(Default)]
pub struct ProcessRunner;

#[cfg(test)]
impl ProcessRunner {
    pub fn new() -> Self {
        Self
    }
}

#[cfg(test)]
#[async_trait]
impl CheckRunner for ProcessRunner {
    async fn run(
        &self,
        tree: &Path,
        command: &str,
        timeout: Duration,
    ) -> Result<CheckOutcome, InfraError> {
        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg(command).current_dir(tree);
        run_with_timeout(cmd, command, timeout).await
    }
}

/// The fixed system directories on the verifier's `PATH`.
const SYSTEM_PATH_DIRS: [&str; 5] = ["/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin"];

/// Build the verifier's `PATH`: the fixed system directories plus the directory of the
/// `cargo` the director runs. The verifier's environment is otherwise cleared and its
/// home is hidden, so without this a check that needs `cargo` could not find it.
///
/// An empty entry means "the current directory" and a relative entry resolves against
/// it, which is the builder-controlled tree, so a builder could plant a fake `git` or
/// `cargo` there. Both are refused, as is an entry containing the `:` separator.
fn compose_path(cargo_dir: Option<&Path>) -> Result<String, InfraError> {
    let mut entries: Vec<&Path> = SYSTEM_PATH_DIRS.iter().map(Path::new).collect();
    entries.extend(cargo_dir);
    let mut parts = Vec::with_capacity(entries.len());
    for entry in entries {
        let shown = entry.display();
        if entry.as_os_str().is_empty() {
            return Err(InfraError::SpawnError(
                "verifier PATH entry is empty".to_string(),
            ));
        }
        if !entry.is_absolute() {
            return Err(InfraError::SpawnError(format!(
                "verifier PATH entry '{shown}' is not absolute"
            )));
        }
        let text = entry.to_str().filter(|s| !s.contains(':')).ok_or_else(|| {
            InfraError::SpawnError(format!("verifier PATH entry '{shown}' is unusable"))
        })?;
        parts.push(text);
    }
    Ok(parts.join(":"))
}

/// The directory of the `cargo` this process was started by: `$CARGO` when it names an
/// existing absolute file (cargo sets it for `cargo run` and `cargo test`), else the
/// first absolute `PATH` entry holding a `cargo`. Empty and relative `PATH` entries
/// are skipped: they search the current directory.
fn resolve_cargo_dir(cargo_env: Option<&OsStr>, path_env: Option<&OsStr>) -> Option<PathBuf> {
    if let Some(cargo) = cargo_env.map(Path::new)
        && cargo.is_absolute()
        && cargo.is_file()
    {
        return cargo.parent().map(Path::to_path_buf);
    }
    find_in_path(path_env?, "cargo")
}

/// The first absolute `PATH` entry holding a file called `name`. Empty and relative
/// entries are skipped: they search the current directory.
fn find_in_path(path_env: &OsStr, name: &str) -> Option<PathBuf> {
    std::env::split_paths(path_env).find(|dir| dir.is_absolute() && dir.join(name).is_file())
}

/// SandboxedRunner executes checks inside SandboxPolicy::verifier, with no network
/// and no credentials (D6).
///
/// The verifier owns flaky retries; each run call executes exactly once.
pub struct SandboxedRunner {
    lane: LaneLayout,
    cache_dir: PathBuf,
    platform: String,
    /// Resolved once, here, in the caller's environment and outside any sandbox. An
    /// unusable `PATH` is reported when the first check runs.
    path: Result<String, InfraError>,
}

impl SandboxedRunner {
    /// Create a new SandboxedRunner. Construct it when verification starts: it looks
    /// up the director's `cargo` now.
    ///
    /// # Arguments
    /// * `lane` - Lane filesystem layout (clone, home, scratch, control, real_home)
    /// * `cache_dir` - Verifier's dependency cache directory (mounted read-only by policy)
    /// * `platform` - Target platform ("darwin" for macOS, "linux" for Linux)
    pub fn new(lane: LaneLayout, cache_dir: PathBuf, platform: String) -> Self {
        let cargo_dir = resolve_cargo_dir(
            std::env::var_os("CARGO").as_deref(),
            std::env::var_os("PATH").as_deref(),
        );
        Self {
            lane,
            cache_dir,
            platform,
            path: compose_path(cargo_dir.as_deref()),
        }
    }
}

#[async_trait]
impl CheckRunner for SandboxedRunner {
    async fn run(
        &self,
        tree: &Path,
        command: &str,
        timeout: Duration,
    ) -> Result<CheckOutcome, InfraError> {
        let path = self.path.clone()?;
        // The rebuilt tree is the verifier's clone: it is the one writable tree, so
        // the policy is built around it, not around the lane's own clone.
        let mut lane = self.lane.clone();
        lane.clone = tree.to_path_buf();
        let policy = SandboxPolicy::verifier(&lane, &self.cache_dir);

        // On macOS, write the profile to a temp file outside the clone. It lives until
        // the check has finished.
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
        // the explicit PATH and what the policy sets (the verifier's CARGO_HOME), never
        // the caller's environment, which may carry API keys.
        let mut env = vec![("PATH".to_string(), path)];
        policy.apply_env(&mut env);

        let mut cmd = Command::new(&sandbox_bin);
        cmd.args(&sandbox_args)
            .current_dir(tree)
            .env_clear()
            .envs(env);
        run_with_timeout(cmd, command, timeout).await
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

/// RAII guard for a held slot (D12). Released on drop, so every exit path of the
/// holder (success, error, timeout, cancellation) frees the slot.
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

/// Acquire a slot of the given class, waiting with bounded backoff while none is free,
/// and hold it until the returned guard is dropped (D12).
///
/// The wait is a tokio sleep, so other tasks (including the slot's current holder, when
/// it runs on the same executor thread) keep running. The slot probe itself touches the
/// filesystem and spawns `kill -0`, so it runs on the blocking pool.
pub async fn acquire_slot(class: &str, limit: usize, dir: &Path) -> Result<SlotGuard> {
    const MAX_BACKOFF_MS: u64 = 1000;
    let mut backoff_ms = 10u64;

    loop {
        let (class, dir) = (class.to_string(), dir.to_path_buf());
        let probe = tokio::task::spawn_blocking(move || {
            cowproof_core::try_acquire_slot(&class, limit, &dir)
        })
        .await
        .map_err(|e| anyhow!("slot probe task failed: {e}"))??;
        match probe {
            Some(slot) => return Ok(SlotGuard::new(slot)),
            None => {
                tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                backoff_ms = std::cmp::min(backoff_ms * 2, MAX_BACKOFF_MS);
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::time::Instant;

    const LIMIT: Duration = Duration::from_secs(60);

    /// Poll until `kill(pid, 0)` reports ESRCH. A killed process is a zombie until its
    /// parent (or init, once reparented) reaps it, and `kill` still succeeds on a
    /// zombie, so a short wait is part of "dead".
    pub(crate) fn assert_process_gone(pid: libc::pid_t) {
        for _ in 0..60 {
            // SAFETY: signal 0 only checks that the process exists.
            let rc = unsafe { libc::kill(pid, 0) };
            let errno = std::io::Error::last_os_error().raw_os_error();
            if rc == -1 && errno == Some(libc::ESRCH) {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("process {pid} is still alive: the background child outlived the timeout");
    }

    /// A check that backgrounds a 30 s sleep, records its pid and waits on it, run with
    /// a 500 ms limit. Returns the background pid after asserting the timeout error.
    pub(crate) async fn run_backgrounding_check(
        runner: &dyn CheckRunner,
        tree: &Path,
    ) -> libc::pid_t {
        let command = "sleep 30 & echo $! > pid; wait";
        let start = Instant::now();
        let result = runner.run(tree, command, Duration::from_millis(500)).await;
        let elapsed = start.elapsed();

        match result {
            Err(InfraError::Timeout(named)) => assert!(
                named.contains(command),
                "the timeout must name the check: {named}"
            ),
            other => panic!("expected InfraError::Timeout, got {other:?}"),
        }
        assert!(elapsed < Duration::from_secs(3), "took {elapsed:?}");
        std::fs::read_to_string(tree.join("pid"))
            .expect("the check never recorded its background pid")
            .trim()
            .parse()
            .unwrap()
    }

    #[tokio::test]
    async fn process_runner_runs_command() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("test.txt"), "hello").unwrap();

        let outcome = ProcessRunner::new()
            .run(tmp.path(), "cat test.txt", LIMIT)
            .await
            .unwrap();

        assert_eq!(outcome.exit_status, 0);
        assert_eq!(outcome.output.trim(), "hello");
        assert_eq!(outcome.attempts, 1);
    }

    #[tokio::test]
    async fn process_runner_reports_failure_and_stderr() {
        let tmp = tempfile::tempdir().unwrap();

        let outcome = ProcessRunner::new()
            .run(tmp.path(), "echo oops >&2; exit 42", LIMIT)
            .await
            .unwrap();

        assert_eq!(outcome.exit_status, 42);
        assert_eq!(outcome.output.trim(), "oops");
    }

    /// The timeout kills the whole process group: the 30 s sleep the check backgrounded
    /// is gone after the timeout, not only the shell that started it.
    #[tokio::test]
    async fn timeout_kills_the_whole_process_group() {
        let tmp = tempfile::tempdir().unwrap();

        let pid = run_backgrounding_check(&ProcessRunner::new(), tmp.path()).await;

        assert_process_gone(pid);
    }

    #[test]
    fn path_refuses_an_empty_entry() {
        match compose_path(Some(Path::new(""))) {
            Err(InfraError::SpawnError(msg)) => assert!(msg.contains("empty"), "{msg}"),
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn path_refuses_a_relative_entry() {
        match compose_path(Some(Path::new("target/debug"))) {
            Err(InfraError::SpawnError(msg)) => {
                assert!(
                    msg.contains("target/debug") && msg.contains("not absolute"),
                    "{msg}"
                )
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn path_is_the_system_dirs_plus_the_cargo_dir() {
        assert_eq!(
            compose_path(Some(Path::new("/opt/cargo/bin"))).unwrap(),
            "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:/opt/cargo/bin"
        );
        assert_eq!(
            compose_path(None).unwrap(),
            "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
        );
    }

    /// The current directory holds a file with the searched name, so an empty entry, `.`
    /// and a relative entry would all "find" it. Only the absolute entry may.
    #[test]
    fn path_lookup_skips_empty_and_relative_entries() {
        let tmp = tempfile::tempdir().unwrap();
        let bin = std::fs::canonicalize(tmp.path()).unwrap();
        let name = format!("cowproof-trap-{}", std::process::id());
        std::fs::write(bin.join(&name), "").unwrap();
        let trap = std::env::current_dir().unwrap().join(&name);
        std::fs::write(&trap, "").unwrap();
        let path = std::env::join_paths([
            PathBuf::new(),
            PathBuf::from("."),
            PathBuf::from("relative"),
            bin.clone(),
        ])
        .unwrap();

        let found = find_in_path(&path, &name);
        std::fs::remove_file(&trap).unwrap();

        assert_eq!(found, Some(bin));
    }

    #[test]
    fn cargo_env_must_be_absolute_and_exist() {
        assert_eq!(
            resolve_cargo_dir(Some(OsStr::new("cargo")), Some(OsStr::new(""))),
            None
        );
        assert_eq!(
            resolve_cargo_dir(Some(OsStr::new("/nonexistent/cargo")), None),
            None
        );
    }

    #[test]
    fn slot_guard_releases_on_drop() {
        let tmp = tempfile::tempdir().unwrap();
        let slot_dir = tmp.path().to_path_buf();

        std::fs::create_dir_all(slot_dir.join("rust-0")).unwrap();
        std::fs::write(slot_dir.join("rust-0/pid"), "999").unwrap();

        {
            let _guard = SlotGuard::new(slot_dir.join("rust-0"));
            assert!(slot_dir.join("rust-0").exists());
        }

        assert!(!slot_dir.join("rust-0").exists());
    }

    #[test]
    fn slot_guard_drop_is_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        let slot = tmp.path().join("rust-0");
        std::fs::create_dir_all(&slot).unwrap();
        std::fs::write(slot.join("pid"), "999").unwrap();

        drop(SlotGuard::new(slot.clone()));
        drop(SlotGuard::new(slot)); // already gone: must not panic
    }

    /// On a current-thread runtime, a waiter that blocked the thread would stop the
    /// test from ever releasing the slot it waits for.
    #[tokio::test]
    async fn acquire_slot_waits_without_blocking_the_executor() {
        let tmp = tempfile::tempdir().unwrap();
        let slot_dir = tmp.path().to_path_buf();
        let guard1 = acquire_slot("light", 1, &slot_dir).await.unwrap();

        let dir = slot_dir.clone();
        let waiter = tokio::spawn(async move { acquire_slot("light", 1, &dir).await.unwrap() });

        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!waiter.is_finished(), "waiter got a slot that was held");

        drop(guard1);
        let guard2 = tokio::time::timeout(Duration::from_secs(5), waiter)
            .await
            .expect("waiter never got the released slot")
            .unwrap();

        assert!(slot_dir.join("light-0").exists());
        drop(guard2);
        assert!(!slot_dir.join("light-0").exists());
    }

    #[tokio::test]
    async fn slot_never_exceeds_limit() {
        let tmp = tempfile::tempdir().unwrap();
        let slot_dir = tmp.path().to_path_buf();

        let _g1 = acquire_slot("pg", 2, &slot_dir).await.unwrap();
        let _g2 = acquire_slot("pg", 2, &slot_dir).await.unwrap();
        assert!(slot_dir.join("pg-0").exists());
        assert!(slot_dir.join("pg-1").exists());

        let third =
            tokio::time::timeout(Duration::from_millis(300), acquire_slot("pg", 2, &slot_dir))
                .await;
        assert!(third.is_err(), "a third slot was granted with limit 2");
        assert!(!slot_dir.join("pg-2").exists());
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
    let reason = match std::process::Command::new("bwrap")
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
    use std::time::Instant;

    const LIMIT: Duration = Duration::from_secs(60);

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
            .run(tree, "cat in.txt && echo from-sandbox > out.txt", LIMIT)
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
        let open = ProcessRunner::new()
            .run(&fx.lane.clone, &cmd, LIMIT)
            .await
            .unwrap();
        assert_eq!(open.exit_status, 0, "{}", open.output);
        assert_eq!(open.output.trim(), "SECRET_CREDENTIAL");

        // The sandbox itself works: a read inside the tree succeeds.
        std::fs::write(fx.lane.clone.join("allowed.txt"), "allowed").unwrap();
        let ok = fx
            .runner()
            .run(&fx.lane.clone, "cat allowed.txt", LIMIT)
            .await
            .unwrap();
        assert_eq!(ok.exit_status, 0, "{}", ok.output);
        assert_eq!(ok.output.trim(), "allowed");

        let denied = fx.runner().run(&fx.lane.clone, &cmd, LIMIT).await.unwrap();
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

        let open = ProcessRunner::new()
            .run(&fx.lane.clone, &cmd, LIMIT)
            .await
            .unwrap();
        assert_eq!(open.output.trim(), "HELD_OUT_CHECK");

        let denied = fx.runner().run(&fx.lane.clone, &cmd, LIMIT).await.unwrap();
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
        let open = ProcessRunner::new()
            .run(&fx.lane.clone, &cmd, LIMIT)
            .await
            .unwrap();
        assert_eq!(open.exit_status, 0, "{}", open.output);
        assert!(
            listener.accept().is_ok(),
            "unsandboxed connect never reached the listener"
        );

        let blocked = fx.runner().run(&fx.lane.clone, &cmd, LIMIT).await.unwrap();
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

        let open = ProcessRunner::new()
            .run(&fx.lane.clone, "env", LIMIT)
            .await
            .unwrap();
        assert!(open.output.contains("CARGO_MANIFEST_DIR="), "control");

        let sandboxed = fx.runner().run(&fx.lane.clone, "env", LIMIT).await.unwrap();
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

    /// Timeout under the real sandbox policy kills the whole group too: the background
    /// sleep the check started inside the sandbox is gone afterwards.
    #[tokio::test]
    async fn sandboxed_timeout_kills_the_whole_process_group() {
        if !sandbox_available() {
            return;
        }
        let fx = SandboxFixture::new();
        let tree = &fx.lane.clone;

        // A pid recorded inside the sandbox means nothing outside it: bwrap runs with
        // `--unshare-pid`, so `$!` there is a pid in the sandbox's own namespace. Prove
        // the kill by effect instead: a background child that outlived the timeout
        // would write `survived` two seconds later.
        let command = "(sleep 2; echo alive > survived) & wait";
        let start = Instant::now();
        let result = fx
            .runner()
            .run(tree, command, Duration::from_millis(500))
            .await;
        match result {
            Err(InfraError::Timeout(named)) => assert!(named.contains(command), "{named}"),
            other => panic!("expected InfraError::Timeout, got {other:?}"),
        }
        assert!(
            start.elapsed() < Duration::from_secs(3),
            "took {:?}",
            start.elapsed()
        );
        tokio::time::sleep(Duration::from_millis(3500)).await;
        assert!(
            !tree.join("survived").exists(),
            "a background child outlived the timeout and wrote its marker"
        );
    }

    /// The verifier's cleared environment carries an explicit PATH: the fixed system
    /// directories and the cargo directory, every entry absolute and none empty.
    #[tokio::test]
    async fn sandboxed_runner_gets_the_explicit_path() {
        if !sandbox_available() {
            return;
        }
        let fx = SandboxFixture::new();
        let runner = fx.runner();
        let expected = runner.path.clone().unwrap();

        let outcome = runner
            .run(&fx.lane.clone, "echo \"$PATH\"", LIMIT)
            .await
            .unwrap();

        assert_eq!(outcome.exit_status, 0, "{}", outcome.output);
        assert_eq!(outcome.output.trim(), expected);
        assert!(
            expected
                .split(':')
                .all(|e| !e.is_empty() && Path::new(e).is_absolute()),
            "{expected}"
        );
    }

    /// Live (D18): `cargo` is reachable and runs under the verifier policy, with the
    /// cleared environment and the hidden home.
    #[tokio::test]
    async fn sandboxed_runner_runs_cargo() {
        if !sandbox_available() {
            return;
        }
        let fx = SandboxFixture::new();

        let outcome = fx
            .runner()
            .run(&fx.lane.clone, "cargo --version", LIMIT)
            .await
            .unwrap();

        assert_eq!(outcome.exit_status, 0, "{}", outcome.output);
        assert!(outcome.output.starts_with("cargo "), "{}", outcome.output);
    }
}
