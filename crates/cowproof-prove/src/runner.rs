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
///
/// Public so `cowproof run` ends a builder's group with the same code the verifier
/// uses for a timed-out check, not a second copy.
pub fn kill_process_group(pgid: u32) {
    signal_group(pgid, libc::SIGKILL);
}

/// SIGTERM every process in the group `pgid`: the polite first step before
/// [`kill_process_group`].
pub fn terminate_process_group(pgid: u32) {
    signal_group(pgid, libc::SIGTERM);
}

/// `id` as a positive `pid_t`, or `None` for 0 and anything too large. `kill(0, ..)` signals
/// the caller's own group and `kill(-1, ..)` every process the caller may signal, so every
/// function below goes through this before it reaches `kill(2)`.
fn positive_pid(id: u32) -> Option<libc::pid_t> {
    libc::pid_t::try_from(id).ok().filter(|p| *p > 0)
}

/// `pgid` as a group to negate for `kill(2)`, or `None` for 0, 1 and anything too large:
/// `kill(-1, ..)` reaches every process the caller may signal, and pid 1's group is init's.
fn group_id(pgid: u32) -> Option<libc::pid_t> {
    positive_pid(pgid).filter(|p| *p > 1)
}

/// What `kill(target, 0)` says about `target` (a pid, or a negated pgid): EPERM means it
/// exists and is not ours, ESRCH means it does not, and any other answer is unknown.
fn target_exists(target: libc::pid_t) -> Option<bool> {
    // SAFETY: signal 0 delivers nothing; `kill(2)` takes two integers and touches no memory.
    let rc = unsafe { libc::kill(target, 0) };
    if rc == 0 {
        return Some(true);
    }
    match std::io::Error::last_os_error().raw_os_error() {
        Some(libc::EPERM) => Some(true),
        Some(libc::ESRCH) => Some(false),
        _ => None,
    }
}

/// Whether the process `pid` exists: `Some(false)` only when the system says there is no such
/// process, `None` when it cannot be asked (including a pid that is 0 or not a valid pid). A
/// zombie still exists.
pub fn pid_exists(pid: u32) -> Option<bool> {
    target_exists(positive_pid(pid)?)
}

/// Whether any process is left in the group `pgid`, answered like [`pid_exists`].
pub fn group_exists(pgid: u32) -> Option<bool> {
    target_exists(-group_id(pgid)?)
}

/// Send `signal` to the one process `pid`. Whether `kill(2)` accepted it; false, with nothing
/// sent, for a pid that is 0 or not a valid pid.
pub fn signal_pid(pid: u32, signal: libc::c_int) -> bool {
    let Some(pid) = positive_pid(pid) else {
        return false;
    };
    // SAFETY: `kill(2)` takes two integers and touches no memory; `pid` is positive.
    unsafe { libc::kill(pid, signal) == 0 }
}

/// Send `signal` to every process in the group `pgid`, through `kill(2)` with the group
/// negated. Whether `kill(2)` accepted it; false, with nothing sent, for a pgid of 0, 1 or
/// one that is not a valid pid.
///
/// Group 0 would be the caller's own group and group 1 would make the id -1, which reaches
/// every process the caller may signal, so the id goes through `group_id` first. Never run
/// the `kill` program for this: procps's `kill` keeps only the first digit of a negative id
/// that is not preceded by `--` (`kill -KILL -1234` is `kill(-1, SIGKILL)`).
pub fn signal_group(pgid: u32, signal: libc::c_int) -> bool {
    let Some(pgid) = group_id(pgid) else {
        return false;
    };
    // SAFETY: `kill(2)` takes two integers and touches no memory; `pgid` is greater than 1,
    // so `-pgid` names one group and never a wildcard.
    unsafe { libc::kill(-pgid, signal) == 0 }
}

/// [`cowproof_core::try_acquire_slot`] with the real probe: a slot's recorded pid is alive unless
/// `kill(2)` signal 0 answers ESRCH. A pid it cannot be asked about counts as alive, so a slot is
/// never taken from a holder that may still be running.
pub fn try_acquire_slot(
    class: &str,
    limit: usize,
    dir: &Path,
) -> Result<Option<std::path::PathBuf>> {
    cowproof_core::try_acquire_slot(class, limit, dir, &|pid| pid_exists(pid) != Some(false))
}

/// The effective user id of this process. `cowproof host-agent --forced` compares it with the
/// owner of the host's config file, which only that user may have written.
pub fn effective_uid() -> u32 {
    // SAFETY: `geteuid(2)` takes no arguments, touches no memory and cannot fail.
    unsafe { libc::geteuid() }
}

/// SIGTERM the one process `pid`: the polite first step before [`kill_pid`].
pub fn terminate_pid(pid: u32) -> bool {
    signal_pid(pid, libc::SIGTERM)
}

/// SIGKILL the one process `pid`.
pub fn kill_pid(pid: u32) -> bool {
    signal_pid(pid, libc::SIGKILL)
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

/// The verifier's `PATH` and the `cargo` executable it finds, resolved in the caller's
/// environment: what the dependency fetch needs to run the same toolchain the checks do.
pub fn verifier_toolchain() -> Result<(String, Option<PathBuf>), InfraError> {
    let cargo_dir = resolve_cargo_dir(
        std::env::var_os("CARGO").as_deref(),
        std::env::var_os("PATH").as_deref(),
    );
    let cargo = cargo_dir.as_ref().map(|d| d.join("cargo"));
    Ok((compose_path(cargo_dir.as_deref())?, cargo))
}

/// SandboxedRunner executes checks inside SandboxPolicy::verifier, with no network
/// and no credentials (D6).
///
/// The verifier owns flaky retries; each run call executes exactly once.
pub struct SandboxedRunner {
    lane: LaneLayout,
    cache_dir: PathBuf,
    platform: String,
    /// The trusted dependency cache (D6): its `cargo/registry` and `cargo/git` are
    /// mounted read-only into every check. `None` for a lane with nothing fetched.
    deps_cache: Option<PathBuf>,
    /// The first port of the lane's block (`COWPROOF_PORT_BASE`, with
    /// `COWPROOF_PORT_COUNT`), when the lane holds a class slot. `None` sets neither.
    port_base: Option<u16>,
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
            deps_cache: None,
            port_base: None,
            path: compose_path(cargo_dir.as_deref()),
        }
    }

    /// Mount the fetched dependency cache at `deps_dir` (`<cache root>/deps/<key>`) into
    /// every check, read-only. The caller links it into the verifier's `CARGO_HOME`
    /// (`cowproof_run::link_dependency_cache`).
    pub fn with_dependency_cache(mut self, deps_dir: PathBuf) -> Self {
        self.deps_cache = Some(deps_dir);
        self
    }

    /// Give every check the lane's port block: `COWPROOF_PORT_BASE=<port_base>` and
    /// `COWPROOF_PORT_COUNT=20`, the same two variables the builder and its `run_check`
    /// get. Without it the checks see neither.
    pub fn with_port_block(mut self, port_base: u16) -> Self {
        self.port_base = Some(port_base);
        self
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
        let mut policy = SandboxPolicy::verifier(&lane, &self.cache_dir);
        if let Some(deps) = &self.deps_cache {
            policy = policy.with_dependency_cache(deps);
        }

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
        if let Some(port_base) = self.port_base {
            env.extend(cowproof_core::port_block_env(port_base));
        }

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

    /// The slot's directory, `<slot dir>/<class>-<n>`. The guard still owns the slot and
    /// releases it on drop.
    pub fn path(&self) -> &Path {
        &self.slot_path
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
/// filesystem and asks `kill(2)`, so it runs on the blocking pool.
pub async fn acquire_slot(class: &str, limit: usize, dir: &Path) -> Result<SlotGuard> {
    acquire_slot_notifying(class, limit, dir, || {}).await
}

/// [`acquire_slot`], calling `on_wait` once, the first time no slot is free (so a caller
/// can say it is waiting without saying it for every retry).
///
/// Dropping the future gives up the wait. A probe already running on the blocking pool can
/// still take a slot after that; it carries this process's pid, so it is reclaimed as a
/// dead holder once the process ends.
pub async fn acquire_slot_notifying(
    class: &str,
    limit: usize,
    dir: &Path,
    on_wait: impl FnOnce(),
) -> Result<SlotGuard> {
    const MAX_BACKOFF_MS: u64 = 1000;
    let mut backoff_ms = 10u64;
    let mut on_wait = Some(on_wait);

    loop {
        let (class, dir) = (class.to_string(), dir.to_path_buf());
        let probe = tokio::task::spawn_blocking(move || try_acquire_slot(&class, limit, &dir))
            .await
            .map_err(|e| anyhow!("slot probe task failed: {e}"))??;
        match probe {
            Some(slot) => return Ok(SlotGuard::new(slot)),
            None => {
                if let Some(notify) = on_wait.take() {
                    notify();
                }
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

    #[test]
    fn pid_and_group_exist_until_the_child_is_reaped() {
        use std::os::unix::process::CommandExt;
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .process_group(0)
            .spawn()
            .expect("spawn sleep");
        let pid = child.id();
        assert_eq!(pid_exists(pid), Some(true));
        assert_eq!(group_exists(pid), Some(true));
        child.kill().expect("kill sleep");
        child.wait().expect("reap sleep");
        assert_eq!(pid_exists(pid), Some(false));
        assert_eq!(group_exists(pid), Some(false));
    }

    #[test]
    fn a_process_that_is_not_ours_exists() {
        // Pid 1 answers EPERM (or 0 as root): it exists either way.
        assert_eq!(pid_exists(1), Some(true));
    }

    #[test]
    fn pid_zero_and_oversized_pids_are_refused_before_any_kill() {
        assert_eq!(positive_pid(0), None);
        assert_eq!(positive_pid(u32::MAX), None);
        assert_eq!(positive_pid(1), Some(1));
        assert_eq!(pid_exists(0), None);
        assert_eq!(pid_exists(u32::MAX), None);
        assert_eq!(group_exists(0), None);
        assert_eq!(group_exists(u32::MAX), None);
        // Signal 0 delivers nothing, so even a missing refusal cannot hurt this process
        // (pid 0 is the caller's own group); the answer must still be false.
        assert!(!signal_pid(0, 0));
        assert!(!signal_pid(u32::MAX, 0));
        // A group of 1 would be kill(-1, ..): every process this user may signal.
        assert_eq!(group_id(1), None);
        assert_eq!(group_id(0), None);
        assert_eq!(group_id(2), Some(2));
        assert_eq!(group_exists(1), None);
        // This process is still here and so is the test.
        assert_eq!(pid_exists(std::process::id()), Some(true));
    }

    #[test]
    fn signal_group_refuses_0_1_and_oversized_ids_before_any_kill() {
        // Only signal 0 here: delivering nothing, it cannot hurt this process even if a
        // refusal were missing (group 0 is the caller's own, group 1 is kill(-1, ..)), and
        // the answer must still be false because nothing was sent.
        assert!(!signal_group(0, 0));
        assert!(!signal_group(1, 0));
        assert!(!signal_group(u32::MAX, 0));
        // This process is still here and so is the test.
        assert_eq!(pid_exists(std::process::id()), Some(true));
    }

    #[test]
    fn signal_group_ends_the_children_of_a_group_it_names() {
        use std::os::unix::process::{CommandExt, ExitStatusExt};
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .process_group(0)
            .spawn()
            .expect("spawn sleep in its own group");
        let pgid = child.id();
        assert_eq!(group_exists(pgid), Some(true));
        assert!(signal_group(pgid, libc::SIGKILL));
        let status = child.wait().expect("reap sleep");
        assert_eq!(status.signal(), Some(libc::SIGKILL));
        assert_eq!(group_exists(pgid), Some(false));
    }

    #[test]
    fn signal_pid_signals_one_child_only() {
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep");
        assert!(kill_pid(child.id()));
        let status = child.wait().expect("reap sleep");
        assert!(!status.success());
    }

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

    /// `on_wait` runs once when the class is full, however long the wait, and never when a
    /// slot is free at once.
    #[tokio::test]
    async fn acquire_slot_notifying_says_so_once() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let tmp = tempfile::tempdir().unwrap();
        let slot_dir = tmp.path().to_path_buf();
        let calls = AtomicUsize::new(0);

        let first = acquire_slot_notifying("light", 1, &slot_dir, || {
            calls.fetch_add(1, Ordering::SeqCst);
        })
        .await
        .unwrap();
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "a free slot needs no notice"
        );

        let holder = std::sync::Mutex::new(Some(first));
        let release = async {
            tokio::time::sleep(Duration::from_millis(300)).await;
            drop(holder.lock().unwrap().take());
        };
        let wait = acquire_slot_notifying("light", 1, &slot_dir, || {
            calls.fetch_add(1, Ordering::SeqCst);
        });
        let (second, ()) = tokio::join!(wait, release);
        let second = second.unwrap();
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "one notice for the whole wait"
        );
        assert!(second.path().ends_with("light-0"));
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
            sock: root.join("lane/sock/runner.sock"),
            lanes_root: root.join("lane"),
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
