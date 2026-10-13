use anyhow::{Result, anyhow};
use async_trait::async_trait;
use cowproof_run::runtime_dirs::RuntimeDir;
use cowproof_run::tools::CheckEnd;
use cowproof_run::{LaneLayout, RustupEnv, SandboxPolicy, render_macos_profile, sandbox_command};
use std::collections::HashMap;
use std::ffi::OsStr;
use std::os::unix::process::ExitStatusExt as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Mutex;
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

    /// A step that makes the dependencies available (the Bundler tree's `bundle install
    /// --local`) could not run, or ended for a reason that is not the lane's lockfile: the
    /// program is missing or cannot run, the step timed out or was killed, or it failed in a way
    /// nothing can attribute to the lane. Infrastructure, never a refutation (S-8).
    #[error("The verifier's dependency setup did not run to a verdict: {0}")]
    Environment(String),
}

/// The outcome of running a single check.
#[derive(Debug, Clone)]
pub struct CheckOutcome {
    pub exit_status: i32,
    pub output: String,
    pub attempts: u32,
    /// How the command ended: with an exit code, or by a signal (`exit_status` is then -1). A
    /// timeout is not an outcome here; it is `InfraError::Timeout`.
    pub end: CheckEnd,
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

/// How long the output pipes may stay open after a command's leader has exited and its group
/// has been killed. A process that escaped the group (its own session) could hold a pipe
/// open for ever; the read is abandoned after this and what was read stands.
const GROUP_DRAIN: Duration = Duration::from_millis(2_000);

/// How long [`run_in_group`] waits, after the leader has exited and the group has been sent
/// SIGKILL, for the kernel to show the group empty. SIGKILL is delivered asynchronously, so
/// without this a member still on a CPU could finish a `write(2)` after the caller has
/// already read what the command left behind. The wait ends early when the group is empty;
/// a zombie nobody reaps (a container without an init) keeps a group listed and costs the
/// whole bound, which is why it is short.
const GROUP_GONE: Duration = Duration::from_millis(1_000);

/// The process groups one runner started and has not finished with.
///
/// A command run through [`run_in_group`] is its own group leader, and its group is listed
/// here from the spawn until the command is over. The runner that owns the set can end
/// exactly those groups ([`GroupSet::end_all`]) when it is interrupted or its lane stops, and
/// nothing else: a group that is not listed is never signalled through the set.
#[derive(Debug, Default)]
pub struct GroupSet {
    groups: std::sync::Mutex<std::collections::BTreeSet<u32>>,
}

impl GroupSet {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, std::collections::BTreeSet<u32>> {
        self.groups.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The listed groups, in order.
    pub fn live(&self) -> Vec<u32> {
        self.lock().iter().copied().collect()
    }

    /// SIGTERM every listed group.
    pub fn terminate_all(&self) {
        for pgid in self.live() {
            terminate_process_group(pgid);
        }
    }

    /// SIGKILL every listed group.
    pub fn kill_all(&self) {
        for pgid in self.live() {
            kill_process_group(pgid);
        }
    }

    /// End the groups listed now the polite way: SIGTERM, up to `grace` for their commands to
    /// finish (each one leaves the set when it does), then SIGKILL to those still listed.
    /// Groups listed after the call starts are not touched, so a command started meanwhile
    /// (a resumed builder's first check) is safe. Returns at once when nothing is listed.
    pub async fn end_all(&self, grace: Duration) {
        let targets = self.live();
        if targets.is_empty() {
            return;
        }
        for pgid in &targets {
            terminate_process_group(*pgid);
        }
        let still_listed = |targets: &[u32]| -> Vec<u32> {
            let live = self.lock();
            targets
                .iter()
                .copied()
                .filter(|g| live.contains(g))
                .collect()
        };
        let deadline = tokio::time::Instant::now() + grace;
        while !still_listed(&targets).is_empty() && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        for pgid in still_listed(&targets) {
            kill_process_group(pgid);
        }
    }
}

/// Lists a group in a [`GroupSet`] while it lives, and SIGKILLs it if dropped before
/// [`LiveGroup::finish`]: a command whose future is dropped (the lane stopped, the task was
/// aborted) must not leave its group behind, and `kill_on_drop` reaches only the leader.
struct LiveGroup<'a> {
    pgid: u32,
    set: Option<&'a GroupSet>,
    armed: bool,
}

impl<'a> LiveGroup<'a> {
    fn new(pgid: u32, set: Option<&'a GroupSet>) -> Self {
        if let Some(set) = set {
            set.lock().insert(pgid);
        }
        LiveGroup {
            pgid,
            set,
            armed: true,
        }
    }

    /// The group has been ended and its leader reaped: delist it and do not signal it again
    /// (its id could have been reused by now).
    fn finish(mut self) {
        self.armed = false;
    }
}

impl Drop for LiveGroup<'_> {
    fn drop(&mut self) {
        if let Some(set) = self.set {
            set.lock().remove(&self.pgid);
        }
        if self.armed {
            kill_process_group(self.pgid);
        }
    }
}

/// How a command run by [`run_in_group`] ended.
#[derive(Debug)]
pub enum GroupEnd {
    /// The leader exited by itself; the rest of its group was killed.
    Exited(std::process::ExitStatus),
    /// It did not finish within the limit: SIGTERM to its group (when a grace was given),
    /// then SIGKILL.
    TimedOut,
}

/// Why [`run_in_group`] could not report an end.
#[derive(Debug)]
pub enum GroupError {
    /// The command did not start (or its pipes could not be taken).
    Spawn(std::io::Error),
    /// Reading its output or waiting for it failed.
    Wait(std::io::Error),
}

impl std::fmt::Display for GroupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GroupError::Spawn(e) => write!(f, "spawn failed: {e}"),
            GroupError::Wait(e) => write!(f, "waiting for the check failed: {e}"),
        }
    }
}

impl std::error::Error for GroupError {}

/// What [`run_in_group`] collected.
#[derive(Debug)]
pub struct GroupOutput {
    pub end: GroupEnd,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// Spawn `cmd` as the leader of its own process group, collect its output and wait for
/// it, all on tokio (nothing blocks the executor). stdin is null.
///
/// The group is listed in `set` (if any) from the spawn to the end. When the leader exits,
/// whatever it left running is SIGKILLed (the pipes then close; a process that escaped the
/// group holds them for at most [`GROUP_DRAIN`]). On expiry the whole group gets SIGTERM
/// when `term_grace` is not zero, the leader gets `term_grace` to exit, and the group then
/// gets SIGKILL, not only the direct child: a check that backgrounds work (`sleep 30 &`, a
/// test server) must not outlive its limit. The child is awaited, so no zombie is left.
/// Dropping the future SIGKILLs the group.
pub async fn run_in_group(
    mut cmd: Command,
    timeout: Duration,
    term_grace: Duration,
    set: Option<&GroupSet>,
) -> Result<GroupOutput, GroupError> {
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .kill_on_drop(true);
    // A freshly written script can be briefly busy to exec (ETXTBSY): see `portkit_core::spawn`.
    let mut child = portkit_core::spawn::spawn_async(&mut cmd)
        .await
        .map_err(GroupError::Spawn)?;
    let bad = |what: &str| GroupError::Spawn(std::io::Error::other(what.to_string()));
    // process_group(0) makes the child its own group leader, so its pid is the pgid.
    let pgid = child
        .id()
        .ok_or_else(|| bad("could not get child process ID"))?;
    let live = LiveGroup::new(pgid, set);
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| bad("child stdout was not piped"))?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| bad("child stderr was not piped"))?;
    let (mut out, mut err) = (Vec::new(), Vec::new());

    let finished = tokio::time::timeout(timeout, async {
        let (mut buf_out, mut buf_err) = ([0u8; 8192], [0u8; 8192]);
        let (mut out_open, mut err_open) = (true, true);
        let mut status = None;
        let mut drain_until: Option<tokio::time::Instant> = None;
        loop {
            if status.is_some() && !out_open && !err_open {
                break;
            }
            tokio::select! {
                n = stdout.read(&mut buf_out), if out_open => match n? {
                    0 => out_open = false,
                    n => out.extend_from_slice(&buf_out[..n]),
                },
                n = stderr.read(&mut buf_err), if err_open => match n? {
                    0 => err_open = false,
                    n => err.extend_from_slice(&buf_err[..n]),
                },
                waited = child.wait(), if status.is_none() => {
                    status = Some(waited?);
                    // The leader is gone: end whatever it left running, so no background
                    // child outlives the command or holds its pipes open.
                    kill_process_group(pgid);
                    drain_until = Some(tokio::time::Instant::now() + GROUP_DRAIN);
                }
                _ = tokio::time::sleep_until(drain_until.unwrap_or_else(tokio::time::Instant::now)),
                    if drain_until.is_some() => break,
            }
        }
        Ok::<_, std::io::Error>(status)
    })
    .await;

    match finished {
        Ok(Ok(Some(status))) => {
            // The group was sent SIGKILL when the leader exited; return only once it is
            // empty, so nothing it ran can still change a file the caller reads next.
            wait_group_gone(pgid).await;
            live.finish();
            Ok(GroupOutput {
                end: GroupEnd::Exited(status),
                stdout: out,
                stderr: err,
            })
        }
        // The loop only ends with the leader's status; a missing one is a wait that failed.
        Ok(Ok(None)) => Err(GroupError::Wait(std::io::Error::other(
            "the leader's exit status was never read",
        ))),
        Ok(Err(e)) => Err(GroupError::Wait(e)),
        Err(_) => {
            if !term_grace.is_zero() {
                terminate_process_group(pgid);
                let _ = tokio::time::timeout(term_grace, child.wait()).await;
            }
            kill_process_group(pgid);
            let _ = child.wait().await;
            live.finish();
            Ok(GroupOutput {
                end: GroupEnd::TimedOut,
                stdout: out,
                stderr: err,
            })
        }
    }
}

/// Run a short probe (`<tool> --version`, a sandboxed `true`) in its own process group and
/// end the whole group when it is over: the one way every probe is run. It is
/// [`run_in_group`] with SIGKILL on expiry and no [`GroupSet`]; the group is also ended when
/// the future is dropped, and a probe that hangs or backgrounds work cannot outlive the
/// caller. The caller sets the environment on `cmd`; stdin is null and both outputs are
/// collected.
pub async fn run_probe(cmd: Command, timeout: Duration) -> Result<GroupOutput, GroupError> {
    run_in_group(cmd, timeout, Duration::ZERO, None).await
}

/// [`run_probe`] for a caller that is not async (the host facts). It drives the probe on a
/// current-thread runtime of its own, on a scoped thread, so it is safe to call from inside
/// another tokio runtime, which `block_on` on the calling thread would not be.
pub fn run_probe_blocking(
    cmd: std::process::Command,
    timeout: Duration,
) -> Result<GroupOutput, GroupError> {
    run_in_group_blocking(cmd, timeout, Duration::ZERO, None)
}

/// [`run_in_group`] for a caller that is not async, listing the group in `set` while it
/// lives. It drives the command on a current-thread runtime of its own, on a scoped thread,
/// so it is safe to call from inside another tokio runtime (a `spawn_blocking` task, the
/// dependency fetch), which `block_on` on the calling thread would not be.
pub fn run_in_group_blocking(
    cmd: std::process::Command,
    timeout: Duration,
    term_grace: Duration,
    set: Option<&GroupSet>,
) -> Result<GroupOutput, GroupError> {
    std::thread::scope(|scope| {
        scope
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(GroupError::Spawn)?;
                runtime.block_on(run_in_group(Command::from(cmd), timeout, term_grace, set))
            })
            .join()
            .unwrap_or_else(|_| {
                Err(GroupError::Wait(std::io::Error::other(
                    "the probe thread panicked",
                )))
            })
    })
}

/// Wait, up to [`GROUP_GONE`], until no process is left in the group `pgid`.
async fn wait_group_gone(pgid: u32) {
    let deadline = tokio::time::Instant::now() + GROUP_GONE;
    while group_exists(pgid) == Some(true) && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
}

/// The verifier's use of [`run_in_group`]: SIGKILL on expiry (no grace), `InfraError`s. The
/// command's group is listed in `set` while it runs, when the runner has one.
async fn run_with_timeout(
    cmd: Command,
    command: &str,
    timeout: Duration,
    set: Option<&GroupSet>,
) -> Result<CheckOutcome, InfraError> {
    let ran = run_in_group(cmd, timeout, Duration::ZERO, set)
        .await
        .map_err(|e| match e {
            GroupError::Spawn(e) => InfraError::SpawnError(format!("spawn failed: {e}")),
            GroupError::Wait(e) => {
                InfraError::Interrupted(format!("waiting for the check failed: {e}"))
            }
        })?;
    match ran.end {
        GroupEnd::Exited(status) => {
            let mut output = String::from_utf8_lossy(&ran.stdout).to_string();
            output.push_str(&String::from_utf8_lossy(&ran.stderr));
            let end = match (status.code(), status.signal()) {
                (Some(code), _) => CheckEnd::Exited { code },
                (None, Some(signal)) => CheckEnd::Signaled { signal },
                (None, None) => CheckEnd::NotRun,
            };
            Ok(CheckOutcome {
                exit_status: status.code().unwrap_or(-1),
                output,
                attempts: 1,
                end,
            })
        }
        GroupEnd::TimedOut => Err(InfraError::Timeout(format!(
            "'{command}' after {:.1}s",
            timeout.as_secs_f64()
        ))),
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
        run_with_timeout(cmd, command, timeout, None).await
    }
}

/// The fixed system directories on the verifier's `PATH`.
const SYSTEM_PATH_DIRS: [&str; 5] = ["/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin"];

/// Build the verifier's `PATH`: the director's cargo bin directory when its `PATH` has
/// one (`cargo_bin`: the rustup proxies, granted read-only by the policy, and first like
/// the director's own), the fixed system directories, then the directory of the `cargo`
/// the director runs. The verifier's environment is otherwise cleared and its home is
/// hidden, so without this a check that needs `cargo` could not find it.
///
/// `runtime` is the executables directory of each runtime the director granted
/// (`--runtime-dir`): after the cargo bin directory and ahead of the system directories,
/// in the order given, like the director's own `PATH` would have them.
///
/// An empty entry means "the current directory" and a relative entry resolves against
/// it, which is the builder-controlled tree, so a builder could plant a fake `git` or
/// `cargo` there. Both are refused, as is an entry containing the `:` separator.
fn compose_path(
    cargo_dir: Option<&Path>,
    cargo_bin: Option<&Path>,
    runtime: &[RuntimeDir],
) -> Result<String, InfraError> {
    let mut entries: Vec<&Path> = Vec::new();
    entries.extend(cargo_bin);
    entries.extend(runtime.iter().map(|r| r.path_entry.as_path()));
    entries.extend(SYSTEM_PATH_DIRS.iter().map(Path::new));
    // The same directory twice adds nothing.
    entries.extend(cargo_dir.filter(|d| Some(*d) != cargo_bin));
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
pub fn verifier_toolchain(real_home: &Path) -> Result<(String, Option<PathBuf>), InfraError> {
    let cargo_dir = resolve_cargo_dir(
        std::env::var_os("CARGO").as_deref(),
        std::env::var_os("PATH").as_deref(),
    );
    let cargo = cargo_dir.as_ref().map(|d| d.join("cargo"));
    let path = director_cargo_bin(real_home);
    Ok((
        compose_path(cargo_dir.as_deref(), path.as_deref(), &[])?,
        cargo,
    ))
}

/// The director's cargo bin directory, when the director's own `PATH` lists it (see
/// [`RustupEnv::cargo_bin_on_path`]).
fn director_cargo_bin(real_home: &Path) -> Option<PathBuf> {
    let path_env = std::env::var_os("PATH")?;
    RustupEnv::from_director_env(real_home)
        .cargo_bin_on_path(&path_env)
        .map(Path::to_path_buf)
}

/// SandboxedRunner executes checks inside SandboxPolicy::verifier, with no network
/// and no credentials (D6).
///
/// The verifier owns flaky retries; each run call executes exactly once.
pub struct SandboxedRunner {
    lane: LaneLayout,
    cache_dir: PathBuf,
    platform: String,
    /// The trusted dependency cache (D6): its `cargo/registry` and `cargo/git` (and the npm
    /// part, `npm/node_modules` and `npm/cache`) are mounted read-only into every check. `None` for a lane with nothing fetched.
    deps_cache: Option<PathBuf>,
    /// The first port of the lane's block (`COWPROOF_PORT_BASE`, with
    /// `COWPROOF_PORT_COUNT`), when the lane holds a class slot. `None` sets neither.
    port_base: Option<u16>,
    /// Executable files the sandbox may read and run besides the system directories (see
    /// [`SandboxedRunner::with_executable`]).
    executables: Vec<PathBuf>,
    /// Where every check's process group is listed while it runs, so the caller can end
    /// them when it is interrupted ([`SandboxedRunner::with_groups`]). `None` lists none.
    groups: Option<std::sync::Arc<GroupSet>>,
    /// The `cargo` directory and the director's cargo bin directory, resolved once, here, in
    /// the caller's environment and outside any sandbox. They and `runtime_dirs` make the
    /// `PATH` ([`compose_path`]); an unusable one is reported when the first check runs.
    cargo_dir: Option<PathBuf>,
    cargo_bin: Option<PathBuf>,
    /// The runtime directories the director granted (`--runtime-dir`): read-only in every
    /// check's sandbox, their executables on its `PATH`.
    runtime_dirs: Vec<RuntimeDir>,
    /// The cargo target directory every command gets as `CARGO_TARGET_DIR`
    /// ([`SandboxedRunner::with_target_dir`]); `None` sets nothing.
    target_dir: Option<PathBuf>,
    /// Also put `target_dir` at `<tree>/target` as a symlink before every command
    /// ([`SandboxedRunner::with_target_link`]).
    link_target: bool,
    /// The `bundle` that installs a Bundler entry's gems ([`SandboxedRunner::with_bundle_exe`]);
    /// `None` runs the `bundle` on the checks' `PATH`.
    bundle_exe: Option<PathBuf>,
    /// The result of the one `bundle install --local` per tree, run before that tree's first
    /// check when the dependency cache has a Bundler part: `None` is success, `Some` the
    /// failure (the step and its first error line).
    setup: Mutex<HashMap<PathBuf, Option<String>>>,
    /// The longest the Bundler step may take ([`BUNDLER_STEP_TIMEOUT`] unless
    /// [`SandboxedRunner::with_bundler_timeout`] says otherwise).
    bundler_timeout: Duration,
}

/// The step that makes a Bundler entry's gems available: run once per tree in the verifier's
/// sandbox, before the first check. `--no-cache` keeps Bundler from writing into the entry's
/// read-only `vendor/cache`.
pub const BUNDLER_STEP: &str = "bundle install --local";

/// Longest the Bundler step may take (native extensions compile in it).
pub const BUNDLER_STEP_TIMEOUT: Duration = Duration::from_secs(20 * 60);

/// What Bundler prints when the LANE's own `Gemfile` or `Gemfile.lock` is what it cannot
/// install (matched in any case, anywhere in the output, only for an exit that is not 126 or
/// 127 and not the sandbox's own exec failure):
///
/// - `could not find gem`: a locked gem is not in the entry's `vendor/cache` and not installed;
/// - `could not find compatible versions`: the resolver found no set of versions;
/// - `your bundle is locked to`: the lockfile pins a version the sources do not offer;
/// - `is not checked out` and `is not yet checked out`: a git or path source the lockfile
///   names is missing;
/// - `there was an error parsing`: the `Gemfile` or a gemspec raised or is not valid Ruby;
/// - `you are trying to install in deployment mode`: the lockfile does not match the `Gemfile`
///   under the frozen setting the verifier uses;
/// - `could not locate gemfile`: the lane has no `Gemfile`.
///
/// Everything else that fails, including a native extension that does not build (a missing
/// compiler or header), a Ruby older than the lockfile's `RUBY VERSION` and an exit nobody can
/// explain, is NOT in this list.
pub const LANE_BUNDLER_PATTERNS: &[&str] = &[
    "could not find gem",
    "could not find compatible versions",
    "your bundle is locked to",
    "is not checked out",
    "is not yet checked out",
    "there was an error parsing",
    "you are trying to install in deployment mode",
    "could not locate gemfile",
];

/// How the Bundler step ended, by cause.
#[derive(Debug, PartialEq, Eq)]
enum BundlerEnd {
    /// `bundle install --local` exited 0.
    Installed,
    /// The lane's own lockfile or `Gemfile` is what failed: a refutation. Carries the
    /// message that names the step and its first error line.
    Lane(String),
    /// The verifier's environment failed, or the cause cannot be told: infrastructure.
    Environment(String),
}

/// Judge how the Bundler step ended. The order is the point:
///
/// 1. A signal, a step that did not run and a timeout are the environment (or the lane's
///    `Gemfile` sleeping, which proves nothing about its gems).
/// 2. Exit 126 and 127 (the shell's "cannot execute" and "not found", also an `env` shim that
///    cannot find `ruby`) and the sandbox wrapper's own exec failure (`sandbox-exec: execvp()`,
///    `bwrap: execvp`, exit 71 on macOS) mean `bundle` never ran.
/// 3. Only then does a pattern of [`LANE_BUNDLER_PATTERNS`] make the failure the lane's.
/// 4. Any other non-zero exit is infrastructure too, with its first line. The default is right
///    because the two mistakes cost differently: a false infrastructure verdict re-runs the
///    proof (the director loses minutes), a false refutation discards good work (the lane is
///    thrown away for a missing compiler on the verifier's machine). When the cause cannot be
///    told, the cheaper mistake is the one to make.
fn classify_bundler_end(o: &CheckOutcome) -> BundlerEnd {
    if o.exit_status == 0 && matches!(o.end, CheckEnd::Exited { code: 0 }) {
        return BundlerEnd::Installed;
    }
    let line = cowproof_run::deps::bundle_failure(o.output.as_bytes());
    let code = match o.end {
        CheckEnd::Exited { code } => code,
        CheckEnd::Signaled { signal } => {
            return BundlerEnd::Environment(format!(
                "`{BUNDLER_STEP}` was killed by signal {signal}: {line}"
            ));
        }
        CheckEnd::NotRun => {
            return BundlerEnd::Environment(format!("`{BUNDLER_STEP}` did not run: {line}"));
        }
        CheckEnd::TimedOut => {
            return BundlerEnd::Environment(format!("`{BUNDLER_STEP}` timed out: {line}"));
        }
    };
    if code == 126 || code == 127 {
        return BundlerEnd::Environment(format!(
            "`{BUNDLER_STEP}` could not run (exit {code}: the program was not found or cannot be \
             executed): {line}"
        ));
    }
    let output = o.output.to_ascii_lowercase();
    if output.contains("sandbox-exec: execvp()") || output.contains("bwrap: execvp") {
        return BundlerEnd::Environment(format!(
            "`{BUNDLER_STEP}` could not start in the sandbox (exit {code}): {line}"
        ));
    }
    if LANE_BUNDLER_PATTERNS.iter().any(|p| output.contains(p)) {
        return BundlerEnd::Lane(format!("`{BUNDLER_STEP}` failed (exit {code}): {line}"));
    }
    BundlerEnd::Environment(format!(
        "`{BUNDLER_STEP}` failed (exit {code}) in a way nothing ties to the lane's lockfile, so \
         the cause is unknown: {line}"
    ))
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
        let cargo_bin = director_cargo_bin(&lane.real_home);
        Self {
            cargo_dir,
            cargo_bin,
            runtime_dirs: Vec::new(),
            lane,
            cache_dir,
            platform,
            deps_cache: None,
            port_base: None,
            executables: Vec::new(),
            groups: None,
            target_dir: None,
            link_target: false,
            bundle_exe: None,
            setup: Mutex::new(HashMap::new()),
            bundler_timeout: BUNDLER_STEP_TIMEOUT,
        }
    }

    /// The `PATH` every check gets ([`compose_path`]).
    fn path(&self) -> Result<String, InfraError> {
        compose_path(
            self.cargo_dir.as_deref(),
            self.cargo_bin.as_deref(),
            &self.runtime_dirs,
        )
    }

    /// Mount the fetched dependency cache at `deps_dir` (`<cache root>/deps/<key>`) into
    /// every check, read-only. The caller links it into the verifier's `CARGO_HOME`
    /// (`cowproof_run::link_dependency_cache`).
    pub fn with_dependency_cache(mut self, deps_dir: PathBuf) -> Self {
        self.deps_cache = Some(deps_dir);
        self
    }

    /// The `bundle` to install a Bundler entry's gems with: an absolute path is granted
    /// read-only and run by that path, with its directory on the `PATH` (so the `ruby` beside it
    /// is found); `None` runs the `bundle` on the checks' `PATH`. Only a tree whose dependency
    /// cache has a Bundler part runs it.
    pub fn with_bundle_exe(mut self, exe: Option<PathBuf>) -> Self {
        self.bundle_exe = exe.filter(|e| e.is_absolute());
        self
    }

    /// Limit the Bundler step to `timeout` instead of [`BUNDLER_STEP_TIMEOUT`]. A step that
    /// runs out is infrastructure ([`InfraError::Environment`]), whatever the limit; tests
    /// shorten it.
    pub fn with_bundler_timeout(mut self, timeout: Duration) -> Self {
        self.bundler_timeout = timeout;
        self
    }

    /// The Bundler step's failures so far, one line each (the step and its first error line):
    /// empty when it was not needed or succeeded. A caller that has run the checks reads this
    /// to end the lane, since every check of such a tree fails with the same text.
    pub fn setup_failures(&self) -> Vec<String> {
        let map = self.setup.lock().unwrap_or_else(|e| e.into_inner());
        let mut all: Vec<String> = map.values().flatten().cloned().collect();
        all.sort();
        all.dedup();
        all
    }

    /// Whether the Bundler step ran (and ended well or not) for at least one tree.
    pub fn setup_ran(&self) -> bool {
        !self
            .setup
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_empty()
    }

    /// Grant the director's runtime directories (`--runtime-dir`, already checked by
    /// `cowproof_run::runtime_dirs::resolve`) to every check: read-only, with their
    /// executables on `PATH` ahead of the system directories. A reference runtime installed
    /// outside the system directories (nvm, pyenv, Homebrew) is then found by the
    /// verifier's held-out capture instead of being skipped.
    pub fn with_runtime_dirs(mut self, dirs: Vec<RuntimeDir>) -> Self {
        self.runtime_dirs = dirs;
        self
    }

    /// Let every check read and run the executable at `exe`, read-only. A `kind: port` replay
    /// runs `cowproof pk port replay` inside the sandbox, and a `cowproof` installed under the
    /// hidden home (`~/.cargo/bin`) would otherwise not be reachable there. The path must be
    /// absolute and outside the lanes root; the sandbox refuses anything else.
    pub fn with_executable(mut self, exe: PathBuf) -> Self {
        self.executables.push(exe);
        self
    }

    /// List the process group of every check in `groups` while it runs. The caller that owns
    /// the set ends exactly those groups ([`GroupSet::end_all`]) when it is signalled, which
    /// is how `cowproof run` stops the proof without waiting for a check to finish.
    pub fn with_groups(mut self, groups: std::sync::Arc<GroupSet>) -> Self {
        self.groups = Some(groups);
        self
    }

    /// Point every command's `CARGO_TARGET_DIR` at `dir`: the verifier's private copy of its
    /// compile-cache seed ([`cowproof_run::verify_target`]). `dir` must be inside a directory the
    /// sandbox may write (the verifier's scratch), and it is the caller's to make. Without this
    /// the variable is not set and cargo builds in the tree's own `target/`.
    pub fn with_target_dir(mut self, dir: PathBuf) -> Self {
        self.target_dir = Some(dir);
        self
    }

    /// Also put the directory given to [`SandboxedRunner::with_target_dir`] at `<tree>/target`
    /// as a symlink before every command (`cowproof_run::link_target_dir`, replacing whatever
    /// stood there), so a check that runs `./target/debug/<name>` finds cargo's output where it
    /// always did. For the verifier's checks only, and only when a seed copy is in use.
    pub fn with_target_link(mut self) -> Self {
        self.link_target = true;
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

impl SandboxedRunner {
    /// Run `argv` in `tree` under `policy` with `path` as the `PATH`: the one place a sandboxed
    /// command is built and started, for a check and for the Bundler step alike.
    async fn run_sandboxed(
        &self,
        policy: &SandboxPolicy,
        tree: &Path,
        path: String,
        argv: Vec<String>,
        label: &str,
        timeout: Duration,
    ) -> Result<CheckOutcome, InfraError> {
        // On macOS, write the profile to a temp file outside the clone. It lives until
        // the command has finished.
        let profile_file = NamedTempFile::new()
            .map_err(|e| InfraError::SpawnError(format!("cannot create sandbox profile: {e}")))?;
        let profile_path = profile_file.path().to_path_buf();

        // Render the Seatbelt profile (macOS) or bubblewrap args (Linux).
        if self.platform == "darwin" {
            let profile_text = render_macos_profile(policy).map_err(|e| {
                InfraError::SpawnError(format!("sandbox profile render failed: {e}"))
            })?;
            std::fs::write(&profile_path, profile_text).map_err(|e| {
                InfraError::SpawnError(format!("cannot write sandbox profile: {e}"))
            })?;
        }

        let (sandbox_bin, sandbox_args) =
            sandbox_command(policy, &profile_path, &argv, &self.platform)
                .map_err(|e| InfraError::SpawnError(format!("sandbox_command failed: {e}")))?;

        // No credentials (D6): the check starts from an empty environment holding only
        // the explicit PATH and what the policy sets (the verifier's CARGO_HOME), never
        // the caller's environment, which may carry API keys.
        let mut env = vec![("PATH".to_string(), path)];
        policy.apply_env(&mut env);
        if let Some(dir) = &self.target_dir {
            let value = dir.to_string_lossy().into_owned();
            match env
                .iter_mut()
                .find(|(k, _)| k == cowproof_run::verify_target::TARGET_DIR_ENV)
            {
                Some(slot) => slot.1 = value,
                None => env.push((
                    cowproof_run::verify_target::TARGET_DIR_ENV.to_string(),
                    value,
                )),
            }
        }
        if let Some(port_base) = self.port_base {
            env.extend(cowproof_core::port_block_env(port_base));
        }

        let mut cmd = Command::new(&sandbox_bin);
        cmd.args(&sandbox_args)
            .current_dir(tree)
            .env_clear()
            .envs(env);
        run_with_timeout(cmd, label, timeout, self.groups.as_deref()).await
    }

    /// `bundle install --local --no-cache` in `tree`, once per tree (the result is kept):
    /// `None` when it succeeded, else the failure's one line. The command runs the lane's
    /// `Gemfile` and compiles native extensions, under the trust of the lane's own tests.
    async fn bundler_setup(
        &self,
        policy: &SandboxPolicy,
        tree: &Path,
        path: &str,
    ) -> Result<Option<String>, InfraError> {
        if let Some(done) = self
            .setup
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(tree)
        {
            return Ok(done.clone());
        }
        let program = match &self.bundle_exe {
            Some(exe) => exe.to_string_lossy().into_owned(),
            None => "bundle".to_string(),
        };
        let argv = vec![
            program,
            "install".to_string(),
            "--local".to_string(),
            "--no-cache".to_string(),
        ];
        let ran = self
            .run_sandboxed(
                policy,
                tree,
                path.to_string(),
                argv,
                BUNDLER_STEP,
                self.bundler_timeout,
            )
            .await;
        // Classified by cause (S-8): only a resolution error the lane's own `Gemfile` or
        // lockfile caused is the lane's failure, and is kept. Anything else is the verifier's
        // environment, or unknown, and is returned as infrastructure without being kept, so
        // a re-run starts the step again.
        let failure = match ran {
            Ok(o) => match classify_bundler_end(&o) {
                BundlerEnd::Installed => None,
                BundlerEnd::Lane(why) => Some(why),
                BundlerEnd::Environment(why) => return Err(InfraError::Environment(why)),
            },
            Err(InfraError::Timeout(_)) => {
                return Err(InfraError::Environment(format!(
                    "`{BUNDLER_STEP}` timed out after {}s",
                    self.bundler_timeout.as_secs_f64()
                )));
            }
            Err(InfraError::SpawnError(why)) => {
                return Err(InfraError::Environment(format!(
                    "`{BUNDLER_STEP}` could not start: {why}"
                )));
            }
            Err(e) => return Err(e),
        };
        self.setup
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(tree.to_path_buf(), failure.clone());
        Ok(failure)
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
        let mut path = self.path()?;
        // The rebuilt tree is the verifier's clone: it is the one writable tree, so
        // the policy is built around it, not around the lane's own clone.
        let mut lane = self.lane.clone();
        lane.clone = tree.to_path_buf();
        let mut policy =
            SandboxPolicy::verifier(&lane, &self.cache_dir).with_runtime_dirs(&self.runtime_dirs);
        let mut bundler = false;
        if let Some(deps) = &self.deps_cache {
            policy = policy.with_dependency_cache(deps);
            // The entry's npm install appears at `<tree>/node_modules` before every check
            // (a read-only mount behind a link), so each check starts from the trusted one.
            cowproof_run::link_npm_modules(deps, tree)
                .map_err(|e| InfraError::SpawnError(format!("node_modules link failed: {e:#}")))?;
            // The same for the Bundler part: its `.gem` files appear at `<tree>/vendor/cache`
            // and Bundler's settings are fixed (frozen, offline, its own scratch install path).
            if deps
                .join(cowproof_run::BUNDLER_ENTRY_DIR)
                .join(cowproof_run::BUNDLER_CACHE)
                .is_dir()
            {
                bundler = true;
                let scratch = self.cache_dir.join("bundler");
                for dir in cowproof_run::BUNDLER_SCRATCH_DIRS {
                    std::fs::create_dir_all(scratch.join(dir)).map_err(|e| {
                        InfraError::SpawnError(format!("cannot create the Bundler scratch: {e}"))
                    })?;
                }
                policy = policy.with_bundler(deps, &scratch);
                cowproof_run::link_vendor_cache(deps, tree).map_err(|e| {
                    InfraError::SpawnError(format!("vendor/cache link failed: {e:#}"))
                })?;
                if let Some(exe) = &self.bundle_exe {
                    policy.executables.push(exe.clone());
                    path = cowproof_run::deps::path_with_tool_dir(&path, Some(exe));
                }
            }
        }
        policy.executables.extend(self.executables.iter().cloned());
        if self.link_target
            && let Some(copy) = &self.target_dir
        {
            cowproof_run::link_target_dir(copy, tree)
                .map_err(|e| InfraError::SpawnError(format!("target link failed: {e:#}")))?;
        }

        // The gems are installed from the entry before the tree's first check; a step that
        // fails fails every check with its text, and the caller reads `setup_failures`.
        if bundler && let Some(failure) = self.bundler_setup(&policy, tree, &path).await? {
            return Ok(CheckOutcome {
                exit_status: 1,
                output: format!("bundler setup failed: {failure}\n"),
                attempts: 1,
                end: CheckEnd::Exited { code: 1 },
            });
        }

        self.run_sandboxed(
            &policy,
            tree,
            path,
            vec!["sh".to_string(), "-c".to_string(), command.to_string()],
            command,
            timeout,
        )
        .await
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

    fn group_tmp() -> tempfile::TempDir {
        tempfile::Builder::new()
            .prefix("cp-group-")
            .tempdir_in("/var/tmp")
            .unwrap()
    }

    /// A shell command that backgrounds a long sleep, records its pid in `pid` and then
    /// runs `rest`.
    fn with_grandchild(rest: &str) -> String {
        format!("sleep 300 & echo $! > pid; {rest}")
    }

    fn sh(tree: &Path, command: &str) -> Command {
        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg(command).current_dir(tree);
        cmd
    }

    async fn recorded_pid(tree: &Path) -> libc::pid_t {
        for _ in 0..200 {
            if let Some(pid) = std::fs::read_to_string(tree.join("pid"))
                .ok()
                .and_then(|t| t.trim().parse().ok())
            {
                return pid;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("the check never recorded its background pid");
    }

    /// A timeout with a grace: SIGTERM first, then SIGKILL; the grandchild goes too, even
    /// when the leader and the grandchild both ignore SIGTERM.
    #[tokio::test]
    async fn timeout_with_a_grace_ends_a_group_that_ignores_sigterm() {
        let tmp = group_tmp();
        let command = with_grandchild("trap '' TERM; while :; do sleep 1; done");
        let set = GroupSet::new();
        let start = Instant::now();
        let ran = run_in_group(
            sh(tmp.path(), &command),
            Duration::from_millis(500),
            Duration::from_millis(500),
            Some(&set),
        )
        .await
        .unwrap();
        assert!(matches!(ran.end, GroupEnd::TimedOut), "{ran:?}");
        assert!(start.elapsed() < Duration::from_secs(5));
        assert!(set.live().is_empty(), "the group is still listed");
        assert_process_gone(recorded_pid(tmp.path()).await);
    }

    /// The shell exits by itself and leaves the grandchild holding the output pipes: the
    /// call returns at once (not at the timeout) and the grandchild is gone.
    #[tokio::test]
    async fn a_leader_that_exits_takes_its_leftovers_with_it() {
        let tmp = group_tmp();
        let command = with_grandchild("echo done");
        let start = Instant::now();
        let ran = run_in_group(
            sh(tmp.path(), &command),
            Duration::from_secs(60),
            Duration::ZERO,
            None,
        )
        .await
        .unwrap();
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "{:?}",
            start.elapsed()
        );
        match ran.end {
            GroupEnd::Exited(status) => assert!(status.success()),
            other => panic!("{other:?}"),
        }
        assert_eq!(String::from_utf8_lossy(&ran.stdout).trim(), "done");
        assert_process_gone(recorded_pid(tmp.path()).await);
    }

    /// `end_all` ends exactly the listed groups, politely, while the call still runs.
    #[tokio::test]
    async fn end_all_ends_the_listed_groups_and_the_call_returns() {
        let tmp = group_tmp();
        let command = with_grandchild("sleep 300");
        let set = std::sync::Arc::new(GroupSet::new());
        let running = tokio::spawn({
            let (set, tree) = (set.clone(), tmp.path().to_path_buf());
            async move {
                run_in_group(
                    sh(&tree, &command),
                    Duration::from_secs(120),
                    Duration::from_secs(5),
                    Some(&set),
                )
                .await
            }
        });
        let pid = recorded_pid(tmp.path()).await;
        assert_eq!(set.live().len(), 1);
        let start = Instant::now();
        set.end_all(Duration::from_secs(5)).await;
        let ran = running.await.unwrap().unwrap();
        // The call was not ended by its own timeout, and the group was not waited out.
        assert!(matches!(ran.end, GroupEnd::Exited(_)), "{ran:?}");
        assert!(start.elapsed() < Duration::from_secs(5));
        assert!(set.live().is_empty());
        assert_process_gone(pid);
    }

    /// Dropping the future (the lane stopped; the task was aborted) SIGKILLs the group.
    #[tokio::test]
    async fn dropping_the_call_kills_the_group_and_delists_it() {
        let tmp = group_tmp();
        let command = with_grandchild("sleep 300");
        let set = std::sync::Arc::new(GroupSet::new());
        let running = tokio::spawn({
            let (set, tree) = (set.clone(), tmp.path().to_path_buf());
            async move {
                let _ = run_in_group(
                    sh(&tree, &command),
                    Duration::from_secs(120),
                    Duration::from_secs(5),
                    Some(&set),
                )
                .await;
            }
        });
        let pid = recorded_pid(tmp.path()).await;
        assert_eq!(set.live().len(), 1);
        running.abort();
        let _ = running.await;
        assert!(set.live().is_empty());
        assert_process_gone(pid);
    }

    /// A probe that outlives its limit is ended with everything it started, and reports the
    /// timeout rather than an exit.
    #[tokio::test]
    async fn a_probe_that_times_out_ends_its_whole_group() {
        let tmp = group_tmp();
        let command = with_grandchild("sleep 300");
        let ran = run_probe(sh(tmp.path(), &command), Duration::from_secs(2))
            .await
            .unwrap();
        assert!(matches!(ran.end, GroupEnd::TimedOut), "{ran:?}");
        assert_process_gone(recorded_pid(tmp.path()).await);
    }

    /// Dropping a probe's future (the preflight was abandoned) ends its group, not only the
    /// leader that `kill_on_drop` reaches.
    #[tokio::test]
    async fn dropping_a_probe_ends_its_whole_group() {
        let tmp = group_tmp();
        let command = with_grandchild("sleep 300");
        let running = tokio::spawn({
            let tree = tmp.path().to_path_buf();
            async move {
                let _ = run_probe(sh(&tree, &command), Duration::from_secs(120)).await;
            }
        });
        let pid = recorded_pid(tmp.path()).await;
        running.abort();
        let _ = running.await;
        assert_process_gone(pid);
    }

    /// The blocking probe works from inside a running tokio runtime (the host facts are
    /// collected from `main`, which is async) and ends the group on timeout.
    #[tokio::test]
    async fn a_blocking_probe_inside_a_runtime_ends_its_whole_group_on_timeout() {
        let tmp = group_tmp();
        let mut command = std::process::Command::new("sh");
        command
            .arg("-c")
            .arg(with_grandchild("sleep 300"))
            .current_dir(tmp.path());
        let ran = run_probe_blocking(command, Duration::from_secs(2)).unwrap();
        assert!(matches!(ran.end, GroupEnd::TimedOut), "{ran:?}");
        assert_process_gone(recorded_pid(tmp.path()).await);
    }

    /// The set signals only what it lists: a group started outside it is left alone.
    #[tokio::test]
    async fn end_all_leaves_a_group_it_did_not_start() {
        let tmp = group_tmp();
        let mut outsider = sh(tmp.path(), "sleep 300");
        outsider.process_group(0).kill_on_drop(true);
        let mut child = outsider.spawn().unwrap();
        let pgid = child.id().unwrap();
        GroupSet::new().end_all(Duration::from_millis(100)).await;
        assert_eq!(
            group_exists(pgid),
            Some(true),
            "an unlisted group was signalled"
        );
        kill_process_group(pgid);
        let _ = child.wait().await;
    }

    #[test]
    fn path_refuses_an_empty_entry() {
        match compose_path(Some(Path::new("")), None, &[]) {
            Err(InfraError::SpawnError(msg)) => assert!(msg.contains("empty"), "{msg}"),
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn path_refuses_a_relative_entry() {
        match compose_path(Some(Path::new("target/debug")), None, &[]) {
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
            compose_path(Some(Path::new("/opt/cargo/bin")), None, &[]).unwrap(),
            "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:/opt/cargo/bin"
        );
        assert_eq!(
            compose_path(None, None, &[]).unwrap(),
            "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
        );
    }

    /// The director's cargo bin directory (the rustup proxies) comes first, like on the
    /// director's own `PATH`, and is not listed twice when it is also the `cargo` dir.
    #[test]
    fn path_puts_the_directors_cargo_bin_first() {
        assert_eq!(
            compose_path(
                Some(Path::new("/opt/tc/bin")),
                Some(Path::new("/h/.cargo/bin")),
                &[]
            )
            .unwrap(),
            "/h/.cargo/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:/opt/tc/bin"
        );
        assert_eq!(
            compose_path(
                Some(Path::new("/h/.cargo/bin")),
                Some(Path::new("/h/.cargo/bin")),
                &[]
            )
            .unwrap(),
            "/h/.cargo/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
        );
        assert!(compose_path(None, Some(Path::new("rel/bin")), &[]).is_err());
    }

    /// The director's runtime directories sit after the cargo bin directory and ahead of the
    /// system directories, in the order given.
    #[test]
    fn path_puts_the_runtime_bins_between_the_cargo_bin_and_the_system_dirs() {
        let rt = |dir: &str| RuntimeDir {
            dir: PathBuf::from(dir),
            path_entry: PathBuf::from(format!("{dir}/bin")),
        };
        assert_eq!(
            compose_path(
                Some(Path::new("/opt/tc/bin")),
                Some(Path::new("/h/.cargo/bin")),
                &[rt("/n/node22"), rt("/p/py3")]
            )
            .unwrap(),
            "/h/.cargo/bin:/n/node22/bin:/p/py3/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:/opt/tc/bin"
        );
        let relative = RuntimeDir {
            dir: PathBuf::from("rel"),
            path_entry: PathBuf::from("rel/bin"),
        };
        assert!(compose_path(None, None, &[relative]).is_err());
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

    /// `with_target_dir` puts `CARGO_TARGET_DIR` in every command's environment, and without it
    /// the variable is not there (the sandbox starts from an empty environment).
    #[tokio::test]
    async fn the_target_dir_is_set_only_when_the_runner_is_given_one() {
        if !sandbox_available() {
            return;
        }
        let fx = SandboxFixture::new();
        let tree = &fx.lane.clone;
        let probe = "printf '%s' \"${CARGO_TARGET_DIR-unset}\"";

        let without = fx.runner().run(tree, probe, LIMIT).await.unwrap();
        assert_eq!(without.exit_status, 0, "{}", without.output);
        assert_eq!(without.output, "unset");

        let target = fx.lane.scratch.join("target");
        let with = fx
            .runner()
            .with_target_dir(target.clone())
            .run(tree, probe, LIMIT)
            .await
            .unwrap();
        assert_eq!(with.exit_status, 0, "{}", with.output);
        assert_eq!(with.output, target.to_string_lossy());
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

    /// A reference runtime the director names (`with_runtime_dirs`) under the hidden real home:
    /// a check finds it on `PATH`, runs it and reads its files; it cannot write to it; without
    /// the grant the same check finds nothing. Nothing else of the home comes with it.
    #[tokio::test]
    async fn sandboxed_runner_runs_a_granted_runtime_read_only() {
        if !sandbox_available() {
            return;
        }
        use std::os::unix::fs::PermissionsExt;
        let fx = SandboxFixture::new();
        let rt = fx.root.join("realhome/.nvm/node22");
        std::fs::create_dir_all(rt.join("bin")).unwrap();
        std::fs::create_dir_all(rt.join("lib")).unwrap();
        std::fs::write(rt.join("lib/data"), "runtime-data").unwrap();
        std::fs::write(fx.root.join("realhome/.nvm/secret"), "SIBLING").unwrap();
        let tool = rt.join("bin/fakenode");
        std::fs::write(
            &tool,
            format!(
                "#!/bin/sh\necho fakenode-v22 $(cat {}/lib/data)\n",
                rt.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755)).unwrap();
        let granted =
            cowproof_run::runtime_dirs::resolve(std::slice::from_ref(&rt), &fx.lane.real_home, &[])
                .unwrap();
        let tree = &fx.lane.clone;
        let sibling = fx.root.join("realhome/.nvm/secret");
        let probe = format!(
            "fakenode; (echo x >> {rt}/lib/data) 2>/dev/null && echo WROTE; \
             (echo x > {rt}/lib/new) 2>/dev/null && echo CREATED; cat {sib} 2>&1",
            rt = rt.display(),
            sib = sibling.display()
        );

        let without = fx.runner().run(tree, "fakenode", LIMIT).await.unwrap();
        assert_ne!(without.exit_status, 0, "{}", without.output);

        let with = fx
            .runner()
            .with_runtime_dirs(granted)
            .run(tree, &probe, LIMIT)
            .await
            .unwrap();
        assert!(
            with.output.contains("fakenode-v22 runtime-data"),
            "{}",
            with.output
        );
        assert!(!with.output.contains("WROTE"), "{}", with.output);
        assert!(!with.output.contains("CREATED"), "{}", with.output);
        assert!(!with.output.contains("SIBLING"), "{}", with.output);
        assert_eq!(
            std::fs::read_to_string(rt.join("lib/data")).unwrap(),
            "runtime-data"
        );
        assert!(!rt.join("lib/new").exists());
    }

    /// A rust toolchain reached through a rustup proxy finds its toolchains through
    /// `RUSTUP_HOME`. The verifier's check starts from an empty environment, so the policy
    /// must name the director's rustup home in it (here: the fake real home's `.rustup`,
    /// unless the director's own `RUSTUP_HOME` names another), and the directory is
    /// readable there.
    #[tokio::test]
    async fn sandboxed_runner_gives_the_check_the_directors_rustup_home() {
        if !sandbox_available() {
            return;
        }
        let fx = SandboxFixture::new();
        std::fs::create_dir_all(fx.root.join("realhome/.rustup")).unwrap();
        let expected = cowproof_run::RustupEnv::from_director_env(&fx.lane.real_home)
            .home
            .expect("the fake real home has a .rustup, so a rustup home resolves");

        let out = fx
            .runner()
            .run(
                &fx.lane.clone,
                "echo \"home=$RUSTUP_HOME\"; test -d \"$RUSTUP_HOME\" && echo readable",
                LIMIT,
            )
            .await
            .unwrap();
        assert_eq!(out.exit_status, 0, "{}", out.output);
        assert!(
            out.output
                .contains(&format!("home={}\n", expected.display())),
            "{}",
            out.output
        );
        assert!(out.output.contains("readable"), "{}", out.output);
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
        let expected = runner.path().unwrap();

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

/// The Bundler step, classified by cause (S-8). The fake `bundle` is a shell script run through
/// the real sandboxed runner; nothing here runs a real `bundle` or `gem`, or reaches a network.
#[cfg(test)]
mod bundler_step_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::time::Instant;

    const LIMIT: Duration = Duration::from_secs(60);

    fn outcome(end: CheckEnd, output: &str) -> CheckOutcome {
        CheckOutcome {
            exit_status: match end {
                CheckEnd::Exited { code } => code,
                _ => -1,
            },
            output: output.to_string(),
            attempts: 1,
            end,
        }
    }

    fn environment(end: CheckEnd, output: &str) -> String {
        match classify_bundler_end(&outcome(end, output)) {
            BundlerEnd::Environment(why) => why,
            other => panic!("expected the environment, got {other:?}"),
        }
    }

    #[test]
    fn a_resolution_error_of_the_lanes_own_lockfile_is_the_lanes_failure() {
        for (output, code) in [
            (
                "Could not find gem 'rack (= 2.0)' in locally installed gems.\n",
                7,
            ),
            (
                "Bundler could not find compatible versions for gem \"x\":\n",
                6,
            ),
            (
                "Your bundle is locked to rack (2.0.0), but that version could not be found.\n",
                7,
            ),
            (
                "The git source `https://g.example/x.git` is not yet checked out.\n",
                7,
            ),
            ("Fetching\nThe path `/x` is not checked out\n", 7),
            (
                "[!] There was an error parsing `Gemfile`: boom. Bundler cannot continue.\n",
                4,
            ),
            (
                "You are trying to install in deployment mode after changing your Gemfile.\n",
                16,
            ),
            ("Could not locate Gemfile\n", 10),
        ] {
            match classify_bundler_end(&outcome(CheckEnd::Exited { code }, output)) {
                BundlerEnd::Lane(why) => assert!(
                    why.contains(&format!("(exit {code})")) && why.contains(BUNDLER_STEP),
                    "{why}"
                ),
                other => panic!("{output:?} should be the lane's, got {other:?}"),
            }
        }
        assert_eq!(
            classify_bundler_end(&outcome(CheckEnd::Exited { code: 0 }, "")),
            BundlerEnd::Installed
        );
    }

    #[test]
    fn a_missing_program_a_signal_a_timeout_and_a_wrapper_failure_are_the_environment() {
        // The shell's "not executable" and "not found", even when the output also holds a
        // lane pattern: `bundle` never ran, so the output is not Bundler's.
        for code in [126, 127] {
            let why = environment(
                CheckEnd::Exited { code },
                "env: ruby: No such file or directory\nCould not find gem x\n",
            );
            assert!(why.contains(&format!("exit {code}")), "{why}");
        }
        let why = environment(CheckEnd::Signaled { signal: 9 }, "Installing\n");
        assert!(why.contains("signal 9"), "{why}");
        assert!(environment(CheckEnd::TimedOut, "").contains("timed out"));
        assert!(environment(CheckEnd::NotRun, "").contains("did not run"));
        let why = environment(
            CheckEnd::Exited { code: 71 },
            "sandbox-exec: execvp() of '/x/bundle' failed: No such file or directory\n",
        );
        assert!(why.contains("could not start in the sandbox"), "{why}");
        let why = environment(
            CheckEnd::Exited { code: 1 },
            "bwrap: execvp /x/bundle: No such file or directory\n",
        );
        assert!(why.contains("could not start in the sandbox"), "{why}");
    }

    #[test]
    fn an_unexplained_failure_is_the_environment_and_a_missing_compiler_is_not_the_lanes() {
        let why = environment(CheckEnd::Exited { code: 1 }, "something odd\n");
        assert!(
            why.contains("(exit 1)")
                && why.contains("cause is unknown")
                && why.contains("something odd"),
            "{why}"
        );
        // A native extension that does not build, here for want of a compiler on the verifier.
        let why = environment(
            CheckEnd::Exited { code: 5 },
            "An error occurred while installing x (1.0), and Bundler cannot continue.\nmake: cc: not found\n",
        );
        assert!(
            why.contains("(exit 5)") && why.contains("An error occurred"),
            "{why}"
        );
    }

    #[test]
    fn the_failure_line_is_escaped_and_cut_whatever_the_cause() {
        let output = format!("\u{1b}[2J\u{9b}31m{}\n", "z".repeat(10 * 1024));
        let why = environment(CheckEnd::Exited { code: 1 }, &output);
        assert!(!why.chars().any(char::is_control), "{why:?}");
        assert!(why.len() < 1024, "{}", why.len());
    }

    /// A runner whose verifier has a Bundler entry and a fake `bundle` that is `script`
    /// (or, with `None`, a path where no program exists).
    fn runner_with_bundle(fx: &SandboxFixture, script: Option<&str>) -> SandboxedRunner {
        let deps = fx.root.join("deps/entry");
        std::fs::create_dir_all(deps.join("bundler/cache")).unwrap();
        let bin = fx.root.join("fakebin");
        std::fs::create_dir_all(&bin).unwrap();
        let exe = bin.join("bundle");
        if let Some(script) = script {
            std::fs::write(&exe, format!("#!/bin/sh\n{script}\n")).unwrap();
            std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        fx.runner()
            .with_dependency_cache(deps)
            .with_bundle_exe(Some(exe))
    }

    async fn setup_error(runner: &SandboxedRunner, fx: &SandboxFixture) -> String {
        match runner.run(&fx.lane.clone, "true", LIMIT).await {
            Err(InfraError::Environment(why)) => why,
            other => panic!("expected InfraError::Environment, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_bundle_that_is_not_there_is_infrastructure() {
        if !sandbox_available() {
            return;
        }
        let fx = SandboxFixture::new();
        let runner = runner_with_bundle(&fx, None);
        let why = setup_error(&runner, &fx).await;
        assert!(why.contains(BUNDLER_STEP), "{why}");
        assert!(runner.setup_failures().is_empty() && !runner.setup_ran());
    }

    #[tokio::test]
    async fn a_bundle_that_exits_127_is_infrastructure() {
        if !sandbox_available() {
            return;
        }
        let fx = SandboxFixture::new();
        let runner = runner_with_bundle(&fx, Some("echo 'env: ruby: not found' >&2; exit 127"));
        let why = setup_error(&runner, &fx).await;
        assert!(
            why.contains("exit 127") && why.contains("ruby: not found"),
            "{why}"
        );
        assert!(runner.setup_failures().is_empty());
    }

    #[tokio::test]
    async fn a_bundle_that_runs_past_its_limit_is_infrastructure_not_a_refutation() {
        if !sandbox_available() {
            return;
        }
        let fx = SandboxFixture::new();
        let runner = runner_with_bundle(&fx, Some("sleep 30"))
            .with_bundler_timeout(Duration::from_millis(500));
        let start = Instant::now();
        let why = setup_error(&runner, &fx).await;
        assert!(
            why.contains("timed out") && why.contains(BUNDLER_STEP),
            "{why}"
        );
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "{:?}",
            start.elapsed()
        );
        assert!(runner.setup_failures().is_empty());
    }

    #[tokio::test]
    async fn a_could_not_find_gem_exit_is_the_lanes_refutation_and_is_kept() {
        if !sandbox_available() {
            return;
        }
        let fx = SandboxFixture::new();
        let runner = runner_with_bundle(
            &fx,
            Some(
                "echo \"Could not find gem 'fake (= 1.0.0)' in locally installed gems.\" >&2; exit 7",
            ),
        );
        let outcome = runner.run(&fx.lane.clone, "true", LIMIT).await.unwrap();
        assert_eq!(outcome.exit_status, 1, "{}", outcome.output);
        let failures = runner.setup_failures();
        assert_eq!(failures.len(), 1, "{failures:?}");
        assert!(
            failures[0].contains("(exit 7)") && failures[0].contains("Could not find gem"),
            "{failures:?}"
        );
        assert!(runner.setup_ran());
    }

    #[tokio::test]
    async fn an_exit_1_without_a_known_pattern_is_infrastructure_with_its_first_line() {
        if !sandbox_available() {
            return;
        }
        let fx = SandboxFixture::new();
        let runner = runner_with_bundle(&fx, Some("echo 'it broke in a new way' >&2; exit 1"));
        let why = setup_error(&runner, &fx).await;
        assert!(
            why.contains("(exit 1)")
                && why.contains("it broke in a new way")
                && why.contains("unknown"),
            "{why}"
        );
        assert!(runner.setup_failures().is_empty());
    }
}
