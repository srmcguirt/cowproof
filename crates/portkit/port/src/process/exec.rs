//! Running a process case: the reference under `pk port exec`, a Rust port under `pk port wrap`.
//!
//! One case is one run: a fresh work directory with the root the process runs in (`cwd`,
//! `HOME=$ROOT/home`, `TMPDIR=$ROOT/tmp`), the shims first on `PATH`, a pinned environment
//! (nothing inherited), `umask 022`, and the network denied. What the process did is read back
//! as the envelope of [`super::envelope`].
//!
//! # Confinement
//!
//! The network is denied by the sandbox cowproof already builds for its own checks
//! ([`Host`] is implemented by `cowproof-cli` over `cowproof-run`'s policies: Seatbelt
//! `(deny network*)` on macOS, bubblewrap `--unshare-net` on Linux); there is no second one
//! here. Inside a sandbox that already exists (the verifier's, `COWPROOF_SANDBOXED=1`) a
//! second cannot be nested on macOS, and the run [inherits](Confinement::Inherited) it. Either
//! way a network probe runs first, in the same confinement the case will run in: it tries to
//! connect to a listener this process holds, and a connection that succeeds fails the run
//! ([`prove_network_denied`]). A capture that cannot show the network is gone is not made.
//!
//! # Determinism
//!
//! The environment is built, not inherited: `PATH` (shims first), `HOME`, `TMPDIR`, `TZ=UTC`,
//! `LANG=C.UTF-8`, `LC_ALL=C.UTF-8`, `PYTHONHASHSEED=0`, `NODE_OPTIONS=`, `PORTKIT_SRC`, then
//! the capture's `--env`, the case's `env` and the input's `env`, later winning. A capture runs
//! each case more than once in separate roots and refuses a case whose runs differ after the
//! declared path substitution, naming the first field that differs.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use serde_json::{json, Value};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

use portkit_core::{diff, DiffOptions, Error, Result};

use super::{envelope, normalized_for, shim, PathNormaliser, ProcessInput, Root, ROOT_TOKENS};
use crate::capture::{CaptureFailure, CaptureReport, CapturedCase};
use crate::fixture::{load_cases, Fixture};

/// Set in the environment of a process that already runs inside a cowproof sandbox.
pub const SANDBOXED_ENV: &str = "COWPROOF_SANDBOXED";

/// The most bytes of stdout, and of stderr, one run may produce.
pub const MAX_OUTPUT: usize = 1 << 20;

/// How many times a capture runs a case by default, in separate roots.
pub const DEFAULT_REPEAT: usize = 2;

// ---- the sandbox host ----------------------------------------------------------------------

/// What the sandbox needs to know about one run.
#[derive(Debug)]
pub struct WrapRequest<'a> {
    /// The run's work directory (the parent of everything below).
    pub work: &'a Path,
    /// Directories the process may write.
    pub rw: Vec<PathBuf>,
    /// Directories the process may read beyond what the system gives every process.
    pub ro: Vec<PathBuf>,
    /// Executable files it must be able to run (the harness binary, for the shims).
    pub executables: Vec<PathBuf>,
    /// The command to run.
    pub argv: &'a [String],
}

/// A sandbox provider: wraps a command so it runs with the network denied and its writes
/// confined, and can end a process group. Implemented once, over cowproof's own policies.
pub trait Host: Send + Sync {
    /// The full command line that runs `req.argv` confined: launcher first.
    fn wrap(&self, req: &WrapRequest<'_>) -> std::result::Result<Vec<String>, String>;
    /// End every process of the group `pgid` (a run that timed out).
    fn kill_group(&self, pgid: u32);
    /// What the confinement is, for messages (`sandbox-exec, network denied`).
    fn describe(&self) -> String;
}

static HOST: OnceLock<Arc<dyn Host>> = OnceLock::new();
static INVOCATION: OnceLock<Vec<String>> = OnceLock::new();

/// Install the sandbox provider for this process. The first install wins.
pub fn install_host(host: Arc<dyn Host>) {
    let _ = HOST.set(host);
}

/// The installed provider.
pub fn installed_host() -> Option<Arc<dyn Host>> {
    HOST.get().cloned()
}

/// Say how this binary is invoked, so the shims can call it again: `[pk]` or
/// `[cowproof, pk]`. The first call wins; the default is the current executable alone.
pub fn set_invocation(command: Vec<String>) {
    let _ = INVOCATION.set(command);
}

/// The command that runs this binary's `pk` tree.
pub fn invocation() -> Vec<String> {
    INVOCATION.get().cloned().unwrap_or_else(|| {
        vec![std::env::current_exe()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| "pk".to_string())]
    })
}

/// How a run is confined.
#[derive(Clone)]
pub enum Confinement {
    /// Wrapped by the [`Host`]'s sandbox.
    Host(Arc<dyn Host>),
    /// The caller is already inside a sandbox: run as we are, and prove the network is gone.
    Inherited,
    /// No confinement and no proof. For the library's own tests; the command line never
    /// offers it.
    Unconfined,
}

impl std::fmt::Debug for Confinement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Confinement::Host(host) => write!(f, "Host({})", host.describe()),
            Confinement::Inherited => f.write_str("Inherited"),
            Confinement::Unconfined => f.write_str("Unconfined"),
        }
    }
}

/// The `--sandbox` choices.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxMode {
    /// Inherit inside a cowproof sandbox (`COWPROOF_SANDBOXED=1`), else use the host's own.
    Auto,
    /// Use the host's own sandbox; refuse to run without one.
    Own,
    /// The caller sandboxes this process (and the probe will say whether it does).
    Inherited,
}

/// Resolve a `--sandbox` choice to a confinement.
pub fn confinement_for(mode: SandboxMode) -> std::result::Result<Confinement, String> {
    let inside = std::env::var(SANDBOXED_ENV).is_ok_and(|v| v == "1");
    match mode {
        SandboxMode::Inherited => Ok(Confinement::Inherited),
        SandboxMode::Auto if inside => Ok(Confinement::Inherited),
        SandboxMode::Auto | SandboxMode::Own => installed_host().map(Confinement::Host).ok_or_else(|| {
            "this build has no sandbox to run a reference in; use `cowproof pk port ...`, or run it \
             inside a sandbox with --sandbox inherited"
                .to_string()
        }),
    }
}

// ---- configuration -------------------------------------------------------------------------

/// How to run a process case.
#[derive(Clone, Debug)]
pub struct ExecConfig {
    /// The command line, a shell fragment the case's `argv` is appended to as `"$@"`.
    /// `PORTKIT_SRC` is set to [`src`](Self::src) for it.
    pub command: String,
    /// The directory the reference lives in. Granted read-only to the sandbox.
    pub src: PathBuf,
    /// Variables for every case, on top of the pinned environment.
    pub env: Vec<(String, String)>,
    /// `PATH` after the shims.
    pub path: String,
    /// The declared `path_roots` (`$ROOT`, `$HOME`, `$TMP`, `$SRC`).
    pub path_roots: Vec<String>,
    pub confinement: Confinement,
    /// Where work directories are made.
    pub work_parent: PathBuf,
    /// The longest one run may take.
    pub timeout: Duration,
    /// Keep work directories (for looking at what a run did).
    pub keep_work: bool,
}

impl ExecConfig {
    pub fn new(
        command: impl Into<String>,
        src: impl Into<PathBuf>,
        confinement: Confinement,
    ) -> Self {
        Self {
            command: command.into(),
            src: src.into(),
            env: Vec::new(),
            path: "/usr/bin:/bin".to_string(),
            path_roots: Vec::new(),
            confinement,
            work_parent: default_work_parent(),
            timeout: Duration::from_secs(60),
            keep_work: false,
        }
    }

    /// Check what can be checked before a run.
    pub fn validate(&self) -> std::result::Result<(), String> {
        if self.command.trim().is_empty() {
            return Err("the command is empty".into());
        }
        for root in &self.path_roots {
            if !ROOT_TOKENS.contains(&root.as_str()) {
                return Err(format!(
                    "unknown path root `{root}` (known: {})",
                    ROOT_TOKENS.join(", ")
                ));
            }
        }
        if !self.src.is_absolute() {
            return Err("src must be an absolute path".into());
        }
        Ok(())
    }
}

/// Where work directories go when nothing says: `$TMPDIR`; with none set on Linux, `/var/tmp`
/// rather than `/tmp`, because a bubblewrap sandbox gives a process an empty `/tmp` of its own
/// and a work directory is better not to sit under it.
fn default_work_parent() -> PathBuf {
    let set = std::env::var_os("TMPDIR").is_some_and(|t| !t.is_empty());
    if !set && cfg!(target_os = "linux") && Path::new("/var/tmp").is_dir() {
        return PathBuf::from("/var/tmp");
    }
    std::env::temp_dir()
}

/// What one run produced.
#[derive(Debug, Clone)]
pub struct RunOutput {
    /// The envelope.
    pub envelope: Value,
    /// Calls no scripted response answered (`program argv...`).
    pub unscripted: Vec<String>,
    /// The `date` shim ran with no `PORTKIT_NOW`.
    pub clock_unpinned: bool,
}

// ---- the work directory --------------------------------------------------------------------

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct WorkDir {
    path: PathBuf,
    keep: bool,
}

impl WorkDir {
    fn create(parent: &Path, keep: bool) -> io::Result<Self> {
        fs::create_dir_all(parent)?;
        let parent = parent.canonicalize()?;
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = parent.join(format!("pk-exec-{}-{nanos:x}-{n}", std::process::id()));
        fs::create_dir(&path)?;
        Ok(Self { path, keep })
    }
}

impl Drop for WorkDir {
    fn drop(&mut self) {
        if !self.keep {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

// ---- running one process -------------------------------------------------------------------

struct Finished {
    code: Option<i32>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

async fn run_process(
    argv: &[String],
    env: &[(String, String)],
    cwd: &Path,
    stdin: Vec<u8>,
    timeout: Duration,
    host: Option<&Arc<dyn Host>>,
) -> Result<Finished> {
    let (program, args) = argv
        .split_first()
        .ok_or_else(|| Error::other("an empty command line"))?;
    let mut command = Command::new(program);
    command
        .args(args)
        .env_clear()
        .envs(env.iter().map(|(k, v)| (k, v)))
        .current_dir(cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .kill_on_drop(true);
    // The reference may be a script written a moment ago (a shim): ETXTBSY is retried.
    let mut child = portkit_core::spawn::spawn_async(&mut command)
        .await
        .map_err(|e| Error::other(format!("could not start `{program}`: {e}")))?;
    let pgid = child.id();

    let mut child_stdin = child.stdin.take().expect("piped");
    let mut writer = tokio::spawn(async move {
        // A process that does not read its stdin closes it; a broken pipe is its answer.
        let _ = child_stdin.write_all(&stdin).await;
        let _ = child_stdin.shutdown().await;
    });
    let mut out = child.stdout.take().expect("piped");
    let mut err = child.stderr.take().expect("piped");
    let mut read_out = tokio::spawn(async move { read_capped(&mut out).await });
    let mut read_err = tokio::spawn(async move { read_capped(&mut err).await });

    // One budget for the process and for its pipes: a background job that keeps stdout open
    // after the shell has gone must not hold the run past the limit.
    let collected = tokio::time::timeout(timeout, async {
        let status = child
            .wait()
            .await
            .map_err(|e| Error::other(format!("waiting for `{program}`: {e}")))?;
        let _ = (&mut writer).await;
        let stdout = (&mut read_out)
            .await
            .map_err(|e| Error::other(e.to_string()))?
            .map_err(|e| Error::other(format!("reading stdout: {e}")))?;
        let stderr = (&mut read_err)
            .await
            .map_err(|e| Error::other(e.to_string()))?
            .map_err(|e| Error::other(format!("reading stderr: {e}")))?;
        Ok::<_, Error>((status, stdout, stderr))
    })
    .await;
    let (status, stdout, stderr) = match collected {
        Ok(done) => done?,
        Err(_) => {
            if let (Some(host), Some(pgid)) = (host, pgid) {
                host.kill_group(pgid);
            }
            let _ = child.start_kill();
            let _ = child.wait().await;
            writer.abort();
            read_out.abort();
            read_err.abort();
            return Err(Error::other(format!(
                "timed out after {}s: {}",
                timeout.as_secs(),
                args.last().map(String::as_str).unwrap_or(program)
            )));
        }
    };
    if stdout.len() > MAX_OUTPUT || stderr.len() > MAX_OUTPUT {
        return Err(Error::other(format!(
            "the process wrote more than {MAX_OUTPUT} bytes to stdout or stderr"
        )));
    }
    Ok(Finished {
        code: status.code(),
        stdout,
        stderr,
    })
}

async fn read_capped<R: tokio::io::AsyncRead + Unpin>(reader: &mut R) -> io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    // One byte past the limit says it was exceeded without holding an unbounded output.
    reader
        .take(MAX_OUTPUT as u64 + 1)
        .read_to_end(&mut buf)
        .await?;
    // Drain the rest so the process is not blocked on a full pipe while it finishes.
    let mut sink = [0u8; 8192];
    while reader.read(&mut sink).await? > 0 {}
    Ok(buf)
}

// ---- the network probe ---------------------------------------------------------------------

/// The network interfaces other than loopback this process can see, from `/proc/net/dev`
/// (Linux; `/proc` is the namespace's own inside a sandbox, where `/sys` is not). `None` where
/// that cannot be read.
fn external_interfaces() -> Option<Vec<String>> {
    let text = fs::read_to_string("/proc/net/dev").ok()?;
    Some(
        text.lines()
            .skip(2)
            .filter_map(|l| l.split_once(':').map(|(name, _)| name.trim().to_string()))
            .filter(|name| name != "lo")
            .collect(),
    )
}

/// What `pk port net-probe <addr>` does, run inside the confinement under test: try to connect
/// to `addr`, and on Linux look for an interface that is not loopback. Prints `denied` when
/// neither finds a way out, `connected` when the connection was made, `reachable: eth0 ..` when
/// the namespace has a way out.
pub fn net_probe(addr: &str) -> i32 {
    use std::net::{SocketAddr, TcpStream};
    let outcome = addr
        .parse::<SocketAddr>()
        .map_err(|e| format!("not an address: {e}"))
        .and_then(|a| {
            TcpStream::connect_timeout(&a, Duration::from_secs(3)).map_err(|e| e.to_string())
        });
    if outcome.is_ok() {
        println!("connected");
        return 0;
    }
    if let Err(why) = &outcome {
        eprintln!("net-probe: {why}");
    }
    match external_interfaces() {
        Some(names) if !names.is_empty() => println!("reachable: {}", names.join(" ")),
        _ => println!("denied"),
    }
    0
}

/// The proof for a process that is already inside a sandbox: it cannot hold a listener of its
/// own to test against (Seatbelt denies the bind; a bubblewrap namespace has a loopback of its
/// own), so it looks at what the sandbox leaves. macOS: binding a socket is refused. Linux: no
/// interface but loopback in the namespace. Anything else is not shown.
fn prove_inherited() -> Result<()> {
    if cfg!(target_os = "macos") {
        return match std::net::TcpListener::bind("127.0.0.1:0") {
            Ok(_) => Err(Error::other(
                "the network is NOT denied: this process can open a socket (it is not inside a sandbox that denies the network)",
            )),
            Err(_) => Ok(()),
        };
    }
    if cfg!(target_os = "linux") {
        return match external_interfaces() {
            Some(names) if names.is_empty() => Ok(()),
            Some(names) => Err(Error::other(format!(
                "the network is NOT denied: this process can see {} (it is not inside a sandbox with its own network namespace)",
                names.join(", ")
            ))),
            None => Err(Error::other(
                "the network cannot be shown to be denied: /proc/net/dev is not readable",
            )),
        };
    }
    Err(Error::other(
        "the network cannot be shown to be denied on this platform",
    ))
}

/// Show that a process run under `cfg`'s confinement cannot reach the network. With the host's
/// sandbox, a listener on `127.0.0.1` is held here and a probe run the way a case is run tries
/// to connect to it (and on Linux looks for an interface other than loopback). Inside an
/// existing sandbox the process looks at what it can do ([`prove_inherited`]). Fails if the
/// network was reachable, or if the probe could not run at all: a confinement that cannot be
/// shown to hold is not assumed to.
pub async fn prove_network_denied(cfg: &ExecConfig) -> Result<()> {
    let host = match &cfg.confinement {
        Confinement::Unconfined => return Ok(()),
        Confinement::Inherited => return prove_inherited(),
        Confinement::Host(host) => host.clone(),
    };
    let listener = std::net::TcpListener::bind("127.0.0.1:0")
        .map_err(|e| Error::other(format!("network probe: cannot listen on 127.0.0.1: {e}")))?;
    listener
        .set_nonblocking(true)
        .map_err(|e| Error::other(e.to_string()))?;
    let addr = listener
        .local_addr()
        .map_err(|e| Error::other(e.to_string()))?;

    let work = WorkDir::create(&cfg.work_parent, false)?;
    let scratch = work.path.join("scratch");
    fs::create_dir_all(&scratch)?;
    let mut argv = invocation();
    argv.extend([
        "port".to_string(),
        "net-probe".to_string(),
        addr.to_string(),
    ]);
    let executables = vec![PathBuf::from(&argv[0])];
    let full = host
        .wrap(&WrapRequest {
            work: &work.path,
            rw: vec![scratch.clone()],
            ro: vec![],
            executables,
            argv: &argv,
        })
        .map_err(|e| Error::other(format!("network probe: cannot build the sandbox: {e}")))?;
    let env = vec![
        ("PATH".to_string(), cfg.path.clone()),
        ("HOME".to_string(), scratch.to_string_lossy().into_owned()),
    ];
    let finished = run_process(
        &full,
        &env,
        &scratch,
        Vec::new(),
        Duration::from_secs(20),
        Some(&host),
    )
    .await
    .map_err(|e| Error::other(format!("network probe could not run: {e}")))?;

    match listener.accept() {
        Ok(_) => {
            return Err(Error::other(
                "the network is NOT denied: a process in the sandbox connected to a listener on 127.0.0.1",
            ))
        }
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
        Err(e) => return Err(Error::other(format!("network probe: listener: {e}"))),
    }
    let said = String::from_utf8_lossy(&finished.stdout);
    match said.trim() {
        "denied" => Ok(()),
        "connected" => Err(Error::other(
            "the network is NOT denied: a process in the sandbox connected to a listener on 127.0.0.1",
        )),
        reachable if reachable.starts_with("reachable:") => Err(Error::other(format!(
            "the network is NOT denied: the sandbox has {}",
            reachable.trim_start_matches("reachable:").trim()
        ))),
        other => Err(Error::other(format!(
            "network probe: the probe neither connected nor was refused (exit {:?}, said {:?}, stderr {:?}); \
             the confinement cannot be shown to hold",
            finished.code,
            other,
            String::from_utf8_lossy(&finished.stderr).trim()
        ))),
    }
}

// ---- one case ------------------------------------------------------------------------------

/// Run `input` once. `case_env` is the case's capture-time `env` (below the input's own).
pub async fn run_once(
    cfg: &ExecConfig,
    input: &ProcessInput,
    case_env: &BTreeMap<String, String>,
) -> Result<RunOutput> {
    cfg.validate().map_err(Error::other)?;
    let work = WorkDir::create(&cfg.work_parent, cfg.keep_work)?;
    let root = Root::materialise(&work.path.join("root"), input)?;
    let shims_dir = work.path.join("shims");
    let state = work.path.join("state");
    let scratch = work.path.join("scratch");
    fs::create_dir_all(&scratch)?;
    let invocation = invocation();
    shim::install(
        &shims_dir,
        &state,
        &invocation,
        &input.shims,
        &input.record_env,
    )?;
    let norm = PathNormaliser::new(&cfg.path_roots, root.path(), &cfg.src);

    // The environment is built, not inherited.
    let mut env: BTreeMap<String, String> = BTreeMap::new();
    let mut set = |k: &str, v: String| {
        env.insert(k.to_string(), v);
    };
    set("PATH", cfg.path.clone());
    set("HOME", root.home().to_string_lossy().into_owned());
    set("TMPDIR", root.tmp().to_string_lossy().into_owned());
    set("TZ", "UTC".into());
    set("LANG", "C.UTF-8".into());
    set("LC_ALL", "C.UTF-8".into());
    set("PYTHONHASHSEED", "0".into());
    set("NODE_OPTIONS", String::new());
    set("PORTKIT_SRC", cfg.src.to_string_lossy().into_owned());
    for (k, v) in &cfg.env {
        env.insert(k.clone(), v.clone());
    }
    for (k, v) in case_env.iter().chain(input.env.iter()) {
        env.insert(k.clone(), v.clone());
    }
    let base_path = env.get("PATH").cloned().unwrap_or_default();
    env.insert(
        "PATH".to_string(),
        format!("{}:{base_path}", shims_dir.to_string_lossy()),
    );
    let env: Vec<(String, String)> = env.into_iter().collect();

    let script = format!("umask 022; {} \"$@\"", cfg.command);
    let mut argv = vec![
        "/bin/sh".to_string(),
        "-c".to_string(),
        script,
        "portkit-ref".to_string(),
    ];
    argv.extend(input.argv.iter().cloned());

    let host = match &cfg.confinement {
        Confinement::Host(host) => Some(host.clone()),
        _ => None,
    };
    let full = match &host {
        Some(host) => {
            let mut executables = vec![PathBuf::from(&invocation[0])];
            executables.retain(|p| p.is_absolute());
            host.wrap(&WrapRequest {
                work: &work.path,
                rw: vec![root.path().to_path_buf(), scratch.clone(), state.clone()],
                ro: vec![shims_dir.clone(), cfg.src.clone()],
                executables,
                argv: &argv,
            })
            .map_err(|e| Error::other(format!("cannot build the sandbox: {e}")))?
        }
        None => argv,
    };

    let finished = run_process(
        &full,
        &env,
        root.path(),
        input.stdin.clone().into_bytes(),
        cfg.timeout,
        host.as_ref(),
    )
    .await?;
    let Some(code) = finished.code else {
        return Err(Error::other(
            "the process was ended by a signal, so there is no exit status to record",
        ));
    };
    let (files_after, deleted) = root.snapshot(&norm)?;
    let calls = shim::read_calls(&state)?;
    let (unscripted, clock_unpinned) = shim::read_flags(&state)?;
    Ok(RunOutput {
        envelope: envelope(
            code,
            &String::from_utf8_lossy(&finished.stdout),
            &String::from_utf8_lossy(&finished.stderr),
            files_after,
            &deleted,
            calls,
            &norm,
        ),
        unscripted,
        clock_unpinned,
    })
}

/// The first field where two envelopes differ, as a JSON Pointer, or `None` when they are equal.
pub fn first_difference(a: &Value, b: &Value) -> Option<String> {
    diff(a, b, &DiffOptions::exact())
        .into_iter()
        .next()
        .map(|d| d.path)
}

// ---- capture -------------------------------------------------------------------------------

/// Capture every case of `cases_path` through the process harness and write fixtures.
///
/// Each case runs `repeat` times in separate roots, and is refused if the runs differ after
/// the declared substitution, if the reference called a program the case did not script, if it
/// read an unpinned clock through `date`, if it failed on a case that was not marked
/// `expect_error`, or if it succeeded on one that was.
pub async fn capture_process(
    cases_path: &Path,
    out_root: &Path,
    cfg: &ExecConfig,
    repeat: usize,
    fail_fast: bool,
) -> Result<CaptureReport> {
    cfg.validate().map_err(Error::other)?;
    let cases = load_cases(cases_path)?;
    prove_network_denied(cfg).await?;

    let mut report = CaptureReport {
        captured: Vec::new(),
        failures: Vec::new(),
    };
    for (index, case) in cases.iter().enumerate() {
        let id = case
            .id
            .clone()
            .unwrap_or_else(|| format!("{:03}", index + 1));
        match capture_case(case, cfg, repeat.max(1)).await {
            Ok(expected) => {
                let fixture = Fixture {
                    tool: case.tool.clone(),
                    id: id.clone(),
                    input: case.input.clone(),
                    expected,
                    captured_at: OffsetDateTime::now_utc().format(&Rfc3339).ok(),
                    source: Some(format!(
                        "{} (pk port exec, {})",
                        cfg.command,
                        std::env::consts::OS
                    )),
                    note: case.note.clone(),
                    accepted: Vec::new(),
                    env: case.env.clone(),
                    expect_error: case.expect_error,
                    normalized: normalized_for(&cfg.path_roots),
                };
                let path = fixture.write(out_root)?;
                report.captured.push(CapturedCase {
                    tool: case.tool.clone(),
                    id,
                    path,
                });
            }
            Err(err) => {
                report.failures.push(CaptureFailure {
                    tool: case.tool.clone(),
                    id,
                    reason: err.to_string(),
                });
                if fail_fast {
                    break;
                }
            }
        }
    }
    Ok(report)
}

async fn capture_case(
    case: &crate::fixture::Case,
    cfg: &ExecConfig,
    repeat: usize,
) -> Result<Value> {
    let input = ProcessInput::parse(&case.input).map_err(Error::other)?;
    let mut first: Option<Value> = None;
    for run in 1..=repeat {
        let out = run_once(cfg, &input, &case.env).await?;
        if let Some(call) = out.unscripted.first() {
            return Err(Error::other(format!(
                "the reference called `{call}`, which the case's shims do not answer; script it in `shims`"
            )));
        }
        if out.clock_unpinned {
            return Err(Error::other(
                "the reference read the clock through `date` and PORTKIT_NOW is not set; pin it with env PORTKIT_NOW=<RFC 3339>",
            ));
        }
        match &first {
            None => first = Some(out.envelope),
            Some(one) => {
                if let Some(path) = first_difference(one, &out.envelope) {
                    return Err(Error::other(format!(
                        "not deterministic: run 1 and run {run} differ at {path:?}; \
                         declare the path roots it varies in (path_roots) or pin what it reads"
                    )));
                }
            }
        }
    }
    let envelope = first.expect("repeat is at least 1");
    let exit = envelope["exit"].as_i64().unwrap_or(0);
    if case.expect_error && exit == 0 {
        return Err(Error::other(
            "the case expects an error but the reference exited 0",
        ));
    }
    if !case.expect_error && exit != 0 {
        return Err(Error::other(format!(
            "the reference exited {exit}; mark the case `expect_error` to record a failure as its fixture"
        )));
    }
    Ok(envelope)
}

// ---- the port side -------------------------------------------------------------------------

/// Answer one plugin request (`{"tool": .., "input": ..}`) by running the port under `cfg`
/// once and returning its envelope: the Rust port's side of `pk port exec`.
pub async fn serve_request(cfg: &ExecConfig, request: &str) -> Result<Value> {
    cfg.validate().map_err(Error::other)?;
    let request: Value = serde_json::from_str(request)
        .map_err(|e| Error::other(format!("the request is not JSON: {e}")))?;
    let input = request
        .get("input")
        .ok_or_else(|| Error::other("the request has no `input`"))?;
    let input = ProcessInput::parse(input).map_err(Error::other)?;
    prove_network_denied(cfg).await?;
    Ok(run_once(cfg, &input, &BTreeMap::new()).await?.envelope)
}

/// The tool spec `pk port wrap --portkit-spec` prints.
pub fn wrap_spec(tool: &str) -> Value {
    json!({
        "name": tool,
        "description": format!("Runs the port of `{tool}` in the process harness and answers its envelope (exit, stdout, stderr, files_after, deleted, calls)."),
        "input_schema": {"type": "object"},
    })
}

/// Read all of stdin.
pub fn read_stdin() -> io::Result<String> {
    let mut text = String::new();
    io::stdin().lock().read_to_string(&mut text)?;
    Ok(text)
}

/// Write `value` and a newline to stdout.
pub fn print_json(value: &Value) -> io::Result<()> {
    let mut out = io::stdout().lock();
    out.write_all(value.to_string().as_bytes())?;
    out.write_all(b"\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("pk-exec-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir.canonicalize().unwrap()
    }

    fn cfg(command: &str, src: &Path, parent: &Path) -> ExecConfig {
        let mut cfg = ExecConfig::new(command, src, Confinement::Unconfined);
        cfg.work_parent = parent.to_path_buf();
        cfg
    }

    fn input(v: Value) -> ProcessInput {
        ProcessInput::parse(&v).unwrap()
    }

    #[tokio::test]
    async fn a_case_runs_in_its_root_with_a_built_environment() {
        let base = scratch("env");
        let mut c = cfg(
            "sh -c 'printf \"%s|%s|%s|%s|%s|%s\" \"$(pwd)\" \"$HOME\" \"$TMPDIR\" \"$TZ\" \"$FROM_CASE\" \"$PORTKIT_SRC\"; echo \"$CARGO_MANIFEST_DIR\" >&2'",
            &base,
            &base,
        );
        c.path_roots = vec!["$ROOT".into(), "$HOME".into(), "$TMP".into(), "$SRC".into()];
        // Cargo sets this for every test process; it must not reach the case.
        assert!(std::env::var_os("CARGO_MANIFEST_DIR").is_some());
        let out = run_once(
            &c,
            &input(json!({"env": {"FROM_CASE": "yes"}})),
            &BTreeMap::new(),
        )
        .await
        .unwrap();
        let e = &out.envelope;
        assert_eq!(e["exit"], 0);
        // cwd is the root, HOME and TMPDIR are inside it, the reference's directory is $SRC.
        assert_eq!(e["stdout"], "$ROOT|$HOME|$TMP|UTC|yes|$SRC");
        // Nothing of the caller's environment reaches the process.
        assert_eq!(e["stderr"], "\n");
        let _ = fs::remove_dir_all(&base);
    }

    #[tokio::test]
    async fn argv_stdin_files_and_their_effects_are_recorded() {
        let base = scratch("fx");
        let c = cfg(
            "sh -c 'read line; cat \"$1\" > out.txt; printf \"%s\" \"$line\"; rm gone.txt; exit 3' sh",
            &base,
            &base,
        );
        let out = run_once(
            &c,
            &input(json!({
                "argv": ["in.txt"],
                "stdin": "typed\n",
                "files": {"in.txt": "body\n", "gone.txt": "x"}
            })),
            &BTreeMap::new(),
        )
        .await
        .unwrap();
        let e = &out.envelope;
        assert_eq!(e["exit"], 3);
        assert_eq!(e["stdout"], "typed");
        assert_eq!(e["files_after"]["out.txt"]["content"], "body\n");
        assert_eq!(
            e["files_after"]["out.txt"]["mode"], 0o644,
            "umask 022 is pinned"
        );
        assert_eq!(e["deleted"], json!(["gone.txt"]));
        assert!(e["files_after"].get("gone.txt").is_none());
        let _ = fs::remove_dir_all(&base);
    }

    #[tokio::test]
    async fn the_precedence_is_pinned_then_capture_then_case_then_input() {
        let base = scratch("prec");
        let mut c = cfg(
            "sh -c 'printf \"%s,%s,%s\" \"$A\" \"$B\" \"$TZ\"'",
            &base,
            &base,
        );
        c.env = vec![
            ("A".into(), "capture".into()),
            ("B".into(), "capture".into()),
            ("TZ".into(), "Asia/Tokyo".into()),
        ];
        let case_env = BTreeMap::from([
            ("A".to_string(), "case".to_string()),
            ("B".to_string(), "case".to_string()),
        ]);
        let out = run_once(&c, &input(json!({"env": {"B": "input"}})), &case_env)
            .await
            .unwrap();
        assert_eq!(out.envelope["stdout"], "case,input,Asia/Tokyo");
        let _ = fs::remove_dir_all(&base);
    }

    #[tokio::test]
    async fn a_timeout_ends_the_run_with_an_error() {
        let base = scratch("timeout");
        let mut c = cfg("exec sleep 30 #", &base, &base);
        c.timeout = Duration::from_millis(300);
        let err = run_once(&c, &input(json!({})), &BTreeMap::new())
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("timed out"), "{err}");
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn the_config_is_checked() {
        let base = std::env::temp_dir();
        let mut c = cfg("true", &base, &base);
        assert!(c.validate().is_ok());
        c.path_roots = vec!["$ELSEWHERE".into()];
        assert!(c.validate().unwrap_err().contains("$ELSEWHERE"));
        c.path_roots.clear();
        c.command = "  ".into();
        assert!(c.validate().unwrap_err().contains("empty"));
        let relative = cfg("true", Path::new("rel"), &base);
        assert!(relative.validate().unwrap_err().contains("absolute"));
    }

    #[test]
    fn the_sandbox_choice_is_resolved() {
        // No host is installed in this test binary: `own` refuses, `inherited` is the caller's.
        assert!(confinement_for(SandboxMode::Own)
            .unwrap_err()
            .contains("no sandbox"));
        assert!(matches!(
            confinement_for(SandboxMode::Inherited).unwrap(),
            Confinement::Inherited
        ));
    }

    #[test]
    fn two_envelopes_that_differ_name_the_first_field() {
        let a = json!({"exit": 0, "files_after": {"a": {"sha256": "1"}}});
        let b = json!({"exit": 0, "files_after": {"a": {"sha256": "2"}}});
        assert_eq!(first_difference(&a, &a), None);
        assert_eq!(first_difference(&a, &b).unwrap(), "/files_after/a/sha256");
    }

    #[test]
    fn a_connection_probe_reports_what_it_could_do() {
        // Something listening: connected. Nothing listening: denied (refused counts).
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        // Always exit 0; what it says is on stdout (`connected`, `denied`, `reachable: ..`).
        assert_eq!(net_probe(&addr), 0);
        assert_eq!(net_probe("not an address"), 0);
    }
}
