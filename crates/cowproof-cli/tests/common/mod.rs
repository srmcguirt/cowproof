//! Shared pieces for the CLI tests that drive a whole lane: a fork lock, sandbox
//! availability, a real git repository, one shared copy of the `cowproof` and `pk` binaries
//! outside the home (per test process, not per test), a FAKE `claude`, and the MCP frames the fake sends to `cowproof lane-tools`.
//!
//! `tests/run.rs` keeps its own copies of these (another lane is editing it); new test
//! files use this module so there is one copy to move it to.

use serde_json::{Value, json};
use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;
use tempfile::TempDir;

pub const REAL_KEY: &str = "sk-test-real-xyz";

/// What the fake prints on stdout: a session, two turns, a result.
const FAKE_STREAM: &str = concat!(
    r#"{"type":"system","subtype":"init","session_id":"0a1b2c3d-1111-2222-3333-444455556666"}"#,
    "\n",
    r#"{"type":"assistant","message":{"id":"m1","usage":{"input_tokens":3,"output_tokens":5,"cache_read_input_tokens":0,"cache_creation_input_tokens":7}}}"#,
    "\n",
    r#"{"type":"assistant","message":{"id":"m2","usage":{"input_tokens":4,"output_tokens":6,"cache_read_input_tokens":7,"cache_creation_input_tokens":0}}}"#,
    "\n",
    r#"{"type":"result","subtype":"success","result":"done","num_turns":2}"#,
);

/// Linux refuses to exec a file some process holds open for writing (ETXTBSY), and a
/// fork on another test thread can inherit that handle. Writing executables and
/// forking both take this lock.
static FORK_LOCK: Mutex<()> = Mutex::new(());

pub fn fork_lock() -> std::sync::MutexGuard<'static, ()> {
    FORK_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// `Command::output` with the spawn under `FORK_LOCK`; only the fork is held.
pub fn output(cmd: &mut Command) -> Output {
    let child = {
        let _g = fork_lock();
        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
    };
    child.wait_with_output().unwrap()
}

/// Whether a sandbox can run here. With `COWPROOF_REQUIRE_SANDBOX=1` an unavailable
/// sandbox fails the test; otherwise the test skips.
pub fn sandbox_available() -> bool {
    if cfg!(target_os = "macos") {
        return true;
    }
    let probe = {
        let _g = fork_lock();
        Command::new("bwrap")
            .args(["--ro-bind", "/", "/", "true"])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
    };
    let reason = match probe.and_then(|c| c.wait_with_output()) {
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

/// `kill(-pgid, 0)` fails with ESRCH: no process is left in the process group `pgid`. A
/// permission error or an unanswerable pgid is not "gone".
#[allow(dead_code)] // `tests/host_agent.rs` and `tests/remote.rs` use it; the other test crates that share this module do not
pub fn group_gone(pgid: &str) -> bool {
    // kill(2), not the shell: dash's `kill` (Ubuntu's /bin/sh) rejects `--`, so a shell
    // probe reads every group as alive there.
    let pgid: u32 = pgid.parse().expect("a numeric pgid");
    cowproof_prove::runner::group_exists(pgid) == Some(false)
}

/// [`group_gone`], polled for at most `within`: a group whose leader has just been told to
/// end is not empty until the kernel has reaped every member, which a loaded host does late.
#[allow(dead_code)] // `tests/remote.rs` uses it; the other test crates that share this module do not
pub fn wait_group_gone(pgid: &str, within: std::time::Duration) -> bool {
    let deadline = std::time::Instant::now() + within;
    loop {
        if group_gone(pgid) {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

/// A signal by the name `kill` takes without its dash (`"KILL"`, `"TERM"`, `"INT"`, or `"0"`
/// for the existence probe), as its `libc` number. No test starts the `kill` program: Ubuntu's
/// procps `kill` keeps only the first digit of a negative id not preceded by `--`, so
/// `kill -KILL -1234` is `kill(-1, SIGKILL)`, which ends every process of the user. Every
/// signal here goes through `kill(2)` in `cowproof_prove::runner`, which refuses group 0 and 1.
#[allow(dead_code)] // each test crate that shares this module uses some of the helpers
pub fn signal_number(name: &str) -> libc::c_int {
    match name {
        "0" => 0,
        "HUP" => libc::SIGHUP,
        "INT" => libc::SIGINT,
        "KILL" => libc::SIGKILL,
        "TERM" => libc::SIGTERM,
        other => panic!("no signal named {other:?} in tests/common"),
    }
}

/// Send the named signal (see [`signal_number`]) to the one process `pid`. Whether `kill(2)`
/// accepted it; with `"0"` that is "the process exists and is ours to signal".
#[allow(dead_code)]
pub fn signal_pid(name: &str, pid: u32) -> bool {
    cowproof_prove::runner::signal_pid(pid, signal_number(name))
}

/// Send the named signal to every process in the group `pgid` (never 0 or 1: those are
/// refused, and the answer is false).
#[allow(dead_code)]
pub fn signal_group(name: &str, pgid: u32) -> bool {
    cowproof_prove::runner::signal_group(pgid, signal_number(name))
}

/// Whether the process `pid` exists (a zombie does): the system's own answer, `ESRCH` being no.
/// A pid it cannot be asked about is not alive.
#[allow(dead_code)]
pub fn pid_alive(pid: u32) -> bool {
    cowproof_prove::runner::pid_exists(pid) == Some(true)
}

/// Prefix of the per-process directory that holds the shared binaries.
const SHARED_BIN_PREFIX: &str = "cp-bin-";

/// The debug `cowproof` and `pk` (277 MB and 205 MB), copied once per test process to where a
/// sandbox can reach them. The build puts them under the home, which both sandboxes hide, so a
/// lane test runs a copy under `/var/tmp`. Copying them for every test saturated a small
/// container's disk during a workspace run.
///
/// `<dir>` is `/var/tmp/cp-bin-<pid>`: `<dir>/cowproof` and `<dir>/pk` (the runner finds `pk`
/// beside its own executable), and `<dir>/bare/cowproof`, a hard link to the same file with no
/// `pk` beside it, for tests of a runner that has none. Nothing here may be written to or
/// removed by a test: a test that needs to replace or remove a file takes its own directory of
/// links ([`link_binaries_into`]) and removes the name before it writes.
struct SharedBins {
    dir: PathBuf,
    cowproof: PathBuf,
    pk: PathBuf,
    bare_cowproof: PathBuf,
}

static SHARED_BINS: OnceLock<SharedBins> = OnceLock::new();

/// Bytes `fs::copy` has moved into the shared directory by this process (hard links add none).
static SHARED_BYTES_COPIED: AtomicU64 = AtomicU64::new(0);

fn shared_bins() -> &'static SharedBins {
    SHARED_BINS.get_or_init(install_shared_bins)
}

/// The shared `cowproof`, with `pk` beside it.
#[allow(dead_code)] // only the lane tests that include `common` copy the binaries
pub fn shared_cowproof() -> &'static Path {
    &shared_bins().cowproof
}

/// The shared `pk`, beside [`shared_cowproof`].
#[allow(dead_code)] // `tests/run.rs` is the one that wants it
pub fn shared_pk() -> &'static Path {
    &shared_bins().pk
}

/// The shared `cowproof` with no `pk` beside it, as an install of `cowproof` alone looks.
#[allow(dead_code)] // the lane tests that run a bare runner use it; the others do not
pub fn shared_cowproof_alone() -> &'static Path {
    &shared_bins().bare_cowproof
}

/// Bytes copied into the shared directory so far by this process.
#[allow(dead_code)] // reported by the helper itself; kept for a test that wants to assert it
pub fn shared_bytes_copied() -> u64 {
    SHARED_BYTES_COPIED.load(Ordering::SeqCst)
}

/// Remove the shared directory when the process exits. Statics are never dropped, so this is
/// an `atexit` handler; a process that is killed leaves its directory for the next run's
/// sweep.
extern "C" fn remove_shared_bins_at_exit() {
    if let Some(bins) = SHARED_BINS.get() {
        let _ = fs::remove_dir_all(&bins.dir);
    }
}

/// Remove the `cp-bin-<pid>` directories whose process is gone: a killed run's leftovers.
fn sweep_dead_shared_bins() {
    let Ok(entries) = fs::read_dir("/var/tmp") else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid) = name
            .to_str()
            .and_then(|n| n.strip_prefix(SHARED_BIN_PREFIX))
            .and_then(|n| n.parse::<u32>().ok())
        else {
            continue;
        };
        if cowproof_prove::runner::pid_exists(pid) == Some(false) {
            let _ = fs::remove_dir_all(entry.path());
        }
    }
}

/// Copy `src` to `dir/name` through a temporary name in the same directory and a rename, so
/// the name never shows a half-written file. The write holds `FORK_LOCK`: a fork on another
/// thread must not inherit the write handle (ETXTBSY on Linux).
fn publish_copy(src: &Path, dir: &Path, name: &str) -> PathBuf {
    let tmp = dir.join(format!(".{name}.tmp"));
    let dest = dir.join(name);
    {
        let _g = fork_lock();
        let bytes = fs::copy(src, &tmp).unwrap();
        SHARED_BYTES_COPIED.fetch_add(bytes, Ordering::SeqCst);
        fs::rename(&tmp, &dest).unwrap();
    }
    dest
}

/// Run an executable once (`--version`, whatever it answers), so its first-run cost (macOS
/// scans a never-run file for seconds) is paid here and not inside a clock the runner keeps.
/// Linux can still refuse the first exec with ETXTBSY if a fork on another thread inherited
/// the write handle (a spawn elsewhere in the test binary does not take [`fork_lock`]); retry
/// briefly. Once one run has started no writer is left.
fn warm_up_shared(exe: &Path) {
    let mut tries = 0;
    loop {
        let child = {
            let _g = fork_lock();
            Command::new(exe)
                .arg("--version")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
        };
        match child {
            Ok(mut child) => {
                let _ = child.wait();
                return;
            }
            Err(e) if e.kind() == std::io::ErrorKind::ExecutableFileBusy && tries < 200 => {
                tries += 1;
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(_) => return,
        }
    }
}

fn install_shared_bins() -> SharedBins {
    sweep_dead_shared_bins();
    let dir = PathBuf::from(format!(
        "/var/tmp/{SHARED_BIN_PREFIX}{}",
        std::process::id()
    ));
    // A directory of this pid is a dead process's, whose pid was reused.
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir(&dir).unwrap();
    let cowproof = publish_copy(Path::new(env!("CARGO_BIN_EXE_cowproof")), &dir, "cowproof");
    let pk = publish_copy(Path::new(env!("CARGO_BIN_EXE_pk")), &dir, "pk");
    let bare = dir.join("bare");
    fs::create_dir(&bare).unwrap();
    let bare_cowproof = link_or_copy(&cowproof, &bare.join("cowproof"));
    warm_up_shared(&cowproof);
    warm_up_shared(&pk);
    let bins = SharedBins {
        dir: dir.clone(),
        cowproof,
        pk,
        bare_cowproof,
    };
    // SAFETY: `atexit` takes a plain `extern "C" fn()` that lives for the whole process.
    unsafe {
        libc::atexit(remove_shared_bins_at_exit);
    }
    eprintln!(
        "cp-bin: {} bytes copied into {}",
        SHARED_BYTES_COPIED.load(Ordering::SeqCst),
        dir.display()
    );
    bins
}

/// A hard link at `dest` to `src` (no bytes written), else a copy when the two are on
/// different file systems.
fn link_or_copy(src: &Path, dest: &Path) -> PathBuf {
    if fs::hard_link(src, dest).is_err() {
        let bytes = {
            let _g = fork_lock();
            fs::copy(src, dest).unwrap()
        };
        SHARED_BYTES_COPIED.fetch_add(bytes, Ordering::SeqCst);
    }
    dest.to_path_buf()
}

/// Hard-link the shared `cowproof` and `pk` into `dir`, side by side, for a test that must
/// remove or replace one of them. Link names are the test's to unlink; its writes must
/// create a new file (remove the name first), never write through the link, which would
/// change the shared binary. Returns the `cowproof` and `pk` paths in `dir`.
#[allow(dead_code)] // `tests/run.rs` is the one that replaces `pk`
pub fn link_binaries_into(dir: &Path) -> (PathBuf, PathBuf) {
    fs::create_dir_all(dir).unwrap();
    (
        link_or_copy(shared_cowproof(), &dir.join("cowproof")),
        link_or_copy(shared_pk(), &dir.join("pk")),
    )
}

/// A temporary directory under `/var/tmp`: not `/tmp` (bwrap hides it) and not the home
/// (both sandboxes hide it).
pub fn var_tmp(prefix: &str) -> TempDir {
    tempfile::Builder::new()
        .prefix(prefix)
        .tempdir_in("/var/tmp")
        .unwrap()
}

/// A FAKE `npm` that succeeds. It records what it was given into the npm cache directory
/// the fetch names (`$npm_config_cache`, a directory of the cache entry being made, the only
/// place the fetch sandbox lets it write besides its scratch directory): `argv.txt` (one
/// argument per line), `env.txt` (its sorted environment), `npmrc.txt` (the `.npmrc` it was
/// given, if any) and `cwd.txt`. It installs `node_modules/fake-pkg/index.js` into its working
/// directory, as `npm ci` installs into the project.
#[allow(dead_code)] // `tests/npm_fetch.rs` and `tests/deps.rs` use it; the other test crates do not
pub const FAKE_NPM_OK: &str = r#"#!/bin/sh
printf '%s\n' "$@" > "$npm_config_cache/argv.txt"
env | sort > "$npm_config_cache/env.txt"
pwd > "$npm_config_cache/cwd.txt"
if [ -f .npmrc ]; then cat .npmrc > "$npm_config_cache/npmrc.txt"; fi
mkdir -p node_modules/fake-pkg
printf 'module.exports = 42;\n' > node_modules/fake-pkg/index.js
exit 0
"#;

/// A FAKE `npm` whose install fails the way a missing package does.
#[allow(dead_code)] // `tests/npm_fetch.rs` uses it; the other test crates do not
pub const FAKE_NPM_FAILS: &str = r#"#!/bin/sh
echo "npm WARN deprecated fake-pkg@1.0.0: for the test" >&2
echo "npm ERR! code E404" >&2
echo "npm ERR! 404 Not Found - GET https://registry.npmjs.org/fake-pkg" >&2
exit 1
"#;

/// A FAKE `npm` that must not be called: a run that reaches it is a cache miss.
#[allow(dead_code)] // `tests/npm_fetch.rs` uses it; the other test crates do not
pub const FAKE_NPM_MUST_NOT_RUN: &str = r#"#!/bin/sh
echo "npm ERR! the fake npm was called although the cache entry was complete" >&2
exit 1
"#;

/// A FAKE `yarn` or `pnpm` that succeeds, as [`FAKE_NPM_OK`] is for npm. It records into
/// the tool's own cache directory, named by `cache_var` (`YARN_CACHE_FOLDER` for yarn,
/// `npm_config_store_dir` for pnpm): `argv.txt`, `env.txt`, `cwd.txt`, and the configuration
/// files it was given (`npmrc.txt`, `yarnrc.txt`, `yarnrc_yml.txt`). It installs
/// `node_modules/fake-pkg/index.js` into its working directory.
#[allow(dead_code)] // `tests/npm_fetch.rs` uses it; the other test crates do not
pub fn fake_js_ok(cache_var: &str) -> String {
    format!(
        r#"#!/bin/sh
dir="${cache_var}"
printf '%s\n' "$@" > "$dir/argv.txt"
env | sort > "$dir/env.txt"
pwd > "$dir/cwd.txt"
if [ -f .npmrc ]; then cat .npmrc > "$dir/npmrc.txt"; fi
if [ -f .yarnrc ]; then cat .yarnrc > "$dir/yarnrc.txt"; fi
if [ -f .yarnrc.yml ]; then cat .yarnrc.yml > "$dir/yarnrc_yml.txt"; fi
mkdir -p node_modules/fake-pkg
printf 'module.exports = 42;\n' > node_modules/fake-pkg/index.js
exit 0
"#
    )
}

/// A FAKE `yarn` whose install fails the way a missing package does.
#[allow(dead_code)] // `tests/npm_fetch.rs` uses it; the other test crates do not
pub const FAKE_YARN_FAILS: &str = r#"#!/bin/sh
echo "warning fake-pkg@1.0.0: deprecated, for the test" >&2
echo "error Couldn't find package \"fake-pkg\" on the \"npm\" registry." >&2
echo "info Visit https://yarnpkg.com/en/docs/cli/install" >&2
exit 1
"#;

/// A FAKE `pnpm` whose install fails the way a missing package does.
#[allow(dead_code)] // `tests/npm_fetch.rs` uses it; the other test crates do not
pub const FAKE_PNPM_FAILS: &str = r#"#!/bin/sh
echo "Progress: resolved 1, reused 0, downloaded 0, added 0" >&2
echo " ERR_PNPM_FETCH_404  GET https://registry.npmjs.org/fake-pkg: Not Found - 404" >&2
exit 1
"#;

/// A FAKE `yarn` or `pnpm` that must not be called: a run that reaches it is a cache miss, or
/// a tree that should not have been installed at all.
#[allow(dead_code)] // `tests/npm_fetch.rs` uses it; the other test crates do not
pub const FAKE_JS_MUST_NOT_RUN: &str = r#"#!/bin/sh
echo "error the fake tool was called although nothing should have been installed" >&2
exit 1
"#;

/// Write an executable named `name` (`npm`, `yarn` or `pnpm`) with `body` into a new directory
/// under `/var/tmp` and return the directory (keep it alive) and the path of the script. Pass
/// the path to a lane as `COWPROOF_NPM`, `COWPROOF_YARN` or `COWPROOF_PNPM`, the way `CARGO`
/// names the cargo the verifier uses.
#[allow(dead_code)] // `tests/npm_fetch.rs` and `tests/deps.rs` use it; the other test crates do not
pub fn fake_tool(name: &str, body: &str) -> (TempDir, PathBuf) {
    let dir = var_tmp(&format!("cp-fake-{name}-"));
    let tool = dir.path().canonicalize().unwrap().join(name);
    {
        // Linux refuses to exec a file some process holds open for writing (ETXTBSY), and a
        // fork on another test thread can inherit that handle: write under the fork lock.
        let _g = fork_lock();
        fs::write(&tool, body).unwrap();
        fs::set_permissions(&tool, fs::Permissions::from_mode(0o755)).unwrap();
    }
    (dir, tool)
}

/// [`fake_tool`] for `npm`.
#[allow(dead_code)] // `tests/npm_fetch.rs` and `tests/deps.rs` use it; the other test crates do not
pub fn fake_npm(body: &str) -> (TempDir, PathBuf) {
    fake_tool("npm", body)
}

/// A held-out file in `dir` with one check, `held`, that runs only in the verifier.
#[allow(dead_code)] // the dependency-fetch tests use it; the other test crates do not
pub fn heldout(dir: &Path, command: &str) -> PathBuf {
    let path = dir.join("h.toml");
    fs::write(
        &path,
        format!("[[check]]\nid = \"held\"\ncommand = {command:?}\n"),
    )
    .unwrap();
    path
}

/// `cowproof run` of `lane` with the held-out file `heldout`, asserting its exit code.
#[allow(dead_code)] // the dependency-fetch tests use it; the other test crates do not
pub fn run_with(lane: &Lane, heldout: &Path, code: i32) -> Output {
    let out = lane.run(&[Path::new("--heldout"), heldout]);
    assert_eq!(
        out.status.code(),
        Some(code),
        "cowproof run:\n{}",
        text(&out)
    );
    out
}

/// The sealed capsule of `lane`.
#[allow(dead_code)] // the dependency-fetch tests use it; the other test crates do not
pub fn capsule(lane: &Lane) -> cowproof_prove::Capsule {
    cowproof_prove::Capsule::read(&lane.capsule_dir()).unwrap()
}

/// The dependency cache entry a capsule names, under the cache root `cache`.
#[allow(dead_code)] // the dependency-fetch tests use it; the other test crates do not
pub fn entry(cache: &Path, capsule: &cowproof_prove::Capsule) -> PathBuf {
    cache
        .join("deps")
        .join(capsule.dependency_cache_key.as_ref().unwrap())
}

/// Every regular file under `dir`, links not followed.
#[allow(dead_code)] // the dependency-fetch tests use it; the other test crates do not
pub fn files_under(dir: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(d) = pending.pop() {
        for e in fs::read_dir(&d).unwrap().flatten() {
            let kind = e.file_type().unwrap();
            if kind.is_dir() {
                pending.push(e.path());
            } else if kind.is_file() {
                found.push(e.path());
            }
        }
    }
    found
}

pub fn git(repo: &Path, args: &[&str]) {
    let out = output(
        Command::new("git")
            .args(["-C", repo.to_str().unwrap()])
            .args(args),
    );
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Shell that feeds an MCP session to `cowproof lane-tools` on the lane's own socket
/// and saves the frames to `$rec/<out>`. `calls` are `(id, tool, arguments)`.
pub fn mcp_session(out: &str, calls: &[(u64, &str, Value)]) -> String {
    let mut lines = vec![
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"fake","version":"0"}}}),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    ];
    for (id, tool, arguments) in calls {
        lines.push(json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":tool,"arguments":arguments}}));
    }
    let printed: String = lines
        .iter()
        .map(|l| format!("printf '%s\\n' '{l}'\n"))
        .collect();
    format!(
        "{{\n{printed}}} | \"$cp_bin\" lane-tools --socket \"$sock\" > \"$rec/{out}\" 2> \"$rec/{out}.err\"\n"
    )
}

/// Shell for a fake that calls `run_check` once for each id, in order.
pub fn run_checks(ids: &[&str]) -> String {
    let calls: Vec<(u64, &str, Value)> = ids
        .iter()
        .enumerate()
        .map(|(i, id)| (3 + i as u64, "run_check", json!({ "id": id })))
        .collect();
    mcp_session("mcp.out", &calls)
}

/// One lane of `cowproof run` against a fake `claude`, with a `cowproof` copy outside
/// the home and a `HOME` of its own for every child (so no test touches the real one).
pub struct Lane {
    /// Holds the repository, the packet, the fake and the cowproof copy.
    /// The lane id, unique per lane (see [`unique_lane_id`]).
    pub id: String,
    _work: TempDir,
    /// Holds the lanes, nothing else.
    pub lanes: TempDir,
    /// The `HOME` of every cowproof child: the director store lives under it.
    pub home: TempDir,
    pub repo: PathBuf,
    pub packet: PathBuf,
    fake: PathBuf,
    pub cowproof: PathBuf,
    /// Extra environment for every `cowproof` child (see [`Lane::set_env`]).
    envs: Vec<(String, OsString)>,
}

static LANE_COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
static LANE_PORTS: Mutex<Vec<u16>> = Mutex::new(Vec::new());

/// A lane id of its own, with a bridge port of its own (D24).
///
/// The builder's bridge port is a hash of the lane id and, on macOS, the sandbox shares
/// the host's loopback, so lanes that run in parallel with one id (or with ids that merely
/// hash alike) would fight over a port. The id is searched for: its port must be unused by
/// every other lane of this process and free on the host right now.
pub fn unique_lane_id() -> String {
    let mut used = LANE_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    loop {
        let n = LANE_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let id = format!("t-ver-{}-{n}", std::process::id());
        let port = cowproof_run::bridge::bridge_port(&id);
        if !used.contains(&port) && std::net::TcpListener::bind(("127.0.0.1", port)).is_ok() {
            used.push(port);
            return id;
        }
    }
}

impl Lane {
    /// A committed repository with a README, and a packet that owns `README.md` and
    /// `created.txt` and declares `checks`. The fake edits README.md, creates
    /// created.txt, then runs `fake_body`.
    #[allow(dead_code)] // `tests/slots.rs` builds every lane with a class
    pub fn new(fake_body: &str, checks: Value) -> Self {
        Self::with_class(fake_body, checks, "light")
    }

    /// [`Lane::new`] with the packet's resource `class` (`light`, `crate`, `rust`, `pg`).
    #[allow(dead_code)] // `tests/slots.rs` uses it; the other test crates that share this module do not
    pub fn with_class(fake_body: &str, checks: Value, class: &str) -> Self {
        let id = unique_lane_id();
        let work = var_tmp("cp-ver-work-");
        let lanes = var_tmp("cp-ver-lanes-");
        let home = var_tmp("cp-ver-home-");
        let repo = work.path().join("repo");
        fs::create_dir(&repo).unwrap();
        git(&repo, &["init", "-q"]);
        git(&repo, &["config", "user.email", "t@example.com"]);
        git(&repo, &["config", "user.name", "T"]);
        fs::write(repo.join("README.md"), "base\n").unwrap();
        git(&repo, &["add", "."]);
        git(&repo, &["commit", "-q", "-m", "base"]);

        let packet = work.path().join("packet.md");
        fs::write(
            &packet,
            format!(
                "# Task\n\n<!-- lane {} -->\n\nChange the README.\n",
                json!({
                    "id": id,
                    "owns": ["README.md", "created.txt"],
                    "class": class,
                    "checks": checks,
                })
            ),
        )
        .unwrap();

        // The test binary lives under the home in a normal checkout, which the sandbox
        // hides, so the process's shared copy outside it is what runs (no `pk` beside it).
        let cowproof = shared_cowproof_alone().to_path_buf();
        let fake = work.path().join("fake-claude");
        let script = format!(
            r#"#!/bin/sh
# The preflight runs `claude --version`; answer it before the lane's body.
if [ "$1" = "--version" ]; then echo "fake-claude 0.0.0"; exit 0; fi
rec="$HOME/fake"
mkdir -p "$rec"
sock="$(dirname "$HOME")/sock/runner.sock"
echo edited >> README.md
echo created > created.txt
cp_bin='{cowproof}'
{fake_body}
printf '%s' '{stream}'
exit 0
"#,
            cowproof = cowproof.display(),
            stream = FAKE_STREAM,
        );
        {
            let _g = fork_lock();
            fs::write(&fake, script).unwrap();
            fs::set_permissions(&fake, fs::Permissions::from_mode(0o755)).unwrap();
        }
        Lane {
            id,
            _work: work,
            lanes,
            home,
            repo,
            packet,
            fake,
            cowproof,
            envs: Vec::new(),
        }
    }

    /// A lane over a committed copy of the project directory `project` (every file in it,
    /// recursively), with the packet text `packet(lane_id)` gives. Unlike [`Lane::new`], the
    /// fake changes nothing by itself: it runs `fake_body` in the clone, so the lane's patch
    /// is exactly what `fake_body` does to the project.
    #[allow(dead_code)] // `tests/adversarial.rs` uses it; the other test crates that share this module do not
    pub fn from_project(fake_body: &str, project: &Path, packet: &dyn Fn(&str) -> String) -> Self {
        let id = unique_lane_id();
        let work = var_tmp("cp-ver-work-");
        let lanes = var_tmp("cp-ver-lanes-");
        let home = var_tmp("cp-ver-home-");
        let repo = work.path().join("repo");
        copy_tree(project, &repo);
        git(&repo, &["init", "-q"]);
        git(&repo, &["config", "user.email", "t@example.com"]);
        git(&repo, &["config", "user.name", "T"]);
        git(&repo, &["add", "."]);
        git(&repo, &["commit", "-q", "-m", "base"]);

        let packet_path = work.path().join("packet.md");
        fs::write(&packet_path, packet(&id)).unwrap();

        let cowproof = shared_cowproof_alone().to_path_buf();
        let fake = work.path().join("fake-claude");
        let script = format!(
            r#"#!/bin/sh
# The preflight runs `claude --version`; answer it before the lane's body.
if [ "$1" = "--version" ]; then echo "fake-claude 0.0.0"; exit 0; fi
rec="$HOME/fake"
mkdir -p "$rec"
sock="$(dirname "$HOME")/sock/runner.sock"
cp_bin='{cowproof}'
{fake_body}
printf '%s' '{stream}'
exit 0
"#,
            cowproof = cowproof.display(),
            stream = FAKE_STREAM,
        );
        {
            let _g = fork_lock();
            fs::write(&fake, script).unwrap();
            fs::set_permissions(&fake, fs::Permissions::from_mode(0o755)).unwrap();
        }
        Lane {
            id,
            _work: work,
            lanes,
            home,
            repo,
            packet: packet_path,
            fake,
            cowproof,
            envs: Vec::new(),
        }
    }

    /// The fake `claude`, for a hosts config that names it as the host's `claude`.
    #[allow(dead_code)] // `tests/remote.rs` uses it; the other test crates that share this module do not
    pub fn fake_claude(&self) -> &Path {
        &self.fake
    }

    /// Set an environment variable for every later `cowproof` child of this lane.
    #[allow(dead_code)] // `tests/deps.rs` uses it; the other test crates that share this module do not
    pub fn set_env(&mut self, key: &str, value: impl Into<OsString>) {
        self.envs.retain(|(k, _)| k != key);
        self.envs.push((key.to_string(), value.into()));
    }

    /// Add `files` (relative path, content) to the repository and commit them, so they
    /// are part of the base the lane starts from.
    #[allow(dead_code)] // `tests/deps.rs` uses it; the other test crates that share this module do not
    pub fn commit_files(&self, files: &[(&str, &str)]) {
        for (rel, content) in files {
            let path = self.repo.join(rel);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, content).unwrap();
        }
        git(&self.repo, &["add", "-A"]);
        git(&self.repo, &["commit", "-q", "-m", "project files"]);
    }

    /// `cowproof` with the lane's `HOME` and no inherited API key.
    pub fn cowproof_cmd(&self) -> Command {
        let mut c = Command::new(&self.cowproof);
        c.env("HOME", self.home.path())
            .env_remove("ANTHROPIC_API_KEY");
        for (k, v) in &self.envs {
            c.env(k, v);
        }
        c
    }

    /// The `cowproof run` command with the real key set, plus `extra` arguments, not yet
    /// started.
    pub fn run_command(&self, extra: &[&Path]) -> Command {
        let mut c = self.cowproof_cmd();
        c.arg("run")
            .arg(&self.packet)
            .arg("--repo")
            .arg(&self.repo)
            .arg("--lanes-root")
            .arg(self.lanes.path())
            .arg("--claude-bin")
            .arg(&self.fake)
            .args(extra)
            .env("ANTHROPIC_API_KEY", REAL_KEY);
        c
    }

    /// `cowproof run` with the real key set, plus `extra` arguments.
    #[allow(dead_code)] // `tests/slots.rs` starts its runs without waiting
    pub fn run(&self, extra: &[&Path]) -> Output {
        output(&mut self.run_command(extra))
    }

    pub fn lane_dir(&self) -> PathBuf {
        self.lanes.path().canonicalize().unwrap().join(&self.id)
    }

    pub fn capsule_dir(&self) -> PathBuf {
        self.lane_dir().join("control/capsule")
    }

    pub fn verdict(&self) -> Value {
        let p = self.lane_dir().join("control/verdict.json");
        serde_json::from_str(
            &fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display())),
        )
        .unwrap()
    }
}

/// Copy the directory `from` to `to`, recursively (regular files and directories only).
#[allow(dead_code)] // `Lane::from_project` uses it; the other test crates that share this module do not
pub fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let dest = to.join(entry.file_name());
        let kind = entry.file_type().unwrap();
        if kind.is_dir() {
            copy_tree(&entry.path(), &dest);
        } else if kind.is_file() {
            fs::copy(entry.path(), &dest).unwrap();
        }
    }
}

/// Start `cmd` without waiting, its stdout dropped and its stderr written to the file
/// `stderr` (read it while the process runs). The spawn is under `FORK_LOCK`.
#[allow(dead_code)] // `tests/slots.rs` uses it; the other test crates that share this module do not
pub fn spawn_to_file(cmd: &mut Command, stderr: &Path) -> std::process::Child {
    let file = fs::File::create(stderr).unwrap();
    let _g = fork_lock();
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(file))
        .spawn()
        .unwrap()
}

/// `out`'s stdout and stderr, for assertion messages.
pub fn text(out: &Output) -> String {
    format!(
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

// ---------------------------------------------------------------------------------------------
// A FAKE OpenRouter (D28 step 2): the upstream the proxy forwards OpenCode's requests to.
// ---------------------------------------------------------------------------------------------

/// One scripted model reply: some text, then tool calls (`(tool name, arguments)`). A reply
/// with tool calls ends with `finish_reason: tool_calls`, one without ends the turn.
#[allow(dead_code)] // only `tests/opencode.rs` scripts replies
#[derive(Clone, Debug)]
pub struct Reply {
    pub text: Option<String>,
    pub tools: Vec<(String, Value)>,
    /// Wait this long before answering (a slow model).
    pub delay_ms: u64,
}

#[allow(dead_code)]
impl Reply {
    pub fn text(text: &str) -> Self {
        Reply {
            text: Some(text.to_string()),
            tools: Vec::new(),
            delay_ms: 0,
        }
    }

    /// The same reply, `ms` milliseconds late.
    pub fn delayed(mut self, ms: u64) -> Self {
        self.delay_ms = ms;
        self
    }

    pub fn tools(text: &str, tools: Vec<(&str, Value)>) -> Self {
        Reply {
            text: Some(text.to_string()),
            tools: tools.into_iter().map(|(n, a)| (n.to_string(), a)).collect(),
            delay_ms: 0,
        }
    }
}

/// What the fake saw of one request.
#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct Seen {
    pub method: String,
    pub path: String,
    pub authorization: Option<String>,
    pub host: Option<String>,
    pub model: Option<String>,
    /// Names of the tools the request offered the model.
    pub tool_names: Vec<String>,
    /// Number of messages in the conversation sent.
    pub messages: usize,
    /// The text of the last message, flattened.
    pub last_message: String,
    /// The system prompt, flattened.
    pub system: String,
    /// Header names, lower case.
    pub header_names: Vec<String>,
}

struct FakeState {
    script: Vec<Reply>,
    next: usize,
    seen: Vec<Seen>,
    /// Answer every chat completion with this status and a JSON error body.
    fail_with: Option<u16>,
    /// What `GET /api/v1/models` answers (see [`FakeOpenRouter::set_models`]).
    models: ModelsMode,
    /// The key `GET /api/v1/models` requires as `Authorization: Bearer <key>`; 403 otherwise.
    expected_key: String,
}

/// The lettered synthetic key the OpenRouter tests give the director, and the one the fake's
/// model list requires. Not a real key and not shaped like one a scanner would flag.
pub fn openrouter_test_key() -> String {
    format!("sk-or-v1-{}", "abcdefghij".repeat(6))
}

/// One entry of the fake's model list, in the shape of OpenRouter's `GET /models`. Prices are
/// the strings OpenRouter sends: USD per token.
#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct FakeModel {
    pub id: String,
    pub prompt: String,
    pub completion: String,
    pub cache_read: Option<String>,
    pub cache_write: Option<String>,
    pub context_length: Option<u64>,
    pub max_completion_tokens: Option<u64>,
}

#[allow(dead_code)]
impl FakeModel {
    /// A model with only a prompt and a completion price, and no limits.
    pub fn new(id: &str, prompt: &str, completion: &str) -> Self {
        FakeModel {
            id: id.to_string(),
            prompt: prompt.to_string(),
            completion: completion.to_string(),
            cache_read: None,
            cache_write: None,
            context_length: None,
            max_completion_tokens: None,
        }
    }

    pub fn cache_read(mut self, price: &str) -> Self {
        self.cache_read = Some(price.to_string());
        self
    }

    pub fn limits(mut self, context_length: u64, max_completion_tokens: u64) -> Self {
        self.context_length = Some(context_length);
        self.max_completion_tokens = Some(max_completion_tokens);
        self
    }

    fn to_json(&self) -> Value {
        let mut pricing = json!({"prompt": self.prompt, "completion": self.completion});
        if let Some(p) = &self.cache_read {
            pricing["input_cache_read"] = json!(p);
        }
        if let Some(p) = &self.cache_write {
            pricing["input_cache_write"] = json!(p);
        }
        json!({
            "id": self.id,
            "name": self.id,
            "context_length": self.context_length,
            "top_provider": {"max_completion_tokens": self.max_completion_tokens},
            "pricing": pricing,
        })
    }
}

/// How the fake answers `GET /api/v1/models`.
#[allow(dead_code)]
#[derive(Clone, Debug)]
pub enum ModelsMode {
    /// 200 with these models.
    List(Vec<FakeModel>),
    /// This status and a JSON error body.
    Status(u16),
    /// 200 with a body that is not JSON.
    Garbage,
    /// Accept the request and never answer.
    Hang,
    /// 200 with a valid JSON body larger than the director's 8 MiB cap.
    Oversize,
}

/// A small HTTP server on 127.0.0.1 that answers OpenAI-style streaming chat completions
/// (`POST /api/v1/chat/completions`) from a script and records every request it gets, whatever
/// the path. A request that offers no tools (a title generator, say) gets a plain reply and does
/// not consume the script.
#[allow(dead_code)]
pub struct FakeOpenRouter {
    addr: std::net::SocketAddr,
    state: std::sync::Arc<Mutex<FakeState>>,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

#[allow(dead_code)]
impl FakeOpenRouter {
    pub fn start(script: Vec<Reply>) -> Self {
        Self::start_with(script, None)
    }

    /// A fake that refuses every chat completion with `status` (an expired key, say).
    pub fn failing(status: u16) -> Self {
        Self::start_with(Vec::new(), Some(status))
    }

    /// Change what `GET /api/v1/models` answers. Until it is called the list holds one model,
    /// `z-ai/glm-5.3-flash`, at the prices the old hand-written table gave.
    pub fn set_models(&self, mode: ModelsMode) {
        self.state.lock().unwrap().models = mode;
    }

    /// The requests for the model list, oldest first.
    pub fn models_requests(&self) -> Vec<Seen> {
        self.seen()
            .into_iter()
            .filter(|r| r.path == "/api/v1/models")
            .collect()
    }

    /// Every request that is not for the model list, oldest first.
    pub fn other_requests(&self) -> Vec<Seen> {
        self.seen()
            .into_iter()
            .filter(|r| r.path != "/api/v1/models")
            .collect()
    }

    fn start_with(script: Vec<Reply>, fail_with: Option<u16>) -> Self {
        use std::sync::atomic::Ordering;
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let state = std::sync::Arc::new(Mutex::new(FakeState {
            script,
            next: 0,
            seen: Vec::new(),
            fail_with,
            models: ModelsMode::List(vec![
                FakeModel::new("z-ai/glm-5.3-flash", "0.0000006", "0.0000022")
                    .cache_read("0.00000011")
                    .limits(200_000, 16_000),
            ]),
            expected_key: openrouter_test_key(),
        }));
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (st, sp) = (state.clone(), stop.clone());
        let thread = std::thread::spawn(move || {
            while !sp.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((conn, _)) => {
                        let st = st.clone();
                        std::thread::spawn(move || {
                            let _ = fake_serve(conn, st);
                        });
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });
        FakeOpenRouter {
            addr,
            state,
            stop,
            thread: Some(thread),
        }
    }

    /// `http://127.0.0.1:<port>`, what `COWPROOF_OPENROUTER_UPSTREAM` is set to.
    pub fn base(&self) -> String {
        format!("http://{}", self.addr)
    }

    pub fn host(&self) -> String {
        self.addr.to_string()
    }

    /// Every request so far, oldest first.
    pub fn seen(&self) -> Vec<Seen> {
        self.state.lock().unwrap().seen.clone()
    }

    /// How many scripted replies were given.
    pub fn replies_given(&self) -> usize {
        self.state.lock().unwrap().next
    }
}

impl Drop for FakeOpenRouter {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// Flatten a chat message's `content` (a string, or a list of `{type:text,text}` parts).
fn flat_content(content: &Value) -> String {
    match content {
        Value::String(s) => s.clone(),
        Value::Array(parts) => parts
            .iter()
            .filter_map(|p| p.get("text").and_then(Value::as_str))
            .collect::<Vec<_>>()
            .join("\n"),
        other => other.to_string(),
    }
}

/// Answer `GET /api/v1/models`, then close the connection.
fn fake_models(
    writer: &mut std::net::TcpStream,
    authorized: bool,
    mode: ModelsMode,
) -> std::io::Result<()> {
    use std::io::Write;
    let (status, body) = if !authorized {
        (
            403,
            json!({"error": {"message": "invalid key", "code": 403}}).to_string(),
        )
    } else {
        match mode {
            ModelsMode::List(models) => (
                200,
                json!({"data": models.iter().map(FakeModel::to_json).collect::<Vec<_>>()})
                    .to_string(),
            ),
            ModelsMode::Status(status) => (
                status,
                json!({"error": {"message": "models are down", "code": status}}).to_string(),
            ),
            ModelsMode::Garbage => (200, "this is { not json".to_string()),
            ModelsMode::Hang => {
                std::thread::sleep(std::time::Duration::from_secs(120));
                return Ok(());
            }
            ModelsMode::Oversize => (
                200,
                format!(
                    r#"{{"data":[],"pad":"{}"}}"#,
                    "x".repeat(8 * 1024 * 1024 + 16)
                ),
            ),
        }
    };
    // The client may stop reading an oversize body; a broken pipe is not the fake's problem.
    let _ = write!(
        writer,
        "HTTP/1.1 {status} Status\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = writer.flush();
    Ok(())
}

fn fake_serve(
    conn: std::net::TcpStream,
    state: std::sync::Arc<Mutex<FakeState>>,
) -> std::io::Result<()> {
    use std::io::{BufRead, BufReader, Read, Write};
    conn.set_nonblocking(false)?;
    conn.set_read_timeout(Some(std::time::Duration::from_secs(120)))?;
    let mut writer = conn.try_clone()?;
    let mut reader = BufReader::new(conn);
    loop {
        // Request line and headers.
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            return Ok(());
        }
        let mut parts = line.split_whitespace();
        let (method, path) = (
            parts.next().unwrap_or("").to_string(),
            parts.next().unwrap_or("").to_string(),
        );
        let mut headers: Vec<(String, String)> = Vec::new();
        loop {
            let mut h = String::new();
            if reader.read_line(&mut h)? == 0 {
                return Ok(());
            }
            let h = h.trim_end();
            if h.is_empty() {
                break;
            }
            if let Some((k, v)) = h.split_once(':') {
                headers.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
            }
        }
        let header = |name: &str| {
            headers
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.clone())
        };
        // Body: Content-Length, or chunked.
        let mut body = Vec::new();
        if let Some(len) = header("content-length").and_then(|v| v.parse::<usize>().ok()) {
            body.resize(len, 0);
            reader.read_exact(&mut body)?;
        } else if header("transfer-encoding").is_some_and(|v| v.contains("chunked")) {
            loop {
                let mut size_line = String::new();
                reader.read_line(&mut size_line)?;
                let size = usize::from_str_radix(size_line.trim(), 16).unwrap_or(0);
                if size == 0 {
                    let mut end = String::new();
                    reader.read_line(&mut end)?;
                    break;
                }
                let mut chunk = vec![0u8; size];
                reader.read_exact(&mut chunk)?;
                body.extend_from_slice(&chunk);
                let mut crlf = String::new();
                reader.read_line(&mut crlf)?;
            }
        }
        let request: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
        let messages = request["messages"].as_array().cloned().unwrap_or_default();
        let tool_names: Vec<String> = request["tools"]
            .as_array()
            .map(|tools| {
                tools
                    .iter()
                    .filter_map(|t| t["function"]["name"].as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        let system = messages
            .iter()
            .filter(|m| m["role"] == "system")
            .map(|m| flat_content(&m["content"]))
            .collect::<Vec<_>>()
            .join("\n");
        let reply = {
            let mut st = state.lock().unwrap();
            st.seen.push(Seen {
                method: method.clone(),
                path: path.clone(),
                authorization: header("authorization"),
                host: header("host"),
                model: request["model"].as_str().map(str::to_string),
                tool_names: tool_names.clone(),
                messages: messages.len(),
                last_message: messages
                    .last()
                    .map(|m| flat_content(&m["content"]))
                    .unwrap_or_default(),
                system,
                header_names: headers.iter().map(|(k, _)| k.clone()).collect(),
            });
            if method == "GET" && path == "/api/v1/models" {
                let authorized = header("authorization").as_deref()
                    == Some(format!("Bearer {}", st.expected_key).as_str());
                let mode = st.models.clone();
                drop(st);
                return fake_models(&mut writer, authorized, mode);
            } else if method != "POST" || path != "/api/v1/chat/completions" {
                None
            } else if let Some(status) = st.fail_with {
                let body =
                    json!({"error": {"message": "No auth credentials found", "code": status}})
                        .to_string();
                drop(st);
                write!(
                    writer,
                    "HTTP/1.1 {status} Error\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )?;
                return Ok(());
            } else if tool_names.is_empty() {
                Some(Reply::text("Title"))
            } else {
                let i = st.next;
                st.next += 1;
                Some(
                    st.script
                        .get(i)
                        .cloned()
                        .unwrap_or_else(|| Reply::text("(the script is out of replies)")),
                )
            }
        };
        let Some(reply) = reply else {
            writer.write_all(
                b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            )?;
            return Ok(());
        };
        if reply.delay_ms > 0 {
            std::thread::sleep(std::time::Duration::from_millis(reply.delay_ms));
        }
        writer.write_all(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n",
        )?;
        let model = request["model"].as_str().unwrap_or("m").to_string();
        let send = |writer: &mut std::net::TcpStream, data: &str| -> std::io::Result<()> {
            let frame = format!("data: {data}\n\n");
            write!(writer, "{:x}\r\n{frame}\r\n", frame.len())?;
            writer.flush()
        };
        let chunk = |delta: Value, finish: Value| {
            json!({"id":"gen-fake","object":"chat.completion.chunk","created":1,"model":model,
                   "choices":[{"index":0,"delta":delta,"finish_reason":finish}]})
            .to_string()
        };
        send(
            &mut writer,
            &chunk(json!({"role":"assistant","content":""}), Value::Null),
        )?;
        if let Some(text) = &reply.text {
            send(&mut writer, &chunk(json!({"content": text}), Value::Null))?;
        }
        for (k, (name, args)) in reply.tools.iter().enumerate() {
            send(
                &mut writer,
                &chunk(
                    json!({"tool_calls":[{"index":k,"id":format!("call_{k}_{}", name.len()),"type":"function",
                          "function":{"name":name,"arguments":args.to_string()}}]}),
                    Value::Null,
                ),
            )?;
        }
        let finish = if reply.tools.is_empty() {
            "stop"
        } else {
            "tool_calls"
        };
        send(&mut writer, &chunk(json!({}), json!(finish)))?;
        send(
            &mut writer,
            &json!({"id":"gen-fake","object":"chat.completion.chunk","created":1,"model":model,"choices":[],
                    "usage":{"prompt_tokens":100,"completion_tokens":20,"total_tokens":120,
                             "prompt_tokens_details":{"cached_tokens":10}}})
            .to_string(),
        )?;
        send(&mut writer, "[DONE]")?;
        writer.write_all(b"0\r\n\r\n")?;
        writer.flush()?;
    }
}

// ---------------------------------------------------------------------------------------------
// A FAKE OpenAI (D28 step 3): the upstream the proxy forwards Codex's requests to.
// ---------------------------------------------------------------------------------------------

/// The lettered synthetic key the Codex tests give the director, and the one the fake requires.
/// Not a real key: it is a repeated alphabet fragment, which the scrub check does not flag.
#[allow(dead_code)] // only `tests/codex.rs` uses the fake OpenAI
pub fn openai_test_key() -> String {
    format!("sk-proj-{}", "abcdefghij".repeat(6))
}

/// One scripted reply of the fake OpenAI: some reasoning, some text, then function calls
/// (`(namespace, tool name, arguments)`; a namespace is how Codex offers an MCP server's
/// tools), and the usage the call reports.
#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct ResponsesReply {
    pub reasoning: Option<String>,
    pub text: Option<String>,
    pub calls: Vec<(Option<String>, String, Value)>,
    /// Wait this long before answering (a slow model).
    pub delay_ms: u64,
    /// `(input, cached input, output)` tokens this call reports.
    pub usage: (u64, u64, u64),
}

#[allow(dead_code)]
impl ResponsesReply {
    pub fn text(text: &str) -> Self {
        ResponsesReply {
            reasoning: None,
            text: Some(text.to_string()),
            calls: Vec::new(),
            delay_ms: 0,
            usage: (100, 10, 20),
        }
    }

    /// Text, then calls to Codex's own tools (`exec_command`, ...).
    pub fn tools(text: &str, calls: Vec<(&str, Value)>) -> Self {
        let mut reply = Self::text(text);
        reply.calls = calls
            .into_iter()
            .map(|(name, args)| (None, name.to_string(), args))
            .collect();
        reply
    }

    /// Text, then calls to the tools of the MCP server `server` (`cowproof-tools`).
    pub fn mcp(text: &str, server: &str, calls: Vec<(&str, Value)>) -> Self {
        let mut reply = Self::text(text);
        reply.calls = calls
            .into_iter()
            .map(|(name, args)| {
                (
                    Some(format!("mcp__{}", server.replace('-', "_"))),
                    name.to_string(),
                    args,
                )
            })
            .collect();
        reply
    }

    /// The same reply, `ms` milliseconds late.
    pub fn delayed(mut self, ms: u64) -> Self {
        self.delay_ms = ms;
        self
    }

    /// The same reply, reporting these tokens.
    pub fn with_usage(mut self, input: u64, cached_input: u64, output: u64) -> Self {
        self.usage = (input, cached_input, output);
        self
    }

    /// The same reply with a reasoning summary before its text.
    pub fn reasoning(mut self, text: &str) -> Self {
        self.reasoning = Some(text.to_string());
        self
    }
}

struct OpenAiState {
    script: Vec<ResponsesReply>,
    next: usize,
    seen: Vec<Seen>,
    /// Answer every request with this status and a JSON error body.
    fail_with: Option<u16>,
    expected_key: String,
}

/// A small HTTP server on 127.0.0.1 that answers OpenAI Responses requests
/// (`POST /v1/responses`, streamed) from a script and records every request it gets, whatever
/// the path or method. It requires `Authorization: Bearer <openai_test_key()>`, as OpenAI
/// requires a key, and answers 401 to anything else. A path it does not serve is a 404.
#[allow(dead_code)]
pub struct FakeOpenAi {
    addr: std::net::SocketAddr,
    state: std::sync::Arc<Mutex<OpenAiState>>,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

#[allow(dead_code)]
impl FakeOpenAi {
    pub fn start(script: Vec<ResponsesReply>) -> Self {
        Self::start_with(script, None)
    }

    /// A fake that refuses every request with `status` (an expired key, say).
    pub fn failing(status: u16) -> Self {
        Self::start_with(Vec::new(), Some(status))
    }

    fn start_with(script: Vec<ResponsesReply>, fail_with: Option<u16>) -> Self {
        use std::sync::atomic::Ordering;
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let state = std::sync::Arc::new(Mutex::new(OpenAiState {
            script,
            next: 0,
            seen: Vec::new(),
            fail_with,
            expected_key: openai_test_key(),
        }));
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (st, sp) = (state.clone(), stop.clone());
        let thread = std::thread::spawn(move || {
            while !sp.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((conn, _)) => {
                        let st = st.clone();
                        std::thread::spawn(move || {
                            let _ = openai_serve(conn, st);
                        });
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });
        FakeOpenAi {
            addr,
            state,
            stop,
            thread: Some(thread),
        }
    }

    /// `http://127.0.0.1:<port>`, what `COWPROOF_OPENAI_UPSTREAM` is set to.
    pub fn base(&self) -> String {
        format!("http://{}", self.addr)
    }

    pub fn host(&self) -> String {
        self.addr.to_string()
    }

    /// Every request so far, oldest first. `tool_names` lists Codex's own tools by name and an
    /// MCP server's as `<namespace>::<tool>`.
    pub fn seen(&self) -> Vec<Seen> {
        self.state.lock().unwrap().seen.clone()
    }

    /// How many scripted replies were given.
    pub fn replies_given(&self) -> usize {
        self.state.lock().unwrap().next
    }
}

impl Drop for FakeOpenAi {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// The text of a Responses `input` item or `instructions`, flattened.
fn responses_text(item: &Value) -> String {
    match item.get("content") {
        Some(content) => flat_content(content),
        None => String::new(),
    }
}

/// One HTTP request: method, path, lower-cased headers and the body.
struct HttpRequest {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

fn read_http_request(
    reader: &mut std::io::BufReader<std::net::TcpStream>,
) -> std::io::Result<Option<HttpRequest>> {
    use std::io::{BufRead, Read};
    let mut line = String::new();
    if reader.read_line(&mut line)? == 0 {
        return Ok(None);
    }
    let mut parts = line.split_whitespace();
    let (method, path) = (
        parts.next().unwrap_or("").to_string(),
        parts.next().unwrap_or("").to_string(),
    );
    let mut headers: Vec<(String, String)> = Vec::new();
    loop {
        let mut h = String::new();
        if reader.read_line(&mut h)? == 0 {
            return Ok(None);
        }
        let h = h.trim_end();
        if h.is_empty() {
            break;
        }
        if let Some((k, v)) = h.split_once(':') {
            headers.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
        }
    }
    let header = |name: &str| {
        headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
    };
    let mut body = Vec::new();
    if let Some(len) = header("content-length").and_then(|v| v.parse::<usize>().ok()) {
        body.resize(len, 0);
        reader.read_exact(&mut body)?;
    } else if header("transfer-encoding").is_some_and(|v| v.contains("chunked")) {
        loop {
            let mut size_line = String::new();
            reader.read_line(&mut size_line)?;
            let size = usize::from_str_radix(size_line.trim(), 16).unwrap_or(0);
            if size == 0 {
                let mut end = String::new();
                reader.read_line(&mut end)?;
                break;
            }
            let mut chunk = vec![0u8; size];
            reader.read_exact(&mut chunk)?;
            body.extend_from_slice(&chunk);
            let mut crlf = String::new();
            reader.read_line(&mut crlf)?;
        }
    }
    Ok(Some(HttpRequest {
        method,
        path,
        headers,
        body,
    }))
}

fn openai_serve(
    conn: std::net::TcpStream,
    state: std::sync::Arc<Mutex<OpenAiState>>,
) -> std::io::Result<()> {
    use std::io::{BufReader, Write};
    conn.set_nonblocking(false)?;
    conn.set_read_timeout(Some(std::time::Duration::from_secs(120)))?;
    let mut writer = conn.try_clone()?;
    let mut reader = BufReader::new(conn);
    while let Some(HttpRequest {
        method,
        path,
        headers,
        body,
    }) = read_http_request(&mut reader)?
    {
        let header = |name: &str| {
            headers
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.clone())
        };
        let request: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
        let input = request["input"].as_array().cloned().unwrap_or_default();
        // Codex offers its tools in `tools`, or, for a model in its own catalog, as an
        // `additional_tools` item of the input; either way an MCP server's or a code-mode
        // namespace's tools are listed as `<namespace>::<tool>`.
        let mut offered: Vec<Value> = request["tools"].as_array().cloned().unwrap_or_default();
        for item in &input {
            if item["type"] == "additional_tools" {
                offered.extend(item["tools"].as_array().cloned().unwrap_or_default());
            }
        }
        let mut tool_names: Vec<String> = Vec::new();
        for tool in offered {
            match tool["type"].as_str() {
                Some("namespace") => {
                    let namespace = tool["name"].as_str().unwrap_or("").to_string();
                    for inner in tool["tools"].as_array().cloned().unwrap_or_default() {
                        tool_names.push(format!(
                            "{namespace}::{}",
                            inner["name"].as_str().unwrap_or("")
                        ));
                    }
                }
                _ => tool_names.push(
                    tool["name"]
                        .as_str()
                        .or_else(|| tool["type"].as_str())
                        .unwrap_or("")
                        .to_string(),
                ),
            }
        }
        // Codex's own base prompt is `instructions`; the lane's preamble arrives as a
        // developer message. Both are "the system prompt" to a reader.
        let system = std::iter::once(request["instructions"].as_str().unwrap_or("").to_string())
            .chain(
                input
                    .iter()
                    .filter(|m| m["role"] == "developer")
                    .map(responses_text),
            )
            .collect::<Vec<_>>()
            .join("\n");
        let (reply, refusal) =
            {
                let mut st = state.lock().unwrap();
                st.seen.push(Seen {
                    method: method.clone(),
                    path: path.clone(),
                    authorization: header("authorization"),
                    host: header("host"),
                    model: request["model"].as_str().map(str::to_string),
                    tool_names,
                    messages: input.len(),
                    last_message: input.last().map(responses_text).unwrap_or_default(),
                    system,
                    header_names: headers.iter().map(|(k, _)| k.clone()).collect(),
                });
                let authorized = header("authorization").as_deref()
                    == Some(format!("Bearer {}", st.expected_key).as_str());
                if method != "POST" || path != "/v1/responses" {
                    (None, Some(404))
                } else if let Some(status) = st.fail_with {
                    (None, Some(status))
                } else if !authorized {
                    (None, Some(401))
                } else {
                    let i = st.next;
                    st.next += 1;
                    (
                        Some(st.script.get(i).cloned().unwrap_or_else(|| {
                            ResponsesReply::text("(the script is out of replies)")
                        })),
                        None,
                    )
                }
            };
        if let Some(status) = refusal {
            let body = if status == 404 {
                String::new()
            } else {
                json!({"error": {"message": "Incorrect API key provided.", "type": "invalid_request_error",
                                 "code": "invalid_api_key"}})
                .to_string()
            };
            write!(
                writer,
                "HTTP/1.1 {status} Error\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )?;
            return Ok(());
        }
        let reply = reply.expect("a reply when there is no refusal");
        if reply.delay_ms > 0 {
            std::thread::sleep(std::time::Duration::from_millis(reply.delay_ms));
        }
        writer.write_all(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n",
        )?;
        let send =
            |writer: &mut std::net::TcpStream, event: &str, data: Value| -> std::io::Result<()> {
                let frame = format!("event: {event}\ndata: {data}\n\n");
                write!(writer, "{:x}\r\n{frame}\r\n", frame.len())?;
                writer.flush()
            };
        let response_id = format!("resp_{}", state.lock().unwrap().next);
        send(
            &mut writer,
            "response.created",
            json!({"type":"response.created","response":{"id":response_id}}),
        )?;
        let mut index = 0;
        let mut output_item = |writer: &mut std::net::TcpStream, item: Value, empty: Value| {
            send(
                writer,
                "response.output_item.added",
                json!({"type":"response.output_item.added","output_index":index,"item":empty}),
            )?;
            send(
                writer,
                "response.output_item.done",
                json!({"type":"response.output_item.done","output_index":index,"item":item}),
            )?;
            index += 1;
            std::io::Result::Ok(())
        };
        if let Some(reasoning) = &reply.reasoning {
            output_item(
                &mut writer,
                json!({"type":"reasoning","id":"rs_1","summary":[{"type":"summary_text","text":reasoning}]}),
                json!({"type":"reasoning","id":"rs_1","summary":[]}),
            )?;
        }
        if let Some(text) = &reply.text {
            output_item(
                &mut writer,
                json!({"type":"message","role":"assistant","id":"msg_1","content":[{"type":"output_text","text":text}]}),
                json!({"type":"message","role":"assistant","id":"msg_1","content":[]}),
            )?;
        }
        for (k, (namespace, name, args)) in reply.calls.iter().enumerate() {
            let mut item = json!({"type":"function_call","id":format!("fc_{k}"),
                                  "call_id":format!("call_{}_{k}", response_id),
                                  "name":name,"arguments":args.to_string()});
            if let Some(namespace) = namespace {
                item["namespace"] = json!(namespace);
            }
            output_item(&mut writer, item.clone(), item)?;
        }
        let (input_tokens, cached, output_tokens) = reply.usage;
        send(
            &mut writer,
            "response.completed",
            json!({"type":"response.completed","response":{"id":response_id,"usage":{
                "input_tokens":input_tokens,"input_tokens_details":{"cached_tokens":cached},
                "output_tokens":output_tokens,"output_tokens_details":{"reasoning_tokens":0},
                "total_tokens":input_tokens + output_tokens}}}),
        )?;
        writer.write_all(b"0\r\n\r\n")?;
        writer.flush()?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// A FAKE Anthropic (D2, subscription mode): the upstream the proxy forwards Claude's requests to.
// ---------------------------------------------------------------------------------------------

/// The lettered synthetic OAuth token the subscription tests give the director. Not a real
/// token: a repeated alphabet fragment after the prefix `claude setup-token` tokens carry.
#[allow(dead_code)] // only `tests/subscription.rs` uses the fake Anthropic
pub fn claude_oauth_test_token() -> String {
    format!("sk-ant-oat01-{}", "abcdefghij".repeat(6))
}

/// A lettered synthetic API key, for the tests that give the director both credentials.
#[allow(dead_code)]
pub fn anthropic_test_key() -> String {
    format!("sk-ant-api03-{}", "zyxwvutsrq".repeat(6))
}

/// What the fake Anthropic saw of one request: the method, the whole target (query included)
/// and every header, names lower case.
#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct AnthropicSeen {
    pub method: String,
    pub target: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

#[allow(dead_code)]
impl AnthropicSeen {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

/// A small HTTP server on 127.0.0.1 that answers `POST /v1/messages` with a one-line JSON
/// message and records every request it gets, whatever the path, method or credential. It does
/// not check the credential: the tests read it from the record, so a wrong one is a finding and
/// not a silent 401.
#[allow(dead_code)]
pub struct FakeAnthropic {
    addr: std::net::SocketAddr,
    seen: std::sync::Arc<Mutex<Vec<AnthropicSeen>>>,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

#[allow(dead_code)]
impl FakeAnthropic {
    pub fn start() -> Self {
        use std::sync::atomic::Ordering;
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = std::sync::Arc::new(Mutex::new(Vec::new()));
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (sn, sp) = (seen.clone(), stop.clone());
        let thread = std::thread::spawn(move || {
            while !sp.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((conn, _)) => {
                        let sn = sn.clone();
                        std::thread::spawn(move || {
                            let _ = anthropic_serve(conn, sn);
                        });
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });
        FakeAnthropic {
            addr,
            seen,
            stop,
            thread: Some(thread),
        }
    }

    /// `http://127.0.0.1:<port>`, what `COWPROOF_ANTHROPIC_UPSTREAM` is set to.
    pub fn base(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Every request so far, oldest first.
    pub fn seen(&self) -> Vec<AnthropicSeen> {
        self.seen.lock().unwrap().clone()
    }

    /// The requests so far for the Messages path (query ignored).
    pub fn messages(&self) -> Vec<AnthropicSeen> {
        self.seen()
            .into_iter()
            .filter(|r| r.target.split('?').next() == Some("/v1/messages"))
            .collect()
    }
}

impl Drop for FakeAnthropic {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

fn anthropic_serve(
    conn: std::net::TcpStream,
    seen: std::sync::Arc<Mutex<Vec<AnthropicSeen>>>,
) -> std::io::Result<()> {
    use std::io::{BufReader, Write};
    conn.set_nonblocking(false)?;
    conn.set_read_timeout(Some(std::time::Duration::from_secs(120)))?;
    let mut writer = conn.try_clone()?;
    let mut reader = BufReader::new(conn);
    // One request per connection: every reply says `Connection: close`.
    if let Some(HttpRequest {
        method,
        path,
        headers,
        body,
    }) = read_http_request(&mut reader)?
    {
        let ok = method == "POST" && path.split('?').next() == Some("/v1/messages");
        seen.lock().unwrap().push(AnthropicSeen {
            method,
            target: path,
            headers,
            body,
        });
        let (status, body) = if ok {
            (
                "200 OK",
                json!({"id":"msg_fake","type":"message","role":"assistant","model":"fake",
                       "content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn",
                       "stop_sequence":null,"usage":{"input_tokens":3,"output_tokens":5}})
                .to_string(),
            )
        } else {
            ("404 Not Found", String::new())
        };
        write!(
            writer,
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )?;
    }
    Ok(())
}
