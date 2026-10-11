//! Shared pieces for the CLI tests that drive a whole lane: a fork lock, sandbox
//! availability, a real git repository, a copy of the `cowproof` binary outside the
//! home, a FAKE `claude`, and the MCP frames the fake sends to `cowproof lane-tools`.
//!
//! `tests/run.rs` keeps its own copies of these (another lane is editing it); new test
//! files use this module so there is one copy to move it to.

use serde_json::{Value, json};
use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::Mutex;
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

/// A temporary directory under `/var/tmp`: not `/tmp` (bwrap hides it) and not the home
/// (both sandboxes hide it).
pub fn var_tmp(prefix: &str) -> TempDir {
    tempfile::Builder::new()
        .prefix(prefix)
        .tempdir_in("/var/tmp")
        .unwrap()
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
    packet: PathBuf,
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
        // hides, so a copy outside it is what runs.
        let cowproof = work.path().join("cowproof");
        {
            let _g = fork_lock();
            fs::copy(env!("CARGO_BIN_EXE_cowproof"), &cowproof).unwrap();
        }
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
