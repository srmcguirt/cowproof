//! What the restored `pk` tests (`pk_cli`, `pk_hook`, `pk_trace`, `pk_parity`) and the stdio
//! protocol tests (`stdio_protocol`) share: a throwaway working directory, a `pk` command
//! with a clean environment, two real tools to call (`fixtures/pk/demo_tools.py`, registered
//! as plugins), and a bounded run that reads both pipes while it waits.
//!
//! A test file includes it as `mod common; mod pk_support;`. It uses `common` for the fork
//! lock, the throwaway directory under `/var/tmp` and the signal helper, so no test starts a
//! process with `kill`.

#![allow(dead_code, reason = "each test file uses some of these")]

use crate::common;
use serde_json::{Value, json};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};
use tempfile::TempDir;

/// How long any one spawned process may run before the test kills it by pid and fails.
pub const BOUND: Duration = Duration::from_secs(60);

/// The environment variables that would change what `pk` does, taken from the process
/// running the tests. Each command removes them, then sets only what the test names.
const CLEARED: &[&str] = &[
    "RUST_LOG",
    "PK_LOG_LEVEL",
    "PK_PARITY__EPSILON",
    "PORTKIT_STATE_DIR",
    "PORTKIT_SESSION",
    "CLAUDE_CONFIG_DIR",
];

/// A working directory and a home, both new and both under `/var/tmp`, removed on drop.
pub struct Work {
    _dir: TempDir,
    pub home: PathBuf,
    pub cwd: PathBuf,
}

impl Work {
    pub fn new() -> Work {
        let dir = common::var_tmp("pk-t-");
        let home = dir.path().join("home");
        let cwd = dir.path().join("cwd");
        std::fs::create_dir(&home).unwrap();
        std::fs::create_dir(&cwd).unwrap();
        Work {
            _dir: dir,
            home,
            cwd,
        }
    }

    /// A `Work` whose `pk.toml` registers `chunk_text` and `word_frequency`, and turns
    /// tracing on (into `traces` under the working directory) when `traced`.
    pub fn with_demo_tools(traced: bool) -> Work {
        let work = Work::new();
        work.write_demo_config(traced);
        work
    }

    /// Write `plugins.toml` and `pk.toml` into the working directory. The plugin layer is an
    /// absolute path, so the home needs no manifest of its own.
    pub fn write_demo_config(&self, traced: bool) {
        let script = demo_tools_script();
        let manifest: String = ["chunk_text", "word_frequency"]
            .iter()
            .map(|tool| {
                format!(
                    "[[plugin]]\ncommand = \"python3\"\nargs = [\"{}\", \"{tool}\"]\n\n",
                    script.display()
                )
            })
            .collect();
        let plugins = self.cwd.join("plugins.toml");
        std::fs::write(&plugins, manifest).unwrap();
        let mut config = format!("[plugins]\nglobal = \"{}\"\n", plugins.display());
        if traced {
            config.push_str("\n[trace]\nenabled = true\ndir = \"traces\"\n");
        }
        std::fs::write(self.cwd.join("pk.toml"), config).unwrap();
    }

    /// `pk` in the working directory, home and environment of this `Work`.
    pub fn pk(&self) -> Command {
        self.command(Path::new(env!("CARGO_BIN_EXE_pk")))
    }

    /// `pk --config pk.toml`, the demo tools registered.
    pub fn pk_with_config(&self) -> Command {
        let mut cmd = self.pk();
        cmd.args(["--config", "pk.toml"]);
        cmd
    }

    /// `cowproof` in the same environment.
    pub fn cowproof(&self) -> Command {
        self.command(Path::new(env!("CARGO_BIN_EXE_cowproof")))
    }

    fn command(&self, exe: &Path) -> Command {
        let mut cmd = Command::new(exe);
        for name in CLEARED {
            cmd.env_remove(name);
        }
        cmd.env("HOME", &self.home).current_dir(&self.cwd);
        cmd
    }

    /// Every `*.jsonl` record under `traces` in the working directory, in file order.
    pub fn trace_records(&self) -> Vec<Value> {
        let mut files: Vec<PathBuf> = std::fs::read_dir(self.cwd.join("traces"))
            .expect("the trace directory must exist")
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|e| e == "jsonl"))
            .collect();
        files.sort();
        files
            .iter()
            .flat_map(|p| {
                std::fs::read_to_string(p)
                    .unwrap()
                    .lines()
                    .map(|l| serde_json::from_str(l).expect("a trace line is JSON"))
                    .collect::<Vec<Value>>()
            })
            .collect()
    }
}

/// `fixtures/pk/demo_tools.py`.
pub fn demo_tools_script() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/pk/demo_tools.py")
}

/// The committed parity fixtures of the demo tools.
pub fn parity_fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/pk/parity")
}

/// Run `cmd` to completion with `stdin` written first (then closed) and both output pipes
/// read while it runs, so an output larger than a pipe buffer cannot stall it. Killed by pid
/// and failed if it outlives [`BOUND`].
pub fn run(cmd: &mut Command, stdin: Option<&[u8]>) -> Output {
    run_bounded(cmd, stdin, BOUND).0
}

/// [`run`], also returning how long the process took after its stdin was closed.
pub fn run_bounded(cmd: &mut Command, stdin: Option<&[u8]>, bound: Duration) -> (Output, Duration) {
    let mut child = {
        let _g = common::fork_lock();
        cmd.stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("cannot start {cmd:?}: {e}"))
    };
    let pid = child.id();
    let mut out_pipe = child.stdout.take().unwrap();
    let mut err_pipe = child.stderr.take().unwrap();
    let out_reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = out_pipe.read_to_end(&mut buf);
        buf
    });
    let err_reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = err_pipe.read_to_end(&mut buf);
        buf
    });
    if let Some(bytes) = stdin {
        let mut pipe = child.stdin.take().unwrap();
        // A server may answer and exit before it has read every byte; that is its business.
        let _ = pipe.write_all(bytes);
        drop(pipe);
    }
    let closed_at = Instant::now();
    let deadline = closed_at + bound;
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            common::signal_pid("KILL", pid);
            let _ = child.wait();
            panic!("process {pid} ({cmd:?}) still running {bound:?} after its stdin closed");
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let took = closed_at.elapsed();
    (
        Output {
            status,
            stdout: out_reader.join().unwrap(),
            stderr: err_reader.join().unwrap(),
        },
        took,
    )
}

/// A passing run's stdout, parsed as one JSON document.
pub fn stdout_json(out: &Output) -> Value {
    assert!(out.status.success(), "{}", describe(out));
    serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!("stdout is not JSON ({e}): {}", describe(out)))
}

/// A run's exit status and both streams, for an assertion message.
pub fn describe(out: &Output) -> String {
    format!(
        "exit {:?}\nstdout: {}\nstderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

pub fn stdout_text(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

pub fn stderr_text(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// One JSON-RPC request line.
pub fn rpc(id: u64, method: &str, params: Value) -> String {
    json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}).to_string()
}

/// The `initialize` request, the `initialized` notification and `tools/list`.
pub fn handshake() -> Vec<String> {
    vec![
        rpc(
            1,
            "initialize",
            json!({"protocolVersion": "2025-06-18", "capabilities": {},
                   "clientInfo": {"name": "t", "version": "0"}}),
        ),
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"}).to_string(),
        rpc(2, "tools/list", json!({})),
    ]
}

/// What an MCP stdio server did with a session.
pub struct Session {
    pub out: Output,
    /// Every stdout line, parsed; each is a JSON-RPC 2.0 object.
    pub frames: Vec<Value>,
    /// How long the server took to exit once its stdin was closed.
    pub exit_after_eof: Duration,
}

impl Session {
    /// The frame answering request `id`.
    pub fn reply(&self, id: u64) -> &Value {
        self.frames
            .iter()
            .find(|f| f["id"] == id)
            .unwrap_or_else(|| panic!("no answer to request {id}: {}", describe(&self.out)))
    }
}

/// How long a server may take to exit after its stdin closes. Generous: the point is that it
/// exits, and a loaded host starts a process slowly.
pub const EXIT_BOUND: Duration = Duration::from_secs(30);

/// Send `lines` (one per line) to an MCP stdio server, close its stdin, and require what a
/// client relies on: it exits 0 within [`EXIT_BOUND`], and every stdout line is a JSON-RPC
/// 2.0 frame. A log line, a banner or a stray print on stdout fails here, naming the line.
pub fn stdio_session(cmd: &mut Command, lines: &[String]) -> Session {
    let mut input = String::new();
    for line in lines {
        input.push_str(line);
        input.push('\n');
    }
    let (out, exit_after_eof) = run_bounded(cmd, Some(input.as_bytes()), EXIT_BOUND);
    assert_eq!(out.status.code(), Some(0), "{}", describe(&out));
    let frames = stdout_text(&out)
        .lines()
        .map(|line| {
            let frame: Value = serde_json::from_str(line).unwrap_or_else(|e| {
                panic!(
                    "stdout must carry only JSON-RPC frames; got {line:?} ({e})\n{}",
                    describe(&out)
                )
            });
            assert_eq!(
                frame["jsonrpc"],
                "2.0",
                "not a JSON-RPC frame: {line:?}\n{}",
                describe(&out)
            );
            frame
        })
        .collect();
    Session {
        out,
        frames,
        exit_after_eof,
    }
}
