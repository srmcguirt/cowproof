//! `cowproof run <packet.md>` end to end, against a FAKE `claude` script and
//! no network.
//!
//! The fake runs inside the real builder sandbox (`sandbox-exec` on macOS,
//! `bwrap` on Linux), so these tests need it: with `COWPROOF_REQUIRE_SANDBOX=1`
//! (set in CI) an unavailable sandbox fails the test; without it the test
//! skips, like `crates/cowproof-run/tests/live.rs`.
//!
//! Test setup keeps the sandbox from hiding what the fake needs: the cowproof
//! binary, the fake, the repository and the lanes root all live under
//! `/var/tmp` (not `/tmp`, which bwrap hides, and not the home, which both
//! sandboxes hide), and the lanes root sits beside, not around, the fake.

#[allow(dead_code)] // this file keeps its own copies of most shared helpers
mod common;

use common::{pid_alive, signal_group, signal_pid};
use cowproof_prove::Capsule;
use cowproof_run::prefix::PREAMBLE;
use serde_json::{Value, json};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tempfile::TempDir;

const REAL_KEY: &str = "sk-test-real-xyz";
/// Another secret in the director's environment. Only an explicit builder
/// environment keeps it out: the placeholder overrides the key variable
/// either way, so the key alone cannot show whether the environment was
/// inherited.
const DIRECTOR_CANARY: &str = "canary-director-env-77";
/// The content of the `.env` files the runner removes at launch (R15). It must reach no
/// file under the lane's `control/` directory, the capsule included.
const CANARY_ENV: &str = "CANARY-ENV-7f3a";
const SESSION: &str = "0a1b2c3d-1111-2222-3333-444455556666";

/// What the fake prints on stdout: valid events, a blank line, a line that is
/// not JSON, and a final line with no newline.
const FAKE_STREAM: &str = concat!(
    r#"{"type":"system","subtype":"init","session_id":"0a1b2c3d-1111-2222-3333-444455556666"}"#,
    "\n",
    r#"{"type":"assistant","message":{"id":"m1","usage":{"input_tokens":3,"output_tokens":5,"cache_read_input_tokens":0,"cache_creation_input_tokens":7}}}"#,
    "\n\n",
    "plain text, not json\n",
    r#"{"type":"assistant","message":{"id":"m2","usage":{"input_tokens":4,"output_tokens":6,"cache_read_input_tokens":7,"cache_creation_input_tokens":0}}}"#,
    "\n",
    r#"{"type":"result","subtype":"success","result":"done","num_turns":2}"#,
);

/// Linux refuses to exec a file that some process holds open for writing
/// (ETXTBSY). Tests run on parallel threads: if one thread forks while another
/// is writing an executable (the copied `cowproof` or a fake `claude`), the
/// child inherits the write handle until it execs, and an exec of that file in
/// the meantime fails with "Text file busy". Writing executables and forking
/// both take this lock, so a fork never overlaps a write.
static FORK_LOCK: Mutex<()> = Mutex::new(());

fn fork_lock() -> std::sync::MutexGuard<'static, ()> {
    FORK_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// `Command::output` with the spawn under `FORK_LOCK`. Only the fork is held,
/// not the wait, so tests still run in parallel.
fn output(cmd: &mut Command) -> Output {
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

/// Run a freshly written executable once (`--version`, whatever it answers), so its first-run
/// cost is paid here and not inside a clock the runner keeps. Only the spawn holds `FORK_LOCK`.
fn warm_up(exe: &Path) {
    let child = {
        let _g = fork_lock();
        Command::new(exe)
            .arg("--version")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
    };
    if let Ok(mut child) = child {
        let _ = child.wait();
    }
}

fn sandbox_available() -> bool {
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

fn var_tmp(prefix: &str) -> TempDir {
    tempfile::Builder::new()
        .prefix(prefix)
        .tempdir_in("/var/tmp")
        .unwrap()
}

fn git(repo: &Path, args: &[&str]) {
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

/// Gives every harness its own lane id, and its own bridge port.
///
/// The builder's bridge port is a hash of the lane id and, on macOS, the
/// sandbox shares the host's loopback, so two harnesses running in parallel
/// would fight over a port if their ids shared one or merely hashed alike (with
/// about 40 harnesses and 20000 ports, a birthday collision is not rare). The
/// id is therefore searched for: its port must be unused by every other
/// harness in this process and free on the host right now.
static HARNESS_COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
static HARNESS_PORTS: Mutex<Vec<u16>> = Mutex::new(Vec::new());

fn unique_lane_id() -> String {
    let mut used = HARNESS_PORTS.lock().unwrap_or_else(|e| e.into_inner());
    loop {
        let n = HARNESS_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let id = format!("t-run-{}-{n}", std::process::id());
        let port = cowproof_run::bridge::bridge_port(&id);
        if !used.contains(&port) && std::net::TcpListener::bind(("127.0.0.1", port)).is_ok() {
            used.push(port);
            return id;
        }
    }
}

struct Harness {
    /// The lane id (lowercase letters, digits and dashes), unique per harness.
    id: String,
    /// Holds the repository, the packet, the fake and the cowproof copy.
    work: TempDir,
    /// Holds the lanes, nothing else.
    lanes: TempDir,
    repo: PathBuf,
    packet: PathBuf,
    packet_text: String,
    fake: PathBuf,
    cowproof: PathBuf,
}

impl Harness {
    /// A committed repository, a packet with three declared checks, a copy of
    /// the cowproof binary outside the home, and a fake `claude` whose body is
    /// `fake_body` (after the common recording prologue).
    fn new(fake_body: &str) -> Self {
        Self::with_packet(
            fake_body,
            json!(["README.md"]),
            json!([
                {"id": "ok", "command": "echo check-ran"},
                {"id": "denied", "command": "cat ../control/builder.stderr"},
                {"id": "slow", "command": "echo start >> ../scratch/trace; sleep 1; echo end >> ../scratch/trace"},
            ]),
        )
    }

    /// Like `new`, with the packet's `owns` and `checks` chosen by the test.
    fn with_packet(fake_body: &str, owns: Value, checks: Value) -> Self {
        let work = var_tmp("cp-run-work-");
        let lanes = var_tmp("cp-run-lanes-");
        let repo = work.path().join("repo");
        fs::create_dir(&repo).unwrap();
        git(&repo, &["init", "-q"]);
        git(&repo, &["config", "user.email", "t@example.com"]);
        git(&repo, &["config", "user.name", "T"]);
        fs::write(repo.join("README.md"), "base\n").unwrap();
        // Removed from the clone at launch (R15): it must never show up in
        // the lane patch, as a deletion or otherwise, nor anywhere in `control/`.
        // Nested ones and `CLAUDE.md` files go too.
        fs::create_dir_all(repo.join("sub")).unwrap();
        fs::create_dir_all(repo.join("docs")).unwrap();
        fs::write(repo.join(".env"), format!("SECRET={CANARY_ENV}\n")).unwrap();
        fs::write(
            repo.join("sub/.env.local"),
            format!("SECRET={CANARY_ENV}\n"),
        )
        .unwrap();
        fs::write(repo.join("CLAUDE.md"), "root instructions\n").unwrap();
        fs::write(repo.join("docs/CLAUDE.md"), "docs instructions\n").unwrap();
        git(&repo, &["add", "."]);
        git(&repo, &["commit", "-q", "-m", "base"]);

        let id = unique_lane_id();
        let packet_text = format!(
            "# Task\n\n<!-- lane {} -->\n\nChange the README.\n",
            json!({
                "id": id,
                "owns": owns,
                "class": "light",
                "checks": checks,
            })
        );
        let packet = work.path().join("packet.md");
        fs::write(&packet, &packet_text).unwrap();

        // The test binary lives under the home in a normal checkout, which
        // the sandbox hides, so the copy is what runs (and what the
        // builder's MCP config names).
        let cowproof = work.path().join("cowproof");
        {
            let _g = fork_lock();
            fs::copy(env!("CARGO_BIN_EXE_cowproof"), &cowproof).unwrap();
            // `pk` goes beside it, as an install puts them: the runner finds the
            // portkit CLI as the sibling of its own executable (G8).
            fs::copy(env!("CARGO_BIN_EXE_pk"), work.path().join("pk")).unwrap();
        }

        let fake = work.path().join("fake-claude");
        let script = format!(
            r#"#!/bin/sh
# The preflight runs `claude --version`; answer it before the lane's body.
if [ "$1" = "--version" ]; then echo "fake-claude 0.0.0"; exit 0; fi
rec="$HOME/fake"
mkdir -p "$rec"
n=1
while [ -e "$rec/seg$n" ]; do n=$((n+1)); done
seg="$rec/seg$n"
mkdir "$seg"
env | sort > "$rec/env.txt"
i=0
resume=""; model=""; prompt=""; prev=""
for a in "$@"; do
    printf '%s' "$a" > "$rec/arg.$i"
    printf '%s' "$a" > "$seg/arg.$i"
    [ "$prev" = "--resume" ] && resume="$a"
    [ "$prev" = "--model" ] && model="$a"
    prompt="$a"; prev="$a"; i=$((i+1))
done
echo "$i" > "$rec/argc"
echo "$i" > "$seg/argc"
printf '%s' "$resume" > "$seg/resume"
printf '%s' "$model" > "$seg/model"
printf '%s' "$prompt" > "$seg/prompt"
cp "$HOME/settings.json" "$seg/settings.json"
cp "$HOME/mcp.json" "$seg/mcp.json"
cp "$HOME/system-prompt.md" "$seg/system-prompt.md"
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

        // The first run of a file that was just written costs macOS seconds, and on a host busy
        // with other builds the scanner's queue made it 24 s for the fake's `--version` in the
        // preflight, which gives up at 30 s. That is the host's cost, not the property under test,
        // and it belongs outside every clock the runner keeps (the preflight's 30 s, the
        // builder's wall-clock limit, `pk doctor`'s 30 s), so each executable runs once here.
        for exe in [&fake, &cowproof, &work.path().join("pk")] {
            warm_up(exe);
        }

        Harness {
            id,
            work,
            lanes,
            repo,
            packet,
            packet_text,
            fake,
            cowproof,
        }
    }

    /// Add (or replace) one field of the packet's `<!-- lane {...} -->` header,
    /// on disk and in `packet_text`.
    fn set_header_field(&mut self, key: &str, value: Value) {
        let start = self.packet_text.find("<!-- lane ").unwrap() + "<!-- lane ".len();
        let end = start + self.packet_text[start..].find(" -->").unwrap();
        let mut header: Value = serde_json::from_str(&self.packet_text[start..end]).unwrap();
        header[key] = value;
        self.packet_text = format!(
            "{}{header}{}",
            &self.packet_text[..start],
            &self.packet_text[end..]
        );
        fs::write(&self.packet, &self.packet_text).unwrap();
    }

    fn command(&self, lanes_root: &Path) -> Command {
        let mut c = Command::new(&self.cowproof);
        c.arg("run")
            .arg(&self.packet)
            .arg("--repo")
            .arg(&self.repo)
            .arg("--lanes-root")
            .arg(lanes_root)
            .arg("--claude-bin")
            .arg(&self.fake)
            .env_remove("ANTHROPIC_API_KEY")
            // An ambient OpenAI key must not make a Codex rung runnable in a test.
            .env_remove("OPENAI_API_KEY")
            .env_remove("COWPROOF_OPENAI_UPSTREAM");
        c
    }

    /// Run the whole flow with the real key set and return what it did.
    fn run(&self) -> Output {
        output(
            self.command(self.lanes.path())
                .env("ANTHROPIC_API_KEY", REAL_KEY)
                .env("DIRECTOR_ONLY_SECRET", DIRECTOR_CANARY),
        )
    }

    /// Run with --unsandboxed flag.
    fn run_unsandboxed(&self) -> Output {
        output(
            self.command(self.lanes.path())
                .arg("--unsandboxed")
                .env("ANTHROPIC_API_KEY", REAL_KEY)
                .env("DIRECTOR_ONLY_SECRET", DIRECTOR_CANARY),
        )
    }

    /// Run the whole flow and require this exit code (the verdict's).
    fn run_expecting(&self, code: i32) -> Output {
        let out = self.run();
        assert_eq!(
            out.status.code(),
            Some(code),
            "cowproof run:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        out
    }

    /// Run the flow to a verdict, whatever it is: for tests about the builder
    /// side, which do not care how the lane was judged. Exit 1 (the run itself
    /// failed) or 4 (infrastructure) is still a failure here.
    fn run_ok(&self) -> Output {
        let out = self.run();
        reached_a_verdict(&out);
        out
    }

    fn verdict(&self) -> Value {
        serde_json::from_str(&self.read("control/verdict.json")).unwrap()
    }

    fn lane(&self) -> PathBuf {
        self.lanes.path().canonicalize().unwrap().join(&self.id)
    }

    fn read(&self, rel: &str) -> String {
        let p = self.lane().join(rel);
        fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
    }

    fn run_json(&self) -> Value {
        serde_json::from_str(&self.read("control/run.json")).unwrap()
    }

    /// What the fake recorded for its `n`th launch (1-based): `resume`,
    /// `model`, `prompt`, `settings.json`, `mcp.json`, `system-prompt.md`.
    fn seg(&self, n: usize, file: &str) -> String {
        self.read(&format!("home/fake/seg{n}/{file}"))
    }

    /// How many times the fake was launched.
    fn launches(&self) -> usize {
        (1..)
            .take_while(|n| self.lane().join(format!("home/fake/seg{n}")).exists())
            .count()
    }

    /// The fake's recorded argv, one entry per argument.
    fn argv(&self) -> Vec<String> {
        let n: usize = self.read("home/fake/argc").trim().parse().unwrap();
        (0..n)
            .map(|i| self.read(&format!("home/fake/arg.{i}")))
            .collect()
    }
}

/// The frames `cowproof lane-tools` printed, by JSON-RPC id.
fn frames(raw: &str) -> Vec<Value> {
    raw.lines()
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("{e}: {l:?}")))
        .collect()
}

fn frame(frames: &[Value], id: u64) -> &Value {
    frames
        .iter()
        .find(|f| f["id"] == id)
        .unwrap_or_else(|| panic!("no frame with id {id} in {frames:?}"))
}

/// Shell that feeds an MCP session to `cowproof lane-tools` on the lane's own
/// socket and saves every frame to `$rec/<out>`. `calls` are `(id, tool,
/// arguments)`.
fn mcp_session(out: &str, calls: &[(u64, &str, Value)]) -> String {
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

#[test]
fn run_json_records_exit_status_turns_and_the_session_id() {
    if !sandbox_available() {
        return;
    }
    let h = Harness::new("");
    let out = h.run_ok();
    let run = h.run_json();
    assert_eq!(run["exitCode"], 0, "{run}");
    assert_eq!(run["status"], "finished");
    assert_eq!(run["turns"], 2, "two assistant messages: {run}");
    assert_eq!(run["sessionId"], SESSION);
    assert_eq!(run["meter"]["session_id"], SESSION);
    assert_eq!(run["stream"]["unparsed"], 1, "the plain-text line: {run}");
    assert_eq!(
        run["lane"]["dir"].as_str().unwrap(),
        h.lane().to_str().unwrap()
    );
    // The summary line, then the verdict line, nothing else. The default
    // packet owns only README.md (the fake also creates created.txt) and the
    // fake runs none of the three declared checks.
    let stdout = String::from_utf8(out.stdout).unwrap();
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 2, "{stdout:?}");
    assert!(
        lines[0].starts_with(&format!("{}: finished, exit 0, 2 turns", h.id)),
        "{stdout}"
    );
    assert!(
        lines[1].starts_with(&format!("{}: refuted: ", h.id)),
        "{stdout}"
    );
    assert!(lines[1].contains("gate ownership failed"), "{stdout}");
    for id in ["ok", "denied", "slow"] {
        assert!(
            lines[1].contains(&format!("check \"{id}\" was never run")),
            "{stdout}"
        );
    }
}

#[test]
fn lane_patch_holds_the_edit_and_the_new_file_and_nothing_from_the_launch_baseline() {
    if !sandbox_available() {
        return;
    }
    let h = Harness::new("");
    h.run_ok();
    let patch = h.read("control/lane.patch");
    assert!(
        patch.contains("diff --git a/README.md b/README.md"),
        "{patch}"
    );
    assert!(patch.contains("+edited"), "{patch}");
    assert!(patch.contains("+++ b/created.txt"), "{patch}");
    assert!(patch.contains("+created"), "{patch}");
    // The runner removed `.env` from the clone at launch; that deletion is the
    // launch patch, not the builder's.
    assert!(!patch.contains(".env"), "{patch}");
    assert!(!patch.contains(CANARY_ENV), "{patch}");
    assert_eq!(
        h.run_json()["patchBytes"].as_u64().unwrap() as usize,
        patch.len()
    );
}

#[test]
fn stream_jsonl_equals_the_fakes_stdout_byte_for_byte() {
    if !sandbox_available() {
        return;
    }
    let h = Harness::new("");
    h.run_ok();
    let stream = fs::read(h.lane().join("control/stream.jsonl")).unwrap();
    assert_eq!(stream, FAKE_STREAM.as_bytes());
}

#[test]
fn the_real_key_never_reaches_the_builder_or_any_file_in_the_lane() {
    if !sandbox_available() {
        return;
    }
    let h = Harness::new("");
    h.run_ok();
    let env = h.read("home/fake/env.txt");
    let key_line = env
        .lines()
        .find(|l| l.starts_with("ANTHROPIC_API_KEY="))
        .unwrap_or_else(|| panic!("no ANTHROPIC_API_KEY in the builder env:\n{env}"));
    assert!(
        key_line.starts_with("ANTHROPIC_API_KEY=placeholder-"),
        "{key_line}"
    );
    assert!(
        !env.contains(DIRECTOR_CANARY),
        "the director's environment reached the builder:\n{env}"
    );
    assert!(
        env.contains("ANTHROPIC_BASE_URL=http://127.0.0.1:"),
        "{env}"
    );

    let mut scanned = 0;
    let mut stack = vec![h.lane()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            let meta = fs::symlink_metadata(&path).unwrap();
            if meta.is_dir() {
                stack.push(path);
            } else if meta.is_file() {
                let bytes = fs::read(&path).unwrap();
                assert!(
                    !bytes
                        .windows(REAL_KEY.len())
                        .any(|w| w == REAL_KEY.as_bytes()),
                    "the real key is in {}",
                    path.display()
                );
                scanned += 1;
            }
        }
    }
    // The scan saw the lane's real files (control, home, the clone and its .git).
    assert!(scanned > 20, "only {scanned} files scanned");
}

/// The builder POSTs to `$ANTHROPIC_BASE_URL` with perl (on every macOS and
/// Linux host) and records the whole HTTP answer. The path is one the proxy
/// refuses, so the REAL egress proxy answers from its own policy and nothing
/// is sent upstream: no network, no stub, and no race over which socket the
/// sandbox sees (a replaced `proxy.sock` would be bound in at launch on
/// Linux). Only the real `ProxyServer` produces this answer, and only the
/// bridge can carry the request to it from inside the sandbox.
const POST_THROUGH_THE_BRIDGE: &str = r#"
host_port="${ANTHROPIC_BASE_URL#http://}"
perl -MIO::Socket::INET -e '
  $s = IO::Socket::INET->new(PeerAddr => $ARGV[0], Proto => "tcp", Timeout => 10)
      or die "connect: $!\n";
  $b = "{}";
  print $s "POST /v1/refused-by-the-proxy HTTP/1.1\r\nHost: $ARGV[0]\r\n"
      . "x-api-key: $ENV{ANTHROPIC_API_KEY}\r\ncontent-type: application/json\r\n"
      . "connection: close\r\ncontent-length: " . length($b) . "\r\n\r\n$b";
  local $/; print <$s>;' "$host_port" > "$rec/answer" 2> "$rec/answer.err"
echo "$?" > "$rec/answer.status"
"#;

#[test]
fn the_builder_reaches_the_real_egress_proxy_through_the_bridge_and_the_bridge_ends_with_it() {
    if !sandbox_available() {
        return;
    }
    let h = Harness::new(POST_THROUGH_THE_BRIDGE);
    h.run_ok();

    // The builder was pointed at its lane's bridge port, recorded in run.json.
    let port = cowproof_run::bridge::bridge_port(&h.id);
    assert!((40_000..60_000).contains(&port), "{port}");
    let env = h.read("home/fake/env.txt");
    assert!(
        env.lines()
            .any(|l| l == format!("ANTHROPIC_BASE_URL=http://127.0.0.1:{port}")),
        "{env}"
    );
    assert_eq!(h.run_json()["bridgePort"], port, "{}", h.run_json());

    // builder -> bridge -> proxy.sock -> the real ProxyServer: its own
    // refusal came back through both hops.
    let answer = h.read("home/fake/answer");
    let err = h.read("home/fake/answer.err");
    assert_eq!(h.read("home/fake/answer.status").trim(), "0", "{err}");
    assert!(
        answer.starts_with("HTTP/1.1 403"),
        "no answer from the proxy through the bridge: {answer:?} {err}"
    );
    assert!(answer.ends_with("forbidden\n"), "{answer:?}");

    // The bridge lived only as long as the builder: its port is free again.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match std::net::TcpListener::bind(("127.0.0.1", port)) {
            Ok(_) => break,
            Err(e) => {
                assert!(
                    Instant::now() < deadline,
                    "the bridge outlived the builder: {e}"
                );
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

#[test]
fn the_fakes_argv_has_the_r15_flags_and_an_mcp_config_naming_the_cowproof_tools() {
    if !sandbox_available() {
        return;
    }
    let h = Harness::new("");
    h.run_ok();
    let argv = h.argv();
    let value_of = |flag: &str| -> &str {
        let i = argv
            .iter()
            .position(|a| a == flag)
            .unwrap_or_else(|| panic!("no {flag} in {argv:?}"));
        &argv[i + 1]
    };
    assert_eq!(argv[0], "-p");
    assert_eq!(value_of("--model"), "haiku");
    assert_eq!(value_of("--output-format"), "stream-json");
    assert_eq!(value_of("--setting-sources"), "");
    assert_eq!(value_of("--max-turns"), "60");
    assert!(argv.contains(&"--tools=Bash,Read,Edit,Write,Glob,Grep".to_string()));
    assert!(argv.contains(
        &"--disallowedTools=Task,Workflow,SendMessage,ScheduleWakeup,CronCreate,Skill,EnterWorktree"
            .to_string()
    ));
    assert!(argv.contains(&"--verbose".to_string()));
    assert!(argv.contains(&"--strict-mcp-config".to_string()));
    assert!(!argv.contains(&"--bare".to_string()), "R15: no --bare");

    let home = h.lane().join("home");
    assert_eq!(
        value_of("--settings"),
        home.join("settings.json").to_str().unwrap()
    );
    let settings: Value = serde_json::from_str(&h.read("home/settings.json")).unwrap();
    assert!(
        settings["permissions"]["allow"]
            .as_array()
            .unwrap()
            .contains(&json!("mcp__cowproof-tools"))
    );
    assert!(
        settings["permissions"]["deny"]
            .as_array()
            .unwrap()
            .contains(&json!("WebFetch"))
    );

    // The packet is the prompt; the shared preamble is the system prompt (D20).
    assert_eq!(argv.last().unwrap(), &h.packet_text);
    assert_eq!(
        value_of("--append-system-prompt-file"),
        home.join("system-prompt.md").to_str().unwrap()
    );
    assert!(h.read("home/system-prompt.md").starts_with(PREAMBLE));
    assert!(!argv.last().unwrap().contains(PREAMBLE));

    // The MCP server is the cowproof binary, serving the lane's own socket.
    assert_eq!(
        value_of("--mcp-config"),
        home.join("mcp.json").to_str().unwrap()
    );
    let mcp: Value = serde_json::from_str(&h.read("home/mcp.json")).unwrap();
    let servers = mcp["mcpServers"].as_object().unwrap();
    assert_eq!(servers.len(), 1, "{mcp}");
    assert_eq!(
        servers["cowproof-tools"]["command"],
        h.cowproof.canonicalize().unwrap().to_str().unwrap()
    );
    assert_eq!(
        servers["cowproof-tools"]["args"],
        json!([
            "lane-tools",
            "--socket",
            h.lane().join("sock/runner.sock").to_str().unwrap()
        ])
    );
}

#[test]
fn the_tools_socket_is_live_when_the_builder_starts() {
    if !sandbox_available() {
        return;
    }
    // The fake's first action is a tool call over the socket. It connects
    // rather than stats: the sandbox hides the socket's directory, so
    // `[ -S ]` is false inside even for a live socket. A runner that bound
    // after launch would leave this connect with nothing to reach.
    let h = Harness::new(&mcp_session("probe.out", &[(3, "check_ruling", json!({}))]));
    h.run_ok();
    let out = frames(&h.read("home/fake/probe.out"));
    let probe = &frame(&out, 3)["result"];
    assert_eq!(probe["isError"], false, "{out:?}");
    assert_eq!(
        probe["structuredContent"]["status"], "no_escalation",
        "{out:?}"
    );
}

#[test]
fn a_builder_ask_over_the_tools_socket_lands_in_the_escalation_queue() {
    if !sandbox_available() {
        return;
    }
    let ask = json!({
        "kind": "design",
        "question": "which way through the fake?",
        "tried": ["read the docs"],
        "options": [{"id": "a", "summary": "first", "cost": "low"}],
        "recommend": "a",
        "blocking": false,
    });
    let h = Harness::new(&mcp_session("mcp.out", &[(3, "ask", ask)]));
    h.run_ok();
    let out = frames(&h.read("home/fake/mcp.out"));
    assert_eq!(frame(&out, 3)["result"]["isError"], false, "{out:?}");
    let queue = h.read("control/escalations.jsonl");
    assert!(queue.contains("which way through the fake?"), "{queue}");
    assert!(queue.contains(&h.id), "{queue}");
}

#[test]
fn run_check_runs_the_declared_command_in_the_check_sandbox() {
    if !sandbox_available() {
        return;
    }
    let h = Harness::new(&mcp_session(
        "mcp.out",
        &[
            (3, "run_check", json!({"id": "ok"})),
            (4, "run_check", json!({"id": "denied"})),
            (5, "run_check", json!({"id": "rm -rf /"})),
        ],
    ));
    h.run_ok();
    let out = frames(&h.read("home/fake/mcp.out"));
    let ok = &frame(&out, 3)["result"]["structuredContent"];
    assert_eq!(ok["passed"], true, "{ok}");
    assert_eq!(ok["exit_status"], 0);
    assert_eq!(ok["output"], "check-ran\n");
    // The same command line that reads the control directory fails in the
    // check sandbox: the runner did not run it with its own privileges.
    assert!(
        h.lane().join("control/builder.stderr").exists(),
        "the file the check tries to read exists"
    );
    let denied = &frame(&out, 4)["result"]["structuredContent"];
    assert_eq!(denied["passed"], false, "{denied}");
    assert_ne!(denied["exit_status"], 0);
    // An id outside the packet's table is refused and never run.
    assert_eq!(frame(&out, 5)["result"]["isError"], true, "{out:?}");
}

#[test]
fn run_check_runs_one_check_at_a_time_per_lane() {
    if !sandbox_available() {
        return;
    }
    let call = |name: &str| mcp_session(name, &[(3, "run_check", json!({"id": "slow"}))]);
    let body = format!("( {} ) &\n( {} ) &\nwait\n", call("mcp.a"), call("mcp.b"));
    let h = Harness::new(&body);
    h.run_ok();
    for name in ["mcp.a", "mcp.b"] {
        let out = frames(&h.read(&format!("home/fake/{name}")));
        assert_eq!(
            frame(&out, 3)["result"]["structuredContent"]["passed"],
            true,
            "{name}: {out:?}"
        );
    }
    // Two overlapping checks would write start, start, end, end.
    assert_eq!(h.read("scratch/trace"), "start\nend\nstart\nend\n");
}

#[test]
fn a_lint_error_stops_the_run_before_any_lane_exists() {
    let h = Harness::new("");
    // A check pipeline that hides its exit status is a lint error.
    let bad = format!(
        "{}\n## Checks\n\n```\ncargo test | grep ok\n```\n",
        h.packet_text
    );
    fs::write(&h.packet, bad).unwrap();
    let lanes_root = h.work.path().join("never-created");
    let out = output(h.command(&lanes_root).env("ANTHROPIC_API_KEY", REAL_KEY));
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("masked-pipe-status"), "{stderr}");
    assert!(stderr.contains("packet lint found errors"), "{stderr}");
    assert!(!lanes_root.exists(), "no lanes root, so no lane dir");
    assert!(!stderr.contains(REAL_KEY));
}

// ---- Proof: the verdict after the builder exits ----------------------------
//
// Each test runs the whole flow with the fake `claude`, which drives
// `cowproof lane-tools` over the lane's socket (MCP `run_check`), and asserts
// the verdict file, the named reason and the exit code. The fake always edits
// README.md and creates created.txt before its own body.

/// Shell for a fake that calls `run_check` once for each id, in order, saving
/// the frames to `$rec/mcp.out` (frame ids start at 3).
fn run_checks(ids: &[&str]) -> String {
    let calls: Vec<(u64, &str, Value)> = ids
        .iter()
        .enumerate()
        .map(|(i, id)| (3 + i as u64, "run_check", json!({ "id": id })))
        .collect();
    mcp_session("mcp.out", &calls)
}

fn passed(h: &Harness, id: u64) -> bool {
    let out = frames(&h.read("home/fake/mcp.out"));
    frame(&out, id)["result"]["structuredContent"]["passed"] == true
}

fn git_out(repo: &Path, args: &[&str]) -> String {
    let out = output(
        Command::new("git")
            .args(["-C", repo.to_str().unwrap()])
            .args(args),
    );
    assert!(out.status.success(), "git {args:?}");
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

fn reasons(verdict: &Value) -> Vec<String> {
    verdict["reasons"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r.as_str().unwrap().to_string())
        .collect()
}

/// A packet that owns what the fake touches, with two checks that read it.
fn owned_packet(fake_body: &str) -> Harness {
    Harness::with_packet(
        fake_body,
        json!(["README.md", "created.txt"]),
        json!([
            {"id": "edit", "command": "grep -q edited README.md"},
            {"id": "made", "command": "test -f created.txt"},
        ]),
    )
}

#[test]
fn every_check_run_and_reproduced_with_owned_edits_is_proved_and_sealed_in_a_capsule() {
    if !sandbox_available() {
        return;
    }
    let h = owned_packet(&run_checks(&["edit", "made"]));
    let out = h.run_expecting(0);
    assert!(
        passed(&h, 3) && passed(&h, 4),
        "both checks pass in the lane"
    );

    let verdict = h.verdict();
    assert_eq!(verdict["verdict"], "proved", "{verdict}");
    assert_eq!(verdict["exitCode"], 0);
    assert!(reasons(&verdict).is_empty(), "{verdict}");
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert_eq!(
        stdout.lines().last().unwrap(),
        format!("{}: proved", h.id),
        "{stdout}"
    );

    // The capsule reads back with every recorded hash verified, and holds what
    // the lane was, not just that a file exists.
    let dir = h.lane().join("control/capsule");
    let capsule = Capsule::read(&dir).expect("the capsule reads back");
    assert_eq!(
        capsule.base_commit,
        git_out(&h.repo, &["rev-parse", "HEAD"])
    );
    assert_eq!(
        capsule.base_tree_hash,
        git_out(&h.repo, &["rev-parse", "HEAD^{tree}"])
    );
    assert_eq!(capsule.builder_model, "haiku");
    assert!(!capsule.unsandboxed);
    assert!(
        capsule.local_replay_only,
        "the test repository has no remote"
    );
    assert_eq!(capsule.lane_state, "proved");
    assert_eq!(capsule.environment.os, std::env::consts::OS);
    for file in [
        "lane.patch",
        "launch_removed.json",
        "gates.json",
        "checks/edit.json",
        "checks/made.json",
    ] {
        assert!(capsule.file_hashes.contains_key(file), "{file} not hashed");
    }
    assert_eq!(
        fs::read(dir.join("lane.patch")).unwrap(),
        fs::read(h.lane().join("control/lane.patch")).unwrap()
    );
    let edit: Value = serde_json::from_str(&h.read("control/capsule/checks/edit.json")).unwrap();
    assert_eq!(edit["command"], "grep -q edited README.md");
    assert_eq!(edit["exit_status"], 0);
    // The launch baseline is the sorted list of removed paths, nothing else.
    assert_eq!(
        capsule.launch_removed,
        [".env", "CLAUDE.md", "docs/CLAUDE.md", "sub/.env.local"]
    );
    assert!(!dir.join("launch.patch").exists());

    // Verify really rebuilt the tree: the patch is applied (created.txt) and so
    // is the launch baseline (`.env` is gone, though the base commit has it).
    let tree = h.lane().join("scratch/verify/tree");
    assert_eq!(
        fs::read_to_string(tree.join("created.txt")).unwrap(),
        "created\n"
    );
    for gone in [".env", "CLAUDE.md", "docs/CLAUDE.md", "sub/.env.local"] {
        assert!(!tree.join(gone).exists(), "{gone} must be removed");
    }
    // The rebuilt tree's baseline commit is the tree the lane launched from.
    let launch_commit = h.run_json()["launchCommit"].as_str().unwrap().to_string();
    let lane_launch_tree = git_out(
        &h.lane().join("clone"),
        &["rev-parse", &format!("{launch_commit}^{{tree}}")],
    );
    assert_eq!(
        git_out(&tree, &["rev-parse", "HEAD^{tree}"]),
        lane_launch_tree
    );
    assert_ne!(
        lane_launch_tree,
        git_out(&h.repo, &["rev-parse", "HEAD^{tree}"]),
        "the baseline removed something"
    );

    // The capsule is tamper evident.
    fs::write(dir.join("lane.patch"), "tampered").unwrap();
    assert!(Capsule::read(&dir).is_err());
}

/// A fake builder that makes a temp file under `$TMPDIR` and writes to it, as
/// Claude Code's Bash tool and every tool that honours `TMPDIR` do. macOS denies
/// every write outside the grants, so this fails unless the temp directory the
/// builder is given is one it may write. (`${TMPDIR:?}` also fails when the
/// variable is unset. Apple's own `mktemp` with no template ignores `TMPDIR` and
/// uses the per-user `/var/folders` directory, so the tests name the template.)
const FAKE_MKTEMP: &str = r#"
t="$(mktemp "${TMPDIR:?}/builder.XXXXXX")" || { echo "mktemp failed" > "$HOME/fake/mktemp.err"; exit 1; }
echo from-the-builder > "$t" || { echo "write failed" > "$HOME/fake/mktemp.err"; exit 1; }
echo "$t" > "$HOME/fake/mktemp.path"
"#;

/// The declared check that makes and writes a temp file of its own.
const MKTEMP_CHECK: &str =
    r#"f="$(mktemp "${TMPDIR:?}/check.XXXXXX")" && echo x > "$f" && test -s "$f""#;

/// A packet that owns what the fake touches, with one check that uses a temp file.
fn mktemp_packet() -> Harness {
    Harness::with_packet(
        &format!("{FAKE_MKTEMP}{}", run_checks(&["edit", "temp"])),
        json!(["README.md", "created.txt"]),
        json!([
            {"id": "edit", "command": "grep -q edited README.md"},
            {"id": "temp", "command": MKTEMP_CHECK},
        ]),
    )
}

#[test]
fn the_builder_and_every_check_get_a_temp_dir_inside_the_lane() {
    if !sandbox_available() {
        return;
    }
    let h = mktemp_packet();
    h.run_expecting(0);
    assert!(
        !h.lane().join("home/fake/mktemp.err").exists(),
        "the builder could not use mktemp: {}",
        h.read("home/fake/mktemp.err")
    );
    // The builder's mktemp file is in the lane's scratch, which it may write.
    let tmp = h.lane().join("scratch/tmp");
    let made = h.read("home/fake/mktemp.path");
    assert!(
        Path::new(made.trim()).starts_with(&tmp),
        "{made} is not under {}",
        tmp.display()
    );
    // The builder's environment names that directory, for the shell tools and
    // for Claude Code's own temp directory.
    let env = h.read("home/fake/env.txt");
    for var in ["TMPDIR", "CLAUDE_CODE_TMPDIR"] {
        assert!(
            env.lines().any(|l| l == format!("{var}={}", tmp.display())),
            "{var} is not {}\n{env}",
            tmp.display()
        );
    }
    // The declared check that uses mktemp passed in the lane and again, in the
    // verifier's own temp directory, in the rebuilt tree: the lane is proved.
    assert!(
        passed(&h, 3) && passed(&h, 4),
        "both checks pass in the lane"
    );
    let verdict = h.verdict();
    assert_eq!(verdict["verdict"], "proved", "{verdict}");
    assert!(h.lane().join("scratch/verify/tmp").is_dir());
}

/// A director whose rustup home is somewhere other than `~/.rustup` (CI images and custom
/// installs): a rustup proxy inside a lane finds its toolchains through `RUSTUP_HOME`,
/// else `$HOME/.rustup`, and the lane's `HOME` holds none. The test's own rustup home is a
/// directory with a `marker` file in it, so it needs no rustup at all: the builder, the
/// builder's `run_check` and the verifier must each see `RUSTUP_HOME` naming a directory
/// they can read, and the toolchain pin passes through with it.
#[test]
fn the_directors_rustup_home_reaches_the_builder_every_check_and_the_verifier() {
    if !sandbox_available() {
        return;
    }
    let rustup = var_tmp("cp-run-rustup-");
    fs::write(rustup.path().join("marker"), "toolchains live here\n").unwrap();
    let canonical = rustup.path().canonicalize().unwrap();
    let h = Harness::with_packet(
        &run_checks(&["edit", "home", "pin"]),
        json!(["README.md", "created.txt"]),
        json!([
            {"id": "edit", "command": "grep -q edited README.md"},
            {"id": "home", "command": "test -n \"$RUSTUP_HOME\" && test -r \"$RUSTUP_HOME/marker\""},
            {"id": "pin", "command": "test \"$RUSTUP_TOOLCHAIN\" = 1.80.0"},
        ]),
    );
    let out = output(
        h.command(h.lanes.path())
            .env("ANTHROPIC_API_KEY", REAL_KEY)
            .env("RUSTUP_HOME", rustup.path())
            .env("RUSTUP_TOOLCHAIN", "1.80.0"),
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "cowproof run:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    // The builder itself: its environment names the director's rustup home (resolved).
    let env = h.read("home/fake/env.txt");
    for line in [
        format!("RUSTUP_HOME={}", canonical.display()),
        "RUSTUP_TOOLCHAIN=1.80.0".to_string(),
    ] {
        assert!(env.lines().any(|l| l == line), "{line} not in\n{env}");
    }
    // The builder's `run_check` sandbox saw it (the three checks passed there) ...
    assert!(
        passed(&h, 3) && passed(&h, 4) && passed(&h, 5),
        "all three checks pass in the lane"
    );
    // ... and so did the verifier's rerun, so the lane is proved.
    let verdict = h.verdict();
    assert_eq!(verdict["verdict"], "proved", "{verdict}");
}

/// A check command that passes only when reading `path` FAILS and its content does not
/// appear in what the failed `cat` printed. `! cat path` alone would also pass for a path
/// that does not exist, so the test pairs it with a control file that does.
fn hidden_file(path: &Path) -> String {
    format!(
        "out=$(cat {0} 2>&1) && exit 1; case \"$out\" in *CANARY*) exit 1;; esac",
        path.display()
    )
}

/// The usual rustup install: the proxies (`cargo`, `rustc`) live in `<home>/.cargo/bin`, the
/// toolchains in `<home>/.rustup`, and the director's `PATH` starts with the first. Both are
/// under the real home, which the sandbox hides, so a check that runs a proxy needs that ONE
/// bin directory on the sandbox `PATH` and readable, and the rustup home named in
/// `RUSTUP_HOME`. The fake proxy here exits 0 only if `$RUSTUP_HOME/marker` is readable, so
/// it proves both; it must run in the builder's `run_check` and in the verifier.
///
/// The rest of the cargo home must stay hidden. `credentials.toml` is not a sufficient
/// witness for that: the profile denies it by name after every grant (D18), so it stays
/// unreadable even if the whole `.cargo` directory were granted (the macOS profile puts
/// that literal deny last; checked by granting `bin.parent()` instead of `bin`). The
/// witness is `config.toml`, which only the hidden home covers, and a control file inside
/// `bin` proves the check can read what is granted (so "cat failed" is not a typo in a path
/// or a sandbox that hides everything).
#[test]
fn a_rustup_proxy_in_the_directors_cargo_bin_runs_in_run_check_and_in_the_verifier() {
    if !sandbox_available() {
        return;
    }
    let fake_home = var_tmp("cp-run-home-");
    let home = fake_home.path().canonicalize().unwrap();
    let bin = home.join(".cargo/bin");
    fs::create_dir_all(&bin).unwrap();
    fs::create_dir_all(home.join(".rustup")).unwrap();
    fs::write(home.join(".rustup/marker"), "toolchains live here\n").unwrap();
    // Secrets that live beside the bin directory, in the cargo home: they must stay hidden.
    // `credentials.toml` is also denied by name; `config.toml` (registry tokens can live
    // there too) is covered by the hidden home alone.
    fs::write(
        home.join(".cargo/credentials.toml"),
        "token = \"CANARY-CARGO\"\n",
    )
    .unwrap();
    fs::write(
        home.join(".cargo/config.toml"),
        "[registry]\ntoken = \"CANARY-CONFIG\"\n",
    )
    .unwrap();
    // A control inside the granted directory: readable.
    fs::write(bin.join("granted.txt"), "readable in the granted bin\n").unwrap();
    {
        let _g = fork_lock();
        let proxy = bin.join("fakerustc");
        fs::write(&proxy, "#!/bin/sh\ntest -r \"$RUSTUP_HOME/marker\"\n").unwrap();
        fs::set_permissions(&proxy, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let h = Harness::with_packet(
        &run_checks(&["edit", "proxy", "control", "config", "creds"]),
        json!(["README.md", "created.txt"]),
        json!([
            {"id": "edit", "command": "grep -q edited README.md"},
            {"id": "proxy", "command": "fakerustc"},
            {"id": "control", "command": format!("grep -q readable {}/.cargo/bin/granted.txt", home.display())},
            {"id": "config", "command": hidden_file(&home.join(".cargo/config.toml"))},
            {"id": "creds", "command": hidden_file(&home.join(".cargo/credentials.toml"))},
        ]),
    );
    let out = output(
        h.command(h.lanes.path())
            .env("ANTHROPIC_API_KEY", REAL_KEY)
            .env("HOME", &home)
            .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
            .env_remove("CARGO_HOME")
            .env_remove("RUSTUP_HOME")
            .env_remove("RUSTUP_TOOLCHAIN"),
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "cowproof run:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        (3..=7).all(|id| passed(&h, id)),
        "the proxy, the readable control and both hidden-file checks pass in the lane"
    );
    // The builder's own PATH keeps the bin directory, first, and nothing else of the home.
    let env = h.read("home/fake/env.txt");
    assert!(
        env.lines()
            .any(|l| l == format!("PATH={}:/usr/bin:/bin", bin.display())),
        "{env}"
    );
    // The verifier ran the proxy again in the rebuilt tree: the lane is proved.
    let verdict = h.verdict();
    assert_eq!(verdict["verdict"], "proved", "{verdict}");
}

/// Every file under `dir` (not following symlinks) whose bytes contain `needle`.
fn files_containing(dir: &Path, needle: &str) -> Vec<PathBuf> {
    let mut found = Vec::new();
    for entry in fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        let kind = entry.file_type().unwrap();
        if kind.is_dir() {
            found.extend(files_containing(&path, needle));
        } else if kind.is_file() {
            let bytes = fs::read(&path).unwrap();
            if bytes.windows(needle.len()).any(|w| w == needle.as_bytes()) {
                found.push(path);
            }
        }
    }
    found
}

#[test]
fn the_content_of_a_removed_env_file_reaches_no_file_under_control() {
    if !sandbox_available() {
        return;
    }
    let h = owned_packet(&run_checks(&["edit", "made"]));
    h.run_expecting(0);
    assert_eq!(h.verdict()["verdict"], "proved");

    let control = h.lane().join("control");
    // The search can find something: the builder's edit is in lane.patch, twice over.
    assert!(
        !files_containing(&control, "+edited").is_empty(),
        "the search found nothing it should find"
    );
    assert_eq!(
        files_containing(&control, CANARY_ENV),
        Vec::<PathBuf>::new(),
        "the removed .env content must appear in no file under control/ (capsule included)"
    );
    // The paths are recorded; the content is not.
    let removed = h.read("control/capsule/launch_removed.json");
    assert!(
        removed.contains("\".env\"") && removed.contains("sub/.env.local"),
        "{removed}"
    );
}

#[test]
fn a_declared_check_the_builder_never_ran_is_incomplete_and_named() {
    if !sandbox_available() {
        return;
    }
    let h = owned_packet(&run_checks(&["edit"]));
    let out = h.run_expecting(3);

    let verdict = h.verdict();
    assert_eq!(verdict["verdict"], "incomplete", "{verdict}");
    assert_eq!(verdict["exitCode"], 3);
    assert_eq!(verdict["unrun"], json!(["made"]));
    let reasons = reasons(&verdict);
    assert_eq!(reasons.len(), 1, "{reasons:?}");
    assert!(reasons[0].contains("\"made\" was never run"), "{reasons:?}");
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout
            .lines()
            .last()
            .unwrap()
            .starts_with(&format!("{}: incomplete: ", h.id))
            && stdout.contains("\"made\""),
        "{stdout}"
    );
    // Only what the builder recorded is sealed: no invented result for `made`.
    assert!(h.lane().join("control/capsule/checks/edit.json").exists());
    assert!(!h.lane().join("control/capsule/checks/made.json").exists());
}

#[test]
fn a_check_that_fails_when_the_builder_runs_it_is_refuted_and_named() {
    if !sandbox_available() {
        return;
    }
    // `breaks` looks for text the fake's edit never writes, so it fails in the
    // lane and fails again in verify: a reproduced failure, one reason.
    let h = Harness::with_packet(
        &run_checks(&["edit", "breaks"]),
        json!(["README.md", "created.txt"]),
        json!([
            {"id": "edit", "command": "grep -q edited README.md"},
            {"id": "breaks", "command": "grep -q no-such-text README.md"},
        ]),
    );
    let out = h.run_expecting(2);
    assert!(passed(&h, 3) && !passed(&h, 4));

    let verdict = h.verdict();
    assert_eq!(verdict["verdict"], "refuted", "{verdict}");
    assert_eq!(verdict["exitCode"], 2);
    assert_eq!(verdict["failedChecks"], json!(["breaks"]));
    assert_eq!(verdict["diverged"], json!([]));
    let reasons = reasons(&verdict);
    assert_eq!(reasons.len(), 1, "{reasons:?}");
    assert!(
        reasons[0].contains("\"breaks\" failed when the builder ran it"),
        "{reasons:?}"
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout
            .lines()
            .last()
            .unwrap()
            .starts_with(&format!("{}: refuted: ", h.id)),
        "{stdout}"
    );
    // A failing recorded result is sealed as a failure.
    let breaks: Value =
        serde_json::from_str(&h.read("control/capsule/checks/breaks.json")).unwrap();
    assert_eq!(breaks["exit_status"], 1);
}

#[test]
fn an_edit_outside_owns_is_refuted_by_the_ownership_gate() {
    if !sandbox_available() {
        return;
    }
    // The fake also creates created.txt, which this packet does not own.
    let h = Harness::with_packet(
        &run_checks(&["edit"]),
        json!(["README.md"]),
        json!([{"id": "edit", "command": "grep -q edited README.md"}]),
    );
    let out = h.run_expecting(2);
    assert!(passed(&h, 3), "the check itself passes");

    let verdict = h.verdict();
    assert_eq!(verdict["verdict"], "refuted", "{verdict}");
    assert_eq!(verdict["exitCode"], 2);
    assert_eq!(verdict["failedGates"], json!(["ownership"]));
    assert_eq!(verdict["failedChecks"], json!([]));
    let reasons = reasons(&verdict);
    assert_eq!(reasons.len(), 1, "{reasons:?}");
    assert!(
        reasons[0].contains("gate ownership failed") && reasons[0].contains("created.txt"),
        "{reasons:?}"
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("gate ownership failed"), "{stdout}");
    // The gate report is sealed too, and says the same.
    let gates: Value = serde_json::from_str(&h.read("control/capsule/gates.json")).unwrap();
    assert_eq!(gates["any_failed"], true);
}

#[test]
fn a_check_that_passes_in_the_lane_but_not_in_the_rebuilt_tree_is_a_divergence() {
    if !sandbox_available() {
        return;
    }
    // The builder owns the clone's `.git`, so it can exclude a file from the
    // patch. `marker` exists in the lane (the check passes there) and is not in
    // lane.patch, so the verifier's rebuilt tree lacks it and the check fails.
    let body = format!(
        "mkdir -p .git/info\necho marker >> .git/info/exclude\necho state > marker\n{}",
        run_checks(&["edit", "marker"])
    );
    let h = Harness::with_packet(
        &body,
        json!(["README.md", "created.txt"]),
        json!([
            {"id": "edit", "command": "grep -q edited README.md"},
            {"id": "marker", "command": "test -f marker"},
        ]),
    );
    let out = h.run_expecting(2);
    assert!(passed(&h, 3) && passed(&h, 4), "both pass in the lane");
    assert!(
        !h.read("control/lane.patch").contains("marker"),
        "the excluded file is not in the patch"
    );

    let verdict = h.verdict();
    assert_eq!(verdict["verdict"], "refuted", "{verdict}");
    assert_eq!(verdict["exitCode"], 2);
    assert_eq!(verdict["diverged"], json!(["marker"]));
    assert_eq!(verdict["failedChecks"], json!([]));
    assert_eq!(verdict["failedGates"], json!([]));
    let reasons = reasons(&verdict);
    assert_eq!(reasons.len(), 1, "{reasons:?}");
    assert!(
        reasons[0].contains("\"marker\" diverged")
            && reasons[0].contains("recorded a pass")
            && reasons[0].contains("verify got exit 1"),
        "{reasons:?}"
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("diverged"), "{stdout}");
}

#[test]
fn run_help_documents_every_exit_code() {
    let out = output(Command::new(env!("CARGO_BIN_EXE_cowproof")).args(["run", "--help"]));
    assert!(out.status.success());
    let help = String::from_utf8(out.stdout)
        .unwrap()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    for code in [
        "0 proved",
        "2 refuted",
        "3 incomplete",
        "4 infrastructure",
        "5 timeout",
        "6 cost-cap",
        "7 stopped",
        "8 escalation-limit",
        "130 interrupted by SIGINT or SIGTERM",
    ] {
        assert!(help.contains(code), "no {code:?} in: {help}");
    }
}
#[test]
fn a_missing_api_key_stops_the_run_before_any_lane_exists() {
    let h = Harness::new("");
    let lanes_root = h.work.path().join("never-created");
    let out = output(&mut h.command(&lanes_root));
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("ANTHROPIC_API_KEY is not set"), "{stderr}");
    assert!(!lanes_root.exists(), "no lanes root, so no lane dir");
}

// ---- The resume loop (D9, D22, D25) -------------------------------------
//
// The test plays the director: it starts `cowproof run`, waits until the
// lane's escalation queue shows the builder's ask, then rules with the real
// `cowproof rule`. The fake `claude` asks on its first launch only; on later
// launches it records what it was started with and runs the checks.

/// How long a parked-lane test waits for a run to ask or to end. It only keeps a hung run from
/// hanging the test, so it is long: a launch that takes a few seconds on an idle machine has
/// taken most of a minute on a loaded Linux host.
const PARKED_WAIT: Duration = Duration::from_secs(180);

/// A `cowproof run` in flight.
fn start(h: &Harness) -> Child {
    let _g = fork_lock();
    h.command(h.lanes.path())
        .env("ANTHROPIC_API_KEY", REAL_KEY)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

/// Wait for the run to end. A run that outlives `PARKED_WAIT` is killed (by
/// its pid, nothing else) and fails the test with what it printed.
fn finish(mut child: Child) -> Output {
    let deadline = Instant::now() + PARKED_WAIT;
    loop {
        if child.try_wait().unwrap().is_some() {
            return child.wait_with_output().unwrap();
        }
        if Instant::now() > deadline {
            child.kill().unwrap();
            let out = child.wait_with_output().unwrap();
            panic!(
                "cowproof run was still going after {PARKED_WAIT:?}:\nstdout: {}\nstderr: {}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// The id of the `nth` (1-based) escalation the queue file shows as asked,
/// waiting for it to appear.
fn wait_for_ask(h: &Harness, child: &mut Child, nth: usize) -> String {
    let path = h.lane().join("control/escalations.jsonl");
    let deadline = Instant::now() + PARKED_WAIT;
    loop {
        let text = fs::read_to_string(&path).unwrap_or_default();
        let asked: Vec<String> = text
            .lines()
            .filter_map(|l| serde_json::from_str::<Value>(l).ok())
            .filter(|v| v["event"] == "asked")
            .map(|v| v["id"].as_str().unwrap().to_string())
            .collect();
        if let Some(id) = asked.get(nth - 1) {
            return id.clone();
        }
        assert!(
            child.try_wait().unwrap().is_none(),
            "the run ended before ask {nth}: {text}"
        );
        assert!(Instant::now() < deadline, "ask {nth} never appeared");
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// `cowproof rule <lane> <id> <verdict args>`, which must succeed.
fn rule(h: &Harness, id: &str, verdict: &[&str]) {
    let out = output(
        Command::new(&h.cowproof)
            .args(["rule", &h.id, id])
            .args(verdict)
            .arg("--lanes-root")
            .arg(h.lanes.path()),
    );
    assert!(
        out.status.success(),
        "cowproof rule {verdict:?}:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Events of one kind in the lane's queue file.
fn queue_events(h: &Harness, event: &str) -> Vec<Value> {
    h.read("control/escalations.jsonl")
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter(|v| v["event"] == event)
        .collect()
}

fn blocking_ask(question: &str) -> Value {
    json!({
        "kind": "blocker",
        "question": question,
        "tried": ["read the packet"],
        "options": [{"id": "a", "summary": "Option A", "cost": "low"}],
        "recommend": "a",
        "blocking": true,
    })
}

/// A fake that, on its first launch only, scribbles over the files the runner
/// wrote in its home (the home is writable) and asks a blocking `ask`; on
/// every later launch it runs the checks, unless `later` says otherwise.
fn asks_first(question: &str, blocking: bool, later: &str) -> String {
    let mut ask = blocking_ask(question);
    ask["blocking"] = json!(blocking);
    format!(
        "if [ \"$n\" = 1 ]; then\n\
         echo '{{}}' > \"$HOME/settings.json\"\n\
         echo '{{}}' > \"$HOME/mcp.json\"\n\
         echo tampered > \"$HOME/system-prompt.md\"\n\
         {}\
         else\n\
         {}\
         fi\n",
        mcp_session("ask.out", &[(3, "ask", ask)]),
        later
    )
}

/// What a fake does on a later launch: run both checks of `owned_packet`.
fn then_checks() -> String {
    run_checks(&["edit", "made"])
}

fn segments(h: &Harness) -> Vec<Value> {
    h.run_json()["segments"].as_array().unwrap().clone()
}

fn stdout_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn an_answer_resumes_the_parked_session_with_the_ruling_and_the_lane_is_proved() {
    if !sandbox_available() {
        return;
    }
    let h = owned_packet(&asks_first("Choose A or B?", true, &then_checks()));
    let mut child = start(&h);
    let id = wait_for_ask(&h, &mut child, 1);
    rule(&h, &id, &["--answer", "use option B"]);
    let out = finish(child);
    assert_eq!(out.status.code(), Some(0), "{}", stdout_of(&out));
    assert_eq!(
        stdout_of(&out).lines().last().unwrap(),
        format!("{}: proved", h.id)
    );

    // Two launches; the second resumed the first one's session.
    assert_eq!(h.launches(), 2);
    let segs = segments(&h);
    assert_eq!(segs.len(), 2, "{segs:?}");
    assert_eq!(segs[0]["start"], "fresh");
    assert_eq!(segs[0]["sessionId"], SESSION);
    assert_eq!(segs[0]["endedBy"], id.as_str(), "{segs:?}");
    assert_eq!(segs[1]["start"], "resumed");
    assert_eq!(segs[1]["resumedSession"], SESSION);
    assert_eq!(segs[1]["startedBy"], id.as_str());
    assert_eq!(segs[1]["endedBy"], Value::Null);
    assert_eq!(segs[1]["model"], "haiku");
    assert_eq!(segs[1]["exitCode"], 0);
    assert_eq!(h.seg(2, "resume"), SESSION, "claude --resume <session id>");
    assert_eq!(h.seg(2, "model"), "haiku");
    // The prompt is the runner's, not the packet: the ruling in a fence.
    assert_eq!(
        h.seg(2, "prompt"),
        format!("Director ruling on {id}:\n```\nuse option B\n```")
    );
    // The first launch got the packet, fresh.
    assert_eq!(h.seg(1, "resume"), "");
    assert_eq!(h.seg(1, "prompt"), h.packet_text);

    // The home was rewritten before the second launch, whatever the first
    // session left in it.
    let settings: Value = serde_json::from_str(&h.seg(2, "settings.json")).unwrap();
    assert!(
        settings["permissions"]["allow"]
            .as_array()
            .unwrap()
            .contains(&json!("mcp__cowproof-tools"))
    );
    let mcp: Value = serde_json::from_str(&h.seg(2, "mcp.json")).unwrap();
    assert!(mcp["mcpServers"]["cowproof-tools"].is_object(), "{mcp}");
    assert!(h.seg(2, "system-prompt.md").starts_with(PREAMBLE));

    // The queue: ruled, delivered through the resume, no fallback.
    let delivered = queue_events(&h, "delivered");
    assert_eq!(delivered.len(), 1);
    assert_eq!(delivered[0]["id"], id.as_str());
    assert_eq!(delivered[0]["fresh"], false);
    assert!(queue_events(&h, "resume-fallback").is_empty());
    assert_eq!(h.run_json()["turns"], 4, "two launches of two turns");
    assert_eq!(h.verdict()["verdict"], "proved");
}

#[test]
fn a_stop_ruling_ends_the_lane_after_one_launch_and_keeps_the_work() {
    if !sandbox_available() {
        return;
    }
    let h = owned_packet(&asks_first("Quit?", true, &then_checks()));
    let mut child = start(&h);
    let id = wait_for_ask(&h, &mut child, 1);
    rule(&h, &id, &["--stop"]);
    let out = finish(child);
    assert_eq!(out.status.code(), Some(7));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("stopped"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    assert_eq!(h.launches(), 1, "no second launch");
    let run = h.run_json();
    assert_eq!(run["status"], "stopped", "{run}");
    assert_eq!(segments(&h).len(), 1);
    assert_eq!(segments(&h)[0]["endedBy"], id.as_str());
    // The work is kept; the lane is not proved.
    assert!(h.read("control/lane.patch").contains("+edited"));
    assert!(!h.lane().join("control/verdict.json").exists());
    assert!(!h.lane().join("control/capsule").exists());
    let ruled = queue_events(&h, "ruled");
    assert_eq!(ruled[0]["verdict"]["verdict"], "stop");
    assert_eq!(queue_events(&h, "delivered").len(), 1);
}

#[test]
fn a_reassign_starts_a_fresh_session_on_the_next_model_with_a_carry_over() {
    if !sandbox_available() {
        return;
    }
    let h = owned_packet(&asks_first("Which design?", true, &then_checks()));
    let mut child = start(&h);
    let id = wait_for_ask(&h, &mut child, 1);
    rule(&h, &id, &["--reassign"]);
    let out = finish(child);
    assert_eq!(out.status.code(), Some(0), "{}", stdout_of(&out));

    let segs = segments(&h);
    assert_eq!(segs.len(), 2, "{segs:?}");
    assert_eq!(segs[1]["start"], "fresh");
    assert_eq!(segs[1]["model"], "sonnet");
    assert_eq!(segs[1]["resumedSession"], Value::Null);
    assert_eq!(h.seg(2, "resume"), "", "a reassign never resumes");
    assert_eq!(h.seg(2, "model"), "sonnet");
    let prompt = h.seg(2, "prompt");
    assert!(prompt.starts_with(&h.packet_text), "{prompt}");
    assert!(prompt.contains("Which design?"), "the question: {prompt}");
    assert!(
        prompt.contains("read the packet"),
        "what was tried: {prompt}"
    );
    assert!(prompt.contains("reassign to sonnet"), "{prompt}");
    assert_eq!(h.run_json()["model"], "sonnet");
    assert!(queue_events(&h, "resume-fallback").is_empty());
    let delivered = queue_events(&h, "delivered");
    assert_eq!(delivered.len(), 1);
    assert_eq!(delivered[0]["fresh"], false);
    // The checks ran on the second model, and the capsule names it.
    assert_eq!(h.verdict()["verdict"], "proved");
    let capsule = Capsule::read(&h.lane().join("control/capsule")).unwrap();
    assert_eq!(capsule.builder_model, "sonnet");
}

#[test]
fn a_reassign_names_its_model_and_a_bad_name_refuses_the_ruling() {
    if !sandbox_available() {
        return;
    }
    let h = owned_packet(&asks_first("Which design?", true, &then_checks()));
    let mut child = start(&h);
    let id = wait_for_ask(&h, &mut child, 1);
    rule(&h, &id, &["--reassign", "--model", "opus"]);
    let out = finish(child);
    assert_eq!(out.status.code(), Some(0), "{}", stdout_of(&out));
    assert_eq!(h.seg(2, "model"), "opus");

    // A name that could be a flag is refused: nothing launches, the work is
    // kept and the ruling is left recorded and undelivered.
    let h = owned_packet(&asks_first("Which design?", true, &then_checks()));
    let mut child = start(&h);
    let id = wait_for_ask(&h, &mut child, 1);
    rule(&h, &id, &["--reassign", "--model=--dangerous"]);
    let out = finish(child);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("is not a model name"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(h.launches(), 1);
    assert_eq!(h.run_json()["status"], "failed");
    assert!(queue_events(&h, "delivered").is_empty());
}

#[test]
fn a_redirect_starts_a_fresh_session_whose_prompt_is_the_new_packet() {
    if !sandbox_available() {
        return;
    }
    let h = owned_packet(&asks_first("Right task?", true, &then_checks()));
    let redirected = h
        .packet_text
        .replace("Change the README.", "Change the README, then stop.");
    assert_ne!(redirected, h.packet_text);
    let packet = h.work.path().join("redirect.md");
    fs::write(&packet, &redirected).unwrap();
    let mut child = start(&h);
    let id = wait_for_ask(&h, &mut child, 1);
    rule(&h, &id, &["--redirect", packet.to_str().unwrap()]);
    let out = finish(child);
    assert_eq!(out.status.code(), Some(0), "{}", stdout_of(&out));

    let segs = segments(&h);
    assert_eq!(segs.len(), 2);
    assert_eq!(segs[1]["start"], "fresh");
    assert_eq!(h.seg(2, "resume"), "");
    assert_eq!(h.seg(2, "model"), "haiku");
    assert_eq!(h.seg(2, "prompt"), redirected, "the packet's body, exactly");
    assert_eq!(queue_events(&h, "delivered").len(), 1);
}

#[test]
fn a_redirect_writes_a_second_packet_version_that_the_capsule_seals() {
    if !sandbox_available() {
        return;
    }
    let h = owned_packet(&asks_first("Right task?", true, &then_checks()));
    let redirected = h
        .packet_text
        .replace("Change the README.", "Change the README, then stop.");
    let packet = h.work.path().join("redirect.md");
    fs::write(&packet, &redirected).unwrap();
    let mut child = start(&h);
    let id = wait_for_ask(&h, &mut child, 1);
    rule(&h, &id, &["--redirect", packet.to_str().unwrap()]);
    let out = finish(child);
    assert_eq!(out.status.code(), Some(0), "{}", stdout_of(&out));

    let dir = h.lane().join("control/capsule");
    // Both versions, byte for byte: the packet the lane started with, then the redirect.
    assert_eq!(
        fs::read_to_string(dir.join("packets/v1.md")).unwrap(),
        h.packet_text
    );
    assert_eq!(
        fs::read_to_string(dir.join("packets/v2.md")).unwrap(),
        redirected
    );
    let index: Value =
        serde_json::from_str(&fs::read_to_string(dir.join("packets/versions.json")).unwrap())
            .unwrap();
    assert_eq!(
        index,
        json!([
            {"version": 1, "file": "v1.md", "introduced_by": null},
            // The escalation whose ruling brought the version.
            {"version": 2, "file": "v2.md", "introduced_by": id},
        ])
    );
    let capsule = Capsule::read(&dir).expect("the capsule reads back");
    for file in ["packets/v1.md", "packets/v2.md", "packets/versions.json"] {
        assert!(capsule.file_hashes.contains_key(file), "{file} not sealed");
    }

    // A changed packet version is refused by the seal, and so by `cowproof verify`.
    let original = fs::read(dir.join("packets/v2.md")).unwrap();
    fs::write(dir.join("packets/v2.md"), "Change nothing.\n").unwrap();
    assert!(matches!(
        Capsule::read(&dir),
        Err(cowproof_prove::CapsuleError::HashMismatch(name, _, _)) if name == "packets/v2.md"
    ));
    let workdir = var_tmp("cp-run-verify-");
    let out = output(
        Command::new(&h.cowproof)
            .env("HOME", workdir.path())
            .env_remove("ANTHROPIC_API_KEY")
            .arg("verify")
            .arg(&dir)
            .arg("--repo")
            .arg(&h.repo)
            .arg("--workdir")
            .arg(workdir.path().join("w")),
    );
    assert_eq!(out.status.code(), Some(4), "{}", stdout_of(&out));
    let err = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(
        err.contains("tampered") && err.contains("packets/v2.md"),
        "{err}"
    );
    fs::write(dir.join("packets/v2.md"), original).unwrap();
    Capsule::read(&dir).expect("restored, the capsule reads again");
}

#[test]
fn a_lane_with_no_redirect_seals_exactly_one_packet_version() {
    if !sandbox_available() {
        return;
    }
    let h = owned_packet(&run_checks(&["edit", "made"]));
    h.run_expecting(0);
    let dir = h.lane().join("control/capsule");
    assert_eq!(
        fs::read_to_string(dir.join("packets/v1.md")).unwrap(),
        h.packet_text
    );
    assert!(!dir.join("packets/v2.md").exists());
    let index: Value =
        serde_json::from_str(&fs::read_to_string(dir.join("packets/versions.json")).unwrap())
            .unwrap();
    assert_eq!(
        index,
        json!([{"version": 1, "file": "v1.md", "introduced_by": null}])
    );
    assert!(
        Capsule::read(&dir)
            .unwrap()
            .file_hashes
            .contains_key("packets/v1.md")
    );
}

#[test]
fn a_redirect_with_another_lanes_id_is_refused_and_nothing_launches() {
    if !sandbox_available() {
        return;
    }
    let h = owned_packet(&asks_first("Right task?", true, &then_checks()));
    let packet = h.work.path().join("redirect.md");
    fs::write(&packet, h.packet_text.replace(&h.id, "someone-else")).unwrap();
    let mut child = start(&h);
    let id = wait_for_ask(&h, &mut child, 1);
    rule(&h, &id, &["--redirect", packet.to_str().unwrap()]);
    let out = finish(child);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("not this lane's"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(h.launches(), 1);
}

// ---- The proof uses the last delivered packet version ----------------------------------
//
// A redirect is the director's own packet, so its header is trusted like the original: the
// gates, the required checks and the sealed capsule come from the LAST version delivered to
// the builder. The tests use their own temporary HOME, never the real one.

/// `text` with one field of its `<!-- lane {...} -->` header replaced.
fn packet_with(text: &str, key: &str, value: Value) -> String {
    let start = text.find("<!-- lane ").unwrap() + "<!-- lane ".len();
    let end = start + text[start..].find(" -->").unwrap();
    let mut header: Value = serde_json::from_str(&text[start..end]).unwrap();
    header[key] = value;
    format!("{}{header}{}", &text[..start], &text[end..])
}

/// [`start`], with a `HOME` of the test's own.
fn start_in(h: &Harness, home: &Path) -> Child {
    let _g = fork_lock();
    h.command(h.lanes.path())
        .env("ANTHROPIC_API_KEY", REAL_KEY)
        .env("HOME", home)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

/// Run `h` until its first launch asks, rule a redirect to `redirect`, and return the output.
fn redirected_run(h: &Harness, redirect: &str) -> Output {
    let home = var_tmp("cp-run-home-");
    let packet = h.work.path().join("redirect.md");
    fs::write(&packet, redirect).unwrap();
    let mut child = start_in(h, home.path());
    let id = wait_for_ask(h, &mut child, 1);
    rule(h, &id, &["--redirect", packet.to_str().unwrap()]);
    finish(child)
}

/// `cowproof verify` of the lane's capsule against the repository, from a home of its own.
fn verify_capsule_of(h: &Harness) -> Output {
    let home = var_tmp("cp-run-home-");
    let elsewhere = var_tmp("cp-run-cwd-");
    output(
        Command::new(&h.cowproof)
            .current_dir(elsewhere.path())
            .env("HOME", home.path())
            .env_remove("ANTHROPIC_API_KEY")
            .arg("verify")
            .arg(h.lane().join("control/capsule"))
            .arg("--repo")
            .arg(&h.repo)
            .arg("--workdir")
            .arg(home.path().join("w")),
    )
}

/// A packet that owns only README.md, though the fake also creates created.txt; the one
/// check passes. The first launch asks (blocking); a later launch runs `edit`.
fn narrow_packet() -> Harness {
    Harness::with_packet(
        &asks_first("Right task?", true, &run_checks(&["edit"])),
        json!(["README.md"]),
        json!([{"id": "edit", "command": "grep -q edited README.md"}]),
    )
}

#[test]
fn a_redirect_that_widens_owns_lets_a_patch_touching_the_new_file_pass_and_it_reproduces() {
    if !sandbox_available() {
        return;
    }
    let h = narrow_packet();
    let widened = packet_with(&h.packet_text, "owns", json!(["README.md", "created.txt"]));
    let out = redirected_run(&h, &widened);
    assert_eq!(out.status.code(), Some(0), "{}", stdout_of(&out));
    let verdict = h.verdict();
    assert_eq!(verdict["verdict"], "proved", "{verdict}");
    assert_eq!(verdict["failedGates"], json!([]), "{verdict}");
    assert!(
        h.read("control/lane.patch").contains("created.txt"),
        "the patch touches the newly owned file"
    );
    // Both versions are sealed, and the capsule replays: `cowproof verify` judges nothing by
    // a header, only the sealed checks and patches, which the final header produced.
    let dir = h.lane().join("control/capsule");
    assert!(dir.join("packets/v2.md").exists());
    let out = verify_capsule_of(&h);
    assert_eq!(out.status.code(), Some(0), "{}", text_of(&out));
    assert_eq!(stdout_of(&out).trim(), "reproduced");
}

#[test]
fn without_a_widening_redirect_the_same_patch_is_refuted_by_the_ownership_gate() {
    if !sandbox_available() {
        return;
    }
    let h = narrow_packet();
    // A redirect that changes only the words keeps `owns` as it was.
    let reworded = h
        .packet_text
        .replace("Change the README.", "Change the README, then stop.");
    assert_ne!(reworded, h.packet_text);
    let out = redirected_run(&h, &reworded);
    assert_eq!(out.status.code(), Some(2), "{}", stdout_of(&out));
    let verdict = h.verdict();
    assert_eq!(verdict["failedGates"], json!(["ownership"]), "{verdict}");
    assert!(
        reasons(&verdict).iter().any(|r| r.contains("created.txt")),
        "{verdict}"
    );
}

/// A packet that owns what the fake touches and declares only `edit`; the first launch asks,
/// a later one runs `later` (a list of check ids).
fn one_check_packet(later: &[&str]) -> Harness {
    Harness::with_packet(
        &asks_first("Right task?", true, &run_checks(later)),
        json!(["README.md", "created.txt"]),
        json!([{"id": "edit", "command": "grep -q edited README.md"}]),
    )
}

fn with_made_check(h: &Harness) -> String {
    packet_with(
        &h.packet_text,
        "checks",
        json!([
            {"id": "edit", "command": "grep -q edited README.md"},
            {"id": "made", "command": "test -f created.txt"},
        ]),
    )
}

#[test]
fn a_redirect_that_adds_a_check_makes_it_required_and_never_running_it_is_incomplete() {
    if !sandbox_available() {
        return;
    }
    let h = one_check_packet(&["edit"]);
    let out = redirected_run(&h, &with_made_check(&h));
    assert_eq!(out.status.code(), Some(3), "{}", stdout_of(&out));
    let verdict = h.verdict();
    assert_eq!(verdict["verdict"], "incomplete", "{verdict}");
    assert_eq!(verdict["unrun"], json!(["made"]), "{verdict}");
    assert!(
        reasons(&verdict)
            .iter()
            .any(|r| r.contains("\"made\" was never run")),
        "{verdict}"
    );
    // Only what the builder recorded is sealed.
    assert!(h.lane().join("control/capsule/checks/edit.json").exists());
    assert!(!h.lane().join("control/capsule/checks/made.json").exists());
}

#[test]
fn a_check_a_redirect_adds_can_be_run_by_the_builder_sealed_and_reproduced() {
    if !sandbox_available() {
        return;
    }
    let h = one_check_packet(&["edit", "made"]);
    let out = redirected_run(&h, &with_made_check(&h));
    assert_eq!(out.status.code(), Some(0), "{}", stdout_of(&out));
    assert!(passed(&h, 3) && passed(&h, 4), "both ran and passed");
    let verdict = h.verdict();
    assert_eq!(verdict["verdict"], "proved", "{verdict}");
    let made: Value = serde_json::from_str(&h.read("control/capsule/checks/made.json")).unwrap();
    assert_eq!(made["command"], "test -f created.txt");
    assert_eq!(made["exit_status"], 0);
    let out = verify_capsule_of(&h);
    assert_eq!(out.status.code(), Some(0), "{}", text_of(&out));
}

#[test]
fn a_check_the_redirect_removes_is_no_longer_required() {
    if !sandbox_available() {
        return;
    }
    // The packet starts with two checks; the redirect declares only `edit`, and the builder
    // runs only `edit` after it.
    let h = owned_packet(&asks_first("Right task?", true, &run_checks(&["edit"])));
    let only_edit = packet_with(
        &h.packet_text,
        "checks",
        json!([{"id": "edit", "command": "grep -q edited README.md"}]),
    );
    let out = redirected_run(&h, &only_edit);
    assert_eq!(out.status.code(), Some(0), "{}", stdout_of(&out));
    let verdict = h.verdict();
    assert_eq!(verdict["verdict"], "proved", "{verdict}");
    assert_eq!(verdict["unrun"], json!([]), "{verdict}");
}

fn text_of(out: &Output) -> String {
    format!(
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

// ---- `require_heldout` is checked before the builder starts ---------------------------------

/// Commit `cowproof.toml` with `[proof] require_heldout = true` into the harness's repository.
fn require_heldout_in_base(h: &Harness) {
    fs::write(
        h.repo.join("cowproof.toml"),
        "[proof]\nrequire_heldout = true\n",
    )
    .unwrap();
    git(&h.repo, &["add", "cowproof.toml"]);
    git(&h.repo, &["commit", "-q", "-m", "require held-out checks"]);
}

#[test]
fn require_heldout_with_no_held_out_file_refuses_before_any_lane_or_builder_exists() {
    if !sandbox_available() {
        return;
    }
    // The fake would leave a marker in its lane home if it ever started.
    let h = Harness::new("echo started > \"$HOME/builder-started\"\n");
    require_heldout_in_base(&h);
    let home = var_tmp("cp-run-home-");
    let out = output(
        h.command(h.lanes.path())
            .env("ANTHROPIC_API_KEY", REAL_KEY)
            .env("HOME", home.path()),
    );
    assert_eq!(out.status.code(), Some(1), "{}", text_of(&out));
    let err = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(
        err.contains("require_heldout") && err.contains("--heldout") && err.contains(&h.id),
        "{err}"
    );
    // No lane directory at all, so no builder: the lanes root is empty.
    assert_eq!(fs::read_dir(h.lanes.path()).unwrap().count(), 0);
    assert!(!h.lane().exists());
}

#[test]
fn require_heldout_with_a_held_out_file_starts_the_builder_as_usual() {
    if !sandbox_available() {
        return;
    }
    let h = owned_packet(&run_checks(&["edit", "made"]));
    require_heldout_in_base(&h);
    let held = var_tmp("cp-run-heldout-");
    let file = held.path().join("held.toml");
    fs::write(
        &file,
        "[[check]]\nid = \"hidden\"\ncommand = \"grep -q edited README.md\"\n",
    )
    .unwrap();
    let home = var_tmp("cp-run-home-");
    let out = output(
        h.command(h.lanes.path())
            .arg("--heldout")
            .arg(&file)
            .env("ANTHROPIC_API_KEY", REAL_KEY)
            .env("HOME", home.path()),
    );
    assert_eq!(out.status.code(), Some(0), "{}", text_of(&out));
    assert_eq!(h.launches(), 1, "the builder ran");
    assert_eq!(h.verdict()["verdict"], "proved");
}

/// A fake whose `--resume` fails at once with no output, like `claude` does
/// for a session that no longer exists.
fn session_gone_then_checks() -> String {
    format!("if [ -n \"$resume\" ]; then exit 1; fi\n{}", then_checks())
}

#[test]
fn a_session_that_is_gone_falls_back_to_a_fresh_launch_with_the_carry_over_summary() {
    if !sandbox_available() {
        return;
    }
    let h = owned_packet(&asks_first(
        "Choose A or B?",
        true,
        &session_gone_then_checks(),
    ));
    let mut child = start(&h);
    let id = wait_for_ask(&h, &mut child, 1);
    rule(&h, &id, &["--answer", "use option B"]);
    let out = finish(child);
    assert_eq!(out.status.code(), Some(0), "{}", stdout_of(&out));

    // fresh, the failed resume, the fallback.
    assert_eq!(h.launches(), 3);
    let segs = segments(&h);
    assert_eq!(segs.len(), 3, "{segs:?}");
    assert_eq!(segs[1]["start"], "resumed");
    assert_eq!(segs[1]["resumedSession"], SESSION);
    assert_eq!(segs[1]["exitCode"], 1);
    assert_eq!(segs[1]["resumeFailed"], "session-gone");
    assert_eq!(segs[2]["start"], "fallback");
    assert_eq!(segs[2]["startedBy"], id.as_str());
    assert_eq!(segs[2]["resumedSession"], Value::Null);
    assert_eq!(h.seg(2, "resume"), SESSION);
    assert_eq!(h.seg(3, "resume"), "", "the fallback is a fresh session");
    assert_eq!(h.seg(3, "model"), "haiku");
    let prompt = h.seg(3, "prompt");
    assert!(prompt.starts_with(&h.packet_text), "the task: {prompt}");
    assert!(
        prompt.contains(&format!(
            "Your previous session could not be resumed. Escalation {id} is answered below."
        )),
        "{prompt}"
    );
    assert!(prompt.contains("Question: Choose A or B?"), "{prompt}");
    assert!(prompt.contains("Ruling: answer: use option B"), "{prompt}");

    // The queue records the fallback, then the fresh delivery.
    let fallbacks = queue_events(&h, "resume-fallback");
    assert_eq!(fallbacks.len(), 1);
    assert_eq!(fallbacks[0]["id"], id.as_str());
    let delivered = queue_events(&h, "delivered");
    assert_eq!(delivered.len(), 1);
    assert_eq!(delivered[0]["fresh"], true);
    assert_eq!(h.verdict()["verdict"], "proved");
}

#[test]
fn a_resume_that_fails_after_doing_work_is_not_a_gone_session() {
    if !sandbox_available() {
        return;
    }
    // The resumed fake prints a stream line and then exits 1: that is a
    // builder failure, not a missing session, so no fallback starts.
    let later = format!(
        "if [ -n \"$resume\" ]; then printf '%s\\n' '{{\"type\":\"system\",\"session_id\":\"{SESSION}\"}}'; exit 1; fi\n{}",
        then_checks()
    );
    let h = owned_packet(&asks_first("Choose A or B?", true, &later));
    let mut child = start(&h);
    let id = wait_for_ask(&h, &mut child, 1);
    rule(&h, &id, &["--answer", "use option B"]);
    let out = finish(child);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(h.launches(), 2, "no fallback launch");
    assert!(queue_events(&h, "resume-fallback").is_empty());
    assert_eq!(h.run_json()["status"], "failed");
    assert_eq!(segments(&h)[1].get("resumeFailed"), None);
}

#[test]
fn a_non_blocking_ask_does_not_wait_and_leaves_one_segment() {
    if !sandbox_available() {
        return;
    }
    // Nobody rules, and the run still ends: it must not wait for a ruling on
    // an ask that did not park the builder.
    let h = owned_packet(&asks_first("Design choice?", false, ":\n"));
    let out = finish(start(&h));
    // The fake ran no checks, so the lane is incomplete (3), not stuck.
    assert_eq!(out.status.code(), Some(3), "{}", stdout_of(&out));
    assert_eq!(queue_events(&h, "asked").len(), 1, "the ask did land");
    assert_eq!(h.launches(), 1);
    let segs = segments(&h);
    assert_eq!(segs.len(), 1);
    assert_eq!(segs[0]["endedBy"], Value::Null);
    assert_eq!(h.run_json()["status"], "finished");
}

#[test]
fn the_fourth_ask_ends_the_lane_as_escalation_limit_without_a_proof() {
    if !sandbox_available() {
        return;
    }
    // Every launch asks again. Three asks are allowed; each is answered and
    // resumed; the fourth is refused by the queue, which ends the lane.
    let ask = mcp_session("ask.out", &[(3, "ask", blocking_ask("Again?"))]);
    let h = owned_packet(&ask);
    let mut child = start(&h);
    for nth in 1..=3 {
        let id = wait_for_ask(&h, &mut child, nth);
        rule(&h, &id, &["--answer", "keep going"]);
    }
    let out = finish(child);
    assert_eq!(out.status.code(), Some(8));
    assert_eq!(h.launches(), 4);
    assert_eq!(h.run_json()["status"], "escalation-limit");
    assert_eq!(queue_events(&h, "lane-escalation-limit").len(), 1);
    assert!(!h.lane().join("control/verdict.json").exists());
}

// ---- The runner ends the session (D9) and escalates early -------------------
//
// A fake that asks blocking and then keeps running (`sleep 120`) is a builder
// that ignores "parked". The runner must end its session itself: SIGTERM to the
// builder's process group two seconds after the park, SIGKILL to the group
// after ten more. Every wait below is bounded; the longest is the 20 s budget.

/// How long after a park the segment must be over (design: 2 s grace plus the
/// group kill, with a wide margin for a loaded CI machine).
const SESSION_END_WITHIN: Duration = Duration::from_secs(20);

/// The runner's own line saying a segment is over and it is waiting for a ruling.
const WAITING: &str = "waiting for the director";

/// A `cowproof run` in flight whose stderr is collected by a thread, so a test
/// can see when the runner reaches a state.
struct Watched {
    child: Child,
    stderr: std::sync::Arc<Mutex<String>>,
}

fn start_watched(h: &Harness, extra: &[&str]) -> Watched {
    let mut child = {
        let _g = fork_lock();
        h.command(h.lanes.path())
            .args(extra)
            .env("ANTHROPIC_API_KEY", REAL_KEY)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
    };
    let pipe = child.stderr.take().unwrap();
    let stderr = std::sync::Arc::new(Mutex::new(String::new()));
    let sink = stderr.clone();
    std::thread::spawn(move || {
        use std::io::BufRead;
        for line in std::io::BufReader::new(pipe).lines().map_while(Result::ok) {
            let mut text = sink.lock().unwrap_or_else(|e| e.into_inner());
            text.push_str(&line);
            text.push('\n');
        }
    });
    Watched { child, stderr }
}

impl Watched {
    fn stderr(&self) -> String {
        self.stderr
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Wait until the runner's stderr contains `needle`, at most `within`. A
    /// run that never gets there is killed (by its pid) and fails the test.
    fn wait_for_stderr(&mut self, needle: &str, within: Duration) {
        let deadline = Instant::now() + within;
        while !self.stderr().contains(needle) {
            if Instant::now() > deadline {
                let _ = self.child.kill();
                let _ = self.child.wait();
                panic!(
                    "no {needle:?} on stderr within {within:?}:\n{}",
                    self.stderr()
                );
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

/// The fake's stdout line for an assistant turn: distinct id, `input` input tokens.
fn turn_line(id: &str, input: u64) -> String {
    format!(
        "printf '%s\\n' '{}'\n",
        json!({"type":"assistant","message":{"id":id,"usage":{"input_tokens":input,"output_tokens":1}}})
    )
}

/// The stream line that gives the session its id (so a resume has something to resume).
fn init_line() -> String {
    format!(
        "printf '%s\\n' '{}'\n",
        json!({"type":"system","subtype":"init","session_id":SESSION})
    )
}

/// `first` on the first launch, `later` on every other one.
fn first_then(first: &str, later: &str) -> String {
    format!("if [ \"$n\" = 1 ]; then\n{first}else\n{later}fi\n")
}

/// Poll until the process `pid` is gone (`kill(2)` with signal 0 says ESRCH), at most 5 s.
fn assert_pid_gone(pid: &str) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if !pid_alive(pid.parse().expect("a numeric pid")) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "process {pid} is still alive 5 s after the lane ended"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn a_parked_blocking_ask_ends_a_builder_that_keeps_running_and_the_answer_resumes_it() {
    if !sandbox_available() {
        return;
    }
    // The first session asks, then ignores "parked" and sleeps for two minutes.
    let ask = mcp_session("ask.out", &[(3, "ask", blocking_ask("Choose A or B?"))]);
    let first = format!("{}{ask}sleep 120\n", init_line());
    let h = owned_packet(&first_then(&first, &then_checks()));
    let mut run = start_watched(&h, &[]);
    let id = wait_for_ask(&h, &mut run.child, 1);
    let asked_at = Instant::now();

    // The segment is over (the runner is waiting for a ruling) well before the
    // sleep would have ended.
    run.wait_for_stderr(WAITING, SESSION_END_WITHIN);
    assert!(asked_at.elapsed() < SESSION_END_WITHIN);

    rule(&h, &id, &["--answer", "use option B"]);
    let out = finish(run.child);
    assert_eq!(out.status.code(), Some(0), "{}", stdout_of(&out));
    assert_eq!(
        stdout_of(&out).lines().last().unwrap(),
        format!("{}: proved", h.id)
    );

    let segs = segments(&h);
    assert_eq!(segs.len(), 2, "{segs:?}");
    assert_eq!(segs[0]["sessionEnd"], "parked", "{segs:?}");
    assert_eq!(segs[0]["killedByRunner"], true);
    assert_eq!(segs[0]["status"], "ended-by-runner");
    assert_eq!(segs[0]["signal"], 15, "SIGTERM ended the group: {segs:?}");
    assert_eq!(segs[0]["endedBy"], id.as_str());
    assert_eq!(segs[1]["start"], "resumed");
    assert_eq!(segs[1]["resumedSession"], SESSION);
    assert_eq!(segs[1]["killedByRunner"], false);
    assert_eq!(h.verdict()["verdict"], "proved");
}

#[test]
fn the_runner_ends_the_whole_process_group_so_no_background_child_survives() {
    if !sandbox_available() {
        return;
    }
    // After asking, the fake starts a background child that ignores SIGTERM
    // (so only the group SIGKILL can end it), would write a marker six seconds
    // later; a second one (whose pid it records) lives for a minute; then the
    // fake sleeps.
    let ask = mcp_session("ask.out", &[(3, "ask", blocking_ask("Stuck?"))]);
    let first = format!(
        "{}{ask}( trap '' TERM; sleep 14; echo alive > \"$HOME/survived\" ) &\n( trap '' TERM; sleep 60 ) &\necho $! > \"$HOME/bgpid\"\nsleep 120\n",
        init_line()
    );
    let h = owned_packet(&first_then(&first, &then_checks()));
    let mut run = start_watched(&h, &[]);
    let id = wait_for_ask(&h, &mut run.child, 1);
    let asked_at = Instant::now();
    run.wait_for_stderr(WAITING, SESSION_END_WITHIN);
    rule(&h, &id, &["--stop"]);
    let out = finish(run.child);
    assert_eq!(out.status.code(), Some(7), "{}", stdout_of(&out));
    assert_eq!(h.run_json()["status"], "stopped");

    // By pid where the sandbox shares the host's pid space (macOS). bwrap runs
    // with --unshare-pid, so on Linux the recorded pid means nothing outside.
    if cfg!(target_os = "macos") {
        let pid = h.read("home/bgpid");
        assert_pid_gone(pid.trim());
    }
    // By effect everywhere: a surviving child writes its marker at six seconds.
    let wait = Duration::from_secs(9).saturating_sub(asked_at.elapsed());
    std::thread::sleep(wait);
    assert!(
        !h.lane().join("home/survived").exists(),
        "a background child outlived the session end and wrote its marker"
    );
}

#[test]
fn a_non_blocking_ask_never_ends_the_session_and_the_builders_own_exit_is_recorded() {
    if !sandbox_available() {
        return;
    }
    // Longer than the 2 s park grace: a runner that ended sessions on any ask
    // would kill this one.
    let ask = mcp_session(
        "ask.out",
        &[(3, "ask", {
            let mut a = blocking_ask("Design choice?");
            a["blocking"] = json!(false);
            a
        })],
    );
    let h = owned_packet(&format!("{ask}sleep 3\nexit 7\n"));
    let out = finish(start(&h));
    assert_eq!(out.status.code(), Some(1), "{}", stdout_of(&out));
    assert_eq!(h.launches(), 1);
    let segs = segments(&h);
    assert_eq!(segs.len(), 1, "{segs:?}");
    assert_eq!(segs[0]["exitCode"], 7, "its own exit status: {segs:?}");
    assert_eq!(segs[0]["signal"], Value::Null);
    assert_eq!(segs[0]["killedByRunner"], false);
    assert_eq!(segs[0]["sessionEnd"], Value::Null);
    assert_eq!(segs[0]["status"], "failed");
    assert_eq!(queue_events(&h, "asked").len(), 1);
}

// ---- A ruling on a NON-blocking ask, while the builder is running ----------
//
// A stop, reassign or redirect ruling on a non-blocking ask ends the live
// session at once (SIGTERM to the group, SIGKILL after the grace), and the
// resume loop acts on it with the handler blocking asks use. An answer does
// not end the session: the builder reads it with `check_ruling`.

/// A hang guard: the ruling must take effect within this long of the director giving it,
/// against a builder that would otherwise sleep for two minutes. It is not the property under
/// test (that is [`a_stop_on_a_non_blocking_ask_ends_the_live_session_and_the_lane`], which
/// measures from the runner's own "ending the builder now" line against `TERM_GRACE`): a ruling
/// given to a loaded host also waits for the `cowproof rule` process to start and for the
/// sandbox to wind down, and a fixed fifteen seconds failed twice in full workspace runs.
const RULED_WITHIN: Duration = Duration::from_secs(90);

/// A fake that, on its first launch, records its pid, starts a 120 s sleep in a background
/// child (so the group has two members) and records that pid, then asks NON-blocking and waits
/// for the sleep; later launches run the checks. Both pids are written before the ask, because
/// the tests rule the moment the ask is recorded and the ruling sends SIGTERM to the group: a
/// fake that wrote `sleeppid` after the ask could be ended before it got there, and the test
/// then read a file that was never written (a failure seen under load).
fn nonblocking_sleeper(question: &str) -> String {
    let mut ask = blocking_ask(question);
    ask["blocking"] = json!(false);
    let first = format!(
        "{}echo $$ > \"$HOME/fakepid\"\nsleep 120 &\necho $! > \"$HOME/sleeppid\"\n{}wait\n",
        init_line(),
        mcp_session("ask.out", &[(3, "ask", ask)])
    );
    first_then(&first, &then_checks())
}

/// Start the run, wait for the first ask to be recorded, rule on it at once.
/// Returns the run, the escalation id and the moment the ruling was given.
fn rule_the_moment_it_is_asked(h: &Harness, verdict: &[&str]) -> (Child, String, Instant) {
    let mut child = start(h);
    let id = wait_for_ask(h, &mut child, 1);
    let ruled_at = Instant::now();
    rule(h, &id, verdict);
    (child, id, ruled_at)
}

/// Ends the first builder's process group by the pid the fake recorded in `home/fakepid`
/// (it is the group leader), on macOS only. The sandbox shares the host's pid space there; on
/// Linux the number is a pid in bwrap's namespace (often 1 to 3) that means nothing out here,
/// and the namespace dies with its init, so nothing is signalled.
fn reap_fake_group(h: &Harness) {
    if cfg!(target_os = "macos")
        && let Ok(pid) = fs::read_to_string(h.lane().join("home/fakepid"))
        && let Ok(pgid) = pid.trim().parse::<u32>()
    {
        signal_group("KILL", pgid);
    }
}

/// Wait until the fake's `n`th launch has begun, at most `RULED_WITHIN` after
/// `ruled_at`; a run that gets there late is killed (by pid) and fails.
fn second_segment_starts_within(h: &Harness, child: &mut Child, ruled_at: Instant) {
    while h.launches() < 2 {
        if ruled_at.elapsed() > RULED_WITHIN {
            let _ = child.kill();
            let _ = child.wait();
            reap_fake_group(h);
            panic!("no second segment {RULED_WITHIN:?} after the ruling");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// What every live ruling must leave behind in the first segment.
fn assert_first_builder_was_ruled_away(h: &Harness, id: &str) {
    let segs = segments(h);
    assert_eq!(segs[0]["sessionEnd"], "ruled", "{segs:?}");
    assert_eq!(segs[0]["killedByRunner"], true, "{segs:?}");
    assert_eq!(segs[0]["status"], "ended-by-runner");
    assert_eq!(segs[0]["signal"], 15, "SIGTERM ended the group: {segs:?}");
    assert_eq!(segs[0]["endedBy"], id);
    // The first builder's whole group is gone: by pid where the sandbox shares
    // the host's pid space (macOS); bwrap's --unshare-pid hides it on Linux.
    if cfg!(target_os = "macos") {
        assert_pid_gone(h.read("home/fakepid").trim());
        assert_pid_gone(h.read("home/sleeppid").trim());
    }
    // Acted on once: one ruling, one delivery.
    assert_eq!(queue_events(h, "ruled").len(), 1);
    assert_eq!(queue_events(h, "delivered").len(), 1);
}

/// What the runner's own line "the builder ended N ms after SIGTERM[, after SIGKILL]" says.
struct EndedAfterTerm {
    took: Duration,
    after_sigkill: bool,
}

/// Wait for that line (at most `within`) and read it. It is printed the moment the runner reads
/// the leader's exit status, so it is the SIGTERM-to-gone time and nothing else: not the
/// `cowproof rule` process starting, not this test's polling, and not what the runner does
/// afterwards (the patch, `pk doctor`, `run.json`).
fn ended_after_term(run: &mut Watched, within: Duration) -> EndedAfterTerm {
    run.wait_for_stderr("ms after SIGTERM", within);
    ended_after_term_in(&run.stderr())
}

/// The same reading from the stderr of a run that has ended.
fn ended_after_term_in(stderr: &str) -> EndedAfterTerm {
    let line = stderr
        .lines()
        .find(|l| l.contains("the builder ended "))
        .unwrap_or_else(|| panic!("no 'the builder ended' line:\n{stderr}"));
    let ms = line
        .split("the builder ended ")
        .nth(1)
        .and_then(|rest| rest.split(" ms").next())
        .and_then(|n| n.parse::<u64>().ok())
        .unwrap_or_else(|| panic!("cannot read the time from {line:?}"));
    EndedAfterTerm {
        took: Duration::from_millis(ms),
        after_sigkill: line.ends_with("after SIGKILL"),
    }
}

/// Start a run whose first builder asks NON-blocking, rule `--stop` on it, and read the
/// runner's account of how long the builder took to go. Returns the run, the escalation id,
/// the moment the runner said it was ending the builder, and that account.
fn stop_a_non_blocking_ask(h: &Harness) -> (Watched, String, Instant, EndedAfterTerm) {
    let mut run = start_watched(h, &[]);
    let id = wait_for_ask(h, &mut run.child, 1);
    rule(h, &id, &["--stop"]);
    run.wait_for_stderr("ending the builder now", RULED_WITHIN);
    let ending = Instant::now();
    let ended = ended_after_term(&mut run, RULED_WITHIN);
    (run, id, ending, ended)
}

#[test]
fn a_stop_on_a_non_blocking_ask_ends_the_live_session_and_the_lane() {
    if !sandbox_available() {
        return;
    }
    // The builder dies on SIGTERM, so a stop must not wait out `TERM_GRACE` for a SIGKILL.
    // What is measured is the runner's own line saying how long the builder took to go after
    // SIGTERM: the stop's other work (the patch, `pk doctor`, `run.json`) is not the property,
    // and on a loaded host it took 9 to 11 seconds while the builder went in under a
    // millisecond. A run that waited the grace out reports about `TERM_GRACE` and says it
    // took a SIGKILL, so the bound is three quarters of it. The waits around it only keep a
    // hang from hanging the test.
    let grace = term_grace();
    let bound = grace * 3 / 4;
    let h = owned_packet(&nonblocking_sleeper("Quit?"));
    let (mut run, id, _, ended) = stop_a_non_blocking_ask(&h);
    assert!(
        !ended.after_sigkill && ended.took < bound,
        "the stop waited for the SIGTERM grace: the builder ended {:?} after SIGTERM (SIGKILL \
         needed: {}), bound {bound:?} of a {grace:?} grace:\n{}",
        ended.took,
        ended.after_sigkill,
        run.stderr()
    );
    let status = exit_within(&mut run, RULED_WITHIN);
    let mut stdout = String::new();

    if let Some(mut pipe) = run.child.stdout.take() {
        use std::io::Read;
        let _ = pipe.read_to_string(&mut stdout);
    }
    assert_eq!(status.code(), Some(7), "{stdout}\n{}", run.stderr());
    assert_eq!(h.launches(), 1, "no second launch");
    assert_eq!(h.run_json()["status"], "stopped");
    assert_eq!(segments(&h).len(), 1);
    assert_first_builder_was_ruled_away(&h, &id);
    // The work is kept; the lane is not proved.
    assert!(h.read("control/lane.patch").contains("+edited"));
    assert!(!h.lane().join("control/verdict.json").exists());
}

/// Like [`nonblocking_sleeper`], but the builder (and so everything it starts) ignores SIGTERM,
/// so only the runner's SIGKILL after `TERM_GRACE` ends it.
fn nonblocking_stubborn(question: &str) -> String {
    let mut ask = blocking_ask(question);
    ask["blocking"] = json!(false);
    let first = format!(
        "{}trap '' TERM\n{}while true; do sleep 1; done\n",
        init_line(),
        mcp_session("ask.out", &[(3, "ask", ask)])
    );
    first_then(&first, &then_checks())
}

#[test]
fn a_stop_does_not_count_the_slow_work_after_the_builder_is_gone_as_waiting_for_the_grace() {
    if !sandbox_available() {
        return;
    }
    // After the builder is reaped the runner still collects the patch, asks `pk doctor` whether
    // the hooks fired and writes `run.json`. A loaded host spends seconds there (9 to 11 in
    // a full workspace run, with the builder gone in under a millisecond), and a test that
    // timed the whole exit read that as a stop that waited out the grace. Here `pk doctor`
    // takes eight seconds on any host: the exit is later than the bound, the builder's own
    // time is not, and the test measures the second.
    let grace = term_grace();
    let bound = grace * 3 / 4;
    let h = owned_packet(&nonblocking_sleeper("Quit?"));
    let pk = h.work.path().join("pk");
    {
        let _g = fork_lock();
        fs::remove_file(&pk).unwrap();
        fs::write(&pk, "#!/bin/sh\n/bin/sleep 8\necho not json\nexit 3\n").unwrap();
        fs::set_permissions(&pk, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let (mut run, _id, ending, ended) = stop_a_non_blocking_ask(&h);
    assert!(
        !ended.after_sigkill && ended.took < bound,
        "the builder ended {:?} after SIGTERM:\n{}",
        ended.took,
        run.stderr()
    );
    let status = exit_within(&mut run, RULED_WITHIN);
    let exit = ending.elapsed();
    assert!(
        exit > bound,
        "the slow `pk doctor` did not delay the exit ({exit:?}), so this proves nothing:\n{}",
        run.stderr()
    );
    assert_eq!(status.code(), Some(7), "{}", run.stderr());
    assert_eq!(h.run_json()["status"], "stopped");
}

#[test]
fn a_stop_of_a_builder_that_ignores_sigterm_is_reported_as_waiting_for_the_grace() {
    if !sandbox_available() {
        return;
    }
    // The other half of the stop test's property: when the grace IS waited out, the runner's
    // line says so, which is what makes the bound in
    // `a_stop_on_a_non_blocking_ask_ends_the_live_session_and_the_lane` fail for it.
    let grace = term_grace();
    let h = owned_packet(&nonblocking_stubborn("Quit?"));
    let (mut run, _id, _, ended) = stop_a_non_blocking_ask(&h);
    if cfg!(target_os = "linux") {
        // On Linux the group's SIGTERM also reaches bubblewrap, and the sandbox's PID
        // namespace ends with it: a builder cannot outlive SIGTERM there, so the line must
        // show a prompt end with no SIGKILL. (Seen in the Linux container: "ended 0 ms".)
        assert!(
            !ended.after_sigkill && ended.took < grace / 4,
            "on Linux the sandbox ends with SIGTERM, but the builder ended {:?} after it \
             (SIGKILL needed: {}):\n{}",
            ended.took,
            ended.after_sigkill,
            run.stderr()
        );
    } else {
        assert!(
            ended.after_sigkill,
            "SIGKILL was needed but the line does not say so:\n{}",
            run.stderr()
        );
        assert!(
            ended.took >= grace * 3 / 4,
            "the builder ended {:?} after SIGTERM, well inside a {grace:?} grace:\n{}",
            ended.took,
            run.stderr()
        );
    }
    let status = exit_within(&mut run, RULED_WITHIN);
    assert_eq!(status.code(), Some(7), "{}", run.stderr());
}

#[test]
fn a_reassign_on_a_non_blocking_ask_ends_the_live_session_and_starts_the_next_model() {
    if !sandbox_available() {
        return;
    }
    let h = owned_packet(&nonblocking_sleeper("Which design?"));
    let (mut child, id, ruled_at) = rule_the_moment_it_is_asked(&h, &["--reassign"]);
    second_segment_starts_within(&h, &mut child, ruled_at);
    let out = finish(child);
    assert_eq!(out.status.code(), Some(0), "{}", stdout_of(&out));
    let segs = segments(&h);
    assert_eq!(segs.len(), 2, "{segs:?}");
    assert_eq!(segs[0]["model"], "haiku");
    assert_eq!(segs[1]["model"], "sonnet", "{segs:?}");
    assert_eq!(segs[1]["start"], "fresh");
    assert_eq!(segs[1]["startedBy"], id.as_str());
    assert_eq!(h.seg(2, "resume"), "", "a reassign never resumes");
    assert!(h.seg(2, "prompt").contains("reassign to sonnet"));
    assert_first_builder_was_ruled_away(&h, &id);
    assert_eq!(h.verdict()["verdict"], "proved");
}

#[test]
fn a_redirect_on_a_non_blocking_ask_ends_the_live_session_and_starts_the_new_packet() {
    if !sandbox_available() {
        return;
    }
    let h = owned_packet(&nonblocking_sleeper("Right task?"));
    let redirected = h
        .packet_text
        .replace("Change the README.", "Change the README, then stop.");
    assert_ne!(redirected, h.packet_text);
    let packet = h.work.path().join("redirect.md");
    fs::write(&packet, &redirected).unwrap();
    let (mut child, id, ruled_at) =
        rule_the_moment_it_is_asked(&h, &["--redirect", packet.to_str().unwrap()]);
    second_segment_starts_within(&h, &mut child, ruled_at);
    let out = finish(child);
    assert_eq!(out.status.code(), Some(0), "{}", stdout_of(&out));
    let segs = segments(&h);
    assert_eq!(segs.len(), 2, "{segs:?}");
    assert_eq!(segs[1]["start"], "fresh");
    assert_eq!(h.seg(2, "resume"), "");
    assert_eq!(h.seg(2, "prompt"), redirected, "the packet's body, exactly");
    assert_first_builder_was_ruled_away(&h, &id);
}

#[test]
fn an_answer_on_a_non_blocking_ask_does_not_end_the_session_the_builder_reads_it() {
    if !sandbox_available() {
        return;
    }
    // The first session asks non-blocking, then polls `check_ruling` until
    // the answer is there (the runner must leave it running), notes that it
    // got it, and exits by itself; the lane is proved.
    let mut ask = blocking_ask("Which colour?");
    ask["blocking"] = json!(false);
    let poll = r#"lane="$(basename "$(dirname "$HOME")")"
i=0
while [ $i -lt 150 ]; do
  {
    printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"fake","version":"0"}}}'
    printf '%s\n' '{"jsonrpc":"2.0","method":"notifications/initialized"}'
    printf '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"check_ruling","arguments":{"id":"%s:E1"}}}\n' "$lane"
  } | "$cp_bin" lane-tools --socket "$sock" > "$rec/cr.out" 2>/dev/null
  if grep -q 'use option B' "$rec/cr.out"; then echo got > "$HOME/gotanswer"; break; fi
  i=$((i+1)); sleep 0.2
done
"#;
    let first = format!(
        "{}{}{poll}{}",
        init_line(),
        mcp_session("ask.out", &[(3, "ask", ask)]),
        then_checks()
    );
    let h = owned_packet(&first_then(&first, ":\n"));
    let (child, id, _) = rule_the_moment_it_is_asked(&h, &["--answer", "use option B"]);
    let out = finish(child);
    assert_eq!(out.status.code(), Some(0), "{}", stdout_of(&out));
    assert_eq!(h.read("home/gotanswer").trim(), "got");
    assert_eq!(h.launches(), 1, "the session was not ended");
    let segs = segments(&h);
    assert_eq!(segs.len(), 1, "{segs:?}");
    assert_eq!(segs[0]["sessionEnd"], Value::Null, "{segs:?}");
    assert_eq!(segs[0]["killedByRunner"], false);
    assert_eq!(segs[0]["endedBy"], Value::Null);
    assert_eq!(h.verdict()["verdict"], "proved");
    let ruled = queue_events(&h, "ruled");
    assert_eq!(ruled[0]["id"], id.as_str());
    assert_eq!(ruled[0]["verdict"]["verdict"], "answer");
}

/// The one forced escalation in the queue: its id, after checking it is forced.
fn forced_escalation(h: &Harness) -> Value {
    let asked = queue_events(h, "asked");
    assert_eq!(asked.len(), 1, "exactly one escalation: {asked:?}");
    assert!(
        asked[0]["origin"]["forced"].is_object(),
        "origin forced: {asked:?}"
    );
    asked[0].clone()
}

#[test]
fn a_turn_budget_forces_one_escalation_ends_the_session_and_a_stop_ends_the_lane() {
    if !sandbox_available() {
        return;
    }
    // Five turns against a budget of three, then the fake keeps running.
    let turns: String = (1..=5).map(|i| turn_line(&format!("m{i}"), 10)).collect();
    let first = format!("{}{turns}sleep 120\n", init_line());
    let h = owned_packet(&first_then(&first, &then_checks()));
    let mut run = start_watched(&h, &["--turn-budget", "3"]);
    let id = wait_for_ask(&h, &mut run.child, 1);
    run.wait_for_stderr(WAITING, SESSION_END_WITHIN);

    let forced = forced_escalation(&h);
    assert_eq!(forced["id"], id.as_str());
    let reason = forced["origin"]["forced"]["reason"].as_str().unwrap();
    assert!(reason.contains("turn budget 3"), "{reason}");
    assert_eq!(forced["ask"]["blocking"], true);

    rule(&h, &id, &["--stop"]);
    let out = finish(run.child);
    assert_eq!(out.status.code(), Some(7), "{}", stdout_of(&out));
    assert_eq!(h.run_json()["status"], "stopped");
    assert_eq!(
        h.launches(),
        1,
        "the lane waited for the ruling, then stopped"
    );
    let segs = segments(&h);
    assert_eq!(segs[0]["sessionEnd"], "forced", "{segs:?}");
    assert_eq!(segs[0]["killedByRunner"], true);
    assert_eq!(segs[0]["endedBy"], id.as_str());
    // Five turns went by and the budget fired once.
    assert_eq!(queue_events(&h, "asked").len(), 1);
}

#[test]
fn a_cost_estimate_past_the_share_forces_one_escalation_and_ends_the_session() {
    if !sandbox_available() {
        return;
    }
    // Haiku input is $1 per million tokens: each turn is an estimated $0.30,
    // so against a $1.00 cap the second turn crosses the 40% share ($0.60).
    let turns: String = (1..=4)
        .map(|i| turn_line(&format!("m{i}"), 300_000))
        .collect();
    let first = format!("{}{turns}sleep 120\n", init_line());
    let h = owned_packet(&first_then(&first, &then_checks()));
    let mut run = start_watched(&h, &["--cost-cap-usd", "1.0"]);
    let id = wait_for_ask(&h, &mut run.child, 1);
    run.wait_for_stderr(WAITING, SESSION_END_WITHIN);

    let forced = forced_escalation(&h);
    assert_eq!(forced["id"], id.as_str());
    let reason = forced["origin"]["forced"]["reason"].as_str().unwrap();
    assert!(reason.contains("estimated cost"), "{reason}");
    assert!(
        forced["ask"]["question"]
            .as_str()
            .unwrap()
            .contains("estimate"),
        "{forced}"
    );

    rule(&h, &id, &["--stop"]);
    let out = finish(run.child);
    assert_eq!(out.status.code(), Some(7), "{}", stdout_of(&out));
    assert_eq!(h.run_json()["status"], "stopped");
    let segs = segments(&h);
    assert_eq!(segs[0]["sessionEnd"], "forced", "{segs:?}");
    assert_eq!(segs[0]["killedByRunner"], true);
    assert_eq!(segs[0]["costIsEstimate"], true);
    let spent = segs[0]["estimatedCostUsd"].as_f64().unwrap();
    assert!(spent >= 0.6, "estimated {spent}");
    assert_eq!(queue_events(&h, "asked").len(), 1);
}

#[test]
fn run_help_documents_the_turn_budget_and_the_cost_cap_defaults() {
    let out = output(Command::new(env!("CARGO_BIN_EXE_cowproof")).args(["run", "--help"]));
    let help = String::from_utf8_lossy(&out.stdout).into_owned();
    for needle in [
        "--turn-budget",
        "[default: 40]",
        "--cost-cap-usd",
        "[default: 5]",
    ] {
        assert!(help.contains(needle), "{needle} missing from:\n{help}");
    }
}

// ---------------------------------------------------------------- net-bridge (D24)

/// A free loopback port.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Spawn `cowproof net-bridge <args>` with stderr piped. No sandbox: these
/// tests are about the subcommand's own contract.
fn spawn_net_bridge(args: &[&str]) -> Child {
    let _g = fork_lock();
    Command::new(env!("CARGO_BIN_EXE_cowproof"))
        .arg("net-bridge")
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

#[test]
fn net_bridge_prints_ready_on_stderr_once_bound_and_relays_to_the_socket() {
    use std::io::{BufRead, BufReader, Read, Write};
    let dir = var_tmp("cp-bridge-");
    let sock = dir.path().join("p.sock");
    let listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            let mut buf = [0u8; 4];
            if stream.read_exact(&mut buf).is_ok() {
                let _ = stream.write_all(&buf.map(|b| b.to_ascii_uppercase()));
            }
        }
    });
    let port = free_port();
    let mut child = spawn_net_bridge(&[
        "--port",
        &port.to_string(),
        "--target",
        sock.to_str().unwrap(),
    ]);
    let mut stderr = BufReader::new(child.stderr.take().unwrap());
    let mut line = String::new();
    stderr.read_line(&mut line).unwrap();
    assert_eq!(line, "READY\n");

    let mut c = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    c.write_all(b"abcd").unwrap();
    let mut got = [0u8; 4];
    c.read_exact(&mut got).unwrap();
    assert_eq!(&got, b"ABCD");
    child.kill().unwrap();
    child.wait().unwrap();
}

#[test]
fn net_bridge_waits_briefly_for_a_busy_port_and_gives_up_when_it_stays_busy() {
    use std::io::{BufRead, BufReader};
    let dir = var_tmp("cp-bridge-");
    let sock = dir.path().join("p.sock");

    // Busy for 400 ms (a previous launch's bridge still exiting): READY follows.
    let held = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = held.local_addr().unwrap().port();
    let mut child = spawn_net_bridge(&[
        "--port",
        &port.to_string(),
        "--target",
        sock.to_str().unwrap(),
    ]);
    std::thread::sleep(Duration::from_millis(400));
    drop(held);
    let mut stderr = BufReader::new(child.stderr.take().unwrap());
    let mut line = String::new();
    stderr.read_line(&mut line).unwrap();
    assert_eq!(line, "READY\n", "the bridge did not retry the busy port");
    child.kill().unwrap();
    child.wait().unwrap();

    // Busy for good: no READY, a failure exit, and the wrapper never runs its command.
    let held = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let busy = held.local_addr().unwrap().port();
    let marker = dir.path().join("ran");
    let out = output(Command::new(env!("CARGO_BIN_EXE_cowproof")).args([
        "net-bridge",
        "--port",
        &busy.to_string(),
        "--target",
        sock.to_str().unwrap(),
        "--",
        "/bin/sh",
        "-c",
        &format!("touch {}", marker.display()),
    ]));
    assert!(!out.status.success(), "{:?}", out.status);
    assert!(!marker.exists(), "the command ran without its bridge");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("not ready"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    drop(held);
}

#[test]
fn net_bridge_wrapper_passes_argv_whole_and_forwards_the_exit_status() {
    let dir = var_tmp("cp-bridge-");
    let sock = dir.path().join("p.sock");
    let port = free_port();
    let out_file = dir.path().join("argv");
    // A hostile-looking argument stays one argument: there is no shell.
    let hostile = "a b; touch PWNED $(id) 'q'";
    let out = output(
        Command::new(env!("CARGO_BIN_EXE_cowproof"))
            .current_dir(dir.path())
            .args([
                "net-bridge",
                "--port",
                &port.to_string(),
                "--target",
                sock.to_str().unwrap(),
                "--",
                "/bin/sh",
                "-c",
                "printf '%s' \"$1\" > \"$2\"; exit 7",
                "sh",
                hostile,
                out_file.to_str().unwrap(),
            ]),
    );
    assert_eq!(
        out.status.code(),
        Some(7),
        "{:?}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(fs::read_to_string(&out_file).unwrap(), hostile);
    assert!(!dir.path().join("PWNED").exists());
}

// ---- SIGINT and SIGTERM end the run (130) -----------------------------------
//
// A builder is not in the terminal's foreground group, so without a handler the
// default signal action would end the runner and leave the builder (and what it
// started) running. Every wait below is bounded.

/// How long after the first signal the run must have exited: SIGTERM to the
/// builder's group, then the leader's exit, with a wide margin for a loaded CI
/// machine. A builder that ignores SIGTERM would take 10 s; none here does.
const INTERRUPT_EXIT_WITHIN: Duration = Duration::from_secs(20);

/// Send `signal` (`"INT"`, `"TERM"`) to a process this test started, by `kill(2)`.
fn send_signal(signal: &str, child: &Child) {
    assert!(
        signal_pid(signal, child.id()),
        "could not send {signal} to pid {}",
        child.id()
    );
}

/// Wait for the file the fake writes once its background child runs. Only a run that never
/// gets there fails the wait, so the deadline is long: a sandbox start on a loaded host has
/// taken most of thirty seconds.
fn wait_for_file(run: &mut Watched, path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(120);
    while !path.exists() {
        assert!(
            run.child.try_wait().unwrap().is_none(),
            "the run ended before {} appeared:\n{}",
            path.display(),
            run.stderr()
        );
        if Instant::now() > deadline {
            let _ = run.child.kill();
            let _ = run.child.wait();
            panic!("{} never appeared:\n{}", path.display(), run.stderr());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Wait for the run to exit by itself within `within`; a run still going is
/// killed (by its pid) and fails the test.
fn exit_within(run: &mut Watched, within: Duration) -> std::process::ExitStatus {
    let deadline = Instant::now() + within;
    loop {
        if let Some(status) = run.child.try_wait().unwrap() {
            return status;
        }
        if Instant::now() > deadline {
            let _ = run.child.kill();
            let _ = run.child.wait();
            panic!(
                "cowproof run was still going {within:?} after the signal:\n{}",
                run.stderr()
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// The three sockets of a lane: the builder tools socket, the director control
/// socket and the egress proxy socket.
fn lane_sockets(h: &Harness) -> [PathBuf; 3] {
    [
        h.lane().join("sock/runner.sock"),
        h.lane().join("control/director.sock"),
        h.lane().join("proxy.sock"),
    ]
}

/// What an interrupted run must leave: exit 130, `interrupted` in `run.json`,
/// no verdict, no socket.
fn assert_interrupted_cleanly(h: &Harness, status: std::process::ExitStatus, run: &Watched) {
    assert_eq!(status.code(), Some(130), "{}", run.stderr());
    let run_json = h.run_json();
    assert_eq!(run_json["status"], "interrupted", "{run_json}");
    assert_eq!(run_json["exitCode"], 130);
    assert!(
        !h.lane().join("control/verdict.json").exists(),
        "an interrupted lane must not be proved"
    );
    assert!(
        !h.lane().join("control/capsule").exists(),
        "an interrupted lane must not be sealed"
    );
    for socket in lane_sockets(h) {
        assert!(
            std::fs::symlink_metadata(&socket).is_err(),
            "{} still exists",
            socket.display()
        );
    }
}

/// The fake: starts two background children that ignore SIGTERM (a marker
/// writer, and one whose pid it records), then sleeps.
fn builder_with_background_children() -> String {
    format!(
        "{}( trap '' TERM; sleep 14; echo alive > \"$HOME/survived\" ) &\n( trap '' TERM; sleep 300 ) &\necho $! > \"$HOME/bgpid\"\nsleep 120\n",
        init_line()
    )
}

/// The signal is sent while the builder runs; the builder's whole group is gone.
fn a_signal_ends_the_builder_its_children_and_the_servers(signal: &str) {
    let h = owned_packet(&builder_with_background_children());
    let mut run = start_watched(&h, &[]);
    wait_for_file(&mut run, &h.lane().join("home/bgpid"));
    let started = Instant::now();
    // Before the signal the sockets exist, so their absence afterwards shows the cleanup.
    for socket in &lane_sockets(&h) {
        assert!(
            socket.exists(),
            "{} is not there to remove",
            socket.display()
        );
    }

    send_signal(signal, &run.child);
    let status = exit_within(&mut run, INTERRUPT_EXIT_WITHIN);
    assert_interrupted_cleanly(&h, status, &run);
    assert_eq!(
        h.run_json()["signal"],
        if signal == "INT" { "SIGINT" } else { "SIGTERM" }
    );
    assert_eq!(h.launches(), 1, "an interrupted run never relaunches");

    // By pid where the sandbox shares the host's pid space (macOS). bwrap runs
    // with --unshare-pid, so on Linux the recorded pid means nothing outside.
    if cfg!(target_os = "macos") {
        let pid = h.read("home/bgpid");
        assert_pid_gone(pid.trim());
    }
    // By effect everywhere: a surviving child writes its marker at six seconds.
    std::thread::sleep(Duration::from_secs(9).saturating_sub(started.elapsed()));
    assert!(
        !h.lane().join("home/survived").exists(),
        "a background child outlived the interrupted run and wrote its marker"
    );
}

#[test]
fn sigint_ends_the_builders_whole_group_removes_the_sockets_and_exits_130() {
    if !sandbox_available() {
        return;
    }
    a_signal_ends_the_builder_its_children_and_the_servers("INT");
}

#[test]
fn sigterm_ends_the_builders_whole_group_removes_the_sockets_and_exits_130() {
    if !sandbox_available() {
        return;
    }
    a_signal_ends_the_builder_its_children_and_the_servers("TERM");
}

#[test]
fn a_signal_while_the_lane_waits_for_a_ruling_ends_the_run_without_a_builder() {
    if !sandbox_available() {
        return;
    }
    let ask = mcp_session("ask.out", &[(3, "ask", blocking_ask("Choose A or B?"))]);
    let h = owned_packet(&format!("{}{ask}sleep 120\n", init_line()));
    let mut run = start_watched(&h, &[]);
    wait_for_ask(&h, &mut run.child, 1);
    run.wait_for_stderr(WAITING, SESSION_END_WITHIN);

    send_signal("INT", &run.child);
    let status = exit_within(&mut run, INTERRUPT_EXIT_WITHIN);
    assert_interrupted_cleanly(&h, status, &run);
    assert_eq!(h.launches(), 1);
}

/// A grace constant of the runner (`TERM_GRACE`, `CHECK_TERM_GRACE`), read from its source
/// so the two cannot drift.
fn grace_from_source(name: &str) -> Duration {
    const SRC: &str = include_str!("../src/run.rs");
    let needle = format!("const {name}: Duration");
    let line = SRC
        .lines()
        .find(|l| l.contains(&needle))
        .unwrap_or_else(|| panic!("src/run.rs no longer defines {name}"));
    let secs = line
        .split("from_secs(")
        .nth(1)
        .and_then(|rest| rest.split(')').next())
        .and_then(|n| n.trim().parse::<u64>().ok())
        .unwrap_or_else(|| panic!("cannot read {name} from {line:?}"));
    Duration::from_secs(secs)
}

/// The runner's `TERM_GRACE`: how long the launcher lets a builder that ignores SIGTERM live
/// before it sends SIGKILL.
fn term_grace() -> Duration {
    grace_from_source("TERM_GRACE")
}

/// The runner's `CHECK_TERM_GRACE`: the same for a `run_check` group.
fn check_term_grace() -> Duration {
    grace_from_source("CHECK_TERM_GRACE")
}

/// A heartbeat file is appended to every half second by a process that must not outlive the
/// lane (or must be gone by some moment). Its length is how many beats it has made.
fn beats(path: &Path) -> u64 {
    fs::metadata(path).map(|m| m.len()).unwrap_or(0)
}

/// Assert that whatever writes `beat` has stopped: the file does not grow over two seconds
/// (four beats). With `settle` above zero it may take that long to stop, which is for a
/// process the runner ends without waiting for it; with zero the process must already be gone
/// (the run has exited). A process that outlived its lane beats for as long as the test looks,
/// however slowly a loaded host ends the others, so the check does not depend on a clock
/// picked for an idle machine the way a marker written after a fixed delay does. A survivor
/// that a loaded host starves for the whole two seconds would pass, which is the one way this
/// can miss a leak.
fn assert_heartbeat_stopped(beat: &Path, settle: Duration, what: &str) {
    let begun = Instant::now();
    loop {
        let before = beats(beat);
        std::thread::sleep(Duration::from_secs(2));
        if beats(beat) == before {
            return;
        }
        assert!(
            begun.elapsed() < settle,
            "{what} was still running {:?} after the lane ended: {} beats and counting",
            begun.elapsed(),
            beats(beat)
        );
    }
}

#[test]
fn a_second_signal_does_not_wait_out_a_builder_that_ignores_sigterm() {
    if !sandbox_available() {
        return;
    }
    // The leader ignores SIGTERM, so the first signal would take TERM_GRACE (ten seconds) to
    // become a SIGKILL. The second must not wait for them. The bound is a share of that grace
    // and not a number of seconds picked for an idle machine. The second signal is sent at
    // once, so a run that waited the grace out exits about TERM_GRACE later. A run that did
    // not exits when the runner has torn down, however slowly a loaded host does that; a
    // teardown that waits out the stream drain (`PUMP_DRAIN`, five seconds) would sit right
    // on the old five-second bound. Three quarters of the grace clears that and still fails
    // a wait for the grace.
    let grace = term_grace();
    let bound = grace * 3 / 4;
    let body = format!(
        "{}trap '' TERM\n( trap '' TERM; sleep 300 ) &\necho $! > \"$HOME/bgpid\"\nwhile true; do sleep 1; done\n",
        init_line()
    );
    let h = owned_packet(&body);
    let mut run = start_watched(&h, &[]);
    wait_for_file(&mut run, &h.lane().join("home/bgpid"));

    send_signal("INT", &run.child);
    run.wait_for_stderr("ending the builder", INTERRUPT_EXIT_WITHIN);
    let second = Instant::now();
    send_signal("INT", &run.child);
    // Past `grace` the launcher's own SIGKILL has fired, which proves nothing about the
    // second signal; the wait here only keeps a hung run from hanging the test.
    let status = exit_within(&mut run, grace + INTERRUPT_EXIT_WITHIN);
    let took = second.elapsed();
    assert!(
        took < bound,
        "the second signal waited for the SIGTERM grace: exit {took:?} after it, \
         bound {bound:?} of a {grace:?} grace:\n{}",
        run.stderr()
    );
    assert_interrupted_cleanly(&h, status, &run);
    if cfg!(target_os = "macos") {
        let pid = h.read("home/bgpid");
        assert_pid_gone(pid.trim());
    }
}

// ---------------------------------------------------------------------------
// Project instructions and the prefix version (D20, audit r15-1)
// ---------------------------------------------------------------------------

/// The SHA-256 of `bytes`, computed here and not by the code under test.
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(bytes))
}

/// The capsule's raw `capsule.json`, which the seal covers.
fn capsule_json(h: &Harness) -> Value {
    serde_json::from_str(&h.read("control/capsule/capsule.json")).unwrap()
}

/// `value[key]` where the key must be present: a missing key is not a null.
fn field<'a>(value: &'a Value, key: &str) -> &'a Value {
    value
        .get(key)
        .unwrap_or_else(|| panic!("no {key:?} in {value}"))
}

#[test]
fn the_builder_gets_claude_md_from_the_base_commit_not_the_working_tree() {
    if !sandbox_available() {
        return;
    }
    let h = owned_packet(&run_checks(&[]));
    let base = "BASE-MARKER: committed project rules\n";
    fs::write(h.repo.join("CLAUDE.md"), base).unwrap();
    git(&h.repo, &["add", "CLAUDE.md"]);
    git(&h.repo, &["commit", "-q", "-m", "project instructions"]);

    // The director edits CLAUDE.md and does not commit. A run refuses a dirty tree, and
    // `--allow-dirty` refuses a dirty CLAUDE.md too (a launch-removed path would travel in
    // base.patch), so the edit is hidden from `git status` with --assume-unchanged: the
    // working-tree file differs from the base and the run starts anyway.
    git(
        &h.repo,
        &["update-index", "--assume-unchanged", "CLAUDE.md"],
    );
    fs::write(h.repo.join("CLAUDE.md"), "DIRTY-MARKER: uncommitted edit\n").unwrap();
    assert_eq!(git_out(&h.repo, &["status", "--porcelain"]), "");
    assert!(
        fs::read_to_string(h.repo.join("CLAUDE.md"))
            .unwrap()
            .contains("DIRTY-MARKER")
    );

    h.run_ok();

    // The instructions section is exactly the committed bytes, after the preamble.
    let system = h.seg(1, "system-prompt.md");
    assert!(system.contains("BASE-MARKER"), "{system}");
    assert!(!system.contains("DIRTY-MARKER"), "{system}");
    assert_eq!(system, format!("{PREAMBLE}\n{base}"));
    assert!(!h.seg(1, "prompt").contains("DIRTY-MARKER"));
    for arg in h.argv() {
        assert!(!arg.contains("DIRTY-MARKER"), "{arg}");
    }

    // What was recorded is the hash of the committed bytes.
    let expected = sha256_hex(base.as_bytes());
    let run = h.run_json();
    assert_eq!(field(&run, "projectInstructionsSha256"), &json!(expected));
    assert_eq!(
        field(&capsule_json(&h), "project_instructions_sha256"),
        &json!(expected)
    );
    let capsule = Capsule::read(&h.lane().join("control/capsule")).unwrap();
    assert_eq!(
        capsule.project_instructions_sha256.as_deref(),
        Some(expected.as_str())
    );
}

#[test]
fn no_claude_md_at_the_base_means_no_instructions_section_and_a_null_hash() {
    if !sandbox_available() {
        return;
    }
    let h = owned_packet(&run_checks(&[]));
    // Untrack CLAUDE.md and exclude it, so the tree is clean but still has the file:
    // the working tree has instructions and the base has none.
    git(&h.repo, &["rm", "-q", "--cached", "CLAUDE.md"]);
    git(&h.repo, &["commit", "-q", "-m", "stop tracking CLAUDE.md"]);
    fs::write(h.repo.join("CLAUDE.md"), "DIRTY-MARKER: untracked file\n").unwrap();
    let exclude = h.repo.join(".git/info/exclude");
    let mut text = fs::read_to_string(&exclude).unwrap_or_default();
    text.push_str("/CLAUDE.md\n");
    fs::write(&exclude, text).unwrap();
    assert_eq!(git_out(&h.repo, &["status", "--porcelain"]), "");

    h.run_ok();

    // The prompt is the preamble alone: no section, no separator, nothing from the tree.
    let system = h.seg(1, "system-prompt.md");
    assert_eq!(system, PREAMBLE);
    assert!(!system.contains("DIRTY-MARKER"));

    assert!(field(&h.run_json(), "projectInstructionsSha256").is_null());
    assert!(field(&capsule_json(&h), "project_instructions_sha256").is_null());
    let capsule = Capsule::read(&h.lane().join("control/capsule")).unwrap();
    assert_eq!(capsule.project_instructions_sha256, None);
}

/// Replace the harness's committed `CLAUDE.md` with a committed symlink to `target`.
fn commit_claude_md_link(h: &Harness, target: &str) {
    git(&h.repo, &["rm", "-q", "CLAUDE.md"]);
    std::os::unix::fs::symlink(target, h.repo.join("CLAUDE.md")).unwrap();
    git(&h.repo, &["add", "-A"]);
    git(&h.repo, &["commit", "-q", "-m", "CLAUDE.md is a link"]);
    assert_eq!(git_out(&h.repo, &["status", "--porcelain"]), "");
}

#[test]
fn a_committed_claude_md_symlink_to_agents_md_gives_the_builder_agents_md() {
    if !sandbox_available() {
        return;
    }
    let h = owned_packet(&run_checks(&["edit", "made"]));
    let agents = "AGENTS-MARKER: the real project rules\n";
    fs::write(h.repo.join("AGENTS.md"), agents).unwrap();
    commit_claude_md_link(&h, "AGENTS.md");

    h.run_expecting(0);

    // The instructions are the link target's bytes, not the link's text.
    let system = h.seg(1, "system-prompt.md");
    assert_eq!(system, format!("{PREAMBLE}\n{agents}"));
    assert!(system.contains("AGENTS-MARKER"));
    let expected = sha256_hex(agents.as_bytes());
    assert_eq!(
        field(&h.run_json(), "projectInstructionsSha256"),
        &json!(expected)
    );
    assert_eq!(
        field(&capsule_json(&h), "project_instructions_sha256"),
        &json!(expected)
    );
}

#[test]
fn a_claude_md_symlink_that_leaves_the_tree_gives_no_instructions_and_a_warning() {
    if !sandbox_available() {
        return;
    }
    let h = owned_packet(&run_checks(&["edit", "made"]));
    // A file the link would reach if it were followed on disk, one level above the repo.
    fs::write(h.work.path().join("outside"), "OUTSIDE-MARKER\n").unwrap();
    commit_claude_md_link(&h, "../outside");

    let out = h.run_expecting(0);

    let system = h.seg(1, "system-prompt.md");
    assert_eq!(system, PREAMBLE);
    assert!(!system.contains("OUTSIDE-MARKER"));
    assert!(field(&h.run_json(), "projectInstructionsSha256").is_null());
    assert!(field(&capsule_json(&h), "project_instructions_sha256").is_null());
    let stderr = String::from_utf8_lossy(&out.stderr);
    let warnings: Vec<&str> = stderr
        .lines()
        .filter(|l| l.contains("no project instructions for the builder"))
        .collect();
    assert_eq!(warnings.len(), 1, "one warning: {stderr}");
    assert!(warnings[0].contains("outside the repository"), "{stderr}");
    assert_eq!(h.verdict()["verdict"], "proved");
}

#[test]
fn prefix_version_in_run_json_and_the_capsule_is_the_runners_prefix_version() {
    if !sandbox_available() {
        return;
    }
    let h = owned_packet(&run_checks(&[]));
    h.run_ok();

    let expected = cowproof_run::prefix::prefix_version();
    // Not merely a hex string: it is the version of this preamble, which is the hash of
    // its bytes.
    assert_eq!(expected, sha256_hex(PREAMBLE.as_bytes()));
    assert_eq!(field(&h.run_json(), "prefixVersion"), &json!(expected));
    assert_eq!(field(&capsule_json(&h), "prefix_version"), &json!(expected));
    let capsule = Capsule::read(&h.lane().join("control/capsule")).unwrap();
    assert_eq!(capsule.prefix_version.as_deref(), Some(expected.as_str()));

    // The harness commits "root instructions\n"; the default case records its hash too.
    assert_eq!(
        field(&h.run_json(), "projectInstructionsSha256"),
        &json!(sha256_hex(b"root instructions\n"))
    );
}

// ---------------------------------------------------------------- hard limits
//
// The wall-clock timeout and the cost-cap stop end a lane with its work kept
// and no proof: status `timeout` / `cost-cap`, exit 5 / 6.

/// No verdict, no capsule and no proof run: the lane was ended, not judged.
fn assert_not_proved(h: &Harness) {
    let control = h.lane().join("control");
    assert!(
        !control.join("verdict.json").exists(),
        "a lane ended by a hard limit has no verdict"
    );
    assert!(
        !control.join("capsule").exists(),
        "a lane ended by a hard limit is not sealed"
    );
}

/// The wall-clock limit of the timeout test, in seconds.
const TIMEOUT_TEST_LIMIT_SECS: u64 = 8;

#[test]
fn the_timeout_ends_a_silent_builder_and_a_child_that_ignores_sigterm_and_nothing_is_proved() {
    if !sandbox_available() {
        return;
    }
    // The builder says nothing and sleeps. A background child ignores SIGTERM (only the group
    // SIGKILL ends it) and appends to a heartbeat file twice a second. The limit is eight
    // seconds, wide enough for a cold sandbox start on a loaded machine (the clock runs from
    // the builder's spawn). Once the leader is gone the runner SIGKILLs the group, so the
    // child must have stopped beating when the run has exited, however late a loaded host got
    // there; a marker written after a fixed delay (it was fourteen seconds) fails when that
    // host takes longer than the delay.
    let first = "( trap '' TERM; while :; do echo . >> \"$HOME/beat\"; sleep 0.5; done ) &\necho $! > \"$HOME/bgpid\"\nsleep 120\n";
    let h = owned_packet(first);
    let child = {
        let _g = fork_lock();
        h.command(h.lanes.path())
            .args(["--timeout-secs", &TIMEOUT_TEST_LIMIT_SECS.to_string()])
            .env("ANTHROPIC_API_KEY", REAL_KEY)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
    };
    let out = finish(child);
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(out.status.code(), Some(5), "{}\n{stderr}", stdout_of(&out));
    assert!(stderr.contains("wall-clock timeout"), "{stderr}");
    // The runner ended the builder when the limit came, not when the 120 s sleep did. What is
    // measured is the runner's own account: the builder's time from its spawn to the exit
    // status being read (`durationMs`), which cannot be less than the limit and has to be
    // within the SIGTERM grace of it, and the runner's own line for how long the leader took
    // to go after SIGTERM. The test's wall clock is not used: it includes the copy of
    // `cowproof` and `pk` running for the first time, the preflight and the proof, which took
    // 52 and 90 seconds on a host busy with other builds while the builder lived 8.
    let limit = Duration::from_secs(TIMEOUT_TEST_LIMIT_SECS);
    let grace = term_grace();
    let segs = segments(&h);
    let lived = Duration::from_millis(segs[0]["durationMs"].as_u64().unwrap());
    assert!(
        lived >= limit && lived < limit + grace,
        "the builder lived {lived:?}, not the {limit:?} limit plus less than a {grace:?} grace \
         (the 120 s sleep was not cut short at the limit):\n{stderr}"
    );
    let ended = ended_after_term_in(&stderr);
    assert!(
        !ended.after_sigkill && ended.took < grace * 3 / 4,
        "the leader needed {:?} after SIGTERM (SIGKILL needed: {}):\n{stderr}",
        ended.took,
        ended.after_sigkill
    );
    assert_eq!(
        stdout_of(&out)
            .lines()
            .last()
            .unwrap()
            .split(',')
            .next()
            .unwrap(),
        format!("{}: timeout", h.id)
    );

    let run = h.run_json();
    assert_eq!(run["status"], "timeout");
    assert_eq!(run["timeoutSecs"], TIMEOUT_TEST_LIMIT_SECS);
    assert_eq!(segs.len(), 1, "no relaunch: {segs:?}");
    assert_eq!(h.launches(), 1);
    assert_eq!(segs[0]["sessionEnd"], "timeout", "{segs:?}");
    assert_eq!(segs[0]["killedByRunner"], true);
    assert_eq!(segs[0]["status"], "ended-by-runner");
    assert_eq!(segs[0]["signal"], 15, "SIGTERM ended the leader: {segs:?}");
    assert_not_proved(&h);

    // The stubborn child is gone: by pid where the sandbox shares the host's pid space
    // (macOS), and by effect everywhere (it has stopped beating).
    if cfg!(target_os = "macos") {
        assert_pid_gone(h.read("home/bgpid").trim());
    }
    assert!(
        beats(&h.lane().join("home/beat")) > 0,
        "the stubborn child never ran"
    );
    assert_heartbeat_stopped(
        &h.lane().join("home/beat"),
        Duration::ZERO,
        "a background child that ignores SIGTERM",
    );
}

#[test]
fn the_headers_timeout_min_beats_the_flag() {
    if !sandbox_available() {
        return;
    }
    // The flag says two seconds; the builder takes five. The header's 100
    // minutes win, so the builder finishes and the lane goes on to its proof.
    let mut h = owned_packet("sleep 5\n");
    h.set_header_field("timeoutMin", json!(100));
    let run = start_watched(&h, &["--timeout-secs", "2"]);
    let out = finish(run.child);
    // No check ran, so the proof says incomplete (3): a verdict, not a timeout.
    assert_eq!(out.status.code(), Some(3), "{}", stdout_of(&out));
    let json = h.run_json();
    assert_eq!(json["status"], "finished");
    assert_eq!(json["timeoutSecs"], 6000);
    let segs = segments(&h);
    assert_eq!(segs[0]["sessionEnd"], Value::Null, "{segs:?}");
    assert_eq!(segs[0]["killedByRunner"], false);
    assert_eq!(h.verdict()["verdict"], "incomplete");
}

/// The wall-clock limit of the parked-time test, in seconds. Only the two launches count
/// (a sandbox start and the park, then a resumed start and two checks run in sandboxes):
/// a fraction of a second to a few seconds on a macOS machine, many times that on a loaded
/// Linux host where every sandbox start queues. The limit is wide enough for the counted
/// time to stay well under it.
const PARKED_TEST_LIMIT_SECS: u64 = 30;

/// How long the director leaves the lane parked: longer than the whole limit, so that
/// counting the wait would end the resumed launch at once.
const PARKED_TEST_WAIT_SECS: u64 = PARKED_TEST_LIMIT_SECS + 4;

#[test]
fn time_parked_waiting_for_a_ruling_does_not_count_toward_the_timeout() {
    if !sandbox_available() {
        return;
    }
    // The builder parks on a blocking ask at once, the director rules more than the whole
    // limit later, and the resumed builder runs its checks. Only the time inside the two
    // launches counts, so the lane is proved.
    let limit = PARKED_TEST_LIMIT_SECS;
    let wait = PARKED_TEST_WAIT_SECS;
    let h = owned_packet(&asks_first("Choose A or B?", true, &then_checks()));
    let mut child = {
        let _g = fork_lock();
        h.command(h.lanes.path())
            .args(["--timeout-secs", &limit.to_string()])
            .env("ANTHROPIC_API_KEY", REAL_KEY)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
    };
    let id = wait_for_ask(&h, &mut child, 1);
    std::thread::sleep(Duration::from_secs(wait));
    rule(&h, &id, &["--answer", "use option B"]);
    let out = finish(child);
    assert_eq!(out.status.code(), Some(0), "{}", stdout_of(&out));
    assert_eq!(
        stdout_of(&out).lines().last().unwrap(),
        format!("{}: proved", h.id)
    );
    assert_eq!(h.launches(), 2);
    let segs = segments(&h);
    assert_eq!(segs[1]["start"], "resumed", "{segs:?}");
    assert!(
        segs.iter().all(|s| s["sessionEnd"] != "timeout"),
        "{segs:?}"
    );

    // The run took longer than the limit, the counted time well under it.
    let json = h.run_json();
    assert_eq!(json["timeoutSecs"], limit);
    let whole = json["durationMs"].as_u64().unwrap();
    let counted = json["activeMs"].as_u64().unwrap();
    assert!(
        whole >= wait * 1000,
        "the run included the {wait}-second wait: {whole} ms"
    );
    assert!(
        counted < limit * 1000,
        "only launch time counts: {counted} ms of a {limit} s limit"
    );
    assert!(
        whole - counted >= wait * 1000,
        "at least the wait was left out: {whole} ms whole, {counted} ms counted"
    );
    assert_eq!(h.verdict()["verdict"], "proved");
}

/// A fake that, on its first launch, prints `first_turns` $0.30 turns (haiku
/// input at $1 per million) and sleeps; on every later launch it prints
/// `later_turns` of them and sleeps for `later_sleep` seconds.
fn costly_builder(first_turns: usize, later_turns: usize, later_sleep: u32) -> String {
    let turns = |from: usize, count: usize| -> String {
        (from..from + count)
            .map(|i| turn_line(&format!("m{i}"), 300_000))
            .collect()
    };
    first_then(
        &format!("{}{}sleep 120\n", init_line(), turns(1, first_turns)),
        &format!("{}sleep {later_sleep}\n", turns(10, later_turns)),
    )
}

#[test]
fn a_cost_estimate_at_the_whole_cap_ends_the_lane_after_the_early_escalation_fired_first() {
    if !sandbox_available() {
        return;
    }
    // Cap $1.00. The first launch's second turn brings the estimate to $0.60,
    // past the 40% share: one forced escalation, which the director answers.
    // The resumed launch adds $0.30 ($0.90, below the cap) and then $0.30 more
    // ($1.20): the lane ends there, long before the builder's 30 s sleep does.
    let h = owned_packet(&costly_builder(2, 2, 30));
    let mut run = start_watched(&h, &["--cost-cap-usd", "1.0"]);
    let id = wait_for_ask(&h, &mut run.child, 1);
    run.wait_for_stderr(WAITING, SESSION_END_WITHIN);
    let forced = forced_escalation(&h);
    let reason = forced["origin"]["forced"]["reason"].as_str().unwrap();
    assert!(reason.contains("estimated cost"), "{reason}");
    assert_eq!(h.launches(), 1, "nothing relaunched before the ruling");

    rule(&h, &id, &["--answer", "keep going"]);
    let out = finish(run.child);
    assert_eq!(out.status.code(), Some(6), "{}", stdout_of(&out));
    assert_eq!(
        stdout_of(&out)
            .lines()
            .last()
            .unwrap()
            .split(',')
            .next()
            .unwrap(),
        format!("{}: cost-cap", h.id)
    );

    let json = h.run_json();
    assert_eq!(json["status"], "cost-cap");
    assert_eq!(json["costIsEstimate"], true);
    assert_eq!(json["costCapUsd"], 1.0);
    assert!(
        json["estimatedCostUsd"].as_f64().unwrap() >= 1.0,
        "{}",
        json["estimatedCostUsd"]
    );
    // The early escalation fired once, before the stop; the stop opened none.
    assert_eq!(queue_events(&h, "asked").len(), 1);
    let segs = segments(&h);
    assert_eq!(segs.len(), 2, "{segs:?}");
    assert_eq!(segs[0]["sessionEnd"], "forced", "{segs:?}");
    assert_eq!(segs[1]["start"], "resumed");
    assert_eq!(segs[1]["sessionEnd"], "cost-cap", "{segs:?}");
    assert_eq!(segs[1]["killedByRunner"], true);
    assert_eq!(segs[1]["signal"], 15, "{segs:?}");
    assert_eq!(h.launches(), 2, "no relaunch after the stop");
    assert_not_proved(&h);
}

#[test]
fn the_headers_max_cost_usd_beats_the_flag_and_a_single_jump_past_the_cap_stops_without_asking() {
    if !sandbox_available() {
        return;
    }
    // One turn of $1.20 against a header cap of $1.00 (the flag says $100):
    // the estimate jumps over the 40% share and the cap together, and the stop
    // wins over the early escalation.
    let first = format!("{}{}sleep 120\n", init_line(), turn_line("m1", 1_200_000));
    let mut h = owned_packet(&first);
    h.set_header_field("maxCostUsd", json!(1.0));
    let child = {
        let _g = fork_lock();
        h.command(h.lanes.path())
            .args(["--cost-cap-usd", "100"])
            .env("ANTHROPIC_API_KEY", REAL_KEY)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
    };
    let out = finish(child);
    assert_eq!(out.status.code(), Some(6), "{}", stdout_of(&out));
    let json = h.run_json();
    assert_eq!(json["status"], "cost-cap");
    assert_eq!(json["costCapUsd"], 1.0);
    assert_eq!(json["costIsEstimate"], true);
    let queue = fs::read_to_string(h.lane().join("control/escalations.jsonl")).unwrap_or_default();
    assert!(
        !queue.contains("\"asked\""),
        "no escalation was opened: {queue}"
    );
    let segs = segments(&h);
    assert_eq!(segs.len(), 1, "{segs:?}");
    assert_eq!(segs[0]["sessionEnd"], "cost-cap");
    assert_not_proved(&h);
}

#[test]
fn run_help_documents_the_two_hard_limits_and_hides_the_test_flag() {
    let out = output(Command::new(env!("CARGO_BIN_EXE_cowproof")).args(["run", "--help"]));
    let help = String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    for needle in [
        "--timeout-min",
        "[default: 45]",
        "header's `timeoutMin` wins",
        "header's `maxCostUsd` wins",
        "not the bill",
    ] {
        assert!(help.contains(needle), "{needle} missing from:\n{help}");
    }
    assert!(!help.contains("--timeout-secs"), "the test flag is hidden");
}

#[test]
fn builder_stderr_with_tokens_is_redacted() {
    if !sandbox_available() {
        return;
    }
    // Fake builder writes synthetic tokens to stderr
    let fake_body = r#"
echo "Error with Bearer sk-synthtoken1234567 in stderr" >&2
echo "Also xoxb-1234567890synthetic" >&2
"#;
    let h = Harness::new(fake_body);
    h.run_ok();

    let stderr = h.read("control/builder.stderr");
    // Redacted tokens should be present
    assert!(
        stderr.contains("[redacted]"),
        "stderr should contain redacted marker: {stderr}"
    );
    // Original tokens should NOT be present
    assert!(
        !stderr.contains("sk-synthtoken1234567"),
        "sk- token should be redacted: {stderr}"
    );
    assert!(
        !stderr.contains("xoxb-1234567890synthetic"),
        "xox token should be redacted: {stderr}"
    );
    // Bearer text should still be there with redacted token
    assert!(
        stderr.contains("Bearer [redacted]"),
        "Bearer header should be redacted: {stderr}"
    );
}

// ---- builder stderr is redacted as it is written ----------------------------
//
// The builder's stderr is a pipe the runner reads: only redacted text reaches
// `control/builder.stderr`, at the time it is written, not after the builder
// exits.

const STDERR_TOKEN: &str = "sk-synthtoken1234567";

/// Wait until `control/builder.stderr` contains `needle`, at most 30 s; a run
/// that never gets there is killed (by its pid) and fails the test.
fn wait_for_stderr_file(run: &mut Watched, h: &Harness, needle: &str) -> String {
    let path = h.lane().join("control/builder.stderr");
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let text = fs::read_to_string(&path).unwrap_or_default();
        if text.contains(needle) {
            return text;
        }
        if Instant::now() > deadline {
            let _ = run.child.kill();
            let _ = run.child.wait();
            panic!("{needle:?} never reached {}: {text:?}", path.display());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn builder_stderr_is_redacted_while_the_builder_is_still_running() {
    if !sandbox_available() {
        return;
    }
    let h = owned_packet(&format!(
        "{}echo \"auth failed: Bearer {STDERR_TOKEN} and xoxb-1234567890synthetic\" >&2\necho up > \"$HOME/written\"\nsleep 120\n",
        init_line()
    ));
    let mut run = start_watched(&h, &[]);
    wait_for_file(&mut run, &h.lane().join("home/written"));
    // The builder is still alive (asleep): an after-exit rewrite has not run.
    let text = wait_for_stderr_file(&mut run, &h, "[redacted]");
    assert!(
        run.child.try_wait().unwrap().is_none(),
        "the run ended early"
    );
    assert!(
        !text.contains(STDERR_TOKEN) && !text.contains("xoxb-1234567890synthetic"),
        "a raw token is on disk while the builder runs: {text:?}"
    );
    assert!(text.contains("Bearer [redacted]"), "{text:?}");
    send_signal("INT", &run.child);
    let status = exit_within(&mut run, INTERRUPT_EXIT_WITHIN);
    assert_eq!(status.code(), Some(130), "{}", run.stderr());
}

#[test]
fn a_token_split_across_two_stderr_writes_is_redacted() {
    if !sandbox_available() {
        return;
    }
    let h = Harness::new("printf 'leak sk-abcd' >&2\nsleep 0.3\nprintf 'efgh1234 tail\\n' >&2\n");
    h.run_ok();
    let text = h.read("control/builder.stderr");
    assert!(text.contains("leak [redacted] tail"), "{text:?}");
    assert!(
        !text.contains("sk-abcd") && !text.contains("efgh1234"),
        "a piece of the token reached the file: {text:?}"
    );
}

#[test]
fn sigint_leaves_no_raw_token_in_builder_stderr_even_for_an_unfinished_line() {
    if !sandbox_available() {
        return;
    }
    // One complete line, then a token with no newline after it.
    let h = owned_packet(&format!(
        "{}echo \"first {STDERR_TOKEN}\" >&2\nprintf 'second sk-partialtoken9999' >&2\necho up > \"$HOME/written\"\nsleep 120\n",
        init_line()
    ));
    let mut run = start_watched(&h, &[]);
    wait_for_file(&mut run, &h.lane().join("home/written"));
    wait_for_stderr_file(&mut run, &h, "first [redacted]");
    send_signal("INT", &run.child);
    let status = exit_within(&mut run, INTERRUPT_EXIT_WITHIN);
    assert_interrupted_cleanly(&h, status, &run);
    let text = h.read("control/builder.stderr");
    assert!(
        !text.contains(STDERR_TOKEN) && !text.contains("sk-partialtoken9999"),
        "a raw token is on disk after SIGINT: {text:?}"
    );
    assert!(
        text.contains("first [redacted]") && text.contains("second [redacted]"),
        "the unfinished line is written, redacted, when the stream ends: {text:?}"
    );
}

// `--unsandboxed` (R-U1): the builder runs without the OS sandbox, the lane is checked by
// the same gates and a sandboxed verifier, and it can end `finished`, never `proved`.

/// The path a builder tries to write, in a directory nothing grants: the sandbox denies it,
/// `--unsandboxed` does not. (`/var/tmp`, so bwrap sees it too.)
fn escape_target() -> (TempDir, PathBuf) {
    let dir = var_tmp("cp-run-escape-");
    let target = dir.path().join("escaped.txt");
    (dir, target)
}

/// A fake builder body that tries to write `target`, records the shell's status in
/// `$HOME/fake/escape.status`, and runs `ok` (a check that passes).
fn escaping_builder(target: &Path) -> String {
    format!(
        "{{ echo escaped > '{}'; }} 2>/dev/null\necho $? > \"$HOME/fake/escape.status\"\n{}",
        target.display(),
        run_checks(&["ok"])
    )
}

fn escaping_harness(target: &Path) -> Harness {
    Harness::with_packet(
        &escaping_builder(target),
        json!(["README.md", "created.txt"]),
        json!([{"id": "ok", "command": "true"}]),
    )
}

#[test]
fn a_builder_write_outside_its_lane_is_denied_by_the_sandbox_and_succeeds_with_unsandboxed() {
    if !sandbox_available() {
        return;
    }
    // Sandboxed: the write is denied, the shell says so, nothing appears.
    let (_dir, target) = escape_target();
    let h = escaping_harness(&target);
    h.run_expecting(0);
    assert_ne!(h.read("home/fake/escape.status").trim(), "0");
    assert!(!target.exists(), "the sandbox let the write through");
    assert_eq!(h.verdict()["verdict"], "proved");

    // Unsandboxed: the same builder writes it.
    let (_dir, target) = escape_target();
    let h = escaping_harness(&target);
    let out = h.run_unsandboxed();
    assert_eq!(out.status.code(), Some(0), "{}", run_text(&out));
    assert_eq!(h.read("home/fake/escape.status").trim(), "0");
    assert_eq!(fs::read_to_string(&target).unwrap(), "escaped\n");
}

fn run_text(out: &Output) -> String {
    format!(
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

#[test]
fn an_unsandboxed_lane_with_passing_checks_is_finished_not_proved_and_verified_in_a_sandbox() {
    if !sandbox_available() {
        return;
    }
    // `marker` is written by the check into its own TMPDIR: the lane's when the builder
    // runs it, the verifier's when verify replays it, so the verifier's copy is its record.
    // `confined` passes only while its write outside the lane is denied, so a verifier
    // that ran unsandboxed would diverge on it.
    let (_dir, target) = escape_target();
    let confined = format!("! {{ echo x > '{}'; }} 2>/dev/null", target.display());
    let h = Harness::with_packet(
        &run_checks(&["edit", "made", "marker", "confined"]),
        json!(["README.md", "created.txt"]),
        json!([
            {"id": "edit", "command": "grep -q edited README.md"},
            {"id": "made", "command": "test -f created.txt"},
            {"id": "marker", "command": "echo ran > \"${TMPDIR:?}/verify-marker\""},
            {"id": "confined", "command": confined},
        ]),
    );
    let out = h.run_unsandboxed();
    assert_eq!(out.status.code(), Some(0), "{}", run_text(&out));

    // One loud warning line on stderr.
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    let warnings: Vec<_> = stderr.lines().filter(|l| l.contains("WARNING")).collect();
    assert_eq!(warnings.len(), 1, "{stderr}");
    assert!(warnings[0].contains("--unsandboxed"), "{stderr}");

    // Finished, with a reason naming the flag; the last stdout line says so.
    let verdict = h.verdict();
    assert_eq!(verdict["verdict"], "finished", "{verdict}");
    assert_eq!(verdict["exitCode"], 0);
    assert_eq!(verdict["unsandboxed"], true);
    assert_eq!(verdict["diverged"], json!([]));
    assert_eq!(verdict["failedChecks"], json!([]));
    assert_eq!(verdict["failedGates"], json!([]));
    let reasons = reasons(&verdict);
    assert_eq!(reasons.len(), 1, "{reasons:?}");
    assert!(reasons[0].contains("--unsandboxed"), "{reasons:?}");
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout
            .lines()
            .last()
            .unwrap()
            .starts_with(&format!("{}: finished: ", h.id)),
        "{stdout}"
    );

    // run.json and the capsule both record it, and the capsule's seal covers the field.
    assert_eq!(h.run_json()["unsandboxed"], true);
    let dir = h.lane().join("control/capsule");
    let capsule = Capsule::read(&dir).expect("the capsule reads back");
    assert!(capsule.unsandboxed);
    assert_eq!(capsule.lane_state, "finished");
    let raw = h.read("control/capsule/capsule.json");
    assert!(raw.contains("\"unsandboxed\": true"), "{raw}");
    fs::write(
        dir.join("capsule.json"),
        raw.replace("\"unsandboxed\": true", "\"unsandboxed\": false"),
    )
    .unwrap();
    assert!(Capsule::read(&dir).is_err(), "the seal must cover the flag");

    // The in-run verify ran and reproduced: it rebuilt the tree, ran the marker check in
    // its own temp directory, and its sandbox held `confined`.
    assert_eq!(
        fs::read_to_string(h.lane().join("scratch/verify/tmp/verify-marker")).unwrap(),
        "ran\n"
    );
    assert_eq!(
        fs::read_to_string(h.lane().join("scratch/verify/tree/created.txt")).unwrap(),
        "created\n"
    );
    assert!(!target.exists(), "the verifier wrote outside its sandbox");
}

#[test]
fn an_unsandboxed_lane_with_a_failing_check_is_refuted() {
    if !sandbox_available() {
        return;
    }
    let h = Harness::with_packet(
        &run_checks(&["bad"]),
        json!(["README.md", "created.txt"]),
        json!([{"id": "bad", "command": "false"}]),
    );
    let out = h.run_unsandboxed();
    assert_eq!(out.status.code(), Some(2), "{}", run_text(&out));
    let verdict = h.verdict();
    assert_eq!(verdict["verdict"], "refuted", "{verdict}");
    assert_eq!(verdict["unsandboxed"], true);
    assert_eq!(verdict["failedChecks"], json!(["bad"]));
    assert_eq!(h.run_json()["unsandboxed"], true);
}

#[test]
fn a_sandboxed_run_records_unsandboxed_false_everywhere() {
    if !sandbox_available() {
        return;
    }
    let h = owned_packet(&run_checks(&["edit", "made"]));
    let out = h.run_expecting(0);
    assert!(
        !String::from_utf8_lossy(&out.stderr).contains("WARNING"),
        "{}",
        run_text(&out)
    );
    assert_eq!(h.verdict()["unsandboxed"], false);
    assert_eq!(h.run_json()["unsandboxed"], false);
}

#[test]
fn run_help_says_unsandboxed_is_for_trusted_local_experiments_and_what_it_gives_up() {
    let out = output(Command::new(env!("CARGO_BIN_EXE_cowproof")).args(["run", "--help"]));
    assert!(out.status.success());
    let help = String::from_utf8(out.stdout)
        .unwrap()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    for needle in [
        "--unsandboxed",
        "trusted local experiments only",
        "never `proved`",
        "`cowproof verify` refuses its capsule",
        "0 proved (or finished, for a lane run with `--unsandboxed`)",
    ] {
        assert!(help.contains(needle), "no {needle:?} in: {help}");
    }
}

/// What the builder prints on stdout reaches `control/stream.jsonl` redacted: string
/// values of a JSON event and a plain text line. The usage numbers in the file are the
/// builder's own, and a line with nothing to redact is kept byte for byte.
#[test]
fn stream_jsonl_is_redacted_and_keeps_the_usage_numbers() {
    if !sandbox_available() {
        return;
    }
    let fake_body = r#"
printf '%s\n' '{"type":"assistant","message":{"id":"mt","content":[{"type":"text","text":"key sk-streamtokenabc and Bearer streambearer"}],"usage":{"input_tokens":3,"output_tokens":5}}}'
printf '%s\n' 'plain line with sk-plainstreamtoken in it'
printf '%s\n' '{"type":"system", "subtype":"note"}'
"#;
    let h = Harness::new(fake_body);
    h.run_ok();
    let stream = h.read("control/stream.jsonl");
    for raw in ["sk-streamtokenabc", "streambearer", "sk-plainstreamtoken"] {
        assert!(
            !stream.contains(raw),
            "{raw} reached stream.jsonl:\n{stream}"
        );
    }
    assert!(stream.contains("Bearer [redacted]"), "{stream}");
    assert!(
        stream.contains("plain line with [redacted] in it"),
        "{stream}"
    );
    let event: Value = stream
        .lines()
        .find(|l| l.contains("\"id\":\"mt\""))
        .map(|l| serde_json::from_str(l).unwrap())
        .expect("the assistant event is in stream.jsonl");
    assert_eq!(
        event["message"]["usage"],
        json!({"input_tokens":3,"output_tokens":5})
    );
    // Nothing to redact: the builder's own bytes, spacing included.
    assert!(
        stream.contains(r#"{"type":"system", "subtype":"note"}"#),
        "{stream}"
    );
}

// Portkit hooks, the lane-private state dir and the lane-end doctor (D5, G8).

/// A hook payload as Claude Code sends it after a `Read`: the minimum that makes
/// `pk hook post-tool-use` write one agent-surface record.
const POST_TOOL_USE: &str = r#"{"session_id":"s1","hook_event_name":"PostToolUse","tool_name":"Read","tool_input":{"file_path":"README.md"},"tool_response":{"content":"base"}}"#;

/// Shell for a fake that fires `pk hook post-tool-use` once, with `pk` found
/// beside the copied cowproof, then runs the packet's two checks.
fn hook_once_then_checks() -> String {
    format!(
        "printf '%s' '{POST_TOOL_USE}' | \"$(dirname \"$cp_bin\")/pk\" hook post-tool-use\n{}",
        run_checks(&["edit", "made"])
    )
}

fn hook_command(settings: &Value, event: &str) -> String {
    settings["hooks"][event][0]["hooks"][0]["command"]
        .as_str()
        .unwrap_or_else(|| panic!("no {event} hook in {settings}"))
        .to_string()
}

#[test]
fn the_builder_settings_have_the_three_hooks_with_the_absolute_pk_beside_cowproof() {
    if !sandbox_available() {
        return;
    }
    let h = Harness::new("");
    h.run_ok();
    let settings: Value = serde_json::from_str(&h.seg(1, "settings.json")).unwrap();
    let pk = h.work.path().canonicalize().unwrap().join("pk");
    for (event, arg) in [
        ("PostToolUse", "post-tool-use"),
        ("UserPromptSubmit", "user-prompt-submit"),
        ("SessionEnd", "session-end"),
    ] {
        let command = hook_command(&settings, event);
        let program = command.split_whitespace().next().unwrap();
        assert!(Path::new(program).is_absolute(), "{command}");
        assert!(program.ends_with("/pk"), "{command}");
        assert!(Path::new(program).is_file(), "{command}");
        assert_eq!(command, format!("{} hook {arg}", pk.display()));
    }
    // The permissions are still there beside the hooks.
    assert!(settings["permissions"]["allow"].is_array(), "{settings}");
    assert!(settings["permissions"]["deny"].is_array(), "{settings}");
}

#[test]
fn the_builder_env_names_the_lane_private_portkit_state_dir_and_session() {
    if !sandbox_available() {
        return;
    }
    let h = Harness::new("");
    h.run_ok();
    let env = h.read("home/fake/env.txt");
    let state = h.lane().join("portkit");
    for line in [
        format!("PORTKIT_STATE_DIR={}", state.display()),
        format!("PORTKIT_SESSION={}", h.id),
        // portkit traces nothing unless asked: without this the hooks would be idle.
        "PK_TRACE__ENABLED=true".to_string(),
    ] {
        assert!(env.lines().any(|l| l == line), "{line} not in\n{env}");
    }
    // Made by the runner, beside the clone and not in it.
    assert!(state.is_dir());
    assert!(!state.starts_with(h.lane().join("clone")));
}

#[test]
fn a_builder_whose_hook_fired_is_traced_in_run_json_and_the_capsule_and_leaves_the_clone_alone() {
    if !sandbox_available() {
        return;
    }
    let h = owned_packet(&hook_once_then_checks());
    h.run_expecting(0);
    assert_eq!(h.verdict()["verdict"], "proved");

    let trace = &h.run_json()["trace"];
    assert_eq!(trace["traced"], true, "{trace}");
    assert!(trace.get("reason").is_none(), "{trace}");
    let checks = trace["checks"].as_array().unwrap();
    let fired = checks
        .iter()
        .find(|c| c["name"] == "hooks have fired")
        .unwrap_or_else(|| panic!("{trace}"));
    assert_eq!(fired["status"], "pass", "{trace}");
    let registered = checks
        .iter()
        .find(|c| c["name"] == "hooks registered")
        .unwrap_or_else(|| panic!("{trace}"));
    assert_eq!(registered["status"], "pass", "{trace}");

    // Sealed in the capsule, which still reads back with every hash verified.
    let capsule_dir = h.lane().join("control/capsule");
    assert!(Capsule::read(&capsule_dir).unwrap().traced);
    let raw: Value = serde_json::from_str(&h.read("control/capsule/capsule.json")).unwrap();
    assert_eq!(raw["traced"], true);

    // The record is in the lane's state dir, named for the lane.
    let traces = h.lane().join("portkit/traces");
    let files: Vec<PathBuf> = fs::read_dir(&traces)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    assert_eq!(files.len(), 1, "{files:?}");
    let name = files[0].file_name().unwrap().to_str().unwrap().to_string();
    assert!(name.ends_with(&format!("-{}.jsonl", h.id)), "{name}");
    let record: Value =
        serde_json::from_str(fs::read_to_string(&files[0]).unwrap().trim()).unwrap();
    assert_eq!(record["tool"], "Read");
    assert_eq!(record["surface"], "agent");

    // Nothing of portkit's is in the clone or the patch: the clone holds only the
    // fake's own edit and file (the runner has staged both to take the patch).
    let clone = h.lane().join("clone");
    assert!(!clone.join(".portkit").exists());
    let status = git_out(&clone, &["status", "--porcelain", "--untracked-files=all"]);
    let mut lines: Vec<&str> = status.lines().collect();
    lines.sort_unstable();
    assert_eq!(lines, ["A  created.txt", "M  README.md"], "{status}");
    assert!(!h.read("control/lane.patch").contains("portkit"));
}

#[test]
fn a_builder_that_ran_no_hook_is_untraced_in_both_files_and_still_proved() {
    if !sandbox_available() {
        return;
    }
    let h = owned_packet(&run_checks(&["edit", "made"]));
    h.run_expecting(0);
    assert_eq!(h.verdict()["verdict"], "proved");

    let trace = &h.run_json()["trace"];
    assert_eq!(trace["traced"], false, "{trace}");
    // The settings were registered; only the evidence is missing.
    let reason = trace["reason"].as_str().unwrap();
    assert!(reason.starts_with("hooks have fired: "), "{reason}");
    let raw: Value = serde_json::from_str(&h.read("control/capsule/capsule.json")).unwrap();
    assert_eq!(raw["traced"], false);
    assert!(
        !Capsule::read(&h.lane().join("control/capsule"))
            .unwrap()
            .traced
    );
    // The state dir exists and holds no trace.
    assert!(!h.lane().join("portkit/traces").exists());
}

#[test]
fn with_no_pk_beside_cowproof_there_are_no_hooks_and_the_lane_is_untraced_but_proved() {
    if !sandbox_available() {
        return;
    }
    let h = owned_packet(&run_checks(&["edit", "made"]));
    fs::remove_file(h.work.path().join("pk")).unwrap();
    h.run_expecting(0);
    assert_eq!(h.verdict()["verdict"], "proved");

    let settings: Value = serde_json::from_str(&h.seg(1, "settings.json")).unwrap();
    assert!(settings.get("hooks").is_none(), "{settings}");
    assert!(settings["permissions"]["allow"].is_array(), "{settings}");

    let trace = &h.run_json()["trace"];
    assert_eq!(trace["traced"], false, "{trace}");
    let reason = trace["reason"].as_str().unwrap();
    assert!(reason.contains("pk was not found"), "{reason}");
    let raw: Value = serde_json::from_str(&h.read("control/capsule/capsule.json")).unwrap();
    assert_eq!(raw["traced"], false);
}

#[test]
fn a_doctor_that_fails_makes_the_lane_untraced_and_never_changes_the_verdict() {
    if !sandbox_available() {
        return;
    }
    let h = owned_packet(&run_checks(&["edit", "made"]));
    // A `pk` that exits non-zero with output that is not JSON, in place of the real one.
    let pk = h.work.path().join("pk");
    {
        let _g = fork_lock();
        fs::remove_file(&pk).unwrap();
        fs::write(&pk, "#!/bin/sh\necho not json\nexit 3\n").unwrap();
        fs::set_permissions(&pk, fs::Permissions::from_mode(0o755)).unwrap();
    }
    h.run_expecting(0);
    assert_eq!(h.verdict()["verdict"], "proved");

    let trace = &h.run_json()["trace"];
    assert_eq!(trace["traced"], false, "{trace}");
    let reason = trace["reason"].as_str().unwrap();
    assert!(reason.contains("printed no JSON (exit 3)"), "{reason}");
    let raw: Value = serde_json::from_str(&h.read("control/capsule/capsule.json")).unwrap();
    assert_eq!(raw["traced"], false);
}

// ----------------------------------------------------------------------------------------
// The ladder and routing (D28 step 1): `cowproof.toml` `[ladder]` and `[routing]` at the base
// commit, a packet header's `rung`, `--model`, and the Claude-only adapter.
// ----------------------------------------------------------------------------------------

impl Harness {
    /// Put `text` in the repository's `cowproof.toml` and commit it, so it is part of the
    /// base commit the lane starts from.
    fn commit_config(&self, text: &str) {
        fs::write(self.repo.join("cowproof.toml"), text).unwrap();
        git(&self.repo, &["add", "cowproof.toml"]);
        git(&self.repo, &["commit", "-q", "-m", "config"]);
    }

    /// `cowproof run` with the real key set and `extra` arguments after the usual ones.
    fn run_with(&self, extra: &[&str]) -> Output {
        output(
            self.command(self.lanes.path())
                .args(extra)
                .env("ANTHROPIC_API_KEY", REAL_KEY),
        )
    }
}

/// The lane reached a verdict, whatever it was (exit 0, 2 or 3).
///
/// The failure's first line carries the exit code and the end of stderr (where the runner says
/// why: a preflight failure, an infrastructure error), because a gate that keeps only the
/// panic's first line used to lose both.
fn reached_a_verdict(out: &Output) {
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        matches!(out.status.code(), Some(0 | 2 | 3)),
        "cowproof run did not reach a verdict: exit {:?}, {}\nstdout: {}\nstderr: {stderr}",
        out.status.code(),
        why_a_run_failed(&stderr),
        String::from_utf8_lossy(&out.stdout),
    );
}

/// The last three non-empty lines of a failed run's stderr, on one line: the runner puts its
/// reason just before "nothing was started" or the error exit.
fn why_a_run_failed(stderr: &str) -> String {
    let mut last: Vec<&str> = stderr
        .lines()
        .rev()
        .filter(|l| !l.trim().is_empty())
        .take(3)
        .collect();
    last.reverse();
    if last.is_empty() {
        "stderr empty".to_string()
    } else {
        format!("stderr ends: {}", last.join(" | "))
    }
}

/// What the first launch ran on: the `--model` the fake saw, and what `run.json` recorded.
fn started_on(h: &Harness, model: &str, source: &str) {
    let run = h.run_json();
    assert_eq!(h.seg(1, "model"), model, "the argv of the first launch");
    assert_eq!(run["segments"][0]["model"], model, "{run}");
    assert_eq!(run["segments"][0]["runtime"], "claude", "{run}");
    assert_eq!(run["runtime"], "claude", "{run}");
    assert_eq!(run["model"], model, "{run}");
    assert_eq!(run["rungSource"], source, "{run}");
    assert_eq!(run["startRung"], format!("claude:{model}"), "{run}");
}

#[test]
fn with_no_config_the_lane_starts_on_the_default_ladders_first_rung() {
    if !sandbox_available() {
        return;
    }
    let h = Harness::new("");
    reached_a_verdict(&h.run_with(&[]));
    started_on(&h, "haiku", "default");
}

#[test]
fn the_flag_names_the_starting_rung_and_the_runtime_prefix_never_reaches_the_argv() {
    if !sandbox_available() {
        return;
    }
    let h = Harness::new("");
    h.commit_config("[routing]\ndefault = \"claude:sonnet\"\n");
    reached_a_verdict(&h.run_with(&["--model", "claude:opus"]));
    started_on(&h, "opus", "flag");
}

#[test]
fn a_bare_flag_model_still_means_claude() {
    if !sandbox_available() {
        return;
    }
    let h = Harness::new("");
    reached_a_verdict(&h.run_with(&["--model", "sonnet"]));
    started_on(&h, "sonnet", "flag");
}

#[test]
fn the_packet_headers_rung_names_the_starting_rung() {
    if !sandbox_available() {
        return;
    }
    let mut h = Harness::new("");
    h.commit_config("[routing]\ndefault = \"claude:opus\"\n");
    h.set_header_field("rung", json!("claude:sonnet"));
    reached_a_verdict(&h.run_with(&[]));
    started_on(&h, "sonnet", "header");
}

#[test]
fn the_class_route_names_the_starting_rung() {
    if !sandbox_available() {
        return;
    }
    let h = Harness::new("");
    h.commit_config(
        "[routing]\ndefault = \"claude:opus\"\nclasses = { light = \"claude:sonnet\" }\n",
    );
    reached_a_verdict(&h.run_with(&[]));
    started_on(&h, "sonnet", "class");
}

#[test]
fn the_routing_default_names_the_starting_rung() {
    if !sandbox_available() {
        return;
    }
    let h = Harness::new("");
    // A class route for another class does not apply to this `light` packet.
    h.commit_config(
        "[routing]\ndefault = \"claude:sonnet\"\nclasses = { rust = \"claude:opus\" }\n",
    );
    reached_a_verdict(&h.run_with(&[]));
    started_on(&h, "sonnet", "default");
}

#[test]
fn the_flag_beats_the_header_beats_the_class_beats_the_default_in_a_real_run() {
    if !sandbox_available() {
        return;
    }
    let config = "[routing]\ndefault = \"claude:opus\"\nclasses = { light = \"claude:sonnet\" }\n";

    let mut all = Harness::new("");
    all.commit_config(config);
    all.set_header_field("rung", json!("claude:haiku"));
    reached_a_verdict(&all.run_with(&["--model", "claude:x-flag-model"]));
    started_on(&all, "x-flag-model", "flag");

    let mut header = Harness::new("");
    header.commit_config(config);
    header.set_header_field("rung", json!("claude:haiku"));
    reached_a_verdict(&header.run_with(&[]));
    started_on(&header, "haiku", "header");

    let class = Harness::new("");
    class.commit_config(config);
    reached_a_verdict(&class.run_with(&[]));
    started_on(&class, "sonnet", "class");
}

#[test]
fn the_base_commits_routing_wins_over_the_working_trees() {
    if !sandbox_available() {
        return;
    }
    let h = Harness::new("");
    h.commit_config("[routing]\ndefault = \"claude:sonnet\"\n");
    // The director's tree has an uncommitted edit of the routing (recorded as the base
    // patch with --allow-dirty): the lane's configuration is still the committed one.
    fs::write(
        h.repo.join("cowproof.toml"),
        "[routing]\ndefault = \"claude:opus\"\n",
    )
    .unwrap();
    reached_a_verdict(&h.run_with(&["--allow-dirty"]));
    started_on(&h, "sonnet", "default");
}

/// A fake that asks a blocking question on its first `last` launches, then runs the checks.
fn asks_until(last: usize, later: &str) -> String {
    let ask = blocking_ask("Which design?");
    format!(
        "if [ \"$n\" -le {last} ]; then\n{}else\n{later}fi\n",
        mcp_session("ask.out", &[(3, "ask", ask)])
    )
}

#[test]
fn reassign_follows_a_custom_four_rung_claude_ladder() {
    if !sandbox_available() {
        return;
    }
    let h = owned_packet(&asks_until(2, &then_checks()));
    h.commit_config(
        "[ladder]\nrungs = [\"claude:alpha\", \"claude:beta\", \"claude:gamma\", \"claude:delta\"]\n",
    );
    let mut child = start(&h);
    let first = wait_for_ask(&h, &mut child, 1);
    rule(&h, &first, &["--reassign"]);
    let second = wait_for_ask(&h, &mut child, 2);
    rule(&h, &second, &["--reassign"]);
    let out = finish(child);
    assert_eq!(out.status.code(), Some(0), "{}", stdout_of(&out));

    assert_eq!(h.launches(), 3);
    for (n, model) in [(1, "alpha"), (2, "beta"), (3, "gamma")] {
        assert_eq!(h.seg(n, "model"), model, "launch {n}");
    }
    let segs = segments(&h);
    let recorded: Vec<(&str, &str)> = segs
        .iter()
        .map(|s| (s["runtime"].as_str().unwrap(), s["model"].as_str().unwrap()))
        .collect();
    assert_eq!(
        recorded,
        [("claude", "alpha"), ("claude", "beta"), ("claude", "gamma")]
    );
    assert!(h.seg(2, "prompt").contains("reassign to beta"));
    assert!(h.seg(3, "prompt").contains("reassign to gamma"));
    let run = h.run_json();
    assert_eq!(run["model"], "gamma", "{run}");
    assert_eq!(run["rungSource"], "default");
    assert_eq!(queue_events(&h, "delivered").len(), 2);
    assert_eq!(h.verdict()["verdict"], "proved");
    let capsule = Capsule::read(&h.lane().join("control/capsule")).unwrap();
    assert_eq!(capsule.builder_model, "gamma");
}

/// A reassign that was refused: the lane failed with `why` in its error, the work is kept,
/// only `launches` builders ran, `delivered` rulings reached a builder, and nothing was proved.
fn assert_reassign_refused(
    h: &Harness,
    out: &Output,
    why: &str,
    launches: usize,
    delivered: usize,
) {
    assert_eq!(out.status.code(), Some(1), "{}", stdout_of(out));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains(why), "{stderr}");
    assert!(stderr.contains("reassign for"), "{stderr}");
    assert_eq!(h.launches(), launches);
    let run = h.run_json();
    assert_eq!(run["status"], "failed", "{run}");
    assert!(run["error"].as_str().unwrap().contains(why), "{run}");
    assert_eq!(queue_events(h, "delivered").len(), delivered);
    assert!(h.read("control/lane.patch").contains("+edited"));
    assert!(!h.lane().join("control/verdict.json").exists());
    assert!(!h.lane().join("control/capsule").exists());
}

#[test]
fn reassign_at_the_top_of_a_custom_ladder_is_refused_as_today() {
    if !sandbox_available() {
        return;
    }
    let h = owned_packet(&asks_until(9, &then_checks()));
    h.commit_config("[ladder]\nrungs = [\"claude:alpha\", \"claude:beta\"]\n");
    let mut child = start(&h);
    let first = wait_for_ask(&h, &mut child, 1);
    rule(&h, &first, &["--reassign"]);
    let second = wait_for_ask(&h, &mut child, 2);
    rule(&h, &second, &["--reassign"]);
    let out = finish(child);
    assert_reassign_refused(&h, &out, "no model above \"beta\" on the ladder", 2, 1);
}

/// `[runtimes.codex.prices]` for `gpt-6-luna`, so a ladder may list a Codex rung.
const CODEX_PRICE: &str =
    "[runtimes.codex.prices.\"gpt-6-luna\"]\ninput = 1.25\noutput = 10\nsource = \"test\"\n";

/// [`start`] with `extra` arguments after the usual ones.
fn start_with(h: &Harness, extra: &[&str]) -> Child {
    let _g = fork_lock();
    h.command(h.lanes.path())
        .args(extra)
        .env("ANTHROPIC_API_KEY", REAL_KEY)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

#[test]
fn reassign_onto_a_codex_rung_that_cannot_run_ends_the_lane_like_the_top_of_the_ladder() {
    if !sandbox_available() {
        return;
    }
    let h = owned_packet(&asks_until(9, &then_checks()));
    h.commit_config(&format!(
        "[ladder]\nrungs = [\"claude:alpha\", \"codex:gpt-6-luna\", \"claude:omega\"]\n\n{CODEX_PRICE}"
    ));
    // No Codex where the director's PATH looks, and no OpenAI key: the rung is on the ladder and
    // priced, but cannot run.
    let mut child = start_with(&h, &["--codex-bin", "no-such-codex-binary"]);
    let first = wait_for_ask(&h, &mut child, 1);
    rule(&h, &first, &["--reassign"]);
    let out = finish(child);
    assert_reassign_refused(
        &h,
        &out,
        "`codex` was not found on this machine's PATH",
        1,
        0,
    );
    // The same state as the top of the ladder: the ruling stays recorded, undelivered.
    assert_eq!(queue_events(&h, "ruled").len(), 1);
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("codex:gpt-6-luna"),
        "the refusal names the rung"
    );
}

#[test]
fn a_named_reassign_onto_a_codex_rung_that_cannot_run_is_refused_too() {
    if !sandbox_available() {
        return;
    }
    let h = owned_packet(&asks_until(9, &then_checks()));
    let mut child = start(&h);
    let first = wait_for_ask(&h, &mut child, 1);
    rule(&h, &first, &["--reassign", "--model", "codex:gpt-6-luna"]);
    let out = finish(child);
    assert_reassign_refused(
        &h,
        &out,
        "`codex` was not found on this machine's PATH",
        1,
        0,
    );
}

/// A run that stopped before anything existed: exit 4, `needle` on stderr, no lane directory
/// and no builder launched.
fn assert_refused_before_start(h: &Harness, out: &Output, needle: &str) {
    assert_eq!(
        out.status.code(),
        Some(4),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains(needle), "{stderr}");
    assert!(stderr.contains("nothing was started"), "{stderr}");
    assert!(!h.lane().exists(), "no lane directory may exist");
}

#[test]
fn starting_on_a_codex_rung_that_cannot_run_is_exit_4_before_anything_starts() {
    if !sandbox_available() {
        return;
    }
    // No OpenAI key in the test's environment, and a price in the base commit, so the key is
    // what is missing, whoever chose the rung.
    let no_key = "OPENAI_API_KEY is not set";

    // The ladder's first rung is the default start.
    let by_default = Harness::new("");
    by_default.commit_config(&format!(
        "[ladder]\nrungs = [\"codex:gpt-6-luna\", \"claude:haiku\"]\n\n{CODEX_PRICE}"
    ));
    let out = by_default.run_with(&[]);
    assert_refused_before_start(&by_default, &out, no_key);
    assert!(
        String::from_utf8_lossy(&out.stderr)
            .contains("rung codex:gpt-6-luna refused (default chose it)"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    // The flag.
    let by_flag = Harness::new("");
    by_flag.commit_config(CODEX_PRICE);
    let out = by_flag.run_with(&["--model", "codex:gpt-6-luna"]);
    assert_refused_before_start(&by_flag, &out, no_key);
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("(flag chose it)"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    // The header, on a ladder that lists the rung.
    let mut by_header = Harness::new("");
    by_header.commit_config(&format!(
        "[ladder]\nrungs = [\"claude:haiku\", \"codex:gpt-6-luna\"]\n\n{CODEX_PRICE}"
    ));
    by_header.set_header_field("rung", json!("codex:gpt-6-luna"));
    let out = by_header.run_with(&[]);
    assert_refused_before_start(&by_header, &out, no_key);
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("(header chose it)"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Without a price it is the price that is named, with the key.
    let unpriced = Harness::new("");
    let out = unpriced.run_with(&["--model", "codex:gpt-6-luna"]);
    assert_refused_before_start(&unpriced, &out, "model \"gpt-6-luna\" has no price");
}

#[test]
fn a_rung_that_is_not_on_the_ladder_is_exit_4_naming_it() {
    if !sandbox_available() {
        return;
    }
    // A header rung off the base commit's ladder: lint reports it, and the run refuses it.
    let mut header = Harness::new("");
    header.commit_config("[ladder]\nrungs = [\"claude:haiku\"]\n");
    header.set_header_field("rung", json!("claude:opus"));
    let out = header.run_with(&[]);
    assert_refused_before_start(&header, &out, "rung claude:opus is not on the ladder");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("error [rung]"),
        "lint named it too: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // The flag overriding it does not excuse it.
    let mut flagged = Harness::new("");
    flagged.commit_config("[ladder]\nrungs = [\"claude:haiku\"]\n");
    flagged.set_header_field("rung", json!("claude:opus"));
    let out = flagged.run_with(&["--model", "claude:haiku"]);
    assert_refused_before_start(&flagged, &out, "rung claude:opus is not on the ladder");

    // A routing rung off the ladder is a broken configuration at the base commit.
    let routing = Harness::new("");
    routing.commit_config(
        "[ladder]\nrungs = [\"claude:haiku\"]\n[routing]\ndefault = \"claude:opus\"\n",
    );
    let out = routing.run_with(&[]);
    assert_refused_before_start(&routing, &out, "rung claude:opus is not on the ladder");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("[routing] default"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    // So is an empty ladder, and a routing mistake no packet asked about.
    let empty = Harness::new("");
    empty.commit_config("[ladder]\nrungs = []\n");
    let out = empty.run_with(&[]);
    assert_refused_before_start(&empty, &out, "must not be empty");
}

#[test]
fn the_capsule_records_the_runtime_the_model_and_where_the_rung_came_from() {
    if !sandbox_available() {
        return;
    }
    let h = owned_packet(&run_checks(&["edit", "made"]));
    h.commit_config("[routing]\nclasses = { light = \"claude:sonnet\" }\n");
    let out = h.run_with(&[]);
    assert_eq!(out.status.code(), Some(0), "{}", stdout_of(&out));
    assert_eq!(h.verdict()["verdict"], "proved");

    let capsule = Capsule::read(&h.lane().join("control/capsule")).unwrap();
    assert_eq!(capsule.builder_runtime, "claude");
    assert_eq!(capsule.builder_model, "sonnet");
    assert_eq!(capsule.rung_source.as_deref(), Some("class"));
    let raw: Value = serde_json::from_str(&h.read("control/capsule/capsule.json")).unwrap();
    assert_eq!(raw["builder_runtime"], "claude");
    assert_eq!(raw["rung_source"], "class");
    let run = h.run_json();
    assert_eq!(run["rungSource"], "class");
    assert_eq!(run["runtime"], "claude");
}

// ----------------------------------------------------------------------------------------
// Packet profiles for the rung the lane actually uses (D28 clause 5): `--model` and a
// `reassign` can land a packet on a rung whose profile `cowproof lint` never resolved.
// ----------------------------------------------------------------------------------------

/// `sonnet` needs a strict profile; `haiku` (the default start) and `opus` need none.
const PROFILE_CONFIG: &str = "[ladder]\nrungs = [\"claude:haiku\", \"claude:sonnet\", \"claude:opus\"]\n\n\
[profiles.strict]\nrequire = [\"tests\", \"mutations\", \"done-checklist\"]\n\n\
[routing.profiles]\n\"claude:sonnet\" = \"strict\"\n";

/// `beta`, the rung above the default start `alpha`, needs tests and mutations.
const REASSIGN_PROFILE_CONFIG: &str = "[ladder]\nrungs = [\"claude:alpha\", \"claude:beta\"]\n\n\
[profiles.strict]\nrequire = [\"tests\", \"mutations\"]\n\n\
[routing.profiles]\n\"claude:beta\" = \"strict\"\n";

const PROFILE_TESTS: &str =
    "\n## Tests\n\n- `a_bad_rung_is_refused` asserts that the run stops before any lane exists.\n";
const PROFILE_MUTATIONS: &str =
    "\n## Mutations\n\n- (a) make the parser accept any rung, then run the tests\n";
const PROFILE_DONE: &str = "\n## Done checklist\n\n1. every test passes\n2. fmt is clean\n";

impl Harness {
    /// Append `text` to the packet, on disk and in `packet_text`.
    fn append_body(&mut self, text: &str) {
        self.packet_text.push_str(text);
        fs::write(&self.packet, &self.packet_text).unwrap();
    }
}

#[test]
fn a_strict_profile_rung_reached_only_by_the_flag_is_refused_at_start_naming_what_is_missing() {
    if !sandbox_available() {
        return;
    }
    // Lint resolves `haiku` (no profile), so only the run can see that `--model sonnet`
    // lands on the strict profile.
    let h = Harness::new("");
    h.commit_config(PROFILE_CONFIG);
    let out = h.run_with(&["--model", "sonnet"]);
    assert_refused_before_start(&h, &out, "rung claude:sonnet refused (flag chose it)");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("profile \"strict\""), "{stderr}");
    for requirement in ["tests: add", "mutations: add", "done-checklist: add"] {
        assert!(stderr.contains(requirement), "{requirement} in {stderr}");
    }
    assert_eq!(h.launches_dir_entries(), 0, "the builder never ran");

    // A packet that has two of the three names only the third.
    let mut partial = Harness::new("");
    partial.commit_config(PROFILE_CONFIG);
    partial.append_body(&format!("{PROFILE_TESTS}{PROFILE_DONE}"));
    let out = partial.run_with(&["--model", "sonnet"]);
    assert_refused_before_start(&partial, &out, "mutations: add");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!stderr.contains("tests: add"), "{stderr}");
    assert!(!stderr.contains("done-checklist: add"), "{stderr}");

    // The same packet, started where lint looked (`haiku`, no profile), runs: the check is
    // about the rung used, not about the packet.
    let unrouted = Harness::new("");
    unrouted.commit_config(PROFILE_CONFIG);
    reached_a_verdict(&unrouted.run_with(&[]));
    started_on(&unrouted, "haiku", "default");
    assert_eq!(unrouted.run_json()["segments"][0]["profile"], Value::Null);
}

impl Harness {
    /// How many entries the lanes root holds: none when a run was refused before it began.
    fn launches_dir_entries(&self) -> usize {
        fs::read_dir(self.lanes.path()).unwrap().count()
    }
}

/// `haiku` (the header's rung) needs the strict profile; `sonnet` needs none.
const HEADER_STRICT_CONFIG: &str = "[ladder]\nrungs = [\"claude:haiku\", \"claude:sonnet\", \"claude:opus\"]\n\n\
[profiles.strict]\nrequire = [\"tests\", \"mutations\", \"done-checklist\"]\n\n\
[routing.profiles]\n\"claude:haiku\" = \"strict\"\n";

#[test]
fn a_packet_routed_to_a_strict_rung_runs_when_the_flag_moves_it_to_a_rung_with_no_profile() {
    if !sandbox_available() {
        return;
    }
    // The header names `haiku`, whose strict profile the packet lacks: lint, which has no
    // `--model`, says so. Inside `run` that finding must not stop a lane that `--model` puts
    // on `sonnet`, which needs nothing.
    let mut h = owned_packet(&run_checks(&["edit", "made"]));
    h.set_header_field("rung", json!("claude:haiku"));
    h.commit_config(HEADER_STRICT_CONFIG);
    let out = h.run_with(&["--model", "sonnet"]);
    assert_eq!(out.status.code(), Some(0), "{}", stdout_of(&out));
    assert!(
        !String::from_utf8_lossy(&out.stderr).contains("[profile]"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(h.verdict()["verdict"], "proved");
    started_on(&h, "sonnet", "flag");
    assert_eq!(h.run_json()["segments"][0]["profile"], Value::Null);
}

#[test]
fn the_same_packet_without_the_flag_is_refused_by_runs_own_start_check() {
    if !sandbox_available() {
        return;
    }
    let mut h = owned_packet(&run_checks(&["edit", "made"]));
    h.set_header_field("rung", json!("claude:haiku"));
    h.commit_config(HEADER_STRICT_CONFIG);
    let out = h.run_with(&[]);
    // Exit 4 from the start check, not exit 1 from lint.
    assert_refused_before_start(&h, &out, "rung claude:haiku refused (header chose it)");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("profile \"strict\""), "{stderr}");
    for requirement in ["tests: add", "mutations: add", "done-checklist: add"] {
        assert!(stderr.contains(requirement), "{requirement} in {stderr}");
    }
    assert!(!stderr.contains("packet lint found errors"), "{stderr}");
    assert!(!stderr.contains("error [profile]"), "{stderr}");
}

#[test]
fn a_broken_profiles_config_still_stops_a_run_that_has_a_flag() {
    if !sandbox_available() {
        return;
    }
    let h = owned_packet(&run_checks(&["edit", "made"]));
    h.commit_config(
        "[ladder]\nrungs = [\"claude:haiku\", \"claude:sonnet\"]\n\n\
         [profiles.strict]\nrequire = [\"coverage\"]\n",
    );
    let out = h.run_with(&["--model", "sonnet"]);
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("error [profile]"), "{stderr}");
    assert!(stderr.contains("packet lint found errors"), "{stderr}");
    assert!(!h.lane().exists(), "no lane directory may exist");
}

#[test]
fn a_packet_with_the_complete_profile_proves_on_the_strict_rung_and_run_json_records_it() {
    if !sandbox_available() {
        return;
    }
    let mut h = owned_packet(&run_checks(&["edit", "made"]));
    h.append_body(&format!("{PROFILE_TESTS}{PROFILE_MUTATIONS}{PROFILE_DONE}"));
    h.commit_config(PROFILE_CONFIG);
    let out = h.run_with(&["--model", "sonnet"]);
    assert_eq!(out.status.code(), Some(0), "{}", stdout_of(&out));
    assert_eq!(h.verdict()["verdict"], "proved");
    started_on(&h, "sonnet", "flag");
    assert_eq!(
        h.run_json()["segments"][0]["profile"],
        json!({
            "rung": "claude:sonnet",
            "name": "strict",
            "requires": ["tests", "mutations", "done-checklist"],
            "met": true,
            "missing": [],
        })
    );
}

#[test]
fn a_reassign_onto_a_rung_whose_profile_the_packet_lacks_ends_the_lane_refused_with_the_work_kept()
{
    if !sandbox_available() {
        return;
    }
    let h = owned_packet(&asks_until(9, &then_checks()));
    h.commit_config(REASSIGN_PROFILE_CONFIG);
    let mut child = start(&h);
    let first = wait_for_ask(&h, &mut child, 1);
    rule(&h, &first, &["--reassign"]);
    let out = finish(child);
    // The same end as a rung with no adapter: failed, patch kept, no verdict, no capsule,
    // the ruling recorded and never delivered.
    assert_reassign_refused(&h, &out, "profile \"strict\"", 1, 0);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("claude:beta is the next rung"), "{stderr}");
    assert!(stderr.contains("tests: add"), "{stderr}");
    assert!(stderr.contains("mutations: add"), "{stderr}");
    assert_eq!(queue_events(&h, "ruled").len(), 1);
    let segs = segments(&h);
    assert_eq!(segs.len(), 1);
    assert_eq!(segs[0]["profile"], Value::Null, "alpha has no profile");
}

#[test]
fn a_reassign_onto_a_profiled_rung_goes_ahead_when_the_packet_meets_it() {
    if !sandbox_available() {
        return;
    }
    let mut h = owned_packet(&asks_until(1, &then_checks()));
    h.append_body(&format!("{PROFILE_TESTS}{PROFILE_MUTATIONS}"));
    h.commit_config(REASSIGN_PROFILE_CONFIG);
    let mut child = start(&h);
    let first = wait_for_ask(&h, &mut child, 1);
    rule(&h, &first, &["--reassign"]);
    let out = finish(child);
    assert_eq!(out.status.code(), Some(0), "{}", stdout_of(&out));
    assert_eq!(h.launches(), 2);
    assert_eq!(h.seg(2, "model"), "beta");
    assert_eq!(h.verdict()["verdict"], "proved");
    let segs = segments(&h);
    assert_eq!(segs[0]["profile"], Value::Null);
    assert_eq!(
        segs[1]["profile"],
        json!({
            "rung": "claude:beta",
            "name": "strict",
            "requires": ["tests", "mutations"],
            "met": true,
            "missing": [],
        })
    );
}

/// `haiku`, the rung a lane starts on and stays on through a redirect, needs tests and
/// mutations; `sonnet` (never reached in these tests) needs the full set.
const REDIRECT_PROFILE_CONFIG: &str = "[ladder]\nrungs = [\"claude:haiku\", \"claude:sonnet\"]\n\n\
[profiles.strict]\nrequire = [\"tests\", \"mutations\"]\n\n\
[routing.profiles]\n\"claude:haiku\" = \"strict\"\n";

/// A harness whose packet meets the strict profile of the rung it starts on, with a redirect
/// file written from it: `edit` changes the packet text, and the file is `redirect.md`.
fn redirect_on_profiled_rung(config: &str, edit: impl Fn(&str) -> String) -> (Harness, PathBuf) {
    redirect_after(
        &asks_first("Right task?", true, &then_checks()),
        config,
        edit,
    )
}

/// `redirect_on_profiled_rung` with the fake claude's script chosen by the caller.
fn redirect_after(fake: &str, config: &str, edit: impl Fn(&str) -> String) -> (Harness, PathBuf) {
    let mut h = owned_packet(fake);
    h.append_body(&format!("{PROFILE_TESTS}{PROFILE_MUTATIONS}"));
    h.commit_config(config);
    let redirected = edit(&h.packet_text);
    assert_ne!(redirected, h.packet_text);
    let packet = h.work.path().join("redirect.md");
    fs::write(&packet, &redirected).unwrap();
    (h, packet)
}

#[test]
fn a_redirect_lacking_a_requirement_of_the_rungs_profile_ends_the_lane_refused_naming_it() {
    if !sandbox_available() {
        return;
    }
    // The redirect drops the mutations section the strict profile of `haiku` requires.
    let (h, packet) = redirect_on_profiled_rung(REDIRECT_PROFILE_CONFIG, |text| {
        text.replace(PROFILE_MUTATIONS, "")
            .replace("Change the README.", "Change the README, then stop.")
    });
    let mut child = start(&h);
    let id = wait_for_ask(&h, &mut child, 1);
    rule(&h, &id, &["--redirect", packet.to_str().unwrap()]);
    let out = finish(child);
    assert_eq!(out.status.code(), Some(1), "{}", stdout_of(&out));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("redirect for"), "{stderr}");
    assert!(stderr.contains("profile \"strict\""), "{stderr}");
    assert!(stderr.contains("claude:haiku"), "{stderr}");
    assert!(stderr.contains("mutations: add"), "{stderr}");
    assert!(
        !stderr.contains("tests: add"),
        "the redirect has its tests: {stderr}"
    );
    // The same end as a refused reassign: failed, work kept, no verdict, the ruling recorded
    // and never delivered, and no second session.
    assert_eq!(h.launches(), 1);
    let run = h.run_json();
    assert_eq!(run["status"], "failed", "{run}");
    let error = run["error"].as_str().unwrap();
    assert!(error.contains("profile \"strict\""), "{run}");
    assert!(error.contains("mutations: add"), "{run}");
    assert_eq!(queue_events(&h, "ruled").len(), 1);
    assert!(queue_events(&h, "delivered").is_empty());
    assert!(h.read("control/lane.patch").contains("+edited"));
    assert!(!h.lane().join("control/verdict.json").exists());
    assert_eq!(segments(&h).len(), 1);
    assert_eq!(segments(&h)[0]["profile"]["met"], true);
}

#[test]
fn a_redirect_that_meets_the_rungs_profile_is_delivered_and_recorded() {
    if !sandbox_available() {
        return;
    }
    let (h, packet) = redirect_on_profiled_rung(REDIRECT_PROFILE_CONFIG, |text| {
        text.replace("Change the README.", "Change the README, then stop.")
    });
    let mut child = start(&h);
    let id = wait_for_ask(&h, &mut child, 1);
    rule(&h, &id, &["--redirect", packet.to_str().unwrap()]);
    let out = finish(child);
    assert_eq!(out.status.code(), Some(0), "{}", stdout_of(&out));
    assert_eq!(h.launches(), 2);
    assert_eq!(queue_events(&h, "delivered").len(), 1);
    let met = json!({
        "rung": "claude:haiku",
        "name": "strict",
        "requires": ["tests", "mutations"],
        "met": true,
        "missing": [],
    });
    let segs = segments(&h);
    assert_eq!(segs[0]["profile"], met);
    assert_eq!(
        segs[1]["profile"], met,
        "the redirected packet's check is recorded"
    );
}

#[test]
fn a_redirect_on_a_rung_with_no_profile_is_delivered_whatever_other_rungs_require() {
    if !sandbox_available() {
        return;
    }
    // `sonnet` is strict, the lane is on `haiku`: the redirect lacks everything and still goes.
    let (h, packet) = redirect_on_profiled_rung(PROFILE_CONFIG, |text| {
        text.replace(PROFILE_TESTS, "")
            .replace(PROFILE_MUTATIONS, "")
            .replace("Change the README.", "Change the README, then stop.")
    });
    let mut child = start(&h);
    let id = wait_for_ask(&h, &mut child, 1);
    rule(&h, &id, &["--redirect", packet.to_str().unwrap()]);
    let out = finish(child);
    assert_eq!(out.status.code(), Some(0), "{}", stdout_of(&out));
    assert_eq!(h.launches(), 2);
    assert_eq!(queue_events(&h, "delivered").len(), 1);
    let segs = segments(&h);
    assert_eq!(segs[0]["profile"], Value::Null);
    assert_eq!(segs[1]["profile"], Value::Null);
}

/// Two rungs, the lane starts on `alpha`. `strict` needs tests and mutations.
const ALPHA_NONE_BETA_STRICT: &str = REASSIGN_PROFILE_CONFIG;
const ALPHA_STRICT_BETA_NONE: &str = "[ladder]\nrungs = [\"claude:alpha\", \"claude:beta\"]\n\n\
[profiles.strict]\nrequire = [\"tests\", \"mutations\"]\n\n\
[routing.profiles]\n\"claude:alpha\" = \"strict\"\n";

#[test]
fn a_redirect_after_a_reassign_is_checked_against_the_profile_of_the_rung_it_landed_on() {
    if !sandbox_available() {
        return;
    }
    // Starts on `alpha` (no profile), is reassigned onto `beta` (strict; the packet meets it,
    // or the reassign itself would be refused), then is redirected to a packet without
    // mutations: the profile that counts is `beta`'s, not the start rung's.
    let (h, packet) = redirect_after(
        &asks_until(2, &then_checks()),
        ALPHA_NONE_BETA_STRICT,
        |text| {
            text.replace(PROFILE_MUTATIONS, "")
                .replace("Change the README.", "Change the README, then stop.")
        },
    );
    let mut child = start(&h);
    let first = wait_for_ask(&h, &mut child, 1);
    rule(&h, &first, &["--reassign"]);
    let second = wait_for_ask(&h, &mut child, 2);
    rule(&h, &second, &["--redirect", packet.to_str().unwrap()]);
    let out = finish(child);
    assert_eq!(out.status.code(), Some(1), "{}", stdout_of(&out));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("redirect for"), "{stderr}");
    assert!(stderr.contains("claude:beta"), "{stderr}");
    assert!(stderr.contains("profile \"strict\""), "{stderr}");
    assert!(stderr.contains("mutations: add"), "{stderr}");
    assert_eq!(h.launches(), 2, "no session starts on the redirect");
    let run = h.run_json();
    assert_eq!(run["status"], "failed", "{run}");
    assert!(
        run["error"]
            .as_str()
            .unwrap()
            .contains("profile \"strict\""),
        "{run}"
    );
    assert_eq!(queue_events(&h, "delivered").len(), 1, "the reassign only");
    let segs = segments(&h);
    assert_eq!(segs.len(), 2);
    assert_eq!(segs[0]["profile"], Value::Null);
    assert_eq!(segs[1]["profile"]["rung"], "claude:beta");
}

#[test]
fn a_redirect_after_a_reassign_off_a_strict_rung_is_not_held_to_the_start_rungs_profile() {
    if !sandbox_available() {
        return;
    }
    // Starts on `alpha` (strict; the packet meets it), is reassigned onto `beta` (no profile),
    // then is redirected to a packet without mutations: `beta` asks for nothing.
    let (h, packet) = redirect_after(
        &asks_until(2, &then_checks()),
        ALPHA_STRICT_BETA_NONE,
        |text| {
            text.replace(PROFILE_MUTATIONS, "")
                .replace("Change the README.", "Change the README, then stop.")
        },
    );
    let mut child = start(&h);
    let first = wait_for_ask(&h, &mut child, 1);
    rule(&h, &first, &["--reassign"]);
    let second = wait_for_ask(&h, &mut child, 2);
    rule(&h, &second, &["--redirect", packet.to_str().unwrap()]);
    let out = finish(child);
    assert_eq!(out.status.code(), Some(0), "{}", stdout_of(&out));
    assert_eq!(h.launches(), 3);
    assert_eq!(h.seg(3, "model"), "beta");
    assert_eq!(queue_events(&h, "delivered").len(), 2);
    let segs = segments(&h);
    assert_eq!(segs[0]["profile"]["met"], true);
    assert_eq!(segs[1]["profile"], Value::Null);
    assert_eq!(segs[2]["profile"], Value::Null);
}

// ----------------------------------------------------------------------------------------
// Trace totals (D5, D23): the usage monitor's per-lane sums, in run.json and the capsule.
// ----------------------------------------------------------------------------------------

/// Shell for a fake that fires `pk hook post-tool-use` for each `(tool, input, output length)`.
fn hooks(calls: &[(&str, Value, usize)]) -> String {
    calls
        .iter()
        .map(|(tool, input, len)| {
            let payload = json!({
                "session_id": "s1",
                "hook_event_name": "PostToolUse",
                "tool_name": tool,
                "tool_input": input,
                "tool_output": "x".repeat(*len),
            });
            format!("printf '%s' '{payload}' | \"$(dirname \"$cp_bin\")/pk\" hook post-tool-use\n")
        })
        .collect()
}

/// An earlier trace file of the same lane (named to sort before today's) with one record and
/// one line that is not a record. The totals must add both files up.
const EARLIER_TRACE: &str = r#"mkdir -p "$PORTKIT_STATE_DIR/traces"
printf '%s\n%s\n' '{"tool":"Read","surface":"agent","outcome":"ok","at":"1999-01-01T00:00:00Z","duration_ms":0.0,"input_bytes":1,"produced_bytes":1000,"delivered_bytes":1000,"target":"old.md"}' 'not a record' > "$PORTKIT_STATE_DIR/traces/1999-01-01-earlier.jsonl"
"#;

#[test]
fn a_traced_lane_records_exact_trace_totals_in_run_json_and_the_capsule() {
    if !sandbox_available() {
        return;
    }
    let body = format!(
        "{EARLIER_TRACE}{}{}",
        hooks(&[
            ("Read", json!({"file_path": "a.md"}), 10),
            ("Read", json!({"file_path": "b.md"}), 25),
            ("Bash", json!({"command": "cargo test --all"}), 100),
            (
                "Bash",
                json!({"command": "pk-read src/lib.rs --range 1:5"}),
                7
            ),
            ("Bash", json!({"command": "pk-read src/lib.rs"}), 3),
        ]),
        run_checks(&["edit", "made"])
    );
    let h = owned_packet(&body);
    h.run_expecting(0);
    assert_eq!(h.verdict()["verdict"], "proved");
    assert_eq!(h.run_json()["trace"]["traced"], true);

    // Six records over two files: the earlier file's Read (1000) and the five hooks.
    let expected = json!({
        "calls": 6,
        "deliveredBytes": 1145,
        "producedBytes": 1145,
        "byTool": {
            "Bash": {"calls": 3, "deliveredBytes": 110},
            "Read": {"calls": 3, "deliveredBytes": 1035},
        },
        "pkRead": {"calls": 2, "deliveredBytes": 10},
        "malformedLines": 1,
    });
    assert_eq!(h.run_json()["traceTotals"], expected);
    let raw: Value = serde_json::from_str(&h.read("control/capsule/capsule.json")).unwrap();
    assert_eq!(raw["trace_totals"], expected);
    let capsule = Capsule::read(&h.lane().join("control/capsule")).unwrap();
    assert_eq!(
        serde_json::to_value(capsule.trace_totals.as_ref().unwrap()).unwrap(),
        expected
    );
}

#[test]
fn an_untraced_lane_records_no_trace_totals_and_is_still_proved() {
    if !sandbox_available() {
        return;
    }
    let h = owned_packet(&run_checks(&["edit", "made"]));
    h.run_expecting(0);
    assert_eq!(h.verdict()["verdict"], "proved");
    let run = h.run_json();
    assert_eq!(run["trace"]["traced"], false, "{run}");
    assert!(run.get("traceTotals").is_some_and(Value::is_null), "{run}");
    let raw: Value = serde_json::from_str(&h.read("control/capsule/capsule.json")).unwrap();
    assert!(raw.get("trace_totals").is_some_and(Value::is_null), "{raw}");
    let capsule = Capsule::read(&h.lane().join("control/capsule")).unwrap();
    assert_eq!(capsule.trace_totals, None);
}

// ---- `run_check` commands run in their own process group ---------------------
//
// A check is its own group leader, so a terminal Ctrl-C does not reach it and the runner ends
// it itself: on the check's timeout (`host_agent.rs` tests the shared code with a one-second
// limit), when the builder is gone (a stop ruling), and on SIGINT or SIGTERM. The check below
// leaves a background subshell that writes a marker after 14 s and records its pid; a check
// that was not ended as a group lets the marker appear.

/// The check leaves a background subshell that appends to `scratch/beat` twice a second and
/// records its pid. A check that was not ended as a group lets it beat on after the lane's end.
const BG_CHECK: &str = "( while :; do echo . >> ../scratch/beat; sleep 0.5; done ) & echo $! > ../scratch/bgpid; sleep 300";

fn bg_check_harness(fake_body: &str) -> Harness {
    Harness::with_packet(
        fake_body,
        json!(["README.md", "created.txt"]),
        json!([{"id": "bg", "command": BG_CHECK}]),
    )
}

/// Shell: start `run_check bg` in the background (it blocks for 300 s) and wait until the
/// check has recorded its background pid and the subshell has beaten once.
fn start_bg_check() -> String {
    format!(
        "( {} ) &\nwhile [ ! -e \"$(dirname \"$HOME\")/scratch/bgpid\" ] || [ ! -e \"$(dirname \"$HOME\")/scratch/beat\" ]; do sleep 0.25; done\n",
        mcp_session("bg.out", &[(3, "run_check", json!({"id": "bg"}))])
    )
}

/// The check's background subshell is gone: by pid where the sandbox shares the host's pid
/// space (macOS), and by effect everywhere (it stops beating). `settle` is how long it may
/// take, zero where the run has already ended.
fn assert_bg_check_ended(h: &Harness, settle: Duration) {
    if cfg!(target_os = "macos") {
        assert_pid_gone(
            fs::read_to_string(h.lane().join("scratch/bgpid"))
                .unwrap()
                .trim(),
        );
    }
    assert_heartbeat_stopped(
        &h.lane().join("scratch/beat"),
        settle,
        "the check's background process",
    );
}

fn a_signal_ends_a_running_check_group(signal: &str) {
    let h = bg_check_harness(&format!("{}{}sleep 120\n", init_line(), start_bg_check()));
    let mut run = start_watched(&h, &[]);
    wait_for_file(&mut run, &h.lane().join("scratch/bgpid"));
    send_signal(signal, &run.child);
    let status = exit_within(&mut run, INTERRUPT_EXIT_WITHIN);
    assert_interrupted_cleanly(&h, status, &run);
    assert_bg_check_ended(&h, Duration::ZERO);
}

#[test]
fn sigint_ends_a_running_checks_whole_group() {
    if !sandbox_available() {
        return;
    }
    a_signal_ends_a_running_check_group("INT");
}

#[test]
fn sigterm_ends_a_running_checks_whole_group() {
    if !sandbox_available() {
        return;
    }
    a_signal_ends_a_running_check_group("TERM");
}

#[test]
fn a_stop_ruling_ends_the_check_the_parked_builder_left_running() {
    if !sandbox_available() {
        return;
    }
    let ask = mcp_session("ask.out", &[(4, "ask", blocking_ask("Quit?"))]);
    let h = bg_check_harness(&format!(
        "{}{}{ask}sleep 120\n",
        init_line(),
        start_bg_check()
    ));
    let mut child = start(&h);
    let id = wait_for_ask(&h, &mut child, 1);
    rule(&h, &id, &["--stop"]);
    let out = finish(child);
    assert_eq!(
        out.status.code(),
        Some(7),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(h.run_json()["status"], "stopped");
    assert_bg_check_ended(&h, Duration::ZERO);
}

#[test]
fn a_check_is_ended_when_the_builder_exits_and_the_lane_parks_before_any_ruling() {
    if !sandbox_available() {
        return;
    }
    let ask = mcp_session("ask.out", &[(4, "ask", blocking_ask("Which way?"))]);
    let h = bg_check_harness(&format!(
        "{}{}{ask}sleep 120\n",
        init_line(),
        start_bg_check()
    ));
    let mut run = start_watched(&h, &[]);
    wait_for_file(&mut run, &h.lane().join("scratch/bgpid"));
    // The ask parks the session: the runner ends the builder and waits for a ruling. Nothing
    // is ruled here, so only the builder's exit can end the check it left running.
    run.wait_for_stderr(WAITING, SESSION_END_WITHIN);
    assert_eq!(h.launches(), 1);
    // The lane is still parked, no ruling given, when the check must be gone. The runner ends
    // the group in the background (SIGTERM, then SIGKILL after `CHECK_TERM_GRACE`), so it
    // may take that long, and a loaded host some more.
    assert_bg_check_ended(&h, check_term_grace() + Duration::from_secs(10));
    assert!(
        run.child.try_wait().unwrap().is_none(),
        "the run ended by itself while parked:\n{}",
        run.stderr()
    );
    // Release the parked lane.
    let id = wait_for_ask(&h, &mut run.child, 1);
    rule(&h, &id, &["--stop"]);
    // Only a hang guard: the exit after a stop also waits for the patch and `pk doctor`, which
    // took longer than the 20 s of `SESSION_END_WITHIN` once in a full run on a busy host. The
    // property of this test (the check is gone while the lane is still parked) was asserted
    // above.
    let status = exit_within(&mut run, RULED_WITHIN);
    assert_eq!(status.code(), Some(7), "{}", run.stderr());
}

// ---- A signal in the proof ends the run gracefully ---------------------------
//
// Past the builder the runner captures the patch and proves the lane. A signal there used to
// end the process at once, with no record: a check the verifier was running kept going, and
// `run.json` was the finished one or absent. Now the verifier's check groups are listed in
// the runner's `GroupSet`, so the signal ends exactly those (SIGTERM, a grace, SIGKILL), and
// `run.json` says `interrupted` with the phase, whatever the checks came to.
//
// The check passes at once when the builder runs it, and is a hold in the verifier, told
// apart by its `TMPDIR` (`scratch/tmp` for the builder, `scratch/verify/tmp` for the
// verifier). The hold keeps a background heartbeat in the verifier's temp directory and
// records its pid there, so the test knows the proof is in the check.

/// What the hold does when the verifier's check is sent SIGTERM: `exit 0` after leaving a
/// marker (the check would then agree with the builder's recorded pass, which is how a
/// signalled proof could come out `proved`), or nothing at all (`trap '' TERM`).
fn proof_hold_check(on_term: &str) -> String {
    format!(
        "case \"$TMPDIR\" in */verify/tmp) {on_term}; \
         ( while :; do echo . >> \"$TMPDIR/beat\"; sleep 0.5; done ) & \
         echo $! > \"$TMPDIR/bgpid\"; \
         while :; do sleep 1 & wait $!; done ;; *) true ;; esac"
    )
}

/// The check, once it has been sent SIGTERM, leaves a marker and exits 0: the verifier would
/// call that a pass, and it matches the builder's recorded one.
const TERM_EXITS_ZERO: &str = "trap 'echo termed > \"$TMPDIR/termed\"; exit 0' TERM";

fn proof_harness(on_term: &str) -> Harness {
    Harness::with_packet(
        &run_checks(&["hold"]),
        json!(["README.md", "created.txt"]),
        json!([{"id": "hold", "command": proof_hold_check(on_term)}]),
    )
}

/// The verifier's temp directory, where the hold keeps its files.
fn proof_tmp(h: &Harness) -> PathBuf {
    h.lane().join("scratch/verify/tmp")
}

/// What a run signalled in the proof must leave, whatever the check did: exit 130, `run.json`
/// `interrupted` in the `proof` phase, whole (no temporary file beside it), no verdict, no
/// socket.
fn assert_interrupted_in_the_proof(
    h: &Harness,
    status: std::process::ExitStatus,
    run: &Watched,
    signal_name: &str,
) {
    assert_eq!(status.code(), Some(130), "{}", run.stderr());
    let run_json = h.run_json();
    assert_eq!(run_json["status"], "interrupted", "{run_json}");
    assert_eq!(run_json["phase"], "proof", "{run_json}");
    assert_eq!(run_json["signal"], signal_name, "{run_json}");
    assert_eq!(run_json["exitCode"], 130, "{run_json}");
    assert!(
        !h.lane().join("control/run.json.tmp").exists(),
        "a temporary run.json is left behind"
    );
    assert!(
        !h.lane().join("control/verdict.json").exists(),
        "a lane signalled in the proof has a verdict: {}",
        h.read("control/verdict.json")
    );
    for socket in lane_sockets(h) {
        assert!(
            std::fs::symlink_metadata(&socket).is_err(),
            "{} still exists",
            socket.display()
        );
    }
}

fn a_signal_in_the_proof_ends_the_verifiers_check_gracefully(signal: &str) {
    let h = proof_harness(TERM_EXITS_ZERO);
    let mut run = start_watched(&h, &[]);
    wait_for_file(&mut run, &proof_tmp(&h).join("bgpid"));
    // The builder's own run of the check passed, so the proof is what is running.
    assert!(passed(&h, 3), "the builder's run of the hold must pass");
    assert!(
        !h.lane().join("control/verdict.json").exists(),
        "the proof is still in its check"
    );

    let signalled = Instant::now();
    send_signal(signal, &run.child);
    let status = exit_within(&mut run, INTERRUPT_EXIT_WITHIN);
    let took = signalled.elapsed();
    assert_interrupted_in_the_proof(
        &h,
        status,
        &run,
        if signal == "INT" { "SIGINT" } else { "SIGTERM" },
    );
    if cfg!(target_os = "linux") {
        // On Linux the group the runner signals is bubblewrap's (`--die-with-parent`,
        // `--unshare-pid`): SIGTERM ends bubblewrap and the kernel kills the sandbox's
        // processes with it, so the check never sees SIGTERM and no marker is left. What
        // holds is that it is gone at once, well inside the grace.
        assert!(
            took < check_term_grace() * 3 / 4,
            "the check was not gone promptly: exit {took:?} after the signal:\n{}",
            run.stderr()
        );
    } else {
        // The check was sent SIGTERM before it was killed (a SIGKILL leaves no marker), and
        // its clean exit did not make the lane proved.
        assert_eq!(
            fs::read_to_string(proof_tmp(&h).join("termed")).unwrap_or_default(),
            "termed\n",
            "the check was killed without a SIGTERM first:\n{}",
            run.stderr()
        );
    }
    assert_heartbeat_stopped(
        &proof_tmp(&h).join("beat"),
        Duration::ZERO,
        "the verifier's check",
    );
    if cfg!(target_os = "macos") {
        assert_pid_gone(
            fs::read_to_string(proof_tmp(&h).join("bgpid"))
                .unwrap()
                .trim(),
        );
    }
    assert_eq!(h.launches(), 1, "an interrupted run never relaunches");
}

#[test]
fn sigint_in_the_proof_ends_the_verifiers_check_with_sigterm_and_records_interrupted() {
    if !sandbox_available() {
        return;
    }
    a_signal_in_the_proof_ends_the_verifiers_check_gracefully("INT");
}

#[test]
fn sigterm_in_the_proof_ends_the_verifiers_check_with_sigterm_and_records_interrupted() {
    if !sandbox_available() {
        return;
    }
    a_signal_in_the_proof_ends_the_verifiers_check_gracefully("TERM");
}

#[test]
fn a_verifier_check_that_ignores_sigterm_is_killed_after_the_grace() {
    if !sandbox_available() {
        return;
    }
    let h = proof_harness("trap '' TERM");
    let mut run = start_watched(&h, &[]);
    wait_for_file(&mut run, &proof_tmp(&h).join("bgpid"));

    let signalled = Instant::now();
    send_signal("INT", &run.child);
    let status = exit_within(&mut run, check_term_grace() + INTERRUPT_EXIT_WITHIN);
    let took = signalled.elapsed();
    assert_interrupted_in_the_proof(&h, status, &run, "SIGINT");
    if cfg!(target_os = "linux") {
        // SIGTERM ends bubblewrap and its sandbox with it (see the test above), so there is
        // no grace to wait out: the check is gone well inside it.
        assert!(
            took < check_term_grace() * 3 / 4,
            "the check was not gone promptly: exit {took:?} after the signal:\n{}",
            run.stderr()
        );
    } else {
        // The check ignores SIGTERM: it was given the grace, and only then killed.
        assert!(
            took >= check_term_grace(),
            "the check was killed after {took:?}, before its {:?} grace:\n{}",
            check_term_grace(),
            run.stderr()
        );
    }
    assert_heartbeat_stopped(
        &proof_tmp(&h).join("beat"),
        Duration::ZERO,
        "the verifier's check",
    );
}

#[test]
fn a_second_signal_in_the_proof_kills_the_check_at_once() {
    if !sandbox_available() {
        return;
    }
    // The check ignores SIGTERM, so the first signal alone takes `CHECK_TERM_GRACE` to become
    // a SIGKILL. The second must not wait for it: three quarters of the grace clears the
    // runner's teardown on a slow host and still fails a wait for the grace.
    let grace = check_term_grace();
    let bound = grace * 3 / 4;
    let h = proof_harness("trap '' TERM");
    let mut run = start_watched(&h, &[]);
    wait_for_file(&mut run, &proof_tmp(&h).join("bgpid"));

    send_signal("INT", &run.child);
    run.wait_for_stderr("in the proof phase: ending the run", INTERRUPT_EXIT_WITHIN);
    let second = Instant::now();
    send_signal("INT", &run.child);
    let status = exit_within(&mut run, grace + INTERRUPT_EXIT_WITHIN);
    let took = second.elapsed();
    assert!(
        took < bound,
        "the second signal waited for the check's grace: exit {took:?} after it, bound \
         {bound:?} of a {grace:?} grace:\n{}",
        run.stderr()
    );
    assert_interrupted_in_the_proof(&h, status, &run, "SIGINT");
    // On Linux the first signal has usually ended everything before the second is read, so
    // there may be no "again" line; the exit time above is what holds there.
    if cfg!(target_os = "macos") {
        assert!(
            run.stderr().contains("SIGINT again: not waiting"),
            "{}",
            run.stderr()
        );
    }
    assert_heartbeat_stopped(
        &proof_tmp(&h).join("beat"),
        Duration::ZERO,
        "the verifier's check",
    );
}
