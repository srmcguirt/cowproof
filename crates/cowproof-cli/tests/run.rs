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
        }

        let fake = work.path().join("fake-claude");
        let script = format!(
            r#"#!/bin/sh
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
            .env_remove("ANTHROPIC_API_KEY");
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
        assert!(
            matches!(out.status.code(), Some(0 | 2 | 3)),
            "cowproof run did not reach a verdict:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
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

const PARKED_WAIT: Duration = Duration::from_secs(60);

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
    assert_eq!(out.status.code(), Some(1));
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
    assert_eq!(out.status.code(), Some(1));
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

/// Poll `kill -0 <pid>` until the process is gone (ESRCH), at most 5 s.
fn assert_pid_gone(pid: &str) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let alive = output(Command::new("kill").args(["-0", pid]))
            .status
            .success();
        if !alive {
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
    assert_eq!(out.status.code(), Some(1), "{}", stdout_of(&out));
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

/// The ruling must take effect within this long of the director giving it,
/// against a builder that would otherwise sleep for two minutes.
const RULED_WITHIN: Duration = Duration::from_secs(15);

/// A fake that, on its first launch, records its pid, asks NON-blocking and
/// sleeps 120 s (in a background child, so the group has two members); later
/// launches run the checks.
fn nonblocking_sleeper(question: &str) -> String {
    let mut ask = blocking_ask(question);
    ask["blocking"] = json!(false);
    let first = format!(
        "{}echo $$ > \"$HOME/fakepid\"\n{}sleep 120 &\necho $! > \"$HOME/sleeppid\"\nwait\n",
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

/// Wait for the run to end, at most `RULED_WITHIN` after `ruled_at`. A run
/// that is still going is killed (by its pid), and so is the first builder's
/// process group (by the pid the fake recorded: it is the group leader), and
/// the test fails.
fn ends_within_of_the_ruling(h: &Harness, mut child: Child, ruled_at: Instant) -> Output {
    loop {
        if child.try_wait().unwrap().is_some() {
            return child.wait_with_output().unwrap();
        }
        if ruled_at.elapsed() > RULED_WITHIN {
            let _ = child.kill();
            let _ = child.wait();
            if let Ok(pid) = fs::read_to_string(h.lane().join("home/fakepid")) {
                let group = format!("-{}", pid.trim());
                let _ = Command::new("kill").args(["-KILL", "--", &group]).output();
            }
            panic!("the run was still going {RULED_WITHIN:?} after the ruling");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Wait until the fake's `n`th launch has begun, at most `RULED_WITHIN` after
/// `ruled_at`; a run that gets there late is killed (by pid) and fails.
fn second_segment_starts_within(h: &Harness, child: &mut Child, ruled_at: Instant) {
    while h.launches() < 2 {
        if ruled_at.elapsed() > RULED_WITHIN {
            let _ = child.kill();
            let _ = child.wait();
            if let Ok(pid) = fs::read_to_string(h.lane().join("home/fakepid")) {
                let group = format!("-{}", pid.trim());
                let _ = Command::new("kill").args(["-KILL", "--", &group]).output();
            }
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

#[test]
fn a_stop_on_a_non_blocking_ask_ends_the_live_session_and_the_lane() {
    if !sandbox_available() {
        return;
    }
    let h = owned_packet(&nonblocking_sleeper("Quit?"));
    let (child, id, ruled_at) = rule_the_moment_it_is_asked(&h, &["--stop"]);
    let out = ends_within_of_the_ruling(&h, child, ruled_at);
    assert_eq!(out.status.code(), Some(1), "{}", stdout_of(&out));
    assert_eq!(h.launches(), 1, "no second launch");
    assert_eq!(h.run_json()["status"], "stopped");
    assert_eq!(segments(&h).len(), 1);
    assert_first_builder_was_ruled_away(&h, &id);
    // The work is kept; the lane is not proved.
    assert!(h.read("control/lane.patch").contains("+edited"));
    assert!(!h.lane().join("control/verdict.json").exists());
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
    assert_eq!(out.status.code(), Some(1), "{}", stdout_of(&out));
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
    assert_eq!(out.status.code(), Some(1), "{}", stdout_of(&out));
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

/// `kill -<signal> <pid>` of a process this test started.
fn send_signal(signal: &str, child: &Child) {
    let out = output(Command::new("kill").args([&format!("-{signal}"), &child.id().to_string()]));
    assert!(
        out.status.success(),
        "kill -{signal}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Wait for the file the fake writes once its background child runs.
fn wait_for_file(run: &mut Watched, path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(30);
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

#[test]
fn a_second_signal_does_not_wait_out_a_builder_that_ignores_sigterm() {
    if !sandbox_available() {
        return;
    }
    // The leader ignores SIGTERM, so the first signal would take ten seconds to
    // become a SIGKILL. The second must not wait for them.
    let body = format!(
        "{}trap '' TERM\n( trap '' TERM; sleep 300 ) &\necho $! > \"$HOME/bgpid\"\nwhile true; do sleep 1; done\n",
        init_line()
    );
    let h = owned_packet(&body);
    let mut run = start_watched(&h, &[]);
    wait_for_file(&mut run, &h.lane().join("home/bgpid"));

    send_signal("INT", &run.child);
    run.wait_for_stderr("ending the builder", Duration::from_secs(10));
    let second = Instant::now();
    send_signal("INT", &run.child);
    let status = exit_within(&mut run, Duration::from_secs(5));
    assert!(
        second.elapsed() < Duration::from_secs(5),
        "the second signal waited for the SIGTERM grace"
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

#[test]
fn the_timeout_ends_a_silent_builder_and_a_child_that_ignores_sigterm_and_nothing_is_proved() {
    if !sandbox_available() {
        return;
    }
    // The builder says nothing and sleeps. A background child ignores SIGTERM
    // (only the group SIGKILL ends it) and would write a marker fourteen seconds in. The limit is eight seconds, wide enough for a
    // cold sandbox start on a loaded machine (the clock runs from the builder's spawn).
    let first = "( trap '' TERM; sleep 14; echo alive > \"$HOME/survived\" ) &\necho $! > \"$HOME/bgpid\"\nsleep 120\n";
    let h = owned_packet(first);
    let began = Instant::now();
    let child = {
        let _g = fork_lock();
        h.command(h.lanes.path())
            .args(["--timeout-secs", "8"])
            .env("ANTHROPIC_API_KEY", REAL_KEY)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
    };
    let out = finish(child);
    let took = began.elapsed();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(out.status.code(), Some(5), "{}\n{stderr}", stdout_of(&out));
    assert!(stderr.contains("wall-clock timeout"), "{stderr}");
    assert!(
        took < Duration::from_secs(45),
        "the 120 s sleep was cut short: {took:?}"
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
    assert_eq!(run["timeoutSecs"], 8);
    let segs = segments(&h);
    assert_eq!(segs.len(), 1, "no relaunch: {segs:?}");
    assert_eq!(h.launches(), 1);
    assert_eq!(segs[0]["sessionEnd"], "timeout", "{segs:?}");
    assert_eq!(segs[0]["killedByRunner"], true);
    assert_eq!(segs[0]["status"], "ended-by-runner");
    assert_eq!(segs[0]["signal"], 15, "SIGTERM ended the leader: {segs:?}");
    assert_not_proved(&h);

    // The stubborn child is gone: by pid where the sandbox shares the host's
    // pid space (macOS), and by effect everywhere (its marker would appear at
    // fourteen seconds into the builder, after the run has already ended).
    if cfg!(target_os = "macos") {
        assert_pid_gone(h.read("home/bgpid").trim());
    }
    std::thread::sleep(Duration::from_secs(8));
    assert!(
        !h.lane().join("home/survived").exists(),
        "a background child outlived the timeout and wrote its marker"
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

#[test]
fn time_parked_waiting_for_a_ruling_does_not_count_toward_the_timeout() {
    if !sandbox_available() {
        return;
    }
    // Eight seconds of wall clock in all. The builder parks on a blocking ask at
    // once, the director rules twelve seconds later (more than the whole limit),
    // and the resumed builder runs its checks. Only the time inside the two
    // launches counts, so the lane is proved.
    let h = owned_packet(&asks_first("Choose A or B?", true, &then_checks()));
    let mut child = {
        let _g = fork_lock();
        h.command(h.lanes.path())
            .args(["--timeout-secs", "8"])
            .env("ANTHROPIC_API_KEY", REAL_KEY)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
    };
    let id = wait_for_ask(&h, &mut child, 1);
    std::thread::sleep(Duration::from_secs(12));
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
    assert_eq!(json["timeoutSecs"], 8);
    let whole = json["durationMs"].as_u64().unwrap();
    let counted = json["activeMs"].as_u64().unwrap();
    assert!(
        whole >= 12_000,
        "the run included the twelve-second wait: {whole} ms"
    );
    assert!(counted < 8_000, "only launch time counts: {counted} ms");
    assert!(
        whole - counted >= 12_000,
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
