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

use cowproof_run::prefix::PREAMBLE;
use serde_json::{Value, json};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::Mutex;
use tempfile::TempDir;

const REAL_KEY: &str = "sk-test-real-xyz";
/// Another secret in the director's environment. Only an explicit builder
/// environment keeps it out: the placeholder overrides the key variable
/// either way, so the key alone cannot show whether the environment was
/// inherited.
const DIRECTOR_CANARY: &str = "canary-director-env-77";
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

struct Harness {
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
        let work = var_tmp("cp-run-work-");
        let lanes = var_tmp("cp-run-lanes-");
        let repo = work.path().join("repo");
        fs::create_dir(&repo).unwrap();
        git(&repo, &["init", "-q"]);
        git(&repo, &["config", "user.email", "t@example.com"]);
        git(&repo, &["config", "user.name", "T"]);
        fs::write(repo.join("README.md"), "base\n").unwrap();
        // Removed from the clone at launch (R15): it must never show up in
        // the lane patch, as a deletion or otherwise.
        fs::write(repo.join(".env"), "SECRET=launch-baseline-only\n").unwrap();
        git(&repo, &["add", "."]);
        git(&repo, &["commit", "-q", "-m", "base"]);

        let packet_text = format!(
            "# Task\n\n<!-- lane {} -->\n\nChange the README.\n",
            json!({
                "id": "t-run",
                "owns": ["README.md"],
                "class": "light",
                "checks": [
                    {"id": "ok", "command": "echo check-ran"},
                    {"id": "denied", "command": "cat ../control/builder.stderr"},
                    {"id": "slow", "command": "echo start >> ../scratch/trace; sleep 1; echo end >> ../scratch/trace"},
                ],
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
mkdir "$rec"
env | sort > "$rec/env.txt"
i=0
for a in "$@"; do printf '%s' "$a" > "$rec/arg.$i"; i=$((i+1)); done
echo "$i" > "$rec/argc"
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
            work,
            lanes,
            repo,
            packet,
            packet_text,
            fake,
            cowproof,
        }
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

    /// Run the whole flow with the real key set, expecting success.
    fn run_ok(&self) -> Output {
        let out = output(
            self.command(self.lanes.path())
                .env("ANTHROPIC_API_KEY", REAL_KEY)
                .env("DIRECTOR_ONLY_SECRET", DIRECTOR_CANARY),
        );
        assert!(
            out.status.success(),
            "cowproof run failed:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        out
    }

    fn lane(&self) -> PathBuf {
        self.lanes.path().canonicalize().unwrap().join("t-run")
    }

    fn read(&self, rel: &str) -> String {
        let p = self.lane().join(rel);
        fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
    }

    fn run_json(&self) -> Value {
        serde_json::from_str(&self.read("control/run.json")).unwrap()
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
    // One summary line on stdout, nothing else.
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert_eq!(stdout.lines().count(), 1, "{stdout:?}");
    assert!(
        stdout.starts_with("t-run: finished, exit 0, 2 turns"),
        "{stdout}"
    );
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
    assert!(!patch.contains("launch-baseline-only"), "{patch}");
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
    assert!(queue.contains("t-run"), "{queue}");
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
