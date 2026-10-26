//! CLI mirrors of the MCP tools (`ask`, `ruling`, `check`). The expected request
//! always comes from the MCP surface: the registered tool, called with the input a
//! model would send (a literal written to the tool's input schema), against one fake
//! runner. The CLI is then run with the flags that should mean the same thing,
//! against a second fake runner, and the two recorded requests must be equal.

#[allow(
    dead_code,
    reason = "this file needs only the signal helper of the shared module"
)]
mod common;

use common::signal_pid;
use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

/// A runner stand-in: answers every request line with `reply` and records it.
fn fake_runner(socket: &Path, reply: Value) -> Arc<Mutex<Vec<Value>>> {
    let listener = UnixListener::bind(socket).unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { return };
            let mut line = String::new();
            BufReader::new(&stream).read_line(&mut line).unwrap();
            log.lock()
                .unwrap()
                .push(serde_json::from_str(&line).unwrap());
            let mut out = &stream;
            writeln!(out, "{reply}").unwrap();
        }
    });
    seen
}

/// Get a test socket path in /var/tmp with a short name. Ensure it doesn't exist.
fn test_socket() -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let name = format!("cpm-{}-{}.sock", std::process::id(), n);
    let path = PathBuf::from("/var/tmp").join(name);
    let _ = std::fs::remove_file(&path); // Clean up if it exists
    path
}

/// Wait for `child` to exit and collect its output, killing it (by pid) and failing the
/// test if it has not finished within a minute.
fn wait_bounded(child: Child) -> Output {
    let pid = child.id();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(child.wait_with_output());
    });
    match rx.recv_timeout(Duration::from_secs(60)) {
        Ok(out) => out.unwrap(),
        Err(_) => {
            signal_pid("KILL", pid);
            panic!("process {pid} did not finish within 60 s");
        }
    }
}

/// Run a CLI command against `socket_path`, feeding `stdin_text` (stdin is closed
/// at once when `None`), and return its stdout, which must be JSON.
fn run_cli(args: &[&str], socket_path: &str, stdin_text: Option<&str>) -> Value {
    let mut child = Command::new(env!("CARGO_BIN_EXE_cowproof"))
        .args(args)
        .args(["--socket", socket_path])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    if let Some(text) = stdin_text {
        stdin.write_all(text.as_bytes()).unwrap();
    }
    drop(stdin);
    let out = wait_bounded(child);
    assert!(
        out.status.success(),
        "CLI command failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("stdout is not JSON ({e}): {stdout:?}"))
}

type Seen = Arc<Mutex<Vec<Value>>>;

/// The one request the MCP tool `name` sends for `input`, and the value it returns.
/// The tool comes from the registry of the real `lane_tools::server`, and the call
/// goes through `Registry::call`, which first checks `input` against the tool's
/// own input schema, so a literal that does not match the schema fails here.
async fn via_mcp_tool(name: &str, input: Value, reply: &Value) -> (Value, Value) {
    let socket = test_socket();
    let seen = fake_runner(&socket, reply.clone());
    let server = cowproof_cli::lane_tools::server(socket.clone());
    let tool = server
        .registry()
        .get(name)
        .unwrap_or_else(|| panic!("the server registers no tool named {name}"));
    assert_eq!(tool.spec().name, name);
    let output = tokio::time::timeout(Duration::from_secs(60), server.registry().call(name, input))
        .await
        .unwrap_or_else(|_| panic!("tool {name} did not answer within 60 s"))
        .unwrap_or_else(|e| panic!("tool {name} failed: {e}"));
    let request = only_request(&seen);
    let _ = std::fs::remove_file(&socket);
    (request, output)
}

/// The one request the `cowproof` command line sends, and what it printed.
fn via_cli(args: &[&str], stdin: Option<&str>, reply: &Value) -> (Value, Value) {
    let socket = test_socket();
    let seen = fake_runner(&socket, reply.clone());
    let socket_str = socket.to_string_lossy();
    let printed = run_cli(args, &socket_str, stdin);
    let request = only_request(&seen);
    let _ = std::fs::remove_file(&socket);
    (request, printed)
}

fn only_request(seen: &Seen) -> Value {
    let requests = seen.lock().unwrap();
    assert_eq!(requests.len(), 1, "{requests:?}");
    requests[0].clone()
}

/// The MCP tool and the CLI send equal requests and show equal output.
async fn assert_mirrored(
    tool: &str,
    mcp_input: Value,
    cli_args: &[&str],
    cli_stdin: Option<&str>,
    reply: Value,
) -> Value {
    let (mcp_request, mcp_output) = via_mcp_tool(tool, mcp_input, &reply).await;
    let (cli_request, cli_output) = via_cli(cli_args, cli_stdin, &reply);
    assert_eq!(cli_request, mcp_request, "request for {cli_args:?}");
    assert_eq!(cli_output, mcp_output, "output for {cli_args:?}");
    assert_eq!(mcp_request["op"], tool);
    mcp_request
}

fn ask_reply() -> Value {
    json!({"ok": true, "id": "l1:E1", "status": "asked"})
}

#[tokio::test]
async fn ask_without_blocking_mirrors_the_mcp_tool() {
    let request = assert_mirrored(
        "ask",
        json!({
            "kind": "design",
            "question": "which way?",
            "tried": ["read the docs", "ran the test: it failed on the second call"],
            "options": [
                {"id": "a", "summary": "first", "cost": "low"},
                {"id": "b", "summary": "second", "cost": "high"},
                {"id": "c", "summary": "third", "cost": "medium: about a day"}
            ],
            "recommend": "b",
            "blocking": false,
        }),
        &[
            "ask",
            "--kind",
            "design",
            "--question",
            "which way?",
            "--tried",
            "read the docs",
            "--tried",
            "ran the test: it failed on the second call",
            "--option",
            "a:first:low",
            "--option",
            "b:second:high",
            "--option",
            "c:third:medium: about a day",
            "--recommend",
            "b",
        ],
        None,
        ask_reply(),
    )
    .await;
    // Guard against a vacuous pass: the request carries the content.
    assert_eq!(request["ask"]["options"][2]["cost"], "medium: about a day");
    assert_eq!(request["ask"]["blocking"], false);
}

#[tokio::test]
async fn ask_with_blocking_mirrors_the_mcp_tool() {
    let request = assert_mirrored(
        "ask",
        json!({
            "kind": "blocker",
            "question": "the check never passes",
            "tried": ["rewrote the helper"],
            "options": [
                {"id": "x", "summary": "relax the check", "cost": "needs a ruling"},
                {"id": "y", "summary": "stop", "cost": "lane ends"}
            ],
            "recommend": "x",
            "blocking": true,
        }),
        &[
            "ask",
            "--kind",
            "blocker",
            "--question",
            "the check never passes",
            "--tried",
            "rewrote the helper",
            "--option",
            "x:relax the check:needs a ruling",
            "--option",
            "y:stop:lane ends",
            "--recommend",
            "x",
            "--blocking",
        ],
        None,
        ask_reply(),
    )
    .await;
    assert_eq!(request["ask"]["blocking"], true);
}

#[tokio::test]
async fn ask_with_no_tried_and_no_options_sends_empty_arrays() {
    assert_mirrored(
        "ask",
        json!({
            "kind": "environment",
            "question": "no network",
            "tried": [],
            "options": [],
            "recommend": "",
            "blocking": false,
        }),
        &[
            "ask",
            "--kind",
            "environment",
            "--question",
            "no network",
            "--recommend",
            "",
        ],
        None,
        ask_reply(),
    )
    .await;
}

#[tokio::test]
async fn ask_reads_the_question_from_stdin_with_a_dash() {
    assert_mirrored(
        "ask",
        json!({
            "kind": "scope",
            "question": "line one\nline two\n",
            "tried": ["tried this"],
            "options": [{"id": "x", "summary": "fix", "cost": "medium"}],
            "recommend": "x",
            "blocking": true,
        }),
        &[
            "ask",
            "--kind",
            "scope",
            "--question",
            "-",
            "--tried",
            "tried this",
            "--option",
            "x:fix:medium",
            "--recommend",
            "x",
            "--blocking",
        ],
        Some("line one\nline two\n"),
        ask_reply(),
    )
    .await;
}

#[tokio::test]
async fn ruling_with_an_id_mirrors_the_mcp_tool() {
    let request = assert_mirrored(
        "check_ruling",
        json!({"id": "l1:E1"}),
        &["ruling", "l1:E1"],
        None,
        json!({"ok": true, "status": "pending", "notes": []}),
    )
    .await;
    assert_eq!(request, json!({"op": "check_ruling", "id": "l1:E1"}));
}

#[tokio::test]
async fn ruling_without_an_id_mirrors_the_mcp_tool() {
    let request = assert_mirrored(
        "check_ruling",
        json!({}),
        &["ruling"],
        None,
        json!({"ok": true, "notes": [{"text": "important", "at_ms": 1234567890}]}),
    )
    .await;
    assert_eq!(request, json!({"op": "check_ruling"}));
}

#[tokio::test]
async fn check_mirrors_the_mcp_tool() {
    let request = assert_mirrored(
        "run_check",
        json!({"id": "unit"}),
        &["check", "unit"],
        None,
        json!({"ok": true, "exit_status": 0, "attempts": 1}),
    )
    .await;
    assert_eq!(request, json!({"op": "run_check", "id": "unit"}));
}

/// Send `tools/call` for `ask` through the real `cowproof lane-tools` stdio server
/// (initialize, then the call) and return the one request it forwarded.
fn via_mcp_stdio_ask(input: &Value, reply: &Value) -> (Value, Value) {
    let socket = test_socket();
    let seen = fake_runner(&socket, reply.clone());
    let frames = [
        json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "t", "version": "0"}}}),
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
               "params": {"name": "ask", "arguments": input}}),
    ];
    let mut child = Command::new(env!("CARGO_BIN_EXE_cowproof"))
        .args(["lane-tools", "--socket"])
        .arg(&socket)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    for frame in &frames {
        writeln!(stdin, "{frame}").unwrap();
    }
    drop(stdin);
    let out = wait_bounded(child);
    assert!(
        out.status.success(),
        "lane-tools failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    let call = stdout
        .lines()
        .map(|l| serde_json::from_str::<Value>(l).unwrap())
        .find(|v| v["id"] == 2)
        .unwrap_or_else(|| panic!("no tools/call answer in {stdout:?}"));
    assert_eq!(call["result"]["isError"], false, "{call}");
    let request = only_request(&seen);
    let _ = std::fs::remove_file(&socket);
    (request, call["result"]["structuredContent"].clone())
}

#[test]
fn ask_over_the_mcp_stdio_protocol_and_the_cli_send_the_same_request() {
    let input = json!({
        "kind": "design",
        "question": "which way?",
        "tried": ["read the docs", "ran the test"],
        "options": [
            {"id": "a", "summary": "first", "cost": "low"},
            {"id": "b", "summary": "second", "cost": "high"}
        ],
        "recommend": "a",
        "blocking": true,
    });
    let reply = ask_reply();
    let (mcp_request, mcp_output) = via_mcp_stdio_ask(&input, &reply);
    let (cli_request, cli_output) = via_cli(
        &[
            "ask",
            "--kind",
            "design",
            "--question",
            "which way?",
            "--tried",
            "read the docs",
            "--tried",
            "ran the test",
            "--option",
            "a:first:low",
            "--option",
            "b:second:high",
            "--recommend",
            "a",
            "--blocking",
        ],
        None,
        &reply,
    );
    assert_eq!(mcp_request["ask"], input);
    assert_eq!(cli_request, mcp_request);
    assert_eq!(cli_output, mcp_output);
}

#[test]
fn the_socket_comes_from_the_environment_when_no_flag_is_given() {
    let socket = test_socket();
    let seen = fake_runner(&socket, json!({"ok": true, "notes": []}));
    let child = Command::new(env!("CARGO_BIN_EXE_cowproof"))
        .args(["ruling", "l1:E1"])
        .env("COWPROOF_RUNNER_SOCKET", &socket)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let out = wait_bounded(child);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        only_request(&seen),
        json!({"op": "check_ruling", "id": "l1:E1"})
    );
    let _ = std::fs::remove_file(&socket);
}

#[test]
fn missing_socket_gives_a_clear_error() {
    let child = Command::new(env!("CARGO_BIN_EXE_cowproof"))
        .args(["check", "unit"])
        .env_remove("COWPROOF_RUNNER_SOCKET")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let out = wait_bounded(child);
    assert!(!out.status.success());

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("COWPROOF_RUNNER_SOCKET"),
        "error message should mention env var: {stderr}"
    );
    assert!(
        stderr.contains("--socket"),
        "error message should mention flag: {stderr}"
    );
}

#[test]
fn a_refusal_from_the_runner_fails_the_command_with_the_reason() {
    let socket = test_socket();
    let seen = fake_runner(&socket, json!({"ok": false, "error": "unknown check id"}));
    let child = Command::new(env!("CARGO_BIN_EXE_cowproof"))
        .args(["check", "nope", "--socket"])
        .arg(&socket)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let out = wait_bounded(child);
    assert_eq!(
        only_request(&seen),
        json!({"op": "run_check", "id": "nope"})
    );
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
    assert!(String::from_utf8_lossy(&out.stderr).contains("unknown check id"));
    let _ = std::fs::remove_file(&socket);
}

#[test]
fn cli_prints_the_runner_response_without_the_ok_field() {
    let socket = test_socket();
    let socket_str = socket.to_string_lossy();
    let _seen = fake_runner(
        &socket,
        json!({
            "ok": true,
            "id": "l1:E1",
            "status": "parked",
            "notes": [{"text": "important", "at_ms": 1234567890}]
        }),
    );
    let output = run_cli(&["ruling", "l1:E1"], &socket_str, None);
    assert_eq!(
        output,
        json!({
            "id": "l1:E1",
            "status": "parked",
            "notes": [{"text": "important", "at_ms": 1234567890}]
        })
    );
    let _ = std::fs::remove_file(&socket);
}
