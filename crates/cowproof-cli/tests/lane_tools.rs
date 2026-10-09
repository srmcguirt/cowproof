//! `cowproof lane-tools` against a fake runner socket: the real binary, real
//! stdio, a real Unix socket. The fake server records every request line it
//! receives, so a test can tell what the client forwarded.

use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

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

/// Run `cowproof lane-tools` with the given JSON-RPC lines on stdin, close
/// stdin, and return every stdout line (each must be JSON) by response id.
fn run_client(socket: &Path, requests: &[Value]) -> Vec<Value> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_cowproof"))
        .args(["lane-tools", "--socket"])
        .arg(socket)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    for r in requests {
        writeln!(stdin, "{r}").unwrap();
    }
    drop(stdin);
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "client failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .map(|l| {
            let v: Value = serde_json::from_str(l)
                .unwrap_or_else(|e| panic!("stdout line is not JSON ({e}): {l:?}"));
            assert_eq!(v["jsonrpc"], "2.0", "not a JSON-RPC frame: {l}");
            v
        })
        .collect()
}

fn rpc(id: u64, method: &str, params: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params})
}

fn handshake() -> Vec<Value> {
    vec![
        rpc(
            1,
            "initialize",
            json!({"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}),
        ),
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        rpc(2, "tools/list", json!({})),
    ]
}

fn sample_ask() -> Value {
    json!({
        "kind": "design",
        "question": "which way?",
        "tried": ["read the docs"],
        "options": [{"id": "a", "summary": "first", "cost": "low"}],
        "recommend": "a",
        "blocking": false,
    })
}

#[test]
fn lists_exactly_three_tools_and_forwards_an_ask_to_the_socket() {
    let tmp = tempfile::tempdir().unwrap();
    let socket = tmp.path().join("runner.sock");
    let seen = fake_runner(
        &socket,
        json!({"ok": true, "id": "l1:E1", "status": "asked"}),
    );

    let mut requests = handshake();
    requests.push(rpc(
        3,
        "tools/call",
        json!({"name": "ask", "arguments": sample_ask()}),
    ));
    let frames = run_client(&socket, &requests);

    // initialize, tools/list and tools/call answered; the notification was not.
    assert_eq!(frames.len(), 3, "{frames:?}");
    assert_eq!(frames[0]["id"], 1);
    let mut names: Vec<&str> = frames[1]["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    names.sort();
    assert_eq!(names, ["ask", "check_ruling", "run_check"]);

    let call = &frames[2]["result"];
    assert_eq!(call["isError"], false, "{call}");
    assert_eq!(
        call["structuredContent"],
        json!({"id": "l1:E1", "status": "asked"})
    );
    assert_eq!(
        *seen.lock().unwrap(),
        [json!({"op": "ask", "ask": sample_ask()})]
    );
}

#[test]
fn check_ruling_and_run_check_forward_only_the_op_and_the_id() {
    let tmp = tempfile::tempdir().unwrap();
    let socket = tmp.path().join("runner.sock");
    let seen = fake_runner(
        &socket,
        json!({"ok": true, "status": "pending", "notes": []}),
    );

    let requests = [
        rpc(
            1,
            "tools/call",
            json!({"name": "check_ruling", "arguments": {"id": "l1:E1"}}),
        ),
        rpc(
            2,
            "tools/call",
            json!({"name": "run_check", "arguments": {"id": "unit"}}),
        ),
    ];
    let frames = run_client(&socket, &requests);

    assert_eq!(frames[0]["result"]["isError"], false, "{frames:?}");
    assert_eq!(frames[1]["result"]["isError"], false, "{frames:?}");
    assert_eq!(
        *seen.lock().unwrap(),
        [
            json!({"op": "check_ruling", "id": "l1:E1"}),
            json!({"op": "run_check", "id": "unit"}),
        ]
    );
}

#[test]
fn a_call_naming_a_lane_or_an_unknown_tool_never_reaches_the_socket() {
    let tmp = tempfile::tempdir().unwrap();
    let socket = tmp.path().join("runner.sock");
    let seen = fake_runner(&socket, json!({"ok": true}));

    let requests = [
        rpc(
            1,
            "tools/call",
            json!({"name": "check_ruling", "arguments": {"id": "x", "lane": "other"}}),
        ),
        rpc(
            2,
            "tools/call",
            json!({"name": "rule", "arguments": {"id": "x"}}),
        ),
    ];
    let frames = run_client(&socket, &requests);

    assert_eq!(frames[0]["result"]["isError"], true, "{frames:?}");
    assert!(frames[1].get("error").is_some(), "{frames:?}");
    assert!(seen.lock().unwrap().is_empty());
}

#[test]
fn a_refusal_from_the_runner_comes_back_as_a_tool_error() {
    let tmp = tempfile::tempdir().unwrap();
    let socket = tmp.path().join("runner.sock");
    fake_runner(&socket, json!({"ok": false, "error": "unknown check id"}));

    let frames = run_client(
        &socket,
        &[rpc(
            1,
            "tools/call",
            json!({"name": "run_check", "arguments": {"id": "nope"}}),
        )],
    );
    let result = &frames[0]["result"];
    assert_eq!(result["isError"], true, "{result}");
    assert!(
        result["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("unknown check id")
    );
}

#[test]
fn with_no_runner_listening_a_call_is_a_tool_error_and_stdout_stays_json() {
    let tmp = tempfile::tempdir().unwrap();
    let socket = tmp.path().join("missing.sock");
    let frames = run_client(
        &socket,
        &[rpc(
            1,
            "tools/call",
            json!({"name": "check_ruling", "arguments": {"id": "l1:E1"}}),
        )],
    );
    assert_eq!(frames[0]["result"]["isError"], true, "{frames:?}");
}
