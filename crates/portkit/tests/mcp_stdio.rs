//! A real handshake against `pk serve` over stdio.
//!
//! The protocol tests in `portkit-mcp` exercise dispatch in-process. This one
//! spawns the actual binary and speaks to its pipes, which is the only way to
//! catch transport-level faults — an unflushed stdout, or a log line written
//! to the protocol channel.

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

use serde_json::{json, Value};

/// Spawn `pk serve`, send each request, and collect one response per line.
fn handshake(requests: &[Value]) -> Vec<Value> {
    let mut child = Command::new(assert_cmd::cargo::cargo_bin("pk"))
        .arg("serve")
        // Force logging on: if any of it reaches stdout, the responses stop
        // parsing and this test fails, which is exactly what we want it to catch.
        .env("RUST_LOG", "debug")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("pk serve must start");

    {
        let stdin = child.stdin.as_mut().expect("stdin");
        for request in requests {
            writeln!(stdin, "{request}").expect("write request");
        }
    }
    // Drop stdin to signal EOF so the server exits rather than blocking.
    drop(child.stdin.take());

    let stdout = child.stdout.take().expect("stdout");
    let responses: Vec<Value> = BufReader::new(stdout)
        .lines()
        .map(|line| {
            let line = line.expect("read line");
            serde_json::from_str(&line)
                .unwrap_or_else(|e| panic!("stdout must carry only JSON frames, got {line:?}: {e}"))
        })
        .collect();

    child.wait().expect("pk serve must exit cleanly");
    responses
}

#[test]
fn a_client_can_initialize_list_and_call_over_stdio() {
    let responses = handshake(&[
        json!({"jsonrpc": "2.0", "id": 1, "method": "initialize",
               "params": {"protocolVersion": "2025-06-18",
                          "capabilities": {},
                          "clientInfo": {"name": "test", "version": "1.0"}}}),
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
        json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
               "params": {"name": "word_frequency",
                          "arguments": {"text": "a b a", "top_k": 1}}}),
    ]);

    // Four messages in, three out — the notification must go unanswered.
    assert_eq!(responses.len(), 3, "notifications must not be answered");

    assert_eq!(responses[0]["id"], 1);
    assert_eq!(responses[0]["result"]["protocolVersion"], "2025-06-18");

    // Not pinned to a count: the reference binary registers demo tools plus
    // whatever the config enables, and that set is meant to grow.
    let tools = responses[1]["result"]["tools"].as_array().unwrap();
    assert!(
        tools.len() >= 2,
        "expected several tools, got {}",
        tools.len()
    );
    assert!(tools.iter().any(|t| t["name"] == "word_frequency"));

    let call = &responses[2]["result"];
    assert_eq!(call["isError"], false);
    assert_eq!(call["structuredContent"]["total"], 3);
    assert_eq!(call["structuredContent"]["words"][0]["word"], "a");
}

#[test]
fn the_server_survives_a_malformed_frame_and_keeps_serving() {
    // A host that sends one bad line should not lose the session.
    let responses = handshake(&[
        json!({"jsonrpc": "2.0", "id": 1, "method": "ping"}),
        json!("{ this is not a request }"),
        json!({"jsonrpc": "2.0", "id": 2, "method": "ping"}),
    ]);

    assert_eq!(responses.len(), 3);
    assert!(responses[0]["error"].is_null());
    assert_eq!(
        responses[2]["id"], 2,
        "the session must continue after a bad frame"
    );
}
