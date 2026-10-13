//! The stdout rule of every MCP stdio server this workspace ships: stdout carries JSON-RPC
//! frames and nothing else, however loud the logging, and closing stdin ends the server with
//! exit 0.
//!
//! portkit's own `tests/mcp_stdio.rs` ran `pk serve` with `RUST_LOG=debug` and failed if any
//! stdout line was not JSON. The import dropped it, and `cowproof serve --director` and
//! `cowproof lane-tools` were added since. One log line on stdout drops the client's
//! connection with an error that points nowhere near the print, so each server gets the same
//! session here, under `RUST_LOG=debug` and `RUST_LOG=trace`:
//!
//! - `cowproof serve --director` (the director's tools, for `.mcp.json`);
//! - `cowproof lane-tools --socket <sock>` (the builder's tools, which cowproof launches in
//!   the sandbox for Claude and Codex; a fake runner answers on the socket);
//! - `pk serve` and `cowproof pk serve` (the portkit server; its log level also comes from
//!   `PK_LOG_LEVEL` and `--log-level`).
//!
//! Each session runs `initialize`, `tools/list` and one tool call, then a malformed line
//! (the server must answer it with a parse error frame and go on) and `ping`, then closes
//! stdin. `cowproof serve --director` and `cowproof lane-tools` install no log subscriber
//! today, so for them the level is a guard against one being added with stdout as its
//! writer; `pk` does log (to stderr), and its sessions assert that it did.

#[allow(dead_code)] // this file needs only the fork lock, `var_tmp` and the signal helper
mod common;
mod pk_support;

use pk_support::{Session, Work, handshake, rpc, stdio_session};
use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::sync::{Arc, Mutex};

const LEVELS: [&str; 2] = ["debug", "trace"];

/// A line that is not JSON at all. A server answers it with a parse error and keeps serving.
const MALFORMED: &str = "{ this is not a request }";

fn ping(id: u64) -> String {
    rpc(id, "ping", json!({}))
}

fn call(id: u64, name: &str, arguments: Value) -> String {
    rpc(
        id,
        "tools/call",
        json!({"name": name, "arguments": arguments}),
    )
}

fn tool_names(session: &Session, id: u64) -> Vec<String> {
    let mut names: Vec<String> = session.reply(id)["result"]["tools"]
        .as_array()
        .unwrap_or_else(|| panic!("no tool list in {}", session.reply(id)))
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_string())
        .collect();
    names.sort();
    names
}

/// What every server owes a client after a malformed line: a parse error frame with a null
/// id, then an answer to the next request.
fn assert_survives_a_malformed_line(session: &Session, ping_id: u64) {
    let parse_errors: Vec<&Value> = session
        .frames
        .iter()
        .filter(|f| f["id"].is_null())
        .collect();
    assert_eq!(parse_errors.len(), 1, "{:?}", session.frames);
    assert_eq!(parse_errors[0]["error"]["code"], -32700, "{parse_errors:?}");
    assert_eq!(
        session.reply(ping_id)["result"],
        json!({}),
        "the session must continue after a bad line"
    );
}

/// With stdin closed and nothing sent, a server has nothing to say and exits 0.
fn assert_quiet_clean_exit(session: &Session) {
    assert_eq!(
        session.out.stdout,
        b"",
        "{}",
        pk_support::describe(&session.out)
    );
    assert!(session.exit_after_eof < pk_support::EXIT_BOUND);
}

// ---- cowproof serve --director --------------------------------------------------------

#[test]
fn serve_director_writes_only_json_frames_under_debug_and_trace_logging() {
    for level in LEVELS {
        let work = Work::new();
        let mut lines = handshake();
        lines.push(call(
            3,
            "lanes",
            json!({"lanes_root": work.cwd.to_str().unwrap()}),
        ));
        lines.push(MALFORMED.to_string());
        lines.push(ping(4));

        let mut cmd = work.cowproof();
        cmd.args(["serve", "--director"]).env("RUST_LOG", level);
        let session = stdio_session(&mut cmd, &lines);

        // initialize, tools/list, the call, the parse error and ping; the notification
        // is not answered.
        assert_eq!(session.frames.len(), 5, "{level}: {:?}", session.frames);
        assert_eq!(
            session.reply(1)["result"]["serverInfo"]["name"],
            "cowproof-director",
            "{level}"
        );
        assert_eq!(
            tool_names(&session, 2),
            ["escalations", "events", "lanes", "note", "rule"],
            "{level}"
        );
        let lanes = &session.reply(3)["result"];
        assert_eq!(lanes["isError"], false, "{level}: {lanes}");
        assert_eq!(lanes["structuredContent"]["lanes"], json!([]), "{level}");
        assert_survives_a_malformed_line(&session, 4);
    }
}

#[test]
fn serve_director_exits_zero_when_stdin_closes_with_nothing_sent() {
    for level in LEVELS {
        let work = Work::new();
        let mut cmd = work.cowproof();
        cmd.args(["serve", "--director"]).env("RUST_LOG", level);
        assert_quiet_clean_exit(&stdio_session(&mut cmd, &[]));
    }
}

// ---- cowproof lane-tools ---------------------------------------------------------------

/// A stand-in for the lane's runner socket: answers every request line with `reply` and
/// records it. (`tests/lane_tools.rs` has one too, private to that file.)
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

#[test]
fn lane_tools_writes_only_json_frames_under_debug_and_trace_logging() {
    for level in LEVELS {
        let work = Work::new();
        let socket = work.cwd.join("runner.sock");
        let seen = fake_runner(
            &socket,
            json!({"ok": true, "id": "l1:E1", "status": "asked"}),
        );
        let ask = json!({
            "kind": "design",
            "question": "which way?",
            "tried": ["read the docs"],
            "options": [{"id": "a", "summary": "first", "cost": "low"}],
            "recommend": "a",
            "blocking": false,
        });
        let mut lines = handshake();
        lines.push(call(3, "ask", ask.clone()));
        lines.push(MALFORMED.to_string());
        lines.push(ping(4));

        let mut cmd = work.cowproof();
        cmd.args(["lane-tools", "--socket"])
            .arg(&socket)
            .env("RUST_LOG", level);
        let session = stdio_session(&mut cmd, &lines);

        assert_eq!(session.frames.len(), 5, "{level}: {:?}", session.frames);
        assert_eq!(
            tool_names(&session, 2),
            ["ask", "check_ruling", "run_check"],
            "{level}"
        );
        let result = &session.reply(3)["result"];
        assert_eq!(result["isError"], false, "{level}: {result}");
        assert_eq!(
            result["structuredContent"],
            json!({"id": "l1:E1", "status": "asked"}),
            "{level}"
        );
        assert_survives_a_malformed_line(&session, 4);
        assert_eq!(
            *seen.lock().unwrap(),
            [json!({"op": "ask", "ask": ask})],
            "{level}"
        );
    }
}

#[test]
fn lane_tools_exits_zero_when_stdin_closes_with_nothing_sent() {
    for level in LEVELS {
        // No runner is listening: with no call made the socket is never opened.
        let work = Work::new();
        let mut cmd = work.cowproof();
        cmd.args(["lane-tools", "--socket"])
            .arg(work.cwd.join("missing.sock"))
            .env("RUST_LOG", level);
        assert_quiet_clean_exit(&stdio_session(&mut cmd, &[]));
    }
}

// ---- pk serve --------------------------------------------------------------------------

/// A session against `pk serve` (or `cowproof pk serve`) with the demo tools, and the proof
/// that logging was on: the server logs each request it dispatches, on stderr.
fn pk_serve_session(via_cowproof: bool, configure: impl Fn(&mut std::process::Command)) -> Session {
    let work = Work::with_demo_tools(false);
    let mut lines = handshake();
    lines.push(call(
        3,
        "word_frequency",
        json!({"text": "a b a", "top_k": 1}),
    ));
    lines.push(MALFORMED.to_string());
    lines.push(ping(4));

    let mut cmd = if via_cowproof {
        let mut cmd = work.cowproof();
        cmd.arg("pk");
        cmd
    } else {
        work.pk()
    };
    cmd.args(["--config", "pk.toml", "serve"]);
    configure(&mut cmd);
    stdio_session(&mut cmd, &lines)
}

fn assert_pk_session(session: &Session, how: &str) {
    assert_eq!(session.frames.len(), 5, "{how}: {:?}", session.frames);
    assert_eq!(
        session.reply(1)["result"]["serverInfo"]["name"],
        "portkit",
        "{how}"
    );
    assert_eq!(
        tool_names(session, 2),
        ["chunk_text", "word_frequency"],
        "{how}"
    );
    let result = &session.reply(3)["result"];
    assert_eq!(result["isError"], false, "{how}: {result}");
    assert_eq!(result["structuredContent"]["total"], 3, "{how}");
    assert_eq!(
        result["structuredContent"]["words"][0]["word"], "a",
        "{how}"
    );
    assert_survives_a_malformed_line(session, 4);
    // Proof that the level took effect: without it a pass would mean nothing.
    let stderr = pk_support::stderr_text(&session.out);
    assert!(
        stderr.contains("dispatching"),
        "{how}: no debug log on stderr, so the level was not applied: {stderr}"
    );
}

#[test]
fn pk_serve_writes_only_json_frames_under_debug_and_trace_logging() {
    for level in LEVELS {
        let session = pk_serve_session(false, |cmd| {
            cmd.env("RUST_LOG", level);
        });
        assert_pk_session(&session, &format!("pk serve, RUST_LOG={level}"));
    }
}

#[test]
fn cowproof_pk_serve_writes_only_json_frames_under_debug_and_trace_logging() {
    for level in LEVELS {
        let session = pk_serve_session(true, |cmd| {
            cmd.env("RUST_LOG", level);
        });
        assert_pk_session(&session, &format!("cowproof pk serve, RUST_LOG={level}"));
    }
}

#[test]
fn pk_serve_keeps_stdout_clean_when_the_level_comes_from_pk_log_level_or_the_flag() {
    let session = pk_serve_session(false, |cmd| {
        cmd.env("PK_LOG_LEVEL", "trace");
    });
    assert_pk_session(&session, "PK_LOG_LEVEL=trace");

    // The flag goes before the subcommand in `Cli`, but it is global: after `serve` works.
    let session = pk_serve_session(false, |cmd| {
        cmd.args(["--log-level", "debug"]);
    });
    assert_pk_session(&session, "--log-level debug");
}

#[test]
fn pk_serve_exits_zero_when_stdin_closes_with_nothing_sent() {
    for level in LEVELS {
        let work = Work::with_demo_tools(false);
        let mut cmd = work.pk_with_config();
        cmd.arg("serve").env("RUST_LOG", level);
        let session = stdio_session(&mut cmd, &[]);
        assert_quiet_clean_exit(&session);
        assert!(
            pk_support::stderr_text(&session.out).contains("stdin closed"),
            "{level}: {}",
            pk_support::describe(&session.out)
        );
    }
}
