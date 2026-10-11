//! `cowproof serve --director` (D4): the director's tools against fake lanes.
//!
//! `rule` and `note` are compared with the CLI the way `mirrors.rs` compares the
//! builder's tools: a fake `control/director.sock` records each request, the
//! real `cowproof rule` / `cowproof note` binary sends one, the registered tool
//! (taken by name from `director_tools::server`) sends the other, and the two
//! recorded requests must be equal. `lanes` is compared with what the real
//! `cowproof watch` prints, `events` with `watch --events` and its own cursor,
//! and one test drives the real `cowproof serve --director` process over stdio.

use serde_json::{Value, json};
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

const LANE: &str = "lane-a";
const ESCALATION: &str = "lane-a:E1";

/// A lanes root under `/var/tmp` with a short name (Unix socket paths are short on
/// macOS). It removes only the directory it created.
struct Root(PathBuf);

impl Root {
    fn new() -> Root {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let path = PathBuf::from(format!("/var/tmp/cpd-{}-{n}", std::process::id()));
        fs::create_dir(&path).unwrap_or_else(|e| panic!("cannot create {}: {e}", path.display()));
        Root(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn arg(&self) -> &str {
        self.0.to_str().unwrap()
    }

    fn control(&self, lane: &str) -> PathBuf {
        let dir = self.0.join(lane).join("control");
        fs::create_dir_all(&dir).unwrap();
        dir
    }
}

impl Drop for Root {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

type Seen = Arc<Mutex<Vec<Value>>>;

/// A lane's director socket: records every request line and answers like the
/// runner does (`{"ok":true,"outcome":...}`).
fn fake_director(root: &Root, lane: &str) -> Seen {
    let listener = UnixListener::bind(root.control(lane).join("director.sock")).unwrap();
    let seen: Seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { return };
            let mut line = String::new();
            BufReader::new(&stream).read_line(&mut line).unwrap();
            let request: Value = serde_json::from_str(&line).unwrap();
            let reply = match request["op"].as_str() {
                Some("rule") => {
                    json!({"ok": true, "outcome": {"id": request["id"], "delivery": "pending"}})
                }
                Some("note") => json!({"ok": true, "outcome": {"id": "N1"}}),
                _ => json!({"ok": false, "error": "unknown op"}),
            };
            log.lock().unwrap().push(request);
            let mut out = &stream;
            writeln!(out, "{reply}").unwrap();
        }
    });
    seen
}

fn only_request(seen: &Seen) -> Value {
    let requests = seen.lock().unwrap();
    assert_eq!(requests.len(), 1, "{requests:?}");
    requests[0].clone()
}

/// Wait for `child` and collect its output, killing it by pid and failing the test
/// if it has not finished within a minute.
fn wait_bounded(child: Child) -> Output {
    let pid = child.id();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(child.wait_with_output());
    });
    match rx.recv_timeout(Duration::from_secs(60)) {
        Ok(out) => out.unwrap(),
        Err(_) => {
            let _ = Command::new("kill")
                .args(["-KILL", &pid.to_string()])
                .status();
            panic!("process {pid} did not finish within 60 s");
        }
    }
}

/// The real `cowproof` binary, with `HOME` pointed into the test's own root so the
/// run never depends on the real one.
fn cowproof(root: &Root, args: &[&str]) -> Output {
    let child = Command::new(env!("CARGO_BIN_EXE_cowproof"))
        .args(args)
        .env("HOME", root.path())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    wait_bounded(child)
}

fn stdout_of(out: &Output) -> String {
    assert!(
        out.status.success(),
        "cowproof failed ({:?}): {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout.clone()).unwrap()
}

/// What the tool `name` returns for `input`: the tool comes from the registry of the
/// real `director_tools::server`, and the call goes through `Registry::call`, which
/// first checks `input` against the tool's own input schema.
async fn call_tool(name: &str, input: Value) -> Result<Value, portkit_core::Error> {
    let server = cowproof_cli::director_tools::server(None);
    let tool = server
        .registry()
        .get(name)
        .unwrap_or_else(|| panic!("the server registers no tool named {name}"));
    assert_eq!(tool.spec().name, name);
    tokio::time::timeout(Duration::from_secs(60), server.registry().call(name, input))
        .await
        .unwrap_or_else(|_| panic!("tool {name} did not answer within 60 s"))
}

async fn tool(name: &str, input: Value) -> Value {
    call_tool(name, input)
        .await
        .unwrap_or_else(|e| panic!("tool {name} failed: {e}"))
}

/// The request and the printed output of the real `cowproof` command `args`
/// (`--lanes-root` is added), against a fresh fake lane.
fn via_cli(args: &[&str]) -> (Value, Value) {
    let root = Root::new();
    let seen = fake_director(&root, LANE);
    let mut full = args.to_vec();
    full.extend(["--lanes-root", root.arg()]);
    let printed = stdout_of(&cowproof(&root, &full));
    let printed = serde_json::from_str(&printed)
        .unwrap_or_else(|e| panic!("stdout is not JSON ({e}): {printed:?}"));
    (only_request(&seen), printed)
}

/// The request and the output of the tool `name`, against a fresh fake lane.
async fn via_tool(name: &str, mut input: Value) -> (Value, Value) {
    let root = Root::new();
    let seen = fake_director(&root, LANE);
    input["lanes_root"] = json!(root.arg());
    let output = tool(name, input).await;
    (only_request(&seen), output)
}

struct RuleCase {
    what: &'static str,
    cli: &'static [&'static str],
    tool: Value,
    verdict: Value,
}

fn rule_cases() -> Vec<RuleCase> {
    vec![
        RuleCase {
            what: "answer",
            cli: &["--answer", "use approach A"],
            tool: json!({"answer": "use approach A"}),
            verdict: json!({"answer": "use approach A"}),
        },
        RuleCase {
            what: "redirect",
            cli: &["--redirect", "packets/next.md"],
            tool: json!({"redirect": "packets/next.md"}),
            verdict: json!({"redirect": "packets/next.md"}),
        },
        RuleCase {
            what: "reassign to the next model",
            cli: &["--reassign"],
            tool: json!({"reassign": {}}),
            verdict: json!({"reassign": {"model": null}}),
        },
        RuleCase {
            what: "reassign to a named model",
            cli: &["--reassign", "--model", "sonnet"],
            tool: json!({"reassign": {"model": "sonnet"}}),
            verdict: json!({"reassign": {"model": "sonnet"}}),
        },
        RuleCase {
            what: "stop",
            cli: &["--stop"],
            tool: json!({"stop": true}),
            verdict: json!("stop"),
        },
    ]
}

#[tokio::test]
async fn rule_sends_the_same_request_through_the_cli_and_the_tool() {
    for case in rule_cases() {
        let mut cli_args = vec!["rule", LANE, ESCALATION];
        cli_args.extend(case.cli);
        let (cli_request, cli_output) = via_cli(&cli_args);

        let mut input = case.tool.clone();
        input["lane"] = json!(LANE);
        input["escalation"] = json!(ESCALATION);
        let (tool_request, tool_output) = via_tool("rule", input).await;

        assert_eq!(cli_request, tool_request, "request for {}", case.what);
        assert_eq!(cli_output, tool_output, "output for {}", case.what);
        // Guard against a vacuous pass: both carry the ruling that was asked for.
        assert_eq!(
            tool_request,
            json!({"op": "rule", "id": ESCALATION, "verdict": case.verdict}),
            "{}",
            case.what
        );
        assert_eq!(
            tool_output,
            json!({"id": ESCALATION, "delivery": "pending"}),
            "{}",
            case.what
        );
    }
}

#[tokio::test]
async fn note_sends_the_same_request_through_the_cli_and_the_tool() {
    let text = "prefer the small change; \"quotes\" and a\nnewline survive";
    let (cli_request, cli_output) = via_cli(&["note", LANE, text]);
    let (tool_request, tool_output) = via_tool("note", json!({"lane": LANE, "text": text})).await;

    assert_eq!(cli_request, tool_request);
    assert_eq!(cli_output, tool_output);
    assert_eq!(tool_request, json!({"op": "note", "text": text}));
    assert_eq!(tool_output, json!({"id": "N1"}));
}

#[tokio::test]
async fn rule_refuses_none_or_several_verdicts_and_sends_nothing() {
    let root = Root::new();
    let seen = fake_director(&root, LANE);
    let base = json!({"lanes_root": root.arg(), "lane": LANE, "escalation": ESCALATION});
    for extra in [
        json!({}),
        json!({"stop": false}),
        json!({"answer": "a", "stop": true}),
        json!({"answer": "a", "redirect": "p.md"}),
    ] {
        let mut input = base.clone();
        input
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        let err = call_tool("rule", input.clone())
            .await
            .expect_err(&format!("{input} should be refused"));
        assert!(err.is_caller_fault(), "{input}: {err}");
    }
    assert!(seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_lane_that_is_not_running_is_reported_by_both() {
    let root = Root::new();
    // A lane with files but no socket.
    root.control(LANE);

    let out = cowproof(&root, &["note", LANE, "hi", "--lanes-root", root.arg()]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("not running"));

    let err = call_tool(
        "note",
        json!({"lanes_root": root.arg(), "lane": LANE, "text": "hi"}),
    )
    .await
    .expect_err("no socket, no note");
    assert!(err.to_string().contains("not running"), "{err}");
}

/// A queue file for `lane`, one event per line.
fn write_queue(root: &Root, lane: &str, events: &[Value]) {
    let mut text = String::new();
    for event in events {
        text.push_str(&format!("{event}\n"));
    }
    fs::write(root.control(lane).join("escalations.jsonl"), text).unwrap();
}

fn append_raw(root: &Root, lane: &str, text: &str) {
    let mut file = fs::OpenOptions::new()
        .append(true)
        .open(root.control(lane).join("escalations.jsonl"))
        .unwrap();
    file.write_all(text.as_bytes()).unwrap();
}

fn asked(lane: &str, n: u32, blocking: bool, at_ms: u64) -> Value {
    json!({
        "event": "asked", "lane": lane, "id": format!("{lane}:E{n}"), "origin": "builder",
        "at_ms": at_ms,
        "ask": {
            "kind": "design", "question": "which way?", "tried": ["read the docs"],
            "options": [{"id": "a", "summary": "first", "cost": "low"}],
            "recommend": "a", "blocking": blocking,
        },
    })
}

/// The rows of `cowproof watch` as `(lane, cells)`.
fn watch_table(root: &Root) -> Vec<(String, Vec<String>)> {
    let out = cowproof(root, &["watch", "--lanes-root", root.arg()]);
    let text = stdout_of(&out);
    let mut lines = text.lines();
    assert_eq!(
        lines.next(),
        Some("LANE\tSTATE\tPARKED\tAGE\tNOTES\tLAST EVENT")
    );
    lines
        .map(|l| {
            let cells: Vec<String> = l.split('\t').map(str::to_string).collect();
            (cells[0].clone(), cells)
        })
        .collect()
}

#[tokio::test]
async fn lanes_reports_the_state_cowproof_watch_prints() {
    let root = Root::new();
    // lane-a finished, with a parked blocking ask and one note nobody has read.
    fs::write(
        root.control("lane-a").join("run.json"),
        json!({"status": "proved"}).to_string(),
    )
    .unwrap();
    write_queue(
        &root,
        "lane-a",
        &[
            asked("lane-a", 1, true, 2000),
            json!({"event": "note", "lane": "lane-a", "id": "lane-a:N1", "text": "hi", "at_ms": 3000}),
        ],
    );
    // lane-b is running with an empty control directory.
    root.control("lane-b");

    let table = watch_table(&root);
    let out = tool("lanes", json!({"lanes_root": root.arg()})).await;
    let lanes = out["lanes"].as_array().unwrap();

    assert_eq!(table.len(), 2);
    assert_eq!(lanes.len(), table.len(), "{out}");
    for ((lane, cells), snapshot) in table.iter().zip(lanes) {
        assert_eq!(snapshot["id"], json!(lane));
        assert_eq!(snapshot["state"], json!(cells[1]), "state of {lane}");
        let parked_cell = match snapshot["parked"]["id"].as_str() {
            Some(id) if snapshot["parked"]["past_cache"] == json!(true) => {
                format!("{id} past cache")
            }
            Some(id) => id.to_string(),
            None => "-".to_string(),
        };
        assert_eq!(parked_cell, cells[2], "parked cell of {lane}");
        assert_eq!(
            snapshot["pending_notes"].to_string(),
            cells[4],
            "notes of {lane}"
        );
    }
    // Guard against a vacuous pass: the fixture really differs between the lanes.
    assert_eq!(lanes[0]["state"], "proved");
    assert_eq!(lanes[0]["parked"]["id"], ESCALATION);
    assert_eq!(lanes[0]["pending_notes"], 1);
    assert_eq!(lanes[1]["state"], "running");
    assert!(lanes[1]["parked"].is_null());
    assert_eq!(lanes[1]["pending_notes"], 0);
}

#[tokio::test]
async fn events_returns_only_what_came_after_the_cursor() {
    let root = Root::new();
    write_queue(
        &root,
        LANE,
        &[
            asked(LANE, 1, false, 1000),
            json!({"event": "ruled", "lane": LANE, "id": ESCALATION,
                   "verdict": {"verdict": "stop"}, "at_ms": 2000}),
        ],
    );
    let input = |cursor: Option<&str>| {
        let mut input = json!({"lanes_root": root.arg()});
        if let Some(cursor) = cursor {
            input["cursor"] = json!(cursor);
        }
        input
    };

    let first = tool("events", input(None)).await;
    let kinds: Vec<&str> = first["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["kind"].as_str().unwrap())
        .collect();
    assert_eq!(kinds, ["asked", "ruled"], "{first}");
    let cursor = first["cursor"].as_str().unwrap().to_string();

    // Nothing new: nothing returned, and the cursor holds still.
    let idle = tool("events", input(Some(&cursor))).await;
    assert_eq!(idle["events"], json!([]), "{idle}");
    assert_eq!(idle["cursor"], first["cursor"]);

    // One more event, then a line the runner has only half written.
    append_raw(
        &root,
        LANE,
        &format!(
            "{}\n",
            json!({"event": "note", "lane": LANE, "id": "lane-a:N1", "text": "hello", "at_ms": 3000})
        ),
    );
    append_raw(
        &root,
        LANE,
        r#"{"event":"note","lane":"lane-a","id":"lane-a:N2""#,
    );
    let second = tool("events", input(Some(&cursor))).await;
    assert_eq!(
        second["events"],
        json!([{"at_ms": 3000, "lane": LANE, "kind": "note", "summary": "lane-a:N1 (5 bytes)"}]),
        "{second}"
    );
    let cursor = second["cursor"].as_str().unwrap().to_string();

    // The half line is read whole once it is finished, and only once.
    append_raw(&root, LANE, r#","text":"x","at_ms":4000}"#);
    append_raw(&root, LANE, "\n");
    let third = tool("events", input(Some(&cursor))).await;
    assert_eq!(
        third["events"],
        json!([{"at_ms": 4000, "lane": LANE, "kind": "note", "summary": "lane-a:N2 (1 bytes)"}]),
        "{third}"
    );
    let done = tool("events", input(Some(third["cursor"].as_str().unwrap()))).await;
    assert_eq!(done["events"], json!([]), "{done}");
}

#[tokio::test]
async fn events_can_be_limited_to_one_lane_and_agree_with_watch_events() {
    let root = Root::new();
    write_queue(&root, "lane-a", &[asked("lane-a", 1, true, 1000)]);
    write_queue(&root, "lane-b", &[asked("lane-b", 1, false, 2000)]);

    let only_b = tool(
        "events",
        json!({"lanes_root": root.arg(), "lane": "lane-b"}),
    )
    .await;
    let rows = only_b["events"].as_array().unwrap();
    assert_eq!(rows.len(), 1, "{only_b}");
    assert_eq!(rows[0]["lane"], "lane-b");
    // The cursor of a one-lane read leaves the other lane unread.
    let rest = tool(
        "events",
        json!({"lanes_root": root.arg(), "cursor": only_b["cursor"]}),
    )
    .await;
    assert_eq!(rest["events"].as_array().unwrap().len(), 1, "{rest}");
    assert_eq!(rest["events"][0]["lane"], "lane-a");

    // Every row appears in `cowproof watch --events` as `<time> <lane> <kind> <summary>`.
    let all = tool("events", json!({"lanes_root": root.arg()})).await;
    let printed = stdout_of(&cowproof(
        &root,
        &["watch", "--events", "--lanes-root", root.arg()],
    ));
    for row in all["events"].as_array().unwrap() {
        let tail = format!(
            "{} {} {}",
            row["lane"].as_str().unwrap(),
            row["kind"].as_str().unwrap(),
            row["summary"].as_str().unwrap()
        );
        assert!(
            printed.lines().any(|l| l.ends_with(&tail)),
            "no line ending {tail:?} in {printed}"
        );
    }
    assert_eq!(printed.lines().count(), 2, "{printed}");
}

#[tokio::test]
async fn events_refuses_a_cursor_it_did_not_issue() {
    let root = Root::new();
    let err = call_tool(
        "events",
        json!({"lanes_root": root.arg(), "cursor": "not a cursor"}),
    )
    .await
    .expect_err("a made-up cursor is an error, not a restart from the top");
    assert!(err.is_caller_fault(), "{err}");
}

#[test]
fn serve_director_answers_over_stdio_and_a_rule_reaches_the_lane() {
    let root = Root::new();
    let seen = fake_director(&root, LANE);
    let frames = [
        json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "t", "version": "0"}}}),
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
        json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {
            "name": "rule",
            "arguments": {"lanes_root": root.arg(), "lane": LANE,
                          "escalation": ESCALATION, "answer": "go with A"}}}),
    ];
    let mut child = Command::new(env!("CARGO_BIN_EXE_cowproof"))
        .args(["serve", "--director"])
        .env("HOME", root.path())
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
        "serve --director failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    let reply = |id: u64| -> Value {
        stdout
            .lines()
            .map(|l| serde_json::from_str::<Value>(l).unwrap())
            .find(|v| v["id"] == id)
            .unwrap_or_else(|| panic!("no answer to request {id} in {stdout:?}"))
    };

    assert_eq!(
        reply(1)["result"]["serverInfo"]["name"],
        "cowproof-director"
    );
    let listed = reply(2);
    let mut names: Vec<&str> = listed["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    names.sort_unstable();
    assert_eq!(names, ["events", "lanes", "note", "rule"]);

    let call = reply(3);
    assert_eq!(call["result"]["isError"], false, "{call}");
    assert_eq!(
        call["result"]["structuredContent"],
        json!({"id": ESCALATION, "delivery": "pending"})
    );
    assert_eq!(
        only_request(&seen),
        json!({"op": "rule", "id": ESCALATION, "verdict": {"answer": "go with A"}})
    );
}

#[test]
fn serve_needs_director_and_its_help_names_the_mcp_use() {
    let root = Root::new();
    let out = cowproof(&root, &["serve"]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("--director"));

    let help = stdout_of(&cowproof(&root, &["serve", "--help"]));
    assert!(help.contains(".mcp.json"), "{help}");
    assert!(help.contains("lanes"), "{help}");
}
