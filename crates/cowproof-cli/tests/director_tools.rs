//! `cowproof serve --director` (D4): the director's tools against fake lanes.
//!
//! `rule` and `note` are compared with the CLI the way `mirrors.rs` compares the
//! builder's tools: a fake `control/director.sock` records each request, the
//! real `cowproof rule` / `cowproof note` binary sends one, the registered tool
//! (taken by name from `director_tools::server`) sends the other, and the two
//! recorded requests must be equal. `lanes` is compared with what the real
//! `cowproof watch` prints, `events` with `watch --events` and its own cursor,
//! and one test drives the real `cowproof serve --director` process over stdio.
//! `escalations` reads queue files that the queue itself wrote (`escalate::Queue`),
//! so a change to what the queue records cannot leave the tool reading a format
//! the tests made up.

#[allow(dead_code)] // this file needs only the signal helper of the shared module
mod common;

use common::signal_pid;
use cowproof_run::escalate::{Ask, AskKind, Clock, Opt, Origin, Queue, QueueEvent, Verdict};
use serde_json::{Value, json};
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
            signal_pid("KILL", pid);
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
        .create(true)
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
    // Twelve long asks: about 53 KB of escalations, over the server's default
    // 16 KiB output budget and under the tool's own 64 KiB cap.
    let question = "q".repeat(4000);
    for n in 0..4 {
        let lane = format!("big-{n}");
        let clock = TestClock::at(now_ms_for_test());
        let mut q = queue(&root, &lane, &clock);
        for _ in 0..3 {
            q.ask(&lane, &real_ask(&question, true), Origin::Builder)
                .unwrap();
        }
    }
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
        json!({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {
            "name": "escalations", "arguments": {"lanes_root": root.arg()}}}),
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
    assert_eq!(names, ["escalations", "events", "lanes", "note", "rule"]);

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

    // Every escalation arrives whole: the server's default output budget does not
    // trim a reply that is inside the tool's own cap.
    let escalations = reply(4);
    assert_eq!(escalations["result"]["isError"], false, "{escalations}");
    let out = &escalations["result"]["structuredContent"];
    assert_eq!(out["escalations"].as_array().unwrap().len(), 12);
    assert_eq!(out["truncated"], false);
    assert!(out["escalations"].to_string().len() > 16 * 1024);
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

/// A queue clock the test sets: milliseconds since the Unix epoch.
#[derive(Clone)]
struct TestClock(Arc<AtomicU64>);

impl TestClock {
    fn at(ms: u64) -> TestClock {
        TestClock(Arc::new(AtomicU64::new(ms)))
    }

    fn set(&self, ms: u64) {
        self.0.store(ms, Ordering::SeqCst);
    }
}

impl Clock for TestClock {
    fn now(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_millis(self.0.load(Ordering::SeqCst))
    }
}

/// The queue the runner would hold for `lane`, on the fixture's control directory.
fn queue(root: &Root, lane: &str, clock: &TestClock) -> Queue {
    Queue::new(&root.control(lane), Box::new(clock.clone())).unwrap()
}

fn real_ask(question: &str, blocking: bool) -> Ask {
    Ask {
        kind: AskKind::Design,
        question: question.to_string(),
        tried: vec!["read the docs".to_string(), "ran the check".to_string()],
        options: vec![
            Opt {
                id: "a".to_string(),
                summary: "the small change".to_string(),
                cost: "an hour".to_string(),
            },
            Opt {
                id: "b".to_string(),
                summary: "the rewrite".to_string(),
                cost: "a day".to_string(),
            },
        ],
        recommend: "a".to_string(),
        blocking,
    }
}

fn now_ms_for_test() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// The escalation ids in a tool reply, in order.
fn ids(out: &Value) -> Vec<String> {
    out["escalations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["id"].as_str().unwrap().to_string())
        .collect()
}

/// Append one real queue event to a lane's queue file.
fn append_event(root: &Root, lane: &str, event: &QueueEvent) {
    append_raw(
        root,
        lane,
        &format!("{}\n", serde_json::to_string(event).unwrap()),
    );
}

/// An `asked` event for `ask`, serialized from the queue's own type, for the
/// states `Queue::ask` refuses to produce (it validates, an old or hand-edited
/// file need not).
fn asked_event(lane: &str, n: u32, ask: Ask, at_ms: u64) -> QueueEvent {
    QueueEvent::Asked {
        lane: lane.to_string(),
        id: format!("{lane}:E{n}"),
        ask,
        origin: Origin::Builder,
        at_ms,
    }
}

#[tokio::test]
async fn escalations_returns_the_open_asks_and_the_ruled_one_only_on_request() {
    let root = Root::new();
    let clock = TestClock::at(now_ms_for_test() - 10 * 60 * 1000);
    let mut q = queue(&root, LANE, &clock);
    let blocking = real_ask("which way for the parser?", true);
    let quiet = real_ask("may I rename the helper?", false);
    let ruled = real_ask("is the retry loop in scope?", true);
    let e1 = q.ask(LANE, &blocking, Origin::Builder).unwrap();
    clock.set(now_ms_for_test() - 5 * 60 * 1000);
    let e2 = q.ask(LANE, &quiet, Origin::Builder).unwrap();
    let e3 = q.ask(LANE, &ruled, Origin::Builder).unwrap();
    q.rule(
        LANE,
        &e3,
        &Verdict::Answer {
            text: "out of scope".to_string(),
        },
    )
    .unwrap();
    let file = root.control(LANE).join("escalations.jsonl");
    let before = fs::read(&file).unwrap();

    let out = tool("escalations", json!({"lanes_root": root.arg()})).await;

    // Exactly the two open ones, oldest first, every ask field as it was asked.
    assert_eq!(ids(&out), [e1.0.as_str(), e2.0.as_str()], "{out}");
    assert_eq!(out["truncated"], false);
    assert_eq!(out["omitted"], 0);
    assert_eq!(out["skipped_lines"], 0);
    assert_eq!(out["unreadable_lanes"], json!([]));
    for (esc, ask) in out["escalations"]
        .as_array()
        .unwrap()
        .iter()
        .zip([&blocking, &quiet])
    {
        assert_eq!(esc["lane"], LANE);
        assert_eq!(esc["status"], "open");
        assert_eq!(esc["ruling"], Value::Null);
        assert_eq!(esc["blocking"], json!(ask.blocking));
        let mut expected = serde_json::to_value(ask).unwrap();
        expected.as_object_mut().unwrap().remove("blocking");
        expected["truncated_fields"] = json!([]);
        assert_eq!(esc["builder_written"], expected);
    }
    // Ages come from the queue's own timestamps.
    let age = |i: usize| out["escalations"][i]["age_ms"].as_u64().unwrap();
    assert!((600_000..660_000).contains(&age(0)), "{}", age(0));
    assert!((300_000..360_000).contains(&age(1)), "{}", age(1));
    // The tool only read the queue.
    assert_eq!(fs::read(&file).unwrap(), before);

    let all = tool(
        "escalations",
        json!({"lanes_root": root.arg(), "include_ruled": true}),
    )
    .await;
    assert_eq!(
        ids(&all),
        [e1.0.as_str(), e2.0.as_str(), e3.0.as_str()],
        "{all}"
    );
    let all = all["escalations"].as_array().unwrap();
    assert_eq!(all[2]["status"], "ruled");
    assert_eq!(all[2]["ruling"], "answer");
    assert_eq!(
        all[2]["builder_written"]["question"],
        "is the retry loop in scope?"
    );
    assert_eq!(all[0]["status"], "open");
    assert_eq!(all[1]["ruling"], Value::Null);
}

#[tokio::test]
async fn escalations_names_each_kind_of_ruling() {
    let root = Root::new();
    let clock = TestClock::at(now_ms_for_test());
    let mut q = queue(&root, LANE, &clock);
    let verdicts = [
        (
            Verdict::Redirect {
                packet_path: "p.md".to_string(),
            },
            "redirect",
        ),
        (Verdict::Reassign { model: None }, "reassign"),
        (Verdict::Stop, "stop"),
    ];
    for (i, (verdict, _)) in verdicts.iter().enumerate() {
        let id = q
            .ask(LANE, &real_ask(&format!("q{i}"), true), Origin::Builder)
            .unwrap();
        q.rule(LANE, &id, verdict).unwrap();
    }
    let out = tool(
        "escalations",
        json!({"lanes_root": root.arg(), "include_ruled": true}),
    )
    .await;
    let kinds: Vec<&str> = out["escalations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["ruling"].as_str().unwrap())
        .collect();
    assert_eq!(kinds, ["redirect", "reassign", "stop"], "{out}");
}

#[tokio::test]
async fn escalations_cuts_long_builder_fields_and_says_which() {
    let root = Root::new();
    let clock = TestClock::at(now_ms_for_test());
    // A 3-byte character, so the cut at 4000 bytes falls inside one.
    let long_question = "\u{20ac}".repeat(2000);
    let mut ask = real_ask(&long_question, true);
    ask.tried = vec!["t".repeat(3000), "u".repeat(2000)];
    ask.options[0].summary = "s".repeat(3000);
    ask.options[1].cost = "c".repeat(2001);
    ask.recommend = "r".repeat(2500);
    // `Queue::ask` refuses these lengths, so the file gets the real event instead.
    queue(&root, LANE, &clock);
    append_event(
        &root,
        LANE,
        &asked_event(LANE, 1, ask, clock.0.load(Ordering::SeqCst)),
    );

    let out = tool("escalations", json!({"lanes_root": root.arg()})).await;
    let written = &out["escalations"][0]["builder_written"];

    let question = written["question"].as_str().unwrap();
    assert_eq!(question.len(), 3999, "cut back to a character boundary");
    assert!(long_question.starts_with(question));
    assert_eq!(written["tried"][0].as_str().unwrap().len(), 2000);
    assert_eq!(
        written["tried"][1],
        "u".repeat(2000),
        "exactly at the cap is whole"
    );
    assert_eq!(
        written["options"][0]["summary"].as_str().unwrap().len(),
        2000
    );
    assert_eq!(written["options"][1]["cost"].as_str().unwrap().len(), 2000);
    assert_eq!(written["recommend"].as_str().unwrap().len(), 2000);
    assert_eq!(
        written["truncated_fields"],
        json!([
            "tried[0]",
            "options[0].summary",
            "options[1].cost",
            "question",
            "recommend"
        ])
    );
}

#[tokio::test]
async fn escalations_caps_the_whole_reply_and_counts_what_it_left_out() {
    let root = Root::new();
    // 24 asks of about 4.3 KB each is well past 64 KiB. A lane may ask three times.
    let question = "q".repeat(4000);
    let mut asked_ids = Vec::new();
    for lane_n in 0..8u64 {
        let lane = format!("lane-{lane_n}");
        let clock = TestClock::at(1_000_000 + lane_n * 1000);
        let mut q = queue(&root, &lane, &clock);
        for _ in 0..3 {
            let id = q
                .ask(&lane, &real_ask(&question, true), Origin::Builder)
                .unwrap();
            asked_ids.push(id.0);
        }
    }

    let out = tool("escalations", json!({"lanes_root": root.arg()})).await;
    let kept = ids(&out);
    let size: usize = out["escalations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e.to_string().len())
        .sum();
    assert!(size <= 64 * 1024, "{size} bytes of escalations");
    assert!(!kept.is_empty());
    assert_eq!(out["truncated"], true, "{} kept", kept.len());
    let omitted = out["omitted"].as_u64().unwrap() as usize;
    assert!(omitted > 0);
    assert_eq!(
        kept.len() + omitted,
        asked_ids.len(),
        "every ask is kept or counted"
    );
    assert_eq!(out["omitted_ids"].as_array().unwrap().len(), omitted);
    // The oldest waits longest, so it is kept and the newest is what is left out.
    assert_eq!(kept[0], "lane-0:E1");
    assert!(
        out["omitted_ids"]
            .as_array()
            .unwrap()
            .contains(&json!("lane-7:E3"))
    );
}

#[tokio::test]
async fn escalations_filters_to_one_lane() {
    let root = Root::new();
    let clock = TestClock::at(now_ms_for_test());
    for lane in ["lane-a", "lane-b"] {
        queue(&root, lane, &clock)
            .ask(
                lane,
                &real_ask(&format!("question of {lane}"), true),
                Origin::Builder,
            )
            .unwrap();
    }
    let all = tool("escalations", json!({"lanes_root": root.arg()})).await;
    assert_eq!(ids(&all), ["lane-a:E1", "lane-b:E1"], "{all}");

    let only_b = tool(
        "escalations",
        json!({"lanes_root": root.arg(), "lane": "lane-b"}),
    )
    .await;
    assert_eq!(ids(&only_b), ["lane-b:E1"], "{only_b}");
    assert_eq!(
        only_b["escalations"][0]["builder_written"]["question"],
        "question of lane-b"
    );
    let none = tool(
        "escalations",
        json!({"lanes_root": root.arg(), "lane": "lane-c"}),
    )
    .await;
    assert_eq!(ids(&none), Vec::<String>::new());
}

#[tokio::test]
async fn escalations_counts_lines_it_cannot_read_and_names_unreadable_lanes() {
    let root = Root::new();
    let clock = TestClock::at(now_ms_for_test());
    queue(&root, LANE, &clock)
        .ask(LANE, &real_ask("still readable?", true), Origin::Builder)
        .unwrap();
    // One garbage line and one half-written line.
    append_raw(&root, LANE, "this is not an event\n");
    append_raw(
        &root,
        LANE,
        r#"{"event":"asked","lane":"lane-a","id":"lane-a:E2""#,
    );
    // Another lane whose queue path is a directory, so it cannot be read.
    fs::create_dir(root.control("lane-b").join("escalations.jsonl")).unwrap();

    let out = tool("escalations", json!({"lanes_root": root.arg()})).await;

    assert_eq!(ids(&out), [ESCALATION], "{out}");
    assert_eq!(out["skipped_lines"], 2, "{out}");
    assert_eq!(out["unreadable_lanes"], json!(["lane-b"]), "{out}");
}

#[tokio::test]
async fn escalations_says_in_its_description_that_the_fields_are_untrusted() {
    let server = cowproof_cli::director_tools::server(None);
    let description = server
        .registry()
        .get("escalations")
        .unwrap()
        .spec()
        .description;
    assert!(
        description.contains("written by the builder"),
        "{description}"
    );
    assert!(description.contains("untrusted"), "{description}");
    // The reply says it too, next to the data.
    let root = Root::new();
    let out = tool("escalations", json!({"lanes_root": root.arg()})).await;
    assert!(
        out["notice"].as_str().unwrap().contains("untrusted"),
        "{out}"
    );
}
