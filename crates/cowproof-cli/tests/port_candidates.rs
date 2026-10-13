//! `cowproof report port-candidates`, end to end: the command line over hand-written lanes
//! roots, and over a root a real `pk hook post-tool-use` just wrote (the way the runner's
//! hooks call it, with `PORTKIT_STATE_DIR=<lane>/portkit`), so the trace shape the report
//! reads cannot drift from the shape portkit writes. The ranking and the fingerprint are
//! tested in `crates/cowproof-report/tests/port_candidates.rs`.

#[allow(dead_code)] // this file needs only a few of the shared helpers
mod common;

use common::{fork_lock, output, text, var_tmp};
use serde_json::{Value, json};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const SECRET_TAIL: &str = "abcdefghij";

fn cowproof(args: &[&str], roots: &[&Path]) -> Output {
    output(
        Command::new(env!("CARGO_BIN_EXE_cowproof"))
            .args(args)
            .args(roots),
    )
}

fn candidates(args: &[&str], roots: &[&Path]) -> Output {
    let mut all = vec!["report", "port-candidates"];
    all.extend_from_slice(args);
    cowproof(&all, roots)
}

fn stdout(out: &Output) -> String {
    String::from_utf8(out.stdout.clone()).unwrap()
}

/// One `pk hook post-tool-use` for a `Bash` call, the way a lane's settings file runs it:
/// a lane-private state dir and session, tracing on, an isolated HOME.
fn bash_hook(root: &Path, lane: &str, command: &str, output_len: usize) {
    hook_event(
        root,
        lane,
        json!({
            "session_id": "sess-1",
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "tool_output": "x".repeat(output_len),
        }),
    );
}

fn hook_event(root: &Path, lane: &str, payload: Value) {
    let home = root.join("home");
    let config = root.join("pk.toml");
    let state = root.join("lanes").join(lane).join("portkit");
    fs::create_dir_all(&home).unwrap();
    fs::write(&config, "[trace]\nenabled = true\n").unwrap();
    let mut child = {
        let _g = fork_lock();
        Command::new(env!("CARGO_BIN_EXE_pk"))
            .arg("--config")
            .arg(&config)
            .args(["hook", "post-tool-use"])
            .env("HOME", &home)
            .env_remove("CLAUDE_CONFIG_DIR")
            .env("PORTKIT_STATE_DIR", &state)
            .env("PORTKIT_SESSION", lane)
            .current_dir(&home)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
    };
    child
        .stdin
        .take()
        .unwrap()
        .write_all(payload.to_string().as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "the hook must exit 0: {out:?}");
}

/// A hand-written hook record (`portkit_core::trace::CallRecord` as JSONL).
fn record(target: &str, bytes: usize) -> String {
    json!({
        "tool": "Bash", "session": "s1", "target": target, "surface": "agent",
        "outcome": "ok", "at": "2026-10-11T00:00:00Z", "duration_ms": 0.0,
        "input_bytes": 40, "produced_bytes": bytes, "delivered_bytes": bytes,
    })
    .to_string()
}

fn put(root: &Path, lane: &str, lines: &[String]) {
    let traces = root.join(lane).join("portkit").join("traces");
    fs::create_dir_all(&traces).unwrap();
    fs::write(traces.join("2026-10-11-s1.jsonl"), lines.join("\n") + "\n").unwrap();
}

fn repeat(target: &str, bytes: usize, n: usize) -> Vec<String> {
    (0..n).map(|_| record(target, bytes)).collect()
}

fn sample_lanes(root: &Path) {
    let mut lines = repeat("cargo test", 20_000, 6);
    lines.extend(repeat("git status", 300, 10));
    lines.extend(repeat("rg foo", 6_000, 3));
    lines.extend(repeat("node scripts/gate.mjs", 9_000, 4));
    lines.push(record("ls -la", 50));
    put(root, "lane-a", &lines);
}

#[test]
fn a_real_pk_trace_is_found_where_the_runner_puts_it_and_ranked() {
    let dir = var_tmp("cp-pccli-real-");
    let root = dir.path();
    for _ in 0..3 {
        bash_hook(root, "lane-a", "cargo test --workspace --locked", 200);
    }
    bash_hook(root, "lane-a", "cargo test -p cowproof-report", 200);
    bash_hook(root, "lane-b", "cargo test", 200);
    for _ in 0..2 {
        bash_hook(root, "lane-a", "git status --short", 50);
    }
    // The same command on two different temp files is one command.
    bash_hook(root, "lane-a", "cat /tmp/aaa111/out.log", 10);
    bash_hook(root, "lane-a", "cat /var/folders/zz/T/tmp.QwErTy/b.log", 10);
    // Not a command.
    hook_event(
        root,
        "lane-a",
        json!({"session_id": "sess-1", "tool_name": "Read",
               "tool_input": {"file_path": "/a/b.rs"}, "tool_output": "abc"}),
    );

    // Where the trace is: <lane>/portkit/traces/<date>-<session>.jsonl.
    let traces = root
        .join("lanes")
        .join("lane-a")
        .join("portkit")
        .join("traces");
    let files: Vec<String> = fs::read_dir(&traces)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(files.len(), 1, "{files:?}");
    assert!(files[0].ends_with("-lane-a.jsonl"), "{files:?}");

    let lanes = root.join("lanes");
    let out = candidates(&["--json"], &[&lanes]);
    assert!(out.status.success(), "{}", text(&out));
    let doc: Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(doc["counts"]["records"], 10, "{doc}");
    assert_eq!(doc["counts"]["commands"], 9, "{doc}");
    assert_eq!(doc["counts"]["notCommands"], 1, "{doc}");
    assert_eq!(doc["counts"]["malformedLines"], 0, "{doc}");
    assert_eq!(doc["counts"]["lanesTraced"], 2, "{doc}");
    // The hook cannot time a call.
    assert_eq!(doc["timeRecorded"], false);
    let list = doc["candidates"].as_array().unwrap();
    let names: Vec<&str> = list
        .iter()
        .map(|c| c["fingerprint"].as_str().unwrap())
        .collect();
    // max calls 5 (cargo test), max bytes 1000: cargo 1 x 1; git 0.4 x 0.1; cat 0.4 x 0.02.
    assert_eq!(names, ["cargo test", "git status", "cat <tmp>"], "{doc}");
    let cargo = &list[0];
    assert_eq!(cargo["calls"], 5);
    assert_eq!(cargo["lanes"], 2);
    assert_eq!(cargo["deliveredBytes"], 1000);
    assert_eq!(cargo["medianMs"], Value::Null);
    assert_eq!(list[1]["deliveredBytes"], 100);
    assert_eq!(list[2]["calls"], 2);
    assert_eq!(list[2]["deliveredBytes"], 20);
    assert!((list[1]["score"].as_f64().unwrap() - 0.04).abs() < 1e-12);
}

#[test]
fn the_table_prints_in_80_columns_and_the_design_spelling_works() {
    let dir = var_tmp("cp-pccli-table-");
    let root = dir.path();
    sample_lanes(root);
    let out = candidates(&[], &[root]);
    assert!(out.status.success(), "{}", text(&out));
    let table = stdout(&out);
    assert!(
        table.contains("Port candidates: 4 of 4 commands run 2+ times; 1 of 1 lanes traced"),
        "{table}"
    );
    let row = table
        .lines()
        .find(|l| l.contains("cargo test"))
        .unwrap_or_else(|| panic!("no cargo row in:\n{table}"));
    let cells: Vec<&str> = row.split_whitespace().collect();
    // rank, command (two words), calls, lanes, time, median, bytes (two words), score.
    assert_eq!(
        cells,
        [
            "1", "cargo", "test", "6", "1", "-", "-", "117.2", "KiB", "0.6000"
        ],
        "{row:?}"
    );
    for line in table.lines() {
        assert!(line.chars().count() <= 80, "{line:?}");
    }
    assert!(table.contains("not in these traces"), "{table}");

    // `cowproof report --port-candidates`, as the design spells it, is the same report.
    let flag = output(
        Command::new(env!("CARGO_BIN_EXE_cowproof"))
            .args(["report", "--port-candidates"])
            .arg(root),
    );
    assert!(flag.status.success(), "{}", text(&flag));
    assert_eq!(stdout(&flag), table);
}

#[test]
fn top_and_min_calls_are_flags_and_zero_is_refused() {
    let dir = var_tmp("cp-pccli-top-");
    let root = dir.path();
    sample_lanes(root);
    let out = candidates(&["--json", "--top", "2"], &[root]);
    let doc: Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(doc["candidates"].as_array().unwrap().len(), 2);
    assert_eq!(doc["candidateCount"], 4);
    let out = candidates(&["--json", "--min-calls", "4"], &[root]);
    let doc: Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(doc["candidateCount"], 3, "{doc}");
    let out = candidates(&["--json", "--min-calls", "1"], &[root]);
    let doc: Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(doc["candidateCount"], 5, "{doc}");
    assert_eq!(candidates(&["--top", "0"], &[root]).status.code(), Some(2));
    assert_eq!(
        candidates(&["--min-calls", "0"], &[root]).status.code(),
        Some(2)
    );
}

#[test]
fn a_root_that_is_not_a_directory_exits_1() {
    let dir = var_tmp("cp-pccli-root-");
    let missing = dir.path().join("missing");
    let out = candidates(&[], &[&missing]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert!(text(&out).contains("lanes root"), "{}", text(&out));
}

#[test]
fn a_secret_shaped_argument_reaches_no_output_and_no_draft() {
    let dir = var_tmp("cp-pccli-secret-");
    let root = dir.path();
    let secret = format!("sk-ant-api03-{}", SECRET_TAIL.repeat(4));
    let mut lines = Vec::new();
    for _ in 0..3 {
        lines.push(record(&format!("curl {secret}"), 500));
        lines.push(record(&format!("deploy --token={secret}"), 500));
        lines.push(record(&format!("API_KEY={secret} make"), 500));
    }
    put(root, "lane-a", &lines);
    let drafts = dir.path().join("drafts-out");
    let table = candidates(&["--draft", drafts.to_str().unwrap()], &[root]);
    let json = candidates(&["--json"], &[root]);
    assert!(table.status.success(), "{}", text(&table));
    let mut everything = text(&table) + &text(&json);
    let mut written = 0;
    for entry in fs::read_dir(&drafts).unwrap() {
        everything.push_str(&fs::read_to_string(entry.unwrap().path()).unwrap());
        written += 1;
    }
    assert_eq!(written, 3);
    assert!(!everything.contains(SECRET_TAIL), "{everything}");
    assert!(!everything.contains("sk-ant"), "{everything}");
}

// ---- --draft ----

/// A repository directory shaped like the real one for the paths a draft names.
fn repo(base: &Path) -> PathBuf {
    let repo = base.join("repo");
    fs::create_dir_all(repo.join("docs").join("handoffs")).unwrap();
    fs::create_dir_all(repo.join("crates")).unwrap();
    // The plugin manifest the packet owns lives here once a repository uses portkit.
    fs::create_dir_all(repo.join(".portkit")).unwrap();
    repo
}

fn lint(repo: &Path, packet: &Path) -> Output {
    output(
        Command::new(env!("CARGO_BIN_EXE_cowproof"))
            .args(["lint", "--repo"])
            .arg(repo)
            .arg(packet),
    )
}

/// The `rule` of each `error [rule]` line of a lint report.
fn error_rules(out: &Output) -> Vec<String> {
    let mut rules: Vec<String> = text(out)
        .lines()
        .filter_map(|line| line.split_once(": error [")?.1.split_once(']'))
        .map(|(rule, _)| rule.to_string())
        .collect();
    rules.sort();
    rules
}

#[test]
fn draft_writes_a_marked_packet_per_candidate_that_lints_with_only_the_fill_errors() {
    let dir = var_tmp("cp-pccli-draft-");
    let lanes = dir.path().join("lanes");
    sample_lanes(&lanes);
    let repo = repo(dir.path());
    let drafts = repo.join("drafts");
    let out = candidates(
        &["--top", "2", "--draft", drafts.to_str().unwrap()],
        &[&lanes],
    );
    assert!(out.status.success(), "{}", text(&out));
    let printed = stdout(&out);
    assert!(
        printed.contains("2 draft packets written (DRAFT, not dispatched):"),
        "{printed}"
    );
    let mut names: Vec<String> = fs::read_dir(&drafts)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(names, ["port-cargo-test.md", "port-node-gate-mjs.md"]);

    for name in &names {
        let path = drafts.join(name);
        let packet = fs::read_to_string(&path).unwrap();
        assert!(packet.contains("# DRAFT: port"), "{packet}");
        assert!(packet.contains("\"kind\": \"port\""), "{packet}");
        assert!(packet.contains("cowproof pk port capture"), "{packet}");
        let linted = lint(&repo, &path);
        assert_eq!(linted.status.code(), Some(1), "{}", text(&linted));
        // Exactly the placeholders: the crate's source file and the cases file have no
        // folder yet, the fixtures glob matches nothing, the cases file the port names is not
        // there, and the replay check names a fixtures directory that does not exist.
        assert_eq!(
            error_rules(&linted),
            [
                "check-path-missing",
                "owns-parent-missing",
                "owns-parent-missing",
                "owns-unmatched",
                "port-cases-missing",
                // The tool is still the placeholder, and the base holds no fixture for it.
                "port-no-base-fixtures"
            ],
            "{}",
            text(&linted)
        );
        for line in text(&linted).lines().filter(|l| l.contains(": error [")) {
            assert!(
                line.contains("FILL-"),
                "an error that is not a placeholder: {line}"
            );
        }
    }
}

#[test]
fn a_draft_with_its_placeholders_filled_lints_clean() {
    let dir = var_tmp("cp-pccli-filled-");
    let lanes = dir.path().join("lanes");
    sample_lanes(&lanes);
    let repo = repo(dir.path());
    let drafts = repo.join("drafts");
    let out = candidates(
        &["--top", "1", "--draft", drafts.to_str().unwrap()],
        &[&lanes],
    );
    assert!(out.status.success(), "{}", text(&out));
    let path = drafts.join("port-cargo-test.md");
    let filled = fs::read_to_string(&path)
        .unwrap()
        .replace("FILL-FIXTURES-DIR", "tests/ports/cargo-test")
        .replace("pk-FILL-NAME", "pk-cargo-test")
        .replace("FILL-TOOL-NAME", "cargo_test")
        .replace("FILL-REFERENCE-COMMAND", "cargo test");
    fs::write(&path, filled).unwrap();
    fs::create_dir_all(repo.join("crates").join("pk-cargo-test").join("src")).unwrap();
    // The director records the fixtures first: the base holds one for the tool.
    fs::create_dir_all(repo.join("tests/ports/cargo-test/fixtures/cargo_test")).unwrap();
    fs::write(
        repo.join("tests/ports/cargo-test/fixtures/cargo_test/001.json"),
        "{\"tool\":\"cargo_test\",\"id\":\"001\",\"input\":{},\"expected\":{}}\n",
    )
    .unwrap();
    fs::write(
        repo.join("tests/ports/cargo-test/cases.jsonl"),
        "{\"tool\":\"cargo_test\",\"input\":{}}\n",
    )
    .unwrap();
    let linted = lint(&repo, &path);
    assert!(linted.status.success(), "{}", text(&linted));

    // And it is a valid port header: the kind and the strictly parsed `port` object.
    let header = cowproof_core::parse_header(&fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(header.kind, cowproof_core::PacketKind::Port);
    assert_eq!(header.class_name, "rust");
    let port = header.port.expect("a port object");
    assert_eq!(port.tools, ["cargo_test"]);
    assert_eq!(port.cases, "tests/ports/cargo-test/cases.jsonl");
    assert_eq!(port.fixtures, "tests/ports/cargo-test/fixtures");
    assert!(
        header
            .owns
            .contains(&"tests/ports/cargo-test/fixtures/**".to_string())
    );
}

#[test]
fn draft_never_overwrites_and_json_lists_what_it_wrote() {
    let dir = var_tmp("cp-pccli-nooverwrite-");
    let lanes = dir.path().join("lanes");
    sample_lanes(&lanes);
    let drafts = dir.path().join("drafts");
    let arg = drafts.to_str().unwrap();
    let first = candidates(&["--json", "--top", "1", "--draft", arg], &[&lanes]);
    assert!(first.status.success(), "{}", text(&first));
    let doc: Value = serde_json::from_str(&stdout(&first)).unwrap();
    let listed: Vec<&str> = doc["drafts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p.as_str().unwrap())
        .collect();
    assert_eq!(
        listed,
        [drafts.join("port-cargo-test.md").to_str().unwrap()]
    );
    let file = drafts.join("port-cargo-test.md");
    fs::write(&file, "mine").unwrap();
    let second = candidates(&["--top", "1", "--draft", arg], &[&lanes]);
    assert_eq!(second.status.code(), Some(1), "{}", text(&second));
    assert!(
        text(&second).contains("never overwrite"),
        "{}",
        text(&second)
    );
    assert_eq!(fs::read_to_string(&file).unwrap(), "mine");
}
