//! Tracing measures what a call actually cost in context.
//!
//! Every optimization in this repo — budgets, schema gating, a resident index
//! — is a hypothesis until something counts bytes. These tests check that the
//! counting is real and that it stays off unless asked for.

use assert_cmd::Command;

fn pk() -> Command {
    Command::cargo_bin("pk").expect("the pk binary must build")
}

/// A workspace with tracing switched on.
fn traced() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("pk.toml"),
        "[trace]\nenabled = true\ndir = \"traces\"\n",
    )
    .unwrap();
    dir
}

/// Run a command; some of these deliberately fail (a rejected call), so the
/// outcome is recorded rather than asserted.
fn run_in(dir: &tempfile::TempDir, args: &[&str]) {
    let _ = pk()
        .current_dir(dir.path())
        .args(["--config", "pk.toml"])
        .args(args)
        .assert();
}

fn records(dir: &tempfile::TempDir) -> Vec<serde_json::Value> {
    let traces = dir.path().join("traces");
    let mut out = Vec::new();
    for entry in std::fs::read_dir(traces).expect("trace dir must exist") {
        let text = std::fs::read_to_string(entry.unwrap().path()).unwrap();
        out.extend(text.lines().filter_map(|l| serde_json::from_str(l).ok()));
    }
    out
}

#[test]
fn nothing_is_recorded_unless_tracing_is_enabled() {
    // Writing a file per call is a side effect nobody asked for.
    let dir = tempfile::tempdir().unwrap();
    pk().current_dir(dir.path())
        .args(["run", "word_frequency", "-a", "text=a b"])
        .assert()
        .success();
    assert!(!dir.path().join(".portkit").exists());
    assert!(!dir.path().join("traces").exists());
}

#[test]
fn a_call_records_what_it_produced_and_what_was_delivered() {
    let dir = traced();
    run_in(&dir, &["run", "word_frequency", "-a", "text=a b a"]);

    let rs = records(&dir);
    assert_eq!(rs.len(), 1);
    let r = &rs[0];
    assert_eq!(r["tool"], "word_frequency");
    assert_eq!(r["surface"], "cli");
    assert_eq!(r["outcome"], "ok");
    assert!(r["produced_bytes"].as_u64().unwrap() > 0);
    assert!(r["input_bytes"].as_u64().unwrap() > 0);
}

#[test]
fn a_trimmed_call_shows_what_the_budget_kept_out_of_context() {
    // The number the whole exercise exists to produce.
    let dir = traced();
    let text = format!("text={}", "the quick brown fox. ".repeat(400));
    run_in(
        &dir,
        &[
            "run",
            "chunk_text",
            "-a",
            &text,
            "-a",
            "size=20",
            "-a",
            "overlap=2",
        ],
    );

    let r = records(&dir).remove(0);
    let produced = r["produced_bytes"].as_u64().unwrap();
    let delivered = r["delivered_bytes"].as_u64().unwrap();
    assert!(
        delivered < produced,
        "expected trimming: {produced} -> {delivered}"
    );
    assert_eq!(r["elisions"].as_u64().unwrap(), 1);
}

#[test]
fn a_rejection_is_recorded_separately_from_a_failure() {
    // A gate that fires often is working; one that never fires may be
    // misconfigured. Collapsing the two would hide both.
    let dir = traced();
    run_in(
        &dir,
        &["run", "chunk_text", "-a", "text=abc", "-a", "bogus=1"],
    );

    let r = records(&dir).remove(0);
    assert_eq!(r["outcome"], "rejected");
    assert_eq!(r["produced_bytes"], 0, "a rejected call produced nothing");
}

#[test]
fn the_mcp_surface_is_recorded_too() {
    // Agents call through MCP; tracing only the CLI would measure the wrong path.
    let dir = traced();
    pk().current_dir(dir.path())
        .args(["--config", "pk.toml", "serve"])
        .write_stdin(
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"word_frequency","arguments":{"text":"a b"}}}"#,
        )
        .assert()
        .success();

    let r = records(&dir).remove(0);
    assert_eq!(r["surface"], "mcp");
}

#[test]
fn timestamps_use_one_format_across_surfaces() {
    // A log with two timestamp formats cannot be sorted or filtered by time.
    let dir = traced();
    run_in(&dir, &["run", "word_frequency", "-a", "text=a"]);
    pk().current_dir(dir.path())
        .args(["--config", "pk.toml", "serve"])
        .write_stdin(
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"word_frequency","arguments":{"text":"b"}}}"#,
        )
        .assert()
        .success();

    let rs = records(&dir);
    assert_eq!(rs.len(), 2);
    for r in &rs {
        let at = r["at"].as_str().unwrap();
        assert!(at.ends_with('Z') && at.contains('T'), "not RFC3339: {at}");
    }
}

#[test]
fn pk_trace_summarizes_the_recorded_calls() {
    let dir = traced();
    run_in(&dir, &["run", "word_frequency", "-a", "text=a b a"]);
    run_in(&dir, &["run", "word_frequency", "-a", "text=c d"]);

    let out = pk()
        .current_dir(dir.path())
        .args(["--config", "pk.toml", "trace"])
        .assert()
        .success();
    let text = String::from_utf8_lossy(&out.get_output().stdout).to_string();
    assert!(text.contains("word_frequency"), "{text}");
    assert!(text.contains("2 calls"), "{text}");
}

#[test]
fn pk_trace_is_quiet_when_there_is_nothing_to_report() {
    let dir = tempfile::tempdir().unwrap();
    pk().current_dir(dir.path())
        .arg("trace")
        .assert()
        .success()
        .stdout(predicates::str::contains("no traces"));
}
