//! Tracing measures what a call actually cost in context. Restored from portkit's
//! `tests/trace.rs`, against the real `pk` binary and the demo tools
//! (`fixtures/pk/demo_tools.py`) registered as plugins.
//!
//! Every optimization in the kit (budgets, schema gating, a resident index) is a hypothesis
//! until something counts bytes. These tests check that the counting is real and that it
//! stays off unless asked for.

#[allow(dead_code)] // this file needs only the fork lock, `var_tmp` and the signal helper
mod common;
mod pk_support;

use pk_support::{Work, describe, run, stdout_text};

/// One `tools/call` frame, sent without a handshake: the server answers it.
fn word_frequency_frame(text: &str) -> String {
    pk_support::rpc(
        1,
        "tools/call",
        serde_json::json!({"name": "word_frequency", "arguments": {"text": text}}),
    )
}

#[test]
fn nothing_is_recorded_unless_tracing_is_enabled() {
    // Writing a file per call is a side effect nobody asked for.
    let work = Work::with_demo_tools(false);
    let out = run(
        work.pk_with_config()
            .args(["run", "word_frequency", "-a", "text=a b"]),
        None,
    );
    assert!(out.status.success(), "{}", describe(&out));
    assert!(!work.cwd.join(".portkit").exists());
    assert!(!work.cwd.join("traces").exists());
}

#[test]
fn a_call_records_what_it_produced_and_what_was_delivered() {
    let work = Work::with_demo_tools(true);
    let out = run(
        work.pk_with_config()
            .args(["run", "word_frequency", "-a", "text=a b a"]),
        None,
    );
    assert!(out.status.success(), "{}", describe(&out));

    let records = work.trace_records();
    assert_eq!(records.len(), 1, "{records:?}");
    let r = &records[0];
    assert_eq!(r["tool"], "word_frequency");
    assert_eq!(r["surface"], "cli");
    assert_eq!(r["outcome"], "ok");
    assert!(r["produced_bytes"].as_u64().unwrap() > 0);
    assert!(r["input_bytes"].as_u64().unwrap() > 0);
    assert_eq!(
        r["produced_bytes"], r["delivered_bytes"],
        "a small result is delivered whole"
    );
}

#[test]
fn a_trimmed_call_shows_what_the_budget_kept_out_of_context() {
    // The number the whole exercise exists to produce.
    let work = Work::with_demo_tools(true);
    let text = format!("text={}", "the quick brown fox. ".repeat(400));
    let out = run(
        work.pk_with_config().args([
            "run",
            "chunk_text",
            "-a",
            &text,
            "-a",
            "size=20",
            "-a",
            "overlap=2",
            "--budget",
            "3000",
        ]),
        None,
    );
    assert!(out.status.success(), "{}", describe(&out));

    let records = work.trace_records();
    assert_eq!(records.len(), 1, "{records:?}");
    let r = &records[0];
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
    // A gate that fires often is working; one that never fires may be misconfigured.
    // Collapsing the two would hide both.
    let work = Work::with_demo_tools(true);
    let rejected = run(
        work.pk_with_config()
            .args(["run", "chunk_text", "-a", "text=abc", "-a", "bogus=1"]),
        None,
    );
    assert!(!rejected.status.success(), "{}", describe(&rejected));
    // The plugin itself refuses this one: the caller could not have known.
    let failed = run(
        work.pk_with_config().args([
            "run",
            "chunk_text",
            "-a",
            "text=abc",
            "-a",
            "size=2",
            "-a",
            "overlap=5",
        ]),
        None,
    );
    assert!(!failed.status.success(), "{}", describe(&failed));

    let records = work.trace_records();
    assert_eq!(records.len(), 2, "{records:?}");
    assert_eq!(records[0]["outcome"], "rejected");
    assert_eq!(
        records[0]["produced_bytes"], 0,
        "a rejected call produced nothing"
    );
    assert_eq!(records[1]["outcome"], "failed");
    assert_eq!(records[1]["produced_bytes"], 0);
}

#[test]
fn the_mcp_surface_is_recorded_too() {
    // Agents call through MCP; tracing only the CLI would measure the wrong path.
    let work = Work::with_demo_tools(true);
    let frame = word_frequency_frame("a b");
    let out = run(
        work.pk_with_config().arg("serve"),
        Some(format!("{frame}\n").as_bytes()),
    );
    assert!(out.status.success(), "{}", describe(&out));

    let records = work.trace_records();
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0]["surface"], "mcp");
    assert_eq!(records[0]["tool"], "word_frequency");
}

#[test]
fn timestamps_use_one_format_across_surfaces() {
    // A log with two timestamp formats cannot be sorted or filtered by time.
    let work = Work::with_demo_tools(true);
    let out = run(
        work.pk_with_config()
            .args(["run", "word_frequency", "-a", "text=a"]),
        None,
    );
    assert!(out.status.success(), "{}", describe(&out));
    let frame = word_frequency_frame("b");
    let out = run(
        work.pk_with_config().arg("serve"),
        Some(format!("{frame}\n").as_bytes()),
    );
    assert!(out.status.success(), "{}", describe(&out));

    let records = work.trace_records();
    assert_eq!(records.len(), 2, "{records:?}");
    let surfaces: Vec<&str> = records
        .iter()
        .map(|r| r["surface"].as_str().unwrap())
        .collect();
    assert_eq!(surfaces, ["cli", "mcp"]);
    for r in &records {
        let at = r["at"].as_str().unwrap();
        assert!(at.ends_with('Z') && at.contains('T'), "not RFC3339: {at}");
    }
}

#[test]
fn pk_trace_summarizes_the_recorded_calls() {
    let work = Work::with_demo_tools(true);
    for text in ["text=a b a", "text=c d"] {
        let out = run(
            work.pk_with_config()
                .args(["run", "word_frequency", "-a", text]),
            None,
        );
        assert!(out.status.success(), "{}", describe(&out));
    }

    let out = run(work.pk_with_config().arg("trace"), None);
    assert!(out.status.success(), "{}", describe(&out));
    let text = stdout_text(&out);
    assert!(text.contains("word_frequency"), "{text}");
    assert!(text.contains("2 calls"), "{text}");
}

#[test]
fn pk_trace_is_quiet_when_there_is_nothing_to_report() {
    let work = Work::new();
    let out = run(work.pk().arg("trace"), None);
    assert!(out.status.success(), "{}", describe(&out));
    assert!(
        stdout_text(&out).contains("no traces"),
        "{}",
        describe(&out)
    );
}
