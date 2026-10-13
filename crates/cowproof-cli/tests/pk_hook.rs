//! `pk hook`, restored from portkit's `tests/hook.rs`.
//!
//! Two properties matter most and neither is about detection quality: a hook must never
//! break the session it is measuring, and it must stay quiet often enough that the agent
//! still reads it when it speaks. Every command here is the real `pk` binary with a
//! throwaway home and working directory; the trace directory is `traces` under the working
//! directory (`pk_support::Work`).
//!
//! `pk.rs` covers where the hook writes under `PORTKIT_STATE_DIR` and `pk doctor`.

#[allow(dead_code)] // this file needs only the fork lock, `var_tmp` and the signal helper
mod common;
mod pk_support;

use pk_support::{Work, describe, run, stdout_text};
use serde_json::json;

/// A working directory whose `pk.toml` turns tracing on.
fn traced() -> Work {
    let work = Work::new();
    std::fs::write(
        work.cwd.join("pk.toml"),
        "[trace]\nenabled = true\ndir = \"traces\"\n",
    )
    .unwrap();
    work
}

/// Run `pk hook <event>` with `payload` on stdin; it must exit 0. Returns its stdout.
fn hook(work: &Work, event: &str, payload: &str) -> String {
    let out = run(
        work.pk_with_config().args(["hook", event]),
        Some(payload.as_bytes()),
    );
    assert!(out.status.success(), "{}", describe(&out));
    stdout_text(&out)
}

fn read_call(work: &Work, session: &str, path: &str, bytes: usize) {
    let payload = json!({
        "session_id": session,
        "hook_event_name": "PostToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": path},
        "tool_output": "x".repeat(bytes),
    });
    hook(work, "post-tool-use", &payload.to_string());
}

fn ask(work: &Work, session: &str) -> String {
    hook(
        work,
        "user-prompt-submit",
        &json!({"session_id": session, "user_message": "go"}).to_string(),
    )
}

#[test]
fn a_malformed_payload_never_breaks_the_session() {
    // Interrupting the work being measured is worse than measuring nothing.
    let work = traced();
    for bad in ["", "not json", "{\"truncated\":", "[]"] {
        let out = run(
            work.pk_with_config().args(["hook", "post-tool-use"]),
            Some(bad.as_bytes()),
        );
        assert!(out.status.success(), "{bad:?}: {}", describe(&out));
        assert_eq!(out.stdout, b"", "{bad:?}: {}", describe(&out));
    }
}

#[test]
fn an_unknown_event_is_ignored_quietly() {
    let work = traced();
    assert!(hook(&work, "some-future-event", "{}").is_empty());
}

#[test]
fn tool_calls_portkit_did_not_serve_are_recorded() {
    // The measurement gap this closes: Read/Grep/Bash happen outside portkit.
    let work = traced();
    read_call(&work, "s1", "/repo/a.rs", 1234);

    let records = work.trace_records();
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0]["tool"], "Read");
    assert_eq!(records[0]["target"], "/repo/a.rs");
    assert_eq!(records[0]["session"], "s1");
    assert_eq!(records[0]["produced_bytes"], 1234);

    let out = run(work.pk_with_config().arg("trace"), None);
    assert!(out.status.success(), "{}", describe(&out));
    let text = stdout_text(&out);
    assert!(text.contains("Read"), "{text}");
}

#[test]
fn nothing_is_recorded_when_tracing_is_off() {
    let work = Work::new();
    let payload = json!({
        "session_id": "s", "tool_name": "Read",
        "tool_input": {"file_path": "/a.rs"}, "tool_output": "xxx"
    });
    let out = run(
        work.pk().args(["hook", "post-tool-use"]),
        Some(payload.to_string().as_bytes()),
    );
    assert!(out.status.success(), "{}", describe(&out));
    assert!(!work.cwd.join("traces").exists());
    assert!(!work.cwd.join(".portkit").exists());
}

#[test]
fn a_legitimate_re_read_draws_no_comment() {
    // Reading again after an edit is normal; commenting on it is noise.
    let work = traced();
    read_call(&work, "s1", "/repo/a.rs", 4000);
    read_call(&work, "s1", "/repo/a.rs", 4000);
    assert!(ask(&work, "s1").is_empty());
}

#[test]
fn a_third_read_names_a_concrete_cheaper_call() {
    let work = traced();
    for _ in 0..3 {
        read_call(&work, "s1", "/repo/a.rs", 4000);
    }
    let out = ask(&work, "s1");
    assert!(out.contains("/repo/a.rs"), "{out}");
    assert!(
        out.contains("pk run sym"),
        "advice must be actionable: {out}"
    );
}

#[test]
fn the_same_advice_is_not_repeated() {
    let work = traced();
    for _ in 0..3 {
        read_call(&work, "s1", "/repo/a.rs", 4000);
    }
    assert!(!ask(&work, "s1").is_empty(), "first time should fire");
    read_call(&work, "s1", "/repo/a.rs", 4000);
    assert!(ask(&work, "s1").is_empty(), "second time must stay quiet");
}

#[test]
fn sessions_are_kept_separate() {
    // One agent's behaviour must not produce advice for another's.
    let work = traced();
    for _ in 0..4 {
        read_call(&work, "noisy", "/repo/a.rs", 4000);
    }
    read_call(&work, "quiet", "/repo/b.rs", 100);
    assert!(ask(&work, "quiet").is_empty());
    assert!(!ask(&work, "noisy").is_empty());
}

#[test]
fn arguments_are_not_stored_only_what_the_call_was_about() {
    // A trace bank full of file contents would be its own problem.
    let work = traced();
    let payload = json!({
        "session_id": "s1", "tool_name": "Write",
        "tool_input": {"file_path": "/repo/secret.rs", "content": "SUPERSECRETVALUE"},
        "tool_output": "ok"
    });
    hook(&work, "post-tool-use", &payload.to_string());

    let mut seen = 0;
    for entry in std::fs::read_dir(work.cwd.join("traces")).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|e| e == "jsonl") {
            let text = std::fs::read_to_string(&path).unwrap();
            assert!(
                !text.contains("SUPERSECRETVALUE"),
                "content leaked into the trace bank: {text}"
            );
            assert!(
                text.contains("/repo/secret.rs"),
                "but the target should be there: {text}"
            );
            seen += 1;
        }
    }
    assert_eq!(seen, 1, "exactly one trace file");
}
