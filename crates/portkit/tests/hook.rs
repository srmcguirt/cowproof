//! Hook handling.
//!
//! Two properties matter most and neither is about detection quality: a hook
//! must never break the session it is measuring, and it must stay quiet often
//! enough that the agent still reads it when it speaks.

use assert_cmd::Command;

fn pk() -> Command {
    Command::cargo_bin("pk").expect("the pk binary must build")
}

fn traced() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("pk.toml"),
        "[trace]\nenabled = true\ndir = \"traces\"\n",
    )
    .unwrap();
    dir
}

fn hook(dir: &tempfile::TempDir, event: &str, payload: &str) -> String {
    let out = pk()
        .current_dir(dir.path())
        .args(["--config", "pk.toml", "hook", event])
        .write_stdin(payload.to_string())
        .assert()
        .success();
    String::from_utf8_lossy(&out.get_output().stdout).to_string()
}

fn read_call(dir: &tempfile::TempDir, session: &str, path: &str, bytes: usize) {
    let payload = serde_json::json!({
        "session_id": session,
        "hook_event_name": "PostToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": path},
        "tool_output": "x".repeat(bytes),
    });
    hook(dir, "post-tool-use", &payload.to_string());
}

fn ask(dir: &tempfile::TempDir, session: &str) -> String {
    hook(
        dir,
        "user-prompt-submit",
        &serde_json::json!({"session_id": session, "user_message": "go"}).to_string(),
    )
}

#[test]
fn a_malformed_payload_never_breaks_the_session() {
    // Interrupting the work being measured is worse than measuring nothing.
    let dir = traced();
    for bad in ["", "not json", "{\"truncated\":", "[]"] {
        pk().current_dir(dir.path())
            .args(["--config", "pk.toml", "hook", "post-tool-use"])
            .write_stdin(bad)
            .assert()
            .success();
    }
}

#[test]
fn an_unknown_event_is_ignored_quietly() {
    let dir = traced();
    let out = hook(&dir, "some-future-event", "{}");
    assert!(out.is_empty());
}

#[test]
fn tool_calls_portkit_did_not_serve_are_recorded() {
    // The measurement gap this closes: Read/Grep/Bash happen outside portkit.
    let dir = traced();
    read_call(&dir, "s1", "/repo/a.rs", 1234);

    let out = pk()
        .current_dir(dir.path())
        .args(["--config", "pk.toml", "trace"])
        .assert()
        .success();
    let text = String::from_utf8_lossy(&out.get_output().stdout).to_string();
    assert!(text.contains("Read"), "{text}");
}

#[test]
fn nothing_is_recorded_when_tracing_is_off() {
    let dir = tempfile::tempdir().unwrap();
    let payload = serde_json::json!({
        "session_id": "s", "tool_name": "Read",
        "tool_input": {"file_path": "/a.rs"}, "tool_output": "xxx"
    });
    pk().current_dir(dir.path())
        .args(["hook", "post-tool-use"])
        .write_stdin(payload.to_string())
        .assert()
        .success();
    assert!(!dir.path().join("traces").exists());
}

#[test]
fn a_legitimate_re_read_draws_no_comment() {
    // Reading again after an edit is normal; commenting on it is noise.
    let dir = traced();
    read_call(&dir, "s1", "/repo/a.rs", 4000);
    read_call(&dir, "s1", "/repo/a.rs", 4000);
    assert!(ask(&dir, "s1").is_empty());
}

#[test]
fn a_third_read_names_a_concrete_cheaper_call() {
    let dir = traced();
    for _ in 0..3 {
        read_call(&dir, "s1", "/repo/a.rs", 4000);
    }
    let out = ask(&dir, "s1");
    assert!(out.contains("/repo/a.rs"), "{out}");
    assert!(
        out.contains("pk run sym"),
        "advice must be actionable: {out}"
    );
}

#[test]
fn the_same_advice_is_not_repeated() {
    let dir = traced();
    for _ in 0..3 {
        read_call(&dir, "s1", "/repo/a.rs", 4000);
    }
    assert!(!ask(&dir, "s1").is_empty(), "first time should fire");
    read_call(&dir, "s1", "/repo/a.rs", 4000);
    assert!(ask(&dir, "s1").is_empty(), "second time must stay quiet");
}

#[test]
fn sessions_are_kept_separate() {
    // One agent's behaviour must not produce advice for another's.
    let dir = traced();
    for _ in 0..4 {
        read_call(&dir, "noisy", "/repo/a.rs", 4000);
    }
    read_call(&dir, "quiet", "/repo/b.rs", 100);
    assert!(ask(&dir, "quiet").is_empty());
    assert!(!ask(&dir, "noisy").is_empty());
}

#[test]
fn arguments_are_not_stored_only_what_the_call_was_about() {
    // A trace bank full of file contents would be its own problem.
    let dir = traced();
    let payload = serde_json::json!({
        "session_id": "s1", "tool_name": "Write",
        "tool_input": {"file_path": "/repo/secret.rs", "content": "SUPERSECRETVALUE"},
        "tool_output": "ok"
    });
    hook(&dir, "post-tool-use", &payload.to_string());

    let traces = std::fs::read_dir(dir.path().join("traces")).unwrap();
    for entry in traces.filter_map(Result::ok) {
        if entry.path().extension().is_some_and(|e| e == "jsonl") {
            let text = std::fs::read_to_string(entry.path()).unwrap();
            assert!(
                !text.contains("SUPERSECRETVALUE"),
                "content leaked into the trace bank"
            );
            assert!(
                text.contains("/repo/secret.rs"),
                "but the target should be there"
            );
        }
    }
}
