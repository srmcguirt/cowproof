//! Claude Code hook handlers.
//!
//! Two jobs. First, close the measurement gap: portkit's traces only ever saw
//! portkit's own tools, while the expensive calls — `Read`, `Grep`, `Bash` —
//! happen outside it. `PostToolUse` records those too, so the trace bank
//! measures the agent rather than measuring portkit measuring itself.
//!
//! Second, say something when the data says it is worth saying. Suggestions go
//! out on `UserPromptSubmit`, because that is the point where injected text is
//! shown to the model and where it is least disruptive.
//!
//! # A hook must never break the session
//!
//! Every failure here exits 0 with no output. A malformed payload, an
//! unwritable trace file, a missing directory — none of that is worth
//! interrupting the work being measured.

use std::io::Read as _;
use std::path::PathBuf;
use std::process::ExitCode;

use serde::Deserialize;
use serde_json::{json, Value};

use portkit_core::rewrite::{detect_definition_search, fingerprint, Rewrite};
use portkit_core::trace::{self, CallRecord, JsonlRecorder, Outcome, Recorder, Surface};
use portkit_core::watch::{inspect, Thresholds};
use portkit_core::Config;

/// The subset of the hook payload we use. Unknown fields are ignored, so new
/// ones in Claude Code cannot break this.
#[derive(Debug, Default, Deserialize)]
struct Payload {
    #[serde(default)]
    session_id: String,
    #[serde(default)]
    tool_name: String,
    #[serde(default)]
    tool_input: Value,
    #[serde(default)]
    tool_output: Value,
}

/// Handle one hook event. Always exits successfully.
pub fn run(event: &str, config: &Config) -> ExitCode {
    let mut raw = String::new();
    if std::io::stdin().read_to_string(&mut raw).is_err() {
        return ExitCode::SUCCESS;
    }
    let payload: Payload = serde_json::from_str(&raw).unwrap_or_default();

    match event {
        "pre-tool-use" => rewrite(&payload, config),
        // Both mean the same thing to a delivery ledger: what we sent may no
        // longer be in the caller's context.
        "pre-compact" | "session-start" => mark_compacted(&payload),
        "post-tool-use" => record(&payload, config),
        "user-prompt-submit" => suggest(&payload, config),
        "session-end" => summarize(&payload, config),
        _ => {}
    }
    ExitCode::SUCCESS
}

/// Treat everything delivered so far as gone.
///
/// `pk-read` answers UNCHANGED on the strength of having sent something
/// earlier in the session. Compaction drops old tool results, so "we sent it"
/// stops implying "they still have it" — and it stops implying that exactly
/// when a re-read matters most. Without this watermark the reference class is
/// unsafe, so it ships with it rather than after it.
fn mark_compacted(payload: &Payload) {
    if payload.session_id.is_empty() {
        return;
    }
    let safe: String = payload
        .session_id
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
        .take(48)
        .collect();
    let path = PathBuf::from(".portkit")
        .join("read")
        .join(format!("{safe}.json"));

    let mut state = portkit_read::SessionState::load(&path);
    state.mark_compacted(portkit_read::now_rfc3339());
    // Failing to write means the next UNCHANGED could be a lie, so say so —
    // silence here is the one place it is not safe.
    if let Err(err) = state.save(&path) {
        eprintln!("portkit: could not record compaction watermark: {err}");
    }
}

/// How hot a command shape must be before a rewrite is worth verifying.
///
/// Count alone ranks `true` (67 calls, 31 bytes) with `sed -n` (185 calls,
/// 4,948 bytes each). Weighting by what a shape actually costs separates them,
/// and keeps the verification tax off commands that are cheap anyway.
const MIN_REPEATS: usize = 3;
const MIN_TOTAL_BYTES: usize = 4_096;

/// Rewrite a hot, verifiably-replaceable command into a cheaper one.
///
/// Returns nothing at all in every uncertain case. A wrong rewrite is
/// unrecoverable — the agent never sees the command it asked for — so the bar
/// is a verified answer, not a plausible one.
fn rewrite(payload: &Payload, config: &Config) {
    if payload.tool_name != "Bash" {
        // additionalContext does not surface on MCP tool calls, and rewriting
        // anything but a shell command is out of scope.
        return;
    }
    let Some(command) = payload.tool_input.get("command").and_then(Value::as_str) else {
        return;
    };

    let Some(candidate) = detect_definition_search(command) else {
        return;
    };
    if !is_hot(config, command) {
        return;
    }
    // Verification runs the replacement for real. Skipped for cold shapes so
    // the cost lands only where a rewrite is actually in prospect.
    if !verifies(&candidate) {
        return;
    }

    let mut updated = payload.tool_input.clone();
    if let Some(obj) = updated.as_object_mut() {
        obj.insert("command".into(), Value::String(candidate.command.clone()));
    }

    let out = json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "updatedInput": updated,
            // One line, once — enough for the agent to learn the tool exists
            // without paying for a reminder on every call.
            "additionalContext": candidate.note,
        }
    });
    println!("{out}");
}

/// Has this command shape been run often enough, and cost enough, to bother?
fn is_hot(config: &Config, command: &str) -> bool {
    if !config.trace.enabled {
        // Without a ledger there is no evidence, and a rewrite on no evidence
        // is a guess.
        return false;
    }
    let path = trace_dir(config).join(format!("{}.jsonl", today()));
    let Ok(records) = trace::read_jsonl(&path) else {
        return false;
    };

    let shape = fingerprint(command);
    let matching: Vec<&CallRecord> = records
        .iter()
        .filter(|r| {
            r.target.as_deref().is_some_and(|t| {
                shape.starts_with(t) || t.starts_with(&shape[..shape.len().min(12)])
            })
        })
        .collect();

    let total: usize = matching.iter().map(|r| r.delivered_bytes).sum();
    matching.len() >= MIN_REPEATS && total >= MIN_TOTAL_BYTES
}

/// Run the replacement and check it answers the question.
///
/// The gate is "contains what the original would have matched", not "produces
/// the same bytes". Byte-equality would forbid the whole point: a symbol
/// lookup returns 40-60x less than the file, and cannot be byte-equal to a
/// grep over it.
fn verifies(candidate: &Rewrite) -> bool {
    let Some((program, args)) = split_command(&candidate.command) else {
        return false;
    };
    let Ok(output) = std::process::Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::null())
        .output()
    else {
        return false;
    };
    if !output.status.success() {
        return false;
    }
    String::from_utf8_lossy(&output.stdout).contains(&candidate.verify_contains)
}

/// Split our own generated command. Not a shell parser — it only ever sees
/// strings this crate produced.
fn split_command(command: &str) -> Option<(String, Vec<String>)> {
    let mut parts = command.split_whitespace().map(str::to_string);
    let program = parts.next()?;
    Some((program, parts.collect()))
}

fn trace_dir(config: &Config) -> PathBuf {
    PathBuf::from(&config.trace.dir)
}

fn today() -> String {
    let d = time::OffsetDateTime::now_utc().date();
    format!("{:04}-{:02}-{:02}", d.year(), u8::from(d.month()), d.day())
}

/// What a call was about — enough to spot the same target twice, without
/// storing arguments, which would put file contents into the trace bank.
fn target_of(tool: &str, input: &Value) -> Option<String> {
    let s = |k: &str| input.get(k).and_then(Value::as_str).map(str::to_string);
    match tool {
        "Read" | "NotebookRead" | "Edit" | "Write" | "NotebookEdit" => s("file_path"),
        "WebFetch" => s("url"),
        "WebSearch" => s("query"),
        "Grep" | "Glob" => s("pattern"),
        // Commands vary in their arguments; the head is what repeats.
        "Bash" => s("command").map(|c| {
            c.split_whitespace()
                .take(2)
                .collect::<Vec<_>>()
                .join(" ")
                .chars()
                .take(60)
                .collect()
        }),
        _ => s("file_path").or_else(|| s("path")).or_else(|| s("name")),
    }
}

fn output_bytes(output: &Value) -> usize {
    match output {
        Value::String(s) => s.len(),
        Value::Null => 0,
        other => serde_json::to_vec(other).map(|v| v.len()).unwrap_or(0),
    }
}

fn record(payload: &Payload, config: &Config) {
    if !config.trace.enabled || payload.tool_name.is_empty() {
        return;
    }
    let path = trace_dir(config).join(format!("{}.jsonl", today()));
    let Ok(recorder) = JsonlRecorder::create(&path) else {
        return;
    };

    let bytes = output_bytes(&payload.tool_output);
    recorder.record(CallRecord {
        tool: payload.tool_name.clone(),
        session: payload.session_id.clone(),
        target: target_of(&payload.tool_name, &payload.tool_input),
        surface: Surface::Agent,
        outcome: Outcome::Ok,
        at: trace::now_rfc3339(),
        duration_ms: 0.0, // the hook sees the result, not the call
        input_bytes: serde_json::to_vec(&payload.tool_input)
            .map(|v| v.len())
            .unwrap_or(0),
        produced_bytes: bytes,
        // Nothing budgeted it; what arrived is what context paid for.
        delivered_bytes: bytes,
        elisions: 0,
    });
}

/// Where the targets already mentioned this session are remembered, so the
/// same advice is not repeated.
fn said_path(config: &Config, session: &str) -> PathBuf {
    let short: String = session.chars().take(32).collect();
    trace_dir(config).join("said").join(format!("{short}.txt"))
}

fn load_said(path: &PathBuf) -> Vec<String> {
    std::fs::read_to_string(path)
        .map(|s| s.lines().map(str::to_string).collect())
        .unwrap_or_default()
}

fn suggest(payload: &Payload, config: &Config) {
    if !config.trace.enabled {
        return;
    }
    let path = trace_dir(config).join(format!("{}.jsonl", today()));
    let Ok(all) = trace::read_jsonl(&path) else {
        return;
    };

    let mine: Vec<CallRecord> = all
        .into_iter()
        .filter(|r| r.session == payload.session_id)
        .collect();
    let said_at = said_path(config, &payload.session_id);
    let said = load_said(&said_at);

    let Some(s) = inspect(&mine, &said, &Thresholds::default()) else {
        return;
    };

    // Remember before printing: a crash after the advice would otherwise
    // repeat it next turn.
    if let Some(parent) = said_at.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let mut updated = said;
    updated.push(s.target.clone());
    let _ = std::fs::write(&said_at, updated.join("\n"));

    // Plain text on UserPromptSubmit is added as context the model can see.
    println!("portkit: {}", s.message);
}

fn summarize(payload: &Payload, config: &Config) {
    if !config.trace.enabled {
        return;
    }
    let path = trace_dir(config).join(format!("{}.jsonl", today()));
    let Ok(all) = trace::read_jsonl(&path) else {
        return;
    };
    let mine: Vec<&CallRecord> = all
        .iter()
        .filter(|r| r.session == payload.session_id)
        .collect();
    if mine.is_empty() {
        return;
    }

    let delivered: usize = mine.iter().map(|r| r.delivered_bytes).sum();
    let saved: usize = mine.iter().map(|r| r.saved_bytes()).sum();
    // stderr: session-end stdout is not shown as context, and this is for the
    // human reading their terminal.
    eprintln!(
        "portkit: {} calls, {:.1} KB delivered, {:.1} KB kept out of context",
        mine.len(),
        delivered as f64 / 1000.0,
        saved as f64 / 1000.0
    );

    // The said-list is per session; clean up rather than accumulate files.
    let _ = std::fs::remove_file(said_path(config, &payload.session_id));
}
