//! The runner side of the builder tools (D22, design "Escalation protocol").
//!
//! The builder's `ask`, `check_ruling` and `run_check` tools run inside the
//! sandbox as a thin client (`cowproof lane-tools`). Each call is one request
//! over the lane's Unix socket; this module answers it outside the sandbox and
//! alone owns the escalation queue, the rulings and the check records.
//!
//! # Protocol
//!
//! Newline-delimited JSON on a stream: one request line, one response line.
//! A request line is at most [`MAX_LINE`] bytes; a longer one gets an error
//! response and the connection is closed. Malformed JSON gets an error
//! response and the connection stays open.
//!
//! ```text
//! {"op":"ask","ask":{...Ask fields...}}
//! {"op":"check_ruling","id":"<escalation id>"}
//! {"op":"run_check","id":"<check id>"}
//! ```
//!
//! Every response carries `"ok"`. A failure is `{"ok":false,"error":"..."}`.
//!
//! # Trust
//!
//! The builder is untrusted and everything it sends is data:
//!
//! - **The lane is never read from a request.** [`serve`] binds a listener to
//!   one lane, and every queue call uses that lane. A `lane` field (or any
//!   other field this module does not know) in a request is ignored.
//! - **An escalation id must be this lane's.** An id naming another lane or
//!   nothing at all gets the same "unknown escalation" error, so a builder
//!   cannot probe another lane's rulings.
//! - **`run_check` takes only a check id from the packet's table.** An id not
//!   in the table is an error and the callback is never called. The command
//!   itself stays with the runner's callback.
//! - **Notes are delivered once.** `check_ruling` returns the lane's pending
//!   notes and marks them delivered in the same call.

use crate::escalate::{Ask, EscalationId, LaneState, NoteId, Origin, Queue};
use crate::wire::{self, Read};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::future::Future;
use std::io;
use std::os::unix::fs::FileTypeExt;
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

/// The most check output returned to the builder, in bytes.
pub const MAX_OUTPUT: usize = 32 * 1024;

pub use wire::MAX_LINE;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The check ids the packet declares. `run_check` accepts nothing else.
pub type CheckTable = BTreeSet<String>;

/// Runs one declared check in a fresh sandbox and reports what it observed.
/// It is given the check id only; the command stays on the runner's side.
pub type RunCheck = Arc<dyn Fn(&str) -> BoxFuture<'static, CheckOutcome> + Send + Sync>;

/// How a `run_check` command ended. Serialized as the capsule's `end` field of a check
/// (`{"kind":"exited","code":0}`, `{"kind":"signaled","signal":9}`, `{"kind":"timed_out"}`,
/// `{"kind":"not_run"}`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CheckEnd {
    /// The command exited on its own with this status.
    Exited { code: i32 },
    /// The command was ended by this signal that nobody on the runner's side sent.
    Signaled { signal: i32 },
    /// The command ran past its limit and the runner killed its process group.
    TimedOut,
    /// The command never started (no sandbox, no such check, the host could not be reached).
    NotRun,
}

/// What running a check produced. Only the exit status decides pass or fail; the output
/// is for the builder to read, and the rest is what the capsule records about the run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckOutcome {
    /// The command's exit code, or -1 when it had none (a signal, the timeout, never started).
    pub exit_status: i32,
    /// The command's stdout then stderr (or the refusal's reason).
    pub output: String,
    /// How the command ended.
    pub end: CheckEnd,
    /// The command's wall-clock time in milliseconds, from just before it started to just after
    /// its group was reaped. Zero for a command that never started.
    pub duration_ms: u64,
}

impl CheckOutcome {
    /// A command that exited by itself with `code`.
    pub fn exited(code: i32, output: impl Into<String>, duration_ms: u64) -> Self {
        Self {
            exit_status: code,
            output: output.into(),
            end: CheckEnd::Exited { code },
            duration_ms,
        }
    }

    /// A command that never ran, with the reason as its output.
    pub fn not_run(output: impl Into<String>) -> Self {
        Self {
            exit_status: -1,
            output: output.into(),
            end: CheckEnd::NotRun,
            duration_ms: 0,
        }
    }
}

/// Bind the lane's socket, replacing a stale socket file left by a previous
/// run. Anything else at that path is an error and is left alone.
pub fn bind(path: &Path) -> io::Result<UnixListener> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => std::fs::remove_file(path)?,
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("{} exists and is not a socket", path.display()),
            ));
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    UnixListener::bind(path)
}

/// Why the runner should end the builder's session (D9: "the runner ends the
/// session"). The tools server sends one when a call leaves the lane parked, so
/// the run loop does not depend on the builder exiting by itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionEnd {
    /// A blocking `ask` parked the lane.
    Parked(EscalationId),
    /// The runner forced an escalation (escalate-early).
    Forced(EscalationId),
    /// A call hit the escalation limit and the lane ended as
    /// `escalation-limit`; nothing is parked, but nothing more may run.
    LimitReached,
    /// The lane's wall-clock limit ran out. Only the launcher decides this, so
    /// it is never sent through [`SessionEndSignal`].
    Timeout,
    /// The running cost estimate reached 100% of the cap: the lane ends now,
    /// without a grace period, and is not proved.
    CostCap,
    /// The director ruled stop, reassign or redirect on a NON-blocking ask
    /// while the builder was running: the session ends at once, with no
    /// grace period, and the resume loop acts on the ruling. Only the
    /// launcher decides this (it hears of the ruling on the director's wake
    /// channel), so it is never sent through [`SessionEndSignal`].
    Ruled(EscalationId),
}

/// Where [`serve_signalling`] sends a [`SessionEnd`]. Create the channel
/// BEFORE the builder is spawned so no signal can be missed.
pub type SessionEndSignal = tokio::sync::mpsc::UnboundedSender<SessionEnd>;

struct Context {
    lane: String,
    queue: Arc<Mutex<Queue>>,
    checks: CheckTable,
    run: RunCheck,
    end: Option<SessionEndSignal>,
}

impl Context {
    fn signal(&self, end: SessionEnd) {
        if let Some(tx) = &self.end {
            // A closed receiver means the run loop is gone; nothing to end.
            let _ = tx.send(end);
        }
    }

    /// After a refused queue call: did the lane end at the escalation limit?
    fn signal_if_limit_reached(&self) {
        let ended = self
            .queue
            .lock()
            .map(|q| q.lane_state(&self.lane) == Some(LaneState::EscalationLimit))
            .unwrap_or(false);
        if ended {
            self.signal(SessionEnd::LimitReached);
        }
    }
}

/// Serve the builder tools for one lane until the listener fails.
///
/// `lane` is the only lane any request can act on. The caller owns the
/// listener's lifetime: dropping or aborting the task ends the service.
pub async fn serve(
    listener: UnixListener,
    lane: String,
    queue: Arc<Mutex<Queue>>,
    checks: CheckTable,
    run: RunCheck,
) -> io::Result<()> {
    serve_signalling(listener, lane, queue, checks, run, None).await
}

/// [`serve`], and a call that parks the lane (a blocking `ask`, or a
/// `run_check` that forces an escalation) or ends it at the escalation limit
/// also sends a [`SessionEnd`] to `end`. The signal is sent as soon as the
/// queue has recorded the escalation, before the reply reaches the builder.
pub async fn serve_signalling(
    listener: UnixListener,
    lane: String,
    queue: Arc<Mutex<Queue>>,
    checks: CheckTable,
    run: RunCheck,
    end: Option<SessionEndSignal>,
) -> io::Result<()> {
    let ctx = Arc::new(Context {
        lane,
        queue,
        checks,
        run,
        end,
    });
    loop {
        let stream = match listener.accept().await {
            Ok((stream, _)) => stream,
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::ConnectionAborted | io::ErrorKind::Interrupted
                ) =>
            {
                continue;
            }
            Err(e) => return Err(e),
        };
        let ctx = ctx.clone();
        tokio::spawn(async move {
            // A broken connection is the client's loss; nothing to report.
            let _ = handle_connection(stream, &ctx).await;
        });
    }
}

async fn handle_connection(stream: UnixStream, ctx: &Context) -> io::Result<()> {
    let (read, mut write) = stream.into_split();
    let mut read = BufReader::new(read);
    loop {
        let response = match wire::read_line_capped(&mut read, wire::MAX_LINE).await? {
            Read::Eof => return Ok(()),
            Read::TooLong => {
                let max_line = wire::MAX_LINE;
                wire::send(
                    &mut write,
                    &wire::failure(&format!("request line exceeds {max_line} bytes")),
                )
                .await?;
                // Close, but only after the client has had the chance to read
                // the error: closing a socket with unread input can reset it.
                write.shutdown().await?;
                let mut sink = vec![0u8; 8192];
                let mut drained = 0usize;
                let _ = tokio::time::timeout(wire::DRAIN_TIME, async {
                    while let Ok(n) = read.read(&mut sink).await {
                        drained += n;
                        if n == 0 || drained > wire::DRAIN_LIMIT {
                            break;
                        }
                    }
                })
                .await;
                return Ok(());
            }
            Read::Line(bytes) => dispatch(&bytes, ctx).await,
        };
        wire::send(&mut write, &response).await?;
    }
}

/// Only the fields this module reads. Everything else, including any `lane`,
/// is dropped by deserialization and never consulted.
#[derive(Deserialize)]
struct Request {
    op: String,
    #[serde(default)]
    ask: Option<Value>,
    #[serde(default)]
    id: Option<String>,
}

async fn dispatch(line: &[u8], ctx: &Context) -> Value {
    let request: Request = match serde_json::from_slice(line) {
        Ok(r) => r,
        Err(e) => return wire::failure(&format!("malformed request: {e}")),
    };
    let result = match request.op.as_str() {
        "ask" => ask(ctx, request.ask),
        "check_ruling" => check_ruling(ctx, request.id),
        "run_check" => run_check(ctx, request.id).await,
        _ => Err("unknown op".to_string()),
    };
    match result {
        Ok(v) => v,
        Err(e) => wire::failure(&e),
    }
}

fn lock(queue: &Mutex<Queue>) -> Result<std::sync::MutexGuard<'_, Queue>, String> {
    queue
        .lock()
        .map_err(|_| "the escalation queue is unavailable".to_string())
}

fn ask(ctx: &Context, ask: Option<Value>) -> Result<Value, String> {
    let ask: Ask = serde_json::from_value(ask.ok_or("missing ask")?)
        .map_err(|e| format!("invalid ask: {e}"))?;
    let asked = lock(&ctx.queue)?.ask(&ctx.lane, &ask, Origin::Builder);
    let id = match asked {
        Ok(id) => id,
        Err(e) => {
            ctx.signal_if_limit_reached();
            return Err(e);
        }
    };
    if ask.blocking {
        ctx.signal(SessionEnd::Parked(id.clone()));
    }
    Ok(json!({
        "ok": true,
        "id": id.0,
        "status": if ask.blocking { "parked" } else { "asked" },
    }))
}

/// The escalation id as this lane would have minted it: `<lane>:E<digits>`.
/// A lane id never contains `:` (`[A-Za-z0-9._-]`), so another lane's id can
/// never take this shape for this lane.
fn own_escalation_id(lane: &str, id: &str) -> Option<EscalationId> {
    let n = id.strip_prefix(lane)?.strip_prefix(":E")?;
    if n.is_empty() || !n.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(EscalationId::from_string(id.to_string()))
}

/// This lane's undelivered notes, oldest first, ordered by numeric sequence.
/// `Queue::pending_notes` now returns only this lane's notes and orders them numerically.
fn own_pending_notes(queue: &Queue, lane: &str) -> Vec<(u64, NoteId, String)> {
    queue
        .pending_notes(lane)
        .into_iter()
        .filter_map(|(id, text)| {
            let digits = id.0.split('-').next_back()?.strip_prefix('n')?;
            if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            let n = digits.parse().ok()?;
            Some((n, id, text))
        })
        .collect()
}

fn check_ruling(ctx: &Context, id: Option<String>) -> Result<Value, String> {
    let mut queue = lock(&ctx.queue)?;
    let notes = own_pending_notes(&queue, &ctx.lane);
    if !notes.is_empty() {
        let ids: Vec<NoteId> = notes.iter().map(|(_, id, _)| id.clone()).collect();
        queue.mark_notes_delivered(&ctx.lane, &ids)?;
    }
    let notes: Vec<Value> = notes
        .into_iter()
        .map(|(_, id, text)| json!({ "id": id.0, "text": text }))
        .collect();

    // If no id provided, return notes only with no_escalation status
    if id.is_none() {
        return Ok(json!({
            "ok": true,
            "status": "no_escalation",
            "notes": notes,
        }));
    }

    let unknown = || "unknown escalation".to_string();
    let id = own_escalation_id(&ctx.lane, &id.unwrap()).ok_or_else(unknown)?;
    let verdict = queue.get(&id).ok_or_else(unknown)?.2.cloned();

    Ok(match verdict {
        None => json!({ "ok": true, "status": "pending", "notes": notes }),
        Some(v) => json!({
            "ok": true,
            "status": "ruled",
            "verdict": serde_json::to_value(v).map_err(|e| e.to_string())?,
            "notes": notes,
        }),
    })
}

async fn run_check(ctx: &Context, id: Option<String>) -> Result<Value, String> {
    let id = id.ok_or("missing id")?;
    if !ctx.checks.contains(&id) {
        return Err("unknown check id".to_string());
    }
    let outcome = (ctx.run)(&id).await;
    let passed = outcome.exit_status == 0;
    // What this run was, for the capsule: kept apart from the pass or fail the escalate-early
    // rule reads, and counted even when recording the pass or fail fails.
    let mut queue = lock(&ctx.queue)?;
    queue.record_check_run(&ctx.lane, &id, &outcome);
    let recorded = queue.record_check(&ctx.lane, &id, passed);
    drop(queue);
    let escalation = match recorded {
        Ok(escalation) => escalation,
        Err(e) => {
            ctx.signal_if_limit_reached();
            return Err(e);
        }
    };
    if let Some(forced) = &escalation {
        ctx.signal(SessionEnd::Forced(forced.clone()));
    }
    Ok(json!({
        "ok": true,
        "id": id,
        "passed": passed,
        "exit_status": outcome.exit_status,
        "output": truncate(&outcome.output, MAX_OUTPUT),
        "escalation": escalation.map(|e| e.0),
    }))
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}\n[output truncated]", &s[..end])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::escalate::{AskKind, CheckRunRecord, Opt, SystemClock, Verdict};
    use sha2::{Digest, Sha256};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tempfile::TempDir;
    use tokio::io::AsyncBufReadExt;
    use tokio::task::JoinHandle;

    const LANE: &str = "l1";

    struct Harness {
        _tmp: TempDir,
        sock: std::path::PathBuf,
        queue: Arc<Mutex<Queue>>,
        calls: Arc<AtomicUsize>,
        task: JoinHandle<io::Result<()>>,
    }

    impl Drop for Harness {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    /// A server on a real socket. Checks `c1` and `c2` are declared; `c1`
    /// exits with `exit_status`, and every call is counted.
    fn harness(exit_status: i32) -> Harness {
        harness_with(exit_status, None)
    }

    /// [`harness`] with a session-end signal.
    fn harness_with(exit_status: i32, end: Option<SessionEndSignal>) -> Harness {
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = calls.clone();
        let run: RunCheck = Arc::new(move |id: &str| -> BoxFuture<'static, CheckOutcome> {
            counter.fetch_add(1, Ordering::SeqCst);
            let output = format!("ran {id}");
            Box::pin(async move { CheckOutcome::exited(exit_status, output, 3) })
        });
        harness_running(run, calls, end)
    }

    /// A server whose `run_check` is `run`; `calls` is whatever count the caller keeps.
    fn harness_running(
        run: RunCheck,
        calls: Arc<AtomicUsize>,
        end: Option<SessionEndSignal>,
    ) -> Harness {
        let tmp = TempDir::new().unwrap();
        let sock_dir = tmp.path().join("sock");
        std::fs::create_dir(&sock_dir).unwrap();
        let sock = sock_dir.join("runner.sock");
        let queue = Arc::new(Mutex::new(
            Queue::new(&tmp.path().join("control"), Box::new(SystemClock)).unwrap(),
        ));
        let checks: CheckTable = ["c1", "c2"].iter().map(|s| s.to_string()).collect();
        let task = tokio::spawn(serve_signalling(
            bind(&sock).unwrap(),
            LANE.to_string(),
            queue.clone(),
            checks,
            run,
            end,
        ));
        Harness {
            _tmp: tmp,
            sock,
            queue,
            calls,
            task,
        }
    }

    struct Client {
        read: BufReader<tokio::net::unix::OwnedReadHalf>,
        write: tokio::net::unix::OwnedWriteHalf,
    }

    impl Client {
        async fn connect(h: &Harness) -> Self {
            let (read, write) = UnixStream::connect(&h.sock).await.unwrap().into_split();
            Client {
                read: BufReader::new(read),
                write,
            }
        }

        async fn send_raw(&mut self, bytes: &[u8]) {
            self.write.write_all(bytes).await.unwrap();
            self.write.flush().await.unwrap();
        }

        async fn recv(&mut self) -> Value {
            let mut line = String::new();
            self.read.read_line(&mut line).await.unwrap();
            serde_json::from_str(&line).unwrap_or_else(|e| panic!("bad response {line:?}: {e}"))
        }

        async fn call(&mut self, request: Value) -> Value {
            self.send_raw(format!("{request}\n").as_bytes()).await;
            self.recv().await
        }
    }

    fn sample_ask(blocking: bool) -> Value {
        json!({
            "kind": "design",
            "question": "which way?",
            "tried": ["read the docs"],
            "options": [{"id": "a", "summary": "first", "cost": "low"}],
            "recommend": "a",
            "blocking": blocking,
        })
    }

    fn sample_ask_typed() -> Ask {
        Ask {
            kind: AskKind::Design,
            question: "other lane question".into(),
            tried: vec![],
            options: vec![Opt {
                id: "a".into(),
                summary: "s".into(),
                cost: "c".into(),
            }],
            recommend: "a".into(),
            blocking: false,
        }
    }

    #[tokio::test]
    async fn ask_is_pending_until_ruled_and_then_check_ruling_returns_the_answer() {
        let h = harness(0);
        let mut c = Client::connect(&h).await;

        let asked = c.call(json!({"op": "ask", "ask": sample_ask(false)})).await;
        assert_eq!(asked["ok"], true, "{asked}");
        assert_eq!(asked["status"], "asked");
        let id = asked["id"].as_str().unwrap().to_string();
        assert_eq!(id, "l1:E1");

        let pending = c.call(json!({"op": "check_ruling", "id": id})).await;
        assert_eq!(pending["status"], "pending", "{pending}");
        assert!(pending.get("verdict").is_none(), "{pending}");

        h.queue
            .lock()
            .unwrap()
            .rule(
                LANE,
                &EscalationId::from_string(id.clone()),
                &Verdict::Answer {
                    text: "go with a".into(),
                },
            )
            .unwrap();

        let ruled = c.call(json!({"op": "check_ruling", "id": id})).await;
        assert_eq!(ruled["status"], "ruled", "{ruled}");
        assert_eq!(
            ruled["verdict"],
            json!({"verdict": "answer", "text": "go with a"})
        );
    }

    #[tokio::test]
    async fn a_blocking_ask_answers_parked() {
        let h = harness(0);
        let mut c = Client::connect(&h).await;
        let asked = c.call(json!({"op": "ask", "ask": sample_ask(true)})).await;
        assert_eq!(asked["status"], "parked", "{asked}");
    }

    #[tokio::test]
    async fn a_note_comes_down_on_check_ruling_once() {
        let h = harness(0);
        let mut c = Client::connect(&h).await;
        let asked = c.call(json!({"op": "ask", "ask": sample_ask(false)})).await;
        let id = asked["id"].as_str().unwrap().to_string();
        h.queue
            .lock()
            .unwrap()
            .note(LANE, "mind the borrow")
            .unwrap();

        let first = c.call(json!({"op": "check_ruling", "id": id})).await;
        assert_eq!(first["notes"].as_array().unwrap().len(), 1, "{first}");
        assert_eq!(first["notes"][0]["text"], "mind the borrow");

        let second = c.call(json!({"op": "check_ruling", "id": id})).await;
        assert_eq!(second["notes"], json!([]), "{second}");
        assert!(h.queue.lock().unwrap().pending_notes(LANE).is_empty());
    }

    #[tokio::test]
    async fn run_check_with_an_undeclared_id_is_an_error_and_never_calls_the_runner() {
        let h = harness(0);
        let mut c = Client::connect(&h).await;
        let r = c.call(json!({"op": "run_check", "id": "rm -rf /"})).await;
        assert_eq!(r["ok"], false, "{r}");
        assert_eq!(h.calls.load(Ordering::SeqCst), 0);
        let r = c.call(json!({"op": "run_check"})).await;
        assert_eq!(r["ok"], false, "{r}");
        assert_eq!(h.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn run_check_with_a_declared_id_runs_once_and_two_failures_force_an_escalation() {
        let h = harness(1);
        let mut c = Client::connect(&h).await;

        let first = c.call(json!({"op": "run_check", "id": "c1"})).await;
        assert_eq!(h.calls.load(Ordering::SeqCst), 1);
        assert_eq!(first["passed"], false, "{first}");
        assert_eq!(first["exit_status"], 1);
        assert_eq!(first["output"], "ran c1");
        assert_eq!(first["escalation"], Value::Null);
        assert_eq!(h.queue.lock().unwrap().escalation_count(LANE), 0);

        let second = c.call(json!({"op": "run_check", "id": "c1"})).await;
        assert_eq!(h.calls.load(Ordering::SeqCst), 2);
        assert_eq!(second["escalation"], "l1:E1", "{second}");
        let queue = h.queue.lock().unwrap();
        assert_eq!(queue.escalation_count(LANE), 1);
        let (_, origin, verdict) = queue.get(&EscalationId::new(LANE, 1)).unwrap();
        assert!(matches!(origin, Origin::Forced { .. }), "{origin:?}");
        assert!(verdict.is_none());
    }

    #[tokio::test]
    async fn a_passing_check_between_failures_forces_nothing() {
        // Failures of different checks never add up.
        let h = harness(1);
        let mut c = Client::connect(&h).await;
        c.call(json!({"op": "run_check", "id": "c1"})).await;
        let r = c.call(json!({"op": "run_check", "id": "c2"})).await;
        assert_eq!(r["escalation"], Value::Null, "{r}");
        assert_eq!(h.queue.lock().unwrap().escalation_count(LANE), 0);
    }

    #[tokio::test]
    async fn a_request_naming_another_lane_acts_on_the_bound_lane_only() {
        let h = harness(1);
        // The other lane has an escalation with a ruling, and a note.
        {
            let mut q = h.queue.lock().unwrap();
            let id = q
                .ask("other", &sample_ask_typed(), Origin::Builder)
                .unwrap();
            q.rule(
                "other",
                &id,
                &Verdict::Answer {
                    text: "OTHER-SECRET".into(),
                },
            )
            .unwrap();
            q.note("other", "other-note").unwrap();
        }
        let mut c = Client::connect(&h).await;

        // ask: lands on the bound lane.
        let asked = c
            .call(json!({"op": "ask", "lane": "other", "ask": sample_ask(false)}))
            .await;
        assert_eq!(asked["id"], "l1:E1", "{asked}");

        // check_ruling for the other lane's escalation: refused, nothing leaks.
        let probe = c
            .call(json!({"op": "check_ruling", "lane": "other", "id": "other:E1"}))
            .await;
        assert_eq!(probe["ok"], false, "{probe}");
        assert!(!probe.to_string().contains("OTHER-SECRET"), "{probe}");
        // ... even though a lane field and a valid own id are sent together.
        let own = c
            .call(json!({"op": "check_ruling", "lane": "other", "id": "l1:E1"}))
            .await;
        assert_eq!(own["status"], "pending", "{own}");
        assert_eq!(own["notes"], json!([]), "{own}");

        // run_check: the two failures escalate the bound lane, not the other.
        for _ in 0..2 {
            c.call(json!({"op": "run_check", "lane": "other", "id": "c1"}))
                .await;
        }

        let queue = h.queue.lock().unwrap();
        // 1 ask + 1 forced escalation on l1; the other lane is as it was.
        assert_eq!(queue.escalation_count(LANE), 2);
        assert_eq!(queue.escalation_count("other"), 1);
        assert_eq!(queue.pending_notes("other").len(), 1);
    }

    #[tokio::test]
    async fn a_lane_whose_id_extends_ours_does_not_leak_notes_into_ours() {
        // Lane `l1` must not see lane `l1-x`'s notes. Both queues store notes with
        // recorded lane; `pending_notes` matches by exact equality.
        let h = harness(0);
        {
            let mut q = h.queue.lock().unwrap();
            q.note("l1-x", "belongs to l1-x").unwrap();
            assert_eq!(
                q.pending_notes(LANE).len(),
                0,
                "l1 should not see l1-x notes"
            );
            q.note(LANE, "mine").unwrap();
            assert_eq!(
                q.pending_notes(LANE).len(),
                1,
                "l1 should see only its own note"
            );
        }
        let mut c = Client::connect(&h).await;
        let asked = c.call(json!({"op": "ask", "ask": sample_ask(false)})).await;
        let id = asked["id"].as_str().unwrap().to_string();

        let r = c.call(json!({"op": "check_ruling", "id": id})).await;
        let texts: Vec<&str> = r["notes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| n["text"].as_str().unwrap())
            .collect();
        assert_eq!(texts, ["mine"], "{r}");
        let q = h.queue.lock().unwrap();
        assert_eq!(
            q.pending_notes("l1-x").len(),
            1,
            "l1-x's note is still pending"
        );
    }

    #[tokio::test]
    async fn notes_come_down_in_numeric_order() {
        let h = harness(0);
        {
            let mut q = h.queue.lock().unwrap();
            for i in 1..=10 {
                q.note(LANE, &format!("note {i}")).unwrap();
            }
        }
        let mut c = Client::connect(&h).await;
        let asked = c.call(json!({"op": "ask", "ask": sample_ask(false)})).await;
        let id = asked["id"].as_str().unwrap().to_string();
        let r = c.call(json!({"op": "check_ruling", "id": id})).await;
        let texts: Vec<String> = r["notes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| n["text"].as_str().unwrap().to_string())
            .collect();
        let expected: Vec<String> = (1..=10).map(|i| format!("note {i}")).collect();
        assert_eq!(texts, expected);
    }

    #[tokio::test]
    async fn check_ruling_without_id_returns_no_escalation_with_notes() {
        let h = harness(0);
        {
            let mut q = h.queue.lock().unwrap();
            q.note(LANE, "pending note").unwrap();
        }
        let mut c = Client::connect(&h).await;
        let r = c.call(json!({"op": "check_ruling"})).await;
        assert_eq!(r["ok"], true);
        assert_eq!(r["status"], "no_escalation");
        let notes = r["notes"].as_array().unwrap();
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0]["text"], "pending note");
    }

    #[tokio::test]
    async fn check_ruling_without_id_marks_notes_delivered_and_second_call_has_none() {
        let h = harness(0);
        {
            let mut q = h.queue.lock().unwrap();
            q.note(LANE, "first note").unwrap();
        }
        let mut c = Client::connect(&h).await;

        let r1 = c.call(json!({"op": "check_ruling"})).await;
        assert_eq!(r1["status"], "no_escalation");
        assert_eq!(r1["notes"].as_array().unwrap().len(), 1);

        let r2 = c.call(json!({"op": "check_ruling"})).await;
        assert_eq!(r2["status"], "no_escalation");
        assert_eq!(
            r2["notes"].as_array().unwrap().len(),
            0,
            "second call should have no notes"
        );
    }

    #[tokio::test]
    async fn a_line_over_64_kib_gets_an_error_and_the_connection_closes() {
        let h = harness(0);
        let mut c = Client::connect(&h).await;
        let mut big = vec![b'a'; 70 * 1024];
        big.push(b'\n');
        c.send_raw(&big).await;

        let r = c.recv().await;
        assert_eq!(r["ok"], false, "{r}");
        assert!(r["error"].as_str().unwrap().contains("exceeds"), "{r}");
        let mut rest = String::new();
        let n = c.read.read_line(&mut rest).await.unwrap();
        assert_eq!(n, 0, "connection must be closed, got {rest:?}");
        assert_eq!(h.queue.lock().unwrap().escalation_count(LANE), 0);
    }

    #[tokio::test]
    async fn a_line_of_exactly_64_kib_is_read_not_refused() {
        let h = harness(0);
        let mut c = Client::connect(&h).await;
        let mut line = vec![b'a'; MAX_LINE];
        line.push(b'\n');
        c.send_raw(&line).await;
        let r = c.recv().await;
        // Too long would say "exceeds"; this is read and found malformed.
        assert!(
            r["error"]
                .as_str()
                .unwrap()
                .starts_with("malformed request"),
            "{r}"
        );
        let ok = c.call(json!({"op": "ask", "ask": sample_ask(false)})).await;
        assert_eq!(ok["ok"], true, "connection should stay open: {ok}");
    }

    #[tokio::test]
    async fn malformed_json_gets_an_error_and_the_next_valid_request_succeeds() {
        let h = harness(0);
        let mut c = Client::connect(&h).await;
        c.send_raw(b"{not json\n").await;
        let bad = c.recv().await;
        assert_eq!(bad["ok"], false, "{bad}");
        assert!(
            bad["error"]
                .as_str()
                .unwrap()
                .starts_with("malformed request"),
            "{bad}"
        );
        let ok = c.call(json!({"op": "ask", "ask": sample_ask(false)})).await;
        assert_eq!(ok["ok"], true, "{ok}");
        assert_eq!(ok["id"], "l1:E1");
    }

    #[tokio::test]
    async fn an_invalid_ask_and_an_unknown_op_are_errors_that_change_nothing() {
        let h = harness(0);
        let mut c = Client::connect(&h).await;
        let mut ask = sample_ask(false);
        ask["recommend"] = json!("not-an-option");
        let r = c.call(json!({"op": "ask", "ask": ask})).await;
        assert_eq!(r["ok"], false, "{r}");
        let r = c.call(json!({"op": "ask"})).await;
        assert_eq!(r["ok"], false, "{r}");
        let r = c.call(json!({"op": "rule", "id": "l1:E1"})).await;
        assert_eq!(r["ok"], false, "{r}");
        assert_eq!(h.queue.lock().unwrap().escalation_count(LANE), 0);
    }

    #[tokio::test]
    async fn a_blocking_ask_signals_the_session_end_and_a_non_blocking_one_does_not() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let h = harness_with(0, Some(tx));
        let mut c = Client::connect(&h).await;
        let r = c.call(json!({"op": "ask", "ask": sample_ask(false)})).await;
        assert_eq!(r["status"], "asked", "{r}");
        assert!(rx.try_recv().is_err(), "a non-blocking ask parks nothing");
        let r = c.call(json!({"op": "ask", "ask": sample_ask(true)})).await;
        assert_eq!(r["status"], "parked", "{r}");
        assert_eq!(
            rx.try_recv().unwrap(),
            SessionEnd::Parked(EscalationId::from_string("l1:E2".into()))
        );
        assert!(rx.try_recv().is_err(), "one signal per park");
    }

    #[tokio::test]
    async fn a_run_check_that_forces_an_escalation_signals_the_session_end_once() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let h = harness_with(1, Some(tx));
        let mut c = Client::connect(&h).await;
        for _ in 0..4 {
            c.call(json!({"op": "run_check", "id": "c1"})).await;
        }
        assert_eq!(
            rx.try_recv().unwrap(),
            SessionEnd::Forced(EscalationId::from_string("l1:E1".into()))
        );
        assert!(
            rx.try_recv().is_err(),
            "four failures, one forced session end"
        );
    }

    #[tokio::test]
    async fn an_ask_past_the_escalation_limit_signals_the_lane_ended() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let h = harness_with(0, Some(tx));
        let mut c = Client::connect(&h).await;
        for _ in 0..3 {
            c.call(json!({"op": "ask", "ask": sample_ask(false)})).await;
        }
        assert!(rx.try_recv().is_err());
        let r = c.call(json!({"op": "ask", "ask": sample_ask(false)})).await;
        assert_eq!(r["ok"], false, "{r}");
        assert_eq!(rx.try_recv().unwrap(), SessionEnd::LimitReached);
    }

    #[test]
    fn bind_replaces_a_stale_socket_but_never_another_kind_of_file() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("runner.sock");
        // A leftover socket file from a previous run.
        std::os::unix::net::UnixListener::bind(&path).unwrap();
        assert!(
            std::fs::symlink_metadata(&path)
                .unwrap()
                .file_type()
                .is_socket()
        );
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async { bind(&path).unwrap() });

        let file = tmp.path().join("precious");
        std::fs::write(&file, "keep").unwrap();
        let err = rt.block_on(async { bind(&file) }).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "keep");
    }

    #[test]
    fn truncate_cuts_on_a_char_boundary() {
        let s = "é".repeat(10); // 20 bytes
        assert_eq!(
            truncate(&s, 5),
            format!("{}\n[output truncated]", "é".repeat(2))
        );
        assert_eq!(truncate("short", 100), "short");
    }
    /// A server whose `run_check` plays `outcomes` in order, one per call, whatever the id.
    fn harness_playing(outcomes: Vec<CheckOutcome>) -> Harness {
        let queue = Mutex::new(std::collections::VecDeque::from(outcomes));
        let run: RunCheck = Arc::new(move |_id: &str| -> BoxFuture<'static, CheckOutcome> {
            let next = queue.lock().unwrap().pop_front().expect("an outcome left");
            Box::pin(async move { next })
        });
        harness_running(run, Arc::new(AtomicUsize::new(0)), None)
    }

    fn sha256_of(text: &str) -> String {
        format!("{:x}", Sha256::digest(text.as_bytes()))
    }

    #[tokio::test]
    async fn a_failing_then_passing_check_records_two_attempts_and_the_passing_run() {
        let h = harness_playing(vec![
            CheckOutcome::exited(1, "bad\n", 11),
            CheckOutcome::exited(0, "good\n", 7),
            CheckOutcome::exited(0, "other\n", 5),
        ]);
        let mut c = Client::connect(&h).await;
        assert_eq!(
            c.call(json!({"op": "run_check", "id": "c1"})).await["passed"],
            false
        );
        assert_eq!(
            c.call(json!({"op": "run_check", "id": "c1"})).await["passed"],
            true
        );
        c.call(json!({"op": "run_check", "id": "c2"})).await;

        let runs = h.queue.lock().unwrap().check_runs(LANE);
        assert_eq!(
            runs["c1"],
            CheckRunRecord {
                attempts: 2,
                exit_status: 0,
                end: CheckEnd::Exited { code: 0 },
                duration_ms: 7,
                output_sha256: sha256_of("good\n"),
                output_len: 5,
            }
        );
        assert_eq!(runs["c2"].attempts, 1);
        assert_eq!(runs["c2"].output_sha256, sha256_of("other\n"));
        // A check never run has no record.
        assert!(h.queue.lock().unwrap().check_runs("other-lane").is_empty());
    }

    #[tokio::test]
    async fn attempts_count_over_the_whole_lane_and_survive_a_reassign() {
        let h = harness_playing(vec![
            CheckOutcome::exited(1, "a", 1),
            CheckOutcome::exited(0, "b", 1),
        ]);
        let mut c = Client::connect(&h).await;
        c.call(json!({"op": "run_check", "id": "c1"})).await;
        // `reassign` clears the pass or fail the escalate-early rule keeps; the count stays.
        h.queue.lock().unwrap().reassign(LANE).unwrap();
        assert!(h.queue.lock().unwrap().check_results(LANE).is_empty());
        c.call(json!({"op": "run_check", "id": "c1"})).await;
        assert_eq!(h.queue.lock().unwrap().check_runs(LANE)["c1"].attempts, 2);
    }

    #[tokio::test]
    async fn a_timeout_a_signal_and_a_refusal_are_recorded_as_such() {
        let timed_out = CheckOutcome {
            exit_status: -1,
            output: "timed out".into(),
            end: CheckEnd::TimedOut,
            duration_ms: 2000,
        };
        let signaled = CheckOutcome {
            exit_status: -1,
            output: String::new(),
            end: CheckEnd::Signaled { signal: 9 },
            duration_ms: 40,
        };
        let h = harness_playing(vec![
            timed_out,
            signaled,
            CheckOutcome::not_run("sandbox unavailable"),
        ]);
        let mut c = Client::connect(&h).await;
        for id in ["c1", "c2", "c1"] {
            let r = c.call(json!({"op": "run_check", "id": id})).await;
            assert_eq!(r["passed"], false, "{r}");
        }
        let runs = h.queue.lock().unwrap().check_runs(LANE);
        // c1 ran twice: the timeout, then the refusal, which is the last run.
        assert_eq!(runs["c1"].attempts, 2);
        assert_eq!(runs["c1"].end, CheckEnd::NotRun);
        assert_eq!(runs["c1"].duration_ms, 0);
        assert_eq!(runs["c2"].end, CheckEnd::Signaled { signal: 9 });
        assert_eq!(runs["c2"].exit_status, -1);
        assert_eq!(runs["c2"].output_len, 0);
    }

    #[tokio::test]
    async fn a_timed_out_last_run_is_recorded_and_the_ends_serialize_by_kind() {
        let h = harness_playing(vec![CheckOutcome {
            exit_status: -1,
            output: "timed out after 2s".into(),
            end: CheckEnd::TimedOut,
            duration_ms: 2001,
        }]);
        let mut c = Client::connect(&h).await;
        c.call(json!({"op": "run_check", "id": "c1"})).await;
        let run = h.queue.lock().unwrap().check_runs(LANE)["c1"].clone();
        assert_eq!(run.end, CheckEnd::TimedOut);
        assert_eq!(run.duration_ms, 2001);
        assert_eq!(
            serde_json::to_value(run.end).unwrap(),
            json!({"kind": "timed_out"})
        );
        assert_eq!(
            serde_json::to_value(CheckEnd::Signaled { signal: 15 }).unwrap(),
            json!({"kind": "signaled", "signal": 15})
        );
        assert_eq!(
            serde_json::to_value(CheckEnd::Exited { code: 3 }).unwrap(),
            json!({"kind": "exited", "code": 3})
        );
    }
}
