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

use crate::escalate::{Ask, EscalationId, NoteId, Origin, Queue};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::future::Future;
use std::io;
use std::os::unix::fs::FileTypeExt;
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

/// The longest request line accepted, in bytes, not counting the newline.
pub const MAX_LINE: usize = 64 * 1024;

/// The most check output returned to the builder, in bytes.
const MAX_OUTPUT: usize = 32 * 1024;

/// After an over-long line the rest of the input is discarded for at most this
/// long and this much, so the error response is delivered before the close.
const DRAIN_LIMIT: usize = 4 * 1024 * 1024;
const DRAIN_TIME: Duration = Duration::from_millis(500);

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The check ids the packet declares. `run_check` accepts nothing else.
pub type CheckTable = BTreeSet<String>;

/// Runs one declared check in a fresh sandbox and reports what it observed.
/// It is given the check id only; the command stays on the runner's side.
pub type RunCheck = Arc<dyn Fn(&str) -> BoxFuture<'static, CheckOutcome> + Send + Sync>;

/// What running a check produced. Only the exit status is recorded as the
/// verdict; the output is for the builder to read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckOutcome {
    pub exit_status: i32,
    pub output: String,
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

struct Context {
    lane: String,
    queue: Arc<Mutex<Queue>>,
    checks: CheckTable,
    run: RunCheck,
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
    let ctx = Arc::new(Context {
        lane,
        queue,
        checks,
        run,
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

enum Read {
    Eof,
    Line(Vec<u8>),
    TooLong,
}

/// Read one line of at most `cap` bytes (not counting the newline).
async fn read_line_capped<R: AsyncBufRead + Unpin>(r: &mut R, cap: usize) -> io::Result<Read> {
    let mut buf: Vec<u8> = Vec::new();
    loop {
        let chunk = r.fill_buf().await?;
        if chunk.is_empty() {
            // EOF: an unterminated final line still counts as a line.
            return Ok(if buf.is_empty() {
                Read::Eof
            } else {
                Read::Line(buf)
            });
        }
        match chunk.iter().position(|b| *b == b'\n') {
            Some(i) => {
                if buf.len() + i > cap {
                    r.consume(i + 1);
                    return Ok(Read::TooLong);
                }
                buf.extend_from_slice(&chunk[..i]);
                r.consume(i + 1);
                return Ok(Read::Line(buf));
            }
            None => {
                let n = chunk.len();
                if buf.len() + n > cap {
                    r.consume(n);
                    return Ok(Read::TooLong);
                }
                buf.extend_from_slice(chunk);
                r.consume(n);
            }
        }
    }
}

async fn handle_connection(stream: UnixStream, ctx: &Context) -> io::Result<()> {
    let (read, mut write) = stream.into_split();
    let mut read = BufReader::new(read);
    loop {
        let response = match read_line_capped(&mut read, MAX_LINE).await? {
            Read::Eof => return Ok(()),
            Read::TooLong => {
                send(
                    &mut write,
                    &failure(&format!("request line exceeds {MAX_LINE} bytes")),
                )
                .await?;
                // Close, but only after the client has had the chance to read
                // the error: closing a socket with unread input can reset it.
                write.shutdown().await?;
                let mut sink = vec![0u8; 8192];
                let mut drained = 0usize;
                let _ = tokio::time::timeout(DRAIN_TIME, async {
                    while let Ok(n) = read.read(&mut sink).await {
                        drained += n;
                        if n == 0 || drained > DRAIN_LIMIT {
                            break;
                        }
                    }
                })
                .await;
                return Ok(());
            }
            Read::Line(bytes) => dispatch(&bytes, ctx).await,
        };
        send(&mut write, &response).await?;
    }
}

async fn send<W: AsyncWriteExt + Unpin>(w: &mut W, response: &Value) -> io::Result<()> {
    let mut line = serde_json::to_vec(response).map_err(io::Error::other)?;
    line.push(b'\n');
    w.write_all(&line).await?;
    w.flush().await
}

fn failure(message: &str) -> Value {
    json!({ "ok": false, "error": message })
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
        Err(e) => return failure(&format!("malformed request: {e}")),
    };
    let result = match request.op.as_str() {
        "ask" => ask(ctx, request.ask),
        "check_ruling" => check_ruling(ctx, request.id),
        "run_check" => run_check(ctx, request.id).await,
        _ => Err("unknown op".to_string()),
    };
    match result {
        Ok(v) => v,
        Err(e) => failure(&e),
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
    let id = lock(&ctx.queue)?.ask(&ctx.lane, &ask, Origin::Builder)?;
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
    let escalation = lock(&ctx.queue)?.record_check(&ctx.lane, &id, passed)?;
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
    use crate::escalate::{AskKind, Opt, SystemClock, Verdict};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tempfile::TempDir;
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
        let tmp = TempDir::new().unwrap();
        let sock_dir = tmp.path().join("sock");
        std::fs::create_dir(&sock_dir).unwrap();
        let sock = sock_dir.join("runner.sock");
        let queue = Arc::new(Mutex::new(
            Queue::new(&tmp.path().join("control"), Box::new(SystemClock)).unwrap(),
        ));
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = calls.clone();
        let run: RunCheck = Arc::new(move |id: &str| -> BoxFuture<'static, CheckOutcome> {
            counter.fetch_add(1, Ordering::SeqCst);
            let output = format!("ran {id}");
            Box::pin(async move {
                CheckOutcome {
                    exit_status,
                    output,
                }
            })
        });
        let checks: CheckTable = ["c1", "c2"].iter().map(|s| s.to_string()).collect();
        let task = tokio::spawn(serve(
            bind(&sock).unwrap(),
            LANE.to_string(),
            queue.clone(),
            checks,
            run,
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
}
