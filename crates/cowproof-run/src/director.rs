//! The director's control socket for ruling on escalations and sending notes (D25).
//!
//! The director reaches a running lane through `<lane>/control/director.sock` to:
//! - Rule on escalations: `cowproof rule <lane> <escalation-id> (--answer <text> | --redirect <packet> | --reassign [--model <m>] | --stop)`
//! - Send notes: `cowproof note <lane> <text>`
//!
//! The socket is mode 0600, inside the control directory (which no sandbox can reach).
//! Newline-delimited JSON protocol with 64 KiB line cap, same as the builder tools socket.
//!
//! # Protocol
//!
//! Requests:
//! ```text
//! {"op":"rule","id":"<escalation id>","verdict":{"answer":"..."}|{"redirect":"<packet path>"}|{"reassign":{"model":null|"..."}}|"stop"}
//! {"op":"note","text":"..."}
//! ```
//!
//! Responses:
//! - Success: `{"ok":true,"outcome":...}`
//! - Failure: `{"ok":false,"error":"..."}`
//! - Rule reply special field: `"delivery":"pending"` or `"delivery":"sent"` when sent through channel (D25)

use crate::escalate::{EscalationId, Queue, Verdict};
use crate::hostload::Snapshot;
use crate::stall;
use crate::wire::{self, Read};
use serde::Deserialize;
use serde_json::{Value, json};
use std::io;
use std::os::unix::fs::FileTypeExt;
use std::path::Path;
use std::sync::{Arc, Mutex, TryLockError};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;

pub use wire::MAX_LINE;

pub type BoxFuture<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

/// Remove a stale socket at `path`. Anything else at that path is an error and left alone.
fn clear_stale(path: &Path) -> io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => std::fs::remove_file(path),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("{} exists and is not a socket", path.display()),
        )),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Bind the director socket, replacing a stale one at that path.
/// Anything else at that path is an error and left alone.
pub fn bind(path: &Path) -> io::Result<UnixListener> {
    clear_stale(path)?;
    UnixListener::bind(path)
}

/// [`bind`] for [`serve_on_thread`]: a listener that belongs to no runtime yet.
pub fn bind_std(path: &Path) -> io::Result<std::os::unix::net::UnixListener> {
    clear_stale(path)?;
    std::os::unix::net::UnixListener::bind(path)
}

/// Verdict event sent to the resume loop (D25).
#[derive(Debug, Clone)]
pub struct VerdictEvent {
    pub id: EscalationId,
    pub verdict: Verdict,
}

/// A step slower than this puts a line on the lane's stderr, and a step still running puts
/// another each time it passes a further multiple of it.
const SLOW_STEP: Duration = Duration::from_secs(1);

/// The longest a request waits for the queue's mutex before it answers that the queue is
/// busy. The director gives up on a lane after ten seconds (`SOCKET_TIMEOUT` in the CLI's
/// `director_tools`), so this leaves it time to read an answer: a queue held that long is
/// then said, and nothing is recorded, instead of the director getting silence.
pub const LOCK_PATIENCE: Duration = Duration::from_secs(8);

/// How often a request that found the queue held tries it again.
const LOCK_POLL: Duration = Duration::from_millis(2);

/// Where the handler's diagnostics go: the lane's stderr (the tests collect them instead).
type Say = Arc<dyn Fn(&str) + Send + Sync>;

struct Context {
    lane: String,
    queue: Arc<Mutex<Queue>>,
    verdict_tx: Option<mpsc::UnboundedSender<VerdictEvent>>,
    /// See [`SLOW_STEP`].
    slow: Duration,
    /// See [`LOCK_PATIENCE`].
    lock_patience: Duration,
    say: Say,
}

impl Context {
    fn new(
        lane: String,
        queue: Arc<Mutex<Queue>>,
        verdict_tx: Option<mpsc::UnboundedSender<VerdictEvent>>,
    ) -> Context {
        Context {
            lane,
            queue,
            verdict_tx,
            slow: SLOW_STEP,
            lock_patience: LOCK_PATIENCE,
            say: Arc::new(|line| eprintln!("{line}")),
        }
    }

    /// One diagnostic line, with the lane's name in front.
    fn say(&self, text: &str) {
        (self.say)(&format!("[{}] director: {text}", self.lane));
    }

    /// The summary line for a request in which some step was slow; nothing when none was.
    fn report(&self, what: &str, trace: &Trace, host_before: &Snapshot) {
        if !trace.has_step_of(self.slow) {
            return;
        }
        let total = trace.total();
        let host = Snapshot::take().since_waiting(host_before, total);
        let host = if host.is_empty() {
            String::new()
        } else {
            format!("; {host}")
        };
        self.say(&format!(
            "{what} took {} ms in all: {}{host}",
            total.as_millis(),
            trace.describe()
        ));
    }
}

/// The steps one request went through, with how long each took.
#[derive(Default)]
struct Trace {
    steps: Vec<(&'static str, Duration)>,
}

impl Trace {
    fn step(&mut self, name: &'static str, took: Duration) {
        self.steps.push((name, took));
    }

    fn has_step_of(&self, limit: Duration) -> bool {
        self.steps.iter().any(|(_, took)| *took >= limit)
    }

    fn total(&self) -> Duration {
        self.steps.iter().map(|(_, took)| *took).sum()
    }

    fn describe(&self) -> String {
        self.steps
            .iter()
            .map(|(name, took)| format!("{name} {} ms", took.as_millis()))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// Where a request's work is. The work runs on a blocking thread; the director thread reads
/// this while it waits, so a request that is taking long can say what it is taking long *in*.
struct Progress {
    state: Mutex<ProgressState>,
}

struct ProgressState {
    step: &'static str,
    since: Instant,
    done: Vec<(&'static str, Duration)>,
}

impl Progress {
    fn new() -> Progress {
        Progress {
            state: Mutex::new(ProgressState {
                step: "worker start",
                since: Instant::now(),
                done: Vec::new(),
            }),
        }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, ProgressState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The work has moved on to `step`.
    fn at(&self, step: &'static str) {
        let mut state = self.state();
        let took = state.since.elapsed();
        let previous = state.step;
        state.done.push((previous, took));
        state.step = step;
        state.since = Instant::now();
    }

    /// The step it is in, and for how long.
    fn current(&self) -> (&'static str, Duration) {
        let state = self.state();
        (state.step, state.since.elapsed())
    }

    /// Every step so far, the one in progress last.
    fn steps(&self) -> Vec<(&'static str, Duration)> {
        let state = self.state();
        let mut steps = state.done.clone();
        steps.push((state.step, state.since.elapsed()));
        steps
    }
}

/// The director socket served on its own OS thread, stopped when this is dropped.
///
/// The director must be able to reach a lane whatever the runner's main runtime is doing: the
/// ruling that ends a parked lane, a stop, a note. The runner's work (the builder's stream,
/// the proxy, the tools server, the checks) shares the main runtime's workers, and one task
/// that holds a worker for seconds would hold the director's `accept` with it. So the socket
/// gets a thread and a current-thread runtime of its own. The handlers only take the queue's
/// mutex, append one line and send on a channel, none of which needs the main runtime. They
/// do that on this runtime's own blocking pool, so a queue held (or a disk that is slow)
/// keeps this thread free to accept, to answer, and to say on stderr what it is waiting in.
pub struct DirectorThread {
    stop: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Drop for DirectorThread {
    fn drop(&mut self) {
        // The thread closes the listener as soon as it reads this; nothing waits for it.
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }
}

/// [`serve`] on a dedicated thread, for a listener from [`bind_std`]. Returns once the thread
/// is serving (or has failed to start).
pub fn serve_on_thread(
    listener: std::os::unix::net::UnixListener,
    lane: String,
    queue: Arc<Mutex<Queue>>,
    verdict_tx: Option<mpsc::UnboundedSender<VerdictEvent>>,
) -> io::Result<DirectorThread> {
    serve_context_on_thread(listener, Context::new(lane, queue, verdict_tx))
}

fn serve_context_on_thread(
    listener: std::os::unix::net::UnixListener,
    ctx: Context,
) -> io::Result<DirectorThread> {
    listener.set_nonblocking(true)?;
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<io::Result<()>>();
    std::thread::Builder::new()
        .name("cowproof-director".into())
        .spawn(move || {
            let built = tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build();
            let runtime = match built {
                Ok(runtime) => runtime,
                Err(e) => {
                    let _ = ready_tx.send(Err(e));
                    return;
                }
            };
            runtime.block_on(async move {
                let listener = match UnixListener::from_std(listener) {
                    Ok(listener) => listener,
                    Err(e) => {
                        let _ = ready_tx.send(Err(e));
                        return;
                    }
                };
                let _ = ready_tx.send(Ok(()));
                // This thread's own clock, next to the runner's: a request that was slow
                // because this thread was not run (or was blocked) says so.
                let _watch = {
                    let ctx_say = ctx.say.clone();
                    let lane = ctx.lane.clone();
                    stall::watch_with(stall::TICK, ctx.slow, move |stall| {
                        ctx_say(&format!(
                            "[{lane}] {}",
                            stall.describe_for("director thread")
                        ));
                    })
                };
                tokio::select! {
                    served = serve_context(listener, ctx) => {
                        if let Err(e) = served {
                            eprintln!("director control socket stopped: {e}");
                        }
                    }
                    _ = stopped => {}
                }
            });
        })?;
    ready_rx
        .recv()
        .map_err(|_| io::Error::other("the director thread ended before it served"))??;
    Ok(DirectorThread { stop: Some(stop) })
}

/// Serve the director control socket for one lane until the listener fails.
pub async fn serve(
    listener: UnixListener,
    lane: String,
    queue: Arc<Mutex<Queue>>,
    verdict_tx: Option<mpsc::UnboundedSender<VerdictEvent>>,
) -> io::Result<()> {
    serve_context(listener, Context::new(lane, queue, verdict_tx)).await
}

async fn serve_context(listener: UnixListener, ctx: Context) -> io::Result<()> {
    let ctx = Arc::new(ctx);
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
            let _ = handle_connection(stream, ctx).await;
        });
    }
}

/// One connection: its requests in turn, each with the time every step of it took. When any
/// step took `ctx.slow` or more, one line on the lane's stderr gives all of them.
async fn handle_connection(stream: UnixStream, ctx: Arc<Context>) -> io::Result<()> {
    let accepted = Instant::now();
    let host_before = Snapshot::take();
    let (read, mut write) = stream.into_split();
    let mut read = BufReader::new(read);
    let mut first = true;
    loop {
        let line = wire::read_line_capped(&mut read, wire::MAX_LINE).await?;
        let mut trace = Trace::default();
        if first {
            // Connect to request: the client's own time, and the wait for this thread to run.
            trace.step("request line", accepted.elapsed());
            first = false;
        }
        match line {
            Read::Eof => {
                // A client that connected, waited and left without asking.
                ctx.report(
                    "a connection that closed without a request",
                    &trace,
                    &host_before,
                );
                return Ok(());
            }
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
            Read::Line(bytes) => {
                let (what, response) = dispatch(&bytes, &ctx, &mut trace).await;
                let sending = Instant::now();
                let sent = wire::send(&mut write, &response).await;
                trace.step("reply", sending.elapsed());
                ctx.report(&what, &trace, &host_before);
                sent?;
            }
        }
    }
}

fn success(outcome: Value) -> Value {
    json!({ "ok": true, "outcome": outcome })
}

/// Only the fields this module reads. Everything else is dropped by deserialization.
#[derive(Deserialize)]
struct Request {
    op: String,
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    verdict: Option<Value>,
}

/// What a request is called in a diagnostic line: the op and, for a ruling, the escalation.
fn describe_request(request: &Request) -> String {
    match (&request.op[..], &request.id) {
        ("rule", Some(id)) => format!("rule {}", id.chars().take(80).collect::<String>()),
        (op, _) => op.chars().take(40).collect(),
    }
}

async fn dispatch(line: &[u8], ctx: &Arc<Context>, trace: &mut Trace) -> (String, Value) {
    let request: Request = match serde_json::from_slice(line) {
        Ok(r) => r,
        Err(e) => {
            return (
                "a malformed request".to_string(),
                wire::failure(&format!("malformed request: {e}")),
            );
        }
    };
    let what = describe_request(&request);
    let result = match request.op.as_str() {
        "rule" => rule(ctx, &what, request.id, request.verdict, trace).await,
        "note" => note(ctx, &what, request.text, trace).await,
        _ => Err("unknown op".to_string()),
    };
    let response = match result {
        Ok(v) => v,
        Err(e) => wire::failure(&e),
    };
    (what, response)
}

/// Run `work` on a blocking thread and wait for it here, saying on the lane's stderr what it
/// is in each time it passes a further `ctx.slow`. The director thread stays free to accept,
/// answer other requests and run its stall watchdog while the work waits, and a work that
/// never finishes still leaves its lines.
async fn run_step<T: Send + 'static>(
    ctx: &Arc<Context>,
    what: &str,
    trace: &mut Trace,
    work: impl FnOnce(&Progress) -> Result<T, String> + Send + 'static,
) -> Result<T, String> {
    let progress = Arc::new(Progress::new());
    let worker = progress.clone();
    let started = Instant::now();
    let mut handle = tokio::task::spawn_blocking(move || work(&worker));
    let mut next = tokio::time::Instant::now() + ctx.slow;
    let joined = loop {
        tokio::select! {
            joined = &mut handle => break joined,
            _ = tokio::time::sleep_until(next) => {
                let (step, in_step) = progress.current();
                ctx.say(&format!(
                    "{what} has been running {} ms, {} ms of it in `{step}`",
                    started.elapsed().as_millis(),
                    in_step.as_millis()
                ));
                next += ctx.slow;
            }
        }
    };
    for (name, took) in progress.steps() {
        trace.step(name, took);
    }
    joined.unwrap_or_else(|e| Err(format!("the director's {what} step failed: {e}")))
}

/// Take the queue's mutex and run `work` with it. A mutex held for longer than
/// `ctx.lock_patience` is not waited for: the request is refused with nothing recorded.
fn with_queue<T>(
    ctx: &Context,
    progress: &Progress,
    work: impl FnOnce(&mut Queue, &Progress) -> Result<T, String>,
) -> Result<T, String> {
    progress.at("queue lock");
    let waiting = Instant::now();
    let mut queue = loop {
        match ctx.queue.try_lock() {
            Ok(queue) => break queue,
            Err(TryLockError::Poisoned(_)) => {
                return Err("the escalation queue is unavailable".to_string());
            }
            Err(TryLockError::WouldBlock) => {
                if waiting.elapsed() >= ctx.lock_patience {
                    return Err(format!(
                        "the lane's escalation queue was in use by the runner for {:?}; nothing was recorded, send this again",
                        ctx.lock_patience
                    ));
                }
                std::thread::sleep(LOCK_POLL);
            }
        }
    };
    work(&mut queue, progress)
}

/// Parse a verdict from the request JSON.
/// Expected shapes:
/// - `{"answer":"..."}` → `Verdict::Answer`
/// - `{"redirect":"<path>"}` → `Verdict::Redirect`
/// - `{"reassign":{"model":null}}` or `{"reassign":{"model":"..."}}` → `Verdict::Reassign`
/// - `"stop"` → `Verdict::Stop`
fn parse_verdict(v: Value) -> Result<Verdict, String> {
    match v {
        Value::Object(obj) => {
            if let Some(Value::String(text)) = obj.get("answer") {
                return Ok(Verdict::Answer { text: text.clone() });
            }
            if let Some(Value::String(packet_path)) = obj.get("redirect") {
                return Ok(Verdict::Redirect {
                    packet_path: packet_path.clone(),
                });
            }
            if let Some(Value::Object(reassign_obj)) = obj.get("reassign") {
                let model = match reassign_obj.get("model") {
                    Some(Value::String(m)) => Some(m.clone()),
                    Some(Value::Null) | None => None,
                    _ => return Err("reassign.model must be a string or null".to_string()),
                };
                return Ok(Verdict::Reassign { model });
            }
            Err("verdict object must contain answer, redirect, or reassign".to_string())
        }
        Value::String(s) if s == "stop" => Ok(Verdict::Stop),
        _ => Err("verdict must be an object or \"stop\"".to_string()),
    }
}

async fn rule(
    ctx: &Arc<Context>,
    what: &str,
    id: Option<String>,
    verdict: Option<Value>,
    trace: &mut Trace,
) -> Result<Value, String> {
    let id = id.ok_or("missing id")?;
    let verdict_value = verdict.ok_or("missing verdict")?;
    let escalation_id = EscalationId::from_string(id);
    let owner = ctx.clone();
    run_step(ctx, what, trace, move |progress| {
        with_queue(&owner, progress, |queue, progress| {
            // Check that the ID belongs to this lane before ruling.
            if let Some((_, _, _)) = queue.get(&escalation_id) {
                // Verify it belongs to this lane by checking the ID format.
                if !escalation_id.0.starts_with(&format!("{}:E", owner.lane)) {
                    return Err(format!(
                        "escalation {} does not belong to this lane {}",
                        escalation_id, owner.lane
                    ));
                }
            } else {
                return Err(format!("escalation {} unknown", escalation_id));
            }

            // Parse the verdict.
            let parsed_verdict = parse_verdict(verdict_value)?;

            // Apply the ruling: this is the reply's whole job. Nothing below waits for the
            // builder, the session or the delivery.
            progress.at("recording the ruling");
            queue.rule(&owner.lane, &escalation_id, &parsed_verdict)?;
            progress.at("waking the runner");

            // Send the verdict through the channel if one exists (D25).
            let delivery_status = if let Some(ref tx) = owner.verdict_tx {
                let event = VerdictEvent {
                    id: escalation_id.clone(),
                    verdict: parsed_verdict.clone(),
                };
                if tx.send(event).is_ok() {
                    "sent"
                } else {
                    "failed-channel-closed"
                }
            } else {
                "pending"
            };

            Ok(success(json!({
                "id": escalation_id.0,
                "delivery": delivery_status
            })))
        })
    })
    .await
}

async fn note(
    ctx: &Arc<Context>,
    what: &str,
    text: Option<String>,
    trace: &mut Trace,
) -> Result<Value, String> {
    let text = text.ok_or("missing text")?;
    let owner = ctx.clone();
    run_step(ctx, what, trace, move |progress| {
        with_queue(&owner, progress, |queue, progress| {
            progress.at("recording the note");
            let note_id = queue.note(&owner.lane, &text)?;
            Ok(success(json!({
                "id": note_id.0
            })))
        })
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn bind_creates_socket() {
        use std::os::unix::fs::FileTypeExt;
        let tmp = TempDir::new().unwrap();
        let sock_path = tmp.path().join("test.sock");
        let _listener = bind(&sock_path).expect("bind failed");
        assert!(sock_path.exists());
        assert!(sock_path.metadata().unwrap().file_type().is_socket());
    }

    #[tokio::test]
    async fn bind_replaces_stale_socket() {
        let tmp = TempDir::new().unwrap();
        let sock_path = tmp.path().join("test.sock");
        let _listener1 = bind(&sock_path).expect("bind failed first time");
        // Second bind should succeed after dropping listener1
        let _listener2 = bind(&sock_path).expect("bind failed second time");
        assert!(sock_path.exists());
    }

    #[tokio::test]
    async fn bind_refuses_non_socket() {
        let tmp = TempDir::new().unwrap();
        let file_path = tmp.path().join("notasocket");
        std::fs::write(&file_path, b"data").unwrap();
        let err = bind(&file_path).unwrap_err();
        assert!(err.to_string().contains("not a socket"));
    }

    #[tokio::test]
    async fn malformed_json_returns_error() {
        let tmp = TempDir::new().unwrap();
        let sock_path = tmp.path().join("test.sock");
        let listener = bind(&sock_path).expect("bind failed");

        let queue = Arc::new(Mutex::new(
            Queue::new(tmp.path(), Box::new(SystemClock)).unwrap(),
        ));
        let serve_task = tokio::spawn(serve(
            listener,
            "test-lane".to_string(),
            queue.clone(),
            None,
        ));

        // Give the server a moment to start
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

        // Connect and send malformed JSON
        let mut stream = UnixStream::connect(&sock_path).await.unwrap();
        stream.write_all(b"not json\n").await.unwrap();

        let mut buf = [0u8; 1024];
        let n = stream.read(&mut buf).await.unwrap();
        let response: Value = serde_json::from_slice(&buf[..n]).unwrap();
        assert!(!response["ok"].as_bool().unwrap());
        assert!(response["error"].as_str().unwrap().contains("malformed"));

        serve_task.abort();
    }

    #[tokio::test]
    async fn parse_verdict_answer() {
        let v = json!({"answer": "test answer"});
        let verdict = parse_verdict(v).unwrap();
        match verdict {
            Verdict::Answer { text } => assert_eq!(text, "test answer"),
            _ => panic!("expected Answer"),
        }
    }

    #[tokio::test]
    async fn parse_verdict_redirect() {
        let v = json!({"redirect": "/path/to/packet.md"});
        let verdict = parse_verdict(v).unwrap();
        match verdict {
            Verdict::Redirect { packet_path } => assert_eq!(packet_path, "/path/to/packet.md"),
            _ => panic!("expected Redirect"),
        }
    }

    #[tokio::test]
    async fn parse_verdict_reassign_no_model() {
        let v = json!({"reassign": {"model": null}});
        let verdict = parse_verdict(v).unwrap();
        match verdict {
            Verdict::Reassign { model: None } => {}
            _ => panic!("expected Reassign with no model"),
        }
    }

    #[tokio::test]
    async fn parse_verdict_reassign_with_model() {
        let v = json!({"reassign": {"model": "sonnet"}});
        let verdict = parse_verdict(v).unwrap();
        match verdict {
            Verdict::Reassign { model: Some(m) } => assert_eq!(m, "sonnet"),
            _ => panic!("expected Reassign with model"),
        }
    }

    #[tokio::test]
    async fn parse_verdict_stop() {
        let v = json!("stop");
        let verdict = parse_verdict(v).unwrap();
        match verdict {
            Verdict::Stop => {}
            _ => panic!("expected Stop"),
        }
    }

    /// One `note` request over a plain blocking socket, so the client needs no runtime.
    /// Returns how long the reply took.
    fn note_round_trip(socket: &Path) -> std::time::Duration {
        use std::io::{BufRead, Write};
        let started = std::time::Instant::now();
        let mut stream = std::os::unix::net::UnixStream::connect(socket).unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(60)))
            .unwrap();
        stream
            .write_all(b"{\"op\":\"note\",\"text\":\"hello\"}\n")
            .unwrap();
        let mut reply = String::new();
        std::io::BufReader::new(stream)
            .read_line(&mut reply)
            .unwrap();
        let reply: Value = serde_json::from_str(&reply).unwrap();
        assert_eq!(reply["ok"], json!(true), "{reply}");
        started.elapsed()
    }

    /// A runtime with a single worker, and a task that holds that worker for `block`.
    fn runtime_with_its_worker_held(block: std::time::Duration) -> tokio::runtime::Runtime {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        runtime.spawn(async move { std::thread::sleep(block) });
        runtime
    }

    /// The director reaches a lane while the runner's main runtime is held by a task that
    /// blocks its worker. The control is the same server spawned on that runtime, which cannot
    /// answer until the worker is free (so the premise holds); the dedicated thread answers
    /// at once. Run the control through `tokio::spawn` in `serve_on_thread` and this fails.
    #[test]
    fn the_director_answers_while_the_main_runtime_is_blocked() {
        const BLOCK: std::time::Duration = std::time::Duration::from_secs(5);
        let tmp = TempDir::new().unwrap();
        let queue_for = |name: &str| {
            let dir = tmp.path().join(name);
            std::fs::create_dir(&dir).unwrap();
            Arc::new(Mutex::new(Queue::new(&dir, Box::new(SystemClock)).unwrap()))
        };

        // The control: the server is a task on the blocked runtime.
        let control_sock = tmp.path().join("control.sock");
        let control_runtime = runtime_with_its_worker_held(BLOCK);
        {
            let _entered = control_runtime.enter();
            let listener = bind(&control_sock).unwrap();
            let queue = queue_for("control");
            tokio::spawn(serve(listener, "lane".to_string(), queue, None));
        }

        // The fix: the server has a thread of its own, started from the blocked runtime.
        let thread_sock = tmp.path().join("thread.sock");
        let thread_runtime = runtime_with_its_worker_held(BLOCK);
        let _thread = {
            let _entered = thread_runtime.enter();
            serve_on_thread(
                bind_std(&thread_sock).unwrap(),
                "lane".to_string(),
                queue_for("thread"),
                None,
            )
            .unwrap()
        };

        // Both workers are held from here until BLOCK is over.
        std::thread::sleep(std::time::Duration::from_millis(500));
        let (control, dedicated) = std::thread::scope(|scope| {
            let control = scope.spawn(|| note_round_trip(&control_sock));
            let dedicated = scope.spawn(|| note_round_trip(&thread_sock));
            (control.join().unwrap(), dedicated.join().unwrap())
        });
        assert!(
            control >= std::time::Duration::from_secs(3),
            "the control should wait for the held worker, but answered in {control:?}"
        );
        assert!(
            dedicated < std::time::Duration::from_secs(2),
            "the dedicated director took {dedicated:?} with the main runtime held for {BLOCK:?}"
        );
    }

    /// The exit of an interrupted run drops the director thread while a handler may be in the
    /// middle of a request. The drop must not wait for it: here a request is held on the
    /// queue's mutex for several seconds (a slow append on a loaded disk looks the same), and
    /// dropping the thread still returns at once. Add a `join` to `DirectorThread::drop`, or
    /// a wait for the thread's runtime, and this fails.
    #[test]
    fn dropping_the_director_thread_does_not_wait_for_a_request_in_flight() {
        const HELD: std::time::Duration = std::time::Duration::from_secs(4);
        let tmp = TempDir::new().unwrap();
        let sock = tmp.path().join("director.sock");
        let queue = Arc::new(Mutex::new(
            Queue::new(tmp.path(), Box::new(SystemClock)).unwrap(),
        ));
        let thread = serve_on_thread(
            bind_std(&sock).unwrap(),
            "lane".to_string(),
            queue.clone(),
            None,
        )
        .unwrap();

        // Something else holds the queue, as a slow append would.
        let (held_tx, held_rx) = std::sync::mpsc::channel::<()>();
        let holder = {
            let queue = queue.clone();
            std::thread::spawn(move || {
                let guard = queue.lock().unwrap();
                held_tx.send(()).unwrap();
                std::thread::sleep(HELD);
                drop(guard);
            })
        };
        held_rx.recv().unwrap();

        // A request that cannot finish until the hold ends: the handler is stuck on the lock,
        // and with it the director thread's only worker.
        let client = std::thread::spawn({
            let sock = sock.clone();
            move || note_round_trip(&sock)
        });
        std::thread::sleep(std::time::Duration::from_millis(500));

        let started = std::time::Instant::now();
        drop(thread);
        let dropped = started.elapsed();
        assert!(
            dropped < std::time::Duration::from_secs(1),
            "dropping the director thread took {dropped:?} with a request in flight for {HELD:?}"
        );
        // The request is answered once the hold is over (the thread was not torn down under it).
        holder.join().unwrap();
        let _ = client.join();
    }

    #[test]
    fn dropping_the_director_thread_closes_its_socket() {
        let tmp = TempDir::new().unwrap();
        let sock = tmp.path().join("director.sock");
        let queue = Arc::new(Mutex::new(
            Queue::new(tmp.path(), Box::new(SystemClock)).unwrap(),
        ));
        let thread =
            serve_on_thread(bind_std(&sock).unwrap(), "lane".to_string(), queue, None).unwrap();
        assert!(note_round_trip(&sock) < std::time::Duration::from_secs(30));
        drop(thread);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            if std::os::unix::net::UnixStream::connect(&sock).is_err() {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the socket still accepts connections"
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }

    /// One request over a plain blocking socket; the reply, or a panic after `patience`.
    fn ask_over(socket: &Path, request: &Value, patience: std::time::Duration) -> Value {
        use std::io::{BufRead, Write};
        let mut stream = std::os::unix::net::UnixStream::connect(socket).unwrap();
        stream.set_read_timeout(Some(patience)).unwrap();
        stream.write_all(format!("{request}\n").as_bytes()).unwrap();
        let mut reply = String::new();
        std::io::BufReader::new(stream)
            .read_line(&mut reply)
            .unwrap_or_else(|e| panic!("no reply within {patience:?}: {e}"));
        serde_json::from_str(&reply).unwrap()
    }

    fn a_blocking_ask() -> crate::escalate::Ask {
        crate::escalate::Ask {
            kind: crate::escalate::AskKind::Blocker,
            question: "Which one?".to_string(),
            tried: vec!["read the packet".to_string()],
            options: vec![crate::escalate::Opt {
                id: "a".to_string(),
                summary: "do A".to_string(),
                cost: "low".to_string(),
            }],
            recommend: "a".to_string(),
            blocking: true,
        }
    }

    /// A director thread whose diagnostics are collected, with short limits.
    struct Served {
        _thread: DirectorThread,
        socket: std::path::PathBuf,
        queue: Arc<Mutex<Queue>>,
        said: Arc<Mutex<Vec<String>>>,
        id: String,
        _dir: TempDir,
    }

    fn served(slow_ms: u64, patience_ms: u64) -> Served {
        let dir = tempfile::Builder::new().tempdir_in("/var/tmp").unwrap();
        let socket = dir.path().join("director.sock");
        let queue = Arc::new(Mutex::new(
            Queue::new(dir.path(), Box::new(SystemClock)).unwrap(),
        ));
        let id = queue
            .lock()
            .unwrap()
            .ask("lane", &a_blocking_ask(), crate::escalate::Origin::Builder)
            .unwrap()
            .0;
        let said: Arc<Mutex<Vec<String>>> = Arc::default();
        let sink = said.clone();
        let mut ctx = Context::new("lane".to_string(), queue.clone(), None);
        ctx.slow = std::time::Duration::from_millis(slow_ms);
        ctx.lock_patience = std::time::Duration::from_millis(patience_ms);
        ctx.say = Arc::new(move |line| sink.lock().unwrap().push(line.to_string()));
        let thread = serve_context_on_thread(bind_std(&socket).unwrap(), ctx).unwrap();
        Served {
            _thread: thread,
            socket,
            queue,
            said,
            id,
            _dir: dir,
        }
    }

    fn rule_request(id: &str) -> Value {
        json!({"op": "rule", "id": id, "verdict": "stop"})
    }

    fn ruled_events(dir: &Path) -> usize {
        std::fs::read_to_string(dir.join("escalations.jsonl"))
            .unwrap()
            .lines()
            .filter(|l| l.contains("\"ruled\""))
            .count()
    }

    /// The queue's mutex held by the runner for longer than the director's patience (the
    /// director gives a lane ten seconds; here the patience is 300 ms and the hold 3 s): the
    /// ruling is answered, as refused with nothing recorded, while the mutex is STILL held,
    /// and the same ruling sent again afterwards is recorded once. With a handler that
    /// waits on the mutex as long as it takes, the reply comes only after the release, which
    /// the test makes wait for the reply: it fails at its read timeout.
    #[test]
    fn a_ruling_is_answered_while_the_runner_holds_the_queue_and_recorded_when_sent_again() {
        let lane = served(100, 300);
        let (held_tx, held_rx) = std::sync::mpsc::channel::<()>();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let queue = lane.queue.clone();
        let holder = std::thread::spawn(move || {
            let guard = queue.lock().unwrap();
            held_tx.send(()).unwrap();
            // Held until the test has its answer; never longer than the hold below.
            let _ = release_rx.recv_timeout(std::time::Duration::from_secs(3));
            drop(guard);
        });
        held_rx.recv().unwrap();

        let started = std::time::Instant::now();
        let busy = ask_over(
            &lane.socket,
            &rule_request(&lane.id),
            std::time::Duration::from_secs(2),
        );
        let took = started.elapsed();
        assert_eq!(busy["ok"], json!(false), "{busy}");
        let error = busy["error"].as_str().unwrap();
        assert!(error.contains("in use by the runner"), "{error}");
        assert!(error.contains("nothing was recorded"), "{error}");
        assert!(
            took < std::time::Duration::from_millis(1500),
            "the busy answer took {took:?}"
        );
        release_tx.send(()).unwrap();
        holder.join().unwrap();

        let dir = lane._dir.path();
        assert_eq!(ruled_events(dir), 0, "a refused ruling is not recorded");
        let again = ask_over(
            &lane.socket,
            &rule_request(&lane.id),
            std::time::Duration::from_secs(5),
        );
        assert_eq!(again["ok"], json!(true), "{again}");
        assert_eq!(ruled_events(dir), 1);

        // What the lane's stderr got: the wait named, with the step it was in, and the
        // director's own thread was never the thing that stood still.
        let said = lane.said.lock().unwrap().join("\n");
        assert!(said.contains("[lane] director: rule "), "{said}");
        assert!(said.contains("in `queue lock`"), "{said}");
        assert!(said.contains("queue lock "), "{said}");
        assert!(!said.contains("director thread stall"), "{said}");
    }

    /// While one request waits for the held queue, another connection is still accepted and
    /// answered by the same thread (a malformed line needs no queue).
    #[test]
    fn a_request_waiting_for_the_queue_does_not_hold_the_director_thread() {
        let lane = served(100, 2000);
        let (held_tx, held_rx) = std::sync::mpsc::channel::<()>();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let queue = lane.queue.clone();
        let holder = std::thread::spawn(move || {
            let guard = queue.lock().unwrap();
            held_tx.send(()).unwrap();
            let _ = release_rx.recv_timeout(std::time::Duration::from_secs(10));
            drop(guard);
        });
        held_rx.recv().unwrap();
        let waiting = {
            let socket = lane.socket.clone();
            let id = lane.id.clone();
            std::thread::spawn(move || {
                ask_over(
                    &socket,
                    &rule_request(&id),
                    std::time::Duration::from_secs(20),
                )
            })
        };
        std::thread::sleep(std::time::Duration::from_millis(300));
        let started = std::time::Instant::now();
        let other = ask_over(
            &lane.socket,
            &json!({"op": "nonsense"}),
            std::time::Duration::from_secs(2),
        );
        assert_eq!(other["error"], json!("unknown op"), "{other}");
        assert!(started.elapsed() < std::time::Duration::from_millis(500));
        release_tx.send(()).unwrap();
        holder.join().unwrap();
        let ruled = waiting.join().unwrap();
        assert_eq!(ruled["ok"], json!(true), "{ruled}");
    }

    /// A client that connects and then takes its time to send is named in the summary, so a
    /// slow reply can be told from a slow request.
    #[test]
    fn a_slow_client_is_named_in_the_summary_line() {
        use std::io::{BufRead, Write};
        let lane = served(100, 2000);
        let mut stream = std::os::unix::net::UnixStream::connect(&lane.socket).unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(400));
        stream
            .write_all(b"{\"op\":\"note\",\"text\":\"late\"}\n")
            .unwrap();
        let mut reply = String::new();
        std::io::BufReader::new(stream)
            .read_line(&mut reply)
            .unwrap();
        assert!(reply.contains("\"ok\":true"), "{reply}");
        // The line is written after the reply; give the thread a moment.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let line = loop {
            let said = lane.said.lock().unwrap().clone();
            if let Some(line) = said.iter().find(|l| l.contains("note took")) {
                break line.clone();
            }
            assert!(std::time::Instant::now() < deadline, "no summary: {said:?}");
            std::thread::sleep(std::time::Duration::from_millis(20));
        };
        // The client waited 400 ms before writing; the clock can read a hair under that.
        let waited: u64 = line
            .split("request line ")
            .nth(1)
            .and_then(|rest| rest.split(" ms").next())
            .and_then(|ms| ms.trim().parse().ok())
            .unwrap_or_else(|| panic!("no request line time: {line}"));
        assert!(waited >= 350, "request line {waited} ms: {line}");
        assert!(line.contains("queue lock "), "{line}");
        assert!(line.contains("recording the note "), "{line}");
        assert!(line.contains("reply "), "{line}");
    }

    /// A request that is quick says nothing at all.
    #[test]
    fn a_quick_request_leaves_no_line() {
        let lane = served(1000, 2000);
        let reply = ask_over(
            &lane.socket,
            &json!({"op": "note", "text": "quick"}),
            std::time::Duration::from_secs(5),
        );
        assert_eq!(reply["ok"], json!(true), "{reply}");
        std::thread::sleep(std::time::Duration::from_millis(100));
        assert!(lane.said.lock().unwrap().is_empty());
    }

    struct SystemClock;
    impl crate::escalate::Clock for SystemClock {
        fn now(&self) -> std::time::SystemTime {
            std::time::SystemTime::now()
        }
    }
}
