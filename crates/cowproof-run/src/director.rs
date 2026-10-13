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
use crate::wire::{self, Read};
use serde::Deserialize;
use serde_json::{Value, json};
use std::io;
use std::os::unix::fs::FileTypeExt;
use std::path::Path;
use std::sync::{Arc, Mutex};
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

struct Context {
    lane: String,
    queue: Arc<Mutex<Queue>>,
    verdict_tx: Option<mpsc::UnboundedSender<VerdictEvent>>,
}

/// The director socket served on its own OS thread, stopped when this is dropped.
///
/// The director must be able to reach a lane whatever the runner's main runtime is doing: the
/// ruling that ends a parked lane, a stop, a note. The runner's work (the builder's stream,
/// the proxy, the tools server, the checks) shares the main runtime's workers, and one task
/// that holds a worker for seconds would hold the director's `accept` with it. So the socket
/// gets a thread and a current-thread runtime of its own. The handlers only take the queue's
/// mutex, append one line and send on a channel, none of which needs the main runtime.
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
                tokio::select! {
                    served = serve(listener, lane, queue, verdict_tx) => {
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
    let ctx = Arc::new(Context {
        lane,
        queue,
        verdict_tx,
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

async fn dispatch(line: &[u8], ctx: &Context) -> Value {
    let request: Request = match serde_json::from_slice(line) {
        Ok(r) => r,
        Err(e) => return wire::failure(&format!("malformed request: {e}")),
    };
    let result = match request.op.as_str() {
        "rule" => rule(ctx, request.id, request.verdict),
        "note" => note(ctx, request.text),
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

fn rule(ctx: &Context, id: Option<String>, verdict: Option<Value>) -> Result<Value, String> {
    let id = id.ok_or("missing id")?;
    let verdict_value = verdict.ok_or("missing verdict")?;

    // Parse the escalation ID and validate it belongs to this lane.
    let escalation_id = EscalationId::from_string(id);
    let mut queue = lock(&ctx.queue)?;

    // Check that the ID belongs to this lane before ruling.
    if let Some((_, _, _)) = queue.get(&escalation_id) {
        // Verify it belongs to this lane by checking the ID format.
        if !escalation_id.0.starts_with(&format!("{}:E", ctx.lane)) {
            return Err(format!(
                "escalation {} does not belong to this lane {}",
                escalation_id, ctx.lane
            ));
        }
    } else {
        return Err(format!("escalation {} unknown", escalation_id));
    }

    // Parse the verdict.
    let parsed_verdict = parse_verdict(verdict_value)?;

    // Apply the ruling.
    queue.rule(&ctx.lane, &escalation_id, &parsed_verdict)?;

    // Send the verdict through the channel if one exists (D25).
    let delivery_status = if let Some(ref tx) = ctx.verdict_tx {
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
}

fn note(ctx: &Context, text: Option<String>) -> Result<Value, String> {
    let text = text.ok_or("missing text")?;
    let mut queue = lock(&ctx.queue)?;

    let note_id = queue.note(&ctx.lane, &text)?;

    Ok(success(json!({
        "id": note_id.0
    })))
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

    struct SystemClock;
    impl crate::escalate::Clock for SystemClock {
        fn now(&self) -> std::time::SystemTime {
            std::time::SystemTime::now()
        }
    }
}
