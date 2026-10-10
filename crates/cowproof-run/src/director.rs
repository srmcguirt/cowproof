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

/// Bind the director socket, replacing a stale one at that path.
/// Anything else at that path is an error and left alone.
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

    struct SystemClock;
    impl crate::escalate::Clock for SystemClock {
        fn now(&self) -> std::time::SystemTime {
            std::time::SystemTime::now()
        }
    }
}
