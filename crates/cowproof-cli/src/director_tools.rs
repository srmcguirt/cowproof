//! `cowproof serve --director`: the director's tools as an MCP stdio server (D4).
//!
//! Four portkit tools, served from a registry by `portkit_mcp`:
//! - `lanes`: every lane's state, parked escalation and pending notes;
//! - `events`: the queue events a lane gained since a cursor, and the next cursor;
//! - `rule`: rule on an escalation through the lane's `control/director.sock`;
//! - `note`: send a note to a running lane through the same socket.
//!
//! No tool waits for a lane. `lanes` and `events` read files and return what is
//! there now, so a caller that wants to follow a lane polls `events` with the
//! cursor it was given. `rule` and `note` are one request and one reply on the
//! lane's socket, bounded by [`SOCKET_TIMEOUT`].
//!
//! `cowproof rule` and `cowproof note` call [`send_rule`] and [`send_note`], the
//! same functions the `rule` and `note` tools call, so the request on the wire
//! is built in one place. `lanes` and `events` use the data functions that
//! `cowproof watch` prints from (`watch::lane_snapshots`, `watch::read_events`).
//!
//! Event summaries carry runner-owned text only (ids, flags, sizes); what a
//! builder wrote in an escalation never comes through these tools.

use crate::root::current_lanes_root;
use crate::watch::{
    DEFAULT_CACHE_TTL, decode_cursor, encode_cursor, lane_snapshots, now_ms, parse_duration,
    read_events,
};
use anyhow::{Result, anyhow};
use portkit_core::{Error, Registry, Tool, ToolSpec, async_trait};
use portkit_mcp::{McpServer, ServerInfo};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

/// The most one reply from a lane may occupy, in bytes.
const MAX_RESPONSE: u64 = 1024 * 1024;

/// How long one request to a lane's socket may take, connect to reply. A lane
/// that accepts and never answers must not hold a director tool call open.
const SOCKET_TIMEOUT: Duration = Duration::from_secs(10);

/// A director's ruling on an escalation: the four verdict kinds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ruling {
    Answer(String),
    Redirect(String),
    Reassign { model: Option<String> },
    Stop,
}

impl Ruling {
    /// The verdict as the lane's director socket reads it (`cowproof_run::director`).
    fn to_wire(&self) -> Value {
        match self {
            Ruling::Answer(text) => json!({ "answer": text }),
            Ruling::Redirect(path) => json!({ "redirect": path }),
            Ruling::Reassign { model } => json!({ "reassign": { "model": model } }),
            Ruling::Stop => json!("stop"),
        }
    }
}

/// Why a request to a lane did not succeed.
#[derive(Debug)]
pub enum SendError {
    /// The lane has no director socket: it is not running.
    NotRunning(String),
    /// Anything else: a bad lane id, a connection failure, a refusal from the lane.
    Failed(String),
}

impl std::fmt::Display for SendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SendError::NotRunning(lane) => write!(f, "lane {lane} is not running"),
            SendError::Failed(reason) => f.write_str(reason),
        }
    }
}

impl std::error::Error for SendError {}

/// Build the `rule` request and send it to the lane's director socket. The one
/// place a ruling is built and sent: `cowproof rule` and the `rule` tool both call it.
pub async fn send_rule(
    lanes_root: &Path,
    lane: &str,
    escalation_id: &str,
    ruling: &Ruling,
) -> Result<Value, SendError> {
    let request = json!({ "op": "rule", "id": escalation_id, "verdict": ruling.to_wire() });
    send(lanes_root, lane, &request).await
}

/// Build the `note` request and send it to the lane's director socket. The one
/// place a note is built and sent: `cowproof note` and the `note` tool both call it.
pub async fn send_note(lanes_root: &Path, lane: &str, text: &str) -> Result<Value, SendError> {
    let request = json!({ "op": "note", "text": text });
    send(lanes_root, lane, &request).await
}

/// One request line out and one reply line back on `<lane>/control/director.sock`.
/// Returns the lane's `outcome`.
async fn send(lanes_root: &Path, lane: &str, request: &Value) -> Result<Value, SendError> {
    // A lane id names one directory under the root, never a path out of it.
    if lane.is_empty() || lane == "." || lane == ".." || lane.contains(['/', '\\']) {
        return Err(SendError::Failed(format!("invalid lane id {lane:?}")));
    }
    let socket = lanes_root.join(lane).join("control").join("director.sock");
    if !socket.exists() {
        return Err(SendError::NotRunning(lane.to_string()));
    }
    let reply = tokio::time::timeout(SOCKET_TIMEOUT, round_trip(&socket, request))
        .await
        .map_err(|_| {
            SendError::Failed(format!(
                "lane {lane} did not answer within {} s",
                SOCKET_TIMEOUT.as_secs()
            ))
        })?
        .map_err(|e| SendError::Failed(e.to_string()))?;
    if reply["ok"] == json!(true) {
        Ok(reply.get("outcome").cloned().unwrap_or_else(|| json!({})))
    } else {
        let reason = reply["error"].as_str().unwrap_or("unknown error");
        Err(SendError::Failed(reason.to_string()))
    }
}

async fn round_trip(socket: &Path, request: &Value) -> Result<Value> {
    let mut stream = UnixStream::connect(socket)
        .await
        .map_err(|e| anyhow!("cannot connect to director socket: {e}"))?;
    let mut line = serde_json::to_vec(request)?;
    line.push(b'\n');
    stream
        .write_all(&line)
        .await
        .map_err(|e| anyhow!("failed to write request: {e}"))?;
    stream.flush().await?;
    let mut reader = BufReader::new(stream.take(MAX_RESPONSE));
    let mut reply = Vec::new();
    reader
        .read_until(b'\n', &mut reply)
        .await
        .map_err(|e| anyhow!("failed to read response: {e}"))?;
    if reply.last() != Some(&b'\n') {
        return Err(anyhow!("director socket closed without a reply"));
    }
    serde_json::from_slice(&reply).map_err(|e| anyhow!("invalid reply from the lane: {e}"))
}

/// What every tool needs: the lanes root the server was started with, if any.
#[derive(Clone)]
struct Context {
    default_root: Option<Arc<PathBuf>>,
}

impl Context {
    /// This call's lanes root: its `lanes_root` input, else the server's `--lanes-root`,
    /// else the default every `cowproof` command shares (`run::lanes_root`).
    fn root(&self, tool: &str, input: &Value) -> portkit_core::Result<PathBuf> {
        let given = input
            .get("lanes_root")
            .and_then(Value::as_str)
            .map(Path::new);
        let arg = given.or(self.default_root.as_deref().map(PathBuf::as_path));
        current_lanes_root(arg).map_err(|e| Error::tool_failed(tool, e.to_string()))
    }
}

fn lanes_root_property() -> Value {
    json!({
        "type": "string",
        "description": "the directory that holds the lanes; omit for the server's own, \
                        by default ~/.cache/cowproof/lanes"
    })
}

fn str_input<'a>(input: &'a Value, name: &str) -> Option<&'a str> {
    input.get(name).and_then(Value::as_str)
}

struct LanesTool(Context);
struct EventsTool(Context);
struct RuleTool(Context);
struct NoteTool(Context);

#[async_trait]
impl Tool for LanesTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec::new(
            "lanes",
            "List every lane with its state, its parked blocking escalation (id and age, not \
             the question), its pending notes and its last event time. Reads the lane files \
             and returns at once.",
            json!({
                "type": "object",
                "properties": {
                    "lanes_root": lanes_root_property(),
                    "cache_ttl": {
                        "type": "string",
                        "description": format!(
                            "how long a parked lane's prompt cache lives, such as 1h or 30m; \
                             default {DEFAULT_CACHE_TTL}")
                    },
                },
                "additionalProperties": false,
            }),
        )
    }

    async fn call(&self, input: Value) -> portkit_core::Result<Value> {
        let root = self.0.root("lanes", &input)?;
        let ttl = parse_duration(str_input(&input, "cache_ttl").unwrap_or(DEFAULT_CACHE_TTL))
            .map_err(|e| Error::invalid_input("lanes", e.to_string()))?;
        let lanes = lane_snapshots(&root, now_ms(), ttl.as_millis() as u64)
            .map_err(|e| Error::tool_failed("lanes", e.to_string()))?;
        Ok(json!({ "lanes_root": root, "lanes": lanes }))
    }
}

#[async_trait]
impl Tool for EventsTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec::new(
            "events",
            "Return the escalation-queue events (asks, rulings, notes, deliveries) that lanes \
             gained since a cursor, and the cursor for the next call. Without a cursor it \
             starts from the beginning of each queue. It never waits: poll it, passing back \
             the cursor you were given.",
            json!({
                "type": "object",
                "properties": {
                    "lanes_root": lanes_root_property(),
                    "cursor": {
                        "type": "string",
                        "description": "the cursor a previous call returned; omit to read from the start"
                    },
                    "lane": {
                        "type": "string",
                        "description": "only this lane's events; omit for every lane"
                    },
                },
                "additionalProperties": false,
            }),
        )
    }

    async fn call(&self, input: Value) -> portkit_core::Result<Value> {
        let root = self.0.root("events", &input)?;
        let since = match str_input(&input, "cursor") {
            Some(text) => {
                decode_cursor(text).map_err(|e| Error::invalid_input("events", e.to_string()))?
            }
            None => Default::default(),
        };
        let batch = read_events(&root, &since, str_input(&input, "lane"))
            .map_err(|e| Error::tool_failed("events", e.to_string()))?;
        Ok(json!({
            "events": batch.events,
            "cursor": encode_cursor(&batch.cursor),
            "unreadable": batch.unreadable,
        }))
    }
}

/// The ruling a `rule` call asks for: exactly one of its four verdict fields.
fn ruling_from_input(input: &Value) -> Result<Ruling, &'static str> {
    let answer = str_input(input, "answer");
    let redirect = str_input(input, "redirect");
    let reassign = input.get("reassign");
    let stop = input.get("stop").and_then(Value::as_bool) == Some(true);
    let given = [
        answer.is_some(),
        redirect.is_some(),
        reassign.is_some(),
        stop,
    ];
    if given.iter().filter(|g| **g).count() != 1 {
        return Err("give exactly one of answer, redirect, reassign or stop (true)");
    }
    Ok(if let Some(text) = answer {
        Ruling::Answer(text.to_string())
    } else if let Some(path) = redirect {
        Ruling::Redirect(path.to_string())
    } else if let Some(reassign) = reassign {
        Ruling::Reassign {
            model: str_input(reassign, "model").map(str::to_string),
        }
    } else {
        Ruling::Stop
    })
}

#[async_trait]
impl Tool for RuleTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec::new(
            "rule",
            "Rule on an open escalation of a running lane. Give exactly one verdict: answer \
             (text the builder resumes with), redirect (a new packet path), reassign (the \
             next model on the ladder, or the one named) or stop. Mirrors `cowproof rule`.",
            json!({
                "type": "object",
                "properties": {
                    "lanes_root": lanes_root_property(),
                    "lane": { "type": "string", "description": "the lane id" },
                    "escalation": {
                        "type": "string",
                        "description": "the escalation id, such as lane-id:E1"
                    },
                    "answer": { "type": "string", "description": "the answer text" },
                    "redirect": { "type": "string", "description": "path to a new packet file" },
                    "reassign": {
                        "type": "object",
                        "properties": {
                            "model": {
                                "type": "string",
                                "description": "a specific model; omit for the next on the ladder"
                            }
                        },
                        "additionalProperties": false
                    },
                    "stop": { "type": "boolean", "description": "true to stop the lane" },
                },
                "required": ["lane", "escalation"],
                "additionalProperties": false,
            }),
        )
    }

    async fn call(&self, input: Value) -> portkit_core::Result<Value> {
        let ruling = ruling_from_input(&input).map_err(|e| Error::invalid_input("rule", e))?;
        let root = self.0.root("rule", &input)?;
        // The schema requires both fields; Registry::call checks it before this runs.
        let lane = str_input(&input, "lane").unwrap_or_default();
        let escalation = str_input(&input, "escalation").unwrap_or_default();
        send_rule(&root, lane, escalation, &ruling)
            .await
            .map_err(|e| Error::tool_failed("rule", e.to_string()))
    }
}

#[async_trait]
impl Tool for NoteTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec::new(
            "note",
            "Send a note to a running lane: guidance the builder reads on its next \
             check_ruling, with no escalation opened. Mirrors `cowproof note`.",
            json!({
                "type": "object",
                "properties": {
                    "lanes_root": lanes_root_property(),
                    "lane": { "type": "string", "description": "the lane id" },
                    "text": { "type": "string", "description": "the note" },
                },
                "required": ["lane", "text"],
                "additionalProperties": false,
            }),
        )
    }

    async fn call(&self, input: Value) -> portkit_core::Result<Value> {
        let root = self.0.root("note", &input)?;
        let lane = str_input(&input, "lane").unwrap_or_default();
        let text = str_input(&input, "text").unwrap_or_default();
        send_note(&root, lane, text)
            .await
            .map_err(|e| Error::tool_failed("note", e.to_string()))
    }
}

/// The director's MCP server. `default_root` is `--lanes-root`; each call may
/// name its own `lanes_root`.
pub fn server(default_root: Option<PathBuf>) -> McpServer {
    let ctx = Context {
        default_root: default_root.map(Arc::new),
    };
    let registry = Registry::new()
        .with(LanesTool(ctx.clone()))
        .with(EventsTool(ctx.clone()))
        .with(RuleTool(ctx.clone()))
        .with(NoteTool(ctx));
    McpServer::new(
        registry,
        ServerInfo::new("cowproof-director", env!("CARGO_PKG_VERSION")).with_instructions(
            "The director's tools for cowproof lanes. `lanes` shows every lane; `events` returns \
             new queue events and a cursor to pass back on the next call, and never waits, so \
             poll it. `rule` and `note` reach a running lane. Event summaries hold ids and sizes, \
             not what a builder wrote.",
        ),
    )
}

/// Serve the director's tools on MCP stdio until the host closes stdin.
pub async fn run(default_root: Option<PathBuf>) -> Result<()> {
    portkit_mcp::serve_stdio(server(default_root))
        .await
        .map_err(|e| anyhow!("{e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_served_tools_are_exactly_the_director_tools() {
        let server = server(None);
        let mut served: Vec<&str> = server.registry().names();
        served.sort_unstable();
        assert_eq!(served, ["events", "lanes", "note", "rule"]);
    }

    #[test]
    fn a_rule_call_names_exactly_one_verdict() {
        assert_eq!(
            ruling_from_input(&json!({"answer": "yes"})),
            Ok(Ruling::Answer("yes".into()))
        );
        assert_eq!(
            ruling_from_input(&json!({"reassign": {}})),
            Ok(Ruling::Reassign { model: None })
        );
        assert_eq!(ruling_from_input(&json!({"stop": true})), Ok(Ruling::Stop));
        assert!(ruling_from_input(&json!({})).is_err());
        assert!(ruling_from_input(&json!({"stop": false})).is_err());
        assert!(ruling_from_input(&json!({"answer": "a", "stop": true})).is_err());
    }

    #[tokio::test]
    async fn a_lane_id_cannot_leave_the_lanes_root() {
        let root = Path::new("/nonexistent-cp-root");
        for lane in ["", ".", "..", "../x", "a/b"] {
            let err = send_note(root, lane, "t").await.unwrap_err();
            assert!(matches!(err, SendError::Failed(_)), "{lane:?}: {err}");
        }
        let err = send_note(root, "ok", "t").await.unwrap_err();
        assert!(matches!(err, SendError::NotRunning(_)), "{err}");
    }
}
