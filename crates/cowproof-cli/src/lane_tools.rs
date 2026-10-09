//! `cowproof lane-tools`: the builder's tools as an MCP stdio server (D22).
//!
//! This process runs inside the sandbox and is only a client. It exposes
//! `ask`, `check_ruling` and `run_check` on portkit's MCP server and forwards
//! each call as one request line to the lane's runner socket, where the
//! runner (outside the sandbox) alone owns the queue, the rulings and the
//! records. It keeps no state, reads no files and never touches the control
//! directory. Stdout carries MCP frames and nothing else.

use anyhow::{Result, anyhow};
use portkit_core::{Error, Registry, Tool, ToolSpec, async_trait};
use portkit_mcp::{McpServer, ServerInfo};
use serde_json::{Value, json};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

/// The most one response from the runner may occupy, in bytes.
const MAX_RESPONSE: u64 = 1024 * 1024;

#[derive(Clone, Copy)]
enum Op {
    Ask,
    CheckRuling,
    RunCheck,
}

struct Forward {
    op: Op,
    socket: Arc<PathBuf>,
}

impl Op {
    fn name(self) -> &'static str {
        match self {
            Op::Ask => "ask",
            Op::CheckRuling => "check_ruling",
            Op::RunCheck => "run_check",
        }
    }
}

fn id_schema(what: &str, optional: bool) -> Value {
    let mut schema = json!({
        "type": "object",
        "properties": { "id": { "type": "string", "description": what } },
        "additionalProperties": false,
    });
    if !optional {
        schema["required"] = json!(["id"]);
    }
    schema
}

#[async_trait]
impl Tool for Forward {
    fn spec(&self) -> ToolSpec {
        match self.op {
            Op::Ask => ToolSpec::new(
                "ask",
                "Ask the director a question. A blocking ask parks you until it is ruled; a \
                 non-blocking ask returns an id you can poll with check_ruling.",
                json!({
                    "type": "object",
                    "properties": {
                        "kind": { "type": "string", "enum": ["blocker", "design", "scope", "environment"] },
                        "question": { "type": "string", "description": "one paragraph" },
                        "tried": { "type": "array", "items": { "type": "string" },
                                   "description": "what was attempted and what happened" },
                        "options": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "id": { "type": "string" },
                                    "summary": { "type": "string" },
                                    "cost": { "type": "string" },
                                },
                                "required": ["id", "summary", "cost"],
                                "additionalProperties": false,
                            },
                        },
                        "recommend": { "type": "string", "description": "the id of one option" },
                        "blocking": { "type": "boolean" },
                    },
                    "required": ["kind", "question", "tried", "options", "recommend", "blocking"],
                    "additionalProperties": false,
                }),
            ),
            Op::CheckRuling => ToolSpec::new(
                "check_ruling",
                "Check whether an ask has been ruled. Also returns any notes the director sent \
                 you since the last call; each note is returned once. Call with no id to receive notes without an escalation.",
                id_schema(
                    "the id `ask` returned, or omit to check for notes only",
                    true,
                ),
            ),
            Op::RunCheck => ToolSpec::new(
                "run_check",
                "Run one of the packet's declared checks in a fresh sandbox and return its exit \
                 status and output.",
                id_schema("a check id declared in the packet", false),
            ),
        }
    }

    async fn call(&self, input: Value) -> portkit_core::Result<Value> {
        let name = self.op.name();
        // Only the fields each op defines are forwarded.
        let request = match self.op {
            Op::Ask => json!({ "op": name, "ask": input }),
            Op::CheckRuling => {
                if input.get("id").is_some() && input["id"] != json!(null) {
                    json!({ "op": name, "id": input["id"] })
                } else {
                    json!({ "op": name })
                }
            }
            Op::RunCheck => json!({ "op": name, "id": input["id"] }),
        };
        let mut response = round_trip(&self.socket, &request)
            .await
            .map_err(|e| Error::tool_failed(name, e.to_string()))?;
        if response["ok"] != json!(true) {
            let reason = response["error"].as_str().unwrap_or("the runner refused");
            return Err(Error::tool_failed(name, reason));
        }
        if let Some(fields) = response.as_object_mut() {
            fields.remove("ok");
        }
        Ok(response)
    }
}

/// One request line out, one response line back, on a fresh connection.
async fn round_trip(socket: &PathBuf, request: &Value) -> Result<Value> {
    let mut stream = UnixStream::connect(socket)
        .await
        .map_err(|e| anyhow!("cannot reach the runner: {e}"))?;
    let mut line = serde_json::to_vec(request)?;
    line.push(b'\n');
    stream.write_all(&line).await?;
    stream.flush().await?;
    let mut reader = BufReader::new(stream.take(MAX_RESPONSE));
    let mut response = Vec::new();
    reader.read_until(b'\n', &mut response).await?;
    if response.last() != Some(&b'\n') {
        return Err(anyhow!("the runner closed the connection without a reply"));
    }
    serde_json::from_slice(&response).map_err(|e| anyhow!("the runner sent an invalid reply: {e}"))
}

/// The MCP server for a lane's socket: exactly three tools.
pub fn server(socket: PathBuf) -> McpServer {
    let socket = Arc::new(socket);
    let tool = |op| Forward {
        op,
        socket: socket.clone(),
    };
    McpServer::new(
        Registry::new()
            .with(tool(Op::Ask))
            .with(tool(Op::CheckRuling))
            .with(tool(Op::RunCheck)),
        ServerInfo::new("cowproof-lane-tools", env!("CARGO_PKG_VERSION")),
    )
}

/// Serve MCP on stdio until the host closes stdin.
pub async fn run(socket: PathBuf) -> Result<()> {
    portkit_mcp::serve_stdio(server(socket))
        .await
        .map_err(|e| anyhow!("{e}"))
}
