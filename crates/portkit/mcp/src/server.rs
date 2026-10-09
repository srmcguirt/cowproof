//! Request dispatch, independent of transport.
//!
//! Keeping dispatch transport-free is what lets the parity harness call tools
//! through the exact code path an agent uses, without spawning a process.

use std::sync::Arc;

use serde_json::{json, Value};
use tracing::{debug, warn};

use portkit_core::budget::{self, Budget};
use portkit_core::trace::{NullRecorder, Outcome, Recorder, Surface, Timer};
use portkit_core::{Error, Registry};

use crate::protocol::*;

/// An MCP server over a [`Registry`].
///
/// Cheap to clone; the registry sits behind an `Arc`.
#[derive(Clone)]
pub struct McpServer {
    registry: Arc<Registry>,
    info: ServerInfo,
    /// Applied to every tool result on the way out, unless the tool declares
    /// a tighter one. An agent cannot ask for less after the fact — by then
    /// the tokens are already spent.
    budget: Budget,
    /// Records what each call actually cost in context. Defaults to
    /// discarding, so tracing is opt-in.
    recorder: Arc<dyn Recorder>,
}

impl McpServer {
    pub fn new(registry: Registry, info: ServerInfo) -> Self {
        Self {
            registry: Arc::new(registry),
            info,
            budget: Budget::default(),
            recorder: Arc::new(NullRecorder),
        }
    }

    /// Record every call's cost. See [`portkit_core::trace`].
    #[must_use]
    pub fn with_recorder(mut self, recorder: Arc<dyn Recorder>) -> Self {
        self.recorder = recorder;
        self
    }

    /// Override the default output budget for this server.
    #[must_use]
    pub fn with_budget(mut self, budget: Budget) -> Self {
        self.budget = budget;
        self
    }

    /// The budget in force for a tool: its own declaration wins over the
    /// server default, because the author knows which results can run away.
    fn budget_for(&self, name: &str) -> Budget {
        self.registry
            .get(name)
            .and_then(|t| t.spec().budget)
            .unwrap_or(self.budget)
    }

    /// Trim a value to budget and attach an actionable note about what went.
    fn budgeted(&self, name: &str, value: serde_json::Value) -> serde_json::Value {
        let spec = self.registry.get(name).map(|t| t.spec());
        let schema = spec.as_ref().and_then(|s| s.output_schema.as_ref());
        let out = budget::apply_annotated(&value, schema, &self.budget_for(name));
        if out.was_trimmed() {
            debug!(
                tool = name,
                from = out.original_bytes,
                to = out.final_bytes,
                "trimmed tool output to budget"
            );
        }
        out.value
    }

    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    pub fn info(&self) -> &ServerInfo {
        &self.info
    }

    /// Handle one raw JSON line, returning the line to write back.
    ///
    /// `None` means "say nothing" — the message was a notification, which the
    /// JSON-RPC spec forbids answering.
    pub async fn handle_line(&self, line: &str) -> Option<String> {
        let value: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(err) => {
                warn!(%err, "malformed JSON on stdin");
                return serde_json::to_string(&Response::error(
                    Value::Null,
                    PARSE_ERROR,
                    format!("parse error: {err}"),
                ))
                .ok();
            }
        };

        let response = self.handle_value(value).await?;
        serde_json::to_string(&response).ok()
    }

    /// Handle one parsed message.
    pub async fn handle_value(&self, value: Value) -> Option<Response> {
        // Batches were removed in MCP 2025-06-18; reject them clearly rather
        // than half-supporting them.
        if value.is_array() {
            return Some(Response::error(
                Value::Null,
                INVALID_REQUEST,
                "batch requests are not supported",
            ));
        }

        let request: Request = match serde_json::from_value(value) {
            Ok(r) => r,
            Err(err) => {
                return Some(Response::error(
                    Value::Null,
                    INVALID_REQUEST,
                    format!("invalid request: {err}"),
                ))
            }
        };

        let is_notification = request.is_notification();
        let id = request.id.clone().unwrap_or(Value::Null);
        debug!(method = %request.method, notification = is_notification, "dispatching");

        let outcome = self.dispatch(&request).await;

        // Notifications get no reply, even when handling them failed.
        if is_notification {
            if let Err(err) = outcome {
                warn!(method = %request.method, %err, "notification handler failed");
            }
            return None;
        }

        Some(match outcome {
            Ok(result) => Response::result(id, result),
            Err(rpc) => Response::error(id, rpc.code, rpc.message),
        })
    }

    async fn dispatch(&self, request: &Request) -> std::result::Result<Value, RpcError> {
        match request.method.as_str() {
            "initialize" => Ok(self.initialize(request.params.as_ref())),
            "ping" => Ok(json!({})),
            "tools/list" => Ok(json!({ "tools": self.tool_descriptors() })),
            "tools/call" => self.tools_call(request.params.as_ref()).await,

            // Client-to-server notifications we acknowledge by ignoring.
            m if m.starts_with("notifications/") => Ok(json!({})),

            other => Err(RpcError {
                code: METHOD_NOT_FOUND,
                message: format!("method not found: {other}"),
            }),
        }
    }

    fn initialize(&self, params: Option<&Value>) -> Value {
        // Echo the client's protocol version when we speak it; otherwise answer
        // with our newest and let the client decide whether it can proceed.
        let requested = params
            .and_then(|p| p.get("protocolVersion"))
            .and_then(Value::as_str);
        let version = match requested {
            Some(v) if SUPPORTED_PROTOCOL_VERSIONS.contains(&v) => v,
            Some(v) => {
                warn!(client_version = %v, "unsupported protocol version; offering ours");
                LATEST_PROTOCOL_VERSION
            }
            None => LATEST_PROTOCOL_VERSION,
        };

        let mut result = json!({
            "protocolVersion": version,
            "capabilities": { "tools": { "listChanged": false } },
            "serverInfo": { "name": self.info.name, "version": self.info.version },
        });

        if let Some(instructions) = &self.info.instructions {
            result["instructions"] = json!(instructions);
        }
        result
    }

    fn tool_descriptors(&self) -> Vec<Value> {
        self.registry
            .specs()
            .into_iter()
            .map(|spec| {
                let mut d = json!({
                    "name": spec.name,
                    "description": spec.description,
                    "inputSchema": spec.input_schema,
                });
                if let Some(schema) = spec.output_schema {
                    d["outputSchema"] = schema;
                }
                d
            })
            .collect()
    }

    async fn tools_call(&self, params: Option<&Value>) -> std::result::Result<Value, RpcError> {
        let params = params.ok_or_else(|| RpcError {
            code: INVALID_PARAMS,
            message: "tools/call requires params".into(),
        })?;

        let name = params
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| RpcError {
                code: INVALID_PARAMS,
                message: "tools/call requires a string `name`".into(),
            })?;

        // Absent arguments mean an empty object, not an error — models routinely
        // omit the key for zero-argument tools.
        let arguments = params
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| json!({}));
        if !arguments.is_object() {
            return Err(RpcError {
                code: INVALID_PARAMS,
                message: "`arguments` must be an object".into(),
            });
        }

        // An unknown tool is a protocol-level mistake: the name was never in
        // tools/list, so surface it as a JSON-RPC error.
        if self.registry.get(name).is_none() {
            return Err(RpcError {
                code: INVALID_PARAMS,
                message: format!("unknown tool `{name}`"),
            });
        }

        // Everything past here is the tool's own business. Failures ride back
        // in-band as isError so the model can read them and try again.
        let timer = Timer::start(
            name,
            Surface::Mcp,
            &arguments,
            portkit_core::trace::now_rfc3339(),
        );
        let result = match self.registry.call(name, arguments).await {
            Ok(value) => {
                let produced = measure(&value);
                let trimmed = self.budgeted(name, value);
                let delivered = measure(&trimmed);
                self.recorder.record(timer.finish(
                    Outcome::Ok,
                    produced,
                    delivered,
                    usize::from(delivered < produced),
                ));
                ToolCallResult::ok(trimmed)
            }
            Err(err) => {
                debug!(tool = %name, %err, "tool call failed");
                // A rejection is the gate working; a failure is the tool
                // breaking. Recording them the same way would hide both.
                let outcome = if err.is_caller_fault() {
                    Outcome::Rejected
                } else {
                    Outcome::Failed
                };
                let message = describe(&err);
                self.recorder
                    .record(timer.finish(outcome, 0, message.len(), 0));
                ToolCallResult::failed(message)
            }
        };

        serde_json::to_value(result).map_err(|err| RpcError {
            code: INTERNAL_ERROR,
            message: format!("could not serialize tool result: {err}"),
        })
    }

    /// Call a tool through the MCP result envelope without a transport.
    ///
    /// This is the path the parity harness uses for `--through-mcp`: it proves
    /// the envelope an agent sees carries the same value the tool returned.
    pub async fn call_tool(&self, name: &str, arguments: Value) -> ToolCallResult {
        match self.registry.call(name, arguments).await {
            Ok(value) => ToolCallResult::ok(self.budgeted(name, value)),
            Err(err) => ToolCallResult::failed(describe(&err)),
        }
    }
}

/// Render an error for a model's eyes: say what went wrong and whose fault it is.
fn describe(err: &Error) -> String {
    if err.is_caller_fault() {
        format!("{err} (check the tool's inputSchema and retry)")
    } else {
        err.to_string()
    }
}

fn measure(v: &serde_json::Value) -> usize {
    serde_json::to_vec(v).map(|b| b.len()).unwrap_or(0)
}

struct RpcError {
    code: i64,
    message: String,
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} (code {})", self.message, self.code)
    }
}
