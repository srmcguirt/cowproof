//! JSON-RPC 2.0 envelopes and the MCP payloads portkit speaks.
//!
//! Hand-rolled rather than pulled from an SDK: a tools-only server is a small
//! amount of protocol, and a template forked into many repos benefits more
//! from being auditable and churn-free than from a dependency.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Protocol revisions this server can speak, newest first.
///
/// During `initialize` the client proposes a version; we echo it back when we
/// recognise it, and otherwise answer with our newest and let the client
/// decide whether it can proceed.
pub const SUPPORTED_PROTOCOL_VERSIONS: &[&str] = &["2025-06-18", "2025-03-26", "2024-11-05"];

pub const LATEST_PROTOCOL_VERSION: &str = SUPPORTED_PROTOCOL_VERSIONS[0];

// JSON-RPC 2.0 error codes (§5.1).
pub const PARSE_ERROR: i64 = -32700;
pub const INVALID_REQUEST: i64 = -32600;
pub const METHOD_NOT_FOUND: i64 = -32601;
pub const INVALID_PARAMS: i64 = -32602;
pub const INTERNAL_ERROR: i64 = -32603;

/// An incoming JSON-RPC message. A missing `id` marks it a notification,
/// which must not be answered.
#[derive(Debug, Clone, Deserialize)]
pub struct Request {
    #[serde(default)]
    pub jsonrpc: String,
    #[serde(default)]
    pub id: Option<Value>,
    pub method: String,
    #[serde(default)]
    pub params: Option<Value>,
}

impl Request {
    pub fn is_notification(&self) -> bool {
        self.id.is_none()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Response {
    pub jsonrpc: &'static str,
    pub id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ResponseError>,
}

impl Response {
    pub fn result(id: Value, result: Value) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            result: Some(result),
            error: None,
        }
    }

    pub fn error(id: Value, code: i64, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            result: None,
            error: Some(ResponseError {
                code,
                message: message.into(),
                data: None,
            }),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ResponseError {
    pub code: i64,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

/// Identity reported to clients during `initialize`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInfo {
    pub name: String,
    pub version: String,
    /// Guidance shown to the model alongside the tool list.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instructions: Option<String>,
}

impl ServerInfo {
    pub fn new(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
            instructions: None,
        }
    }

    pub fn with_instructions(mut self, instructions: impl Into<String>) -> Self {
        let instructions = instructions.into();
        if !instructions.trim().is_empty() {
            self.instructions = Some(instructions);
        }
        self
    }
}

impl Default for ServerInfo {
    fn default() -> Self {
        Self::new("portkit", env!("CARGO_PKG_VERSION"))
    }
}

/// Result of `tools/call`.
///
/// Tool failures travel here with `is_error: true` rather than as a JSON-RPC
/// error — the MCP spec routes them in-band so the model can read what went
/// wrong and correct its next call, instead of the transport swallowing it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCallResult {
    pub content: Vec<Content>,
    /// Machine-readable result, mirroring the text content. Clients that
    /// understand it skip re-parsing the text block.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "structuredContent"
    )]
    pub structured_content: Option<Value>,
    #[serde(default, rename = "isError")]
    pub is_error: bool,
}

impl ToolCallResult {
    pub fn ok(value: Value) -> Self {
        let text = serde_json::to_string_pretty(&value).unwrap_or_else(|_| value.to_string());
        Self {
            content: vec![Content::text(text)],
            structured_content: Some(value),
            is_error: false,
        }
    }

    pub fn failed(message: impl Into<String>) -> Self {
        Self {
            content: vec![Content::text(message)],
            structured_content: None,
            is_error: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Content {
    Text { text: String },
}

impl Content {
    pub fn text(text: impl Into<String>) -> Self {
        Content::Text { text: text.into() }
    }

    pub fn as_text(&self) -> &str {
        match self {
            Content::Text { text } => text,
        }
    }
}
