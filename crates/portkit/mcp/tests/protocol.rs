//! Protocol-level tests for the MCP server.
//!
//! These drive raw JSON-RPC lines rather than the typed helpers, because that
//! is what an actual host sends — a bug in serialization would slip past a
//! test that only ever spoke Rust structs.

use portkit_core::{async_trait, Error, Registry, Result, Tool, ToolSpec};
use portkit_mcp::{McpServer, ServerInfo, LATEST_PROTOCOL_VERSION};
use serde_json::{json, Value};

struct Echo;

#[async_trait]
impl Tool for Echo {
    fn spec(&self) -> ToolSpec {
        ToolSpec::new(
            "echo",
            "Return the input unchanged.",
            json!({"type": "object", "properties": {"value": {}}}),
        )
    }

    async fn call(&self, input: Value) -> Result<Value> {
        Ok(input)
    }
}

struct AlwaysFails;

#[async_trait]
impl Tool for AlwaysFails {
    fn spec(&self) -> ToolSpec {
        ToolSpec::new("boom", "Always fails.", json!({"type": "object"}))
    }

    async fn call(&self, _input: Value) -> Result<Value> {
        Err(Error::tool_failed("boom", "detonated as designed"))
    }
}

fn server() -> McpServer {
    McpServer::new(
        Registry::new().with(Echo).with(AlwaysFails),
        ServerInfo::new("test-server", "9.9.9").with_instructions("Testing only."),
    )
}

async fn send(server: &McpServer, request: Value) -> Value {
    let line = server
        .handle_line(&request.to_string())
        .await
        .expect("expected a response to a request carrying an id");
    serde_json::from_str(&line).expect("response must be valid JSON")
}

#[tokio::test]
async fn initialize_reports_tools_capability_and_identity() {
    let response = send(
        &server(),
        json!({"jsonrpc": "2.0", "id": 1, "method": "initialize",
               "params": {"protocolVersion": LATEST_PROTOCOL_VERSION}}),
    )
    .await;

    let result = &response["result"];
    assert_eq!(result["protocolVersion"], LATEST_PROTOCOL_VERSION);
    assert_eq!(result["serverInfo"]["name"], "test-server");
    assert_eq!(result["serverInfo"]["version"], "9.9.9");
    assert_eq!(result["instructions"], "Testing only.");
    assert!(result["capabilities"]["tools"].is_object());
}

#[tokio::test]
async fn initialize_echoes_an_older_protocol_version_it_supports() {
    // Hosts pin older revisions; answering with our newest would strand them.
    let response = send(
        &server(),
        json!({"jsonrpc": "2.0", "id": 1, "method": "initialize",
               "params": {"protocolVersion": "2024-11-05"}}),
    )
    .await;
    assert_eq!(response["result"]["protocolVersion"], "2024-11-05");
}

#[tokio::test]
async fn initialize_offers_its_own_version_when_the_client_asks_for_an_unknown_one() {
    let response = send(
        &server(),
        json!({"jsonrpc": "2.0", "id": 1, "method": "initialize",
               "params": {"protocolVersion": "1999-01-01"}}),
    )
    .await;
    assert_eq!(
        response["result"]["protocolVersion"],
        LATEST_PROTOCOL_VERSION
    );
}

#[tokio::test]
async fn tools_list_exposes_each_tool_with_its_schema() {
    let response = send(
        &server(),
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
    )
    .await;

    let tools = response["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 2);
    // Registry ordering is stable, so hosts see a consistent list.
    assert_eq!(tools[0]["name"], "boom");
    assert_eq!(tools[1]["name"], "echo");
    assert!(tools[1]["inputSchema"].is_object());
}

#[tokio::test]
async fn tools_call_returns_both_text_and_structured_content() {
    let response = send(
        &server(),
        json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
               "params": {"name": "echo", "arguments": {"value": 42}}}),
    )
    .await;

    let result = &response["result"];
    assert_eq!(result["isError"], false);
    assert_eq!(result["structuredContent"], json!({"value": 42}));

    // The text block must parse back to the same value for clients that do
    // not read structuredContent.
    let text = result["content"][0]["text"].as_str().unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(text).unwrap(),
        json!({"value": 42})
    );
}

#[tokio::test]
async fn tools_call_defaults_missing_arguments_to_an_empty_object() {
    // Models routinely omit `arguments` for zero-argument tools.
    let response = send(
        &server(),
        json!({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "echo"}}),
    )
    .await;
    assert_eq!(response["result"]["structuredContent"], json!({}));
}

#[tokio::test]
async fn a_failing_tool_reports_in_band_so_the_model_can_recover() {
    let response = send(
        &server(),
        json!({"jsonrpc": "2.0", "id": 5, "method": "tools/call",
               "params": {"name": "boom", "arguments": {}}}),
    )
    .await;

    // Per the MCP spec, tool failures are results with isError, not JSON-RPC
    // errors — the transport must not swallow them.
    assert!(
        response["error"].is_null(),
        "tool failure must not become a transport error"
    );
    assert_eq!(response["result"]["isError"], true);
    assert!(response["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains("detonated as designed"));
}

#[tokio::test]
async fn calling_an_unregistered_tool_is_a_protocol_error() {
    let response = send(
        &server(),
        json!({"jsonrpc": "2.0", "id": 6, "method": "tools/call",
               "params": {"name": "nope", "arguments": {}}}),
    )
    .await;
    assert_eq!(response["error"]["code"], -32602);
}

#[tokio::test]
async fn notifications_are_never_answered() {
    // A reply to a notification is a protocol violation that wedges some hosts.
    let server = server();
    assert!(server
        .handle_line(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}).to_string())
        .await
        .is_none());
}

#[tokio::test]
async fn unknown_methods_return_method_not_found() {
    let response = send(
        &server(),
        json!({"jsonrpc": "2.0", "id": 7, "method": "resources/list"}),
    )
    .await;
    assert_eq!(response["error"]["code"], -32601);
}

#[tokio::test]
async fn malformed_json_returns_a_parse_error_rather_than_panicking() {
    let line = server()
        .handle_line("{not json")
        .await
        .expect("parse errors are reported");
    let response: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(response["error"]["code"], -32700);
}

#[tokio::test]
async fn ping_is_answered_so_hosts_can_health_check() {
    let response = send(
        &server(),
        json!({"jsonrpc": "2.0", "id": 8, "method": "ping"}),
    )
    .await;
    assert!(response["error"].is_null());
    assert!(response["result"].is_object());
}

#[tokio::test]
async fn batch_requests_are_rejected_clearly() {
    // Removed from MCP in 2025-06-18; a clear rejection beats partial support.
    let line = server()
        .handle_line(r#"[{"jsonrpc":"2.0","id":1,"method":"ping"}]"#)
        .await
        .unwrap();
    let response: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(response["error"]["code"], -32600);
}
