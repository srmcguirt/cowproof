//! The requirement this whole layer exists for: schema references are checked
//! *before* the agent's call reaches the tool.
//!
//! It is not enough that a bad name produces an error. The tool must not run
//! at all — a query that executes against a hallucinated column has already
//! done whatever damage it was going to do.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use portkit_core::{async_trait, Registry, Result, Tool, ToolSpec};
use portkit_schema::{SchemaRegistry, Snapshot};
use serde_json::{json, Value};

/// Counts its own invocations, so a test can assert it never ran.
#[derive(Clone, Default)]
struct Query {
    calls: Arc<AtomicUsize>,
}

#[async_trait]
impl Tool for Query {
    fn spec(&self) -> ToolSpec {
        ToolSpec::new(
            "query",
            "Read columns from a table.",
            json!({
                "type": "object",
                "properties": {
                    "table": {
                        "type": "string",
                        "description": "Schema-qualified table name.",
                        "x-schema-ref": "fellwork#table"
                    },
                    "columns": {
                        "type": "array",
                        "items": { "type": "string", "x-schema-ref": "fellwork#column(table)" }
                    }
                },
                "required": ["table"],
                "additionalProperties": false
            }),
        )
    }

    async fn call(&self, input: Value) -> Result<Value> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(json!({"ran": true, "table": input.get("table").cloned()}))
    }
}

fn gated() -> (Registry, Arc<AtomicUsize>) {
    let snapshot = Snapshot::load(std::path::Path::new("tests/fixtures/fellwork.json"))
        .expect("committed fixture must load");
    let tool = Query::default();
    let calls = tool.calls.clone();
    let registry = Registry::new()
        .with(tool)
        .with_resolver(Arc::new(SchemaRegistry::new().with(snapshot)));
    (registry, calls)
}

#[tokio::test]
async fn a_valid_call_reaches_the_tool() {
    let (registry, calls) = gated();
    let out = registry
        .call(
            "query",
            json!({"table": "source.tokens", "columns": ["lemma"]}),
        )
        .await
        .expect("real names must pass");
    assert_eq!(out["ran"], true);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_hallucinated_table_never_reaches_the_tool() {
    let (registry, calls) = gated();
    let err = registry
        .call("query", json!({"table": "source.user_accounts"}))
        .await
        .unwrap_err();

    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "the tool must not have run"
    );
    assert!(
        err.is_caller_fault(),
        "the model can fix this by changing arguments"
    );
    assert!(err.to_string().contains("not a known table"), "{err}");
}

#[tokio::test]
async fn a_hallucinated_column_never_reaches_the_tool() {
    let (registry, calls) = gated();
    let err = registry
        .call(
            "query",
            json!({"table": "source.tokens", "columns": ["user_email"]}),
        )
        .await
        .unwrap_err();

    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "the tool must not have run"
    );
    assert!(err.to_string().contains("/columns/0"), "{err}");
}

#[tokio::test]
async fn a_typo_comes_back_with_the_correction_and_provenance() {
    let (registry, _) = gated();
    let err = registry
        .call(
            "query",
            json!({"table": "source.tokens", "columns": ["surface_from"]}),
        )
        .await
        .unwrap_err()
        .to_string();

    assert!(
        err.contains("`surface_form`"),
        "should suggest the real column: {err}"
    );
    assert!(
        err.contains("PostgresCatalog"),
        "should say what it checked against: {err}"
    );
}

#[tokio::test]
async fn shape_errors_are_reported_before_reference_errors() {
    // A reference check on a malformed call produces confusing follow-on
    // errors, so JSON Schema validation has to win.
    let (registry, calls) = gated();
    let err = registry
        .call("query", json!({"table": "source.nope", "bogus": 1}))
        .await
        .unwrap_err()
        .to_string();

    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(
        err.contains("bogus"),
        "shape error should surface first: {err}"
    );
}

#[tokio::test]
async fn without_a_resolver_reference_checking_is_simply_skipped() {
    // Downstream repos that have no snapshot must still be able to use tools.
    let registry = Registry::new().with(Query::default());
    let out = registry
        .call("query", json!({"table": "anything.at.all"}))
        .await;
    assert!(
        out.is_ok(),
        "an unconfigured registry must not reject every call"
    );
}

#[tokio::test]
async fn the_gate_also_applies_on_the_mcp_surface() {
    // Agents call through MCP, so a gate that only guards the CLI is no gate.
    use portkit_mcp::{McpServer, ServerInfo};
    let (registry, calls) = gated();
    let server = McpServer::new(registry, ServerInfo::default());

    let result = server
        .call_tool(
            "query",
            json!({"table": "source.tokens", "columns": ["user_email"]}),
        )
        .await;

    assert!(result.is_error, "MCP must report the rejection");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "the tool must not have run"
    );
    assert!(result.content[0].as_text().contains("not a known column"));
}
