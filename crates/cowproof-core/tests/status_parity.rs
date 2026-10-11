//! Parity tests for status taxonomy classification.
//! Captures behavior from the Node reference and verifies the Rust port.

use async_trait::async_trait;
use cowproof_core::status::*;
use portkit_core::{Registry, Tool, ToolSpec};
use portkit_port::{CaptureOptions, assert_parity};
use serde_json::{Value, json};
use std::path::Path;

/// Tool implementation for classify_status.
struct ClassifyStatusTool;

#[async_trait]
impl Tool for ClassifyStatusTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec::new(
            "classify_status",
            "Classify a lane status from facts",
            json!({
                "type": "object",
                "properties": {
                    "exitCode": { "type": ["integer", "null"] },
                    "signal": { "type": ["string", "null"] },
                    "terminalEvent": { "type": "boolean", "default": false },
                    "lastType": { "type": ["string", "null"] },
                    "handoff": { "type": "boolean", "default": false },
                    "providerRefusal": { "type": "boolean", "default": false },
                    "truncated": { "type": "boolean", "default": false },
                    "timeout": { "type": "boolean", "default": false },
                    "costCap": { "type": "boolean", "default": false },
                    "sandboxDenied": { "type": "boolean", "default": false },
                    "appendOnlyBreaches": { "type": ["integer", "array"], "default": 0 },
                    "violations": { "type": ["integer", "array"], "default": 0 }
                }
            }),
        )
    }

    async fn call(&self, input: Value) -> portkit_core::Result<Value> {
        let facts: StatusFacts = serde_json::from_value(input)?;
        let (status, status_class) = classify_status(&facts);
        Ok(json!({
            "status": status.as_str(),
            "statusClass": status_class.as_str()
        }))
    }
}

/// Tool implementation for classify_opencode.
struct ClassifyOpencodeTool;

#[async_trait]
impl Tool for ClassifyOpencodeTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec::new(
            "classify_opencode",
            "Classify a lane status using the opencode branch",
            json!({
                "type": "object",
                "properties": {
                    "exitCode": { "type": ["integer", "null"] },
                    "handoff": { "type": "boolean", "default": false },
                    "providerRefusal": { "type": "boolean", "default": false },
                    "truncated": { "type": "boolean", "default": false }
                }
            }),
        )
    }

    async fn call(&self, input: Value) -> portkit_core::Result<Value> {
        let facts: StatusFacts = serde_json::from_value(input)?;
        let (status, status_class) = classify_opencode(&facts);
        Ok(json!({
            "status": status.as_str(),
            "statusClass": status_class.as_str()
        }))
    }
}

/// Create a registry with the status classification tools.
fn create_registry() -> Registry {
    Registry::new()
        .with(ClassifyStatusTool)
        .clone()
        .with(ClassifyOpencodeTool)
        .clone()
}

/// Run parity tests against committed fixtures.
#[tokio::test]
async fn parity_committed_fixtures() {
    // Find the fixture directory relative to the test binary
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let fixture_dir = Path::new(manifest_dir).join("tests/fixtures/status");
    let registry = create_registry();

    // Run parity on committed fixtures
    assert_parity(&fixture_dir, &registry).await;
}

/// Capture fresh fixtures from the Node adapter.
/// Run with: PORTKIT_CAPTURE=1 cargo test --test status_parity -- --ignored --nocapture
#[tokio::test]
#[ignore]
async fn capture_from_adapter() {
    if std::env::var("PORTKIT_CAPTURE").is_err() {
        println!("Skipping capture test. Set PORTKIT_CAPTURE=1 to run.");
        return;
    }

    let adapter_cmd = std::env::var("PORTKIT_ADAPTER_CMD")
        .expect("set PORTKIT_ADAPTER_CMD to the Node reference adapter command");

    let opts = CaptureOptions::new(adapter_cmd);

    let output_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/status");
    let cases_file = output_dir.join("cases.jsonl");

    match portkit_port::capture(&cases_file, &output_dir, &opts).await {
        Ok(report) => {
            println!("Capture report: {:?}", report);
            if report.is_success() {
                println!("Capture successful!");
            } else {
                eprintln!("Capture had failures!");
            }
        }
        Err(e) => {
            eprintln!("Capture failed: {}", e);
            panic!("Failed to capture from adapter");
        }
    }
}
