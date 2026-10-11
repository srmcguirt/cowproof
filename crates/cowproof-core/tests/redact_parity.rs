use async_trait::async_trait;
use cowproof_core::redact;
use portkit_core::{Registry, Tool, ToolSpec};
use portkit_port::{CaptureOptions, assert_parity};
use serde_json::{Value, json};
use std::path::Path;

/// Tool implementation for redact.
struct RedactTool;

#[async_trait]
impl Tool for RedactTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec::new(
            "redact",
            "Redact sensitive tokens from text",
            json!({
                "type": "object",
                "properties": {
                    "input": { "type": "string" }
                },
                "required": ["input"]
            }),
        )
    }

    async fn call(&self, input: Value) -> portkit_core::Result<Value> {
        let text: String = serde_json::from_value(input["input"].clone())?;
        let output = redact(&text);
        Ok(json!({ "output": output }))
    }
}

/// Create a registry with the redact tool.
fn create_registry() -> Registry {
    Registry::new().with(RedactTool).clone()
}

/// Run parity tests against committed fixtures.
#[tokio::test]
async fn parity_committed_fixtures() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let fixture_dir = Path::new(manifest_dir).join("tests/fixtures/redact");
    let registry = create_registry();

    assert_parity(&fixture_dir, &registry).await;
}

/// Capture fresh fixtures from the Node adapter.
/// Run with: PORTKIT_CAPTURE=1 PORTKIT_ADAPTER_CMD='node /path/to/redact-adapter.mjs' cargo test --test redact_parity -- --ignored --nocapture
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

    let output_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/redact");
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
