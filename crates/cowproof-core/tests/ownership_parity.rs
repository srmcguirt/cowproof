//! Parity tests for the ownership functions: `glob_to_regex`, `glob_matches`,
//! `removed_lines` and `outside_ownership`.
//! Replays behaviour captured from the Node reference through the direct and MCP surfaces.
//!
//! Globs are compared by behaviour, not by regex text: V8 escapes differently in
//! `RegExp.source`, so each glob case carries a `probe` list and the result is one
//! match flag per probe. `glob_to_regex` compiles the Rust regex text with the
//! `regex` crate; `glob_matches` runs the matcher the gates actually use.

use async_trait::async_trait;
use cowproof_core::{glob_matches, glob_to_regex, outside_ownership, removed_lines};
use portkit_core::{Error, Registry, Result, Tool, ToolSpec};
use portkit_port::{CaptureOptions, assert_parity};
use serde_json::{Value, json};
use std::path::Path;

fn string_arg<'a>(tool: &str, input: &'a Value, key: &str) -> Result<&'a str> {
    input
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| Error::invalid_input(tool, format!("{key} must be a string")))
}

fn strings_arg(tool: &str, input: &Value, key: &str) -> Result<Vec<String>> {
    input
        .get(key)
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(String::from)
                .collect()
        })
        .ok_or_else(|| Error::invalid_input(tool, format!("{key} must be an array of strings")))
}

fn glob_spec(name: &str, description: &str) -> ToolSpec {
    ToolSpec::new(
        name,
        description,
        json!({
            "type": "object",
            "properties": {
                "glob": { "type": "string" },
                "probe": { "type": "array", "items": { "type": "string" } }
            },
            "required": ["glob", "probe"]
        }),
    )
}

/// `glob_to_regex`: the regex text it returns, compiled and run on each probe.
struct GlobToRegexTool;

#[async_trait]
impl Tool for GlobToRegexTool {
    fn spec(&self) -> ToolSpec {
        glob_spec(
            "glob_to_regex",
            "Match probe paths with the regex that glob_to_regex builds",
        )
    }

    async fn call(&self, input: Value) -> Result<Value> {
        let glob = string_arg("glob_to_regex", &input, "glob")?;
        let probe = strings_arg("glob_to_regex", &input, "probe")?;
        let source = glob_to_regex(glob);
        let re = regex::Regex::new(&source).map_err(|e| {
            Error::tool_failed(
                "glob_to_regex",
                format!("regex {source:?} did not compile: {e}"),
            )
        })?;
        let matches: Vec<bool> = probe.iter().map(|p| re.is_match(p)).collect();
        Ok(json!({ "matches": matches }))
    }
}

/// `glob_matches`: the matcher the ownership gates call, run on each probe.
struct GlobMatchesTool;

#[async_trait]
impl Tool for GlobMatchesTool {
    fn spec(&self) -> ToolSpec {
        glob_spec("glob_matches", "Match probe paths with glob_matches")
    }

    async fn call(&self, input: Value) -> Result<Value> {
        let glob = string_arg("glob_matches", &input, "glob")?;
        let probe = strings_arg("glob_matches", &input, "probe")?;
        let matches: Vec<bool> = probe.iter().map(|p| glob_matches(glob, p)).collect();
        Ok(json!({ "matches": matches }))
    }
}

/// `removed_lines`: lines a patch removes from one file.
struct RemovedLinesTool;

#[async_trait]
impl Tool for RemovedLinesTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec::new(
            "removed_lines",
            "Count the lines a patch removes from one file",
            json!({
                "type": "object",
                "properties": {
                    "patch": { "type": "string" },
                    "file": { "type": "string" }
                },
                "required": ["patch", "file"]
            }),
        )
    }

    async fn call(&self, input: Value) -> Result<Value> {
        let patch = string_arg("removed_lines", &input, "patch")?;
        let file = string_arg("removed_lines", &input, "file")?;
        Ok(json!({ "count": removed_lines(patch, file) }))
    }
}

/// `outside_ownership`: files that are protected or not owned.
struct OutsideOwnershipTool;

#[async_trait]
impl Tool for OutsideOwnershipTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec::new(
            "outside_ownership",
            "List the files that are protected or outside the ownership globs",
            json!({
                "type": "object",
                "properties": {
                    "files": { "type": "array", "items": { "type": "string" } },
                    "owns": { "type": "array", "items": { "type": "string" } },
                    "protected": { "type": "array", "items": { "type": "string" } }
                },
                "required": ["files", "owns", "protected"]
            }),
        )
    }

    async fn call(&self, input: Value) -> Result<Value> {
        let files = strings_arg("outside_ownership", &input, "files")?;
        let owns = strings_arg("outside_ownership", &input, "owns")?;
        let protected = strings_arg("outside_ownership", &input, "protected")?;
        Ok(json!({ "outside": outside_ownership(&files, &owns, &protected) }))
    }
}

fn create_registry() -> Registry {
    Registry::new()
        .with(GlobToRegexTool)
        .with(GlobMatchesTool)
        .with(RemovedLinesTool)
        .with(OutsideOwnershipTool)
}

/// Replay the committed fixtures through the direct and MCP surfaces.
#[tokio::test]
async fn parity_committed_fixtures() {
    let fixture_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ownership");
    assert_parity(&fixture_dir, &create_registry()).await;
}

/// The one accepted difference (`removed-lines-removed-text-starts-dashes`, ruling P4-R1) exempts
/// `/count` from replay, so pin the Rust side here: a removed line whose text starts with `--`
/// is a real removal and counts, while the file headers do not.
#[test]
fn removed_line_starting_with_dashes_counts_in_rust() {
    let patch = "diff --git a/test.txt b/test.txt\nindex 1234567..abcdefg 100644\n--- a/test.txt\n+++ b/test.txt\n@@ -1,3 +1,2 @@\n--- sql comment\n a\n b";
    assert_eq!(removed_lines(patch, "test.txt"), 1);
}

/// Capture fresh fixtures from the Node adapter.
/// Run with: PORTKIT_CAPTURE=1 PORTKIT_ADAPTER_CMD="node <adapter>" cargo test -p cowproof-core --test ownership_parity -- --ignored --nocapture
/// Capture records the adapter command as `source`; replace it with a neutral
/// description (and drop `captured_at`) before committing, as the status fixtures do.
/// Capture also writes no `accepted` entries: `removed-lines-removed-text-starts-dashes` needs its
/// `/count` acceptance (Node bug, Rust correct; ruling P4-R1) added back after a recapture.
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

    let output_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ownership");
    let cases_file = output_dir.join("cases.jsonl");

    match portkit_port::capture(&cases_file, &output_dir, &opts).await {
        Ok(report) => {
            println!("Capture report: {report:?}");
            assert!(report.is_success(), "capture had failures: {report:?}");
            println!("Capture successful!");
        }
        Err(e) => panic!("Failed to capture from adapter: {e}"),
    }
}
