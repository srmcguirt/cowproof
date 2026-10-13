//! The parity harness through `pk port replay`, restored from portkit's `tests/parity.rs`
//! and the two replay tests of `tests/cli.rs`.
//!
//! portkit replayed `fixtures/` against its built-in demo registry in-process. Here the
//! fixtures (`fixtures/pk/parity/`, the ten recorded cases of `chunk_text` and
//! `word_frequency`) replay through the real `pk` binary against the same two tools served
//! as plugins, on the direct registry and through the MCP envelope: a tool that is right
//! direct and wrong through MCP is still broken for the agent that has to call it.

#[allow(dead_code)] // this file needs only the fork lock, `var_tmp` and the signal helper
mod common;
mod pk_support;

use pk_support::{Work, describe, parity_fixtures, run, stdout_json, stdout_text};
use serde_json::{Value, json};
use std::collections::BTreeSet;

#[test]
fn replay_of_the_committed_fixtures_passes_on_both_surfaces() {
    let work = Work::with_demo_tools(false);
    let out = run(
        work.pk_with_config()
            .args(["port", "replay", "--fixtures"])
            .arg(parity_fixtures()),
        None,
    );
    assert!(out.status.success(), "{}", describe(&out));
    let text = stdout_text(&out);
    assert!(
        text.contains("surface: direct") && text.contains("surface: mcp"),
        "{text}"
    );
}

#[test]
fn replay_json_reports_every_fixture_on_each_surface() {
    let work = Work::with_demo_tools(false);
    let out = run(
        work.pk_with_config()
            .args(["port", "replay", "--json", "--fixtures"])
            .arg(parity_fixtures()),
        None,
    );
    let report = stdout_json(&out);
    for surface in ["direct", "mcp"] {
        assert!(report[surface].is_object(), "{surface}: {report}");
        let text = report[surface].to_string();
        for case in [
            "defaults-applied",
            "ties-break-alphabetically",
            "empty-input",
        ] {
            assert!(
                text.contains(case),
                "{surface} did not replay {case}: {text}"
            );
        }
    }
}

#[test]
fn replay_exits_non_zero_when_a_fixture_does_not_match() {
    // Guards the property CI depends on: drift must fail the build.
    let work = Work::with_demo_tools(false);
    let fixtures = work.cwd.join("fixtures");
    let tool_dir = fixtures.join("word_frequency");
    std::fs::create_dir_all(&tool_dir).unwrap();
    std::fs::write(
        tool_dir.join("wrong.json"),
        json!({
            "tool": "word_frequency",
            "id": "wrong",
            "input": {"text": "a b"},
            "expected": {"total": 99, "unique": 2, "words": []}
        })
        .to_string(),
    )
    .unwrap();

    let out = run(
        work.pk_with_config()
            .args(["port", "replay", "--fixtures"])
            .arg(&fixtures),
        None,
    );
    assert_eq!(out.status.code(), Some(1), "{}", describe(&out));
    let text = stdout_text(&out);
    assert!(text.contains("/total"), "{text}");
}

#[test]
fn every_registered_tool_has_at_least_one_fixture() {
    // A tool with no fixtures passes parity vacuously. Catch that here rather than
    // discovering it after shipping a silently unverified port.
    let work = Work::with_demo_tools(false);
    let out = run(work.pk_with_config().args(["tools", "--json"]), None);
    let registered: BTreeSet<String> = stdout_json(&out)
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["name"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(registered.len(), 2, "{registered:?}");

    let mut with_fixtures = BTreeSet::new();
    for tool_dir in std::fs::read_dir(parity_fixtures()).unwrap() {
        for fixture in std::fs::read_dir(tool_dir.unwrap().path()).unwrap() {
            let fixture: Value =
                serde_json::from_str(&std::fs::read_to_string(fixture.unwrap().path()).unwrap())
                    .unwrap();
            with_fixtures.insert(fixture["tool"].as_str().unwrap().to_string());
        }
    }
    assert_eq!(
        registered, with_fixtures,
        "a tool without a fixture is unverified; a fixture without a tool cannot replay"
    );
}
