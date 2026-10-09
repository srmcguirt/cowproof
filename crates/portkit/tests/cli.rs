//! End-to-end tests against the built `pk` binary.

use assert_cmd::Command;
use predicates::prelude::*;

fn pk() -> Command {
    Command::cargo_bin("pk").expect("the pk binary must build")
}

#[test]
fn bare_invocation_shows_help_and_fails() {
    pk().assert()
        .failure()
        .stderr(predicate::str::contains("Usage"));
}

#[test]
fn version_matches_the_crate() {
    pk().arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn tools_lists_the_registered_tools() {
    pk().arg("tools").assert().success().stdout(
        predicate::str::contains("chunk_text").and(predicate::str::contains("word_frequency")),
    );
}

#[test]
fn tools_json_emits_parseable_specs() {
    let out = pk().args(["tools", "--json"]).assert().success();
    let specs: Vec<serde_json::Value> =
        serde_json::from_slice(&out.get_output().stdout).expect("--json must emit valid JSON");
    // Not pinned to a count: the reference binary registers demo tools plus
    // whatever the config enables, and that set is meant to grow.
    assert!(
        specs.len() >= 2,
        "expected several tools, got {}",
        specs.len()
    );
    assert!(specs.iter().all(|s| s["input_schema"].is_object()));
    assert!(specs.iter().any(|s| s["name"] == "chunk_text"));
}

#[test]
fn schema_prints_the_tools_json_schema() {
    let out = pk().args(["schema", "chunk_text"]).assert().success();
    let spec: serde_json::Value = serde_json::from_slice(&out.get_output().stdout).unwrap();
    assert_eq!(spec["name"], "chunk_text");
    assert_eq!(spec["input_schema"]["required"][0], "text");
}

#[test]
fn run_accepts_inline_args_and_types_them() {
    let out = pk()
        .args([
            "run",
            "chunk_text",
            "-a",
            "text=abcdefghij",
            "-a",
            "size=4",
            "-a",
            "overlap=1",
        ])
        .assert()
        .success();
    let value: serde_json::Value = serde_json::from_slice(&out.get_output().stdout).unwrap();
    // `size=4` must arrive as a number, not the string "4".
    assert_eq!(value["chunks"][0]["text"], "abcd");
}

#[test]
fn run_reads_arguments_from_stdin() {
    let out = pk()
        .args(["run", "word_frequency", "--input", "-"])
        .write_stdin(r#"{"text": "a b a", "top_k": 2}"#)
        .assert()
        .success();
    let value: serde_json::Value = serde_json::from_slice(&out.get_output().stdout).unwrap();
    assert_eq!(value["total"], 3);
    assert_eq!(value["words"][0]["word"], "a");
}

#[test]
fn run_through_mcp_gives_the_same_answer_as_a_direct_call() {
    // The claim the whole template rests on: the agent surface does not
    // distort results.
    let args = ["run", "word_frequency", "-a", "text=a b a b c"];
    let direct = pk().args(args).assert().success();
    let via_mcp = pk().args(args).arg("--through-mcp").assert().success();
    assert_eq!(direct.get_output().stdout, via_mcp.get_output().stdout);
}

#[test]
fn an_unknown_tool_names_the_alternatives() {
    pk().args(["run", "nope"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("chunk_text"));
}

#[test]
fn invalid_input_fails_without_panicking() {
    pk().args([
        "run",
        "chunk_text",
        "-a",
        "text=abc",
        "-a",
        "size=2",
        "-a",
        "overlap=5",
    ])
    .assert()
    .failure()
    .stderr(predicate::str::contains("overlap").and(predicate::str::contains("panicked").not()));
}

#[test]
fn config_shows_the_effective_settings() {
    let out = pk().arg("config").assert().success();
    let cfg: serde_json::Value = serde_json::from_slice(&out.get_output().stdout).unwrap();
    assert_eq!(cfg["parity"]["epsilon"], 1e-9);
}

#[test]
fn environment_variables_override_config_defaults() {
    let out = pk()
        .env("PK_PARITY__EPSILON", "0.5")
        .arg("config")
        .assert()
        .success();
    let cfg: serde_json::Value = serde_json::from_slice(&out.get_output().stdout).unwrap();
    assert_eq!(cfg["parity"]["epsilon"], 0.5);
}

#[test]
fn replay_of_the_committed_fixtures_passes_on_both_surfaces() {
    pk().args(["port", "replay", "--fixtures", "fixtures"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("surface: direct")
                .and(predicate::str::contains("surface: mcp")),
        );
}

#[test]
fn replay_exits_non_zero_when_a_fixture_does_not_match() {
    // Guards the property CI depends on: drift must fail the build.
    let dir = tempfile::tempdir().unwrap();
    let tool_dir = dir.path().join("word_frequency");
    std::fs::create_dir_all(&tool_dir).unwrap();
    std::fs::write(
        tool_dir.join("wrong.json"),
        serde_json::json!({
            "tool": "word_frequency",
            "id": "wrong",
            "input": {"text": "a b"},
            "expected": {"total": 99, "unique": 2, "words": []}
        })
        .to_string(),
    )
    .unwrap();

    pk().args(["port", "replay", "--fixtures"])
        .arg(dir.path())
        .assert()
        .failure()
        .stdout(predicate::str::contains("/total"));
}

/// A text long enough that chunking it blows any sensible budget.
fn oversized_text() -> String {
    "the quick brown fox jumps over the lazy dog. ".repeat(400)
}

#[test]
fn oversized_output_is_trimmed_to_budget() {
    let out = pk()
        .args(["run", "chunk_text", "-a"])
        .arg(format!("text={}", oversized_text()))
        .args([
            "-a",
            "size=20",
            "-a",
            "overlap=2",
            "--budget",
            "4000",
            "--compact",
        ])
        .assert()
        .success();
    let bytes = out.get_output().stdout.len();
    // +1 for the trailing newline from println!.
    assert!(bytes <= 4_001, "budget 4000 exceeded: {bytes} bytes");
}

#[test]
fn a_trimmed_result_says_how_to_get_the_rest() {
    // "Truncated" with no next step sends the agent back to reading it all.
    let out = pk()
        .args(["run", "chunk_text", "-a"])
        .arg(format!("text={}", oversized_text()))
        .args(["-a", "size=20", "-a", "overlap=2", "--budget", "4000"])
        .assert()
        .success();
    let v: serde_json::Value = serde_json::from_slice(&out.get_output().stdout).unwrap();
    let note = &v["_elided"][0];
    assert_eq!(note["path"], "/chunks");
    assert!(note["total"].as_u64().unwrap() > note["kept"].as_u64().unwrap());
    assert!(
        note["retry"].as_str().unwrap().contains("size"),
        "the hint should come from the tool's schema: {note}"
    );
}

#[test]
fn trimming_keeps_the_summary_fields_beside_the_trimmed_array() {
    let out = pk()
        .args(["run", "chunk_text", "-a"])
        .arg(format!("text={}", oversized_text()))
        .args(["-a", "size=20", "-a", "overlap=2", "--budget", "2000"])
        .assert()
        .success();
    let v: serde_json::Value = serde_json::from_slice(&out.get_output().stdout).unwrap();
    // The count is the part most worth keeping when the list is cut.
    assert_eq!(v["count"], 1000);
}

#[test]
fn full_bypasses_the_budget() {
    let out = pk()
        .args(["run", "chunk_text", "-a"])
        .arg(format!("text={}", oversized_text()))
        .args(["-a", "size=20", "-a", "overlap=2", "--full", "--compact"])
        .assert()
        .success();
    assert!(out.get_output().stdout.len() > 60_000);
}

#[test]
fn budget_and_full_are_mutually_exclusive() {
    pk().args([
        "run",
        "chunk_text",
        "-a",
        "text=abc",
        "--budget",
        "100",
        "--full",
    ])
    .assert()
    .failure();
}

#[test]
fn a_small_result_is_not_annotated() {
    let out = pk()
        .args(["run", "word_frequency", "-a", "text=a b a"])
        .assert()
        .success();
    let v: serde_json::Value = serde_json::from_slice(&out.get_output().stdout).unwrap();
    assert!(
        v.get("_elided").is_none(),
        "nothing was trimmed, so say nothing"
    );
}

#[test]
fn completion_scripts_generate() {
    pk().args(["completion", "zsh"])
        .assert()
        .success()
        .stdout(predicate::str::contains("pk"));
}
