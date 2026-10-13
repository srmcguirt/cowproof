//! `pk`'s command surface end to end, restored from portkit's `tests/cli.rs`.
//!
//! portkit's reference binary carried two built-in demo tools. This workspace has none, so
//! the tests register `fixtures/pk/demo_tools.py` (`chunk_text` and `word_frequency`) as
//! plugins through a `pk.toml` and call the real `pk` binary. The replay tests that were in
//! `cli.rs` are in `pk_parity.rs`; the budget tests keep their place here.

#[allow(dead_code)] // this file needs only the fork lock, `var_tmp` and the signal helper
mod common;
mod pk_support;

use pk_support::{Work, describe, run, stderr_text, stdout_json, stdout_text};
use serde_json::Value;

/// A text long enough that chunking it blows any sensible budget.
fn oversized_text() -> String {
    "the quick brown fox jumps over the lazy dog. ".repeat(400)
}

fn chunk_args(budget_args: &[&str]) -> Vec<String> {
    let mut args: Vec<String> = ["run", "chunk_text", "-a"]
        .map(String::from)
        .into_iter()
        .collect();
    args.push(format!("text={}", oversized_text()));
    args.extend(["-a", "size=20", "-a", "overlap=2"].map(String::from));
    args.extend(budget_args.iter().map(|a| a.to_string()));
    args
}

#[test]
fn bare_invocation_shows_help_and_fails() {
    let work = Work::new();
    let out = run(&mut work.pk(), None);
    assert!(!out.status.success(), "{}", describe(&out));
    assert!(stderr_text(&out).contains("Usage"), "{}", describe(&out));
}

#[test]
fn version_prints_the_name_and_a_semantic_version() {
    let work = Work::new();
    let out = run(work.pk().arg("--version"), None);
    assert!(out.status.success(), "{}", describe(&out));
    // The version is portkit-cli's own, so this does not pin a number; `pk.rs` checks that
    // `cowproof pk` prints the same line.
    let text = stdout_text(&out);
    let version = text
        .trim()
        .strip_prefix("pk ")
        .unwrap_or_else(|| panic!("not `pk <version>`: {text:?}"));
    let parts: Vec<&str> = version.split('.').collect();
    assert_eq!(parts.len(), 3, "{version}");
    assert!(
        parts.iter().all(|p| p.parse::<u32>().is_ok()),
        "not major.minor.patch: {version}"
    );
}

#[test]
fn tools_lists_the_registered_tools() {
    let work = Work::with_demo_tools(false);
    let out = run(work.pk_with_config().arg("tools"), None);
    assert!(out.status.success(), "{}", describe(&out));
    let text = stdout_text(&out);
    assert!(
        text.contains("chunk_text") && text.contains("word_frequency"),
        "{text}"
    );
}

#[test]
fn tools_json_emits_parseable_specs() {
    let work = Work::with_demo_tools(false);
    let out = run(work.pk_with_config().args(["tools", "--json"]), None);
    let specs = stdout_json(&out);
    let specs = specs.as_array().expect("--json emits an array");
    assert_eq!(specs.len(), 2, "{specs:?}");
    assert!(specs.iter().all(|s| s["input_schema"].is_object()));
    assert!(specs.iter().any(|s| s["name"] == "chunk_text"));
}

#[test]
fn schema_prints_the_tools_json_schema() {
    let work = Work::with_demo_tools(false);
    let out = run(work.pk_with_config().args(["schema", "chunk_text"]), None);
    let spec = stdout_json(&out);
    assert_eq!(spec["name"], "chunk_text");
    assert_eq!(spec["input_schema"]["required"][0], "text");
}

#[test]
fn run_accepts_inline_args_and_types_them() {
    let work = Work::with_demo_tools(false);
    let out = run(
        work.pk_with_config().args([
            "run",
            "chunk_text",
            "-a",
            "text=abcdefghij",
            "-a",
            "size=4",
            "-a",
            "overlap=1",
        ]),
        None,
    );
    let value = stdout_json(&out);
    // `size=4` must arrive as a number, not the string "4": the schema rejects a string.
    assert_eq!(value["chunks"][0]["text"], "abcd");
    assert_eq!(value["chunks"][1]["text"], "defg");
}

#[test]
fn run_reads_arguments_from_stdin() {
    let work = Work::with_demo_tools(false);
    let out = run(
        work.pk_with_config()
            .args(["run", "word_frequency", "--input", "-"]),
        Some(br#"{"text": "a b a", "top_k": 2}"#),
    );
    let value = stdout_json(&out);
    assert_eq!(value["total"], 3);
    assert_eq!(value["words"][0]["word"], "a");
}

#[test]
fn run_through_mcp_gives_the_same_answer_as_a_direct_call() {
    // The claim the whole kit rests on: the agent surface does not distort results.
    let work = Work::with_demo_tools(false);
    let args = ["run", "word_frequency", "-a", "text=a b a b c"];
    let direct = run(work.pk_with_config().args(args), None);
    let via_mcp = run(work.pk_with_config().args(args).arg("--through-mcp"), None);
    assert!(direct.status.success(), "{}", describe(&direct));
    assert!(via_mcp.status.success(), "{}", describe(&via_mcp));
    assert_eq!(direct.stdout, via_mcp.stdout);
    assert_eq!(stdout_json(&direct)["total"], 5);
}

#[test]
fn an_unknown_tool_names_the_alternatives() {
    let work = Work::with_demo_tools(false);
    let out = run(work.pk_with_config().args(["run", "nope"]), None);
    assert!(!out.status.success(), "{}", describe(&out));
    let err = stderr_text(&out);
    assert!(
        err.contains("nope") && err.contains("chunk_text") && err.contains("word_frequency"),
        "{err}"
    );
}

#[test]
fn invalid_input_fails_without_panicking() {
    let work = Work::with_demo_tools(false);
    // The plugin refuses an overlap that is not smaller than the size and says why.
    let out = run(
        work.pk_with_config().args([
            "run",
            "chunk_text",
            "-a",
            "text=abc",
            "-a",
            "size=2",
            "-a",
            "overlap=5",
        ]),
        None,
    );
    assert!(!out.status.success(), "{}", describe(&out));
    let err = stderr_text(&out);
    assert!(err.contains("overlap"), "{err}");
    assert!(!err.contains("panicked"), "{err}");
    assert_eq!(out.stdout, b"", "a failed call prints no result");
}

#[test]
fn an_argument_outside_the_schema_is_rejected_before_the_tool_runs() {
    let work = Work::with_demo_tools(false);
    let out = run(
        work.pk_with_config()
            .args(["run", "chunk_text", "-a", "text=abc", "-a", "bogus=1"]),
        None,
    );
    assert!(!out.status.success(), "{}", describe(&out));
    assert!(stderr_text(&out).contains("bogus"), "{}", describe(&out));
}

#[test]
fn config_shows_the_effective_settings() {
    let work = Work::new();
    let out = run(work.pk().arg("config"), None);
    assert_eq!(stdout_json(&out)["parity"]["epsilon"], 1e-9);
}

#[test]
fn environment_variables_override_config_defaults() {
    let work = Work::new();
    let out = run(
        work.pk().env("PK_PARITY__EPSILON", "0.5").arg("config"),
        None,
    );
    assert_eq!(stdout_json(&out)["parity"]["epsilon"], 0.5);
}

#[test]
fn oversized_output_is_trimmed_to_budget() {
    let work = Work::with_demo_tools(false);
    let out = run(
        work.pk_with_config()
            .args(chunk_args(&["--budget", "4000", "--compact"])),
        None,
    );
    assert!(out.status.success(), "{}", describe(&out));
    // +1 for the trailing newline.
    assert!(out.stdout.len() <= 4_001, "{} bytes", out.stdout.len());
    // The trim is announced on stderr, never on stdout.
    assert!(stderr_text(&out).contains("trimmed"), "{}", describe(&out));
}

#[test]
fn a_trimmed_result_says_how_to_get_the_rest() {
    // "Truncated" with no next step sends the agent back to reading it all.
    let work = Work::with_demo_tools(false);
    let out = run(
        work.pk_with_config()
            .args(chunk_args(&["--budget", "4000"])),
        None,
    );
    let v = stdout_json(&out);
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
    let work = Work::with_demo_tools(false);
    let out = run(
        work.pk_with_config()
            .args(chunk_args(&["--budget", "2000"])),
        None,
    );
    let v = stdout_json(&out);
    // The count is the part most worth keeping when the list is cut.
    assert_eq!(v["count"], 1000);
    assert!(v["chunks"].as_array().unwrap().len() < 1000);
}

#[test]
fn full_bypasses_the_budget() {
    let work = Work::with_demo_tools(false);
    let out = run(
        work.pk_with_config()
            .args(chunk_args(&["--full", "--compact"])),
        None,
    );
    assert!(out.status.success(), "{}", describe(&out));
    assert!(out.stdout.len() > 60_000, "{} bytes", out.stdout.len());
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["chunks"].as_array().unwrap().len(), 1000);
    assert!(v.get("_elided").is_none());
}

#[test]
fn budget_and_full_are_mutually_exclusive() {
    let work = Work::with_demo_tools(false);
    let out = run(
        work.pk_with_config().args([
            "run",
            "chunk_text",
            "-a",
            "text=abc",
            "--budget",
            "100",
            "--full",
        ]),
        None,
    );
    assert!(!out.status.success(), "{}", describe(&out));
    assert_eq!(
        out.status.code(),
        Some(2),
        "a usage error: {}",
        describe(&out)
    );
}

#[test]
fn a_small_result_is_not_annotated() {
    let work = Work::with_demo_tools(false);
    let out = run(
        work.pk_with_config()
            .args(["run", "word_frequency", "-a", "text=a b a"]),
        None,
    );
    let v = stdout_json(&out);
    assert!(
        v.get("_elided").is_none(),
        "nothing was trimmed, so say nothing"
    );
}

#[test]
fn completion_scripts_generate() {
    let work = Work::new();
    let out = run(work.pk().args(["completion", "zsh"]), None);
    assert!(out.status.success(), "{}", describe(&out));
    assert!(stdout_text(&out).contains("pk"), "{}", describe(&out));
}
