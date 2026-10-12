//! `cowproof report handback`: the per-lane handoff report, end to end through the one
//! `cowproof` binary. It is the command line the standalone `cowproof-report` binary used
//! to be (`cowproof-report <lane-dir> [--repo DIR] [--packet FILE] [--baseline FILE]
//! [--json]` is now `cowproof report handback <lane-dir> ...`). Its parsing and rules are
//! unit-tested in `crates/cowproof-report/src/handback.rs`; these tests are the old
//! binary's fixture tests, run against the new subcommand over the same fixtures.
//!
//! The fixtures belong to `cowproof-report` (`crates/cowproof-report/tests/fixtures`), which
//! the published `cowproof` crate does not contain, so the tests that read them run in the
//! workspace only (see `common/workspace.rs`); the two that need no fixture always run.

#[path = "common/workspace.rs"]
mod workspace;

use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../cowproof-report/tests/fixtures")
        .join(name)
}

fn handback(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_cowproof"))
        .args(["report", "handback"])
        .args(args)
        .output()
        .expect("running cowproof report handback")
}

fn text(out: &Output) -> String {
    format!(
        "status: {:?}\nstdout: {}\nstderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// The report as JSON, plus the raw stdout for snapshot comparison.
fn json_report(args: &[&str]) -> (Value, String) {
    let mut all = args.to_vec();
    all.push("--json");
    let out = handback(&all);
    assert!(out.status.success(), "{}", text(&out));
    let raw = String::from_utf8(out.stdout).unwrap();
    (
        serde_json::from_str(&raw).expect("--json prints one JSON document"),
        raw,
    )
}

/// The report for `dir` must equal its committed `expected.json`, byte for byte once the
/// trailing newline is trimmed.
fn snapshot(name: &str, extra: &[&str]) -> Value {
    let dir = fixture(name);
    let dir_arg = dir.to_str().unwrap();
    let mut args = vec![dir_arg];
    args.extend_from_slice(extra);
    let (report, raw) = json_report(&args);
    let expected = fs::read_to_string(dir.join("expected.json")).expect("expected.json must exist");
    assert_eq!(
        raw.trim(),
        expected.trim(),
        "{name}: rendered report must match expected.json"
    );
    report
}

fn classifications(report: &Value) -> Vec<&str> {
    report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["classification"].as_str().unwrap())
        .collect()
}

#[test]
fn the_mixed_fixture_reports_checks_assertion_loss_and_handoff_sections() {
    if workspace::skipped("the_mixed_fixture_reports_checks_assertion_loss_and_handoff_sections") {
        return;
    }
    let dir = fixture("mixed");
    let packet = dir.join("packet.md");
    let (r, _) = json_report(&[dir.to_str().unwrap(), "--packet", packet.to_str().unwrap()]);
    assert_eq!(r["lane_id"], "fixture-lane");
    assert_eq!(r["minutes"], 2);
    assert_eq!(classifications(&r), vec!["pass", "fail", "not run"]);
    assert_eq!(r["removed_assertions"][0]["net_loss"], 2);
    assert_eq!(r["limits"].as_array().unwrap().len(), 1);
    assert_eq!(r["unverified"].as_array().unwrap().len(), 1);
    assert_eq!(r["questions"].as_array().unwrap().len(), 1);
    assert_eq!(r["verdict_hint"], "fix-then-apply");
}

#[test]
fn the_flaw_lane_fixture_runs_all_rules_including_the_baseline() {
    if workspace::skipped("the_flaw_lane_fixture_runs_all_rules_including_the_baseline") {
        return;
    }
    let dir = fixture("flaws");
    let (r, _) = json_report(&[dir.to_str().unwrap(), "--baseline", "20260401_existing.sql"]);
    let flaws = r["flaws"].as_array().unwrap();
    assert!(flaws.len() >= 18, "reported {} flaws", flaws.len());
    assert!(flaws.iter().any(|f| {
        f["file"] == "crates/demo/target/debug/demo"
            && f["explanation"] == "Build output or scratch files appear in the patch."
    }));
    assert!(
        flaws
            .iter()
            .any(|f| f["file"] == "supabase/migrations/20260401_existing.sql")
    );
    assert!(!flaws.iter().any(|f| {
        f["file"] == "supabase/migrations/20260402_new.sql"
            && f["pattern"].as_str().unwrap().starts_with("--baseline")
    }));
}

#[test]
fn the_table_format_fixture_matches_its_snapshot() {
    if workspace::skipped("the_table_format_fixture_matches_its_snapshot") {
        return;
    }
    let r = snapshot("table", &[]);
    assert_eq!(r["lane_id"], "fixture-table");
    assert_eq!(classifications(&r), vec!["pass", "fail", "unclear"]);
}

#[test]
fn the_bullet_format_fixture_matches_its_snapshot() {
    if workspace::skipped("the_bullet_format_fixture_matches_its_snapshot") {
        return;
    }
    let r = snapshot("bullet", &[]);
    assert_eq!(r["lane_id"], "fixture-bullet");
    let classes = classifications(&r);
    assert_eq!(classes.len(), 4);
    for want in ["pass", "fail", "unclear"] {
        assert!(classes.contains(&want), "{classes:?} lacks {want}");
    }
}

#[test]
fn the_fenced_format_fixture_matches_its_snapshot() {
    if workspace::skipped("the_fenced_format_fixture_matches_its_snapshot") {
        return;
    }
    let r = snapshot("fenced", &[]);
    assert_eq!(r["lane_id"], "fixture-fenced");
    let classes = classifications(&r);
    assert_eq!(classes.len(), 4);
    for want in ["pass", "fail"] {
        assert!(classes.contains(&want), "{classes:?} lacks {want}");
    }
}

#[test]
fn the_arrow_format_fixture_matches_its_snapshot() {
    if workspace::skipped("the_arrow_format_fixture_matches_its_snapshot") {
        return;
    }
    let r = snapshot("arrow", &[]);
    assert_eq!(r["lane_id"], "fixture-arrow");
    let classes = classifications(&r);
    assert_eq!(classes.len(), 3);
    for want in ["pass", "unclear"] {
        assert!(classes.contains(&want), "{classes:?} lacks {want}");
    }
}

#[test]
fn the_questions_fixture_matches_its_snapshot() {
    if workspace::skipped("the_questions_fixture_matches_its_snapshot") {
        return;
    }
    let r = snapshot("questions", &[]);
    assert_eq!(r["lane_id"], "fixture-questions");
    assert_eq!(r["questions"].as_array().unwrap().len(), 3);
}

#[test]
fn the_limits_fixture_matches_its_snapshot() {
    if workspace::skipped("the_limits_fixture_matches_its_snapshot") {
        return;
    }
    let r = snapshot("limits", &[]);
    assert_eq!(r["lane_id"], "fixture-limits");
    assert!(!r["limits"].as_array().unwrap().is_empty());
    assert!(!r["unverified"].as_array().unwrap().is_empty());
}

#[test]
fn the_baseline_fixture_matches_its_snapshot() {
    if workspace::skipped("the_baseline_fixture_matches_its_snapshot") {
        return;
    }
    let r = snapshot("baseline", &["--baseline", "20260401_existing.sql"]);
    assert_eq!(r["lane_id"], "fixture-baseline");
}

#[test]
fn without_json_it_prints_the_text_report_and_a_verdict_hint() {
    if workspace::skipped("without_json_it_prints_the_text_report_and_a_verdict_hint") {
        return;
    }
    let dir = fixture("table");
    let out = handback(&[dir.to_str().unwrap()]);
    assert!(out.status.success(), "{}", text(&out));
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.starts_with("Lane: fixture-table | status: "),
        "{stdout}"
    );
    assert!(stdout.contains("\nChecks:\n"), "{stdout}");
    assert!(stdout.contains("\nVerdict hint: "), "{stdout}");
}

#[test]
fn a_lane_directory_that_is_not_a_lane_exits_2_naming_the_file() {
    let empty = tempfile::tempdir().unwrap();
    let out = handback(&[empty.path().to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(2), "{}", text(&out));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("summary.json"), "{stderr}");
    assert!(stderr.starts_with("cowproof report handback: "), "{stderr}");
    assert!(out.stdout.is_empty(), "{}", text(&out));
}

#[test]
fn an_unknown_option_and_a_missing_lane_directory_are_usage_errors_with_exit_2() {
    let dir = tempfile::tempdir().unwrap();
    let unknown = handback(&[dir.path().to_str().unwrap(), "--nope"]);
    assert_eq!(unknown.status.code(), Some(2), "{}", text(&unknown));
    assert!(String::from_utf8_lossy(&unknown.stderr).contains("--nope"));

    let none = handback(&[]);
    assert_eq!(none.status.code(), Some(2), "{}", text(&none));
    assert!(String::from_utf8_lossy(&none.stderr).contains("LANE_DIR"));
}
