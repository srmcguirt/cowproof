//! `cowproof report rollup`, end to end: the command line over hand-built lanes roots,
//! and over a root a real `cowproof run` against a FAKE `claude` just wrote, so the
//! shapes the rollup reads cannot drift from the shapes the runner writes. The
//! aggregation itself is tested in `crates/cowproof-report/tests/rollup.rs`. The lane
//! test needs the sandbox like `tests/run.rs` (skipped without it, a failure under
//! `COWPROOF_REQUIRE_SANDBOX=1`).

mod common;

use common::{Lane, output, run_checks, sandbox_available, text, var_tmp};
use serde_json::{Value, json};
use std::fs;
use std::path::Path;
use std::process::{Command, Output};

fn cowproof(args: &[&str], roots: &[&Path]) -> Output {
    output(
        Command::new(env!("CARGO_BIN_EXE_cowproof"))
            .args(args)
            .args(roots),
    )
}

fn rollup(args: &[&str], roots: &[&Path]) -> Output {
    let mut all = vec!["report", "rollup"];
    all.extend_from_slice(args);
    cowproof(&all, roots)
}

fn stdout(out: &Output) -> String {
    String::from_utf8(out.stdout.clone()).unwrap()
}

/// A lane the way the runner leaves it, down to the keys the rollup reads.
fn put(root: &Path, id: &str, rung: (&str, &str), class: &str, outcome: &str, unsandboxed: bool) {
    let control = root.join(id).join("control");
    fs::create_dir_all(&control).unwrap();
    let (runtime, model) = rung;
    let run = json!({
        "id": id,
        "host": null,
        "status": "finished",
        "unsandboxed": unsandboxed,
        "estimatedCostUsd": 0.25,
        "costIsEstimate": true,
        "exitCode": 0,
        "runtime": runtime,
        "model": model,
        "startRung": format!("{runtime}:{model}"),
        "rungSource": "default",
        "turns": 5,
        "segments": [{"index": 0, "runtime": runtime, "model": model, "turns": 5,
                      "estimatedCostUsd": 0.25, "costIsEstimate": true}],
        "classSlot": {"class": class, "limit": 2, "waitMs": 0},
    });
    let verdict = json!({"id": id, "verdict": outcome, "unsandboxed": unsandboxed, "exitCode": 0,
                         "reasons": [], "unrun": [], "failedChecks": [], "heldOutFailed": [],
                         "diverged": [], "failedGates": []});
    fs::write(control.join("run.json"), run.to_string()).unwrap();
    fs::write(control.join("verdict.json"), verdict.to_string()).unwrap();
}

#[test]
fn the_table_prints_per_rung_and_class_in_80_columns() {
    let dir = var_tmp("cp-rollcli-table-");
    let root = dir.path();
    put(root, "a", ("claude", "haiku"), "rust", "proved", false);
    put(root, "b", ("claude", "haiku"), "rust", "refuted", false);
    put(
        root,
        "c",
        ("openrouter", "glm-5.3-flash"),
        "light",
        "proved",
        false,
    );
    let out = rollup(&[], &[root]);
    assert!(out.status.success(), "{}", text(&out));
    let table = stdout(&out);
    assert!(
        table.contains("Lane rollup: 3 counted of 3 lanes in 1 root"),
        "{table}"
    );
    assert!(table.contains("claude:haiku\n"), "{table}");
    assert!(table.contains("openrouter:glm-5.3-flash\n"), "{table}");
    // haiku x rust: two lanes, one first-try pass, one proved, cost 0.50 over one proved.
    let row = table
        .lines()
        .find(|l| l.trim_start().starts_with("rust "))
        .unwrap_or_else(|| panic!("no rust row in:\n{table}"));
    let cells: Vec<&str> = row.split_whitespace().collect();
    assert_eq!(
        cells,
        [
            "rust", "2", "1/2", "50%", "1/2", "50%", "0.250", "0.500", "0.500", "5", "0.00"
        ],
        "{row:?}"
    );
    for line in table.lines() {
        assert!(line.chars().count() <= 80, "{line:?}");
    }
}

#[test]
fn json_prints_the_same_numbers_as_one_document() {
    let dir = var_tmp("cp-rollcli-json-");
    let root = dir.path();
    put(root, "a", ("claude", "haiku"), "rust", "proved", false);
    put(root, "b", ("claude", "haiku"), "rust", "refuted", false);
    let out = rollup(&["--json"], &[root]);
    assert!(out.status.success(), "{}", text(&out));
    // One document, and nothing else on stdout.
    let doc: Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(doc["roots"], 1);
    assert_eq!(doc["includeUnsandboxed"], false);
    assert_eq!(doc["counts"]["counted"], 2);
    let g = &doc["groups"][0];
    assert_eq!(g["startRung"], "claude:haiku");
    assert_eq!(g["class"], "rust");
    assert_eq!(g["lanes"], 2);
    assert_eq!(g["firstTryRate"], 0.5);
    assert_eq!(g["provedRate"], 0.5);
    assert_eq!(g["totalCostUsd"], 0.5);
    assert_eq!(g["costPerProvedUsd"], 0.5);
    assert_eq!(doc["lanes"].as_array().unwrap().len(), 2);
    // The round trip: the document parses back into the library's own.
    let again = cowproof_report::rollup::rollup(
        &[root.to_path_buf()],
        &cowproof_report::rollup::Options::default(),
    )
    .unwrap();
    assert_eq!(doc, again.to_json());
}

#[test]
fn include_unsandboxed_counts_them() {
    let dir = var_tmp("cp-rollcli-unsandboxed-");
    let root = dir.path();
    put(root, "box", ("claude", "haiku"), "rust", "proved", false);
    put(root, "free", ("claude", "haiku"), "rust", "finished", true);

    let out = rollup(&["--json"], &[root]);
    let doc: Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(doc["counts"]["counted"], 1);
    assert_eq!(doc["counts"]["excludedUnsandboxed"], 1);
    assert_eq!(doc["groups"][0]["lanes"], 1);

    let out = rollup(&["--json", "--include-unsandboxed"], &[root]);
    let doc: Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(doc["includeUnsandboxed"], true);
    assert_eq!(doc["counts"]["counted"], 2);
    assert_eq!(doc["groups"][0]["lanes"], 2);
    assert_eq!(doc["groups"][0]["proved"], 2);
}

#[test]
fn a_root_that_is_missing_fails_and_no_root_is_a_usage_error() {
    let dir = var_tmp("cp-rollcli-missing-");
    let missing = dir.path().join("no-such-root");
    let out = rollup(&[], &[&missing]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("no-such-root"),
        "{}",
        text(&out)
    );
    assert!(out.stdout.is_empty(), "{}", text(&out));

    let out = rollup(&[], &[]);
    assert_eq!(out.status.code(), Some(2), "{}", text(&out));
}

#[test]
fn several_roots_are_rolled_up_together() {
    let a = var_tmp("cp-rollcli-a-");
    let b = var_tmp("cp-rollcli-b-");
    put(a.path(), "x", ("claude", "haiku"), "rust", "proved", false);
    put(b.path(), "x", ("claude", "haiku"), "rust", "proved", false);
    let out = rollup(&["--json"], &[a.path(), b.path()]);
    let doc: Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(doc["roots"], 2);
    assert_eq!(doc["groups"][0]["lanes"], 2);
}

#[test]
fn a_real_lane_rolls_up_to_what_its_own_files_say() {
    if !sandbox_available() {
        return;
    }
    let lane = Lane::new(
        &run_checks(&["edit", "made"]),
        json!([
            {"id": "edit", "command": "grep -q edited README.md"},
            {"id": "made", "command": "test -f created.txt"},
        ]),
    );
    let out = lane.run(&[]);
    assert_eq!(out.status.code(), Some(0), "cowproof run:\n{}", text(&out));
    let verdict = lane.verdict();
    assert_eq!(verdict["verdict"], "proved");
    let run: Value = serde_json::from_str(
        &fs::read_to_string(lane.lane_dir().join("control/run.json")).unwrap(),
    )
    .unwrap();
    // The keys the rollup depends on are in the writer's output.
    for key in [
        "runtime",
        "model",
        "startRung",
        "rungSource",
        "turns",
        "estimatedCostUsd",
    ] {
        assert!(!run[key].is_null(), "run.json has no {key}: {run}");
    }
    assert!(!run["segments"][0]["runtime"].is_null(), "{run}");
    assert!(lane.capsule_dir().is_dir());

    let out = rollup(&["--json"], &[lane.lanes.path()]);
    assert!(out.status.success(), "{}", text(&out));
    let doc: Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(doc["counts"]["seen"], 1);
    assert_eq!(doc["counts"]["counted"], 1);
    assert_eq!(doc["counts"]["unreadable"], 0);
    assert_eq!(doc["counts"]["malformed"], 0);
    assert_eq!(doc["counts"]["running"], 0);
    let row = &doc["lanes"][0];
    assert_eq!(row["id"], lane.id.as_str());
    assert_eq!(row["outcome"], "proved");
    assert_eq!(row["proved"], true);
    assert_eq!(row["firstTry"], true);
    assert_eq!(row["reassigns"], 0);
    assert_eq!(row["remote"], false);
    assert_eq!(row["unsandboxed"], false);
    assert_eq!(row["legacy"], false);
    assert_eq!(row["class"], "light");
    assert_eq!(row["firstRung"], run["startRung"]);
    assert_eq!(
        row["finalRung"],
        format!(
            "{}:{}",
            run["runtime"].as_str().unwrap(),
            run["model"].as_str().unwrap()
        )
    );
    assert_eq!(row["firstRung"], row["finalRung"]);
    assert_eq!(row["rungSource"], run["rungSource"]);
    assert_eq!(row["turns"], run["turns"]);
    assert_eq!(row["turns"], 2);
    assert_eq!(row["costUsd"], run["estimatedCostUsd"]);
    assert_eq!(row["costIsEstimate"], true);
    let g = &doc["groups"][0];
    assert_eq!(g["startRung"], run["startRung"]);
    assert_eq!(g["class"], "light");
    assert_eq!(g["lanes"], 1);
    assert_eq!(g["firstTryPassed"], 1);
    assert_eq!(g["proved"], 1);
    assert_eq!(g["meanReassigns"], 0.0);

    // The table names the same group.
    let out = rollup(&[], &[lane.lanes.path()]);
    assert!(out.status.success(), "{}", text(&out));
    let table = stdout(&out);
    assert!(
        table.contains(run["startRung"].as_str().unwrap()),
        "{table}"
    );
    assert!(table.contains("1/1 100%"), "{table}");
}
