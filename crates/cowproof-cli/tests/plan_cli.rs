//! `cowproof plan check|next|board|brief|set`: the plan-file commands, end to end through
//! the one `cowproof` binary. They are the command lines the standalone `cowproof-plan`
//! binary used to be (`cowproof-plan next --repo R --json` is now `cowproof plan next
//! --repo R --json`). The library behind them is tested in
//! `crates/cowproof-plan/tests/plan.rs`; these tests run the commands themselves. `plan
//! run` and `plan collect` need hosts and lanes and are covered where those are.

use serde_json::Value;
use std::fs;
use std::path::Path;
use std::process::{Command, Output};

fn plan(repo: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_cowproof"))
        .arg("plan")
        .args(args)
        .arg("--repo")
        .arg(repo)
        .output()
        .expect("running cowproof plan")
}

fn text(out: &Output) -> String {
    format!(
        "status: {:?}\nstdout: {}\nstderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn stdout(out: &Output) -> String {
    String::from_utf8(out.stdout.clone()).unwrap()
}

fn repo_with_plan(contents: &str) -> tempfile::TempDir {
    let repo = tempfile::tempdir().unwrap();
    fs::write(repo.path().join("work.lanes.json"), contents).unwrap();
    repo
}

const PLAN: &str = r#"{"version":1,"plan":"work","lanes":[
  {"id":"done","title":"done","priority":5,"status":"applied","commit":"abc"},
  {"id":"later","title":"later","priority":1,"status":"packet","dependsOn":["blocked"]},
  {"id":"blocked","title":"blocked","priority":1,"status":"planned"},
  {"id":"ready","title":"ready","priority":2,"status":"packet","dependsOn":["done"],"estimateHours":3},
  {"id":"parked","title":"parked","priority":9,"status":"held"}
]}"#;

#[test]
fn check_prints_ok_and_exits_0_for_a_valid_plan() {
    let repo = repo_with_plan(
        r#"{"version":1,"plan":"work","lanes":[
        {"id":"done","title":"done","priority":5,"status":"applied","commit":"abc"},
        {"id":"next","title":"next","priority":1,"status":"planned","dependsOn":["done"]}
      ]}"#,
    );
    let out = plan(repo.path(), &["check"]);
    assert!(out.status.success(), "{}", text(&out));
    assert!(
        stdout(&out).trim_end().ends_with("work.lanes.json: ok"),
        "{}",
        text(&out)
    );

    // A packet-status lane without its packet file is a problem, named by file and lane.
    let repo = repo_with_plan(PLAN);
    let out = plan(repo.path(), &["check"]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert!(
        stdout(&out)
            .contains("work.lanes.json [ready]: packet status requires an existing packet file"),
        "{}",
        text(&out)
    );
}

#[test]
fn check_prints_each_problem_and_exits_1() {
    let repo = repo_with_plan(
        r#"{"version":1,"plan":"alpha","baseline":{"migration":481,"contract":"C1.33"},
      "numbering":{"migrationGlob":"migrations/{n}_*.sql","contractPrefix":"C1."},
      "lanes":[
        {"id":"bad-old","title":"bad","priority":1,"status":"planned","reserves":{"migration":466,"contract":"C1.34"}},
        {"id":"other","title":"other","priority":2,"status":"planned","reserves":{"migration":482,"contract":"C1.34"}}
      ]}"#,
    );
    let out = plan(repo.path(), &["check"]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    let printed = stdout(&out);
    assert!(
        printed
            .lines()
            .any(|l| l.starts_with("work.lanes.json [bad-old]: ")
                && l.contains("above baseline 481")),
        "{printed}"
    );
    assert!(
        printed.lines().any(
            |l| l.starts_with("work.lanes.json [other]: ") && l.contains("unique across plans")
        ),
        "{printed}"
    );
}

#[test]
fn check_names_a_plan_file_that_is_not_json() {
    let repo = repo_with_plan("not json");
    let out = plan(repo.path(), &["check"]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("parsing plan"),
        "{}",
        text(&out)
    );
}

#[test]
fn next_lists_only_unblocked_packet_lanes_in_priority_order() {
    let repo = repo_with_plan(PLAN);
    let out = plan(repo.path(), &["next"]);
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(
        stdout(&out).trim_end(),
        "ready  priority=2  migration=-  estimate=3h"
    );

    let out = plan(repo.path(), &["next", "--json"]);
    assert!(out.status.success(), "{}", text(&out));
    let rows: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(rows.as_array().unwrap().len(), 1);
    assert_eq!(rows[0]["id"], "ready");
    assert_eq!(rows[0]["plan"], "work");
    assert_eq!(rows[0]["priority"], 2);
    assert_eq!(rows[0]["estimateHours"], 3.0);
}

#[test]
fn next_with_nothing_ready_explains_unpacketized_and_blocked_lanes() {
    let repo = repo_with_plan(
        r#"{"version":1,"plan":"work","lanes":[
        {"id":"planned-one","title":"planned","priority":1,"status":"planned"},
        {"id":"blocked-one","title":"blocked","priority":2,"status":"packet","dependsOn":["planned-one"]}
      ]}"#,
    );
    let out = plan(repo.path(), &["next"]);
    assert!(out.status.success(), "{}", text(&out));
    let printed = stdout(&out);
    assert!(printed.starts_with("No ready lanes.\n"), "{printed}");
    assert!(
        printed.contains("Planned without a packet: 1\n"),
        "{printed}"
    );
    assert!(
        printed
            .lines()
            .any(|l| l.contains("planned-one") && l.contains("plan=work")),
        "{printed}"
    );
    assert!(printed.contains("Blocked: 1\n"), "{printed}");
    assert!(
        printed
            .lines()
            .any(|l| l.contains("blocked-one") && l.contains("planned-one")),
        "{printed}"
    );
}

#[test]
fn board_prints_a_tab_separated_table_and_json() {
    let repo = repo_with_plan(PLAN);
    let out = plan(repo.path(), &["board"]);
    assert!(out.status.success(), "{}", text(&out));
    let printed = stdout(&out);
    let mut lines = printed.lines();
    assert_eq!(
        lines.next(),
        Some("PLAN\tID\tSTATUS\tPRI\tHOST\tRESERVES\tBLOCKED-BY")
    );
    let later = printed
        .lines()
        .find(|l| l.split('\t').nth(1) == Some("later"))
        .unwrap_or_else(|| panic!("no row for `later`: {printed}"));
    let cells: Vec<&str> = later.split('\t').collect();
    assert_eq!(cells[0], "work");
    assert_eq!(cells[2], "packet");
    assert_eq!(cells[6], "blocked");

    let out = plan(repo.path(), &["board", "--json"]);
    assert!(out.status.success(), "{}", text(&out));
    let rows: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(rows.as_array().unwrap().len(), 5);
    let later = rows
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == "later")
        .unwrap();
    assert_eq!(later["blockedBy"][0], "blocked");
}

#[test]
fn brief_summarizes_running_held_ready_and_founder_waiting_lanes() {
    let repo = repo_with_plan(
        r#"{"version":1,"plan":"work","lanes":[
        {"id":"going","title":"going","priority":1,"status":"running"},
        {"id":"parked","title":"parked","priority":2,"status":"held"},
        {"id":"ready","title":"ready","priority":3,"status":"packet"}
      ]}"#,
    );
    let out = plan(repo.path(), &["brief"]);
    assert!(out.status.success(), "{}", text(&out));
    let printed = stdout(&out);
    assert_eq!(
        printed.lines().collect::<Vec<_>>(),
        vec![
            "Running: going",
            "Awaiting review: -",
            "Held: parked",
            "Ready next: ready",
            "Waiting on founder: -",
        ]
    );

    let out = plan(repo.path(), &["brief", "--json"]);
    assert!(out.status.success(), "{}", text(&out));
    let doc: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(doc["running"][0], "going");
    assert_eq!(doc["held"][0], "parked");
    assert_eq!(doc["readyNext"][0], "ready");
    assert_eq!(doc["lines"].as_array().unwrap().len(), 5);
}

#[test]
fn brief_reads_a_lanes_root_for_lanes_that_have_no_summary_yet() {
    let repo = repo_with_plan(
        r#"{"version":1,"plan":"work","lanes":[{"id":"worker","title":"w","priority":1,"status":"packet"}]}"#,
    );
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("worker-20261011")).unwrap();
    let out = plan(
        repo.path(),
        &["brief", "--root", root.path().to_str().unwrap()],
    );
    assert!(out.status.success(), "{}", text(&out));
    assert!(
        stdout(&out).starts_with("Running: worker-20261011\n"),
        "{}",
        text(&out)
    );
}

/// Lanes `x` and `x-1`: the directory `x-1-<stamp>` is lane `x-1`'s, and lane `x`, whose
/// prefix `x-` it also begins with, has no claim on it.
const PREFIX_PLAN: &str = r#"{"version":1,"plan":"work","lanes":[
  {"id":"x","title":"x","priority":1,"status":"running"},
  {"id":"x-1","title":"x-1","priority":1,"status":"packet"}
]}"#;

#[test]
fn brief_does_not_give_a_longer_lanes_directory_to_a_shorter_lane() {
    let repo = repo_with_plan(PREFIX_PLAN);
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("x-1-20261011")).unwrap();
    let out = plan(
        repo.path(),
        &["brief", "--root", root.path().to_str().unwrap()],
    );
    assert!(out.status.success(), "{}", text(&out));
    // Lane `x` is running in the plan, and the directory has no summary: if `x` claimed it,
    // the directory would not be listed as running.
    assert!(
        stdout(&out).starts_with("Running: x, x-1-20261011\n"),
        "{}",
        text(&out)
    );
}

#[test]
fn brief_awaits_review_only_of_the_lane_that_owns_a_finished_directory() {
    let repo = repo_with_plan(PREFIX_PLAN);
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("x-1-20261011");
    fs::create_dir(&dir).unwrap();
    let summary = fs::File::create(dir.join("summary.json")).unwrap();
    // Newer than the plan file, whatever the clock granularity.
    summary
        .set_modified(std::time::SystemTime::now() + std::time::Duration::from_secs(3600))
        .unwrap();
    let out = plan(
        repo.path(),
        &["brief", "--root", root.path().to_str().unwrap()],
    );
    assert!(out.status.success(), "{}", text(&out));
    assert!(
        stdout(&out).contains("\nAwaiting review: x-1\n"),
        "{}",
        text(&out)
    );
}

fn lane_plan(status: &str) -> String {
    format!(
        r#"{{"version":1,"plan":"work","lanes":[{{"id":"worker","title":"worker","priority":1,"status":"{status}"}}]}}"#
    )
}

fn read_plan(repo: &Path) -> Value {
    serde_json::from_slice(&fs::read(repo.join("work.lanes.json")).unwrap()).unwrap()
}

#[test]
fn set_running_needs_a_packet_and_records_it() {
    let repo = repo_with_plan(&lane_plan("planned"));
    fs::write(
        repo.path().join("worker.md"),
        "<!-- lane {\"id\":\"worker\",\"owns\":[\"src/**\"]} -->\n",
    )
    .unwrap();

    let refused = plan(repo.path(), &["set", "worker", "running"]);
    assert_eq!(refused.status.code(), Some(1), "{}", text(&refused));
    assert_eq!(read_plan(repo.path())["lanes"][0]["status"], "planned");

    let out = plan(
        repo.path(),
        &["set", "worker", "running", "--packet", "worker.md"],
    );
    assert!(out.status.success(), "{}", text(&out));
    assert!(
        stdout(&out)
            .trim_end()
            .ends_with("work.lanes.json: worker -> running"),
        "{}",
        text(&out)
    );
    let updated = read_plan(repo.path());
    assert_eq!(updated["lanes"][0]["status"], "running");
    assert_eq!(updated["lanes"][0]["packet"], "worker.md");
}

#[test]
fn set_refuses_a_packet_whose_header_names_another_lane() {
    let repo = repo_with_plan(&lane_plan("planned"));
    fs::write(
        repo.path().join("wrong.md"),
        "<!-- lane {\"id\":\"other\",\"owns\":[\"src/**\"]} -->\n",
    )
    .unwrap();
    fs::write(repo.path().join("invalid.md"), "no lane header\n").unwrap();

    let wrong = plan(
        repo.path(),
        &["set", "worker", "running", "--packet", "wrong.md"],
    );
    assert_eq!(wrong.status.code(), Some(1), "{}", text(&wrong));
    assert!(
        String::from_utf8_lossy(&wrong.stderr).contains("does not match lane id"),
        "{}",
        text(&wrong)
    );
    let invalid = plan(
        repo.path(),
        &["set", "worker", "running", "--packet", "invalid.md"],
    );
    assert_eq!(invalid.status.code(), Some(1), "{}", text(&invalid));
    let missing = plan(
        repo.path(),
        &["set", "worker", "running", "--packet", "missing.md"],
    );
    assert_eq!(missing.status.code(), Some(1), "{}", text(&missing));
    assert_eq!(read_plan(repo.path())["lanes"][0]["status"], "planned");
}

#[test]
fn set_ships_a_held_or_review_lane_with_its_commit_and_release() {
    for initial in ["held", "review"] {
        let repo = repo_with_plan(&lane_plan(initial));
        let refused = plan(repo.path(), &["set", "worker", "shipped"]);
        assert_eq!(
            refused.status.code(),
            Some(1),
            "{initial}: {}",
            text(&refused)
        );

        let out = plan(
            repo.path(),
            &[
                "set",
                "worker",
                "shipped",
                "--commit",
                "abc123",
                "--release",
                "v1.2.3",
            ],
        );
        assert!(out.status.success(), "{initial}: {}", text(&out));
        let updated = read_plan(repo.path());
        assert_eq!(updated["lanes"][0]["status"], "shipped");
        assert_eq!(updated["lanes"][0]["commit"], "abc123");
        assert_eq!(updated["lanes"][0]["release"], "v1.2.3");
    }
}
