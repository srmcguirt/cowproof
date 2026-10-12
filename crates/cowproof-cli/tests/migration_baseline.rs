//! The migration baseline, end to end: `[proof] migration_baseline` in the base commit's
//! `cowproof.toml` makes the flaws gate refuse a patch that edits or deletes an applied
//! migration, and `gates.json` (sealed in the capsule) records the baseline the gate used.
//! A FAKE `claude` plays the builder: no network, no model. Needs the sandbox like
//! `tests/run.rs` (skipped without it, a failure under `COWPROOF_REQUIRE_SANDBOX=1`).

mod common;

use common::{Lane, output, run_checks, sandbox_available, text, var_tmp};
use cowproof_prove::Capsule;
use serde_json::Value;
use std::fs;
use std::process::{Command, Output};

const BASE_CONFIG: &str = "[proof]\npacks = [\"generic\"]\nmigration_baseline = \"010_late.sql\"\n";

/// A project whose base commit declares the baseline `010_late.sql`, with applied
/// migrations `001`, `002` and `010`, and a check that always passes.
fn project(config: &str) -> tempfile::TempDir {
    let dir = var_tmp("cp-mig-project-");
    let root = dir.path();
    fs::write(root.join("cowproof.toml"), config).unwrap();
    fs::write(root.join("check.sh"), "exit 0\n").unwrap();
    let migrations = root.join("db/migrations");
    fs::create_dir_all(&migrations).unwrap();
    for (name, sql) in [
        ("001_init.sql", "create table a (id int);\n"),
        ("002_more.sql", "create table b (id int);\n"),
        ("010_late.sql", "create table c (id int);\n"),
    ] {
        fs::write(migrations.join(name), sql).unwrap();
    }
    dir
}

fn packet(id: &str) -> String {
    format!(
        "# Migrations\n\n<!-- lane {{\"id\":\"{id}\",\"owns\":[\"db/**\",\"cowproof.toml\"],\
         \"class\":\"light\",\"allow\":[\"sh check.sh\"],\"maxCostUsd\":1.0,\"timeoutMin\":15,\
         \"checks\":[{{\"id\":\"unit\",\"command\":\"sh check.sh\"}}]}} -->\n\n\
         ## Task\n\nChange the schema.\n\n## Checks\n\n- `sh check.sh`\n"
    )
}

/// A lane over `project(config)` whose fake builder runs `edits`, then the check.
fn lane(config: &str, edits: &str) -> Lane {
    let project = project(config);
    let body = format!("{edits}\n{}", run_checks(&["unit"]));
    Lane::from_project(&body, project.path(), &packet)
}

fn stdout(out: &Output) -> String {
    String::from_utf8(out.stdout.clone()).unwrap()
}

fn gates(lane: &Lane) -> Vec<Value> {
    let text = fs::read_to_string(lane.capsule_dir().join("gates.json")).unwrap();
    let report: Value = serde_json::from_str(&text).unwrap();
    report["gates"].as_array().unwrap().clone()
}

fn gate(gates: &[Value], name: &str) -> Value {
    gates
        .iter()
        .find(|g| g["name"] == name)
        .unwrap_or_else(|| panic!("no gate {name} in {gates:?}"))
        .clone()
}

#[test]
fn a_patch_that_edits_an_applied_migration_is_refuted_naming_the_file_and_the_baseline() {
    if !sandbox_available() {
        return;
    }
    let lane = lane(
        BASE_CONFIG,
        "echo 'alter table b add column x int;' >> db/migrations/002_more.sql",
    );
    let out = lane.run(&[]);
    assert_eq!(out.status.code(), Some(2), "{}", text(&out));
    let verdict = lane.verdict();
    assert_eq!(verdict["verdict"], "refuted", "{verdict}");
    assert_eq!(verdict["failedChecks"], serde_json::json!([]), "{verdict}");
    assert_eq!(
        verdict["failedGates"],
        serde_json::json!(["flaws"]),
        "{verdict}"
    );

    let gates = gates(&lane);
    let flaws = gate(&gates, "flaws");
    assert_eq!(flaws["passed"], false, "{flaws}");
    let evidence = flaws["evidence"].to_string();
    assert!(
        evidence.contains("db/migrations/002_more.sql"),
        "{evidence}"
    );
    assert!(evidence.contains("010_late.sql"), "{evidence}");
    // The director learns it from what `cowproof run` prints.
    let report = stdout(&out);
    assert!(report.contains("gate flaws failed"), "{report}");
    assert!(report.contains("db/migrations/002_more.sql"), "{report}");
    assert!(report.contains("010_late.sql"), "{report}");
}

#[test]
fn a_patch_that_deletes_an_applied_migration_is_refuted() {
    if !sandbox_available() {
        return;
    }
    let lane = lane(BASE_CONFIG, "rm db/migrations/001_init.sql");
    let out = lane.run(&[]);
    assert_eq!(out.status.code(), Some(2), "{}", text(&out));
    let verdict = lane.verdict();
    assert_eq!(verdict["verdict"], "refuted", "{verdict}");
    let evidence = gate(&gates(&lane), "flaws")["evidence"].to_string();
    assert!(
        evidence.contains("db/migrations/001_init.sql"),
        "{evidence}"
    );
    assert!(evidence.contains("010_late.sql"), "{evidence}");
}

#[test]
fn a_new_migration_after_the_baseline_is_proved_and_the_capsule_records_the_baseline() {
    if !sandbox_available() {
        return;
    }
    let lane = lane(
        BASE_CONFIG,
        "echo 'create table d (id int);' > db/migrations/011_new.sql",
    );
    let out = lane.run(&[]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert_eq!(lane.verdict()["verdict"], "proved");

    // gates.json is sealed in the capsule and says which baseline the gate used.
    let capsule_dir = lane.capsule_dir();
    let gates = gates(&lane);
    let flaws = gate(&gates, "flaws");
    assert_eq!(flaws["passed"], true, "{flaws}");
    assert_eq!(flaws["warned"], false, "{flaws}");
    let evidence = flaws["evidence"].to_string();
    assert!(
        evidence.contains("migration_baseline 010_late.sql"),
        "{evidence}"
    );
    assert!(
        Capsule::read(&capsule_dir)
            .unwrap()
            .file_hashes
            .contains_key("gates.json")
    );

    // `cowproof verify` replays the sealed capsule on a fresh clone.
    let fresh = var_tmp("cp-mig-fresh-");
    let cloned = output(
        Command::new("git")
            .args(["clone", "-q"])
            .arg(&lane.repo)
            .arg(fresh.path().join("repo")),
    );
    assert!(cloned.status.success(), "{}", text(&cloned));
    let elsewhere = var_tmp("cp-mig-cwd-");
    let workdir = var_tmp("cp-mig-wd-");
    let verified = output(
        lane.cowproof_cmd()
            .current_dir(elsewhere.path())
            .arg("verify")
            .arg(&capsule_dir)
            .arg("--repo")
            .arg(fresh.path().join("repo"))
            .arg("--workdir")
            .arg(workdir.path()),
    );
    assert_eq!(verified.status.code(), Some(0), "{}", text(&verified));
}

#[test]
fn a_patch_cannot_move_the_baseline_it_is_judged_by() {
    if !sandbox_available() {
        return;
    }
    // The builder edits applied migration 002 and rewrites the baseline in cowproof.toml
    // to 001: the gate still judges it against the base's 010, and flags the edit to
    // cowproof.toml (owned here, so the protected-paths gate warns instead of failing).
    let lane = lane(
        BASE_CONFIG,
        "echo 'select 1;' >> db/migrations/002_more.sql\n\
         printf '[proof]\\npacks = [\"generic\"]\\nmigration_baseline = \"001_init.sql\"\\n' > cowproof.toml",
    );
    let out = lane.run(&[]);
    assert_eq!(out.status.code(), Some(2), "{}", text(&out));
    let gates = gates(&lane);
    let flaws = gate(&gates, "flaws");
    assert_eq!(flaws["passed"], false, "{flaws}");
    let evidence = flaws["evidence"].to_string();
    assert!(
        evidence.contains("db/migrations/002_more.sql"),
        "{evidence}"
    );
    assert!(evidence.contains("010_late.sql"), "{evidence}");
    let protected = gate(&gates, "protected_paths");
    assert_eq!(protected["warned"], true, "{protected}");
    assert!(protected["evidence"].to_string().contains("cowproof.toml"));
}

#[test]
fn without_a_baseline_the_gate_says_the_migration_rule_was_skipped() {
    if !sandbox_available() {
        return;
    }
    let lane = lane(
        "[proof]\npacks = [\"generic\"]\n",
        "echo 'select 1;' >> db/migrations/001_init.sql",
    );
    let out = lane.run(&[]);
    // Behaves as before: nothing else objects, so the lane proves, with a warning.
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let flaws = gate(&gates(&lane), "flaws");
    assert_eq!(flaws["passed"], true, "{flaws}");
    assert_eq!(flaws["warned"], true, "{flaws}");
    let evidence = flaws["evidence"].to_string();
    assert!(
        evidence.contains("applied_migration rules skipped"),
        "{evidence}"
    );
    assert!(evidence.contains("migration_baseline"), "{evidence}");
}
