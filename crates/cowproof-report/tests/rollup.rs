//! `cowproof_report::rollup`: the aggregate over lanes roots. Every lanes root here is
//! built by hand under `/var/tmp` with `run.json` and `verdict.json` in the shape the
//! runner writes (`crates/cowproof-cli/src/run.rs`); the CLI's own test rolls up a real
//! fake-claude lane so these shapes cannot drift from the writer.

use cowproof_report::rollup::{Options, rollup};
use serde_json::{Value, json};
use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

fn var_tmp(prefix: &str) -> TempDir {
    tempfile::Builder::new()
        .prefix(prefix)
        .tempdir_in("/var/tmp")
        .unwrap()
}

/// One launch of a builder, as `segment_record` writes it. `runtime: None` is a lane from
/// before D28 step 1, whose segments carry no `runtime`.
struct Seg {
    runtime: Option<&'static str>,
    model: &'static str,
    turns: u64,
    cost: f64,
}

fn seg(rung: &'static str, turns: u64, cost: f64) -> Seg {
    match rung.split_once(':') {
        Some((runtime, model)) => Seg {
            runtime: Some(runtime),
            model,
            turns,
            cost,
        },
        None => Seg {
            runtime: None,
            model: rung,
            turns,
            cost,
        },
    }
}

/// A lane as the builder left it. The defaults are a sandboxed local lane of class `rust`
/// that ended `finished`.
struct Lane {
    id: &'static str,
    class: &'static str,
    segs: Vec<Seg>,
    source: Option<&'static str>,
    host: Option<&'static str>,
    unsandboxed: bool,
    status: &'static str,
    cost_is_estimate: bool,
}

impl Lane {
    fn new(id: &'static str, segs: Vec<Seg>) -> Lane {
        Lane {
            id,
            class: "rust",
            segs,
            source: Some("class"),
            host: None,
            unsandboxed: false,
            status: "finished",
            cost_is_estimate: true,
        }
    }
    fn class(mut self, class: &'static str) -> Lane {
        self.class = class;
        self
    }
    fn host(mut self, host: &'static str) -> Lane {
        self.host = Some(host);
        self
    }
    fn unsandboxed(mut self) -> Lane {
        self.unsandboxed = true;
        self
    }
    fn status(mut self, status: &'static str) -> Lane {
        self.status = status;
        self
    }

    /// `control/run.json` as `run_one` writes it, to the keys the rollup reads.
    fn run_json(&self) -> Value {
        let last = self.segs.last().unwrap();
        let first = &self.segs[0];
        let legacy = last.runtime.is_none();
        let segments: Vec<Value> = self
            .segs
            .iter()
            .enumerate()
            .map(|(i, s)| {
                let mut v = json!({
                    "index": i,
                    "model": s.model,
                    "start": "fresh",
                    "resumedSession": null,
                    "startedBy": null,
                    "status": "finished",
                    "exitCode": 0,
                    "turns": s.turns,
                    "estimatedCostUsd": s.cost,
                    "costIsEstimate": true,
                    "durationMs": 1000,
                    "endedBy": null,
                });
                if let Some(runtime) = s.runtime {
                    v["runtime"] = json!(runtime);
                }
                v
            })
            .collect();
        let mut run = json!({
            "id": self.id,
            "host": self.host,
            "status": self.status,
            "unsandboxed": self.unsandboxed,
            "estimatedCostUsd": self.segs.iter().map(|s| s.cost).sum::<f64>(),
            "costIsEstimate": self.cost_is_estimate,
            "exitCode": 0,
            "model": last.model,
            "turns": self.segs.iter().map(|s| s.turns).sum::<u64>(),
            "segments": segments,
            "classSlot": { "class": self.class, "limit": 2, "waitMs": 0 },
        });
        if !legacy {
            run["runtime"] = json!(last.runtime.unwrap());
            run["startRung"] = json!(format!("{}:{}", first.runtime.unwrap(), first.model));
            run["rungSource"] = json!(self.source.unwrap());
        }
        run
    }
}

fn verdict_json(id: &str, outcome: &str, unsandboxed: bool) -> Value {
    json!({
        "id": id,
        "verdict": outcome,
        "unsandboxed": unsandboxed,
        "exitCode": if outcome == "proved" || outcome == "finished" { 0 } else { 2 },
        "reasons": [],
        "unrun": [],
        "failedChecks": [],
        "heldOutFailed": [],
        "diverged": [],
        "failedGates": [],
    })
}

fn write(root: &Path, id: &str, file: &str, content: &str) {
    let control = root.join(id).join("control");
    fs::create_dir_all(&control).unwrap();
    fs::write(control.join(file), content).unwrap();
}

/// A lane that ended with `outcome` as its verdict.
fn put(root: &Path, lane: Lane, outcome: &str) {
    write(
        root,
        lane.id,
        "run.json",
        &serde_json::to_string_pretty(&lane.run_json()).unwrap(),
    );
    write(
        root,
        lane.id,
        "verdict.json",
        &serde_json::to_string_pretty(&verdict_json(lane.id, outcome, lane.unsandboxed)).unwrap(),
    );
}

fn roll(roots: &[&Path], include_unsandboxed: bool) -> Value {
    let roots: Vec<PathBuf> = roots.iter().map(|p| p.to_path_buf()).collect();
    rollup(
        &roots,
        &Options {
            include_unsandboxed,
        },
    )
    .unwrap()
    .to_json()
}

/// Every entry examined is in exactly one class.
fn assert_partition(r: &Value) {
    let c = &r["counts"];
    let sum: u64 = [
        "counted",
        "running",
        "neverStarted",
        "unreadable",
        "malformed",
        "symlinked",
        "excludedUnsandboxed",
    ]
    .iter()
    .map(|k| c[*k].as_u64().unwrap())
    .sum();
    assert_eq!(sum, c["seen"].as_u64().unwrap(), "{c}");
}

fn group<'a>(r: &'a Value, rung: &str, class: &str) -> &'a Value {
    r["groups"]
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["startRung"] == rung && g["class"] == class)
        .unwrap_or_else(|| panic!("no group {rung} x {class} in {}", r["groups"]))
}

fn near(v: &Value, want: f64) {
    let got = v
        .as_f64()
        .unwrap_or_else(|| panic!("{v} is not a number, wanted {want}"));
    assert!((got - want).abs() < 1e-9, "{got} != {want}");
}

#[test]
fn a_first_try_pass_is_proved_with_no_reassign_and_the_same_rung_throughout() {
    let dir = var_tmp("cp-roll-first-");
    let root = dir.path();
    put(
        root,
        Lane::new("direct", vec![seg("claude:haiku", 4, 0.10)]),
        "proved",
    );
    put(
        root,
        Lane::new(
            "climbed",
            vec![seg("claude:haiku", 5, 0.20), seg("claude:sonnet", 3, 0.50)],
        ),
        "proved",
    );
    let r = roll(&[root], false);

    let rows: std::collections::BTreeMap<String, &Value> = r["lanes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| (l["id"].as_str().unwrap().to_string(), l))
        .collect();
    let direct = rows["direct"];
    assert_eq!(direct["firstRung"], "claude:haiku");
    assert_eq!(direct["finalRung"], "claude:haiku");
    assert_eq!(direct["proved"], true);
    assert_eq!(direct["firstTry"], true);
    assert_eq!(direct["reassigns"], 0);

    // Proved after a reassign: proved, but not on the first try, and the lane is grouped
    // under the rung it started on.
    let climbed = rows["climbed"];
    assert_eq!(climbed["firstRung"], "claude:haiku");
    assert_eq!(climbed["finalRung"], "claude:sonnet");
    assert_eq!(climbed["proved"], true);
    assert_eq!(climbed["firstTry"], false);
    assert_eq!(climbed["reassigns"], 1);
    near(&climbed["costUsd"], 0.70);
    assert_eq!(climbed["turns"], 8);

    let g = group(&r, "claude:haiku", "rust");
    assert_eq!(g["lanes"], 2);
    assert_eq!(g["firstTryPassed"], 1);
    assert_eq!(g["proved"], 2);
}

#[test]
fn a_redirect_or_a_resume_on_the_same_rung_is_not_a_reassign() {
    let dir = var_tmp("cp-roll-redirect-");
    let root = dir.path();
    // Three launches on one rung (a ruling resumed the session twice): no reassign.
    put(
        root,
        Lane::new(
            "resumed",
            vec![
                seg("claude:haiku", 2, 0.05),
                seg("claude:haiku", 2, 0.05),
                seg("claude:haiku", 2, 0.05),
            ],
        ),
        "proved",
    );
    let r = roll(&[root], false);
    let l = &r["lanes"][0];
    assert_eq!(l["reassigns"], 0);
    assert_eq!(l["firstTry"], true);
}

#[test]
fn a_reassign_across_runtimes_counts_and_the_lane_stays_in_its_starting_group() {
    let dir = var_tmp("cp-roll-cross-");
    let root = dir.path();
    put(
        root,
        Lane::new(
            "cross",
            vec![
                seg("openrouter:glm-5.3-flash", 3, 0.01),
                seg("claude:haiku", 4, 0.20),
                seg("claude:sonnet", 4, 0.60),
            ],
        )
        .class("light"),
        "proved",
    );
    let r = roll(&[root], false);
    let l = &r["lanes"][0];
    assert_eq!(l["reassigns"], 2);
    assert_eq!(l["finalRung"], "claude:sonnet");
    let g = group(&r, "openrouter:glm-5.3-flash", "light");
    assert_eq!(g["lanes"], 1);
    near(&g["meanReassigns"], 2.0);
    assert_eq!(g["firstTryPassed"], 0);
}

/// Seven lanes over two start rungs and two classes, with the numbers worked out by hand.
fn seed_groups(root: &Path) {
    put(
        root,
        Lane::new("l1", vec![seg("claude:haiku", 4, 0.10)]),
        "proved",
    );
    put(
        root,
        Lane::new("l2", vec![seg("claude:haiku", 6, 0.30)]),
        "proved",
    );
    put(
        root,
        Lane::new(
            "l3",
            vec![seg("claude:haiku", 5, 0.20), seg("claude:sonnet", 3, 0.50)],
        ),
        "proved",
    );
    put(
        root,
        Lane::new("l4", vec![seg("claude:haiku", 10, 0.40)]),
        "refuted",
    );
    put(
        root,
        Lane::new("l5", vec![seg("claude:haiku", 2, 0.05)]).class("light"),
        "proved",
    );
    put(
        root,
        Lane::new("l6", vec![seg("claude:sonnet", 3, 0.60)]),
        "proved",
    );
    put(
        root,
        Lane::new(
            "l7",
            vec![seg("claude:sonnet", 4, 0.80), seg("claude:opus", 8, 1.20)],
        ),
        "refuted",
    );
}

#[test]
fn lanes_group_by_start_rung_and_class_with_exact_numbers() {
    let dir = var_tmp("cp-roll-groups-");
    seed_groups(dir.path());
    let r = roll(&[dir.path()], false);

    assert_partition(&r);
    assert_eq!(r["counts"]["counted"], 7);
    assert_eq!(r["groups"].as_array().unwrap().len(), 3);

    // haiku x rust: l1 l2 l3 l4. Costs 0.10 0.30 0.70 0.40, turns 4 6 8 10.
    let g = group(&r, "claude:haiku", "rust");
    assert_eq!(g["lanes"], 4);
    assert_eq!(g["firstTryPassed"], 2);
    near(&g["firstTryRate"], 0.5);
    assert_eq!(g["proved"], 3);
    near(&g["provedRate"], 0.75);
    near(&g["medianCostUsd"], 0.35);
    near(&g["totalCostUsd"], 1.50);
    near(&g["costPerProvedUsd"], 0.50);
    near(&g["medianTurns"], 7.0);
    near(&g["meanReassigns"], 0.25);

    // haiku x light: one proved lane.
    let g = group(&r, "claude:haiku", "light");
    assert_eq!(g["lanes"], 1);
    assert_eq!(g["firstTryPassed"], 1);
    assert_eq!(g["proved"], 1);
    near(&g["medianCostUsd"], 0.05);
    near(&g["costPerProvedUsd"], 0.05);
    near(&g["meanReassigns"], 0.0);

    // sonnet x rust: l6 (proved) and l7 (reassigned to opus, refuted).
    let g = group(&r, "claude:sonnet", "rust");
    assert_eq!(g["lanes"], 2);
    assert_eq!(g["firstTryPassed"], 1);
    assert_eq!(g["proved"], 1);
    near(&g["medianCostUsd"], 1.30);
    near(&g["totalCostUsd"], 2.60);
    near(&g["costPerProvedUsd"], 2.60);
    near(&g["medianTurns"], 7.5);
    near(&g["meanReassigns"], 0.5);

    // Where the lanes that started on each rung ended.
    let climbed = r["climbed"].as_array().unwrap();
    assert_eq!(climbed.len(), 2);
    assert_eq!(climbed[0]["startRung"], "claude:haiku");
    assert_eq!(climbed[0]["lanes"], 5);
    assert_eq!(climbed[0]["climbed"], 1);
    assert_eq!(
        climbed[0]["endedOn"],
        json!({"claude:haiku": 4, "claude:sonnet": 1})
    );
    assert_eq!(climbed[1]["startRung"], "claude:sonnet");
    assert_eq!(climbed[1]["lanes"], 2);
    assert_eq!(climbed[1]["climbed"], 1);
    assert_eq!(
        climbed[1]["endedOn"],
        json!({"claude:opus": 1, "claude:sonnet": 1})
    );
}

#[test]
fn a_group_with_no_proved_lane_has_no_cost_per_proved() {
    let dir = var_tmp("cp-roll-noproved-");
    put(
        dir.path(),
        Lane::new("bad", vec![seg("claude:haiku", 4, 0.10)]),
        "refuted",
    );
    let r = roll(&[dir.path()], false);
    let g = group(&r, "claude:haiku", "rust");
    assert_eq!(g["proved"], 0);
    near(&g["provedRate"], 0.0);
    near(&g["firstTryRate"], 0.0);
    assert!(g["costPerProvedUsd"].is_null(), "{g}");
    near(&g["totalCostUsd"], 0.10);
}

#[test]
fn a_lane_from_before_d28_counts_as_claude_with_its_model() {
    let dir = var_tmp("cp-roll-legacy-");
    let root = dir.path();
    // No `runtime`, `startRung` or `rungSource` anywhere: run.json as step 0 wrote it.
    let old = Lane::new("old", vec![seg("haiku", 3, 0.12)]);
    assert!(old.run_json().get("runtime").is_none());
    assert!(old.run_json()["segments"][0].get("runtime").is_none());
    put(root, old, "proved");
    put(
        root,
        Lane::new("new", vec![seg("claude:haiku", 3, 0.12)]),
        "proved",
    );
    let r = roll(&[root], false);

    // Both land in one group, and only the old one is flagged.
    let g = group(&r, "claude:haiku", "rust");
    assert_eq!(g["lanes"], 2);
    assert_eq!(r["counts"]["legacy"], 1);
    let old = r["lanes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|l| l["id"] == "old")
        .unwrap();
    assert_eq!(old["legacy"], true);
    assert_eq!(old["firstRung"], "claude:haiku");
    assert_eq!(old["finalRung"], "claude:haiku");
    assert!(old["rungSource"].is_null());
    let text = rollup_text(&[root], false);
    assert!(text.contains("before D28"), "no footnote in:\n{text}");
}

fn rollup_text(roots: &[&Path], include_unsandboxed: bool) -> String {
    let roots: Vec<PathBuf> = roots.iter().map(|p| p.to_path_buf()).collect();
    rollup(
        &roots,
        &Options {
            include_unsandboxed,
        },
    )
    .unwrap()
    .render()
}

#[test]
fn a_running_lane_is_counted_as_running_and_never_as_a_failure() {
    let dir = var_tmp("cp-roll-running-");
    let root = dir.path();
    put(
        root,
        Lane::new("done", vec![seg("claude:haiku", 4, 0.10)]),
        "proved",
    );
    // Still running: the builder has not exited, so there is no run.json and no verdict,
    // only what the runner has written so far (`cowproof watch` calls this `running`).
    write(root, "live", "escalations.jsonl", "");
    // The builder exited and the proof has not finished: run.json says `finished`, there
    // is no verdict yet.
    write(
        root,
        "proving",
        "run.json",
        &serde_json::to_string(
            &Lane::new("proving", vec![seg("claude:haiku", 4, 0.10)]).run_json(),
        )
        .unwrap(),
    );
    let r = roll(&[root], false);
    assert_partition(&r);
    assert_eq!(r["counts"]["running"], 2);
    assert_eq!(r["counts"]["counted"], 1);
    assert_eq!(r["counts"]["unreadable"], 0);
    let g = group(&r, "claude:haiku", "rust");
    assert_eq!(g["lanes"], 1);
    assert_eq!(g["proved"], 1);
    near(&g["provedRate"], 1.0);
    near(&g["firstTryRate"], 1.0);
    assert_eq!(
        r["lanes"].as_array().unwrap().len(),
        1,
        "running lanes have no row"
    );
}

#[test]
fn a_lane_that_ended_without_a_verdict_counts_as_not_proved() {
    let dir = var_tmp("cp-roll-timeout-");
    let root = dir.path();
    put(
        root,
        Lane::new("ok", vec![seg("claude:haiku", 4, 0.10)]),
        "proved",
    );
    // A timeout and a cost cap write run.json and never reach the proof.
    for (id, status) in [("slow", "timeout"), ("dear", "cost-cap")] {
        write(
            root,
            id,
            "run.json",
            &serde_json::to_string(
                &Lane::new(id, vec![seg("claude:haiku", 20, 0.90)])
                    .status(status)
                    .run_json(),
            )
            .unwrap(),
        );
    }
    let r = roll(&[root], false);
    assert_eq!(r["counts"]["running"], 0);
    let g = group(&r, "claude:haiku", "rust");
    assert_eq!(g["lanes"], 3);
    assert_eq!(g["proved"], 1);
    assert_eq!(g["firstTryPassed"], 1);
    near(&g["totalCostUsd"], 1.90);
    near(&g["costPerProvedUsd"], 1.90);
}

#[test]
fn a_run_that_never_started_a_builder_is_not_a_lane_for_the_rates() {
    let dir = var_tmp("cp-roll-never-");
    let root = dir.path();
    // `record_stopped`: run.json with the id, the host, the duration and the reason.
    write(
        root,
        "refused",
        "run.json",
        r#"{"id":"refused","host":null,"durationMs":3,"status":"failed","error":"preflight","exitCode":4}"#,
    );
    let r = roll(&[root], false);
    assert_eq!(r["counts"]["neverStarted"], 1);
    assert_eq!(r["counts"]["counted"], 0);
    assert!(r["groups"].as_array().unwrap().is_empty());
}

#[test]
fn a_lane_with_neither_file_is_unreadable() {
    let dir = var_tmp("cp-roll-unreadable-");
    let root = dir.path();
    put(
        root,
        Lane::new("ok", vec![seg("claude:haiku", 4, 0.10)]),
        "proved",
    );
    // No control directory at all, an empty one, and a verdict with no run.json.
    fs::create_dir(root.join("bare")).unwrap();
    fs::create_dir_all(root.join("empty/control")).unwrap();
    write(
        root,
        "orphan",
        "verdict.json",
        &serde_json::to_string(&verdict_json("orphan", "proved", false)).unwrap(),
    );
    // A stray file in the root is not a lane and is not counted.
    fs::write(root.join("notes.txt"), "x").unwrap();
    let r = roll(&[root], false);
    assert_partition(&r);
    assert_eq!(r["counts"]["unreadable"], 3);
    assert_eq!(r["counts"]["counted"], 1);
    assert_eq!(r["counts"]["seen"], 4);
    assert_eq!(group(&r, "claude:haiku", "rust")["lanes"], 1);
}

#[test]
fn a_malformed_file_is_counted_and_does_not_stop_the_rollup() {
    let dir = var_tmp("cp-roll-malformed-");
    let root = dir.path();
    put(
        root,
        Lane::new("ok", vec![seg("claude:haiku", 4, 0.10)]),
        "proved",
    );
    write(root, "badrun", "run.json", "{ not json");
    write(
        root,
        "badrun",
        "verdict.json",
        &serde_json::to_string(&verdict_json("badrun", "proved", false)).unwrap(),
    );
    write(
        root,
        "badverdict",
        "run.json",
        &serde_json::to_string(
            &Lane::new("badverdict", vec![seg("claude:haiku", 4, 0.10)]).run_json(),
        )
        .unwrap(),
    );
    write(root, "badverdict", "verdict.json", "\u{0}\u{0}");
    // Valid JSON that is not an object is malformed too.
    write(root, "array", "run.json", "[1,2]");
    let r = roll(&[root], false);
    assert_partition(&r);
    assert_eq!(r["counts"]["malformed"], 3);
    assert_eq!(r["counts"]["counted"], 1);
    assert_eq!(group(&r, "claude:haiku", "rust")["lanes"], 1);
}

#[test]
fn a_symlinked_lane_directory_pointing_outside_the_root_is_skipped() {
    let dir = var_tmp("cp-roll-link-");
    let root = dir.path().join("lanes");
    let outside = dir.path().join("elsewhere");
    fs::create_dir(&root).unwrap();
    fs::create_dir(&outside).unwrap();
    put(
        &root,
        Lane::new("ok", vec![seg("claude:haiku", 4, 0.10)]),
        "proved",
    );
    // A real, proved, expensive lane that is not under the root.
    put(
        &outside,
        Lane::new("far", vec![seg("claude:opus", 9, 9.0)]),
        "proved",
    );
    symlink(outside.join("far"), root.join("linked")).unwrap();
    // A lane directory whose `control` is a link, and one whose run.json is a link.
    fs::create_dir(root.join("ctl")).unwrap();
    symlink(outside.join("far/control"), root.join("ctl/control")).unwrap();
    write(&root, "file", "verdict.json", "{}");
    symlink(
        outside.join("far/control/run.json"),
        root.join("file/control/run.json"),
    )
    .unwrap();

    let r = roll(&[&root], false);
    assert_partition(&r);
    assert_eq!(r["counts"]["symlinked"], 3);
    assert_eq!(r["counts"]["counted"], 1);
    assert_eq!(r["groups"].as_array().unwrap().len(), 1);
    assert_eq!(group(&r, "claude:haiku", "rust")["lanes"], 1);
    let text = serde_json::to_string(&r).unwrap();
    assert!(!text.contains("claude:opus"), "followed a link: {text}");
}

#[test]
fn unsandboxed_lanes_are_left_out_of_the_rates_unless_asked_for() {
    let dir = var_tmp("cp-roll-unsandboxed-");
    let root = dir.path();
    put(
        root,
        Lane::new("box", vec![seg("claude:haiku", 4, 0.10)]),
        "proved",
    );
    // An unsandboxed lane is `finished`, never `proved` (it cannot be), and it passed
    // everything a sandboxed one would have.
    put(
        root,
        Lane::new("free", vec![seg("claude:haiku", 4, 0.30)]).unsandboxed(),
        "finished",
    );
    let r = roll(&[root], false);
    assert_partition(&r);
    assert_eq!(r["counts"]["excludedUnsandboxed"], 1);
    assert_eq!(r["counts"]["counted"], 1);
    let g = group(&r, "claude:haiku", "rust");
    assert_eq!(g["lanes"], 1);
    near(&g["totalCostUsd"], 0.10);
    assert!(rollup_text(&[root], false).contains("--include-unsandboxed"));

    let r = roll(&[root], true);
    assert_eq!(r["counts"]["excludedUnsandboxed"], 0);
    assert_eq!(r["counts"]["counted"], 2);
    let g = group(&r, "claude:haiku", "rust");
    assert_eq!(g["lanes"], 2);
    assert_eq!(
        g["proved"], 2,
        "a finished unsandboxed lane counts as proved"
    );
    assert_eq!(g["firstTryPassed"], 2);
    near(&g["totalCostUsd"], 0.40);
    let free = r["lanes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|l| l["id"] == "free")
        .unwrap();
    assert_eq!(free["unsandboxed"], true);
    assert_eq!(free["outcome"], "finished");
}

#[test]
fn an_unsandboxed_lane_that_was_refuted_is_not_proved_even_when_included() {
    let dir = var_tmp("cp-roll-unsandboxed-bad-");
    put(
        dir.path(),
        Lane::new("free", vec![seg("claude:haiku", 4, 0.30)]).unsandboxed(),
        "refuted",
    );
    let r = roll(&[dir.path()], true);
    assert_eq!(group(&r, "claude:haiku", "rust")["proved"], 0);
}

#[test]
fn remote_lanes_are_recorded_by_their_host() {
    let dir = var_tmp("cp-roll-remote-");
    let root = dir.path();
    put(
        root,
        Lane::new("here", vec![seg("claude:haiku", 4, 0.10)]),
        "proved",
    );
    put(
        root,
        Lane::new("there", vec![seg("claude:haiku", 4, 0.10)]).host("buildbox"),
        "proved",
    );
    let r = roll(&[root], false);
    assert_eq!(r["counts"]["remote"], 1);
    let there = r["lanes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|l| l["id"] == "there")
        .unwrap();
    assert_eq!(there["remote"], true);
    assert_eq!(there["host"], "buildbox");
    let here = r["lanes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|l| l["id"] == "here")
        .unwrap();
    assert_eq!(here["remote"], false);
    assert!(here["host"].is_null());
}

#[test]
fn several_roots_add_up_and_the_same_lane_name_in_two_roots_is_two_lanes() {
    let a = var_tmp("cp-roll-a-");
    let b = var_tmp("cp-roll-b-");
    put(
        a.path(),
        Lane::new("same", vec![seg("claude:haiku", 4, 0.10)]),
        "proved",
    );
    put(
        b.path(),
        Lane::new("same", vec![seg("claude:haiku", 4, 0.30)]),
        "refuted",
    );
    let r = roll(&[a.path(), b.path()], false);
    assert_eq!(r["counts"]["counted"], 2);
    let g = group(&r, "claude:haiku", "rust");
    assert_eq!(g["lanes"], 2);
    assert_eq!(g["proved"], 1);
    near(&g["totalCostUsd"], 0.40);
}

#[test]
fn rung_source_and_cost_estimates_are_reported() {
    let dir = var_tmp("cp-roll-source-");
    let root = dir.path();
    put(
        root,
        Lane::new("a", vec![seg("claude:haiku", 1, 0.1)]),
        "proved",
    );
    let mut flag = Lane::new("b", vec![seg("claude:haiku", 1, 0.1)]);
    flag.source = Some("flag");
    put(root, flag, "proved");
    let r = roll(&[root], false);
    assert_eq!(r["counts"]["rungSources"], json!({"class": 1, "flag": 1}));
    let a = r["lanes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|l| l["id"] == "a")
        .unwrap();
    assert_eq!(a["rungSource"], "class");
    assert_eq!(a["costIsEstimate"], true);
    assert!(rollup_text(&[root], false).contains("estimate"));
}

#[test]
fn a_root_that_is_not_a_directory_is_an_error() {
    let dir = var_tmp("cp-roll-missing-");
    let err = rollup(
        &[dir.path().join("nope")],
        &Options {
            include_unsandboxed: false,
        },
    )
    .unwrap_err();
    assert!(format!("{err:#}").contains("nope"), "{err:#}");
}

#[test]
fn text_from_a_json_file_cannot_carry_terminal_escapes() {
    let dir = var_tmp("cp-roll-escape-");
    let root = dir.path();
    let mut run = Lane::new("evil", vec![seg("claude:haiku", 1, 0.1)]).run_json();
    run["model"] = json!("ha\u{1b}[31miku");
    run["segments"][0]["model"] = json!("ha\u{1b}[31miku");
    run["classSlot"]["class"] = json!("ru\u{7}st");
    write(
        root,
        "evil",
        "run.json",
        &serde_json::to_string(&run).unwrap(),
    );
    write(
        root,
        "evil",
        "verdict.json",
        &serde_json::to_string(&verdict_json("evil", "proved", false)).unwrap(),
    );
    let text = rollup_text(&[root], false);
    assert!(
        !text.contains('\u{1b}') && !text.contains('\u{7}'),
        "{text:?}"
    );
    let json = serde_json::to_string(&roll(&[root], false)).unwrap();
    assert!(
        !json.contains("\\u001b") && !json.contains("\\u0007"),
        "{json}"
    );
}

#[test]
fn the_plain_table_fits_80_columns() {
    let dir = var_tmp("cp-roll-width-");
    let root = dir.path();
    seed_groups(root);
    put(
        root,
        Lane::new("w", vec![seg("openrouter:glm-5.3-flash", 3, 123.45)])
            .class("a-very-long-class-name-indeed"),
        "proved",
    );
    let text = rollup_text(&[root], false);
    for line in text.lines() {
        assert!(
            line.chars().count() <= 80,
            "{} columns: {line:?}",
            line.chars().count()
        );
    }
    assert!(text.contains("claude:haiku"));
    assert!(text.contains("openrouter:glm-5.3-flash"));
}

#[test]
fn an_empty_root_prints_a_table_of_nothing_and_succeeds() {
    let dir = var_tmp("cp-roll-empty-");
    let r = roll(&[dir.path()], false);
    assert_eq!(r["counts"]["seen"], 0);
    assert!(r["groups"].as_array().unwrap().is_empty());
    assert!(rollup_text(&[dir.path()], false).contains("no lanes"));
}
