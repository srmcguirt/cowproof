//! `cowproof verify <capsule>` and held-out checks, end to end: a real `cowproof run`
//! against a FAKE `claude` makes the capsule, and the verifier replays it. Needs the
//! sandbox like `tests/run.rs` (skipped without it, a failure under
//! `COWPROOF_REQUIRE_SANDBOX=1`).

mod common;

use common::{Lane, git, mcp_session, output, run_checks, sandbox_available, text, var_tmp};
use cowproof_prove::{Capsule, HELDOUT_FILE};
use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn checks() -> Value {
    json!([
        {"id": "edit", "command": "grep -q edited README.md"},
        {"id": "made", "command": "test -f created.txt"},
    ])
}

/// A lane whose builder edits README.md, creates created.txt and runs both checks.
fn lane() -> Lane {
    Lane::new(&run_checks(&["edit", "made"]), checks())
}

fn fresh_clone(lane: &Lane) -> tempfile::TempDir {
    let dir = var_tmp("cp-ver-fresh-");
    let out = output(
        Command::new("git")
            .args(["clone", "-q"])
            .arg(&lane.repo)
            .arg(dir.path().join("repo")),
    );
    assert!(out.status.success(), "{}", text(&out));
    dir
}

/// `cowproof verify` run from `cwd` (never the repository or the lane).
fn verify(lane: &Lane, capsule: &Path, repo: &Path, workdir: &Path, cwd: &Path) -> Output {
    output(
        lane.cowproof_cmd()
            .current_dir(cwd)
            .arg("verify")
            .arg(capsule)
            .arg("--repo")
            .arg(repo)
            .arg("--workdir")
            .arg(workdir),
    )
}

/// Run the lane (it reaches `expect`) and replay its capsule from another directory on
/// a fresh clone of the repository.
fn replay(lane: &Lane) -> Output {
    let fresh = fresh_clone(lane);
    let elsewhere = var_tmp("cp-ver-cwd-");
    let workdir = var_tmp("cp-ver-wd-");
    verify(
        lane,
        &lane.capsule_dir(),
        &fresh.path().join("repo"),
        workdir.path(),
        elsewhere.path(),
    )
}

fn run_expecting(lane: &Lane, args: &[&Path], code: i32) -> Output {
    let out = lane.run(args);
    assert_eq!(
        out.status.code(),
        Some(code),
        "cowproof run:\n{}",
        text(&out)
    );
    out
}

fn stdout(out: &Output) -> String {
    String::from_utf8(out.stdout.clone()).unwrap()
}

#[test]
fn verify_help_documents_every_exit_code() {
    let out = output(Command::new(env!("CARGO_BIN_EXE_cowproof")).args(["verify", "--help"]));
    assert!(out.status.success());
    let help = stdout(&out)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    for code in ["0 reproduced", "2 diverged", "4 infrastructure"] {
        assert!(help.contains(code), "no {code:?} in: {help}");
    }
}

#[test]
fn a_proved_lane_reproduces_from_another_directory_on_a_fresh_clone() {
    if !sandbox_available() {
        return;
    }
    let lane = lane();
    run_expecting(&lane, &[], 0);
    assert_eq!(lane.verdict()["verdict"], "proved");

    let fresh = fresh_clone(&lane);
    let fresh_repo = fresh.path().join("repo");
    let elsewhere = var_tmp("cp-ver-cwd-");
    let workdir = var_tmp("cp-ver-wd-");
    let out = verify(
        &lane,
        &lane.capsule_dir(),
        &fresh_repo,
        workdir.path(),
        elsewhere.path(),
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert_eq!(stdout(&out).trim(), "reproduced");

    // It really rebuilt: the lane's file is in the tree the verifier made, though the
    // fresh clone never had it.
    assert!(!fresh_repo.join("created.txt").exists());
    let tree = workdir
        .path()
        .canonicalize()
        .unwrap()
        .join("lane/scratch/verify/tree");
    assert_eq!(
        fs::read_to_string(tree.join("created.txt")).unwrap(),
        "created\n"
    );
    assert!(
        fs::read_to_string(tree.join("README.md"))
            .unwrap()
            .contains("edited")
    );
}

/// A capsule written before D28 has no `builder_runtime` and no `rung_source`. Sealed again
/// over those bytes, as the older writer would have sealed it, it still reproduces.
#[test]
fn a_capsule_without_the_runtime_and_rung_source_fields_still_reproduces() {
    if !sandbox_available() {
        return;
    }
    let lane = lane();
    run_expecting(&lane, &[], 0);
    let capsule = lane.capsule_dir();
    let path = capsule.join("capsule.json");
    let mut json: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(json["builder_runtime"], "claude", "the new run records it");
    assert_eq!(json["rung_source"], "default");
    let object = json.as_object_mut().unwrap();
    assert!(object.remove("builder_runtime").is_some());
    assert!(object.remove("rung_source").is_some());
    let raw = serde_json::to_vec_pretty(&json).unwrap();
    fs::write(&path, &raw).unwrap();
    fs::write(capsule.join("capsule.sha256"), Capsule::hash_bytes(&raw)).unwrap();

    let old = Capsule::read(&capsule).expect("an older capsule reads");
    assert_eq!(old.builder_runtime, "claude");
    assert_eq!(old.rung_source, None);
    let out = replay(&lane);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert_eq!(stdout(&out).trim(), "reproduced");
}

/// A capsule written before the trace totals has no `trace_totals`. Sealed again over those
/// bytes, as the older writer would have sealed it, it still reproduces.
#[test]
fn a_capsule_without_trace_totals_still_reproduces() {
    if !sandbox_available() {
        return;
    }
    let lane = lane();
    run_expecting(&lane, &[], 0);
    let capsule = lane.capsule_dir();
    let path = capsule.join("capsule.json");
    let mut json: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert!(
        json.as_object_mut()
            .unwrap()
            .remove("trace_totals")
            .is_some(),
        "the new run writes the key"
    );
    let raw = serde_json::to_vec_pretty(&json).unwrap();
    fs::write(&path, &raw).unwrap();
    fs::write(capsule.join("capsule.sha256"), Capsule::hash_bytes(&raw)).unwrap();

    let old = Capsule::read(&capsule).expect("an older capsule reads");
    assert_eq!(old.trace_totals, None);
    let out = replay(&lane);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert_eq!(stdout(&out).trim(), "reproduced");
}

/// The capsule is read byte for byte: a hand edit to `capsule.json` and to `lane.patch`
/// are each refused and named, and the untouched capsule still reproduces.
#[test]
fn a_tampered_capsule_is_refused_naming_the_tamper() {
    if !sandbox_available() {
        return;
    }
    let lane = lane();
    run_expecting(&lane, &[], 0);
    let capsule = lane.capsule_dir();

    // lane.patch.
    let patch_path = capsule.join("lane.patch");
    let patch = fs::read(&patch_path).unwrap();
    fs::write(&patch_path, b"tampered").unwrap();
    let out = replay(&lane);
    assert_eq!(out.status.code(), Some(4), "{}", text(&out));
    let err = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(
        err.contains("tampered") && err.contains("lane.patch"),
        "{err}"
    );
    fs::write(&patch_path, &patch).unwrap();

    // capsule.json: `unsandboxed` flipped, which would otherwise be refused anyway, so
    // the refusal must come from the seal and name capsule.json.
    let json_path = capsule.join("capsule.json");
    let json = fs::read_to_string(&json_path).unwrap();
    assert!(json.contains("\"unsandboxed\": false"));
    fs::write(
        &json_path,
        json.replace("\"unsandboxed\": false", "\"unsandboxed\": true"),
    )
    .unwrap();
    let out = replay(&lane);
    assert_eq!(out.status.code(), Some(4), "{}", text(&out));
    let err = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(
        err.contains("tampered") && err.contains("capsule.json"),
        "{err}"
    );
    fs::write(&json_path, &json).unwrap();

    // Restored, the same capsule reproduces: the refusals were the tampering.
    let out = replay(&lane);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
}

/// The seal covers what `verify` runs: a `checks/injected.json` added to a sealed capsule
/// is refused (exit 4, naming the file) and its command never runs, and the capsule
/// reproduces again once the file is removed.
#[test]
fn an_unsealed_check_added_to_a_capsule_is_refused_and_never_run() {
    if !sandbox_available() {
        return;
    }
    let lane = lane();
    run_expecting(&lane, &[], 0);
    let capsule = lane.capsule_dir();

    let markers = var_tmp("cp-ver-marker-");
    let marker = markers.path().join("injected-ran");
    let injected = capsule.join("checks/injected.json");
    fs::write(
        &injected,
        serde_json::to_vec(&json!({
            "command": format!("touch '{}'", marker.display()),
            "exit_status": 0,
            "attempts": 1,
            "duration_ms": 1,
            "output_sha256": "ignored",
        }))
        .unwrap(),
    )
    .unwrap();
    let out = replay(&lane);
    assert_eq!(out.status.code(), Some(4), "{}", text(&out));
    let err = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(err.contains("checks/injected.json"), "{err}");
    assert!(!marker.exists(), "the unsealed check ran");

    fs::remove_file(&injected).unwrap();
    let out = replay(&lane);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert!(!marker.exists(), "the unsealed check ran");
}

/// A capsule from a builder that ran unconfined is not a proof to hand to someone else:
/// standalone `cowproof verify` refuses it with exit 4, naming `unsandboxed`, before it
/// rebuilds anything. The run that made it checked it (and ended `finished`).
#[test]
fn a_capsule_from_an_unsandboxed_lane_is_refused_by_standalone_verify() {
    if !sandbox_available() {
        return;
    }
    let lane = lane();
    let out = run_expecting(&lane, &[Path::new("--unsandboxed")], 0);
    assert!(stdout(&out).contains(": finished"), "{}", text(&out));
    assert_eq!(lane.verdict()["verdict"], "finished");
    assert!(Capsule::read(&lane.capsule_dir()).unwrap().unsandboxed);

    let fresh = fresh_clone(&lane);
    let elsewhere = var_tmp("cp-ver-cwd-");
    let workdir = var_tmp("cp-ver-wd-");
    let out = verify(
        &lane,
        &lane.capsule_dir(),
        &fresh.path().join("repo"),
        workdir.path(),
        elsewhere.path(),
    );
    assert_eq!(out.status.code(), Some(4), "{}", text(&out));
    let err = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(err.contains("unsandboxed"), "{err}");
    assert!(
        !stdout(&out).contains("reproduced"),
        "an unsandboxed capsule must not reproduce: {}",
        text(&out)
    );
    // Refused before anything was rebuilt.
    assert!(
        !workdir
            .path()
            .canonicalize()
            .unwrap()
            .join("lane/scratch/verify/tree")
            .exists()
    );
}

/// A check the builder recorded as a pass that the rebuilt tree cannot reproduce: the
/// builder owns the clone's `.git`, so it can keep a file out of the patch.
#[test]
fn a_recorded_check_that_does_not_reproduce_exits_2_naming_it() {
    if !sandbox_available() {
        return;
    }
    let body = format!(
        "mkdir -p .git/info\necho marker >> .git/info/exclude\necho state > marker\n{}",
        run_checks(&["edit", "marker"])
    );
    let lane = Lane::new(
        &body,
        json!([
            {"id": "edit", "command": "grep -q edited README.md"},
            {"id": "marker", "command": "test -f marker"},
        ]),
    );
    run_expecting(&lane, &[], 2);

    let out = replay(&lane);
    assert_eq!(out.status.code(), Some(2), "{}", text(&out));
    let out_text = stdout(&out);
    assert!(
        out_text.contains("diverged") && out_text.contains("\"marker\""),
        "{out_text}"
    );
    assert!(!out_text.contains("\"edit\""), "{out_text}");
}

// ---- held-out checks (D5) ------------------------------------------------------------

const CANARY: &str = "HELDOUT-CANARY-5d1f";

fn heldout_file(dir: &Path, command: &str) -> PathBuf {
    let path = dir.join("h.toml");
    fs::write(
        &path,
        format!("[[check]]\nid = \"hidden-edit\"\ncommand = \"{command} # {CANARY}\"\n"),
    )
    .unwrap();
    path
}

/// Every file under `dir` (not following symlinks) whose bytes contain `needle`.
fn files_containing(dir: &Path, needle: &str) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let Ok(entries) = fs::read_dir(dir) else {
        return found;
    };
    for entry in entries {
        let entry = entry.unwrap();
        let path = entry.path();
        let kind = entry.file_type().unwrap();
        if kind.is_dir() {
            found.extend(files_containing(&path, needle));
        } else if kind.is_file() {
            let bytes = fs::read(&path).unwrap();
            if bytes.windows(needle.len()).any(|w| w == needle.as_bytes()) {
                found.push(path);
            }
        }
    }
    found
}

#[test]
fn held_out_checks_that_pass_prove_the_lane_and_live_only_in_the_capsule() {
    if !sandbox_available() {
        return;
    }
    let lane = lane();
    let held = var_tmp("cp-ver-held-");
    let file = heldout_file(held.path(), "grep -q edited README.md");
    run_expecting(&lane, &[Path::new("--heldout"), &file], 0);
    assert_eq!(lane.verdict()["verdict"], "proved");

    // The file is in the capsule's packets/, byte for byte, hashed, and the capsule reads.
    let capsule = lane.capsule_dir();
    assert_eq!(
        fs::read(capsule.join(HELDOUT_FILE)).unwrap(),
        fs::read(&file).unwrap()
    );
    assert!(
        Capsule::read(&capsule)
            .unwrap()
            .file_hashes
            .contains_key(HELDOUT_FILE)
    );
    let gates: Value =
        serde_json::from_str(&fs::read_to_string(capsule.join("gates.json")).unwrap()).unwrap();
    let gate = gates["gates"]
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["name"] == "held_out")
        .unwrap();
    assert_eq!(gate["passed"], true, "{gate}");
    assert_eq!(gate["warned"], false, "{gate}");

    // Nowhere in the lane's clone, home or scratch: the content only reaches the
    // capsule (a positive control shows the search can find it).
    let dir = lane.lane_dir();
    assert!(!files_containing(&capsule, CANARY).is_empty());
    for part in ["clone", "home", "scratch"] {
        let found = files_containing(&dir.join(part), CANARY);
        assert!(
            found.is_empty(),
            "held-out content leaked into lane/{part}: {found:?}"
        );
    }
}

#[test]
fn a_failing_held_out_check_refutes_the_lane_and_is_named() {
    if !sandbox_available() {
        return;
    }
    let lane = lane();
    let held = var_tmp("cp-ver-held-");
    let file = heldout_file(held.path(), "grep -q no-such-line README.md");
    let out = run_expecting(&lane, &[Path::new("--heldout"), &file], 2);

    // Every visible check passed; only the held-out check refutes.
    let verdict = lane.verdict();
    assert_eq!(verdict["verdict"], "refuted", "{verdict}");
    assert_eq!(verdict["failedChecks"], json!([]));
    assert_eq!(verdict["diverged"], json!([]));
    assert_eq!(verdict["failedGates"], json!([]));
    assert_eq!(verdict["heldOutFailed"], json!(["hidden-edit"]));
    assert!(
        verdict["reasons"][0]
            .as_str()
            .unwrap()
            .contains("held-out check \"hidden-edit\""),
        "{verdict}"
    );
    assert!(stdout(&out).contains("hidden-edit"), "{}", text(&out));

    // `cowproof verify` on the same capsule says the same.
    let out = replay(&lane);
    assert_eq!(out.status.code(), Some(2), "{}", text(&out));
    assert!(stdout(&out).contains("\"hidden-edit\""), "{}", text(&out));
}

#[test]
fn without_the_flag_the_director_store_supplies_the_held_out_checks() {
    if !sandbox_available() {
        return;
    }
    let lane = lane();
    let id = cowproof_core::heldout::repo_id(&lane.repo).unwrap();
    let store = cowproof_core::heldout::default_store(lane.home.path(), &id, &lane.id).unwrap();
    fs::create_dir_all(store.parent().unwrap()).unwrap();
    heldout_file(store.parent().unwrap(), "grep -q no-such-line README.md");
    fs::rename(store.parent().unwrap().join("h.toml"), &store).unwrap();

    run_expecting(&lane, &[], 2);
    let verdict = lane.verdict();
    assert_eq!(
        verdict["heldOutFailed"],
        json!(["hidden-edit"]),
        "{verdict}"
    );
    assert!(lane.capsule_dir().join(HELDOUT_FILE).is_file());
}

#[test]
fn a_held_out_file_inside_the_repository_stops_the_run_before_any_lane_exists() {
    let lane = lane();
    let inside = lane.repo.join("h.toml");
    heldout_file(&lane.repo, "true");
    let out = lane.run(&[Path::new("--heldout"), &inside]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("inside the repository"),
        "{}",
        text(&out)
    );
    assert!(!lane.lane_dir().exists());
}

// ---- What the capsule records about the builder's check runs ---------------

/// The SHA-256 of `bytes`, computed here and not by the code under test.
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(bytes))
}

/// A lane whose builder runs the check `flip` while it still fails, edits README.md, and runs
/// it again: two attempts, the second a pass that takes at least 100 ms and prints `flipped-ok`.
fn flip_lane() -> Lane {
    let run_flip = |out: &str| mcp_session(out, &[(3, "run_check", json!({"id": "flip"}))]);
    let body = format!(
        "{}echo second >> README.md\n{}",
        run_flip("a.out"),
        run_flip("b.out")
    );
    Lane::new(
        &body,
        json!([{"id": "flip", "command": "grep -q second README.md && sleep 0.1 && echo flipped-ok"}]),
    )
}

fn check_record(lane: &Lane, id: &str) -> Value {
    serde_json::from_slice(&fs::read(lane.capsule_dir().join(format!("checks/{id}.json"))).unwrap())
        .unwrap()
}

fn passed_in(lane: &Lane, out: &str) -> bool {
    let raw = fs::read_to_string(lane.lane_dir().join("home/fake").join(out)).unwrap();
    raw.lines()
        .map(|l| serde_json::from_str::<Value>(l).unwrap())
        .find(|f| f["id"] == 3)
        .unwrap()["result"]["structuredContent"]["passed"]
        == true
}

#[test]
fn a_check_that_failed_then_passed_records_two_attempts_a_duration_and_the_passing_output() {
    if !sandbox_available() {
        return;
    }
    let lane = flip_lane();
    run_expecting(&lane, &[], 0);
    assert!(!passed_in(&lane, "a.out"), "the first run must fail");
    assert!(passed_in(&lane, "b.out"), "the second run must pass");

    let record = check_record(&lane, "flip");
    assert_eq!(record["exit_status"], 0, "{record}");
    assert_eq!(record["attempts"], 2, "{record}");
    assert!(
        record["duration_ms"].as_u64().unwrap() >= 100,
        "the passing run slept 100 ms: {record}"
    );
    assert_eq!(
        record["output_sha256"],
        sha256_hex(b"flipped-ok\n"),
        "{record}"
    );
    assert_eq!(record["output_len"], 11, "{record}");
    assert_eq!(
        record["end"],
        json!({"kind": "exited", "code": 0}),
        "{record}"
    );
    // The output itself is not in the capsule: the record has these fields and no others.
    let mut keys: Vec<&str> = record
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "attempts",
            "command",
            "duration_ms",
            "end",
            "exit_status",
            "output_len",
            "output_sha256",
            "timeout_ms",
            "verifier"
        ]
    );
    // No limit of its own: the lane's default (20 minutes) is what the run was held to.
    assert_eq!(record["timeout_ms"], 20 * 60 * 1000, "{record}");
    // No remote holds the test repository's base commit.
    let capsule = Capsule::read(&lane.capsule_dir()).unwrap();
    assert_eq!(capsule.base_remote, None);
    assert!(capsule.local_replay_only);
}

#[test]
fn a_check_the_runner_timed_out_is_recorded_as_timed_out() {
    if !sandbox_available() {
        return;
    }
    let lane = Lane::new(
        &run_checks(&["slow"]),
        json!([{"id": "slow", "command": "sleep 6"}]),
    );
    // The check overruns its 2 s limit, so the builder saw a failure. The capsule records that
    // limit and the verifier replays under it, so it times out too: an infrastructure end
    // (exit 4), not a divergence, as for any verifier timeout.
    let out = run_expecting(
        &lane,
        &[Path::new("--check-timeout-secs"), Path::new("2")],
        4,
    );
    assert!(
        text(&out).contains("check slow") && text(&out).contains("Timeout"),
        "{}",
        text(&out)
    );
    let record = check_record(&lane, "slow");
    assert_eq!(record["timeout_ms"], 2000, "{record}");
    assert_eq!(record["end"], json!({"kind": "timed_out"}), "{record}");
    assert_eq!(record["exit_status"], -1, "{record}");
    assert_eq!(record["attempts"], 1, "{record}");
    assert!(
        record["duration_ms"].as_u64().unwrap() >= 2000,
        "it ran to its limit: {record}"
    );
    assert!(record["output_len"].as_u64().unwrap() > 0, "{record}");
    assert_eq!(record["output_sha256"].as_str().unwrap().len(), 64);
    assert_eq!(lane.verdict()["failedChecks"], json!(["slow"]));
}

/// A check that declares `"timeout": "1s"` against `sleep 30` ends timed out in the builder's
/// `run_check` within a few seconds (the lane's default is 20 minutes), the capsule records the
/// 1 s limit, and `cowproof verify` replays under that recorded limit, not its default, so it
/// too times out within a few seconds and says so.
#[test]
fn a_check_with_its_own_limit_times_out_in_run_check_and_in_the_verifier() {
    if !sandbox_available() {
        return;
    }
    let lane = Lane::new(
        &run_checks(&["slow"]),
        json!([{"id": "slow", "command": "sleep 30", "timeout": "1s"}]),
    );
    let started = std::time::Instant::now();
    let out = lane.run(&[]);
    let elapsed = started.elapsed();
    let record = check_record(&lane, "slow");
    assert_eq!(record["end"], json!({"kind": "timed_out"}), "{record}");
    assert_eq!(record["timeout_ms"], 1000, "{record}");
    let ms = record["duration_ms"].as_u64().unwrap();
    assert!(
        (1000..15_000).contains(&ms),
        "the builder's run stopped at its own 1 s limit: {record}"
    );
    assert!(
        elapsed < std::time::Duration::from_secs(120),
        "the whole run, replay included, did not wait out sleep 30 twice: {elapsed:?} {}",
        text(&out)
    );

    // A later `cowproof verify` holds the replay to the recorded 1 s too.
    let started = std::time::Instant::now();
    let replayed = replay(&lane);
    assert_eq!(replayed.status.code(), Some(4), "{}", text(&replayed));
    let err = String::from_utf8_lossy(&replayed.stderr).to_string();
    assert!(
        err.contains("check slow") && err.contains("Timeout"),
        "{err}"
    );
    assert!(
        started.elapsed() < std::time::Duration::from_secs(60),
        "{:?}",
        started.elapsed()
    );
}

/// `cowproof verify` refuses a capsule whose recorded limit is not the one its packet header
/// declares. The edit also has to survive the seal, so the capsule is resealed after it.
#[test]
fn verify_refuses_a_capsule_whose_limit_differs_from_the_header() {
    if !sandbox_available() {
        return;
    }
    let lane = Lane::new(
        &run_checks(&["quick"]),
        json!([{"id": "quick", "command": "true", "timeout": "30s"}]),
    );
    run_expecting(&lane, &[], 0);
    assert_eq!(check_record(&lane, "quick")["timeout_ms"], 30_000);
    assert_eq!(replay(&lane).status.code(), Some(0), "unedited reproduces");

    let dir = lane.capsule_dir();
    let mut capsule = Capsule::read(&dir).unwrap();
    let mut record = check_record(&lane, "quick");
    record["timeout_ms"] = json!(31_000);
    fs::write(
        dir.join("checks/quick.json"),
        serde_json::to_vec_pretty(&record).unwrap(),
    )
    .unwrap();
    capsule.write(&dir).unwrap();
    let out = replay(&lane);
    assert_eq!(out.status.code(), Some(4), "{}", text(&out));
    let err = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(
        err.contains("\"quick\"") && err.contains("the header is what was proved"),
        "{err}"
    );
}

#[test]
fn a_capsule_naming_the_remote_tracking_ref_that_held_the_base_commit() {
    if !sandbox_available() {
        return;
    }
    let lane = lane();
    let remote = var_tmp("cp-ver-remote-");
    git(remote.path(), &["init", "-q", "--bare"]);
    git(
        &lane.repo,
        &["remote", "add", "origin", remote.path().to_str().unwrap()],
    );
    git(
        &lane.repo,
        &["push", "-q", "origin", "HEAD:refs/heads/main"],
    );
    run_expecting(&lane, &[], 0);
    let capsule = Capsule::read(&lane.capsule_dir()).unwrap();
    assert_eq!(capsule.base_remote.as_deref(), Some("origin/main"));
    assert!(!capsule.local_replay_only);
    // A name, never the address, which can carry a credential.
    let raw = fs::read_to_string(lane.capsule_dir().join("capsule.json")).unwrap();
    assert!(!raw.contains(remote.path().to_str().unwrap()), "{raw}");
}

/// The seal covers the new records: a shorter duration, a different attempt count and a
/// different output hash in `checks/<id>.json` are each refused (exit 4, naming the file), and the
/// untouched capsule still reproduces.
#[test]
fn editing_a_recorded_duration_attempts_or_output_hash_fails_verify() {
    if !sandbox_available() {
        return;
    }
    let lane = flip_lane();
    run_expecting(&lane, &[], 0);
    let path = lane.capsule_dir().join("checks/flip.json");
    let original = fs::read(&path).unwrap();
    for (field, value) in [
        ("duration_ms", json!(1)),
        ("attempts", json!(1)),
        ("output_sha256", json!(sha256_hex(b"something else"))),
    ] {
        let mut record: Value = serde_json::from_slice(&original).unwrap();
        record[field] = value;
        fs::write(&path, serde_json::to_vec_pretty(&record).unwrap()).unwrap();
        let out = replay(&lane);
        assert_eq!(out.status.code(), Some(4), "{field}: {}", text(&out));
        let err = String::from_utf8_lossy(&out.stderr).to_string();
        assert!(
            err.contains("tampered") && err.contains("checks/flip.json"),
            "{field}: {err}"
        );
    }
    fs::write(&path, &original).unwrap();
    let out = replay(&lane);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
}

/// A capsule made before runs were recorded has `exit_status` 0 or 1, one attempt, no duration,
/// an empty output hash and neither `output_len` nor `end`. Sealed again over those bytes, as the
/// older writer would have sealed it, it still reads and reproduces.
#[test]
fn a_capsule_whose_check_records_predate_the_run_fields_still_reproduces() {
    if !sandbox_available() {
        return;
    }
    let lane = flip_lane();
    run_expecting(&lane, &[], 0);
    let capsule = lane.capsule_dir();
    let record = check_record(&lane, "flip");
    let old = json!({
        "command": record["command"],
        "exit_status": 0,
        "attempts": 1,
        "duration_ms": 0,
        "output_sha256": "",
    });
    let old_bytes = serde_json::to_vec_pretty(&old).unwrap();
    fs::write(capsule.join("checks/flip.json"), &old_bytes).unwrap();
    let path = capsule.join("capsule.json");
    let mut json: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    json["file_hashes"]["checks/flip.json"] = json!(Capsule::hash_bytes(&old_bytes));
    let raw = serde_json::to_vec_pretty(&json).unwrap();
    fs::write(&path, &raw).unwrap();
    fs::write(capsule.join("capsule.sha256"), Capsule::hash_bytes(&raw)).unwrap();

    Capsule::read(&capsule).expect("an older capsule reads");
    let out = replay(&lane);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert_eq!(stdout(&out).trim(), "reproduced");
}

// ---- The verifier's own run of each check ----------------------------------

/// A lane with two checks: `stable` prints the same bytes every time, `rand` prints sixteen
/// random bytes in hex, so the verifier's output can never be the builder's.
fn verifier_lane() -> Lane {
    Lane::new(
        &run_checks(&["stable", "rand"]),
        json!([
            {"id": "stable", "command": "echo same"},
            {"id": "rand", "command": "od -An -N16 -tx1 /dev/urandom"},
        ]),
    )
}

/// Seal `capsule.json` again after a test changed a file listed in it, as the writer would.
fn reseal(capsule: &Path, file: &str, bytes: &[u8]) {
    fs::write(capsule.join(file), bytes).unwrap();
    let path = capsule.join("capsule.json");
    let mut json: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    json["file_hashes"][file] = json!(Capsule::hash_bytes(bytes));
    let raw = serde_json::to_vec_pretty(&json).unwrap();
    fs::write(&path, &raw).unwrap();
    fs::write(capsule.join("capsule.sha256"), Capsule::hash_bytes(&raw)).unwrap();
}

#[test]
fn the_capsule_records_the_verifiers_own_run_beside_the_builders_and_notes_a_different_output() {
    if !sandbox_available() {
        return;
    }
    let lane = verifier_lane();
    let run = run_expecting(&lane, &[], 0);
    // A note is not a failure: the lane is proved.
    assert_eq!(lane.verdict()["verdict"], "proved");

    // `stable`: both runs print `same\n`. The verifier's record has its own exit, end, a
    // duration over zero and the hash and length of its own output.
    let stable = check_record(&lane, "stable");
    let verifier = &stable["verifier"];
    assert_eq!(verifier["exit_status"], 0, "{stable}");
    assert_eq!(
        verifier["end"],
        json!({"kind": "exited", "code": 0}),
        "{stable}"
    );
    assert!(verifier["duration_ms"].as_u64().unwrap() > 0, "{stable}");
    assert_eq!(verifier["output_sha256"], sha256_hex(b"same\n"), "{stable}");
    assert_eq!(verifier["output_len"], 5, "{stable}");
    // The builder's fields are as they were.
    assert_eq!(stable["output_sha256"], sha256_hex(b"same\n"), "{stable}");
    assert_eq!(stable["attempts"], 1, "{stable}");
    assert_eq!(
        stable["end"],
        json!({"kind": "exited", "code": 0}),
        "{stable}"
    );

    // `rand`: two different outputs, both recorded, neither the other's.
    let rand = check_record(&lane, "rand");
    let (builder_hash, verifier_hash) = (
        rand["output_sha256"].as_str().unwrap(),
        rand["verifier"]["output_sha256"].as_str().unwrap(),
    );
    assert_eq!(builder_hash.len(), 64, "{rand}");
    assert_eq!(verifier_hash.len(), 64, "{rand}");
    assert_ne!(builder_hash, verifier_hash, "{rand}");
    assert!(
        rand["verifier"]["output_len"].as_u64().unwrap() > 0,
        "{rand}"
    );
    assert!(
        rand["verifier"]["duration_ms"].as_u64().unwrap() > 0,
        "{rand}"
    );

    // The record is sealed: the capsule reads, and `cowproof run` named the note for `rand`
    // only, after its verdict line.
    Capsule::read(&lane.capsule_dir()).expect("the capsule is sealed over the verifier's record");
    let said = stdout(&run);
    assert!(
        said.contains("check \"rand\": the verifier's output is not byte-identical"),
        "{said}"
    );
    assert!(!said.contains("check \"stable\""), "{said}");

    // `cowproof verify` is a third run: it compares pass or fail with the builder's record,
    // reproduces, and prints the same note for `rand` and none for `stable`.
    let out = replay(&lane);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let said = stdout(&out);
    assert!(said.starts_with("reproduced\n"), "{said}");
    assert!(
        said.contains("note: check \"rand\": the verifier's output is not byte-identical"),
        "{said}"
    );
    assert!(!said.contains("\"stable\""), "{said}");
}

#[test]
fn a_lane_whose_outputs_agree_prints_no_note() {
    if !sandbox_available() {
        return;
    }
    let lane = Lane::new(
        &run_checks(&["stable"]),
        json!([{"id": "stable", "command": "echo same"}]),
    );
    let run = run_expecting(&lane, &[], 0);
    assert!(!stdout(&run).contains("byte-identical"), "{}", stdout(&run));
    let out = replay(&lane);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert_eq!(stdout(&out).trim(), "reproduced");
}

#[test]
fn editing_the_verifiers_record_fails_verify() {
    if !sandbox_available() {
        return;
    }
    let lane = verifier_lane();
    run_expecting(&lane, &[], 0);
    let path = lane.capsule_dir().join("checks/stable.json");
    let original = fs::read(&path).unwrap();
    for (field, value) in [
        ("duration_ms", json!(1)),
        ("output_len", json!(99)),
        ("output_sha256", json!(sha256_hex(b"something else"))),
        ("exit_status", json!(1)),
    ] {
        let mut record: Value = serde_json::from_slice(&original).unwrap();
        record["verifier"][field] = value;
        fs::write(&path, serde_json::to_vec_pretty(&record).unwrap()).unwrap();
        let out = replay(&lane);
        assert_eq!(out.status.code(), Some(4), "{field}: {}", text(&out));
        let err = String::from_utf8_lossy(&out.stderr).to_string();
        assert!(
            err.contains("tampered") && err.contains("checks/stable.json"),
            "{field}: {err}"
        );
    }
    // Removing the record is an edit too.
    let mut record: Value = serde_json::from_slice(&original).unwrap();
    record.as_object_mut().unwrap().remove("verifier");
    fs::write(&path, serde_json::to_vec_pretty(&record).unwrap()).unwrap();
    let out = replay(&lane);
    assert_eq!(out.status.code(), Some(4), "{}", text(&out));
    fs::write(&path, &original).unwrap();
    let out = replay(&lane);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
}

/// A capsule sealed before the verifier's runs were recorded has no `verifier` object in its
/// check files. It reads and reproduces; the builder's hash is still there, so the third run of
/// `cowproof verify` still notes the check whose output differs.
#[test]
fn a_capsule_without_the_verifiers_record_still_reproduces() {
    if !sandbox_available() {
        return;
    }
    let lane = verifier_lane();
    run_expecting(&lane, &[], 0);
    let capsule = lane.capsule_dir();
    for id in ["stable", "rand"] {
        let mut record = check_record(&lane, id);
        assert!(record.as_object_mut().unwrap().remove("verifier").is_some());
        reseal(
            &capsule,
            &format!("checks/{id}.json"),
            &serde_json::to_vec_pretty(&record).unwrap(),
        );
    }
    assert!(check_record(&lane, "stable").get("verifier").is_none());
    Capsule::read(&capsule).expect("a capsule without the verifier's record reads");
    let out = replay(&lane);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let said = stdout(&out);
    assert!(said.starts_with("reproduced\n"), "{said}");
    assert!(said.contains("note: check \"rand\""), "{said}");
    assert!(!said.contains("\"stable\""), "{said}");
}
