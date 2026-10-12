//! `cowproof verify <capsule>` and held-out checks, end to end: a real `cowproof run`
//! against a FAKE `claude` makes the capsule, and the verifier replays it. Needs the
//! sandbox like `tests/run.rs` (skipped without it, a failure under
//! `COWPROOF_REQUIRE_SANDBOX=1`).

mod common;

use common::{Lane, output, run_checks, sandbox_available, text, var_tmp};
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
