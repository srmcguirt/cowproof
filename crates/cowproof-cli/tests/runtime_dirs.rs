//! `--runtime-dir` and `COWPROOF_RUNTIME_DIRS`: the director's reference runtimes (nvm, pyenv,
//! Homebrew) granted to the verifier and to the builder's `run_check`, read-only, with their
//! `bin` on `PATH`. A real `cowproof run` against a FAKE `claude`; the runtimes are fake
//! scripts under the lane's own `HOME`, which the sandbox hides, so a check can only find one
//! if the grant did its job. The held-out side is in `port_packets.rs`.
//!
//! Needs the sandbox like `tests/run.rs` where a test runs a check (skipped without it, a
//! failure under `COWPROOF_REQUIRE_SANDBOX=1`); the refusal tests need none, because every
//! refusal happens before the lane, the slots and the sandbox exist.

mod common;

use common::{Lane, fork_lock, run_checks, sandbox_available, text};
use cowproof_prove::Capsule;
use serde_json::{Value, json};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// A fake runtime at `dir`: `bin/<program>` prints `says`, and `lib/<data>` holds `content`.
fn runtime(dir: &Path, program: &str, says: &str, data: &str, content: &str) -> PathBuf {
    fs::create_dir_all(dir.join("bin")).unwrap();
    fs::create_dir_all(dir.join("lib")).unwrap();
    fs::write(dir.join("lib").join(data), content).unwrap();
    let _g = fork_lock();
    let exe = dir.join("bin").join(program);
    fs::write(&exe, format!("#!/bin/sh\necho {says}\n")).unwrap();
    fs::set_permissions(&exe, fs::Permissions::from_mode(0o755)).unwrap();
    dir.canonicalize().unwrap()
}

/// The checks of the lane: each finds the runtime by where its program is on `PATH`, so they
/// do not need to know where the test put it. `ro` writes to both runtimes and expects every
/// write to fail, after a control write that must work.
fn checks() -> Value {
    let find =
        |program: &str| format!("$(cd \"$(dirname \"$(command -v {program})\")/..\" && pwd)");
    let (a, b) = (find("fakenode"), find("fakepy"));
    json!([
        {"id": "edit", "command": "grep -q edited README.md"},
        {"id": "run", "command": "test \"$(fakenode --version)\" = v22.3.0 && test \"$(fakepy)\" = py-three"},
        {"id": "read", "command": format!(
            "grep -q runtime-data {a}/lib/data.txt && grep -q more-data {b}/lib/more.txt")},
        {"id": "ro", "command": format!(
            "echo ok >> created.txt && A={a} && B={b} && grep -q runtime-data \"$A/lib/data.txt\" \
             && ! (echo x >> \"$A/lib/data.txt\") 2>/dev/null \
             && ! (echo x > \"$A/lib/new\") 2>/dev/null \
             && ! (echo x > \"$A/bin/fakenode\") 2>/dev/null \
             && ! (echo x > \"$B/lib/new\") 2>/dev/null \
             && ! mv \"$A/lib/data.txt\" \"$A/lib/moved\" 2>/dev/null \
             && ! rm \"$B/lib/more.txt\" 2>/dev/null")},
    ])
}

fn lane() -> Lane {
    Lane::new(&run_checks(&["edit", "run", "read", "ro"]), checks())
}

/// The two fake runtimes under the lane's hidden `HOME`.
fn runtimes(lane: &Lane) -> (PathBuf, PathBuf) {
    let home = lane.home.path();
    (
        runtime(
            &home.join(".nvm/versions/node/v22"),
            "fakenode",
            "v22.3.0",
            "data.txt",
            "runtime-data",
        ),
        runtime(
            &home.join("pyenv/3.12"),
            "fakepy",
            "py-three",
            "more.txt",
            "more-data",
        ),
    )
}

fn run_json(lane: &Lane) -> Value {
    let path = lane.lane_dir().join("control/run.json");
    serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap()
}

#[test]
fn a_runtime_from_a_flag_and_one_from_the_environment_run_in_run_check_and_the_verifier() {
    if !sandbox_available() {
        return;
    }
    let mut lane = lane();
    let (node, py) = runtimes(&lane);
    lane.set_env("COWPROOF_RUNTIME_DIRS", py.as_os_str());
    let out = lane.run(&[Path::new("--runtime-dir"), &node]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));

    // Every check passed in the builder's sandbox, and the verifier's rerun agreed: proved.
    let verdict = lane.verdict();
    assert_eq!(verdict["verdict"], "proved", "{verdict}");
    assert_eq!(verdict["failedChecks"], json!([]), "{verdict}");

    // The read-only grant held: nothing was written, renamed or removed on the host.
    assert_eq!(
        fs::read_to_string(node.join("lib/data.txt")).unwrap(),
        "runtime-data"
    );
    assert_eq!(
        fs::read_to_string(py.join("lib/more.txt")).unwrap(),
        "more-data"
    );
    for gone in [
        node.join("lib/new"),
        node.join("lib/moved"),
        py.join("lib/new"),
    ] {
        assert!(!gone.exists(), "{} was created", gone.display());
    }

    // What the proof saw is recorded: flags first, then the environment.
    let named = json!([node.to_str().unwrap(), py.to_str().unwrap()]);
    assert_eq!(run_json(&lane)["runtimeDirs"], named);
    let capsule = Capsule::read(&lane.capsule_dir()).unwrap();
    assert_eq!(
        capsule.runtime_dirs,
        [node.to_str().unwrap(), py.to_str().unwrap()]
    );
    let sealed = fs::read_to_string(lane.capsule_dir().join("capsule.json")).unwrap();
    assert!(sealed.contains("\"runtime_dirs\""), "{sealed}");

    // `cowproof verify` of that capsule needs the same directories again.
    let verify = |extra: &[&Path]| {
        let mut cmd = lane.cowproof_cmd();
        cmd.arg("verify")
            .arg(lane.capsule_dir())
            .arg("--repo")
            .arg(&lane.repo)
            .args(extra)
            .env_remove("COWPROOF_RUNTIME_DIRS");
        common::output(&mut cmd)
    };
    let with = verify(&[
        Path::new("--runtime-dir"),
        &node,
        Path::new("--runtime-dir"),
        &py,
    ]);
    assert_eq!(with.status.code(), Some(0), "{}", text(&with));
    assert!(text(&with).contains("reproduced"), "{}", text(&with));
    let without = verify(&[]);
    assert_eq!(without.status.code(), Some(2), "{}", text(&without));
    assert!(text(&without).contains("diverged"), "{}", text(&without));
}

#[test]
fn control_without_the_grant_the_hidden_runtime_is_not_found() {
    if !sandbox_available() {
        return;
    }
    let lane = lane();
    runtimes(&lane);
    let out = lane.run(&[]);
    assert_ne!(out.status.code(), Some(0), "{}", text(&out));
    let verdict = lane.verdict();
    assert_ne!(verdict["verdict"], "proved", "{verdict}");
    let failed = verdict["failedChecks"].to_string();
    for id in ["run", "read", "ro"] {
        assert!(failed.contains(id), "{id} should have failed\n{verdict}");
    }
    assert!(!failed.contains("edit"), "{verdict}");
    assert_eq!(run_json(&lane)["runtimeDirs"], json!([]));
    let capsule = Capsule::read(&lane.capsule_dir()).unwrap();
    assert!(capsule.runtime_dirs.is_empty());
    let sealed = fs::read_to_string(lane.capsule_dir().join("capsule.json")).unwrap();
    assert!(!sealed.contains("runtime_dirs"), "{sealed}");
}

/// Every refusal is an error before the lane exists: exit 4, a message naming the directory,
/// no lane directory and nothing in the lanes root.
#[test]
fn a_refused_directory_stops_the_run_before_any_lane_exists() {
    let lane = Lane::new("true\n", json!([{"id": "edit", "command": "true"}]));
    let home = lane.home.path().to_path_buf();
    let scratch = common::var_tmp("cp-rt-refuse-");
    let with_ssh = runtime(&scratch.path().join("holds-ssh"), "tool", "x", "d", "d");
    fs::create_dir_all(with_ssh.join(".ssh")).unwrap();
    let named_config = scratch.path().join("named/.config");
    let named_config = runtime(&named_config, "tool", "x", "d", "d");
    let cargo = runtime(&scratch.path().join("cargo-holder"), "tool", "x", "d", "d");
    fs::create_dir_all(cargo.join(".cargo")).unwrap();
    fs::write(cargo.join(".cargo/credentials.toml"), "x").unwrap();
    let file = scratch.path().join("a-file");
    fs::write(&file, "x").unwrap();
    let lanes_root = lane.lanes.path().to_path_buf();
    fs::create_dir_all(home.join(".cache/cowproof/bin")).unwrap();
    let cases: Vec<(PathBuf, &str)> = vec![
        (PathBuf::from("/"), "filesystem root"),
        (home.clone(), "home directory"),
        (home.parent().unwrap().to_path_buf(), "home directory"),
        (with_ssh, "credential location (.ssh)"),
        (named_config, "credential location (.config)"),
        (cargo, "credential location (.cargo/credentials*)"),
        (lanes_root, "the lanes root"),
        (lane.repo.clone(), "the repository"),
        (home.join(".cache/cowproof"), "the cowproof cache"),
        (PathBuf::from("relative/rt"), "not an absolute path"),
        (scratch.path().join("missing"), "cannot be resolved"),
        (file, "not a directory"),
    ];
    for (dir, why) in &cases {
        let out = lane.run(&[Path::new("--runtime-dir"), dir]);
        let shown = text(&out);
        assert_eq!(out.status.code(), Some(4), "{}: {shown}", dir.display());
        assert!(shown.contains("runtime directory refused"), "{shown}");
        assert!(shown.contains(why), "{}: {shown}", dir.display());
        assert!(shown.contains("nothing was started"), "{shown}");
        assert!(!lane.lane_dir().exists(), "a lane was created");
        let left: Vec<_> = fs::read_dir(lane.lanes.path()).unwrap().collect();
        assert!(left.is_empty(), "the lanes root holds {left:?}");
    }

    // The environment variable is held to the same rules, and an empty entry is an error.
    let mut env_lane = Lane::new("true\n", json!([{"id": "edit", "command": "true"}]));
    env_lane.set_env("COWPROOF_RUNTIME_DIRS", "/");
    let out = env_lane.run(&[]);
    assert_eq!(out.status.code(), Some(4), "{}", text(&out));
    assert!(text(&out).contains("filesystem root"), "{}", text(&out));
    env_lane.set_env("COWPROOF_RUNTIME_DIRS", "/usr/bin::/bin");
    let out = env_lane.run(&[]);
    assert_eq!(out.status.code(), Some(4), "{}", text(&out));
    assert!(text(&out).contains("empty entry"), "{}", text(&out));
    assert!(!env_lane.lane_dir().exists());
}

/// A refused directory also stops `cowproof verify`, before it makes a workdir.
#[test]
fn verify_refuses_the_same_directories_before_it_builds_anything() {
    let lane = Lane::new("true\n", json!([{"id": "edit", "command": "true"}]));
    let capsule = lane.home.path().join("not-a-capsule-yet");
    fs::create_dir_all(&capsule).unwrap();
    let home = lane.home.path().to_path_buf();
    for (dir, why) in [
        (PathBuf::from("/"), "filesystem root"),
        (home.clone(), "home directory"),
        (lane.repo.clone(), "the repository"),
        (capsule.clone(), "the capsule"),
    ] {
        let mut cmd = lane.cowproof_cmd();
        cmd.arg("verify")
            .arg(&capsule)
            .arg("--repo")
            .arg(&lane.repo)
            .arg("--runtime-dir")
            .arg(&dir);
        let out = common::output(&mut cmd);
        let shown = text(&out);
        assert_eq!(out.status.code(), Some(4), "{}: {shown}", dir.display());
        assert!(shown.contains("refused:"), "{shown}");
        assert!(shown.contains(why), "{}: {shown}", dir.display());
        assert!(shown.contains("nothing was started"), "{shown}");
        assert!(
            !home.join(".cache/cowproof/verify").exists(),
            "a workdir was made"
        );
    }
}
