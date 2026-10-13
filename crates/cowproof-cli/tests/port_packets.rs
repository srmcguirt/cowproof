//! `kind: port` packets, end to end (portkit-integration.md, sections 3d, 3e and 6.4): a real
//! `cowproof run` against a FAKE `claude` that plays the builder, a real `rustc` for the Rust
//! tool it writes, and portkit's real replay in the verifier's sandbox. No network, no model.
//!
//! The project is the committed fixture under `fixtures/port/`: a shell reference
//! (`reference/text.sh`) with two tools, `upper` and `shout`, visible fixtures recorded from it,
//! and the director's held-out cases beside the project, outside the repository. The fake
//! builder writes `tools/text.rs` and registers the tools in `.portkit/plugins.toml`. Controls
//! keep the tests from being vacuous: a correct port proves, and each defect is caught by the
//! gate meant for it and no other.
//!
//! Needs the sandbox like `tests/run.rs` (skipped without it, a failure under
//! `COWPROOF_REQUIRE_SANDBOX=1`). The fixture lives at the repository root (`fixtures/port/`),
//! outside the published crate, so the tests that use it run in the workspace only (see
//! `common/workspace.rs`); the README test reads the README the crate packages.

mod common;
#[path = "common/workspace.rs"]
mod workspace;

use common::{Lane, copy_tree, run_checks, sandbox_available, text, var_tmp};
use cowproof_prove::Capsule;
use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Output;

/// The id the committed packet carries; each lane swaps in a unique one.
const PACKET_ID: &str = "port-1";

fn fixture() -> PathBuf {
    // Canonical: `--heldout` refuses a path with `..` in it.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/port")
        .canonicalize()
        .unwrap()
}

fn heldout() -> PathBuf {
    fixture().join("heldout/heldout.toml")
}

/// The committed packet text for the lane `id`, with `edit` applied to it.
fn packet(id: &str, edit: &dyn Fn(String) -> String) -> String {
    let text = fs::read_to_string(fixture().join("packet.md")).unwrap();
    assert!(text.contains(&format!("\"id\":\"{PACKET_ID}\"")));
    edit(text.replace(
        &format!("\"id\":\"{PACKET_ID}\""),
        &format!("\"id\":\"{id}\""),
    ))
}

/// The Rust program the honest builder writes. `{SHOUT}` is what `shout` appends.
const TEXT_RS: &str = r#"use std::io::Read;

fn field<'a>(json: &'a str, key: &str) -> Option<&'a str> {
    let marker = format!("\"{key}\":\"");
    let start = json.find(&marker)? + marker.len();
    let end = json[start..].find('"')? + start;
    Some(&json[start..end])
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let tool = args.get(1).map(String::as_str).unwrap_or("upper");
    if args.iter().any(|a| a == "--portkit-spec") {
        println!("{{\"name\":\"{tool}\",\"description\":\"text tool\",\"input_schema\":{{\"type\":\"object\"}}}}");
        return;
    }
    let mut request = String::new();
    std::io::stdin().read_to_string(&mut request).unwrap();
    let text = field(&request, "text").unwrap_or("");
    let upper = text.to_uppercase();
    let result = if tool == "shout" { format!("{upper}{SHOUT}") } else { upper };
    println!("{{\"result\":\"{result}\"}}");
}
"#;

/// The cheat: the visible inputs are matched, everything else is echoed unchanged.
const HARD_CODED_RS: &str = r#"use std::io::Read;

fn field<'a>(json: &'a str, key: &str) -> Option<&'a str> {
    let marker = format!("\"{key}\":\"");
    let start = json.find(&marker)? + marker.len();
    let end = json[start..].find('"')? + start;
    Some(&json[start..end])
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let tool = args.get(1).map(String::as_str).unwrap_or("upper");
    if args.iter().any(|a| a == "--portkit-spec") {
        println!("{{\"name\":\"{tool}\",\"description\":\"text tool\",\"input_schema\":{{\"type\":\"object\"}}}}");
        return;
    }
    let mut request = String::new();
    std::io::stdin().read_to_string(&mut request).unwrap();
    let text = field(&request, "text").unwrap_or("");
    let result = match (tool, text) {
        ("upper", "hello") => "HELLO",
        ("upper", "Rust 2024") => "RUST 2024",
        ("shout", "hi there") => "HI THERE!",
        _ => text,
    };
    println!("{{\"result\":\"{result}\"}}");
}
"#;

fn manifest(tools: &[&str]) -> String {
    tools
        .iter()
        .map(|tool| format!("[[plugin]]\ncommand = \"target/text\"\nargs = [\"{tool}\"]\n"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Shell for a builder that writes `source` as `tools/text.rs`, registers `tools`, and runs
/// the packet's one check as any builder does before it finishes.
fn builder(source: &str, tools: &[&str], more: &str) -> String {
    format!(
        "cat > tools/text.rs <<'RUST'\n{source}RUST\ncat > .portkit/plugins.toml <<'TOML'\n{}TOML\n{more}\n{}",
        manifest(tools),
        run_checks(&["build"]),
    )
}

fn honest() -> String {
    builder(&TEXT_RS.replace("{SHOUT}", "!"), &["upper", "shout"], "")
}

fn lane(body: &str) -> Lane {
    lane_with(body, &|t| t)
}

fn lane_with(body: &str, edit: &'static dyn Fn(String) -> String) -> Lane {
    Lane::from_project(body, &fixture().join("project"), &move |id| {
        packet(id, edit)
    })
}

fn run(lane: &Lane) -> Output {
    let heldout = heldout();
    lane.run(&[Path::new("--heldout"), &heldout])
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

fn failed(gates: &[Value]) -> Vec<String> {
    gates
        .iter()
        .filter(|g| g["passed"] == false)
        .map(|g| g["name"].as_str().unwrap().to_string())
        .collect()
}

#[test]
fn the_committed_packet_lints_clean_against_the_committed_project() {
    if workspace::skipped("the_committed_packet_lints_clean_against_the_committed_project") {
        return;
    }
    // The lint rules read the same files the proof does; no sandbox needed.
    let lane = lane("true");
    let out = lane
        .cowproof_cmd()
        .args(["lint", "--repo"])
        .arg(&lane.repo)
        .arg(&lane.packet)
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", text(&out));
    // The director's held-out cases are not in the repository the builder gets.
    assert!(!fixture().join("project/heldout.toml").exists());
    assert!(!fixture().join("project/heldout.cases.jsonl").exists());
}

#[test]
fn a_correct_port_is_proved_and_the_capsule_records_the_replay() {
    if workspace::skipped("a_correct_port_is_proved_and_the_capsule_records_the_replay") {
        return;
    }
    if !sandbox_available() {
        return;
    }
    let lane = lane(&honest());
    let out = run(&lane);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let verdict = lane.verdict();
    assert_eq!(verdict["verdict"], "proved", "{verdict}");
    assert_eq!(verdict["failedGates"], json!([]), "{verdict}");
    assert_eq!(verdict["heldOutFailed"], json!([]), "{verdict}");

    // gates.json: the port gate passed, and the held-out gate says what ran.
    let gates = gates(&lane);
    assert_eq!(failed(&gates), Vec::<String>::new(), "{gates:?}");
    let port = gate(&gates, "port_replay");
    assert_eq!(port["passed"], true, "{port}");
    assert!(port["evidence"].to_string().contains("3 fixture"), "{port}");
    let held = gate(&gates, "held_out");
    assert_eq!(held["warned"], false, "{held}");
    let evidence = held["evidence"].to_string();
    assert!(
        evidence.contains("Held-out port cases present"),
        "{evidence}"
    );
    assert!(
        evidence.contains("2 captured against the reference, all passed"),
        "{evidence}"
    );

    // The capsule entry (section 3e): reference command, source commit, fixture-set hash and
    // the trimmed per-surface report, sealed, and the held-out cases hashed in packets/.
    let capsule = Capsule::read(&lane.capsule_dir()).unwrap();
    let port = capsule.port.expect("a port capsule");
    assert_eq!(port.reference.as_ref().unwrap().cmd, "sh reference/text.sh");
    assert_eq!(port.tools, ["upper", "shout"]);
    assert_eq!(port.epsilon, 0.0);
    let result = port.result.expect("the replay is recorded");
    assert!(result.success, "{:?}", result.failures);
    assert_eq!(result.source_commit, capsule.base_commit);
    assert_eq!(result.fixture_count, 3);
    assert_eq!(result.fixture_hash.len(), 64);
    // The honest builder leaves the fixtures as the director committed them, so the recorded
    // hash is the hash of the directory in the repository the lane started from.
    let (committed, files) =
        cowproof_prove::fixture_set_hash(&lane.repo.join("ports/upper/fixtures")).unwrap();
    assert_eq!(
        (result.fixture_hash.as_str(), result.fixture_count),
        (committed.as_str(), files)
    );
    let surfaces: Vec<&str> = result.surfaces.keys().map(String::as_str).collect();
    assert_eq!(surfaces, ["direct", "mcp"]);
    assert_eq!(result.surfaces["direct"].passed, 3);
    assert!(result.surfaces["direct"].outcomes.is_empty());
    assert_eq!(result.held_out.state, "passed");
    assert_eq!(result.held_out.cases, 2);
    assert!(
        capsule
            .file_hashes
            .contains_key("packets/heldout.cases.jsonl")
    );

    // A second machine replays it: `cowproof verify` rebuilds the tree and runs the replay.
    let verify = lane
        .cowproof_cmd()
        .arg("verify")
        .arg(lane.capsule_dir())
        .arg("--repo")
        .arg(&lane.repo)
        .output()
        .unwrap();
    assert_eq!(verify.status.code(), Some(0), "{}", text(&verify));
    assert!(stdout(&verify).contains("reproduced"), "{}", text(&verify));
}

#[test]
fn one_wrong_output_is_refuted_by_port_replay_naming_the_surface() {
    if workspace::skipped("one_wrong_output_is_refuted_by_port_replay_naming_the_surface") {
        return;
    }
    if !sandbox_available() {
        return;
    }
    // `shout` forgets the `!`: the build check passes, the visible fixture shout/hi differs.
    let lane = lane(&builder(
        &TEXT_RS.replace("{SHOUT}", ""),
        &["upper", "shout"],
        "",
    ));
    let out = run(&lane);
    assert_eq!(out.status.code(), Some(2), "{}", text(&out));
    let verdict = lane.verdict();
    assert_eq!(verdict["verdict"], "refuted", "{verdict}");
    assert_eq!(verdict["failedChecks"], json!([]), "{verdict}");
    assert_eq!(verdict["failedGates"], json!(["port_replay"]), "{verdict}");

    let gates = gates(&lane);
    assert_eq!(failed(&gates), vec!["held_out", "port_replay"], "{gates:?}");
    let evidence = gate(&gates, "port_replay")["evidence"].to_string();
    assert!(
        evidence.contains("direct shout/hi: differs from the reference at \\\"/result\\\""),
        "{evidence}"
    );
    assert!(evidence.contains("mcp shout/hi: differs"), "{evidence}");
    // Nothing else fails: the upper tool is right on both surfaces.
    assert!(!evidence.contains("upper/"), "{evidence}");

    // The capsule keeps only the failing outcome, with its difference.
    let capsule = Capsule::read(&lane.capsule_dir()).unwrap();
    let result = capsule.port.unwrap().result.unwrap();
    assert!(!result.success);
    let direct = &result.surfaces["direct"];
    assert_eq!((direct.passed, direct.failed), (2, 1));
    assert_eq!(direct.outcomes.len(), 1);
    assert_eq!(direct.outcomes[0].id, "hi");

    let report = stdout(&out);
    assert!(report.contains("gate port_replay failed"), "{report}");
}

#[test]
fn a_tool_missing_from_the_registry_is_refuted_with_not_ported() {
    if workspace::skipped("a_tool_missing_from_the_registry_is_refuted_with_not_ported") {
        return;
    }
    if !sandbox_available() {
        return;
    }
    // Only `upper` is registered: no tool answers the shout fixture.
    let lane = lane(&builder(&TEXT_RS.replace("{SHOUT}", "!"), &["upper"], ""));
    let out = run(&lane);
    assert_eq!(out.status.code(), Some(2), "{}", text(&out));
    let verdict = lane.verdict();
    assert_eq!(verdict["verdict"], "refuted", "{verdict}");
    assert_eq!(verdict["failedGates"], json!(["port_replay"]), "{verdict}");
    let gates = gates(&lane);
    let evidence = gate(&gates, "port_replay")["evidence"].to_string();
    assert!(
        evidence.contains("direct shout/hi: not ported (no tool answers it)"),
        "{evidence}"
    );
    assert!(
        evidence.contains("1 fixture(s) are not ported"),
        "{evidence}"
    );
    let capsule = Capsule::read(&lane.capsule_dir()).unwrap();
    let result = capsule.port.unwrap().result.unwrap();
    assert_eq!(result.surfaces["mcp"].not_ported, 1);
}

#[test]
fn control_a_port_that_matches_only_the_visible_fixtures_fails_the_held_out_cases() {
    if workspace::skipped(
        "control_a_port_that_matches_only_the_visible_fixtures_fails_the_held_out_cases",
    ) {
        return;
    }
    if !sandbox_available() {
        return;
    }
    // The visible replay is green on both surfaces; the cases only the director holds are not.
    let lane = lane(&builder(HARD_CODED_RS, &["upper", "shout"], ""));
    let out = run(&lane);
    assert_eq!(out.status.code(), Some(2), "{}", text(&out));
    let verdict = lane.verdict();
    assert_eq!(verdict["verdict"], "refuted", "{verdict}");
    assert_eq!(verdict["failedGates"], json!(["port_replay"]), "{verdict}");

    let capsule = Capsule::read(&lane.capsule_dir()).unwrap();
    let result = capsule.port.unwrap().result.unwrap();
    assert_eq!(
        result.surfaces["direct"].failed, 0,
        "visible replay is green"
    );
    assert_eq!(result.held_out.state, "failed");
    let reason = result.held_out.reason.unwrap();
    assert!(reason.contains("held-out direct upper/digits"), "{reason}");

    // gates.json alone tells the truth: the held-out gate failed, and says which case.
    let gates = gates(&lane);
    assert_eq!(failed(&gates), vec!["held_out", "port_replay"], "{gates:?}");
    let held = gate(&gates, "held_out")["evidence"].to_string();
    assert!(held.contains("held-out port cases: failed"), "{held}");
}

#[test]
fn a_verifier_without_the_reference_runtime_reports_held_out_skipped() {
    if workspace::skipped("a_verifier_without_the_reference_runtime_reports_held_out_skipped") {
        return;
    }
    if !sandbox_available() {
        return;
    }
    // The reference needs a runtime nobody has: the held-out cases cannot be captured. The
    // lane is still proved on the visible fixtures, and the skip is said, not hidden.
    let lane = lane_with(&honest(), &|t| {
        t.replace(
            "\"runtime\":\"sh\"",
            "\"runtime\":\"no-such-runtime-cowproof>=1\"",
        )
    });
    let out = run(&lane);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert_eq!(lane.verdict()["verdict"], "proved");
    let report = stdout(&out);
    assert!(
        report
            .contains("held-out: skipped (the verifier's sandbox has no no-such-runtime-cowproof"),
        "{report}"
    );
    let gates = gates(&lane);
    let held = gate(&gates, "held_out");
    assert_eq!(held["passed"], true, "{held}");
    assert_eq!(held["warned"], true, "{held}");
    assert!(
        held["evidence"].to_string().contains("held-out: skipped"),
        "{held}"
    );
    let capsule = Capsule::read(&lane.capsule_dir()).unwrap();
    let result = capsule.port.unwrap().result.unwrap();
    assert_eq!(result.held_out.state, "skipped");
    assert_eq!(result.held_out.cases, 0);
}

/// A reference runtime the director installed under its (hidden) home, with a version
/// minimum: `fakenode --version` is what the verifier probes, so the fake must really run.
fn fake_node(lane: &Lane) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let dir = lane.home.path().join(".nvm/versions/node/v22");
    fs::create_dir_all(dir.join("bin")).unwrap();
    let _g = common::fork_lock();
    let exe = dir.join("bin/fakenode");
    fs::write(&exe, "#!/bin/sh\necho v22.3.0\n").unwrap();
    fs::set_permissions(&exe, fs::Permissions::from_mode(0o755)).unwrap();
    dir.canonicalize().unwrap()
}

#[test]
fn a_runtime_dir_makes_a_held_out_case_run_instead_of_being_skipped() {
    if workspace::skipped("a_runtime_dir_makes_a_held_out_case_run_instead_of_being_skipped") {
        return;
    }
    if !sandbox_available() {
        return;
    }
    let lane = lane_with(&honest(), &|t| {
        t.replace("\"runtime\":\"sh\"", "\"runtime\":\"fakenode>=22\"")
    });
    let node = fake_node(&lane);
    let heldout = heldout();
    let out = lane.run(&[
        Path::new("--heldout"),
        &heldout,
        Path::new("--runtime-dir"),
        &node,
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert_eq!(lane.verdict()["verdict"], "proved");
    let report = stdout(&out);
    assert!(!report.contains("held-out: skipped"), "{report}");
    // The held-out cases were captured against the reference and replayed, not skipped.
    let capsule = Capsule::read(&lane.capsule_dir()).unwrap();
    assert_eq!(capsule.runtime_dirs, [node.to_str().unwrap()]);
    let held = capsule.port.as_ref().unwrap().result.as_ref().unwrap();
    assert_eq!(held.held_out.state, "passed", "{:?}", held.held_out);
    assert_eq!(held.held_out.cases, 2);

    let verify = |envs: &[(&str, &Path)], args: &[&Path]| {
        let mut cmd = lane.cowproof_cmd();
        cmd.arg("verify")
            .arg(lane.capsule_dir())
            .arg("--repo")
            .arg(&lane.repo)
            .args(args)
            .env_remove("COWPROOF_RUNTIME_DIRS");
        for (k, v) in envs {
            cmd.env(k, v);
        }
        common::output(&mut cmd)
    };
    // The same directory again, by flag or by environment: replayed, nothing skipped.
    for out in [
        verify(&[], &[Path::new("--runtime-dir"), &node]),
        verify(&[("COWPROOF_RUNTIME_DIRS", &node)], &[]),
    ] {
        assert_eq!(out.status.code(), Some(0), "{}", text(&out));
        assert!(stdout(&out).contains("reproduced"), "{}", text(&out));
        assert!(
            !stdout(&out).contains("held-out: skipped"),
            "{}",
            text(&out)
        );
    }
    // Without it the held-out cases are skipped exactly as before, and the message names the
    // capsule's list and what to pass.
    let out = verify(&[], &[]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let report = stdout(&out);
    assert!(
        report.contains("held-out: skipped (the verifier's sandbox has no fakenode"),
        "{report}"
    );
    assert!(
        report.contains(&format!(
            "the capsule's proof was made with the runtime directory {}",
            node.display()
        )),
        "{report}"
    );
    assert!(
        report.contains("--runtime-dir <dir> or set COWPROOF_RUNTIME_DIRS"),
        "{report}"
    );
}

/// The held-out port cases need a runtime nobody has, so the verifier skips them. The base
/// commit's `cowproof.toml` is the fixture's, with `require_heldout = <value>` added under its
/// `[proof]` table when `setting` is given.
fn skipped_heldout_lane(setting: Option<bool>) -> Lane {
    let project = var_tmp("cp-port-project-");
    copy_tree(&fixture().join("project"), project.path());
    let config = project.path().join("cowproof.toml");
    let text = fs::read_to_string(&config).unwrap();
    assert!(text.contains("[proof]\n"));
    if let Some(value) = setting {
        let line = format!("[proof]\nrequire_heldout = {value}\n");
        fs::write(&config, text.replace("[proof]\n", &line)).unwrap();
    }
    // `from_project` copies and commits the tree before it returns; `project` can go after.
    Lane::from_project(&honest(), project.path(), &|id| {
        packet(id, &|t| {
            t.replace(
                "\"runtime\":\"sh\"",
                "\"runtime\":\"no-such-runtime-cowproof>=1\"",
            )
        })
    })
}

#[test]
fn require_heldout_refuses_a_port_lane_whose_held_out_cases_were_skipped() {
    if workspace::skipped("require_heldout_refuses_a_port_lane_whose_held_out_cases_were_skipped") {
        return;
    }
    if !sandbox_available() {
        return;
    }
    let lane = skipped_heldout_lane(Some(true));
    let out = run(&lane);
    assert_eq!(out.status.code(), Some(2), "{}", text(&out));
    let verdict = lane.verdict();
    assert_eq!(verdict["verdict"], "refuted", "{verdict}");
    assert_eq!(verdict["failedGates"], json!(["held_out"]), "{verdict}");
    let report = stdout(&out);
    assert!(
        report
            .contains("held-out: skipped (the verifier's sandbox has no no-such-runtime-cowproof"),
        "{report}"
    );
    assert!(report.contains("require_heldout"), "{report}");

    // gates.json alone tells the truth: the held-out gate failed and names the skip.
    let gates = gates(&lane);
    assert_eq!(failed(&gates), vec!["held_out"], "{gates:?}");
    let held = gate(&gates, "held_out");
    assert_eq!(held["warned"], false, "{held}");
    let evidence = held["evidence"].to_string();
    assert!(evidence.contains("held-out: skipped"), "{evidence}");
    assert!(evidence.contains("require_heldout"), "{evidence}");
    // The port itself replayed green: only the setting refuses it.
    assert_eq!(gate(&gates, "port_replay")["passed"], true);
    let capsule = Capsule::read(&lane.capsule_dir()).unwrap();
    assert_eq!(
        capsule.port.unwrap().result.unwrap().held_out.state,
        "skipped"
    );
}

#[test]
fn without_require_heldout_the_same_skip_is_only_a_warning() {
    if workspace::skipped("without_require_heldout_the_same_skip_is_only_a_warning") {
        return;
    }
    if !sandbox_available() {
        return;
    }
    // No setting, and `require_heldout = false`, behave alike; the explicit one is run here
    // and the unset case is `a_verifier_without_the_reference_runtime_reports_held_out_skipped`.
    let lane = skipped_heldout_lane(Some(false));
    let out = run(&lane);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert_eq!(lane.verdict()["verdict"], "proved");
    let gates = gates(&lane);
    assert!(failed(&gates).is_empty(), "{gates:?}");
    let held = gate(&gates, "held_out");
    assert_eq!(held["warned"], true, "{held}");
    assert!(!held["evidence"].to_string().contains("require_heldout"));
}

#[test]
fn a_changed_base_fixture_and_an_unruled_accepted_difference_are_refuted() {
    if workspace::skipped("a_changed_base_fixture_and_an_unruled_accepted_difference_are_refuted") {
        return;
    }
    if !sandbox_available() {
        return;
    }
    // The builder owns the fixtures directory, so the cheapest way to a green replay is to
    // edit what the reference said, or to accept the difference without a ruling.
    let rewrite_expected = "sed -i.bak 's/HI THERE!/HI THERE/' ports/upper/fixtures/shout/hi.json && rm ports/upper/fixtures/shout/hi.json.bak";
    let accept_unruled = r#"cat > ports/upper/fixtures/shout/hi.json <<'JSON'
{
  "tool": "shout",
  "id": "hi",
  "input": {"text": "hi there"},
  "expected": {"result": "HI THERE!"},
  "source": "sh reference/text.sh",
  "accepted": [{"path": "/result", "reason": "close enough"}]
}
JSON"#;
    for (edit, needle) in [
        (rewrite_expected, "the lane changed its \\\"expected\\\""),
        (accept_unruled, "port-accepted-unruled"),
    ] {
        let lane = lane(&builder(
            &TEXT_RS.replace("{SHOUT}", ""),
            &["upper", "shout"],
            edit,
        ));
        let out = run(&lane);
        assert_eq!(out.status.code(), Some(2), "{needle}: {}", text(&out));
        let verdict = lane.verdict();
        assert_eq!(verdict["failedGates"], json!(["port_replay"]), "{verdict}");
        let evidence = gate(&gates(&lane), "port_replay")["evidence"].to_string();
        assert!(evidence.contains(needle), "{needle}: {evidence}");
    }
}

#[test]
fn held_out_port_cases_need_a_port_packet_with_a_reference() {
    if workspace::skipped("held_out_port_cases_need_a_port_packet_with_a_reference") {
        return;
    }
    // A work packet handed a held-out file with port cases is stopped before a lane exists.
    let lane = Lane::new("true", json!([]));
    let held = heldout();
    let out = lane.run(&[Path::new("--heldout"), &held]);
    assert_ne!(out.status.code(), Some(0), "{}", text(&out));
    assert!(text(&out).contains("kind\": \"port\""), "{}", text(&out));
    assert!(!lane.lane_dir().exists());
}

#[test]
fn the_readme_example_header_is_a_valid_port_header() {
    // The documented example must parse with the strict parser, or the docs lie.
    // The workspace's README, or the copy `cargo package` puts at the crate root.
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let readme = fs::read_to_string(match workspace::root() {
        Some(root) => root.join("README.md"),
        None => manifest.join("README.md"),
    })
    .unwrap();
    let section = readme
        .split("## Port packets: `kind: port`")
        .nth(1)
        .expect("the README has a Port packets section");
    let start = section.find("<!-- lane {").expect("an example header");
    let end = section[start..].find("-->").expect("the header ends") + start + 3;
    let header = cowproof_core::parse_header(&section[start..end]).unwrap();
    assert_eq!(header.kind, cowproof_core::PacketKind::Port);
    let port = header.port.unwrap();
    assert_eq!(port.tools, ["parse_header", "glob_matches"]);
    assert_eq!(port.parity.epsilon, Some(0.0));
    assert_eq!(port.reference.unwrap().runtime.as_deref(), Some("node>=22"));
}

// ---- platform-tagged fixtures and an empty base ----

/// The two platform names fixtures are tagged with, this host's first.
fn platforms() -> (&'static str, &'static str) {
    let host = portkit_port::host_platform();
    let other = if host == "linux" { "macos" } else { "linux" };
    (host, other)
}

/// Shell that writes `ports/upper/fixtures/<tool>/<name>.json` with `doc` as its content.
fn write_fixture(tool: &str, name: &str, doc: &Value) -> String {
    format!(
        "mkdir -p ports/upper/fixtures/{tool}\ncat > 'ports/upper/fixtures/{tool}/{name}.json' <<'JSON'\n{}\nJSON\n",
        serde_json::to_string_pretty(doc).unwrap()
    )
}

#[test]
fn fixtures_tagged_for_another_platform_are_counted_and_not_replayed() {
    if workspace::skipped("fixtures_tagged_for_another_platform_are_counted_and_not_replayed") {
        return;
    }
    if !sandbox_available() {
        return;
    }
    let (host, other) = platforms();
    // A case in three versions: the committed untagged ones, one for this host (right) and one
    // for the other platform whose expectation is WRONG, so a replay that ran it would fail.
    let mut more = write_fixture(
        "upper",
        &format!("hello@{host}"),
        &json!({"tool": "upper", "id": format!("hello@{host}"), "platform": host,
                "input": {"text": "hello"}, "expected": {"result": "HELLO"}}),
    );
    more += &write_fixture(
        "upper",
        &format!("hello@{other}"),
        &json!({"tool": "upper", "id": format!("hello@{other}"), "platform": other,
                "input": {"text": "hello"}, "expected": {"result": "NOT WHAT THE PORT SAYS"}}),
    );
    let lane = lane(&builder(
        &TEXT_RS.replace("{SHOUT}", "!"),
        &["upper", "shout"],
        &more,
    ));
    let out = run(&lane);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert_eq!(lane.verdict()["verdict"], "proved");

    // The gate says so, and the other platform's fixture is in no pass count.
    let gates = gates(&lane);
    let port = gate(&gates, "port_replay");
    assert_eq!(port["passed"], true, "{port}");
    assert!(
        port["evidence"]
            .to_string()
            .contains("1 fixture(s) tagged for other platforms were not replayed"),
        "{port}"
    );
    let capsule = Capsule::read(&lane.capsule_dir()).unwrap();
    let result = capsule.port.unwrap().result.unwrap();
    assert!(result.success, "{:?}", result.failures);
    assert_eq!(result.fixture_count, 5);
    for surface in ["direct", "mcp"] {
        let s = &result.surfaces[surface];
        assert_eq!(
            (s.passed, s.failed, s.other_platform),
            (4, 0, 1),
            "{surface}"
        );
    }
}

#[test]
fn retagging_a_base_fixture_for_another_platform_cannot_skip_it() {
    if workspace::skipped("retagging_a_base_fixture_for_another_platform_cannot_skip_it") {
        return;
    }
    if !sandbox_available() {
        return;
    }
    let (host, other) = platforms();
    // The builder rewrites the only `shout` fixture as one for the other platform. Replayed on
    // this host, `shout` then has nothing: it was never proved here.
    let rewritten = write_fixture(
        "shout",
        "hi",
        &json!({"tool": "shout", "id": format!("hi@{other}"), "platform": other,
                "input": {"text": "hi there"}, "expected": {"result": "HI THERE!"}}),
    );
    let lane = lane(&builder(
        &TEXT_RS.replace("{SHOUT}", "!"),
        &["upper", "shout"],
        &rewritten,
    ));
    let out = run(&lane);
    assert_eq!(out.status.code(), Some(2), "{}", text(&out));
    let verdict = lane.verdict();
    assert_eq!(verdict["verdict"], "refuted", "{verdict}");
    assert!(
        verdict["failedGates"].to_string().contains("port_replay"),
        "{verdict}"
    );
    let gates = gates(&lane);
    let evidence = gate(&gates, "port_replay")["evidence"].to_string();
    assert!(
        evidence.contains(&format!(
            "tool \\\"shout\\\" has no fixture for {host} (its fixtures cover {other}), so it was never proved on this platform"
        )),
        "{evidence}"
    );
    // The change to the base fixture is named too.
    assert!(
        evidence.contains("changed its \\\"platform\\\""),
        "{evidence}"
    );
}

/// The project with the `shout` fixtures removed: a base that records none for that tool.
fn empty_base_lane(body: &str) -> Lane {
    let project = var_tmp("cp-port-empty-base-");
    copy_tree(&fixture().join("project"), project.path());
    fs::remove_dir_all(project.path().join("ports/upper/fixtures/shout")).unwrap();
    Lane::from_project(body, project.path(), &|id| packet(id, &|t| t))
}

#[test]
fn preflight_refuses_a_port_packet_whose_base_has_no_fixtures_for_a_tool() {
    if workspace::skipped("preflight_refuses_a_port_packet_whose_base_has_no_fixtures_for_a_tool") {
        return;
    }
    let lane = empty_base_lane("true");
    // Without held-out cases that name the tool, `lint` and `run` both refuse.
    let lint = lane
        .cowproof_cmd()
        .args(["lint", "--repo"])
        .arg(&lane.repo)
        .arg(&lane.packet)
        .output()
        .unwrap();
    assert!(!lint.status.success(), "{}", text(&lint));
    let stderr = String::from_utf8_lossy(&lint.stderr).to_string();
    assert!(stderr.contains("error [port-no-base-fixtures]"), "{stderr}");
    assert!(stderr.contains("\"shout\""), "{stderr}");
    assert!(
        stderr.contains("record the fixtures in the base first"),
        "{stderr}"
    );

    let out = lane.run(&[]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(stderr.contains("error [port-no-base-fixtures]"), "{stderr}");
    assert!(stderr.contains("packet lint found errors"), "{stderr}");
    assert!(
        !lane.lane_dir().exists(),
        "a refused run starts no lane: {}",
        lane.lane_dir().display()
    );
}

#[test]
fn held_out_cases_that_name_the_tool_make_the_empty_base_a_warning() {
    if workspace::skipped("held_out_cases_that_name_the_tool_make_the_empty_base_a_warning") {
        return;
    }
    let lane = empty_base_lane("true");
    // The committed held-out cases name `shout` (and `upper`), so `lint --heldout` only warns.
    let heldout = heldout();
    let lint = lane
        .cowproof_cmd()
        .args(["lint", "--repo"])
        .arg(&lane.repo)
        .arg("--heldout")
        .arg(&heldout)
        .arg(&lane.packet)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&lint.stderr).to_string();
    assert!(lint.status.success(), "{}", text(&lint));
    assert!(stderr.contains("warn [port-no-base-fixtures]"), "{stderr}");
    assert!(!stderr.contains("error ["), "{stderr}");

    // `cowproof run` reads the same file: it is not refused at lint. (It may be refused later
    // for the sandbox, or refuted for the missing fixtures; it is not exit 1 from the lint.)
    let out = run(&lane);
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(stderr.contains("warn [port-no-base-fixtures]"), "{stderr}");
    assert!(!stderr.contains("packet lint found errors"), "{stderr}");
}
