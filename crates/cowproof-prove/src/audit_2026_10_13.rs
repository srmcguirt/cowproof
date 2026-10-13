//! Proof tests for `docs/audit-2026-10-13.md`: each open finding's is `#[ignore]`d and FAILS
//! today, so the suite stays green; a resolved finding's runs with the suite. Run the open
//! ones with `cargo test -p cowproof-prove -- --ignored audit_`.

use super::*;

fn outcome(tool: &str, id: &str) -> CaseOutcome {
    serde_json::from_value(serde_json::json!({
        "tool": tool, "id": id, "surface": "direct", "status": "pass",
    }))
    .unwrap()
}

fn report_with(outcomes: Vec<CaseOutcome>, other_platform: usize) -> ReplayReport {
    serde_json::from_value(serde_json::json!({
        "outcomes": outcomes,
        "passed": outcomes.len(),
        "accepted": 0,
        "failed": 0,
        "errored": 0,
        "not_ported": 0,
        "other_platform": other_platform,
    }))
    .unwrap()
}

/// The tool `t` of the S-2 tests: its base fixtures, the lane's own, and the replay of this
/// platform, which ran only `ran`.
fn s2_judge(
    base: &FixtureCases,
    lane_added: &[(&str, Option<String>)],
    ran: &[&str],
    other_platform: usize,
    held_out_tools: &[String],
) -> Vec<String> {
    let mut on_disk = base.clone();
    for (id, platform) in lane_added {
        on_disk.insert(("t".into(), (*id).into()), platform.clone());
    }
    let r = report_with(
        ran.iter().map(|id| outcome("t", id)).collect(),
        other_platform,
    );
    let mut replayed = Replayed {
        reports: BTreeMap::from([("direct".to_string(), r.clone()), ("mcp".to_string(), r)]),
        failures: Vec::new(),
    };
    judge(
        "",
        &mut replayed,
        &["t".to_string()],
        &["t".to_string()],
        &on_disk,
        base,
        held_out_tools,
    );
    replayed.failures
}

fn other_platform() -> String {
    let host = portkit_port::host_platform();
    ["linux", "macos"]
        .into_iter()
        .find(|p| *p != host)
        .unwrap()
        .to_string()
}

/// S-2. The base holds one fixture for tool `t`, captured on the OTHER platform. The lane adds
/// an untagged fixture of its own for `t` (its `expected` is whatever its port prints). On this
/// platform the replay runs only the lane's fixture; coverage counts the base's fixtures only,
/// so the port of `t` is not proved on a platform where no reference-captured fixture of it was
/// replayed.
#[test]
fn audit_s2_a_lane_added_fixture_hides_a_tool_that_the_base_only_covers_for_the_other_platform() {
    let host = portkit_port::host_platform();
    let other = other_platform();
    let mut base: FixtureCases = BTreeMap::new();
    base.insert(("t".into(), format!("1@{other}")), Some(other.clone()));
    let failures = s2_judge(&base, &[("lane-own", None)], &["lane-own"], 1, &[]);
    assert!(
        failures.iter().any(|f| f.contains(&format!(
            "tool \"t\" has no fixture for {host} (its fixtures cover {other})"
        ))),
        "tool `t` has no reference-captured fixture for {host} (its base fixture is for {other}), \
         and the judge must say so: {failures:?}"
    );
}

/// The converse of S-2: a base with an untagged fixture still proves, whatever the lane adds,
/// tagged or not. Lane-added fixtures are replayed and judged, only not counted as coverage.
#[test]
fn audit_s2_a_base_fixture_that_runs_here_proves_the_tool_with_lane_added_fixtures() {
    let host = portkit_port::host_platform();
    let other = other_platform();
    let mut base: FixtureCases = BTreeMap::new();
    base.insert(("t".into(), "1".into()), None);
    let added = [
        ("lane-a", None),
        (&*format!("lane-b@{host}"), Some(host.to_string())),
        (&*format!("lane-c@{other}"), Some(other.clone())),
    ];
    let failures = s2_judge(
        &base,
        &added,
        &["1", "lane-a", &format!("lane-b@{host}")],
        1,
        &[],
    );
    assert_eq!(failures, Vec::<String>::new());
}

/// The director's held-out cases are captured live on the verifier's platform, so they cover
/// their tool even when the base's fixtures are all for the other platform.
#[test]
fn audit_s2_held_out_cases_cover_a_tool_the_base_only_covers_for_the_other_platform() {
    let other = other_platform();
    let mut base: FixtureCases = BTreeMap::new();
    base.insert(("t".into(), format!("1@{other}")), Some(other.clone()));
    let failures = s2_judge(
        &base,
        &[("lane-own", None)],
        &["lane-own"],
        1,
        &["t".to_string()],
    );
    assert_eq!(failures, Vec::<String>::new());
}

/// S-1. The failure lines of the port judge name the fixture by the `tool` and `id` the
/// fixture FILE holds, which the lane wrote; `first_line` strips control characters from the
/// error text only. `cowproof verify` prints each failure with `println!("port: {failure}")`.
#[test]
fn audit_s1_a_fixture_id_with_escape_sequences_reaches_the_port_failure_line() {
    let id = "x\u{1b}[2J\u{1b}[1;1Hdiverged: nothing to see\u{1b}]52;c;ZXZpbA==\u{7}";
    let mut bad = outcome("t", id);
    bad.status = Status::Fail;
    let r = report_with(vec![bad], 0);
    let mut replayed = Replayed {
        reports: BTreeMap::from([("direct".to_string(), r.clone()), ("mcp".to_string(), r)]),
        failures: Vec::new(),
    };
    let mut on_disk: FixtureCases = BTreeMap::new();
    on_disk.insert(("t".into(), id.into()), None);
    judge(
        "",
        &mut replayed,
        &["t".to_string()],
        &["t".to_string()],
        &on_disk,
        &on_disk,
        &[],
    );
    assert!(!replayed.failures.is_empty());
    for failure in &replayed.failures {
        assert!(
            !failure.chars().any(char::is_control),
            "a control character reaches a line `cowproof verify` prints raw: {failure:?}"
        );
    }
}
