//! Proof tests for `docs/audit-2026-10-13.md`: each is `#[ignore]`d and FAILS today, so the
//! suite stays green. Run them with `cargo test -p cowproof-prove -- --ignored audit_`.

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

/// S-2. The base holds one fixture for tool `t`, captured on the OTHER platform. The lane adds
/// an untagged fixture of its own for `t` (its `expected` is whatever its port prints). On this
/// platform the replay runs only the lane's fixture, and the judge reports no failure: the port
/// of `t` is proved on a platform where no reference-captured fixture of it was ever replayed.
#[test]
#[ignore = "S-2: open finding"]
fn audit_s2_a_lane_added_fixture_hides_a_tool_that_the_base_only_covers_for_the_other_platform() {
    let host = portkit_port::host_platform();
    let other = ["linux", "macos"].into_iter().find(|p| *p != host).unwrap();
    // On disk: the base's `t/1@<other>` (skipped here) and the lane's untagged `t/lane-own`.
    let mut on_disk: FixtureCases = BTreeMap::new();
    on_disk.insert(("t".into(), format!("1@{other}")), Some(other.to_string()));
    on_disk.insert(("t".into(), "lane-own".into()), None);
    let r = report_with(vec![outcome("t", "lane-own")], 1);
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
    );
    assert!(
        !replayed.failures.is_empty(),
        "tool `t` has no reference-captured fixture for {host} (its base fixture is for {other}), \
         yet the judge found nothing wrong: {:?}",
        replayed.failures
    );
}

/// S-1. The failure lines of the port judge name the fixture by the `tool` and `id` the
/// fixture FILE holds, which the lane wrote; `first_line` strips control characters from the
/// error text only. `cowproof verify` prints each failure with `println!("port: {failure}")`.
#[test]
#[ignore = "S-1: open finding"]
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
    );
    assert!(!replayed.failures.is_empty());
    for failure in &replayed.failures {
        assert!(
            !failure.chars().any(char::is_control),
            "a control character reaches a line `cowproof verify` prints raw: {failure:?}"
        );
    }
}
