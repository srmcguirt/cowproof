use anyhow::Result;
use cowproof_host::LaneStatus;
use cowproof_plan::{
    HostCapacity, Plan, PlanHostRunner, check_plans, choose_host, collect_running,
    duplicate_running_id, lanes, ready_next, waiting_on_founder,
};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::PathBuf;

fn plan(name: &str, contents: &str) -> Plan {
    Plan {
        path: PathBuf::from(name),
        document: serde_json::from_str::<Value>(contents).unwrap(),
    }
}

#[test]
fn real_numbering_mistake_reports_both_reservation_reasons() {
    let alpha = plan(
        "alpha.lanes.json",
        r#"{
      "version":1,"plan":"alpha","baseline":{"migration":481,"contract":"C1.33"},
      "numbering":{"migrationGlob":"migrations/{n}_*.sql","contractPrefix":"C1."},
      "lanes":[
        {"id":"bad-old","title":"bad","priority":1,"status":"planned","reserves":{"migration":466,"contract":"C1.34"}},
        {"id":"other","title":"other","priority":2,"status":"planned","reserves":{"migration":482,"contract":"C1.34"}}
      ]}"#,
    );
    let errors = check_plans(std::path::Path::new("."), &[alpha]);
    let reasons: Vec<&str> = errors
        .iter()
        .filter(|p| p.lane == "bad-old")
        .map(|p| p.rule.as_str())
        .collect();
    assert!(
        reasons.iter().any(|r| r.contains("above baseline 481")),
        "{reasons:?}"
    );
    assert!(
        reasons.iter().any(|r| r.contains("unique across plans")),
        "{reasons:?}"
    );
    assert!(
        errors
            .iter()
            .any(|p| p.lane == "other" && p.rule.contains("unique across plans"))
    );
}

#[test]
fn next_only_returns_unblocked_packet_lanes_in_priority_order() {
    let p = plan(
        "p",
        r#"{"version":1,"plan":"p","lanes":[
      {"id":"done","title":"done","priority":5,"status":"applied","commit":"abc"},
      {"id":"later","title":"later","priority":1,"status":"packet","dependsOn":["blocked"]},
      {"id":"blocked","title":"blocked","priority":1,"status":"planned"},
      {"id":"ready","title":"ready","priority":2,"status":"packet","dependsOn":["done"],"estimateHours":3}
    ]}"#,
    );
    let all = lanes(&[p]);
    let next = ready_next(&all);
    assert_eq!(
        next.iter().map(|l| l.id.as_str()).collect::<Vec<_>>(),
        vec!["ready"]
    );
}

#[test]
fn fixture_alpha_has_valid_reservation_order() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/alpha.lanes.json");
    let p = Plan {
        path: path.clone(),
        document: serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap(),
    };
    assert!(
        check_plans(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../..")
                .as_path(),
            &[p]
        )
        .is_empty()
    );
}

#[test]
fn applied_migration_cannot_pass_an_unfinished_predecessor() {
    let p = plan(
        "p",
        r#"{"version":1,"plan":"p","lanes":[
      {"id":"first","title":"first","priority":1,"status":"planned","reserves":{"migration":10}},
      {"id":"second","title":"second","priority":2,"status":"applied","commit":"abc","reserves":{"migration":11}}
    ]}"#,
    );
    let errors = check_plans(std::path::Path::new("."), &[p]);
    assert!(
        errors
            .iter()
            .any(|problem| problem.lane == "second" && problem.rule.contains("mark it held"))
    );
}

#[test]
fn schema_and_dependency_cycles_are_reported() {
    let p = plan(
        "p",
        r#"{"version":2,"plan":"p","unexpected":true,"lanes":[
      {"id":"a","title":"a","priority":1,"status":"planned","dependsOn":["b"]},
      {"id":"b","title":"b","priority":1,"status":"planned","dependsOn":["a"]}
    ]}"#,
    );
    let errors = check_plans(std::path::Path::new("."), &[p]);
    assert!(
        errors
            .iter()
            .any(|problem| problem.rule.contains("version must be 1"))
    );
    assert!(
        errors
            .iter()
            .any(|problem| problem.rule.contains("unknown property unexpected"))
    );
    assert_eq!(
        errors
            .iter()
            .filter(|problem| problem.rule.contains("must not contain a cycle"))
            .count(),
        2
    );
}

#[test]
fn founder_waiting_brief_excludes_completed_and_dropped_lanes() {
    let p = plan(
        "p",
        r#"{"version":1,"plan":"p","lanes":[
      {"id":"idea-waits","title":"idea","priority":1,"status":"idea","decision":"Waiting on the founder"},
      {"id":"planned-waits","title":"planned","priority":1,"status":"planned","notes":"Need founder decision"},
      {"id":"packet-waits","title":"packet","priority":1,"status":"packet","notes":"Ask the founder"},
      {"id":"held-waits","title":"held","priority":1,"status":"held","decision":"Await founder"},
      {"id":"dropped-waits","title":"dropped","priority":1,"status":"dropped","notes":"Waiting on the founder"},
      {"id":"applied-waits","title":"applied","priority":1,"status":"applied","notes":"Waiting on the founder"},
      {"id":"shipped-waits","title":"shipped","priority":1,"status":"shipped","notes":"Waiting on the founder"},
      {"id":"split-fields","title":"split","priority":1,"status":"planned","decision":"Founder review","notes":"Waiting"}
    ]}"#,
    );
    let waiting = waiting_on_founder(&lanes(&[p]));
    assert_eq!(
        waiting,
        vec!["held-waits", "idea-waits", "packet-waits", "planned-waits"]
    );
}

#[test]
fn dispatch_uses_ready_priority_class_capacity_preference_and_disk_floor() {
    let p = plan(
        "p",
        r#"{"version":1,"plan":"p","lanes":[
      {"id":"later","title":"later","priority":2,"status":"packet","class":"rust"},
      {"id":"first","title":"first","priority":1,"status":"packet","class":"rust","host":"remote1"}
    ]}"#,
    );
    let ready = ready_next(&lanes(&[p]));
    assert_eq!(
        ready.iter().map(|l| l.id.as_str()).collect::<Vec<_>>(),
        vec!["first", "later"]
    );
    let capacity = |disk, running| HostCapacity {
        class_limits: BTreeMap::from([("rust".into(), 1)]),
        class_running: BTreeMap::from([("rust".into(), running)]),
        above_disk_floors: disk,
    };
    let hosts = BTreeMap::from([
        ("local".into(), capacity(true, 0)),
        ("remote1".into(), capacity(false, 0)),
    ]);
    assert_eq!(choose_host(&ready[0], &hosts).as_deref(), Some("local"));
    assert_eq!(choose_host(&ready[1], &hosts).as_deref(), Some("local"));
    let no_room = BTreeMap::from([("local".into(), capacity(true, 1))]);
    assert_eq!(choose_host(&ready[0], &no_room), None);
}

#[test]
fn dispatch_prefers_configured_host_and_refuses_duplicate_running_id() {
    let p = plan(
        "p",
        r#"{"version":1,"plan":"p","lanes":[
      {"id":"same","title":"same","priority":1,"status":"packet","class":"rust","host":"remote1"}
    ]}"#,
    );
    let mut all = lanes(&[p]);
    let cap = HostCapacity {
        class_limits: BTreeMap::from([("rust".into(), 2)]),
        class_running: BTreeMap::new(),
        above_disk_floors: true,
    };
    let hosts = BTreeMap::from([("local".into(), cap.clone()), ("remote1".into(), cap)]);
    assert_eq!(choose_host(&all[0], &hosts).as_deref(), Some("remote1"));
    assert!(!duplicate_running_id(&all, "same"));
    all[0].status = "running".into();
    assert!(duplicate_running_id(&all, "same"));
}

struct FakeHosts {
    states: BTreeMap<String, LaneStatus>,
    collected: Vec<String>,
}
impl PlanHostRunner for FakeHosts {
    fn status(&mut self, lane: &cowproof_plan::LaneRef) -> Result<LaneStatus> {
        Ok(self.states[&lane.id].clone())
    }
    fn collect(&mut self, lane: &cowproof_plan::LaneRef) -> Result<()> {
        self.collected.push(lane.id.clone());
        Ok(())
    }
}

#[test]
fn collect_moves_finished_to_review_and_lost_back_to_packet_with_fake_host_runner() {
    let root = std::env::temp_dir().join(format!("lanes-plan-collect-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("finished.md"), "finished packet").unwrap();
    std::fs::write(root.join("lost.md"), "lost packet").unwrap();
    let plan_path = root.join("collect.lanes.json");
    std::fs::write(&plan_path, r#"{"version":1,"plan":"collect","lanes":[
      {"id":"finished","title":"finished","priority":1,"status":"running","packet":"finished.md","class":"rust","host":"local"},
      {"id":"lost","title":"lost","priority":2,"status":"running","packet":"lost.md","class":"rust","host":"remote1"}
    ]}"#).unwrap();
    let mut hosts = FakeHosts {
        states: BTreeMap::from([
            ("finished".into(), LaneStatus::Finished),
            ("lost".into(), LaneStatus::Lost),
        ]),
        collected: Vec::new(),
    };
    assert_eq!(
        collect_running(&root, &mut hosts).unwrap(),
        vec![
            ("finished".into(), "review".into()),
            ("lost".into(), "packet".into())
        ]
    );
    assert_eq!(hosts.collected, vec!["finished"]);
    let collected: Value = serde_json::from_slice(&std::fs::read(plan_path).unwrap()).unwrap();
    assert_eq!(collected["lanes"][0]["status"], "review");
    assert_eq!(collected["lanes"][1]["status"], "packet");
    assert!(
        collected["lanes"][1]["notes"]
            .as_str()
            .unwrap()
            .contains("host lost")
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn setting_packet_and_running_in_one_update_records_the_packet() {
    use cowproof_plan::set_status;

    let root = std::env::temp_dir().join(format!("lanes-plan-set-packet-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(
        root.join("worker.md"),
        "<!-- lane {\"id\":\"worker\"} -->\n",
    )
    .unwrap();
    let plan_path = root.join("work.lanes.json");
    std::fs::write(&plan_path, r#"{"version":1,"plan":"work","lanes":[{"id":"worker","title":"worker","priority":1,"status":"planned"}]}"#).unwrap();
    let plans = cowproof_plan::load_plans(&root, &[]).unwrap();
    assert!(set_status(&root, &plans, "worker", "running", None, None, None).is_err());
    set_status(
        &root,
        &plans,
        "worker",
        "running",
        None,
        None,
        Some("worker.md"),
    )
    .unwrap();
    let updated: Value = serde_json::from_slice(&std::fs::read(&plan_path).unwrap()).unwrap();
    assert_eq!(updated["lanes"][0]["status"], "running");
    assert_eq!(updated["lanes"][0]["packet"], "worker.md");
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn held_and_review_can_ship_with_commit_and_release_together() {
    use cowproof_plan::set_status;

    for initial in ["held", "review"] {
        let root =
            std::env::temp_dir().join(format!("lanes-plan-ship-{initial}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let plan_path = root.join("work.lanes.json");
        std::fs::write(&plan_path, format!(r#"{{"version":1,"plan":"work","lanes":[{{"id":"worker","title":"worker","priority":1,"status":"{initial}"}}]}}"#)).unwrap();
        let plans = cowproof_plan::load_plans(&root, &[]).unwrap();
        assert!(set_status(&root, &plans, "worker", "shipped", None, None, None).is_err());
        set_status(
            &root,
            &plans,
            "worker",
            "shipped",
            Some("abc123"),
            Some("v1.2.3"),
            None,
        )
        .unwrap();
        let updated: Value = serde_json::from_slice(&std::fs::read(&plan_path).unwrap()).unwrap();
        assert_eq!(updated["lanes"][0]["status"], "shipped");
        assert_eq!(updated["lanes"][0]["commit"], "abc123");
        assert_eq!(updated["lanes"][0]["release"], "v1.2.3");
        std::fs::remove_dir_all(root).unwrap();
    }
}
