//! What the capsule records about the builder's check runs and the packet versions, and that the
//! seal covers it: a hand edit to a duration, an output hash or a packet version is refused by
//! `Capsule::read`, which is the first thing `cowproof verify` does.

use cowproof_prove::capsule::{
    CheckEnd, CheckResult, EnvironmentFingerprint, PACKET_VERSIONS_FILE, read_packet_versions,
    write_packet_versions,
};
use cowproof_prove::{Capsule, CapsuleError};
use serde_json::json;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

fn capsule() -> Capsule {
    Capsule::new(
        "0".repeat(40),
        "1".repeat(40),
        EnvironmentFingerprint {
            os: "test".into(),
            arch: "test".into(),
            tools: HashMap::new(),
        },
        "haiku".into(),
        "api-key".into(),
    )
}

fn recorded() -> CheckResult {
    CheckResult {
        command: "cargo test".into(),
        exit_status: 0,
        attempts: 2,
        duration_ms: 1234,
        output_sha256: Capsule::hash_bytes(b"test result: ok\n"),
        output_len: Some(16),
        end: Some(CheckEnd::Exited { code: 0 }),
        verifier: None,
        timeout_ms: None,
    }
}

/// A sealed capsule directory holding one check and two packet versions (a redirect).
fn sealed(dir: &Path) {
    fs::create_dir_all(dir.join("checks")).unwrap();
    fs::write(
        dir.join("checks/unit.json"),
        serde_json::to_vec_pretty(&recorded()).unwrap(),
    )
    .unwrap();
    write_packet_versions(
        dir,
        &[
            (None, "first packet\n".to_string()),
            (Some("lane:E1".to_string()), "second packet\n".to_string()),
        ],
    )
    .unwrap();
    fs::write(dir.join("lane.patch"), "").unwrap();
    capsule().write(dir).unwrap();
}

#[test]
fn the_packet_versions_are_written_byte_for_byte_and_indexed() {
    let dir = tempfile::tempdir().unwrap();
    sealed(dir.path());
    assert_eq!(
        fs::read_to_string(dir.path().join("packets/v1.md")).unwrap(),
        "first packet\n"
    );
    assert_eq!(
        fs::read_to_string(dir.path().join("packets/v2.md")).unwrap(),
        "second packet\n"
    );
    let index: serde_json::Value =
        serde_json::from_slice(&fs::read(dir.path().join(PACKET_VERSIONS_FILE)).unwrap()).unwrap();
    assert_eq!(
        index,
        json!([
            {"version": 1, "file": "v1.md", "introduced_by": null},
            {"version": 2, "file": "v2.md", "introduced_by": "lane:E1"},
        ])
    );
    let capsule = Capsule::read(dir.path()).expect("the capsule reads back");
    for file in [
        "packets/v1.md",
        "packets/v2.md",
        "packets/versions.json",
        "checks/unit.json",
    ] {
        assert!(capsule.file_hashes.contains_key(file), "{file} not sealed");
    }
    let read = read_packet_versions(dir.path()).unwrap();
    assert_eq!(read.len(), 2);
    assert_eq!(read[0].0.version, 1);
    assert_eq!(read[0].0.introduced_by, None);
    assert_eq!(read[0].1, "first packet\n");
    assert_eq!(read[1].0.introduced_by.as_deref(), Some("lane:E1"));
    assert_eq!(read[1].1, "second packet\n");
}

fn assert_refused_as_changed(dir: &Path, file: &str) {
    match Capsule::read(dir) {
        Err(CapsuleError::HashMismatch(name, _, _)) => assert_eq!(name, file),
        other => panic!("{file}: expected a hash mismatch, got {other:?}"),
    }
}

#[test]
fn editing_a_check_record_or_a_packet_version_in_a_sealed_capsule_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    sealed(dir.path());

    // A shorter duration in the check record.
    let check = dir.path().join("checks/unit.json");
    let original = fs::read_to_string(&check).unwrap();
    assert!(original.contains("\"duration_ms\": 1234"));
    fs::write(&check, original.replace("1234", "1")).unwrap();
    assert_refused_as_changed(dir.path(), "checks/unit.json");
    fs::write(&check, &original).unwrap();

    // The attempt count and the output hash are covered the same way.
    fs::write(
        &check,
        original.replace("\"attempts\": 2", "\"attempts\": 1"),
    )
    .unwrap();
    assert_refused_as_changed(dir.path(), "checks/unit.json");
    fs::write(&check, &original).unwrap();

    // A packet version, the index, and a version added afterwards.
    for file in ["packets/v1.md", "packets/v2.md", "packets/versions.json"] {
        let path = dir.path().join(file);
        let original = fs::read(&path).unwrap();
        fs::write(&path, b"tampered").unwrap();
        assert_refused_as_changed(dir.path(), file);
        fs::write(&path, original).unwrap();
    }
    fs::write(dir.path().join("packets/v3.md"), "a packet nobody ran").unwrap();
    assert!(matches!(
        Capsule::read(dir.path()),
        Err(CapsuleError::UnsealedFile(name)) if name == "packets/v3.md"
    ));
    fs::remove_file(dir.path().join("packets/v3.md")).unwrap();

    // Restored, it reads again: the refusals were the edits.
    Capsule::read(dir.path()).expect("the untouched capsule reads");
}

#[test]
fn a_check_record_from_before_runs_were_recorded_still_reads() {
    // The five fields every older capsule has; `output_len` and `end` are absent.
    let old = json!({
        "command": "cargo test",
        "exit_status": 1,
        "attempts": 1,
        "duration_ms": 0,
        "output_sha256": "",
    });
    let read: CheckResult = serde_json::from_value(old).expect("an older record parses");
    assert_eq!(read.exit_status, 1);
    assert_eq!(read.output_len, None);
    assert_eq!(read.end, None);

    // And an older capsule.json, with no `base_remote` key at all.
    let dir = tempfile::tempdir().unwrap();
    sealed(dir.path());
    let path = dir.path().join("capsule.json");
    let mut json: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert!(
        json.as_object_mut()
            .unwrap()
            .remove("base_remote")
            .is_some()
    );
    let raw = serde_json::to_vec_pretty(&json).unwrap();
    fs::write(&path, &raw).unwrap();
    fs::write(dir.path().join("capsule.sha256"), Capsule::hash_bytes(&raw)).unwrap();
    assert_eq!(Capsule::read(dir.path()).unwrap().base_remote, None);
}

#[test]
fn a_capsule_without_packet_versions_reads_as_none() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("lane.patch"), "").unwrap();
    capsule().write(dir.path()).unwrap();
    assert!(read_packet_versions(dir.path()).unwrap().is_empty());
}

#[test]
fn an_index_naming_a_file_outside_packets_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir_all(dir.path().join("packets")).unwrap();
    fs::write(
        dir.path().join(PACKET_VERSIONS_FILE),
        json!([{"version": 1, "file": "../lane.patch", "introduced_by": null}]).to_string(),
    )
    .unwrap();
    assert!(matches!(
        read_packet_versions(dir.path()),
        Err(CapsuleError::InvalidFormat(_))
    ));
}

#[test]
fn the_compile_cache_record_round_trips_under_the_seal_and_older_capsules_read_without_it() {
    use cowproof_prove::capsule::VerifyCache;

    // No record: the key is not written at all, so an older capsule's bytes and seal are the same.
    let dir = tempfile::tempdir().unwrap();
    sealed(dir.path());
    let plain = fs::read_to_string(dir.path().join("capsule.json")).unwrap();
    assert!(!plain.contains("verify_cache"), "{plain}");
    assert_eq!(Capsule::read(dir.path()).unwrap().verify_cache, None);

    // A record written, sealed and read back.
    let record = VerifyCache {
        status: "built".to_string(),
        key: Some("a".repeat(64)),
        copy: Some("clone".to_string()),
        note: None,
    };
    let mut capsule = Capsule::read(dir.path()).unwrap();
    capsule.verify_cache = Some(record.clone());
    capsule.write(dir.path()).unwrap();
    let json = fs::read_to_string(dir.path().join("capsule.json")).unwrap();
    assert!(json.contains("\"verify_cache\""), "{json}");
    assert!(
        !json.contains("\"note\""),
        "an absent note is not written: {json}"
    );
    assert_eq!(
        Capsule::read(dir.path()).unwrap().verify_cache,
        Some(record.clone())
    );

    // It is under the seal: changing what it says is refused.
    let path = dir.path().join("capsule.json");
    fs::write(&path, json.replace("\"built\"", "\"hit\"")).unwrap();
    assert!(matches!(
        Capsule::read(dir.path()),
        Err(CapsuleError::HashMismatch(name, _, _)) if name == "capsule.json"
    ));
    fs::write(&path, &json).unwrap();
    Capsule::read(dir.path()).expect("restored, it reads again");

    // A record holding only its status (the fields are optional) still parses.
    let minimal: VerifyCache = serde_json::from_value(json!({"status": "off"})).unwrap();
    assert_eq!(
        minimal,
        VerifyCache {
            status: "off".to_string(),
            key: None,
            copy: None,
            note: None,
        }
    );
}
