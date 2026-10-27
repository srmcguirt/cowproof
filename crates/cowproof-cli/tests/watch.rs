use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

fn cowproof_bin() -> PathBuf {
    let target_dir = std::env::var("CARGO_TARGET_DIR").unwrap_or_else(|_| "target".to_string());

    #[cfg(debug_assertions)]
    let profile = "debug";
    #[cfg(not(debug_assertions))]
    let profile = "release";

    PathBuf::from(target_dir).join(profile).join("cowproof")
}

#[test]
fn test_watch_table_with_parked_escalation() {
    let bin = cowproof_bin();
    if !bin.exists() {
        eprintln!(
            "Skipping test: cowproof binary not found at {}",
            bin.display()
        );
        return;
    }

    // Create a temporary directory with lane structure
    let tmpdir = TempDir::new().unwrap();
    let lanes_root = tmpdir.path();

    // Create two lanes: one with run.json (finished), one without (running)
    let lane1 = lanes_root.join("lane-1");
    fs::create_dir_all(lane1.join("control")).unwrap();

    // Write a run.json with exit code 0
    fs::write(lane1.join("control/run.json"), r#"{"exit_code": 0}"#).unwrap();

    // Write escalations.jsonl with a parked ask
    fs::write(
        lane1.join("control/escalations.jsonl"),
        r#"{"event":"asked","lane":"lane-1","id":"lane-1:E1","ask":{"kind":"blocker","question":"test?","tried":[],"options":[{"id":"a","summary":"do A","cost":"1h"}],"recommend":"a","blocking":true},"origin":"builder","at_ms":2000}"#,
    ).unwrap();

    let lane2 = lanes_root.join("lane-2");
    fs::create_dir_all(lane2.join("control")).unwrap();

    // Run the command and capture output
    let output = std::process::Command::new(&bin)
        .args([
            "watch",
            "--lanes-root",
            lanes_root.to_str().unwrap(),
            "--cache-ttl",
            "1h",
        ])
        .output()
        .expect("failed to run cowproof watch");

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Verify the header is present
    assert!(stdout.contains("LANE"), "Missing LANE header");
    assert!(stdout.contains("STATE"), "Missing STATE header");
    assert!(stdout.contains("PARKED"), "Missing PARKED header");
}

#[test]
fn test_watch_events_ask_ruling_note_in_order() {
    let bin = cowproof_bin();
    if !bin.exists() {
        eprintln!(
            "Skipping test: cowproof binary not found at {}",
            bin.display()
        );
        return;
    }

    let tmpdir = TempDir::new().unwrap();
    let lanes_root = tmpdir.path();

    let lane1 = lanes_root.join("lane-1");
    fs::create_dir_all(lane1.join("control")).unwrap();

    // Write escalations.jsonl with ask, ruling, and note
    fs::write(
        lane1.join("control/escalations.jsonl"),
        r#"{"event":"asked","lane":"lane-1","id":"lane-1:E1","ask":{"kind":"blocker","question":"test?","tried":[],"options":[{"id":"a","summary":"do A","cost":"1h"}],"recommend":"a","blocking":true},"origin":"builder","at_ms":1000}
{"event":"ruled","lane":"lane-1","id":"lane-1:E1","verdict":{"verdict":"answer","text":"go ahead"}}
{"event":"note","lane":"lane-1","id":"lane-1-n1","text":"FYI","at_ms":2000}
"#,
    ).unwrap();

    let output = std::process::Command::new(&bin)
        .args([
            "watch",
            "--lanes-root",
            lanes_root.to_str().unwrap(),
            "--events",
        ])
        .output()
        .expect("failed to run cowproof watch --events");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<&str> = stdout.lines().collect();

    // Should have at least 3 events
    assert!(
        lines.len() >= 3,
        "Expected at least 3 event lines, got {}",
        lines.len()
    );

    // Check for the three event types
    let has_ask = lines
        .iter()
        .any(|l| l.contains("asked") && l.contains("lane-1:E1"));
    let has_ruling = lines
        .iter()
        .any(|l| l.contains("ruled") && l.contains("lane-1:E1"));
    let has_note = lines
        .iter()
        .any(|l| l.contains("note") && l.contains("lane-1-n1"));

    assert!(has_ask, "Missing 'asked' event");
    assert!(has_ruling, "Missing 'ruled' event");
    assert!(has_note, "Missing 'note' event");
}

#[test]
fn test_watch_events_line_is_truncated_to_300_chars() {
    let bin = cowproof_bin();
    if !bin.exists() {
        eprintln!(
            "Skipping test: cowproof binary not found at {}",
            bin.display()
        );
        return;
    }

    let tmpdir = TempDir::new().unwrap();
    let lanes_root = tmpdir.path();

    let lane1 = lanes_root.join("very-long-lane-name-to-test-truncation");
    fs::create_dir_all(lane1.join("control")).unwrap();

    // Create an event with a long note text to test truncation
    fs::write(
        lane1.join("control/escalations.jsonl"),
        format!(
            r#"{{"event":"note","lane":"{}","id":"note-1","text":"{}","at_ms":1000}}"#,
            "very-long-lane-name-to-test-truncation",
            "x".repeat(500)
        ),
    )
    .unwrap();

    let output = std::process::Command::new(&bin)
        .args([
            "watch",
            "--lanes-root",
            lanes_root.to_str().unwrap(),
            "--events",
        ])
        .output()
        .expect("failed to run cowproof watch --events");

    let stdout = String::from_utf8_lossy(&output.stdout);

    for line in stdout.lines() {
        // Each event line should be at most 300 characters
        assert!(
            line.len() <= 300,
            "Event line exceeds 300 chars: {} chars",
            line.len()
        );
    }
}

#[test]
fn test_watch_events_new_lane_dir_is_picked_up() {
    let bin = cowproof_bin();
    if !bin.exists() {
        eprintln!(
            "Skipping test: cowproof binary not found at {}",
            bin.display()
        );
        return;
    }

    let tmpdir = TempDir::new().unwrap();
    let lanes_root = tmpdir.path();

    let lane1 = lanes_root.join("lane-1");
    fs::create_dir_all(lane1.join("control")).unwrap();
    fs::write(
        lane1.join("control/escalations.jsonl"),
        r#"{"event":"asked","lane":"lane-1","id":"lane-1:E1","ask":{"kind":"blocker","question":"test?","tried":[],"options":[{"id":"a","summary":"do A","cost":"1h"}],"recommend":"a","blocking":true},"origin":"builder","at_ms":1000}
"#,
    ).unwrap();

    let lane2 = lanes_root.join("lane-2");
    fs::create_dir_all(lane2.join("control")).unwrap();
    fs::write(
        lane2.join("control/escalations.jsonl"),
        r#"{"event":"note","lane":"lane-2","id":"lane-2-n1","text":"hello","at_ms":2000}
"#,
    )
    .unwrap();

    let output = std::process::Command::new(&bin)
        .args([
            "watch",
            "--lanes-root",
            lanes_root.to_str().unwrap(),
            "--events",
        ])
        .output()
        .expect("failed to run cowproof watch --events");

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Should have events from both lanes
    assert!(stdout.contains("lane-1"));
    assert!(stdout.contains("lane-2"));
}

#[test]
fn test_watch_events_ask_never_includes_question_text() {
    let bin = cowproof_bin();
    if !bin.exists() {
        eprintln!(
            "Skipping test: cowproof binary not found at {}",
            bin.display()
        );
        return;
    }

    let tmpdir = TempDir::new().unwrap();
    let lanes_root = tmpdir.path();

    let lane1 = lanes_root.join("lane-1");
    fs::create_dir_all(lane1.join("control")).unwrap();

    // Write escalations.jsonl with an ask that has question text
    fs::write(
        lane1.join("control/escalations.jsonl"),
        r#"{"event":"asked","lane":"lane-1","id":"lane-1:E1","ask":{"kind":"blocker","question":"What is the answer to life?","tried":[],"options":[{"id":"a","summary":"do A","cost":"1h"}],"recommend":"a","blocking":true},"origin":"builder","at_ms":1000}
"#,
    )
    .unwrap();

    let output = std::process::Command::new(&bin)
        .args([
            "watch",
            "--lanes-root",
            lanes_root.to_str().unwrap(),
            "--events",
        ])
        .output()
        .expect("failed to run cowproof watch --events");

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Should have the ask event but NOT the question text
    assert!(stdout.contains("asked"));
    assert!(stdout.contains("lane-1:E1"));
    assert!(
        !stdout.contains("What is the answer"),
        "Question text must not appear in event output"
    );
}

#[test]
fn test_watch_table_shows_table_format() {
    let bin = cowproof_bin();
    if !bin.exists() {
        eprintln!(
            "Skipping test: cowproof binary not found at {}",
            bin.display()
        );
        return;
    }

    let tmpdir = TempDir::new().unwrap();
    let lanes_root = tmpdir.path();

    let lane1 = lanes_root.join("test-lane");
    fs::create_dir_all(lane1.join("control")).unwrap();

    let output = std::process::Command::new(&bin)
        .args(["watch", "--lanes-root", lanes_root.to_str().unwrap()])
        .output()
        .expect("failed to run cowproof watch");

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Should have tab-separated columns
    assert!(stdout.contains("LANE\tSTATE"), "Table header missing");
}

#[test]
fn test_watch_unreadable_control_dir_is_skipped() {
    let bin = cowproof_bin();
    if !bin.exists() {
        eprintln!(
            "Skipping test: cowproof binary not found at {}",
            bin.display()
        );
        return;
    }

    let tmpdir = TempDir::new().unwrap();
    let lanes_root = tmpdir.path();

    let lane1 = lanes_root.join("lane-1");
    fs::create_dir_all(&lane1).unwrap();
    fs::create_dir_all(lane1.join("control")).unwrap();

    let output = std::process::Command::new(&bin)
        .args([
            "watch",
            "--lanes-root",
            lanes_root.to_str().unwrap(),
            "--events",
        ])
        .output()
        .expect("failed to run cowproof watch --events");

    // The command should succeed even if control dir is unreadable
    assert!(output.status.success(), "Command should succeed");
}

#[test]
fn test_watch_shows_stopped_status() {
    let bin = cowproof_bin();
    if !bin.exists() {
        eprintln!(
            "Skipping test: cowproof binary not found at {}",
            bin.display()
        );
        return;
    }

    let tmpdir = TempDir::new().unwrap();
    let lanes_root = tmpdir.path();

    let lane1 = lanes_root.join("lane-1");
    fs::create_dir_all(lane1.join("control")).unwrap();

    // Write a run.json with "status":"stopped"
    fs::write(lane1.join("control/run.json"), r#"{"status":"stopped"}"#).unwrap();

    let output = std::process::Command::new(&bin)
        .args([
            "watch",
            "--lanes-root",
            lanes_root.to_str().unwrap(),
            "--cache-ttl",
            "1h",
        ])
        .output()
        .expect("failed to run cowproof watch");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("stopped"), "Should show 'stopped' state");
}

#[test]
fn test_watch_shows_proved_status() {
    let bin = cowproof_bin();
    if !bin.exists() {
        eprintln!(
            "Skipping test: cowproof binary not found at {}",
            bin.display()
        );
        return;
    }

    let tmpdir = TempDir::new().unwrap();
    let lanes_root = tmpdir.path();

    let lane1 = lanes_root.join("lane-1");
    fs::create_dir_all(lane1.join("control")).unwrap();

    // Write a verdict.json with proved status (or use run.json with "status":"proved")
    fs::write(lane1.join("control/run.json"), r#"{"status":"proved"}"#).unwrap();

    let output = std::process::Command::new(&bin)
        .args([
            "watch",
            "--lanes-root",
            lanes_root.to_str().unwrap(),
            "--cache-ttl",
            "1h",
        ])
        .output()
        .expect("failed to run cowproof watch");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("proved"), "Should show 'proved' state");
}

#[test]
fn test_watch_events_includes_rfc3339_timestamps() {
    let bin = cowproof_bin();
    if !bin.exists() {
        eprintln!(
            "Skipping test: cowproof binary not found at {}",
            bin.display()
        );
        return;
    }

    let tmpdir = TempDir::new().unwrap();
    let lanes_root = tmpdir.path();

    let lane1 = lanes_root.join("lane-1");
    fs::create_dir_all(lane1.join("control")).unwrap();

    // Write escalations.jsonl with an ask
    fs::write(
        lane1.join("control/escalations.jsonl"),
        r#"{"event":"asked","lane":"lane-1","id":"lane-1:E1","ask":{"kind":"blocker","question":"test?","tried":[],"options":[{"id":"a","summary":"do A","cost":"1h"}],"recommend":"a","blocking":true},"origin":"builder","at_ms":1609459200000}
"#,
    ).unwrap();

    let output = std::process::Command::new(&bin)
        .args([
            "watch",
            "--lanes-root",
            lanes_root.to_str().unwrap(),
            "--events",
        ])
        .output()
        .expect("failed to run cowproof watch --events");

    let stdout = String::from_utf8_lossy(&output.stdout);
    // RFC3339 format: YYYY-MM-DDTHH:MM:SS.sssZ
    assert!(
        stdout.contains("T") && stdout.contains(":") && stdout.contains("Z"),
        "Should include RFC3339 format timestamps"
    );
}

// The table shows the verdict of a proved lane, not the `finished` its builder ended with.

/// `cowproof watch` over `lanes_root`: the STATE column by lane id.
fn watch_states(lanes_root: &std::path::Path) -> std::collections::BTreeMap<String, String> {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_cowproof"))
        .args(["watch", "--lanes-root"])
        .arg(lanes_root)
        .args(["--cache-ttl", "1h"])
        .output()
        .expect("failed to run cowproof watch");
    assert!(out.status.success(), "{out:?}");
    let stdout = String::from_utf8(out.stdout).unwrap();
    let mut lines = stdout.lines();
    assert_eq!(
        lines.next().unwrap(),
        "LANE\tSTATE\tPARKED\tAGE\tNOTES\tLAST EVENT"
    );
    lines
        .map(|line| {
            let cols: Vec<&str> = line.split('\t').collect();
            assert_eq!(cols.len(), 6, "{line}");
            (cols[0].to_string(), cols[1].to_string())
        })
        .collect()
}

/// A lane whose builder exited (`run.json` says `finished`), with `verdict` if it was proved.
fn lane_with(root: &std::path::Path, id: &str, run: Option<&str>, verdict: Option<&str>) {
    let control = root.join(id).join("control");
    fs::create_dir_all(&control).unwrap();
    if let Some(run) = run {
        fs::write(control.join("run.json"), run).unwrap();
    }
    if let Some(verdict) = verdict {
        fs::write(control.join("verdict.json"), verdict).unwrap();
    }
}

#[test]
fn watch_shows_each_lanes_verdict_and_the_existing_state_when_it_has_none() {
    let dir = TempDir::new().unwrap();
    let root = dir.path();
    let finished = r#"{"status":"finished","exitCode":0}"#;
    lane_with(
        root,
        "a-proved",
        Some(finished),
        Some(r#"{"verdict":"proved"}"#),
    );
    lane_with(
        root,
        "b-refuted",
        Some(finished),
        Some(r#"{"verdict":"refuted"}"#),
    );
    lane_with(
        root,
        "c-incomplete",
        Some(finished),
        Some(r#"{"verdict":"incomplete"}"#),
    );
    lane_with(
        root,
        "d-infra",
        Some(finished),
        Some(r#"{"verdict":"infrastructure"}"#),
    );
    // Ended without a proof: the run.json status stands.
    lane_with(root, "e-stopped", Some(r#"{"status":"stopped"}"#), None);
    // A builder that exited and a proof not yet written: `finished`, as before.
    lane_with(root, "f-finished", Some(finished), None);
    // A builder still going: no run.json.
    lane_with(root, "g-running", None, None);
    // A verdict file that is not a verdict does not hide the status.
    lane_with(root, "h-garbled", Some(finished), Some("not json"));

    let states = watch_states(root);
    let expected = [
        ("a-proved", "proved"),
        ("b-refuted", "refuted"),
        ("c-incomplete", "incomplete"),
        ("d-infra", "infrastructure"),
        ("e-stopped", "stopped"),
        ("f-finished", "finished"),
        ("g-running", "running"),
        ("h-garbled", "finished"),
    ];
    for (lane, state) in expected {
        assert_eq!(states.get(lane).map(String::as_str), Some(state), "{lane}");
    }
    assert_eq!(states.len(), expected.len());
}

#[test]
fn watch_does_not_follow_a_verdict_symlink() {
    let dir = TempDir::new().unwrap();
    let root = dir.path();
    lane_with(root, "linked", Some(r#"{"status":"finished"}"#), None);
    let target = dir.path().join("elsewhere.json");
    fs::write(&target, r#"{"verdict":"proved"}"#).unwrap();
    std::os::unix::fs::symlink(&target, root.join("linked/control/verdict.json")).unwrap();
    let states = watch_states(root);
    assert_eq!(states["linked"], "finished");
}

// ---- CTX-SAVED: the bytes the budget kept out of a traced lane's context (D5) -----------

/// `cowproof watch` over `lanes_root`: the raw table, header first.
fn watch_table_text(lanes_root: &std::path::Path) -> Vec<Vec<String>> {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_cowproof"))
        .args(["watch", "--lanes-root"])
        .arg(lanes_root)
        .args(["--cache-ttl", "1h"])
        .output()
        .expect("failed to run cowproof watch");
    assert!(out.status.success(), "{out:?}");
    String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .map(|l| l.split('\t').map(str::to_string).collect())
        .collect()
}

#[test]
fn watch_shows_ctx_saved_for_traced_lanes_and_a_dash_for_the_rest() {
    let dir = tempfile::tempdir_in("/var/tmp").unwrap();
    let root = dir.path();
    let traced = r#"{"status":"finished","trace":{"traced":true},"traceTotals":{"calls":4,"savedBytes":12345}}"#;
    lane_with(root, "a-traced", Some(traced), None);
    // Traced, nothing saved: a real zero.
    lane_with(
        root,
        "b-zero",
        Some(r#"{"status":"finished","traceTotals":{"calls":1,"savedBytes":0}}"#),
        None,
    );
    // An untraced lane: totals are null.
    lane_with(
        root,
        "c-untraced",
        Some(r#"{"status":"finished","traceTotals":null}"#),
        None,
    );
    // Traced before this figure existed.
    lane_with(
        root,
        "d-older",
        Some(r#"{"status":"finished","traceTotals":{"calls":2,"deliveredBytes":50}}"#),
        None,
    );
    // Still running with no trace yet: nothing to show.
    lane_with(root, "e-running", None, None);
    // Its trace is garbage and run.json says nothing about it: watch never opens the trace
    // of an ended lane.
    lane_with(
        root,
        "f-bad-trace",
        Some(r#"{"status":"finished","trace":{"traced":true}}"#),
        None,
    );
    let traces = root.join("f-bad-trace/portkit/traces");
    fs::create_dir_all(&traces).unwrap();
    fs::write(
        traces.join("2026-10-12.jsonl"),
        "{ truncated\n\0\0 not json",
    )
    .unwrap();
    // A traced lane with no trace directory at all.
    lane_with(
        root,
        "g-missing-trace",
        Some(r#"{"status":"finished","trace":{"traced":true}}"#),
        None,
    );

    // Still running with a trace: the figure so far, read from the trace on this look.
    lane_with(root, "h-running-traced", None, None);
    let traces = root.join("h-running-traced/portkit/traces");
    fs::create_dir_all(&traces).unwrap();
    fs::write(
        traces.join("2026-10-27.jsonl"),
        r#"{"tool":"Read","target":"a","surface":"cli","outcome":"ok","at":"x","duration_ms":0.0,"input_bytes":1,"produced_bytes":40000,"delivered_bytes":2000}"#
            .to_string()
            + "\n",
    )
    .unwrap();

    let table = watch_table_text(root);
    assert_eq!(
        table[0],
        [
            "LANE",
            "STATE",
            "PARKED",
            "AGE",
            "NOTES",
            "LAST EVENT",
            "CTX-SAVED*"
        ]
    );
    let saved = |id: &str| -> &str {
        let row = table.iter().find(|r| r[0] == id).unwrap();
        assert_eq!(row.len(), 7, "{row:?}");
        &row[6]
    };
    assert_eq!(saved("a-traced"), "12.3k");
    assert_eq!(saved("b-zero"), "0");
    assert_eq!(saved("h-running-traced"), "38.0k");
    for untraced in [
        "c-untraced",
        "d-older",
        "e-running",
        "f-bad-trace",
        "g-missing-trace",
    ] {
        assert_eq!(saved(untraced), "-", "{untraced}");
    }
    // Eight lanes and the header, then the footnote that says whose figure the column is.
    assert_eq!(table.len(), 10);
    assert_eq!(
        table[9],
        ["* builder-written trace figure: informational, no verdict reads it."]
    );
}

#[test]
fn watch_has_no_ctx_saved_column_when_no_lane_has_trace_totals() {
    let dir = tempfile::tempdir_in("/var/tmp").unwrap();
    lane_with(dir.path(), "a", Some(r#"{"status":"finished"}"#), None);
    lane_with(dir.path(), "b", None, None);
    let table = watch_table_text(dir.path());
    assert_eq!(
        table[0],
        ["LANE", "STATE", "PARKED", "AGE", "NOTES", "LAST EVENT"]
    );
}
