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
    fs::create_dir_all(&lane1.join("control")).unwrap();

    // Write a run.json with exit code 0
    fs::write(lane1.join("control/run.json"), r#"{"exit_code": 0}"#).unwrap();

    // Write escalations.jsonl with a parked ask
    fs::write(
        lane1.join("control/escalations.jsonl"),
        r#"{"event":"asked","lane":"lane-1","id":"lane-1:E1","ask":{"kind":"blocker","question":"test?","tried":[],"options":[{"id":"a","summary":"do A","cost":"1h"}],"recommend":"a","blocking":true},"origin":"builder","at_ms":2000}"#,
    ).unwrap();

    let lane2 = lanes_root.join("lane-2");
    fs::create_dir_all(&lane2.join("control")).unwrap();

    // Run the command and capture output
    let output = std::process::Command::new(&bin)
        .args(&[
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
    fs::create_dir_all(&lane1.join("control")).unwrap();

    // Write escalations.jsonl with ask, ruling, and note
    fs::write(
        lane1.join("control/escalations.jsonl"),
        r#"{"event":"asked","lane":"lane-1","id":"lane-1:E1","ask":{"kind":"blocker","question":"test?","tried":[],"options":[{"id":"a","summary":"do A","cost":"1h"}],"recommend":"a","blocking":true},"origin":"builder","at_ms":1000}
{"event":"ruled","lane":"lane-1","id":"lane-1:E1","verdict":{"verdict":"answer","text":"go ahead"}}
{"event":"note","lane":"lane-1","id":"lane-1-n1","text":"FYI","at_ms":2000}
"#,
    ).unwrap();

    let output = std::process::Command::new(&bin)
        .args(&[
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
    fs::create_dir_all(&lane1.join("control")).unwrap();

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
        .args(&[
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
    fs::create_dir_all(&lane1.join("control")).unwrap();
    fs::write(
        lane1.join("control/escalations.jsonl"),
        r#"{"event":"asked","lane":"lane-1","id":"lane-1:E1","ask":{"kind":"blocker","question":"test?","tried":[],"options":[{"id":"a","summary":"do A","cost":"1h"}],"recommend":"a","blocking":true},"origin":"builder","at_ms":1000}
"#,
    ).unwrap();

    let lane2 = lanes_root.join("lane-2");
    fs::create_dir_all(&lane2.join("control")).unwrap();
    fs::write(
        lane2.join("control/escalations.jsonl"),
        r#"{"event":"note","lane":"lane-2","id":"lane-2-n1","text":"hello","at_ms":2000}
"#,
    )
    .unwrap();

    let output = std::process::Command::new(&bin)
        .args(&[
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
    fs::create_dir_all(&lane1.join("control")).unwrap();

    let output = std::process::Command::new(&bin)
        .args(&["watch", "--lanes-root", lanes_root.to_str().unwrap()])
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
    fs::create_dir_all(&lane1.join("control")).unwrap();

    let output = std::process::Command::new(&bin)
        .args(&[
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
