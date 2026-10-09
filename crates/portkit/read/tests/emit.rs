//! The emit contract.
//!
//! `reference` is the one fidelity class that can produce a silent wrong
//! answer: the agent proceeds on stale content believing it is current, and
//! nothing in the transcript reveals it. Every other class degrades to "less
//! than you asked for", which is recoverable. So most of these tests are about
//! when UNCHANGED must *not* be claimed.

use std::path::Path;
use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_pk-read")
}

struct Session {
    dir: tempfile::TempDir,
}

impl Session {
    fn new(lines: usize) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let body: String = (1..=lines).map(|i| format!("line {i} content\n")).collect();
        std::fs::write(dir.path().join("f.txt"), body).unwrap();
        Self { dir }
    }

    fn run(&self, args: &[&str]) -> String {
        let out = Command::new(bin())
            .args(args)
            .current_dir(self.dir.path())
            .env("PORTKIT_SESSION", "test")
            .env("PORTKIT_STATE_DIR", self.dir.path().join("state"))
            .output()
            .expect("pk-read must run");
        String::from_utf8_lossy(&out.stdout).to_string()
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }
}

#[test]
fn a_first_read_returns_the_content() {
    let s = Session::new(100);
    let out = s.run(&["--range", "40:50", "f.txt"]);
    assert!(out.contains("40\u{2502}line 40"), "{out}");
    assert!(out.contains("50\u{2502}line 50"), "{out}");
    assert!(!out.contains("UNCHANGED"));
}

#[test]
fn a_fully_held_range_returns_a_reference_not_the_content() {
    let s = Session::new(100);
    s.run(&["--range", "40:50", "f.txt"]);
    let out = s.run(&["--range", "40:50", "f.txt"]);
    assert!(out.starts_with("UNCHANGED L40-50"), "{out}");
    assert!(
        !out.contains("line 40 content"),
        "content should not repeat: {out}"
    );
}

#[test]
fn an_overlapping_range_sends_only_the_gap() {
    // The measured case: 53 of 113 consecutive range pairs overlap.
    let s = Session::new(200);
    s.run(&["--range", "40:80", "f.txt"]);
    let out = s.run(&["--range", "60:100", "f.txt"]);

    assert!(
        out.contains("KNOWN L60-80"),
        "must declare what is withheld: {out}"
    );
    assert!(
        !out.contains("70\u{2502}"),
        "line 70 was already sent: {out}"
    );
    assert!(
        out.contains("81\u{2502}"),
        "line 81 is new and must be sent: {out}"
    );
    assert!(out.contains("100\u{2502}"), "{out}");
}

#[test]
fn every_withheld_answer_names_its_recovery() {
    // Same reason the budget hint exists: "truncated" with no next step sends
    // the caller to get it another way.
    let s = Session::new(100);
    s.run(&["--range", "10:20", "f.txt"]);

    let unchanged = s.run(&["--range", "10:20", "f.txt"]);
    assert!(unchanged.contains("--full"), "{unchanged}");

    let partial = s.run(&["--range", "15:30", "f.txt"]);
    assert!(partial.contains("--full"), "{partial}");
}

#[test]
fn full_ignores_session_state_or_recovery_does_not_recover() {
    let s = Session::new(100);
    s.run(&["--range", "10:20", "f.txt"]);
    let out = s.run(&["--range", "10:20", "f.txt", "--full"]);
    assert!(out.contains("10\u{2502}line 10"), "{out}");
    assert!(!out.contains("UNCHANGED"), "{out}");
}

#[test]
fn a_changed_file_is_never_reported_as_unchanged() {
    // The dangerous failure: stale content believed current.
    let s = Session::new(100);
    s.run(&["--range", "10:20", "f.txt"]);

    let body: String = (1..=100).map(|i| format!("EDITED {i}\n")).collect();
    std::fs::write(s.path().join("f.txt"), body).unwrap();

    let out = s.run(&["--range", "10:20", "f.txt"]);
    assert!(
        !out.contains("UNCHANGED"),
        "claimed unchanged after an edit: {out}"
    );
    assert!(out.contains("EDITED 10"), "{out}");
}

#[test]
fn compaction_stops_the_reference_claim() {
    let s = Session::new(100);
    s.run(&["--range", "10:20", "f.txt"]);
    assert!(s.run(&["--range", "10:20", "f.txt"]).contains("UNCHANGED"));

    s.run(&["--compacted"]);
    let out = s.run(&["--range", "10:20", "f.txt"]);
    assert!(
        !out.contains("UNCHANGED"),
        "delivery survived compaction: {out}"
    );
    assert!(out.contains("10\u{2502}line 10"), "{out}");
}

#[test]
fn separate_sessions_do_not_share_deliveries() {
    // A fresh worker has a fresh context; telling it UNCHANGED would be wrong.
    let s = Session::new(100);
    s.run(&["--range", "10:20", "f.txt"]);

    let out = Command::new(bin())
        .args(["--range", "10:20", "f.txt"])
        .current_dir(s.path())
        .env("PORTKIT_SESSION", "a-different-worker")
        .env("PORTKIT_STATE_DIR", s.path().join("state"))
        .output()
        .unwrap();
    let out = String::from_utf8_lossy(&out.stdout);
    assert!(!out.contains("UNCHANGED"), "leaked across sessions: {out}");
}

#[test]
fn ls_mode_drops_the_columns_nobody_reads_back() {
    let s = Session::new(10);
    std::fs::write(s.path().join("other.txt"), "x").unwrap();
    let out = s.run(&["--ls", "."]);
    assert!(out.contains("f.txt"), "{out}");
    assert!(out.contains("other.txt"), "{out}");
    // No permission bits, owner, or timestamps.
    assert!(!out.contains("rw-"), "{out}");
}
