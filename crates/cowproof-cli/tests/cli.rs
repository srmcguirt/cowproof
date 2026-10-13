//! Tests for cowproof CLI basic functionality.

use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_cowproof")
}

/// `--version` prints the program name and the workspace version, which this
/// crate takes from `[workspace.package]` (`version.workspace = true`).
#[test]
fn cowproof_version_prints_the_workspace_version() {
    let output = Command::new(bin())
        .arg("--version")
        .output()
        .expect("failed to run cowproof --version");

    assert!(
        output.status.success(),
        "cowproof --version exited {:?}: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(
        stdout.trim_end(),
        format!("cowproof {}", env!("CARGO_PKG_VERSION"))
    );
}

/// The top-level error print escapes lane-derived text. `cowproof run` names a packet path in
/// its error context; a path with `ESC [2J` in it must reach stderr as an escape, never as the
/// control character, and the chain's own lines (`Caused by:`) stay lines.
#[test]
fn the_top_level_error_escapes_a_control_character_in_a_path() {
    let home = tempfile::tempdir_in("/var/tmp").unwrap();
    let packet = home.path().join("lane\u{1b}[2J\u{9b}31m.md");
    let output = Command::new(bin())
        .arg("run")
        .arg(&packet)
        .env("HOME", home.path())
        .output()
        .expect("failed to run cowproof run");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("lane\\u{1b}[2J\\u{9b}31m.md"),
        "the path is shown as an escape: {stderr:?}"
    );
    assert!(
        !stderr.chars().any(|c| c.is_control() && c != '\n'),
        "a control character reaches the terminal: {stderr:?}"
    );
    assert!(stderr.contains("\nCaused by:\n"), "{stderr:?}");
}
