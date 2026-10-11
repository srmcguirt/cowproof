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
