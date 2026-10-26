//! Integration tests that read above the crate.
//!
//! Most of `cowproof`'s tests read only what the published crate contains. A few check a
//! property of the whole repository (no Rust file anywhere runs the `kill` program, the
//! Claude Code plugin agrees with the workspace version, the report crate's fixtures
//! render the same through the CLI). They need the checkout: `crates/cowproof-cli` two
//! levels below a workspace root that holds `plugin/`, `fixtures/` and the other crates.
//! In the `cowproof` tarball that root does not exist, so those tests print a note and
//! return, and the workspace run still exercises them.
//!
//! CI sets `COWPROOF_WORKSPACE_TESTS=1`: with it, a missing workspace is a failure, so a
//! gate that always skips (a moved crate, a wrong path) cannot go unnoticed.
//!
//! Included with `#[path = "common/workspace.rs"] mod workspace;` by the test files that
//! need it, so a file that does not need it carries none of it.

use std::path::{Path, PathBuf};

/// The workspace root when this crate is checked out as `crates/cowproof-cli` of it,
/// canonical, else `None`.
pub fn root() -> Option<PathBuf> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).canonicalize().ok()?;
    let root = manifest.parent()?.parent()?.to_path_buf();
    let workspace = std::fs::read_to_string(root.join("Cargo.toml")).ok()?;
    let here = root.join("crates/cowproof-cli").canonicalize().ok()?;
    (workspace.contains("[workspace]") && here == manifest).then_some(root)
}

/// Panics when `COWPROOF_WORKSPACE_TESTS=1` demands the workspace and it is absent.
pub fn demand(what: &str) {
    assert!(
        root().is_some() || std::env::var("COWPROOF_WORKSPACE_TESTS").as_deref() != Ok("1"),
        "{what}: COWPROOF_WORKSPACE_TESTS=1 but the workspace root was not found two levels \
         above {}",
        env!("CARGO_MANIFEST_DIR")
    );
}

/// Whether the test named `what` must be skipped because the workspace is absent. Prints
/// the skip, and panics instead when `COWPROOF_WORKSPACE_TESTS=1` says it must run.
#[allow(dead_code, reason = "`no_kill_binary` uses `demand` and `root` only")]
pub fn skipped(what: &str) -> bool {
    demand(what);
    if root().is_some() {
        return false;
    }
    eprintln!(
        "skipped {what}: it reads the repository above the crate, which the published \
         crate does not contain"
    );
    true
}
