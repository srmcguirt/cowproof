//! A reader that returns only what the caller does not already have.
//!
//! Measured motivation, from 878 local sessions: `sed -n 'A,Bp' file` accounts
//! for 397 calls and 1.83 MB, the largest single shell fingerprint. Those are
//! not repeats of identical ranges — keying on the exact `(path, start, end)`
//! tuple finds **zero**. They are *overlapping* ranges: 53 of 113 consecutive
//! pairs cover territory already sent. Tracking line coverage rather than
//! ranges recovers 4.9% of those bytes.
//!
//! Not a large number, and worth saying so. What it buys beyond the bytes is a
//! verified rewrite path — the machinery a bigger replacement can then ride on.

pub mod state;

pub use state::{gaps, intersect, merge, FileState, Interval, SessionState};

use std::path::Path;

/// Content hash of a file, or `None` when it cannot be read.
///
/// blake3 rather than the cheap hash used elsewhere in portkit: a collision
/// here means claiming the caller holds current content when it does not, and
/// that failure is silent.
pub fn hash_file(path: &Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    Some(blake3::hash(&bytes).to_hex().to_string())
}

/// Where session state lives: `~/.portkit/read/`, never the working directory.
///
/// `PORTKIT_STATE_DIR` overrides it. That exists so tests can isolate — moving
/// state out of the working directory also moved it out of reach of a tempdir
/// — and it lets anyone put state somewhere other than home.
pub fn state_dir() -> std::path::PathBuf {
    if let Some(dir) = std::env::var_os("PORTKIT_STATE_DIR") {
        return std::path::PathBuf::from(dir);
    }
    std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join(".portkit")
        .join("read")
}

pub fn now_rfc3339() -> String {
    use time::format_description::well_known::Rfc3339;
    time::OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_default()
}
