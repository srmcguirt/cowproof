//! Reading a lane's portkit trace, once, for everything that reads it (D5, D23).
//!
//! A lane's `PORTKIT_STATE_DIR` is `<lane>/portkit` and `[trace] dir` resolves to
//! `<state>/traces`, so the trace is `<lane>/portkit/traces/*.jsonl`, one
//! `portkit_core::trace::CallRecord` per line. [`read_lane_traces`] is the safe walk: no
//! symlink is followed at any step (the lane's `portkit` directory, its `traces` directory
//! and each trace file are all builder-writable), a file larger than 32 MiB is unreadable,
//! and a line that is not a record is counted, not fatal. `cowproof report port-candidates`
//! and the runner's lane-end totals both read through it, so there is one trace parser.

use cowproof_prove::{ToolTotals, TraceTotals};
use portkit_core::trace::CallRecord;
use std::fs;
use std::io::Read;
use std::path::Path;

/// A trace file larger than this is unreadable (a day of one lane is KBs).
pub const MAX_FILE_BYTES: u64 = 32 * 1024 * 1024;

/// What the walk of one lane concluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaneState {
    /// At least one trace file was read.
    Traced,
    /// No trace file: no `portkit/traces` directory, or nothing readable in it.
    Untraced,
    /// The walk stopped at a symlink or an unreadable directory (counted in `symlinked` or
    /// `unreadable`); the lane is neither traced nor untraced.
    Skipped,
}

/// Everything read from one lane's trace directory.
#[derive(Debug)]
pub struct LaneTraces {
    pub state: LaneState,
    /// Trace files read.
    pub files: usize,
    /// Symlinks skipped: the `portkit` or `traces` directory, or a trace file.
    pub symlinked: usize,
    /// Directories and files that could not be read, or were too large.
    pub unreadable: usize,
    /// Lines that did not parse as records.
    pub malformed_lines: usize,
    pub records: Vec<CallRecord>,
}

/// `<lane>/portkit/traces/*.jsonl`, with no link followed at any step.
pub fn read_lane_traces(lane_dir: &Path) -> LaneTraces {
    let mut out = LaneTraces {
        state: LaneState::Untraced,
        files: 0,
        symlinked: 0,
        unreadable: 0,
        malformed_lines: 0,
        records: Vec::new(),
    };
    let mut traces = lane_dir.to_path_buf();
    for part in ["portkit", "traces"] {
        traces.push(part);
        match fs::symlink_metadata(&traces) {
            Ok(m) if m.file_type().is_symlink() => {
                out.symlinked += 1;
                out.state = LaneState::Skipped;
                return out;
            }
            Ok(m) if m.is_dir() => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return out,
            _ => {
                out.unreadable += 1;
                out.state = LaneState::Skipped;
                return out;
            }
        }
    }
    let Ok(read) = fs::read_dir(&traces) else {
        out.unreadable += 1;
        out.state = LaneState::Skipped;
        return out;
    };
    let mut files: Vec<_> = read.filter_map(Result::ok).collect();
    files.sort_by_key(|e| e.file_name());
    for file in files {
        let path = file.path();
        if path.extension().is_none_or(|ext| ext != "jsonl") {
            continue;
        }
        let Ok(kind) = file.file_type() else {
            out.unreadable += 1;
            continue;
        };
        if kind.is_symlink() {
            out.symlinked += 1;
            continue;
        }
        if !kind.is_file() {
            continue;
        }
        match read_bounded(&path) {
            Some(bytes) => {
                out.files += 1;
                parse_records(&bytes, &mut out);
            }
            None => out.unreadable += 1,
        }
    }
    if out.files > 0 {
        out.state = LaneState::Traced;
    }
    out
}

/// The file, or none when it is too large or cannot be read. The read is bounded as well
/// as the size checked: a file can grow between the two.
fn read_bounded(path: &Path) -> Option<Vec<u8>> {
    if fs::metadata(path).ok()?.len() > MAX_FILE_BYTES {
        return None;
    }
    let mut bytes = Vec::new();
    fs::File::open(path)
        .ok()?
        .take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    (bytes.len() as u64 <= MAX_FILE_BYTES).then_some(bytes)
}

fn parse_records(bytes: &[u8], out: &mut LaneTraces) {
    for line in bytes.split(|b| *b == b'\n') {
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        match serde_json::from_slice::<CallRecord>(line) {
            Ok(record) => out.records.push(record),
            Err(_) => out.malformed_lines += 1,
        }
    }
}

/// The lane's totals: `None` when no trace file was read (an untraced lane has none, and a
/// walk that was skipped has none either).
pub fn lane_trace_totals(lane_dir: &Path) -> Option<TraceTotals> {
    let traces = read_lane_traces(lane_dir);
    (traces.state == LaneState::Traced)
        .then(|| trace_totals(&traces.records, traces.malformed_lines as u64))
}

/// Add up records: calls and delivered bytes by tool, the sums, and what `pk-read` delivered.
pub fn trace_totals(records: &[CallRecord], malformed_lines: u64) -> TraceTotals {
    let mut totals = TraceTotals {
        malformed_lines,
        ..TraceTotals::default()
    };
    for record in records {
        let delivered = record.delivered_bytes as u64;
        totals.calls += 1;
        totals.delivered_bytes = totals.delivered_bytes.saturating_add(delivered);
        totals.produced_bytes = totals
            .produced_bytes
            .saturating_add(record.produced_bytes as u64);
        let tool: &mut ToolTotals = totals.by_tool.entry(record.tool.clone()).or_default();
        tool.calls += 1;
        tool.delivered_bytes = tool.delivered_bytes.saturating_add(delivered);
        if record.tool == "Bash" && record.target.as_deref().is_some_and(runs_pk_read) {
            totals.pk_read.calls += 1;
            totals.pk_read.delivered_bytes =
                totals.pk_read.delivered_bytes.saturating_add(delivered);
        }
    }
    totals
}

/// Whether a `Bash` record's target (the first two words of the command, cut at 60
/// characters) runs `pk-read`: its program, after leading `NAME=value` words, is `pk-read`
/// by any path. `cd dir && pk-read x` is `cd dir` in the trace and cannot be told.
fn runs_pk_read(target: &str) -> bool {
    target
        .split_whitespace()
        .find(|word| !is_env_assignment(word))
        .is_some_and(|program| program.rsplit('/').next() == Some("pk-read"))
}

fn is_env_assignment(word: &str) -> bool {
    let Some((name, _)) = word.split_once('=') else {
        return false;
    };
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;
    use portkit_core::trace::{Outcome, Surface};

    fn record(tool: &str, target: Option<&str>, delivered: usize) -> CallRecord {
        CallRecord {
            tool: tool.into(),
            session: String::new(),
            target: target.map(str::to_string),
            surface: Surface::Agent,
            outcome: Outcome::Ok,
            at: "2026-10-11T00:00:00Z".into(),
            duration_ms: 0.0,
            input_bytes: 1,
            produced_bytes: delivered + 5,
            delivered_bytes: delivered,
            elisions: 0,
        }
    }

    #[test]
    fn totals_add_calls_and_bytes_by_tool_and_find_pk_read() {
        let records = [
            record("Read", Some("a.rs"), 100),
            record("Read", Some("b.rs"), 10),
            record("Bash", Some("cargo test"), 1000),
            record("Bash", Some("pk-read src/x.rs"), 7),
            record("Bash", Some("/opt/bin/pk-read --ls"), 3),
            record("Bash", Some("PK=1 pk-read x"), 2),
            record("Bash", Some("echo pk-read"), 4),
            record("Grep", None, 0),
        ];
        let t = trace_totals(&records, 2);
        assert_eq!(t.calls, 8);
        assert_eq!(t.delivered_bytes, 100 + 10 + 1000 + 7 + 3 + 2 + 4);
        assert_eq!(t.produced_bytes, t.delivered_bytes + 5 * 8);
        assert_eq!(t.malformed_lines, 2);
        assert_eq!(
            t.by_tool["Read"],
            ToolTotals {
                calls: 2,
                delivered_bytes: 110
            }
        );
        assert_eq!(t.by_tool["Bash"].calls, 5);
        assert_eq!(t.by_tool["Grep"].calls, 1);
        assert_eq!(
            t.pk_read,
            ToolTotals {
                calls: 3,
                delivered_bytes: 12
            }
        );
    }

    #[test]
    fn a_lane_with_no_trace_directory_has_no_totals() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(lane_trace_totals(dir.path()), None);
        assert_eq!(read_lane_traces(dir.path()).state, LaneState::Untraced);
    }
}
