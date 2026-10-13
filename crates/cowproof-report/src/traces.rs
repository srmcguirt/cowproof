//! Reading a lane's portkit trace, once, for everything that reads it (D5, D23).
//!
//! A lane's `PORTKIT_STATE_DIR` is `<lane>/portkit` and `[trace] dir` resolves to
//! `<state>/traces`, so the trace is `<lane>/portkit/traces/*.jsonl`, one
//! `portkit_core::trace::CallRecord` per line. [`read_lane_traces`] is the safe walk: no
//! symlink is followed at any step (the lane's `portkit` directory, its `traces` directory
//! and each trace file are all builder-writable), a file larger than 32 MiB is unreadable,
//! the walk as a whole stops at 64 MiB and 256 files (what is left is counted, not read), only
//! the 4096 smallest names of the directory are ever held,
//! and a line that is not a record is counted, not fatal. `cowproof report port-candidates`
//! and the runner's lane-end totals both read through it, so there is one trace parser.

use cowproof_prove::{ToolTotals, TraceTotals};
use portkit_core::trace::{CallRecord, Summary};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BinaryHeap, HashSet};
use std::fs;
use std::io::Read;
use std::path::Path;

/// A trace file larger than this is unreadable (a day of one lane is KBs).
pub const MAX_FILE_BYTES: u64 = 32 * 1024 * 1024;

/// The walk of one lane reads at most this many bytes of trace in all (audit S-5): the bound
/// on a file is per file, and the records of every file are held in memory at once. Twice the
/// largest single file, and ten thousand times a day of one lane.
pub const MAX_LANE_BYTES: u64 = 64 * 1024 * 1024;

/// The walk of one lane reads at most this many trace files (audit S-5). A lane writes one
/// file a day.
pub const MAX_LANE_FILES: usize = 256;

/// The walk of one lane lists at most this many `.jsonl` names from the `traces` directory
/// (S-5 follow-up): a builder owns that directory and can fill it with millions of entries,
/// and the director's process held every one to sort them. Only this many entries are held
/// at a time, and they are the smallest by name, so what is read does not depend on the order
/// the directory returns names in. The names beyond it are counted in `unread_files`.
pub const MAX_LANE_LISTING: usize = 4096;

/// `by_tool` keeps this many tool names; the rest are folded into [`OTHER_TOOLS`] (audit S-5).
pub const MAX_TOOL_NAMES: usize = 64;

/// A tool name is cut to this many bytes (on a character boundary) before it is a key.
pub const MAX_TOOL_NAME_BYTES: usize = 64;

/// The `by_tool` entry that holds the calls and bytes of every folded tool name.
pub const OTHER_TOOLS: &str = "other";

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
    /// Trace files not read because the lane had passed [`MAX_LANE_BYTES`] or
    /// [`MAX_LANE_FILES`]. The lane is still `Traced`; the totals cover the files before.
    pub unread_files: usize,
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
        unread_files: 0,
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
    let (files, overflow) = list_bounded(read, MAX_LANE_LISTING);
    out.unread_files += overflow;
    let mut budget = MAX_LANE_BYTES;
    for file in files {
        let path = file.path();
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
        if out.files >= MAX_LANE_FILES {
            out.unread_files += 1;
            continue;
        }
        match read_bounded(&path, budget) {
            Ok(bytes) => {
                budget -= bytes.len() as u64;
                out.files += 1;
                parse_records(&bytes, &mut out);
            }
            Err(Unread::Unreadable) => out.unreadable += 1,
            Err(Unread::OverBudget) => out.unread_files += 1,
        }
    }
    if out.files > 0 {
        out.state = LaneState::Traced;
    }
    out
}

/// A directory entry ordered by its name, for the bounded listing.
struct Named(fs::DirEntry);

impl PartialEq for Named {
    fn eq(&self, other: &Self) -> bool {
        self.0.file_name() == other.0.file_name()
    }
}

impl Eq for Named {}

impl PartialOrd for Named {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Named {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.file_name().cmp(&other.0.file_name())
    }
}

/// The `.jsonl` entries of `read` with the `limit` smallest names, sorted by name, and how
/// many more `.jsonl` entries there were. The whole directory is walked but at most `limit`
/// entries are held: a max-heap on the name drops the largest whenever it is full. A
/// directory returns its names in an order of its own, so stopping after `limit` entries
/// would read a different set on each run; keeping the smallest names reads the same set
/// whatever the order (a name is unique in a directory, so there are no ties).
fn list_bounded(read: fs::ReadDir, limit: usize) -> (Vec<fs::DirEntry>, usize) {
    let mut heap: BinaryHeap<Named> = BinaryHeap::with_capacity(limit.min(1024) + 1);
    let mut overflow = 0usize;
    for entry in read.filter_map(Result::ok) {
        if Path::new(&entry.file_name())
            .extension()
            .is_none_or(|ext| ext != "jsonl")
        {
            continue;
        }
        heap.push(Named(entry));
        if heap.len() > limit {
            heap.pop();
            overflow += 1;
        }
    }
    let files = heap.into_sorted_vec().into_iter().map(|n| n.0).collect();
    (files, overflow)
}

/// Why a trace file was not read.
enum Unread {
    /// Larger than [`MAX_FILE_BYTES`], or it could not be read.
    Unreadable,
    /// Within the file bound, but more than the lane has left of [`MAX_LANE_BYTES`].
    OverBudget,
}

/// The file, or why not. The read is bounded as well as the size checked: a file can grow
/// between the two. `budget` is what the lane has left of its aggregate bound.
fn read_bounded(path: &Path, budget: u64) -> Result<Vec<u8>, Unread> {
    let len = fs::metadata(path).map_err(|_| Unread::Unreadable)?.len();
    if len > MAX_FILE_BYTES {
        return Err(Unread::Unreadable);
    }
    if len > budget {
        return Err(Unread::OverBudget);
    }
    let mut bytes = Vec::new();
    fs::File::open(path)
        .map_err(|_| Unread::Unreadable)?
        .take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Unread::Unreadable)?;
    let read = bytes.len() as u64;
    if read > MAX_FILE_BYTES {
        Err(Unread::Unreadable)
    } else if read > budget {
        Err(Unread::OverBudget)
    } else {
        Ok(bytes)
    }
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
/// walk that was skipped has none either). A lane past the aggregate bound is still traced:
/// its totals cover the files read and `unread_files` says how many were left.
pub fn lane_trace_totals(lane_dir: &Path) -> Option<TraceTotals> {
    let traces = read_lane_traces(lane_dir);
    (traces.state == LaneState::Traced).then(|| {
        let mut totals = trace_totals(&traces.records, traces.malformed_lines as u64);
        totals.unread_files = traces.unread_files as u64;
        totals
    })
}

/// `name` cut to [`MAX_TOOL_NAME_BYTES`] bytes at a character boundary.
fn cut_tool_name(name: &str) -> &str {
    if name.len() <= MAX_TOOL_NAME_BYTES {
        return name;
    }
    let mut end = MAX_TOOL_NAME_BYTES;
    while !name.is_char_boundary(end) {
        end -= 1;
    }
    &name[..end]
}

/// Keep the [`MAX_TOOL_NAMES`] busiest tools (most calls; the name breaks a tie) and fold the
/// rest into [`OTHER_TOOLS`], adding to a real tool of that name if it is among the kept.
/// Returns how many names were folded. A pure function of the map.
fn fold_tools(by_tool: &mut BTreeMap<String, ToolTotals>) -> u64 {
    if by_tool.len() <= MAX_TOOL_NAMES {
        return 0;
    }
    let mut ranked: Vec<(String, ToolTotals)> = std::mem::take(by_tool).into_iter().collect();
    ranked.sort_by(|a, b| b.1.calls.cmp(&a.1.calls).then_with(|| a.0.cmp(&b.0)));
    let folded = ranked.split_off(MAX_TOOL_NAMES);
    by_tool.extend(ranked);
    let other: &mut ToolTotals = by_tool.entry(OTHER_TOOLS.to_string()).or_default();
    for (_, tool) in &folded {
        other.calls = other.calls.saturating_add(tool.calls);
        other.delivered_bytes = other.delivered_bytes.saturating_add(tool.delivered_bytes);
    }
    folded.len() as u64
}

/// Add up records: calls, rejected calls, produced, delivered and saved bytes (portkit's own
/// [`Summary`], so the sums are the ones `pk trace` prints), the re-read rate, calls and
/// delivered bytes by tool (at most [`MAX_TOOL_NAMES`] names, each cut to
/// [`MAX_TOOL_NAME_BYTES`]; the rest folded into [`OTHER_TOOLS`] and counted), and what
/// `pk-read` delivered. This is the one place the lane totals are computed, and a pure
/// function of the records.
pub fn trace_totals(records: &[CallRecord], malformed_lines: u64) -> TraceTotals {
    let mut summary = Summary::default();
    let mut seen: HashSet<(&str, &str)> = HashSet::new();
    let (mut targeted, mut reread) = (0u64, 0u64);
    let mut totals = TraceTotals {
        malformed_lines,
        ..TraceTotals::default()
    };
    for record in records {
        summary.add(record);
        let delivered = record.delivered_bytes as u64;
        if let Some(target) = record.target.as_deref() {
            targeted += 1;
            // `insert` is false when the pair was already there: this call is a re-read.
            if !seen.insert((record.tool.as_str(), target)) {
                reread += 1;
            }
        }
        let tool: &mut ToolTotals = totals
            .by_tool
            .entry(cut_tool_name(&record.tool).to_string())
            .or_default();
        tool.calls += 1;
        tool.delivered_bytes = tool.delivered_bytes.saturating_add(delivered);
        if record.tool == "Bash" && record.target.as_deref().is_some_and(runs_pk_read) {
            totals.pk_read.calls += 1;
            totals.pk_read.delivered_bytes =
                totals.pk_read.delivered_bytes.saturating_add(delivered);
        }
    }
    totals.folded_tool_names = fold_tools(&mut totals.by_tool);
    totals.calls = summary.calls as u64;
    totals.rejected = summary.rejected as u64;
    totals.produced_bytes = summary.produced_bytes as u64;
    totals.delivered_bytes = summary.delivered_bytes as u64;
    totals.saved_bytes = summary.saved_bytes() as u64;
    totals.reread_rate = (targeted > 0).then(|| reread as f64 / targeted as f64);
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

    fn full(
        tool: &str,
        target: Option<&str>,
        outcome: Outcome,
        produced: usize,
        delivered: usize,
    ) -> CallRecord {
        CallRecord {
            outcome,
            produced_bytes: produced,
            delivered_bytes: delivered,
            ..record(tool, target, 0)
        }
    }

    #[test]
    fn totals_carry_saved_bytes_and_rejected_calls_the_way_portkit_sums_them() {
        let records = [
            full("Read", Some("a"), Outcome::Ok, 1000, 200),
            full("Read", Some("b"), Outcome::Ok, 500, 500),
            full("Edit", Some("c"), Outcome::Rejected, 30, 30),
            full("Edit", Some("d"), Outcome::Rejected, 30, 30),
            full("Bash", None, Outcome::Failed, 70, 10),
        ];
        let t = trace_totals(&records, 0);
        assert_eq!(t.calls, 5);
        assert_eq!(t.rejected, 2, "a failed call is not a rejected one");
        assert_eq!((t.produced_bytes, t.delivered_bytes), (1630, 770));
        assert_eq!(t.saved_bytes, 1630 - 770);

        // Summed, not per record: a call that delivered more than it produced does not make
        // the lane's saved bytes negative or hide the other calls' savings.
        let over = [
            full("Read", Some("a"), Outcome::Ok, 100, 400),
            full("Read", Some("b"), Outcome::Ok, 1000, 100),
        ];
        assert_eq!(trace_totals(&over, 0).saved_bytes, 1100 - 500);
        let all_over = [full("Read", Some("a"), Outcome::Ok, 1, 400)];
        assert_eq!(trace_totals(&all_over, 0).saved_bytes, 0);
        assert_eq!(trace_totals(&[], 0).saved_bytes, 0);
        assert_eq!(trace_totals(&[], 0).rejected, 0);
    }

    #[test]
    fn the_reread_rate_counts_a_repeated_tool_and_target_but_never_the_first_call() {
        let records = [
            record("Read", Some("a.rs"), 1),
            record("Read", Some("b.rs"), 1),
            record("Read", Some("a.rs"), 1),
            // The same target through another tool is not a re-read of the first tool's.
            record("Grep", Some("a.rs"), 1),
            record("Read", Some("a.rs"), 1),
            // No target: in neither the numerator nor the denominator.
            record("Bash", None, 1),
        ];
        let t = trace_totals(&records, 0);
        assert_eq!(t.calls, 6);
        // Five calls name a target; the third and the fifth repeat (Read, a.rs).
        assert_eq!(t.reread_rate, Some(2.0 / 5.0));

        let fresh = [record("Read", Some("a"), 1), record("Read", Some("b"), 1)];
        assert_eq!(trace_totals(&fresh, 0).reread_rate, Some(0.0));
        let one = [record("Read", Some("a"), 1)];
        assert_eq!(trace_totals(&one, 0).reread_rate, Some(0.0));
        let twice = [record("Read", Some("a"), 1), record("Read", Some("a"), 1)];
        assert_eq!(trace_totals(&twice, 0).reread_rate, Some(0.5));
    }

    #[test]
    fn the_reread_rate_is_null_when_no_call_names_a_target() {
        let records = [record("Read", None, 1), record("Bash", None, 1)];
        let t = trace_totals(&records, 0);
        assert_eq!(t.calls, 2);
        assert_eq!(t.reread_rate, None);
        assert_eq!(trace_totals(&[], 0).reread_rate, None);
        let json = serde_json::to_value(&t).unwrap();
        assert!(json["rereadRate"].is_null(), "{json}");
    }

    #[test]
    fn malformed_lines_do_not_count_as_calls_or_as_rereads() {
        let lane = tempfile::tempdir_in("/var/tmp").unwrap();
        let traces = lane.path().join("portkit/traces");
        fs::create_dir_all(&traces).unwrap();
        let good = |target: &str| {
            format!(
                r#"{{"tool":"Read","target":"{target}","surface":"agent","outcome":"ok","at":"x","duration_ms":0.0,"input_bytes":1,"produced_bytes":90,"delivered_bytes":40}}"#
            )
        };
        // A re-read of `a`, a cut-off line that also names `a`, and a line that is not JSON.
        let text = format!(
            "{}\n{}\n{{\"tool\":\"Read\",\"target\":\"a\",\"surf\nnot json\n",
            good("a"),
            good("a")
        );
        fs::write(traces.join("2026-10-12.jsonl"), text).unwrap();
        let t = lane_trace_totals(lane.path()).expect("a traced lane");
        assert_eq!(t.malformed_lines, 2);
        assert_eq!(t.calls, 2);
        assert_eq!(t.reread_rate, Some(0.5));
        assert_eq!((t.saved_bytes, t.rejected), (100, 0));
    }

    #[test]
    fn absurd_records_saturate_instead_of_panicking() {
        let records = [
            full("Read", Some("a"), Outcome::Ok, usize::MAX, usize::MAX),
            full("Read", Some("a"), Outcome::Ok, usize::MAX, 0),
        ];
        let t = trace_totals(&records, 0);
        assert_eq!(t.produced_bytes, u64::MAX);
        assert_eq!(t.delivered_bytes, u64::MAX);
        assert_eq!(t.saved_bytes, 0);
        assert_eq!(t.reread_rate, Some(0.5));
    }

    #[test]
    fn a_lane_with_no_trace_directory_has_no_totals() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(lane_trace_totals(dir.path()), None);
        assert_eq!(read_lane_traces(dir.path()).state, LaneState::Untraced);
    }

    #[test]
    fn more_than_64_tool_names_fold_into_other_with_their_calls_and_bytes_summed() {
        // Tool `t00` has 1 call, `t01` 2, ... `t64` 65: 65 names, the quietest one folds.
        let mut records = Vec::new();
        for n in 0..=64u64 {
            for _ in 0..=n {
                records.push(record(&format!("t{n:02}"), None, 3));
            }
        }
        let t = trace_totals(&records, 0);
        assert_eq!(t.folded_tool_names, 1);
        assert_eq!(t.by_tool.len(), MAX_TOOL_NAMES + 1);
        assert!(!t.by_tool.contains_key("t00"));
        assert_eq!(
            t.by_tool[OTHER_TOOLS],
            ToolTotals {
                calls: 1,
                delivered_bytes: 3
            }
        );
        // Nothing is lost: the by-tool calls and bytes still add up to the totals.
        assert_eq!(t.by_tool.values().map(|v| v.calls).sum::<u64>(), t.calls);
        assert_eq!(
            t.by_tool.values().map(|v| v.delivered_bytes).sum::<u64>(),
            t.delivered_bytes
        );

        // A hundred names fold thirty-six; the same records in another order total the same.
        let many: Vec<_> = (0..100)
            .map(|n| record(&format!("n{n:03}"), None, 1))
            .collect();
        let t = trace_totals(&many, 0);
        assert_eq!(t.folded_tool_names, 36);
        assert_eq!(t.by_tool[OTHER_TOOLS].calls, 36);
        let mut reversed = many.clone();
        reversed.reverse();
        assert_eq!(trace_totals(&reversed, 0), t);
    }

    #[test]
    fn exactly_64_tool_names_are_kept_whole() {
        let records: Vec<_> = (0..MAX_TOOL_NAMES)
            .map(|n| record(&format!("t{n}"), None, 1))
            .collect();
        let t = trace_totals(&records, 0);
        assert_eq!(t.folded_tool_names, 0);
        assert_eq!(t.by_tool.len(), MAX_TOOL_NAMES);
        assert!(!t.by_tool.contains_key(OTHER_TOOLS));
    }

    #[test]
    fn a_tool_name_is_cut_to_64_bytes_on_a_character_boundary() {
        let long = "T".repeat(1024);
        // Three bytes a character: 21 of them are 63 bytes, the 22nd would pass 64.
        let wide = "\u{20ac}".repeat(400);
        let t = trace_totals(&[record(&long, None, 1), record(&wide, None, 1)], 0);
        let names: Vec<&String> = t.by_tool.keys().collect();
        assert_eq!(names.len(), 2);
        assert!(
            names.iter().all(|n| n.len() <= MAX_TOOL_NAME_BYTES),
            "{names:?}"
        );
        assert!(t.by_tool.contains_key(&"T".repeat(64)));
        assert!(t.by_tool.contains_key(&"\u{20ac}".repeat(21)));
        // Two long names that share a 64-byte head are one tool; their calls add up.
        let a = format!("{}a", "S".repeat(64));
        let b = format!("{}b", "S".repeat(64));
        let t = trace_totals(&[record(&a, None, 1), record(&b, None, 2)], 0);
        assert_eq!(
            t.by_tool[&"S".repeat(64)],
            ToolTotals {
                calls: 2,
                delivered_bytes: 3
            }
        );
    }

    #[test]
    fn a_5_mib_tool_name_leaves_the_totals_small() {
        let t = trace_totals(&[record(&"T".repeat(5 * 1024 * 1024), None, 1)], 0);
        assert!(serde_json::to_vec(&t).unwrap().len() < 1024);
    }

    #[test]
    fn the_totals_are_marked_builder_written_and_older_totals_read_as_such() {
        let t = trace_totals(&[], 0);
        assert!(t.builder_written);
        let json = serde_json::to_value(&t).unwrap();
        assert_eq!(json["builderWritten"], true, "{json}");
        assert_eq!(json["foldedToolNames"], 0);
        assert_eq!(json["unreadFiles"], 0);

        // A capsule written before the marker, the fold count and the walk bound.
        let old: TraceTotals = serde_json::from_value(serde_json::json!({
            "calls": 2,
            "deliveredBytes": 5,
            "producedBytes": 6,
            "byTool": {"Read": {"calls": 2, "deliveredBytes": 5}},
            "pkRead": {"calls": 0, "deliveredBytes": 0},
            "malformedLines": 0,
        }))
        .unwrap();
        assert!(old.builder_written, "its figures were builder-written too");
        assert_eq!((old.folded_tool_names, old.unread_files), (0, 0));
        assert_eq!(old.calls, 2);
    }

    fn trace_file(traces: &Path, name: &str, extra_bytes: u64) {
        let path = traces.join(name);
        fs::write(&path, line() + "\n").unwrap();
        if extra_bytes > 0 {
            let len = fs::metadata(&path).unwrap().len();
            // Sparse zeros after the record: one malformed line, no disk used.
            fs::OpenOptions::new()
                .write(true)
                .open(&path)
                .unwrap()
                .set_len(len + extra_bytes)
                .unwrap();
        }
    }

    fn line() -> String {
        r#"{"tool":"Read","target":"a","surface":"agent","outcome":"ok","at":"x","duration_ms":0.0,"input_bytes":1,"produced_bytes":90,"delivered_bytes":40}"#.to_string()
    }

    #[test]
    fn the_walk_stops_at_the_aggregate_byte_bound_and_counts_what_it_left() {
        let lane = tempfile::tempdir_in("/var/tmp").unwrap();
        let traces = lane.path().join("portkit/traces");
        fs::create_dir_all(&traces).unwrap();
        // Three files of 30 MiB (each under the file bound): two fit in 64 MiB, not three.
        for name in ["a.jsonl", "b.jsonl", "c.jsonl"] {
            trace_file(&traces, name, 30 * 1024 * 1024);
        }
        let walk = read_lane_traces(lane.path());
        assert_eq!(walk.state, LaneState::Traced);
        assert_eq!((walk.files, walk.unread_files, walk.unreadable), (2, 1, 0));
        assert_eq!(walk.records.len(), 2);
        let t = lane_trace_totals(lane.path()).expect("still traced");
        assert_eq!((t.calls, t.unread_files), (2, 1));
    }

    #[test]
    fn the_walk_stops_at_the_file_count_bound_and_counts_what_it_left() {
        let lane = tempfile::tempdir_in("/var/tmp").unwrap();
        let traces = lane.path().join("portkit/traces");
        fs::create_dir_all(&traces).unwrap();
        for n in 0..MAX_LANE_FILES + 5 {
            trace_file(&traces, &format!("{n:04}.jsonl"), 0);
        }
        let walk = read_lane_traces(lane.path());
        assert_eq!(walk.state, LaneState::Traced);
        assert_eq!((walk.files, walk.unread_files), (MAX_LANE_FILES, 5));
        assert_eq!(walk.records.len(), MAX_LANE_FILES);
        // The files read are the first by name; the same lane walked twice totals the same.
        assert_eq!(
            lane_trace_totals(lane.path()),
            lane_trace_totals(lane.path())
        );
        assert_eq!(lane_trace_totals(lane.path()).unwrap().unread_files, 5);
    }

    #[test]
    fn the_listing_of_a_huge_directory_holds_a_bounded_set_of_the_smallest_names() {
        let lane = tempfile::tempdir_in("/var/tmp").unwrap();
        let traces = lane.path().join("portkit/traces");
        fs::create_dir_all(&traces).unwrap();
        for n in 0..5000 {
            fs::write(traces.join(format!("{n:05}.jsonl")), line() + "\n").unwrap();
        }
        // Not a trace file: neither held nor counted.
        fs::write(traces.join("00000.txt"), "x").unwrap();

        let (held, overflow) = list_bounded(fs::read_dir(&traces).unwrap(), MAX_LANE_LISTING);
        assert_eq!(held.len(), MAX_LANE_LISTING);
        assert_eq!(overflow, 5000 - MAX_LANE_LISTING);
        let names: Vec<String> = held
            .iter()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        let expected: Vec<String> = (0..MAX_LANE_LISTING)
            .map(|n| format!("{n:05}.jsonl"))
            .collect();
        assert_eq!(names, expected, "the smallest names, in name order");

        // The whole walk: 256 read, the other 4744 counted (3840 past the file bound, 904
        // past the listing), and the same lane walked twice gives the same totals.
        let walk = read_lane_traces(lane.path());
        assert_eq!(walk.state, LaneState::Traced);
        assert_eq!((walk.files, walk.unread_files), (MAX_LANE_FILES, 4744));
        let first = lane_trace_totals(lane.path()).unwrap();
        let second = lane_trace_totals(lane.path()).unwrap();
        assert_eq!(first, second);
        assert_eq!(
            (first.calls, first.unread_files),
            (MAX_LANE_FILES as u64, 4744)
        );
    }

    #[test]
    fn a_lane_within_the_bounds_has_nothing_unread() {
        let lane = tempfile::tempdir_in("/var/tmp").unwrap();
        let traces = lane.path().join("portkit/traces");
        fs::create_dir_all(&traces).unwrap();
        trace_file(&traces, "a.jsonl", 0);
        let walk = read_lane_traces(lane.path());
        assert_eq!((walk.files, walk.unread_files), (1, 0));
        assert_eq!(lane_trace_totals(lane.path()).unwrap().unread_files, 0);
    }
}
