//! Watch subcommand: observe lanes and their escalation events.
//!
//! `cowproof watch` shows the status of parked lanes and their events.
//! - Without `--events`: print a table with lane status, parked escalation age, and event counts.
//! - With `--events`: stream events as RFC3339-timestamped lines (one event per line, max 300 chars).
//! - With `--follow`: keep running and emit events as they are appended to the queue.
//!
//! Reading and printing are separate. [`lane_snapshots`] and [`read_events`]
//! return data; the table and the event lines print it, and the director's
//! `lanes` and `events` tools (`director_tools`) serialize the same data.

use anyhow::{Result, anyhow, bail};
use cowproof_run::escalate::{QueueEvent, read_queue_events};
use cowproof_run::watch::{Parked, parked};
use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io::{Read, Seek};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::sleep;

#[derive(clap::Parser)]
pub struct WatchArgs {
    /// Directory that holds the lanes (default: ~/.cache/cowproof/lanes)
    #[arg(long)]
    pub lanes_root: Option<PathBuf>,

    /// Emit events as one line per event instead of a status table
    #[arg(long)]
    pub events: bool,

    /// With --events, keep running and emit new events as they arrive
    #[arg(long)]
    pub follow: bool,

    /// Cache TTL for parked escalations (default: 1h)
    #[arg(long, default_value = DEFAULT_CACHE_TTL)]
    pub cache_ttl: String,
}

/// The cache lifetime `--cache-ttl` and the `lanes` tool use when none is given.
pub const DEFAULT_CACHE_TTL: &str = "1h";

/// Parse a duration string like "1h", "30m", "1h30m", etc.
pub fn parse_duration(s: &str) -> Result<Duration> {
    let mut total = Duration::ZERO;
    let mut remaining = s.trim();

    while !remaining.is_empty() {
        // Skip whitespace
        remaining = remaining.trim_start();

        // Find the numeric part
        let num_end = remaining
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(remaining.len());
        if num_end == 0 {
            bail!("invalid duration format: {}", s);
        }

        let num: u64 = remaining[..num_end].parse()?;
        remaining = remaining[num_end..].trim_start();

        // Find the unit
        let unit_end = remaining
            .find(|c: char| !c.is_ascii_alphabetic())
            .unwrap_or(remaining.len());
        if unit_end == 0 {
            bail!("invalid duration format: {}", s);
        }

        let unit = &remaining[..unit_end];
        remaining = &remaining[unit_end..];

        let duration = match unit {
            "s" | "sec" | "second" => Duration::from_secs(num),
            "m" | "min" | "minute" => Duration::from_secs(num * 60),
            "h" | "hr" | "hour" => Duration::from_secs(num * 3600),
            "d" | "day" => Duration::from_secs(num * 86400),
            _ => bail!("unknown duration unit: {}", unit),
        };
        total += duration;
    }

    Ok(total)
}

/// Format duration as a human-readable age string.
fn format_age(duration: Duration) -> String {
    let secs = duration.as_secs();
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m", secs / 60)
    } else if secs < 86400 {
        format!("{}h", secs / 3600)
    } else {
        format!("{}d", secs / 86400)
    }
}

/// Get current time as milliseconds since epoch.
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Convert milliseconds since epoch to RFC3339 string.
fn ms_to_rfc3339(ms: u64) -> String {
    if ms == 0 {
        return "-".to_string();
    }
    // Convert ms to seconds and nanoseconds for RFC3339
    let secs = (ms / 1000) as i64;
    let nanos = ((ms % 1000) * 1_000_000) as u32;

    // Simple UTC timestamp format without external dependencies
    // Convert Unix timestamp to calendar date and time
    let days_since_epoch = secs / 86400;
    let secs_today = secs % 86400;

    let hours = secs_today / 3600;
    let minutes = (secs_today % 3600) / 60;
    let seconds = secs_today % 60;
    let millis = nanos / 1_000_000;

    // Approximate year/month/day from days since epoch (1970-01-01)
    // This is simplified; for a production implementation, use a proper date library
    let mut year = 1970;
    let mut remaining_days = days_since_epoch;

    loop {
        let days_in_year = if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) {
            366
        } else {
            365
        };
        if remaining_days < days_in_year {
            break;
        }
        remaining_days -= days_in_year;
        year += 1;
    }

    let is_leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days_in_months = if is_leap {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    let mut month = 1;
    let mut day = remaining_days + 1;
    for &days in &days_in_months {
        if day <= days as i64 {
            break;
        }
        day -= days as i64;
        month += 1;
    }

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        year, month, day, hours, minutes, seconds, millis
    )
}

/// Truncate a string to at most max_chars, preserving safety.
fn truncate_line(s: &str, max_chars: usize) -> String {
    if s.len() <= max_chars {
        s.to_string()
    } else {
        // Try to truncate on a char boundary
        let mut truncated = &s[..max_chars];
        while !truncated.is_empty() && !s.is_char_boundary(truncated.len()) {
            truncated = &truncated[..truncated.len() - 1];
        }
        format!("{}...", truncated)
    }
}

pub async fn watch(args: WatchArgs) -> Result<()> {
    let lanes_root = crate::root::current_lanes_root(args.lanes_root.as_deref())?;
    let cache_ttl = parse_duration(&args.cache_ttl)?;
    let cache_ttl_ms = cache_ttl.as_millis() as u64;

    if args.events {
        watch_events(&lanes_root, args.follow).await
    } else {
        watch_table(&lanes_root, cache_ttl_ms)
    }
}

/// Collect all lanes from the lanes root.
pub(crate) fn collect_lanes(lanes_root: &Path) -> Result<Vec<PathBuf>> {
    if !lanes_root.is_dir() {
        return Ok(Vec::new());
    }

    let mut lanes = Vec::new();
    for entry in fs::read_dir(lanes_root)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            let control_dir = path.join("control");
            if control_dir.is_dir() {
                lanes.push(path);
            }
        }
    }

    // Sort by name for consistent output
    lanes.sort();
    Ok(lanes)
}

/// The verdict named in `control/verdict.json` (`proved`, `refuted`, `incomplete`,
/// `infrastructure`, or `finished` for an unsandboxed lane), when the lane has been proved.
/// The file is read without following a link and only up to a bound; anything else is none.
fn lane_verdict(lane_dir: &Path) -> Option<String> {
    let path = lane_dir.join("control/verdict.json");
    let meta = fs::symlink_metadata(&path).ok()?;
    if !meta.is_file() || meta.len() > 1024 * 1024 {
        return None;
    }
    let mut text = String::new();
    fs::File::open(&path)
        .ok()?
        .take(1024 * 1024)
        .read_to_string(&mut text)
        .ok()?;
    let doc: serde_json::Value = serde_json::from_str(&text).ok()?;
    let name = doc.get("verdict")?.as_str()?;
    // A label out of a file the builder cannot write, printed in a table: bound it anyway.
    (!name.is_empty()
        && name.len() <= 32
        && name.chars().all(|c| c.is_ascii_lowercase() || c == '-'))
    .then(|| name.to_string())
}

/// Get the state of a lane: its verdict when it has one (`control/verdict.json`), otherwise
/// the status in `control/run.json`, otherwise `running`. `run.json` alone says `finished` for
/// a builder that exited, however the proof went. A `run.json` that cannot be read (too large
/// or not JSON) says `finished`; the `run_json` field and the `?` cells say it is unreadable.
fn get_lane_state(lane_dir: &Path, run: &RunJson) -> String {
    if let Some(verdict) = lane_verdict(lane_dir) {
        return verdict;
    }
    let obj = match run {
        RunJson::Absent => return "running".to_string(),
        RunJson::Unreadable => return "finished".to_string(),
        RunJson::Doc(obj) => obj,
    };
    // Check for status field (stopped, failed, timeout, finished, ...)
    if let Some(status) = obj.get("status").and_then(|v| v.as_str()) {
        return status.to_string();
    }
    // Fall back to exitCode (exit 0, exit 1, etc.)
    if let Some(exit_code) = obj.get("exitCode").and_then(|v| v.as_i64()) {
        return format!("exit {}", exit_code);
    }
    // Legacy: exit_code field
    if let Some(exit_code) = obj.get("exit_code").and_then(|v| v.as_i64()) {
        return format!("exit {}", exit_code);
    }
    "finished".to_string()
}

/// Get the last event time for a lane, if any.
fn get_last_event_time(lane_dir: &Path) -> Option<u64> {
    let control_dir = lane_dir.join("control");
    let queue_file = control_dir.join("escalations.jsonl");

    let (events, _) = read_queue_events(&queue_file).ok()?;
    let mut max_ms = 0u64;

    for event in events {
        let at_ms = match event {
            QueueEvent::Asked { at_ms, .. } => at_ms,
            QueueEvent::Ruled { at_ms, .. } => at_ms,
            QueueEvent::Delivered { at_ms, .. } => at_ms,
            QueueEvent::ResumeFallback { at_ms, .. } => at_ms,
            QueueEvent::LaneEscalationLimit { at_ms, .. } => at_ms,
            QueueEvent::Note { at_ms, .. } => at_ms,
            QueueEvent::NoteDelivered { at_ms, .. } => at_ms,
            QueueEvent::Rejected { .. } => continue,
        };
        if at_ms > 0 {
            max_ms = max_ms.max(at_ms);
        }
    }

    if max_ms > 0 { Some(max_ms) } else { None }
}

/// Count pending notes in a lane (notes without a delivered marker).
fn count_pending_notes(control_dir: &Path, lane_name: &str) -> Result<usize> {
    let queue_file = control_dir.join("escalations.jsonl");

    let (events, _) = match read_queue_events(&queue_file) {
        Ok(read) => read,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(anyhow!("cannot read escalations: {e}")),
    };

    let mut notes: HashMap<String, bool> = HashMap::new();

    for event in events {
        match event {
            QueueEvent::Note { lane, id, .. } if lane == lane_name => {
                notes.insert(id, false);
            }
            QueueEvent::NoteDelivered { lane, id, .. } if lane == lane_name => {
                notes.insert(id, true);
            }
            _ => {}
        }
    }

    Ok(notes.values().filter(|&delivered| !delivered).count())
}

/// A lane's credential mode when it is not the default API key (D28 clause 6), from the
/// `authMode`, `credentialKind` and `credentialInLane` of `control/run.json`. A lane with no such
/// record (older, still running, or an API-key lane) has none, and `watch` shows it as it always
/// did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LaneCredential {
    pub mode: String,
    pub kind: Option<String>,
    pub in_lane: bool,
}

impl LaneCredential {
    /// The cell `watch` prints: `subscription (claude-oauth-token)`, with `, in lane` when a
    /// credential was readable inside the lane.
    fn cell(&self) -> String {
        let mut inner = self.kind.clone().unwrap_or_default();
        if self.in_lane {
            if !inner.is_empty() {
                inner.push_str(", ");
            }
            inner.push_str("in lane");
        }
        if inner.is_empty() {
            self.mode.clone()
        } else {
            format!("{} ({inner})", self.mode)
        }
    }
}

/// The longest `control/run.json` that `watch` and the `lanes` tool read.
const MAX_RUN_JSON_BYTES: u64 = 4 * 1024 * 1024;

/// What `control/run.json` of a lane held when it was read.
#[derive(Debug, Clone, PartialEq)]
enum RunJson {
    /// There is no such file: the runner writes it at lane end, so the lane is still running.
    Absent,
    /// The file is there and cannot be used: not a regular file (a link is not followed),
    /// larger than [`MAX_RUN_JSON_BYTES`], or not JSON. It is never shown as nothing: the
    /// cells that come from it say `?` (audit S-5), because a builder that could blank them
    /// would hide a credential in its lane.
    Unreadable,
    Doc(serde_json::Value),
}

/// `control/run.json` of a lane, read once, without following a link and only up to a bound.
fn read_run_json(lane_dir: &Path) -> RunJson {
    let path = lane_dir.join("control/run.json");
    let meta = match fs::symlink_metadata(&path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return RunJson::Absent,
        Err(_) => return RunJson::Unreadable,
    };
    if !meta.is_file() || meta.len() > MAX_RUN_JSON_BYTES {
        return RunJson::Unreadable;
    }
    let mut text = String::new();
    let read = fs::File::open(&path)
        .and_then(|f| f.take(MAX_RUN_JSON_BYTES + 1).read_to_string(&mut text));
    if read.is_err() || text.len() as u64 > MAX_RUN_JSON_BYTES {
        return RunJson::Unreadable;
    }
    serde_json::from_str(&text).map_or(RunJson::Unreadable, RunJson::Doc)
}

/// The credential mode recorded in the lane's `control/run.json`, when it is not `api-key`. The
/// file is read without following a link and only up to a bound; the label is a file the builder
/// cannot write, printed in a table, so it is held to a short lower-case alphabet anyway.
fn lane_credential(run: &RunJson) -> Option<LaneCredential> {
    let RunJson::Doc(doc) = run else {
        return None;
    };
    let label = |v: &serde_json::Value| {
        v.as_str()
            .filter(|n| {
                !n.is_empty()
                    && n.len() <= 32
                    && n.chars().all(|c| c.is_ascii_lowercase() || c == '-')
            })
            .map(str::to_string)
    };
    let mode = label(doc.get("authMode")?)?;
    let in_lane = doc.get("credentialInLane").and_then(|v| v.as_bool()) == Some(true);
    if mode == "api-key" && !in_lane {
        return None;
    }
    Some(LaneCredential {
        mode,
        kind: doc.get("credentialKind").and_then(label),
        in_lane,
    })
}

/// The bytes the budget kept out of an ended traced lane's context: `traceTotals.savedBytes`
/// of `control/run.json` (D5). The runner reads the lane's trace once, at lane end, and writes
/// the totals into `run.json` then, so an untraced lane and an older `run.json` without the
/// figure have none; a `run.json` that cannot be read has none here and the snapshot says so
/// in `run_json`. A lane that is still running has no `run.json` yet: [`lane_snapshots`] reads
/// its figure so far from the trace itself ([`live_ctx_saved`]). The figure is the builder's
/// own account (it can write its trace): informational, and labelled so wherever it is shown.
fn lane_ctx_saved(run: &RunJson) -> Option<u64> {
    let RunJson::Doc(doc) = run else {
        return None;
    };
    doc.get("traceTotals")?.get("savedBytes")?.as_u64()
}

/// The bytes the budget has kept out of a running lane's context so far, read from the lane's
/// portkit trace on each look (`cowproof_report::traces::live_lane_trace_totals`: no link
/// followed, at most 8 MiB and 4096 directory entries, a malformed line counted rather than
/// fatal), so a missing or malformed trace cannot fail `watch`. None when the lane has no trace
/// or the walk gave up. The runner does not yet know whether `pk doctor` passed, or whether a
/// segment will run on a runtime without hooks, so a lane can show a figure while it runs and
/// none once it ends untraced.
fn live_ctx_saved(lane_dir: &Path) -> Option<u64> {
    cowproof_report::traces::live_lane_trace_totals(lane_dir).map(|t| t.saved_bytes)
}

/// Bytes as a short human figure: `950`, `12.3k`, `4.5M`, `1.2G` (decimal units).
fn human_bytes(bytes: u64) -> String {
    if bytes < 1000 {
        return bytes.to_string();
    }
    let mut value = bytes as f64;
    for unit in ["k", "M", "G", "T", "P", "E"] {
        value /= 1000.0;
        // `999_999` is `1.0M`, not `1000.0k`.
        if format!("{value:.1}")
            .parse::<f64>()
            .is_ok_and(|v| v < 1000.0)
        {
            return format!("{value:.1}{unit}");
        }
    }
    format!("{value:.1}E")
}

/// One lane as the table and the director's `lanes` tool show it.
#[derive(Debug, Clone, Serialize)]
pub struct LaneSnapshot {
    pub id: String,
    pub state: String,
    /// The lane's parked blocking escalation: its id and age, not its text.
    pub parked: Option<Parked>,
    /// The queue could not be read, so `parked` and `pending_notes` are unknown.
    pub queue_unreadable: bool,
    pub pending_notes: Option<usize>,
    pub last_event_ms: Option<u64>,
    /// The credential mode, present only when it is not the default API key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential: Option<LaneCredential>,
    /// Bytes the budget kept out of the lane's context: the lane-end trace totals
    /// (`traceTotals.savedBytes`) once it has ended, the trace so far while it runs, none for
    /// an untraced lane. The builder wrote the trace it comes from, so the name says whose
    /// figure it is (audit S-6).
    #[serde(
        rename = "ctx_saved_bytes_builder_reported",
        skip_serializing_if = "Option::is_none"
    )]
    pub ctx_saved_bytes: Option<u64>,
    /// The saved figure was read from the trace of a lane that is still running, so it is the
    /// figure so far and the lane-end one replaces it.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub ctx_saved_while_running: bool,
    /// `"unreadable"` when the lane's `run.json` is there and cannot be used (too large, a
    /// link, or not JSON): `credential` and the saved figure are then unknown, not absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_json: Option<&'static str>,
}

impl LaneSnapshot {
    /// Whether the lane's `run.json` could not be read, so the cells from it are `?`.
    fn run_json_unreadable(&self) -> bool {
        self.run_json.is_some()
    }
}

/// Every lane under `lanes_root`, sorted by name, as data.
pub fn lane_snapshots(
    lanes_root: &Path,
    now_ms: u64,
    cache_ttl_ms: u64,
) -> Result<Vec<LaneSnapshot>> {
    let mut rows = Vec::new();
    for lane_dir in collect_lanes(lanes_root)? {
        let id = lane_dir.file_name().and_then(|n| n.to_str()).unwrap_or("?");
        let control_dir = lane_dir.join("control");
        let parked = parked(&control_dir, id, now_ms, cache_ttl_ms);
        let notes = count_pending_notes(&control_dir, id);
        // Read once: the state, the credential and the saved figure all come from it.
        let run = read_run_json(&lane_dir);
        let state = get_lane_state(&lane_dir, &run);
        // No `run.json` and no verdict: the runner has not reached lane end.
        let running = run == RunJson::Absent && state == "running";
        let ctx_saved_bytes = if running {
            live_ctx_saved(&lane_dir)
        } else {
            lane_ctx_saved(&run)
        };
        rows.push(LaneSnapshot {
            id: id.to_string(),
            state,
            queue_unreadable: parked.is_err() || notes.is_err(),
            parked: parked.ok().flatten(),
            pending_notes: notes.ok(),
            last_event_ms: get_last_event_time(&lane_dir),
            credential: lane_credential(&run),
            ctx_saved_while_running: running && ctx_saved_bytes.is_some(),
            ctx_saved_bytes,
            run_json: (run == RunJson::Unreadable).then_some("unreadable"),
        });
    }
    Ok(rows)
}

fn watch_table(lanes_root: &Path, cache_ttl_ms: u64) -> Result<()> {
    let now_ms = now_ms();
    let rows = lane_snapshots(lanes_root, now_ms, cache_ttl_ms)?;
    print!("{}", render_table(&rows, now_ms));
    if let Some(note) = saved_footnote(&rows) {
        println!("{note}");
    }
    Ok(())
}

/// The table `watch` prints, tab separated, one line per lane after the header.
///
/// Two columns are optional so that the table of plain lanes is unchanged: `CTX-SAVED` appears
/// when some lane has trace totals, and `CREDENTIAL` when some lane is not on the default API
/// key. `CTX-SAVED` is `-` for a lane without a figure (untraced, or an older `run.json`); a
/// running lane shows its figure so far. It is `?` for a lane whose `run.json` could not be read. A column also appears for
/// such a lane, so a builder cannot blank it by making its `run.json` unreadable (audit S-5).
/// The saved figure is the builder's own account, so its header carries a `*` (audit S-6) and
/// [`saved_footnote`] explains it under the table.
fn render_table(rows: &[LaneSnapshot], now_ms: u64) -> String {
    let show_saved = show_saved_column(rows);
    let show_credential = show_credential_column(rows);
    let mut header = "LANE\tSTATE\tPARKED\tAGE\tNOTES\tLAST EVENT".to_string();
    if show_saved {
        header.push_str("\tCTX-SAVED*");
    }
    if show_credential {
        header.push_str("\tCREDENTIAL");
    }
    let mut out = header + "\n";

    for row in rows {
        let (parked_info, parked_age) = if row.queue_unreadable {
            ("?".to_string(), "?".to_string())
        } else if let Some(p) = &row.parked {
            let cache_marker = if p.past_cache { " past cache" } else { "" };
            (
                format!("{}{}", p.id, cache_marker),
                format_age(Duration::from_millis(p.age_ms)),
            )
        } else {
            ("-".to_string(), "-".to_string())
        };
        let notes = row
            .pending_notes
            .map_or_else(|| "?".to_string(), |n| n.to_string());
        let last_event = match row.last_event_ms {
            Some(last_ms) => format_age(Duration::from_millis(now_ms.saturating_sub(last_ms))),
            None => "-".to_string(),
        };

        let mut line = format!(
            "{}\t{}\t{}\t{}\t{}\t{}",
            row.id, row.state, parked_info, parked_age, notes, last_event
        );
        if show_saved {
            line.push('\t');
            line.push_str(&if row.run_json_unreadable() {
                "?".to_string()
            } else {
                row.ctx_saved_bytes.map_or("-".to_string(), human_bytes)
            });
        }
        if show_credential {
            line.push('\t');
            line.push_str(&if row.run_json_unreadable() {
                "?".to_string()
            } else {
                row.credential
                    .as_ref()
                    .map_or_else(|| "api-key".to_string(), LaneCredential::cell)
            });
        }
        out.push_str(&line);
        out.push('\n');
    }
    out
}

fn show_saved_column(rows: &[LaneSnapshot]) -> bool {
    rows.iter()
        .any(|r| r.ctx_saved_bytes.is_some() || r.run_json_unreadable())
}

fn show_credential_column(rows: &[LaneSnapshot]) -> bool {
    rows.iter()
        .any(|r| r.credential.is_some() || r.run_json_unreadable())
}

/// The line under the table when `CTX-SAVED*` shows.
fn saved_footnote(rows: &[LaneSnapshot]) -> Option<&'static str> {
    show_saved_column(rows)
        .then_some("* builder-written trace figure: informational, no verdict reads it.")
}

/// One queue event as `watch --events` prints it and the `events` tool returns it.
/// `summary` is runner-owned text: ids, flags and sizes, never the builder's words.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EventRow {
    pub at_ms: u64,
    pub lane: String,
    pub kind: String,
    pub summary: String,
}

/// How far into each lane's queue file has been read, in bytes, keyed by lane id.
pub type Cursor = BTreeMap<String, u64>;

/// A cursor as the text the `events` tool hands out and takes back.
pub fn encode_cursor(cursor: &Cursor) -> String {
    serde_json::to_string(cursor).unwrap_or_else(|_| "{}".to_string())
}

/// The inverse of [`encode_cursor`]. A cursor that does not parse is an error:
/// quietly starting over would repeat every event.
pub fn decode_cursor(text: &str) -> Result<Cursor> {
    serde_json::from_str(text).map_err(|e| anyhow!("invalid cursor: {e}"))
}

/// What one pass over the queues found.
#[derive(Debug, Clone)]
pub struct EventBatch {
    pub events: Vec<EventRow>,
    /// Pass this back as `since` to read only what comes after.
    pub cursor: Cursor,
    /// Lanes whose queue file could not be read this time.
    pub unreadable: Vec<String>,
}

/// Project one queue line for lane `lane_name`; `None` when it is not an event of that lane.
fn event_row(obj: &Value, lane_name: &str) -> Option<EventRow> {
    let kind = obj.get("event")?.as_str()?;
    if obj.get("lane")?.as_str()? != lane_name {
        return None;
    }
    let str_field = |name: &str, default: &'static str| {
        obj.get(name)
            .and_then(|v| v.as_str())
            .unwrap_or(default)
            .to_string()
    };
    let summary = match kind {
        "asked" => {
            let blocking = obj
                .get("ask")
                .and_then(|a| a.get("blocking"))
                .and_then(|b| b.as_bool())
                .unwrap_or(false);
            let blocking_text = if blocking { "blocking" } else { "non-blocking" };
            format!("{} ({})", str_field("id", "?"), blocking_text)
        }
        "ruled" | "note-delivered" | "resume-fallback" => str_field("id", "?"),
        "note" => {
            let text_len = obj
                .get("text")
                .and_then(|v| v.as_str())
                .map(|t| t.len())
                .unwrap_or(0);
            format!("{} ({} bytes)", str_field("id", "?"), text_len)
        }
        "rejected" => format!("{}: {}", str_field("id", "?"), str_field("reason", "?")),
        "delivered" => {
            let fresh = obj.get("fresh").and_then(|v| v.as_bool()).unwrap_or(false);
            let fresh_text = if fresh { "fresh" } else { "resumed" };
            format!("{} ({})", str_field("id", "?"), fresh_text)
        }
        "lane-escalation-limit" => str_field("id", "(no id)"),
        _ => "?".to_string(),
    };
    Some(EventRow {
        at_ms: obj.get("at_ms").and_then(|v| v.as_u64()).unwrap_or(0),
        lane: lane_name.to_string(),
        kind: kind.to_string(),
        summary,
    })
}

/// Read what each lane's queue has gained since `since`, optionally for one lane.
///
/// Only complete lines are consumed, so a line the runner is still writing is
/// read whole on the next pass. A queue file shorter than its offset is read
/// again from the start. Lanes not read this pass keep their old offset.
pub fn read_events(
    lanes_root: &Path,
    since: &Cursor,
    lane_filter: Option<&str>,
) -> Result<EventBatch> {
    let mut batch = EventBatch {
        events: Vec::new(),
        cursor: since.clone(),
        unreadable: Vec::new(),
    };

    for lane_dir in collect_lanes(lanes_root)? {
        let lane_name = lane_dir.file_name().and_then(|n| n.to_str()).unwrap_or("?");
        if lane_filter.is_some_and(|f| f != lane_name) {
            continue;
        }
        let queue_file = lane_dir.join("control").join("escalations.jsonl");
        if !queue_file.is_file() {
            continue;
        }

        let read = (|| -> std::io::Result<(u64, Vec<u8>)> {
            let mut file = fs::File::open(&queue_file)?;
            let size = file.metadata()?.len();
            let mut offset = since.get(lane_name).copied().unwrap_or(0);
            if offset > size {
                offset = 0;
            }
            file.seek(std::io::SeekFrom::Start(offset))?;
            let mut buffer = Vec::new();
            file.read_to_end(&mut buffer)?;
            Ok((offset, buffer))
        })();
        let (offset, buffer) = match read {
            Ok(r) => r,
            Err(_) => {
                batch.unreadable.push(lane_name.to_string());
                continue;
            }
        };

        let complete = buffer
            .iter()
            .rposition(|&b| b == b'\n')
            .map_or(0, |i| i + 1);
        let content = String::from_utf8_lossy(&buffer[..complete]);
        for line in content.lines() {
            if line.trim().is_empty() {
                continue;
            }
            if let Ok(obj) = serde_json::from_str::<Value>(line)
                && let Some(row) = event_row(&obj, lane_name)
            {
                batch.events.push(row);
            }
        }
        batch
            .cursor
            .insert(lane_name.to_string(), offset + complete as u64);
    }

    Ok(batch)
}

async fn watch_events(lanes_root: &Path, follow: bool) -> Result<()> {
    let mut cursor = Cursor::new();

    loop {
        let batch = read_events(lanes_root, &cursor, None)?;
        for lane in &batch.unreadable {
            eprintln!("error: {}", lane);
        }
        for e in &batch.events {
            let line = format!(
                "{} {} {} {}",
                ms_to_rfc3339(e.at_ms),
                e.lane,
                e.kind,
                e.summary
            );
            println!("{}", truncate_line(&line, 300));
        }
        cursor = batch.cursor;

        if !follow {
            break;
        }

        sleep(Duration::from_millis(500)).await;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Notes written and delivered through the real queue: only the undelivered
    /// one is pending, for this lane only.
    #[test]
    fn count_pending_notes_counts_only_undelivered_notes_of_the_lane() {
        use cowproof_run::escalate::{Queue, SystemClock};
        let dir = tempfile::tempdir().unwrap();
        let mut queue = Queue::new(dir.path(), Box::new(SystemClock)).unwrap();
        let first = queue.note("lane-a", "first").unwrap();
        queue.note("lane-a", "second").unwrap();
        queue.note("lane-b", "other lane").unwrap();
        queue.mark_notes_delivered("lane-a", &[first]).unwrap();
        drop(queue);
        assert_eq!(count_pending_notes(dir.path(), "lane-a").unwrap(), 1);
        assert_eq!(count_pending_notes(dir.path(), "lane-b").unwrap(), 1);
    }

    /// A queue file as `cowproof run` can leave it: events, a line that is not JSON, a
    /// half-written last line. `control/escalations.jsonl` under a fresh lane directory.
    fn lane_with_queue(lines: &[&str]) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir_in("/var/tmp").unwrap();
        let control = dir.path().join("control");
        fs::create_dir_all(&control).unwrap();
        fs::write(control.join("escalations.jsonl"), lines.join("\n")).unwrap();
        (dir, control)
    }

    const NOTE_1: &str =
        r#"{"event":"note","lane":"lane-a","id":"lane-a:N1","text":"first","at_ms":10}"#;
    const NOTE_2: &str =
        r#"{"event":"note","lane":"lane-a","id":"lane-a:N2","text":"second","at_ms":20}"#;
    const NOTE_1_DELIVERED: &str =
        r#"{"event":"note-delivered","lane":"lane-a","id":"lane-a:N1","at_ms":30}"#;
    const RULED: &str = r#"{"event":"ruled","lane":"lane-a","id":"lane-a:E1","verdict":{"verdict":"answer","text":"go"},"at_ms":500}"#;

    /// A malformed line is skipped, as the queue's own parser skips it, and the well-formed
    /// events around it, a ruling among them, give the last-event time and the pending count
    /// the by-hand reader gave.
    #[test]
    fn a_malformed_line_is_skipped_and_the_ruling_still_sets_the_last_event_time() {
        let (dir, control) = lane_with_queue(&[
            NOTE_1,
            "this is not json",
            RULED,
            NOTE_2,
            NOTE_1_DELIVERED,
            r#"{"event":"note","lane":"lane-a","id":"lane-a:N3","te"#,
        ]);
        assert_eq!(get_last_event_time(dir.path()), Some(500));
        assert_eq!(count_pending_notes(&control, "lane-a").unwrap(), 1);
        assert_eq!(count_pending_notes(&control, "lane-b").unwrap(), 0);
    }

    /// A line the builder wrote that looks like a ruling or a note but is not a valid
    /// `QueueEvent` (a verdict that does not exist, a note with no text, a time that is not a
    /// number) changes neither figure. The by-hand reader counted the note and took the time.
    #[test]
    fn lines_that_look_like_events_but_are_not_valid_do_not_change_the_figures() {
        let valid = [NOTE_1, NOTE_2, NOTE_1_DELIVERED, RULED];
        let lookalikes = [
            r#"{"event":"ruled","lane":"lane-a","id":"lane-a:E9","verdict":{"verdict":"approve"},"at_ms":999999}"#,
            r#"{"event":"note","lane":"lane-a","id":"lane-a:N9","at_ms":999999}"#,
            r#"{"event":"note","lane":"lane-a","id":"lane-a:N8","text":"x","at_ms":"999999"}"#,
            r#"{"event":"note-delivered","lane":"lane-a","at_ms":999999}"#,
        ];
        let (clean, clean_control) = lane_with_queue(&valid);
        let mixed: Vec<&str> = valid.iter().chain(lookalikes.iter()).copied().collect();
        let (dirty, dirty_control) = lane_with_queue(&mixed);

        assert_eq!(get_last_event_time(clean.path()), Some(500));
        assert_eq!(get_last_event_time(dirty.path()), Some(500));
        assert_eq!(count_pending_notes(&clean_control, "lane-a").unwrap(), 1);
        assert_eq!(count_pending_notes(&dirty_control, "lane-a").unwrap(), 1);
    }

    #[test]
    fn test_parse_duration_hours() {
        let d = parse_duration("1h").unwrap();
        assert_eq!(d.as_secs(), 3600);
    }

    #[test]
    fn test_parse_duration_minutes() {
        let d = parse_duration("30m").unwrap();
        assert_eq!(d.as_secs(), 1800);
    }

    #[test]
    fn test_parse_duration_combined() {
        let d = parse_duration("1h30m").unwrap();
        assert_eq!(d.as_secs(), 5400);
    }

    #[test]
    fn test_format_age_seconds() {
        let age = format_age(Duration::from_secs(45));
        assert_eq!(age, "45s");
    }

    #[test]
    fn test_format_age_hours() {
        let age = format_age(Duration::from_secs(3600));
        assert_eq!(age, "1h");
    }

    #[test]
    fn test_truncate_line() {
        let s = "hello world this is a long string";
        let truncated = truncate_line(s, 10);
        assert!(truncated.len() <= 13);
    }

    #[test]
    fn a_cursor_round_trips_and_a_shortened_queue_is_read_again_from_the_start() {
        let mut cursor = Cursor::new();
        cursor.insert("lane-a".to_string(), 1000);
        assert_eq!(decode_cursor(&encode_cursor(&cursor)).unwrap(), cursor);
        assert!(decode_cursor("lane-a:7").is_err());

        let root = tempfile::TempDir::new().unwrap();
        let control = root.path().join("lane-a/control");
        fs::create_dir_all(&control).unwrap();
        let line = "{\"event\":\"ruled\",\"lane\":\"lane-a\",\"id\":\"lane-a:E1\",\"at_ms\":5}\n";
        fs::write(control.join("escalations.jsonl"), line).unwrap();

        // The offset is past the end of the file, as after a queue rewritten shorter.
        let batch = read_events(root.path(), &cursor, None).unwrap();
        assert_eq!(batch.events.len(), 1);
        assert_eq!(batch.cursor["lane-a"], line.len() as u64);
    }

    #[test]
    fn test_ms_to_rfc3339_known_epoch() {
        // 1970-01-01T00:00:00.000Z (epoch)
        let result = ms_to_rfc3339(0);
        assert_eq!(result, "-");

        // 1970-01-01T00:00:01.000Z (1 second after epoch)
        let result = ms_to_rfc3339(1000);
        assert!(result.starts_with("1970-01-01"));
        assert!(result.contains("00:00:01"));
        assert!(result.ends_with("Z"));

        // Verify RFC3339 format: YYYY-MM-DDTHH:MM:SS.sssZ
        assert!(result.contains("T"));
        assert!(result.contains(":"));
        assert!(result.contains("."));
        let parts: Vec<&str> = result.split('.').collect();
        assert_eq!(parts.len(), 2, "RFC3339 must have milliseconds");
        assert!(parts[1].starts_with("0") && parts[1].ends_with("Z"));
    }

    fn lane_with_run_json(json: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("control")).unwrap();
        fs::write(dir.path().join("control/run.json"), json).unwrap();
        dir
    }

    /// What `run.json` of a lane that holds `json` reads as.
    fn run_of(json: &str) -> RunJson {
        read_run_json(lane_with_run_json(json).path())
    }

    #[test]
    fn the_credential_column_names_a_subscription_lane_and_says_when_a_credential_is_in_the_lane() {
        let sub = lane_with_run_json(
            r#"{"authMode":"subscription","credentialKind":"claude-oauth-token","credentialInLane":false}"#,
        );
        let credential = lane_credential(&read_run_json(sub.path())).unwrap();
        assert_eq!(credential.cell(), "subscription (claude-oauth-token)");
        assert!(!credential.in_lane);

        // A lane that did hold a credential says so, as the design (D28 clause 6) requires.
        let held = lane_with_run_json(
            r#"{"authMode":"subscription","credentialKind":"claude-oauth-token","credentialInLane":true}"#,
        );
        assert_eq!(
            lane_credential(&read_run_json(held.path())).unwrap().cell(),
            "subscription (claude-oauth-token, in lane)"
        );

        // The default API key, a lane with no record and a hostile label show nothing.
        for json in [
            r#"{"authMode":"api-key","credentialKind":null,"credentialInLane":false}"#,
            r#"{"status":"finished"}"#,
            r#"{"authMode":"Sub\tscription"}"#,
        ] {
            assert_eq!(lane_credential(&run_of(json)), None, "{json}");
        }
        // A run.json that cannot be read has no credential to name; the snapshot says so.
        assert_eq!(lane_credential(&run_of("not json")), None);
        // An API-key lane that somehow held a credential is shown.
        let odd = lane_with_run_json(r#"{"authMode":"api-key","credentialInLane":true}"#);
        assert_eq!(
            lane_credential(&read_run_json(odd.path())).unwrap().cell(),
            "api-key (in lane)"
        );
    }

    #[test]
    fn human_bytes_are_short_decimal_figures() {
        for (bytes, shown) in [
            (0, "0"),
            (950, "950"),
            (999, "999"),
            (1000, "1.0k"),
            (12_345, "12.3k"),
            (999_999, "1.0M"),
            (4_500_000, "4.5M"),
            (1_200_000_000, "1.2G"),
            (u64::MAX, "18.4E"),
        ] {
            assert_eq!(human_bytes(bytes), shown, "{bytes}");
        }
    }

    #[test]
    fn ctx_saved_is_the_saved_bytes_of_a_traced_lanes_totals_and_none_otherwise() {
        let saved = lane_with_run_json(r#"{"traceTotals":{"calls":3,"savedBytes":12345}}"#);
        assert_eq!(lane_ctx_saved(&read_run_json(saved.path())), Some(12_345));
        let zero = lane_with_run_json(r#"{"traceTotals":{"savedBytes":0}}"#);
        assert_eq!(lane_ctx_saved(&read_run_json(zero.path())), Some(0));

        // Untraced (null totals), an older run.json (totals without the figure), a figure that
        // is not a count, and a run.json that is not JSON all show nothing, and none fails.
        for json in [
            r#"{"traceTotals":null}"#,
            r#"{"status":"finished"}"#,
            r#"{"traceTotals":{"calls":3,"deliveredBytes":9}}"#,
            r#"{"traceTotals":{"savedBytes":"12"}}"#,
            r#"{"traceTotals":{"savedBytes":-1}}"#,
            "not json",
            "",
        ] {
            assert_eq!(lane_ctx_saved(&run_of(json)), None, "{json}");
        }
        // A lane that is still running has no run.json yet.
        let running = tempfile::tempdir().unwrap();
        fs::create_dir_all(running.path().join("control")).unwrap();
        assert_eq!(lane_ctx_saved(&read_run_json(running.path())), None);
    }

    fn trace_line(produced: u64, delivered: u64) -> String {
        format!(
            r#"{{"tool":"Read","target":"a","surface":"cli","outcome":"ok","at":"x","duration_ms":0.0,"input_bytes":1,"produced_bytes":{produced},"delivered_bytes":{delivered}}}"#
        )
    }

    #[test]
    fn a_running_lane_shows_the_saved_bytes_of_its_trace_so_far() {
        let root = tempfile::tempdir().unwrap();
        let lane = root.path().join("lane-a");
        let traces = lane.join("portkit/traces");
        fs::create_dir_all(lane.join("control")).unwrap();
        fs::create_dir_all(&traces).unwrap();
        let file = traces.join("2026-10-27.jsonl");
        fs::write(&file, trace_line(9_000, 1_000) + "\n").unwrap();
        let look = || lane_snapshots(root.path(), 0, 0).unwrap().remove(0);

        let first = look();
        assert_eq!(first.state, "running");
        assert_eq!(first.ctx_saved_bytes, Some(8_000));
        assert!(first.ctx_saved_while_running);
        let json = serde_json::to_value(&first).unwrap();
        assert_eq!(json["ctx_saved_bytes_builder_reported"], 8_000);
        assert_eq!(json["ctx_saved_while_running"], true);

        // The builder goes on writing: the next look sees the new record, and a line it is
        // still writing does not fail the look.
        fs::write(
            &file,
            format!(
                "{}\n{}\n{{\"tool\":",
                trace_line(9_000, 1_000),
                trace_line(500, 0)
            ),
        )
        .unwrap();
        assert_eq!(look().ctx_saved_bytes, Some(8_500));

        // At lane end the runner's figure in run.json is the one shown, not the trace.
        fs::write(
            lane.join("control/run.json"),
            r#"{"status":"finished","traceTotals":{"savedBytes":7}}"#,
        )
        .unwrap();
        let ended = look();
        assert_eq!(ended.ctx_saved_bytes, Some(7));
        assert!(!ended.ctx_saved_while_running);
        let json = serde_json::to_value(&ended).unwrap();
        assert!(json.get("ctx_saved_while_running").is_none(), "{json}");
    }

    #[test]
    fn a_running_lane_without_a_usable_trace_shows_no_figure() {
        let root = tempfile::tempdir().unwrap();
        let lane = root.path().join("lane-a");
        fs::create_dir_all(lane.join("control")).unwrap();
        // No trace directory at all.
        assert_eq!(
            lane_snapshots(root.path(), 0, 0).unwrap()[0].ctx_saved_bytes,
            None
        );
        // A `portkit` directory that is a link is not followed.
        let elsewhere = tempfile::tempdir().unwrap();
        fs::create_dir_all(elsewhere.path().join("traces")).unwrap();
        fs::write(
            elsewhere.path().join("traces/a.jsonl"),
            trace_line(9_000, 1_000) + "\n",
        )
        .unwrap();
        std::os::unix::fs::symlink(elsewhere.path(), lane.join("portkit")).unwrap();
        let row = lane_snapshots(root.path(), 0, 0).unwrap().remove(0);
        assert_eq!(row.ctx_saved_bytes, None);
        assert!(!row.ctx_saved_while_running);
    }

    #[test]
    fn a_proved_lane_is_not_read_live_even_before_its_run_json() {
        // A verdict without run.json is not a running lane: its trace is not opened.
        let root = tempfile::tempdir().unwrap();
        let lane = root.path().join("lane-a");
        fs::create_dir_all(lane.join("portkit/traces")).unwrap();
        fs::create_dir_all(lane.join("control")).unwrap();
        fs::write(lane.join("control/verdict.json"), r#"{"verdict":"proved"}"#).unwrap();
        fs::write(
            lane.join("portkit/traces/a.jsonl"),
            trace_line(9_000, 1_000) + "\n",
        )
        .unwrap();
        let row = lane_snapshots(root.path(), 0, 0).unwrap().remove(0);
        assert_eq!(row.state, "proved");
        assert_eq!(row.ctx_saved_bytes, None);
    }

    #[test]
    fn a_malformed_or_missing_trace_never_reaches_the_watch_column() {
        // For an ended lane `watch` reads run.json only. A lane whose trace directory is
        // garbage (or a symlink loop, or absent) and whose run.json has no totals still shows
        // `-`.
        let lane = lane_with_run_json(r#"{"status":"finished"}"#);
        let traces = lane.path().join("portkit/traces");
        fs::create_dir_all(&traces).unwrap();
        fs::write(traces.join("2026-10-12.jsonl"), "{ truncated\n\u{0}\u{0}").unwrap();
        assert_eq!(lane_ctx_saved(&read_run_json(lane.path())), None);
    }

    fn snapshot(id: &str, saved: Option<u64>) -> LaneSnapshot {
        LaneSnapshot {
            id: id.into(),
            state: "proved".into(),
            parked: None,
            queue_unreadable: false,
            pending_notes: Some(0),
            last_event_ms: None,
            credential: None,
            ctx_saved_bytes: saved,
            ctx_saved_while_running: false,
            run_json: None,
        }
    }

    #[test]
    fn the_ctx_saved_column_is_a_figure_for_a_traced_lane_and_a_dash_for_any_other() {
        let rows = [
            snapshot("lane-a", Some(12_345)),
            snapshot("lane-b", None),
            snapshot("lane-c", Some(0)),
        ];
        let table = render_table(&rows, 0);
        let lines: Vec<Vec<&str>> = table.lines().map(|l| l.split('\t').collect()).collect();
        assert_eq!(
            lines[0],
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
        let saved = |id: &str| lines.iter().find(|l| l[0] == id).unwrap()[6];
        assert_eq!(saved("lane-a"), "12.3k");
        // An untraced lane (or one with no totals yet) is `-`, never `0`; a traced lane that
        // saved nothing is a real `0`.
        assert_eq!(saved("lane-b"), "-");
        assert_eq!(saved("lane-c"), "0");
        assert!(lines.iter().all(|l| l.len() == 7), "{table}");
    }

    #[test]
    fn the_table_of_lanes_without_trace_totals_is_unchanged() {
        let table = render_table(&[snapshot("lane-a", None), snapshot("lane-b", None)], 0);
        assert!(
            table.starts_with("LANE\tSTATE\tPARKED\tAGE\tNOTES\tLAST EVENT\n"),
            "{table}"
        );
        assert!(!table.contains("CTX-SAVED"), "{table}");
        assert_eq!(saved_footnote(&[snapshot("lane-a", None)]), None);
        assert!(table.lines().all(|l| l.split('\t').count() == 6), "{table}");
    }

    #[test]
    fn ctx_saved_comes_before_the_credential_column() {
        let mut sub = snapshot("lane-a", Some(2_000));
        sub.credential = Some(LaneCredential {
            mode: "subscription".into(),
            kind: Some("claude-oauth-token".into()),
            in_lane: false,
        });
        let table = render_table(&[sub, snapshot("lane-b", None)], 0);
        let header = table.lines().next().unwrap();
        assert!(header.ends_with("\tCTX-SAVED*\tCREDENTIAL"), "{header}");
        let a = table.lines().nth(1).unwrap();
        assert!(
            a.ends_with("\t2.0k\tsubscription (claude-oauth-token)"),
            "{a}"
        );
        let b = table.lines().nth(2).unwrap();
        assert!(b.ends_with("\t-\tapi-key"), "{b}");
    }

    #[test]
    fn run_json_reads_as_absent_unreadable_or_a_document() {
        let none = tempfile::tempdir().unwrap();
        fs::create_dir_all(none.path().join("control")).unwrap();
        assert_eq!(read_run_json(none.path()), RunJson::Absent);
        assert!(matches!(
            run_of(r#"{"status":"finished"}"#),
            RunJson::Doc(_)
        ));
        // Malformed, empty and too large are not nothing.
        assert_eq!(run_of("not json"), RunJson::Unreadable);
        assert_eq!(run_of(""), RunJson::Unreadable);
        let big = format!(r#"{{"pad":"{}"}}"#, "x".repeat(MAX_RUN_JSON_BYTES as usize));
        assert_eq!(run_of(&big), RunJson::Unreadable);
        // A link is not followed.
        let lane = tempfile::tempdir().unwrap();
        let elsewhere = lane.path().join("elsewhere.json");
        fs::write(&elsewhere, r#"{"status":"finished"}"#).unwrap();
        fs::create_dir_all(lane.path().join("control")).unwrap();
        std::os::unix::fs::symlink(&elsewhere, lane.path().join("control/run.json")).unwrap();
        assert_eq!(read_run_json(lane.path()), RunJson::Unreadable);
    }

    #[test]
    fn an_oversized_run_json_shows_question_marks_not_blanks() {
        let mut row = snapshot("lane-a", None);
        row.run_json = Some("unreadable");
        let table = render_table(&[row, snapshot("lane-b", Some(5))], 0);
        let header = table.lines().next().unwrap();
        assert!(header.ends_with("\tCTX-SAVED*\tCREDENTIAL"), "{header}");
        let a = table.lines().nth(1).unwrap();
        assert!(a.ends_with("\t?\t?"), "{a}");
        let b = table.lines().nth(2).unwrap();
        assert!(b.ends_with("\t5\tapi-key"), "{b}");
        // The columns also appear when only the unreadable lane would have filled them.
        let mut only = snapshot("lane-a", None);
        only.run_json = Some("unreadable");
        assert!(render_table(&[only.clone()], 0).contains("CTX-SAVED*\tCREDENTIAL"));
        assert!(saved_footnote(&[only]).is_some());
    }

    #[test]
    fn the_lanes_json_names_the_builder_reported_figure_and_flags_an_unreadable_run_json() {
        let mut row = snapshot("lane-a", Some(7));
        row.run_json = Some("unreadable");
        let json = serde_json::to_value(&row).unwrap();
        assert_eq!(json["ctx_saved_bytes_builder_reported"], 7);
        assert!(json.get("ctx_saved_bytes").is_none(), "{json}");
        assert_eq!(json["run_json"], "unreadable");
        let plain = serde_json::to_value(snapshot("lane-b", None)).unwrap();
        assert!(plain.get("run_json").is_none(), "{plain}");
    }

    #[test]
    fn the_footnote_shows_under_the_table_only_when_the_saved_column_does() {
        let note = saved_footnote(&[snapshot("lane-a", Some(1))]).expect("a footnote");
        assert!(note.starts_with("* builder-written"), "{note}");
        assert!(saved_footnote(&[snapshot("lane-a", None)]).is_none());
    }
}
