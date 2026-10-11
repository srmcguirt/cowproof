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
fn collect_lanes(lanes_root: &Path) -> Result<Vec<PathBuf>> {
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

/// Get the state of a lane from its control/run.json file.
fn get_lane_state(lane_dir: &Path) -> String {
    let run_json = lane_dir.join("control/run.json");
    if !run_json.exists() {
        return "running".to_string();
    }

    match fs::read_to_string(&run_json) {
        Ok(content) => match serde_json::from_str::<serde_json::Value>(&content) {
            Ok(obj) => {
                // Check for status field (stopped, proved, refuted, incomplete, infrastructure)
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
            Err(_) => "finished".to_string(),
        },
        Err(_) => "finished".to_string(),
    }
}

/// Get the last event time for a lane, if any.
fn get_last_event_time(lane_dir: &Path) -> Option<u64> {
    let control_dir = lane_dir.join("control");
    let queue_file = control_dir.join("escalations.jsonl");
    if !queue_file.is_file() {
        return None;
    }

    // Read the queue file and find the maximum at_ms
    if let Ok(content) = fs::read_to_string(&queue_file) {
        let mut max_ms = 0u64;
        for line in content.lines() {
            if let Ok(obj) = serde_json::from_str::<serde_json::Value>(line)
                && let Some(at_ms) = obj.get("at_ms").and_then(|v| v.as_u64())
                && at_ms > 0
            {
                max_ms = max_ms.max(at_ms);
            }
        }
        if max_ms > 0 {
            return Some(max_ms);
        }
    }
    None
}

/// Count pending notes in a lane (notes without a delivered marker).
fn count_pending_notes(control_dir: &Path, lane_name: &str) -> Result<usize> {
    let queue_file = control_dir.join("escalations.jsonl");
    if !queue_file.exists() {
        return Ok(0);
    }

    let mut notes: HashMap<String, bool> = HashMap::new();
    if let Ok(content) = fs::read_to_string(&queue_file) {
        for line in content.lines() {
            if let Ok(obj) = serde_json::from_str::<serde_json::Value>(line)
                && let Some(event_type) = obj.get("event").and_then(|v| v.as_str())
                && let Some(event_lane) = obj.get("lane").and_then(|v| v.as_str())
                && event_lane == lane_name
            {
                match event_type {
                    "note" => {
                        if let Some(id) = obj.get("id").and_then(|v| v.as_str()) {
                            notes.insert(id.to_string(), false);
                        }
                    }
                    "note-delivered" => {
                        if let Some(id) = obj.get("id").and_then(|v| v.as_str()) {
                            notes.insert(id.to_string(), true);
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    Ok(notes.values().filter(|&delivered| !delivered).count())
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
        rows.push(LaneSnapshot {
            id: id.to_string(),
            state: get_lane_state(&lane_dir),
            queue_unreadable: parked.is_err() || notes.is_err(),
            parked: parked.ok().flatten(),
            pending_notes: notes.ok(),
            last_event_ms: get_last_event_time(&lane_dir),
        });
    }
    Ok(rows)
}

fn watch_table(lanes_root: &Path, cache_ttl_ms: u64) -> Result<()> {
    let now_ms = now_ms();
    let rows = lane_snapshots(lanes_root, now_ms, cache_ttl_ms)?;

    println!("LANE\tSTATE\tPARKED\tAGE\tNOTES\tLAST EVENT");

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

        println!(
            "{}\t{}\t{}\t{}\t{}\t{}",
            row.id, row.state, parked_info, parked_age, notes, last_event
        );
    }

    Ok(())
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
}
