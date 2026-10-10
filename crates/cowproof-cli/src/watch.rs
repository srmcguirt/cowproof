//! Watch subcommand: observe lanes and their escalation events.
//!
//! `cowproof watch` shows the status of parked lanes and their events.
//! - Without `--events`: print a table with lane status, parked escalation age, and event counts.
//! - With `--events`: stream events as RFC3339-timestamped lines (one event per line, max 300 chars).
//! - With `--follow`: keep running and emit events as they are appended to the queue.

use anyhow::{Result, bail};
use cowproof_run::watch::parked;
use std::collections::HashMap;
use std::fs;
use std::io::Seek;
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
    #[arg(long, default_value = "1h")]
    pub cache_ttl: String,
}

/// Parse a duration string like "1h", "30m", "1h30m", etc.
fn parse_duration(s: &str) -> Result<Duration> {
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
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Convert milliseconds since epoch to RFC3339 string.
fn ms_to_rfc3339(ms: u64) -> String {
    // Simple UTC timestamp format: show seconds.milliseconds
    let secs = ms / 1000;
    let millis = ms % 1000;
    format!("{}.{:03}Z", secs, millis)
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

fn expand_lanes_root(root: &Option<PathBuf>) -> Result<PathBuf> {
    if let Some(explicit) = root {
        return Ok(explicit.to_path_buf());
    }

    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/"));
    Ok(home.join(".cache/cowproof/lanes"))
}

pub async fn watch(args: WatchArgs) -> Result<()> {
    let lanes_root = expand_lanes_root(&args.lanes_root)?;
    let cache_ttl = parse_duration(&args.cache_ttl)?;
    let cache_ttl_ms = cache_ttl.as_millis() as u64;

    if args.events {
        watch_events(&lanes_root, cache_ttl_ms, args.follow).await
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
                if let Some(exit_code) = obj.get("exit_code").and_then(|v| v.as_i64()) {
                    format!("exit {}", exit_code)
                } else {
                    "finished".to_string()
                }
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

fn watch_table(lanes_root: &Path, cache_ttl_ms: u64) -> Result<()> {
    let lanes = collect_lanes(lanes_root)?;
    let now_ms = now_ms();

    println!("LANE\tSTATE\tPARKED\tAGE\tNOTES\tLAST EVENT");

    for lane_dir in lanes {
        let lane_name = lane_dir.file_name().and_then(|n| n.to_str()).unwrap_or("?");

        let state = get_lane_state(&lane_dir);
        let control_dir = lane_dir.join("control");

        // Get parked escalation info
        let parked_info = match parked(&control_dir, lane_name, now_ms, cache_ttl_ms) {
            Ok(Some(p)) => {
                let cache_marker = if p.past_cache { " past cache" } else { "" };
                format!("{}{}", p.id, cache_marker)
            }
            Ok(None) => "-".to_string(),
            Err(_) => "?".to_string(),
        };

        let parked_age = match parked(&control_dir, lane_name, now_ms, cache_ttl_ms) {
            Ok(Some(p)) => format_age(Duration::from_millis(p.age_ms)),
            Ok(None) => "-".to_string(),
            Err(_) => "?".to_string(),
        };

        let notes = count_pending_notes(&control_dir, lane_name)
            .map(|n| n.to_string())
            .unwrap_or_else(|_| "?".to_string());

        let last_event = if let Some(last_ms) = get_last_event_time(&lane_dir) {
            if last_ms > 0 {
                let age = now_ms.saturating_sub(last_ms);
                format_age(Duration::from_millis(age))
            } else {
                "-".to_string()
            }
        } else {
            "-".to_string()
        };

        println!(
            "{}\t{}\t{}\t{}\t{}\t{}",
            lane_name, state, parked_info, parked_age, notes, last_event
        );
    }

    Ok(())
}

async fn watch_events(lanes_root: &Path, _cache_ttl_ms: u64, follow: bool) -> Result<()> {
    let mut offsets: HashMap<String, u64> = HashMap::new();
    let mut last_lanes: HashMap<String, bool> = HashMap::new();

    loop {
        let lanes = collect_lanes(lanes_root)?;

        // Track which lanes existed in the previous iteration
        let current_lanes: HashMap<String, bool> = lanes
            .iter()
            .map(|p| (p.to_string_lossy().to_string(), true))
            .collect();

        // For new lanes, emit events from the start
        for lane_dir in &lanes {
            let lane_key = lane_dir.to_string_lossy().to_string();
            if !last_lanes.contains_key(&lane_key) {
                offsets.remove(&lane_key);
            }
        }

        // Emit events from all lanes
        for lane_dir in lanes {
            let lane_key = lane_dir.to_string_lossy().to_string();
            let lane_name = lane_dir.file_name().and_then(|n| n.to_str()).unwrap_or("?");
            let control_dir = lane_dir.join("control");

            // Read the queue file and only emit new events
            let queue_file = control_dir.join("escalations.jsonl");
            if !queue_file.is_file() {
                continue;
            }

            let mut file = match fs::File::open(&queue_file) {
                Ok(f) => f,
                Err(_) => {
                    eprintln!("error: {}", lane_name);
                    continue;
                }
            };

            // Get file size
            let file_size = match file.metadata() {
                Ok(m) => m.len(),
                Err(_) => {
                    eprintln!("error: {}", lane_name);
                    continue;
                }
            };

            // Get the offset from the last read
            let start_offset = offsets.get(&lane_key).copied().unwrap_or(0);

            // Only read if there's new data
            if file_size > start_offset {
                if file.seek(std::io::SeekFrom::Start(start_offset)).is_err() {
                    eprintln!("error: {}", lane_name);
                    continue;
                }

                let mut buffer = Vec::new();
                if std::io::Read::read_to_end(&mut file, &mut buffer).is_err() {
                    eprintln!("error: {}", lane_name);
                    continue;
                }

                let content = String::from_utf8_lossy(&buffer);
                for line in content.lines() {
                    if line.trim().is_empty() {
                        continue;
                    }

                    // Try to parse as a QueueEvent and emit as WatchEvent
                    if let Ok(obj) = serde_json::from_str::<serde_json::Value>(line)
                        && let Some(event_type) = obj.get("event").and_then(|v| v.as_str())
                        && let Some(lane_in_event) = obj.get("lane").and_then(|v| v.as_str())
                        && lane_in_event == lane_name
                    {
                        let at_ms = obj.get("at_ms").and_then(|v| v.as_u64()).unwrap_or(0);
                        let kind_str = event_type;
                        let summary = match event_type {
                            "asked" => {
                                let blocking = obj
                                    .get("ask")
                                    .and_then(|a| a.get("blocking"))
                                    .and_then(|b| b.as_bool())
                                    .unwrap_or(false);
                                let id = obj.get("id").and_then(|v| v.as_str()).unwrap_or("?");
                                let blocking_text =
                                    if blocking { "blocking" } else { "non-blocking" };
                                format!("{} ({})", id, blocking_text)
                            }
                            "ruled" => obj
                                .get("id")
                                .and_then(|v| v.as_str())
                                .unwrap_or("?")
                                .to_string(),
                            "note" => {
                                let id = obj.get("id").and_then(|v| v.as_str()).unwrap_or("?");
                                let text_len = obj
                                    .get("text")
                                    .and_then(|v| v.as_str())
                                    .map(|t| t.len())
                                    .unwrap_or(0);
                                format!("{} ({} bytes)", id, text_len)
                            }
                            "note-delivered" => obj
                                .get("id")
                                .and_then(|v| v.as_str())
                                .unwrap_or("?")
                                .to_string(),
                            "rejected" => {
                                let id = obj.get("id").and_then(|v| v.as_str()).unwrap_or("?");
                                let reason =
                                    obj.get("reason").and_then(|v| v.as_str()).unwrap_or("?");
                                format!("{}: {}", id, reason)
                            }
                            "delivered" => {
                                let id = obj.get("id").and_then(|v| v.as_str()).unwrap_or("?");
                                let fresh =
                                    obj.get("fresh").and_then(|v| v.as_bool()).unwrap_or(false);
                                let fresh_text = if fresh { "fresh" } else { "resumed" };
                                format!("{} ({})", id, fresh_text)
                            }
                            "resume-fallback" => obj
                                .get("id")
                                .and_then(|v| v.as_str())
                                .unwrap_or("?")
                                .to_string(),
                            "lane-escalation-limit" => obj
                                .get("id")
                                .and_then(|v| v.as_str())
                                .unwrap_or("(no id)")
                                .to_string(),
                            _ => "?".to_string(),
                        };

                        let rfc_time = ms_to_rfc3339(at_ms);
                        let event_line =
                            format!("{} {} {} {}", rfc_time, lane_name, kind_str, summary);
                        let output = truncate_line(&event_line, 300);
                        println!("{}", output);
                    }
                }

                offsets.insert(lane_key.clone(), file_size);
            }

            last_lanes.insert(lane_key, true);
        }

        last_lanes = current_lanes;

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
}
