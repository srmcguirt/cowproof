//! Watch events: projection of the queue file into events (D22).
//!
//! This module provides functions to observe the escalation queue's events
//! and parked state for a lane without modifying the queue.

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::escalate::QueueEvent;

/// Kind of watch event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WatchKind {
    /// An ask was recorded (blocking flag indicates blocking).
    Ask,
    /// A ruling was recorded.
    Ruling,
    /// An ask was rejected.
    Rejected,
    /// A ruling reached the builder.
    Delivered,
    /// A parked session could not be resumed; counts as escalation.
    ResumeFallback,
    /// The lane ended as escalation-limit.
    LaneEscalationLimit,
    /// A note was sent.
    Note,
    /// A note was delivered.
    NoteDelivered,
}

/// One event from the queue file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchEvent {
    /// Milliseconds since Unix epoch.
    pub at_ms: u64,
    /// Lane name.
    pub lane: String,
    /// Event kind.
    pub kind: WatchKind,
    /// Runner-owned text only: no builder question text (trust boundary).
    /// For asks, shows id and blocking flag.
    /// For notes, shows id and byte length.
    pub summary: String,
}

/// Report of events with parse errors counted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchReport {
    pub events: Vec<WatchEvent>,
    pub skipped_lines: usize,
}

/// Currently parked escalation info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Parked {
    /// Escalation ID.
    pub id: String,
    /// Age in milliseconds.
    pub age_ms: u64,
    /// Cache TTL in milliseconds.
    pub cache_ttl_ms: u64,
    /// Whether age exceeds cache_ttl.
    pub past_cache: bool,
}

/// Project the queue file into watch events for a lane.
///
/// Events are returned in order. Malformed lines are skipped and counted.
/// The summary contains runner-owned text only:
/// - For asks: the id and blocking flag, not the question text
/// - For notes: the id and text byte length
/// - For other kinds: descriptive text
pub fn events(
    control_dir: &Path,
    lane: &str,
    since_ms: Option<u64>,
) -> std::io::Result<WatchReport> {
    let queue_file = control_dir.join("escalations.jsonl");
    let mut result = WatchReport {
        events: Vec::new(),
        skipped_lines: 0,
    };

    if !queue_file.exists() {
        return Ok(result);
    }

    let file = File::open(queue_file)?;
    let reader = BufReader::new(file);

    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }

        let event = match serde_json::from_str::<QueueEvent>(&line) {
            Ok(e) => e,
            Err(_) => {
                result.skipped_lines += 1;
                continue;
            }
        };

        match &event {
            QueueEvent::Asked {
                lane: event_lane,
                id,
                ask,
                at_ms,
                origin: _,
            } if event_lane == lane => {
                if let Some(since) = since_ms
                    && *at_ms < since
                {
                    continue;
                }
                let blocking_text = if ask.blocking {
                    "blocking"
                } else {
                    "non-blocking"
                };
                result.events.push(WatchEvent {
                    at_ms: *at_ms,
                    lane: event_lane.clone(),
                    kind: WatchKind::Ask,
                    summary: format!("{} ({})", id, blocking_text),
                });
            }
            QueueEvent::Ruled {
                lane: event_lane,
                id,
                verdict: _,
            } if event_lane == lane => {
                // Ruled events don't have at_ms; treat them as always included (no time filter)
                result.events.push(WatchEvent {
                    at_ms: 0,
                    lane: event_lane.clone(),
                    kind: WatchKind::Ruling,
                    summary: id.clone(),
                });
            }
            QueueEvent::Note {
                lane: event_lane,
                id,
                text,
                at_ms,
            } if event_lane == lane => {
                if let Some(since) = since_ms
                    && *at_ms < since
                {
                    continue;
                }
                result.events.push(WatchEvent {
                    at_ms: *at_ms,
                    lane: event_lane.clone(),
                    kind: WatchKind::Note,
                    summary: format!("{} ({} bytes)", id, text.len()),
                });
            }
            QueueEvent::NoteDelivered {
                lane: event_lane,
                id,
                at_ms,
            } if event_lane == lane => {
                if let Some(since) = since_ms
                    && *at_ms < since
                {
                    continue;
                }
                result.events.push(WatchEvent {
                    at_ms: *at_ms,
                    lane: event_lane.clone(),
                    kind: WatchKind::NoteDelivered,
                    summary: id.clone(),
                });
            }
            QueueEvent::Rejected {
                lane: event_lane,
                id,
                reason,
            } if event_lane == lane => {
                result.events.push(WatchEvent {
                    at_ms: 0,
                    lane: event_lane.clone(),
                    kind: WatchKind::Rejected,
                    summary: format!("{}: {}", id, reason),
                });
            }
            QueueEvent::Delivered {
                lane: event_lane,
                id,
                fresh,
            } if event_lane == lane => {
                let fresh_text = if *fresh { "fresh" } else { "resumed" };
                result.events.push(WatchEvent {
                    at_ms: 0,
                    lane: event_lane.clone(),
                    kind: WatchKind::Delivered,
                    summary: format!("{} ({})", id, fresh_text),
                });
            }
            QueueEvent::ResumeFallback {
                lane: event_lane,
                id,
            } if event_lane == lane => {
                result.events.push(WatchEvent {
                    at_ms: 0,
                    lane: event_lane.clone(),
                    kind: WatchKind::ResumeFallback,
                    summary: id.clone(),
                });
            }
            QueueEvent::LaneEscalationLimit {
                lane: event_lane,
                id,
            } if event_lane == lane => {
                let id_text = id.as_ref().map_or("(no id)".to_string(), |i| i.clone());
                result.events.push(WatchEvent {
                    at_ms: 0,
                    lane: event_lane.clone(),
                    kind: WatchKind::LaneEscalationLimit,
                    summary: id_text,
                });
            }
            _ => {
                // Events for other lanes are skipped
            }
        }
    }

    Ok(result)
}

/// Get the currently parked escalation for a lane, if any.
///
/// A lane with a parked escalation that has no ruling is considered parked.
/// Returns the escalation id, age in milliseconds, cache_ttl, and whether
/// age exceeds cache_ttl (past_cache).
pub fn parked(
    control_dir: &Path,
    lane: &str,
    now_ms: u64,
    cache_ttl_ms: u64,
) -> std::io::Result<Option<Parked>> {
    let queue_file = control_dir.join("escalations.jsonl");
    if !queue_file.exists() {
        return Ok(None);
    }

    let file = File::open(queue_file)?;
    let reader = BufReader::new(file);

    let mut asked: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    let mut ruled: std::collections::HashSet<String> = std::collections::HashSet::new();

    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }

        if let Ok(event) = serde_json::from_str::<QueueEvent>(&line) {
            match event {
                QueueEvent::Asked {
                    lane: event_lane,
                    id,
                    at_ms,
                    ..
                } if event_lane == lane => {
                    asked.insert(id, at_ms);
                }
                QueueEvent::Ruled {
                    lane: event_lane,
                    id,
                    verdict: _,
                } if event_lane == lane => {
                    ruled.insert(id);
                }
                _ => {}
            }
        }
    }

    // Find the most recent unruled ask
    let mut latest: Option<(String, u64)> = None;
    for (id, at_ms) in asked {
        if !ruled.contains(&id) && (latest.is_none() || at_ms > latest.as_ref().unwrap().1) {
            latest = Some((id, at_ms));
        }
    }

    if let Some((id, at_ms)) = latest {
        let age_ms = now_ms.saturating_sub(at_ms);
        let past_cache = age_ms > cache_ttl_ms;
        Ok(Some(Parked {
            id,
            age_ms,
            cache_ttl_ms,
            past_cache,
        }))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_events_ask_ruling_note_in_order() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let control_dir = tmpdir.path();

        // Manually write events
        let queue_file = control_dir.join("escalations.jsonl");
        std::fs::write(
            &queue_file,
            r#"{"event":"asked","lane":"l1","id":"l1:E1","ask":{"kind":"blocker","question":"test?","tried":[],"options":[{"id":"a","summary":"do A","cost":"1h"}],"recommend":"a","blocking":true},"origin":"builder","at_ms":1000}
{"event":"ruled","lane":"l1","id":"l1:E1","verdict":{"verdict":"answer","text":"go ahead"}}
{"event":"note","lane":"l1","id":"l1-n1","text":"FYI","at_ms":2000}
"#,
        )
        .unwrap();

        let report = events(control_dir, "l1", None).unwrap();
        assert_eq!(report.events.len(), 3);
        assert_eq!(report.skipped_lines, 0);

        assert_eq!(report.events[0].kind, WatchKind::Ask);
        assert_eq!(report.events[0].summary, "l1:E1 (blocking)");

        assert_eq!(report.events[1].kind, WatchKind::Ruling);
        assert_eq!(report.events[1].summary, "l1:E1");

        assert_eq!(report.events[2].kind, WatchKind::Note);
        assert_eq!(report.events[2].summary, "l1-n1 (3 bytes)");
    }

    #[test]
    fn test_events_since_filters_by_time() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let control_dir = tmpdir.path();

        let queue_file = control_dir.join("escalations.jsonl");
        std::fs::write(
            &queue_file,
            r#"{"event":"asked","lane":"l1","id":"l1:E1","ask":{"kind":"blocker","question":"test?","tried":[],"options":[{"id":"a","summary":"do A","cost":"1h"}],"recommend":"a","blocking":true},"origin":"builder","at_ms":1000}
{"event":"note","lane":"l1","id":"l1-n1","text":"FYI","at_ms":2000}
"#,
        )
        .unwrap();

        let report = events(control_dir, "l1", Some(1500)).unwrap();
        assert_eq!(report.events.len(), 1);
        assert_eq!(report.events[0].kind, WatchKind::Note);
    }

    #[test]
    fn test_events_skips_malformed_lines() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let control_dir = tmpdir.path();

        let queue_file = control_dir.join("escalations.jsonl");
        std::fs::write(
            &queue_file,
            r#"{"event":"asked","lane":"l1","id":"l1:E1","ask":{"kind":"blocker","question":"test?","tried":[],"options":[{"id":"a","summary":"do A","cost":"1h"}],"recommend":"a","blocking":true},"origin":"builder","at_ms":1000}
this is not json
{"event":"note","lane":"l1","id":"l1-n1","text":"FYI","at_ms":2000}
"#,
        )
        .unwrap();

        let report = events(control_dir, "l1", None).unwrap();
        assert_eq!(report.events.len(), 2);
        assert_eq!(report.skipped_lines, 1);
    }

    #[test]
    fn test_parked_returns_latest_unruled_ask() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let control_dir = tmpdir.path();

        let queue_file = control_dir.join("escalations.jsonl");
        std::fs::write(
            &queue_file,
            r#"{"event":"asked","lane":"l1","id":"l1:E1","ask":{"kind":"blocker","question":"test?","tried":[],"options":[{"id":"a","summary":"do A","cost":"1h"}],"recommend":"a","blocking":true},"origin":"builder","at_ms":1000}
{"event":"asked","lane":"l1","id":"l1:E2","ask":{"kind":"blocker","question":"test?","tried":[],"options":[{"id":"a","summary":"do A","cost":"1h"}],"recommend":"a","blocking":true},"origin":"builder","at_ms":2000}
"#,
        )
        .unwrap();

        let parked = parked(
            control_dir,
            "l1",
            70 * 60 * 1000 + 4_200_000,
            60 * 60 * 1000,
        )
        .unwrap()
        .unwrap();
        assert_eq!(parked.id, "l1:E2");
        assert_eq!(parked.age_ms, 70 * 60 * 1000 + 4_200_000 - 2000);
        assert_eq!(parked.cache_ttl_ms, 60 * 60 * 1000);
        assert!(parked.past_cache);
    }

    #[test]
    fn test_parked_returns_none_after_ruling() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let control_dir = tmpdir.path();

        let queue_file = control_dir.join("escalations.jsonl");
        std::fs::write(
            &queue_file,
            r#"{"event":"asked","lane":"l1","id":"l1:E1","ask":{"kind":"blocker","question":"test?","tried":[],"options":[{"id":"a","summary":"do A","cost":"1h"}],"recommend":"a","blocking":true},"origin":"builder","at_ms":1000}
{"event":"ruled","lane":"l1","id":"l1:E1","verdict":{"verdict":"answer","text":"go ahead"}}
"#,
        )
        .unwrap();

        let result = parked(control_dir, "l1", 5000, 60 * 60 * 1000).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_events_rejected() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let control_dir = tmpdir.path();

        let queue_file = control_dir.join("escalations.jsonl");
        std::fs::write(
            &queue_file,
            r#"{"event":"rejected","lane":"l1","id":"l1:E1","reason":"unknown escalation"}
"#,
        )
        .unwrap();

        let report = events(control_dir, "l1", None).unwrap();
        assert_eq!(report.events.len(), 1);
        assert_eq!(report.events[0].kind, WatchKind::Rejected);
        assert!(report.events[0].summary.contains("l1:E1"));
        assert!(report.events[0].summary.contains("unknown escalation"));
    }

    #[test]
    fn test_events_delivered() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let control_dir = tmpdir.path();

        let queue_file = control_dir.join("escalations.jsonl");
        std::fs::write(
            &queue_file,
            r#"{"event":"delivered","lane":"l1","id":"l1:E1","fresh":false}
"#,
        )
        .unwrap();

        let report = events(control_dir, "l1", None).unwrap();
        assert_eq!(report.events.len(), 1);
        assert_eq!(report.events[0].kind, WatchKind::Delivered);
        assert!(report.events[0].summary.contains("l1:E1"));
        assert!(report.events[0].summary.contains("resumed"));
    }

    #[test]
    fn test_events_resume_fallback() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let control_dir = tmpdir.path();

        let queue_file = control_dir.join("escalations.jsonl");
        std::fs::write(
            &queue_file,
            r#"{"event":"resume-fallback","lane":"l1","id":"l1:E1"}
"#,
        )
        .unwrap();

        let report = events(control_dir, "l1", None).unwrap();
        assert_eq!(report.events.len(), 1);
        assert_eq!(report.events[0].kind, WatchKind::ResumeFallback);
        assert_eq!(report.events[0].summary, "l1:E1");
    }

    #[test]
    fn test_events_lane_escalation_limit() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let control_dir = tmpdir.path();

        let queue_file = control_dir.join("escalations.jsonl");
        std::fs::write(
            &queue_file,
            r#"{"event":"lane-escalation-limit","lane":"l1","id":"l1:E3"}
"#,
        )
        .unwrap();

        let report = events(control_dir, "l1", None).unwrap();
        assert_eq!(report.events.len(), 1);
        assert_eq!(report.events[0].kind, WatchKind::LaneEscalationLimit);
        assert_eq!(report.events[0].summary, "l1:E3");
    }
}
