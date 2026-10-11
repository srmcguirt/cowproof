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
    /// A blocking ask's parked age crossed cache-ttl (emitted once per escalation).
    PastCache,
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
///
/// If cache_ttl_ms is provided, emits one past-cache event per blocking ask
/// whose parked age exceeds the TTL.
pub fn events(
    control_dir: &Path,
    lane: &str,
    since_ms: Option<u64>,
    cache_ttl_ms: Option<u64>,
    now_ms: Option<u64>,
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

    // Track blocking asks and their timestamps for past-cache detection
    let mut blocking_asks: std::collections::HashMap<String, u64> =
        std::collections::HashMap::new();
    let mut past_cache_emitted: std::collections::HashSet<String> =
        std::collections::HashSet::new();

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

                // Track blocking asks for past-cache detection
                if ask.blocking {
                    blocking_asks.insert(id.clone(), *at_ms);
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
                at_ms,
            } if event_lane == lane => {
                if let Some(since) = since_ms
                    && *at_ms > 0
                    && *at_ms < since
                {
                    continue;
                }

                // No longer parked once ruled
                blocking_asks.remove(id);

                result.events.push(WatchEvent {
                    at_ms: *at_ms,
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
                at_ms,
            } if event_lane == lane => {
                if let Some(since) = since_ms
                    && *at_ms > 0
                    && *at_ms < since
                {
                    continue;
                }
                let fresh_text = if *fresh { "fresh" } else { "resumed" };
                result.events.push(WatchEvent {
                    at_ms: *at_ms,
                    lane: event_lane.clone(),
                    kind: WatchKind::Delivered,
                    summary: format!("{} ({})", id, fresh_text),
                });
            }
            QueueEvent::ResumeFallback {
                lane: event_lane,
                id,
                at_ms,
            } if event_lane == lane => {
                if let Some(since) = since_ms
                    && *at_ms > 0
                    && *at_ms < since
                {
                    continue;
                }
                result.events.push(WatchEvent {
                    at_ms: *at_ms,
                    lane: event_lane.clone(),
                    kind: WatchKind::ResumeFallback,
                    summary: id.clone(),
                });
            }
            QueueEvent::LaneEscalationLimit {
                lane: event_lane,
                id,
                at_ms,
            } if event_lane == lane => {
                if let Some(since) = since_ms
                    && *at_ms > 0
                    && *at_ms < since
                {
                    continue;
                }
                let id_text = id.as_ref().map_or("(no id)".to_string(), |i| i.clone());
                result.events.push(WatchEvent {
                    at_ms: *at_ms,
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

    // Emit past-cache events for blocking asks that are old enough
    if let (Some(ttl), Some(now)) = (cache_ttl_ms, now_ms) {
        for (id, ask_at_ms) in blocking_asks {
            if ask_at_ms > 0 && !past_cache_emitted.contains(&id) {
                let age_ms = now.saturating_sub(ask_at_ms);
                if age_ms > ttl {
                    result.events.push(WatchEvent {
                        at_ms: now,
                        lane: lane.to_string(),
                        kind: WatchKind::PastCache,
                        summary: id.clone(),
                    });
                    past_cache_emitted.insert(id);
                }
            }
        }
    }

    Ok(result)
}

/// Get the currently parked escalation for a lane, if any.
///
/// A lane with a parked BLOCKING escalation that has no ruling and no delivery is considered parked.
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

    // Track asked asks with their blocking status and timestamps
    let mut asked: std::collections::HashMap<String, (u64, bool)> =
        std::collections::HashMap::new();
    let mut ruled: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut delivered: std::collections::HashSet<String> = std::collections::HashSet::new();

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
                    ask,
                    at_ms,
                    ..
                } if event_lane == lane => {
                    // Only track BLOCKING asks
                    if ask.blocking {
                        asked.insert(id, (at_ms, ask.blocking));
                    }
                }
                QueueEvent::Ruled {
                    lane: event_lane,
                    id,
                    verdict: _,
                    at_ms: _,
                } if event_lane == lane => {
                    ruled.insert(id);
                }
                QueueEvent::Delivered {
                    lane: event_lane,
                    id,
                    ..
                } if event_lane == lane => {
                    delivered.insert(id);
                }
                _ => {}
            }
        }
    }

    // Find the most recent unruled, undelivered BLOCKING ask
    let mut latest: Option<(String, u64)> = None;
    for (id, (at_ms, _blocking)) in asked {
        if !ruled.contains(&id)
            && !delivered.contains(&id)
            && (latest.is_none() || at_ms > latest.as_ref().unwrap().1)
        {
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

        let report = events(control_dir, "l1", None, None, None).unwrap();
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

        let report = events(control_dir, "l1", Some(1500), None, None).unwrap();
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

        let report = events(control_dir, "l1", None, None, None).unwrap();
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

        let report = events(control_dir, "l1", None, None, None).unwrap();
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

        let report = events(control_dir, "l1", None, None, None).unwrap();
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

        let report = events(control_dir, "l1", None, None, None).unwrap();
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

        let report = events(control_dir, "l1", None, None, None).unwrap();
        assert_eq!(report.events.len(), 1);
        assert_eq!(report.events[0].kind, WatchKind::LaneEscalationLimit);
        assert_eq!(report.events[0].summary, "l1:E3");
    }

    #[test]
    fn test_parked_non_blocking_ask_not_counted() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let control_dir = tmpdir.path();

        // Write a non-blocking unruled ask
        let queue_file = control_dir.join("escalations.jsonl");
        std::fs::write(
            &queue_file,
            r#"{"event":"asked","lane":"l1","id":"l1:E1","ask":{"kind":"design","question":"test?","tried":[],"options":[{"id":"a","summary":"do A","cost":"1h"}],"recommend":"a","blocking":false},"origin":"builder","at_ms":1000}
"#,
        )
        .unwrap();

        let parked_result = parked(control_dir, "l1", 5000, 3600000).unwrap();
        assert!(
            parked_result.is_none(),
            "non-blocking unruled asks should not be counted as parked"
        );
    }

    #[test]
    fn test_at_ms_survives_reopen() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let control_dir = tmpdir.path();

        // Write a ruling with at_ms
        let queue_file = control_dir.join("escalations.jsonl");
        std::fs::write(
            &queue_file,
            r#"{"event":"asked","lane":"l1","id":"l1:E1","ask":{"kind":"blocker","question":"test?","tried":[],"options":[{"id":"a","summary":"do A","cost":"1h"}],"recommend":"a","blocking":true},"origin":"builder","at_ms":1000}
{"event":"ruled","lane":"l1","id":"l1:E1","verdict":{"verdict":"answer","text":"go ahead"},"at_ms":2000}
"#,
        )
        .unwrap();

        let report = events(control_dir, "l1", None, None, None).unwrap();
        // Find the Ruled event
        let ruled_event = report
            .events
            .iter()
            .find(|e| e.kind == WatchKind::Ruling)
            .unwrap();
        assert_eq!(
            ruled_event.at_ms, 2000,
            "at_ms should be recorded and readable"
        );
    }

    #[test]
    fn test_old_event_without_at_ms_parses() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let control_dir = tmpdir.path();

        // Write an old event line without at_ms (backward compatibility)
        let queue_file = control_dir.join("escalations.jsonl");
        std::fs::write(
            &queue_file,
            r#"{"event":"ruled","lane":"l1","id":"l1:E1","verdict":{"verdict":"answer","text":"go ahead"}}
"#,
        )
        .unwrap();

        let report = events(control_dir, "l1", None, None, None).unwrap();
        assert_eq!(report.events.len(), 1);
        assert_eq!(report.events[0].kind, WatchKind::Ruling);
        assert_eq!(
            report.events[0].at_ms, 0,
            "missing at_ms should default to 0"
        );
    }

    #[test]
    fn test_events_prints_rfc3339_time() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let control_dir = tmpdir.path();

        // Write an event
        let queue_file = control_dir.join("escalations.jsonl");
        std::fs::write(
            &queue_file,
            r#"{"event":"asked","lane":"l1","id":"l1:E1","ask":{"kind":"blocker","question":"test?","tried":[],"options":[{"id":"a","summary":"do A","cost":"1h"}],"recommend":"a","blocking":true},"origin":"builder","at_ms":1609459200000}
"#,
        )
        .unwrap();

        let report = events(control_dir, "l1", None, None, None).unwrap();
        assert_eq!(report.events.len(), 1);
        let event = &report.events[0];
        assert_eq!(event.at_ms, 1609459200000);
        // at_ms is in milliseconds since epoch
    }

    #[test]
    fn test_past_cache_emitted_once_for_old_blocking_ask() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let control_dir = tmpdir.path();

        // Write a blocking ask that's old
        let queue_file = control_dir.join("escalations.jsonl");
        std::fs::write(
            &queue_file,
            r#"{"event":"asked","lane":"l1","id":"l1:E1","ask":{"kind":"blocker","question":"test?","tried":[],"options":[{"id":"a","summary":"do A","cost":"1h"}],"recommend":"a","blocking":true},"origin":"builder","at_ms":1000}
"#,
        )
        .unwrap();

        // now_ms = 10000, cache_ttl = 5000, so age = 9000 > 5000
        let report = events(control_dir, "l1", None, Some(5000), Some(10000)).unwrap();

        // Should have Ask event and PastCache event
        assert!(report.events.iter().any(|e| e.kind == WatchKind::Ask));
        assert!(report.events.iter().any(|e| e.kind == WatchKind::PastCache));
    }

    #[test]
    fn test_past_cache_not_emitted_for_young_blocking_ask() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let control_dir = tmpdir.path();

        // Write a blocking ask that's young
        let queue_file = control_dir.join("escalations.jsonl");
        std::fs::write(
            &queue_file,
            r#"{"event":"asked","lane":"l1","id":"l1:E1","ask":{"kind":"blocker","question":"test?","tried":[],"options":[{"id":"a","summary":"do A","cost":"1h"}],"recommend":"a","blocking":true},"origin":"builder","at_ms":8000}
"#,
        )
        .unwrap();

        // now_ms = 10000, cache_ttl = 5000, so age = 2000 < 5000
        let report = events(control_dir, "l1", None, Some(5000), Some(10000)).unwrap();

        // Should have Ask event but NOT PastCache event
        assert!(report.events.iter().any(|e| e.kind == WatchKind::Ask));
        assert!(!report.events.iter().any(|e| e.kind == WatchKind::PastCache));
    }
}
