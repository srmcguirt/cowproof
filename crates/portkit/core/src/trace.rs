//! Per-call telemetry: what each tool actually cost in context.
//!
//! Claude Code exports OpenTelemetry — counts, latencies, token totals per
//! session. What it does not export is **bytes returned per tool call**, and
//! that is the number that decides whether a tool is worth having. Finding it
//! otherwise means parsing session transcripts after the fact; one such pass
//! over 878 sessions turned up 59,077 calls and 353 MB, with `read_file`
//! taking 33% of calls and images 74% of bytes. Useful, but archaeology.
//!
//! So portkit records it as it happens.
//!
//! # Recorded at the surfaces, not in the registry
//!
//! [`crate::Registry::call`] returns full fidelity; the CLI and MCP layers
//! apply the budget. Only they know what was *delivered* as opposed to what
//! was produced, and delivered is what context pays for. Recording in the
//! registry would report the pre-budget size and overstate every call.

use std::sync::Mutex;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// How a call ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Ok,
    /// Rejected before the tool ran — bad shape, or a name that does not exist.
    /// Tracked separately because a gate that fires often is doing its job,
    /// and one that never fires may be misconfigured.
    Rejected,
    /// The tool ran and failed.
    Failed,
}

/// Which surface the call came through.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Surface {
    Cli,
    Mcp,
    /// A call portkit did not serve, observed through a Claude Code hook.
    ///
    /// These are the expensive ones — `Read`, `Grep`, `Bash` — and without
    /// them the trace bank only measures portkit measuring itself.
    Agent,
}

/// One tool call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallRecord {
    pub tool: String,
    /// Which session produced it, so per-session patterns can be detected.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub session: String,
    /// What the call was about — a file path, a URL, a command. Enough to see
    /// the same target being fetched repeatedly, without storing arguments.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    pub surface: Surface,
    pub outcome: Outcome,
    pub at: String,
    pub duration_ms: f64,
    /// Arguments, serialized. Small, but it is what the model spent to ask.
    pub input_bytes: usize,
    /// What the tool produced, before any budget was applied.
    pub produced_bytes: usize,
    /// What actually reached the caller. The number context pays for.
    pub delivered_bytes: usize,
    /// How many arrays were trimmed to make it fit.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub elisions: usize,
}

fn is_zero(n: &usize) -> bool {
    *n == 0
}

impl CallRecord {
    /// Bytes the budget kept out of context. The whole point of the exercise.
    pub fn saved_bytes(&self) -> usize {
        self.produced_bytes.saturating_sub(self.delivered_bytes)
    }
}

/// Somewhere to put records.
///
/// Recording must never break a call, so implementations swallow their own
/// errors rather than propagating them.
pub trait Recorder: Send + Sync {
    fn record(&self, record: CallRecord);
}

/// Discards everything. The default, so tracing is opt-in.
pub struct NullRecorder;

impl Recorder for NullRecorder {
    fn record(&self, _record: CallRecord) {}
}

/// Appends one JSON object per line.
///
/// JSONL because it is append-only, survives a crash mid-write with at most
/// one bad line, and is trivially greppable — the same reasons the parity
/// harness uses it for cases.
pub struct JsonlRecorder {
    file: Mutex<std::fs::File>,
}

impl JsonlRecorder {
    pub fn create(path: &std::path::Path) -> std::io::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        Ok(Self {
            file: Mutex::new(file),
        })
    }

    /// `<root>/.portkit/traces/<yyyy-mm-dd>.jsonl`
    pub fn daily(root: &std::path::Path, today: &str) -> std::io::Result<Self> {
        Self::create(
            &root
                .join(".portkit")
                .join("traces")
                .join(format!("{today}.jsonl")),
        )
    }
}

impl Recorder for JsonlRecorder {
    fn record(&self, record: CallRecord) {
        use std::io::Write;
        let Ok(mut line) = serde_json::to_vec(&record) else {
            return;
        };
        line.push(b'\n');
        // A failed write must not fail the tool call that produced it.
        if let Ok(mut f) = self.file.lock() {
            let _ = f.write_all(&line);
        }
    }
}

/// RFC 3339, UTC. One format for every surface — a trace file with two
/// timestamp formats in it cannot be sorted or filtered by time.
///
/// Best-effort: a clock failure must never fail the call being measured.
pub fn now_rfc3339() -> String {
    use time::format_description::well_known::Rfc3339;
    time::OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_default()
}

/// Times a call and builds the record.
pub struct Timer {
    tool: String,
    surface: Surface,
    started: std::time::Instant,
    at: String,
    input_bytes: usize,
}

impl Timer {
    pub fn start(tool: &str, surface: Surface, input: &serde_json::Value, at: String) -> Self {
        Self {
            tool: tool.to_string(),
            surface,
            started: std::time::Instant::now(),
            at,
            input_bytes: serde_json::to_vec(input).map(|v| v.len()).unwrap_or(0),
        }
    }

    pub fn finish(
        self,
        outcome: Outcome,
        produced_bytes: usize,
        delivered_bytes: usize,
        elisions: usize,
    ) -> CallRecord {
        CallRecord {
            tool: self.tool,
            session: String::new(),
            target: None,
            surface: self.surface,
            outcome,
            at: self.at,
            duration_ms: duration_ms(self.started.elapsed()),
            input_bytes: self.input_bytes,
            produced_bytes,
            delivered_bytes,
            elisions,
        }
    }
}

fn duration_ms(d: Duration) -> f64 {
    // Three decimals: sub-millisecond calls are the interesting ones once a
    // resident index is doing the work.
    (d.as_secs_f64() * 1000.0 * 1000.0).round() / 1000.0
}

/// Aggregate view over recorded calls.
#[derive(Debug, Default, Clone, Serialize)]
pub struct Summary {
    pub calls: usize,
    pub ok: usize,
    pub rejected: usize,
    pub failed: usize,
    pub produced_bytes: usize,
    pub delivered_bytes: usize,
    pub total_ms: f64,
}

impl Summary {
    pub fn saved_bytes(&self) -> usize {
        self.produced_bytes.saturating_sub(self.delivered_bytes)
    }

    pub fn add(&mut self, r: &CallRecord) {
        self.calls += 1;
        match r.outcome {
            Outcome::Ok => self.ok += 1,
            Outcome::Rejected => self.rejected += 1,
            Outcome::Failed => self.failed += 1,
        }
        self.produced_bytes += r.produced_bytes;
        self.delivered_bytes += r.delivered_bytes;
        self.total_ms += r.duration_ms;
    }
}

/// Read a trace file, skipping lines a crash left malformed.
pub fn read_jsonl(path: &std::path::Path) -> std::io::Result<Vec<CallRecord>> {
    let raw = std::fs::read_to_string(path)?;
    Ok(raw
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn rec(tool: &str, produced: usize, delivered: usize, outcome: Outcome) -> CallRecord {
        CallRecord {
            tool: tool.into(),
            session: String::new(),
            target: None,
            surface: Surface::Mcp,
            outcome,
            at: "2026-09-09T00:00:00Z".into(),
            duration_ms: 1.5,
            input_bytes: 40,
            produced_bytes: produced,
            delivered_bytes: delivered,
            elisions: usize::from(produced > delivered),
        }
    }

    #[test]
    fn a_record_reports_what_the_budget_kept_out_of_context() {
        assert_eq!(rec("t", 100_000, 16_000, Outcome::Ok).saved_bytes(), 84_000);
    }

    #[test]
    fn an_untrimmed_call_saved_nothing() {
        assert_eq!(rec("t", 500, 500, Outcome::Ok).saved_bytes(), 0);
    }

    #[test]
    fn a_summary_separates_rejections_from_failures() {
        // A gate that fires often is working; one that never fires may be
        // misconfigured. Collapsing them would hide both.
        let mut s = Summary::default();
        s.add(&rec("a", 10, 10, Outcome::Ok));
        s.add(&rec("b", 10, 10, Outcome::Rejected));
        s.add(&rec("c", 10, 10, Outcome::Failed));
        assert_eq!((s.calls, s.ok, s.rejected, s.failed), (3, 1, 1, 1));
    }

    #[test]
    fn records_round_trip_through_jsonl() {
        let dir = std::env::temp_dir().join(format!("pk-trace-{}", std::process::id()));
        let path = dir.join("t.jsonl");
        let _ = std::fs::remove_file(&path);

        let r = JsonlRecorder::create(&path).unwrap();
        r.record(rec("alpha", 900, 100, Outcome::Ok));
        r.record(rec("beta", 50, 50, Outcome::Rejected));
        drop(r);

        let back = read_jsonl(&path).unwrap();
        assert_eq!(back.len(), 2);
        assert_eq!(back[0].tool, "alpha");
        assert_eq!(back[0].saved_bytes(), 800);
        assert_eq!(back[1].outcome, Outcome::Rejected);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_corrupt_line_does_not_lose_the_rest_of_the_file() {
        // An append-only log can be cut mid-write by a crash.
        let dir = std::env::temp_dir().join(format!("pk-trace-bad-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("t.jsonl");
        std::fs::write(&path, "{\"tool\":\"good\",\"surface\":\"cli\",\"outcome\":\"ok\",\"at\":\"x\",\"duration_ms\":1.0,\"input_bytes\":1,\"produced_bytes\":2,\"delivered_bytes\":2}\n{ truncated\n").unwrap();
        let back = read_jsonl(&path).unwrap();
        assert_eq!(back.len(), 1);
        assert_eq!(back[0].tool, "good");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn timestamps_are_rfc3339_on_every_surface() {
        // Mixed formats in one log make it unsortable.
        let t = now_rfc3339();
        assert!(t.ends_with('Z'), "expected RFC3339 UTC, got {t}");
        assert_eq!(t.chars().nth(4), Some('-'), "got {t}");
    }

    #[test]
    fn the_timer_measures_the_call_and_sizes_the_input() {
        let t = Timer::start("t", Surface::Cli, &json!({"a": 1}), "now".into());
        let r = t.finish(Outcome::Ok, 1_000, 200, 1);
        assert_eq!(r.input_bytes, 7); // {"a":1}
        assert_eq!(r.saved_bytes(), 800);
        assert!(r.duration_ms >= 0.0);
    }
}
