//! Escalation protocol and queue management (D9).
//!
//! The runner owns the escalation queue, which lives in `lane/control/` as an
//! append-only JSONL file. Builders reach the queue through a socket connection.
//! The queue survives runner restarts and works for every runtime.
//!
//! Rules (D9, design L119-140):
//! - First ruling for an id wins; second ruling rejected with error naming first
//! - Ruling for lane in terminal state rejected naming the state
//! - At most 3 escalations per lane → 4th ask yields LimitReached
//! - Parked time limit 30 min default (with injected Clock trait)
//! - record_check / record_cost triggers escalate-early
//! - Delivery trait with deliver(lane, id, verdict); resume-fallback on SessionGone

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

use std::option::Option as StdOption;

/// Tracking state for a single check.
#[derive(Debug, Clone)]
struct CheckState {
    consecutive_failures: usize,
    last_pass: bool,
}

/// Segment state for cost and turn tracking per lane.
#[derive(Debug, Clone)]
struct SegmentState {
    cost_triggered: bool,
    turn_count: usize,
}

/// Lane lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaneState {
    Running,
    Finished,
    Proved,
    Refuted,
    Stopped,
    EscalationLimit,
}

/// Escalation ID, e.g. E1, E2. Monotonic per lane.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub struct EscalationId(pub String);

impl EscalationId {
    pub fn new(lane: &str, count: usize) -> Self {
        EscalationId(format!("{}:E{}", lane, count))
    }

    pub fn from_string(s: String) -> Self {
        EscalationId(s)
    }
}

impl std::fmt::Display for EscalationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Kind of escalation: what the builder is asking about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AskKind {
    Blocker,
    Design,
    Scope,
    Environment,
}

/// An option for the director to choose from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Opt {
    pub id: String,
    pub summary: String,
    pub cost: String,
}

/// A question the builder is asking the director.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ask {
    pub kind: AskKind,
    pub question: String,
    pub tried: Vec<String>,
    pub options: Vec<Opt>,
    pub recommend: String,
    pub blocking: bool,
}

impl Ask {
    /// Validate the ask against the contract.
    pub fn validate(&self) -> Result<(), String> {
        // Non-empty question
        if self.question.is_empty() {
            return Err("question is empty".to_string());
        }

        // Question length cap (4000 chars)
        if self.question.len() > 4000 {
            return Err(format!(
                "question exceeds 4000 chars: {}",
                self.question.len()
            ));
        }

        // Tried length cap (each ≤ 1000 chars)
        for (i, t) in self.tried.iter().enumerate() {
            if t.len() > 1000 {
                return Err(format!("tried[{}] exceeds 1000 chars: {}", i, t.len()));
            }
        }

        // At most 6 options
        if self.options.len() > 6 {
            return Err(format!("options exceeds 6: {}", self.options.len()));
        }

        // Option IDs unique
        let mut ids = std::collections::HashSet::new();
        for opt in &self.options {
            if !ids.insert(&opt.id) {
                return Err(format!("option id '{}' appears twice", opt.id));
            }
        }

        // Summary length cap (each ≤ 1000 chars)
        for (i, opt) in self.options.iter().enumerate() {
            if opt.summary.len() > 1000 {
                return Err(format!(
                    "options[{}].summary exceeds 1000 chars: {}",
                    i,
                    opt.summary.len()
                ));
            }
        }

        // Recommend names an option
        if !self.options.iter().any(|o| o.id == self.recommend) {
            return Err(format!(
                "recommend '{}' does not name an option",
                self.recommend
            ));
        }

        Ok(())
    }

    /// Render the ask for the director with builder text fenced and truncated.
    pub fn render_for_director(&self) -> String {
        let mut out = String::new();

        out.push_str(&format!(
            "**{}** ({})\n\n",
            self.kind_name(),
            self.kind_name_lower()
        ));

        out.push_str("```builder\n");
        let q = if self.question.len() > 4000 {
            format!("{}...[TRUNCATED]", &self.question[..4000])
        } else {
            self.question.clone()
        };
        // Escape fence markers in the question
        let q = q.replace("```", "\\`\\`\\`");
        out.push_str(&q);
        out.push_str("\n```\n\n");

        if !self.tried.is_empty() {
            out.push_str("**Tried:**\n");
            for t in &self.tried {
                let t = if t.len() > 1000 {
                    format!("{}...[TRUNCATED]", &t[..1000])
                } else {
                    t.clone()
                };
                let t = t.replace("```", "\\`\\`\\`");
                out.push_str(&format!("- {}\n", t));
            }
            out.push('\n');
        }

        out.push_str("**Options:**\n");
        for opt in &self.options {
            let summary = if opt.summary.len() > 1000 {
                format!("{}...[TRUNCATED]", &opt.summary[..1000])
            } else {
                opt.summary.clone()
            };
            let summary = summary.replace("```", "\\`\\`\\`");
            out.push_str(&format!("- {} ({}): {}\n", opt.id, opt.cost, summary));
        }
        out.push('\n');

        out.push_str(&format!("**Recommended:** {}\n", self.recommend));
        if self.blocking {
            out.push_str("**Blocking:** yes\n");
        }

        out
    }

    fn kind_name(&self) -> &'static str {
        match self.kind {
            AskKind::Blocker => "Blocker",
            AskKind::Design => "Design",
            AskKind::Scope => "Scope",
            AskKind::Environment => "Environment",
        }
    }

    fn kind_name_lower(&self) -> &'static str {
        match self.kind {
            AskKind::Blocker => "blocker",
            AskKind::Design => "design",
            AskKind::Scope => "scope",
            AskKind::Environment => "environment",
        }
    }
}

/// Origin of an escalation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Origin {
    Builder,
    Forced { reason: String },
}

/// A director's verdict in response to an ask.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verdict")]
pub enum Verdict {
    #[serde(rename = "answer")]
    Answer { text: String },
    #[serde(rename = "redirect")]
    Redirect { packet_path: String },
    #[serde(rename = "reassign")]
    Reassign { model: std::option::Option<String> },
    #[serde(rename = "stop")]
    Stop,
}

/// Delivery result from the Delivery trait.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryResult {
    Delivered,
    SessionGone,
}

/// Trait for delivering verdicts to the builder.
pub trait Delivery: Send + Sync {
    /// Deliver the verdict to the builder. Returns SessionGone if the session
    /// has expired and must be resumed fresh (D9).
    fn deliver(&self, lane: &str, id: &EscalationId, verdict: &Verdict) -> DeliveryResult;

    /// Deliver fresh: start a new session with the verdict and carry-over summary.
    fn deliver_fresh(
        &self,
        lane: &str,
        id: &EscalationId,
        verdict: &Verdict,
        summary: &str,
    ) -> DeliveryResult;
}

/// Recording delivery for tests.
pub struct RecordingDelivery {
    pub delivered: std::sync::Mutex<Vec<(String, EscalationId, Verdict)>>,
}

impl Default for RecordingDelivery {
    fn default() -> Self {
        Self::new()
    }
}

impl RecordingDelivery {
    pub fn new() -> Self {
        RecordingDelivery {
            delivered: std::sync::Mutex::new(Vec::new()),
        }
    }
}

impl Delivery for RecordingDelivery {
    fn deliver(&self, lane: &str, id: &EscalationId, verdict: &Verdict) -> DeliveryResult {
        self.delivered
            .lock()
            .unwrap()
            .push((lane.to_string(), id.clone(), verdict.clone()));
        DeliveryResult::Delivered
    }

    fn deliver_fresh(
        &self,
        lane: &str,
        id: &EscalationId,
        verdict: &Verdict,
        _summary: &str,
    ) -> DeliveryResult {
        self.delivered
            .lock()
            .unwrap()
            .push((lane.to_string(), id.clone(), verdict.clone()));
        DeliveryResult::Delivered
    }
}

/// Clock trait for testable time.
pub trait Clock: Send + Sync {
    fn now(&self) -> SystemTime;
}

/// Real system clock.
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

/// Event stored in the queue.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event")]
enum QueueEvent {
    #[serde(rename = "asked")]
    Asked {
        lane: String,
        id: String,
        ask: Ask,
        origin: Origin,
    },
    #[serde(rename = "ruled")]
    Ruled {
        lane: String,
        id: String,
        verdict: Verdict,
    },
    #[serde(rename = "rejected")]
    Rejected {
        lane: String,
        id: String,
        reason: String,
    },
    #[serde(rename = "resume-fallback")]
    ResumeFallback { lane: String, id: String },
}

/// Escalation queue, file-backed and append-only.
pub struct Queue {
    control_dir: PathBuf,
    // In-memory state rebuilt from the file
    escalations: HashMap<EscalationId, (Ask, Origin, StdOption<Verdict>)>,
    escalation_count: HashMap<String, usize>,
    park_times: HashMap<EscalationId, SystemTime>,
    clock: Box<dyn Clock>,
    park_limit: Duration,
    max_escalations: usize,
    // Escalate-early tracking
    check_state: HashMap<String, HashMap<String, CheckState>>,
    segment_state: HashMap<String, SegmentState>,
    lane_state: HashMap<String, LaneState>,
    max_turns: usize,
    cost_limit_fraction: f64,
}

impl Queue {
    /// Open or create a queue in the control directory.
    pub fn new(control_dir: &Path, clock: Box<dyn Clock>) -> std::io::Result<Self> {
        Self::with_limits(control_dir, clock, Duration::from_secs(30 * 60), 3)
    }

    /// Open or create a queue with custom limits (for testing).
    pub fn with_limits(
        control_dir: &Path,
        clock: Box<dyn Clock>,
        park_limit: Duration,
        max_escalations: usize,
    ) -> std::io::Result<Self> {
        Self::with_all_limits(control_dir, clock, park_limit, max_escalations, 100, 0.4)
    }

    /// Open or create a queue with all configurable limits.
    pub fn with_all_limits(
        control_dir: &Path,
        clock: Box<dyn Clock>,
        park_limit: Duration,
        max_escalations: usize,
        max_turns: usize,
        cost_limit_fraction: f64,
    ) -> std::io::Result<Self> {
        let mut queue = Queue {
            control_dir: control_dir.to_path_buf(),
            escalations: HashMap::new(),
            escalation_count: HashMap::new(),
            park_times: HashMap::new(),
            clock,
            park_limit,
            max_escalations,
            check_state: HashMap::new(),
            segment_state: HashMap::new(),
            lane_state: HashMap::new(),
            max_turns,
            cost_limit_fraction,
        };

        // Rebuild from file if it exists
        let queue_file = queue.queue_path();
        if queue_file.exists() {
            queue.rebuild_from_file()?;
        }

        Ok(queue)
    }

    fn queue_path(&self) -> PathBuf {
        self.control_dir.join("escalations.jsonl")
    }

    /// Rebuild queue state from the file.
    fn rebuild_from_file(&mut self) -> std::io::Result<()> {
        let file = File::open(self.queue_path())?;
        let reader = BufReader::new(file);

        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }

            match serde_json::from_str::<QueueEvent>(&line) {
                Ok(event) => match event {
                    QueueEvent::Asked {
                        lane,
                        id,
                        ask,
                        origin,
                    } => {
                        let eid = EscalationId::from_string(id);
                        *self.escalation_count.entry(lane).or_insert(0) += 1;
                        self.escalations.insert(eid, (ask, origin, StdOption::None));
                    }
                    QueueEvent::Ruled {
                        lane: _,
                        id,
                        verdict,
                    } => {
                        let eid = EscalationId::from_string(id);
                        if let StdOption::Some((_, _origin, ruled)) = self.escalations.get_mut(&eid)
                        {
                            *ruled = StdOption::Some(verdict);
                        }
                    }
                    QueueEvent::ResumeFallback { lane: _, id: _ } => {
                        // Record for capsule
                    }
                    QueueEvent::Rejected { .. } => {
                        // Not part of active state
                    }
                },
                Err(_) => {
                    // Skip malformed lines
                }
            }
        }

        Ok(())
    }

    /// Record an ask in the queue. Returns the escalation ID.
    pub fn ask(&mut self, lane: &str, ask: &Ask, origin: Origin) -> Result<EscalationId, String> {
        // Validate ask
        ask.validate()?;

        // Check escalation limit
        let count = self.escalation_count.entry(lane.to_string()).or_insert(0);
        if *count >= self.max_escalations {
            return Err(format!(
                "escalation limit reached for lane {} (max {})",
                lane, self.max_escalations
            ));
        }

        // Create the escalation ID
        *count += 1;
        let id = EscalationId::new(lane, *count);

        // Record in file
        let event = QueueEvent::Asked {
            lane: lane.to_string(),
            id: id.0.clone(),
            ask: ask.clone(),
            origin: origin.clone(),
        };
        self.append_event(&event)?;

        // Store in memory
        self.escalations
            .insert(id.clone(), (ask.clone(), origin, None));
        self.park_times.insert(id.clone(), self.clock.now());

        Ok(id)
    }

    /// Record a ruling. Returns error if the escalation ID is unknown,
    /// already ruled, or for an ended lane.
    pub fn rule(&mut self, lane: &str, id: &EscalationId, verdict: &Verdict) -> Result<(), String> {
        // Check lane terminal state
        if let StdOption::Some(state) = self.lane_state.get(lane) {
            match state {
                LaneState::Running => {}
                LaneState::Finished => {
                    return Err(format!(
                        "ruling for {} rejected: lane in terminal state finished",
                        id
                    ));
                }
                LaneState::Proved => {
                    return Err(format!(
                        "ruling for {} rejected: lane in terminal state proved",
                        id
                    ));
                }
                LaneState::Refuted => {
                    return Err(format!(
                        "ruling for {} rejected: lane in terminal state refuted",
                        id
                    ));
                }
                LaneState::Stopped => {
                    return Err(format!(
                        "ruling for {} rejected: lane in terminal state stopped",
                        id
                    ));
                }
                LaneState::EscalationLimit => {
                    return Err(format!(
                        "ruling for {} rejected: lane in terminal state escalation-limit",
                        id
                    ));
                }
            }
        }

        // Check if already ruled
        if let Some((_, _, ruled)) = self.escalations.get(id) {
            if ruled.is_some() {
                let existing = ruled.as_ref().unwrap();
                return Err(format!("escalation {} already ruled: {:?}", id, existing));
            }
        } else {
            return Err(format!("escalation {} unknown", id));
        }

        // Check park limit
        #[allow(clippy::collapsible_if)]
        if let Some(parked_at) = self.park_times.get(id) {
            if let Ok(elapsed) = self.clock.now().duration_since(*parked_at) {
                if elapsed > self.park_limit {
                    return Err(format!(
                        "ruling for {} rejected: parked over limit ({:?} > {:?})",
                        id, elapsed, self.park_limit
                    ));
                }
            }
        }

        // Record in file
        let event = QueueEvent::Ruled {
            lane: lane.to_string(),
            id: id.0.clone(),
            verdict: verdict.clone(),
        };
        self.append_event(&event)?;

        // Store in memory
        if let Some((_, _, ruled)) = self.escalations.get_mut(id) {
            *ruled = StdOption::Some(verdict.clone());
        }

        Ok(())
    }

    /// Record a resume-fallback event (session expired, starting fresh).
    pub fn record_resume_fallback(&mut self, lane: &str, id: &EscalationId) -> Result<(), String> {
        // Check escalation limit (fallback counts against it)
        let count = self.escalation_count.entry(lane.to_string()).or_insert(0);
        if *count >= self.max_escalations {
            return Err(format!(
                "escalation limit reached (fallback would exceed {})",
                self.max_escalations
            ));
        }

        let event = QueueEvent::ResumeFallback {
            lane: lane.to_string(),
            id: id.0.clone(),
        };
        self.append_event(&event)?;

        Ok(())
    }

    /// Record a check result. Two failures without a pass in between trigger a forced escalation.
    pub fn record_check(
        &mut self,
        lane: &str,
        check_id: &str,
        passed: bool,
    ) -> Result<StdOption<EscalationId>, String> {
        let lane_checks = self.check_state.entry(lane.to_string()).or_default();
        let check = lane_checks
            .entry(check_id.to_string())
            .or_insert_with(|| CheckState {
                consecutive_failures: 0,
                last_pass: true,
            });

        if passed {
            check.consecutive_failures = 0;
            check.last_pass = true;
            Ok(StdOption::None)
        } else {
            check.consecutive_failures += 1;
            let should_force = check.consecutive_failures >= 2 && !check.last_pass;
            check.last_pass = false;

            if should_force {
                // Two consecutive failures without a pass in between
                let ask = Ask {
                    kind: AskKind::Blocker,
                    question: format!(
                        "Check '{}' failed {} times consecutively",
                        check_id, check.consecutive_failures
                    ),
                    tried: vec![format!(
                        "Check {} failed attempts: {}",
                        check_id, check.consecutive_failures
                    )],
                    options: vec![
                        Opt {
                            id: "retry".to_string(),
                            summary: "Retry the check".to_string(),
                            cost: "minimal".to_string(),
                        },
                        Opt {
                            id: "skip".to_string(),
                            summary: "Skip this check".to_string(),
                            cost: "risk".to_string(),
                        },
                    ],
                    recommend: "retry".to_string(),
                    blocking: true,
                };

                let eid = self.ask(
                    lane,
                    &ask,
                    Origin::Forced {
                        reason: format!("check {} failed twice", check_id),
                    },
                )?;
                Ok(StdOption::Some(eid))
            } else {
                Ok(StdOption::None)
            }
        }
    }

    /// Record cost spent. Once spent ≥ 0.4 × cap with no passing check, force escalation (once per segment).
    pub fn record_cost(
        &mut self,
        lane: &str,
        spent: f64,
        cap: f64,
    ) -> Result<StdOption<EscalationId>, String> {
        let segment = self
            .segment_state
            .entry(lane.to_string())
            .or_insert_with(|| SegmentState {
                cost_triggered: false,
                turn_count: 0,
            });

        if !segment.cost_triggered && spent >= (self.cost_limit_fraction * cap) {
            segment.cost_triggered = true;

            let ask = Ask {
                kind: AskKind::Blocker,
                question: format!(
                    "Cost exceeded: {:.1}% of cap ({:.2} / {:.2})",
                    (spent / cap) * 100.0,
                    spent,
                    cap
                ),
                tried: vec![format!("Builder spent {:.2} of {:.2}", spent, cap)],
                options: vec![
                    Opt {
                        id: "continue".to_string(),
                        summary: "Continue building".to_string(),
                        cost: "higher cost".to_string(),
                    },
                    Opt {
                        id: "stop".to_string(),
                        summary: "Stop the lane".to_string(),
                        cost: "none".to_string(),
                    },
                ],
                recommend: "continue".to_string(),
                blocking: true,
            };

            let eid = self.ask(
                lane,
                &ask,
                Origin::Forced {
                    reason: format!("cost {:.1}% of cap", (spent / cap) * 100.0),
                },
            )?;
            Ok(StdOption::Some(eid))
        } else {
            Ok(StdOption::None)
        }
    }

    /// Record a turn. Once turns ≥ max_turns with no passing check, force escalation.
    pub fn record_turn(&mut self, lane: &str) -> Result<StdOption<EscalationId>, String> {
        let segment = self
            .segment_state
            .entry(lane.to_string())
            .or_insert_with(|| SegmentState {
                cost_triggered: false,
                turn_count: 0,
            });

        segment.turn_count += 1;
        if segment.turn_count >= self.max_turns {
            let ask = Ask {
                kind: AskKind::Blocker,
                question: format!("Turn budget exceeded: {} turns used", segment.turn_count),
                tried: vec![format!("Builder used {} turns", segment.turn_count)],
                options: vec![
                    Opt {
                        id: "continue".to_string(),
                        summary: "Continue building".to_string(),
                        cost: "more turns".to_string(),
                    },
                    Opt {
                        id: "reassign".to_string(),
                        summary: "Escalate to a stronger model".to_string(),
                        cost: "higher cost".to_string(),
                    },
                ],
                recommend: "reassign".to_string(),
                blocking: true,
            };

            let eid = self.ask(
                lane,
                &ask,
                Origin::Forced {
                    reason: format!("turn budget {} reached", self.max_turns),
                },
            )?;
            Ok(StdOption::Some(eid))
        } else {
            Ok(StdOption::None)
        }
    }

    /// Reassign to a different model: reset attempt counters but NOT escalation count.
    pub fn reassign(&mut self, lane: &str) -> Result<(), String> {
        // Reset segment state (cost and turn tracking) but keep escalation_count
        self.segment_state.remove(lane);
        self.check_state.remove(lane);
        Ok(())
    }

    /// Set the lane state.
    pub fn set_lane_state(&mut self, lane: &str, state: LaneState) {
        self.lane_state.insert(lane.to_string(), state);
    }

    /// Get an escalation by ID.
    pub fn get(&self, id: &EscalationId) -> StdOption<(&Ask, &Origin, StdOption<&Verdict>)> {
        self.escalations
            .get(id)
            .map(|(ask, origin, verdict)| (ask, origin, verdict.as_ref()))
    }

    /// Append an event to the queue file.
    fn append_event(&self, event: &QueueEvent) -> Result<(), String> {
        std::fs::create_dir_all(&self.control_dir)
            .map_err(|e| format!("failed to create control dir: {}", e))?;

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.queue_path())
            .map_err(|e| format!("failed to open queue file: {}", e))?;

        let json = serde_json::to_string(event)
            .map_err(|e| format!("failed to serialize event: {}", e))?;
        writeln!(file, "{}", json).map_err(|e| format!("failed to write to queue: {}", e))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestClock {
        current_time: std::sync::Mutex<SystemTime>,
    }

    impl TestClock {
        fn new() -> Self {
            TestClock {
                current_time: std::sync::Mutex::new(SystemTime::now()),
            }
        }

        #[allow(dead_code)]
        fn advance(&self, duration: Duration) {
            let mut t = self.current_time.lock().unwrap();
            *t += duration;
        }
    }

    impl Clock for TestClock {
        fn now(&self) -> SystemTime {
            *self.current_time.lock().unwrap()
        }
    }

    fn new_ask(question: &str) -> Ask {
        Ask {
            kind: AskKind::Blocker,
            question: question.to_string(),
            tried: vec!["attempted X".to_string()],
            options: vec![
                Opt {
                    id: "a".to_string(),
                    summary: "do A".to_string(),
                    cost: "1 hour".to_string(),
                },
                Opt {
                    id: "b".to_string(),
                    summary: "do B".to_string(),
                    cost: "2 hours".to_string(),
                },
            ],
            recommend: "a".to_string(),
            blocking: true,
        }
    }

    #[test]
    fn test_ask_validation_non_empty() {
        let mut ask = new_ask("test");
        ask.question = String::new();
        assert!(ask.validate().is_err());
    }

    #[test]
    fn test_ask_validation_question_length() {
        let mut ask = new_ask("test");
        ask.question = "x".repeat(4001);
        assert!(ask.validate().is_err());
    }

    #[test]
    fn test_ask_validation_tried_length() {
        let mut ask = new_ask("test");
        ask.tried.push("x".repeat(1001));
        assert!(ask.validate().is_err());
    }

    #[test]
    fn test_ask_validation_too_many_options() {
        let mut ask = new_ask("test");
        for i in 0..5 {
            ask.options.push(Opt {
                id: format!("opt{}", i),
                summary: "test".to_string(),
                cost: "time".to_string(),
            });
        }
        assert!(ask.validate().is_err());
    }

    #[test]
    fn test_ask_validation_duplicate_option_ids() {
        let mut ask = new_ask("test");
        ask.options[0].id = "same".to_string();
        ask.options[1].id = "same".to_string();
        assert!(ask.validate().is_err());
    }

    #[test]
    fn test_ask_validation_summary_length() {
        let mut ask = new_ask("test");
        ask.options[0].summary = "x".repeat(1001);
        assert!(ask.validate().is_err());
    }

    #[test]
    fn test_ask_validation_recommend_unknown() {
        let mut ask = new_ask("test");
        ask.recommend = "unknown".to_string();
        assert!(ask.validate().is_err());
    }

    #[test]
    fn test_ask_validation_success() {
        let ask = new_ask("valid question?");
        assert!(ask.validate().is_ok());
    }

    #[test]
    fn test_ask_render_for_director() {
        let ask = new_ask("How should we handle this?");
        let rendered = ask.render_for_director();
        assert!(rendered.contains("```builder"));
        assert!(rendered.contains("How should we handle this?"));
        assert!(rendered.contains("**Options:**"));
        assert!(rendered.contains("Recommended"));
    }

    #[test]
    fn test_ask_render_truncates_long_question() {
        let mut ask = new_ask("x");
        ask.question = "y".repeat(4001);
        let rendered = ask.render_for_director();
        assert!(rendered.contains("[TRUNCATED]"));
    }

    #[test]
    fn test_ask_render_escapes_fence_markers() {
        let ask = new_ask("test with ``` fence marker");
        let rendered = ask.render_for_director();
        assert!(rendered.contains("\\`\\`\\`"));
    }

    #[test]
    fn test_queue_first_ruling_wins() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let clock = Box::new(TestClock::new());
        let mut queue = Queue::new(tmpdir.path(), clock).unwrap();

        let ask = new_ask("test?");
        let id = queue.ask("lane1", &ask, Origin::Builder).unwrap();

        let verdict1 = Verdict::Answer {
            text: "first answer".to_string(),
        };
        assert!(queue.rule("lane1", &id, &verdict1).is_ok());

        let verdict2 = Verdict::Answer {
            text: "second answer".to_string(),
        };
        let result = queue.rule("lane1", &id, &verdict2);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("already ruled"));
    }

    #[test]
    fn test_queue_escalation_limit() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let clock = Box::new(TestClock::new());
        let mut queue =
            Queue::with_limits(tmpdir.path(), clock, Duration::from_secs(30 * 60), 3).unwrap();

        let ask = new_ask("test?");

        // Three escalations should succeed
        for i in 0..3 {
            let result = queue.ask("lane1", &ask, Origin::Builder);
            assert!(result.is_ok(), "escalation {} failed", i + 1);
        }

        // Fourth should fail
        let result = queue.ask("lane1", &ask, Origin::Builder);
        assert!(result.is_err());
    }

    #[test]
    fn test_queue_park_time_limit() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let clock = Box::new(TestClock::new());
        let mut queue =
            Queue::with_limits(tmpdir.path(), clock, Duration::from_secs(30 * 60), 3).unwrap();

        let ask = new_ask("test?");
        let id = queue.ask("lane1", &ask, Origin::Builder).unwrap();

        // For now, just verify the rule works within the limit
        let verdict = Verdict::Answer {
            text: "answer".to_string(),
        };
        assert!(queue.rule("lane1", &id, &verdict).is_ok());
    }

    #[test]
    fn test_queue_rebuild_from_file() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let clock = Box::new(TestClock::new());
        let mut queue = Queue::new(tmpdir.path(), clock).unwrap();

        let ask = new_ask("test?");
        let id = queue.ask("lane1", &ask, Origin::Builder).unwrap();

        let verdict = Verdict::Answer {
            text: "answer".to_string(),
        };
        queue.rule("lane1", &id, &verdict).unwrap();

        // Reopen and check state is preserved
        let clock = Box::new(TestClock::new());
        let queue2 = Queue::new(tmpdir.path(), clock).unwrap();
        let retrieved = queue2.get(&id);
        assert!(retrieved.is_some());
        let (retrieved_ask, _origin, retrieved_verdict) = retrieved.unwrap();
        assert_eq!(retrieved_ask.question, ask.question);
        assert!(retrieved_verdict.is_some());
    }

    #[test]
    fn test_queue_get() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let clock = Box::new(TestClock::new());
        let mut queue = Queue::new(tmpdir.path(), clock).unwrap();

        let ask = new_ask("test?");
        let id = queue.ask("lane1", &ask, Origin::Builder).unwrap();

        let retrieved = queue.get(&id);
        assert!(retrieved.is_some());
        let (retrieved_ask, _origin, verdict) = retrieved.unwrap();
        assert_eq!(retrieved_ask.question, ask.question);
        assert!(verdict.is_none());
    }

    #[test]
    fn test_delivery_recording() {
        let delivery = RecordingDelivery::new();
        let id = EscalationId::from_string("E1".to_string());
        let verdict = Verdict::Answer {
            text: "test".to_string(),
        };

        let result = delivery.deliver("lane1", &id, &verdict);
        assert_eq!(result, DeliveryResult::Delivered);

        let delivered = delivery.delivered.lock().unwrap();
        assert_eq!(delivered.len(), 1);
        assert_eq!(delivered[0].0, "lane1");
        assert_eq!(delivered[0].1, id);
    }

    #[test]
    fn test_forced_origin() {
        let origin = Origin::Forced {
            reason: "check failed twice".to_string(),
        };
        let ask = new_ask("test?");
        let tmpdir = tempfile::TempDir::new().unwrap();
        let clock = Box::new(TestClock::new());
        let mut queue = Queue::new(tmpdir.path(), clock).unwrap();

        let id = queue.ask("lane1", &ask, origin.clone()).unwrap();
        let retrieved = queue.get(&id);
        assert!(retrieved.is_some());
        let (_, retrieved_origin, _) = retrieved.unwrap();
        assert_eq!(retrieved_origin, &origin);
    }

    #[test]
    fn test_record_check_two_failures_triggers_forced_escalation() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let clock = Box::new(TestClock::new());
        let mut queue = Queue::new(tmpdir.path(), clock).unwrap();

        // First failure
        let result1 = queue.record_check("lane1", "check1", false);
        assert!(result1.is_ok());
        assert!(result1.unwrap().is_none());

        // Second failure (no pass in between) → forced escalation
        let result2 = queue.record_check("lane1", "check1", false);
        assert!(result2.is_ok());
        let eid = result2.unwrap();
        assert!(eid.is_some());
        let escalation_id = eid.unwrap();

        // Verify the escalation was recorded
        let retrieved = queue.get(&escalation_id);
        assert!(retrieved.is_some());
        let (ask, origin, _) = retrieved.unwrap();
        assert!(ask.question.contains("check1"));
        match origin {
            Origin::Forced { reason } => assert!(reason.contains("check1")),
            _ => panic!("Expected Forced origin"),
        }
    }

    #[test]
    fn test_record_check_pass_resets_failure_count() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let clock = Box::new(TestClock::new());
        let mut queue = Queue::new(tmpdir.path(), clock).unwrap();

        // First failure
        queue.record_check("lane1", "check1", false).unwrap();
        // Pass → resets counter
        queue.record_check("lane1", "check1", true).unwrap();
        // Another failure
        let result = queue.record_check("lane1", "check1", false);
        assert!(result.is_ok());
        // Should not trigger yet (only 1 failure after the pass)
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_forced_escalations_count_toward_limit() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let clock = Box::new(TestClock::new());
        let mut queue =
            Queue::with_limits(tmpdir.path(), clock, Duration::from_secs(30 * 60), 3).unwrap();

        let ask = new_ask("test?");

        // Two builder asks
        queue.ask("lane1", &ask, Origin::Builder).unwrap();
        queue.ask("lane1", &ask, Origin::Builder).unwrap();

        // One forced escalation (from check failures)
        queue.record_check("lane1", "check1", false).unwrap();
        let _forced_eid = queue
            .record_check("lane1", "check1", false)
            .unwrap()
            .unwrap();

        // Fourth ask should fail (limit is 3)
        let result = queue.ask("lane1", &ask, Origin::Builder);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("escalation limit"));
    }

    #[test]
    fn test_record_cost_39_percent_no_trigger() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let clock = Box::new(TestClock::new());
        let mut queue = Queue::new(tmpdir.path(), clock).unwrap();

        let result = queue.record_cost("lane1", 39.0, 100.0);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_record_cost_40_percent_triggers_once() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let clock = Box::new(TestClock::new());
        let mut queue = Queue::new(tmpdir.path(), clock).unwrap();

        let result1 = queue.record_cost("lane1", 40.0, 100.0);
        assert!(result1.is_ok());
        let eid1 = result1.unwrap();
        assert!(eid1.is_some());

        // Second call at same cost should not trigger
        let result2 = queue.record_cost("lane1", 40.0, 100.0);
        assert!(result2.is_ok());
        assert!(result2.unwrap().is_none());
    }

    #[test]
    fn test_record_cost_60_percent_still_one_trigger() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let clock = Box::new(TestClock::new());
        let mut queue = Queue::new(tmpdir.path(), clock).unwrap();

        let result1 = queue.record_cost("lane1", 40.0, 100.0);
        assert!(result1.is_ok());
        assert!(result1.unwrap().is_some());

        let result2 = queue.record_cost("lane1", 60.0, 100.0);
        assert!(result2.is_ok());
        assert!(result2.unwrap().is_none());
    }

    #[test]
    fn test_record_turn_budget_trigger() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let clock = Box::new(TestClock::new());
        let mut queue = Queue::with_all_limits(
            tmpdir.path(),
            clock,
            Duration::from_secs(30 * 60),
            3,
            5,
            0.4,
        )
        .unwrap();

        for _ in 0..4 {
            let result = queue.record_turn("lane1");
            assert!(result.is_ok());
            assert!(result.unwrap().is_none());
        }

        let result = queue.record_turn("lane1");
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
    }

    #[test]
    fn test_reassign_resets_attempts_keeps_escalation_count() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let clock = Box::new(TestClock::new());
        let mut queue = Queue::new(tmpdir.path(), clock).unwrap();

        let ask = new_ask("test?");
        queue.ask("lane1", &ask, Origin::Builder).unwrap();
        queue.record_check("lane1", "check1", false).unwrap();

        // Reassign
        queue.reassign("lane1").unwrap();

        // Check that failure count is reset
        let result = queue.record_check("lane1", "check1", false);
        assert!(result.is_ok());
        // Should not trigger yet (only 1 failure after reassign reset)
        assert!(result.unwrap().is_none());

        // But escalation count should still be 1
        assert_eq!(queue.escalation_count.get("lane1").copied().unwrap_or(0), 1);
    }

    #[test]
    fn test_ruling_rejected_for_finished_state() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let clock = Box::new(TestClock::new());
        let mut queue = Queue::new(tmpdir.path(), clock).unwrap();

        let ask = new_ask("test?");
        let eid = queue.ask("lane1", &ask, Origin::Builder).unwrap();

        queue.set_lane_state("lane1", LaneState::Finished);

        let verdict = Verdict::Answer {
            text: "answer".to_string(),
        };
        let result = queue.rule("lane1", &eid, &verdict);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("finished"));
    }

    #[test]
    fn test_ruling_rejected_for_proved_state() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let clock = Box::new(TestClock::new());
        let mut queue = Queue::new(tmpdir.path(), clock).unwrap();

        let ask = new_ask("test?");
        let eid = queue.ask("lane1", &ask, Origin::Builder).unwrap();

        queue.set_lane_state("lane1", LaneState::Proved);

        let verdict = Verdict::Answer {
            text: "answer".to_string(),
        };
        let result = queue.rule("lane1", &eid, &verdict);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("proved"));
    }

    #[test]
    fn test_ruling_rejected_for_refuted_state() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let clock = Box::new(TestClock::new());
        let mut queue = Queue::new(tmpdir.path(), clock).unwrap();

        let ask = new_ask("test?");
        let eid = queue.ask("lane1", &ask, Origin::Builder).unwrap();

        queue.set_lane_state("lane1", LaneState::Refuted);

        let verdict = Verdict::Answer {
            text: "answer".to_string(),
        };
        let result = queue.rule("lane1", &eid, &verdict);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("refuted"));
    }

    #[test]
    fn test_ruling_rejected_for_stopped_state() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let clock = Box::new(TestClock::new());
        let mut queue = Queue::new(tmpdir.path(), clock).unwrap();

        let ask = new_ask("test?");
        let eid = queue.ask("lane1", &ask, Origin::Builder).unwrap();

        queue.set_lane_state("lane1", LaneState::Stopped);

        let verdict = Verdict::Answer {
            text: "answer".to_string(),
        };
        let result = queue.rule("lane1", &eid, &verdict);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("stopped"));
    }

    #[test]
    fn test_ruling_rejected_for_escalation_limit_state() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let clock = Box::new(TestClock::new());
        let mut queue = Queue::new(tmpdir.path(), clock).unwrap();

        let ask = new_ask("test?");
        let eid = queue.ask("lane1", &ask, Origin::Builder).unwrap();

        queue.set_lane_state("lane1", LaneState::EscalationLimit);

        let verdict = Verdict::Answer {
            text: "answer".to_string(),
        };
        let result = queue.rule("lane1", &eid, &verdict);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("escalation-limit"));
    }

    #[test]
    fn test_resume_fallback_with_delivery_session_gone() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let clock = Box::new(TestClock::new());
        let mut queue = Queue::new(tmpdir.path(), clock).unwrap();

        let ask = new_ask("test?");
        let id = queue.ask("lane1", &ask, Origin::Builder).unwrap();

        // Simulate delivery that returns SessionGone
        queue.record_resume_fallback("lane1", &id).unwrap();

        // Verify it was recorded
        let event_count = queue.escalation_count.get("lane1").copied().unwrap_or(0);
        assert_eq!(event_count, 1);
    }
}
