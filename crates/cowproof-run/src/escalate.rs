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
//! - Delivery trait with deliver(lane, id, verdict); `Queue::rule_and_deliver`
//!   is the one path that rules and delivers. On SessionGone it records a
//!   resume-fallback (counted against the escalation limit) and starts a fresh
//!   session with a carry-over summary built from the queue.

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

impl LaneState {
    /// Name used in errors and logs, matching the design's lane-state names.
    pub fn name(self) -> &'static str {
        match self {
            LaneState::Running => "running",
            LaneState::Finished => "finished",
            LaneState::Proved => "proved",
            LaneState::Refuted => "refuted",
            LaneState::Stopped => "stopped",
            LaneState::EscalationLimit => "escalation-limit",
        }
    }
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
            format!("{}...[TRUNCATED]", cut(&self.question, 4000))
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
                    format!("{}...[TRUNCATED]", cut(t, 1000))
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
                format!("{}...[TRUNCATED]", cut(&opt.summary, 1000))
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

/// A delivery failed for a reason other than a gone session (spawn failure,
/// broken pipe, and so on). The message is for the director.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryError(pub String);

impl std::fmt::Display for DeliveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "delivery failed: {}", self.0)
    }
}

impl std::error::Error for DeliveryError {}

/// Trait for delivering verdicts to the builder.
pub trait Delivery: Send {
    /// Deliver the verdict to the builder by resuming its parked session.
    /// Returns `SessionGone` if the session is missing or expired (D9).
    fn deliver(
        &mut self,
        lane: &str,
        id: &EscalationId,
        verdict: &Verdict,
    ) -> Result<DeliveryResult, DeliveryError>;

    /// Start a fresh session on the same model and clone with the verdict and
    /// the runner's carry-over summary.
    fn deliver_fresh(
        &mut self,
        lane: &str,
        id: &EscalationId,
        verdict: &Verdict,
        summary: &str,
    ) -> Result<(), DeliveryError>;
}

/// Recording delivery for tests and dry runs: always delivers to the live session.
#[derive(Debug, Default)]
pub struct RecordingDelivery {
    pub delivered: Vec<(String, EscalationId, Verdict)>,
    pub fresh: Vec<(String, EscalationId, Verdict, String)>,
}

impl RecordingDelivery {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Delivery for RecordingDelivery {
    fn deliver(
        &mut self,
        lane: &str,
        id: &EscalationId,
        verdict: &Verdict,
    ) -> Result<DeliveryResult, DeliveryError> {
        self.delivered
            .push((lane.to_string(), id.clone(), verdict.clone()));
        Ok(DeliveryResult::Delivered)
    }

    fn deliver_fresh(
        &mut self,
        lane: &str,
        id: &EscalationId,
        verdict: &Verdict,
        summary: &str,
    ) -> Result<(), DeliveryError> {
        self.fresh.push((
            lane.to_string(),
            id.clone(),
            verdict.clone(),
            summary.to_string(),
        ));
        Ok(())
    }
}

/// How `Queue::rule_and_deliver` got the ruling to the builder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryOutcome {
    /// The parked session was resumed with the ruling.
    Delivered,
    /// The session was gone; a fresh session started with the ruling and a
    /// carry-over summary. Recorded as `resume-fallback` and counted against
    /// the escalation limit.
    FreshSession,
    /// The session was gone and the fallback would exceed the escalation
    /// limit: the lane ended as `escalation-limit`, no fresh session started.
    EscalationLimit,
}

/// Why `Queue::rule_and_deliver` failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleError {
    /// The ruling was rejected (duplicate, unknown id, wrong lane, terminal
    /// lane state, park limit). Nothing was delivered.
    Ruling(String),
    /// The ruling is recorded but the delivery failed. The ruling stays
    /// recorded, so a second ruling for the same id is still a duplicate.
    Delivery(DeliveryError),
    /// Writing a queue event failed after the ruling was accepted.
    Record(String),
}

impl std::fmt::Display for RuleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuleError::Ruling(m) | RuleError::Record(m) => write!(f, "{}", m),
            RuleError::Delivery(e) => write!(f, "{}", e),
        }
    }
}

impl std::error::Error for RuleError {}

/// First `max` bytes of `s`, backed off to a char boundary (a byte slice
/// through a multi-byte character would panic).
fn cut(s: &str, max: usize) -> &str {
    let mut end = max.min(s.len());
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

fn describe_verdict(verdict: &Verdict) -> String {
    match verdict {
        Verdict::Answer { text } => format!("answer: {}", text),
        Verdict::Redirect { packet_path } => format!("redirect to packet {}", packet_path),
        Verdict::Reassign { model: Some(m) } => format!("reassign to {}", m),
        Verdict::Reassign { model: None } => "reassign to the next model on the ladder".to_string(),
        Verdict::Stop => "stop".to_string(),
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
        /// Milliseconds since the Unix epoch when the lane parked. Lets a
        /// rebuilt queue keep enforcing the park limit. 0 = unknown (old file).
        #[serde(default)]
        at_ms: u64,
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
    /// The ruling reached the builder. `fresh` = through a fresh session.
    #[serde(rename = "delivered")]
    Delivered {
        lane: String,
        id: String,
        #[serde(default)]
        fresh: bool,
    },
    /// The parked session could not be resumed; counts as one escalation.
    #[serde(rename = "resume-fallback")]
    ResumeFallback { lane: String, id: String },
    /// The lane ended as `escalation-limit`.
    #[serde(rename = "lane-escalation-limit")]
    LaneEscalationLimit {
        lane: String,
        #[serde(default)]
        id: StdOption<String>,
    },
}

/// One escalation held by the queue.
struct Entry {
    lane: String,
    ask: Ask,
    origin: Origin,
    verdict: StdOption<Verdict>,
    delivered: bool,
}

/// Escalation queue, file-backed and append-only.
pub struct Queue {
    control_dir: PathBuf,
    // In-memory state rebuilt from the file
    escalations: HashMap<EscalationId, Entry>,
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

    fn now_ms(&self) -> u64 {
        self.clock
            .now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
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

            // Skip malformed lines
            let Ok(event) = serde_json::from_str::<QueueEvent>(&line) else {
                continue;
            };
            match event {
                QueueEvent::Asked {
                    lane,
                    id,
                    ask,
                    origin,
                    at_ms,
                } => {
                    let eid = EscalationId::from_string(id);
                    *self.escalation_count.entry(lane.clone()).or_insert(0) += 1;
                    if at_ms > 0 {
                        self.park_times.insert(
                            eid.clone(),
                            SystemTime::UNIX_EPOCH + Duration::from_millis(at_ms),
                        );
                    }
                    self.escalations.insert(
                        eid,
                        Entry {
                            lane,
                            ask,
                            origin,
                            verdict: StdOption::None,
                            delivered: false,
                        },
                    );
                }
                QueueEvent::Ruled {
                    lane: _,
                    id,
                    verdict,
                } => {
                    if let Some(entry) = self.escalations.get_mut(&EscalationId::from_string(id)) {
                        entry.verdict = StdOption::Some(verdict);
                    }
                }
                QueueEvent::Delivered { id, .. } => {
                    if let Some(entry) = self.escalations.get_mut(&EscalationId::from_string(id)) {
                        entry.delivered = true;
                    }
                }
                QueueEvent::ResumeFallback { lane, id: _ } => {
                    // A fallback counts against the escalation limit.
                    *self.escalation_count.entry(lane).or_insert(0) += 1;
                }
                QueueEvent::LaneEscalationLimit { lane, id: _ } => {
                    self.lane_state.insert(lane, LaneState::EscalationLimit);
                }
                QueueEvent::Rejected { .. } => {
                    // Not part of active state
                }
            }
        }

        Ok(())
    }

    /// End a lane as `escalation-limit` and persist that, so a rebuilt queue
    /// still refuses rulings for it.
    fn end_lane_escalation_limit(
        &mut self,
        lane: &str,
        id: StdOption<&EscalationId>,
    ) -> Result<(), String> {
        self.append_event(&QueueEvent::LaneEscalationLimit {
            lane: lane.to_string(),
            id: id.map(|i| i.0.clone()),
        })?;
        self.lane_state
            .insert(lane.to_string(), LaneState::EscalationLimit);
        Ok(())
    }

    /// Record an ask in the queue. Returns the escalation ID.
    ///
    /// The lane's 4th escalation (counting forced ones and resume-fallbacks)
    /// is refused and the lane ends as `escalation-limit`.
    pub fn ask(&mut self, lane: &str, ask: &Ask, origin: Origin) -> Result<EscalationId, String> {
        // Validate ask
        ask.validate()?;

        // Check escalation limit
        let count = self.escalation_count.get(lane).copied().unwrap_or(0);
        if count >= self.max_escalations {
            self.end_lane_escalation_limit(lane, StdOption::None)?;
            return Err(format!(
                "escalation limit reached for lane {} (max {})",
                lane, self.max_escalations
            ));
        }

        // Create the escalation ID
        let id = EscalationId::new(lane, count + 1);

        // Record in file first: a failed write must not consume an escalation.
        let event = QueueEvent::Asked {
            lane: lane.to_string(),
            id: id.0.clone(),
            ask: ask.clone(),
            origin: origin.clone(),
            at_ms: self.now_ms(),
        };
        self.append_event(&event)?;

        // Store in memory
        *self.escalation_count.entry(lane.to_string()).or_insert(0) += 1;
        self.escalations.insert(
            id.clone(),
            Entry {
                lane: lane.to_string(),
                ask: ask.clone(),
                origin,
                verdict: StdOption::None,
                delivered: false,
            },
        );
        self.park_times.insert(id.clone(), self.clock.now());

        Ok(id)
    }

    /// Check whether a ruling for `id` is acceptable right now.
    fn check_ruling(&mut self, lane: &str, id: &EscalationId) -> Result<(), String> {
        // Lane terminal state
        if let StdOption::Some(state) = self.lane_state.get(lane)
            && *state != LaneState::Running
        {
            return Err(format!(
                "ruling for {} rejected: lane in terminal state {}",
                id,
                state.name()
            ));
        }

        // Unknown, wrong lane or already ruled
        match self.escalations.get(id) {
            None => return Err(format!("escalation {} unknown", id)),
            Some(entry) if entry.lane != lane => {
                return Err(format!(
                    "escalation {} belongs to lane {}, not {}",
                    id, entry.lane, lane
                ));
            }
            Some(Entry {
                verdict: StdOption::Some(existing),
                ..
            }) => {
                return Err(format!("escalation {} already ruled: {:?}", id, existing));
            }
            Some(_) => {}
        }

        // Park limit: past it the lane ends as escalation-limit.
        let over = self
            .park_times
            .get(id)
            .and_then(|parked_at| self.clock.now().duration_since(*parked_at).ok())
            .filter(|elapsed| *elapsed > self.park_limit);
        if let StdOption::Some(elapsed) = over {
            self.end_lane_escalation_limit(lane, StdOption::Some(id))?;
            return Err(format!(
                "ruling for {} rejected: parked over limit ({:?} > {:?}); lane in terminal state escalation-limit",
                id, elapsed, self.park_limit
            ));
        }

        Ok(())
    }

    /// Record a ruling. Returns error if the escalation ID is unknown, belongs
    /// to another lane, was already ruled (first ruling wins), or the lane has
    /// ended. Rejections are logged in the queue file.
    pub fn rule(&mut self, lane: &str, id: &EscalationId, verdict: &Verdict) -> Result<(), String> {
        if let Err(reason) = self.check_ruling(lane, id) {
            // Best effort: the rejection itself is what the caller gets back.
            let _ = self.append_event(&QueueEvent::Rejected {
                lane: lane.to_string(),
                id: id.0.clone(),
                reason: reason.clone(),
            });
            return Err(reason);
        }

        let event = QueueEvent::Ruled {
            lane: lane.to_string(),
            id: id.0.clone(),
            verdict: verdict.clone(),
        };
        self.append_event(&event)?;

        if let Some(entry) = self.escalations.get_mut(id) {
            entry.verdict = StdOption::Some(verdict.clone());
        }

        Ok(())
    }

    /// Rule on an escalation and get the ruling to the builder.
    ///
    /// 1. Applies every ruling rule (see [`Queue::rule`]) and records the ruling.
    /// 2. Calls `delivery.deliver`.
    /// 3. `Delivered`: records `delivered`.
    /// 4. `SessionGone`: if a fallback would exceed the escalation limit the
    ///    lane ends as `escalation-limit` and nothing more is delivered.
    ///    Otherwise records `resume-fallback` (one more escalation against the
    ///    limit) and calls `delivery.deliver_fresh` with the ruling plus a
    ///    carry-over summary built from the queue.
    /// 5. A delivery error is returned as [`RuleError::Delivery`]; the ruling
    ///    and any fallback already recorded stay recorded.
    pub fn rule_and_deliver(
        &mut self,
        lane: &str,
        id: &EscalationId,
        verdict: &Verdict,
        delivery: &mut dyn Delivery,
    ) -> Result<DeliveryOutcome, RuleError> {
        self.rule(lane, id, verdict).map_err(RuleError::Ruling)?;

        match delivery
            .deliver(lane, id, verdict)
            .map_err(RuleError::Delivery)?
        {
            DeliveryResult::Delivered => {
                self.record_delivered(lane, id, false)?;
                Ok(DeliveryOutcome::Delivered)
            }
            DeliveryResult::SessionGone => {
                let count = self.escalation_count.get(lane).copied().unwrap_or(0);
                if count >= self.max_escalations {
                    self.end_lane_escalation_limit(lane, StdOption::Some(id))
                        .map_err(RuleError::Record)?;
                    return Ok(DeliveryOutcome::EscalationLimit);
                }

                self.append_event(&QueueEvent::ResumeFallback {
                    lane: lane.to_string(),
                    id: id.0.clone(),
                })
                .map_err(RuleError::Record)?;
                *self.escalation_count.entry(lane.to_string()).or_insert(0) += 1;

                let summary = self.carry_over_summary(id, verdict);
                delivery
                    .deliver_fresh(lane, id, verdict, &summary)
                    .map_err(RuleError::Delivery)?;
                self.record_delivered(lane, id, true)?;
                Ok(DeliveryOutcome::FreshSession)
            }
        }
    }

    fn record_delivered(
        &mut self,
        lane: &str,
        id: &EscalationId,
        fresh: bool,
    ) -> Result<(), RuleError> {
        self.append_event(&QueueEvent::Delivered {
            lane: lane.to_string(),
            id: id.0.clone(),
            fresh,
        })
        .map_err(RuleError::Record)?;
        if let Some(entry) = self.escalations.get_mut(id) {
            entry.delivered = true;
        }
        Ok(())
    }

    /// Whether the ruling for `id` reached the builder.
    pub fn is_delivered(&self, id: &EscalationId) -> bool {
        self.escalations.get(id).is_some_and(|e| e.delivered)
    }

    /// Number of escalations counted against the lane's limit (asks, forced
    /// escalations and resume-fallbacks).
    pub fn escalation_count(&self, lane: &str) -> usize {
        self.escalation_count.get(lane).copied().unwrap_or(0)
    }

    /// State of the lane as far as the queue knows (`None` = never set).
    pub fn lane_state(&self, lane: &str) -> StdOption<LaneState> {
        self.lane_state.get(lane).copied()
    }

    /// What a fresh session needs: the question, what was tried, the ruling.
    fn carry_over_summary(&self, id: &EscalationId, verdict: &Verdict) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "Your previous session could not be resumed. Escalation {} is answered below.\n\n",
            id
        ));
        if let Some(entry) = self.escalations.get(id) {
            out.push_str(&format!("Question: {}\n", entry.ask.question));
            if !entry.ask.tried.is_empty() {
                out.push_str("Tried:\n");
                for t in &entry.ask.tried {
                    out.push_str(&format!("- {}\n", t));
                }
            }
        }
        out.push_str(&format!("Ruling: {}\n", describe_verdict(verdict)));
        out
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
            .map(|e| (&e.ask, &e.origin, e.verdict.as_ref()))
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
    use std::collections::VecDeque;
    use std::sync::Arc;

    struct TestClock {
        current_time: std::sync::Mutex<SystemTime>,
    }

    impl TestClock {
        fn new() -> Self {
            TestClock {
                current_time: std::sync::Mutex::new(SystemTime::now()),
            }
        }

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

    impl Clock for Arc<TestClock> {
        fn now(&self) -> SystemTime {
            TestClock::now(self)
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
        let clock = Arc::new(TestClock::new());
        let mut queue = Queue::with_limits(
            tmpdir.path(),
            Box::new(clock.clone()),
            Duration::from_secs(30 * 60),
            3,
        )
        .unwrap();

        let ask = new_ask("test?");
        let early = queue.ask("lane1", &ask, Origin::Builder).unwrap();
        let late = queue.ask("lane1", &ask, Origin::Builder).unwrap();
        let verdict = Verdict::Answer {
            text: "answer".to_string(),
        };

        // Exactly at the limit is still fine.
        clock.advance(Duration::from_secs(30 * 60));
        queue.rule("lane1", &early, &verdict).unwrap();

        // One second past the limit is rejected and ends the lane.
        clock.advance(Duration::from_secs(1));
        let err = queue.rule("lane1", &late, &verdict).unwrap_err();
        assert!(err.contains("parked over limit"), "{err}");
        assert!(err.contains("escalation-limit"), "{err}");
        assert_eq!(queue.lane_state("lane1"), Some(LaneState::EscalationLimit));
        assert!(queue.get(&late).unwrap().2.is_none());
    }

    #[test]
    fn test_park_limit_survives_rebuild() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let clock = Arc::new(TestClock::new());
        let mut queue = Queue::new(tmpdir.path(), Box::new(clock.clone())).unwrap();
        let id = queue
            .ask("lane1", &new_ask("test?"), Origin::Builder)
            .unwrap();
        drop(queue);

        // The runner restarts 31 minutes later.
        clock.advance(Duration::from_secs(31 * 60));
        let mut queue = Queue::new(tmpdir.path(), Box::new(clock.clone())).unwrap();
        let err = queue
            .rule(
                "lane1",
                &id,
                &Verdict::Answer {
                    text: "late".to_string(),
                },
            )
            .unwrap_err();
        assert!(err.contains("parked over limit"), "{err}");
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
        let mut delivery = RecordingDelivery::new();
        let id = EscalationId::from_string("E1".to_string());
        let verdict = Verdict::Answer {
            text: "test".to_string(),
        };

        let result = delivery.deliver("lane1", &id, &verdict);
        assert_eq!(result, Ok(DeliveryResult::Delivered));

        assert_eq!(delivery.delivered.len(), 1);
        assert_eq!(delivery.delivered[0].0, "lane1");
        assert_eq!(delivery.delivered[0].1, id);
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

    // ---- rule_and_deliver ----

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Call {
        Deliver {
            lane: String,
            id: EscalationId,
            verdict: Verdict,
        },
        Fresh {
            lane: String,
            id: EscalationId,
            verdict: Verdict,
            summary: String,
        },
    }

    /// Scripted Delivery double: answers `deliver` from a queue of results
    /// and records every call in order.
    struct ScriptedDelivery {
        deliver_results: VecDeque<Result<DeliveryResult, DeliveryError>>,
        fresh_result: Result<(), DeliveryError>,
        calls: Vec<Call>,
    }

    impl ScriptedDelivery {
        fn new(results: Vec<Result<DeliveryResult, DeliveryError>>) -> Self {
            ScriptedDelivery {
                deliver_results: results.into(),
                fresh_result: Ok(()),
                calls: Vec::new(),
            }
        }

        fn gone() -> Self {
            Self::new(vec![Ok(DeliveryResult::SessionGone)])
        }
    }

    impl Delivery for ScriptedDelivery {
        fn deliver(
            &mut self,
            lane: &str,
            id: &EscalationId,
            verdict: &Verdict,
        ) -> Result<DeliveryResult, DeliveryError> {
            self.calls.push(Call::Deliver {
                lane: lane.to_string(),
                id: id.clone(),
                verdict: verdict.clone(),
            });
            self.deliver_results
                .pop_front()
                .expect("deliver called more often than scripted")
        }

        fn deliver_fresh(
            &mut self,
            lane: &str,
            id: &EscalationId,
            verdict: &Verdict,
            summary: &str,
        ) -> Result<(), DeliveryError> {
            self.calls.push(Call::Fresh {
                lane: lane.to_string(),
                id: id.clone(),
                verdict: verdict.clone(),
                summary: summary.to_string(),
            });
            self.fresh_result.clone()
        }
    }

    fn answer(text: &str) -> Verdict {
        Verdict::Answer {
            text: text.to_string(),
        }
    }

    fn queue_lines(dir: &Path) -> Vec<String> {
        std::fs::read_to_string(dir.join("escalations.jsonl"))
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect()
    }

    fn count_events(dir: &Path, name: &str) -> usize {
        let needle = format!("\"event\":\"{}\"", name);
        queue_lines(dir)
            .iter()
            .filter(|l| l.contains(&needle))
            .count()
    }

    #[test]
    fn test_rule_and_deliver_delivered_path() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let mut queue = Queue::new(tmpdir.path(), Box::new(TestClock::new())).unwrap();
        let id = queue
            .ask("lane1", &new_ask("test?"), Origin::Builder)
            .unwrap();
        let verdict = answer("use A");
        let mut delivery = ScriptedDelivery::new(vec![Ok(DeliveryResult::Delivered)]);

        let outcome = queue
            .rule_and_deliver("lane1", &id, &verdict, &mut delivery)
            .unwrap();

        assert_eq!(outcome, DeliveryOutcome::Delivered);
        // deliver called exactly once with the verdict; deliver_fresh never.
        assert_eq!(
            delivery.calls,
            vec![Call::Deliver {
                lane: "lane1".to_string(),
                id: id.clone(),
                verdict: verdict.clone(),
            }]
        );
        assert!(queue.is_delivered(&id));
        assert_eq!(queue.get(&id).unwrap().2, Some(&verdict));
        assert_eq!(queue.escalation_count("lane1"), 1);
        assert_eq!(count_events(tmpdir.path(), "resume-fallback"), 0);
        assert_eq!(count_events(tmpdir.path(), "delivered"), 1);
    }

    #[test]
    fn test_rule_and_deliver_session_gone_falls_back_to_fresh_session() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let mut queue = Queue::new(tmpdir.path(), Box::new(TestClock::new())).unwrap();
        let id = queue
            .ask(
                "lane1",
                &new_ask("Which parser should we use?"),
                Origin::Builder,
            )
            .unwrap();
        let verdict = answer("use the streaming parser");
        let mut delivery = ScriptedDelivery::gone();

        assert_eq!(queue.escalation_count("lane1"), 1);
        let outcome = queue
            .rule_and_deliver("lane1", &id, &verdict, &mut delivery)
            .unwrap();
        assert_eq!(queue.escalation_count("lane1"), 2);

        assert_eq!(outcome, DeliveryOutcome::FreshSession);
        // deliver, then deliver_fresh, in that order, nothing else.
        assert_eq!(delivery.calls.len(), 2);
        assert!(matches!(delivery.calls[0], Call::Deliver { .. }));
        let Call::Fresh {
            lane,
            id: fresh_id,
            verdict: fresh_verdict,
            summary,
        } = &delivery.calls[1]
        else {
            panic!("second call must be deliver_fresh: {:?}", delivery.calls[1]);
        };
        assert_eq!(lane, "lane1");
        assert_eq!(fresh_id, &id);
        assert_eq!(fresh_verdict, &verdict);
        // Carry-over: the original question, what was tried, the ruling text.
        assert!(summary.contains("Which parser should we use?"), "{summary}");
        assert!(summary.contains("attempted X"), "{summary}");
        assert!(summary.contains("use the streaming parser"), "{summary}");

        assert_eq!(count_events(tmpdir.path(), "resume-fallback"), 1);
        assert_eq!(count_events(tmpdir.path(), "delivered"), 1);
        assert!(queue.is_delivered(&id));
    }

    #[test]
    fn test_rule_and_deliver_session_gone_at_limit_ends_lane() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let mut queue = Queue::new(tmpdir.path(), Box::new(TestClock::new())).unwrap();
        let ask = new_ask("test?");
        queue.ask("lane1", &ask, Origin::Builder).unwrap();
        queue.ask("lane1", &ask, Origin::Builder).unwrap();
        let third = queue.ask("lane1", &ask, Origin::Builder).unwrap();
        assert_eq!(queue.escalation_count("lane1"), 3);
        let mut delivery = ScriptedDelivery::gone();

        let outcome = queue
            .rule_and_deliver("lane1", &third, &answer("go"), &mut delivery)
            .unwrap();

        assert_eq!(outcome, DeliveryOutcome::EscalationLimit);
        assert_eq!(queue.lane_state("lane1"), Some(LaneState::EscalationLimit));
        // deliver was tried; deliver_fresh was NOT called.
        assert_eq!(delivery.calls.len(), 1);
        assert!(matches!(delivery.calls[0], Call::Deliver { .. }));
        // The count did not move past the limit and no fallback was recorded.
        assert_eq!(queue.escalation_count("lane1"), 3);
        assert_eq!(count_events(tmpdir.path(), "resume-fallback"), 0);
        assert!(!queue.is_delivered(&third));
        // The ruling itself stays recorded.
        assert!(queue.get(&third).unwrap().2.is_some());
    }

    #[test]
    fn test_rebuild_after_resume_fallback_reproduces_count_and_event() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let mut queue = Queue::new(tmpdir.path(), Box::new(TestClock::new())).unwrap();
        let ask = new_ask("test?");
        let id = queue.ask("lane1", &ask, Origin::Builder).unwrap();
        let mut delivery = ScriptedDelivery::gone();
        queue
            .rule_and_deliver("lane1", &id, &answer("go"), &mut delivery)
            .unwrap();
        assert_eq!(queue.escalation_count("lane1"), 2);
        drop(queue);

        // The event is in the file.
        assert_eq!(count_events(tmpdir.path(), "resume-fallback"), 1);

        let mut queue = Queue::new(tmpdir.path(), Box::new(TestClock::new())).unwrap();
        assert_eq!(queue.escalation_count("lane1"), 2);
        assert!(queue.is_delivered(&id));
        assert_eq!(queue.get(&id).unwrap().2, Some(&answer("go")));

        // The rebuilt count is enforced: one more ask fits, the next does not.
        queue.ask("lane1", &ask, Origin::Builder).unwrap();
        assert!(queue.ask("lane1", &ask, Origin::Builder).is_err());
    }

    #[test]
    fn test_rebuild_keeps_lane_ended_at_limit() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let mut queue = Queue::new(tmpdir.path(), Box::new(TestClock::new())).unwrap();
        let ask = new_ask("test?");
        queue.ask("lane1", &ask, Origin::Builder).unwrap();
        queue.ask("lane1", &ask, Origin::Builder).unwrap();
        let third = queue.ask("lane1", &ask, Origin::Builder).unwrap();
        let mut delivery = ScriptedDelivery::gone();
        queue
            .rule_and_deliver("lane1", &third, &answer("go"), &mut delivery)
            .unwrap();
        drop(queue);

        let queue = Queue::new(tmpdir.path(), Box::new(TestClock::new())).unwrap();
        assert_eq!(queue.lane_state("lane1"), Some(LaneState::EscalationLimit));
    }

    #[test]
    fn test_rule_and_deliver_delivery_error_keeps_ruling() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let mut queue = Queue::new(tmpdir.path(), Box::new(TestClock::new())).unwrap();
        let id = queue
            .ask("lane1", &new_ask("test?"), Origin::Builder)
            .unwrap();
        let mut delivery =
            ScriptedDelivery::new(vec![Err(DeliveryError("pipe broke".to_string()))]);

        let err = queue
            .rule_and_deliver("lane1", &id, &answer("first"), &mut delivery)
            .unwrap_err();

        // Surfaced, not swallowed.
        assert_eq!(
            err,
            RuleError::Delivery(DeliveryError("pipe broke".to_string()))
        );
        assert!(err.to_string().contains("pipe broke"));
        // The ruling stays recorded and nothing counts as delivered.
        assert_eq!(queue.get(&id).unwrap().2, Some(&answer("first")));
        assert!(!queue.is_delivered(&id));
        assert_eq!(count_events(tmpdir.path(), "ruled"), 1);
        assert_eq!(count_events(tmpdir.path(), "delivered"), 0);

        // A second ruling for the same id is still a duplicate, and it never
        // reaches the delivery.
        let mut delivery2 = ScriptedDelivery::new(vec![]);
        let err2 = queue
            .rule_and_deliver("lane1", &id, &answer("second"), &mut delivery2)
            .unwrap_err();
        assert!(
            matches!(&err2, RuleError::Ruling(m) if m.contains("already ruled")),
            "{err2:?}"
        );
        assert!(delivery2.calls.is_empty());
    }

    #[test]
    fn test_rule_and_deliver_fresh_error_surfaced_fallback_stays_recorded() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let mut queue = Queue::new(tmpdir.path(), Box::new(TestClock::new())).unwrap();
        let id = queue
            .ask("lane1", &new_ask("test?"), Origin::Builder)
            .unwrap();
        let mut delivery = ScriptedDelivery::gone();
        delivery.fresh_result = Err(DeliveryError("spawn failed".to_string()));

        let err = queue
            .rule_and_deliver("lane1", &id, &answer("go"), &mut delivery)
            .unwrap_err();

        assert_eq!(
            err,
            RuleError::Delivery(DeliveryError("spawn failed".to_string()))
        );
        assert_eq!(queue.escalation_count("lane1"), 2);
        assert_eq!(count_events(tmpdir.path(), "resume-fallback"), 1);
        assert!(!queue.is_delivered(&id));
    }

    #[test]
    fn test_rule_and_deliver_rejected_ruling_never_delivers() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let mut queue = Queue::new(tmpdir.path(), Box::new(TestClock::new())).unwrap();
        let id = queue
            .ask("lane1", &new_ask("test?"), Origin::Builder)
            .unwrap();
        queue.set_lane_state("lane1", LaneState::Stopped);
        let mut delivery = ScriptedDelivery::new(vec![]);

        let err = queue
            .rule_and_deliver("lane1", &id, &answer("late"), &mut delivery)
            .unwrap_err();

        assert!(
            matches!(&err, RuleError::Ruling(m) if m.contains("stopped")),
            "{err:?}"
        );
        assert!(delivery.calls.is_empty());
        assert!(queue.get(&id).unwrap().2.is_none());
    }

    #[test]
    fn test_rejected_ruling_is_logged() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let mut queue = Queue::new(tmpdir.path(), Box::new(TestClock::new())).unwrap();
        let id = queue
            .ask("lane1", &new_ask("test?"), Origin::Builder)
            .unwrap();
        queue.rule("lane1", &id, &answer("first")).unwrap();
        assert!(queue.rule("lane1", &id, &answer("second")).is_err());

        let rejected: Vec<String> = queue_lines(tmpdir.path())
            .into_iter()
            .filter(|l| l.contains("\"event\":\"rejected\""))
            .collect();
        assert_eq!(rejected.len(), 1);
        assert!(rejected[0].contains("already ruled"), "{}", rejected[0]);
    }

    #[test]
    fn test_ruling_for_another_lane_rejected() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let mut queue = Queue::new(tmpdir.path(), Box::new(TestClock::new())).unwrap();
        let id = queue
            .ask("lane1", &new_ask("test?"), Origin::Builder)
            .unwrap();

        let err = queue.rule("lane2", &id, &answer("wrong lane")).unwrap_err();
        assert!(err.contains("belongs to lane lane1"), "{err}");
        assert!(queue.get(&id).unwrap().2.is_none());
    }

    #[test]
    fn test_ask_at_limit_ends_lane() {
        let tmpdir = tempfile::TempDir::new().unwrap();
        let mut queue = Queue::new(tmpdir.path(), Box::new(TestClock::new())).unwrap();
        let ask = new_ask("test?");
        let first = queue.ask("lane1", &ask, Origin::Builder).unwrap();
        queue.ask("lane1", &ask, Origin::Builder).unwrap();
        queue.ask("lane1", &ask, Origin::Builder).unwrap();
        assert!(queue.ask("lane1", &ask, Origin::Builder).is_err());

        assert_eq!(queue.lane_state("lane1"), Some(LaneState::EscalationLimit));
        let err = queue.rule("lane1", &first, &answer("late")).unwrap_err();
        assert!(err.contains("escalation-limit"), "{err}");
    }

    #[test]
    fn test_render_truncates_on_char_boundary() {
        // 4001 bytes of 2-byte characters: byte 4000 is a boundary, 3999 is not.
        let mut ask = new_ask("x");
        ask.question = format!("a{}", "\u{e9}".repeat(2000));
        let rendered = ask.render_for_director();
        assert!(rendered.contains("[TRUNCATED]"));
    }
}
