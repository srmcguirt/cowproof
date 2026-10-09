//! Stream meter for consuming and analyzing Claude API stream-json events (D23, R15).
//!
//! [`StreamMeter`] consumes stream-json lines one at a time, accumulating per-turn metrics
//! about session activity, tool calls and results, usage, and final outcomes.

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

/// A single stream-json event from the Claude API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamEvent {
    #[serde(rename = "type")]
    pub event_type: String,
}

/// Per-turn usage metrics (D23).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TurnUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_read_input_tokens: u64,
    pub cache_creation_input_tokens: u64,
    pub cache_creation_1h_input_tokens: u64,
    pub cache_creation_5m_input_tokens: u64,
}

/// Summary of a tool call paired with its result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    pub id: String,
    pub name: String,
    pub input_bytes: u64,
    pub output_bytes: u64,
    pub is_error: bool,
}

/// Summary of all metrics accumulated from the stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeterSummary {
    pub session_id: Option<String>,
    pub tool_calls: Vec<ToolCall>,
    pub tool_calls_by_name: BTreeMap<String, (u64, u64, u64)>, // (count, bytes_in, bytes_out)
    pub turns: Vec<TurnUsage>,
    pub total_input_tokens: u64,
    pub total_output_tokens: u64,
    pub total_cache_read_tokens: u64,
    pub total_cache_creation_tokens: u64,
    pub cache_creation_1h_tokens: u64,
    pub cache_creation_5m_tokens: u64,
    pub resume_warm: Option<bool>,
    pub total_bandwidth_bytes: u64,
    pub result_subtype: Option<String>,
    pub result_text_length: u64,
    pub total_cost_usd: Option<f64>,
    pub num_turns: Option<u64>,
    pub permission_denials: Vec<String>,
    pub unknown_event_count: u64,
}

/// Meter for consuming stream-json lines and accumulating metrics.
pub struct StreamMeter {
    resumed: bool,
    session_id: Option<String>,
    tool_calls: Vec<ToolCall>,
    tool_calls_by_name: BTreeMap<String, (u64, u64, u64)>,
    tool_use_pending: HashMap<String, (String, u64)>, // id -> (name, input_bytes)
    turns: Vec<TurnUsage>,
    total_input_tokens: u64,
    total_output_tokens: u64,
    total_cache_read_tokens: u64,
    total_cache_creation_tokens: u64,
    cache_creation_1h_tokens: u64,
    cache_creation_5m_tokens: u64,
    result_subtype: Option<String>,
    result_text_length: u64,
    total_cost_usd: Option<f64>,
    num_turns: Option<u64>,
    permission_denials: Vec<String>,
    unknown_event_count: u64,
}

impl StreamMeter {
    /// Create a new meter. Pass `resumed=true` if this is a resumed run (with cached content).
    pub fn new(resumed: bool) -> Self {
        Self {
            resumed,
            session_id: None,
            tool_calls: Vec::new(),
            tool_calls_by_name: BTreeMap::new(),
            tool_use_pending: HashMap::new(),
            turns: Vec::new(),
            total_input_tokens: 0,
            total_output_tokens: 0,
            total_cache_read_tokens: 0,
            total_cache_creation_tokens: 0,
            cache_creation_1h_tokens: 0,
            cache_creation_5m_tokens: 0,
            result_subtype: None,
            result_text_length: 0,
            total_cost_usd: None,
            num_turns: None,
            permission_denials: Vec::new(),
            unknown_event_count: 0,
        }
    }

    /// Feed a single JSON line from the stream.
    /// Panics if the line is not valid JSON; skips unknown event types.
    pub fn feed(&mut self, line: &str) -> Result<Vec<StreamEvent>> {
        let json: serde_json::Value =
            serde_json::from_str(line).map_err(|e| anyhow!("not valid JSON: {}", e))?;

        let mut events = Vec::new();

        // Extract type field
        let event_type = json.get("type").and_then(|t| t.as_str());

        match event_type {
            Some("system") => {
                if let Some(session) = json.get("session_id").and_then(|s| s.as_str()) {
                    self.session_id = Some(session.to_string());
                }
                events.push(StreamEvent {
                    event_type: "system".to_string(),
                });
            }
            Some("assistant") => {
                // Parse assistant message for tool_use events and per-turn usage
                if let Some(message) = json.get("message").and_then(|m| m.as_object()) {
                    // Extract tool_use events
                    if let Some(content) = message.get("content").and_then(|c| c.as_array()) {
                        for item in content {
                            if let Some(tool_use) = item.as_object()
                                && let (Some(id), Some(name)) = (
                                    tool_use.get("id").and_then(|i| i.as_str()),
                                    tool_use.get("name").and_then(|n| n.as_str()),
                                )
                            {
                                let input_bytes = tool_use
                                    .get("input")
                                    .map(|i| {
                                        serde_json::to_string(i).unwrap_or_default().len() as u64
                                    })
                                    .unwrap_or(0);
                                self.tool_use_pending
                                    .insert(id.to_string(), (name.to_string(), input_bytes));
                            }
                        }
                    }
                    // Track per-turn usage
                    if let Some(usage) = message.get("usage").and_then(|u| u.as_object()) {
                        self.accumulate_turn_usage(usage);
                    }
                }
                events.push(StreamEvent {
                    event_type: "assistant".to_string(),
                });
            }
            Some("user") => {
                // Parse tool_result events and match them to pending tool_use events
                if let Some(message) = json.get("message").and_then(|m| m.as_object())
                    && let Some(content) = message.get("content").and_then(|c| c.as_array())
                {
                    for item in content {
                        if let Some(obj) = item.as_object()
                            && obj.get("type").and_then(|t| t.as_str()) == Some("tool_result")
                            && let Some(tool_use_id) =
                                obj.get("tool_use_id").and_then(|id| id.as_str())
                        {
                            let output_bytes = obj
                                .get("content")
                                .map(|c| {
                                    if let Some(text) = c.as_str() {
                                        text.len() as u64
                                    } else if let Some(arr) = c.as_array() {
                                        serde_json::to_string(arr).unwrap_or_default().len() as u64
                                    } else {
                                        serde_json::to_string(c).unwrap_or_default().len() as u64
                                    }
                                })
                                .unwrap_or(0);
                            let is_error = obj
                                .get("is_error")
                                .and_then(|e| e.as_bool())
                                .unwrap_or(false);

                            if let Some((name, input_bytes)) =
                                self.tool_use_pending.remove(tool_use_id)
                            {
                                let call = ToolCall {
                                    id: tool_use_id.to_string(),
                                    name: name.clone(),
                                    input_bytes,
                                    output_bytes,
                                    is_error,
                                };
                                self.tool_calls.push(call);

                                // Track by name
                                let entry =
                                    self.tool_calls_by_name.entry(name).or_insert((0, 0, 0));
                                entry.0 += 1;
                                entry.1 += input_bytes;
                                entry.2 += output_bytes;
                            }
                        }
                    }
                }
                events.push(StreamEvent {
                    event_type: "user".to_string(),
                });
            }
            Some("result") => {
                // Parse final result
                if let Some(subtype) = json.get("subtype").and_then(|s| s.as_str()) {
                    self.result_subtype = Some(subtype.to_string());
                }
                if let Some(result) = json.get("result").and_then(|r| r.as_str()) {
                    self.result_text_length = result.len() as u64;
                }
                if let Some(cost) = json.get("total_cost_usd").and_then(|c| c.as_f64()) {
                    self.total_cost_usd = Some(cost);
                }
                if let Some(turns) = json.get("num_turns").and_then(|t| t.as_u64()) {
                    self.num_turns = Some(turns);
                }
                // Parse final usage from result (cumulative)
                if let Some(usage) = json.get("usage").and_then(|u| u.as_object()) {
                    if let Some(inp) = usage.get("input_tokens").and_then(|t| t.as_u64()) {
                        self.total_input_tokens = inp;
                    }
                    if let Some(out) = usage.get("output_tokens").and_then(|t| t.as_u64()) {
                        self.total_output_tokens = out;
                    }
                    if let Some(cr) = usage
                        .get("cache_read_input_tokens")
                        .and_then(|t| t.as_u64())
                    {
                        self.total_cache_read_tokens = cr;
                    }
                    if let Some(cc) = usage
                        .get("cache_creation_input_tokens")
                        .and_then(|t| t.as_u64())
                    {
                        self.total_cache_creation_tokens = cc;
                    }
                    if let Some(cache_creation) =
                        usage.get("cache_creation").and_then(|c| c.as_object())
                    {
                        if let Some(t1h) = cache_creation
                            .get("ephemeral_1h_input_tokens")
                            .and_then(|t| t.as_u64())
                        {
                            self.cache_creation_1h_tokens = t1h;
                        }
                        if let Some(t5m) = cache_creation
                            .get("ephemeral_5m_input_tokens")
                            .and_then(|t| t.as_u64())
                        {
                            self.cache_creation_5m_tokens = t5m;
                        }
                    }
                }
                if let Some(denials) = json.get("permission_denials").and_then(|d| d.as_array()) {
                    for denial in denials {
                        if let Some(text) = denial.as_str() {
                            self.permission_denials.push(text.to_string());
                        }
                    }
                }
                events.push(StreamEvent {
                    event_type: "result".to_string(),
                });
            }
            _ => {
                self.unknown_event_count += 1;
            }
        }

        Ok(events)
    }

    /// Accumulate per-turn usage from an assistant message's usage field.
    fn accumulate_turn_usage(&mut self, usage: &serde_json::Map<String, serde_json::Value>) {
        let mut turn = TurnUsage::default();
        if let Some(inp) = usage.get("input_tokens").and_then(|t| t.as_u64()) {
            turn.input_tokens = inp;
        }
        if let Some(out) = usage.get("output_tokens").and_then(|t| t.as_u64()) {
            turn.output_tokens = out;
        }
        if let Some(cr) = usage
            .get("cache_read_input_tokens")
            .and_then(|t| t.as_u64())
        {
            turn.cache_read_input_tokens = cr;
        }
        if let Some(cc) = usage
            .get("cache_creation_input_tokens")
            .and_then(|t| t.as_u64())
        {
            turn.cache_creation_input_tokens = cc;
        }
        if let Some(cache_creation) = usage.get("cache_creation").and_then(|c| c.as_object()) {
            if let Some(t1h) = cache_creation
                .get("ephemeral_1h_input_tokens")
                .and_then(|t| t.as_u64())
            {
                turn.cache_creation_1h_input_tokens = t1h;
            }
            if let Some(t5m) = cache_creation
                .get("ephemeral_5m_input_tokens")
                .and_then(|t| t.as_u64())
            {
                turn.cache_creation_5m_input_tokens = t5m;
            }
        }
        self.turns.push(turn);
    }

    /// Generate a summary of all accumulated metrics.
    pub fn summary(&self) -> MeterSummary {
        let resume_warm = if self.resumed {
            self.turns.first().map(|t| t.cache_read_input_tokens > 0)
        } else {
            None
        };

        let total_bandwidth_bytes = self
            .tool_calls
            .iter()
            .map(|tc| tc.output_bytes)
            .sum::<u64>()
            + self.result_text_length;

        MeterSummary {
            session_id: self.session_id.clone(),
            tool_calls: self.tool_calls.clone(),
            tool_calls_by_name: self.tool_calls_by_name.clone(),
            turns: self.turns.clone(),
            total_input_tokens: self.total_input_tokens,
            total_output_tokens: self.total_output_tokens,
            total_cache_read_tokens: self.total_cache_read_tokens,
            total_cache_creation_tokens: self.total_cache_creation_tokens,
            cache_creation_1h_tokens: self.cache_creation_1h_tokens,
            cache_creation_5m_tokens: self.cache_creation_5m_tokens,
            resume_warm,
            total_bandwidth_bytes,
            result_subtype: self.result_subtype.clone(),
            result_text_length: self.result_text_length,
            total_cost_usd: self.total_cost_usd,
            num_turns: self.num_turns,
            permission_denials: self.permission_denials.clone(),
            unknown_event_count: self.unknown_event_count,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_run1_fixture_session_and_tool_calls() {
        let fixture = include_str!("../tests/fixtures/stream-run1.jsonl");
        let mut meter = StreamMeter::new(false);

        for line in fixture.lines() {
            if !line.is_empty() {
                let _ = meter.feed(line).expect("should parse");
            }
        }

        let summary = meter.summary();

        // Session ID from the init event
        assert_eq!(
            summary.session_id.as_deref(),
            Some("00000000-0000-4000-8000-000000000001")
        );

        // Both tool calls with unique IDs now match to results
        assert_eq!(summary.tool_calls.len(), 2);
        assert_eq!(summary.tool_calls[0].name, "Bash");
        assert_eq!(summary.tool_calls[1].name, "mcp__probe__ping");
        assert!(!summary.tool_calls[0].is_error);
        assert!(!summary.tool_calls[1].is_error);
    }

    #[test]
    fn parse_run1_fixture_totals() {
        let fixture = include_str!("../tests/fixtures/stream-run1.jsonl");
        let mut meter = StreamMeter::new(false);

        for line in fixture.lines() {
            if !line.is_empty() {
                let _ = meter.feed(line).expect("should parse");
            }
        }

        let summary = meter.summary();

        // Total usage from the result event
        assert_eq!(summary.total_input_tokens, 6);
        assert_eq!(summary.total_output_tokens, 161);
        assert_eq!(summary.total_cache_read_tokens, 1668);
        assert_eq!(summary.total_cache_creation_tokens, 1900);
        assert_eq!(summary.cache_creation_1h_tokens, 1900);
        assert_eq!(summary.cache_creation_5m_tokens, 0);
    }

    #[test]
    fn per_turn_usage_run1() {
        let fixture = include_str!("../tests/fixtures/stream-run1.jsonl");
        let mut meter = StreamMeter::new(false);

        for line in fixture.lines() {
            if !line.is_empty() {
                let _ = meter.feed(line).expect("should parse");
            }
        }

        let summary = meter.summary();

        // Per-turn usage from assistant messages is tracked
        assert!(!summary.turns.is_empty());
        // Final totals from result event match the contract
        assert_eq!(summary.total_input_tokens, 6);
        assert_eq!(summary.total_output_tokens, 161);
    }

    #[test]
    fn run1_fresh_run_no_resume() {
        let fixture = include_str!("../tests/fixtures/stream-run1.jsonl");
        let mut meter = StreamMeter::new(false);

        for line in fixture.lines() {
            if !line.is_empty() {
                let _ = meter.feed(line).expect("should parse");
            }
        }

        let summary = meter.summary();

        // Fresh run: resume_warm is None
        assert_eq!(summary.resume_warm, None);
    }

    #[test]
    fn resume_fixture_warm_cache() {
        let fixture = include_str!("../tests/fixtures/stream-resume.jsonl");
        let mut meter = StreamMeter::new(true);

        for line in fixture.lines() {
            if !line.is_empty() {
                let _ = meter.feed(line).expect("should parse");
            }
        }

        let summary = meter.summary();

        // Resumed run with cache_read > 0: resume_warm is Some(true)
        assert_eq!(summary.resume_warm, Some(true));
    }

    #[test]
    fn synthetic_cold_resume() {
        let cold_resume = r#"{"type":"system","session_id":"test-session"}
{"type":"assistant","message":{"usage":{"input_tokens":4,"output_tokens":7,"cache_read_input_tokens":0,"cache_creation_input_tokens":31}}}
{"type":"result","subtype":"success","result":"test","usage":{"input_tokens":4,"output_tokens":7,"cache_read_input_tokens":0,"cache_creation_input_tokens":31}}"#;

        let mut meter = StreamMeter::new(true);
        for line in cold_resume.lines() {
            if !line.is_empty() {
                let _ = meter.feed(line).expect("should parse");
            }
        }

        let summary = meter.summary();

        // Resumed run but cache_read == 0: Some(false)
        assert_eq!(summary.resume_warm, Some(false));
    }

    #[test]
    fn unknown_event_type_skipped_and_counted() {
        let fixture = r#"{"type":"system","session_id":"test"}
{"type":"unknown_event_type","data":"ignored"}
{"type":"result","subtype":"success"}"#;

        let mut meter = StreamMeter::new(false);
        for line in fixture.lines() {
            if !line.is_empty() {
                let _ = meter.feed(line).expect("should parse");
            }
        }

        let summary = meter.summary();

        assert_eq!(summary.unknown_event_count, 1);
    }

    #[test]
    fn non_json_line_returns_error() {
        let mut meter = StreamMeter::new(false);
        let result = meter.feed("not a json line at all");
        assert!(result.is_err());
    }

    #[test]
    fn bash_command_with_success() {
        let fixture = r#"{"type":"system","session_id":"test","tools":["Bash"]}
{"type":"assistant","message":{"content":[{"type":"tool_use","id":"toolu_1","name":"Bash","input":{"command":"echo hello > probe.txt"}}]}}
{"type":"user","message":{"content":[{"tool_use_id":"toolu_1","type":"tool_result","content":"ok","is_error":false}]}}
{"type":"result","subtype":"success"}"#;

        let mut meter = StreamMeter::new(false);
        for line in fixture.lines() {
            if !line.is_empty() {
                let _ = meter.feed(line).expect("should parse");
            }
        }

        let summary = meter.summary();

        assert_eq!(summary.tool_calls.len(), 1);
        assert_eq!(summary.tool_calls[0].name, "Bash");
        assert!(!summary.tool_calls[0].is_error);
    }

    #[test]
    fn bash_command_with_error() {
        let fixture = r#"{"type":"system","session_id":"test","tools":["Bash"]}
{"type":"assistant","message":{"content":[{"type":"tool_use","id":"toolu_1","name":"Bash","input":{"command":"false"}}]}}
{"type":"user","message":{"content":[{"tool_use_id":"toolu_1","type":"tool_result","content":"error","is_error":true}]}}
{"type":"result","subtype":"success"}"#;

        let mut meter = StreamMeter::new(false);
        for line in fixture.lines() {
            if !line.is_empty() {
                let _ = meter.feed(line).expect("should parse");
            }
        }

        let summary = meter.summary();

        assert_eq!(summary.tool_calls.len(), 1);
        assert!(summary.tool_calls[0].is_error);
    }

    #[test]
    fn cache_read_tokens_properly_accumulated() {
        let fixture = include_str!("../tests/fixtures/stream-run1.jsonl");
        let mut meter = StreamMeter::new(false);

        for line in fixture.lines() {
            if !line.is_empty() {
                let _ = meter.feed(line).expect("should parse");
            }
        }

        let summary = meter.summary();
        assert_eq!(
            summary.total_cache_read_tokens, 1668,
            "cache_read_input_tokens must be accumulated from result event"
        );
    }

    #[test]
    fn mutation_proof_resume_warm_detection() {
        let fixture = include_str!("../tests/fixtures/stream-resume.jsonl");
        let mut meter = StreamMeter::new(true);

        for line in fixture.lines() {
            if !line.is_empty() {
                let _ = meter.feed(line).expect("should parse");
            }
        }

        let summary = meter.summary();
        assert_eq!(
            summary.resume_warm,
            Some(true),
            "resume_warm must be true when resumed=true and first turn cache_read > 0"
        );
    }
}
