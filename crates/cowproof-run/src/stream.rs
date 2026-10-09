//! Stream meter for consuming and analyzing Claude API stream-json events (D23, R15).
//!
//! [`StreamMeter`] consumes stream-json lines one at a time, accumulating the
//! metrics the runner needs without depending on any hook firing (R15):
//!
//! * per-turn usage: one [`TurnUsage`] per distinct assistant message id.
//!   Claude Code emits one `assistant` event per content block, repeating the
//!   same message id and usage on each, so events are de-duplicated by id
//!   (a later event for the same id replaces the earlier snapshot). An
//!   assistant event with no id counts as its own turn.
//! * totals: taken from the `result` event's `usage`, the canonical source.
//!   Input, cache-read and cache-creation per-turn sums equal these totals;
//!   per-turn `output_tokens` is a streaming snapshot and can be lower than
//!   the result total (it excludes thinking tokens), so output is not summed.
//! * tool calls, matched by id to their results, with input and output bytes.
//!   A result whose id has no earlier tool_use is an orphan and is counted.
//! * which Bash commands ran and whether each succeeded
//!   ([`StreamMeter::bash_commands`]), for escalate-early.
//! * bandwidth: see [`MeterSummary::total_bandwidth_bytes`].

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
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TurnUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_read_input_tokens: u64,
    pub cache_creation_input_tokens: u64,
    pub cache_creation_1h_input_tokens: u64,
    pub cache_creation_5m_input_tokens: u64,
}

/// Summary of a tool call paired with its result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolCall {
    pub id: String,
    pub name: String,
    /// The `command` input of a Bash call; `None` for every other tool.
    pub command: Option<String>,
    pub input_bytes: u64,
    pub output_bytes: u64,
    pub is_error: bool,
}

/// A Bash command that ran and whether it succeeded (its result was not an error).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BashCommand {
    pub command: String,
    pub succeeded: bool,
}

/// Summary of all metrics accumulated from the stream.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MeterSummary {
    pub session_id: Option<String>,
    pub tool_calls: Vec<ToolCall>,
    /// name -> (count, input bytes, output bytes)
    pub tool_calls_by_name: BTreeMap<String, (u64, u64, u64)>,
    /// tool_results whose tool_use_id had no earlier tool_use.
    pub orphan_results: u64,
    /// Output bytes of those orphan results (they still reached the context).
    pub orphan_output_bytes: u64,
    /// tool_uses still waiting for a result when the summary was taken.
    pub pending_tool_uses: u64,
    pub turns: Vec<TurnUsage>,
    pub total_input_tokens: u64,
    pub total_output_tokens: u64,
    pub total_cache_read_tokens: u64,
    pub total_cache_creation_tokens: u64,
    pub cache_creation_1h_tokens: u64,
    pub cache_creation_5m_tokens: u64,
    pub resume_warm: Option<bool>,
    /// Bytes delivered into the model context or back to the director:
    /// output bytes of every tool result (matched and orphan) plus the length
    /// of the final result text. Tool input bytes are not counted.
    pub total_bandwidth_bytes: u64,
    pub result_subtype: Option<String>,
    pub result_text_length: u64,
    pub total_cost_usd: Option<f64>,
    pub num_turns: Option<u64>,
    pub permission_denials: Vec<String>,
    pub unknown_event_count: u64,
}

impl MeterSummary {
    /// The Bash commands that ran, in order, with whether each succeeded.
    pub fn bash_commands(&self) -> Vec<BashCommand> {
        self.tool_calls
            .iter()
            .filter_map(|tc| {
                tc.command.as_ref().map(|c| BashCommand {
                    command: c.clone(),
                    succeeded: !tc.is_error,
                })
            })
            .collect()
    }
}

/// Meter for consuming stream-json lines and accumulating metrics.
pub struct StreamMeter {
    resumed: bool,
    session_id: Option<String>,
    tool_calls: Vec<ToolCall>,
    tool_calls_by_name: BTreeMap<String, (u64, u64, u64)>,
    /// id -> (name, command, input_bytes)
    tool_use_pending: HashMap<String, (String, Option<String>, u64)>,
    orphan_results: u64,
    orphan_output_bytes: u64,
    turns: Vec<TurnUsage>,
    turn_by_message_id: HashMap<String, usize>,
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

fn u64_at(map: &serde_json::Map<String, serde_json::Value>, key: &str) -> u64 {
    map.get(key).and_then(|t| t.as_u64()).unwrap_or(0)
}

fn usage_of(usage: &serde_json::Map<String, serde_json::Value>) -> TurnUsage {
    let mut turn = TurnUsage {
        input_tokens: u64_at(usage, "input_tokens"),
        output_tokens: u64_at(usage, "output_tokens"),
        cache_read_input_tokens: u64_at(usage, "cache_read_input_tokens"),
        cache_creation_input_tokens: u64_at(usage, "cache_creation_input_tokens"),
        ..TurnUsage::default()
    };
    if let Some(cc) = usage.get("cache_creation").and_then(|c| c.as_object()) {
        turn.cache_creation_1h_input_tokens = u64_at(cc, "ephemeral_1h_input_tokens");
        turn.cache_creation_5m_input_tokens = u64_at(cc, "ephemeral_5m_input_tokens");
    }
    turn
}

/// Bytes a tool_result content delivers: text length for a string or for text
/// blocks, serialized length for anything else.
fn result_bytes(content: Option<&serde_json::Value>) -> u64 {
    match content {
        None | Some(serde_json::Value::Null) => 0,
        Some(serde_json::Value::String(s)) => s.len() as u64,
        Some(serde_json::Value::Array(blocks)) => blocks
            .iter()
            .map(|b| match b.get("text").and_then(|t| t.as_str()) {
                Some(text) if b.get("type").and_then(|t| t.as_str()) == Some("text") => {
                    text.len() as u64
                }
                _ => serde_json::to_string(b).unwrap_or_default().len() as u64,
            })
            .sum(),
        Some(other) => serde_json::to_string(other).unwrap_or_default().len() as u64,
    }
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
            orphan_results: 0,
            orphan_output_bytes: 0,
            turns: Vec::new(),
            turn_by_message_id: HashMap::new(),
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
    ///
    /// Returns an error if the line is not valid JSON. Events of unknown type
    /// are counted (`unknown_event_count`) and skipped. Malformed fields inside
    /// a known event are skipped rather than failing the stream.
    pub fn feed(&mut self, line: &str) -> Result<Vec<StreamEvent>> {
        let json: serde_json::Value =
            serde_json::from_str(line).map_err(|e| anyhow!("not valid JSON: {}", e))?;

        let mut events = Vec::new();
        match json.get("type").and_then(|t| t.as_str()) {
            Some("system") => {
                if let Some(session) = json.get("session_id").and_then(|s| s.as_str()) {
                    self.session_id = Some(session.to_string());
                }
                events.push(StreamEvent {
                    event_type: "system".to_string(),
                });
            }
            Some("assistant") => {
                if let Some(message) = json.get("message").and_then(|m| m.as_object()) {
                    if let Some(content) = message.get("content").and_then(|c| c.as_array()) {
                        for item in content {
                            self.note_tool_use(item);
                        }
                    }
                    if let Some(usage) = message.get("usage").and_then(|u| u.as_object()) {
                        let turn = usage_of(usage);
                        let id = message.get("id").and_then(|i| i.as_str());
                        match id.and_then(|i| self.turn_by_message_id.get(i)) {
                            Some(&index) => self.turns[index] = turn,
                            None => {
                                if let Some(id) = id {
                                    self.turn_by_message_id
                                        .insert(id.to_string(), self.turns.len());
                                }
                                self.turns.push(turn);
                            }
                        }
                    }
                }
                events.push(StreamEvent {
                    event_type: "assistant".to_string(),
                });
            }
            Some("user") => {
                if let Some(content) = json
                    .get("message")
                    .and_then(|m| m.get("content"))
                    .and_then(|c| c.as_array())
                {
                    for item in content {
                        self.note_tool_result(item);
                    }
                }
                events.push(StreamEvent {
                    event_type: "user".to_string(),
                });
            }
            Some("result") => {
                self.note_result(&json);
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

    fn note_tool_use(&mut self, item: &serde_json::Value) {
        if item.get("type").and_then(|t| t.as_str()) != Some("tool_use") {
            return;
        }
        let (Some(id), Some(name)) = (
            item.get("id").and_then(|i| i.as_str()),
            item.get("name").and_then(|n| n.as_str()),
        ) else {
            return;
        };
        let input = item.get("input");
        let input_bytes = input
            .map(|i| serde_json::to_string(i).unwrap_or_default().len() as u64)
            .unwrap_or(0);
        let command = if name == "Bash" {
            input
                .and_then(|i| i.get("command"))
                .and_then(|c| c.as_str())
                .map(str::to_string)
        } else {
            None
        };
        self.tool_use_pending
            .insert(id.to_string(), (name.to_string(), command, input_bytes));
    }

    fn note_tool_result(&mut self, item: &serde_json::Value) {
        if item.get("type").and_then(|t| t.as_str()) != Some("tool_result") {
            return;
        }
        let Some(tool_use_id) = item.get("tool_use_id").and_then(|i| i.as_str()) else {
            return;
        };
        let output_bytes = result_bytes(item.get("content"));
        let is_error = item
            .get("is_error")
            .and_then(|e| e.as_bool())
            .unwrap_or(false);

        match self.tool_use_pending.remove(tool_use_id) {
            Some((name, command, input_bytes)) => {
                let entry = self
                    .tool_calls_by_name
                    .entry(name.clone())
                    .or_insert((0, 0, 0));
                entry.0 += 1;
                entry.1 += input_bytes;
                entry.2 += output_bytes;
                self.tool_calls.push(ToolCall {
                    id: tool_use_id.to_string(),
                    name,
                    command,
                    input_bytes,
                    output_bytes,
                    is_error,
                });
            }
            None => {
                self.orphan_results += 1;
                self.orphan_output_bytes += output_bytes;
            }
        }
    }

    fn note_result(&mut self, json: &serde_json::Value) {
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
        if let Some(usage) = json.get("usage").and_then(|u| u.as_object()) {
            let total = usage_of(usage);
            self.total_input_tokens = total.input_tokens;
            self.total_output_tokens = total.output_tokens;
            self.total_cache_read_tokens = total.cache_read_input_tokens;
            self.total_cache_creation_tokens = total.cache_creation_input_tokens;
            self.cache_creation_1h_tokens = total.cache_creation_1h_input_tokens;
            self.cache_creation_5m_tokens = total.cache_creation_5m_input_tokens;
        }
        if let Some(denials) = json.get("permission_denials").and_then(|d| d.as_array()) {
            for denial in denials {
                // Claude Code emits objects with a tool_name; accept bare strings too.
                let label = denial
                    .as_str()
                    .or_else(|| denial.get("tool_name").and_then(|n| n.as_str()));
                if let Some(label) = label {
                    self.permission_denials.push(label.to_string());
                }
            }
        }
    }

    /// The Bash commands that ran so far and whether each succeeded.
    pub fn bash_commands(&self) -> Vec<BashCommand> {
        self.summary().bash_commands()
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
            + self.orphan_output_bytes
            + self.result_text_length;

        MeterSummary {
            session_id: self.session_id.clone(),
            tool_calls: self.tool_calls.clone(),
            tool_calls_by_name: self.tool_calls_by_name.clone(),
            orphan_results: self.orphan_results,
            orphan_output_bytes: self.orphan_output_bytes,
            pending_tool_uses: self.tool_use_pending.len() as u64,
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

    const RUN1: &str = include_str!("../tests/fixtures/stream-run1.jsonl");
    const RESUME: &str = include_str!("../tests/fixtures/stream-resume.jsonl");

    fn meter_for(resumed: bool, text: &str) -> StreamMeter {
        let mut meter = StreamMeter::new(resumed);
        for line in text.lines().filter(|l| !l.is_empty()) {
            meter.feed(line).expect("line should parse");
        }
        meter
    }

    fn turn(input: u64, output: u64, read: u64, create: u64, h1: u64) -> TurnUsage {
        TurnUsage {
            input_tokens: input,
            output_tokens: output,
            cache_read_input_tokens: read,
            cache_creation_input_tokens: create,
            cache_creation_1h_input_tokens: h1,
            cache_creation_5m_input_tokens: 0,
        }
    }

    #[test]
    fn run1_session_and_tool_calls() {
        let summary = meter_for(false, RUN1).summary();
        assert_eq!(
            summary.session_id.as_deref(),
            Some("00000000-0000-4000-8000-000000000001")
        );
        assert_eq!(summary.tool_calls.len(), 2);
        assert_eq!(summary.tool_calls[0].name, "Bash");
        assert_eq!(summary.tool_calls[1].name, "mcp__probe__ping");
        assert!(!summary.tool_calls[0].is_error);
        assert!(!summary.tool_calls[1].is_error);
        assert_eq!(summary.orphan_results, 0);
        assert_eq!(summary.pending_tool_uses, 0);
        assert_eq!(summary.result_subtype.as_deref(), Some("success"));
        assert_eq!(summary.num_turns, Some(3));
        assert_eq!(summary.unknown_event_count, 0);
    }

    #[test]
    fn run1_totals_equal_result_usage() {
        let summary = meter_for(false, RUN1).summary();
        assert_eq!(summary.total_input_tokens, 6);
        assert_eq!(summary.total_output_tokens, 161);
        assert_eq!(summary.total_cache_read_tokens, 1668);
        assert_eq!(summary.total_cache_creation_tokens, 1900);
        assert_eq!(summary.cache_creation_1h_tokens, 1900);
        assert_eq!(summary.cache_creation_5m_tokens, 0);
    }

    #[test]
    fn run1_per_turn_usage_is_per_message_and_matches_totals() {
        let summary = meter_for(false, RUN1).summary();
        // Four assistant events, two distinct message ids: three events repeat
        // msg_FIXTURE_2 (one per content block), one is msg_FIXTURE_3.
        assert_eq!(
            summary.turns,
            vec![turn(4, 2, 0, 1668, 1668), turn(2, 5, 1668, 232, 232)]
        );
        let sum = |f: fn(&TurnUsage) -> u64| summary.turns.iter().map(f).sum::<u64>();
        assert_eq!(sum(|t| t.input_tokens), summary.total_input_tokens);
        assert_eq!(
            sum(|t| t.cache_read_input_tokens),
            summary.total_cache_read_tokens
        );
        assert_eq!(
            sum(|t| t.cache_creation_input_tokens),
            summary.total_cache_creation_tokens
        );
        assert_eq!(
            sum(|t| t.cache_creation_1h_input_tokens),
            summary.cache_creation_1h_tokens
        );
        // Streamed output_tokens are snapshots and exclude thinking, so they do
        // not sum to the result total (7 versus 161); the result total is canonical.
        assert_eq!(sum(|t| t.output_tokens), 7);
        assert!(sum(|t| t.output_tokens) <= summary.total_output_tokens);
    }

    #[test]
    fn run1_fresh_run_has_no_resume_state() {
        assert_eq!(meter_for(false, RUN1).summary().resume_warm, None);
    }

    #[test]
    fn resume_fixture_totals_and_warm_cache() {
        let summary = meter_for(true, RESUME).summary();
        assert_eq!(summary.resume_warm, Some(true));
        assert_eq!(summary.turns, vec![turn(4, 7, 1900, 31, 31)]);
        assert_eq!(summary.total_input_tokens, 4);
        assert_eq!(summary.total_output_tokens, 7);
        assert_eq!(summary.total_cache_read_tokens, 1900);
        assert_eq!(summary.total_cache_creation_tokens, 31);
        assert_eq!(summary.cache_creation_1h_tokens, 31);
        assert_eq!(summary.cache_creation_5m_tokens, 0);
        assert_eq!(summary.num_turns, Some(1));
        assert!(summary.tool_calls.is_empty());
    }

    #[test]
    fn cold_resume_is_some_false() {
        let cold = r#"{"type":"system","session_id":"s"}
{"type":"assistant","message":{"id":"m1","usage":{"input_tokens":4,"output_tokens":7,"cache_read_input_tokens":0,"cache_creation_input_tokens":31}}}
{"type":"result","subtype":"success","result":"t","usage":{"input_tokens":4,"output_tokens":7,"cache_read_input_tokens":0,"cache_creation_input_tokens":31}}"#;
        assert_eq!(meter_for(true, cold).summary().resume_warm, Some(false));
    }

    #[test]
    fn resumed_with_no_assistant_turn_is_unknown() {
        let none = r#"{"type":"system","session_id":"s"}"#;
        assert_eq!(meter_for(true, none).summary().resume_warm, None);
    }

    #[test]
    fn assistant_events_without_message_id_are_separate_turns() {
        let text = r#"{"type":"assistant","message":{"usage":{"input_tokens":1}}}
{"type":"assistant","message":{"usage":{"input_tokens":2}}}"#;
        let summary = meter_for(false, text).summary();
        assert_eq!(summary.turns.len(), 2);
    }

    #[test]
    fn bash_commands_from_run1() {
        let meter = meter_for(false, RUN1);
        let expected = vec![BashCommand {
            command: "echo hello > probe.txt".to_string(),
            succeeded: true,
        }];
        assert_eq!(meter.bash_commands(), expected);
        assert_eq!(meter.summary().bash_commands(), expected);
        // The MCP tool is not a Bash command.
        assert_eq!(meter.summary().tool_calls[1].command, None);
    }

    #[test]
    fn bash_command_with_is_error_result_failed() {
        let text = r#"{"type":"assistant","message":{"id":"m1","content":[{"type":"tool_use","id":"toolu_1","name":"Bash","input":{"command":"false"}}]}}
{"type":"user","message":{"content":[{"tool_use_id":"toolu_1","type":"tool_result","content":"exit 1","is_error":true}]}}"#;
        let meter = meter_for(false, text);
        assert_eq!(
            meter.bash_commands(),
            vec![BashCommand {
                command: "false".to_string(),
                succeeded: false
            }]
        );
        assert!(meter.summary().tool_calls[0].is_error);
    }

    #[test]
    fn tool_use_without_result_is_pending_not_a_command() {
        let text = r#"{"type":"assistant","message":{"id":"m1","content":[{"type":"tool_use","id":"toolu_1","name":"Bash","input":{"command":"sleep 9"}}]}}"#;
        let meter = meter_for(false, text);
        assert!(meter.bash_commands().is_empty());
        assert_eq!(meter.summary().pending_tool_uses, 1);
    }

    #[test]
    fn orphan_tool_result_is_counted_and_never_panics() {
        let text = r#"{"type":"user","message":{"content":[{"tool_use_id":"toolu_nope","type":"tool_result","content":"stray","is_error":false}]}}
{"type":"user","message":{"content":[{"type":"tool_result","content":"no id at all"}]}}
{"type":"user","message":{"content":"plain string content"}}
{"type":"user"}"#;
        let summary = meter_for(false, text).summary();
        assert_eq!(summary.orphan_results, 1);
        assert_eq!(summary.orphan_output_bytes, 5);
        assert!(summary.tool_calls.is_empty());
        assert!(summary.tool_calls_by_name.is_empty());
        assert_eq!(summary.total_bandwidth_bytes, 5);
    }

    #[test]
    fn duplicate_result_for_one_tool_use_is_an_orphan() {
        let text = r#"{"type":"assistant","message":{"id":"m1","content":[{"type":"tool_use","id":"toolu_1","name":"Bash","input":{"command":"ls"}}]}}
{"type":"user","message":{"content":[{"tool_use_id":"toolu_1","type":"tool_result","content":"a"}]}}
{"type":"user","message":{"content":[{"tool_use_id":"toolu_1","type":"tool_result","content":"b"}]}}"#;
        let summary = meter_for(false, text).summary();
        assert_eq!(summary.tool_calls.len(), 1);
        assert_eq!(summary.orphan_results, 1);
    }

    #[test]
    fn tool_bytes_by_name_for_run1() {
        let summary = meter_for(false, RUN1).summary();
        let bash = summary.tool_calls_by_name["Bash"];
        let ping = summary.tool_calls_by_name["mcp__probe__ping"];
        assert_eq!((bash.0, bash.2), (1, 31)); // "(Bash completed with no output)"
        assert_eq!((ping.0, ping.1, ping.2), (1, 2, 4)); // input {} and text "pong"
        assert!(bash.1 > 0);
    }

    #[test]
    fn bandwidth_total_is_tool_output_plus_result_text() {
        // run1: 31 (Bash output) + 4 ("pong") + 4 (result "DONE")
        let run1 = meter_for(false, RUN1).summary();
        assert_eq!(run1.result_text_length, 4);
        assert_eq!(run1.total_bandwidth_bytes, 39);
        // resume: no tools, result "probe.txt"
        let resume = meter_for(true, RESUME).summary();
        assert_eq!(resume.total_bandwidth_bytes, 9);
    }

    #[test]
    fn unknown_event_types_are_counted() {
        let text = r#"{"type":"system","session_id":"t"}
{"type":"unknown_event_type","data":"ignored"}
{"type":"rate_limit_event"}
{"no_type":true}
{"type":"result","subtype":"success"}"#;
        let summary = meter_for(false, text).summary();
        assert_eq!(summary.unknown_event_count, 3);
    }

    #[test]
    fn non_json_line_returns_error() {
        let mut meter = StreamMeter::new(false);
        assert!(meter.feed("not a json line at all").is_err());
        assert!(meter.feed("").is_err());
        // The meter is still usable afterwards.
        assert!(meter.feed(r#"{"type":"system","session_id":"x"}"#).is_ok());
    }

    #[test]
    fn permission_denials_accept_objects_and_strings() {
        let text = r#"{"type":"result","subtype":"success","permission_denials":[{"tool_name":"Bash","tool_use_id":"t","tool_input":{}},"Write"]}"#;
        let summary = meter_for(false, text).summary();
        assert_eq!(summary.permission_denials, vec!["Bash", "Write"]);
    }

    #[test]
    fn summary_round_trips_through_serde() {
        let summary = meter_for(false, RUN1).summary();
        let json = serde_json::to_string(&summary).expect("serialize");
        let back: MeterSummary = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, summary);
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["total_cache_read_tokens"], 1668);
        assert_eq!(value["orphan_results"], 0);
        assert_eq!(value["turns"].as_array().unwrap().len(), 2);
    }
}
