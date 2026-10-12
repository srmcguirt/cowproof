//! Replay captured fixtures against the Rust port and report the differences.

use std::fmt;
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tracing::debug;

use portkit_core::{diff, DiffOptions, Difference, Error, Registry, Result};
use portkit_mcp::{McpServer, ServerInfo};

use crate::fixture::{load_fixtures, Fixture};

/// Which code path a fixture is replayed through.
///
/// Both should agree. Running `Mcp` in CI is what catches the envelope itself
/// distorting results — a tool that is correct but unreachable through the
/// agent surface is still a broken port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Surface {
    /// Call the registry directly.
    #[default]
    Direct,
    /// Call through `tools/call` and read `structuredContent` back, exactly as
    /// an MCP client would.
    Mcp,
}

impl fmt::Display for Surface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Surface::Direct => "direct",
            Surface::Mcp => "mcp",
        })
    }
}

#[derive(Debug, Clone, Default)]
pub struct ReplayOptions {
    pub diff: DiffOptions,
    pub surface: Surface,
    /// Replay only this tool when set.
    pub only_tool: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseOutcome {
    pub tool: String,
    pub id: String,
    pub surface: Surface,
    pub status: Status,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub differences: Vec<Difference>,
    /// Differences the fixture explicitly accepts, carried through so a
    /// report shows what the port is knowingly diverging on.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accepted: Vec<AcceptedNote>,
    /// Set when the tool errored rather than merely disagreeing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// One tolerated difference, paired with the reason it is tolerated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcceptedNote {
    pub path: String,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// Output matched the reference within tolerance.
    Pass,
    /// Output differed.
    Fail,
    /// Output differed only where the fixture says it may. Not a failure, but
    /// surfaced in reports so the divergence stays visible.
    Accepted,
    /// The tool errored, or is not registered yet.
    Error,
    /// No such tool in the registry — not started, or renamed.
    NotPorted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayReport {
    pub outcomes: Vec<CaseOutcome>,
    pub passed: usize,
    /// Cases that differed only in ways the fixture accepts.
    pub accepted: usize,
    pub failed: usize,
    pub errored: usize,
    pub not_ported: usize,
}

impl ReplayReport {
    fn from_outcomes(outcomes: Vec<CaseOutcome>) -> Self {
        let count = |s: Status| outcomes.iter().filter(|o| o.status == s).count();
        Self {
            passed: count(Status::Pass),
            accepted: count(Status::Accepted),
            failed: count(Status::Fail),
            errored: count(Status::Error),
            not_ported: count(Status::NotPorted),
            outcomes,
        }
    }

    pub fn total(&self) -> usize {
        self.outcomes.len()
    }

    /// Whether every replayed case matched.
    ///
    /// Unported tools count as failure: a port is not done while a fixture has
    /// no implementation to answer it.
    pub fn is_success(&self) -> bool {
        self.failed == 0 && self.errored == 0 && self.not_ported == 0
    }

    /// Per-tool `(tool, passed, total)`, in stable order, for progress reporting.
    pub fn by_tool(&self) -> Vec<(String, usize, usize)> {
        let mut tools: Vec<&str> = self.outcomes.iter().map(|o| o.tool.as_str()).collect();
        tools.sort_unstable();
        tools.dedup();

        tools
            .into_iter()
            .map(|tool| {
                let cases = self.outcomes.iter().filter(|o| o.tool == tool);
                let total = cases.clone().count();
                // Accepted differences count as passing: the port is doing
                // what the fixture says it should.
                let passed = cases
                    .filter(|o| matches!(o.status, Status::Pass | Status::Accepted))
                    .count();
                (tool.to_string(), passed, total)
            })
            .collect()
    }
}

/// Replay every fixture under `root` against `registry`.
pub async fn replay(
    root: &Path,
    registry: &Registry,
    opts: &ReplayOptions,
) -> Result<ReplayReport> {
    let fixtures = load_fixtures(root)?;
    replay_fixtures(&fixtures, registry, opts).await
}

/// Replay an already-loaded set of fixtures.
pub async fn replay_fixtures(
    fixtures: &[Fixture],
    registry: &Registry,
    opts: &ReplayOptions,
) -> Result<ReplayReport> {
    // Built once, outside the loop: constructing a server per case would make
    // the MCP surface look slower than it is.
    let server = McpServer::new(registry.clone(), ServerInfo::default());

    let mut outcomes = Vec::new();
    for fixture in fixtures {
        if let Some(only) = &opts.only_tool {
            if &fixture.tool != only {
                continue;
            }
        }
        outcomes.push(replay_one(fixture, registry, &server, opts).await);
    }

    Ok(ReplayReport::from_outcomes(outcomes))
}

async fn replay_one(
    fixture: &Fixture,
    registry: &Registry,
    server: &McpServer,
    opts: &ReplayOptions,
) -> CaseOutcome {
    let base = |status: Status| CaseOutcome {
        tool: fixture.tool.clone(),
        id: fixture.id.clone(),
        surface: opts.surface,
        status,
        differences: Vec::new(),
        accepted: Vec::new(),
        error: None,
    };

    if registry.get(&fixture.tool).is_none() {
        return CaseOutcome {
            error: Some(format!("`{}` is not registered", fixture.tool)),
            ..base(Status::NotPorted)
        };
    }

    // A fixture whose output went through a transform this build does not know cannot be
    // compared: its meaning would be whatever the current binary does.
    if let Some(normalized) = &fixture.normalized {
        if let Err(why) = crate::process::check_normalized(normalized) {
            return CaseOutcome {
                error: Some(why),
                ..base(Status::Error)
            };
        }
    }

    let actual = match opts.surface {
        Surface::Direct => registry.call(&fixture.tool, fixture.input.clone()).await,
        Surface::Mcp => call_via_mcp(server, fixture).await,
    };

    let actual = match actual {
        Ok(v) => v,
        // A "must reject" case (G4): the port's failure is compared as the same envelope the
        // reference's was recorded as. A port that does not fail returns its value and is
        // compared against the error, which differs.
        Err(err) if fixture.expect_error => error_envelope_of(&err),
        Err(err) => {
            return CaseOutcome {
                error: Some(err.to_string()),
                ..base(Status::Error)
            };
        }
    };

    // Split what the fixture has signed off on from what it has not. The
    // exemption is scoped to a path, so accepting one field never quietly
    // excuses a regression elsewhere in the same case.
    let (tolerated, differences): (Vec<_>, Vec<_>) = diff(&fixture.expected, &actual, &opts.diff)
        .into_iter()
        .partition(|d| fixture.accepted.iter().any(|a| a.covers(&d.path)));

    let accepted: Vec<AcceptedNote> = tolerated
        .iter()
        .filter_map(|d| {
            fixture
                .accepted
                .iter()
                .find(|a| a.covers(&d.path))
                .map(|a| AcceptedNote {
                    path: d.path.clone(),
                    reason: a.reason.clone(),
                })
        })
        .collect();

    debug!(
        tool = %fixture.tool,
        id = %fixture.id,
        differences = differences.len(),
        accepted = accepted.len(),
        "replayed"
    );

    if !differences.is_empty() {
        return CaseOutcome {
            differences,
            accepted,
            ..base(Status::Fail)
        };
    }
    if accepted.is_empty() {
        base(Status::Pass)
    } else {
        CaseOutcome {
            accepted,
            ..base(Status::Accepted)
        }
    }
}

/// A port's failure as the envelope `capture` records for a reference that failed (G4):
/// `{"error": {"exit": N, "message": ".."}}`.
///
/// A plugin that exits non-zero fails with `exited with exit status: N: <first stderr line>`;
/// the exit and the message are read back from that text, wherever in the error it sits (the
/// MCP surface wraps it). Any other failure has no exit (`null`) and its text as the message.
pub fn error_envelope_of(err: &Error) -> Value {
    let text = match err {
        Error::ToolFailed { message, .. } => message.clone(),
        other => other.to_string(),
    };
    for marker in ["exited with exit status: ", "exited with exit code: "] {
        if let Some(at) = text.find(marker) {
            let rest = &text[at + marker.len()..];
            if let Some((code, message)) = rest.split_once(": ") {
                if let Ok(code) = code.trim().parse::<i32>() {
                    return json!({"error": {"exit": code, "message": message.trim()}});
                }
            }
        }
    }
    json!({"error": {"exit": null, "message": text}})
}

/// Drive one call through the MCP envelope and unwrap it the way a client does.
async fn call_via_mcp(server: &McpServer, fixture: &Fixture) -> Result<Value> {
    let result = server.call_tool(&fixture.tool, fixture.input.clone()).await;

    if result.is_error {
        let message = result
            .content
            .first()
            .map(|c| c.as_text().to_string())
            .unwrap_or_else(|| "tool reported an error with no message".into());
        return Err(portkit_core::Error::tool_failed(&fixture.tool, message));
    }

    match result.structured_content {
        Some(value) => Ok(value),
        // A tool that returns only prose cannot be compared structurally.
        // Fall back to parsing the text block, which is what a client without
        // structuredContent support would have to do anyway.
        None => {
            let text = result
                .content
                .first()
                .map(|c| c.as_text())
                .unwrap_or_default();
            serde_json::from_str(text).map_err(|e| {
                portkit_core::Error::tool_failed(
                    &fixture.tool,
                    format!(
                        "MCP result carried no structuredContent and its text was not JSON: {e}"
                    ),
                )
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use portkit_core::{async_trait, Result as CoreResult, Tool, ToolSpec};
    use serde_json::{json, Value};

    use crate::fixture::AcceptedDifference;

    /// A tool that deliberately disagrees with the reference in one field,
    /// standing in for a Rust library that behaves slightly differently from
    /// its Python counterpart.
    struct Drifts;

    #[async_trait]
    impl Tool for Drifts {
        fn spec(&self) -> ToolSpec {
            ToolSpec::new(
                "drifts",
                "Returns a fixed value.",
                json!({"type": "object"}),
            )
        }
        async fn call(&self, _input: Value) -> CoreResult<Value> {
            Ok(json!({"stable": 1, "quirk": "rust-behaviour"}))
        }
    }

    fn fixture(accepted: Vec<AcceptedDifference>) -> Fixture {
        Fixture {
            tool: "drifts".into(),
            id: "case".into(),
            input: json!({}),
            expected: json!({"stable": 1, "quirk": "python-behaviour"}),
            captured_at: None,
            source: None,
            note: None,
            accepted,
            env: Default::default(),
            expect_error: false,
            normalized: None,
        }
    }

    async fn run(f: Fixture) -> ReplayReport {
        let registry = Registry::new().with(Drifts);
        replay_fixtures(&[f], &registry, &ReplayOptions::default())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn an_unexplained_difference_fails() {
        let report = run(fixture(vec![])).await;
        assert!(!report.is_success());
        assert_eq!(report.failed, 1);
    }

    #[tokio::test]
    async fn a_documented_difference_passes_but_is_reported() {
        let report = run(fixture(vec![AcceptedDifference {
            path: "/quirk".into(),
            reason: "comrak normalises this; marko does not".into(),
        }]))
        .await;

        assert!(
            report.is_success(),
            "an accepted difference must not fail the build"
        );
        assert_eq!(report.accepted, 1);
        // The reason must survive into the report, or review cannot audit it.
        assert!(crate::render(&report).contains("comrak normalises this"));
    }

    #[tokio::test]
    async fn accepting_one_field_does_not_excuse_another() {
        // The exemption must be scoped, not a blanket pass for the case.
        let mut f = fixture(vec![AcceptedDifference {
            path: "/quirk".into(),
            reason: "known parser difference".into(),
        }]);
        f.expected = json!({"stable": 99, "quirk": "python-behaviour"});

        let report = run(f).await;
        assert!(!report.is_success());
        assert_eq!(report.failed, 1);
    }

    /// A tool that fails the way a plugin does when its process exits non-zero.
    struct Rejects(&'static str);

    #[async_trait]
    impl Tool for Rejects {
        fn spec(&self) -> ToolSpec {
            ToolSpec::new("rejects", "Always fails.", json!({"type": "object"}))
        }
        async fn call(&self, _input: Value) -> CoreResult<Value> {
            Err(Error::tool_failed("rejects", self.0))
        }
    }

    fn must_reject(expected: Value, expect_error: bool) -> Fixture {
        Fixture {
            tool: "rejects".into(),
            id: "bad".into(),
            input: json!({}),
            expected,
            captured_at: None,
            source: None,
            note: None,
            accepted: vec![],
            env: Default::default(),
            expect_error,
            normalized: None,
        }
    }

    async fn run_with(tool: impl Tool + 'static, f: Fixture, surface: Surface) -> ReplayReport {
        let registry = Registry::new().with(tool);
        let opts = ReplayOptions {
            surface,
            ..Default::default()
        };
        replay_fixtures(&[f], &registry, &opts).await.unwrap()
    }

    #[tokio::test]
    async fn a_port_that_fails_the_same_way_passes_a_must_reject_case_on_both_surfaces() {
        let expected = json!({"error": {"exit": 2, "message": "no such flag"}});
        for surface in [Surface::Direct, Surface::Mcp] {
            let report = run_with(
                Rejects("exited with exit status: 2: no such flag"),
                must_reject(expected.clone(), true),
                surface,
            )
            .await;
            assert!(report.is_success(), "{surface}: {}", crate::render(&report));
        }
    }

    #[tokio::test]
    async fn a_port_that_fails_differently_is_refuted_naming_the_field() {
        let expected = json!({"error": {"exit": 2, "message": "no such flag"}});
        for (failure, field) in [
            ("exited with exit status: 1: no such flag", "/error/exit"),
            (
                "exited with exit status: 2: another message",
                "/error/message",
            ),
        ] {
            let report = run_with(
                Rejects(failure),
                must_reject(expected.clone(), true),
                Surface::Direct,
            )
            .await;
            assert!(!report.is_success());
            assert_eq!(report.failed, 1, "{failure}");
            assert!(
                crate::render(&report).contains(field),
                "{}",
                crate::render(&report)
            );
        }
        // A failure that is not a process exit has no exit to compare.
        let report = run_with(
            Rejects("could not start: boom"),
            must_reject(expected, true),
            Surface::Direct,
        )
        .await;
        assert_eq!(report.failed, 1);
    }

    #[tokio::test]
    async fn a_port_that_accepts_what_must_be_rejected_is_refuted() {
        // `Drifts` answers a value where the reference failed.
        let mut f = fixture(vec![]);
        f.tool = "drifts".into();
        f.expected = json!({"error": {"exit": 2, "message": "no such flag"}});
        f.expect_error = true;
        let report = run(f).await;
        assert_eq!(report.failed, 1);
        assert!(
            crate::render(&report).contains("/error"),
            "{}",
            crate::render(&report)
        );
    }

    #[tokio::test]
    async fn a_failure_is_still_an_error_when_the_case_does_not_expect_one() {
        let report = run_with(
            Rejects("exited with exit status: 2: x"),
            must_reject(json!({"ok": true}), false),
            Surface::Direct,
        )
        .await;
        assert_eq!(report.errored, 1);
    }

    #[test]
    fn error_envelopes_are_read_back_from_the_text_wherever_it_sits() {
        let direct = Error::tool_failed("t", "exited with exit status: 2: bad flag");
        assert_eq!(
            error_envelope_of(&direct),
            json!({"error": {"exit": 2, "message": "bad flag"}})
        );
        let wrapped = Error::tool_failed(
            "t",
            "tool `t` failed: exited with exit status: 3: bad: flag",
        );
        assert_eq!(
            error_envelope_of(&wrapped),
            json!({"error": {"exit": 3, "message": "bad: flag"}})
        );
        let signalled = Error::tool_failed("t", "exited with signal: 9 (SIGKILL): ");
        assert_eq!(error_envelope_of(&signalled)["error"]["exit"], Value::Null);
    }

    #[tokio::test]
    async fn a_fixture_with_an_unknown_normalizer_is_an_error_not_a_pass() {
        let mut f = fixture(vec![]);
        f.expected = json!({"stable": 1, "quirk": "rust-behaviour"});
        f.normalized = Some(crate::Normalized {
            name: "path-roots".into(),
            version: 99,
            roots: vec!["$ROOT".into()],
        });
        let report = run(f).await;
        assert_eq!(report.errored, 1);
        assert!(
            report.outcomes[0].error.as_deref().unwrap().contains("v99"),
            "{:?}",
            report.outcomes[0].error
        );
        let mut known = fixture(vec![]);
        known.expected = json!({"stable": 1, "quirk": "rust-behaviour"});
        known.normalized = crate::process::normalized_for(&["$ROOT".to_string()]);
        assert!(run(known).await.is_success());
    }
}
