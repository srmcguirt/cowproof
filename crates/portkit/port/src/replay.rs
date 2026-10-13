//! Replay captured fixtures against the Rust port and report the differences.

use std::fmt;
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tracing::debug;

use portkit_core::{diff, DiffOptions, Difference, Error, Registry, Result};
use portkit_mcp::{McpServer, ServerInfo};

use crate::fixture::{host_platform, load_fixtures, Fixture};

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

/// A fixture a replay did not run because it is tagged for another platform.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkippedFixture {
    pub tool: String,
    pub id: String,
    /// The platform the fixture is tagged for.
    pub platform: String,
}

/// A tool whose fixtures were all tagged for other platforms: nothing of it was replayed here,
/// so the port was never proved on this platform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformGap {
    pub tool: String,
    /// The platforms its fixtures cover (all other than this host's).
    pub platforms: Vec<String>,
}

impl fmt::Display for PlatformGap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "tool {:?} has no fixture for {} (its fixtures cover {}), so it was never proved on this platform",
            self.tool,
            host_platform(),
            self.platforms.join(", ")
        )
    }
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
    /// Fixtures tagged for another platform: not replayed, and never counted as passed.
    #[serde(default)]
    pub other_platform: usize,
    /// Which fixtures those were.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub other_platform_cases: Vec<SkippedFixture>,
}

impl ReplayReport {
    fn from_outcomes(outcomes: Vec<CaseOutcome>, skipped: Vec<SkippedFixture>) -> Self {
        let count = |s: Status| outcomes.iter().filter(|o| o.status == s).count();
        Self {
            passed: count(Status::Pass),
            accepted: count(Status::Accepted),
            failed: count(Status::Fail),
            errored: count(Status::Error),
            not_ported: count(Status::NotPorted),
            other_platform: skipped.len(),
            other_platform_cases: skipped,
            outcomes,
        }
    }

    /// The tools that have fixtures tagged for other platforms and none replayed on this one.
    pub fn platform_gaps(&self) -> Vec<PlatformGap> {
        let mut gaps: Vec<PlatformGap> = Vec::new();
        for skipped in &self.other_platform_cases {
            if self.outcomes.iter().any(|o| o.tool == skipped.tool) {
                continue;
            }
            match gaps.iter_mut().find(|g| g.tool == skipped.tool) {
                Some(gap) => {
                    if !gap.platforms.contains(&skipped.platform) {
                        gap.platforms.push(skipped.platform.clone());
                    }
                }
                None => gaps.push(PlatformGap {
                    tool: skipped.tool.clone(),
                    platforms: vec![skipped.platform.clone()],
                }),
            }
        }
        gaps.sort_by(|a, b| a.tool.cmp(&b.tool));
        for gap in &mut gaps {
            gap.platforms.sort();
        }
        gaps
    }

    pub fn total(&self) -> usize {
        self.outcomes.len()
    }

    /// Whether every replayed case matched.
    ///
    /// Unported tools count as failure: a port is not done while a fixture has
    /// no implementation to answer it. So does a tool whose fixtures are all for other
    /// platforms: a port must never prove on a platform it was never captured on.
    pub fn is_success(&self) -> bool {
        self.failed == 0
            && self.errored == 0
            && self.not_ported == 0
            && self.platform_gaps().is_empty()
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

    let host = host_platform();
    let mut outcomes = Vec::new();
    let mut skipped = Vec::new();
    for fixture in fixtures {
        if let Some(only) = &opts.only_tool {
            if &fixture.tool != only {
                continue;
            }
        }
        // A fixture tagged for another platform says what the reference did there; it is not
        // a claim about this one, so it is not run and not counted as passed.
        if !fixture.applies_on(host) {
            skipped.push(SkippedFixture {
                tool: fixture.tool.clone(),
                id: fixture.id.clone(),
                platform: fixture.platform.clone().unwrap_or_default(),
            });
            continue;
        }
        outcomes.push(replay_one(fixture, registry, &server, opts).await);
    }

    Ok(ReplayReport::from_outcomes(outcomes, skipped))
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

    // A process wrapper says which roots it substitutes; they must be the ones the fixture was
    // captured with, or the two sides speak different vocabularies.
    if let Some(wrapped) = registry
        .get(&fixture.tool)
        .and_then(|tool| tool.spec().path_roots)
    {
        if let Err(why) = crate::process::check_roots(&wrapped, fixture.normalized.as_ref()) {
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
            platform: None,
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
            platform: None,
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

    /// A process wrapper: it answers the fixture's `expected` and declares the roots it
    /// substitutes in its spec, as `pk port wrap --portkit-spec` does.
    struct Wrapped(Vec<String>);

    #[async_trait]
    impl Tool for Wrapped {
        fn spec(&self) -> ToolSpec {
            ToolSpec::new("drifts", "A wrapped port.", json!({"type": "object"}))
                .with_path_roots(self.0.clone())
        }
        async fn call(&self, _input: Value) -> CoreResult<Value> {
            Ok(json!({"stable": 1, "quirk": "python-behaviour"}))
        }
    }

    fn roots(roots: &[&str]) -> Vec<String> {
        roots.iter().map(|r| r.to_string()).collect()
    }

    fn captured_with(declared: &[&str]) -> Fixture {
        let mut f = fixture(vec![]);
        f.normalized = crate::process::normalized_for(&roots(declared));
        f
    }

    #[tokio::test]
    async fn a_wrap_with_other_roots_than_the_fixture_was_captured_with_fails_naming_both() {
        for surface in [Surface::Direct, Surface::Mcp] {
            // Matching roots (in any order, repeats aside) pass.
            for wrapped in [
                roots(&["$HOME", "$ROOT", "$TMP"]),
                roots(&["$TMP", "$ROOT", "$HOME", "$ROOT"]),
            ] {
                let f = captured_with(&["$ROOT", "$HOME", "$TMP"]);
                let report = run_with(Wrapped(wrapped), f, surface).await;
                assert!(report.is_success(), "{surface}: {}", crate::render(&report));
            }
            // A root the wrap leaves out, a root it adds, and none against some are mismatches.
            for (wrapped, captured) in [
                (roots(&["$ROOT"]), &["$HOME", "$ROOT"][..]),
                (roots(&["$ROOT", "$SRC"]), &["$ROOT"][..]),
                (roots(&[]), &["$ROOT"][..]),
                (roots(&["$ROOT"]), &[][..]),
            ] {
                let report =
                    run_with(Wrapped(wrapped.clone()), captured_with(captured), surface).await;
                assert_eq!(report.errored, 1, "{surface}: {wrapped:?} vs {captured:?}");
                assert!(!report.is_success());
                let why = report.outcomes[0].error.clone().unwrap();
                // Both sides are named, the wrap's first.
                let wrapped_text = if wrapped.is_empty() {
                    "none".to_string()
                } else {
                    wrapped.join(", ")
                };
                let captured_text = if captured.is_empty() {
                    "none".to_string()
                } else {
                    captured.join(", ")
                };
                assert!(
                    why.contains(&format!("substitutes the roots [{wrapped_text}]"))
                        && why.contains(&format!("captured with [{captured_text}]")),
                    "{why}"
                );
            }
        }
    }

    #[tokio::test]
    async fn a_tool_that_declares_no_roots_is_not_compared() {
        // `Drifts` is no process wrapper: its spec says nothing about roots.
        let f = captured_with(&["$ROOT"]);
        let report = run(f).await;
        assert_eq!(report.errored, 0);
        assert_eq!(
            report.failed, 1,
            "it fails on its own difference, not on roots"
        );
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

    // ---- platform-tagged fixtures ----

    /// The platform that is not the one running.
    fn other_platform() -> &'static str {
        crate::fixture::PLATFORMS
            .iter()
            .copied()
            .find(|p| *p != host_platform())
            .unwrap()
    }

    /// A fixture `Drifts` passes, written under `<id>` and tagged for `platform` (the id gets
    /// the suffix).
    fn passing(tool: &str, id: &str, platform: Option<&str>) -> Fixture {
        let mut f = fixture(vec![]);
        f.tool = tool.into();
        f.expected = json!({"stable": 1, "quirk": "rust-behaviour"});
        match platform {
            Some(p) => {
                f.id = format!("{id}@{p}");
                f.platform = Some(p.into());
            }
            None => f.id = id.into(),
        }
        f
    }

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::path::Path::new("/var/tmp")
            .join(format!("pk-replay-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[tokio::test]
    async fn a_mixed_directory_replays_the_untagged_and_its_own_platform_only() {
        let dir = scratch("mixed");
        let (host, other) = (host_platform(), other_platform());
        // One case in three versions: untagged, for this host, and for the other platform.
        for f in [
            passing("drifts", "a", None),
            passing("drifts", "a", Some(host)),
            // The other platform's fixture would fail here (its expectation is wrong), so a
            // replay that ran it would show.
            Fixture {
                expected: json!({"stable": 99}),
                ..passing("drifts", "a", Some(other))
            },
        ] {
            f.write(&dir).unwrap();
        }
        let registry = Registry::new().with(Drifts);
        for surface in [Surface::Direct, Surface::Mcp] {
            let opts = ReplayOptions {
                surface,
                ..Default::default()
            };
            let report = replay(&dir, &registry, &opts).await.unwrap();
            let ran: Vec<&str> = report.outcomes.iter().map(|o| o.id.as_str()).collect();
            assert_eq!(ran, ["a", &format!("a@{host}")], "{surface}");
            assert_eq!(report.passed, 2, "{surface}");
            assert_eq!(report.failed, 0, "{surface}");
            assert_eq!(report.other_platform, 1, "{surface}");
            assert_eq!(
                report.other_platform_cases,
                [SkippedFixture {
                    tool: "drifts".into(),
                    id: format!("a@{other}"),
                    platform: other.into()
                }]
            );
            // Never counted as passed, nor in the total or the per-tool figures.
            assert_eq!(report.total(), 2);
            assert_eq!(report.by_tool(), [("drifts".to_string(), 2, 2)]);
            assert!(report.platform_gaps().is_empty());
            assert!(report.is_success(), "{surface}");
            let text = crate::render(&report);
            assert!(text.contains("2 passed"), "{text}");
            assert!(text.contains("1 for other platforms"), "{text}");
            // The count is in the JSON report a verifier reads.
            let json = serde_json::to_value(&report).unwrap();
            assert_eq!(json["other_platform"], 1);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_tool_with_only_other_platform_fixtures_fails_naming_the_tool_and_platforms() {
        let dir = scratch("gap");
        let (host, other) = (host_platform(), other_platform());
        passing("drifts", "a", Some(host)).write(&dir).unwrap();
        // `elsewhere` is not registered: a skipped fixture is never looked up.
        passing("elsewhere", "a", Some(other)).write(&dir).unwrap();
        passing("elsewhere", "b", Some(other)).write(&dir).unwrap();
        let registry = Registry::new().with(Drifts);
        let report = replay(&dir, &registry, &ReplayOptions::default())
            .await
            .unwrap();
        // Nothing of it errored or was reported not ported: it was not replayed at all.
        assert_eq!(
            (report.passed, report.errored, report.not_ported),
            (1, 0, 0)
        );
        assert_eq!(report.other_platform, 2);
        let gaps = report.platform_gaps();
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0].tool, "elsewhere");
        assert_eq!(gaps[0].platforms, [other]);
        assert!(!report.is_success());
        let text = crate::render(&report);
        assert!(
            text.contains("\"elsewhere\"") && text.contains(other),
            "{text}"
        );
        assert!(text.contains(&format!("no fixture for {host}")), "{text}");

        // Only the other platform's fixtures for the one tool: the replay is empty and fails.
        let only = scratch("gap-only");
        passing("drifts", "a", Some(other)).write(&only).unwrap();
        let report = replay(&only, &registry, &ReplayOptions::default())
            .await
            .unwrap();
        assert_eq!(report.total(), 0);
        assert_eq!(report.other_platform, 1);
        assert!(!report.is_success());
        assert_eq!(report.platform_gaps()[0].tool, "drifts");

        // `--tool` leaves another tool's gap out of the report.
        let opts = ReplayOptions {
            only_tool: Some("drifts".into()),
            ..Default::default()
        };
        let report = replay(&dir, &registry, &opts).await.unwrap();
        assert_eq!(report.other_platform, 0);
        assert!(report.is_success());
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&only);
    }

    #[tokio::test]
    async fn untagged_fixtures_replay_exactly_as_before_on_any_platform() {
        let dir = scratch("old");
        passing("drifts", "a", None).write(&dir).unwrap();
        passing("drifts", "b", None).write(&dir).unwrap();
        let raw = std::fs::read_to_string(dir.join("drifts/a.json")).unwrap();
        assert!(!raw.contains("platform"), "{raw}");
        let registry = Registry::new().with(Drifts);
        let report = replay(&dir, &registry, &ReplayOptions::default())
            .await
            .unwrap();
        assert_eq!((report.passed, report.other_platform), (2, 0));
        assert!(report.is_success());
        // A report without the new fields (one made before them) still reads.
        let old = json!({
            "outcomes": [], "passed": 0, "accepted": 0, "failed": 0, "errored": 0,
            "not_ported": 0,
        });
        let old: ReplayReport = serde_json::from_value(old).unwrap();
        assert_eq!(old.other_platform, 0);
        assert!(old.other_platform_cases.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
