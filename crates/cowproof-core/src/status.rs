//! Status taxonomy for lane runs: the complete set of outcomes with deterministic precedence.
//!
//! Ported from `mail/scripts/lanes/run-lane.mjs` L285-302 (classifyStatus)
//! and L888-891 (classifyOpencode branch).

use serde::{Deserialize, Deserializer, Serialize};

/// Deserialize a count from either an array length or a direct integer.
/// Node passes arrays; Rust API uses counts. This accepts both for parity testing.
fn deserialize_count<'de, D>(deserializer: D) -> Result<usize, D::Error>
where
    D: Deserializer<'de>,
{
    use serde_json::Value;
    match Value::deserialize(deserializer)? {
        Value::Array(arr) => Ok(arr.len()),
        Value::Number(num) => num
            .as_u64()
            .map(|n| n as usize)
            .ok_or_else(|| serde::de::Error::custom("number out of range")),
        _ => Err(serde::de::Error::custom(
            "expected array or number for count field",
        )),
    }
}

/// Input facts that determine a lane's outcome status.
/// Field names match the Node reference (camelCase via serde).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusFacts {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signal: Option<String>,
    #[serde(default)]
    pub terminal_event: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_type: Option<String>,
    #[serde(default)]
    pub handoff: bool,
    #[serde(default)]
    pub provider_refusal: bool,
    #[serde(default)]
    pub truncated: bool,
    #[serde(default)]
    pub timeout: bool,
    #[serde(default)]
    pub cost_cap: bool,
    #[serde(default)]
    pub sandbox_denied: bool,
    #[serde(default, deserialize_with = "deserialize_count")]
    pub append_only_breaches: usize,
    #[serde(default, deserialize_with = "deserialize_count")]
    pub violations: usize,
}

/// Lane outcome status with kebab-case serialization to match the Node taxonomy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LaneStatus {
    Finished,
    FinishedNoHandoff,
    WorkerStopped,
    WorkerCrashed,
    WorkerKilled,
    WorkerFailed,
    Truncated,
    ProviderRefused,
    SandboxDenied,
    Timeout,
    CostCap,
    OutsideOwnership,
    AppendOnlyBreach,
    RunnerError,
}

impl LaneStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Finished => "finished",
            Self::FinishedNoHandoff => "finished-no-handoff",
            Self::WorkerStopped => "worker-stopped",
            Self::WorkerCrashed => "worker-crashed",
            Self::WorkerKilled => "worker-killed",
            Self::WorkerFailed => "worker-failed",
            Self::Truncated => "truncated",
            Self::ProviderRefused => "provider-refused",
            Self::SandboxDenied => "sandbox-denied",
            Self::Timeout => "timeout",
            Self::CostCap => "cost-cap",
            Self::OutsideOwnership => "outside-ownership",
            Self::AppendOnlyBreach => "append-only-breach",
            Self::RunnerError => "runner-error",
        }
    }
}

/// Classification category for a lane status.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StatusClass {
    Finished,
    Worker,
    Provider,
    Host,
    Runner,
}

impl StatusClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Finished => "finished",
            Self::Worker => "worker",
            Self::Provider => "provider",
            Self::Host => "host",
            Self::Runner => "runner",
        }
    }
}

/// Classify a lane's outcome from the complete set of facts.
/// Implements the precedence order from run-lane.mjs L285-302.
pub fn classify_status(facts: &StatusFacts) -> (LaneStatus, StatusClass) {
    // Precedence order (earliest check wins):
    // 1. timeout (host/runner level)
    if facts.timeout {
        return (LaneStatus::Timeout, StatusClass::Runner);
    }

    // 2. cost-cap (runner level)
    if facts.cost_cap {
        return (LaneStatus::CostCap, StatusClass::Runner);
    }

    // 3. violations / outside-ownership (runner level)
    if facts.violations > 0 {
        return (LaneStatus::OutsideOwnership, StatusClass::Runner);
    }

    // 4. append-only breaches (runner level)
    if facts.append_only_breaches > 0 {
        return (LaneStatus::AppendOnlyBreach, StatusClass::Runner);
    }

    // 5. sandbox-denied without terminal event (host level)
    if facts.sandbox_denied && !facts.terminal_event {
        return (LaneStatus::SandboxDenied, StatusClass::Host);
    }

    // 6. provider refusal (provider level)
    if facts.provider_refusal {
        return (LaneStatus::ProviderRefused, StatusClass::Provider);
    }

    // 7. signal (worker killed)
    if facts.signal.is_some() {
        return (LaneStatus::WorkerKilled, StatusClass::Worker);
    }

    // 8. truncated (worker issue)
    if facts.truncated {
        return (LaneStatus::Truncated, StatusClass::Worker);
    }

    // 9. turn.completed path
    if facts.last_type.as_deref() == Some("turn.completed") {
        // In Node: exitCode !== 0 is true when exitCode is missing (undefined)
        // In Rust: we have Option<i32>, so missing is None, and None != Some(0) is true
        if facts.exit_code != Some(0) {
            return (LaneStatus::WorkerCrashed, StatusClass::Worker);
        }
        return if facts.handoff {
            (LaneStatus::Finished, StatusClass::Finished)
        } else {
            (LaneStatus::FinishedNoHandoff, StatusClass::Worker)
        };
    }

    // 10. turn.failed or error path
    if matches!(
        facts.last_type.as_deref(),
        Some("turn.failed") | Some("error")
    ) {
        return (LaneStatus::WorkerFailed, StatusClass::Worker);
    }

    // 11. no terminal event + specific exits
    if !facts.terminal_event {
        // In Node: exitCode === 0 || exitCode === 1 means both values match exactly
        // If exitCode is undefined, neither check matches, so it falls through
        if facts.exit_code == Some(0) || facts.exit_code == Some(1) {
            return (LaneStatus::WorkerStopped, StatusClass::Worker);
        }
        // In Node: exitCode !== 0 is true when exitCode is undefined/null
        // This includes missing exit code (None) and any non-zero exit
        if facts.exit_code.is_none() || facts.exit_code.is_some_and(|code| code != 0) {
            return (LaneStatus::WorkerCrashed, StatusClass::Worker);
        }
    }

    // 12. catchall (shouldn't reach here in practice)
    (LaneStatus::RunnerError, StatusClass::Runner)
}

/// Classify a lane's outcome for the opencode-only branch.
/// This path is taken when certain failures have already been ruled out.
/// Ported from run-lane.mjs L888-891 (opencode branch).
pub fn classify_opencode(facts: &StatusFacts) -> (LaneStatus, StatusClass) {
    let status = if facts.provider_refusal {
        LaneStatus::ProviderRefused
    } else if facts.truncated {
        LaneStatus::Truncated
    } else if facts.handoff && facts.exit_code == Some(0) {
        LaneStatus::Finished
    } else if facts.exit_code == Some(0) {
        LaneStatus::FinishedNoHandoff
    } else {
        LaneStatus::WorkerFailed
    };

    let status_class = match &status {
        LaneStatus::Finished => StatusClass::Finished,
        LaneStatus::ProviderRefused => StatusClass::Provider,
        LaneStatus::Truncated | LaneStatus::FinishedNoHandoff | LaneStatus::WorkerFailed => {
            StatusClass::Worker
        }
        _ => StatusClass::Runner,
    };

    (status, status_class)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timeout_precedence() {
        let facts = StatusFacts {
            timeout: true,
            violations: 5, // should be ignored due to timeout
            ..Default::default()
        };
        let (status, class) = classify_status(&facts);
        assert_eq!(status, LaneStatus::Timeout);
        assert_eq!(class, StatusClass::Runner);
    }

    #[test]
    fn test_violations_checked_before_lower_precedence() {
        let facts = StatusFacts {
            violations: 1,
            sandbox_denied: true, // should be ignored
            ..Default::default()
        };
        let (status, class) = classify_status(&facts);
        assert_eq!(status, LaneStatus::OutsideOwnership);
        assert_eq!(class, StatusClass::Runner);
    }

    #[test]
    fn test_finished_with_handoff() {
        let facts = StatusFacts {
            last_type: Some("turn.completed".into()),
            exit_code: Some(0),
            handoff: true,
            ..Default::default()
        };
        let (status, class) = classify_status(&facts);
        assert_eq!(status, LaneStatus::Finished);
        assert_eq!(class, StatusClass::Finished);
    }

    #[test]
    fn test_finished_no_handoff() {
        let facts = StatusFacts {
            last_type: Some("turn.completed".into()),
            exit_code: Some(0),
            handoff: false,
            ..Default::default()
        };
        let (status, class) = classify_status(&facts);
        assert_eq!(status, LaneStatus::FinishedNoHandoff);
        assert_eq!(class, StatusClass::Worker);
    }

    #[test]
    fn test_worker_stopped() {
        let facts = StatusFacts {
            exit_code: Some(0),
            ..Default::default()
        };
        let (status, class) = classify_status(&facts);
        assert_eq!(status, LaneStatus::WorkerStopped);
        assert_eq!(class, StatusClass::Worker);
    }

    #[test]
    fn test_worker_crashed_no_terminal_event() {
        let facts = StatusFacts {
            exit_code: Some(42),
            ..Default::default()
        };
        let (status, class) = classify_status(&facts);
        assert_eq!(status, LaneStatus::WorkerCrashed);
        assert_eq!(class, StatusClass::Worker);
    }

    #[test]
    fn test_worker_crashed_from_turn_completed() {
        let facts = StatusFacts {
            last_type: Some("turn.completed".into()),
            exit_code: Some(1),
            ..Default::default()
        };
        let (status, class) = classify_status(&facts);
        assert_eq!(status, LaneStatus::WorkerCrashed);
        assert_eq!(class, StatusClass::Worker);
    }

    #[test]
    fn test_worker_failed() {
        let facts = StatusFacts {
            last_type: Some("turn.failed".into()),
            ..Default::default()
        };
        let (status, class) = classify_status(&facts);
        assert_eq!(status, LaneStatus::WorkerFailed);
        assert_eq!(class, StatusClass::Worker);
    }
}
