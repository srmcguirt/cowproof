use crate::capsule::{Capsule, EnvironmentFingerprint};
use crate::runner::{CheckOutcome, CheckRunner, InfraError};
use crate::verify::{VerifyError, VerifyResult, verify};
use std::collections::HashMap;
use std::path::Path;
use tempfile::TempDir;

// ============================================================================
// Shape-only tests (preserved from original)
// ============================================================================

/// Test that a capsule can be written and read back with correct hash verification.
#[test]
fn test_capsule_roundtrip() {
    let temp_dir = TempDir::new().unwrap();

    let mut capsule = Capsule::new(
        "abc123".to_string(),
        "tree_hash_123".to_string(),
        EnvironmentFingerprint {
            os: "macOS".to_string(),
            arch: "arm64".to_string(),
            tools: HashMap::new(),
        },
        "claude:haiku".to_string(),
        "api-key".to_string(),
    );

    capsule.estimated_cost_usd = 0.42;
    capsule.estimated_tokens = 12345;

    capsule.write(temp_dir.path()).unwrap();

    let read_capsule = Capsule::read(temp_dir.path()).unwrap();

    assert_eq!(read_capsule.base_commit, "abc123");
    assert_eq!(read_capsule.base_tree_hash, "tree_hash_123");
    assert_eq!(read_capsule.estimated_cost_usd, 0.42);
    assert_eq!(read_capsule.estimated_tokens, 12345);
}

/// Test that editing a tracked file in the capsule causes hash mismatch on read.
#[test]
fn test_capsule_hash_mismatch_detected() {
    let temp_dir = TempDir::new().unwrap();

    let mut capsule = Capsule::new(
        "abc123".to_string(),
        "tree_hash_123".to_string(),
        EnvironmentFingerprint {
            os: "macOS".to_string(),
            arch: "arm64".to_string(),
            tools: HashMap::new(),
        },
        "claude:haiku".to_string(),
        "api-key".to_string(),
    );

    // Create a supplementary file and track its hash
    let test_file_path = temp_dir.path().join("test.txt");
    std::fs::write(&test_file_path, "original content").unwrap();
    let file_hash = Capsule::hash_file(&test_file_path).unwrap();
    capsule
        .file_hashes
        .insert("test.txt".to_string(), file_hash);

    capsule.write(temp_dir.path()).unwrap();

    // Corrupt the tracked file
    std::fs::write(&test_file_path, "corrupted content").unwrap();

    let result = Capsule::read(temp_dir.path());
    assert!(result.is_err());
    let error_msg = result.unwrap_err().to_string();
    assert!(error_msg.contains("Hash mismatch"));
}

/// Test that reading a capsule with missing files fails appropriately.
#[test]
fn test_capsule_missing_file_detected() {
    let temp_dir = TempDir::new().unwrap();

    let mut capsule = Capsule::new(
        "abc123".to_string(),
        "tree_hash_123".to_string(),
        EnvironmentFingerprint {
            os: "macOS".to_string(),
            arch: "arm64".to_string(),
            tools: HashMap::new(),
        },
        "claude:haiku".to_string(),
        "api-key".to_string(),
    );

    capsule.write(temp_dir.path()).unwrap();

    // Remove capsule.json
    std::fs::remove_file(temp_dir.path().join("capsule.json")).unwrap();

    let result = Capsule::read(temp_dir.path());
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Missing file"));
}

// ============================================================================
// End-to-end verify() tests
// ============================================================================

struct MockRunner {
    results: std::sync::Mutex<std::collections::HashMap<String, CheckOutcome>>,
    fail_with_infra: bool,
}

impl MockRunner {
    fn new() -> Self {
        Self {
            results: std::sync::Mutex::new(std::collections::HashMap::new()),
            fail_with_infra: false,
        }
    }

    fn set_result(&self, check_id: String, outcome: CheckOutcome) {
        self.results.lock().unwrap().insert(check_id, outcome);
    }
}

#[async_trait::async_trait]
impl CheckRunner for MockRunner {
    async fn run(&self, _tree: &Path, command: &str) -> Result<CheckOutcome, InfraError> {
        if self.fail_with_infra {
            return Err(InfraError::SpawnError("mock infra error".to_string()));
        }
        self.results
            .lock()
            .unwrap()
            .get(command)
            .cloned()
            .ok_or_else(|| InfraError::SpawnError("check not mocked".to_string()))
    }
}

/// Test: matching pass/fail for 2 checks → Reproduced
#[tokio::test]
async fn test_verify_matching_results_reproduced() {
    let capsule_dir = TempDir::new().unwrap();
    let workdir = TempDir::new().unwrap();

    // Create tree with test.txt
    std::fs::write(workdir.path().join("test.txt"), "content").unwrap();

    // Create empty patches
    std::fs::write(capsule_dir.path().join("launch.patch"), "").unwrap();
    std::fs::write(capsule_dir.path().join("lane.patch"), "").unwrap();

    // Create check results (both pass)
    std::fs::create_dir(capsule_dir.path().join("checks")).unwrap();
    for check_id in &["check1", "check2"] {
        let check_result = serde_json::json!({
            "command": "test -f test.txt",
            "exit_status": 0,
            "attempts": 1,
            "duration_ms": 10,
            "output_sha256": "hash"
        });
        std::fs::write(
            capsule_dir.path().join(format!("checks/{}.json", check_id)),
            serde_json::to_string(&check_result).unwrap(),
        )
        .unwrap();
    }

    // Create capsule
    let mut capsule = Capsule::new(
        "base_commit".to_string(),
        "tree_hash".to_string(),
        EnvironmentFingerprint {
            os: "Linux".to_string(),
            arch: "x86_64".to_string(),
            tools: HashMap::new(),
        },
        "claude:haiku".to_string(),
        "api-key".to_string(),
    );
    capsule.write(capsule_dir.path()).unwrap();

    // Set up runner to return passing results
    let runner = MockRunner::new();
    runner.set_result(
        "check1".to_string(),
        CheckOutcome {
            exit_status: 0,
            output: "pass".to_string(),
            attempts: 1,
        },
    );
    runner.set_result(
        "check2".to_string(),
        CheckOutcome {
            exit_status: 0,
            output: "pass".to_string(),
            attempts: 1,
        },
    );

    let result = verify(capsule_dir.path(), workdir.path(), &runner).await;
    assert!(result.is_ok());
    if let Ok(report) = result {
        assert!(matches!(report.result, VerifyResult::Reproduced));
    }
}

/// Test: one check recorded pass but fails on replay → Diverged
#[tokio::test]
async fn test_verify_diverged_check() {
    let capsule_dir = TempDir::new().unwrap();
    let workdir = TempDir::new().unwrap();

    // Create tree with test.txt
    std::fs::write(workdir.path().join("test.txt"), "content").unwrap();

    // Create empty patches
    std::fs::write(capsule_dir.path().join("launch.patch"), "").unwrap();
    std::fs::write(capsule_dir.path().join("lane.patch"), "").unwrap();

    // Create check result (recorded as pass)
    std::fs::create_dir(capsule_dir.path().join("checks")).unwrap();
    let check_result = serde_json::json!({
        "command": "test -f nonexistent.txt",
        "exit_status": 0,
        "attempts": 1,
        "duration_ms": 10,
        "output_sha256": "hash"
    });
    std::fs::write(
        capsule_dir.path().join("checks/check1.json"),
        serde_json::to_string(&check_result).unwrap(),
    )
    .unwrap();

    // Create capsule
    let mut capsule = Capsule::new(
        "base_commit".to_string(),
        "tree_hash".to_string(),
        EnvironmentFingerprint {
            os: "Linux".to_string(),
            arch: "x86_64".to_string(),
            tools: HashMap::new(),
        },
        "claude:haiku".to_string(),
        "api-key".to_string(),
    );
    capsule.write(capsule_dir.path()).unwrap();

    // Set up runner to fail (file doesn't exist)
    let runner = MockRunner::new();
    runner.set_result(
        "check1".to_string(),
        CheckOutcome {
            exit_status: 1,
            output: "fail".to_string(),
            attempts: 1,
        },
    );

    let result = verify(capsule_dir.path(), workdir.path(), &runner).await;
    assert!(result.is_ok());
    if let Ok(report) = result {
        if let VerifyResult::Diverged { check_ids } = report.result {
            assert_eq!(check_ids, vec!["check1"]);
        } else {
            panic!("Expected Diverged");
        }
    }
}

/// Test: flaky check fails twice then passes on attempt 3 → counts as pass → Reproduced
#[tokio::test]
async fn test_verify_flaky_retry_succeeds() {
    let capsule_dir = TempDir::new().unwrap();
    let workdir = TempDir::new().unwrap();

    // Empty patches
    std::fs::write(capsule_dir.path().join("launch.patch"), "").unwrap();
    std::fs::write(capsule_dir.path().join("lane.patch"), "").unwrap();

    // Create check result
    std::fs::create_dir(capsule_dir.path().join("checks")).unwrap();
    let check_result = serde_json::json!({
        "command": "flaky_check",
        "exit_status": 0,
        "attempts": 3,
        "duration_ms": 10,
        "output_sha256": "hash"
    });
    std::fs::write(
        capsule_dir.path().join("checks/flaky_check.json"),
        serde_json::to_string(&check_result).unwrap(),
    )
    .unwrap();

    // Create capsule with flaky_check marked as flaky
    let mut capsule = Capsule::new(
        "base_commit".to_string(),
        "tree_hash".to_string(),
        EnvironmentFingerprint {
            os: "Linux".to_string(),
            arch: "x86_64".to_string(),
            tools: HashMap::new(),
        },
        "claude:haiku".to_string(),
        "api-key".to_string(),
    );
    capsule.flaky_checks.insert("flaky_check".to_string());
    capsule.write(capsule_dir.path()).unwrap();

    // Runner that fails twice then passes
    struct FlakyRunner(std::sync::Mutex<u32>);

    #[async_trait::async_trait]
    impl CheckRunner for FlakyRunner {
        async fn run(&self, _tree: &Path, _command: &str) -> Result<CheckOutcome, InfraError> {
            let mut att = self.0.lock().unwrap();
            *att += 1;
            if *att < 3 {
                Ok(CheckOutcome {
                    exit_status: 1,
                    output: "failed".to_string(),
                    attempts: *att,
                })
            } else {
                Ok(CheckOutcome {
                    exit_status: 0,
                    output: "passed".to_string(),
                    attempts: *att,
                })
            }
        }
    }

    let runner = FlakyRunner(std::sync::Mutex::new(0));
    let result = verify(capsule_dir.path(), workdir.path(), &runner).await;

    assert!(result.is_ok());
    if let Ok(report) = result {
        assert!(matches!(report.result, VerifyResult::Reproduced));
    }
}

/// Test: non-flaky check failing once → Diverged
#[tokio::test]
async fn test_verify_non_flaky_fails_diverged() {
    let capsule_dir = TempDir::new().unwrap();
    let workdir = TempDir::new().unwrap();

    // Empty patches
    std::fs::write(capsule_dir.path().join("launch.patch"), "").unwrap();
    std::fs::write(capsule_dir.path().join("lane.patch"), "").unwrap();

    // Create check result (recorded as pass)
    std::fs::create_dir(capsule_dir.path().join("checks")).unwrap();
    let check_result = serde_json::json!({
        "command": "check1",
        "exit_status": 0,
        "attempts": 1,
        "duration_ms": 10,
        "output_sha256": "hash"
    });
    std::fs::write(
        capsule_dir.path().join("checks/check1.json"),
        serde_json::to_string(&check_result).unwrap(),
    )
    .unwrap();

    // Create capsule (NOT marked as flaky)
    let mut capsule = Capsule::new(
        "base_commit".to_string(),
        "tree_hash".to_string(),
        EnvironmentFingerprint {
            os: "Linux".to_string(),
            arch: "x86_64".to_string(),
            tools: HashMap::new(),
        },
        "claude:haiku".to_string(),
        "api-key".to_string(),
    );
    capsule.write(capsule_dir.path()).unwrap();

    // Runner that fails
    let runner = MockRunner::new();
    runner.set_result(
        "check1".to_string(),
        CheckOutcome {
            exit_status: 1,
            output: "failed".to_string(),
            attempts: 1,
        },
    );

    let result = verify(capsule_dir.path(), workdir.path(), &runner).await;
    assert!(result.is_ok());
    if let Ok(report) = result {
        if let VerifyResult::Diverged { check_ids } = report.result {
            assert_eq!(check_ids, vec!["check1"]);
        } else {
            panic!("Expected Diverged");
        }
    }
}

/// Test: runner returns InfraError → VerifyError::Infrastructure
#[tokio::test]
async fn test_verify_runner_infra_error() {
    let capsule_dir = TempDir::new().unwrap();
    let workdir = TempDir::new().unwrap();

    // Empty patches
    std::fs::write(capsule_dir.path().join("launch.patch"), "").unwrap();
    std::fs::write(capsule_dir.path().join("lane.patch"), "").unwrap();

    // Create check result
    std::fs::create_dir(capsule_dir.path().join("checks")).unwrap();
    let check_result = serde_json::json!({
        "command": "check1",
        "exit_status": 0,
        "attempts": 1,
        "duration_ms": 10,
        "output_sha256": "hash"
    });
    std::fs::write(
        capsule_dir.path().join("checks/check1.json"),
        serde_json::to_string(&check_result).unwrap(),
    )
    .unwrap();

    // Create capsule
    let mut capsule = Capsule::new(
        "base_commit".to_string(),
        "tree_hash".to_string(),
        EnvironmentFingerprint {
            os: "Linux".to_string(),
            arch: "x86_64".to_string(),
            tools: HashMap::new(),
        },
        "claude:haiku".to_string(),
        "api-key".to_string(),
    );
    capsule.write(capsule_dir.path()).unwrap();

    // Runner that returns infra error
    let runner = MockRunner::new();
    runner.results.lock().unwrap().clear(); // no results, will cause infra error
    let result = verify(capsule_dir.path(), workdir.path(), &runner).await;

    assert!(result.is_err());
    assert!(matches!(result, Err(VerifyError::Infrastructure(_))));
}

/// Test: unsandboxed capsule → never reported as proved
#[tokio::test]
async fn test_verify_unsandboxed_not_proved() {
    let capsule_dir = TempDir::new().unwrap();
    let workdir = TempDir::new().unwrap();

    let mut capsule = Capsule::new(
        "abc123".to_string(),
        "tree_hash".to_string(),
        EnvironmentFingerprint {
            os: "Linux".to_string(),
            arch: "x86_64".to_string(),
            tools: HashMap::new(),
        },
        "claude:haiku".to_string(),
        "api-key".to_string(),
    );

    capsule.unsandboxed = true;
    capsule.write(capsule_dir.path()).unwrap();

    let runner = MockRunner::new();
    let result = verify(capsule_dir.path(), workdir.path(), &runner).await;

    assert!(result.is_err());
    assert!(matches!(result, Err(VerifyError::UnsandboxedNotProved)));
}
