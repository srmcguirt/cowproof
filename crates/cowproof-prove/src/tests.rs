use crate::capsule::{Capsule, CapsuleError, CheckResult, EnvironmentFingerprint};
use crate::runner::{
    CheckOutcome, CheckRunner, InfraError, ProcessRunner, SandboxFixture, sandbox_available,
};
use crate::verify::{VerifyError, VerifyOptions, VerifyResult, verify};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
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
// End-to-end verify() tests. Every test builds a real git repo, authors real
// patches, writes a real capsule and calls verify(), which always clones the
// source repo at the base commit and applies base, launch, lane in order.
// ============================================================================

/// A real git repository in a temp dir, used both to author patches and as the
/// source repo that verify() clones.
struct Repo {
    dir: TempDir,
}

impl Repo {
    fn new() -> Self {
        let repo = Self {
            dir: TempDir::new().unwrap(),
        };
        repo.git(&["init", "--quiet"]);
        repo
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    fn git(&self, args: &[&str]) -> String {
        let output = Command::new("git")
            .arg("-C")
            .arg(self.path())
            .args(["-c", "commit.gpgsign=false"])
            .args(args)
            .env("GIT_AUTHOR_NAME", "tester")
            .env("GIT_AUTHOR_EMAIL", "tester")
            .env("GIT_COMMITTER_NAME", "tester")
            .env("GIT_COMMITTER_EMAIL", "tester")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap()
    }

    /// Apply edits (`None` deletes the file), commit them, and return the diff they made.
    fn change(&self, edits: &[(&str, Option<&str>)]) -> String {
        for (name, content) in edits {
            let path = self.path().join(name);
            match content {
                Some(c) => std::fs::write(path, c).unwrap(),
                None => std::fs::remove_file(path).unwrap(),
            }
        }
        self.git(&["add", "-A"]);
        let patch = self.git(&["diff", "--cached"]);
        assert!(!patch.is_empty(), "edits produced no diff");
        self.git(&["commit", "--quiet", "-m", "step"]);
        patch
    }

    /// Commit the current contents as the base; return (commit, tree hash).
    fn base(&self, files: &[(&str, &str)]) -> (String, String) {
        for (name, content) in files {
            std::fs::write(self.path().join(name), content).unwrap();
        }
        self.git(&["add", "-A"]);
        self.git(&["commit", "--quiet", "-m", "base"]);
        (
            self.git(&["rev-parse", "HEAD"]).trim().to_string(),
            self.git(&["rev-parse", "HEAD^{tree}"]).trim().to_string(),
        )
    }
}

fn fingerprint() -> EnvironmentFingerprint {
    EnvironmentFingerprint {
        os: "Linux".to_string(),
        arch: "x86_64".to_string(),
        tools: HashMap::new(),
    }
}

/// One recorded check: id, command, recorded exit status.
type Recorded<'a> = (&'a str, &'a str, i32);

struct CapsuleSpec<'a> {
    base: &'a (String, String),
    /// (file name, content), for base.patch / launch.patch / lane.patch.
    patches: &'a [(&'a str, &'a str)],
    checks: &'a [Recorded<'a>],
    flaky: &'a [&'a str],
    unsandboxed: bool,
}

fn write_capsule(dir: &Path, spec: &CapsuleSpec) {
    for (name, content) in spec.patches {
        std::fs::write(dir.join(name), content).unwrap();
    }
    std::fs::create_dir_all(dir.join("checks")).unwrap();
    for (id, command, exit_status) in spec.checks {
        let result = CheckResult {
            command: (*command).to_string(),
            exit_status: *exit_status,
            attempts: 1,
            duration_ms: 1,
            output_sha256: "ignored".to_string(),
        };
        std::fs::write(
            dir.join(format!("checks/{id}.json")),
            serde_json::to_string(&result).unwrap(),
        )
        .unwrap();
    }
    let mut capsule = Capsule::new(
        spec.base.0.clone(),
        spec.base.1.clone(),
        fingerprint(),
        "claude:haiku".to_string(),
        "api-key".to_string(),
    );
    capsule.flaky_checks = spec
        .flaky
        .iter()
        .map(|s| (*s).to_string())
        .collect::<HashSet<_>>();
    capsule.unsandboxed = spec.unsandboxed;
    capsule.write(dir).unwrap();
}

/// Runner that returns scripted exit statuses per command and records every call.
struct ScriptedRunner {
    script: Mutex<HashMap<String, VecDeque<i32>>>,
    calls: Mutex<Vec<String>>,
    infra_failure: bool,
}

impl ScriptedRunner {
    fn new(script: &[(&str, &[i32])]) -> Self {
        Self {
            script: Mutex::new(
                script
                    .iter()
                    .map(|(c, s)| ((*c).to_string(), s.iter().copied().collect()))
                    .collect(),
            ),
            calls: Mutex::new(Vec::new()),
            infra_failure: false,
        }
    }

    fn failing_infra() -> Self {
        Self {
            infra_failure: true,
            ..Self::new(&[])
        }
    }

    fn call_count(&self) -> usize {
        self.calls.lock().unwrap().len()
    }
}

#[async_trait::async_trait]
impl CheckRunner for ScriptedRunner {
    async fn run(
        &self,
        _tree: &Path,
        command: &str,
        _timeout: Duration,
    ) -> Result<CheckOutcome, InfraError> {
        self.calls.lock().unwrap().push(command.to_string());
        if self.infra_failure {
            return Err(InfraError::SpawnError("scripted infra failure".to_string()));
        }
        let status = self
            .script
            .lock()
            .unwrap()
            .get_mut(command)
            .and_then(VecDeque::pop_front)
            .ok_or_else(|| InfraError::SpawnError(format!("nothing scripted for {command}")))?;
        Ok(CheckOutcome {
            exit_status: status,
            output: String::new(),
            attempts: 1,
        })
    }
}

/// The three-patch chain shared by the order tests. Each patch only applies on top of
/// the one before it: launch.patch rewrites `line=base` and deletes `.env`; lane.patch
/// rewrites the line launch.patch produced.
struct Chain {
    repo: Repo,
    base: (String, String),
    launch: String,
    lane: String,
}

fn chain() -> Chain {
    let repo = Repo::new();
    let base = repo.base(&[(".env", "SECRET=1\n"), ("src.txt", "line=base\n")]);
    let launch = repo.change(&[(".env", None), ("src.txt", Some("line=launch\n"))]);
    let lane = repo.change(&[("src.txt", Some("line=edited\n"))]);
    Chain {
        repo,
        base,
        launch,
        lane,
    }
}

fn dirs() -> (TempDir, TempDir) {
    (TempDir::new().unwrap(), TempDir::new().unwrap())
}

/// Options whose slots live under the test's own work dir, so tests never share the
/// machine-wide slots with each other or with real lanes.
fn test_opts(work: &Path) -> VerifyOptions {
    VerifyOptions {
        slot_dir: work.join(".slots"),
        slot_class: "rust".to_string(),
        slot_limit: 2,
        default_timeout: Duration::from_secs(60),
    }
}

/// 1. Order: launch.patch (deletes .env, rewrites src.txt) then lane.patch (edits the
/// rewritten line), checked by a real process on the rebuilt tree.
#[tokio::test]
async fn test_replay_order_launch_then_lane_reproduces() {
    let c = chain();
    let (capsule_dir, work) = dirs();
    write_capsule(
        capsule_dir.path(),
        &CapsuleSpec {
            base: &c.base,
            patches: &[("launch.patch", &c.launch), ("lane.patch", &c.lane)],
            checks: &[("order", "test ! -f .env && grep -q edited src.txt", 0)],
            flaky: &[],
            unsandboxed: false,
        },
    );

    let report = verify(
        capsule_dir.path(),
        c.repo.path(),
        work.path(),
        &ProcessRunner::new(),
        test_opts(work.path()),
    )
    .await
    .unwrap();

    assert!(
        matches!(report.result, VerifyResult::Reproduced),
        "{report:?}"
    );
    assert_eq!(report.checks.len(), 1);
    assert!(report.checks[0].passed);
}

/// 2a. An EMPTY launch.patch leaves lane.patch without its context: infrastructure
/// error naming lane.patch, never a divergence, and no check runs.
#[tokio::test]
async fn test_empty_launch_patch_makes_lane_patch_fail_as_infrastructure() {
    let c = chain();
    let (capsule_dir, work) = dirs();
    write_capsule(
        capsule_dir.path(),
        &CapsuleSpec {
            base: &c.base,
            patches: &[("launch.patch", ""), ("lane.patch", &c.lane)],
            checks: &[("order", "true", 0)],
            flaky: &[],
            unsandboxed: false,
        },
    );
    let runner = ScriptedRunner::new(&[("true", &[0])]);

    match verify(
        capsule_dir.path(),
        c.repo.path(),
        work.path(),
        &runner,
        test_opts(work.path()),
    )
    .await
    {
        Err(VerifyError::Infrastructure(msg)) => {
            assert!(msg.contains("lane.patch"), "should name lane.patch: {msg}")
        }
        other => panic!("expected Infrastructure, got {other:?}"),
    }
    assert_eq!(runner.call_count(), 0);
}

/// 2b. A capsule with no launch.patch at all behaves the same.
#[tokio::test]
async fn test_missing_launch_patch_makes_lane_patch_fail_as_infrastructure() {
    let c = chain();
    let (capsule_dir, work) = dirs();
    write_capsule(
        capsule_dir.path(),
        &CapsuleSpec {
            base: &c.base,
            patches: &[("lane.patch", &c.lane)],
            checks: &[("order", "true", 0)],
            flaky: &[],
            unsandboxed: false,
        },
    );
    let runner = ScriptedRunner::new(&[("true", &[0])]);

    match verify(
        capsule_dir.path(),
        c.repo.path(),
        work.path(),
        &runner,
        test_opts(work.path()),
    )
    .await
    {
        Err(VerifyError::Infrastructure(msg)) => {
            assert!(msg.contains("lane.patch"), "should name lane.patch: {msg}")
        }
        other => panic!("expected Infrastructure, got {other:?}"),
    }
    assert_eq!(runner.call_count(), 0);
}

/// 3. base.patch (dirty base) is applied before launch.patch, which only applies on
/// top of it; lane.patch then adds a file.
#[tokio::test]
async fn test_base_patch_applied_before_launch_patch() {
    let repo = Repo::new();
    let base = repo.base(&[(".env", "SECRET=1\n"), ("src.txt", "line=base\n")]);
    let base_patch = repo.change(&[("src.txt", Some("line=dirty\n"))]);
    let launch = repo.change(&[(".env", None), ("src.txt", Some("line=launched\n"))]);
    let lane = repo.change(&[("lane.txt", Some("new\n"))]);

    let (capsule_dir, work) = dirs();
    write_capsule(
        capsule_dir.path(),
        &CapsuleSpec {
            base: &base,
            patches: &[
                ("base.patch", &base_patch),
                ("launch.patch", &launch),
                ("lane.patch", &lane),
            ],
            checks: &[(
                "chain",
                "grep -q launched src.txt && test -f lane.txt && test ! -f .env",
                0,
            )],
            flaky: &[],
            unsandboxed: false,
        },
    );

    let report = verify(
        capsule_dir.path(),
        repo.path(),
        work.path(),
        &ProcessRunner::new(),
        test_opts(work.path()),
    )
    .await
    .unwrap();
    assert!(
        matches!(report.result, VerifyResult::Reproduced),
        "{report:?}"
    );

    // Without base.patch, launch.patch has no context: infrastructure naming it.
    let (capsule_dir2, work2) = dirs();
    write_capsule(
        capsule_dir2.path(),
        &CapsuleSpec {
            base: &base,
            patches: &[("launch.patch", &launch), ("lane.patch", &lane)],
            checks: &[("chain", "true", 0)],
            flaky: &[],
            unsandboxed: false,
        },
    );
    match verify(
        capsule_dir2.path(),
        repo.path(),
        work2.path(),
        &ProcessRunner::new(),
        test_opts(work2.path()),
    )
    .await
    {
        Err(VerifyError::Infrastructure(msg)) => assert!(msg.contains("launch.patch"), "{msg}"),
        other => panic!("expected Infrastructure, got {other:?}"),
    }
}

/// 4a. Two checks, one recorded pass and one recorded fail, both repeat: Reproduced.
#[tokio::test]
async fn test_matching_pass_and_fail_reproduced() {
    let c = chain();
    let (capsule_dir, work) = dirs();
    write_capsule(
        capsule_dir.path(),
        &CapsuleSpec {
            base: &c.base,
            patches: &[("launch.patch", &c.launch), ("lane.patch", &c.lane)],
            checks: &[("passes", "true", 0), ("fails", "false", 1)],
            flaky: &[],
            unsandboxed: false,
        },
    );

    let report = verify(
        capsule_dir.path(),
        c.repo.path(),
        work.path(),
        &ProcessRunner::new(),
        test_opts(work.path()),
    )
    .await
    .unwrap();

    assert!(
        matches!(report.result, VerifyResult::Reproduced),
        "{report:?}"
    );
    assert_eq!(report.checks.len(), 2);
    assert!(report.checks.iter().all(|m| m.matched_capsule));
}

/// 4b. A recorded pass that fails on replay diverges, naming exactly that check id.
#[tokio::test]
async fn test_recorded_pass_failing_on_replay_diverges() {
    let c = chain();
    let (capsule_dir, work) = dirs();
    write_capsule(
        capsule_dir.path(),
        &CapsuleSpec {
            base: &c.base,
            patches: &[("launch.patch", &c.launch), ("lane.patch", &c.lane)],
            checks: &[("steady", "true", 0), ("liar", "false", 0)],
            flaky: &[],
            unsandboxed: false,
        },
    );

    let report = verify(
        capsule_dir.path(),
        c.repo.path(),
        work.path(),
        &ProcessRunner::new(),
        test_opts(work.path()),
    )
    .await
    .unwrap();

    match report.result {
        VerifyResult::Diverged { check_ids } => assert_eq!(check_ids, vec!["liar".to_string()]),
        other => panic!("expected Diverged, got {other:?}"),
    }
}

/// 5a. A flaky check that fails twice then passes on attempt 3 reproduces.
#[tokio::test]
async fn test_flaky_check_passing_on_third_attempt_reproduced() {
    let c = chain();
    let (capsule_dir, work) = dirs();
    write_capsule(
        capsule_dir.path(),
        &CapsuleSpec {
            base: &c.base,
            patches: &[("launch.patch", &c.launch), ("lane.patch", &c.lane)],
            checks: &[("wobbly", "wobbly-cmd", 0)],
            flaky: &["wobbly"],
            unsandboxed: false,
        },
    );
    let runner = ScriptedRunner::new(&[("wobbly-cmd", &[1, 1, 0])]);

    let report = verify(
        capsule_dir.path(),
        c.repo.path(),
        work.path(),
        &runner,
        test_opts(work.path()),
    )
    .await
    .unwrap();

    assert!(
        matches!(report.result, VerifyResult::Reproduced),
        "{report:?}"
    );
    assert_eq!(runner.call_count(), 3);
}

/// 5b. The same script on a check NOT marked flaky fails once and diverges.
#[tokio::test]
async fn test_non_flaky_check_failing_once_diverges() {
    let c = chain();
    let (capsule_dir, work) = dirs();
    write_capsule(
        capsule_dir.path(),
        &CapsuleSpec {
            base: &c.base,
            patches: &[("launch.patch", &c.launch), ("lane.patch", &c.lane)],
            checks: &[("steady", "steady-cmd", 0)],
            flaky: &[],
            unsandboxed: false,
        },
    );
    let runner = ScriptedRunner::new(&[("steady-cmd", &[1, 0, 0])]);

    let report = verify(
        capsule_dir.path(),
        c.repo.path(),
        work.path(),
        &runner,
        test_opts(work.path()),
    )
    .await
    .unwrap();

    match report.result {
        VerifyResult::Diverged { check_ids } => assert_eq!(check_ids, vec!["steady".to_string()]),
        other => panic!("expected Diverged, got {other:?}"),
    }
    assert_eq!(runner.call_count(), 1);
}

/// 6. A runner infrastructure error is Infrastructure, never Diverged.
#[tokio::test]
async fn test_runner_infra_error_is_infrastructure_not_divergence() {
    let c = chain();
    let (capsule_dir, work) = dirs();
    write_capsule(
        capsule_dir.path(),
        &CapsuleSpec {
            base: &c.base,
            patches: &[("launch.patch", &c.launch), ("lane.patch", &c.lane)],
            checks: &[("any", "any-cmd", 0)],
            flaky: &[],
            unsandboxed: false,
        },
    );
    let runner = ScriptedRunner::failing_infra();

    match verify(
        capsule_dir.path(),
        c.repo.path(),
        work.path(),
        &runner,
        test_opts(work.path()),
    )
    .await
    {
        Err(VerifyError::Infrastructure(msg)) => {
            assert!(msg.contains("scripted infra failure"), "{msg}")
        }
        other => panic!("expected Infrastructure, got {other:?}"),
    }
}

/// 7. An unsandboxed capsule is never proved: no tree is built and no check runs.
#[tokio::test]
async fn test_unsandboxed_capsule_never_proved() {
    let c = chain();
    let (capsule_dir, work) = dirs();
    write_capsule(
        capsule_dir.path(),
        &CapsuleSpec {
            base: &c.base,
            patches: &[("launch.patch", &c.launch), ("lane.patch", &c.lane)],
            checks: &[("any", "true", 0)],
            flaky: &[],
            unsandboxed: true,
        },
    );
    let runner = ScriptedRunner::new(&[("true", &[0])]);

    let result = verify(
        capsule_dir.path(),
        c.repo.path(),
        work.path(),
        &runner,
        test_opts(work.path()),
    )
    .await;

    assert!(
        matches!(result, Err(VerifyError::UnsandboxedNotProved)),
        "{result:?}"
    );
    assert_eq!(runner.call_count(), 0);
    assert!(!work.path().join("tree").exists());
}

/// 8. A lane.patch altered after the capsule was written fails Capsule::read, and so
/// verify, before any tree is built or check run.
#[tokio::test]
async fn test_tampered_lane_patch_rejected_before_anything_runs() {
    let c = chain();
    let (capsule_dir, work) = dirs();
    write_capsule(
        capsule_dir.path(),
        &CapsuleSpec {
            base: &c.base,
            patches: &[("launch.patch", &c.launch), ("lane.patch", &c.lane)],
            checks: &[("any", "true", 0)],
            flaky: &[],
            unsandboxed: false,
        },
    );
    let tampered = c.lane.replace("line=edited", "line=EVIL");
    assert_ne!(tampered, c.lane);
    std::fs::write(capsule_dir.path().join("lane.patch"), tampered).unwrap();

    match Capsule::read(capsule_dir.path()) {
        Err(CapsuleError::HashMismatch(file, _, _)) => assert_eq!(file, "lane.patch"),
        other => panic!("expected HashMismatch, got {other:?}"),
    }

    let runner = ScriptedRunner::new(&[("true", &[0])]);
    match verify(
        capsule_dir.path(),
        c.repo.path(),
        work.path(),
        &runner,
        test_opts(work.path()),
    )
    .await
    {
        Err(VerifyError::Capsule(CapsuleError::HashMismatch(file, _, _))) => {
            assert_eq!(file, "lane.patch")
        }
        other => panic!("expected Capsule(HashMismatch), got {other:?}"),
    }
    assert_eq!(runner.call_count(), 0);
    assert!(!work.path().join("tree").exists());
}

/// 9. A capsule whose recorded base tree hash does not match the base commit is an
/// infrastructure error: the rebuilt tree is not the tree the capsule describes.
#[tokio::test]
async fn test_base_tree_hash_mismatch_is_infrastructure() {
    let c = chain();
    let (capsule_dir, work) = dirs();
    let wrong_base = (c.base.0.clone(), "0".repeat(40));
    write_capsule(
        capsule_dir.path(),
        &CapsuleSpec {
            base: &wrong_base,
            patches: &[("launch.patch", &c.launch), ("lane.patch", &c.lane)],
            checks: &[("any", "true", 0)],
            flaky: &[],
            unsandboxed: false,
        },
    );
    let runner = ScriptedRunner::new(&[("true", &[0])]);

    match verify(
        capsule_dir.path(),
        c.repo.path(),
        work.path(),
        &runner,
        test_opts(work.path()),
    )
    .await
    {
        Err(VerifyError::Infrastructure(msg)) => assert!(msg.contains("tree hash"), "{msg}"),
        other => panic!("expected Infrastructure, got {other:?}"),
    }
    assert_eq!(runner.call_count(), 0);
}

/// 10. verify never reuses an existing tree: a pre-built `workdir/tree` is refused,
/// not trusted.
#[tokio::test]
async fn test_existing_tree_is_refused_not_reused() {
    let c = chain();
    let (capsule_dir, work) = dirs();
    write_capsule(
        capsule_dir.path(),
        &CapsuleSpec {
            base: &c.base,
            patches: &[("launch.patch", &c.launch), ("lane.patch", &c.lane)],
            checks: &[("any", "true", 0)],
            flaky: &[],
            unsandboxed: false,
        },
    );
    let prebuilt: PathBuf = work.path().join("tree");
    std::fs::create_dir_all(&prebuilt).unwrap();
    let runner = ScriptedRunner::new(&[("true", &[0])]);

    match verify(
        capsule_dir.path(),
        c.repo.path(),
        work.path(),
        &runner,
        test_opts(work.path()),
    )
    .await
    {
        Err(VerifyError::Infrastructure(msg)) => assert!(msg.contains("existing tree"), "{msg}"),
        other => panic!("expected Infrastructure, got {other:?}"),
    }
    assert_eq!(runner.call_count(), 0);
}

// ============================================================================
// End-to-end with the production runner (D6): real repo, real capsule, real
// sandbox. The tree verify() rebuilds is the sandbox's writable clone.
// ============================================================================

/// A base with `README`, an EMPTY launch.patch, and a lane.patch (made by `git diff`)
/// that adds `file_name`.
fn adding_lane(file_name: &str) -> (Repo, (String, String), String) {
    let repo = Repo::new();
    let base = repo.base(&[("README", "base\n")]);
    let lane = repo.change(&[(file_name, Some("content\n"))]);
    (repo, base, lane)
}

/// 1. The recorded check `test -f newfile` passed, and replaying base + empty
/// launch.patch + lane.patch under the sandbox passes it again: Reproduced. A second
/// recorded check proves the verifier really is sandboxed: reading the real home must
/// fail, which `! cat` records as a pass, so an unsandboxed runner would diverge.
#[tokio::test]
async fn test_sandboxed_verify_reproduces_a_recorded_pass() {
    if !sandbox_available() {
        return;
    }
    let (repo, base, lane) = adding_lane("newfile");
    let fx = SandboxFixture::new();
    let secret = fx.root.join("realhome/credential");
    std::fs::write(&secret, "SECRET_CREDENTIAL").unwrap();
    let hidden = format!("! cat {}", secret.display());
    let (capsule_dir, work) = dirs();
    write_capsule(
        capsule_dir.path(),
        &CapsuleSpec {
            base: &base,
            patches: &[("launch.patch", ""), ("lane.patch", &lane)],
            checks: &[
                ("adds-newfile", "test -f newfile", 0),
                ("home-hidden", &hidden, 0),
            ],
            flaky: &[],
            unsandboxed: false,
        },
    );

    let report = verify(
        capsule_dir.path(),
        repo.path(),
        work.path(),
        &fx.runner(),
        test_opts(work.path()),
    )
    .await
    .unwrap();

    assert!(
        matches!(report.result, VerifyResult::Reproduced),
        "{report:?}"
    );
    assert_eq!(report.checks.len(), 2);
    assert!(report.checks.iter().all(|c| c.passed && c.matched_capsule));
    // The replayed tree is the one the checks ran in.
    assert!(work.path().join("tree/newfile").is_file());
}

/// 2. The recorded check passed (`test -f newfile`) but the replayed tree lacks the
/// file, because the lane.patch adds a different one: Diverged, naming that check, with
/// the actual status 1 from the sandboxed run.
#[tokio::test]
async fn test_sandboxed_verify_diverges_when_the_replayed_tree_lacks_the_file() {
    if !sandbox_available() {
        return;
    }
    let (repo, base, lane) = adding_lane("other");
    let fx = SandboxFixture::new();
    let (capsule_dir, work) = dirs();
    write_capsule(
        capsule_dir.path(),
        &CapsuleSpec {
            base: &base,
            patches: &[("launch.patch", ""), ("lane.patch", &lane)],
            checks: &[("adds-newfile", "test -f newfile", 0)],
            flaky: &[],
            unsandboxed: false,
        },
    );

    let report = verify(
        capsule_dir.path(),
        repo.path(),
        work.path(),
        &fx.runner(),
        test_opts(work.path()),
    )
    .await
    .unwrap();

    match &report.result {
        VerifyResult::Diverged { check_ids } => {
            assert_eq!(check_ids, &vec!["adds-newfile".to_string()])
        }
        other => panic!("expected Diverged, got {other:?}"),
    }
    assert_eq!(report.checks[0].capsule_exit_status, 0);
    assert_eq!(report.checks[0].actual_exit_status, 1);
    assert!(!report.checks[0].passed);
    assert!(work.path().join("tree/other").is_file());
    assert!(!work.path().join("tree/newfile").exists());
}

// ============================================================================
// Class slot (D12) and per-check timeout
// ============================================================================

/// Runner whose one check takes 600 ms and which records how many checks are inside
/// `run` at once.
struct SlowRunner {
    inside: AtomicUsize,
    max_inside: AtomicUsize,
}

#[async_trait::async_trait]
impl CheckRunner for SlowRunner {
    async fn run(
        &self,
        _tree: &Path,
        _command: &str,
        _timeout: Duration,
    ) -> Result<CheckOutcome, InfraError> {
        let now = self.inside.fetch_add(1, Ordering::SeqCst) + 1;
        self.max_inside.fetch_max(now, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(600)).await;
        self.inside.fetch_sub(1, Ordering::SeqCst);
        Ok(CheckOutcome {
            exit_status: 0,
            output: String::new(),
            attempts: 1,
        })
    }
}

/// A capsule over the shared chain whose one recorded check is `true` (passed).
fn passing_capsule(c: &Chain) -> TempDir {
    let capsule_dir = TempDir::new().unwrap();
    write_capsule(
        capsule_dir.path(),
        &CapsuleSpec {
            base: &c.base,
            patches: &[("launch.patch", &c.launch), ("lane.patch", &c.lane)],
            checks: &[("slow", "true", 0)],
            flaky: &[],
            unsandboxed: false,
        },
    );
    capsule_dir
}

/// With a class of capacity 2, three concurrent verifications (one task, so a verify
/// that blocked the executor while waiting for a slot would deadlock the test) never
/// have more than two checks running, and all three finish.
#[tokio::test]
async fn test_class_slot_caps_concurrent_verifications() {
    let c = chain();
    let capsule_dir = passing_capsule(&c);
    let slots = TempDir::new().unwrap();
    let works = [
        TempDir::new().unwrap(),
        TempDir::new().unwrap(),
        TempDir::new().unwrap(),
    ];
    let runner = SlowRunner {
        inside: AtomicUsize::new(0),
        max_inside: AtomicUsize::new(0),
    };
    let opts = || VerifyOptions {
        slot_dir: slots.path().to_path_buf(),
        slot_class: "rust".to_string(),
        slot_limit: 2,
        default_timeout: Duration::from_secs(60),
    };

    let (a, b, d) = tokio::join!(
        verify(
            capsule_dir.path(),
            c.repo.path(),
            works[0].path(),
            &runner,
            opts()
        ),
        verify(
            capsule_dir.path(),
            c.repo.path(),
            works[1].path(),
            &runner,
            opts()
        ),
        verify(
            capsule_dir.path(),
            c.repo.path(),
            works[2].path(),
            &runner,
            opts()
        ),
    );

    for report in [a.unwrap(), b.unwrap(), d.unwrap()] {
        assert!(
            matches!(report.result, VerifyResult::Reproduced),
            "{report:?}"
        );
    }
    assert_eq!(
        runner.max_inside.load(Ordering::SeqCst),
        2,
        "capacity 2 allows two checks at once and never three"
    );
    // Every slot was released.
    for n in 0..2 {
        assert!(!slots.path().join(format!("rust-{n}")).exists());
    }
}

/// A check that overruns `default_timeout` is an infrastructure error naming the
/// check's id (never a divergence), the slot is released, and the whole group was
/// killed.
#[tokio::test]
async fn test_check_timeout_is_infrastructure_naming_the_check_and_frees_the_slot() {
    let c = chain();
    let (capsule_dir, work) = dirs();
    write_capsule(
        capsule_dir.path(),
        &CapsuleSpec {
            base: &c.base,
            patches: &[("launch.patch", &c.launch), ("lane.patch", &c.lane)],
            checks: &[("hangs", "sleep 30 & echo $! > ../bg.pid; wait", 0)],
            flaky: &[],
            unsandboxed: false,
        },
    );
    let mut opts = test_opts(work.path());
    opts.slot_limit = 1;
    opts.default_timeout = Duration::from_millis(500);
    let slot_dir = opts.slot_dir.clone();

    let started = std::time::Instant::now();
    let result = verify(
        capsule_dir.path(),
        c.repo.path(),
        work.path(),
        &ProcessRunner::new(),
        opts,
    )
    .await;

    match result {
        Err(VerifyError::Infrastructure(msg)) => {
            assert!(msg.contains("check hangs"), "must name the check id: {msg}");
            assert!(msg.contains("Timeout"), "{msg}");
        }
        other => panic!("expected Infrastructure, got {other:?}"),
    }
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "{:?}",
        started.elapsed()
    );
    let pid: libc::pid_t = std::fs::read_to_string(work.path().join("bg.pid"))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    crate::runner::tests::assert_process_gone(pid);
    assert!(
        cowproof_core::try_acquire_slot("rust", 1, &slot_dir)
            .unwrap()
            .is_some(),
        "the timed-out verify still holds its slot"
    );
}

/// The slot is also released when the verifier fails before running any check.
#[tokio::test]
async fn test_slot_is_released_when_verification_errors() {
    let c = chain();
    let (capsule_dir, work) = dirs();
    write_capsule(
        capsule_dir.path(),
        &CapsuleSpec {
            base: &c.base,
            patches: &[("launch.patch", &c.launch), ("lane.patch", &c.lane)],
            checks: &[("order", "true", 0)],
            flaky: &[],
            unsandboxed: false,
        },
    );
    let mut opts = test_opts(work.path());
    opts.slot_limit = 1;
    let slot_dir = opts.slot_dir.clone();

    let result = verify(
        capsule_dir.path(),
        c.repo.path(),
        work.path(),
        &ScriptedRunner::failing_infra(),
        opts,
    )
    .await;

    assert!(
        matches!(result, Err(VerifyError::Infrastructure(_))),
        "{result:?}"
    );
    assert!(
        cowproof_core::try_acquire_slot("rust", 1, &slot_dir)
            .unwrap()
            .is_some(),
        "the failed verify still holds its slot"
    );
}
