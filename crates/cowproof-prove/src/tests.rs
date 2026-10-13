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

/// The prefix version and the project instructions hash are in `capsule.json`, which the
/// seal covers, and an older capsule without them still reads.
#[test]
fn test_prefix_version_and_instructions_hash_round_trip_and_are_sealed() {
    let dir = TempDir::new().unwrap();
    let mut capsule = Capsule::new(
        "abc".to_string(),
        "def".to_string(),
        fingerprint(),
        "claude:haiku".to_string(),
        "api-key".to_string(),
    );
    capsule.prefix_version = Some("v".repeat(64));
    capsule.project_instructions_sha256 = Some("i".repeat(64));
    capsule.write(dir.path()).unwrap();

    let read = Capsule::read(dir.path()).unwrap();
    assert_eq!(read.prefix_version, Some("v".repeat(64)));
    assert_eq!(read.project_instructions_sha256, Some("i".repeat(64)));

    // The seal covers them: a hand edit of either is refused.
    edit_capsule_json(dir.path(), &"i".repeat(64), &"j".repeat(64));
    assert_capsule_json_mismatch(dir.path());
}

#[test]
fn test_a_capsule_written_before_the_two_fields_still_reads() {
    let dir = TempDir::new().unwrap();
    let mut capsule = Capsule::new(
        "abc".to_string(),
        "def".to_string(),
        fingerprint(),
        "claude:haiku".to_string(),
        "api-key".to_string(),
    );
    capsule.prefix_version = Some("v".repeat(64));
    capsule.project_instructions_sha256 = Some("i".repeat(64));
    capsule.write(dir.path()).unwrap();

    // Make it an older capsule: neither key in capsule.json, and the seal recomputed
    // over those bytes, as the older writer would have sealed it.
    let path = dir.path().join("capsule.json");
    let mut json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let object = json.as_object_mut().unwrap();
    assert!(object.remove("prefix_version").is_some());
    assert!(object.remove("project_instructions_sha256").is_some());
    let raw = serde_json::to_vec_pretty(&json).unwrap();
    std::fs::write(&path, &raw).unwrap();
    std::fs::write(dir.path().join("capsule.sha256"), Capsule::hash_bytes(&raw)).unwrap();

    let read = Capsule::read(dir.path()).expect("an older capsule reads");
    assert_eq!(read.prefix_version, None);
    assert_eq!(read.project_instructions_sha256, None);
    assert_eq!(read.base_commit, "abc");
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
// source repo at the base commit, applies base.patch, replays the launch baseline
// (deleting `launch_removed`), then applies lane.patch.
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
    /// (file name, content), for base.patch / lane.patch.
    patches: &'a [(&'a str, &'a str)],
    /// Paths removed during the launch baseline, sorted.
    launch_removed: &'a [&'a str],
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
            output_len: None,
            end: None,
            verifier: None,
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
    capsule.launch_removed = spec
        .launch_removed
        .iter()
        .map(|s| (*s).to_string())
        .collect();
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
            end: crate::capsule::CheckEnd::Exited { code: status },
        })
    }
}

/// The chain shared by the order tests. The launch baseline deletes `.env` only (it is
/// `launch_removed`, never a patch); lane.patch, authored against the tree after that
/// deletion, edits src.txt from "line=base" to "line=edited".
struct Chain {
    repo: Repo,
    base: (String, String),
    lane: String,
}

fn chain() -> Chain {
    let repo = Repo::new();
    let base = repo.base(&[(".env", "SECRET=1\n"), ("src.txt", "line=base\n")]);
    // Apply only the launch baseline deletion (no content changes).
    repo.change(&[(".env", None)]);
    // Now create lane.patch from this state (after launch baseline, before lane patch).
    let lane = repo.change(&[("src.txt", Some("line=edited\n"))]);
    Chain { repo, base, lane }
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
        held_slot_path: None,
        allow_unsandboxed: false,
        pk_exe: None,
        runtime_dirs: Vec::new(),
    }
}

/// 1. Order: launch baseline (deletes .env) then lane.patch (edits src.txt),
/// checked by a real process on the rebuilt tree.
#[tokio::test]
async fn test_replay_order_launch_then_lane_reproduces() {
    let c = chain();
    let (capsule_dir, work) = dirs();
    write_capsule(
        capsule_dir.path(),
        &CapsuleSpec {
            base: &c.base,
            patches: &[("lane.patch", &c.lane)],
            launch_removed: &[".env"],
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

/// Order matters. The builder wrote its own `.env` after the launch baseline removed
/// the base's: lane.patch CREATES `.env`, so it applies only on a tree where the
/// baseline has already deleted the base's `.env`.
fn recreate_chain() -> Chain {
    let repo = Repo::new();
    let base = repo.base(&[(".env", "SECRET=1\n"), ("src.txt", "line=base\n")]);
    repo.change(&[(".env", None)]);
    let lane = repo.change(&[(".env", Some("builder=1\n"))]);
    Chain { repo, base, lane }
}

#[tokio::test]
async fn test_lane_patch_creating_a_removed_path_applies_after_the_baseline() {
    let c = recreate_chain();
    let (capsule_dir, work) = dirs();
    write_capsule(
        capsule_dir.path(),
        &CapsuleSpec {
            base: &c.base,
            patches: &[("lane.patch", &c.lane)],
            launch_removed: &[".env"],
            checks: &[(
                "order",
                "grep -q builder=1 .env && ! grep -q SECRET .env",
                0,
            )],
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
}

/// Without the baseline replay, lane.patch has no context (`.env` still exists):
/// infrastructure error naming lane.patch, never a divergence, and no check runs.
#[tokio::test]
async fn test_empty_launch_removed_leaves_lane_patch_without_its_context() {
    let c = recreate_chain();
    let (capsule_dir, work) = dirs();
    write_capsule(
        capsule_dir.path(),
        &CapsuleSpec {
            base: &c.base,
            patches: &[("lane.patch", &c.lane)],
            launch_removed: &[],
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

/// base.patch (a dirty base that adds `.env.local`) is applied BEFORE the baseline,
/// which deletes `.env.local` and so needs it present; lane.patch then adds a file.
fn dirty_chain() -> (Chain, String) {
    let repo = Repo::new();
    let base = repo.base(&[(".env", "SECRET=1\n"), ("src.txt", "line=base\n")]);
    let base_patch = repo.change(&[(".env.local", Some("DIRTY=1\n"))]);
    repo.change(&[(".env", None), (".env.local", None)]);
    let lane = repo.change(&[("lane.txt", Some("new\n"))]);
    (Chain { repo, base, lane }, base_patch)
}

#[tokio::test]
async fn test_base_patch_applied_before_the_launch_baseline() {
    let (c, base_patch) = dirty_chain();
    let (capsule_dir, work) = dirs();
    write_capsule(
        capsule_dir.path(),
        &CapsuleSpec {
            base: &c.base,
            patches: &[("base.patch", &base_patch), ("lane.patch", &c.lane)],
            launch_removed: &[".env", ".env.local"],
            checks: &[(
                "chain",
                "test ! -e .env && test ! -e .env.local && test -f lane.txt",
                0,
            )],
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

    // Without base.patch, `.env.local` was never there to remove: infrastructure naming it.
    let (capsule_dir2, work2) = dirs();
    write_capsule(
        capsule_dir2.path(),
        &CapsuleSpec {
            base: &c.base,
            patches: &[("lane.patch", &c.lane)],
            launch_removed: &[".env", ".env.local"],
            checks: &[("chain", "true", 0)],
            flaky: &[],
            unsandboxed: false,
        },
    );
    match verify(
        capsule_dir2.path(),
        c.repo.path(),
        work2.path(),
        &ProcessRunner::new(),
        test_opts(work2.path()),
    )
    .await
    {
        Err(VerifyError::Infrastructure(msg)) => assert!(msg.contains(".env.local"), "{msg}"),
        other => panic!("expected Infrastructure, got {other:?}"),
    }
}

/// The rebuilt tree's hash (`git write-tree`, the index the baseline commit left;
/// lane.patch only touches the working tree) equals the launch tree of a base with
/// `.env`, a nested `.env.local`, and two `CLAUDE.md`.
#[tokio::test]
async fn test_rebuilt_tree_hash_equals_the_launch_tree() {
    let repo = Repo::new();
    std::fs::create_dir_all(repo.path().join("sub")).unwrap();
    std::fs::create_dir_all(repo.path().join("docs")).unwrap();
    let base = repo.base(&[
        (".env", "SECRET=1\n"),
        ("sub/.env.local", "SECRET=2\n"),
        ("CLAUDE.md", "root\n"),
        ("docs/CLAUDE.md", "docs\n"),
        ("sub/keep.txt", "keep\n"),
        ("src.txt", "line=base\n"),
    ]);
    repo.change(&[
        (".env", None),
        ("sub/.env.local", None),
        ("CLAUDE.md", None),
        ("docs/CLAUDE.md", None),
    ]);
    let launch_tree = repo.git(&["rev-parse", "HEAD^{tree}"]).trim().to_string();
    assert_ne!(launch_tree, base.1);
    let lane = repo.change(&[("src.txt", Some("line=edited\n"))]);

    let (capsule_dir, work) = dirs();
    write_capsule(
        capsule_dir.path(),
        &CapsuleSpec {
            base: &base,
            patches: &[("lane.patch", &lane)],
            // Sorted, as the runner records them.
            launch_removed: &[".env", "CLAUDE.md", "docs/CLAUDE.md", "sub/.env.local"],
            checks: &[(
                "tree",
                &format!("test \"$(git write-tree)\" = {launch_tree} && grep -q edited src.txt"),
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
    let tree = work.path().join("tree");
    assert!(!tree.join("docs").exists(), "the emptied directory is gone");
    assert!(tree.join("sub/keep.txt").exists());
}

// ---------------------------------------------------------------------------
// The capsule is untrusted input: `launch_removed` names files to DELETE. Every refusal
// is an Infrastructure error naming the path, with nothing deleted from the tree.
// ---------------------------------------------------------------------------

/// Run verify over `c` with `.env` (which is valid and listed FIRST) followed by `removed`,
/// expect an Infrastructure error whose message contains `names`, and prove nothing was
/// deleted: `.env` is still there, HEAD is still the base commit and the tree is clean.
async fn assert_refused_untouched(c: &Chain, work: &TempDir, removed: &[&str], names: &[&str]) {
    let capsule_dir = TempDir::new().unwrap();
    let mut all = vec![".env"];
    all.extend_from_slice(removed);
    write_capsule(
        capsule_dir.path(),
        &CapsuleSpec {
            base: &c.base,
            patches: &[("lane.patch", &c.lane)],
            launch_removed: &all,
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
        Err(VerifyError::Infrastructure(msg)) => {
            for name in names {
                assert!(msg.contains(name), "should contain {name:?}: {msg}");
            }
        }
        other => panic!("expected Infrastructure for {removed:?}, got {other:?}"),
    }
    assert_eq!(runner.call_count(), 0);
    let tree = work.path().join("tree");
    assert_eq!(
        std::fs::read_to_string(tree.join(".env")).unwrap(),
        "SECRET=1\n",
        "the valid path listed first must not be deleted either"
    );
    let git = |args: &[&str]| {
        let out = Command::new("git")
            .arg("-C")
            .arg(&tree)
            .args(args)
            .output()
            .unwrap();
        String::from_utf8(out.stdout).unwrap()
    };
    assert_eq!(
        git(&["status", "--porcelain"]),
        "",
        "tree must be unchanged"
    );
    assert_eq!(git(&["rev-parse", "HEAD"]).trim(), c.base.0);
}

#[tokio::test]
async fn test_launch_path_with_dotdot_is_refused_and_nothing_outside_is_deleted() {
    let c = chain();
    let work = TempDir::new().unwrap();
    // `tree/../outside` is `work/outside`.
    let outside = work.path().join("outside");
    std::fs::write(&outside, "precious").unwrap();

    assert_refused_untouched(&c, &work, &["../outside"], &["../outside"]).await;

    assert_eq!(std::fs::read_to_string(&outside).unwrap(), "precious");
}

#[tokio::test]
async fn test_absolute_launch_path_is_refused_and_the_target_survives() {
    let c = chain();
    let work = TempDir::new().unwrap();
    let outside_dir = TempDir::new().unwrap();
    let outside = outside_dir.path().join("secret.txt");
    std::fs::write(&outside, "precious").unwrap();
    let abs = outside.to_str().unwrap().to_string();

    assert_refused_untouched(&c, &work, &[&abs], &[&abs]).await;

    assert_eq!(std::fs::read_to_string(&outside).unwrap(), "precious");
}

/// The base commit holds `link`, a symlink to a directory outside the tree; the capsule
/// asks to delete `link/file`, which would remove the outside file if followed.
#[tokio::test]
async fn test_launch_path_through_a_symlink_is_refused_and_the_target_survives() {
    let outside_dir = TempDir::new().unwrap();
    let outside = outside_dir.path().join("file");
    std::fs::write(&outside, "precious").unwrap();
    let repo = Repo::new();
    std::os::unix::fs::symlink(outside_dir.path(), repo.path().join("link")).unwrap();
    let base = repo.base(&[(".env", "SECRET=1\n"), ("src.txt", "line=base\n")]);
    repo.change(&[(".env", None)]);
    let lane = repo.change(&[("src.txt", Some("line=edited\n"))]);
    let c = Chain { repo, base, lane };
    let work = TempDir::new().unwrap();

    assert_refused_untouched(&c, &work, &["link/file"], &["link/file"]).await;

    assert_eq!(std::fs::read_to_string(&outside).unwrap(), "precious");
}

#[tokio::test]
async fn test_launch_path_that_does_not_exist_is_refused() {
    let c = chain();
    let work = TempDir::new().unwrap();

    assert_refused_untouched(
        &c,
        &work,
        &["nope/missing.txt"],
        &["nope/missing.txt", "does not exist"],
    )
    .await;
}

/// The remaining malformed shapes, each refused naming itself with nothing deleted.
#[tokio::test]
async fn test_malformed_launch_paths_are_refused() {
    let repo = Repo::new();
    std::fs::create_dir_all(repo.path().join("sub")).unwrap();
    let base = repo.base(&[
        (".env", "SECRET=1\n"),
        ("src.txt", "line=base\n"),
        ("sub/x.txt", "x\n"),
    ]);
    repo.change(&[(".env", None)]);
    let lane = repo.change(&[("src.txt", Some("line=edited\n"))]);
    let c = Chain { repo, base, lane };

    for (path, why) in [
        ("./src.txt", "`.` or `..`"),
        ("sub/../src.txt", "`.` or `..`"),
        ("sub//x.txt", "empty path component"),
        ("src.txt/", "empty path component"),
        ("", "empty path component"),
        (".git/config", "`.git`"),
        (".GIT/config", "`.git`"),
        ("sub", "a directory is not a recorded removal"),
        ("src.txt/x", "non-directory"),
        (".env", "duplicate"),
    ] {
        let work = TempDir::new().unwrap();
        // `.env` is always listed first, so the duplicate case lists it twice.
        assert_refused_untouched(&c, &work, &[path], &[path, why]).await;
    }
}

/// A file or directory name that merely CONTAINS two dots is not a `..` component.
#[tokio::test]
async fn test_a_name_containing_two_dots_is_a_legitimate_removal() {
    let repo = Repo::new();
    let base = repo.base(&[("a..b", "x\n"), ("src.txt", "line=base\n")]);
    repo.change(&[("a..b", None)]);
    let lane = repo.change(&[("src.txt", Some("line=edited\n"))]);
    let (capsule_dir, work) = dirs();
    write_capsule(
        capsule_dir.path(),
        &CapsuleSpec {
            base: &base,
            patches: &[("lane.patch", &lane)],
            launch_removed: &["a..b"],
            checks: &[("gone", "test ! -e a..b && grep -q edited src.txt", 0)],
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
}

/// The runner removes a symlink standing in for `.claude` (it records `.claude`). Verify
/// must unlink that symlink and leave what it points at alone.
#[tokio::test]
async fn test_a_recorded_symlink_is_unlinked_not_followed() {
    let outside_dir = TempDir::new().unwrap();
    let outside = outside_dir.path().join("settings.json");
    std::fs::write(&outside, "precious").unwrap();
    let repo = Repo::new();
    std::os::unix::fs::symlink(outside_dir.path(), repo.path().join(".claude")).unwrap();
    let base = repo.base(&[("src.txt", "line=base\n")]);
    repo.change(&[(".claude", None)]);
    let lane = repo.change(&[("src.txt", Some("line=edited\n"))]);
    let (capsule_dir, work) = dirs();
    write_capsule(
        capsule_dir.path(),
        &CapsuleSpec {
            base: &base,
            patches: &[("lane.patch", &lane)],
            launch_removed: &[".claude"],
            checks: &[("gone", "test ! -e .claude && test ! -L .claude", 0)],
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
    assert_eq!(std::fs::read_to_string(&outside).unwrap(), "precious");
}

// ---------------------------------------------------------------------------
// The launch baseline lives in a hashed capsule file, not in the unhashed capsule.json.
// ---------------------------------------------------------------------------

fn capsule_with_removed(dir: &Path, removed: &[&str]) {
    let mut capsule = Capsule::new(
        "abc".to_string(),
        "def".to_string(),
        fingerprint(),
        "claude:haiku".to_string(),
        "api-key".to_string(),
    );
    capsule.launch_removed = removed.iter().map(|s| (*s).to_string()).collect();
    capsule.write(dir).unwrap();
}

#[test]
fn test_launch_removed_round_trips_and_is_not_duplicated_in_capsule_json() {
    let dir = TempDir::new().unwrap();
    capsule_with_removed(dir.path(), &[".env", "sub/CLAUDE.md"]);

    let read = Capsule::read(dir.path()).unwrap();
    assert_eq!(read.launch_removed, vec![".env", "sub/CLAUDE.md"]);
    assert!(read.file_hashes.contains_key("launch_removed.json"));
    // A second, unhashed copy in capsule.json could be edited without detection.
    let json = std::fs::read_to_string(dir.path().join("capsule.json")).unwrap();
    assert!(!json.contains("\"launch_removed\""), "{json}");
    assert!(!json.contains("CLAUDE.md"), "{json}");
}

#[test]
fn test_editing_launch_removed_after_write_makes_read_fail() {
    let dir = TempDir::new().unwrap();
    capsule_with_removed(dir.path(), &[".env"]);
    std::fs::write(dir.path().join("launch_removed.json"), r#"["src.txt"]"#).unwrap();

    match Capsule::read(dir.path()) {
        Err(CapsuleError::HashMismatch(file, _, _)) => assert_eq!(file, "launch_removed.json"),
        other => panic!("expected HashMismatch, got {other:?}"),
    }
}

#[test]
fn test_deleting_launch_removed_after_write_makes_read_fail() {
    let dir = TempDir::new().unwrap();
    capsule_with_removed(dir.path(), &[".env"]);
    std::fs::remove_file(dir.path().join("launch_removed.json")).unwrap();

    match Capsule::read(dir.path()) {
        Err(CapsuleError::MissingFile(file)) => assert_eq!(file, "launch_removed.json"),
        other => panic!("expected MissingFile, got {other:?}"),
    }
}

/// An edited baseline stops `verify` before it builds a tree, let alone deletes a file.
#[tokio::test]
async fn test_verify_rejects_an_edited_launch_removed_before_building_anything() {
    let c = chain();
    let (capsule_dir, work) = dirs();
    write_capsule(
        capsule_dir.path(),
        &CapsuleSpec {
            base: &c.base,
            patches: &[("lane.patch", &c.lane)],
            launch_removed: &[".env"],
            checks: &[("any", "true", 0)],
            flaky: &[],
            unsandboxed: false,
        },
    );
    std::fs::write(
        capsule_dir.path().join("launch_removed.json"),
        r#"["src.txt"]"#,
    )
    .unwrap();
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
            assert_eq!(file, "launch_removed.json")
        }
        other => panic!("expected Capsule(HashMismatch), got {other:?}"),
    }
    assert!(!work.path().join("tree").exists());
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
            patches: &[("lane.patch", &c.lane)],
            launch_removed: &[".env"],
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
            patches: &[("lane.patch", &c.lane)],
            launch_removed: &[".env"],
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
            patches: &[("lane.patch", &c.lane)],
            launch_removed: &[".env"],
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
            patches: &[("lane.patch", &c.lane)],
            launch_removed: &[".env"],
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
            patches: &[("lane.patch", &c.lane)],
            launch_removed: &[".env"],
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
            patches: &[("lane.patch", &c.lane)],
            launch_removed: &[".env"],
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

/// 7b. `allow_unsandboxed` (set only by `cowproof run`) replays the same capsule: the tree is
/// built and the check runs. The default stays a refusal (test 7).
#[tokio::test]
async fn test_allow_unsandboxed_replays_an_unsandboxed_capsule() {
    let c = chain();
    let (capsule_dir, work) = dirs();
    write_capsule(
        capsule_dir.path(),
        &CapsuleSpec {
            base: &c.base,
            patches: &[("lane.patch", &c.lane)],
            launch_removed: &[".env"],
            checks: &[("any", "true", 0)],
            flaky: &[],
            unsandboxed: true,
        },
    );
    let runner = ScriptedRunner::new(&[("true", &[0])]);
    let mut opts = test_opts(work.path());
    opts.allow_unsandboxed = true;

    let report = verify(
        capsule_dir.path(),
        c.repo.path(),
        work.path(),
        &runner,
        opts,
    )
    .await
    .expect("an allowed unsandboxed capsule is replayed");

    assert!(
        matches!(report.result, VerifyResult::Reproduced),
        "{report:?}"
    );
    assert_eq!(runner.call_count(), 1);
    assert!(work.path().join("tree").exists());
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
            patches: &[("lane.patch", &c.lane)],
            launch_removed: &[".env"],
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
            patches: &[("lane.patch", &c.lane)],
            launch_removed: &[".env"],
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
            patches: &[("lane.patch", &c.lane)],
            launch_removed: &[".env"],
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

/// A base with `README`, an EMPTY launch baseline, and a lane.patch (made by `git diff`)
/// that adds `file_name`.
fn adding_lane(file_name: &str) -> (Repo, (String, String), String) {
    let repo = Repo::new();
    let base = repo.base(&[("README", "base\n")]);
    let lane = repo.change(&[(file_name, Some("content\n"))]);
    (repo, base, lane)
}

/// 1. The recorded check `test -f newfile` passed, and replaying base + empty
/// the launch baseline + lane.patch under the sandbox passes it again: Reproduced. A second
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
            patches: &[("lane.patch", &lane)],
            launch_removed: &[],
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
            patches: &[("lane.patch", &lane)],
            launch_removed: &[],
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
            end: crate::capsule::CheckEnd::Exited { code: 0 },
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
            patches: &[("lane.patch", &c.lane)],
            launch_removed: &[".env"],
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
        held_slot_path: None,
        allow_unsandboxed: false,
        pk_exe: None,
        runtime_dirs: Vec::new(),
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
            patches: &[("lane.patch", &c.lane)],
            launch_removed: &[".env"],
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
        crate::runner::try_acquire_slot("rust", 1, &slot_dir)
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
            patches: &[("lane.patch", &c.lane)],
            launch_removed: &[".env"],
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
        crate::runner::try_acquire_slot("rust", 1, &slot_dir)
            .unwrap()
            .is_some(),
        "the failed verify still holds its slot"
    );
}

/// A caller that holds the class's only slot passes it as `held_slot_path`: `verify`
/// takes no second one (it would wait forever on a limit of one), finishes, and leaves the
/// caller's slot where it was.
#[tokio::test]
async fn test_verify_reuses_a_held_slot_instead_of_taking_another() {
    let c = chain();
    let capsule_dir = passing_capsule(&c);
    let (_unused, work) = dirs();
    let mut opts = test_opts(work.path());
    opts.slot_limit = 1;
    let held = crate::runner::try_acquire_slot("rust", 1, &opts.slot_dir)
        .unwrap()
        .expect("the one slot is free");
    opts.held_slot_path = Some(held.clone());

    let report = tokio::time::timeout(
        Duration::from_secs(30),
        verify(
            capsule_dir.path(),
            c.repo.path(),
            work.path(),
            &ProcessRunner::new(),
            opts,
        ),
    )
    .await
    .expect("verify waited for a slot the caller holds")
    .unwrap();

    assert!(
        matches!(report.result, VerifyResult::Reproduced),
        "{report:?}"
    );
    assert!(held.is_dir(), "verify released a slot it did not take");
}

/// A held slot that is no longer there is a caller bug and an infrastructure error, not
/// a quiet pass through.
#[tokio::test]
async fn test_verify_refuses_a_held_slot_that_is_gone() {
    let c = chain();
    let capsule_dir = passing_capsule(&c);
    let (_unused, work) = dirs();
    let mut opts = test_opts(work.path());
    opts.held_slot_path = Some(work.path().join("no-such-slot"));

    let result = verify(
        capsule_dir.path(),
        c.repo.path(),
        work.path(),
        &ProcessRunner::new(),
        opts,
    )
    .await;

    assert!(
        matches!(&result, Err(VerifyError::Infrastructure(m)) if m.contains("slot")),
        "{result:?}"
    );
}

// ============================================================================
// The seal on capsule.json: the hash of its raw bytes, in capsule.sha256.
// ============================================================================

fn sealed_capsule(dir: &Path) {
    let mut capsule = Capsule::new(
        "abc123".to_string(),
        "tree_hash_123".to_string(),
        fingerprint(),
        "claude:haiku".to_string(),
        "api-key".to_string(),
    );
    capsule.write(dir).unwrap();
}

/// The lane's class is written to `capsule.json` and read back; a capsule from before the
/// field existed reads as `light`, the packet default.
#[test]
fn test_capsule_records_the_class_and_defaults_to_light() {
    let dir = TempDir::new().unwrap();
    let mut capsule = Capsule::new(
        "abc123".to_string(),
        "tree_hash_123".to_string(),
        fingerprint(),
        "claude:haiku".to_string(),
        "api-key".to_string(),
    );
    assert_eq!(capsule.class, "light");
    capsule.class = "rust".to_string();
    capsule.write(dir.path()).unwrap();
    assert_eq!(Capsule::read(dir.path()).unwrap().class, "rust");

    let text = std::fs::read_to_string(dir.path().join("capsule.json")).unwrap();
    let mut value: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(value["class"], "rust");
    value.as_object_mut().unwrap().remove("class");
    let old: Capsule = serde_json::from_value(value).unwrap();
    assert_eq!(old.class, "light");
}

/// The builder's runtime and where its starting rung came from (D28) are written to
/// `capsule.json`, sealed with the rest, and read back; a capsule from before they existed
/// reads as a `claude` lane with no recorded source, the only kind there was.
#[test]
fn test_capsule_records_the_runtime_and_rung_source_sealed_and_older_capsules_still_read() {
    let dir = TempDir::new().unwrap();
    let mut capsule = Capsule::new(
        "abc123".to_string(),
        "tree_hash_123".to_string(),
        fingerprint(),
        "gpt-6-luna".to_string(),
        "api-key".to_string(),
    );
    assert_eq!(capsule.builder_runtime, "claude");
    assert_eq!(capsule.rung_source, None);
    capsule.builder_runtime = "codex".to_string();
    capsule.rung_source = Some("class".to_string());
    capsule.write(dir.path()).unwrap();

    let read = Capsule::read(dir.path()).unwrap();
    assert_eq!(read.builder_runtime, "codex");
    assert_eq!(read.builder_model, "gpt-6-luna");
    assert_eq!(read.rung_source.as_deref(), Some("class"));

    // The seal covers both: a hand edit of either is refused.
    edit_capsule_json(
        dir.path(),
        "\"builder_runtime\": \"codex\"",
        "\"builder_runtime\": \"claude\"",
    );
    assert_capsule_json_mismatch(dir.path());
    capsule.write(dir.path()).unwrap();
    edit_capsule_json(
        dir.path(),
        "\"rung_source\": \"class\"",
        "\"rung_source\": \"flag\"",
    );
    assert_capsule_json_mismatch(dir.path());

    // An older capsule: neither key in capsule.json, the seal recomputed over those bytes.
    capsule.write(dir.path()).unwrap();
    let path = dir.path().join("capsule.json");
    let mut json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let object = json.as_object_mut().unwrap();
    assert!(object.remove("builder_runtime").is_some());
    assert!(object.remove("rung_source").is_some());
    let raw = serde_json::to_vec_pretty(&json).unwrap();
    std::fs::write(&path, &raw).unwrap();
    std::fs::write(dir.path().join("capsule.sha256"), Capsule::hash_bytes(&raw)).unwrap();
    let old = Capsule::read(dir.path()).expect("an older capsule reads");
    assert_eq!(old.builder_runtime, "claude");
    assert_eq!(old.rung_source, None);
    assert_eq!(old.builder_model, "gpt-6-luna");
}

/// Replace `from` with `to` in capsule.json, as a hand edit would, leaving the seal alone.
fn edit_capsule_json(dir: &Path, from: &str, to: &str) {
    let path = dir.join("capsule.json");
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.contains(from), "capsule.json has no {from:?}:\n{text}");
    std::fs::write(&path, text.replace(from, to)).unwrap();
}

fn assert_capsule_json_mismatch(dir: &Path) {
    match Capsule::read(dir) {
        Err(CapsuleError::HashMismatch(file, _, _)) => assert_eq!(file, "capsule.json"),
        other => panic!("expected a capsule.json HashMismatch, got {other:?}"),
    }
}

#[test]
fn test_editing_lane_state_after_write_makes_read_fail() {
    let dir = TempDir::new().unwrap();
    sealed_capsule(dir.path());
    assert_eq!(Capsule::read(dir.path()).unwrap().lane_state, "finished");
    edit_capsule_json(
        dir.path(),
        "\"lane_state\": \"finished\"",
        "\"lane_state\": \"proved\"",
    );
    assert_capsule_json_mismatch(dir.path());
}

#[test]
fn test_editing_unsandboxed_after_write_makes_read_fail() {
    let dir = TempDir::new().unwrap();
    sealed_capsule(dir.path());
    edit_capsule_json(
        dir.path(),
        "\"unsandboxed\": false",
        "\"unsandboxed\": true",
    );
    assert_capsule_json_mismatch(dir.path());
}

/// The seal is over the bytes on disk: a byte-for-byte different file with the same
/// meaning (compact JSON instead of the written form) is refused too.
#[test]
fn test_a_reformatted_but_equal_capsule_json_is_refused() {
    let dir = TempDir::new().unwrap();
    sealed_capsule(dir.path());
    let path = dir.path().join("capsule.json");
    let value: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    assert_capsule_json_mismatch(dir.path());
}

#[test]
fn test_the_seal_is_the_sha256_of_the_raw_capsule_json_and_is_not_inside_it() {
    use sha2::{Digest, Sha256};
    let dir = TempDir::new().unwrap();
    sealed_capsule(dir.path());
    let raw = std::fs::read(dir.path().join("capsule.json")).unwrap();
    let seal = std::fs::read_to_string(dir.path().join("capsule.sha256")).unwrap();
    assert_eq!(seal.trim(), format!("{:x}", Sha256::digest(&raw)));
    // Not a self-hash inside the hashed file: capsule.json does not list itself or
    // carry the seal.
    let json: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    assert!(
        !json["file_hashes"]
            .as_object()
            .unwrap()
            .contains_key("capsule.json")
    );
    assert!(!String::from_utf8_lossy(&raw).contains(seal.trim()));
}

#[test]
fn test_a_capsule_without_its_seal_is_refused() {
    let dir = TempDir::new().unwrap();
    sealed_capsule(dir.path());
    std::fs::remove_file(dir.path().join("capsule.sha256")).unwrap();
    match Capsule::read(dir.path()) {
        Err(CapsuleError::MissingFile(file)) => assert_eq!(file, "capsule.sha256"),
        other => panic!("expected MissingFile, got {other:?}"),
    }
}

/// Rewriting a capsule (as `cowproof run` does to record the verdict) reseals it.
#[test]
fn test_rewriting_a_capsule_reseals_it() {
    let dir = TempDir::new().unwrap();
    sealed_capsule(dir.path());
    let mut capsule = Capsule::read(dir.path()).unwrap();
    capsule.lane_state = "proved".to_string();
    capsule.write(dir.path()).unwrap();
    assert_eq!(Capsule::read(dir.path()).unwrap().lane_state, "proved");
}

// ============================================================================
// Held-out checks in the capsule (D5): `packets/heldout.toml` is hashed with the
// packets and RUN by `verify` on the rebuilt tree.
// ============================================================================

const HELDOUT_PASSING: &str =
    "[[check]]\nid = \"hidden-edit\"\ncommand = \"grep -q line=edited src.txt\"\n";
const HELDOUT_FAILING: &str = "[[check]]\nid = \"hidden-edit\"\ncommand = \"grep -q line=edited src.txt\"\n\n[[check]]\nid = \"hidden-base\"\ncommand = \"grep -q line=base src.txt\"\n";

/// The shared chain's capsule with one recorded passing check and `heldout` in `packets/`.
fn capsule_with_heldout(c: &Chain, heldout: &str) -> TempDir {
    let dir = TempDir::new().unwrap();
    std::fs::create_dir_all(dir.path().join("packets")).unwrap();
    std::fs::write(dir.path().join(crate::HELDOUT_FILE), heldout).unwrap();
    write_capsule(
        dir.path(),
        &CapsuleSpec {
            base: &c.base,
            patches: &[("lane.patch", &c.lane)],
            launch_removed: &[".env"],
            checks: &[("visible", "true", 0)],
            flaky: &[],
            unsandboxed: false,
        },
    );
    dir
}

#[tokio::test]
async fn test_held_out_checks_that_pass_on_the_rebuilt_tree_reproduce() {
    let c = chain();
    let (_, work) = dirs();
    let capsule_dir = capsule_with_heldout(&c, HELDOUT_PASSING);
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
    assert_eq!(report.heldout.len(), 1);
    assert_eq!(report.heldout[0].check_id, "hidden-edit");
    assert!(report.heldout[0].passed);
}

/// The failing held-out check is named; the one that passes is not.
#[tokio::test]
async fn test_a_failing_held_out_check_refutes_and_is_named() {
    let c = chain();
    let (_, work) = dirs();
    let capsule_dir = capsule_with_heldout(&c, HELDOUT_FAILING);
    let report = verify(
        capsule_dir.path(),
        c.repo.path(),
        work.path(),
        &ProcessRunner::new(),
        test_opts(work.path()),
    )
    .await
    .unwrap();
    match &report.result {
        VerifyResult::HeldOutFailed { check_ids } => {
            assert_eq!(check_ids, &vec!["hidden-base".to_string()])
        }
        other => panic!("expected HeldOutFailed, got {other:?}"),
    }
    assert!(report.checks.iter().all(|m| m.matched_capsule));
}

/// Held-out commands run once each, after the recorded checks, on the same tree.
#[tokio::test]
async fn test_held_out_commands_run_after_the_recorded_checks() {
    let c = chain();
    let (_, work) = dirs();
    let capsule_dir = capsule_with_heldout(&c, HELDOUT_FAILING);
    let runner = ScriptedRunner::new(&[
        ("true", &[0]),
        ("grep -q line=edited src.txt", &[0]),
        ("grep -q line=base src.txt", &[1]),
    ]);
    verify(
        capsule_dir.path(),
        c.repo.path(),
        work.path(),
        &runner,
        test_opts(work.path()),
    )
    .await
    .unwrap();
    assert_eq!(
        *runner.calls.lock().unwrap(),
        vec![
            "true".to_string(),
            "grep -q line=edited src.txt".to_string(),
            "grep -q line=base src.txt".to_string(),
        ]
    );
}

/// A diverged recorded check wins the verdict, and the held-out failure is still reported.
#[tokio::test]
async fn test_a_divergence_and_a_held_out_failure_are_both_reported() {
    let c = chain();
    let (_, work) = dirs();
    let capsule_dir = capsule_with_heldout(&c, HELDOUT_FAILING);
    let runner = ScriptedRunner::new(&[
        ("true", &[1]),
        ("grep -q line=edited src.txt", &[0]),
        ("grep -q line=base src.txt", &[1]),
    ]);
    let report = verify(
        capsule_dir.path(),
        c.repo.path(),
        work.path(),
        &runner,
        test_opts(work.path()),
    )
    .await
    .unwrap();
    match &report.result {
        VerifyResult::Diverged { check_ids } => assert_eq!(check_ids, &vec!["visible".to_string()]),
        other => panic!("expected Diverged, got {other:?}"),
    }
    assert_eq!(
        report
            .heldout
            .iter()
            .filter(|o| !o.passed)
            .map(|o| o.check_id.as_str())
            .collect::<Vec<_>>(),
        vec!["hidden-base"]
    );
}

#[tokio::test]
async fn test_an_edited_held_out_file_is_refused_before_anything_runs() {
    let c = chain();
    let (_, work) = dirs();
    let capsule_dir = capsule_with_heldout(&c, HELDOUT_FAILING);
    std::fs::write(
        capsule_dir.path().join(crate::HELDOUT_FILE),
        HELDOUT_PASSING,
    )
    .unwrap();
    let runner = ScriptedRunner::new(&[]);
    let result = verify(
        capsule_dir.path(),
        c.repo.path(),
        work.path(),
        &runner,
        test_opts(work.path()),
    )
    .await;
    match result {
        Err(VerifyError::Capsule(CapsuleError::HashMismatch(file, _, _))) => {
            assert_eq!(file, "packets/heldout.toml")
        }
        other => panic!("expected a HashMismatch, got {other:?}"),
    }
    assert_eq!(runner.call_count(), 0);
}

#[tokio::test]
async fn test_a_held_out_file_that_does_not_parse_is_infrastructure() {
    let c = chain();
    let (_, work) = dirs();
    let capsule_dir = capsule_with_heldout(&c, "[[check]\nid = ");
    let result = verify(
        capsule_dir.path(),
        c.repo.path(),
        work.path(),
        &ScriptedRunner::new(&[("true", &[0])]),
        test_opts(work.path()),
    )
    .await;
    match result {
        Err(VerifyError::Infrastructure(msg)) => assert!(msg.contains("heldout.toml"), "{msg}"),
        other => panic!("expected Infrastructure, got {other:?}"),
    }
}

// ============================================================================
// The seal covers what verify acts on: a file in a sealed subdirectory that
// `capsule.json` does not list is refused, never read and never run.
// ============================================================================

fn shell_quote(path: &Path) -> String {
    format!("'{}'", path.display())
}

/// An unsealed `checks/injected.json` carries a command that writes a marker file.
/// `verify` must refuse the capsule, naming the file, and must never run the command.
#[tokio::test]
async fn an_unsealed_check_file_is_refused_and_never_run() {
    let c = chain();
    let (_, work) = dirs();
    let capsule_dir = passing_capsule(&c);
    let markers = TempDir::new().unwrap();
    let marker = markers.path().join("injected-ran");
    let injected = CheckResult {
        command: format!("touch {}", shell_quote(&marker)),
        exit_status: 0,
        attempts: 1,
        duration_ms: 1,
        output_sha256: "ignored".to_string(),
        output_len: None,
        end: None,
        verifier: None,
    };
    std::fs::write(
        capsule_dir.path().join("checks/injected.json"),
        serde_json::to_string(&injected).unwrap(),
    )
    .unwrap();

    let result = verify(
        capsule_dir.path(),
        c.repo.path(),
        work.path(),
        &ProcessRunner::new(),
        test_opts(work.path()),
    )
    .await;

    assert!(
        !marker.exists(),
        "the unsealed check ran: its marker file exists"
    );
    let err = result.expect_err("an unsealed check file must make verify fail");
    assert!(
        err.to_string().contains("checks/injected.json"),
        "the error must name the file: {err}"
    );
    assert!(!work.path().join("tree").exists());
}

/// `._has-world.json` is what macOS `tar` adds next to `has-world.json`. It is refused by
/// name, with the hint for the archive, instead of failing later on its bytes.
#[tokio::test]
async fn an_appledouble_file_is_refused_with_the_copyfile_hint() {
    let c = chain();
    let (_, work) = dirs();
    let capsule_dir = passing_capsule(&c);
    // AppleDouble bytes are binary, not JSON, and not UTF-8.
    std::fs::write(
        capsule_dir.path().join("checks/._slow.json"),
        [0x00, 0x05, 0x16, 0x07, 0x00, 0x02, 0x00, 0x00, 0xff, 0xfe],
    )
    .unwrap();
    let runner = ScriptedRunner::new(&[("true", &[0])]);

    let result = verify(
        capsule_dir.path(),
        c.repo.path(),
        work.path(),
        &runner,
        test_opts(work.path()),
    )
    .await;

    match result {
        Err(VerifyError::Capsule(CapsuleError::UnsealedFile(name))) => {
            assert_eq!(name, "checks/._slow.json")
        }
        other => panic!("expected Capsule(UnsealedFile), got {other:?}"),
    }
    let message = Capsule::read(capsule_dir.path()).unwrap_err().to_string();
    assert!(message.contains("checks/._slow.json"), "{message}");
    assert!(message.contains("COPYFILE_DISABLE=1"), "{message}");
    assert_eq!(runner.call_count(), 0);
    assert!(!work.path().join("tree").exists());
}

/// An ordinary unsealed name gets no tar hint.
#[test]
fn an_unsealed_file_that_is_not_appledouble_gets_no_tar_hint() {
    let dir = TempDir::new().unwrap();
    sealed_capsule(dir.path());
    std::fs::write(dir.path().join("checks/extra.json"), "{}").unwrap();
    let message = Capsule::read(dir.path()).unwrap_err().to_string();
    assert!(message.contains("checks/extra.json"), "{message}");
    assert!(!message.contains("COPYFILE_DISABLE"), "{message}");
}

/// `packets/` and `applied/` are sealed subdirectories too: an extra file in either is
/// refused by name. So is a subdirectory, since `write` hashes only flat files.
#[test]
fn an_unsealed_file_in_packets_or_applied_is_refused() {
    for (sub, name) in [
        ("packets", "extra.toml"),
        ("packets", "heldout.toml"),
        ("applied", "extra.json"),
        ("checks", "extra.txt"),
    ] {
        let dir = TempDir::new().unwrap();
        sealed_capsule(dir.path());
        std::fs::write(dir.path().join(sub).join(name), "x").unwrap();
        match Capsule::read(dir.path()) {
            Err(CapsuleError::UnsealedFile(file)) => assert_eq!(file, format!("{sub}/{name}")),
            other => panic!("{sub}/{name}: expected UnsealedFile, got {other:?}"),
        }
    }
    for sub in ["packets", "checks", "applied"] {
        let dir = TempDir::new().unwrap();
        sealed_capsule(dir.path());
        std::fs::create_dir(dir.path().join(sub).join("nested")).unwrap();
        match Capsule::read(dir.path()) {
            Err(CapsuleError::UnsealedFile(file)) => assert_eq!(file, format!("{sub}/nested")),
            other => panic!("{sub}/nested: expected UnsealedFile, got {other:?}"),
        }
    }
}

/// A top-level capsule file the seal does not list is refused as well: `verify` applies
/// `base.patch` whenever it is present, so adding one to a capsule written without it
/// would change the rebuilt tree under an intact seal.
#[tokio::test]
async fn an_unsealed_top_level_patch_is_refused_and_never_applied() {
    let c = chain();
    let (_, work) = dirs();
    let capsule_dir = passing_capsule(&c);
    std::fs::write(capsule_dir.path().join("base.patch"), "not a patch\n").unwrap();
    let runner = ScriptedRunner::new(&[("true", &[0])]);

    let result = verify(
        capsule_dir.path(),
        c.repo.path(),
        work.path(),
        &runner,
        test_opts(work.path()),
    )
    .await;

    match result {
        Err(VerifyError::Capsule(CapsuleError::UnsealedFile(name))) => {
            assert_eq!(name, "base.patch")
        }
        other => panic!("expected Capsule(UnsealedFile), got {other:?}"),
    }
    assert_eq!(runner.call_count(), 0);
    assert!(!work.path().join("tree").exists());
}

/// A file name that is not UTF-8 in a sealed subdirectory is refused, naming the
/// directory, never skipped. Checked on the entry check itself, because macOS refuses to
/// create such a name on disk.
#[cfg(unix)]
#[test]
fn a_non_utf8_file_name_in_a_sealed_subdirectory_is_refused() {
    use std::os::unix::ffi::OsStrExt;
    let odd = std::ffi::OsStr::from_bytes(b"bad-\xff.json");
    match crate::capsule::check_entry_is_sealed("checks", odd, &HashMap::new()) {
        Err(CapsuleError::InvalidFormat(msg)) => assert!(msg.contains("checks/"), "{msg}"),
        other => panic!("expected InvalidFormat naming checks/, got {other:?}"),
    }
}

/// `load_checks` takes its ids from the sealed list. With a capsule whose `file_hashes`
/// lists `a` only, a `b.json` on disk is not loaded, whether or not `Capsule::read` would
/// have refused the directory first.
#[test]
fn load_checks_takes_its_ids_from_file_hashes_not_the_directory() {
    let dir = TempDir::new().unwrap();
    std::fs::create_dir_all(dir.path().join("checks")).unwrap();
    let check = |command: &str| {
        serde_json::to_string(&CheckResult {
            command: command.to_string(),
            exit_status: 0,
            attempts: 1,
            duration_ms: 1,
            output_sha256: "ignored".to_string(),
            output_len: None,
            end: None,
            verifier: None,
        })
        .unwrap()
    };
    std::fs::write(dir.path().join("checks/a.json"), check("true")).unwrap();
    std::fs::write(dir.path().join("checks/b.json"), check("touch pwned")).unwrap();
    std::fs::write(dir.path().join("checks/c.txt"), "not a check").unwrap();
    let mut capsule = Capsule::new(
        "abc123".to_string(),
        "tree_hash_123".to_string(),
        fingerprint(),
        "claude:haiku".to_string(),
        "api-key".to_string(),
    );
    capsule
        .file_hashes
        .insert("checks/a.json".to_string(), "unused".to_string());
    capsule
        .file_hashes
        .insert("checks/c.txt".to_string(), "unused".to_string());

    let loaded = crate::verify::load_checks(dir.path(), &capsule).unwrap();
    assert_eq!(loaded.keys().collect::<Vec<_>>(), vec!["a"]);
    assert_eq!(loaded["a"].command, "true");

    // A listed key that climbs out of checks/ is refused, not read.
    capsule
        .file_hashes
        .insert("checks/x/y.json".to_string(), "unused".to_string());
    match crate::verify::load_checks(dir.path(), &capsule) {
        Err(VerifyError::Infrastructure(msg)) => assert!(msg.contains("checks/x/y.json"), "{msg}"),
        other => panic!("expected Infrastructure, got {other:?}"),
    }
}

/// A capsule `write` sealed, with its check and held-out file, still reads and verifies:
/// the unsealed-file check refuses nothing `write` produced.
#[tokio::test]
async fn a_sealed_capsule_still_verifies() {
    let c = chain();
    let (_, work) = dirs();
    let capsule_dir = capsule_with_heldout(&c, HELDOUT_PASSING);
    // Rewriting reseals it (as `cowproof run` does for the verdict) and still reads.
    let mut again = Capsule::read(capsule_dir.path()).unwrap();
    again.write(capsule_dir.path()).unwrap();

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
    assert_eq!(report.checks[0].check_id, "visible");
}

/// The trace totals are in `capsule.json`, which the seal covers, and an older capsule without
/// them still reads (D5, D23).
#[test]
fn test_trace_totals_round_trip_are_sealed_and_older_capsules_still_read() {
    use crate::capsule::{ToolTotals, TraceTotals};
    let dir = TempDir::new().unwrap();
    let mut capsule = Capsule::new(
        "abc".to_string(),
        "def".to_string(),
        fingerprint(),
        "claude:haiku".to_string(),
        "api-key".to_string(),
    );
    let mut totals = TraceTotals {
        calls: 3,
        delivered_bytes: 4242,
        produced_bytes: 5000,
        ..TraceTotals::default()
    };
    totals.by_tool.insert(
        "Read".to_string(),
        ToolTotals {
            calls: 3,
            delivered_bytes: 4242,
        },
    );
    capsule.traced = true;
    capsule.trace_totals = Some(totals.clone());
    capsule.write(dir.path()).unwrap();

    assert_eq!(
        Capsule::read(dir.path()).unwrap().trace_totals,
        Some(totals)
    );
    let raw: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.path().join("capsule.json")).unwrap()).unwrap();
    assert_eq!(raw["trace_totals"]["deliveredBytes"], 4242);
    assert_eq!(raw["trace_totals"]["byTool"]["Read"]["calls"], 3);

    // The seal covers them: a hand edit is refused.
    edit_capsule_json(dir.path(), "4242", "1");
    assert_capsule_json_mismatch(dir.path());
}

#[test]
fn test_a_capsule_written_before_trace_totals_still_reads() {
    let dir = TempDir::new().unwrap();
    let mut capsule = Capsule::new(
        "abc".to_string(),
        "def".to_string(),
        fingerprint(),
        "claude:haiku".to_string(),
        "api-key".to_string(),
    );
    capsule.trace_totals = Some(Default::default());
    capsule.write(dir.path()).unwrap();

    let path = dir.path().join("capsule.json");
    let mut json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert!(
        json.as_object_mut()
            .unwrap()
            .remove("trace_totals")
            .is_some()
    );
    let raw = serde_json::to_vec_pretty(&json).unwrap();
    std::fs::write(&path, &raw).unwrap();
    std::fs::write(dir.path().join("capsule.sha256"), Capsule::hash_bytes(&raw)).unwrap();

    let read = Capsule::read(dir.path()).expect("an older capsule reads");
    assert_eq!(read.trace_totals, None);
    assert_eq!(read.base_commit, "abc");
}

// ============================================================================
// Port capsules (`kind: port`): the entry, the held-out gate in gates.json
// ============================================================================

fn port_entry(success: bool, held_out: &str) -> crate::port::PortCapsule {
    let mut entry: crate::port::PortCapsule = serde_json::from_value(serde_json::json!({
        "lang": "node", "adapter": "function",
        "reference": {"cmd": "node ref.mjs", "env": {"TZ": "UTC"}, "runtime": "node>=22"},
        "fixtures": "ports/x/fixtures", "tools": ["upper"],
        "epsilon": 0.0, "ignore_paths": [], "unordered_arrays": false,
    }))
    .unwrap();
    entry.result = Some(crate::port::PortResult {
        source_commit: "abc".to_string(),
        fixture_hash: "f".repeat(64),
        fixture_count: 3,
        success,
        surfaces: std::collections::BTreeMap::new(),
        held_out: crate::port::PortHeldOut {
            state: held_out.to_string(),
            reason: (held_out == "skipped").then(|| "no node".to_string()),
            cases: 2,
            fixture_hash: String::new(),
            surfaces: std::collections::BTreeMap::new(),
        },
        failures: if success {
            vec![]
        } else {
            vec!["direct upper/hello: differs".to_string()]
        },
    });
    entry
}

#[test]
fn test_the_port_entry_round_trips_and_is_sealed() {
    let dir = TempDir::new().unwrap();
    let mut capsule = Capsule::new(
        "abc".to_string(),
        "def".to_string(),
        fingerprint(),
        "claude:haiku".to_string(),
        "api-key".to_string(),
    );
    capsule.port = Some(port_entry(true, "passed"));
    capsule.write(dir.path()).unwrap();

    let read = Capsule::read(dir.path()).unwrap();
    let port = read.port.expect("the entry is read back");
    assert_eq!(port.reference.as_ref().unwrap().cmd, "node ref.mjs");
    let result = port.result.unwrap();
    assert_eq!(result.source_commit, "abc");
    assert_eq!(result.fixture_hash, "f".repeat(64));
    assert_eq!(result.held_out.state, "passed");

    // The seal covers it: the hash of the fixture set cannot be edited after the fact.
    edit_capsule_json(dir.path(), &"f".repeat(64), &"e".repeat(64));
    assert_capsule_json_mismatch(dir.path());
}

#[test]
fn test_a_capsule_written_before_port_packets_still_reads_and_has_no_port_entry() {
    let dir = TempDir::new().unwrap();
    let mut capsule = Capsule::new(
        "abc".to_string(),
        "def".to_string(),
        fingerprint(),
        "claude:haiku".to_string(),
        "api-key".to_string(),
    );
    capsule.port = Some(port_entry(true, "none"));
    capsule.write(dir.path()).unwrap();

    // An older capsule has no `port` key; seal it as the older writer would have.
    let path = dir.path().join("capsule.json");
    let mut json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert!(json.as_object_mut().unwrap().remove("port").is_some());
    let raw = serde_json::to_vec_pretty(&json).unwrap();
    std::fs::write(&path, &raw).unwrap();
    std::fs::write(dir.path().join("capsule.sha256"), Capsule::hash_bytes(&raw)).unwrap();

    let read = Capsule::read(dir.path()).expect("an older capsule reads");
    assert!(read.port.is_none());
    assert_eq!(read.base_commit, "abc");
}

fn gate_report(held_out_passed: bool) -> crate::gates::GateReport {
    let gate = |name: &str, passed: bool, evidence: &[&str]| crate::gates::GateResult {
        name: name.to_string(),
        passed,
        warned: false,
        evidence: evidence.iter().map(|e| e.to_string()).collect(),
    };
    crate::gates::GateReport {
        gates: vec![
            gate("ownership", true, &[]),
            gate(
                "held_out",
                held_out_passed,
                &["Held-out checks present: 2 checks"],
            ),
        ],
        any_failed: !held_out_passed,
    }
}

fn held(id: &str, passed: bool) -> crate::verify::HeldOutOutcome {
    crate::verify::HeldOutOutcome {
        check_id: id.to_string(),
        passed,
    }
}

#[test]
fn test_the_held_out_gate_carries_each_checks_pass_or_fail() {
    let mut report = gate_report(true);
    crate::gates::record_verify_results(
        &mut report,
        &[held("one", true), held("two", false)],
        None,
        false,
    );
    let gate = report.gates.iter().find(|g| g.name == "held_out").unwrap();
    assert!(!gate.passed);
    assert_eq!(
        gate.evidence,
        [
            "Held-out checks present: 2 checks",
            "held-out check \"one\": passed",
            "held-out check \"two\": failed",
        ]
    );
    assert!(report.any_failed);
    // No port gate for ordinary work.
    assert!(report.gates.iter().all(|g| g.name != "port_replay"));

    // All passing: the gate stays green and says so.
    let mut green = gate_report(true);
    crate::gates::record_verify_results(
        &mut green,
        &[held("one", true), held("two", true)],
        None,
        false,
    );
    assert!(green.gates.iter().all(|g| g.passed));
    assert!(!green.any_failed);
    assert!(green.gates[1].evidence[2].ends_with("\"two\": passed"));
}

#[test]
fn test_require_heldout_makes_skipped_held_out_port_cases_fail_the_gate() {
    let outcome = crate::port::PortOutcome {
        result: port_entry(true, "skipped").result.unwrap(),
    };
    // Required: the skip fails the held-out gate, says why, and is not only a warning.
    let mut required = gate_report(true);
    crate::gates::record_verify_results(&mut required, &[], Some(&outcome), true);
    let gate = required
        .gates
        .iter()
        .find(|g| g.name == "held_out")
        .unwrap();
    assert!(!gate.passed);
    assert!(!gate.warned);
    assert!(
        gate.evidence
            .iter()
            .any(|e| e == "held-out: skipped (no node)")
    );
    assert!(
        gate.evidence
            .iter()
            .any(|e| e.contains("skipped") && e.contains("require_heldout"))
    );
    assert!(required.any_failed);
    // The port replay itself still passed: only the held-out gate refuses.
    assert!(
        required
            .gates
            .iter()
            .any(|g| g.name == "port_replay" && g.passed)
    );

    // Not required: the same skip stays a warning.
    let mut optional = gate_report(true);
    crate::gates::record_verify_results(&mut optional, &[], Some(&outcome), false);
    let gate = optional
        .gates
        .iter()
        .find(|g| g.name == "held_out")
        .unwrap();
    assert!(gate.passed);
    assert!(gate.warned);
    assert!(!optional.any_failed);

    // Required, but the held-out cases ran: nothing changes.
    let ran = crate::port::PortOutcome {
        result: port_entry(true, "passed").result.unwrap(),
    };
    let mut passed = gate_report(true);
    crate::gates::record_verify_results(&mut passed, &[], Some(&ran), true);
    assert!(!passed.any_failed);
}

#[test]
fn test_a_port_capsule_adds_the_port_replay_gate_and_records_the_held_out_state() {
    for (success, held_out, gate_passes, warned) in [
        (true, "passed", true, false),
        (true, "skipped", true, true),
        (false, "failed", false, false),
    ] {
        let mut report = gate_report(true);
        let outcome = crate::port::PortOutcome {
            result: port_entry(success, held_out).result.unwrap(),
        };
        crate::gates::record_verify_results(&mut report, &[], Some(&outcome), false);
        let port = report.gates.last().unwrap();
        assert_eq!(port.name, "port_replay");
        assert_eq!(port.passed, success, "{held_out}");
        if !success {
            assert_eq!(port.evidence, ["direct upper/hello: differs"]);
        }
        let held = report.gates.iter().find(|g| g.name == "held_out").unwrap();
        assert_eq!(held.passed, gate_passes, "{held_out}");
        assert_eq!(held.warned, warned, "{held_out}");
        assert!(
            held.evidence.iter().any(|e| e.contains(held_out)),
            "{held_out}: {:?}",
            held.evidence
        );
        assert_eq!(report.any_failed, !success);
    }
}

/// The runtime directories a proof was granted (`runtime_dirs`) are in `capsule.json`, sealed
/// and read back; a capsule with none writes no key at all, so every capsule from before the
/// setting keeps its bytes and its seal.
#[test]
fn test_capsule_records_the_granted_runtime_dirs_sealed_and_absent_when_none() {
    let dir = TempDir::new().unwrap();
    let mut capsule = Capsule::new(
        "abc123".to_string(),
        "tree_hash_123".to_string(),
        fingerprint(),
        "haiku".to_string(),
        "api-key".to_string(),
    );
    capsule.write(dir.path()).unwrap();
    let json = std::fs::read_to_string(dir.path().join("capsule.json")).unwrap();
    assert!(!json.contains("runtime_dirs"), "{json}");
    assert!(Capsule::read(dir.path()).unwrap().runtime_dirs.is_empty());

    capsule.runtime_dirs = vec!["/opt/node22".to_string(), "/opt/py312".to_string()];
    capsule.write(dir.path()).unwrap();
    assert_eq!(
        Capsule::read(dir.path()).unwrap().runtime_dirs,
        ["/opt/node22", "/opt/py312"]
    );
    // The seal covers it: dropping a directory by hand is refused.
    edit_capsule_json(dir.path(), "\"/opt/node22\",", "");
    assert_capsule_json_mismatch(dir.path());
}
