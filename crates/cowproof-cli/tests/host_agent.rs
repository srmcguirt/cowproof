//! `cowproof host-agent` (D27): the remote verbs `prepare`, `patch`, `doctor` and `cleanup`.
//!
//! Every test drives the real binary against temporary directories under `/var/tmp`, with a
//! `HOME` of its own and the working directory set to one of them, so nothing reads the real
//! `HOME` or writes into the source tree. The "remote" is the same machine: the lanes root
//! stands for `~/.cache/cowproof/remote-lanes` on the other host.

#[allow(dead_code)] // this file needs only a few of the shared helpers
mod common;

use common::{fork_lock, git, output, sandbox_available, var_tmp};
use serde_json::Value;
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use tempfile::TempDir;

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// A source repository with two commits, a bundle of it, a lanes root that does not exist
/// yet, and a `HOME`.
struct Fx {
    work: TempDir,
    home: TempDir,
    repo: PathBuf,
    sha: String,
    bundle: PathBuf,
    root: PathBuf,
}

fn git_out(repo: &Path, args: &[&str]) -> Vec<u8> {
    let out = output(
        Command::new("git")
            .args(["-C", repo.to_str().unwrap()])
            .args(args),
    );
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    out.stdout
}

fn git_text(repo: &Path, args: &[&str]) -> String {
    String::from_utf8(git_out(repo, args))
        .unwrap()
        .trim()
        .to_string()
}

impl Fx {
    fn new() -> Self {
        let work = var_tmp("cp-hostagent-work-");
        let home = var_tmp("cp-hostagent-home-");
        let repo = work.path().join("repo");
        fs::create_dir(&repo).unwrap();
        git(&repo, &["init", "-q"]);
        git(&repo, &["config", "user.email", "t@example.com"]);
        git(&repo, &["config", "user.name", "T"]);
        fs::write(repo.join("README.md"), "first\n").unwrap();
        git(&repo, &["add", "."]);
        git(&repo, &["commit", "-q", "-m", "first"]);
        fs::create_dir(repo.join("src")).unwrap();
        fs::write(repo.join("src/lib.txt"), "library\n").unwrap();
        fs::write(repo.join("blob.bin"), [0u8, 159, 146, 150, 255, 0, 1, 2]).unwrap();
        git(&repo, &["add", "."]);
        git(&repo, &["commit", "-q", "-m", "second"]);
        let sha = git_text(&repo, &["rev-parse", "HEAD"]);
        let bundle = work.path().join("base.bundle");
        git(
            &repo,
            &["bundle", "create", bundle.to_str().unwrap(), "HEAD"],
        );
        let root = work.path().join("lanes");
        Fx {
            work,
            home,
            repo,
            sha,
            bundle,
            root,
        }
    }

    /// `cowproof host-agent <args>` with `--root` appended, stdin from `stdin` (or null).
    fn agent(&self, args: &[&str], stdin: Option<&Path>) -> Output {
        self.agent_in(args, stdin, Some(&self.root))
    }

    fn agent_in(&self, args: &[&str], stdin: Option<&Path>, root: Option<&Path>) -> Output {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_cowproof"));
        cmd.arg("host-agent")
            .args(args)
            .current_dir(self.work.path())
            .env("HOME", self.home.path())
            .env_remove("ANTHROPIC_API_KEY")
            .stdin(match stdin {
                Some(p) => Stdio::from(fs::File::open(p).unwrap()),
                None => Stdio::null(),
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(root) = root {
            cmd.arg("--root").arg(root);
        }
        let child = {
            let _g = fork_lock();
            cmd.spawn().unwrap()
        };
        child.wait_with_output().unwrap()
    }

    /// `prepare` of the fixture's base into `id`.
    fn prepare(&self, id: &str, extra: &[&str]) -> Output {
        let mut args = vec![
            "prepare",
            "--lane-id",
            id,
            "--base",
            &self.sha,
            "--director-version",
            VERSION,
        ];
        args.extend_from_slice(extra);
        self.agent(&args, Some(&self.bundle))
    }

    fn clone_of(&self, id: &str) -> PathBuf {
        self.root.join(id).join("clone")
    }

    /// Everything beside the lanes root that a refused `prepare` must not leave behind.
    fn work_entries(&self) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(self.work.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }
}

fn json_of(out: &Output) -> Value {
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "stdout is not one JSON object ({e}): {:?} / stderr {:?}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    })
}

fn assert_ok(out: &Output) -> Value {
    let json = json_of(out);
    assert_eq!(out.status.code(), Some(0), "{json}");
    assert_eq!(json["ok"], true, "{json}");
    json
}

fn assert_refused(out: &Output) -> String {
    let json = json_of(out);
    assert_eq!(out.status.code(), Some(1), "{json}");
    assert_eq!(json["ok"], false, "{json}");
    json["error"].as_str().expect("an error string").to_string()
}

fn tracked(repo: &Path) -> Vec<String> {
    git_text(repo, &["ls-files"])
        .lines()
        .map(String::from)
        .collect()
}

#[test]
fn prepare_builds_the_local_runners_lane_at_the_base() {
    let fx = Fx::new();
    let out = fx.prepare("lane-a", &[]);
    let json = assert_ok(&out);
    assert_eq!(json["lane_id"], "lane-a");
    assert_eq!(json["base_commit"], fx.sha.as_str());

    let lane = fx.root.join("lane-a");
    for dir in ["clone", "home", "scratch", "control", "sock"] {
        assert!(lane.join(dir).is_dir(), "{dir} is missing");
    }
    let mode = fs::metadata(lane.join("sock"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o700, "the socket directory is owner-only");

    // The clone is the base: the same files with the same content, one launch-baseline commit
    // on top, and it is a clone with no remote.
    let clone = fx.clone_of("lane-a");
    assert_eq!(tracked(&clone), tracked(&fx.repo));
    for rel in tracked(&fx.repo) {
        assert_eq!(
            fs::read(clone.join(&rel)).unwrap(),
            fs::read(fx.repo.join(&rel)).unwrap(),
            "{rel} differs"
        );
    }
    assert_eq!(git_text(&clone, &["rev-parse", "HEAD~1"]), fx.sha);
    assert_eq!(git_text(&clone, &["status", "--porcelain"]), "");
    assert_eq!(git_text(&clone, &["remote"]), "");
    assert!(!clone.join(".git/objects/info/alternates").exists());

    // The runner's control file, written by the same code.
    let control: Value =
        serde_json::from_slice(&fs::read(lane.join("control/lane.json")).unwrap()).unwrap();
    assert_eq!(control["base_commit"], fx.sha.as_str());
    assert_eq!(
        control["launch_commit"],
        git_text(&clone, &["rev-parse", "HEAD"]).as_str()
    );

    // Nothing is left beside the root: the throwaway source and the bundle are gone.
    assert_eq!(fx.work_entries(), ["base.bundle", "lanes", "repo"]);
}

#[test]
fn prepare_applies_the_base_patch_on_top_of_the_base() {
    let fx = Fx::new();
    // A base patch as the runner records one: tracked edits and a new file.
    fs::write(fx.repo.join("README.md"), "first\nedited by the director\n").unwrap();
    fs::write(fx.repo.join("new.txt"), "new file\n").unwrap();
    git(&fx.repo, &["add", "-A"]);
    let patch = git_out(&fx.repo, &["diff", "--cached", "--binary", "HEAD"]);
    let patch_file = fx.work.path().join("base.patch");
    fs::write(&patch_file, patch).unwrap();
    git(&fx.repo, &["reset", "-q", "--hard", "HEAD"]);
    git(&fx.repo, &["clean", "-fdq"]);

    let out = fx.prepare("lane-p", &["--base-patch", patch_file.to_str().unwrap()]);
    let json = assert_ok(&out);
    assert_eq!(json["base_patch"], true);

    let clone = fx.clone_of("lane-p");
    assert_eq!(
        fs::read_to_string(clone.join("README.md")).unwrap(),
        "first\nedited by the director\n"
    );
    assert_eq!(
        fs::read_to_string(clone.join("new.txt")).unwrap(),
        "new file\n"
    );
    // base, "base patch", "launch baseline"; the tree is clean on top of both.
    assert_eq!(
        git_text(
            &clone,
            &["rev-list", "--count", &format!("{}..HEAD", fx.sha)]
        ),
        "2"
    );
    assert_eq!(git_text(&clone, &["status", "--porcelain"]), "");
    assert_eq!(
        fx.work_entries(),
        ["base.bundle", "base.patch", "lanes", "repo"]
    );

    // A base patch that is not a file is refused before anything is made.
    let out = fx.prepare("lane-q", &["--base-patch", "/var/tmp/cp-no-such-patch"]);
    assert!(assert_refused(&out).contains("not a file"));
    assert!(!fx.root.join("lane-q").exists());
}

#[test]
fn a_different_version_is_refused_naming_both_and_leaves_no_lane() {
    let fx = Fx::new();
    let out = fx.agent(
        &[
            "prepare",
            "--lane-id",
            "lane-v",
            "--base",
            &fx.sha,
            "--director-version",
            "9.9.9-director",
        ],
        Some(&fx.bundle),
    );
    let error = assert_refused(&out);
    assert!(error.contains("9.9.9-director"), "{error}");
    assert!(error.contains(VERSION), "{error}");
    assert!(!fx.root.join("lane-v").exists());
    assert_eq!(fx.work_entries(), ["base.bundle", "repo"]);
}

#[test]
fn preparing_the_same_lane_twice_is_refused_and_keeps_the_first() {
    let fx = Fx::new();
    assert_ok(&fx.prepare("lane-t", &[]));
    fs::write(fx.clone_of("lane-t").join("marker.txt"), "mine\n").unwrap();

    let error = assert_refused(&fx.prepare("lane-t", &[]));
    assert!(error.contains("already exists"), "{error}");
    assert_eq!(
        fs::read_to_string(fx.clone_of("lane-t").join("marker.txt")).unwrap(),
        "mine\n",
        "the first lane is untouched"
    );
    assert_eq!(fx.work_entries(), ["base.bundle", "lanes", "repo"]);
}

#[test]
fn a_bundle_without_the_commit_or_not_a_bundle_leaves_no_lane() {
    let fx = Fx::new();
    let absent = "1".repeat(40);
    let out = fx.agent(
        &[
            "prepare",
            "--lane-id",
            "lane-m",
            "--base",
            &absent,
            "--director-version",
            VERSION,
        ],
        Some(&fx.bundle),
    );
    let error = assert_refused(&out);
    assert!(error.contains("does not contain"), "{error}");
    assert!(error.contains(&absent), "{error}");
    assert!(!fx.root.join("lane-m").exists());

    let garbage = fx.work.path().join("garbage");
    fs::write(&garbage, "this is not a bundle\n").unwrap();
    let out = fx.agent(
        &[
            "prepare",
            "--lane-id",
            "lane-g",
            "--base",
            &fx.sha,
            "--director-version",
            VERSION,
        ],
        Some(&garbage),
    );
    assert_refused(&out);
    assert!(!fx.root.join("lane-g").exists());

    // An abbreviation is not a commit id the director would send.
    let out = fx.agent(
        &[
            "prepare",
            "--lane-id",
            "lane-s",
            "--base",
            &fx.sha[..8],
            "--director-version",
            VERSION,
        ],
        Some(&fx.bundle),
    );
    assert!(assert_refused(&out).contains("full commit id"));

    assert_eq!(
        fs::read_dir(&fx.root).unwrap().count(),
        0,
        "no lane directory was left"
    );
    assert_eq!(
        fx.work_entries(),
        ["base.bundle", "garbage", "lanes", "repo"]
    );
}

#[test]
fn prepare_refuses_ids_that_could_leave_the_root() {
    let fx = Fx::new();
    for bad in ["../x", "a/b", "..", ".", "", "/abs", "x y"] {
        let out = fx.agent(
            &[
                "prepare",
                "--lane-id",
                bad,
                "--base",
                &fx.sha,
                "--director-version",
                VERSION,
            ],
            Some(&fx.bundle),
        );
        assert_refused(&out);
    }
    assert!(!fx.work.path().join("x").exists());
    assert_eq!(fx.work_entries(), ["base.bundle", "repo"]);
}

/// The oracle for the patch format: the very git command line `cowproof run` documents,
/// run by the test in the clone after the verb has staged the changes.
fn oracle_patch(clone: &Path, launch: &str) -> Vec<u8> {
    git_out(
        clone,
        &[
            "diff",
            "--cached",
            "--binary",
            "--no-ext-diff",
            "--no-textconv",
            launch,
        ],
    )
}

#[test]
fn patch_reproduces_the_edits_in_the_runners_format() {
    if !sandbox_available() {
        return;
    }
    let fx = Fx::new();
    assert_ok(&fx.prepare("lane-d", &[]));
    let clone = fx.clone_of("lane-d");
    let launch = git_text(&clone, &["rev-parse", "HEAD"]);

    // A tracked edit, a new file, a binary file changed, and a deletion.
    fs::write(clone.join("README.md"), "first\nthe builder was here\n").unwrap();
    fs::write(clone.join("created.txt"), "created\n").unwrap();
    fs::write(clone.join("blob.bin"), [255u8, 0, 254, 0, 7, 7, 7, 9]).unwrap();
    fs::remove_file(clone.join("src/lib.txt")).unwrap();

    let out = fx.agent(&["patch", "--lane-id", "lane-d"], None);
    assert_eq!(out.status.code(), Some(0));
    let patch = out.stdout.clone();
    assert!(!patch.is_empty());
    let text = String::from_utf8_lossy(&patch);
    assert!(
        text.contains("GIT binary patch"),
        "binary files travel in the patch"
    );
    assert!(text.contains("created.txt"));

    // Byte-identical to what git writes for the runner's command line.
    assert_eq!(patch, oracle_patch(&clone, &launch));

    // It applies cleanly to a fresh clone of the base and reproduces every edit.
    let fresh = fx.work.path().join("fresh");
    git(
        fx.work.path(),
        &[
            "clone",
            "-q",
            fx.repo.to_str().unwrap(),
            fresh.to_str().unwrap(),
        ],
    );
    git(&fresh, &["checkout", "-q", "--detach", &fx.sha]);
    let patch_file = fx.work.path().join("lane.patch");
    fs::write(&patch_file, &patch).unwrap();
    git(&fresh, &["apply", patch_file.to_str().unwrap()]);
    assert_eq!(
        fs::read_to_string(fresh.join("README.md")).unwrap(),
        "first\nthe builder was here\n"
    );
    assert_eq!(
        fs::read_to_string(fresh.join("created.txt")).unwrap(),
        "created\n"
    );
    assert_eq!(
        fs::read(fresh.join("blob.bin")).unwrap(),
        [255u8, 0, 254, 0, 7, 7, 7, 9]
    );
    assert!(!fresh.join("src/lib.txt").exists());

    // A second call gives the same bytes.
    let again = fx.agent(&["patch", "--lane-id", "lane-d"], None);
    assert_eq!(again.stdout, patch);
}

#[test]
fn patch_of_an_untouched_lane_is_empty_and_a_missing_or_linked_lane_is_refused() {
    if !sandbox_available() {
        return;
    }
    let fx = Fx::new();
    assert_ok(&fx.prepare("lane-e", &[]));
    let out = fx.agent(&["patch", "--lane-id", "lane-e"], None);
    assert_eq!(out.status.code(), Some(0));
    assert!(out.stdout.is_empty(), "no edits, no patch");

    let error = assert_refused(&fx.agent(&["patch", "--lane-id", "nonexistent"], None));
    assert!(error.contains("no lane"), "{error}");

    // A link standing in for a lane is not a lane.
    symlink(fx.root.join("lane-e"), fx.root.join("linked")).unwrap();
    let error = assert_refused(&fx.agent(&["patch", "--lane-id", "linked"], None));
    assert!(error.contains("not a lane directory"), "{error}");

    assert_refused(&fx.agent(&["patch", "--lane-id", "../lane-e"], None));
}

fn write_executable(path: &Path, script: &str) {
    let _g = fork_lock();
    fs::write(path, script).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

#[test]
fn doctor_reports_the_version_claude_and_the_sandbox() {
    let fx = Fx::new();
    let claude = fx.work.path().join("fake-claude");
    write_executable(
        &claude,
        "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo \"fake-claude 9.9.9\"; exit 0; fi\nexit 99\n",
    );
    let out = fx.agent(&["doctor", "--claude-bin", claude.to_str().unwrap()], None);
    let json = json_of(&out);
    assert_eq!(json["version"], VERSION);
    assert_eq!(json["claude"], true, "{json}");
    assert!(
        json["claude_detail"]
            .as_str()
            .unwrap()
            .contains("fake-claude 9.9.9"),
        "{json}"
    );
    assert_eq!(json["sandbox"], sandbox_available(), "{json}");
    assert!(json["sandbox_detail"].is_string());
    assert_eq!(json["ok"], sandbox_available(), "{json}");
    assert_eq!(
        out.status.code(),
        Some(if sandbox_available() { 0 } else { 1 })
    );
    assert!(!fx.root.exists(), "doctor does not create the lanes root");

    // A claude that does not exist: reported, and the host is not ready.
    let out = fx.agent(
        &[
            "doctor",
            "--claude-bin",
            fx.work.path().join("nope").to_str().unwrap(),
        ],
        None,
    );
    let json = json_of(&out);
    assert_eq!(json["claude"], false, "{json}");
    assert_eq!(json["ok"], false);
    assert_eq!(out.status.code(), Some(1));

    // A claude that fails `--version` is not "available" either.
    let broken = fx.work.path().join("broken-claude");
    write_executable(&broken, "#!/bin/sh\nexit 3\n");
    let json = json_of(&fx.agent(&["doctor", "--claude-bin", broken.to_str().unwrap()], None));
    assert_eq!(json["claude"], false, "{json}");
}

#[test]
fn cleanup_removes_the_lane_and_is_idempotent() {
    let fx = Fx::new();
    assert_ok(&fx.prepare("lane-c", &[]));
    // A lane keeps its own read-only entries and links; none of them stops the removal.
    symlink("/var/tmp", fx.clone_of("lane-c").join("link-out")).unwrap();

    let json = assert_ok(&fx.agent(&["cleanup", "--lane-id", "lane-c"], None));
    assert_eq!(json["removed"], true);
    assert!(!fx.root.join("lane-c").exists());
    assert!(
        Path::new("/var/tmp").is_dir(),
        "a link inside a lane is not followed"
    );

    let json = assert_ok(&fx.agent(&["cleanup", "--lane-id", "lane-c"], None));
    assert_eq!(json["removed"], false);

    // A root that was never created is fine too.
    let nowhere = fx.work.path().join("never-made");
    let out = fx.agent_in(&["cleanup", "--lane-id", "x"], None, Some(&nowhere));
    assert_ok(&out);
    assert!(!nowhere.exists());
}

#[test]
fn cleanup_refuses_ids_that_leave_the_root() {
    let fx = Fx::new();
    assert_ok(&fx.prepare("lane-keep", &[]));
    let outside = fx.work.path().join("x");
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("precious"), "keep\n").unwrap();

    for bad in ["../x", "..", ".", "", "a/b", "/abs"] {
        assert_refused(&fx.agent(&["cleanup", "--lane-id", bad], None));
    }
    assert!(outside.join("precious").is_file());
    assert!(fx.root.join("lane-keep").is_dir());
}

#[test]
fn cleanup_unlinks_a_planted_symlink_and_never_touches_its_target() {
    let fx = Fx::new();
    fs::create_dir_all(&fx.root).unwrap();
    let target = fx.work.path().join("outside-target");
    fs::create_dir(&target).unwrap();
    fs::write(target.join("precious"), "keep\n").unwrap();
    symlink(&target, fx.root.join("planted")).unwrap();

    let json = assert_ok(&fx.agent(&["cleanup", "--lane-id", "planted"], None));
    assert_eq!(json["removed"], true);
    assert!(
        fs::symlink_metadata(fx.root.join("planted")).is_err(),
        "the link is gone"
    );
    assert_eq!(
        fs::read_to_string(target.join("precious")).unwrap(),
        "keep\n",
        "its target survived"
    );

    // A dangling link is removed as well.
    symlink(fx.work.path().join("not-there"), fx.root.join("dangling")).unwrap();
    assert_ok(&fx.agent(&["cleanup", "--lane-id", "dangling"], None));
    assert!(fs::symlink_metadata(fx.root.join("dangling")).is_err());

    // A plain file is not a lane: refused and left alone.
    fs::write(fx.root.join("afile"), "x").unwrap();
    assert_refused(&fx.agent(&["cleanup", "--lane-id", "afile"], None));
    assert!(fx.root.join("afile").is_file());
}
