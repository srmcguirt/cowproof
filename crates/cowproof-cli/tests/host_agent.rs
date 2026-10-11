//! `cowproof host-agent` (D27): the remote verbs `prepare`, `patch`, `doctor`, `cleanup`,
//! `builder` and `check`.
//!
//! Every test drives the real binary against temporary directories under `/var/tmp`, with a
//! `HOME` of its own and the working directory set to one of them, so nothing reads the real
//! `HOME` or writes into the source tree. The "remote" is the same machine: the lanes root
//! stands for `~/.cache/cowproof/remote-lanes` on the other host.

#[allow(dead_code)] // this file needs only a few of the shared helpers
mod common;

use common::{
    REAL_KEY, fork_lock, git, group_gone, output, sandbox_available, unique_lane_id, var_tmp,
};
use cowproof_run::bridge::bridge_port;
use serde_json::{Value, json};
use std::fs;
use std::io::Write;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::os::unix::net::UnixListener;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};
use tempfile::TempDir;

const VERSION: &str = env!("CARGO_PKG_VERSION");
/// The host-agent protocol this build speaks (`HOST_PROTOCOL` in `src/host_agent.rs`).
const PROTOCOL: &str = "2";

/// A source repository with two commits, a bundle of it, a lanes root that does not exist
/// yet, and a `HOME`.
struct Fx {
    work: TempDir,
    home: TempDir,
    repo: PathBuf,
    sha: String,
    bundle: PathBuf,
    /// Holds the framed stdin files for `prepare`, beside nothing else.
    inputs: TempDir,
    /// `prepare`'s stdin for the bundle with no base patch.
    framed: PathBuf,
    root: PathBuf,
}

/// `prepare`'s stdin: the header line, the base patch, the bundle.
fn frame(patch: &[u8], bundle: &Path) -> Vec<u8> {
    let mut bytes = format!("{}\n", json!({"patch_bytes": patch.len()})).into_bytes();
    bytes.extend_from_slice(patch);
    bytes.extend_from_slice(&fs::read(bundle).unwrap());
    bytes
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
        let inputs = var_tmp("cp-hostagent-inputs-");
        let framed = inputs.path().join("no-patch.stdin");
        fs::write(&framed, frame(b"", &bundle)).unwrap();
        Fx {
            work,
            home,
            repo,
            sha,
            bundle,
            inputs,
            framed,
            root,
        }
    }

    /// A framed `prepare` stdin file with `patch` and `bundle`, kept outside the work directory.
    fn framed_with(&self, name: &str, patch: &[u8], bundle: &Path) -> PathBuf {
        let path = self.inputs.path().join(name);
        fs::write(&path, frame(patch, bundle)).unwrap();
        path
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
            "--protocol",
            PROTOCOL,
        ];
        args.extend_from_slice(extra);
        self.agent(&args, Some(&self.framed))
    }

    /// `prepare` with `patch` as the director's base patch, framed on stdin.
    fn prepare_with_patch(&self, id: &str, patch: &[u8]) -> Output {
        let stdin = self.framed_with(&format!("{id}.stdin"), patch, &self.bundle);
        let args = [
            "prepare",
            "--lane-id",
            id,
            "--base",
            &self.sha,
            "--director-version",
            VERSION,
            "--protocol",
            PROTOCOL,
        ];
        self.agent(&args, Some(&stdin))
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
fn prepare_applies_the_base_patch_it_reads_on_stdin_on_top_of_the_base() {
    let fx = Fx::new();
    // A base patch as the runner records one: tracked edits, a new file and a binary one that
    // is not UTF-8 and holds a NUL, so only a byte-exact frame gives it back.
    fs::write(fx.repo.join("README.md"), "first\nedited by the director\n").unwrap();
    fs::write(fx.repo.join("new.txt"), "new file\n").unwrap();
    let binary = [0u8, 159, 146, 150, 255, 0, b'\n', 10, 13];
    fs::write(fx.repo.join("new.bin"), binary).unwrap();
    git(&fx.repo, &["add", "-A"]);
    let patch = git_out(&fx.repo, &["diff", "--cached", "--binary", "HEAD"]);
    git(&fx.repo, &["reset", "-q", "--hard", "HEAD"]);
    git(&fx.repo, &["clean", "-fdq"]);

    let out = fx.prepare_with_patch("lane-p", &patch);
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
    assert_eq!(fs::read(clone.join("new.bin")).unwrap(), binary);
    // base, "base patch", "launch baseline"; the tree is clean on top of both.
    assert_eq!(
        git_text(
            &clone,
            &["rev-list", "--count", &format!("{}..HEAD", fx.sha)]
        ),
        "2"
    );
    assert_eq!(git_text(&clone, &["status", "--porcelain"]), "");
    // The patch was read from stdin: no host file was named, and nothing is left beside the root.
    assert_eq!(fx.work_entries(), ["base.bundle", "lanes", "repo"]);

    // A header that promises more patch than stdin holds is refused, and leaves no lane.
    let mut short = format!("{}\n", json!({"patch_bytes": patch.len() + 1000})).into_bytes();
    short.extend_from_slice(&patch);
    let short_file = fx.inputs.path().join("short.stdin");
    fs::write(&short_file, short).unwrap();
    let out = fx.agent(
        &[
            "prepare",
            "--lane-id",
            "lane-q",
            "--base",
            &fx.sha,
            "--director-version",
            VERSION,
            "--protocol",
            PROTOCOL,
        ],
        Some(&short_file),
    );
    assert!(assert_refused(&out).contains("ended inside the base patch"));
    assert!(!fx.root.join("lane-q").exists());

    // A bundle with no header (what a director of the older protocol sends) is refused
    // without being read as a patch, and a patch that does not apply leaves no lane either.
    let out = fx.agent(
        &[
            "prepare",
            "--lane-id",
            "lane-r",
            "--base",
            &fx.sha,
            "--director-version",
            VERSION,
            "--protocol",
            PROTOCOL,
        ],
        Some(&fx.bundle),
    );
    assert!(assert_refused(&out).contains("header"));
    let out = fx.prepare_with_patch("lane-s", b"diff --git a/nope b/nope\nnot a patch\n");
    assert_refused(&out);
    assert!(!fx.root.join("lane-r").exists() && !fx.root.join("lane-s").exists());
    assert_eq!(fx.work_entries(), ["base.bundle", "lanes", "repo"]);
}

#[test]
fn prepare_refuses_a_missing_or_different_protocol_naming_both_and_leaves_no_lane() {
    let fx = Fx::new();
    let base = |protocol: Option<&'static str>| {
        let mut args = vec![
            "prepare",
            "--lane-id",
            "lane-n",
            "--base",
            &fx.sha,
            "--director-version",
            VERSION,
        ];
        if let Some(p) = protocol {
            args.extend(["--protocol", p]);
        }
        fx.agent(&args, Some(&fx.framed))
    };
    let error = assert_refused(&base(Some("1")));
    assert!(
        error.contains("protocol 1") && error.contains(&format!("protocol {PROTOCOL}")),
        "{error}"
    );
    let error = assert_refused(&base(None));
    assert!(
        error.contains("protocol mismatch") && error.contains("no host-agent protocol"),
        "{error}"
    );
    assert!(!fx.root.join("lane-n").exists());
    assert_eq!(fx.work_entries(), ["base.bundle", "repo"]);
    // The right one works.
    assert_ok(&base(Some(PROTOCOL)));
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
            "--protocol",
            PROTOCOL,
        ],
        Some(&fx.framed),
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
            "--protocol",
            PROTOCOL,
        ],
        Some(&fx.framed),
    );
    let error = assert_refused(&out);
    assert!(error.contains("does not contain"), "{error}");
    assert!(error.contains(&absent), "{error}");
    assert!(!fx.root.join("lane-m").exists());

    let garbage_bundle = fx.inputs.path().join("garbage");
    fs::write(&garbage_bundle, "this is not a bundle\n").unwrap();
    let garbage = fx.framed_with("garbage.stdin", b"", &garbage_bundle);
    let out = fx.agent(
        &[
            "prepare",
            "--lane-id",
            "lane-g",
            "--base",
            &fx.sha,
            "--director-version",
            VERSION,
            "--protocol",
            PROTOCOL,
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
            "--protocol",
            PROTOCOL,
        ],
        Some(&fx.framed),
    );
    assert!(assert_refused(&out).contains("full commit id"));

    assert_eq!(
        fs::read_dir(&fx.root).unwrap().count(),
        0,
        "no lane directory was left"
    );
    assert_eq!(fx.work_entries(), ["base.bundle", "lanes", "repo"]);
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
                "--protocol",
                PROTOCOL,
            ],
            Some(&fx.framed),
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
    assert_eq!(json["protocol"].to_string(), PROTOCOL, "{json}");
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

// ---------------------------------------------------------------------------------------------
// `builder` and `check` (D27)
// ---------------------------------------------------------------------------------------------

/// The placeholder the director's proxy would have made for the lane.
const PLACEHOLDER: &str = "placeholder-0123abcd-test";

/// What the fake builder prints on stdout: two JSON lines, then bytes that are not UTF-8 and
/// no final newline, so only a byte-for-byte copy gives them back.
fn fake_stdout() -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(
        b"{\"type\":\"system\",\"subtype\":\"init\",\"session_id\":\"0a1b2c3d-1111-2222-3333-444455556666\"}\n",
    );
    bytes.extend_from_slice(
        b"{\"type\":\"result\",\"subtype\":\"success\",\"result\":\"done \\u00e9\",\"num_turns\":1}\n",
    );
    bytes.extend_from_slice(&[0xff, 0xfe]);
    bytes.extend_from_slice(b"tail-without-a-newline");
    bytes
}

/// The shell text that prints [`fake_stdout`].
const FAKE_PRINT: &str = concat!(
    r#"printf '%s\n' '{"type":"system","subtype":"init","session_id":"0a1b2c3d-1111-2222-3333-444455556666"}'"#,
    "\n",
    r#"printf '%s\n' '{"type":"result","subtype":"success","result":"done \u00e9","num_turns":1}'"#,
    "\n",
    r#"printf '\377\376tail-without-a-newline'"#,
    "\n",
);

/// A prepared remote lane with forwarded sockets, a copy of `cowproof` outside the home, and a
/// fake `claude` that records what it sees under `$HOME/fake` (the lane's `home/fake`).
struct Bfx {
    fx: Fx,
    id: String,
    /// Holds the `cowproof` copy and the fake.
    _tools: TempDir,
    /// A directory outside the lane that the fake tries to write to.
    outside: TempDir,
    cowproof: PathBuf,
    fake: PathBuf,
    /// What stands in for the `ssh -R` forwards; kept open for the life of the test.
    _sockets: Vec<UnixListener>,
}

impl Bfx {
    fn new(body: &str) -> Self {
        let fx = Fx::new();
        let id = unique_lane_id();
        assert_ok(&fx.prepare(&id, &[]));
        let tools = var_tmp("cp-hostagent-tools-");
        let outside = var_tmp("cp-hostagent-outside-");
        // The test binary lives under the home in a normal checkout, which the sandbox hides, so
        // a copy outside it is what runs.
        let cowproof = tools.path().join("cowproof");
        {
            let _g = fork_lock();
            fs::copy(env!("CARGO_BIN_EXE_cowproof"), &cowproof).unwrap();
        }
        let fake = tools.path().join("fake-claude");
        let script = format!(
            r#"#!/bin/sh
if [ "$1" = "--version" ]; then echo "fake-claude 0.0.0"; exit 0; fi
rec="$HOME/fake"
mkdir -p "$rec"
{body}
"#
        );
        {
            let _g = fork_lock();
            fs::write(&fake, script).unwrap();
            fs::set_permissions(&fake, fs::Permissions::from_mode(0o755)).unwrap();
        }
        let lane = fx.root.join(&id);
        let sockets = vec![
            UnixListener::bind(lane.join("proxy.sock")).unwrap(),
            UnixListener::bind(lane.join("sock/runner.sock")).unwrap(),
        ];
        Bfx {
            fx,
            id,
            _tools: tools,
            outside,
            cowproof,
            fake,
            _sockets: sockets,
        }
    }

    fn lane(&self) -> PathBuf {
        self.fx.root.join(&self.id)
    }

    /// Where the fake records, as the test sees it.
    fn rec(&self) -> PathBuf {
        self.lane().join("home/fake")
    }

    fn spec(&self) -> Value {
        json!({
            "model": "haiku",
            "prompt": "Do the thing.",
            "system_prompt": "You are a builder.\n",
            "settings": {"permissions": {"allow": ["Bash"], "deny": ["WebFetch"]}},
            "placeholder_key": PLACEHOLDER,
            "bridge_port": bridge_port(&self.id),
            "port_base": 57040,
            "max_turns": 5,
            "claude_bin": self.fake,
        })
    }

    /// `host-agent <verb> --lane-id <id> ...` on the binary copy, with the real key in the
    /// environment (it must never reach the builder), stdin and stdout piped.
    fn command(&self, verb: &[&str], lane_id: &str) -> Command {
        let mut cmd = Command::new(&self.cowproof);
        cmd.arg("host-agent")
            .args(verb)
            .arg("--lane-id")
            .arg(lane_id)
            .arg("--root")
            .arg(&self.fx.root)
            .current_dir(self.fx.work.path())
            .env("HOME", self.fx.home.path())
            .env("ANTHROPIC_API_KEY", REAL_KEY)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        cmd
    }

    fn start(&self, verb: &[&str], stdin: &Value) -> Child {
        self.start_lane(verb, &self.id, stdin)
    }

    fn start_lane(&self, verb: &[&str], lane_id: &str, stdin: &Value) -> Child {
        let mut cmd = self.command(verb, lane_id);
        let mut child = {
            let _g = fork_lock();
            cmd.spawn().unwrap()
        };
        // One line, ended by a newline. The pipe stays in `child.stdin`, open: for `builder`
        // that is the lifeline, and `wait_with_output` (for `check`, which reads to the end of
        // its stdin) closes it.
        let pipe = child.stdin.as_mut().unwrap();
        // A refusal can exit before it has read everything; that is not a failure here.
        let _ = pipe.write_all(format!("{stdin}\n").as_bytes());
        let _ = pipe.flush();
        child
    }

    /// The builder to its end, with its stdin held open until then (the lifeline).
    fn run_builder(&self, spec: &Value) -> Output {
        let mut child = self.start(&["builder"], spec);
        let lifeline = child.stdin.take();
        let out = child.wait_with_output().unwrap();
        drop(lifeline);
        out
    }

    fn run_check(&self, check_id: &str, spec: &Value) -> Output {
        self.start(&["check", "--check-id", check_id], spec)
            .wait_with_output()
            .unwrap()
    }

    fn recorded(&self, name: &str) -> String {
        fs::read_to_string(self.rec().join(name))
            .unwrap_or_else(|e| panic!("the fake recorded no {name}: {e}"))
    }

    fn escape_target(&self) -> PathBuf {
        self.outside.path().join("pwned")
    }
}

/// A fake that records its surroundings, writes in its clone, tries to write outside it, sends
/// stdout and stderr and exits 7.
fn recording_body(escape_target: &Path) -> String {
    format!(
        r#"cp "$HOME/settings.json" "$HOME/mcp.json" "$HOME/system-prompt.md" "$rec/"
env | sort > "$rec/env.txt"
printf '%s\n' "$@" > "$rec/args.txt"
pwd > "$rec/pwd.txt"
echo made > made.txt
echo "oops sk-synthetic0123456789abcdef" >&2
if ( echo x > '{}' ) 2>/dev/null; then echo allowed > "$rec/escape"; else echo denied > "$rec/escape"; fi
{FAKE_PRINT}exit 7
"#,
        escape_target.display()
    )
}

/// `Bfx::new` for a body that needs the escape target, which exists only after the fixture.
fn recording_fixture() -> Bfx {
    // The outside directory is made inside `new`; the body is written afterwards.
    let bfx = Bfx::new("exit 99");
    let script = format!(
        "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo fake-claude; exit 0; fi\nrec=\"$HOME/fake\"\nmkdir -p \"$rec\"\n{}",
        recording_body(&bfx.escape_target())
    );
    {
        let _g = fork_lock();
        fs::write(&bfx.fake, script).unwrap();
    }
    bfx
}

fn env_lines(text: &str) -> Vec<&str> {
    text.lines().collect()
}

#[test]
fn builder_runs_the_fake_in_the_remote_sandbox_and_hands_back_its_stdout_and_exit_code() {
    if !sandbox_available() {
        return;
    }
    let bfx = recording_fixture();
    let out = bfx.run_builder(&bfx.spec());

    // The fake's stdout is ours, byte for byte, and its exit code is ours.
    assert_eq!(
        out.stdout,
        fake_stdout(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        out.status.code(),
        Some(7),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    // The lane files are in the fake's home, written by the shared code.
    let settings: Value = serde_json::from_str(&bfx.recorded("settings.json")).unwrap();
    assert_eq!(settings["permissions"]["deny"], json!(["WebFetch"]));
    assert_eq!(bfx.recorded("system-prompt.md"), "You are a builder.\n");

    // `mcp.json` points `lane-tools` at the remote lane's runner socket.
    let mcp: Value = serde_json::from_str(&bfx.recorded("mcp.json")).unwrap();
    let server = &mcp["mcpServers"]["cowproof-tools"];
    let lane = bfx.fx.root.canonicalize().unwrap().join(&bfx.id);
    assert_eq!(server["type"], "stdio");
    assert_eq!(
        server["command"],
        bfx.cowproof.canonicalize().unwrap().to_str().unwrap()
    );
    assert_eq!(
        server["args"],
        json!([
            "lane-tools",
            "--socket",
            lane.join("sock/runner.sock").to_str().unwrap()
        ])
    );

    // The environment: the bridge, the placeholder and nothing of the real key.
    let env = bfx.recorded("env.txt");
    let lines = env_lines(&env);
    let has = |line: String| lines.contains(&line.as_str());
    assert!(
        has(format!(
            "ANTHROPIC_BASE_URL=http://127.0.0.1:{}",
            bridge_port(&bfx.id)
        )),
        "{env}"
    );
    assert!(has(format!("ANTHROPIC_API_KEY={PLACEHOLDER}")), "{env}");
    assert!(
        has(format!(
            "COWPROOF_RUNNER_SOCKET={}",
            lane.join("sock/runner.sock").display()
        )),
        "{env}"
    );
    assert!(has("COWPROOF_PORT_BASE=57040".to_string()), "{env}");
    assert!(
        has(format!("HOME={}", lane.join("home").display())),
        "{env}"
    );
    assert!(
        !env.contains(REAL_KEY),
        "the real key reached the builder: {env}"
    );
    let args = bfx.recorded("args.txt");
    assert!(args.lines().any(|l| l == "haiku"), "{args}");
    assert_eq!(args.lines().last(), Some("Do the thing."));
    assert_eq!(
        bfx.recorded("pwd.txt").trim(),
        lane.join("clone").to_str().unwrap()
    );

    // It worked in its clone, and the sandbox kept it out of everything else.
    assert_eq!(
        fs::read_to_string(bfx.fx.clone_of(&bfx.id).join("made.txt")).unwrap(),
        "made\n"
    );
    assert_eq!(bfx.recorded("escape").trim(), "denied");
    assert!(
        !bfx.escape_target().exists(),
        "the builder wrote outside its clone"
    );

    // Its stderr is in the control directory, redacted by the runner's own pump.
    let stderr = fs::read_to_string(bfx.lane().join("control/builder.stderr")).unwrap();
    assert!(stderr.contains("oops [redacted]"), "{stderr}");
    assert!(!stderr.contains("sk-synthetic"), "{stderr}");
}

#[test]
fn builder_refuses_a_spec_that_carries_an_api_key_and_starts_nothing() {
    if !sandbox_available() {
        return;
    }
    let bfx = Bfx::new("echo started > \"$rec/started\"\nexit 0");
    let real = "sk-test-real-xyz-0123456789";
    let mut cases: Vec<(&str, Value)> = Vec::new();
    for (name, edit) in [
        (
            "a key in the settings env",
            json!({"settings": {"env": {"ANTHROPIC_API_KEY": real}}}),
        ),
        (
            "a key-shaped value anywhere",
            json!({"settings": {"note": format!("use {real}")}}),
        ),
        ("a top-level api key", json!({"api_key": real})),
        (
            "an auth token field",
            json!({"settings": {"hooks": {"auth_token": "x"}}}),
        ),
        (
            "a real key as the placeholder",
            json!({"placeholder_key": real}),
        ),
        (
            "a key in the prompt",
            json!({"prompt": format!("export KEY={real}")}),
        ),
    ] {
        let mut spec = bfx.spec();
        for (k, v) in edit.as_object().unwrap() {
            spec[k] = v.clone();
        }
        cases.push((name, spec));
    }
    for (name, spec) in cases {
        let out = bfx.run_builder(&spec);
        let json = json_of(&out);
        assert_eq!(out.status.code(), Some(1), "{name}: {json}");
        assert_eq!(json["ok"], false, "{name}: {json}");
        let error = json["error"].as_str().unwrap();
        assert!(error.contains("API key or credential"), "{name}: {error}");
        assert!(
            !error.contains(real) && !error.contains("sk-"),
            "{name}: the error repeats the key"
        );
        assert!(
            !String::from_utf8_lossy(&out.stderr).contains("sk-test"),
            "{name}: stderr repeats the key"
        );
    }
    // Nothing started, and no lane file was written.
    assert!(!bfx.rec().exists(), "a builder started");
    assert!(!bfx.lane().join("home/settings.json").exists());
    assert!(!bfx.lane().join("control/builder.stderr").exists());
}

#[test]
fn builder_accepts_a_prompt_that_only_explains_bearer_auth() {
    if !sandbox_available() {
        return;
    }
    let bfx = Bfx::new(&format!(
        "echo started > \"$rec/started\"\n{FAKE_PRINT}exit 0"
    ));
    let mut spec = bfx.spec();
    spec["prompt"] = json!("Send the header Authorization: Bearer <token> to the API.");
    let out = bfx.run_builder(&spec);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.stdout, fake_stdout());
    assert_eq!(bfx.recorded("started").trim(), "started");
}

#[test]
fn builder_refuses_a_launch_that_does_not_fit_the_lane() {
    if !sandbox_available() {
        return;
    }
    let bfx = Bfx::new("echo started > \"$rec/started\"\nexit 0");
    let edits: Vec<(&str, Value)> = vec![
        (
            "another lane's bridge port",
            json!({"bridge_port": bridge_port(&bfx.id).wrapping_add(1)}),
        ),
        ("a port block outside the range", json!({"port_base": 1000})),
        (
            "a placeholder that is not one",
            json!({"placeholder_key": "hello"}),
        ),
        (
            "a model that looks like a flag",
            json!({"model": "--dangerous"}),
        ),
        ("a relative claude", json!({"claude_bin": "claude"})),
        (
            "a missing claude",
            json!({"claude_bin": "/var/tmp/cp-no-such-claude"}),
        ),
        (
            "a bad session id",
            json!({"resume_session_id": "not a session"}),
        ),
        ("no turns", json!({"max_turns": 0})),
        ("an unknown field", json!({"mcp": {"mcpServers": {}}})),
    ];
    for (name, edit) in edits {
        let mut spec = bfx.spec();
        for (k, v) in edit.as_object().unwrap() {
            spec[k] = v.clone();
        }
        let out = bfx.run_builder(&spec);
        let json = json_of(&out);
        assert_eq!(out.status.code(), Some(1), "{name}: {json}");
        assert_eq!(json["ok"], false, "{name}: {json}");
    }
    assert!(!bfx.rec().exists(), "a builder started");

    // A socket that was never forwarded: refused, and the message says what to do.
    fs::remove_file(bfx.lane().join("sock/runner.sock")).unwrap();
    let out = bfx.run_builder(&bfx.spec());
    let error = assert_refused(&out);
    assert!(
        error.contains("runner.sock") && error.contains("ssh -R"),
        "{error}"
    );
    fs::remove_file(bfx.lane().join("proxy.sock")).unwrap();
    let error = assert_refused(&bfx.run_builder(&bfx.spec()));
    assert!(error.contains("proxy.sock"), "{error}");

    // No lane, no builder.
    let out = bfx
        .start_lane(&["builder"], "no-such-lane", &bfx.spec())
        .wait_with_output()
        .unwrap();
    assert!(assert_refused(&out).contains("no lane"));
    assert!(!bfx.rec().exists(), "a builder started");
}

/// Wait until `path` exists (the fake has got that far), or fail after a minute.
fn wait_for(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(60);
    while !path.exists() {
        assert!(
            Instant::now() < deadline,
            "{} never appeared",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn wait_exit(child: &mut Child, limit: Duration) -> std::process::ExitStatus {
    let deadline = Instant::now() + limit;
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        assert!(Instant::now() < deadline, "host-agent builder did not exit");
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn signal_pid(signal: &str, pid: &str) -> bool {
    let _g = fork_lock();
    Command::new("kill")
        .args([signal, pid])
        .stderr(Stdio::null())
        .status()
        .unwrap()
        .success()
}

/// Kills the fake's background child by the pid it recorded, whatever the test did.
struct Reaper(PathBuf);

impl Drop for Reaper {
    fn drop(&mut self) {
        if let Ok(pid) = fs::read_to_string(&self.0) {
            signal_pid("-KILL", pid.trim());
        }
    }
}

/// SIGTERM to `host-agent builder` ends the builder and a background child of it, by effect: the
/// child writes a marker line every 0.2 s, and after the exit the marker stops growing.
fn assert_sigterm_ends_the_builder(body: &str, limit: Duration) {
    let bfx = Bfx::new(body);
    let _reaper = Reaper(bfx.rec().join("bg.pid"));
    let mut child = bfx.start(&["builder"], &bfx.spec());
    let marker = bfx.rec().join("marker");
    wait_for(&marker);
    let pid = child.id().to_string();
    assert!(signal_pid("-TERM", &pid), "could not signal host-agent");

    let status = wait_exit(&mut child, limit);
    assert_eq!(status.code(), Some(130), "an interrupted builder exits 130");
    let size = fs::metadata(&marker).unwrap().len();
    std::thread::sleep(Duration::from_millis(1500));
    assert_eq!(
        fs::metadata(&marker).unwrap().len(),
        size,
        "a child kept writing after the kill"
    );
    let bg = fs::read_to_string(bfx.rec().join("bg.pid")).unwrap();
    assert!(
        !signal_pid("-0", bg.trim()),
        "the background child is still alive"
    );
}

#[test]
fn sigterm_to_builder_ends_the_fake_and_a_background_child_that_ignores_sigterm() {
    if !sandbox_available() {
        return;
    }
    assert_sigterm_ends_the_builder(
        r#"( trap '' TERM; while :; do echo tick >> "$rec/marker"; sleep 0.2; done ) >/dev/null 2>&1 &
echo $! > "$rec/bg.pid"
sleep 600
"#,
        Duration::from_secs(30),
    );
}

#[test]
fn a_builder_that_ignores_sigterm_is_killed_after_the_grace() {
    if !sandbox_available() {
        return;
    }
    assert_sigterm_ends_the_builder(
        r#"trap '' TERM
echo $$ > "$rec/bg.pid"
while :; do echo tick >> "$rec/marker"; sleep 0.2; done
"#,
        Duration::from_secs(60),
    );
}

/// How long `host-agent builder` gets to end its group after a stop: the grace it gives the
/// builder (`TERM_GRACE`, 10 s) and five seconds more.
const STOP_WITHIN: Duration = Duration::from_secs(15);

/// Kills `host-agent` when dropped, so a test that fails leaves nothing running.
struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Kills the builder's whole process group by the pgid it recorded, whatever the test did. The
/// sandbox shares the host's pid space on macOS only, so the number means nothing elsewhere.
struct GroupReaper(PathBuf);

impl Drop for GroupReaper {
    fn drop(&mut self) {
        if cfg!(target_os = "macos")
            && let Ok(pgid) = fs::read_to_string(&self.0)
        {
            signal_pid("-KILL", &format!("-{}", pgid.trim()));
        }
    }
}

/// A fake builder that records its pgid, starts a background child that ignores SIGTERM and
/// ticks into `marker`, and then sleeps.
const TICKING_BUILDER: &str = r#"echo $$ > "$rec/pgid"
( trap '' TERM; while :; do echo tick >> "$rec/marker"; sleep 0.2; done ) >/dev/null 2>&1 &
echo $! > "$rec/bg.pid"
sleep 600
"#;

/// After the stop: the builder's group is gone (on macOS, where the sandbox shares the pid
/// space) and its background child stopped writing, which holds everywhere.
fn assert_builder_group_ended(bfx: &Bfx) {
    let marker = bfx.rec().join("marker");
    let size = fs::metadata(&marker).unwrap().len();
    std::thread::sleep(Duration::from_millis(1500));
    assert_eq!(
        fs::metadata(&marker).unwrap().len(),
        size,
        "a child kept writing after the stop"
    );
    if cfg!(target_os = "macos") {
        let pgid = fs::read_to_string(bfx.rec().join("pgid")).unwrap();
        assert!(
            group_gone(pgid.trim()),
            "process group {} is still alive",
            pgid.trim()
        );
    }
}

#[test]
fn the_remote_builder_ends_when_its_stdin_closes() {
    if !sandbox_available() {
        return;
    }
    let bfx = Bfx::new(TICKING_BUILDER);
    let _reaper = GroupReaper(bfx.rec().join("pgid"));
    let mut agent = KillOnDrop(bfx.start(&["builder"], &bfx.spec()));
    // The spec line was written and the pipe is still open: the builder lives on.
    wait_for(&bfx.rec().join("marker"));
    std::thread::sleep(Duration::from_millis(500));
    assert!(
        agent.0.try_wait().unwrap().is_none(),
        "the builder ended while the lifeline was open"
    );

    // The director lets go (or its ssh dies and sshd closes the pipe): end of file.
    let began = Instant::now();
    drop(agent.0.stdin.take());
    let status = wait_exit(&mut agent.0, STOP_WITHIN);
    assert_eq!(status.code(), Some(130), "an ended builder exits 130");
    assert!(began.elapsed() < STOP_WITHIN);
    assert_builder_group_ended(&bfx);
}

#[test]
fn a_builder_whose_stdout_breaks_is_ended() {
    if !sandbox_available() {
        return;
    }
    let bfx = Bfx::new(
        r#"echo $$ > "$rec/pgid"
while :; do echo tick >> "$rec/marker"; printf 'line\n'; sleep 0.2; done
"#,
    );
    let _reaper = GroupReaper(bfx.rec().join("pgid"));
    let mut agent = KillOnDrop(bfx.start(&["builder"], &bfx.spec()));
    // It is delivering output, then nobody reads it any more.
    let mut out = agent.0.stdout.take().unwrap();
    let mut first = [0u8; 5];
    std::io::Read::read_exact(&mut out, &mut first).unwrap();
    assert_eq!(&first, b"line\n");
    drop(out);

    // Stdin is still open: only the broken stdout ends it.
    let status = wait_exit(&mut agent.0, STOP_WITHIN);
    assert_eq!(status.code(), Some(130), "an ended builder exits 130");
    assert!(agent.0.stdin.is_some());
    assert_builder_group_ended(&bfx);
}

// ---------------------------------------------------------------------------------------------
// The recorded builder group (R-5)
// ---------------------------------------------------------------------------------------------

/// The record `host-agent builder` keeps of its group, once it is there.
fn group_record(bfx: &Bfx) -> Value {
    let path = bfx.lane().join("control/builder.group.json");
    wait_for(&path);
    serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap()
}

/// Kills the group named in a record file, by the pgid it holds, whatever the test did. The
/// record is the host's own view of the number, so it is right on every platform.
struct RecordReaper(PathBuf);

impl Drop for RecordReaper {
    fn drop(&mut self) {
        if let Ok(text) = fs::read_to_string(&self.0)
            && let Ok(record) = serde_json::from_str::<Value>(&text)
            && let Some(pgid) = record["pgid"].as_u64()
        {
            signal_pid("-KILL", &format!("-{pgid}"));
        }
    }
}

/// Kills a group by the pgid read from its record, after the record itself may be gone.
struct PgidReaper(u64);

impl Drop for PgidReaper {
    fn drop(&mut self) {
        signal_pid("-KILL", &format!("-{}", self.0));
    }
}

#[test]
fn the_builder_records_its_group_and_removes_the_record_when_the_group_is_gone() {
    if !sandbox_available() {
        return;
    }
    let bfx = Bfx::new("echo up > \"$rec/up\"\nsleep 600\n");
    let _reaper = RecordReaper(bfx.lane().join("control/builder.group.json"));
    let mut agent = KillOnDrop(bfx.start(&["builder"], &bfx.spec()));
    wait_for(&bfx.rec().join("up"));
    let record = group_record(&bfx);
    let pgid = record["pgid"].as_u64().unwrap();
    assert!(pgid > 1);
    assert_eq!(record["leader"].as_u64(), Some(pgid), "{record}");
    assert!(
        record["leader_start"]
            .as_str()
            .is_some_and(|s| !s.is_empty()),
        "no start time: {record}"
    );
    assert!(!group_gone(&pgid.to_string()), "the group is not running");

    drop(agent.0.stdin.take());
    wait_exit(&mut agent.0, STOP_WITHIN);
    assert!(group_gone(&pgid.to_string()));
    assert!(
        !bfx.lane().join("control/builder.group.json").exists(),
        "the record outlived the group"
    );
}

#[test]
fn cleanup_ends_a_live_builder_group_before_removing_the_lane() {
    if !sandbox_available() {
        return;
    }
    // A leader that takes SIGTERM and carries on, and a child that ignores it: only the
    // grace period and then SIGKILL end this group.
    let bfx = Bfx::new(
        r#"trap 'echo got-term >> "$rec/term"' TERM
( trap '' TERM; while :; do echo tick >> "$rec/marker"; sleep 0.2; done ) >/dev/null 2>&1 &
while :; do echo tick >> "$rec/marker"; sleep 0.2; done
"#,
    );
    let _reaper = RecordReaper(bfx.lane().join("control/builder.group.json"));
    let mut agent = KillOnDrop(bfx.start(&["builder"], &bfx.spec()));
    wait_for(&bfx.rec().join("marker"));
    let pgid = group_record(&bfx)["pgid"].as_u64().unwrap();
    let _group = PgidReaper(pgid);
    assert!(!group_gone(&pgid.to_string()));

    // The director has let go and already asks for the lane to go: the host's builder is still
    // in its grace period, writing.
    let began = Instant::now();
    let json = assert_ok(&bfx.fx.agent(&["cleanup", "--lane-id", &bfx.id], None));
    assert!(began.elapsed() < Duration::from_secs(40));
    assert_eq!(json["removed"], true, "{json}");
    assert_eq!(json["group"]["pgid"].as_u64(), Some(pgid), "{json}");
    assert_eq!(json["group"]["state"], "ended", "{json}");
    assert_eq!(json["group"]["signals"], json!(["TERM", "KILL"]), "{json}");

    assert!(group_gone(&pgid.to_string()), "the group is still alive");
    assert!(!bfx.lane().exists(), "the lane is still there");
    std::thread::sleep(Duration::from_secs(2));
    assert!(!bfx.lane().exists(), "something put the lane back");
    assert!(group_gone(&pgid.to_string()));
    wait_exit(&mut agent.0, STOP_WITHIN);
}

#[test]
fn a_recorded_group_whose_leader_was_replaced_is_not_signalled() {
    let fx = Fx::new();
    assert_ok(&fx.prepare("lane-r", &[]));
    // An unrelated process that leads a group of its own, as a builder's leader would.
    let stranger = {
        let _g = fork_lock();
        Command::new("sleep")
            .arg("30")
            .process_group(0)
            .stdin(Stdio::null())
            .spawn()
            .unwrap()
    };
    let pid = stranger.id();
    let _stranger = KillOnDrop(stranger);
    fs::write(
        fx.root.join("lane-r/control/builder.group.json"),
        json!({"pgid": pid, "leader": pid, "leader_start": "proc:1-not-its-start"}).to_string(),
    )
    .unwrap();

    let json = assert_ok(&fx.agent(&["cleanup", "--lane-id", "lane-r"], None));
    assert_eq!(json["removed"], true, "{json}");
    assert_eq!(json["group"]["state"], "replaced", "{json}");
    assert_eq!(json["group"]["signals"], json!([]), "{json}");
    std::thread::sleep(Duration::from_millis(500));
    assert!(
        signal_pid("-0", &pid.to_string()),
        "a process that only shares the recorded pid was signalled"
    );
    assert!(!group_gone(&pid.to_string()), "its group was signalled");
}

#[test]
fn a_relaunch_ends_the_previous_group_first() {
    if !sandbox_available() {
        return;
    }
    // The first launch leaves a marker and waits; the second one, which finds the marker,
    // records the moment it starts.
    let bfx = Bfx::new(
        r#"if [ -e "$rec/first" ]; then echo second > "$rec/second"; sleep 600; fi
echo first > "$rec/first"
sleep 600
"#,
    );
    let _reaper = RecordReaper(bfx.lane().join("control/builder.group.json"));
    let mut first = KillOnDrop(bfx.start(&["builder"], &bfx.spec()));
    wait_for(&bfx.rec().join("first"));
    let before = group_record(&bfx)["pgid"].as_u64().unwrap();
    let _first_group = PgidReaper(before);
    assert!(!group_gone(&before.to_string()));

    // The first host-agent still holds its lifeline: the old group is alive when the second
    // launch begins, and only that launch can end it.
    let mut second = KillOnDrop(bfx.start(&["builder"], &bfx.spec()));
    wait_for(&bfx.rec().join("second"));
    assert!(
        group_gone(&before.to_string()),
        "the second builder started while the first group ({before}) was alive"
    );
    wait_exit(&mut first.0, STOP_WITHIN);

    // The record is the second group's now, and the first host-agent's late exit left it be.
    let deadline = Instant::now() + Duration::from_secs(20);
    let after = loop {
        let now = group_record(&bfx)["pgid"].as_u64().unwrap();
        if now != before || Instant::now() > deadline {
            break now;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let _second_group = PgidReaper(after);
    assert_ne!(after, before, "the new group was never recorded");
    assert!(!group_gone(&after.to_string()));
    drop(second.0.stdin.take());
    wait_exit(&mut second.0, STOP_WITHIN);
}

#[test]
fn patch_ends_a_group_that_is_still_stopping_before_it_takes_the_patch() {
    if !sandbox_available() {
        return;
    }
    let bfx = Bfx::new("echo up > \"$rec/up\"\nsleep 600\n");
    let _reaper = RecordReaper(bfx.lane().join("control/builder.group.json"));
    let _agent = KillOnDrop(bfx.start(&["builder"], &bfx.spec()));
    wait_for(&bfx.rec().join("up"));
    let pgid = group_record(&bfx)["pgid"].as_u64().unwrap();
    let _group = PgidReaper(pgid);

    let out = bfx.fx.agent(&["patch", "--lane-id", &bfx.id], None);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(
        group_gone(&pgid.to_string()),
        "patch left the group running"
    );
}

#[test]
fn a_garbage_record_names_nothing_to_signal() {
    let fx = Fx::new();
    assert_ok(&fx.prepare("lane-g", &[]));
    for bad in [
        "not json".to_string(),
        json!({"pgid": 1, "leader": 1, "leader_start": "x"}).to_string(),
        json!({"pgid": 0, "leader": 0, "leader_start": "x"}).to_string(),
        json!({"pgid": 4242, "leader": 4243, "leader_start": "x"}).to_string(),
    ] {
        fs::write(fx.root.join("lane-g/control/builder.group.json"), &bad).unwrap();
        let json = assert_ok(&fx.agent(&["cleanup", "--lane-id", "lane-g"], None));
        assert_eq!(json["group"], Value::Null, "{bad}: {json}");
        assert_ok(&fx.prepare("lane-g", &[]));
    }
}

#[test]
fn a_spec_that_ends_at_end_of_file_is_refused_as_an_older_protocol_and_nothing_starts() {
    if !sandbox_available() {
        return;
    }
    let bfx = Bfx::new("echo started > \"$rec/started\"\nexit 0");
    // What a director of protocol 1 sends: the spec with no newline, then end of file.
    let mut child = {
        let mut cmd = bfx.command(&["builder"], &bfx.id);
        let _g = fork_lock();
        cmd.spawn().unwrap()
    };
    let mut pipe = child.stdin.take().unwrap();
    let _ = pipe.write_all(bfx.spec().to_string().as_bytes());
    drop(pipe);
    let out = child.wait_with_output().unwrap();
    let error = assert_refused(&out);
    assert!(
        error.contains("ended by a newline") && error.contains("protocol"),
        "{error}"
    );
    assert!(!bfx.rec().exists(), "a builder started");
    assert!(!bfx.lane().join("home/settings.json").exists());
}

fn check_spec(command: &str, timeout_secs: u64) -> Value {
    json!({"command": command, "timeout_secs": timeout_secs, "port_base": 57040})
}

#[test]
fn check_reports_the_exit_code_of_a_passing_and_a_failing_command() {
    if !sandbox_available() {
        return;
    }
    let bfx = Bfx::new("exit 0");
    let out = bfx.run_check("c-pass", &check_spec("echo fine; exit 0", 60));
    let json = assert_ok(&out);
    assert_eq!(json["exit_code"], 0);
    assert_eq!(json["timed_out"], false);
    assert_eq!(json["output_tail"], "fine\n");

    // A failing check is a report, not a refusal: exit 0 for the verb, ok false, the code kept.
    let out = bfx.run_check("c-fail", &check_spec("echo broken >&2; exit 3", 60));
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let json = json_of(&out);
    assert_eq!(json["ok"], false);
    assert_eq!(json["exit_code"], 3);
    assert_eq!(json["timed_out"], false);
    assert_eq!(json["output_tail"], "broken\n");

    // It runs in the clone, in the check sandbox: the clone is writable, the rest is not.
    let target = bfx.escape_target();
    let command = format!(
        "pwd; echo from-check > made-by-check.txt; (echo x > '{}') 2>/dev/null && echo allowed || echo denied; echo $COWPROOF_PORT_BASE",
        target.display()
    );
    let json = assert_ok(&bfx.run_check("c-sandbox", &check_spec(&command, 60)));
    let clone = bfx.lane().canonicalize().unwrap().join("clone");
    assert_eq!(
        json["output_tail"],
        format!("{}\ndenied\n57040\n", clone.display())
    );
    assert!(!target.exists());
    assert_eq!(
        fs::read_to_string(bfx.fx.clone_of(&bfx.id).join("made-by-check.txt")).unwrap(),
        "from-check\n"
    );
}

#[test]
fn check_redacts_a_token_and_caps_the_output() {
    if !sandbox_available() {
        return;
    }
    let bfx = Bfx::new("exit 0");
    let json = assert_ok(&bfx.run_check(
        "c-secret",
        // Built at run time: a spec that held the token itself would be refused.
        &check_spec(
            "echo token $(printf 'sk-%s' synthetic0123456789abcdef) here",
            60,
        ),
    ));
    assert_eq!(json["output_tail"], "token [redacted] here\n");

    // The cap keeps the end of the output, at most the local run_check limit, and says so.
    let json = assert_ok(&bfx.run_check(
        "c-big",
        &check_spec(
            "head -c 200000 /dev/zero | tr '\\0' x; echo; echo the-end",
            60,
        ),
    ));
    let tail = json["output_tail"].as_str().unwrap();
    assert!(tail.starts_with("[output truncated]\n"), "{}", &tail[..40]);
    assert!(tail.ends_with("x\nthe-end\n"));
    assert!(
        tail.len() <= 32 * 1024 + "[output truncated]\n".len(),
        "{}",
        tail.len()
    );
}

#[test]
fn check_kills_a_command_that_runs_past_its_timeout() {
    if !sandbox_available() {
        return;
    }
    let bfx = Bfx::new("exit 0");
    // The command sleeps 30 s and the limit is 1 s. The bound is far above the limit because the
    // process start (a fresh binary copy, assessed by the OS on first run, and the fork lock
    // other tests hold while they copy theirs) can take seconds under load; it is still below
    // the sleep, so a timeout that did not kill the command would show.
    let child = bfx.start(
        &["check", "--check-id", "c-slow"],
        &check_spec("sleep 30", 1),
    );
    let started = Instant::now();
    let out = child.wait_with_output().unwrap();
    assert!(
        started.elapsed() < Duration::from_secs(25),
        "the timeout did not fire: {:?}",
        started.elapsed()
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let json = json_of(&out);
    assert_eq!(json["ok"], false);
    assert_eq!(json["timed_out"], true);
    assert_eq!(json["exit_code"], -1);
    assert!(json["output_tail"].as_str().unwrap().contains("timed out"));
}

#[test]
fn check_refuses_a_key_a_bad_spec_and_a_lane_that_is_not_there() {
    if !sandbox_available() {
        return;
    }
    let bfx = Bfx::new("exit 0");
    let mut with_key = check_spec("true", 60);
    with_key["command"] =
        json!("curl -H 'x-api-key: sk-test-real-xyz-0123456789' http://example.invalid");
    let error = assert_refused(&bfx.run_check("c-key", &with_key));
    assert!(error.contains("API key or credential"), "{error}");
    assert!(!error.contains("sk-test"));

    for (name, spec) in [
        ("no timeout", json!({"command": "true", "timeout_secs": 0})),
        ("a timeout past the local limit", check_spec("true", 1201)),
        ("an empty command", check_spec("", 60)),
        (
            "an unknown field",
            json!({"command": "true", "timeout_secs": 5, "env": {}}),
        ),
        (
            "a port block outside the range",
            json!({"command": "true", "timeout_secs": 5, "port_base": 80}),
        ),
    ] {
        let out = bfx.run_check("c-bad", &spec);
        assert_eq!(json_of(&out)["ok"], false, "{name}");
        assert_eq!(out.status.code(), Some(1), "{name}");
    }
    assert!(!bfx.lane().join("clone/made-by-check.txt").exists());

    let out = bfx
        .start_lane(
            &["check", "--check-id", "x"],
            "no-such-lane",
            &check_spec("true", 5),
        )
        .wait_with_output()
        .unwrap();
    assert!(assert_refused(&out).contains("no lane"));
}
