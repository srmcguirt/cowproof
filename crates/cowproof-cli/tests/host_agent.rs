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
    REAL_KEY, fork_lock, git, group_gone, output, pid_alive, sandbox_available, signal_group,
    signal_pid, unique_lane_id, var_tmp, wait_group_gone,
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
/// How long a group whose leader has exited may still be listed: the kernel reaps its members
/// late on a loaded host, so a "gone" assertion polls this long (a "still alive" one looks once).
const GROUP_GONE_WITHIN: Duration = Duration::from_secs(10);
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
            .env_remove("XDG_CONFIG_HOME")
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
    /// Holds the fake.
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
        // the process's shared copy outside it is what runs (no `pk` beside it).
        let cowproof = common::shared_cowproof_alone().to_path_buf();
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

/// Kills the fake's background child by the pid it recorded, whatever the test did. The
/// sandbox shares the host's pid space on macOS only: on Linux the recorded number is a pid in
/// bwrap's namespace (often 1 to 3) that names some other process here, and the namespace dies
/// with its init, so nothing is signalled.
struct Reaper(PathBuf);

impl Drop for Reaper {
    fn drop(&mut self) {
        if cfg!(target_os = "macos")
            && let Ok(pid) = fs::read_to_string(&self.0)
            && let Ok(pid) = pid.trim().parse::<u32>()
        {
            signal_pid("KILL", pid);
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
    let pid = child.id();
    assert!(signal_pid("TERM", pid), "could not signal host-agent");

    let status = wait_exit(&mut child, limit);
    assert_eq!(status.code(), Some(130), "an interrupted builder exits 130");
    let size = fs::metadata(&marker).unwrap().len();
    std::thread::sleep(Duration::from_millis(1500));
    assert_eq!(
        fs::metadata(&marker).unwrap().len(),
        size,
        "a child kept writing after the kill"
    );
    // By pid only where the sandbox shares the host's pid space (macOS); by effect (the
    // marker above) everywhere.
    if cfg!(target_os = "macos") {
        let bg = fs::read_to_string(bfx.rec().join("bg.pid")).unwrap();
        assert!(
            !pid_alive(bg.trim().parse().unwrap()),
            "the background child is still alive"
        );
    }
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
            && let Ok(pgid) = pgid.trim().parse::<u32>()
        {
            signal_group("KILL", pgid);
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
            wait_group_gone(pgid.trim(), GROUP_GONE_WITHIN),
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
            && let Some(pgid) = record["pgid"].as_u64().and_then(|p| u32::try_from(p).ok())
        {
            signal_group("KILL", pgid);
        }
    }
}

/// Kills a group by the pgid read from its record, after the record itself may be gone.
struct PgidReaper(u64);

impl Drop for PgidReaper {
    fn drop(&mut self) {
        if let Ok(pgid) = u32::try_from(self.0) {
            signal_group("KILL", pgid);
        }
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
    assert!(wait_group_gone(&pgid.to_string(), GROUP_GONE_WITHIN));
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
    assert_eq!(json["group"]["signals"][0], "TERM", "{json}");
    // macOS has no pid namespace, so the child that ignores SIGTERM needs the SIGKILL. On
    // Linux the builder runs in bwrap's pid namespace: SIGTERM ends bwrap, and the kernel kills
    // every process in a namespace whose init is gone, so the group may end before the grace.
    #[cfg(target_os = "macos")]
    assert_eq!(json["group"]["signals"], json!(["TERM", "KILL"]), "{json}");

    assert!(
        wait_group_gone(&pgid.to_string(), GROUP_GONE_WITHIN),
        "the group is still alive"
    );
    assert!(!bfx.lane().exists(), "the lane is still there");
    std::thread::sleep(Duration::from_secs(2));
    assert!(!bfx.lane().exists(), "something put the lane back");
    assert!(wait_group_gone(&pgid.to_string(), GROUP_GONE_WITHIN));
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
        pid_alive(pid),
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
        wait_group_gone(&before.to_string(), GROUP_GONE_WITHIN),
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
        wait_group_gone(&pgid.to_string(), GROUP_GONE_WITHIN),
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
    // What the capsule records: no signal, and the command's own time.
    assert!(json["signal"].is_null(), "{json}");
    assert!(json["duration_ms"].is_u64(), "{json}");

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
    assert!(json["signal"].is_null(), "{json}");
    assert!(json["duration_ms"].as_u64().unwrap() >= 1000, "{json}");
}

/// A check that leaves a background subshell: it records its pid and writes a marker after
/// 12 s. A check that was not ended as a whole group lets the marker appear.
const BG_CHECK: &str = "( sleep 12; echo alive > survived ) & echo $! > bgpid; sleep 300";

/// The background subshell is gone: by pid where the sandbox shares the host's pid space
/// (macOS), and by effect everywhere (the marker never appears).
fn assert_check_leftover_ended(clone: &Path, seen_at: Instant) {
    if cfg!(target_os = "macos") {
        let pid: u32 = fs::read_to_string(clone.join("bgpid"))
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while pid_alive(pid) {
            assert!(
                Instant::now() < deadline,
                "the check's child {pid} is alive"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    std::thread::sleep(Duration::from_secs(15).saturating_sub(seen_at.elapsed()));
    assert!(
        !clone.join("survived").exists(),
        "the check's background process outlived the check and wrote its marker"
    );
}

#[test]
fn check_timeout_ends_the_background_process_the_shell_left_behind() {
    if !sandbox_available() {
        return;
    }
    let bfx = Bfx::new("exit 0");
    let clone = bfx.fx.clone_of(&bfx.id);
    let child = bfx.start(&["check", "--check-id", "c-bg"], &check_spec(BG_CHECK, 1));
    let seen_at = Instant::now();
    let out = child.wait_with_output().unwrap();
    let json = json_of(&out);
    assert_eq!(json["timed_out"], true, "{json}");
    assert_check_leftover_ended(&clone, seen_at);
}

#[test]
fn check_ends_its_group_when_the_host_agent_is_signalled() {
    if !sandbox_available() {
        return;
    }
    for signal in ["TERM", "INT"] {
        let bfx = Bfx::new("exit 0");
        let clone = bfx.fx.clone_of(&bfx.id);
        let mut agent = bfx.start(
            &["check", "--check-id", "c-sig"],
            &check_spec(BG_CHECK, 600),
        );
        // `check` reads its spec to the end of its input.
        drop(agent.stdin.take());
        wait_for(&clone.join("bgpid"));
        let seen_at = Instant::now();
        assert!(signal_pid(signal, agent.id()), "could not signal {signal}");
        wait_exit(&mut agent, STOP_WITHIN);
        let out = agent.wait_with_output().unwrap();
        let json = json_of(&out);
        assert_eq!(json["ok"], false, "{signal}: {json}");
        assert_eq!(json["timed_out"], false, "{signal}: {json}");
        assert_check_leftover_ended(&clone, seen_at);
    }
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

// ---------------------------------------------------------------------------
// `host-agent --forced`: what a forced-command key (`command="... host-agent --forced"`)
// runs. sshd puts the client's command in SSH_ORIGINAL_COMMAND; only the closed set of verbs,
// in the form the director writes, gets through.

/// The exit code of a refused forced command (`FORCED_REFUSED_EXIT` in `src/host_agent.rs`).
const FORCED_REFUSED: i32 = 77;

impl Fx {
    /// `cowproof host-agent --forced` with `original` as SSH_ORIGINAL_COMMAND (or none).
    fn forced(&self, original: Option<&str>) -> Output {
        self.forced_with_env(original, &[])
    }

    /// [`Fx::forced`] with more environment variables (`XDG_CONFIG_HOME`, say).
    fn forced_with_env(&self, original: Option<&str>, env: &[(&str, &Path)]) -> Output {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_cowproof"));
        cmd.args(["host-agent", "--forced"])
            .current_dir(self.work.path())
            .env("HOME", self.home.path())
            .env_remove("ANTHROPIC_API_KEY")
            .env_remove("XDG_CONFIG_HOME")
            .env_remove("SSH_ORIGINAL_COMMAND")
            .envs(env.iter().copied())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(original) = original {
            cmd.env("SSH_ORIGINAL_COMMAND", original);
        }
        let child = {
            let _g = fork_lock();
            cmd.spawn().unwrap()
        };
        child.wait_with_output().unwrap()
    }
}

fn assert_forced_refusal(out: &Output) -> String {
    let json = json_of(out);
    assert_eq!(out.status.code(), Some(FORCED_REFUSED), "{json}");
    assert_eq!(json["ok"], false, "{json}");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).lines().count(),
        1,
        "one JSON line"
    );
    let error = json["error"].as_str().expect("an error string");
    assert!(error.starts_with("refused: "), "{error}");
    error.to_string()
}

#[test]
fn forced_runs_the_verb_the_client_asked_for_in_this_process() {
    let fx = Fx::new();
    let claude = fx.work.path().join("fake-claude");
    write_executable(
        &claude,
        "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo \"fake-claude 9.9.9\"; exit 0; fi\nexit 99\n",
    );
    // The owner's config says which claude may run and where the lanes are.
    fx.write_config(&claude, &fx.root);
    // word 0 is not the binary that runs: it only has to be a path named cowproof.
    let asked = format!(
        "/nonexistent dir/it's/cowproof host-agent doctor --claude-bin {} --root {}",
        claude.display(),
        fx.root.display()
    );
    let asked = asked.replacen(
        "/nonexistent dir/it's/cowproof",
        "'/nonexistent dir/it'\\''s/cowproof'",
        1,
    );
    let out = fx.forced(Some(&asked));
    let json = json_of(&out);
    assert_eq!(json["version"], VERSION, "{json}");
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
    // The same exit code as the verb called directly.
    assert_eq!(
        out.status.code(),
        Some(if sandbox_available() { 0 } else { 1 })
    );
    assert!(!fx.root.exists(), "doctor does not create the lanes root");
}

#[test]
fn forced_gives_a_verbs_own_failure_its_own_exit_code() {
    let fx = Fx::new();
    fx.write_config(&fx.work.path().join("claude"), &fx.root);
    let out = fx.forced(Some(&format!(
        "cowproof host-agent cleanup --lane-id ../escape --root {}",
        fx.root.display()
    )));
    // A verb that ran and failed is exit 1 with its JSON error, not a forced-mode refusal.
    assert_eq!(out.status.code(), Some(1));
    let json = json_of(&out);
    assert_eq!(json["ok"], false, "{json}");
    assert!(
        !json["error"].as_str().unwrap().starts_with("refused"),
        "{json}"
    );
}

#[test]
fn forced_refuses_every_command_that_is_not_a_verb_and_runs_nothing() {
    let fx = Fx::new();
    let marker = fx.work.path().join("ran");
    let before = fx.work_entries();
    let asked = [
        "cowproof verify /x".to_string(),
        "bash".to_string(),
        format!("cowproof host-agent doctor; touch {}", marker.display()),
        format!(
            "cowproof host-agent doctor --root {} && touch {}",
            fx.root.display(),
            marker.display()
        ),
        format!("touch {}", marker.display()),
        "cowproof host-agent shell".to_string(),
        "cowproof host-agent --forced doctor".to_string(),
        "cowproof host-agent doctor --forced".to_string(),
        "cowproof-evil host-agent doctor".to_string(),
        "$(id)".to_string(),
        "cowproof host-agent doctor \"x\"".to_string(),
        "cowproof host-agent doctor\ntouch x".to_string(),
        String::new(),
    ];
    for text in &asked {
        let out = fx.forced(Some(text));
        let error = assert_forced_refusal(&out);
        // The message names what was wrong and never quotes the command.
        // (The words the messages themselves use are not a quotation.)
        let own = ["cowproof", "host-agent", "--forced"];
        for word in text.split(' ').filter(|w| w.len() > 5 && !own.contains(w)) {
            assert!(!error.contains(word), "{error:?} quotes {word:?}");
        }
        assert!(
            out.stderr.is_empty(),
            "{:?}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    assert!(!marker.exists(), "a refused command ran");
    assert!(!fx.root.exists());
    assert_eq!(fx.work_entries(), before);
}

#[test]
fn forced_without_a_requested_command_is_an_interactive_login_and_is_refused() {
    let fx = Fx::new();
    let error = assert_forced_refusal(&fx.forced(None));
    assert!(error.contains("interactive login"), "{error}");
    assert_forced_refusal(&fx.forced(Some("")));
}

#[test]
fn forced_is_a_flag_of_host_agent_not_of_a_verb_and_not_combined_with_one() {
    let fx = Fx::new();
    // On the real command line too: `--forced` and a verb together are a usage error.
    let out = fx.agent(&["--forced", "doctor"], None);
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
    // Neither a verb nor `--forced`.
    let out = fx.agent_in(&[], None, None);
    assert_eq!(out.status.code(), Some(2));
    // A verb has no `--forced` of its own.
    let out = fx.agent(&["doctor", "--forced"], None);
    assert_eq!(out.status.code(), Some(2));
}

// ---------------------------------------------------------------------------
// The forced key and the host owner's config (D27 clause 6): `~/.config/cowproof/host.toml`
// decides which `claude` may run and which lanes directory may be used; the director may only
// repeat it.

impl Fx {
    /// The owner's config file in this host's home.
    fn config_file(&self) -> PathBuf {
        self.home.path().join(".config/cowproof/host.toml")
    }

    /// The text of a config naming `claude` and `root`.
    fn config_text(claude: &Path, root: &Path) -> String {
        let quoted = |p: &Path| toml::Value::String(p.to_str().unwrap().to_string()).to_string();
        format!("claude = {}\nroot = {}\n", quoted(claude), quoted(root))
    }

    /// Write the owner's config the way `host setup --write-config` does (file 0600, its
    /// directory 0700) and return its path.
    fn write_config(&self, claude: &Path, root: &Path) -> PathBuf {
        let path = self.config_file();
        let dir = path.parent().unwrap();
        fs::create_dir_all(dir).unwrap();
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(&path, Self::config_text(claude, root)).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        path
    }

    /// An executable that records that it ran, by creating `marker`, and says it is a fake.
    fn marker_claude(&self, name: &str, marker: &Path) -> PathBuf {
        let path = self.work.path().join(name);
        write_executable(
            &path,
            &format!(
                "#!/bin/sh\necho ran > '{}'\nif [ \"$1\" = \"--version\" ]; then echo \"{name} 9.9.9\"; exit 0; fi\nexit 99\n",
                marker.display()
            ),
        );
        path
    }

    /// Everything directly inside this host's home.
    fn home_entries(&self) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(self.home.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }
}

/// The error of a forced refusal (exit 77, one JSON line).
fn forced_refusal_of(fx: &Fx, asked: &str) -> String {
    assert_forced_refusal(&fx.forced(Some(asked)))
}

#[test]
fn forced_doctor_runs_the_configs_claude_not_the_directors() {
    let fx = Fx::new();
    let ran = fx.work.path().join("config-claude-ran");
    let claude = fx.marker_claude("config-claude", &ran);
    fx.write_config(&claude, &fx.root);

    // Without `--claude-bin`: the config's claude is the one checked.
    let out = fx.forced(Some("cowproof host-agent doctor"));
    let json = json_of(&out);
    assert_eq!(json["config"], "ok", "{json}");
    assert_eq!(json["claude"], true, "{json}");
    assert!(
        json["claude_detail"]
            .as_str()
            .unwrap()
            .contains("config-claude 9.9.9"),
        "{json}"
    );
    assert!(ran.exists(), "the configured claude did not run");
    assert_eq!(json["protocol"].to_string(), PROTOCOL, "{json}");
    assert_eq!(json["sandbox"], sandbox_available(), "{json}");
    assert_eq!(
        out.status.code(),
        Some(if sandbox_available() { 0 } else { 1 })
    );

    // The director may repeat the config's values, as it does, and the answer is the same.
    let asked = format!(
        "cowproof host-agent doctor --claude-bin {} --root {}",
        claude.display(),
        fx.root.display()
    );
    let again = json_of(&fx.forced(Some(&asked)));
    assert_eq!(again["config"], "ok", "{again}");
    assert_eq!(again["claude"], true, "{again}");
    assert!(!fx.root.exists(), "doctor does not create the lanes root");
}

#[test]
fn forced_doctor_refuses_a_claude_that_is_not_the_configured_one_and_never_runs_it() {
    let fx = Fx::new();
    let config_ran = fx.work.path().join("config-claude-ran");
    let claude = fx.marker_claude("config-claude", &config_ran);
    fx.write_config(&claude, &fx.root);
    let other_ran = fx.work.path().join("other-ran");
    let other = fx.marker_claude("other-claude", &other_ran);
    let trap = fx.work.path().join("trap-dir");
    fs::create_dir(&trap).unwrap();
    let on_path = fx.marker_claude("claude", &other_ran);
    fs::rename(&on_path, trap.join("claude")).unwrap();

    for given in [
        other.to_str().unwrap().to_string(),
        // The same file by another name is still another name: compared as written.
        format!(
            "{}/../{}/config-claude",
            fx.work.path().display(),
            fx.work.path().file_name().unwrap().to_str().unwrap()
        ),
        // A bare name would be looked up on PATH.
        "claude".to_string(),
        trap.join("claude").to_str().unwrap().to_string(),
    ] {
        let out = fx.forced(Some(&format!(
            "cowproof host-agent doctor --claude-bin {given}"
        )));
        let error = assert_forced_refusal(&out);
        assert!(error.contains("--claude-bin"), "{error}");
        assert!(error.contains("host.toml"), "{error}");
        // The argument is named, its value is not repeated (a bare `claude` is a word of
        // the message itself).
        assert!(given == "claude" || !error.contains(&given), "{error}");
    }
    assert!(!other_ran.exists(), "a claude the director chose ran");
    assert!(
        !config_ran.exists(),
        "nothing runs when the call is refused"
    );
}

#[test]
fn forced_without_a_config_only_doctor_answers_and_nothing_runs() {
    let fx = Fx::new();
    let ran = fx.work.path().join("other-ran");
    let other = fx.marker_claude("other-claude", &ran);
    let home_before = fx.home_entries();

    // doctor says so, with the command the owner runs, and runs no claude at all, whatever
    // `--claude-bin` it was given.
    let out = fx.forced(Some(&format!(
        "cowproof host-agent doctor --claude-bin {}",
        other.display()
    )));
    let json = json_of(&out);
    assert_eq!(out.status.code(), Some(1), "{json}");
    assert_eq!(json["ok"], false, "{json}");
    assert_eq!(json["config"], "missing", "{json}");
    assert_eq!(json["protocol"].to_string(), PROTOCOL, "{json}");
    assert_eq!(json["version"], VERSION, "{json}");
    let fix = json["fix"].as_str().unwrap();
    assert!(fix.ends_with(" host setup --write-config"), "{fix}");
    assert!(fix.contains("cowproof"), "{fix}");
    assert!(
        json["config_detail"]
            .as_str()
            .unwrap()
            .contains(".config/cowproof/host.toml"),
        "{json}"
    );
    assert!(!ran.exists(), "doctor ran a claude with no config");

    // Every other verb is refused, in the form the director writes.
    let sha = "a".repeat(40);
    let root = fx.root.display();
    for asked in [
        format!(
            "cowproof host-agent prepare --lane-id l-1 --base {sha} --director-version {VERSION} --protocol {PROTOCOL} --root {root}"
        ),
        format!("cowproof host-agent builder --lane-id l-1 --root {root}"),
        format!("cowproof host-agent check --lane-id l-1 --check-id c --root {root}"),
        format!("cowproof host-agent patch --lane-id l-1 --root {root}"),
        format!("cowproof host-agent stderr --lane-id l-1 --root {root}"),
        format!("cowproof host-agent cleanup --lane-id l-1 --root {root}"),
        "cowproof host-agent cleanup --lane-id l-1".to_string(),
    ] {
        let error = forced_refusal_of(&fx, &asked);
        assert!(error.contains("missing"), "{error}");
        assert!(error.contains("host setup --write-config"), "{error}");
    }
    assert!(!fx.root.exists());
    assert_eq!(
        fx.home_entries(),
        home_before,
        "a refused call wrote in HOME"
    );
}

#[test]
fn forced_refuses_a_config_that_others_could_have_written() {
    let fx = Fx::new();
    let ran = fx.work.path().join("config-claude-ran");
    let claude = fx.marker_claude("config-claude", &ran);
    let path = fx.write_config(&claude, &fx.root);
    let cleanup = format!(
        "cowproof host-agent cleanup --lane-id l-1 --root {}",
        fx.root.display()
    );

    // Writable by others (0666), by the group (0620): the verbs refuse, naming the problem;
    // doctor reports it and runs no claude.
    for mode in [0o666, 0o620] {
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        let error = forced_refusal_of(&fx, &cleanup);
        assert!(error.contains("invalid"), "{error}");
        assert!(
            error.contains("writable by its group or by others"),
            "{mode:o}: {error}"
        );
        let out = fx.forced(Some("cowproof host-agent doctor"));
        let json = json_of(&out);
        assert_eq!(out.status.code(), Some(1), "{json}");
        assert_eq!(json["config"], "invalid", "{json}");
        assert!(
            json["config_detail"]
                .as_str()
                .unwrap()
                .contains("writable by its group or by others"),
            "{json}"
        );
        assert!(
            json["fix"]
                .as_str()
                .unwrap()
                .ends_with("--write-config --force"),
            "{json}"
        );
        assert!(
            !ran.exists(),
            "doctor ran a claude from an untrusted config"
        );
    }

    // A directory that others can write is as bad: they could swap the file.
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::set_permissions(path.parent().unwrap(), fs::Permissions::from_mode(0o770)).unwrap();
    let error = forced_refusal_of(&fx, &cleanup);
    assert!(
        error.contains("directory") && error.contains("writable"),
        "{error}"
    );
    fs::set_permissions(path.parent().unwrap(), fs::Permissions::from_mode(0o700)).unwrap();

    // A link in place of the file, and a file the parser rejects.
    let real = fx.work.path().join("real-host.toml");
    fs::rename(&path, &real).unwrap();
    symlink(&real, &path).unwrap();
    let error = forced_refusal_of(&fx, &cleanup);
    assert!(error.contains("symbolic link"), "{error}");
    fs::remove_file(&path).unwrap();
    fs::write(&path, "claude = \"relative\"\n").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let error = forced_refusal_of(&fx, &cleanup);
    assert!(error.contains("absolute"), "{error}");

    // Put right, it is trusted again.
    fx.write_config(&claude, &fx.root);
    let json = json_of(&fx.forced(Some("cowproof host-agent doctor")));
    assert_eq!(json["config"], "ok", "{json}");
}

#[test]
fn forced_ignores_xdg_config_home_and_reads_only_the_one_in_home() {
    let fx = Fx::new();
    let xdg = var_tmp("cp-hostagent-xdg-");
    let xdg_ran = fx.work.path().join("xdg-claude-ran");
    let xdg_claude = fx.marker_claude("xdg-claude", &xdg_ran);
    let dir = xdg.path().join("cowproof");
    fs::create_dir(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    let file = dir.join("host.toml");
    fs::write(&file, Fx::config_text(&xdg_claude, &fx.root)).unwrap();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
    let xdg_env = [("XDG_CONFIG_HOME", xdg.path())];

    // Nothing in HOME: a valid file in XDG_CONFIG_HOME does not count. The client cannot set
    // HOME through sshd's AcceptEnv the way it can set XDG_*.
    let doctor = "cowproof host-agent doctor";
    let out = fx.forced_with_env(Some(doctor), &xdg_env);
    let json = json_of(&out);
    assert_eq!(out.status.code(), Some(1), "{json}");
    assert_eq!(json["config"], "missing", "{json}");
    assert!(
        json["config_detail"]
            .as_str()
            .unwrap()
            .contains(&fx.home.path().display().to_string()),
        "{json}"
    );
    let asked = format!(
        "cowproof host-agent cleanup --lane-id l-1 --root {}",
        fx.root.display()
    );
    let error = assert_forced_refusal(&fx.forced_with_env(Some(&asked), &xdg_env));
    assert!(error.contains("missing"), "{error}");

    // A different valid file in HOME: that one is the config, and the XDG one never runs.
    let home_ran = fx.work.path().join("home-claude-ran");
    let home_claude = fx.marker_claude("home-claude", &home_ran);
    fx.write_config(&home_claude, &fx.root);
    for env in [&xdg_env[..], &[]] {
        let json = json_of(&fx.forced_with_env(Some(doctor), env));
        assert_eq!(json["config"], "ok", "{json}");
        assert!(
            json["claude_detail"]
                .as_str()
                .unwrap()
                .contains("home-claude 9.9.9"),
            "{json}"
        );
    }
    assert!(home_ran.exists());
    assert!(!xdg_ran.exists(), "the claude of the XDG file ran");
    // The director cannot name the XDG file's claude either.
    let out = fx.forced_with_env(
        Some(&format!(
            "cowproof host-agent doctor --claude-bin {}",
            xdg_claude.display()
        )),
        &xdg_env,
    );
    let error = assert_forced_refusal(&out);
    assert!(error.contains("--claude-bin"), "{error}");
    assert!(!xdg_ran.exists(), "the claude of the XDG file ran");
}

#[test]
fn forced_refuses_a_config_that_lies_under_the_lanes_root() {
    let fx = Fx::new();
    let ran = fx.work.path().join("config-claude-ran");
    let claude = fx.marker_claude("config-claude", &ran);
    let cleanup = |root: &Path| {
        format!(
            "cowproof host-agent cleanup --lane-id l-1 --root {}",
            root.display()
        )
    };

    // The lanes root is a directory that holds the config (here the home itself): whatever a
    // lane holds, the director filled, so the config could be one of its files.
    fx.write_config(&claude, fx.home.path());
    let error = forced_refusal_of(&fx, &cleanup(fx.home.path()));
    assert!(
        error.contains("invalid") && error.contains("lanes root"),
        "{error}"
    );
    let out = fx.forced(Some("cowproof host-agent doctor"));
    let json = json_of(&out);
    assert_eq!(json["config"], "invalid", "{json}");
    assert!(
        json["config_detail"]
            .as_str()
            .unwrap()
            .contains("lanes root"),
        "{json}"
    );
    assert!(
        !ran.exists(),
        "doctor ran a claude from a config in the lanes root"
    );

    // Through a link to the root, and as a root that is the config's own directory.
    let link = fx.work.path().join("home-link");
    symlink(fx.home.path(), &link).unwrap();
    fx.write_config(&claude, &link);
    assert!(forced_refusal_of(&fx, &cleanup(&link)).contains("lanes root"));
    let own_dir = fx.home.path().join(".config/cowproof");
    fx.write_config(&claude, &own_dir);
    assert!(forced_refusal_of(&fx, &cleanup(&own_dir)).contains("lanes root"));

    // The default remote root counts even when the config names another root: with `~/.config`
    // reaching into it, the config is a file a lane could hold.
    let inside = fx.home.path().join(".cache/cowproof/remote-lanes/cfg");
    fs::remove_dir_all(fx.home.path().join(".config")).unwrap();
    fs::create_dir_all(&inside).unwrap();
    symlink(&inside, fx.home.path().join(".config")).unwrap();
    fx.write_config(&claude, &fx.root);
    let error = forced_refusal_of(&fx, &cleanup(&fx.root));
    assert!(error.contains("lanes root"), "{error}");
    fs::remove_file(fx.home.path().join(".config")).unwrap();
    fs::remove_dir_all(fx.home.path().join(".cache")).unwrap();

    // A root beside the config, not above it, is fine.
    let sibling = fx.home.path().join("lanes");
    fx.write_config(&claude, &sibling);
    let json = json_of(&fx.forced(Some("cowproof host-agent doctor")));
    assert_eq!(json["config"], "ok", "{json}");
}

#[test]
fn forced_root_must_be_the_configured_one_for_every_verb() {
    let fx = Fx::new();
    let claude = fx.work.path().join("claude");
    write_executable(&claude, "#!/bin/sh\nexit 0\n");
    fx.write_config(&claude, &fx.root);

    // Another lanes directory the host user can write, holding a lane that must survive.
    let other = fx.work.path().join("somewhere-else");
    let victim = other.join("victim");
    fs::create_dir_all(victim.join("control")).unwrap();
    fs::write(victim.join("precious.txt"), "keep\n").unwrap();
    let sha = "a".repeat(40);
    for given in [
        other.display().to_string(),
        // Relative to the working directory, which is not the configured root either.
        "somewhere-else".to_string(),
        format!("{}/../somewhere-else", fx.root.display()),
    ] {
        for asked in [
            format!("cowproof host-agent cleanup --lane-id victim --root {given}"),
            format!("cowproof host-agent patch --lane-id victim --root {given}"),
            format!("cowproof host-agent stderr --lane-id victim --root {given}"),
            format!("cowproof host-agent builder --lane-id victim --root {given}"),
            format!("cowproof host-agent check --lane-id victim --check-id c --root {given}"),
            format!("cowproof host-agent doctor --root {given}"),
            format!(
                "cowproof host-agent prepare --lane-id fresh --base {sha} --director-version {VERSION} --protocol {PROTOCOL} --root {given}"
            ),
        ] {
            let error = forced_refusal_of(&fx, &asked);
            assert!(error.contains("--root"), "{asked}: {error}");
            assert!(error.contains("host.toml"), "{error}");
            assert!(!error.contains(&given), "{error}");
        }
    }
    // Nothing under the other root was touched, and nothing was made under it or the real one.
    assert_eq!(
        fs::read_to_string(victim.join("precious.txt")).unwrap(),
        "keep\n"
    );
    assert!(victim.join("control").is_dir());
    assert!(!other.join("fresh").exists());
    assert!(!fx.root.exists());

    // The configured root applies when `--root` is left out, and when it is repeated.
    assert_ok(&fx.prepare("lane-a", &[]));
    assert_ok(&fx.prepare("lane-b", &[]));
    let out = fx.forced(Some("cowproof host-agent cleanup --lane-id lane-a"));
    assert_eq!(json_of(&out)["removed"], true);
    let out = fx.forced(Some(&format!(
        "cowproof host-agent cleanup --lane-id lane-b --root {}",
        fx.root.display()
    )));
    assert_eq!(json_of(&out)["removed"], true);
    assert!(!fx.root.join("lane-a").exists() && !fx.root.join("lane-b").exists());
}

impl Bfx {
    /// `host-agent --forced` asked to run `builder` for this lane, with `spec` on stdin and the
    /// lifeline held open until it ends. The owner's config must already be in place.
    fn forced_builder(&self, spec: &Value) -> Output {
        let asked = format!(
            "{} host-agent builder --lane-id {} --root {}",
            self.cowproof.display(),
            self.id,
            self.fx.root.display()
        );
        let mut cmd = Command::new(&self.cowproof);
        cmd.args(["host-agent", "--forced"])
            .current_dir(self.fx.work.path())
            .env("HOME", self.fx.home.path())
            .env_remove("ANTHROPIC_API_KEY")
            .env_remove("XDG_CONFIG_HOME")
            .env("SSH_ORIGINAL_COMMAND", asked)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = {
            let _g = fork_lock();
            cmd.spawn().unwrap()
        };
        let pipe = child.stdin.as_mut().unwrap();
        let _ = pipe.write_all(format!("{spec}\n").as_bytes());
        let _ = pipe.flush();
        let lifeline = child.stdin.take();
        let out = child.wait_with_output().unwrap();
        drop(lifeline);
        out
    }
}

#[test]
fn forced_builder_refuses_a_claude_that_is_not_the_configured_one_and_launches_nothing() {
    if !sandbox_available() {
        return;
    }
    let bfx = Bfx::new("echo started > \"$rec/started\"\nexit 0");
    bfx.fx.write_config(&bfx.fake, &bfx.fx.root);
    let ran = bfx.fx.work.path().join("other-ran");
    let other = bfx.fx.marker_claude("other-claude", &ran);

    for given in [
        json!(other),
        // Not even a spelling of the configured file, and not an absolute path at all.
        json!(format!(
            "{}/../{}/fake-claude",
            bfx.fake.parent().unwrap().display(),
            bfx.fake
                .parent()
                .unwrap()
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
        )),
        json!("claude"),
    ] {
        let mut spec = bfx.spec();
        spec["claude_bin"] = given.clone();
        let out = bfx.forced_builder(&spec);
        let error = assert_forced_refusal(&out);
        assert!(error.contains("claude_bin"), "{error}");
        assert!(error.contains("host.toml"), "{error}");
        let given = given.as_str().unwrap();
        assert!(given == "claude" || !error.contains(given), "{error}");
    }
    assert!(!ran.exists(), "a claude the director chose ran");
    assert!(!bfx.rec().exists(), "the configured claude started too");
    let control = bfx.lane().join("control");
    assert!(
        !control.join("builder.group.json").exists(),
        "a builder group was recorded"
    );
    assert!(!control.join("builder.stderr").exists());
    // The lane files were not rewritten either.
    assert!(!bfx.lane().join("home/settings.json").exists());

    // The configured claude, in the same call, runs: the pin is the only difference.
    let out = bfx.forced_builder(&bfx.spec());
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(bfx.recorded("started").trim(), "started");
    assert!(!ran.exists());
}
