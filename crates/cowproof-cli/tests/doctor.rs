//! `cowproof doctor` and the preflight `cowproof run` starts with.
//!
//! Every test drives the real `cowproof` binary against its own temporary directories
//! under `/var/tmp` (the repository, the lanes root, a `HOME`, a fake `claude`), with
//! the working directory set to one of them, so nothing here writes into the source
//! tree: Cargo runs integration tests with the package directory as the working
//! directory, and an earlier version of the claude check ran the fake builders of
//! `tests/run.rs` from there. Nothing reads the real `HOME` or an API key's value;
//! the key is a synthetic string.
//!
//! The sandbox check is forced to fail through the one seam its launch really has: the
//! launcher (`sandbox-exec`, `bwrap`) is found on the builder's `PATH`, so a `PATH` with
//! no launcher on it makes the launch fail the way a host without one would.

#[allow(dead_code, reason = "this file needs only a few of the shared helpers")]
mod common;

use common::{fork_lock, git, output, sandbox_available, text, var_tmp};
use serde_json::Value;
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tempfile::TempDir;

const KEY: &str = "sk-test-doctor-synthetic";

/// A repository with a commit, an absent lanes root, a `HOME`, a packet and a fake
/// `claude` that answers `--version` and nothing else.
struct Fixture {
    work: TempDir,
    home: TempDir,
    repo: PathBuf,
    /// Not created: the preflight must not create it.
    lanes: PathBuf,
    packet: PathBuf,
    claude: PathBuf,
}

fn write_executable(path: &Path, script: &str) {
    let _g = fork_lock();
    fs::write(path, script).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

impl Fixture {
    fn new() -> Self {
        let work = var_tmp("cp-doctor-work-");
        let home = var_tmp("cp-doctor-home-");
        let repo = work.path().join("repo");
        fs::create_dir(&repo).unwrap();
        git(&repo, &["init", "-q"]);
        git(&repo, &["config", "user.email", "t@example.com"]);
        git(&repo, &["config", "user.name", "T"]);
        fs::write(repo.join("README.md"), "base\n").unwrap();
        git(&repo, &["add", "."]);
        git(&repo, &["commit", "-q", "-m", "base"]);

        let packet = work.path().join("packet.md");
        fs::write(
            &packet,
            r#"# Task

<!-- lane {"id":"t-doctor","owns":["README.md"],"class":"light","checks":[{"id":"ok","command":"true"}]} -->

Change the README.
"#,
        )
        .unwrap();

        // Records its arguments next to itself; anything but `--version` is a failure.
        let claude = work.path().join("fake-claude");
        write_executable(
            &claude,
            r#"#!/bin/sh
printf '%s\n' "$*" >> "$(dirname "$0")/claude-argv"
if [ "$1" = "--version" ]; then echo "fake-claude 9.9.9"; exit 0; fi
echo "unexpected arguments: $*" >&2
exit 99
"#,
        );
        let lanes = work.path().join("lanes");
        Fixture {
            work,
            home,
            repo,
            lanes,
            packet,
            claude,
        }
    }

    /// `cowproof` with its own `HOME`, the work directory as the working directory, no
    /// API key and the ordinary `PATH`.
    fn cowproof(&self) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_cowproof"));
        c.current_dir(self.work.path())
            .env("HOME", self.home.path())
            .env_remove("ANTHROPIC_API_KEY");
        c
    }

    /// `cowproof doctor` with the fixture's repository, lanes root and fake claude, and
    /// a floor that any disk clears.
    fn doctor(&self) -> Command {
        self.doctor_with(&self.repo, &self.claude, "0.001")
    }

    fn doctor_with(&self, repo: &Path, claude: &Path, floor_gb: &str) -> Command {
        let mut c = self.cowproof();
        c.arg("doctor")
            .arg("--repo")
            .arg(repo)
            .arg("--lanes-root")
            .arg(&self.lanes)
            .arg("--claude-bin")
            .arg(claude)
            .args(["--disk-floor-gb", floor_gb]);
        c
    }

    /// `cowproof run` with the synthetic key set.
    fn run(&self) -> Command {
        self.run_with(&self.repo, &self.claude, "0.001")
    }

    fn run_with(&self, repo: &Path, claude: &Path, floor_gb: &str) -> Command {
        let mut c = self.cowproof();
        c.arg("run")
            .arg(&self.packet)
            .arg("--repo")
            .arg(repo)
            .arg("--lanes-root")
            .arg(&self.lanes)
            .arg("--claude-bin")
            .arg(claude)
            .args(["--disk-floor-gb", floor_gb])
            .env("ANTHROPIC_API_KEY", KEY);
        c
    }

    /// A `PATH` directory with `cp`, `df` and `git` and no sandbox launcher.
    fn path_without_a_sandbox_launcher(&self) -> String {
        let bin = self.work.path().join("bin");
        fs::create_dir_all(&bin).unwrap();
        for tool in ["cp", "df", "git"] {
            let found = std::env::split_paths(&std::env::var_os("PATH").unwrap())
                .map(|d| d.join(tool))
                .find(|p| p.is_file())
                .unwrap_or_else(|| panic!("{tool} is not on PATH"));
            if !bin.join(tool).exists() {
                symlink(found, bin.join(tool)).unwrap();
            }
        }
        bin.to_string_lossy().into_owned()
    }

    /// What `cowproof` must have left behind after a preflight: nothing next to the
    /// lanes root, and the lanes root itself either absent or empty.
    fn assert_nothing_left(&self) {
        let parent = self.lanes.parent().unwrap();
        let leftovers: Vec<_> = fs::read_dir(parent)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains("preflight"))
            .collect();
        assert!(leftovers.is_empty(), "probe left behind: {leftovers:?}");
        if self.lanes.exists() {
            assert_eq!(fs::read_dir(&self.lanes).unwrap().count(), 0);
        }
    }
}

/// `name: status - detail` lines of `doctor`'s stdout.
fn lines(out: &Output) -> Vec<String> {
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::to_string)
        .collect()
}

fn line<'a>(lines: &'a [String], name: &str) -> &'a str {
    lines
        .iter()
        .find(|l| l.starts_with(&format!("{name}: ")))
        .unwrap_or_else(|| panic!("no {name} line in {lines:?}"))
}

fn code(out: &Output) -> i32 {
    out.status.code().unwrap_or(-1)
}

/// A `cowproof run` that the preflight stopped: exit 4, the failing check named, and no
/// lane, clone or socket (the lanes root is absent or empty, no probe is left).
fn assert_run_stopped(f: &Fixture, out: &Output, check: &str) {
    assert_eq!(code(out), 4, "{}", text(out));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains(&format!("preflight failed: {check}:")),
        "{}",
        text(out)
    );
    f.assert_nothing_left();
}

#[test]
fn doctor_prints_one_line_per_check_and_exits_0_on_a_healthy_host() {
    if !sandbox_available() {
        return;
    }
    let f = Fixture::new();
    let out = output(f.doctor().env("ANTHROPIC_API_KEY", KEY));
    assert_eq!(code(&out), 0, "{}", text(&out));
    let lines = lines(&out);
    let names: Vec<&str> = lines.iter().map(|l| l.split(':').next().unwrap()).collect();
    assert_eq!(names, ["sandbox", "clone", "disk", "claude", "key", "git"]);
    assert!(
        line(&lines, "sandbox").starts_with("sandbox: ok"),
        "{lines:?}"
    );
    // Copy-on-write is ok, a plain copy is a warning: either way the lane can start.
    assert!(
        line(&lines, "clone").starts_with("clone: ok")
            || line(&lines, "clone").starts_with("clone: warn"),
        "{lines:?}"
    );
    assert!(line(&lines, "disk").starts_with("disk: ok"), "{lines:?}");
    assert!(
        line(&lines, "claude").starts_with("claude: ok - fake-claude 9.9.9"),
        "{lines:?}"
    );
    assert!(line(&lines, "key").starts_with("key: ok"), "{lines:?}");
    assert!(line(&lines, "git").starts_with("git: ok"), "{lines:?}");
    assert!(!String::from_utf8_lossy(&out.stdout).contains(KEY));
    // The lanes root was not created for the probes.
    assert!(!f.lanes.exists());
    f.assert_nothing_left();
    // The builder was asked for its version and nothing else, from its own directory.
    let argv = fs::read_to_string(f.work.path().join("claude-argv")).unwrap();
    assert_eq!(argv.trim(), "--version");
}

#[test]
fn doctor_json_is_one_object_per_check() {
    let f = Fixture::new();
    let out = output(f.doctor().arg("--json"));
    let lines = lines(&out);
    assert_eq!(lines.len(), 6, "{}", text(&out));
    let mut names = Vec::new();
    for l in &lines {
        let v: Value = serde_json::from_str(l).unwrap_or_else(|e| panic!("{l}: {e}"));
        assert!(
            ["ok", "warn", "fail"].contains(&v["status"].as_str().unwrap()),
            "{l}"
        );
        assert!(!v["detail"].as_str().unwrap().is_empty(), "{l}");
        names.push(v["name"].as_str().unwrap().to_string());
    }
    assert_eq!(names, ["sandbox", "clone", "disk", "claude", "key", "git"]);
}

#[test]
fn doctor_warns_but_exits_0_without_a_key() {
    if !sandbox_available() {
        return;
    }
    let f = Fixture::new();
    let out = output(&mut f.doctor());
    assert_eq!(code(&out), 0, "{}", text(&out));
    assert!(
        line(&lines(&out), "key").starts_with("key: warn"),
        "{}",
        text(&out)
    );
}

#[test]
fn doctor_exits_1_and_names_the_disk_when_the_floor_is_not_met() {
    let f = Fixture::new();
    let out = output(&mut f.doctor_with(&f.repo, &f.claude, "1000000"));
    assert_eq!(code(&out), 1, "{}", text(&out));
    assert!(
        line(&lines(&out), "disk").starts_with("disk: fail"),
        "{}",
        text(&out)
    );
    f.assert_nothing_left();
}

#[test]
fn doctor_fails_the_git_check_without_a_repository_or_without_a_commit() {
    let f = Fixture::new();
    // Not a repository.
    let plain = f.work.path().join("plain");
    fs::create_dir(&plain).unwrap();
    let out = output(&mut f.doctor_with(&plain, &f.claude, "0.001"));
    assert_eq!(code(&out), 1, "{}", text(&out));
    assert!(
        line(&lines(&out), "git").starts_with("git: fail"),
        "{}",
        text(&out)
    );
    // A repository whose HEAD has no commit.
    let empty = f.work.path().join("empty");
    fs::create_dir(&empty).unwrap();
    git(&empty, &["init", "-q"]);
    let out = output(&mut f.doctor_with(&empty, &f.claude, "0.001"));
    assert_eq!(code(&out), 1, "{}", text(&out));
    assert!(
        line(&lines(&out), "git").starts_with("git: fail"),
        "{}",
        text(&out)
    );
}

#[test]
fn doctor_fails_the_claude_check_for_a_missing_binary_and_for_one_that_cannot_report_a_version() {
    let f = Fixture::new();
    let out = output(&mut f.doctor_with(&f.repo, Path::new("/nonexistent/claude"), "0.001"));
    assert_eq!(code(&out), 1, "{}", text(&out));
    assert!(
        line(&lines(&out), "claude").starts_with("claude: fail"),
        "{}",
        text(&out)
    );

    let broken = f.work.path().join("broken-claude");
    write_executable(&broken, "#!/bin/sh\nexit 3\n");
    let out = output(&mut f.doctor_with(&f.repo, &broken, "0.001"));
    assert_eq!(code(&out), 1, "{}", text(&out));
    assert!(
        line(&lines(&out), "claude").starts_with("claude: fail"),
        "{}",
        text(&out)
    );
}

#[test]
fn doctor_fails_the_sandbox_check_when_the_launcher_cannot_be_started() {
    let f = Fixture::new();
    let path = f.path_without_a_sandbox_launcher();
    let out = output(f.doctor().arg("--json").env("PATH", &path));
    assert_eq!(code(&out), 1, "{}", text(&out));
    let lines = lines(&out);
    let by_name = |name: &str| -> Value {
        let l = lines
            .iter()
            .find(|l| l.contains(&format!("\"name\":\"{name}\"")))
            .unwrap_or_else(|| panic!("no {name} in {lines:?}"));
        serde_json::from_str(l).unwrap()
    };
    let sandbox = by_name("sandbox");
    assert_eq!(sandbox["status"], "fail", "{lines:?}");
    let launcher = if cfg!(target_os = "macos") {
        "sandbox-exec"
    } else {
        "bwrap"
    };
    assert!(
        sandbox["detail"].as_str().unwrap().contains(launcher),
        "{sandbox}"
    );
    // Only the sandbox failed: the other tools were on the PATH.
    for name in ["disk", "claude", "git"] {
        assert_eq!(by_name(name)["status"], "ok", "{name}: {lines:?}");
    }
}

#[test]
fn run_stops_before_any_lane_when_the_disk_floor_is_not_met() {
    let f = Fixture::new();
    let out = output(&mut f.run_with(&f.repo, &f.claude, "1000000"));
    assert_run_stopped(&f, &out, "disk");
    assert!(!f.lanes.exists());
}

#[test]
fn run_stops_before_any_lane_without_an_api_key() {
    let f = Fixture::new();
    let out = output(f.run().env_remove("ANTHROPIC_API_KEY"));
    assert_run_stopped(&f, &out, "key");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("ANTHROPIC_API_KEY is not set"),
        "{}",
        text(&out)
    );
    assert!(!f.lanes.exists());
}

#[test]
fn run_stops_before_any_lane_with_an_empty_api_key() {
    let f = Fixture::new();
    let out = output(f.run().env("ANTHROPIC_API_KEY", ""));
    assert_run_stopped(&f, &out, "key");
    assert!(!f.lanes.exists());
}

#[test]
fn run_stops_before_any_lane_when_claude_cannot_be_found() {
    let f = Fixture::new();
    // The lanes root exists but is empty: it must stay empty.
    fs::create_dir(&f.lanes).unwrap();
    let out = output(&mut f.run_with(&f.repo, Path::new("/nonexistent/claude"), "0.001"));
    assert_run_stopped(&f, &out, "claude");
}

#[test]
fn run_stops_before_any_lane_when_the_sandbox_cannot_start() {
    let f = Fixture::new();
    let path = f.path_without_a_sandbox_launcher();
    let out = output(f.run().env("PATH", &path));
    assert_run_stopped(&f, &out, "sandbox");
    assert!(!f.lanes.exists());
}

#[test]
fn run_stops_before_any_lane_when_the_repository_has_no_commit() {
    let f = Fixture::new();
    let empty = f.work.path().join("empty");
    fs::create_dir(&empty).unwrap();
    git(&empty, &["init", "-q"]);
    let out = output(&mut f.run_with(&empty, &f.claude, "0.001"));
    assert_run_stopped(&f, &out, "git");
}
