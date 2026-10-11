//! The infrastructure preflight, shared by `cowproof doctor` and `cowproof run`.
//!
//! [`preflight`] returns one [`Check`] per precondition, in a fixed order: `sandbox`,
//! `clone`, `disk`, `claude`, `key`, `git`. `doctor` prints them all; `run` stops on any
//! failure (fail closed, `docs/design.md`), before it creates a lane directory, a
//! clone or a socket.
//!
//! The checks use the same code paths a lane does, so a pass means the lane can start,
//! not that a tool is installed: the sandbox check runs `true` through the runner's own
//! `sandboxed_command` with a real `SandboxPolicy`, and the clone check copies with the
//! strategies `prepare_lane` uses. Nothing here is created under the lanes root: the
//! probes live in one throwaway directory next to it (inside its nearest existing
//! ancestor, so on the same filesystem), which is removed before `preflight` returns.

use crate::root::resolve_executable;
use crate::run::{builder_path, sandboxed_command};
use cowproof_run::{LaneLayout, SandboxPolicy, lane::probe_clone_method};
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

/// How long the sandboxed `true` and `claude --version` may take before the check fails.
const LAUNCH_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckStatus {
    Ok,
    /// Reported; does not stop `run`.
    Warn,
    /// Stops `run`; makes `doctor` exit 1.
    Fail,
}

impl CheckStatus {
    pub fn label(self) -> &'static str {
        match self {
            CheckStatus::Ok => "ok",
            CheckStatus::Warn => "warn",
            CheckStatus::Fail => "fail",
        }
    }
}

/// One precondition: its name, whether it holds, and one line saying why.
#[derive(Debug, Clone, Serialize)]
pub struct Check {
    pub name: &'static str,
    pub status: CheckStatus,
    pub detail: String,
}

impl Check {
    fn new(name: &'static str, status: CheckStatus, detail: impl Into<String>) -> Self {
        Check {
            name,
            status,
            detail: detail.into(),
        }
    }
    fn ok(name: &'static str, detail: impl Into<String>) -> Self {
        Self::new(name, CheckStatus::Ok, detail)
    }
    fn warn(name: &'static str, detail: impl Into<String>) -> Self {
        Self::new(name, CheckStatus::Warn, detail)
    }
    fn fail(name: &'static str, detail: impl Into<String>) -> Self {
        Self::new(name, CheckStatus::Fail, detail)
    }
}

/// What the checks look at.
pub struct PreflightOptions<'a> {
    /// The repository the lane would be cut from (must have a committed HEAD).
    pub repo: &'a Path,
    /// The lanes root. It need not exist, and the preflight never creates it.
    pub lanes_root: &'a Path,
    /// Free space, in GB, below which the `disk` check fails.
    pub disk_floor_gb: f64,
    /// The builder executable as the user gave it: a name searched on `director_path`,
    /// or a path relative to `cwd`.
    pub claude_bin: &'a str,
    /// The director's `PATH`; the sandbox launcher is found on the builder's `PATH`
    /// derived from it, exactly as in a run.
    pub director_path: &'a str,
    pub cwd: &'a Path,
    pub real_home: &'a Path,
    /// A missing `ANTHROPIC_API_KEY` is a failure for `run` and a warning for `doctor`.
    pub for_run: bool,
}

/// Run every check. Never panics and never returns early: each check reports for itself.
pub async fn preflight(opts: &PreflightOptions<'_>) -> Vec<Check> {
    let existing = nearest_existing_dir(opts.lanes_root);
    let probe = Probe::create(&existing);
    let (sandbox, clone) = match &probe {
        Ok(probe) => (check_sandbox(probe, opts).await, check_clone(probe)),
        Err(why) => (Check::fail("sandbox", why), Check::fail("clone", why)),
    };
    vec![
        sandbox,
        clone,
        check_disk(&existing, opts.disk_floor_gb),
        check_claude(opts).await,
        check_api_key(opts.for_run),
        check_git(opts.repo),
    ]
}

/// The deepest existing directory on the way to `path` (`path` itself when it exists).
/// The probes and the free-space reading go there, so the lanes root is not created.
fn nearest_existing_dir(path: &Path) -> PathBuf {
    path.ancestors()
        .find(|p| p.is_dir())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("/"))
}

/// A directory this preflight created, removed when it is dropped. Only the exact
/// directory it made is removed (it is created with `create_dir`, so an existing
/// entry of the same name is an error, never reused).
struct Probe {
    root: PathBuf,
}

impl Probe {
    fn create(parent: &Path) -> Result<Probe, String> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let made = parent.join(format!(
            ".cowproof-preflight-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir(&made)
            .map_err(|e| format!("cannot write under {}: {e}", parent.display()))?;
        // Canonical, like the lanes root a run uses, so the sandbox grants name real paths.
        match fs::canonicalize(&made) {
            Ok(root) => Ok(Probe { root }),
            Err(e) => {
                let _ = fs::remove_dir(&made);
                Err(format!("cannot resolve {}: {e}", made.display()))
            }
        }
    }
}

impl Drop for Probe {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

/// How the sandboxed `true` ended, as far as the verdict cares.
#[derive(Debug)]
enum SandboxLaunch {
    /// The launcher ran and the program exited: `code` is `None` for a signal.
    Ran {
        code: Option<i32>,
        stderr: String,
    },
    /// The policy did not render, or the launcher did not start.
    CouldNotStart(String),
    TimedOut,
}

/// Map a launch to a check. Only an exit status of 0 from the program, run by the
/// launcher, passes; a launcher that exists but refuses (no user namespaces, a denied
/// `sandbox-exec`) exits non-zero and fails, as does one that never starts.
fn sandbox_verdict(launch: SandboxLaunch, program: &str, launcher: &str) -> Check {
    match launch {
        SandboxLaunch::Ran { code: Some(0), .. } => {
            Check::ok("sandbox", format!("{program} ran under {launcher}"))
        }
        SandboxLaunch::Ran { code, stderr } => {
            let why = stderr.lines().next().unwrap_or("").trim();
            let status = code.map_or("a signal".to_string(), |c| format!("exit {c}"));
            Check::fail(
                "sandbox",
                if why.is_empty() {
                    format!("{launcher} ran {program} and it ended with {status}")
                } else {
                    format!("{launcher} ran {program} and it ended with {status}: {why}")
                },
            )
        }
        SandboxLaunch::CouldNotStart(why) => Check::fail("sandbox", why),
        SandboxLaunch::TimedOut => Check::fail(
            "sandbox",
            format!("{launcher} did not finish {program} in {LAUNCH_TIMEOUT:?}"),
        ),
    }
}

/// Run `true` under the runner's own sandbox code with a real, minimal policy (the
/// `capture` policy: write the clone and scratch, no network), in a lane layout under
/// the probe directory.
async fn check_sandbox(probe: &Probe, opts: &PreflightOptions<'_>) -> Check {
    let program = if cfg!(target_os = "macos") {
        "/usr/bin/true"
    } else {
        "/bin/true"
    };
    let launcher = if cfg!(target_os = "macos") {
        "sandbox-exec"
    } else {
        "bwrap"
    };
    let lane = probe.root.join("lane");
    let layout = LaneLayout {
        clone: lane.join("clone"),
        home: lane.join("home"),
        scratch: lane.join("scratch"),
        control: lane.join("control"),
        real_home: opts.real_home.to_path_buf(),
        sock: lane.join("sock/runner.sock"),
        lanes_root: probe.root.clone(),
    };
    for dir in [
        &layout.clone,
        &layout.home,
        &layout.scratch,
        &layout.control,
    ] {
        if let Err(e) = fs::create_dir_all(dir) {
            return Check::fail("sandbox", format!("cannot create {}: {e}", dir.display()));
        }
    }
    let policy = SandboxPolicy::capture(&layout);
    // The builder's PATH, as in a run: the launcher is found on it.
    let env = vec![(
        "PATH".to_string(),
        builder_path(opts.director_path, opts.real_home),
    )];
    let mut command = match sandboxed_command(
        &policy,
        &layout.control.join("preflight.sb"),
        &[program.to_string()],
        env,
        &layout.clone,
    ) {
        Ok(command) => command,
        Err(e) => {
            return sandbox_verdict(
                SandboxLaunch::CouldNotStart(format!("cannot build the sandbox: {e:#}")),
                program,
                launcher,
            );
        }
    };
    let launch = match tokio::time::timeout(LAUNCH_TIMEOUT, command.output()).await {
        Err(_) => SandboxLaunch::TimedOut,
        Ok(Err(e)) => SandboxLaunch::CouldNotStart(format!(
            "cannot start {launcher} on the builder's PATH: {e}"
        )),
        Ok(Ok(out)) => SandboxLaunch::Ran {
            code: out.status.code(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        },
    };
    sandbox_verdict(launch, program, launcher)
}

/// The copy strategy a lane would use here. Copy-on-write is ok; a full copy still
/// works, so it only warns.
fn check_clone(probe: &Probe) -> Check {
    match probe_clone_method(&probe.root) {
        Ok(method) if method == "copy" => Check::warn(
            "clone",
            "no copy-on-write here: each lane is a full copy of the object store (copy)",
        ),
        Ok(method) => Check::ok("clone", format!("{method} works on the lanes filesystem")),
        Err(e) => Check::fail("clone", format!("no copy strategy works here: {e:#}")),
    }
}

const GB: f64 = 1024.0 * 1024.0 * 1024.0;

/// Free space against the floor. Equal to the floor passes.
fn disk_verdict(free_bytes: u64, floor_gb: f64, dir: &Path) -> Check {
    if !floor_gb.is_finite() || floor_gb < 0.0 {
        return Check::fail(
            "disk",
            format!("--disk-floor-gb must be a number of GB, 0 or more (got {floor_gb})"),
        );
    }
    let free_gb = free_bytes as f64 / GB;
    if (free_bytes as f64) < floor_gb * GB {
        Check::fail(
            "disk",
            format!(
                "{free_gb:.1} GB free under {}, below the {floor_gb} GB floor",
                dir.display()
            ),
        )
    } else {
        Check::ok(
            "disk",
            format!("{free_gb:.1} GB free (floor {floor_gb} GB)"),
        )
    }
}

/// The "Available" column of `df -Pk` output, in KiB. The columns are read from the
/// capacity column (`NN%`) backwards, so a filesystem or mount name with spaces in it
/// does not shift them.
fn parse_df_available_kib(output: &str) -> Option<u64> {
    let line = output.lines().filter(|l| !l.trim().is_empty()).nth(1)?;
    let fields: Vec<&str> = line.split_whitespace().collect();
    let capacity = fields
        .iter()
        .position(|f| f.len() > 1 && f.ends_with('%') && f[..f.len() - 1].parse::<u32>().is_ok())?;
    fields.get(capacity.checked_sub(1)?)?.parse().ok()
}

fn check_disk(dir: &Path, floor_gb: f64) -> Check {
    let out = match std::process::Command::new("df")
        .arg("-Pk")
        .arg(dir)
        .stdin(Stdio::null())
        .output()
    {
        Ok(out) if out.status.success() => out,
        Ok(out) => {
            return Check::fail(
                "disk",
                format!("df {} failed: {}", dir.display(), out.status),
            );
        }
        Err(e) => return Check::fail("disk", format!("cannot run df: {e}")),
    };
    match parse_df_available_kib(&String::from_utf8_lossy(&out.stdout)) {
        Some(kib) => disk_verdict(kib.saturating_mul(1024), floor_gb, dir),
        None => Check::fail(
            "disk",
            format!("cannot read the free space of {}", dir.display()),
        ),
    }
}

/// The builder resolves on the director's `PATH` and `--version` runs. The key is not
/// passed to it.
async fn check_claude(opts: &PreflightOptions<'_>) -> Check {
    let path = match resolve_executable(opts.claude_bin, opts.director_path, opts.cwd) {
        Ok(path) => path,
        Err(e) => return Check::fail("claude", format!("{e}")),
    };
    let mut command = tokio::process::Command::new(&path);
    command
        .arg("--version")
        .env_remove("ANTHROPIC_API_KEY")
        .stdin(Stdio::null())
        .kill_on_drop(true);
    match tokio::time::timeout(LAUNCH_TIMEOUT, command.output()).await {
        Err(_) => Check::fail(
            "claude",
            format!(
                "{} --version did not finish in {LAUNCH_TIMEOUT:?}",
                path.display()
            ),
        ),
        Ok(Err(e)) => Check::fail("claude", format!("cannot run {}: {e}", path.display())),
        Ok(Ok(out)) if !out.status.success() => Check::fail(
            "claude",
            format!("{} --version ended with {}", path.display(), out.status),
        ),
        Ok(Ok(out)) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let version: String = stdout
                .lines()
                .map(str::trim)
                .find(|l| !l.is_empty())
                .unwrap_or("no version printed")
                .chars()
                .take(60)
                .collect();
            Check::ok("claude", format!("{version} ({})", path.display()))
        }
    }
}

/// `ANTHROPIC_API_KEY` is set and not empty. The value is never read into a message.
fn check_api_key(for_run: bool) -> Check {
    match std::env::var_os("ANTHROPIC_API_KEY") {
        Some(k) if !k.is_empty() => Check::ok("key", "ANTHROPIC_API_KEY is set"),
        _ if for_run => Check::fail("key", "ANTHROPIC_API_KEY is not set"),
        _ => Check::warn(
            "key",
            "ANTHROPIC_API_KEY is not set (cowproof run needs it)",
        ),
    }
}

/// The repository is a git repository whose HEAD is a commit.
fn check_git(repo: &Path) -> Check {
    match std::process::Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["rev-parse", "--verify", "--quiet", "HEAD^{commit}"])
        .stdin(Stdio::null())
        .output()
    {
        Err(e) => Check::fail("git", format!("cannot run git: {e}")),
        Ok(out) if out.status.success() => {
            let head = String::from_utf8_lossy(&out.stdout);
            let short: String = head.trim().chars().take(7).collect();
            Check::ok("git", format!("{} is at {short}", repo.display()))
        }
        Ok(out) => {
            let why = String::from_utf8_lossy(&out.stderr);
            let why = why.lines().next().unwrap_or("").trim();
            Check::fail(
                "git",
                if why.is_empty() {
                    format!("{} is not a git repository with a commit", repo.display())
                } else {
                    format!(
                        "{} is not a git repository with a commit: {why}",
                        repo.display()
                    )
                },
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(check: &Check) -> CheckStatus {
        check.status
    }

    #[test]
    fn only_a_zero_exit_from_the_launched_program_passes_the_sandbox_check() {
        let ran = |code, stderr: &str| SandboxLaunch::Ran {
            code,
            stderr: stderr.to_string(),
        };
        let pass = sandbox_verdict(ran(Some(0), ""), "/usr/bin/true", "sandbox-exec");
        assert_eq!(status(&pass), CheckStatus::Ok);
        assert_eq!(pass.name, "sandbox");

        // The launcher is there but refuses: its stderr is the reason, and it fails.
        let refused = sandbox_verdict(
            ran(
                Some(71),
                "bwrap: No permissions to create new namespace\nmore",
            ),
            "/bin/true",
            "bwrap",
        );
        assert_eq!(status(&refused), CheckStatus::Fail);
        assert!(refused.detail.contains("exit 71"), "{}", refused.detail);
        assert!(
            refused
                .detail
                .contains("No permissions to create new namespace"),
            "{}",
            refused.detail
        );
        assert!(!refused.detail.contains("more"), "{}", refused.detail);

        // Killed by a signal: no exit code, not a pass.
        let signalled = sandbox_verdict(ran(None, ""), "/bin/true", "bwrap");
        assert_eq!(status(&signalled), CheckStatus::Fail);
        assert!(
            signalled.detail.contains("a signal"),
            "{}",
            signalled.detail
        );
    }

    #[test]
    fn a_launcher_that_cannot_start_or_never_finishes_fails_the_sandbox_check() {
        let missing = sandbox_verdict(
            SandboxLaunch::CouldNotStart("cannot start sandbox-exec: No such file".into()),
            "/usr/bin/true",
            "sandbox-exec",
        );
        assert_eq!(status(&missing), CheckStatus::Fail);
        assert!(
            missing.detail.contains("No such file"),
            "{}",
            missing.detail
        );

        let slow = sandbox_verdict(SandboxLaunch::TimedOut, "/bin/true", "bwrap");
        assert_eq!(status(&slow), CheckStatus::Fail);
    }

    #[test]
    fn free_space_below_the_floor_fails_and_the_floor_itself_passes() {
        let dir = Path::new("/lanes");
        let gb = |n: f64| (n * GB) as u64;
        assert_eq!(status(&disk_verdict(gb(4.9), 5.0, dir)), CheckStatus::Fail);
        assert_eq!(status(&disk_verdict(gb(5.0), 5.0, dir)), CheckStatus::Ok);
        assert_eq!(status(&disk_verdict(gb(50.0), 5.0, dir)), CheckStatus::Ok);
        assert_eq!(status(&disk_verdict(0, 0.0, dir)), CheckStatus::Ok);
        let fail = disk_verdict(gb(1.0), 1_000_000.0, dir);
        assert_eq!(status(&fail), CheckStatus::Fail);
        assert!(fail.detail.contains("1000000"), "{}", fail.detail);
        // A floor that is not a number of GB is an error, not a pass.
        for bad in [-1.0, f64::NAN, f64::INFINITY] {
            assert_eq!(status(&disk_verdict(gb(50.0), bad, dir)), CheckStatus::Fail);
        }
    }

    #[test]
    fn df_output_is_read_from_the_capacity_column_even_with_spaces_in_names() {
        let linux = "Filesystem     1024-blocks      Used Available Capacity Mounted on\n\
                     /dev/sda1        101930568  61930568  35790000      64% /\n";
        assert_eq!(parse_df_available_kib(linux), Some(35_790_000));
        let spaced = "Filesystem 1024-blocks Used Available Capacity Mounted on\n\
                      map auto home 1000 400 600 40% /System/Volumes/Data/home dir\n";
        assert_eq!(parse_df_available_kib(spaced), Some(600));
        assert_eq!(parse_df_available_kib("Filesystem only a header\n"), None);
        assert_eq!(parse_df_available_kib(""), None);
    }

    #[test]
    fn the_nearest_existing_directory_is_the_lanes_root_when_it_exists() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(nearest_existing_dir(tmp.path()), tmp.path());
        let deep = tmp.path().join("a/b/c");
        assert_eq!(nearest_existing_dir(&deep), tmp.path());
        assert!(!deep.exists(), "looking must not create anything");
    }

    #[test]
    fn the_probe_directory_is_removed_when_it_is_dropped() {
        let tmp = tempfile::tempdir().unwrap();
        let root = {
            let probe = Probe::create(tmp.path()).unwrap();
            assert!(probe.root.is_dir());
            fs::write(probe.root.join("x"), "x").unwrap();
            probe.root.clone()
        };
        assert!(!root.exists());
        assert_eq!(fs::read_dir(tmp.path()).unwrap().count(), 0);
        assert!(Probe::create(&tmp.path().join("missing")).is_err());
    }

    #[test]
    fn check_statuses_serialize_in_lower_case() {
        let json = serde_json::to_string(&Check::warn("key", "x")).unwrap();
        assert_eq!(json, r#"{"name":"key","status":"warn","detail":"x"}"#);
    }
}
