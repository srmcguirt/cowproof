//! `cowproof host-agent`: the remote side of remote lanes (D27, hidden).
//!
//! The director keeps the runner (queue, rulings, proxy, key, proof, held-out checks); a remote
//! host runs only the sandboxed processes. This is the closed set of verbs the director may
//! run there over SSH. `builder` and `check` are the next slice; this one has the four that
//! need no sockets:
//!
//! - `prepare --lane-id <id> --base <sha> --director-version <v> [--base-patch <file>]`: a git
//!   bundle on stdin that contains `<sha>`. The lane is built by the local runner's own
//!   `prepare_lane` (same layout, permissions, isolated clone, launch baseline and
//!   `control/lane.json`) from a throwaway source repository made out of the bundle, with the
//!   base patch applied there as uncommitted work, so there is no second clone implementation.
//! - `patch --lane-id <id>`: the lane patch, the bytes `cowproof run` writes to `lane.patch`,
//!   from the same `capture_patch` (run in the check sandbox, because the builder owns the
//!   clone's `.git`).
//! - `doctor [--claude-bin <name>]`: the preflight's `sandbox` and `claude` checks.
//! - `cleanup --lane-id <id>`: removes `<root>/<id>`; idempotent; never follows a link.
//!
//! Every verb prints one JSON object (`{"ok": true, ...}` or `{"ok": false, "error": "..."}`)
//! and exits 0 or 1, with one exception: `patch` prints the raw patch bytes on success (a
//! patch need not be UTF-8, and JSON would change it), and the JSON error only on failure.
//! The lanes root is `--root`, or `~/.cache/cowproof/remote-lanes`.

use crate::preflight::{Check, CheckStatus, PreflightOptions, preflight};
use crate::run::{builder_path, capture_patch};
use anyhow::{Context, Result, anyhow, bail};
use cowproof_run::LaneLayout;
use cowproof_run::lane::{LaneControl, PrepareOptions, prepare_lane, validate_lane_id};
use serde_json::{Value, json};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The remote host's side of D27.
#[derive(clap::Parser)]
pub struct HostAgentArgs {
    #[command(subcommand)]
    command: HostAgentAction,
}

#[derive(clap::Subcommand)]
enum HostAgentAction {
    /// Receive the base as a git bundle on stdin and build the lane.
    Prepare {
        #[arg(long)]
        lane_id: String,
        /// The full commit id the lane starts from; the bundle must contain it
        #[arg(long)]
        base: String,
        /// The director's cowproof version; this binary must be the same
        #[arg(long)]
        director_version: String,
        /// A file on this host with the director's `base.patch`, applied on top of the base
        #[arg(long)]
        base_patch: Option<PathBuf>,
        /// Directory that holds the lanes (default: ~/.cache/cowproof/remote-lanes)
        #[arg(long)]
        root: Option<PathBuf>,
    },
    /// Print the lane patch (raw bytes) against the launch baseline.
    Patch {
        #[arg(long)]
        lane_id: String,
        #[arg(long)]
        root: Option<PathBuf>,
    },
    /// Report the version, `claude` and the sandbox.
    Doctor {
        /// The Claude Code executable to check, resolved on PATH
        #[arg(long, default_value = "claude")]
        claude_bin: String,
        #[arg(long)]
        root: Option<PathBuf>,
    },
    /// Remove a lane (idempotent).
    Cleanup {
        #[arg(long)]
        lane_id: String,
        #[arg(long)]
        root: Option<PathBuf>,
    },
}

/// Run one verb, print its output, and return the exit code (0 or 1).
pub async fn run(args: HostAgentArgs) -> Result<i32> {
    let outcome = match args.command {
        HostAgentAction::Prepare {
            lane_id,
            base,
            director_version,
            base_patch,
            root,
        } => remote_root(root).and_then(|root| {
            prepare(
                &lane_id,
                &base,
                &director_version,
                base_patch.as_deref(),
                &root,
            )
        }),
        HostAgentAction::Doctor { claude_bin, root } => match remote_root(root) {
            Ok(root) => doctor(&claude_bin, &root).await,
            Err(e) => Err(e),
        },
        HostAgentAction::Cleanup { lane_id, root } => {
            remote_root(root).and_then(|root| cleanup(&lane_id, &root))
        }
        HostAgentAction::Patch { lane_id, root } => {
            let bytes = match remote_root(root) {
                Ok(root) => patch(&lane_id, &root).await,
                Err(e) => Err(e),
            };
            return Ok(match bytes {
                Ok(bytes) => {
                    let mut out = std::io::stdout().lock();
                    out.write_all(&bytes)?;
                    out.flush()?;
                    0
                }
                Err(e) => print_outcome(Err(e))?,
            });
        }
    };
    print_outcome(outcome)
}

/// Print a verb's JSON and return its exit code. A returned error becomes `ok: false`.
fn print_outcome(outcome: Result<Value>) -> Result<i32> {
    let value = outcome.unwrap_or_else(|e| json!({"ok": false, "error": format!("{e:#}")}));
    println!("{}", serde_json::to_string(&value)?);
    Ok(if value["ok"] == true { 0 } else { 1 })
}

/// `--root`, or `~/.cache/cowproof/remote-lanes`; a relative `--root` is taken from the
/// working directory.
fn remote_root(arg: Option<PathBuf>) -> Result<PathBuf> {
    match arg {
        Some(p) => Ok(std::env::current_dir()?.join(p)),
        None => Ok(real_home()?.join(".cache/cowproof/remote-lanes")),
    }
}

fn real_home() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| anyhow!("HOME is not set"))
}

/// A full object name: 40 (SHA-1) or 64 (SHA-256) lowercase hex digits. Anything else could
/// be a ref name, an abbreviation or an option.
fn validate_commit_id(base: &str) -> Result<()> {
    let hex = base
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if !hex || !(base.len() == 40 || base.len() == 64) {
        bail!("--base must be a full commit id (40 or 64 lowercase hex digits)");
    }
    Ok(())
}

/// A directory this verb made, removed when dropped.
struct Throwaway(PathBuf);

impl Drop for Throwaway {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// A git command in `dir`, with its failure turned into the error.
fn git(dir: &Path, args: &[&str]) -> Result<()> {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .with_context(|| format!("running git {}", args.join(" ")))?;
    if !out.status.success() {
        bail!(
            "git {} failed: {}",
            args.first().copied().unwrap_or(""),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// Build the lane `<root>/<id>` from the bundle on stdin.
fn prepare(
    lane_id: &str,
    base: &str,
    director_version: &str,
    base_patch: Option<&Path>,
    root: &Path,
) -> Result<Value> {
    validate_lane_id(lane_id)?;
    let version = env!("CARGO_PKG_VERSION");
    if director_version != version {
        bail!(
            "version mismatch: the director runs cowproof {director_version}, this host runs {version}"
        );
    }
    validate_commit_id(base)?;
    let base_patch = base_patch
        .map(|p| std::env::current_dir().map(|cwd| cwd.join(p)))
        .transpose()?;
    if let Some(p) = &base_patch
        && !p.is_file()
    {
        bail!("the base patch {} is not a file", p.display());
    }

    fs::create_dir_all(root).with_context(|| format!("creating {}", root.display()))?;
    let root = root.canonicalize().context("resolving the lanes root")?;
    let lane_dir = root.join(lane_id);
    if fs::symlink_metadata(&lane_dir).is_ok() {
        bail!("lane {lane_id} already exists in {}", root.display());
    }

    // The throwaway source repository sits beside the root, never inside it:
    // `prepare_lane` refuses a lanes root that contains its source.
    let incoming = root.with_file_name(format!(
        "{}.incoming-{lane_id}-{}",
        root.file_name()
            .ok_or_else(|| anyhow!("the lanes root must not be /"))?
            .to_string_lossy(),
        std::process::id()
    ));
    fs::create_dir(&incoming).with_context(|| format!("creating {}", incoming.display()))?;
    let incoming = Throwaway(incoming);
    let src = incoming.0.join("src");
    let bundle = incoming.0.join("in.bundle");
    {
        let mut file = fs::File::create(&bundle).context("creating the bundle file")?;
        std::io::copy(&mut std::io::stdin().lock(), &mut file)
            .context("reading the bundle from stdin")?;
    }
    git(&incoming.0, &["init", "-q", "src"])?;
    git(&src, &["bundle", "unbundle", &bundle.to_string_lossy()]).context("reading the bundle")?;
    if git(&src, &["cat-file", "-e", &format!("{base}^{{commit}}")]).is_err() {
        bail!("the bundle does not contain commit {base}");
    }
    git(&src, &["checkout", "-q", "--detach", base])?;
    if let Some(p) = &base_patch {
        git(&src, &["apply", "--", &p.to_string_lossy()]).context("applying the base patch")?;
    }

    let prepared = prepare_lane(
        &src,
        &root,
        lane_id,
        PrepareOptions {
            allow_dirty: base_patch.is_some(),
        },
    )?;
    // As the runner does right after `prepare_lane`: the builder's and the checks' TMPDIR.
    fs::create_dir_all(cowproof_run::lane_tmp(&prepared.layout.scratch))
        .context("creating the lane's temp directory")?;
    Ok(json!({
        "ok": true,
        "lane_id": lane_id,
        "lane_dir": lane_dir,
        "version": version,
        "base_commit": prepared.base_commit,
        "launch_commit": prepared.launch_commit,
        "removed": prepared.launch_removed,
        "base_patch": prepared.base_patch.is_some(),
    }))
}

/// The lane at `<root>/<id>`, resolved: a real directory under the real root, never a link.
fn lane_dir_of(lane_id: &str, root: &Path) -> Result<PathBuf> {
    validate_lane_id(lane_id)?;
    let root = root
        .canonicalize()
        .with_context(|| format!("no lanes root at {}", root.display()))?;
    let lane_dir = root.join(lane_id);
    let meta = fs::symlink_metadata(&lane_dir)
        .map_err(|_| anyhow!("no lane {lane_id} in {}", root.display()))?;
    if !meta.is_dir() {
        bail!("{} is not a lane directory", lane_dir.display());
    }
    Ok(lane_dir)
}

/// The lane patch: everything changed since the launch baseline, as `cowproof run` writes it
/// to `lane.patch` (the very same `capture_patch`).
async fn patch(lane_id: &str, root: &Path) -> Result<Vec<u8>> {
    patch_with_home(lane_id, root, real_home()?).await
}

async fn patch_with_home(lane_id: &str, root: &Path, home: PathBuf) -> Result<Vec<u8>> {
    let lane_dir = lane_dir_of(lane_id, root)?;
    let control_file = lane_dir.join("control/lane.json");
    let control: LaneControl = serde_json::from_slice(
        &fs::read(&control_file).with_context(|| format!("reading {}", control_file.display()))?,
    )
    .context("parsing control/lane.json")?;
    let layout = LaneLayout::for_lane_dir(&lane_dir, home.clone())?;
    fs::create_dir_all(cowproof_run::lane_tmp(&layout.scratch))
        .context("creating the lane's temp directory")?;
    let path = builder_path(&std::env::var("PATH").unwrap_or_default(), &home);
    capture_patch(&layout, &control.launch_commit, &path).await
}

/// The preflight's `sandbox` and `claude` checks. `ok` means both pass; the key is not
/// checked, because a remote host must not have one (D27).
async fn doctor(claude_bin: &str, root: &Path) -> Result<Value> {
    let cwd = std::env::current_dir()?;
    let home = real_home()?;
    let director_path = std::env::var("PATH").unwrap_or_default();
    let checks = preflight(&PreflightOptions {
        repo: &cwd,
        lanes_root: root,
        disk_floor_gb: 0.0,
        claude_bin,
        director_path: &director_path,
        cwd: &cwd,
        real_home: &home,
        for_run: false,
    })
    .await;
    let find = |name: &str| -> Result<&Check> {
        checks
            .iter()
            .find(|c| c.name == name)
            .ok_or_else(|| anyhow!("the preflight has no {name} check"))
    };
    let (sandbox, claude) = (find("sandbox")?, find("claude")?);
    let passed = |c: &Check| c.status != CheckStatus::Fail;
    Ok(json!({
        "ok": passed(sandbox) && passed(claude),
        "version": env!("CARGO_PKG_VERSION"),
        "claude": passed(claude),
        "claude_detail": claude.detail,
        "sandbox": passed(sandbox),
        "sandbox_detail": sandbox.detail,
    }))
}

/// Remove `<root>/<id>`. A missing lane is success. A link at that path is unlinked and its
/// target is left alone; `remove_dir_all` does not follow links inside the lane either.
fn cleanup(lane_id: &str, root: &Path) -> Result<Value> {
    validate_lane_id(lane_id)?;
    let target = root.join(lane_id);
    let removed = match fs::symlink_metadata(&target) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => bail!("cannot look at {}: {e}", target.display()),
        Ok(meta) if meta.file_type().is_symlink() => {
            fs::remove_file(&target)
                .with_context(|| format!("removing the link {}", target.display()))?;
            true
        }
        Ok(meta) if meta.is_dir() => {
            fs::remove_dir_all(&target)
                .with_context(|| format!("removing {}", target.display()))?;
            true
        }
        Ok(_) => bail!("{} is not a lane directory", target.display()),
    };
    Ok(json!({"ok": true, "lane_id": lane_id, "removed": removed}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cowproof_run::lane::prepare_lane;

    fn git_in(dir: &Path, args: &[&str]) {
        git(dir, args).unwrap();
    }

    /// Whether this host can run the check sandbox (`doctor` uses the same code).
    fn can_sandbox() -> bool {
        cfg!(target_os = "macos")
            || Command::new("bwrap")
                .args(["--ro-bind", "/", "/", "true"])
                .output()
                .is_ok_and(|o| o.status.success())
    }

    /// The remote `patch` and the local runner's `capture_patch` give the same bytes for the
    /// same tree, and the remote one finds the launch commit by itself in `lane.json`.
    #[tokio::test]
    async fn patch_is_byte_identical_to_the_local_runners_capture() {
        if !can_sandbox() {
            return;
        }
        let tmp = tempfile::Builder::new()
            .prefix("cp-hostagent-unit-")
            .tempdir_in("/var/tmp")
            .unwrap();
        let home = tmp.path().join("home");
        let repo = tmp.path().join("repo");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir(&repo).unwrap();
        git_in(&repo, &["init", "-q"]);
        git_in(&repo, &["config", "user.email", "t@example.com"]);
        git_in(&repo, &["config", "user.name", "T"]);
        fs::write(repo.join("a.txt"), "one\n").unwrap();
        fs::write(repo.join("b.bin"), [0u8, 1, 2, 255]).unwrap();
        git_in(&repo, &["add", "."]);
        git_in(&repo, &["commit", "-q", "-m", "base"]);

        let root = tmp.path().join("lanes");
        let prepared =
            prepare_lane(&repo, &root, "unit", PrepareOptions { allow_dirty: false }).unwrap();
        let layout = prepared.layout.clone();
        fs::create_dir_all(cowproof_run::lane_tmp(&layout.scratch)).unwrap();
        fs::write(layout.clone.join("a.txt"), "one\ntwo\n").unwrap();
        fs::write(layout.clone.join("b.bin"), [9u8, 8, 7, 0]).unwrap();
        fs::write(layout.clone.join("c.txt"), "new\n").unwrap();

        let path = builder_path(&std::env::var("PATH").unwrap_or_default(), &home);
        let local = capture_patch(&layout, &prepared.launch_commit, &path)
            .await
            .unwrap();
        let remote = patch_with_home("unit", &root, home).await.unwrap();
        assert!(!local.is_empty());
        assert!(String::from_utf8_lossy(&local).contains("GIT binary patch"));
        assert_eq!(remote, local);
    }

    #[test]
    fn commit_ids_are_full_lowercase_hex() {
        assert!(validate_commit_id(&"a".repeat(40)).is_ok());
        assert!(validate_commit_id(&"0".repeat(64)).is_ok());
        for bad in [
            "",
            "HEAD",
            "--upload-pack=x",
            &"A".repeat(40),
            &"a".repeat(39),
        ] {
            assert!(validate_commit_id(bad).is_err(), "{bad}");
        }
    }
}
