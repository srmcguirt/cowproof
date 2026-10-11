//! `cowproof verify <capsule-dir> --repo <path>`: replay a capsule on a second machine.
//!
//! It reads only the capsule directory and the repository it is given, so it works from
//! any working directory and a fresh clone: the base commit is rebuilt from `--repo`, the
//! capsule's patches are applied, and every recorded check, then every held-out check the
//! capsule carries, runs in the same no-network verifier sandbox `cowproof run` uses
//! ([`verifier_runner`] is the one constructor both call).

use anyhow::{Context, Result, anyhow, bail};
use clap::Parser;
use cowproof_prove::{
    Capsule, VerifyError,
    runner::{SandboxedRunner, host_platform, verifier_toolchain},
    verify::{VerifyOptions, VerifyResult, verify},
};
use cowproof_run::{
    LaneLayout,
    deps::{self, FETCH_TIMEOUT, FetchNetwork, FetchOutcome, FetchTools, Prefetch},
    lane_tmp, link_dependency_cache,
};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Parser)]
#[command(after_help = "\
Exit codes: 0 reproduced (every recorded check matched and every held-out check passed); \
2 diverged (a recorded check's pass or fail differs, or a held-out check failed; the check \
is named); 4 infrastructure (the capsule was refused as tampered, unsandboxed or unreadable, \
or the replay could not run, or the dependency fetch the checks need failed; never a \
refutation).

Dependencies: a capsule whose tree has a Cargo.lock names a dependency cache key. The cache \
is <cache root>/deps/<key>, the cache root being ~/.cache/cowproof or $COWPROOF_CACHE_ROOT; \
verify fetches it (cargo fetch --locked, in a sandbox; the network is $COWPROOF_FETCH_NETWORK, \
`open` by default or `none`) when it is absent, and mounts it read-only for the checks.")]
pub struct VerifyArgs {
    /// The capsule directory (`control/capsule` of a lane)
    capsule_dir: PathBuf,
    /// A repository that holds the capsule's base commit (a fresh clone is enough)
    #[arg(long)]
    repo: PathBuf,
    /// Directory to rebuild in. Default: a new directory under `~/.cache/cowproof/verify`,
    /// removed when the capsule reproduces
    #[arg(long)]
    workdir: Option<PathBuf>,
}

/// The sandboxed check runner the verifier uses, for both `cowproof run` and
/// `cowproof verify`. `verify_dir` is the directory `verify` rebuilds in: the runner's
/// layout names only it as scratch, so nothing else the lane left in its own scratch is
/// visible to a check. Clears any earlier `verify_dir` (the builder owned the lane's
/// scratch), then creates it with the verifier's own `CARGO_HOME` inside. `deps` is the
/// fetched dependency cache (D6): its `registry` (and `git`) are linked into that
/// `CARGO_HOME` and mounted read-only, and nothing else of it is visible.
pub(crate) fn verifier_runner(
    layout: &LaneLayout,
    verify_dir: &Path,
    deps: Option<&Path>,
) -> Result<SandboxedRunner> {
    remove_path(verify_dir).context("clearing the verify directory")?;
    let cache = verify_dir.join("cache");
    fs::create_dir_all(cache.join(".cargo")).context("creating the verify directory")?;
    // The verifier's `TMPDIR` (a check that runs `mktemp`); macOS denies the rest.
    fs::create_dir_all(lane_tmp(verify_dir)).context("creating the verifier's temp directory")?;
    let mut verify_layout = layout.clone();
    verify_layout.scratch = verify_dir.to_path_buf();
    let mut runner =
        SandboxedRunner::new(verify_layout, cache.clone(), host_platform().to_string());
    if let Some(deps) = deps {
        link_dependency_cache(deps, &cache.join(".cargo"))?;
        runner = runner.with_dependency_cache(deps.to_path_buf());
    }
    Ok(runner)
}

/// What rebuilds the tree a lane's dependencies are fetched for: the same four steps
/// `verify` takes (base commit, `base.patch`, launch baseline, `lane.patch`).
pub(crate) struct Rebuild {
    pub repo: PathBuf,
    pub base_commit: String,
    pub base_patch: Option<Vec<u8>>,
    pub launch_removed: Vec<String>,
    pub lane_patch: Vec<u8>,
}

impl Rebuild {
    /// Build the tree in `tree`, an empty directory. The registry configuration is the
    /// tree's BEFORE `lane.patch` (D14): a patch that touches it changes nothing here.
    fn build(&self, tree: &Path) -> Result<()> {
        git(
            None,
            &["clone", "--quiet", "--no-checkout", "--"],
            &[self.repo.as_os_str(), tree.as_os_str()],
            None,
        )
        .context("cloning the repository")?;
        git(
            Some(tree),
            &["checkout", "--quiet", "--detach", &self.base_commit],
            &[],
            None,
        )
        .context("checking out the base commit")?;
        if let Some(patch) = &self.base_patch {
            apply(tree, patch).context("applying base.patch")?;
        }
        remove_launch_paths(tree, &self.launch_removed)?;
        let config = deps::RegistryConfigSnapshot::take(tree)?;
        apply(tree, &self.lane_patch).context("applying lane.patch")?;
        config.restore(tree)
    }
}

/// `git` with hooks off, in `dir` or at the top, with `stdin` when given.
fn git(
    dir: Option<&Path>,
    args: &[&str],
    paths: &[&std::ffi::OsStr],
    stdin: Option<&[u8]>,
) -> Result<()> {
    let mut command = Command::new("git");
    command.args(["-c", "core.hooksPath=/dev/null"]);
    if let Some(dir) = dir {
        command.arg("-C").arg(dir);
    }
    command.args(args).args(paths);
    command
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let mut child = command.spawn().context("starting git")?;
    if let (Some(bytes), Some(mut pipe)) = (stdin, child.stdin.take()) {
        pipe.write_all(bytes).context("writing to git")?;
    }
    let out = child.wait_with_output().context("waiting for git")?;
    if !out.status.success() {
        bail!(
            "git {} failed: {}",
            args.first().copied().unwrap_or(""),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

fn apply(tree: &Path, patch: &[u8]) -> Result<()> {
    if patch.iter().all(u8::is_ascii_whitespace) {
        return Ok(());
    }
    git(Some(tree), &["apply", "-"], &[], Some(patch))
}

/// Delete the launch baseline's paths (R15), refusing anything but a relative path to a
/// file or symlink inside the tree that no symlink or `.git` component leads through. A
/// symlink at the end is unlinked, never followed (a committed `CLAUDE.md -> AGENTS.md`
/// is a launch-removed path).
fn remove_launch_paths(tree: &Path, removed: &[String]) -> Result<()> {
    for rel in removed {
        let parts: Vec<&str> = rel.split('/').collect();
        let bad = rel.is_empty()
            || parts
                .iter()
                .any(|c| c.is_empty() || *c == "." || *c == ".." || c.eq_ignore_ascii_case(".git"));
        if bad || rel.contains('\0') {
            bail!("launch baseline: refused path {rel:?}");
        }
        let mut current = tree.to_path_buf();
        for (i, c) in parts.iter().enumerate() {
            current.push(c);
            let last = i + 1 == parts.len();
            match fs::symlink_metadata(&current) {
                Ok(m) if last && (m.is_file() || m.file_type().is_symlink()) => {
                    fs::remove_file(&current)?
                }
                Ok(m) if !last && m.is_dir() => {}
                Ok(_) => bail!("launch baseline: {rel:?} is not a plain file path"),
                Err(e) => bail!("launch baseline: cannot remove {rel:?}: {e}"),
            }
        }
    }
    Ok(())
}

/// Fetch (or find in the cache) the dependencies of the tree `rebuild` describes, before
/// verify runs (D6, D11, D14). `Ok(None)`: nothing to fetch. The fetch is blocking work,
/// so it runs off the async threads.
pub(crate) async fn fetch_dependencies(
    rebuild: Rebuild,
    layout: &LaneLayout,
) -> Result<Option<Prefetch>> {
    let network = FetchNetwork::from_env()?;
    let (path, cargo) = verifier_toolchain().map_err(|e| anyhow!("{e}"))?;
    let root = deps::cache_root(&layout.real_home);
    let layout = layout.clone();
    tokio::task::spawn_blocking(move || {
        deps::prefetch(
            |tree| rebuild.build(tree),
            &root,
            &layout,
            network,
            &FetchTools { path, cargo },
            FETCH_TIMEOUT,
        )
    })
    .await
    .context("the dependency fetch task died")?
}

/// The dependency cache a capsule's checks need, for `cowproof verify`: the capsule's
/// key, fetched here when this machine lacks it. `Err` is an infrastructure reason.
async fn capsule_dependencies(
    capsule_dir: &Path,
    repo: &Path,
    layout: &LaneLayout,
) -> std::result::Result<Option<PathBuf>, String> {
    // An unreadable or tampered capsule is `verify`'s to refuse, with its own message.
    let Ok(capsule) = Capsule::read(capsule_dir) else {
        return Ok(None);
    };
    let Some(key) = capsule.dependency_cache_key.clone() else {
        return Ok(None);
    };
    let read = |name: &str| fs::read(capsule_dir.join(name)).ok();
    let rebuild = Rebuild {
        repo: repo.to_path_buf(),
        base_commit: capsule.base_commit.clone(),
        base_patch: read("base.patch"),
        launch_removed: capsule.launch_removed.clone(),
        lane_patch: read("lane.patch").unwrap_or_default(),
    };
    match fetch_dependencies(rebuild, layout).await {
        Err(e) => Err(format!("dependency fetch could not run: {e:#}")),
        Ok(None) => Err(format!(
            "the capsule names dependency cache {key}, but the rebuilt tree has no Cargo.lock"
        )),
        Ok(Some(p)) if p.key != key => Err(format!(
            "the rebuilt tree's dependency cache key {} is not the capsule's {key}",
            p.key
        )),
        Ok(Some(Prefetch {
            outcome: FetchOutcome::Failed(why),
            ..
        })) => Err(format!("dependency fetch failed: {why}")),
        Ok(Some(p)) => Ok(Some(p.dir)),
    }
}

/// Remove `path` whatever it is, without following a symlink.
fn remove_path(path: &Path) -> std::io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(m) if m.is_dir() => fs::remove_dir_all(path),
        Ok(_) => fs::remove_file(path),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Replay the capsule; the return value is the process exit code.
pub async fn verify_capsule(args: VerifyArgs) -> Result<i32> {
    if !args.capsule_dir.is_dir() {
        bail!(
            "capsule directory does not exist: {}",
            args.capsule_dir.display()
        );
    }
    if !args.repo.is_dir() {
        bail!("repository does not exist: {}", args.repo.display());
    }
    let capsule_dir = args.capsule_dir.canonicalize()?;
    let repo = args.repo.canonicalize()?;
    let real_home =
        PathBuf::from(std::env::var_os("HOME").ok_or_else(|| anyhow!("HOME is not set"))?);

    // The workdir is laid out like a lane (`<root>/lane/{clone,home,scratch,control}`,
    // lanes root `<root>`), so the sandbox policy sees the shape it sees in `run`.
    let (root, ours) = match args.workdir {
        Some(dir) => {
            fs::create_dir_all(&dir)
                .with_context(|| format!("creating workdir {}", dir.display()))?;
            (dir.canonicalize()?, false)
        }
        None => {
            let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
            let dir = real_home.join(format!(
                ".cache/cowproof/verify/{}-{stamp}",
                std::process::id()
            ));
            fs::create_dir_all(&dir)
                .with_context(|| format!("creating workdir {}", dir.display()))?;
            (dir.canonicalize()?, true)
        }
    };
    let lane = root.join("lane");
    let layout = LaneLayout {
        clone: lane.join("clone"),
        home: lane.join("home"),
        scratch: lane.join("scratch"),
        control: lane.join("control"),
        real_home,
        sock: lane.join("sock/runner.sock"),
        lanes_root: root.clone(),
    };
    for dir in [
        &layout.clone,
        &layout.home,
        &layout.scratch,
        &layout.control,
        &lane.join("sock"),
    ] {
        fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    let verify_dir = layout.scratch.join("verify");
    let deps_dir = match capsule_dependencies(&capsule_dir, &repo, &layout).await {
        Ok(dir) => dir,
        Err(why) => {
            eprintln!("infrastructure: {why}");
            if ours {
                let _ = fs::remove_dir_all(&root);
            }
            return Ok(4);
        }
    };
    let runner = verifier_runner(&layout, &verify_dir, deps_dir.as_deref())?;

    let code = match verify(
        &capsule_dir,
        &repo,
        &verify_dir,
        &runner,
        VerifyOptions::default(),
    )
    .await
    {
        Ok(report) => match report.result {
            VerifyResult::Reproduced => {
                println!("reproduced");
                0
            }
            VerifyResult::Diverged { check_ids } => {
                println!("diverged: check {}", quote_ids(&check_ids));
                for id in report.heldout.iter().filter(|o| !o.passed) {
                    println!("held-out check {:?} failed", id.check_id);
                }
                2
            }
            VerifyResult::HeldOutFailed { check_ids } => {
                println!("diverged: held-out check {} failed", quote_ids(&check_ids));
                2
            }
        },
        Err(VerifyError::Capsule(e)) => {
            eprintln!("refused: the capsule was tampered with or is damaged: {e}");
            4
        }
        Err(e) => {
            eprintln!("infrastructure: {e}");
            4
        }
    };
    if ours && code == 0 {
        // The directory was created here and holds only the rebuilt tree.
        let _ = fs::remove_dir_all(&root);
    } else {
        eprintln!("rebuilt tree kept in {}", verify_dir.join("tree").display());
    }
    Ok(code)
}

fn quote_ids(ids: &[String]) -> String {
    ids.iter()
        .map(|id| format!("{id:?}"))
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_launch_removed_symlink_is_unlinked_and_its_target_is_left_alone() {
        let dir = tempfile::TempDir::new().unwrap();
        fs::write(dir.path().join("AGENTS.md"), "rules").unwrap();
        std::os::unix::fs::symlink("AGENTS.md", dir.path().join("CLAUDE.md")).unwrap();
        remove_launch_paths(dir.path(), &["CLAUDE.md".to_string()]).unwrap();
        assert!(fs::symlink_metadata(dir.path().join("CLAUDE.md")).is_err());
        assert_eq!(
            fs::read_to_string(dir.path().join("AGENTS.md")).unwrap(),
            "rules"
        );
    }

    #[test]
    fn a_path_through_a_symlinked_directory_is_still_refused() {
        let dir = tempfile::TempDir::new().unwrap();
        let outside = tempfile::TempDir::new().unwrap();
        fs::write(outside.path().join("CLAUDE.md"), "precious").unwrap();
        std::os::unix::fs::symlink(outside.path(), dir.path().join("sub")).unwrap();
        let err = remove_launch_paths(dir.path(), &["sub/CLAUDE.md".to_string()]).unwrap_err();
        assert!(err.to_string().contains("not a plain file path"), "{err}");
        assert_eq!(
            fs::read_to_string(outside.path().join("CLAUDE.md")).unwrap(),
            "precious"
        );
    }
}
