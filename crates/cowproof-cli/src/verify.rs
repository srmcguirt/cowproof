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
    VerifyError,
    runner::{SandboxedRunner, host_platform},
    verify::{VerifyOptions, VerifyResult, verify},
};
use cowproof_run::LaneLayout;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Parser)]
#[command(after_help = "\
Exit codes: 0 reproduced (every recorded check matched and every held-out check passed); \
2 diverged (a recorded check's pass or fail differs, or a held-out check failed; the check \
is named); 4 infrastructure (the capsule was refused as tampered, unsandboxed or unreadable, \
or the replay could not run; never a refutation).")]
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
/// scratch), then creates it with the verifier's own dependency cache inside.
pub(crate) fn verifier_runner(layout: &LaneLayout, verify_dir: &Path) -> Result<SandboxedRunner> {
    remove_path(verify_dir).context("clearing the verify directory")?;
    let cache = verify_dir.join("cache");
    fs::create_dir_all(cache.join(".cargo")).context("creating the verify directory")?;
    let mut verify_layout = layout.clone();
    verify_layout.scratch = verify_dir.to_path_buf();
    Ok(SandboxedRunner::new(
        verify_layout,
        cache,
        host_platform().to_string(),
    ))
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
    let runner = verifier_runner(&layout, &verify_dir)?;

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
