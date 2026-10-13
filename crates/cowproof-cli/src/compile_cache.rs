//! The verifier's compile cache, set up in the one place both `cowproof run` and
//! `cowproof verify` set the verifier up (R3, D11). The design is in
//! [`cowproof_run::verify_target`]; this is the orchestration.
//!
//! [`attach`] is called with the verifier's runner just before the replay. For a tree with a
//! `Cargo.toml` at its root it finds the seed for the base commit (or builds it from the BASE
//! commit's tree, never a lane's, in the verifier sandbox, under the verifier's time limit),
//! makes a private copy of it in the verifier's scratch, and points the runner's
//! `CARGO_TARGET_DIR` at the copy. Every way it can fail is a [`VerifyCache`] record, never an
//! error: the verification runs as it did without a seed, and the record says why.

use crate::verify::{Rebuild, verifier_runner};
use anyhow::{Context, Result, anyhow};
use cowproof_prove::capsule::VerifyCache;
use cowproof_prove::runner::{CheckRunner, GroupSet, SandboxedRunner, run_probe};
use cowproof_run::LaneLayout;
use cowproof_run::cache::{self, Area};
use cowproof_run::deps;
use cowproof_run::runtime_dirs::RuntimeDir;
use cowproof_run::verify_target::{
    self, CopyMethod, Installed, KeyInputs, Lookup, Mode, SEED_COMMAND,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::process::Command;

/// How long `rustc -vV` may take.
const PROBE_TIMEOUT: Duration = Duration::from_secs(30);

/// The longest note kept in the capsule.
const NOTE_LIMIT: usize = 400;

/// What [`attach`] needs to know about the verification it is for.
pub(crate) struct Request<'a> {
    /// `COWPROOF_VERIFY_CACHE`, read once at startup.
    pub mode: Mode,
    /// The repository that holds the base commit.
    pub repo: &'a Path,
    pub base_commit: &'a str,
    /// The base commit's tree hash (the capsule's `base_tree_hash`).
    pub base_tree_hash: &'a str,
    /// The layout the verifier's runner was made from.
    pub layout: &'a LaneLayout,
    /// The dependency cache entry the verifier mounts (`<cache root>/deps/<key>`), when it has
    /// one: the seed build mounts the same one.
    pub deps: Option<&'a Path>,
    /// The runtime directories the director granted.
    pub runtime: &'a [RuntimeDir],
    /// The run's process groups (`cowproof run`), so a signal ends the seed build with the run.
    pub groups: Option<Arc<GroupSet>>,
    /// The directory the verification rebuilds in; the private copy goes in it, as `target`.
    pub verify_dir: &'a Path,
    /// The time limit of the seed build: the verifier's default limit per command.
    pub timeout: Duration,
}

fn record(status: &str) -> VerifyCache {
    VerifyCache {
        status: status.to_string(),
        key: None,
        copy: None,
        note: None,
    }
}

fn failed(key: Option<&str>, why: impl std::fmt::Display) -> VerifyCache {
    let mut note = format!("{why}").replace('\n', " ");
    if note.len() > NOTE_LIMIT {
        let mut end = NOTE_LIMIT;
        while !note.is_char_boundary(end) {
            end -= 1;
        }
        note.truncate(end);
        note.push_str("...");
    }
    VerifyCache {
        status: "failed".to_string(),
        key: key.map(str::to_string),
        copy: None,
        note: Some(note),
    }
}

/// Give `runner` its private copy of the compile-cache seed, building the seed first on a miss.
/// Returns the runner (with `CARGO_TARGET_DIR` set when a copy was made) and what happened.
/// Never fails: see the module comment.
pub(crate) async fn attach(
    runner: SandboxedRunner,
    req: &Request<'_>,
) -> (SandboxedRunner, VerifyCache) {
    match prepare(req).await {
        Ok((dir, record)) => (runner.with_target_dir(dir).with_target_link(), record),
        Err(record) => (runner, record),
    }
}

/// The private copy's directory and the record, or the record of why there is none.
async fn prepare(req: &Request<'_>) -> Result<(PathBuf, VerifyCache), VerifyCache> {
    if req.mode == Mode::Off {
        return Err(record("off"));
    }
    if !has_root_file(req.repo, req.base_commit, "Cargo.toml").await {
        return Err(record("not_cargo"));
    }
    // The seed build is `--locked`: a base with no lockfile cannot be built offline, so say so
    // without a checkout and a build that could only fail.
    if !has_root_file(req.repo, req.base_commit, "Cargo.lock").await {
        return Err(failed(
            None,
            "the base commit has no Cargo.lock at its root, which the seed build's --locked needs",
        ));
    }
    let (rustc_vv, host) = rustc_vv(&req.layout.real_home)
        .await
        .map_err(|e| failed(None, format!("rustc -vV: {e:#}")))?;
    let dependency_key = req
        .deps
        .and_then(Path::file_name)
        .map(|n| n.to_string_lossy().into_owned());
    let key = verify_target::key(&KeyInputs {
        base_tree_hash: req.base_tree_hash,
        dependency_key: dependency_key.as_deref(),
        rustc_vv: &rustc_vv,
        host: &host,
        command: SEED_COMMAND,
    });
    let fail = |why: String| failed(Some(&key), why);
    let root = deps::cache_root(&req.layout.real_home);
    cache::prepare(
        &root,
        &req.layout.real_home,
        Area::VerifyTarget,
        &crate::cache::alive,
    )
    .map_err(|e| fail(format!("{e:#}")))?;

    let found = verify_target::lookup(&root, &key, &crate::cache::alive)
        .map_err(|e| fail(format!("{e:#}")))?;
    let (status, entry) = match found {
        Lookup::Hit => ("hit", verify_target::entry_dir(&root, &key)),
        Lookup::Absent => match build(req, &root, &key).await {
            Ok(Installed::Built) => ("built", verify_target::entry_dir(&root, &key)),
            Ok(Installed::Existing) => ("hit", verify_target::entry_dir(&root, &key)),
            Err(why) => return Err(fail(why)),
        },
    };

    // The copy is made here, outside any sandbox, so the seed is granted to none.
    let seed = verify_target::seed_target(&entry);
    let dest = req.verify_dir.join(verify_target::TARGET);
    let copied = {
        let dest = dest.clone();
        tokio::task::spawn_blocking(move || verify_target::copy_tree(&seed, &dest))
            .await
            .map_err(|e| fail(format!("the copy task died: {e}")))?
    };
    let method: CopyMethod = match copied {
        Ok(method) => method,
        Err(e) => {
            let _ = cowproof_core::fsutil::remove_tree(&dest);
            return Err(fail(format!(
                "copying the seed into {}: {e}",
                req.verify_dir.display()
            )));
        }
    };
    Ok((
        dest,
        VerifyCache {
            status: status.to_string(),
            key: Some(key),
            copy: Some(method.name().to_string()),
            note: None,
        },
    ))
}

/// Whether the base commit's tree has the file `name` at its root (`Cargo.toml` decides which
/// trees get a seed at all). Asked of git directly, so a hit costs no checkout.
async fn has_root_file(repo: &Path, commit: &str, name: &str) -> bool {
    let (repo, spec) = (repo.to_path_buf(), format!("{commit}:{name}"));
    tokio::task::spawn_blocking(move || {
        std::process::Command::new("git")
            .args(["-c", "core.hooksPath=/dev/null", "-C"])
            .arg(&repo)
            .args(["cat-file", "-t", &spec])
            .output()
            .is_ok_and(|o| o.status.success() && o.stdout.trim_ascii() == b"blob")
    })
    .await
    .unwrap_or(false)
}

/// `rustc -vV` of the toolchain the verifier's checks find (its `PATH`, the director's `RUSTUP_*`
/// settings), run outside any sandbox from `/`: the output and its `host:` triple. A
/// `rust-toolchain` file in a tree is not consulted here; one in the base is covered by the base
/// tree hash in the key.
async fn rustc_vv(real_home: &Path) -> Result<(String, String)> {
    let (path, _cargo) =
        cowproof_prove::runner::verifier_toolchain(real_home).map_err(|e| anyhow!("{e}"))?;
    let rustc = path
        .split(':')
        .map(|dir| Path::new(dir).join("rustc"))
        .find(|p| p.is_file())
        .ok_or_else(|| anyhow!("no rustc on the verifier's PATH"))?;
    let mut cmd = Command::new(&rustc);
    cmd.arg("-vV").current_dir("/").env("PATH", &path);
    let ran = run_probe(cmd, PROBE_TIMEOUT)
        .await
        .map_err(|e| anyhow!("{e}"))?;
    let cowproof_prove::runner::GroupEnd::Exited(status) = ran.end else {
        return Err(anyhow!("timed out"));
    };
    let out = String::from_utf8_lossy(&ran.stdout).into_owned();
    if !status.success() {
        return Err(anyhow!(
            "exited with {status}: {}",
            String::from_utf8_lossy(&ran.stderr).trim()
        ));
    }
    let host = verify_target::host_triple(&out).unwrap_or_else(deps::host_target);
    Ok((out, host))
}

/// A private work directory that is removed when dropped, on every path, a signal included.
struct Work(PathBuf);

impl Drop for Work {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Build the seed for `key` from the BASE commit's tree and install it. The tree is the base
/// commit alone: no `base.patch`, no launch baseline, no `lane.patch`, so nothing a lane wrote
/// is compiled into the seed. The build is the one command a check is, in the verifier's own
/// sandbox (no network, the dependency cache read-only), with `CARGO_TARGET_DIR` inside the
/// work directory it may write.
async fn build(req: &Request<'_>, root: &Path, key: &str) -> Result<Installed, String> {
    let work = Work(cache::new_work_dir(root).map_err(|e| format!("{e:#}"))?);
    let sandbox = work.0.join("sandbox");
    let target = sandbox.join(verify_target::TARGET);
    let mut seed_runner = verifier_runner(req.layout, &sandbox, req.deps, req.runtime)
        .map_err(|e| format!("setting up the seed build: {e:#}"))?
        .with_target_dir(target.clone());
    if let Some(groups) = &req.groups {
        seed_runner = seed_runner.with_groups(groups.clone());
    }
    let tree = sandbox.join("tree");
    let rebuild = Rebuild {
        repo: req.repo.to_path_buf(),
        base_commit: req.base_commit.to_string(),
        base_patch: None,
        launch_removed: Vec::new(),
        lane_patch: Vec::new(),
    };
    {
        let tree = tree.clone();
        tokio::task::spawn_blocking(move || rebuild.build(&tree))
            .await
            .map_err(|e| format!("the base checkout task died: {e}"))?
            .map_err(|e| format!("checking out the base commit: {e:#}"))?;
    }
    let ran = seed_runner
        .run(&tree, SEED_COMMAND, req.timeout)
        .await
        .map_err(|e| format!("the seed build `{SEED_COMMAND}` could not run: {e}"))?;
    if ran.exit_status != 0 {
        return Err(format!(
            "the seed build `{SEED_COMMAND}` of the base commit exited {}: {}",
            ran.exit_status,
            last_line(&ran.output)
        ));
    }
    let fresh = work.0.join("new");
    fs::create_dir(&fresh).map_err(|e| format!("creating {}: {e}", fresh.display()))?;
    fs::rename(&target, fresh.join(verify_target::TARGET))
        .map_err(|e| format!("moving the built target directory: {e}"))?;
    verify_target::install(&fresh, root, key, &crate::cache::alive)
        .context("installing the seed")
        .map_err(|e| format!("{e:#}"))
}

/// The last non-empty line of a command's output, for a note.
fn last_line(output: &str) -> String {
    output
        .lines()
        .rev()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("no output")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_long_note_is_cut_on_a_character_boundary_and_kept_on_one_line() {
        let long = format!("first\nsecond {}", "é".repeat(500));
        let r = failed(Some("k"), long);
        let note = r.note.unwrap();
        assert!(!note.contains('\n'), "{note}");
        assert!(note.ends_with("..."), "{note}");
        assert!(note.len() <= NOTE_LIMIT + 3, "{}", note.len());
        assert_eq!(r.status, "failed");
        assert_eq!(r.key.as_deref(), Some("k"));
    }

    #[test]
    fn the_last_line_skips_blank_lines() {
        assert_eq!(last_line("a\nb\n\n  \n"), "b");
        assert_eq!(last_line(""), "no output");
    }
}
