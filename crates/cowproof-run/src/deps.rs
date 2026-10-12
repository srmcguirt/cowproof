//! Dependency prefetch before verify runs (D6, D11, D14, F-1).
//!
//! The verifier runs a lane's checks offline, so the dependencies they need are fetched
//! first, by the runner, outside any builder, into a cache the verifier gets read-only.
//!
//! * **Key** ([`dependency_cache_key`]): lockfile, registry configuration and target,
//!   computed on the REBUILT tree: the base commit, then `base.patch`, then the launch
//!   baseline, then `lane.patch`. The registry configuration is the one the tree had
//!   BEFORE `lane.patch` (see [`RegistryConfigSnapshot`]): a builder never chooses
//!   where its dependencies come from.
//! * **Cache**: `<cache root>/deps/<key>/cargo/{registry,git}`. A hit is a complete
//!   directory. A miss runs `cargo fetch --locked` in a sandbox into a private work
//!   directory and renames it into place, so a concurrent lane sees either no entry or a
//!   whole one, never half of one.
//! * **The fetch sandbox** ([`SandboxPolicy::dependency_fetch`]): it may write only its
//!   own work directory (the `CARGO_HOME` it fills and a private `HOME`) and read the
//!   rebuilt tree, the toolchain and the one `cargo` executable. It holds no key (its
//!   environment is `PATH`, `CARGO_HOME`, `RUSTUP_HOME` and `HOME`, nothing inherited),
//!   cannot see the lane's control directory, the other lanes or the real home, and
//!   `cargo fetch` runs no `build.rs` and no procedural macro. Its NETWORK is the one
//!   knob: [`FetchNetwork`], `COWPROOF_FETCH_NETWORK`. The default is `open`, full
//!   outbound network (a registry-only egress filter does not exist yet, so the
//!   alternatives are this or no real project ever fetches); `none` is a sandbox with no
//!   network at all, enough for a registry that is a directory in the repository.
//! * **Cache root**: `~/.cache/cowproof`, or the directory named by the environment
//!   variable `COWPROOF_CACHE_ROOT` ([`CACHE_ROOT_ENV`]). Tests set it so they never touch
//!   the real cache.
//! * **Upkeep**: every hit and install takes a lease and touches a use marker in the entry,
//!   and `cowproof cache prune` removes the unused (see [`crate::cache`]); a fetch also
//!   clears the stale work directories of interrupted runs.
//! * **What is covered**: Cargo only. A tree with a `Cargo.lock` is fetched; a tree
//!   without one has nothing to fetch and no cache entry. npm and the others are in the
//!   backlog, not here.

use crate::cache::{self, Alive};
use crate::{
    LaneLayout, NetworkMode, REGISTRY_CONFIGS, SandboxPolicy, dependency_cache_key,
    render_macos_profile, sandbox_command,
};
use anyhow::{Context, Result, bail};
use std::ffi::OsString;
use std::fs;
use std::io::Read;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// The environment variable that overrides the cache root.
pub const CACHE_ROOT_ENV: &str = "COWPROOF_CACHE_ROOT";

/// The environment variable that picks the fetch's network: `open` (default) or `none`.
pub const FETCH_NETWORK_ENV: &str = "COWPROOF_FETCH_NETWORK";

/// How long one `cargo fetch` may take.
pub const FETCH_TIMEOUT: Duration = Duration::from_secs(15 * 60);

/// The cache root: `$COWPROOF_CACHE_ROOT` when set and non-empty, else `~/.cache/cowproof`.
pub fn cache_root(home: &Path) -> PathBuf {
    cache_root_from(std::env::var_os(CACHE_ROOT_ENV), home)
}

fn cache_root_from(value: Option<OsString>, home: &Path) -> PathBuf {
    match value {
        Some(v) if !v.is_empty() => PathBuf::from(v),
        _ => home.join(".cache/cowproof"),
    }
}

/// The directory of one cache entry.
pub fn cache_dir(cache_root: &Path, key: &str) -> PathBuf {
    cache_root.join("deps").join(key)
}

/// What network the fetch sandbox gets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchNetwork {
    /// Full outbound network. The sandbox still holds no key, no control directory and
    /// no home.
    Open,
    /// No network at all.
    None,
}

impl FetchNetwork {
    /// From `COWPROOF_FETCH_NETWORK`: unset or empty is `open`.
    pub fn from_env() -> Result<Self> {
        Self::parse(std::env::var(FETCH_NETWORK_ENV).ok().as_deref())
    }

    fn parse(value: Option<&str>) -> Result<Self> {
        match value {
            None | Some("") | Some("open") => Ok(Self::Open),
            Some("none") => Ok(Self::None),
            Some(other) => bail!("{FETCH_NETWORK_ENV} must be `open` or `none`, not {other:?}"),
        }
    }

    /// The sandbox network mode.
    pub fn mode(self) -> NetworkMode {
        match self {
            Self::Open => NetworkMode::Unrestricted,
            Self::None => NetworkMode::None,
        }
    }
}

/// The platform part of the cache key (D14): what the fetch is for.
pub fn host_target() -> String {
    format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS)
}

/// How a prefetch ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchOutcome {
    /// The cache entry was already complete.
    Hit,
    /// This call fetched it.
    Fetched,
    /// The fetch could not run or failed; the reason is for the director.
    Failed(String),
}

impl FetchOutcome {
    /// The word the capsule records: `hit`, `fetched` or `failed`.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Hit => "hit",
            Self::Fetched => "fetched",
            Self::Failed(_) => "failed",
        }
    }
}

/// The result of [`prefetch`] for a tree that has something to fetch.
#[derive(Debug, Clone)]
pub struct Prefetch {
    /// The cache key (D11, D14).
    pub key: String,
    pub outcome: FetchOutcome,
    /// `<cache root>/deps/<key>`: valid when the outcome is not `Failed`.
    pub dir: PathBuf,
}

/// The `PATH` for the fetch and the `cargo` executable it runs.
#[derive(Debug, Clone)]
pub struct FetchTools {
    /// The fetch's `PATH`, as the verifier's is.
    pub path: String,
    /// The `cargo` to run, granted read-only when it lives under the hidden home.
    pub cargo: Option<PathBuf>,
}

/// The registry configuration files of a tree, as they were at one moment.
///
/// Take it after the base is rebuilt and before `lane.patch` is applied, and
/// [`restore`](Self::restore) it afterwards: whatever the patch did to those files, the
/// key and the fetch see the base's (D14).
#[derive(Debug)]
pub struct RegistryConfigSnapshot(Vec<(&'static str, Option<Vec<u8>>)>);

impl RegistryConfigSnapshot {
    /// Read every registry configuration file of `tree` (`None` for an absent one).
    pub fn take(tree: &Path) -> Result<Self> {
        let mut files = Vec::new();
        for name in REGISTRY_CONFIGS {
            let path = tree.join(name);
            let content = match fs::symlink_metadata(&path) {
                Ok(m) if m.is_file() => {
                    Some(fs::read(&path).with_context(|| format!("reading {}", path.display()))?)
                }
                // A directory or a symlink is not a configuration file cargo or npm
                // would read as one: treat it as absent.
                Ok(_) => None,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
            };
            files.push((*name, content));
        }
        Ok(Self(files))
    }

    /// Put the snapshot back: rewrite the files that existed, remove the ones that did
    /// not. A patch can have replaced a parent directory or the file with a symlink; the
    /// symlink is removed itself and never followed.
    pub fn restore(&self, tree: &Path) -> Result<()> {
        for (name, content) in &self.0 {
            let path = tree.join(name);
            if let Some(parent) = path.parent()
                && parent != tree
                && fs::symlink_metadata(parent).is_ok_and(|m| !m.is_dir())
            {
                fs::remove_file(parent)
                    .with_context(|| format!("removing {}", parent.display()))?;
            }
            match fs::symlink_metadata(&path) {
                Ok(m) if m.is_dir() => fs::remove_dir_all(&path),
                Ok(_) => fs::remove_file(&path),
                Err(_) => Ok(()),
            }
            .with_context(|| format!("clearing {}", path.display()))?;
            if let Some(content) = content {
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::write(&path, content)
                    .with_context(|| format!("restoring {}", path.display()))?;
            }
        }
        Ok(())
    }
}

/// Prefetch the dependencies of the tree that `rebuild` builds (D6, D11, D14).
///
/// `rebuild` receives an empty directory and must leave the rebuilt tree in it, with
/// registry configuration from the base (see [`RegistryConfigSnapshot`]). It runs in a
/// private work directory under the cache root, which is removed before this returns.
///
/// `Ok(None)`: the tree has no `Cargo.lock`, so there is nothing to fetch. `Ok(Some)`:
/// the key, and whether the cache was hit, fetched or the fetch failed. `Err`: the
/// rebuild or the key could not be made; the caller treats it like a failed fetch.
pub fn prefetch(
    rebuild: impl FnOnce(&Path) -> Result<()>,
    cache_root: &Path,
    lane: &LaneLayout,
    network: FetchNetwork,
    tools: &FetchTools,
    timeout: Duration,
    alive: Alive,
) -> Result<Option<Prefetch>> {
    let work_root = cache_root.join("deps-work");
    fs::create_dir_all(&work_root).context("creating the dependency work directory")?;
    fs::create_dir_all(cache_root.join("deps")).context("creating the dependency cache")?;
    // A `cowproof` that was interrupted left its work directory behind (nothing removes it
    // but the run that made it): clear the ones whose process is gone. Best effort, and
    // never a directory whose process is alive.
    let _ = cache::remove_stale_work(cache_root, &lane.real_home, alive);
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let work = work_root.join(format!("{}-{stamp}", std::process::id()));
    fs::create_dir(&work).context("creating the dependency work directory")?;
    let run = FetchRun {
        lane,
        network,
        tools,
        timeout,
        alive,
    };
    let result = prefetch_in(&work, rebuild, cache_root, &run);
    let _ = fs::remove_dir_all(&work);
    result
}

/// What one [`prefetch`] call runs with.
struct FetchRun<'a> {
    lane: &'a LaneLayout,
    network: FetchNetwork,
    tools: &'a FetchTools,
    timeout: Duration,
    alive: Alive<'a>,
}

fn prefetch_in(
    work: &Path,
    rebuild: impl FnOnce(&Path) -> Result<()>,
    cache_root: &Path,
    run: &FetchRun,
) -> Result<Option<Prefetch>> {
    let FetchRun {
        lane,
        network,
        tools,
        timeout,
        alive,
    } = *run;
    let tree = work.join("tree");
    fs::create_dir(&tree)?;
    rebuild(&tree).context("rebuilding the tree to fetch dependencies for")?;
    if !tree.join("Cargo.lock").is_file() {
        return Ok(None);
    }
    let key = dependency_cache_key(&tree, &host_target()).context("computing the cache key")?;
    let dir = cache_dir(cache_root, &key);
    let done = |outcome| {
        Ok(Some(Prefetch {
            key: key.clone(),
            outcome,
            dir: dir.clone(),
        }))
    };

    // A hit or an install is a USE of the entry: it takes this process's lease and
    // touches the use marker (`cache::claim`), so a prune neither removes an entry a run is
    // about to mount nor mistakes it for unused. `cowproof run` and `cowproof verify` both
    // mount what this function returns, so this is the one place.
    let claim = || cache::claim(&dir, std::process::id(), alive);
    // An entry a prune removed between the look and the claim is looked at again.
    for _ in 0..3 {
        match entry_state(&dir) {
            EntryState::Complete => match claim() {
                Ok(()) => return done(FetchOutcome::Hit),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return done(FetchOutcome::Failed(claim_failure(&dir, &e))),
            },
            EntryState::Absent => break,
            EntryState::Incomplete => {
                return done(FetchOutcome::Failed(format!(
                    "the cache entry {} exists but is incomplete; remove it",
                    dir.display()
                )));
            }
        }
    }

    let fresh = work.join("new");
    let outcome = match fetch_cargo(work, &tree, &fresh, lane, network, tools, timeout) {
        Ok(()) => match install(&fresh, &dir) {
            Ok(outcome) => match claim() {
                Ok(()) => outcome,
                Err(e) => FetchOutcome::Failed(claim_failure(&dir, &e)),
            },
            Err(e) => FetchOutcome::Failed(format!("{e:#}")),
        },
        Err(e) => FetchOutcome::Failed(format!("{e:#}")),
    };
    done(outcome)
}

fn claim_failure(dir: &Path, e: &std::io::Error) -> String {
    format!(
        "could not record the use of the cache entry {}: {e}",
        dir.display()
    )
}

#[derive(Debug, PartialEq, Eq)]
enum EntryState {
    Absent,
    Complete,
    Incomplete,
}

fn entry_state(dir: &Path) -> EntryState {
    match fs::symlink_metadata(dir) {
        Err(_) => EntryState::Absent,
        Ok(_) if dir.join("cargo/registry").is_dir() => EntryState::Complete,
        Ok(_) => EntryState::Incomplete,
    }
}

/// Move a finished fetch into the cache. The rename is the only moment the entry
/// appears, so it is whole or absent. If another lane installed the same key first the
/// rename fails, the entry is complete, and this lane's copy is dropped: a hit.
fn install(fresh: &Path, dir: &Path) -> Result<FetchOutcome> {
    match fs::rename(fresh, dir) {
        Ok(()) => Ok(FetchOutcome::Fetched),
        Err(e) => {
            if entry_state(dir) == EntryState::Complete {
                let _ = fs::remove_dir_all(fresh);
                Ok(FetchOutcome::Hit)
            } else {
                Err(e).with_context(|| format!("moving the fetched cache to {}", dir.display()))
            }
        }
    }
}

/// `cargo fetch --locked` in `tree`, filling `<fresh>/cargo`, under
/// [`SandboxPolicy::dependency_fetch`].
fn fetch_cargo(
    work: &Path,
    tree: &Path,
    fresh: &Path,
    lane: &LaneLayout,
    network: FetchNetwork,
    tools: &FetchTools,
    timeout: Duration,
) -> Result<()> {
    let cargo_home = fresh.join("cargo");
    let home = work.join("home");
    fs::create_dir_all(&cargo_home).context("creating the fetch CARGO_HOME")?;
    // The verifier mounts `registry` whether or not this fetch left one (a project with
    // only path dependencies has none): the mount point always exists.
    fs::create_dir_all(cargo_home.join("registry"))?;
    fs::create_dir_all(&home)?;

    let mut policy = SandboxPolicy::dependency_fetch(lane, fresh, network.mode());
    policy.rw_paths.push(home.clone());
    policy.ro_paths.push(tree.to_path_buf());
    if let Some(cargo) = tools
        .cargo
        .as_ref()
        .filter(|c| c.is_absolute() && c.is_file())
    {
        policy.executables.push(cargo.clone());
    }
    let program = match &tools.cargo {
        Some(c) if c.is_absolute() => c.to_string_lossy().into_owned(),
        _ => "cargo".to_string(),
    };
    // `RUSTUP_HOME` (the director's rustup home) comes from the policy, with its grant.
    let mut env = vec![
        ("PATH".to_string(), tools.path.clone()),
        ("HOME".to_string(), home.to_string_lossy().into_owned()),
    ];
    policy.env_set = vec![(
        "CARGO_HOME".to_string(),
        cargo_home.to_string_lossy().into_owned(),
    )];
    policy.apply_env(&mut env);

    let profile = work.join("fetch.sb");
    let platform = if cfg!(target_os = "macos") {
        "darwin"
    } else {
        "linux"
    };
    if platform == "darwin" {
        fs::write(&profile, render_macos_profile(&policy)?)
            .context("writing the fetch sandbox profile")?;
    }
    let argv = [program, "fetch".to_string(), "--locked".to_string()];
    let (sandbox_bin, sandbox_args) = sandbox_command(&policy, &profile, &argv, platform)?;

    // Output goes to a file the runner opened, so the sandboxed process needs no grant
    // for it and nothing can fill a pipe while this thread waits.
    let log_path = work.join("fetch.log");
    let log = fs::File::create(&log_path)?;
    let mut command = Command::new(sandbox_bin);
    command
        .args(sandbox_args)
        .env_clear()
        .envs(env)
        .current_dir(tree)
        .stdin(Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log)
        .process_group(0);
    let mut child = command
        .spawn()
        .context("starting the sandboxed cargo fetch")?;
    let pgid = child.id() as i32;
    let deadline = Instant::now() + timeout;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            kill_group(pgid);
            let _ = child.wait();
            bail!(
                "cargo fetch --locked timed out after {}s",
                timeout.as_secs()
            );
        }
        std::thread::sleep(Duration::from_millis(25));
    };
    // The leader is gone; nothing it started may outlive the fetch.
    kill_group(pgid);
    if !status.success() {
        bail!(
            "cargo fetch --locked failed ({status}): {}",
            tail(&log_path, 1500)
        );
    }
    Ok(())
}

fn kill_group(pgid: i32) {
    // SAFETY: killpg only signals the process group this function started.
    unsafe {
        libc::killpg(pgid, libc::SIGKILL);
    }
}

/// The last `max` bytes of a log, on one line.
fn tail(path: &Path, max: usize) -> String {
    let mut text = String::new();
    if let Ok(mut f) = fs::File::open(path) {
        let mut bytes = Vec::new();
        let _ = f.read_to_end(&mut bytes);
        let from = bytes.len().saturating_sub(max);
        text = String::from_utf8_lossy(&bytes[from..]).into_owned();
    }
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn complete_entry(dir: &Path) {
        fs::create_dir_all(dir.join("cargo/registry")).unwrap();
    }

    #[test]
    fn the_cache_root_is_the_variable_when_set_and_the_home_default_otherwise() {
        let home = Path::new("/home/x");
        assert_eq!(
            cache_root_from(Some("/var/tmp/c".into()), home),
            PathBuf::from("/var/tmp/c")
        );
        assert_eq!(
            cache_root_from(None, home),
            PathBuf::from("/home/x/.cache/cowproof")
        );
        assert_eq!(
            cache_root_from(Some("".into()), home),
            PathBuf::from("/home/x/.cache/cowproof")
        );
        assert_eq!(
            cache_dir(Path::new("/r"), "abc"),
            PathBuf::from("/r/deps/abc")
        );
    }

    #[test]
    fn the_fetch_network_defaults_to_open_and_none_is_a_sandbox_without_network() {
        assert_eq!(FetchNetwork::parse(None).unwrap(), FetchNetwork::Open);
        assert_eq!(FetchNetwork::parse(Some("")).unwrap(), FetchNetwork::Open);
        assert_eq!(
            FetchNetwork::parse(Some("open")).unwrap(),
            FetchNetwork::Open
        );
        assert_eq!(
            FetchNetwork::parse(Some("none")).unwrap(),
            FetchNetwork::None
        );
        assert_eq!(FetchNetwork::None.mode(), NetworkMode::None);
        assert_eq!(FetchNetwork::Open.mode(), NetworkMode::Unrestricted);
        let e = FetchNetwork::parse(Some("proxy")).unwrap_err().to_string();
        assert!(e.contains(FETCH_NETWORK_ENV) && e.contains("proxy"), "{e}");
    }

    #[test]
    fn outcome_names_are_the_three_capsule_words() {
        assert_eq!(FetchOutcome::Hit.name(), "hit");
        assert_eq!(FetchOutcome::Fetched.name(), "fetched");
        assert_eq!(FetchOutcome::Failed("why".into()).name(), "failed");
    }

    #[test]
    fn install_puts_the_whole_entry_in_place_and_leaves_no_work_copy() {
        let tmp = TempDir::new().unwrap();
        let fresh = tmp.path().join("new");
        complete_entry(&fresh);
        fs::write(fresh.join("cargo/registry/crate"), "x").unwrap();
        let dir = tmp.path().join("deps/key");
        fs::create_dir_all(dir.parent().unwrap()).unwrap();
        assert_eq!(install(&fresh, &dir).unwrap(), FetchOutcome::Fetched);
        assert_eq!(entry_state(&dir), EntryState::Complete);
        assert_eq!(
            fs::read_to_string(dir.join("cargo/registry/crate")).unwrap(),
            "x"
        );
        assert!(!fresh.exists(), "the work copy moved, it was not copied");
    }

    #[test]
    fn install_loses_a_race_as_a_hit_and_keeps_the_winners_entry_untouched() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("deps/key");
        complete_entry(&dir);
        fs::write(dir.join("cargo/registry/winner"), "w").unwrap();
        let fresh = tmp.path().join("new");
        complete_entry(&fresh);
        fs::write(fresh.join("cargo/registry/loser"), "l").unwrap();
        assert_eq!(install(&fresh, &dir).unwrap(), FetchOutcome::Hit);
        assert!(dir.join("cargo/registry/winner").is_file());
        assert!(!dir.join("cargo/registry/loser").exists());
        assert!(!fresh.exists(), "the losing copy is removed");
    }

    #[test]
    fn two_threads_installing_one_key_leave_one_whole_entry_and_one_fetched() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("deps/key");
        fs::create_dir_all(dir.parent().unwrap()).unwrap();
        let outcomes: Vec<FetchOutcome> = std::thread::scope(|s| {
            let handles: Vec<_> = (0..8)
                .map(|i| {
                    let fresh = tmp.path().join(format!("new{i}"));
                    complete_entry(&fresh);
                    fs::write(fresh.join("cargo/registry/who"), i.to_string()).unwrap();
                    let dir = dir.clone();
                    s.spawn(move || install(&fresh, &dir).unwrap())
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        assert_eq!(
            outcomes
                .iter()
                .filter(|o| **o == FetchOutcome::Fetched)
                .count(),
            1,
            "{outcomes:?}"
        );
        assert_eq!(entry_state(&dir), EntryState::Complete);
        for i in 0..8 {
            assert!(!tmp.path().join(format!("new{i}")).exists());
        }
    }

    #[test]
    fn a_directory_without_a_registry_is_incomplete_not_a_hit() {
        let tmp = TempDir::new().unwrap();
        assert_eq!(entry_state(&tmp.path().join("nope")), EntryState::Absent);
        fs::create_dir_all(tmp.path().join("half/cargo")).unwrap();
        assert_eq!(
            entry_state(&tmp.path().join("half")),
            EntryState::Incomplete
        );
        complete_entry(&tmp.path().join("whole"));
        assert_eq!(entry_state(&tmp.path().join("whole")), EntryState::Complete);
    }

    #[test]
    fn restoring_the_snapshot_undoes_what_a_patch_did_to_registry_config() {
        let tmp = TempDir::new().unwrap();
        let t = tmp.path();
        fs::create_dir_all(t.join(".cargo")).unwrap();
        fs::write(t.join(".cargo/config.toml"), "base config\n").unwrap();
        let snapshot = RegistryConfigSnapshot::take(t).unwrap();
        // The patch edits one config and adds another.
        fs::write(t.join(".cargo/config.toml"), "builder config\n").unwrap();
        fs::write(t.join(".npmrc"), "registry=http://evil\n").unwrap();
        snapshot.restore(t).unwrap();
        assert_eq!(
            fs::read_to_string(t.join(".cargo/config.toml")).unwrap(),
            "base config\n"
        );
        assert!(
            !t.join(".npmrc").exists(),
            "a config the base lacked is removed"
        );
    }

    #[test]
    fn restoring_never_follows_a_symlinked_parent_out_of_the_tree() {
        let tmp = TempDir::new().unwrap();
        let t = tmp.path().join("tree");
        let outside = tmp.path().join("outside");
        fs::create_dir_all(&t).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("config.toml"), "must survive\n").unwrap();
        let snapshot = RegistryConfigSnapshot::take(&t).unwrap();
        std::os::unix::fs::symlink(&outside, t.join(".cargo")).unwrap();
        snapshot.restore(&t).unwrap();
        assert_eq!(
            fs::read_to_string(outside.join("config.toml")).unwrap(),
            "must survive\n",
            "the file behind the symlink was removed"
        );
        assert!(
            !t.join(".cargo").exists(),
            "the symlink itself is gone: the base had no .cargo"
        );
    }

    #[test]
    fn a_symlinked_config_file_is_taken_as_absent() {
        let tmp = TempDir::new().unwrap();
        let t = tmp.path();
        fs::write(t.join("real"), "x").unwrap();
        std::os::unix::fs::symlink(t.join("real"), t.join(".npmrc")).unwrap();
        let snapshot = RegistryConfigSnapshot::take(t).unwrap();
        snapshot.restore(t).unwrap();
        assert!(!t.join(".npmrc").exists());
        assert!(t.join("real").exists());
    }

    #[test]
    fn a_tree_without_a_cargo_lock_has_nothing_to_fetch_and_no_cache_entry() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("cache");
        let lane = LaneLayout {
            clone: tmp.path().join("lane/clone"),
            home: tmp.path().join("lane/home"),
            scratch: tmp.path().join("lane/scratch"),
            control: tmp.path().join("lane/control"),
            real_home: tmp.path().join("home"),
            sock: tmp.path().join("lane/sock/runner.sock"),
            lanes_root: tmp.path().to_path_buf(),
        };
        let tools = FetchTools {
            path: "/usr/bin:/bin".into(),
            cargo: None,
        };
        let got = prefetch(
            |tree| {
                fs::write(tree.join("package-lock.json"), "{}")?;
                Ok(())
            },
            &root,
            &lane,
            FetchNetwork::None,
            &tools,
            Duration::from_secs(5),
            &|_| true,
        )
        .unwrap();
        assert!(got.is_none());
        assert_eq!(
            fs::read_dir(root.join("deps")).unwrap().count(),
            0,
            "no entry was made"
        );
        assert_eq!(
            fs::read_dir(root.join("deps-work")).unwrap().count(),
            0,
            "the work directory is removed"
        );
    }

    #[test]
    fn a_complete_entry_is_a_hit_and_nothing_runs() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("cache");
        let lane = LaneLayout {
            clone: tmp.path().join("lane/clone"),
            home: tmp.path().join("lane/home"),
            scratch: tmp.path().join("lane/scratch"),
            control: tmp.path().join("lane/control"),
            real_home: tmp.path().join("home"),
            sock: tmp.path().join("lane/sock/runner.sock"),
            lanes_root: tmp.path().to_path_buf(),
        };
        // No cargo and no sandbox are available to this test: a hit must not need them.
        let tools = FetchTools {
            path: String::new(),
            cargo: None,
        };
        let build = |tree: &Path| -> Result<()> {
            fs::write(tree.join("Cargo.lock"), "# lock\n")?;
            Ok(())
        };
        let key = {
            let t = tmp.path().join("probe");
            fs::create_dir(&t).unwrap();
            build(&t).unwrap();
            dependency_cache_key(&t, &host_target()).unwrap()
        };
        complete_entry(&cache_dir(&root, &key));
        let got = prefetch(
            build,
            &root,
            &lane,
            FetchNetwork::None,
            &tools,
            Duration::from_secs(5),
            &|_| true,
        )
        .unwrap()
        .unwrap();
        assert_eq!(got.outcome, FetchOutcome::Hit);
        assert_eq!(got.key, key);
        assert_eq!(got.dir, cache_dir(&root, &key));
        // The hit is a use: this process holds a lease and the marker is fresh.
        let entry = cache_dir(&root, &key);
        assert!(
            entry
                .join(cache::LEASES)
                .join(std::process::id().to_string())
                .is_file()
        );
        let used = fs::metadata(entry.join(cache::LAST_USED))
            .unwrap()
            .modified()
            .unwrap();
        assert!(SystemTime::now().duration_since(used).unwrap() < Duration::from_secs(60));
    }

    #[test]
    fn a_fetch_clears_the_work_directory_of_an_interrupted_run_and_only_that() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("cache");
        let lane = LaneLayout {
            clone: tmp.path().join("lane/clone"),
            home: tmp.path().join("lane/home"),
            scratch: tmp.path().join("lane/scratch"),
            control: tmp.path().join("lane/control"),
            real_home: tmp.path().join("home"),
            sock: tmp.path().join("lane/sock/runner.sock"),
            lanes_root: tmp.path().to_path_buf(),
        };
        let (dead, live) = (4_000_002u32, std::process::id());
        let work = root.join("deps-work");
        for name in [format!("{dead}-1"), format!("{live}-1")] {
            fs::create_dir_all(work.join(name).join("tree")).unwrap();
        }
        let tools = FetchTools {
            path: String::new(),
            cargo: None,
        };
        let got = prefetch(
            |_| Ok(()),
            &root,
            &lane,
            FetchNetwork::None,
            &tools,
            Duration::from_secs(5),
            &|pid| pid == live,
        )
        .unwrap();
        assert!(got.is_none());
        assert!(!work.join(format!("{dead}-1")).exists());
        assert!(work.join(format!("{live}-1/tree")).is_dir());
    }
}
