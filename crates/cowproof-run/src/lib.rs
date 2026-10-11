//! Sandbox policy for every sandboxed process cowproof starts (D8).
//!
//! One [`SandboxPolicy`] value describes what a process may touch. It is
//! rendered to a macOS Seatbelt profile ([`render_macos_profile`]) or to
//! bubblewrap arguments ([`render_bwrap_args`]). The design follows
//! anthropics/sandbox-runtime (D4, see `NOTICE`).
//!
//! Path rule (the Seatbelt matcher compares real paths, so a rule written for
//! a symlinked spelling such as `/tmp/x` or `/var/folders/...` silently does
//! not apply: an allow fails closed, a deny fails open). Every path is
//! therefore resolved by [`canonicalize_for_sandbox`] at render time, after
//! any caller edits to the policy, and only the resolved path is emitted.

pub mod bridge;
pub mod claude;
pub mod deps;
pub mod director;
pub mod lane;
pub mod prefix;
pub mod proxy;
pub mod stream;
pub mod tools;
pub mod wire;

use sha2::{Digest, Sha256};

use anyhow::{Context, Result, anyhow, bail};
use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};

pub mod escalate;
pub mod watch;

/// Network mode for sandbox policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkMode {
    /// No network access.
    None,
    /// Access to the lane's egress proxy through the in-sandbox bridge (D24).
    /// `socket` is the proxy's Unix socket: granted by exact path on macOS
    /// (connect) and bound in by itself on Linux (`--ro-bind`). `port` is the
    /// bridge's `127.0.0.1` port inside the sandbox: on macOS it is the only
    /// local port the sandbox may bind or connect to; on Linux the sandbox has
    /// its own empty network namespace (`--unshare-net`) and the port is only
    /// the bridge's address in it.
    Proxy { port: u16, socket: PathBuf },
    /// Registry-only access through the proxy.
    RegistryReadOnly { port: u16, socket: PathBuf },
    /// Unrestricted network (legacy: current runner until egress proxy lands).
    /// Documented as legacy; used ONLY by existing CLI runner with explicit opt-in.
    Unrestricted,
}

/// Sandbox policy defining filesystem and network access for a sandboxed process.
#[derive(Debug, Clone)]
pub struct SandboxPolicy {
    /// Read-write paths.
    pub rw_paths: Vec<PathBuf>,
    /// Read-only paths.
    pub ro_paths: Vec<PathBuf>,
    /// Paths neither readable nor writable, applied after every grant
    /// (the lane control directory, A-3).
    pub deny_paths: Vec<PathBuf>,
    /// Network access mode.
    pub network: NetworkMode,
    /// Environment variables to set inside the sandbox.
    pub env_set: Vec<(String, String)>,
    /// Environment variables allowed (if None, all allowed).
    pub env_allowlist: Option<BTreeSet<String>>,
    /// The user's real home directory. It is hidden (denied on macOS, a tmpfs
    /// on Linux) except for the toolchain paths the policy grants back.
    pub home: PathBuf,
    /// The one Unix socket the sandboxed process may connect to: the lane's
    /// runner socket (D22). Only `builder` and `run_check` set it. The grant
    /// covers the socket and nothing else: no other socket, and no other file
    /// in the socket's directory (macOS: denied for reads; Linux: only the
    /// socket file is bound in).
    pub connect_socket: Option<PathBuf>,
    /// The directory that holds every lane. Hidden in the sandbox to prevent
    /// cross-lane access.
    pub lanes_root: PathBuf,
    /// Executable files (not directories) to grant read-only access to.
    /// Symlinks are resolved to their canonical targets, and both the symlink
    /// and target are granted. Used for toolchain binaries that live under
    /// the hidden home.
    pub executables: Vec<PathBuf>,
}

impl SandboxPolicy {
    /// Builder for a lane doing development work.
    /// rw: clone, lane home (D18: its `.cargo` is the builder's CARGO_HOME), scratch
    /// ro: real ~/.cargo/registry and ~/.cargo/git; real ~/.rustup
    /// network: must be passed by caller (not hardcoded)
    pub fn builder(lane: &LaneLayout, network: NetworkMode) -> Self {
        let lane_cargo = lane.home.join(".cargo");
        Self {
            rw_paths: vec![
                lane.clone.clone(),
                lane.scratch.clone(),
                lane.home.clone(),
                lane_cargo.clone(),
            ],
            ro_paths: vec![
                lane.real_home.join(".rustup"),
                lane.real_home.join(".cargo/registry"),
                lane.real_home.join(".cargo/git"),
            ],
            deny_paths: vec![lane.control.clone()],
            network,
            // Claude Code builds its own temp directory as
            // `$CLAUDE_CODE_TMPDIR/claude-<uid>` (from `$TMPDIR`, else `/tmp`, when
            // unset), and its Bash tool cannot start without one it may write.
            env_set: vec![
                cargo_home(&lane_cargo),
                tmpdir(lane),
                (
                    "CLAUDE_CODE_TMPDIR".to_string(),
                    lane_tmp(&lane.scratch).to_string_lossy().into_owned(),
                ),
            ],
            env_allowlist: None,
            home: lane.real_home.clone(),
            connect_socket: Some(lane.sock.clone()),
            lanes_root: lane.lanes_root.clone(),
            executables: vec![],
        }
    }

    /// Builder for a lane with read-only access to specific executables.
    ///
    /// Like `builder`, but also grants read-only access to individual executable files.
    /// Each executable is canonicalized (symlinks followed to their targets).
    /// Refuses non-regular files and paths inside the lanes root or repo.
    ///
    /// - macOS: `(allow file-read* (literal "<canonical file>"))`, plus metadata on
    ///   ancestors of the executable and the lanes root so path walks work.
    /// - Linux: `--ro-bind <file> <file>`.
    pub fn builder_with_executables(
        lane: &LaneLayout,
        network: NetworkMode,
        executables: &[PathBuf],
    ) -> Result<Self> {
        let mut policy = Self::builder(lane, network);
        policy.executables = executables.to_vec();
        Ok(policy)
    }

    /// Verifier for checking patches.
    /// rw: clone, scratch, verifier cache dir (passed as parameter)
    /// ro: real ~/.rustup
    /// network: none (D6)
    pub fn verifier(lane: &LaneLayout, cache_dir: &Path) -> Self {
        let verifier_cargo = cache_dir.join(".cargo");
        Self {
            rw_paths: vec![
                lane.clone.clone(),
                lane.scratch.clone(),
                verifier_cargo.clone(),
            ],
            ro_paths: vec![lane.real_home.join(".rustup")],
            deny_paths: vec![lane.control.clone()],
            network: NetworkMode::None,
            // Checks never reach a registry (D6): cargo is told so, and fails fast
            // instead of retrying a network that is not there.
            env_set: vec![
                cargo_home(&verifier_cargo),
                tmpdir(lane),
                ("CARGO_NET_OFFLINE".to_string(), "true".to_string()),
            ],
            env_allowlist: None,
            home: lane.real_home.clone(),
            connect_socket: None,
            lanes_root: lane.lanes_root.clone(),
            executables: vec![],
        }
    }

    /// Mount the trusted dependency cache (D6) into this policy: the cache's
    /// `cargo/registry`, and `cargo/git` when it has one, become READ-ONLY grants.
    /// The caller links them into the verifier's own `CARGO_HOME`
    /// ([`link_dependency_cache`]), so cargo finds them there and can write nothing
    /// into them. On macOS the profile also denies writes to every read-only grant,
    /// so the mount stays read-only wherever the cache lives.
    pub fn with_dependency_cache(mut self, deps_dir: &Path) -> Self {
        for name in DEPENDENCY_CACHE_DIRS {
            let dir = deps_dir.join("cargo").join(name);
            if dir.is_dir() {
                self.ro_paths.push(dir);
            }
        }
        self
    }

    /// Run check: read-write to clone and scratch (and the lane's own cargo
    /// home); no network, except the lane's runner socket (a check run through
    /// `run_check` may itself call the builder tools).
    pub fn run_check(lane: &LaneLayout) -> Self {
        let lane_cargo = lane.home.join(".cargo");
        Self {
            rw_paths: vec![lane.clone.clone(), lane.scratch.clone(), lane_cargo.clone()],
            ro_paths: vec![lane.real_home.join(".rustup")],
            deny_paths: vec![lane.control.clone()],
            network: NetworkMode::None,
            env_set: vec![cargo_home(&lane_cargo), tmpdir(lane)],
            env_allowlist: None,
            home: lane.real_home.clone(),
            connect_socket: Some(lane.sock.clone()),
            lanes_root: lane.lanes_root.clone(),
            executables: vec![],
        }
    }

    /// Dependency fetch: write to cache_dir; read-only registry access.
    /// network: must be passed by caller
    pub fn dependency_fetch(lane: &LaneLayout, cache_dir: &Path, network: NetworkMode) -> Self {
        Self {
            rw_paths: vec![cache_dir.to_path_buf()],
            ro_paths: vec![],
            deny_paths: vec![lane.control.clone()],
            network,
            env_set: vec![],
            env_allowlist: None,
            home: lane.real_home.clone(),
            connect_socket: None,
            lanes_root: lane.lanes_root.clone(),
            executables: vec![],
        }
    }

    /// Capture for porting: read-write to clone and scratch; no network (D10).
    pub fn capture(lane: &LaneLayout) -> Self {
        Self {
            rw_paths: vec![lane.clone.clone(), lane.scratch.clone()],
            ro_paths: vec![],
            deny_paths: vec![lane.control.clone()],
            network: NetworkMode::None,
            env_set: vec![tmpdir(lane)],
            env_allowlist: None,
            home: lane.real_home.clone(),
            connect_socket: None,
            lanes_root: lane.lanes_root.clone(),
            executables: vec![],
        }
    }

    /// Apply `env_set` to a child environment, replacing an existing value for
    /// the same key.
    pub fn apply_env(&self, env: &mut Vec<(String, String)>) {
        for (k, v) in &self.env_set {
            match env.iter_mut().find(|(ek, _)| ek == k) {
                Some(slot) => slot.1 = v.clone(),
                None => env.push((k.clone(), v.clone())),
            }
        }
    }
}

/// The directories of a fetched `CARGO_HOME` that the verifier gets (D6): the
/// registry index, `.crate` files and unpacked sources, and git dependencies.
pub const DEPENDENCY_CACHE_DIRS: [&str; 2] = ["registry", "git"];

/// Link the cache's `registry` (and `git`, when present) into `cargo_home`, the
/// verifier's private `CARGO_HOME`. The links point at the cache, which
/// [`SandboxPolicy::with_dependency_cache`] grants read-only; the rest of
/// `cargo_home` (its package lock, config) stays writable and private to the verifier.
pub fn link_dependency_cache(deps_dir: &Path, cargo_home: &Path) -> Result<()> {
    for name in DEPENDENCY_CACHE_DIRS {
        let target = deps_dir.join("cargo").join(name);
        if !target.is_dir() {
            continue;
        }
        let link = cargo_home.join(name);
        match std::fs::symlink_metadata(&link) {
            Ok(m) if m.is_dir() => std::fs::remove_dir_all(&link),
            Ok(_) => std::fs::remove_file(&link),
            Err(_) => Ok(()),
        }
        .with_context(|| format!("clearing {}", link.display()))?;
        std::os::unix::fs::symlink(&target, &link)
            .with_context(|| format!("linking {} into the verifier's CARGO_HOME", name))?;
    }
    Ok(())
}

/// The temp directory a sandboxed process gets: a directory of the lane's own
/// scratch, which every policy that writes temp files already grants read-write.
/// On macOS the profile denies writes outside the grants, and a process with no
/// `TMPDIR` falls back to `/tmp` or the system temp directory, both denied. The
/// caller creates it before launch (`create_dir_all`).
pub fn lane_tmp(scratch: &Path) -> PathBuf {
    scratch.join("tmp")
}

fn tmpdir(lane: &LaneLayout) -> (String, String) {
    (
        "TMPDIR".to_string(),
        lane_tmp(&lane.scratch).to_string_lossy().into_owned(),
    )
}

fn cargo_home(path: &Path) -> (String, String) {
    (
        "CARGO_HOME".to_string(),
        path.to_string_lossy().into_owned(),
    )
}

/// Lane filesystem layout.
#[derive(Debug, Clone)]
pub struct LaneLayout {
    /// Clone of the repository.
    pub clone: PathBuf,
    /// The lane's private HOME (not the user's real home).
    pub home: PathBuf,
    /// Scratch directory.
    pub scratch: PathBuf,
    /// Lane control directory: held-out checks, rulings, queue. Never
    /// readable or writable from inside a sandbox (A-3).
    pub control: PathBuf,
    /// The user's real home directory, hidden from the sandbox.
    pub real_home: PathBuf,
    /// The runner socket FILE, `<lane>/sock/runner.sock` (D22). Its directory
    /// is created by `prepare_lane` with mode 0700; the runner binds the
    /// socket there before the builder starts.
    pub sock: PathBuf,
    /// The directory that holds every lane, with this lane at `<lanes_root>/<id>`.
    /// Hidden in sandbox policies to prevent cross-lane access.
    pub lanes_root: PathBuf,
}

/// Lockfiles, at the tree root only, that determine the dependencies (D11).
const LOCKFILES: &[&str] = &[
    "Cargo.lock",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "Gemfile.lock",
];

/// Registry and source configuration, relative to the tree root (D14). The cache key
/// hashes them, the fetch reads them from the base only, and the protected-paths gate
/// refuses a lane patch that touches them.
pub const REGISTRY_CONFIGS: &[&str] = &[
    ".cargo/config.toml",
    ".cargo/config",
    ".npmrc",
    ".yarnrc",
    ".yarnrc.yml",
];

/// Compute a deterministic cache key for dependency resolution (D11, D14).
///
/// The key is a sha256 hash over the target triple, then every lockfile and registry
/// config that exists at the tree root (never in subdirectories such as `target/` or
/// `node_modules/`), in a fixed order. Each file is hashed with its relative name and
/// its length, so the same bytes in a different file, or bytes moving from one file to
/// the next, give a different key. Changing the triple, a lockfile or a registry config
/// changes the key; creation order and directory iteration order do not.
pub fn dependency_cache_key(repo_tree: &Path, target_triple: &str) -> Result<String> {
    let mut hasher = Sha256::new();
    hasher.update(target_triple.len().to_le_bytes());
    hasher.update(target_triple.as_bytes());

    let mut names: Vec<&str> = LOCKFILES.iter().chain(REGISTRY_CONFIGS).copied().collect();
    names.sort_unstable();
    for name in names {
        let path = repo_tree.join(name);
        if !path.is_file() {
            continue;
        }
        let contents =
            std::fs::read(&path).with_context(|| format!("cannot read {}", path.display()))?;
        hasher.update(name.len().to_le_bytes());
        hasher.update(name.as_bytes());
        hasher.update(contents.len().to_le_bytes());
        hasher.update(&contents);
    }

    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(test)]
mod cache_key_tests {
    use super::*;

    #[test]
    fn same_inputs_produce_same_key() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();

        std::fs::create_dir_all(root.join(".cargo")).unwrap();
        std::fs::write(root.join("Cargo.lock"), "deps = []").unwrap();
        std::fs::write(root.join(".cargo").join("config.toml"), "[build]").unwrap();

        let key1 = dependency_cache_key(root, "x86_64-unknown-linux-gnu").unwrap();
        let key2 = dependency_cache_key(root, "x86_64-unknown-linux-gnu").unwrap();

        assert_eq!(key1, key2);
    }

    #[test]
    fn different_triple_produces_different_key() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();

        std::fs::write(root.join("Cargo.lock"), "deps = []").unwrap();
        std::fs::create_dir_all(root.join(".cargo")).ok();
        std::fs::write(root.join(".cargo").join("config.toml"), "[build]").unwrap();

        let key1 = dependency_cache_key(root, "x86_64-unknown-linux-gnu").unwrap();
        let key2 = dependency_cache_key(root, "aarch64-unknown-linux-gnu").unwrap();

        assert_ne!(key1, key2);
    }

    #[test]
    fn different_lockfile_produces_different_key() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let triple = "x86_64-unknown-linux-gnu";

        std::fs::create_dir_all(root.join(".cargo")).ok();
        std::fs::write(root.join(".cargo").join("config.toml"), "[build]").unwrap();

        // Create Cargo.lock with content A
        std::fs::write(root.join("Cargo.lock"), "old").unwrap();
        let key1 = dependency_cache_key(root, triple).unwrap();

        // Update Cargo.lock with content B
        std::fs::write(root.join("Cargo.lock"), "new").unwrap();
        let key2 = dependency_cache_key(root, triple).unwrap();

        assert_ne!(key1, key2);
    }

    #[test]
    fn different_config_produces_different_key() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let triple = "x86_64-unknown-linux-gnu";

        std::fs::write(root.join("Cargo.lock"), "deps").unwrap();

        // Create config with A
        std::fs::create_dir_all(root.join(".cargo")).ok();
        std::fs::write(root.join(".cargo").join("config.toml"), "[build]").unwrap();
        let key1 = dependency_cache_key(root, triple).unwrap();

        // Update config to B
        std::fs::write(
            root.join(".cargo").join("config.toml"),
            "[build]\nopt-level = 2",
        )
        .unwrap();
        let key2 = dependency_cache_key(root, triple).unwrap();

        assert_ne!(key1, key2);
    }

    #[test]
    fn file_order_does_not_affect_key() {
        // This test verifies the key is order-independent by creating files
        // in a different order and checking the key is the same.
        let tmp1 = tempfile::tempdir().unwrap();
        let tmp2 = tempfile::tempdir().unwrap();
        let triple = "x86_64-unknown-linux-gnu";

        // Create files in tmp1 in order A, B, C
        std::fs::write(tmp1.path().join("Cargo.lock"), "cargo").unwrap();
        std::fs::create_dir_all(tmp1.path().join(".cargo")).ok();
        std::fs::write(tmp1.path().join(".cargo").join("config.toml"), "[cfg]").unwrap();
        std::fs::write(tmp1.path().join("package-lock.json"), "npm").unwrap();

        // Create files in tmp2 in order C, B, A (reverse)
        std::fs::write(tmp2.path().join("package-lock.json"), "npm").unwrap();
        std::fs::create_dir_all(tmp2.path().join(".cargo")).ok();
        std::fs::write(tmp2.path().join(".cargo").join("config.toml"), "[cfg]").unwrap();
        std::fs::write(tmp2.path().join("Cargo.lock"), "cargo").unwrap();

        let key1 = dependency_cache_key(tmp1.path(), triple).unwrap();
        let key2 = dependency_cache_key(tmp2.path(), triple).unwrap();

        assert_eq!(key1, key2);
    }

    #[test]
    fn key_handles_missing_lockfiles() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();

        std::fs::create_dir_all(root.join(".cargo")).ok();
        std::fs::write(root.join(".cargo").join("config.toml"), "[build]").unwrap();

        // Should not panic even though there's no lockfile
        let key = dependency_cache_key(root, "x86_64-unknown-linux-gnu").unwrap();
        assert!(!key.is_empty());
    }

    #[test]
    fn key_handles_missing_config() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();

        std::fs::write(root.join("Cargo.lock"), "deps").unwrap();

        // Should not panic even though there's no config
        let key = dependency_cache_key(root, "x86_64-unknown-linux-gnu").unwrap();
        assert!(!key.is_empty());
    }

    #[test]
    fn lockfile_in_nested_dir_does_not_affect_key() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let triple = "x86_64-unknown-linux-gnu";

        std::fs::write(root.join("Cargo.lock"), "root").unwrap();

        let key1 = dependency_cache_key(root, triple).unwrap();

        // Create lockfile in node_modules/ (should be ignored)
        std::fs::create_dir_all(root.join("node_modules/dep")).ok();
        std::fs::write(root.join("node_modules/dep/package-lock.json"), "nested").unwrap();

        let key2 = dependency_cache_key(root, triple).unwrap();

        // Key must be the same; nested lockfile is ignored
        assert_eq!(key1, key2);

        // Create another in target/ (should also be ignored)
        std::fs::create_dir_all(root.join("target/debug")).ok();
        std::fs::write(root.join("target/debug/Cargo.lock"), "target").unwrap();

        let key3 = dependency_cache_key(root, triple).unwrap();

        // Still the same
        assert_eq!(key1, key3);
    }

    #[test]
    fn same_bytes_in_a_different_lockfile_change_the_key() {
        let triple = "x86_64-unknown-linux-gnu";
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        std::fs::write(a.path().join("Cargo.lock"), "same").unwrap();
        std::fs::write(b.path().join("package-lock.json"), "same").unwrap();
        assert_ne!(
            dependency_cache_key(a.path(), triple).unwrap(),
            dependency_cache_key(b.path(), triple).unwrap()
        );

        // Bytes moving across the boundary between two files change the key too.
        let c = tempfile::tempdir().unwrap();
        let d = tempfile::tempdir().unwrap();
        std::fs::write(c.path().join("Cargo.lock"), "ab").unwrap();
        std::fs::write(c.path().join("package-lock.json"), "c").unwrap();
        std::fs::write(d.path().join("Cargo.lock"), "a").unwrap();
        std::fs::write(d.path().join("package-lock.json"), "bc").unwrap();
        assert_ne!(
            dependency_cache_key(c.path(), triple).unwrap(),
            dependency_cache_key(d.path(), triple).unwrap()
        );
    }
}

/// Resolve `path` to the spelling the kernel (and so Seatbelt) compares.
///
/// The longest existing prefix is resolved with `fs::canonicalize` (symlinks
/// such as macOS `/tmp` and `/var`, and any `..` in that prefix, are
/// followed); the not-yet-existing remainder is appended unchanged. A `..` in
/// that remainder is rejected, because folding it lexically could aim a rule
/// past a symlink the kernel would follow. A symlink that exists but cannot be
/// resolved (dangling, loop) is an error rather than a silently unmatched
/// rule. Relative paths are rejected.
pub fn canonicalize_for_sandbox(path: &Path) -> Result<PathBuf> {
    if !path.is_absolute() {
        bail!("sandbox path must be absolute: {}", path.display());
    }
    let comps: Vec<Component<'_>> = path.components().collect();
    let mut n = comps.len();
    let mut resolved = loop {
        let prefix: PathBuf = comps[..n].iter().collect();
        match std::fs::symlink_metadata(&prefix) {
            Ok(_) => {
                break std::fs::canonicalize(&prefix)
                    .with_context(|| format!("cannot resolve {}", prefix.display()))?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && n > 1 => n -= 1,
            Err(e) => {
                return Err(e).with_context(|| format!("cannot inspect {}", prefix.display()));
            }
        }
    };
    for c in &comps[n..] {
        match c {
            Component::Normal(name) => resolved.push(name),
            _ => bail!(
                "unresolved component {:?} in non-existent part of {}",
                c,
                path.display()
            ),
        }
    }
    Ok(resolved)
}

/// A policy with every path resolved, deduplicated and checked.
struct Resolved {
    home: PathBuf,
    rw: BTreeSet<PathBuf>,
    ro: BTreeSet<PathBuf>,
    lanes_root: PathBuf,
    deny: BTreeSet<PathBuf>,
    credentials: Vec<PathBuf>,
    /// The connectable socket file and its directory, resolved.
    socket: Option<(PathBuf, PathBuf)>,
    /// Executable files: both original paths (for symlinks) and canonical targets.
    /// Stored as BTreeSet to deduplicate when symlink and target are both listed.
    executables: BTreeSet<PathBuf>,
}

fn resolve_all(paths: &[PathBuf]) -> Result<BTreeSet<PathBuf>> {
    paths.iter().map(|p| canonicalize_for_sandbox(p)).collect()
}

fn resolve(policy: &SandboxPolicy) -> Result<Resolved> {
    let home = canonicalize_for_sandbox(&policy.home)?;
    let rw = resolve_all(&policy.rw_paths)?;
    let mut ro = resolve_all(&policy.ro_paths)?;
    // D10: the toolchain stays readable for every policy.
    ro.insert(canonicalize_for_sandbox(&home.join(".rustup"))?);
    for p in rw.iter().chain(ro.iter()) {
        if home.starts_with(p) {
            bail!(
                "grant {} would expose the hidden home {}",
                p.display(),
                home.display()
            );
        }
    }
    let deny = resolve_all(&policy.deny_paths)?;
    // D18: cargo credentials stay denied on every policy.
    let credentials = [".cargo/credentials.toml", ".cargo/credentials"]
        .iter()
        .map(|c| canonicalize_for_sandbox(&home.join(c)))
        .collect::<Result<Vec<_>>>()?;

    // Hide the lanes root to prevent cross-lane access (the backlog).
    // Check against real_home (the user's actual home), not the lane's private home,
    // which is expected to be inside lanes_root.
    let lanes_root = canonicalize_for_sandbox(&policy.lanes_root)?;
    if lanes_root == home {
        bail!(
            "lanes_root {} must not equal the real home {}",
            lanes_root.display(),
            home.display()
        );
    }
    if lanes_root == Path::new("/") {
        bail!("lanes_root must not be the filesystem root /");
    }
    if home.starts_with(&lanes_root) {
        bail!(
            "lanes_root {} must not contain the real home {}",
            lanes_root.display(),
            home.display()
        );
    }

    let socket = match &policy.connect_socket {
        None => None,
        Some(sock) => {
            let sock = canonicalize_for_sandbox(sock)?;
            let dir = sock
                .parent()
                .ok_or_else(|| anyhow!("socket {} has no directory", sock.display()))?
                .to_path_buf();
            // The directory is denied for reads and writes on macOS; a grant
            // inside it would be cut off by that rule.
            if let Some(p) = rw.iter().chain(ro.iter()).find(|p| p.starts_with(&dir)) {
                bail!(
                    "grant {} lies inside the socket directory {}",
                    p.display(),
                    dir.display()
                );
            }
            Some((sock, dir))
        }
    };

    // Validate and collect executables (both original and canonical paths).
    let mut executables = BTreeSet::new();
    for exe_path in &policy.executables {
        // Refuse non-absolute paths
        if !exe_path.is_absolute() {
            bail!("executable path must be absolute: {}", exe_path.display());
        }
        // Refuse paths inside lanes root
        if exe_path.starts_with(&lanes_root) {
            bail!(
                "executable {} lies inside the lanes root {}",
                exe_path.display(),
                lanes_root.display()
            );
        }

        // Verify the file exists (symlinks OK)
        std::fs::metadata(exe_path)
            .with_context(|| format!("cannot stat executable {}", exe_path.display()))?;

        // Canonicalize to verify the target exists and is a regular file
        let canonical = std::fs::canonicalize(exe_path)
            .with_context(|| format!("cannot resolve executable {}", exe_path.display()))?;

        let metadata = std::fs::metadata(&canonical)
            .with_context(|| format!("cannot stat executable {}", canonical.display()))?;
        if !metadata.is_file() {
            bail!("executable {} is not a regular file", canonical.display());
        }

        // Re-check that the canonical path is not inside lanes root
        if canonical.starts_with(&lanes_root) {
            bail!(
                "executable {} (canonical) lies inside the lanes root {}",
                canonical.display(),
                lanes_root.display()
            );
        }

        // Grant both the original path (for symlinks) and the canonical target
        executables.insert(exe_path.clone());
        executables.insert(canonical);
    }

    Ok(Resolved {
        home,
        rw,
        ro,
        lanes_root,
        deny,
        credentials,
        socket,
        executables,
    })
}

/// A path as a Seatbelt string literal. Non-UTF-8 and control characters are
/// refused: they cannot be written faithfully and could inject profile text.
fn sbpl(path: &Path) -> Result<String> {
    let s = path
        .to_str()
        .ok_or_else(|| anyhow!("sandbox path is not UTF-8: {}", path.display()))?;
    if s.chars().any(char::is_control) {
        bail!("sandbox path contains a control character: {s:?}");
    }
    Ok(serde_json::to_string(s)?)
}

/// The device files a sandboxed process may write. Everything else under `/dev`
/// is covered by the global write deny. `/dev/null` and `/dev/zero` are the
/// sinks shells and tools open for redirection, `/dev/tty` is what git and
/// cargo open to test for a terminal, and `/dev/dtracehelper` is opened by
/// the macOS system libraries at process start.
const MACOS_DEV_WRITES: [&str; 4] = ["/dev/null", "/dev/zero", "/dev/tty", "/dev/dtracehelper"];

/// Render a sandbox policy as a macOS Seatbelt profile.
///
/// Seatbelt applies the last matching rule, so the order is the policy. File
/// writes are denied everywhere right after `(allow default)`, the grants come
/// next (read-write grants, then the device files), and the denies that must
/// win over a grant come last (read-only grants nested in a read-write one,
/// credentials, then `deny_paths`). The lanes_root deny is placed before the
/// RW/RO allows so that specific grants override it.
pub fn render_macos_profile(policy: &SandboxPolicy) -> Result<String> {
    let r = resolve(policy)?;
    let mut out = String::from("(version 1)\n(allow default)\n");
    // `(allow default)` allows file writes, so deny them everywhere first. Every
    // write the builder needs is a later allow, which wins by order.
    out.push_str("(deny file-write* (subpath \"/\"))\n");
    out.push_str(&format!(
        "(deny file-read* file-write* (subpath {}))\n",
        sbpl(&r.home)?
    ));

    // Metadata on the directories leading to a grant inside the hidden home,
    // so path resolution can traverse them without listing or reading.
    let mut metadata = BTreeSet::new();
    metadata.insert(r.home.clone());
    for p in r.rw.iter().chain(r.ro.iter()) {
        for a in p.ancestors().skip(1) {
            if a.starts_with(&r.home) {
                metadata.insert(a.to_path_buf());
            }
        }
    }
    // Metadata on ancestors of executables so path resolution works.
    for e in &r.executables {
        for a in e.ancestors().skip(1) {
            metadata.insert(a.to_path_buf());
        }
    }
    out.push_str("(allow file-read-metadata");
    for m in &metadata {
        out.push_str(&format!(" (literal {})", sbpl(m)?));
    }
    out.push_str(")\n");

    // Hide the lanes root before granting access to this lane's paths,
    // so the specific grants override this deny for this lane only.
    out.push_str(&format!(
        "(deny file-read* file-write* (subpath {}))\n",
        sbpl(&r.lanes_root)?
    ));
    // The deny above also hides metadata on the lanes root and on this lane's
    // own directories inside it, so a path walk to a grant (git's realpath,
    // `mkdir -p`, `test -S`) fails. Allow metadata only, as `literal`, on exactly
    // those directories: it permits `stat` but not listing or reading.
    let mut lane_metadata = BTreeSet::new();
    lane_metadata.insert(r.lanes_root.clone());
    for p in r.rw.iter().chain(r.ro.iter()) {
        for a in p.ancestors().skip(1) {
            if a.starts_with(&r.lanes_root) {
                lane_metadata.insert(a.to_path_buf());
            }
        }
    }
    out.push_str("(allow file-read-metadata");
    for m in &lane_metadata {
        out.push_str(&format!(" (literal {})", sbpl(m)?));
    }
    out.push_str(")\n");

    for p in &r.rw {
        out.push_str(&format!(
            "(allow file-read* file-write* (subpath {}))\n",
            sbpl(p)?
        ));
    }
    for p in &r.ro {
        out.push_str(&format!("(allow file-read* (subpath {}))\n", sbpl(p)?));
    }
    out.push_str("(allow file-write*");
    for d in MACOS_DEV_WRITES {
        out.push_str(&format!(" (literal {})", sbpl(Path::new(d))?));
    }
    out.push_str(")\n");
    // The global write deny already makes a read-only grant unwritable, so this
    // deny is only needed where a read-only grant sits inside a read-write one
    // (the dependency cache mounted under the builder's home): it must come after
    // every read-write allow to win.
    for p in &r.ro {
        out.push_str(&format!("(deny file-write* (subpath {}))\n", sbpl(p)?));
    }
    for e in &r.executables {
        out.push_str(&format!("(allow file-read* (literal {}))\n", sbpl(e)?));
    }
    for c in &r.credentials {
        out.push_str(&format!(
            "(deny file-read* file-write* (literal {}))\n",
            sbpl(c)?
        ));
    }
    for d in &r.deny {
        out.push_str(&format!(
            "(deny file-read* file-write* (subpath {}))\n",
            sbpl(d)?
        ));
    }

    // The socket directory: nothing in it can be read or listed. Connecting to
    // the one socket is a network operation and is granted below; Seatbelt
    // does not need the file rules to allow it.
    if let Some((_, dir)) = &r.socket {
        out.push_str(&format!(
            "(deny file-read* file-write* (subpath {}))\n",
            sbpl(dir)?
        ));
    }

    match &policy.network {
        NetworkMode::None => out.push_str("(deny network*)\n"),
        NetworkMode::Proxy { port, socket } | NetworkMode::RegistryReadOnly { port, socket } => {
            out.push_str("(deny network*)\n");
            // The in-sandbox bridge (D24): it binds `localhost:<port>` and its
            // client connects to it, so bind, inbound and outbound on that one
            // port, and nothing on any other. It reaches the proxy through the
            // exact socket path, never the bare `(remote unix-socket)`.
            out.push_str(&format!(
                "(allow network-bind (local ip \"localhost:{port}\"))\n"
            ));
            out.push_str(&format!(
                "(allow network-inbound (local ip \"localhost:{port}\"))\n"
            ));
            out.push_str(&format!(
                "(allow network-outbound (remote ip \"localhost:{port}\"))\n"
            ));
            out.push_str(&format!(
                "(allow network-outbound (remote unix-socket (path-literal {})))\n",
                sbpl(&canonicalize_for_sandbox(socket)?)?
            ));
        }
        // Legacy: no network rules.
        NetworkMode::Unrestricted => {}
    }

    // The runner socket (D22): exactly this path, never the bare
    // `(remote unix-socket)`, which would admit every Unix socket. It follows
    // the `(deny network*)` above because Seatbelt applies the last matching
    // rule. Unrestricted mode has no deny to carve an exception from, so the
    // socket is already reachable and no network rule is written.
    if let Some((sock, _)) = &r.socket
        && policy.network != NetworkMode::Unrestricted
    {
        out.push_str(&format!(
            "(allow network-outbound (remote unix-socket (path-literal {})))\n",
            sbpl(sock)?
        ));
    }
    Ok(out)
}

fn bind(args: &mut Vec<String>, flag: &str, src: &Path, dest: &Path) -> Result<()> {
    let s = src
        .to_str()
        .ok_or_else(|| anyhow!("not UTF-8: {}", src.display()))?;
    let d = dest
        .to_str()
        .ok_or_else(|| anyhow!("not UTF-8: {}", dest.display()))?;
    args.extend([flag.to_string(), s.to_string(), d.to_string()]);
    Ok(())
}

/// Render a sandbox policy as bubblewrap arguments for Linux.
///
/// The root is read-only, `/tmp` and the real home are empty tmpfs mounts, and
/// only granted paths are bound back in. The lanes root is a tmpfs (if it exists
/// on the host) before this lane's paths are bound on top. A path that does not
/// exist on the host cannot be bound and is skipped, except a `deny_paths`
/// entry: hiding it is required, so a missing one is an error.
pub fn render_bwrap_args(policy: &SandboxPolicy, cmd: &[String]) -> Result<Vec<String>> {
    let r = resolve(policy)?;
    let mut args: Vec<String> = [
        "--die-with-parent",
        "--unshare-pid",
        "--ro-bind",
        "/",
        "/",
        "--dev",
        "/dev",
        "--proc",
        "/proc",
        "--tmpfs",
        "/tmp",
        "--tmpfs",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    args.push(
        r.home
            .to_str()
            .ok_or_else(|| anyhow!("not UTF-8: {}", r.home.display()))?
            .to_string(),
    );

    // Hide the lanes root with a tmpfs so other lanes' paths are not accessible,
    // before binding this lane's paths on top of it.
    let lr = r
        .lanes_root
        .to_str()
        .ok_or_else(|| anyhow!("not UTF-8: {}", r.lanes_root.display()))?;
    if r.lanes_root.exists() {
        args.extend(["--tmpfs".into(), lr.into()]);
    }

    for p in &r.rw {
        if p.exists() {
            bind(&mut args, "--bind", p, p)?;
        }
    }
    for p in &r.ro {
        if p.exists() {
            bind(&mut args, "--ro-bind", p, p)?;
        }
    }
    for e in &r.executables {
        if e.exists() {
            bind(&mut args, "--ro-bind", e, e)?;
        }
    }
    // The runner socket file alone (D22), never its directory, so nothing else
    // in the socket directory is visible. Bound when it exists, like the proxy
    // socket: the runner binds it before the builder starts.
    if let Some((sock, _)) = &r.socket
        && sock.exists()
    {
        bind(&mut args, "--ro-bind", sock, sock)?;
    }
    for c in &r.credentials {
        if c.exists() {
            bind(&mut args, "--ro-bind", Path::new("/dev/null"), c)?;
        }
    }
    // Hidden last, so a deny inside a granted path wins.
    for d in &r.deny {
        if !d.exists() {
            bail!(
                "deny path {} does not exist; create it before rendering so it can be hidden",
                d.display()
            );
        }
        let ds = d
            .to_str()
            .ok_or_else(|| anyhow!("not UTF-8: {}", d.display()))?;
        args.extend([
            "--tmpfs".into(),
            ds.into(),
            "--remount-ro".into(),
            ds.into(),
        ]);
    }

    match &policy.network {
        NetworkMode::None => args.push("--unshare-net".to_string()),
        NetworkMode::Proxy { socket, .. } | NetworkMode::RegistryReadOnly { socket, .. } => {
            args.push("--unshare-net".to_string());
            // The proxy's Unix socket is bound in when it exists.
            if socket.exists() {
                let s = canonicalize_for_sandbox(socket)?;
                bind(&mut args, "--ro-bind", &s, &s)?;
            }
        }
        // Legacy: no network restrictions.
        NetworkMode::Unrestricted => {}
    }

    if !cmd.is_empty() {
        args.push("--".to_string());
    }
    args.extend_from_slice(cmd);
    Ok(args)
}

/// Build the sandbox command to run with the given policy.
pub fn sandbox_command(
    policy: &SandboxPolicy,
    profile_path: &Path,
    cmd: &[String],
    platform: &str,
) -> Result<(String, Vec<String>)> {
    match platform {
        "darwin" => {
            let mut args = vec![
                "-f".to_string(),
                profile_path.to_string_lossy().into_owned(),
            ];
            args.extend_from_slice(cmd);
            Ok(("sandbox-exec".to_string(), args))
        }
        "linux" => Ok(("bwrap".to_string(), render_bwrap_args(policy, cmd)?)),
        _ => bail!("unsupported platform: {platform}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// Absolute, non-symlinked, non-existent paths: renders are pure.
    fn test_lane() -> LaneLayout {
        LaneLayout {
            clone: PathBuf::from("/nonexistent-cp/lanes/l1/clone"),
            home: PathBuf::from("/nonexistent-cp/lanes/l1/home"),
            scratch: PathBuf::from("/nonexistent-cp/lanes/l1/scratch"),
            control: PathBuf::from("/nonexistent-cp/lanes/l1/control"),
            real_home: PathBuf::from("/nonexistent-cp/realhome"),
            sock: PathBuf::from("/nonexistent-cp/lanes/l1/sock/runner.sock"),
            lanes_root: PathBuf::from("/nonexistent-cp/lanes"),
        }
    }

    fn all_policies(lane: &LaneLayout) -> Vec<(&'static str, SandboxPolicy)> {
        let cache = PathBuf::from("/nonexistent-cp/cache");
        vec![
            ("builder", SandboxPolicy::builder(lane, NetworkMode::None)),
            ("verifier", SandboxPolicy::verifier(lane, &cache)),
            ("run_check", SandboxPolicy::run_check(lane)),
            (
                "dependency_fetch",
                SandboxPolicy::dependency_fetch(lane, &cache, NetworkMode::None),
            ),
            ("capture", SandboxPolicy::capture(lane)),
        ]
    }

    #[test]
    fn no_constructors_default_to_unrestricted() {
        for (name, p) in all_policies(&test_lane()) {
            assert_ne!(p.network, NetworkMode::Unrestricted, "{name}");
        }
    }

    #[test]
    fn unrestricted_renders_no_network_rules() {
        let lane = test_lane();
        let policy = SandboxPolicy::builder(&lane, NetworkMode::Unrestricted);
        let profile = render_macos_profile(&policy).unwrap();
        assert!(!profile.contains("network"), "{profile}");
        let args = render_bwrap_args(&policy_without_deny(policy), &[]).unwrap();
        assert!(!args.contains(&"--unshare-net".to_string()));
    }

    /// bwrap refuses to render a deny path that does not exist on the host.
    fn policy_without_deny(mut p: SandboxPolicy) -> SandboxPolicy {
        p.deny_paths.clear();
        p
    }

    #[test]
    fn none_and_proxy_network_rules() {
        let lane = test_lane();
        let none = render_macos_profile(&SandboxPolicy::capture(&lane)).unwrap();
        assert!(none.contains("(deny network*)\n"));
        assert!(!none.contains("allow network"));

        let proxy = SandboxPolicy::builder(
            &lane,
            NetworkMode::Proxy {
                port: 4123,
                socket: PathBuf::from("/nonexistent-cp/proxy.sock"),
            },
        );
        let profile = render_macos_profile(&proxy).unwrap();
        let deny = profile.find("(deny network*)").unwrap();
        let allow = profile
            .find("(allow network-outbound (remote ip \"localhost:4123\"))")
            .unwrap();
        // Seatbelt applies the last matching rule: the allow must follow the deny.
        assert!(deny < allow, "{profile}");
    }

    /// Every `(allow network...)` line of a profile.
    fn network_allows(profile: &str) -> Vec<&str> {
        profile
            .lines()
            .filter(|l| l.starts_with("(allow network"))
            .collect()
    }

    #[test]
    fn the_macos_proxy_profile_allows_the_bridge_port_and_the_two_sockets_and_no_other_network() {
        let lane = test_lane();
        let proxy_sock = "/nonexistent-cp/lanes/l1/proxy.sock";
        let policy = SandboxPolicy::builder(
            &lane,
            NetworkMode::Proxy {
                port: 41_003,
                socket: PathBuf::from(proxy_sock),
            },
        );
        let profile = render_macos_profile(&policy).unwrap();
        // Exactly these allows, nothing else: the bridge binds, accepts and
        // is dialled on one local port, and the two Unix sockets are exact
        // paths (the runner's and the proxy's).
        let expected = vec![
            "(allow network-bind (local ip \"localhost:41003\"))".to_string(),
            "(allow network-inbound (local ip \"localhost:41003\"))".to_string(),
            "(allow network-outbound (remote ip \"localhost:41003\"))".to_string(),
            format!("(allow network-outbound (remote unix-socket (path-literal \"{proxy_sock}\")))"),
            "(allow network-outbound (remote unix-socket (path-literal \"/nonexistent-cp/lanes/l1/sock/runner.sock\")))".to_string(),
        ];
        assert_eq!(network_allows(&profile), expected, "{profile}");
        // No wildcard port, no host other than localhost, no bare socket rule.
        assert!(!profile.contains("localhost:*"), "{profile}");
        assert!(!profile.contains("(remote unix-socket)"), "{profile}");
        assert!(!profile.contains("(remote ip \"*"), "{profile}");
        // Every allow follows the deny.
        let deny = profile.find("(deny network*)").unwrap();
        assert!(
            profile
                .match_indices("(allow network")
                .all(|(i, _)| i > deny),
            "{profile}"
        );
    }

    #[test]
    fn the_linux_proxy_args_keep_the_empty_network_namespace_and_bind_only_the_proxy_socket_file() {
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        for d in ["lanes/l1/clone", "lanes/l1/control", "lanes/l1/sock"] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }
        let lane = LaneLayout {
            clone: root.join("lanes/l1/clone"),
            home: root.join("lanes/l1/home"),
            scratch: root.join("lanes/l1/scratch"),
            control: root.join("lanes/l1/control"),
            real_home: root.join("realhome"),
            sock: root.join("lanes/l1/sock/runner.sock"),
            lanes_root: root.join("lanes"),
        };
        let proxy_sock = root.join("lanes/l1/proxy.sock");
        // The file stands in for the socket: bwrap's bind only needs a path.
        std::fs::write(&proxy_sock, b"").unwrap();
        let policy = SandboxPolicy::builder(
            &lane,
            NetworkMode::Proxy {
                port: 41_003,
                socket: proxy_sock.clone(),
            },
        );
        let args = render_bwrap_args(&policy, &["cmd".into()]).unwrap();
        assert!(args.iter().any(|a| a == "--unshare-net"), "{args:?}");
        assert!(!args.iter().any(|a| a == "--share-net"), "{args:?}");
        let sock = proxy_sock.to_str().unwrap();
        let bound = args
            .windows(3)
            .any(|w| w[0] == "--ro-bind" && w[1] == sock && w[2] == sock);
        assert!(bound, "proxy.sock is not bound by itself: {args:?}");
        // The file alone: its directory (the lane directory) is never bound
        // as a whole.
        let lane_dir = root.join("lanes/l1");
        assert!(
            !args.windows(3).any(|w| w[0].starts_with("--")
                && w[0].contains("bind")
                && w[1] == lane_dir.to_str().unwrap()),
            "{args:?}"
        );
    }

    #[test]
    fn socket_grant_is_exact_path_after_the_network_deny_and_only_for_builder_and_run_check() {
        let lane = test_lane();
        let sock = "/nonexistent-cp/lanes/l1/sock/runner.sock";
        let rule =
            format!("(allow network-outbound (remote unix-socket (path-literal \"{sock}\")))");
        for (name, p) in all_policies(&lane) {
            let profile = render_macos_profile(&p).unwrap();
            let owns = matches!(name, "builder" | "run_check");
            assert_eq!(profile.contains(&rule), owns, "{name}\n{profile}");
            assert_eq!(
                profile.contains("unix-socket"),
                owns,
                "{name} mentions a socket it does not own\n{profile}"
            );
            // The directory is closed to reads and writes, for owners only.
            let dir_deny =
                "(deny file-read* file-write* (subpath \"/nonexistent-cp/lanes/l1/sock\"))";
            assert_eq!(profile.contains(dir_deny), owns, "{name}\n{profile}");
            // Never the bare form, which admits every Unix socket.
            assert!(!profile.contains("(remote unix-socket)"), "{name}");
        }
        let profile =
            render_macos_profile(&SandboxPolicy::builder(&lane, NetworkMode::None)).unwrap();
        let deny = profile.find("(deny network*)").unwrap();
        // Seatbelt applies the last matching rule: the allow must follow the deny.
        assert!(
            deny < profile.find("(remote unix-socket").unwrap(),
            "{profile}"
        );
    }

    #[test]
    fn a_grant_inside_the_socket_directory_is_refused() {
        let lane = test_lane();
        let mut p = SandboxPolicy::builder(&lane, NetworkMode::None);
        p.rw_paths.push(lane.sock.parent().unwrap().join("inner"));
        let err = render_macos_profile(&p).unwrap_err().to_string();
        assert!(err.contains("inside the socket directory"), "{err}");
    }

    #[test]
    fn linux_binds_the_socket_file_alone_and_only_for_owners() {
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        for d in [
            "lane/clone",
            "lane/home",
            "lane/scratch",
            "lane/control",
            "lane/sock",
            "realhome/.rustup",
        ] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }
        let lane = LaneLayout {
            clone: root.join("lane/clone"),
            home: root.join("lane/home"),
            scratch: root.join("lane/scratch"),
            control: root.join("lane/control"),
            real_home: root.join("realhome"),
            sock: root.join("lane/sock/runner.sock"),
            lanes_root: root.join("lane"),
        };
        std::fs::write(&lane.sock, b"").unwrap();
        let sock = lane.sock.to_str().unwrap().to_string();
        let dir = lane.sock.parent().unwrap().to_str().unwrap().to_string();
        let cache = root.join("cache");
        for (name, p) in [
            ("builder", SandboxPolicy::builder(&lane, NetworkMode::None)),
            ("run_check", SandboxPolicy::run_check(&lane)),
            ("verifier", SandboxPolicy::verifier(&lane, &cache)),
            ("capture", SandboxPolicy::capture(&lane)),
        ] {
            let args = render_bwrap_args(&p, &[]).unwrap();
            let bound = args
                .windows(3)
                .any(|w| w[0] == "--ro-bind" && w[1] == sock && w[2] == sock);
            assert_eq!(
                bound,
                matches!(name, "builder" | "run_check"),
                "{name}: {args:?}"
            );
            // Never the directory: nothing else in it may be visible.
            assert!(!args.contains(&dir), "{name}: {args:?}");
        }
    }

    #[test]
    fn d18_builder_sets_cargo_home_env() {
        let lane = test_lane();
        let policy = SandboxPolicy::builder(&lane, NetworkMode::None);
        assert!(
            policy.env_set.contains(&(
                "CARGO_HOME".to_string(),
                "/nonexistent-cp/lanes/l1/home/.cargo".to_string()
            )),
            "{:?}",
            policy.env_set
        );
        let mut env = vec![
            ("CARGO_HOME".to_string(), "/real/.cargo".to_string()),
            ("PATH".to_string(), "/bin".to_string()),
        ];
        policy.apply_env(&mut env);
        assert_eq!(env[0].1, "/nonexistent-cp/lanes/l1/home/.cargo");
        // The real value is replaced, not duplicated; the policy's other
        // variables (the temp directories) are added once each.
        assert_eq!(env.iter().filter(|(k, _)| k == "CARGO_HOME").count(), 1);
        assert_eq!(env.len(), 2 + policy.env_set.len() - 1);
    }

    #[test]
    fn d18_builder_rw_and_ro_structure() {
        let lane = test_lane();
        let policy = SandboxPolicy::builder(&lane, NetworkMode::None);
        assert!(policy.rw_paths.contains(&lane.home.join(".cargo")));
        assert!(policy.rw_paths.contains(&lane.clone));
        assert!(policy.rw_paths.contains(&lane.scratch));
        // The real ~/.cargo is never writable; only registry and git are readable.
        let real_cargo = lane.real_home.join(".cargo");
        assert!(!policy.rw_paths.contains(&real_cargo));
        assert!(!policy.ro_paths.contains(&real_cargo));
        assert!(policy.ro_paths.contains(&real_cargo.join("registry")));
        assert!(policy.ro_paths.contains(&real_cargo.join("git")));
        assert!(policy.ro_paths.contains(&lane.real_home.join(".rustup")));
    }

    #[test]
    fn d18_other_policies_never_touch_real_cargo() {
        let lane = test_lane();
        let real_cargo = lane.real_home.join(".cargo");
        for (name, p) in all_policies(&lane) {
            // No policy may ever write the real ~/.cargo.
            assert!(
                !p.rw_paths.iter().any(|x| x.starts_with(&real_cargo)),
                "{name} can write the real ~/.cargo"
            );
            // Only the builder may read it, and only registry and git.
            for path in &p.ro_paths {
                if path.starts_with(&real_cargo) {
                    assert_eq!(name, "builder", "{name} reads the real ~/.cargo");
                    assert!(
                        path == &real_cargo.join("registry") || path == &real_cargo.join("git"),
                        "{}",
                        path.display()
                    );
                }
            }
        }
        // verifier, fetch and capture never get the builder's lane home.
        for (name, p) in all_policies(&lane) {
            if ["verifier", "dependency_fetch", "capture"].contains(&name) {
                assert!(
                    !p.rw_paths.contains(&lane.home)
                        && !p.rw_paths.contains(&lane.home.join(".cargo")),
                    "{name} must not get the builder's lane home"
                );
            }
        }
        let verifier = SandboxPolicy::verifier(&lane, Path::new("/nonexistent-cp/cache"));
        assert!(
            verifier
                .rw_paths
                .contains(&PathBuf::from("/nonexistent-cp/cache/.cargo"))
        );
    }

    #[test]
    fn a3_every_policy_denies_control_and_never_grants_it() {
        let lane = test_lane();
        for (name, p) in all_policies(&lane) {
            assert!(p.deny_paths.contains(&lane.control), "{name}");
            for rw in p.rw_paths.iter().chain(p.ro_paths.iter()) {
                assert!(
                    !lane.control.starts_with(rw),
                    "{name}: control is inside grant {}",
                    rw.display()
                );
            }
            let profile = render_macos_profile(&p).unwrap();
            let deny = format!(
                "(deny file-read* file-write* (subpath \"{}\"))",
                lane.control.display()
            );
            let at = profile.find(&deny).unwrap_or_else(|| panic!("{name}"));
            // Seatbelt: last match wins, so the deny must follow every allow.
            let last_allow = profile.rfind("(allow file-").unwrap();
            assert!(last_allow < at, "{name}: an allow follows the control deny");
        }
    }

    #[test]
    fn table_driven_macos_profiles() {
        for (name, p) in all_policies(&test_lane()) {
            let profile = render_macos_profile(&p).unwrap();
            assert!(
                profile.starts_with("(version 1)\n(allow default)\n"),
                "{name}"
            );
            assert!(
                profile.contains(
                    "(deny file-read* file-write* (subpath \"/nonexistent-cp/realhome\"))"
                ),
                "{name}"
            );
        }
    }

    #[test]
    fn table_driven_linux_args() {
        // control does not exist in the unit-test lane; bwrap needs it to.
        for (name, p) in all_policies(&test_lane()) {
            assert!(render_bwrap_args(&p, &["cmd".into()]).is_err(), "{name}");
            let args = render_bwrap_args(&policy_without_deny(p), &["cmd".into()]).unwrap();
            assert!(args.contains(&"--unshare-pid".to_string()), "{name}");
            assert!(args.contains(&"--die-with-parent".to_string()), "{name}");
            assert_eq!(args.last().unwrap(), "cmd", "{name}");
        }
    }

    #[test]
    fn sandbox_command_per_platform() {
        let lane = test_lane();
        let policy = policy_without_deny(SandboxPolicy::builder(&lane, NetworkMode::None));
        let (cmd, args) = sandbox_command(
            &policy,
            Path::new("/l/sandbox.sb"),
            &["test".into()],
            "darwin",
        )
        .unwrap();
        assert_eq!(cmd, "sandbox-exec");
        assert_eq!(args, ["-f", "/l/sandbox.sb", "test"]);
        let (cmd, args) = sandbox_command(
            &policy,
            Path::new("/l/sandbox.sb"),
            &["test".into()],
            "linux",
        )
        .unwrap();
        assert_eq!(cmd, "bwrap");
        assert_eq!(args.last().unwrap(), "test");
        assert!(sandbox_command(&policy, Path::new("/x"), &[], "plan9").is_err());
    }

    // D10 regression contract.

    #[test]
    fn regression_linux_unshare_pid() {
        let policy = policy_without_deny(SandboxPolicy::builder(&test_lane(), NetworkMode::None));
        assert!(
            render_bwrap_args(&policy, &[])
                .unwrap()
                .contains(&"--unshare-pid".to_string())
        );
    }

    #[test]
    fn regression_home_hidden() {
        let lane = test_lane();
        let home = "/nonexistent-cp/realhome";
        let policy = policy_without_deny(SandboxPolicy::builder(&lane, NetworkMode::None));
        let args = render_bwrap_args(&policy, &[]).unwrap();
        // Linux: home and /tmp are tmpfs mounts, made before any grant is bound.
        assert!(args.windows(2).any(|w| w[0] == "--tmpfs" && w[1] == home));
        assert!(args.windows(2).any(|w| w[0] == "--tmpfs" && w[1] == "/tmp"));
        let rustup = format!("{home}/.rustup");
        // macOS: home denied, toolchain re-allowed read-only.
        let profile =
            render_macos_profile(&SandboxPolicy::builder(&lane, NetworkMode::None)).unwrap();
        let deny = profile
            .find(&format!(
                "(deny file-read* file-write* (subpath \"{home}\"))"
            ))
            .unwrap();
        let rustup_allow = profile
            .find(&format!("(allow file-read* (subpath \"{rustup}\"))"))
            .unwrap();
        assert!(deny < rustup_allow);
        assert!(!profile.contains(&format!(
            "(allow file-read* file-write* (subpath \"{home}\"))"
        )));
    }

    #[test]
    fn linux_grants_bind_after_home_and_tmp_are_hidden_and_control_is_hidden_last() {
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        for d in [
            "lane/clone",
            "lane/home",
            "lane/scratch",
            "lane/control",
            "realhome/.rustup",
        ] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }
        let lane = LaneLayout {
            clone: root.join("lane/clone"),
            home: root.join("lane/home"),
            scratch: root.join("lane/scratch"),
            control: root.join("lane/control"),
            real_home: root.join("realhome"),
            sock: root.join("lane/sock/runner.sock"),
            lanes_root: root.join("lane"),
        };
        let args =
            render_bwrap_args(&SandboxPolicy::builder(&lane, NetworkMode::None), &[]).unwrap();
        let at = |flag: &str, path: &Path| {
            args.windows(3)
                .position(|w| w[0] == flag && Path::new(&w[1]) == path)
                .unwrap_or_else(|| panic!("{flag} {} missing in {args:?}", path.display()))
        };
        let tmp_hidden = args
            .windows(2)
            .position(|w| w == ["--tmpfs", "/tmp"])
            .unwrap();
        let home_hidden = at_tmpfs(&args, &lane.real_home);
        for g in [&lane.clone, &lane.scratch, &lane.home] {
            let b = at("--bind", g);
            assert!(b > tmp_hidden && b > home_hidden);
        }
        assert!(at("--ro-bind", &lane.real_home.join(".rustup")) > home_hidden);
        // control is hidden after every bind and made read-only
        let ctrl = at_tmpfs(&args, &lane.control);
        assert!(
            args.iter()
                .enumerate()
                .all(|(i, a)| !(a == "--bind" || a == "--ro-bind") || i < ctrl)
        );
        assert_eq!(args[ctrl + 2], "--remount-ro");
        assert_eq!(Path::new(&args[ctrl + 3]), lane.control);
    }

    fn at_tmpfs(args: &[String], path: &Path) -> usize {
        args.windows(2)
            .position(|w| w[0] == "--tmpfs" && Path::new(&w[1]) == path)
            .unwrap_or_else(|| panic!("--tmpfs {} missing in {args:?}", path.display()))
    }

    #[test]
    fn regression_credentials_denied() {
        let profile =
            render_macos_profile(&SandboxPolicy::builder(&test_lane(), NetworkMode::None)).unwrap();
        for c in ["credentials.toml", "credentials"] {
            assert!(
                profile.contains(&format!(
                    "(deny file-read* file-write* (literal \"/nonexistent-cp/realhome/.cargo/{c}\"))"
                )),
                "{profile}"
            );
        }
        // The credential denies follow the registry grant (last match wins).
        let reg = profile.find("/.cargo/registry").unwrap();
        let cred = profile.find("/.cargo/credentials.toml").unwrap();
        assert!(reg < cred);
    }

    #[test]
    fn regression_command_passthrough() {
        let policy = policy_without_deny(SandboxPolicy::builder(&test_lane(), NetworkMode::None));
        let cmd: Vec<String> = ["mycommand", "arg1", "arg2"].map(String::from).to_vec();
        let args = render_bwrap_args(&policy, &cmd).unwrap();
        assert_eq!(&args[args.len() - 3..], ["mycommand", "arg1", "arg2"]);
        assert_eq!(args[args.len() - 4], "--");
    }

    #[test]
    fn regression_profile_outside_clone() {
        // The profile path is chosen by the caller; the policy never grants a
        // location above the clone, so a profile stored beside the clone (in
        // the lane root) is not writable from inside. The lane root itself is
        // never a grant.
        let lane = test_lane();
        let lane_root = PathBuf::from("/nonexistent-cp/lanes/l1");
        for (name, p) in all_policies(&lane) {
            assert!(!p.rw_paths.contains(&lane_root), "{name}");
            assert!(!p.ro_paths.contains(&lane_root), "{name}");
        }
        let (_, args) = sandbox_command(
            &SandboxPolicy::builder(&lane, NetworkMode::None),
            &lane_root.join("sandbox.sb"),
            &[],
            "darwin",
        )
        .unwrap();
        assert!(!args[1].starts_with(lane.clone.to_str().unwrap()));
    }

    // Path handling (defect 1).

    #[test]
    fn grants_that_would_expose_home_are_rejected() {
        let lane = test_lane();
        let mut p = SandboxPolicy::capture(&lane);
        p.rw_paths.push(lane.real_home.clone());
        assert!(render_macos_profile(&p).is_err());
        let mut p = SandboxPolicy::capture(&lane);
        p.ro_paths.push(PathBuf::from("/"));
        assert!(render_macos_profile(&p).is_err());
        assert!(render_bwrap_args(&p, &[]).is_err());
    }

    #[test]
    fn profile_text_cannot_be_injected_through_a_path() {
        let lane = test_lane();
        let mut p = SandboxPolicy::capture(&lane);
        p.rw_paths
            .push(PathBuf::from("/nonexistent-cp/a\n(allow default)"));
        assert!(render_macos_profile(&p).is_err());
        let mut p = SandboxPolicy::capture(&lane);
        p.rw_paths.push(PathBuf::from("/nonexistent-cp/q\"uote"));
        let profile = render_macos_profile(&p).unwrap();
        assert!(profile.contains("\"/nonexistent-cp/q\\\"uote\""));
    }

    #[test]
    fn canonicalize_resolves_symlinks_and_rejects_dotdot_in_missing_suffix() {
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        std::fs::create_dir_all(root.join("real/sub")).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(root.join("real"), root.join("link")).unwrap();

        // existing path through a symlink
        #[cfg(unix)]
        assert_eq!(
            canonicalize_for_sandbox(&tmp.path().join("link/sub")).unwrap(),
            root.join("real/sub")
        );
        // not-yet-existing tail is re-joined onto the resolved ancestor
        #[cfg(unix)]
        assert_eq!(
            canonicalize_for_sandbox(&root.join("link/new/deeper")).unwrap(),
            root.join("real/new/deeper")
        );
        // `..` in the existing part is resolved by the filesystem
        assert_eq!(
            canonicalize_for_sandbox(&root.join("real/sub/../sub/x")).unwrap(),
            root.join("real/sub/x")
        );
        // `..` in a non-existent suffix is refused
        assert!(canonicalize_for_sandbox(&root.join("real/missing/../x")).is_err());
        assert!(canonicalize_for_sandbox(&root.join("missing/..")).is_err());
        // relative paths are refused
        assert!(canonicalize_for_sandbox(Path::new("relative/x")).is_err());
        // a dangling symlink cannot be resolved: refuse rather than guess
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(root.join("gone"), root.join("dangling")).unwrap();
            assert!(canonicalize_for_sandbox(&root.join("dangling")).is_err());
            assert!(canonicalize_for_sandbox(&root.join("dangling/x")).is_err());
        }
        // root and a trailing slash
        assert_eq!(
            canonicalize_for_sandbox(Path::new("/")).unwrap(),
            PathBuf::from("/")
        );
        assert_eq!(
            canonicalize_for_sandbox(&PathBuf::from(format!("{}/real/", root.display()))).unwrap(),
            root.join("real")
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_symlinked_spellings_render_as_private_paths() {
        // /tmp -> /private/tmp and /var -> /private/var. Seatbelt only matches
        // the real path, so a rule for the symlink spelling would not apply.
        let tmp = tempfile::tempdir().unwrap(); // /var/folders/... on macOS
        assert!(tmp.path().starts_with("/var/") || tmp.path().starts_with("/private/var/"));
        let base = std::fs::canonicalize(tmp.path()).unwrap();
        assert!(base.starts_with("/private/var/"), "{}", base.display());
        let spelled = |sub: &str| {
            PathBuf::from(format!(
                "/var{}/{sub}",
                &base.to_str().unwrap()["/private/var".len()..]
            ))
        };

        let lane = LaneLayout {
            clone: spelled("lane/clone"),
            home: spelled("lane/home"),
            scratch: PathBuf::from("/tmp/cowproof-unit-l57000"), // does not exist yet
            control: spelled("lane/control"),
            real_home: spelled("realhome"),
            sock: spelled("lane/sock/runner.sock"),
            lanes_root: spelled("lane"),
        };
        for (name, p) in all_policies(&lane) {
            let profile = render_macos_profile(&p).unwrap();
            assert!(
                !profile.contains("\"/var/"),
                "{name}: symlink spelling leaked\n{profile}"
            );
            assert!(
                !profile.contains("\"/tmp/"),
                "{name}: symlink spelling leaked\n{profile}"
            );
            assert!(
                profile.contains(&format!("\"{}/realhome\"", base.display())),
                "{name}"
            );
            assert!(
                profile.contains(&format!(
                    "(deny file-read* file-write* (subpath \"{}/lane/control\"))",
                    base.display()
                )),
                "{name}: control deny must use the real path\n{profile}"
            );
        }
        let builder =
            render_macos_profile(&SandboxPolicy::builder(&lane, NetworkMode::None)).unwrap();
        assert!(
            builder.contains(
                "(allow file-read* file-write* (subpath \"/private/tmp/cowproof-unit-l57000\"))"
            ),
            "{builder}"
        );
    }

    #[test]
    fn lanes_root_deny_is_added_to_macos_profile() {
        let lane = test_lane();
        let policy = SandboxPolicy::builder(&lane, NetworkMode::None);
        let profile = render_macos_profile(&policy).unwrap();
        let lanes_root_deny = format!(
            "(deny file-read* file-write* (subpath \"{}\"))",
            lane.lanes_root.display()
        );
        assert!(
            profile.contains(&lanes_root_deny),
            "lanes_root deny missing: {profile}"
        );
        // The deny must come before the RW allows (so allows override it)
        let deny_pos = profile.find(&lanes_root_deny).unwrap();
        let rw_allow = format!(
            "(allow file-read* file-write* (subpath \"{}\"))",
            lane.clone.display()
        );
        let allow_pos = profile.find(&rw_allow).unwrap();
        assert!(
            deny_pos < allow_pos,
            "lanes_root deny must come before RW allows"
        );
    }

    #[test]
    fn lanes_root_metadata_is_literal_and_follows_the_deny() {
        // A path walk to this lane's grants (git's realpath, `mkdir -p`) needs
        // `stat` on the lanes root and the lane directory. The allow must follow
        // the lanes-root deny (the last matching rule wins) and be `literal`, so
        // it never lets a builder list or read another lane.
        let lane = test_lane();
        let policy = SandboxPolicy::builder(&lane, NetworkMode::None);
        let profile = render_macos_profile(&policy).unwrap();
        let deny = format!(
            "(deny file-read* file-write* (subpath \"{}\"))",
            lane.lanes_root.display()
        );
        let deny_pos = profile.find(&deny).expect("lanes_root deny");
        let line = profile[deny_pos..]
            .lines()
            .find(|l| l.starts_with("(allow file-read-metadata"))
            .expect("a metadata allow after the lanes-root deny");
        let root = format!("(literal \"{}\")", lane.lanes_root.display());
        assert!(line.contains(&root), "{line}");
        let lane_dir = lane.clone.parent().unwrap();
        assert!(
            line.contains(&format!("(literal \"{}\")", lane_dir.display())),
            "{line}"
        );
        assert!(
            !line.contains("subpath"),
            "metadata must be literal: {line}"
        );
    }

    #[test]
    fn lanes_root_tmpfs_is_added_to_linux_args_before_binds() {
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        for d in [
            "lane/clone",
            "lane/home",
            "lane/scratch",
            "lane/control",
            "lane/sock",
            "realhome/.rustup",
        ] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }
        let lane = LaneLayout {
            clone: root.join("lane/clone"),
            home: root.join("lane/home"),
            scratch: root.join("lane/scratch"),
            control: root.join("lane/control"),
            real_home: root.join("realhome"),
            sock: root.join("lane/sock/runner.sock"),
            lanes_root: root.join("lane"),
        };
        std::fs::write(&lane.sock, b"").unwrap();

        let policy = SandboxPolicy::builder(&lane, NetworkMode::None);
        let args = render_bwrap_args(&policy, &[]).unwrap();

        let lanes_root_str = lane.lanes_root.to_str().unwrap();
        // Find the tmpfs index for lanes_root
        let tmpfs_idx = args
            .windows(2)
            .position(|w| w[0] == "--tmpfs" && w[1] == lanes_root_str)
            .expect("lanes_root tmpfs not found in args");

        // Find the bind index for clone
        let clone_str = lane.clone.to_str().unwrap();
        let bind_idx = args
            .windows(3)
            .position(|w| w[0] == "--bind" && w[1] == clone_str)
            .expect("clone bind not found in args");

        // tmpfs should come before bind (tmpfs is at tmpfs_idx, bind starts at bind_idx*3)
        assert!(
            tmpfs_idx * 2 < bind_idx * 3,
            "lanes_root tmpfs must come before RW binds"
        );
    }

    #[test]
    fn lanes_root_contain_repo_in_prepare_lane_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let repo_root = tmp.path().join("repo");
        std::fs::create_dir_all(&repo_root).unwrap();
        // Initialize a minimal git repo
        std::process::Command::new("git")
            .args([
                "-C",
                repo_root.to_str().unwrap(),
                "init",
                "-q",
                "-b",
                "main",
            ])
            .output()
            .unwrap();
        std::fs::write(repo_root.join("README.md"), "test").unwrap();
        std::process::Command::new("git")
            .args([
                "-C",
                repo_root.to_str().unwrap(),
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@test.com",
                "commit",
                "-q",
                "-m",
                "init",
                "-A",
            ])
            .output()
            .unwrap();

        // Try to use lanes_root that contains the repo (parent of repo)
        let lanes_root = tmp.path();
        let err = crate::lane::prepare_lane(
            &repo_root,
            lanes_root,
            "l1",
            crate::lane::PrepareOptions { allow_dirty: false },
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("lanes_root") && (err.contains("repository") || err.contains("repo")),
            "expected error about lanes_root containing repository, got: {err}"
        );
    }

    #[test]
    fn lanes_root_equal_to_root_is_refused() {
        // Test with real temp directories so canonicalization works
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();

        // Create required directories
        for d in [
            "lane/clone",
            "lane/home",
            "lane/control",
            "lane/sock",
            "realhome/.rustup",
        ] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }

        let lane = LaneLayout {
            clone: root.join("lane/clone"),
            home: root.join("lane/home"),
            scratch: root.join("lane/scratch"),
            control: root.join("lane/control"),
            real_home: root.join("realhome"),
            sock: root.join("lane/sock/runner.sock"),
            lanes_root: PathBuf::from("/"), // Root is the special case
        };

        std::fs::create_dir_all(&lane.scratch).unwrap();
        let policy = SandboxPolicy::builder(&lane, NetworkMode::None);
        let err = render_macos_profile(&policy).unwrap_err().to_string();
        assert!(
            err.contains("must not be the filesystem root"),
            "expected error about lanes_root equal to root, got: {err}"
        );
    }

    #[test]
    fn lanes_root_with_private_home_inside_is_accepted() {
        // Test that a lane's private home can be inside lanes_root.
        // This is the normal case: <lanes_root>/<lane>/home is the private home,
        // and lanes_root is < user's real home.
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();

        // Create lanes_root and a separate real_home outside of it
        let lanes_root = root.join("lanes");
        let real_home = root.join("realhome");
        std::fs::create_dir_all(&lanes_root).unwrap();
        std::fs::create_dir_all(&real_home).unwrap();

        // Create required directories for lane
        for d in ["lane/clone", "lane/home", "lane/control", "lane/sock"] {
            std::fs::create_dir_all(lanes_root.join(d)).unwrap();
        }

        let lane = LaneLayout {
            clone: lanes_root.join("lane/clone"),
            home: lanes_root.join("lane/home"), // Private home inside lanes_root
            scratch: lanes_root.join("lane/scratch"),
            control: lanes_root.join("lane/control"),
            real_home: real_home.clone(), // Real home OUTSIDE lanes_root
            sock: lanes_root.join("lane/sock/runner.sock"),
            lanes_root: lanes_root.clone(),
        };

        std::fs::create_dir_all(&lane.scratch).unwrap();
        std::fs::create_dir_all(real_home.join(".rustup")).unwrap();
        let policy = SandboxPolicy::builder(&lane, NetworkMode::None);
        let result = render_macos_profile(&policy);
        assert!(
            result.is_ok(),
            "policy should succeed when private home is inside lanes_root but real_home is outside: {:?}",
            result.err()
        );
    }

    #[test]
    fn lanes_root_equal_to_real_home_is_refused() {
        // Test that lanes_root cannot equal or contain the user's real home.
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();

        // Make real_home the same as lanes_root
        let lanes_root = root.join("lanes");
        std::fs::create_dir_all(&lanes_root).unwrap();

        // Create required directories
        for d in ["lane/clone", "lane/home", "lane/control", "lane/sock"] {
            std::fs::create_dir_all(lanes_root.join(d)).unwrap();
        }

        let lane = LaneLayout {
            clone: lanes_root.join("lane/clone"),
            home: lanes_root.join("lane/home"),
            scratch: lanes_root.join("lane/scratch"),
            control: lanes_root.join("lane/control"),
            real_home: lanes_root.clone(), // Real home EQUALS lanes_root (should fail)
            sock: lanes_root.join("lane/sock/runner.sock"),
            lanes_root: lanes_root.clone(),
        };

        std::fs::create_dir_all(&lane.scratch).unwrap();
        let policy = SandboxPolicy::builder(&lane, NetworkMode::None);
        let err = render_macos_profile(&policy).unwrap_err().to_string();
        assert!(
            err.contains("must not equal the real home")
                || err.contains("must not contain the real home"),
            "expected error about lanes_root and real_home, got: {err}"
        );
    }

    #[test]
    fn lanes_root_contains_real_home_is_refused() {
        // Test that lanes_root cannot contain the user's real home.
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();

        // Make real_home inside lanes_root
        let lanes_root = root.join("lanes");
        std::fs::create_dir_all(&lanes_root).unwrap();

        let real_home = lanes_root.join("realhome"); // Real home INSIDE lanes_root (should fail)
        std::fs::create_dir_all(&real_home).unwrap();

        // Create required directories
        for d in ["lane/clone", "lane/home", "lane/control", "lane/sock"] {
            std::fs::create_dir_all(lanes_root.join(d)).unwrap();
        }

        let lane = LaneLayout {
            clone: lanes_root.join("lane/clone"),
            home: lanes_root.join("lane/home"),
            scratch: lanes_root.join("lane/scratch"),
            control: lanes_root.join("lane/control"),
            real_home: real_home.clone(),
            sock: lanes_root.join("lane/sock/runner.sock"),
            lanes_root: lanes_root.clone(),
        };

        std::fs::create_dir_all(&lane.scratch).unwrap();
        let policy = SandboxPolicy::builder(&lane, NetworkMode::None);
        let err = render_macos_profile(&policy).unwrap_err().to_string();
        assert!(
            err.contains("must not contain the real home"),
            "expected error about lanes_root containing real_home, got: {err}"
        );
    }

    #[test]
    fn executable_symlink_is_granted_as_canonical_target() {
        // Create a temp directory with a real executable and a symlink to it
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();

        // Create a real executable
        let exe_dir = root.join("bin");
        std::fs::create_dir(&exe_dir).unwrap();
        let real_exe = exe_dir.join("mytool");
        std::fs::write(&real_exe, b"#!/bin/sh\necho hello").unwrap();
        std::fs::set_permissions(&real_exe, std::fs::Permissions::from_mode(0o755)).unwrap();

        // Create a symlink to it
        let symlink_exe = root.join("bin-link").join("mytool");
        std::fs::create_dir(root.join("bin-link")).unwrap();
        std::os::unix::fs::symlink(&real_exe, &symlink_exe).unwrap();

        let lane = test_lane();
        let policy = SandboxPolicy::builder_with_executables(
            &lane,
            NetworkMode::None,
            std::slice::from_ref(&symlink_exe),
        )
        .unwrap();

        let profile = render_macos_profile(&policy).unwrap();
        let canonical = std::fs::canonicalize(&real_exe).unwrap();
        let grant = format!("(allow file-read* (literal \"{}\"))", canonical.display());
        assert!(
            profile.contains(&grant),
            "executable grant should contain canonical path\nGrant: {grant}\nProfile: {profile}"
        );
    }

    #[test]
    fn executable_directory_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();

        let lane = LaneLayout {
            clone: root.join("lane/clone"),
            home: root.join("lane/home"),
            scratch: root.join("lane/scratch"),
            control: root.join("lane/control"),
            real_home: root.join("realhome"),
            sock: root.join("lane/sock/runner.sock"),
            lanes_root: root.join("lane"),
        };

        // Create required directories
        for d in [
            "lane/clone",
            "lane/home",
            "lane/control",
            "lane/sock",
            "realhome",
            "bindir",
        ] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }

        let policy = SandboxPolicy::builder_with_executables(
            &lane,
            NetworkMode::None,
            &[root.join("bindir")], // This is a directory, should be refused
        )
        .unwrap();

        let err = render_macos_profile(&policy).unwrap_err().to_string();
        assert!(
            err.contains("not a regular file"),
            "directory executable should be refused: {err}"
        );
    }

    #[test]
    fn linux_executable_bind_is_correct() {
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();

        // Create a real executable
        let exe_dir = root.join("bin");
        std::fs::create_dir(&exe_dir).unwrap();
        let exe = exe_dir.join("mytool");
        std::fs::write(&exe, b"#!/bin/sh\necho hello").unwrap();
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();

        for d in [
            "lane/clone",
            "lane/home",
            "lane/control",
            "lane/sock",
            "realhome/.rustup",
        ] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }

        let lane = LaneLayout {
            clone: root.join("lane/clone"),
            home: root.join("lane/home"),
            scratch: root.join("lane/scratch"),
            control: root.join("lane/control"),
            real_home: root.join("realhome"),
            sock: root.join("lane/sock/runner.sock"),
            lanes_root: root.join("lane"),
        };

        let policy = SandboxPolicy::builder_with_executables(
            &lane,
            NetworkMode::None,
            std::slice::from_ref(&exe),
        )
        .unwrap();
        let args = render_bwrap_args(&policy, &[]).unwrap();

        // Find the tmpfs that hides the lanes root
        let lanes_root_tmpfs_idx = args
            .windows(2)
            .position(|w| w[0] == "--tmpfs" && w[1].contains("lane"))
            .expect("should have a --tmpfs for lanes_root");

        // The executable bind should come after the lanes root tmpfs
        let exe_bind_idx = args
            .windows(3)
            .position(|w| {
                w[0] == "--ro-bind" && w[1].contains("bin/mytool") && w[2].contains("bin/mytool")
            })
            .expect("should have --ro-bind for the executable");

        assert!(
            lanes_root_tmpfs_idx < exe_bind_idx,
            "executable bind should come after lanes_root tmpfs: tmpfs at {}, bind at {}",
            lanes_root_tmpfs_idx,
            exe_bind_idx
        );
    }
    /// A fetched `CARGO_HOME` on disk: `registry` and `git`.
    fn fetched_cache(root: &Path, with_git: bool) -> PathBuf {
        let deps = root.join("deps/key");
        std::fs::create_dir_all(deps.join("cargo/registry")).unwrap();
        if with_git {
            std::fs::create_dir_all(deps.join("cargo/git")).unwrap();
        }
        deps
    }

    #[test]
    fn the_dependency_cache_mount_is_read_only_and_only_registry_and_git() {
        let tmp = tempfile::TempDir::new().unwrap();
        let deps = fetched_cache(tmp.path(), true);
        std::fs::create_dir_all(deps.join("cargo/other")).unwrap();
        let lane = test_lane();
        let policy = SandboxPolicy::verifier(&lane, Path::new("/nonexistent-cp/cache"))
            .with_dependency_cache(&deps);
        for dir in ["registry", "git"] {
            let p = deps.join("cargo").join(dir);
            assert!(policy.ro_paths.contains(&p), "{dir}: {:?}", policy.ro_paths);
            assert!(
                !policy.rw_paths.contains(&p),
                "{dir} must never be writable"
            );
        }
        assert!(
            !policy.ro_paths.iter().any(|p| p.ends_with("other")),
            "only registry and git are mounted: {:?}",
            policy.ro_paths
        );
        // No git directory in the cache: nothing to mount for it.
        let no_git = fetched_cache(&tmp.path().join("b"), false);
        let policy = SandboxPolicy::verifier(&lane, Path::new("/nonexistent-cp/cache"))
            .with_dependency_cache(&no_git);
        assert!(!policy.ro_paths.iter().any(|p| p.ends_with("git")));
    }

    #[test]
    fn the_verifier_tells_cargo_it_is_offline_and_no_other_policy_is_changed() {
        let lane = test_lane();
        let verifier = SandboxPolicy::verifier(&lane, Path::new("/nonexistent-cp/cache"));
        assert!(
            verifier
                .env_set
                .contains(&("CARGO_NET_OFFLINE".to_string(), "true".to_string())),
            "{:?}",
            verifier.env_set
        );
        assert_eq!(verifier.network, NetworkMode::None);
        assert!(
            !SandboxPolicy::run_check(&lane)
                .env_set
                .iter()
                .any(|(k, _)| k == "CARGO_NET_OFFLINE")
        );
    }

    #[test]
    fn macos_read_only_grants_deny_writes_after_every_grant() {
        let tmp = tempfile::TempDir::new().unwrap();
        let deps = fetched_cache(tmp.path(), false).canonicalize().unwrap();
        let registry = deps.join("cargo/registry");
        let lane = test_lane();
        let policy = SandboxPolicy::verifier(&lane, Path::new("/nonexistent-cp/cache"))
            .with_dependency_cache(&deps);
        let profile = render_macos_profile(&policy).unwrap();
        let quoted = format!("(subpath {})", sbpl(&registry).unwrap());
        let grant = profile
            .find(&format!("(allow file-read* {quoted})"))
            .expect("read grant");
        let deny = profile
            .find(&format!("(deny file-write* {quoted})"))
            .expect("write deny");
        let last_rw = profile.rfind("(allow file-read* file-write*").unwrap();
        assert!(
            grant < deny && last_rw < deny,
            "the write deny must follow every grant (last match wins):\n{profile}"
        );
        // Linux: the whole filesystem is read-only already; the registry is bound
        // read-only and never with `--bind`.
        let args = render_bwrap_args(&policy_without_deny(policy.clone()), &[]).unwrap();
        let reg = registry.to_str().unwrap();
        assert!(
            args.windows(3)
                .any(|w| w[0] == "--ro-bind" && w[1] == reg && w[2] == reg),
            "{args:?}"
        );
        assert!(
            !args.windows(3).any(|w| w[0] == "--bind" && w[1] == reg),
            "{args:?}"
        );
    }

    #[test]
    fn linking_the_dependency_cache_points_registry_and_git_at_it_and_replaces_stale_dirs() {
        let tmp = tempfile::TempDir::new().unwrap();
        let deps = fetched_cache(tmp.path(), true);
        let cargo_home = tmp.path().join("verify/.cargo");
        // A stale real directory (an earlier lane's) is replaced, not merged.
        std::fs::create_dir_all(cargo_home.join("registry/stale")).unwrap();
        link_dependency_cache(&deps, &cargo_home).unwrap();
        for dir in ["registry", "git"] {
            assert_eq!(
                std::fs::read_link(cargo_home.join(dir)).unwrap(),
                deps.join("cargo").join(dir)
            );
        }
        assert!(!cargo_home.join("registry/stale").exists());
        // Nothing fetched means nothing linked.
        let bare = tmp.path().join("bare");
        std::fs::create_dir_all(&bare).unwrap();
        let home2 = tmp.path().join("home2");
        std::fs::create_dir_all(&home2).unwrap();
        link_dependency_cache(&bare, &home2).unwrap();
        assert_eq!(std::fs::read_dir(&home2).unwrap().count(), 0);
    }

    // The macOS profile denies file writes everywhere and grants them back.

    const GLOBAL_WRITE_DENY: &str = "(deny file-write* (subpath \"/\"))";

    /// A builder policy with a read-write grant and a read-only grant inside it.
    fn nested_grant_profile() -> Vec<String> {
        let mut policy = SandboxPolicy::builder(&test_lane(), NetworkMode::None);
        policy.rw_paths.push(PathBuf::from("/nonexistent-cp/rw"));
        policy.ro_paths.push(PathBuf::from("/nonexistent-cp/rw/ro"));
        render_macos_profile(&policy)
            .unwrap()
            .lines()
            .map(String::from)
            .collect()
    }

    fn positions(lines: &[String], pred: impl Fn(&str) -> bool) -> Vec<usize> {
        (0..lines.len()).filter(|&i| pred(&lines[i])).collect()
    }

    #[test]
    fn the_global_write_deny_directly_follows_allow_default() {
        for (name, p) in all_policies(&test_lane()) {
            let profile = render_macos_profile(&p).unwrap();
            let lines: Vec<&str> = profile.lines().collect();
            assert_eq!(lines[1], "(allow default)", "{name}\n{profile}");
            assert_eq!(lines[2], GLOBAL_WRITE_DENY, "{name}\n{profile}");
            assert_eq!(
                lines.iter().filter(|l| **l == GLOBAL_WRITE_DENY).count(),
                1,
                "{name}\n{profile}"
            );
        }
    }

    #[test]
    fn every_write_allow_comes_after_the_global_write_deny() {
        let lines = nested_grant_profile();
        let deny = lines.iter().position(|l| l == GLOBAL_WRITE_DENY).unwrap();
        let rw = positions(&lines, |l| l.starts_with("(allow file-read* file-write*"));
        let dev = positions(&lines, |l| l.starts_with("(allow file-write*"));
        // The builder's own grants and the extra one, then the device files.
        assert!(rw.len() >= 5, "rw allows: {rw:?}");
        assert_eq!(dev.len(), 1, "device allow: {dev:?}");
        for i in rw.iter().chain(dev.iter()) {
            assert!(deny < *i, "line {i} is before the global deny:\n{lines:#?}");
        }
        assert!(
            lines.contains(
                &"(allow file-read* file-write* (subpath \"/nonexistent-cp/rw\"))".to_string()
            ),
            "{lines:#?}"
        );
    }

    #[test]
    fn every_read_only_write_deny_comes_after_every_write_allow() {
        let lines = nested_grant_profile();
        let allows = positions(&lines, |l| {
            l.starts_with("(allow file-read* file-write*") || l.starts_with("(allow file-write*")
        });
        let last_allow = *allows.iter().max().unwrap();
        let ro_denies = positions(&lines, |l| {
            l.starts_with("(deny file-write* (subpath") && l != GLOBAL_WRITE_DENY
        });
        // The builder has three read-only mounts, and the nested one.
        assert_eq!(ro_denies.len(), 4, "{lines:#?}");
        for i in &ro_denies {
            assert!(
                last_allow < *i,
                "read-only deny at {i} is before the write allow at {last_allow}:\n{lines:#?}"
            );
        }
        assert!(
            lines.contains(&"(deny file-write* (subpath \"/nonexistent-cp/rw/ro\"))".to_string()),
            "{lines:#?}"
        );
    }

    #[test]
    fn the_device_files_a_process_needs_are_writable() {
        let lines = nested_grant_profile();
        let deny = lines.iter().position(|l| l == GLOBAL_WRITE_DENY).unwrap();
        let allow = lines
            .iter()
            .position(|l| l.starts_with("(allow file-write* (literal"))
            .unwrap();
        assert!(deny < allow);
        for dev in ["/dev/null", "/dev/zero", "/dev/tty", "/dev/dtracehelper"] {
            assert!(
                lines[allow].contains(&format!("(literal \"{dev}\")")),
                "{dev} missing from {}",
                lines[allow]
            );
        }
        // Devices, not the directory: no other /dev path becomes writable.
        assert!(!lines[allow].contains("subpath"), "{}", lines[allow]);
    }

    #[test]
    fn every_policy_that_writes_scratch_gets_a_temp_dir_inside_it() {
        let lane = test_lane();
        let want = lane.scratch.join("tmp").to_string_lossy().into_owned();
        assert_eq!(lane_tmp(&lane.scratch), lane.scratch.join("tmp"));
        for (name, p) in all_policies(&lane) {
            let tmpdir = p.env_set.iter().find(|(k, _)| k == "TMPDIR");
            if name == "dependency_fetch" {
                // It writes only its cache directory and runs no check.
                assert!(tmpdir.is_none(), "{name}: {:?}", p.env_set);
                continue;
            }
            assert_eq!(tmpdir.map(|(_, v)| v), Some(&want), "{name}");
            // The temp dir is under a read-write grant, so macOS lets it be written.
            assert!(
                p.rw_paths
                    .iter()
                    .any(|g| lane.scratch.join("tmp").starts_with(g)),
                "{name}: {want} is under no read-write grant"
            );
        }
        // Claude Code reads its own variable first; only the builder runs it.
        for (name, p) in all_policies(&lane) {
            let claude = p.env_set.iter().find(|(k, _)| k == "CLAUDE_CODE_TMPDIR");
            assert_eq!(
                claude.map(|(_, v)| v),
                (name == "builder").then_some(&want),
                "{name}"
            );
        }
    }
}
