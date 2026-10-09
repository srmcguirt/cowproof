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

pub mod claude;
pub mod lane;
pub mod prefix;
pub mod proxy;
pub mod stream;

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
    /// Access to a local egress proxy (macOS localhost port, Linux Unix socket).
    /// The socket path is used for Linux bind-mount; port is used for macOS localhost.
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
            env_set: vec![cargo_home(&lane_cargo)],
            env_allowlist: None,
            home: lane.real_home.clone(),
        }
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
            env_set: vec![cargo_home(&verifier_cargo)],
            env_allowlist: None,
            home: lane.real_home.clone(),
        }
    }

    /// Run check: read-write to clone and scratch (and the lane's own cargo
    /// home); no network.
    pub fn run_check(lane: &LaneLayout) -> Self {
        let lane_cargo = lane.home.join(".cargo");
        Self {
            rw_paths: vec![lane.clone.clone(), lane.scratch.clone(), lane_cargo.clone()],
            ro_paths: vec![lane.real_home.join(".rustup")],
            deny_paths: vec![lane.control.clone()],
            network: NetworkMode::None,
            env_set: vec![cargo_home(&lane_cargo)],
            env_allowlist: None,
            home: lane.real_home.clone(),
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
        }
    }

    /// Capture for porting: read-write to clone and scratch; no network (D10).
    pub fn capture(lane: &LaneLayout) -> Self {
        Self {
            rw_paths: vec![lane.clone.clone(), lane.scratch.clone()],
            ro_paths: vec![],
            deny_paths: vec![lane.control.clone()],
            network: NetworkMode::None,
            env_set: vec![],
            env_allowlist: None,
            home: lane.real_home.clone(),
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
}

/// Lockfiles, at the tree root only, that determine the dependencies (D11).
const LOCKFILES: &[&str] = &[
    "Cargo.lock",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "Gemfile.lock",
];

/// Registry and source configuration, relative to the tree root (D14).
const REGISTRY_CONFIGS: &[&str] = &[
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
    deny: BTreeSet<PathBuf>,
    credentials: Vec<PathBuf>,
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
    Ok(Resolved {
        home,
        rw,
        ro,
        deny,
        credentials,
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

/// Render a sandbox policy as a macOS Seatbelt profile.
///
/// Seatbelt applies the last matching rule, so grants come before the denies
/// that must win over them (credentials, then `deny_paths`).
pub fn render_macos_profile(policy: &SandboxPolicy) -> Result<String> {
    let r = resolve(policy)?;
    let mut out = String::from("(version 1)\n(allow default)\n");
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
    out.push_str("(allow file-read-metadata");
    for m in &metadata {
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

    match &policy.network {
        NetworkMode::None => out.push_str("(deny network*)\n"),
        NetworkMode::Proxy { port, .. } | NetworkMode::RegistryReadOnly { port, .. } => {
            out.push_str("(deny network*)\n");
            out.push_str(&format!(
                "(allow network-outbound (remote ip \"localhost:{port}\"))\n"
            ));
        }
        // Legacy: no network rules.
        NetworkMode::Unrestricted => {}
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
/// only granted paths are bound back in. A path that does not exist on the
/// host cannot be bound and is skipped, except a `deny_paths` entry: hiding it
/// is required, so a missing one is an error.
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

    /// Absolute, non-symlinked, non-existent paths: renders are pure.
    fn test_lane() -> LaneLayout {
        LaneLayout {
            clone: PathBuf::from("/nonexistent-cp/lanes/l1/clone"),
            home: PathBuf::from("/nonexistent-cp/lanes/l1/home"),
            scratch: PathBuf::from("/nonexistent-cp/lanes/l1/scratch"),
            control: PathBuf::from("/nonexistent-cp/lanes/l1/control"),
            real_home: PathBuf::from("/nonexistent-cp/realhome"),
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
        assert_eq!(env.len(), 2);
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
}
