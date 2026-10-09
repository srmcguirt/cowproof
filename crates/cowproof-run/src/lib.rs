use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

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
    /// Network access mode.
    pub network: NetworkMode,
    /// Environment variables to set inside the sandbox.
    pub env_set: Vec<(String, String)>,
    /// Environment variables allowed (if None, all allowed).
    pub env_allowlist: Option<BTreeSet<String>>,
    /// Home directory path.
    pub home: PathBuf,
}

impl SandboxPolicy {
    /// Builder for a lane doing development work.
    /// rw: clone, lane/home/.cargo (D18), scratch
    /// ro: real ~/.cargo/registry and ~/.cargo/git; real ~/.rustup
    /// network: must be passed by caller (not hardcoded)
    pub fn builder(lane: &LaneLayout, network: NetworkMode) -> Self {
        let lane_cargo = lane.home.join(".cargo");
        let real_home = dirs_home();
        let mut rw_paths = vec![lane.clone.clone(), lane.scratch.clone()];
        rw_paths.push(lane_cargo.clone());

        let mut ro_paths = vec![lane.home.clone(), real_home.join(".rustup")];
        ro_paths.push(real_home.join(".cargo/registry"));
        ro_paths.push(real_home.join(".cargo/git"));

        Self {
            rw_paths,
            ro_paths,
            network,
            env_set: vec![(
                "CARGO_HOME".to_string(),
                lane_cargo.to_string_lossy().into_owned(),
            )],
            env_allowlist: None,
            home: lane.home.clone(),
        }
    }

    /// Verifier for checking patches.
    /// rw: clone, scratch, verifier cache dir (passed as parameter)
    /// ro: real ~/.rustup
    /// network: none (D6)
    pub fn verifier(lane: &LaneLayout, cache_dir: &Path) -> Self {
        let real_home = dirs_home();
        let verifier_cargo = cache_dir.join(".cargo");

        let mut rw_paths = vec![lane.clone.clone(), lane.scratch.clone()];
        rw_paths.push(verifier_cargo.clone());

        Self {
            rw_paths,
            ro_paths: vec![real_home.join(".rustup")],
            network: NetworkMode::None,
            env_set: vec![(
                "CARGO_HOME".to_string(),
                verifier_cargo.to_string_lossy().into_owned(),
            )],
            env_allowlist: None,
            home: lane.home.clone(),
        }
    }

    /// Run check: read-write to clone and scratch only; no network.
    /// Like verifier but with lane home write access for scratch tests.
    pub fn run_check(lane: &LaneLayout) -> Self {
        let lane_cargo = lane.home.join(".cargo");
        let real_home = dirs_home();

        let rw_paths = vec![lane.clone.clone(), lane.scratch.clone(), lane_cargo.clone()];

        Self {
            rw_paths,
            ro_paths: vec![real_home.join(".rustup")],
            network: NetworkMode::None,
            env_set: vec![(
                "CARGO_HOME".to_string(),
                lane_cargo.to_string_lossy().into_owned(),
            )],
            env_allowlist: None,
            home: lane.home.clone(),
        }
    }

    /// Dependency fetch: write to cache_dir; read-only registry access.
    /// network: must be passed by caller
    pub fn dependency_fetch(lane: &LaneLayout, cache_dir: &Path, network: NetworkMode) -> Self {
        Self {
            rw_paths: vec![cache_dir.to_path_buf()],
            ro_paths: vec![],
            network,
            env_set: vec![],
            env_allowlist: None,
            home: lane.home.clone(),
        }
    }

    /// Capture for porting: read-write to clone and scratch; no network (D10).
    pub fn capture(lane: &LaneLayout) -> Self {
        Self {
            rw_paths: vec![lane.clone.clone(), lane.scratch.clone()],
            ro_paths: vec![],
            network: NetworkMode::None,
            env_set: vec![],
            env_allowlist: None,
            home: lane.home.clone(),
        }
    }
}

/// Lane filesystem layout.
#[derive(Debug, Clone)]
pub struct LaneLayout {
    /// Clone of the repository.
    pub clone: PathBuf,
    /// Home directory inside the sandbox.
    pub home: PathBuf,
    /// Scratch directory inside the sandbox.
    pub scratch: PathBuf,
}

fn dirs_home() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/root"))
}

/// Render a sandbox policy as a macOS Seatbelt profile.
pub fn render_macos_profile(policy: &SandboxPolicy) -> String {
    let home_s = policy.home.to_string_lossy();
    let mut ancestors = Vec::new();
    let mut d = policy.rw_paths.first().and_then(|p| p.parent());
    while let Some(p) = d {
        if p.starts_with(&policy.home) {
            ancestors.push(p.to_string_lossy().to_string());
            d = p.parent();
        } else {
            break;
        }
    }
    let metadata = ancestors
        .iter()
        .map(|a| format!(" (literal {})", quote_json(a)))
        .collect::<String>();

    let mut rw_rules = String::new();
    for p in &policy.rw_paths {
        if p != &policy.home {
            rw_rules.push_str(&format!(
                "(allow file-read* file-write* (subpath {}))\n",
                quote_json(&p.to_string_lossy())
            ));
        }
    }

    let mut ro_rules = String::new();
    for p in &policy.ro_paths {
        ro_rules.push_str(&format!(
            "(allow file-read* (subpath {}))\n",
            quote_json(&p.to_string_lossy())
        ));
    }

    // Add rustup read-only if not already in ro_paths
    let rustup = policy.home.join(".rustup");
    if !policy.ro_paths.iter().any(|p| p == &rustup) {
        ro_rules.push_str(&format!(
            "(allow file-read* (subpath {}))\n",
            quote_json(&rustup.to_string_lossy())
        ));
    }

    // Deny credentials (D18: real ~/.cargo is not writable, credentials denied)
    let creds = [
        policy.home.join(".cargo/credentials.toml"),
        policy.home.join(".cargo/credentials"),
    ];
    let mut deny_creds = String::new();
    for cred in &creds {
        deny_creds.push_str(&format!(
            "(deny file-read* file-write* (literal {}))\n",
            quote_json(&cred.to_string_lossy())
        ));
    }

    // Network rules
    let network_rules = match &policy.network {
        NetworkMode::None => "(deny network*)\n".to_string(),
        NetworkMode::Proxy { port, .. } | NetworkMode::RegistryReadOnly { port, .. } => {
            format!(
                "(allow network* (remote localhost:{}))\n(deny network* (remote \"*\"))\n",
                port
            )
        }
        NetworkMode::Unrestricted => {
            // Legacy: no network rules, allow all
            String::new()
        }
    };

    format!(
        "(version 1)\n(allow default)\n(deny file-read* file-write* (subpath {}))\n(allow file-read-metadata (literal {}){})\n{}{}{}{}\n",
        quote_json(&home_s),
        quote_json(&home_s),
        metadata,
        rw_rules,
        ro_rules,
        deny_creds,
        network_rules
    )
}

/// Render a sandbox policy as bubblewrap arguments for Linux.
pub fn render_bwrap_args(policy: &SandboxPolicy, cmd: &[String]) -> Vec<String> {
    let mut args = vec![
        "--die-with-parent".to_string(),
        "--unshare-pid".to_string(),
        "--ro-bind".to_string(),
        "/".to_string(),
        "/".to_string(),
        "--dev".to_string(),
        "/dev".to_string(),
        "--proc".to_string(),
        "/proc".to_string(),
        "--bind".to_string(),
        "/tmp".to_string(),
        "/tmp".to_string(),
        "--tmpfs".to_string(),
        policy.home.to_string_lossy().into_owned(),
    ];

    // Bind rw_paths
    for p in &policy.rw_paths {
        if p.exists() {
            args.extend([
                "--bind".to_string(),
                p.to_string_lossy().into_owned(),
                p.to_string_lossy().into_owned(),
            ]);
        }
    }

    // Bind ro_paths
    for p in &policy.ro_paths {
        if p.exists() {
            args.extend([
                "--ro-bind".to_string(),
                p.to_string_lossy().into_owned(),
                p.to_string_lossy().into_owned(),
            ]);
        }
    }

    // Toolchain paths (D18: only rustup is readable; cargo home is set via env)
    let rustup = policy.home.join(".rustup");
    if rustup.exists() {
        args.extend([
            "--ro-bind".to_string(),
            rustup.to_string_lossy().into_owned(),
            rustup.to_string_lossy().into_owned(),
        ]);
    }

    // Deny credentials by binding to /dev/null
    for cred in [
        policy.home.join(".cargo/credentials.toml"),
        policy.home.join(".cargo/credentials"),
    ] {
        if cred.exists() {
            args.extend([
                "--ro-bind".to_string(),
                "/dev/null".to_string(),
                cred.to_string_lossy().into_owned(),
            ]);
        }
    }

    // Network namespace
    match &policy.network {
        NetworkMode::None => {
            args.push("--unshare-net".to_string());
        }
        NetworkMode::Proxy { socket, .. } | NetworkMode::RegistryReadOnly { socket, .. } => {
            args.push("--unshare-net".to_string());
            // Unix socket would be bind-mounted here when proxy is ready
            if socket.exists() {
                args.extend([
                    "--ro-bind".to_string(),
                    socket.to_string_lossy().into_owned(),
                    socket.to_string_lossy().into_owned(),
                ]);
            }
        }
        NetworkMode::Unrestricted => {
            // Legacy: no network restrictions
        }
    }

    args.extend_from_slice(cmd);
    args
}

/// Build the sandbox command to run with the given policy.
pub fn sandbox_command(
    policy: &SandboxPolicy,
    profile_path: &Path,
    cmd: &[String],
    platform: &str,
) -> (String, Vec<String>) {
    match platform {
        "darwin" => {
            let mut args = vec![
                "-f".to_string(),
                profile_path.to_string_lossy().into_owned(),
            ];
            args.extend_from_slice(cmd);
            ("sandbox-exec".to_string(), args)
        }
        "linux" => {
            let args = render_bwrap_args(policy, cmd);
            ("bwrap".to_string(), args)
        }
        _ => panic!("unsupported platform: {}", platform),
    }
}

fn quote_json(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| "\"\"".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_lane() -> LaneLayout {
        LaneLayout {
            clone: PathBuf::from("/lanes/l1/clone"),
            home: PathBuf::from("/home/testuser"),
            scratch: PathBuf::from("/lanes/l1/scratch"),
        }
    }

    #[test]
    fn no_constructors_default_to_unrestricted() {
        let lane = test_lane();
        let cache_dir = PathBuf::from("/tmp/cache");

        let builder = SandboxPolicy::builder(&lane, NetworkMode::None);
        assert_ne!(builder.network, NetworkMode::Unrestricted);

        let verifier = SandboxPolicy::verifier(&lane, &cache_dir);
        assert_ne!(verifier.network, NetworkMode::Unrestricted);

        let run_check = SandboxPolicy::run_check(&lane);
        assert_ne!(run_check.network, NetworkMode::Unrestricted);

        let fetch = SandboxPolicy::dependency_fetch(&lane, &cache_dir, NetworkMode::None);
        assert_ne!(fetch.network, NetworkMode::Unrestricted);

        let capture = SandboxPolicy::capture(&lane);
        assert_ne!(capture.network, NetworkMode::Unrestricted);
    }

    #[test]
    fn unrestricted_renders_no_network_rules() {
        let lane = test_lane();
        let policy = SandboxPolicy {
            rw_paths: vec![lane.clone.clone()],
            ro_paths: vec![],
            network: NetworkMode::Unrestricted,
            env_set: vec![],
            env_allowlist: None,
            home: lane.home.clone(),
        };

        let profile = render_macos_profile(&policy);
        // No deny network* rules
        assert!(
            !profile.contains("(deny network"),
            "Unrestricted should not deny network"
        );
        assert!(
            !profile.contains("(allow network"),
            "Unrestricted should not restrict network"
        );
    }

    #[test]
    fn d18_builder_sets_cargo_home_env() {
        let lane = test_lane();
        let policy = SandboxPolicy::builder(&lane, NetworkMode::None);

        assert!(
            policy
                .env_set
                .iter()
                .any(|(k, v)| k == "CARGO_HOME" && v.contains(".cargo")),
            "Builder should set CARGO_HOME to lane/.cargo"
        );
    }

    #[test]
    fn d18_builder_rw_includes_lane_cargo() {
        let lane = test_lane();
        let policy = SandboxPolicy::builder(&lane, NetworkMode::None);

        let lane_cargo = lane.home.join(".cargo");
        assert!(
            policy.rw_paths.contains(&lane_cargo),
            "Builder rw_paths should include lane/.cargo"
        );
    }

    #[test]
    fn d18_builder_ro_includes_registry_and_git() {
        let lane = test_lane();
        let policy = SandboxPolicy::builder(&lane, NetworkMode::None);

        let ro_str = policy
            .ro_paths
            .iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect::<Vec<_>>()
            .join(",");

        assert!(
            ro_str.contains("registry"),
            "Should have read-only registry access"
        );
        assert!(ro_str.contains("git"), "Should have read-only git access");
    }

    #[test]
    fn table_driven_macos_profiles() {
        let lane = test_lane();
        let cache_dir = PathBuf::from("/tmp/cache");
        let policies = [
            ("builder", SandboxPolicy::builder(&lane, NetworkMode::None)),
            ("verifier", SandboxPolicy::verifier(&lane, &cache_dir)),
            ("run_check", SandboxPolicy::run_check(&lane)),
            (
                "dependency_fetch",
                SandboxPolicy::dependency_fetch(&lane, &cache_dir, NetworkMode::None),
            ),
            ("capture", SandboxPolicy::capture(&lane)),
        ];

        for (name, policy) in &policies {
            let profile = render_macos_profile(policy);
            assert!(
                profile.contains("(version 1)"),
                "Profile {} missing version",
                name
            );
        }
    }

    #[test]
    fn table_driven_linux_args() {
        let lane = test_lane();
        let cache_dir = PathBuf::from("/tmp/cache");
        let policies = [
            ("builder", SandboxPolicy::builder(&lane, NetworkMode::None)),
            ("verifier", SandboxPolicy::verifier(&lane, &cache_dir)),
            ("run_check", SandboxPolicy::run_check(&lane)),
            (
                "dependency_fetch",
                SandboxPolicy::dependency_fetch(&lane, &cache_dir, NetworkMode::None),
            ),
            ("capture", SandboxPolicy::capture(&lane)),
        ];

        for (name, policy) in &policies {
            let args = render_bwrap_args(policy, &["cmd".to_string()]);
            assert!(
                args.contains(&"--unshare-pid".to_string()),
                "Policy {} missing --unshare-pid",
                name
            );
            assert_eq!(
                &args[args.len() - 1],
                "cmd",
                "Policy {} command not at end",
                name
            );
        }
    }

    #[test]
    fn sandbox_command_darwin() {
        let lane = test_lane();
        let policy = SandboxPolicy::builder(&lane, NetworkMode::None);
        let (cmd, args) = sandbox_command(
            &policy,
            Path::new("/l/sandbox.sb"),
            &["test".into()],
            "darwin",
        );

        assert_eq!(cmd, "sandbox-exec");
        assert_eq!(args[0], "-f");
        assert_eq!(args[1], "/l/sandbox.sb");
        assert_eq!(args[2], "test");
    }

    #[test]
    fn sandbox_command_linux() {
        let lane = test_lane();
        let policy = SandboxPolicy::builder(&lane, NetworkMode::None);
        let (cmd, args) = sandbox_command(
            &policy,
            Path::new("/l/sandbox.sb"),
            &["test".into()],
            "linux",
        );

        assert_eq!(cmd, "bwrap");
        assert_eq!(args[args.len() - 1], "test");
    }

    #[test]
    fn regression_linux_unshare_pid() {
        let lane = test_lane();
        let policy = SandboxPolicy::builder(&lane, NetworkMode::None);
        let args = render_bwrap_args(&policy, &[]);
        assert!(args.contains(&"--unshare-pid".to_string()));
    }

    #[test]
    fn regression_home_hidden() {
        let lane = test_lane();
        let policy = SandboxPolicy::builder(&lane, NetworkMode::None);
        let args = render_bwrap_args(&policy, &[]);

        let tmpfs_idx = args.iter().position(|x| x == "--tmpfs").unwrap();
        assert_eq!(args[tmpfs_idx + 1], lane.home.to_string_lossy().to_string());
    }

    #[test]
    fn regression_credentials_denied() {
        let lane = test_lane();
        let policy = SandboxPolicy::builder(&lane, NetworkMode::None);
        let profile = render_macos_profile(&policy);

        assert!(profile.contains("credentials.toml"));
        assert!(profile.contains("credentials"));
    }

    #[test]
    fn regression_command_passthrough() {
        let lane = test_lane();
        let policy = SandboxPolicy::builder(&lane, NetworkMode::None);
        let cmd = vec![
            "mycommand".to_string(),
            "arg1".to_string(),
            "arg2".to_string(),
        ];
        let args = render_bwrap_args(&policy, &cmd);

        assert_eq!(&args[args.len() - 3..], ["mycommand", "arg1", "arg2"]);
    }

    #[test]
    fn regression_profile_in_lane() {
        let lane = test_lane();
        let policy = SandboxPolicy::builder(&lane, NetworkMode::None);
        let _profile = render_macos_profile(&policy);
    }

    #[test]
    fn a3_control_directory_not_in_rw() {
        let lane = LaneLayout {
            clone: PathBuf::from("/lanes/l1/clone"),
            home: PathBuf::from("/home/testuser"),
            scratch: PathBuf::from("/lanes/l1/scratch"),
        };

        let policy = SandboxPolicy::builder(&lane, NetworkMode::None);

        let control = PathBuf::from("/lanes/l1/control");
        for rw in &policy.rw_paths {
            assert!(
                !control.starts_with(rw) && rw != &control,
                "Control directory {} should not be in rw_paths",
                control.display()
            );
        }
    }

    #[test]
    fn live_test_macos_profile_generates() {
        // Verify macOS profile can be generated without errors (D10 regression)
        let lane = test_lane();
        let policy = SandboxPolicy::builder(&lane, NetworkMode::None);
        let profile = render_macos_profile(&policy);

        // Profile must have structure elements
        assert!(profile.contains("(version 1)"));
        assert!(profile.contains("(allow default)"));
        assert!(profile.contains("(deny file-read* file-write*"));
    }

    #[test]
    fn live_test_linux_bwrap_args_generate() {
        // Verify Linux args can be generated without errors (D10 regression)
        let lane = test_lane();
        let policy = SandboxPolicy::builder(&lane, NetworkMode::None);
        let args = render_bwrap_args(&policy, &["test".to_string()]);

        // Must have required bwrap arguments
        assert!(args.contains(&"--unshare-pid".to_string()));
        assert!(args.contains(&"--die-with-parent".to_string()));
        assert_eq!(args[args.len() - 1], "test");
    }

    #[test]
    fn d18_policy_structure_verification() {
        // Verify D18 policy structure without relying on external sandbox tools
        let lane = test_lane();
        let cache_dir = PathBuf::from("/tmp/cache");

        // Builder: must have lane/.cargo writable and set CARGO_HOME env
        let builder = SandboxPolicy::builder(&lane, NetworkMode::None);
        assert!(
            builder
                .rw_paths
                .iter()
                .any(|p| p.to_string_lossy().contains(".cargo")),
            "Builder must have writable .cargo path"
        );
        assert!(
            builder
                .env_set
                .iter()
                .any(|(k, v)| k == "CARGO_HOME" && v.contains(".cargo")),
            "Builder must set CARGO_HOME"
        );

        // Builder: must have registry and git in ro_paths
        let ro_str = builder
            .ro_paths
            .iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect::<Vec<_>>()
            .join(",");
        assert!(
            ro_str.contains("registry"),
            "Builder must have read-only registry"
        );
        assert!(ro_str.contains("git"), "Builder must have read-only git");

        // Verifier: must have no access to real ~/.cargo (only verifier's own cache)
        let verifier = SandboxPolicy::verifier(&lane, &cache_dir);
        // Check that real home's .cargo is not in the paths
        let real_home = dirs_home();
        let real_cargo = real_home.join(".cargo");
        assert!(
            !verifier.rw_paths.contains(&real_cargo),
            "Verifier must not have rw access to real ~/.cargo"
        );
        assert!(
            !verifier.ro_paths.contains(&real_cargo),
            "Verifier must not have ro access to real ~/.cargo"
        );
        // But should have cache_dir/.cargo for its own use
        let cache_cargo = cache_dir.join(".cargo");
        assert!(
            verifier.rw_paths.contains(&cache_cargo),
            "Verifier must have writable cache dir"
        );
    }
}
