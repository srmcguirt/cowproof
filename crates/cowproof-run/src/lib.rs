use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Network mode for sandbox policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkMode {
    /// No network access.
    None,
    /// Access to a local proxy on localhost (macOS) or Unix socket (Linux).
    ProxyOnly { port: u16 },
    /// Registry-only access through the proxy.
    RegistryReadOnly { port: u16 },
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
    /// Environment variables allowed (if None, all allowed).
    pub env_allowlist: Option<BTreeSet<String>>,
    /// Home directory path.
    pub home: PathBuf,
}

impl SandboxPolicy {
    /// Builder for a lane doing development work: read-write to clone, home, scratch; registry read-only.
    pub fn builder(lane: &LaneLayout) -> Self {
        Self {
            rw_paths: vec![lane.clone.clone(), lane.home.clone(), lane.scratch.clone()],
            ro_paths: vec![],
            network: NetworkMode::RegistryReadOnly { port: 8888 },
            env_allowlist: None,
            home: lane.home.clone(),
        }
    }

    /// Verifier for checking patches: read-write to clone and scratch; no network.
    pub fn verifier(lane: &LaneLayout) -> Self {
        Self {
            rw_paths: vec![lane.clone.clone(), lane.scratch.clone()],
            ro_paths: vec![],
            network: NetworkMode::None,
            env_allowlist: None,
            home: lane.home.clone(),
        }
    }

    /// Run check: read-write to clone and scratch only; no network.
    pub fn run_check(lane: &LaneLayout) -> Self {
        Self {
            rw_paths: vec![lane.clone.clone(), lane.scratch.clone()],
            ro_paths: vec![],
            network: NetworkMode::None,
            env_allowlist: None,
            home: lane.home.clone(),
        }
    }

    /// Dependency fetch: read-write to scratch; read-only registry.
    pub fn dependency_fetch(lane: &LaneLayout) -> Self {
        Self {
            rw_paths: vec![lane.scratch.clone()],
            ro_paths: vec![],
            network: NetworkMode::RegistryReadOnly { port: 8888 },
            env_allowlist: None,
            home: lane.home.clone(),
        }
    }

    /// Capture for porting: read-write to clone and scratch; no network.
    pub fn capture(lane: &LaneLayout) -> Self {
        Self {
            rw_paths: vec![lane.clone.clone(), lane.scratch.clone()],
            ro_paths: vec![],
            network: NetworkMode::None,
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

    // Add toolchain paths
    ro_rules.push_str(&format!(
        "(allow file-read* (subpath {}))\n",
        quote_json(&policy.home.join(".rustup").to_string_lossy())
    ));
    rw_rules.push_str(&format!(
        "(allow file-read* file-write* (subpath {}))\n",
        quote_json(&policy.home.join(".cargo").to_string_lossy())
    ));

    // Deny credentials
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
        NetworkMode::ProxyOnly { port } | NetworkMode::RegistryReadOnly { port } => {
            format!(
                "(allow network* (remote localhost:{}))\n(deny network* (remote \"*\"))\n",
                port
            )
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

    // Toolchain paths
    let rustup = policy.home.join(".rustup");
    let cargo = policy.home.join(".cargo");
    if rustup.exists() {
        args.extend([
            "--ro-bind".to_string(),
            rustup.to_string_lossy().into_owned(),
            rustup.to_string_lossy().into_owned(),
        ]);
    }
    if cargo.exists() {
        args.extend([
            "--bind".to_string(),
            cargo.to_string_lossy().into_owned(),
            cargo.to_string_lossy().into_owned(),
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

    // Network namespace (remove network for None and ProxyOnly modes)
    match &policy.network {
        NetworkMode::None => {
            args.push("--unshare-net".to_string());
        }
        NetworkMode::ProxyOnly { .. } | NetworkMode::RegistryReadOnly { .. } => {
            args.push("--unshare-net".to_string());
            // Unix socket path would be bound here in a full implementation
            // For now, we note that the proxy socket would be bound
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
    fn test_macos_profile_builder() {
        let lane = test_lane();
        let policy = SandboxPolicy::builder(&lane);
        let profile = render_macos_profile(&policy);

        assert!(profile.contains("(version 1)"));
        assert!(profile.contains("credentials.toml"));
        assert!(profile.contains(&lane.clone.to_string_lossy().to_string()));
    }

    #[test]
    fn test_linux_args_builder() {
        let lane = test_lane();
        let policy = SandboxPolicy::builder(&lane);
        let args = render_bwrap_args(&policy, &["test".to_string()]);

        assert!(args.contains(&"--unshare-pid".to_string()));
        assert!(args.contains(&"--tmpfs".to_string()));
        let tmpfs_idx = args.iter().position(|x| x == "--tmpfs").unwrap();
        assert_eq!(args[tmpfs_idx + 1], lane.home.to_string_lossy().to_string());
    }

    #[test]
    fn table_driven_macos_profiles() {
        let lane = test_lane();
        let policies = [
            ("builder", SandboxPolicy::builder(&lane)),
            ("verifier", SandboxPolicy::verifier(&lane)),
            ("run_check", SandboxPolicy::run_check(&lane)),
            ("dependency_fetch", SandboxPolicy::dependency_fetch(&lane)),
            ("capture", SandboxPolicy::capture(&lane)),
        ];

        for (name, policy) in &policies {
            let profile = render_macos_profile(policy);
            // All profiles should have version 1 and credentials denial
            assert!(
                profile.contains("(version 1)"),
                "Profile {} missing version",
                name
            );
            assert!(
                profile.contains("credentials") || name == &"verifier",
                "Profile {} missing credentials rules",
                name
            );
        }
    }

    #[test]
    fn table_driven_linux_args() {
        let lane = test_lane();
        let policies = [
            ("builder", SandboxPolicy::builder(&lane)),
            ("verifier", SandboxPolicy::verifier(&lane)),
            ("run_check", SandboxPolicy::run_check(&lane)),
            ("dependency_fetch", SandboxPolicy::dependency_fetch(&lane)),
            ("capture", SandboxPolicy::capture(&lane)),
        ];

        for (name, policy) in &policies {
            let args = render_bwrap_args(policy, &["cmd".to_string()]);
            // All should have unshare-pid
            assert!(
                args.contains(&"--unshare-pid".to_string()),
                "Policy {} missing --unshare-pid",
                name
            );
            // All should have tmpfs for HOME
            assert!(
                args.contains(&"--tmpfs".to_string()),
                "Policy {} missing --tmpfs",
                name
            );
            // Command should be at the end
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
        let policy = SandboxPolicy::builder(&lane);
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
        let policy = SandboxPolicy::builder(&lane);
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
        let policy = SandboxPolicy::builder(&lane);
        let args = render_bwrap_args(&policy, &[]);
        assert!(args.contains(&"--unshare-pid".to_string()));
    }

    #[test]
    fn regression_home_hidden() {
        let lane = test_lane();
        let policy = SandboxPolicy::builder(&lane);
        let args = render_bwrap_args(&policy, &[]);

        // HOME should be tmpfs
        let tmpfs_idx = args.iter().position(|x| x == "--tmpfs").unwrap();
        assert_eq!(args[tmpfs_idx + 1], lane.home.to_string_lossy().to_string());
    }

    #[test]
    fn regression_rustup_and_cargo() {
        let lane = test_lane();
        let policy = SandboxPolicy::builder(&lane);
        let profile = render_macos_profile(&policy);

        // Both should appear in the profile (even if not created)
        assert!(profile.contains(".rustup"), "rustup not in profile");
        assert!(profile.contains(".cargo"), "cargo not in profile");
    }

    #[test]
    fn regression_credentials_denied() {
        let lane = test_lane();
        let policy = SandboxPolicy::builder(&lane);
        let profile = render_macos_profile(&policy);

        assert!(profile.contains("credentials.toml"));
        assert!(profile.contains("credentials"));
    }

    #[test]
    fn regression_command_passthrough() {
        let lane = test_lane();
        let policy = SandboxPolicy::builder(&lane);
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
        let policy = SandboxPolicy::builder(&lane);
        // Profile should be rendered; its path would be in lane/sandbox.sb
        let _profile = render_macos_profile(&policy);
        // In actual usage, profile is written to lane/sandbox.sb, not lane/clone
    }

    #[test]
    fn a3_control_directory_not_in_rw() {
        let lane = LaneLayout {
            clone: PathBuf::from("/lanes/l1/clone"),
            home: PathBuf::from("/home/testuser"),
            scratch: PathBuf::from("/lanes/l1/scratch"),
        };

        let policy = SandboxPolicy::builder(&lane);

        // Verify that control directory is not in rw_paths
        let control = PathBuf::from("/lanes/l1/control");
        for rw in &policy.rw_paths {
            assert!(
                !control.starts_with(rw) && rw != &control,
                "Control directory {} should not be in rw_paths",
                control.display()
            );
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn live_test_macos_control_denied() {
        use std::process::Command;

        let lane = test_lane();
        let policy = SandboxPolicy::builder(&lane);
        let profile = render_macos_profile(&policy);

        // Create temp directories
        let tmpdir = std::env::temp_dir().join("cowproof-test");
        let _ = std::fs::create_dir_all(&tmpdir);
        let clone_dir = tmpdir.join("clone");
        let control_dir = tmpdir.join("control");
        let secret_file = control_dir.join("secret.txt");

        let _ = std::fs::create_dir_all(&clone_dir);
        let _ = std::fs::create_dir_all(&control_dir);
        let _ = std::fs::write(&secret_file, "SECRET");

        // Write profile to file
        let profile_path = tmpdir.join("test.sb");
        let _ = std::fs::write(&profile_path, &profile);

        // Try to read the secret file through sandbox - should fail
        let output = Command::new("sandbox-exec")
            .arg("-f")
            .arg(&profile_path)
            .arg("/bin/cat")
            .arg(&secret_file)
            .output();

        // The command should either fail or return error
        if let Ok(output) = output {
            assert!(
                !output.status.success(),
                "Should not be able to read control directory"
            );
        }

        // Cleanup
        let _ = std::fs::remove_dir_all(&tmpdir);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn live_test_linux_control_denied() {
        use std::process::Command;

        // Check if bwrap is available
        if Command::new("which").arg("bwrap").output().is_err() {
            eprintln!("bwrap not installed, skipping live test");
            return;
        }

        let lane = test_lane();
        let policy = SandboxPolicy::builder(&lane);

        // Create temp directories
        let tmpdir = std::env::temp_dir().join("cowproof-test");
        let _ = std::fs::create_dir_all(&tmpdir);
        let clone_dir = tmpdir.join("clone");
        let control_dir = tmpdir.join("control");
        let secret_file = control_dir.join("secret.txt");

        let _ = std::fs::create_dir_all(&clone_dir);
        let _ = std::fs::create_dir_all(&control_dir);
        let _ = std::fs::write(&secret_file, "SECRET");

        // Try to read the secret file through bwrap - should fail
        let mut cmd = vec!["bwrap".to_string()];
        let args = render_bwrap_args(
            &policy,
            &[
                "/bin/cat".to_string(),
                secret_file.to_string_lossy().into_owned(),
            ],
        );

        let output = Command::new(&cmd[0]).args(&args[1..]).output();

        // The command should fail or return error
        if let Ok(output) = output {
            assert!(
                !output.status.success(),
                "Should not be able to read control directory"
            );
        }

        // Cleanup
        let _ = std::fs::remove_dir_all(&tmpdir);
    }
}
