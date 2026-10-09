//! Live sandbox tests: real `sandbox-exec` (macOS) or `bwrap` (Linux)
//! processes, never the real home. Every lane lives in a temporary directory
//! (deliberately left in its symlinked spelling, e.g. `/var/folders/...` on
//! macOS) beside a temporary FAKE home.
//!
//! Each script prints a marker for every probe and the tests assert on stdout
//! and on the files afterwards, so a sandbox that failed to start cannot make
//! a denial test pass: the allowed probes must succeed in the same run.

use cowproof_run::{LaneLayout, NetworkMode, SandboxPolicy, render_macos_profile, sandbox_command};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU32, Ordering};

const CONTROL_SECRET: &str = "CONTROL-SECRET-4f1c";
const CRED_SECRET: &str = "CRED-SECRET-77ab";
const HOME_SECRET: &str = "HOME-SECRET-92de";
const SOCK_DIR_SECRET: &str = "SOCK-DIR-SECRET-5c08";

static COUNTER: AtomicU32 = AtomicU32::new(0);

struct Fixture {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    lane: LaneLayout,
    lane_root: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf(); // not canonicalized on purpose
        let lane_root = root.join("lane");
        let fake_home = root.join("home");
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        // The scratch directory is under /tmp, a symlink on macOS.
        let scratch = PathBuf::from(format!("/tmp/cowproof-live-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&scratch);
        std::fs::create_dir_all(&scratch).unwrap();
        for d in [
            "lane/clone",
            "lane/control",
            "lane/sock",
            "other/sock",
            "lane/home/.cargo",
            "home/.cargo/bin",
            "home/.cargo/registry",
            "home/.rustup",
        ] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }
        let w = |p: PathBuf, s: &str| std::fs::write(p, s).unwrap();
        w(root.join("lane/control/secret"), CONTROL_SECRET);
        w(root.join("lane/clone/file"), "clone-original");
        w(root.join("lane/sock/stray"), SOCK_DIR_SECRET);
        w(root.join("home/.cargo/registry/x"), "registry-x");
        w(root.join("home/.cargo/credentials.toml"), CRED_SECRET);
        w(root.join("home/.cargo/bin/tool"), "tool-original");
        w(root.join("home/secret.txt"), HOME_SECRET);
        w(root.join("home/.rustup/toolchain"), "rustup-x");
        let lane = LaneLayout {
            clone: lane_root.join("clone"),
            home: lane_root.join("home"),
            scratch,
            control: lane_root.join("control"),
            real_home: fake_home,
            sock: lane_root.join("sock/runner.sock"),
            lanes_root: root.join("lane"),
        };
        Fixture {
            _tmp: tmp,
            root,
            lane,
            lane_root,
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.lane.scratch);
    }
}

/// Can this host run the sandbox at all? Linux needs bubblewrap and user
/// namespaces; macOS always has sandbox-exec.
/// Whether the live tests can create a sandbox here. With
/// `COWPROOF_REQUIRE_SANDBOX=1` (set in CI) an unavailable sandbox is a test
/// failure, not a skip, so a runner that cannot sandbox can never report these
/// tests as passing.
fn sandbox_available() -> bool {
    if cfg!(target_os = "macos") {
        return true;
    }
    let reason = match Command::new("bwrap")
        .args(["--ro-bind", "/", "/", "true"])
        .output()
    {
        Ok(o) if o.status.success() => return true,
        Ok(o) => format!(
            "bwrap cannot create a sandbox here (user namespaces unavailable?): {}",
            String::from_utf8_lossy(&o.stderr).trim()
        ),
        Err(e) => format!("bwrap is not installed: {e}"),
    };
    if std::env::var_os("COWPROOF_REQUIRE_SANDBOX").is_some_and(|v| v == "1") {
        panic!("COWPROOF_REQUIRE_SANDBOX=1 but {reason}");
    }
    eprintln!("SKIP: {reason}");
    false
}

fn platform() -> &'static str {
    if cfg!(target_os = "macos") {
        "darwin"
    } else {
        "linux"
    }
}

/// Run `script` under `/bin/sh -c` inside the sandbox described by `policy`.
fn run(policy: &SandboxPolicy, profile_dir: &Path, script: &str) -> Output {
    let profile_path = profile_dir.join("sandbox.sb");
    if cfg!(target_os = "macos") {
        std::fs::write(&profile_path, render_macos_profile(policy).unwrap()).unwrap();
    }
    let cmd: Vec<String> = ["/bin/sh", "-c", script].map(String::from).to_vec();
    let (program, args) = sandbox_command(policy, &profile_path, &cmd, platform()).unwrap();
    let mut c = Command::new(program);
    c.args(args);
    let mut env = vec![("PATH".to_string(), "/usr/bin:/bin".to_string())];
    policy.apply_env(&mut env);
    c.env_clear().envs(env);
    c.output().unwrap()
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn describe(o: &Output) -> String {
    format!(
        "status {:?}\nstdout:\n{}\nstderr:\n{}",
        o.status.code(),
        stdout(o),
        String::from_utf8_lossy(&o.stderr)
    )
}

fn read(p: impl AsRef<Path>) -> String {
    std::fs::read_to_string(p).unwrap_or_default()
}

// ---------------------------------------------------------------- A-3

#[test]
fn live_a3_builder_cannot_touch_control_but_owns_clone() {
    if !sandbox_available() {
        return;
    }
    let f = Fixture::new();
    let policy = SandboxPolicy::builder(&f.lane, NetworkMode::None);
    let c = f.lane.control.display();
    let k = f.lane.clone.display();
    let s = f.lane.scratch.display();
    let script = format!(
        r#"
echo "R_CONTROL:$(cat '{c}/secret' 2>&1)"
echo hacked > '{c}/secret' 2>/dev/null; echo "W_CONTROL:$?"
echo new > '{c}/new' 2>/dev/null; echo "C_CONTROL:$?"
for e in $(ls '{c}' 2>/dev/null); do echo "LISTED:$e"; done
echo "R_CLONE:$(cat '{k}/file' 2>&1)"
echo changed > '{k}/file'; echo "W_CLONE:$?"
echo made > '{k}/made'; echo "C_CLONE:$?"
echo s > '{s}/s'; echo "W_SCRATCH:$?"
"#
    );
    let o = run(&policy, &f.lane_root, &script);
    let out = stdout(&o);
    let why = describe(&o);
    assert!(o.status.success(), "{why}");
    assert!(
        !out.contains(CONTROL_SECRET),
        "control secret was read\n{why}"
    );
    // allowed operations worked in the same sandbox (the sandbox did start)
    assert!(out.contains("R_CLONE:clone-original"), "{why}");
    assert!(
        out.contains("W_CLONE:0") && out.contains("C_CLONE:0"),
        "{why}"
    );
    assert!(out.contains("W_SCRATCH:0"), "{why}");
    // every control write failed; nothing in control can be listed (macOS:
    // denied; Linux: the control path is an empty read-only tmpfs)
    for m in ["W_CONTROL", "C_CONTROL"] {
        assert!(
            out.contains(&format!("{m}:")) && !out.contains(&format!("{m}:0")),
            "{m} must fail\n{why}"
        );
    }
    assert!(
        !out.contains("LISTED:"),
        "control entries were listed\n{why}"
    );
    // ... and the files agree
    assert_eq!(read(f.lane.control.join("secret")), CONTROL_SECRET);
    assert!(!f.lane.control.join("new").exists());
    assert_eq!(read(f.lane.clone.join("file")), "changed\n");
    assert_eq!(read(f.lane.scratch.join("s")), "s\n");
}

#[test]
fn live_a3_every_policy_denies_control() {
    if !sandbox_available() {
        return;
    }
    let f = Fixture::new();
    let cache = f.root.join("cache");
    std::fs::create_dir_all(cache.join(".cargo")).unwrap();
    let policies = [
        (
            "builder",
            SandboxPolicy::builder(&f.lane, NetworkMode::None),
        ),
        ("verifier", SandboxPolicy::verifier(&f.lane, &cache)),
        ("run_check", SandboxPolicy::run_check(&f.lane)),
        (
            "dependency_fetch",
            SandboxPolicy::dependency_fetch(&f.lane, &cache, NetworkMode::None),
        ),
        ("capture", SandboxPolicy::capture(&f.lane)),
    ];
    let c = f.lane.control.display();
    for (name, policy) in &policies {
        let script = format!(
            r#"echo "R:$(cat '{c}/secret' 2>&1)"; echo x > '{c}/secret' 2>/dev/null; echo "W:$?"; echo START"#
        );
        let o = run(policy, &f.lane_root, &script);
        let out = stdout(&o);
        assert!(
            out.contains("START"),
            "{name}: sandbox did not run\n{}",
            describe(&o)
        );
        assert!(!out.contains(CONTROL_SECRET), "{name}\n{}", describe(&o));
        assert!(
            !out.contains("W:0"),
            "{name} wrote control\n{}",
            describe(&o)
        );
        assert_eq!(
            read(f.lane.control.join("secret")),
            CONTROL_SECRET,
            "{name}"
        );
    }
}

// ---------------------------------------------------------------- D18

#[test]
fn live_d18_builder_cannot_write_real_cargo() {
    if !sandbox_available() {
        return;
    }
    let f = Fixture::new();
    let policy = SandboxPolicy::builder(&f.lane, NetworkMode::None);
    let h = f.lane.real_home.display();
    let lh = f.lane.home.display();
    let script = format!(
        r#"
echo x > '{h}/.cargo/bin/evil' 2>/dev/null; echo "W_BIN:$?"
echo x > '{h}/.cargo/bin/tool' 2>/dev/null; echo "OW_BIN:$?"
echo "R_BIN:$(cat '{h}/.cargo/bin/tool' 2>&1)"
echo "R_REG:$(cat '{h}/.cargo/registry/x' 2>&1)"
echo x > '{h}/.cargo/registry/y' 2>/dev/null; echo "W_REG:$?"
echo x > '{h}/.cargo/registry/x' 2>/dev/null; echo "OW_REG:$?"
echo "R_CRED:$(cat '{h}/.cargo/credentials.toml' 2>&1)"
echo x > '{h}/.cargo/credentials.toml' 2>/dev/null; echo "W_CRED:$?"
echo "R_HOME:$(cat '{h}/secret.txt' 2>&1)"
echo x > '{h}/dropped' 2>/dev/null; echo "W_HOME:$?"
echo "R_RUSTUP:$(cat '{h}/.rustup/toolchain' 2>&1)"
echo x > '{h}/.rustup/y' 2>/dev/null; echo "W_RUSTUP:$?"
echo y > '{lh}/.cargo/y'; echo "W_LANE_CARGO:$?"
echo "CARGO_HOME=$CARGO_HOME"
"#
    );
    let o = run(&policy, &f.lane_root, &script);
    let out = stdout(&o);
    let why = describe(&o);
    assert!(o.status.success(), "{why}");
    // allowed
    assert!(out.contains("R_REG:registry-x"), "{why}");
    assert!(out.contains("R_RUSTUP:rustup-x"), "{why}");
    assert!(out.contains("W_LANE_CARGO:0"), "{why}");
    assert!(out.contains(&format!("CARGO_HOME={lh}/.cargo")), "{why}");
    // denied
    // (Linux hides the home as a tmpfs: a write there succeeds but never
    // reaches the host, which the file checks below assert.)
    let mut denied = vec!["W_BIN", "OW_BIN", "W_REG", "OW_REG", "W_CRED", "W_RUSTUP"];
    if cfg!(target_os = "macos") {
        denied.push("W_HOME");
    }
    for m in denied {
        assert!(
            out.contains(&format!("{m}:")) && !out.contains(&format!("{m}:0")),
            "{m} must fail\n{why}"
        );
    }
    for secret in [CRED_SECRET, HOME_SECRET, "tool-original"] {
        assert!(!out.contains(secret), "{secret} was read\n{why}");
    }
    // files agree
    let home = &f.lane.real_home;
    assert!(!home.join(".cargo/bin/evil").exists());
    assert_eq!(read(home.join(".cargo/bin/tool")), "tool-original");
    assert!(!home.join(".cargo/registry/y").exists());
    assert_eq!(read(home.join(".cargo/registry/x")), "registry-x");
    assert_eq!(read(home.join(".cargo/credentials.toml")), CRED_SECRET);
    assert!(!home.join("dropped").exists());
    assert!(!home.join(".rustup/y").exists());
    assert_eq!(read(f.lane.home.join(".cargo/y")), "y\n");
}

#[test]
fn live_d18_verifier_and_capture_get_no_real_cargo() {
    if !sandbox_available() {
        return;
    }
    let f = Fixture::new();
    let cache = f.root.join("cache");
    std::fs::create_dir_all(cache.join(".cargo")).unwrap();
    let h = f.lane.real_home.display();
    for (name, policy) in [
        ("verifier", SandboxPolicy::verifier(&f.lane, &cache)),
        ("capture", SandboxPolicy::capture(&f.lane)),
        (
            "dependency_fetch",
            SandboxPolicy::dependency_fetch(&f.lane, &cache, NetworkMode::None),
        ),
    ] {
        let script = format!(
            r#"echo "R_REG:$(cat '{h}/.cargo/registry/x' 2>&1)"; echo x > '{h}/.cargo/bin/evil' 2>/dev/null; echo "W_BIN:$?"; echo START"#
        );
        let o = run(&policy, &f.lane_root, &script);
        let out = stdout(&o);
        assert!(out.contains("START"), "{name}\n{}", describe(&o));
        assert!(
            !out.contains("registry-x"),
            "{name} read the real registry\n{}",
            describe(&o)
        );
        assert!(!out.contains("W_BIN:0"), "{name}");
        assert!(!f.lane.real_home.join(".cargo/bin/evil").exists(), "{name}");
    }
}

// ---------------------------------------------------------------- network

/// Succeeds (exit 0) when a TCP connection to 127.0.0.1:`port` opens.
fn connect_script(port: u16) -> String {
    format!("exec /bin/bash -c 'exec 3<>/dev/tcp/127.0.0.1/{port}'")
}

#[test]
fn live_network_none_blocks_tcp() {
    if !sandbox_available() {
        return;
    }
    let f = Fixture::new();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    // control: the same connect works when the network is unrestricted
    let open = SandboxPolicy::builder(&f.lane, NetworkMode::Unrestricted);
    let o = run(&open, &f.lane_root, &connect_script(port));
    assert!(
        o.status.success(),
        "unrestricted connect must work\n{}",
        describe(&o)
    );

    let none = SandboxPolicy::builder(&f.lane, NetworkMode::None);
    let o = run(&none, &f.lane_root, &connect_script(port));
    assert!(
        !o.status.success(),
        "NetworkMode::None let a connection through\n{}",
        describe(&o)
    );
    // the sandbox itself started: a file probe still works
    let o = run(&none, &f.lane_root, "echo START");
    assert!(stdout(&o).contains("START"), "{}", describe(&o));

    // every no-network constructor
    let cache = f.root.join("cache");
    std::fs::create_dir_all(cache.join(".cargo")).unwrap();
    for (name, p) in [
        ("verifier", SandboxPolicy::verifier(&f.lane, &cache)),
        ("run_check", SandboxPolicy::run_check(&f.lane)),
        ("capture", SandboxPolicy::capture(&f.lane)),
    ] {
        let o = run(&p, &f.lane_root, &connect_script(port));
        assert!(
            !o.status.success(),
            "{name} reached the network\n{}",
            describe(&o)
        );
    }
}

#[cfg(target_os = "macos")]
#[test]
fn live_macos_proxy_mode_allows_only_the_proxy_port() {
    let f = Fixture::new();
    let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
    let other = TcpListener::bind("127.0.0.1:0").unwrap();
    let (pp, op) = (
        proxy.local_addr().unwrap().port(),
        other.local_addr().unwrap().port(),
    );
    for mode in [
        NetworkMode::Proxy {
            port: pp,
            socket: f.root.join("proxy.sock"),
        },
        NetworkMode::RegistryReadOnly {
            port: pp,
            socket: f.root.join("proxy.sock"),
        },
    ] {
        let policy = SandboxPolicy::builder(&f.lane, mode.clone());
        let o = run(&policy, &f.lane_root, &connect_script(pp));
        assert!(
            o.status.success(),
            "{mode:?}: proxy port must be reachable\n{}",
            describe(&o)
        );
        let o = run(&policy, &f.lane_root, &connect_script(op));
        assert!(
            !o.status.success(),
            "{mode:?}: another port was reachable\n{}",
            describe(&o)
        );
    }
}

// ---------------------------------------------------------------- D22 socket

/// Answers `pong` to a line on every connection and counts the connections.
fn serve_pong(path: &Path) -> std::sync::Arc<AtomicU32> {
    let listener = UnixListener::bind(path).unwrap();
    let accepted = std::sync::Arc::new(AtomicU32::new(0));
    let count = accepted.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            count.fetch_add(1, Ordering::SeqCst);
            let mut line = String::new();
            let _ = BufReader::new(&stream).read_line(&mut line);
            let _ = writeln!(stream, "pong");
        }
    });
    accepted
}

/// Prints `CONNECTED:pong` after a ping round trip with the socket at
/// `path`, or `REFUSED:...` when the connection is not allowed. perl is on
/// every macOS and Linux host and speaks Unix sockets.
fn socket_probe(tag: &str, path: &Path) -> String {
    format!(
        r#"perl -MSocket -e '$p = shift; socket(S, PF_UNIX, SOCK_STREAM, 0) or die; if (connect(S, sockaddr_un($p))) {{ select(S); $| = 1; print S "ping\n"; $l = <S>; select(STDOUT); print "{tag}_CONNECTED:$l" }} else {{ print "{tag}_REFUSED:$!\n" }}' '{}'"#,
        path.display()
    )
}

#[test]
fn live_d22_builder_and_run_check_reach_their_own_runner_socket_only() {
    if !sandbox_available() {
        return;
    }
    let f = Fixture::new();
    let own_hits = serve_pong(&f.lane.sock);
    let other_sock = f.root.join("other/sock/runner.sock");
    let other_hits = serve_pong(&other_sock);

    let script = format!(
        "echo START\n{}\n{}",
        socket_probe("OWN", &f.lane.sock),
        socket_probe("OTHER", &other_sock)
    );
    for (name, policy) in [
        (
            "builder",
            SandboxPolicy::builder(&f.lane, NetworkMode::None),
        ),
        ("run_check", SandboxPolicy::run_check(&f.lane)),
    ] {
        let o = run(&policy, &f.lane_root, &script);
        let out = stdout(&o);
        let why = describe(&o);
        assert!(out.contains("START"), "{name}: sandbox did not run\n{why}");
        assert!(
            out.contains("OWN_CONNECTED:pong"),
            "{name}: its own runner socket must be reachable\n{why}"
        );
        assert!(
            out.contains("OTHER_REFUSED:") && !out.contains("OTHER_CONNECTED"),
            "{name}: another lane's socket was reachable\n{why}"
        );
    }
    assert_eq!(
        own_hits.load(Ordering::SeqCst),
        2,
        "one connection per policy"
    );
    assert_eq!(
        other_hits.load(Ordering::SeqCst),
        0,
        "the other runner saw a connection"
    );
}

#[test]
fn live_d22_verifier_capture_and_dependency_fetch_get_no_socket() {
    if !sandbox_available() {
        return;
    }
    let f = Fixture::new();
    let hits = serve_pong(&f.lane.sock);
    let cache = f.root.join("cache");
    std::fs::create_dir_all(cache.join(".cargo")).unwrap();
    let script = format!("echo START\n{}", socket_probe("OWN", &f.lane.sock));
    for (name, policy) in [
        ("verifier", SandboxPolicy::verifier(&f.lane, &cache)),
        ("capture", SandboxPolicy::capture(&f.lane)),
        (
            "dependency_fetch",
            SandboxPolicy::dependency_fetch(&f.lane, &cache, NetworkMode::None),
        ),
    ] {
        let o = run(&policy, &f.lane_root, &script);
        let out = stdout(&o);
        assert!(out.contains("START"), "{name}\n{}", describe(&o));
        assert!(
            out.contains("OWN_REFUSED:") && !out.contains("OWN_CONNECTED"),
            "{name} reached the runner socket\n{}",
            describe(&o)
        );
    }
    assert_eq!(hits.load(Ordering::SeqCst), 0);
}

#[test]
fn live_d22_socket_grant_opens_neither_control_nor_the_rest_of_the_socket_dir() {
    if !sandbox_available() {
        return;
    }
    let f = Fixture::new();
    serve_pong(&f.lane.sock);
    let c = f.lane.control.display();
    let d = f.lane.sock.parent().unwrap().display();
    let script = format!(
        r#"
{probe}
echo "R_CONTROL:$(cat '{c}/secret' 2>&1)"
echo x > '{c}/new' 2>/dev/null; echo "W_CONTROL:$?"
for e in $(ls '{c}' 2>/dev/null); do echo "LISTED_CONTROL:$e"; done
echo "R_STRAY:$(cat '{d}/stray' 2>&1)"
for e in $(ls '{d}' 2>/dev/null); do echo "LISTED_SOCK:$e"; done
echo x > '{d}/planted' 2>/dev/null; echo "W_SOCK_DIR:$?"
echo END
"#,
        probe = socket_probe("OWN", &f.lane.sock)
    );
    for (name, policy) in [
        (
            "builder",
            SandboxPolicy::builder(&f.lane, NetworkMode::None),
        ),
        ("run_check", SandboxPolicy::run_check(&f.lane)),
    ] {
        let o = run(&policy, &f.lane_root, &script);
        let out = stdout(&o);
        let why = describe(&o);
        // the socket grant works in the same sandbox, so the denials below
        // are not a sandbox that failed to start
        assert!(out.contains("OWN_CONNECTED:pong"), "{name}\n{why}");
        assert!(out.contains("END"), "{name}\n{why}");
        for secret in [CONTROL_SECRET, SOCK_DIR_SECRET] {
            assert!(!out.contains(secret), "{name}: {secret} was read\n{why}");
        }
        assert!(!out.contains("W_CONTROL:0"), "{name}\n{why}");
        assert!(
            !out.contains("LISTED_CONTROL:"),
            "{name}: control was listed\n{why}"
        );
        // The stray file is never listed. macOS denies the whole directory;
        // on Linux only the socket file is bound into a fresh tmpfs, so the
        // runner.sock entry is visible and a write there succeeds but never
        // reaches the host (the file checks below).
        assert!(
            !out.contains("LISTED_SOCK:stray"),
            "{name}: the socket directory exposed a file\n{why}"
        );
        if cfg!(target_os = "macos") {
            assert!(!out.contains("LISTED_SOCK:"), "{name}: listed\n{why}");
            assert!(!out.contains("W_SOCK_DIR:0"), "{name}\n{why}");
        }
        assert!(!f.lane.control.join("new").exists(), "{name}");
        assert!(
            !f.lane.sock.parent().unwrap().join("planted").exists(),
            "{name}"
        );
        assert_eq!(read(f.lane.control.join("secret")), CONTROL_SECRET);
    }
}

// ------------------------------------------------- cross-lane isolation

#[test]
fn live_lanes_root_hide_other_lanes() {
    if !sandbox_available() {
        eprintln!("sandbox not available, skipping");
        return;
    }

    // Create lanes in a directory outside /tmp and the home.
    // On Linux use /var/tmp; on macOS use target dir.
    let mut lanes_root = PathBuf::from("/var/tmp");
    if !lanes_root.exists() {
        lanes_root = PathBuf::from("/tmp");
    }
    let test_lanes = lanes_root.join(format!("cowproof-xlaneisolation-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&test_lanes);
    std::fs::create_dir_all(&test_lanes).unwrap();

    // The real_home must be OUTSIDE lanes_root. Create it in a sibling directory.
    let test_homes = lanes_root.join(format!("cowproof-homes-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&test_homes);
    std::fs::create_dir_all(&test_homes).unwrap();
    let fake_home = test_homes.join("shared_home");
    std::fs::create_dir_all(&fake_home).unwrap();

    // Create lane A
    let lane_a_root = test_lanes.join("lane_a");
    for d in [
        "lane_a/clone",
        "lane_a/home",
        "lane_a/control",
        "lane_a/sock",
    ] {
        std::fs::create_dir_all(test_lanes.join(d)).unwrap();
    }
    let scratch_a = test_lanes.join("scratch_a");
    std::fs::create_dir_all(&scratch_a).unwrap();

    // Create a real Unix socket listener for lane A
    let sock_path_a = lane_a_root.join("sock/runner.sock");
    let sock_dir_a = sock_path_a.parent().unwrap().to_path_buf();
    std::fs::create_dir_all(&sock_dir_a).unwrap();
    let _listener_a =
        std::os::unix::net::UnixListener::bind(&sock_path_a).expect("failed to bind lane A socket");

    // Write secret files before moving paths into LaneLayout
    std::fs::write(lane_a_root.join("clone/myfile"), "lane_a_secret").unwrap();
    std::fs::write(lane_a_root.join("control/control_file"), "lane_a_control").unwrap();

    let lane_a = LaneLayout {
        clone: lane_a_root.join("clone"),
        home: lane_a_root.join("home"),
        scratch: scratch_a.clone(),
        control: lane_a_root.join("control"),
        real_home: fake_home.clone(),
        sock: sock_path_a,
        lanes_root: test_lanes.clone(),
    };

    // Create lane B with secrets
    let lane_b_root = test_lanes.join("lane_b");
    for d in [
        "lane_b/clone",
        "lane_b/home",
        "lane_b/control",
        "lane_b/sock",
    ] {
        std::fs::create_dir_all(test_lanes.join(d)).unwrap();
    }
    let scratch_b = test_lanes.join("scratch_b");
    std::fs::create_dir_all(&scratch_b).unwrap();

    // Create a real Unix socket listener for lane B
    let sock_path_b = lane_b_root.join("sock/runner.sock");
    let sock_dir_b = sock_path_b.parent().unwrap().to_path_buf();
    std::fs::create_dir_all(&sock_dir_b).unwrap();
    let _listener_b =
        std::os::unix::net::UnixListener::bind(&sock_path_b).expect("failed to bind lane B socket");

    // Write secret files before moving paths into LaneLayout
    std::fs::write(lane_b_root.join("clone/secret"), "SECRET_B_CLONE").unwrap();
    std::fs::write(lane_b_root.join("control/secret"), "SECRET_B_CONTROL").unwrap();
    std::fs::write(sock_dir_b.join("secret_file"), "SECRET_B_SOCK").unwrap();

    let lane_b = LaneLayout {
        clone: lane_b_root.join("clone"),
        home: lane_b_root.join("home"),
        scratch: scratch_b.clone(),
        control: lane_b_root.join("control"),
        real_home: fake_home.clone(),
        sock: sock_path_b,
        lanes_root: test_lanes.clone(),
    };

    // Build a sandbox policy for lane A and run probes
    let policy = SandboxPolicy::builder(&lane_a, NetworkMode::None);

    // Build the test command that tries to read lane B's files
    let cmd = vec![
        "/bin/sh".to_string(),
        "-c".to_string(),
        format!(
            "cat {} 2>/dev/null || echo 'DENIED_B_CLONE:' && \
             cat {} 2>/dev/null || echo 'DENIED_B_CONTROL:' && \
             cat {} 2>/dev/null || echo 'DENIED_B_SOCK:' && \
             cat {} 2>/dev/null && echo ':ALLOWED_A_CLONE'",
            lane_b.clone.join("secret").display(),
            lane_b.control.join("secret").display(),
            sock_dir_b.join("secret_file").display(),
            lane_a.clone.join("myfile").display()
        ),
    ];

    let out = if cfg!(target_os = "macos") {
        let profile = render_macos_profile(&policy).unwrap();
        let profile_path = test_lanes.join("policy.sb");
        std::fs::write(&profile_path, profile).unwrap();
        let (exe, args) =
            cowproof_run::sandbox_command(&policy, &profile_path, &cmd, "darwin").unwrap();
        let o = Command::new(exe).args(&args).output().unwrap();
        describe(&o)
    } else {
        let args = cowproof_run::render_bwrap_args(&policy, &cmd).unwrap();
        let o = Command::new("bwrap").args(&args).output().unwrap();
        describe(&o)
    };

    // Lane A should NOT see lane B's files
    assert!(
        out.contains("DENIED_B_CLONE:"),
        "lane_a could read lane_b's clone: {}",
        out
    );
    assert!(
        out.contains("DENIED_B_CONTROL:"),
        "lane_a could read lane_b's control: {}",
        out
    );
    assert!(
        out.contains("DENIED_B_SOCK:"),
        "lane_a could read lane_b's socket file: {}",
        out
    );
    // Lane A SHOULD see its own file
    assert!(
        out.contains("lane_a_secret:ALLOWED_A_CLONE"),
        "lane_a could not read its own clone: {}",
        out
    );

    // Cleanup
    let _ = std::fs::remove_dir_all(&test_lanes);
    let _ = std::fs::remove_dir_all(&test_homes);
}

// ------------------------------------------------- the bug these tests guard

/// Premise check for the canonicalization rule: Seatbelt matches real paths,
/// so a deny written with the symlinked spelling does not apply. If this ever
/// starts failing, Apple changed the matcher and the canonicalization notes in
/// the library need revisiting.
#[cfg(target_os = "macos")]
#[test]
fn live_macos_symlink_spelling_deny_fails_open() {
    let f = Fixture::new();
    assert!(
        f.root.starts_with("/var/"),
        "expected a /var/... tempdir, got {}",
        f.root.display()
    );
    let c = f.lane.control.display();
    let profile = format!("(version 1)\n(allow default)\n(deny file-read* (subpath \"{c}\"))\n");
    let path = f.lane_root.join("naive.sb");
    std::fs::write(&path, profile).unwrap();
    let o = Command::new("sandbox-exec")
        .args([
            "-f",
            path.to_str().unwrap(),
            "/bin/cat",
            &format!("{c}/secret"),
        ])
        .output()
        .unwrap();
    assert!(
        stdout(&o).contains(CONTROL_SECRET),
        "the symlink-spelled deny unexpectedly applied\n{}",
        describe(&o)
    );
}
