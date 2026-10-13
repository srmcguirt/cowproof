//! The dependency fetch's process group and its registry-only network (lane/fetch-hardening),
//! end to end: a real `cowproof run` against a FAKE `claude` and a FAKE `cargo`, with no
//! network beyond `127.0.0.1`.
//!
//! * A signal during the fetch ends the `cargo fetch` group with the run (it used to run on
//!   until it ended or `FETCH_TIMEOUT`).
//! * The default fetch network is `registry`: the fake `cargo` is pointed at the runner's
//!   CONNECT proxy by `CARGO_HTTP_PROXY`, asks for a tunnel to a host, and the proxy
//!   tunnels only to an allowed host on port 443. The allowed host's name is mapped to a
//!   fake upstream on `127.0.0.1` with `COWPROOF_FETCH_RESOLVE`, so no test touches DNS.
//!   A refused host fails the fetch as infrastructure (exit 4), naming the host.
//! * The allowlist is the BASE's: a `fetch_hosts` the patch adds is ignored.
//!
//! The fake `cargo` is a bash script (`/dev/tcp` is its HTTP client). Needs the sandbox like
//! `tests/run.rs` and `tests/deps.rs`. On Linux the fetch sandbox has a network namespace
//! of its own and reaches the proxy through the bound-in socket and the bridge; macOS shares
//! the host's loopback and uses the same socket and bridge.

mod common;

use common::{
    Lane, fork_lock, pid_alive, run_checks, sandbox_available, signal_pid, spawn_to_file, text,
    var_tmp,
};
use cowproof_prove::Capsule;
use serde_json::{Value, json};
use std::fs;
use std::io::Write;
use std::net::{SocketAddr, TcpListener};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// What the fake registry says to whoever the proxy tunnels to it.
const BANNER: &str = "REGISTRY-BANNER";

/// A fake `cargo`: answers `--version`, runs `fetch_body` for `fetch`, and does nothing
/// else.
fn fake_cargo(dir: &Path, fetch_body: &str) -> PathBuf {
    let path = dir.join("cargo");
    let script = format!(
        "#!/bin/bash\ncase \"$1\" in\n  --version) echo 'cargo 0.0.0'; exit 0 ;;\n  fetch) ;;\n  *) exit 0 ;;\nesac\n{fetch_body}\n"
    );
    let _g = fork_lock();
    fs::write(&path, script).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    path
}

/// A fake `cargo fetch` that asks the proxy `CARGO_HTTP_PROXY` names for a tunnel to
/// `host:443` and, if it gets one, records what the registry at the other end says.
fn tunnel_to(host: &str) -> String {
    format!(
        r#"port="${{CARGO_HTTP_PROXY##*:}}"
case "$CARGO_HTTP_PROXY" in http://127.0.0.1:*) ;; *) echo "CARGO_HTTP_PROXY=$CARGO_HTTP_PROXY" >&2; exit 6 ;; esac
[ "$HTTPS_PROXY" = "$CARGO_HTTP_PROXY" ] || {{ echo "HTTPS_PROXY=$HTTPS_PROXY" >&2; exit 6; }}
exec 3<>/dev/tcp/127.0.0.1/$port || exit 7
printf 'CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n' >&3
IFS= read -r status <&3
case "$status" in
  *" 200 "*) ;;
  *) echo "the proxy said: $status" >&2; exit 1 ;;
esac
IFS= read -r blank <&3
IFS= read -r banner <&3
printf '%s\n' "$banner" > "$CARGO_HOME/registry/banner"
"#
    )
}

/// A fake registry on `127.0.0.1` that greets every connection and counts them.
struct Upstream {
    addr: SocketAddr,
    accepted: Arc<AtomicUsize>,
}

fn upstream() -> Upstream {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let addr = listener.local_addr().unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let count = accepted.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            count.fetch_add(1, Ordering::SeqCst);
            let _ = writeln!(stream, "{BANNER}");
        }
    });
    Upstream { addr, accepted }
}

/// A lane whose base holds a `Cargo.lock` (and `extra` files) and whose one check is `true`,
/// fetching into its own cache root with the fake `cargo`.
fn lane(cache: &Path, cargo: &Path, network: &str, extra: &[(&str, &str)], body: &str) -> Lane {
    let mut lane = Lane::new(body, json!([{"id": "ok", "command": "true"}]));
    let mut files = vec![("Cargo.lock", "# lock\nversion = 4\n")];
    files.extend_from_slice(extra);
    lane.commit_files(&files);
    lane.set_env("COWPROOF_CACHE_ROOT", cache);
    lane.set_env("COWPROOF_FETCH_NETWORK", network);
    lane.set_env("CARGO", cargo);
    lane
}

fn capsule(lane: &Lane) -> Capsule {
    Capsule::read(&lane.capsule_dir()).unwrap()
}

fn entries(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .map(|rd| {
            rd.map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names
}

fn run(lane: &Lane, code: i32) -> std::process::Output {
    let out = lane.run(&[]);
    assert_eq!(
        out.status.code(),
        Some(code),
        "cowproof run:\n{}",
        text(&out)
    );
    out
}

// ---- A signal during the fetch -----------------------------------------------------------

/// A `cargo fetch` that never finishes: it backgrounds a heartbeat in its `HOME` (the fetch's
/// private home) and waits. Both loops are bounded, so a fetch the runner failed to end does
/// not outlive the test run by much.
const HOLD: &str = r#"
( for i in $(seq 1 120); do echo . >> "$HOME/beat"; sleep 0.5; done ) &
echo $! > "$HOME/bgpid"
echo $$ > "$HOME/leader"
for i in $(seq 1 60); do sleep 1; done
"#;

/// The `home` of the fetch that is running under `cache`: `deps-work/<pid>-<time>/home`.
fn fetch_home(cache: &Path) -> Option<PathBuf> {
    fs::read_dir(cache.join("deps-work"))
        .ok()?
        .filter_map(Result::ok)
        .map(|e| e.path().join("home"))
        .find(|h| h.join("bgpid").is_file() && h.join("leader").is_file())
}

fn wait_until(what: &str, within: Duration, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + within;
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn beats(home: &Path) -> usize {
    fs::read_to_string(home.join("beat"))
        .unwrap_or_default()
        .lines()
        .count()
}

fn a_signal_during_the_fetch_ends_the_cargo_fetch_group(network: &str, signal: &str) {
    if !sandbox_available() {
        return;
    }
    let cache = var_tmp("cp-fe-cache-");
    let fake = var_tmp("cp-fe-cargo-");
    let cargo = fake_cargo(fake.path(), HOLD);
    let lane = lane(cache.path(), &cargo, network, &[], &run_checks(&["ok"]));
    let stderr = lane.lanes.path().join("run.stderr");
    let mut child = spawn_to_file(&mut lane.run_command(&[]), &stderr);

    let mut home = None;
    wait_until("the fetch to start", Duration::from_secs(180), || {
        home = fetch_home(cache.path());
        home.is_some() || child.try_wait().unwrap().is_some()
    });
    let Some(home) = home else {
        panic!(
            "cowproof ended before the fetch started:\n{}",
            fs::read_to_string(&stderr).unwrap_or_default()
        );
    };
    let bg: u32 = fs::read_to_string(home.join("bgpid"))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let leader: u32 = fs::read_to_string(home.join("leader"))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    wait_until("a heartbeat", Duration::from_secs(30), || beats(&home) > 0);

    signal_pid(signal, child.id());
    let signalled = Instant::now();
    let mut status = None;
    wait_until("cowproof to exit", Duration::from_secs(90), || {
        status = child.try_wait().unwrap();
        status.is_some()
    });
    let took = signalled.elapsed();
    let leftover = |reason: &str| {
        // Do not leave the fake running if the assertion below is the one failing.
        if cfg!(target_os = "macos") {
            signal_pid("KILL", bg);
            signal_pid("KILL", leader);
        }
        panic!(
            "{reason}\n{}",
            fs::read_to_string(&stderr).unwrap_or_default()
        );
    };
    if status.unwrap().code() != Some(130) {
        leftover(&format!("exit {:?}, not 130", status.unwrap()));
    }
    let run_json: Value = serde_json::from_str(
        &fs::read_to_string(lane.lane_dir().join("control/run.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(run_json["status"], "interrupted", "{run_json}");
    assert!(
        !lane.lane_dir().join("control/verdict.json").exists(),
        "a lane signalled in the fetch has a verdict"
    );

    // The fake and its child are gone, within a bound: the heartbeat stops (the one test
    // that works on Linux too, where the sandbox's pids are its own) and, on macOS, where the
    // sandbox shares the host's pid space, neither process exists.
    let seen = beats(&home);
    std::thread::sleep(Duration::from_millis(1800));
    if beats(&home) != seen {
        leftover(&format!(
            "the fetch's heartbeat went on after the run exited ({took:?} after the signal)"
        ));
    }
    if cfg!(target_os = "macos") {
        wait_until(
            "the fake cargo and its child to be gone",
            Duration::from_secs(10),
            || !pid_alive(bg) && !pid_alive(leader),
        );
    }
}

#[test]
fn sigint_during_the_fetch_ends_the_cargo_fetch_group_and_records_interrupted() {
    a_signal_during_the_fetch_ends_the_cargo_fetch_group("registry", "INT");
}

#[test]
fn sigterm_during_the_fetch_ends_the_cargo_fetch_group_and_records_interrupted() {
    a_signal_during_the_fetch_ends_the_cargo_fetch_group("none", "TERM");
}

// ---- The registry-only network -----------------------------------------------------------

#[test]
fn the_default_fetch_reaches_an_allowed_registry_host_through_the_proxy() {
    // `COWPROOF_FETCH_NETWORK` is not set at all: `registry` is the default. The fake exits
    // 6 when it has no `CARGO_HTTP_PROXY`, which is what `open` and `none` would give it.
    if !sandbox_available() {
        return;
    }
    let registry = upstream();
    let cache = var_tmp("cp-fe-cache-");
    let fake = var_tmp("cp-fe-cargo-");
    let cargo = fake_cargo(fake.path(), &tunnel_to("index.crates.io"));
    let mut lane = lane(cache.path(), &cargo, "registry", &[], &run_checks(&["ok"]));
    lane.set_env(
        "COWPROOF_FETCH_RESOLVE",
        format!("index.crates.io={}", registry.addr),
    );
    let mut command = lane.run_command(&[]);
    command.env_remove("COWPROOF_FETCH_NETWORK");
    let out = common::output(&mut command);
    assert_eq!(out.status.code(), Some(0), "cowproof run:\n{}", text(&out));
    // The testing hook is loud and recorded: one warning line, and the capsule says so.
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    let warnings: Vec<&str> = stderr
        .lines()
        .filter(|l| l.contains("COWPROOF_FETCH_RESOLVE is set"))
        .collect();
    assert_eq!(warnings.len(), 1, "{}", text(&out));
    assert!(
        warnings[0].contains(&format!("index.crates.io={}", registry.addr))
            && warnings[0].contains("(testing only)"),
        "{}",
        warnings[0]
    );
    assert_eq!(lane.verdict()["verdict"], "proved", "{}", text(&out));
    let c = capsule(&lane);
    assert_eq!(c.dependency_fetch_outcome.as_deref(), Some("fetched"));
    assert_eq!(
        c.dependency_fetch_resolve.as_deref(),
        Some(format!("index.crates.io={}", registry.addr).as_str()),
        "the capsule records that the hook was set"
    );
    let json = fs::read_to_string(lane.capsule_dir().join("capsule.json")).unwrap();
    assert!(json.contains("\"dependency_fetch_resolve\""), "{json}");
    let key = c.dependency_cache_key.unwrap();
    assert_eq!(
        fs::read_to_string(
            cache
                .path()
                .join("deps")
                .join(&key)
                .join("cargo/registry/banner")
        )
        .unwrap(),
        format!("{BANNER}\n"),
        "the fetch's bytes came through the tunnel"
    );
    assert_eq!(registry.accepted.load(Ordering::SeqCst), 1);
    assert!(entries(&cache.path().join("deps-work")).is_empty());
}

#[test]
fn a_host_the_base_does_not_allow_fails_the_fetch_as_infrastructure_naming_the_host() {
    if !sandbox_available() {
        return;
    }
    let registry = upstream();
    let cache = var_tmp("cp-fe-cache-");
    let fake = var_tmp("cp-fe-cargo-");
    let cargo = fake_cargo(fake.path(), &tunnel_to("evil.example"));
    let mut lane = lane(cache.path(), &cargo, "registry", &[], &run_checks(&["ok"]));
    // The name even resolves to a live fake: it is the allowlist, not the network, that
    // stops it.
    lane.set_env(
        "COWPROOF_FETCH_RESOLVE",
        format!("evil.example={}", registry.addr),
    );
    let out = run(&lane, 4);
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(
        stdout.contains(&format!("{}: infrastructure: ", lane.id))
            && stdout.contains("dependency fetch failed: ")
            && stdout.contains("cargo fetch --locked failed")
            && stdout.contains("refused a connection to evil.example:443"),
        "{}",
        text(&out)
    );
    let verdict = lane.verdict();
    assert_eq!(verdict["verdict"], "infrastructure", "{verdict}");
    assert_eq!(verdict["failedChecks"], json!([]));
    assert_eq!(
        registry.accepted.load(Ordering::SeqCst),
        0,
        "the upstream was contacted"
    );
    let c = capsule(&lane);
    assert_eq!(c.dependency_fetch_outcome.as_deref(), Some("failed"));
    assert!(entries(&cache.path().join("deps")).is_empty());
}

#[test]
fn a_host_the_base_cowproof_toml_allows_is_reached() {
    if !sandbox_available() {
        return;
    }
    let registry = upstream();
    let cache = var_tmp("cp-fe-cache-");
    let fake = var_tmp("cp-fe-cargo-");
    let cargo = fake_cargo(fake.path(), &tunnel_to("git.example"));
    let mut lane = lane(
        cache.path(),
        &cargo,
        "registry",
        &[(
            "cowproof.toml",
            "[proof]\nfetch_hosts = [\"git.example\"]\n",
        )],
        &run_checks(&["ok"]),
    );
    lane.set_env(
        "COWPROOF_FETCH_RESOLVE",
        format!("git.example={}", registry.addr),
    );
    let out = run(&lane, 0);
    assert_eq!(lane.verdict()["verdict"], "proved", "{}", text(&out));
    assert_eq!(registry.accepted.load(Ordering::SeqCst), 1);
}

#[test]
fn a_fetch_hosts_the_patch_adds_is_ignored_by_the_allowlist() {
    if !sandbox_available() {
        return;
    }
    let registry = upstream();
    let cache = var_tmp("cp-fe-cache-");
    let fake = var_tmp("cp-fe-cargo-");
    let cargo = fake_cargo(fake.path(), &tunnel_to("evil.example"));
    // The builder writes the host into cowproof.toml. The base has no such file.
    let body = format!(
        "printf '[proof]\\nfetch_hosts = [\"evil.example\"]\\n' > cowproof.toml\n{}",
        run_checks(&["ok"])
    );
    let mut lane = lane(cache.path(), &cargo, "registry", &[], &body);
    lane.set_env(
        "COWPROOF_FETCH_RESOLVE",
        format!("evil.example={}", registry.addr),
    );
    let out = run(&lane, 4);
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(
        stdout.contains("refused a connection to evil.example:443"),
        "{}",
        text(&out)
    );
    assert_eq!(
        registry.accepted.load(Ordering::SeqCst),
        0,
        "the patch's host was reached"
    );
    assert_eq!(lane.verdict()["verdict"], "infrastructure");
}

#[test]
fn a_resolve_hook_target_that_is_not_loopback_fails_the_fetch_naming_the_variable() {
    if !sandbox_available() {
        return;
    }
    let cache = var_tmp("cp-fe-cache-");
    let fake = var_tmp("cp-fe-cargo-");
    let cargo = fake_cargo(fake.path(), &tunnel_to("index.crates.io"));
    for bad in [
        "index.crates.io=10.0.0.1:443",
        "index.crates.io=93.184.216.34:443",
        "index.crates.io=localhost:443",
    ] {
        let mut lane = lane(cache.path(), &cargo, "registry", &[], &run_checks(&["ok"]));
        lane.set_env("COWPROOF_FETCH_RESOLVE", bad);
        let out = run(&lane, 4);
        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        assert!(
            stdout.contains("infrastructure")
                && stdout.contains("COWPROOF_FETCH_RESOLVE")
                && stdout.contains("loopback"),
            "{bad}: {}",
            text(&out)
        );
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        assert!(
            !stderr.contains("COWPROOF_FETCH_RESOLVE is set"),
            "an invalid value must not read as accepted: {}",
            text(&out)
        );
        assert!(entries(&cache.path().join("deps")).is_empty(), "{bad}");
    }
}
