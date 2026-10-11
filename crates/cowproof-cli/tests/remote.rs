//! `cowproof run --host <alias>` end to end (D24, D27): the real `cowproof` binary on both
//! sides, a FAKE `claude`, and a FAKE `ssh` first on `PATH` (`tests/common/fake_ssh.py`) that
//! runs the "remote" commands on this machine in a fresh environment with a home of its own.
//! The real `ssh` is never started: the fake is on `PATH` ahead of it, and every test sets that.
//!
//! Needs the sandbox like `tests/run.rs` (skipped without it, a failure under
//! `COWPROOF_REQUIRE_SANDBOX=1`) and `python3`, which the fake ssh is written in.

mod common;

use common::{
    Lane, REAL_KEY, fork_lock, output, run_checks, sandbox_available, spawn_to_file, text, var_tmp,
};
use cowproof_prove::Capsule;
use serde_json::{Value, json};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};
use tempfile::TempDir;

const FAKE_SSH: &str = include_str!("common/fake_ssh.py");

/// The whole of a quick remote run, deadlocks included.
const RUN_WITHIN: Duration = Duration::from_secs(120);

fn checks() -> Value {
    json!([
        {"id": "edit", "command": "grep -q edited README.md"},
        {"id": "made", "command": "test -f created.txt"},
    ])
}

/// A lane whose builder runs on the fake host.
struct Remote {
    lane: Lane,
    /// Holds the fake `ssh`.
    _bin: TempDir,
    /// The remote user's home, and the fake ssh's log and stdin records.
    _home: TempDir,
    ssh_dir: TempDir,
    /// The remote lanes root (`remoteRoot` in the hosts config).
    root: TempDir,
    _config: TempDir,
}

impl Remote {
    fn new(fake_body: &str, checks: Value) -> Self {
        Self::with_host(fake_body, checks, |_, _| {})
    }

    /// `edit` can change the host entry (the `claude` path, say) before it is written.
    fn with_host(fake_body: &str, checks: Value, edit: impl FnOnce(&Lane, &mut Value)) -> Self {
        let mut lane = Lane::new(fake_body, checks);
        let bin = var_tmp("cp-remote-bin-");
        let home = var_tmp("cp-remote-home-");
        let ssh_dir = var_tmp("cp-remote-ssh-");
        let root = var_tmp("cp-remote-root-");
        let config = var_tmp("cp-remote-config-");
        {
            let _g = fork_lock();
            let ssh = bin.path().join("ssh");
            fs::write(&ssh, FAKE_SSH).unwrap();
            fs::set_permissions(&ssh, fs::Permissions::from_mode(0o755)).unwrap();
        }
        let mut entry = json!({
            "ssh": "fake-host",
            "cowproof": lane.cowproof,
            "claude": lane.fake_claude(),
            "remoteRoot": root.path(),
        });
        edit(&lane, &mut entry);
        let hosts = config.path().join("hosts.json");
        fs::write(&hosts, json!({"fake": entry}).to_string()).unwrap();

        let mut path = bin.path().as_os_str().to_owned();
        path.push(":");
        path.push(std::env::var_os("PATH").unwrap_or_default());
        lane.set_env("PATH", path);
        lane.set_env("COWPROOF_HOSTS_FILE", hosts);
        lane.set_env("FAKE_SSH_LOG", ssh_dir.path().join("log.jsonl"));
        lane.set_env("FAKE_SSH_DIR", ssh_dir.path());
        lane.set_env("FAKE_REMOTE_HOME", home.path());
        lane.set_env("FAKE_REMOTE_ROOT", root.path());
        lane.set_env("FAKE_SSH_FORBIDDEN", REAL_KEY);
        Remote {
            lane,
            _bin: bin,
            _home: home,
            ssh_dir,
            root,
            _config: config,
        }
    }

    /// `cowproof run --host fake` plus `extra` flags, not yet started.
    fn command(&self, extra: &[&str]) -> Command {
        let mut args: Vec<&Path> = vec![Path::new("--host"), Path::new("fake")];
        args.extend(extra.iter().map(Path::new));
        self.lane.run_command(&args)
    }

    fn remote_lane(&self) -> PathBuf {
        self.root.path().join(&self.lane.id)
    }

    fn log(&self) -> Vec<Value> {
        let path = self.ssh_dir.path().join("log.jsonl");
        fs::read_to_string(&path)
            .map(|t| {
                t.lines()
                    .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("{l}: {e}")))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The argv of every ssh invocation that was logged, in order.
    fn argvs(&self) -> Vec<Vec<String>> {
        self.log()
            .iter()
            .filter_map(|e| e["argv"].as_array())
            .map(|a| a.iter().map(|w| w.as_str().unwrap().to_string()).collect())
            .collect()
    }

    /// The steps of the run, by name, repeats collapsed: `master`, `forward`, `exit` and the
    /// `host-agent` verbs.
    fn steps(&self) -> Vec<String> {
        let mut steps: Vec<String> = self.argvs().iter().filter_map(|a| step_name(a)).collect();
        steps.dedup();
        steps
    }

    fn master_pid(&self) -> i64 {
        self.log()
            .iter()
            .find(|e| e["event"] == "master-started")
            .and_then(|e| e["pid"].as_i64())
            .expect("the master never started")
    }

    fn run_json(&self) -> Value {
        let p = self.lane.lane_dir().join("control/run.json");
        serde_json::from_str(
            &fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display())),
        )
        .unwrap()
    }

    /// The master is stopped, its control path is gone, and the host holds no lane of ours.
    fn assert_torn_down(&self) {
        assert!(
            self.log().iter().any(|e| e["event"] == "master-stopped"),
            "the master never stopped: {:?}",
            self.log()
        );
        assert_pid_gone(self.master_pid());
        assert!(
            !self.lane.lane_dir().join("control/ssh.ctl").exists(),
            "the control path is still there"
        );
        assert!(
            fs::symlink_metadata(self.remote_lane()).is_err(),
            "{} is still on the host",
            self.remote_lane().display()
        );
    }
}

fn step_name(argv: &[String]) -> Option<String> {
    if argv.iter().any(|a| a == "-M") {
        return Some("master".into());
    }
    if let Some(i) = argv.iter().position(|a| a == "-O") {
        return argv.get(i + 1).cloned();
    }
    let command = argv.last()?;
    let verb = command.split(" host-agent ").nth(1)?;
    verb.split(' ').next().map(String::from)
}

/// Poll `kill -0 <pid>` until the process is gone, at most 10 s.
fn assert_pid_gone(pid: i64) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let alive = output(Command::new("kill").args(["-0", &pid.to_string()]))
            .status
            .success();
        if !alive {
            return;
        }
        assert!(Instant::now() < deadline, "process {pid} is still alive");
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Run `cmd` to its end within `RUN_WITHIN`; a run that outlives it is killed by pid.
fn finish(mut cmd: Command) -> std::process::Output {
    let mut child = {
        let _g = fork_lock();
        cmd.stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap()
    };
    let deadline = Instant::now() + RUN_WITHIN;
    while child.try_wait().unwrap().is_none() {
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("cowproof run was still going after {RUN_WITHIN:?}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    child.wait_with_output().unwrap()
}

/// A builder that records its environment, then runs both checks.
fn proving_builder() -> String {
    format!("env > \"$rec/env.txt\"\n{}", run_checks(&["edit", "made"]))
}

/// A run that proves, with everything the assertions below read.
fn proved_run() -> (Remote, std::process::Output) {
    let remote = Remote::new(&proving_builder(), checks());
    let out = finish(remote.command(&[]));
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    (remote, out)
}

// ---------------------------------------------------------------------------

#[test]
fn a_remote_lane_is_proved_from_the_patch_the_host_returned() {
    if !sandbox_available() {
        return;
    }
    let (remote, out) = proved_run();
    assert_eq!(remote.lane.verdict()["verdict"], "proved", "{}", text(&out));

    // The builder worked on the host: its edits are in the patch that came back, and the
    // director's own clone of the lane is untouched.
    let lane_dir = remote.lane.lane_dir();
    let patch = fs::read_to_string(lane_dir.join("control/lane.patch")).unwrap();
    assert!(patch.contains("+edited"), "{patch}");
    assert!(patch.contains("created.txt"), "{patch}");
    assert!(
        !lane_dir.join("clone/created.txt").exists(),
        "the builder ran in the director's clone"
    );
    // The proof ran here, on the rebuilt tree, and sealed a capsule that says where the work was.
    let capsule = Capsule::read(&remote.lane.capsule_dir()).unwrap();
    assert_eq!(capsule.host.as_deref(), Some("fake"));
    let raw: Value =
        serde_json::from_slice(&fs::read(remote.lane.capsule_dir().join("capsule.json")).unwrap())
            .unwrap();
    assert_eq!(raw["host"], "fake");
    assert_eq!(remote.run_json()["host"], "fake");
    assert_eq!(remote.run_json()["status"], "finished");
    assert_eq!(remote.run_json()["trace"]["traced"], false);
    // The capsule is the same whole as a local one: its checks replay here.
    assert_eq!(capsule.lane_state, "proved");
    remote.assert_torn_down();
}

#[test]
fn the_ssh_log_has_every_step_in_order_and_each_one_goes_through_the_master() {
    if !sandbox_available() {
        return;
    }
    let (remote, _out) = proved_run();
    assert_eq!(
        remote.steps(),
        [
            "master", "doctor", "prepare", "forward", "builder", "check", "patch", "cleanup",
            "exit"
        ],
        "{:?}",
        remote.argvs()
    );
    let argvs = remote.argvs();
    let count = |name: &str| {
        argvs
            .iter()
            .filter(|a| step_name(a).as_deref() == Some(name))
            .count()
    };
    assert_eq!(count("forward"), 2, "proxy.sock and runner.sock");
    assert_eq!(count("check"), 2, "both declared checks ran on the host");
    assert_eq!(count("builder"), 1);

    // Both forwards come after prepare and before the builder.
    let at = |name: &str| {
        argvs
            .iter()
            .position(|a| step_name(a).as_deref() == Some(name))
            .unwrap()
    };
    let last_forward = argvs
        .iter()
        .rposition(|a| step_name(a).as_deref() == Some("forward"))
        .unwrap();
    assert!(
        at("prepare") < at("forward"),
        "forwards before prepare: {argvs:?}"
    );
    assert!(last_forward < at("builder"), "{argvs:?}");

    let ctl = remote.lane.lane_dir().join("control/ssh.ctl");
    let ctl = ctl.to_str().unwrap();
    let master = &argvs[at("master")];
    for expected in [
        "-M",
        "-N",
        "ControlPersist=no",
        "StreamLocalBindUnlink=yes",
        "ExitOnForwardFailure=yes",
    ] {
        assert!(
            master.iter().any(|a| a == expected),
            "{expected} missing: {master:?}"
        );
    }
    assert!(
        master.windows(2).any(|w| w[0] == "-S" && w[1] == ctl),
        "{master:?}"
    );
    // Everything else is `ssh -S <that control path> ...`: one connection per lane.
    for argv in argvs.iter().filter(|a| !a.iter().any(|w| w == "-M")) {
        assert!(
            argv.windows(2).any(|w| w[0] == "-S" && w[1] == ctl),
            "{argv:?}"
        );
    }
    // Remote commands start with the configured cowproof and name the configured root.
    let prepare = argvs[at("prepare")].last().unwrap();
    assert!(
        prepare.starts_with(remote.lane.cowproof.to_str().unwrap()),
        "{prepare}"
    );
    assert!(prepare.contains(" --lane-id "), "{prepare}");
    assert!(
        prepare.contains(&format!("--director-version {}", env!("CARGO_PKG_VERSION"))),
        "{prepare}"
    );
    assert!(
        prepare.contains(remote.root.path().to_str().unwrap()),
        "{prepare}"
    );
    // The forwards: the host's sockets to the lane's own.
    let forwards: Vec<&Vec<String>> = argvs
        .iter()
        .filter(|a| step_name(a).as_deref() == Some("forward"))
        .collect();
    let spec = |argv: &Vec<String>| {
        let i = argv.iter().position(|a| a == "-R").unwrap();
        argv[i + 1].clone()
    };
    let lane_dir = remote.lane.lane_dir();
    let expected_local = [
        lane_dir.join("proxy.sock").display().to_string(),
        lane_dir.join("sock/runner.sock").display().to_string(),
    ];
    let specs: Vec<String> = forwards.iter().map(|a| spec(a)).collect();
    for (spec, local) in specs.iter().zip(&expected_local) {
        let (host_side, local_side) = spec.split_once(':').unwrap();
        assert_eq!(local_side, local, "{spec}");
        assert!(
            host_side.starts_with('/') && host_side.contains(&remote.lane.id),
            "{spec}"
        );
    }
    assert!(
        specs[0].contains("/proxy.sock:") && specs[1].contains("/sock/runner.sock:"),
        "{specs:?}"
    );
}

#[test]
fn the_forwards_come_after_prepare() {
    if !sandbox_available() {
        return;
    }
    let (remote, _out) = proved_run();
    let steps = remote.steps();
    let at = |name: &str| steps.iter().position(|s| s == name).unwrap();
    assert!(at("doctor") < at("prepare"), "{steps:?}");
    assert!(at("prepare") < at("forward"), "{steps:?}");
    assert!(at("forward") < at("builder"), "{steps:?}");
}

#[test]
fn the_real_key_is_in_no_argv_no_spec_and_no_file_on_the_host() {
    if !sandbox_available() {
        return;
    }
    let remote = Remote::new(&proving_builder(), checks());
    let out = finish(remote.command(&[]));
    // The director held the key the whole time: the proxy needed it.
    for argv in remote.argvs() {
        for word in &argv {
            assert!(!word.contains(REAL_KEY), "the key is in an argv: {argv:?}");
        }
    }
    let stdins: Vec<PathBuf> = fs::read_dir(remote.ssh_dir.path())
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("stdin.")
        })
        .collect();
    for file in &stdins {
        let bytes = fs::read(file).unwrap();
        assert!(
            !bytes
                .windows(REAL_KEY.len())
                .any(|w| w == REAL_KEY.as_bytes()),
            "the key is in {}",
            file.display()
        );
    }
    // No file on the host: the fake ssh read every file under the host's lanes root and home
    // just before the lane was removed (clone, home, sessions, specs, the bundle's checkout).
    let scanned: usize = fs::read_to_string(remote.ssh_dir.path().join("scanned.txt"))
        .expect("the fake ssh never scanned the host")
        .parse()
        .unwrap();
    assert!(scanned > 10, "the scan read only {scanned} files");
    let leaks = fs::read_to_string(remote.ssh_dir.path().join("leaks.txt")).unwrap();
    assert_eq!(leaks, "", "the real key is on the host");
    // The builder spec is there, and holds the lane's placeholder instead.
    let spec_file = stdins
        .iter()
        .find(|f| fs::read_to_string(f).is_ok_and(|t| t.contains("\"placeholder_key\"")))
        .expect("no builder spec was sent");
    let spec: Value = serde_json::from_slice(&fs::read(spec_file).unwrap()).unwrap();
    assert!(
        spec["placeholder_key"]
            .as_str()
            .unwrap()
            .starts_with("placeholder-"),
        "{spec}"
    );
    // And the run was a real one, not a lane that failed before it sent anything: doctor,
    // prepare (the bundle), the builder spec, two checks, patch and cleanup all read stdin.
    assert!(stdins.len() >= 7, "{stdins:?}");
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
}

#[test]
fn the_builder_on_the_host_sees_the_placeholder_and_never_the_key() {
    if !sandbox_available() {
        return;
    }
    // The fake builder writes its environment into the clone, so it comes back in the patch
    // (the ownership gate refuses the stray file; the patch is kept all the same). That is the
    // one way out of the host the director can read after the lane is removed.
    let remote = Remote::new("env > env.txt\n", checks());
    let out = finish(remote.command(&[]));
    assert!(
        matches!(out.status.code(), Some(2 | 3)),
        "an unowned file and no checks run is not a proof: {}",
        text(&out)
    );
    let patch = fs::read_to_string(remote.lane.lane_dir().join("control/lane.patch")).unwrap();
    assert!(patch.contains("+ANTHROPIC_API_KEY=placeholder-"), "{patch}");
    assert!(
        patch.contains("+HOME="),
        "the environment was not recorded: {patch}"
    );
    assert!(!patch.contains(REAL_KEY), "{patch}");
    // The fake ssh gave the host a fresh environment, not the director's.
    assert!(!patch.contains("+FAKE_SSH_LOG="), "{patch}");
    remote.assert_torn_down();
}

#[test]
fn a_failing_remote_doctor_is_infrastructure_and_nothing_is_prepared() {
    if !sandbox_available() {
        return;
    }
    let remote = Remote::with_host(&proving_builder(), checks(), |_, entry| {
        entry["claude"] = json!("/nonexistent/claude");
    });
    let out = finish(remote.command(&[]));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(4), "{}", text(&out));
    assert!(stderr.contains("remote doctor"), "{stderr}");
    assert!(stderr.contains("nothing was started"), "{stderr}");
    assert_eq!(
        remote.steps(),
        ["master", "doctor", "exit"],
        "{:?}",
        remote.argvs()
    );
    assert!(
        !remote.remote_lane().exists(),
        "a lane was prepared on the host"
    );
    assert!(
        fs::read_dir(remote.root.path()).unwrap().next().is_none(),
        "the host's lanes root is not empty"
    );
    let run = remote.run_json();
    assert_eq!(run["status"], "infrastructure");
    assert_eq!(run["host"], "fake");
    assert!(!remote.lane.lane_dir().join("control/verdict.json").exists());
    assert!(remote.log().iter().any(|e| e["event"] == "master-stopped"));
    assert_pid_gone(remote.master_pid());
}

/// A fake builder that reports a session, records its pids and then waits: a leader, and a
/// background child that ignores SIGTERM.
fn waiting_builder() -> String {
    "printf '%s\\n' '{\"type\":\"system\",\"subtype\":\"init\",\"session_id\":\"0a1b2c3d-1111-2222-3333-444455556666\"}'\n\
     echo $$ > \"$HOME/builderpid\"\n\
     ( trap '' TERM; sleep 300 ) &\n\
     echo $! > \"$HOME/bgpid\"\n\
     sleep 120\n"
        .to_string()
}

fn wait_for(path: &Path, child: &mut Child) {
    let deadline = Instant::now() + Duration::from_secs(60);
    while !fs::read_to_string(path).is_ok_and(|t| !t.trim().is_empty()) {
        assert!(
            child.try_wait().unwrap().is_none(),
            "the run ended before {}",
            path.display()
        );
        assert!(
            Instant::now() < deadline,
            "{} never appeared",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn pid_in(path: &Path) -> i64 {
    fs::read_to_string(path).unwrap().trim().parse().unwrap()
}

#[test]
fn sigint_during_the_remote_builder_ends_it_and_its_group_and_stops_the_master() {
    if !sandbox_available() {
        return;
    }
    let remote = Remote::new(&waiting_builder(), checks());
    let stderr = remote.ssh_dir.path().join("director.stderr");
    let mut run = spawn_to_file(&mut remote.command(&[]), &stderr);
    let home = remote.remote_lane().join("home");
    wait_for(&home.join("bgpid"), &mut run);
    let (builder, background) = (
        pid_in(&home.join("builderpid")),
        pid_in(&home.join("bgpid")),
    );
    let host_agent = remote
        .log()
        .iter()
        .rev()
        .find(|e| e["event"] == "command-started")
        .and_then(|e| e["pid"].as_i64())
        .expect("no command started");

    let out = output(Command::new("kill").args(["-INT", &run.id().to_string()]));
    assert!(out.status.success(), "{}", text(&out));
    let deadline = Instant::now() + Duration::from_secs(60);
    let status = loop {
        if let Some(status) = run.try_wait().unwrap() {
            break status;
        }
        if Instant::now() > deadline {
            let _ = run.kill();
            let _ = run.wait();
            panic!(
                "the run outlived SIGINT:\n{}",
                fs::read_to_string(&stderr).unwrap()
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let log = fs::read_to_string(&stderr).unwrap();
    assert_eq!(status.code(), Some(130), "{log}");
    let run_json = remote.run_json();
    assert_eq!(run_json["status"], "interrupted");
    assert_eq!(run_json["host"], "fake");
    assert!(!remote.lane.lane_dir().join("control/verdict.json").exists());
    assert!(!remote.lane.lane_dir().join("control/capsule").exists());

    // `host-agent builder` got the hangup, ended the builder's whole group, and the lane and
    // the master went with it. (The sandbox shares the host's pid space on macOS only.)
    assert_pid_gone(host_agent);
    if cfg!(target_os = "macos") {
        assert_pid_gone(builder);
        assert_pid_gone(background);
    }
    remote.assert_torn_down();
    assert_eq!(
        remote.steps().last().map(String::as_str),
        Some("exit"),
        "{:?}",
        remote.steps()
    );
}

#[test]
fn a_hard_timeout_on_a_remote_lane_ends_it_like_a_local_one() {
    if !sandbox_available() {
        return;
    }
    let remote = Remote::new(&waiting_builder(), checks());
    let began = Instant::now();
    let out = finish(remote.command(&["--timeout-secs", "8"]));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(5), "{}", text(&out));
    assert!(stderr.contains("wall-clock timeout"), "{stderr}");
    assert!(
        began.elapsed() < Duration::from_secs(100),
        "the 120 s sleep was cut short"
    );
    let run = remote.run_json();
    assert_eq!(run["status"], "timeout");
    assert_eq!(run["host"], "fake");
    assert_eq!(run["segments"].as_array().unwrap().len(), 1);
    assert_eq!(run["segments"][0]["sessionEnd"], "timeout");
    assert!(!remote.lane.lane_dir().join("control/verdict.json").exists());
    assert!(!remote.lane.lane_dir().join("control/capsule").exists());
    // The patch came back before the lane was removed.
    assert!(remote.lane.lane_dir().join("control/lane.patch").exists());
    remote.assert_torn_down();
}

#[test]
fn a_refuted_remote_run_still_removes_the_host_lane_and_stops_the_master() {
    if !sandbox_available() {
        return;
    }
    let failing = json!([{"id": "edit", "command": "grep -q nothere README.md"}]);
    let remote = Remote::new(&run_checks(&["edit"]), failing);
    let out = finish(remote.command(&[]));
    assert_eq!(out.status.code(), Some(2), "{}", text(&out));
    assert_eq!(remote.lane.verdict()["verdict"], "refuted");
    assert_eq!(remote.run_json()["host"], "fake");
    assert!(remote.lane.lane_dir().join("control/lane.patch").exists());
    remote.assert_torn_down();
    assert_eq!(
        remote.steps().last().map(String::as_str),
        Some("exit"),
        "{:?}",
        remote.steps()
    );
    let steps = remote.steps();
    let at = |name: &str| steps.iter().position(|s| s == name).unwrap();
    assert!(
        at("patch") < at("cleanup") && at("cleanup") < at("exit"),
        "{steps:?}"
    );
}

#[test]
fn run_check_runs_in_the_hosts_clone_not_the_directors() {
    if !sandbox_available() {
        return;
    }
    // `created.txt` exists only where the builder worked. A check that passes proves it ran
    // there; the director's own clone of the lane has no such file.
    let only_here = json!([{"id": "made", "command": "test -f created.txt"}]);
    let remote = Remote::new(&run_checks(&["made"]), only_here);
    let out = finish(remote.command(&[]));
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert!(!remote.lane.lane_dir().join("clone/created.txt").exists());
    assert_eq!(remote.lane.verdict()["verdict"], "proved");
}

// ---------------------------------------------------------------------------
// The host entry and the hosts config
// ---------------------------------------------------------------------------

#[test]
fn an_unknown_alias_stops_the_run_before_any_lane_exists() {
    let remote = Remote::new("true\n", checks());
    let out = finish(
        remote
            .lane
            .run_command(&[Path::new("--host"), Path::new("nope")]),
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert!(
        stderr.contains("\"nope\" is not in the hosts config"),
        "{stderr}"
    );
    assert!(!remote.lane.lane_dir().exists());
    assert!(remote.log().is_empty(), "ssh was started");
}

#[test]
fn a_host_entry_without_cowproof_or_claude_says_what_to_add() {
    let remote = Remote::with_host("true\n", checks(), |_, entry| {
        entry.as_object_mut().unwrap().remove("cowproof");
    });
    let out = finish(remote.command(&[]));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert!(stderr.contains("has no cowproof"), "{stderr}");
    assert!(remote.log().is_empty(), "ssh was started");
}

#[test]
fn allow_dirty_and_unsandboxed_are_refused_with_host() {
    let remote = Remote::new("true\n", checks());
    for flag in ["--allow-dirty", "--unsandboxed"] {
        let out = finish(remote.command(&[flag]));
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(1), "{}", text(&out));
        assert!(
            stderr.contains(&format!("{flag} cannot be combined with --host")),
            "{stderr}"
        );
    }
    assert!(remote.log().is_empty(), "ssh was started");
}

#[test]
fn the_hosts_file_comes_from_the_environment_then_the_user_config() {
    // Each run stops at the alias lookup, and the error names the file it read.
    let lane = Lane::new("true\n", checks());
    let first = var_tmp("cp-hosts-a-");
    let second = var_tmp("cp-hosts-b-");
    for dir in [&first, &second] {
        fs::write(dir.path().join("hosts.json"), "{}").unwrap();
    }
    let user = lane.home.path().join(".config/cowproof");
    fs::create_dir_all(&user).unwrap();
    fs::write(user.join("hosts.json"), "{}").unwrap();

    let read = |envs: &[(&str, &Path)]| -> String {
        let mut cmd = lane.run_command(&[Path::new("--host"), Path::new("x")]);
        cmd.env_remove("COWPROOF_HOSTS_FILE")
            .env_remove("LANES_HOSTS_FILE");
        for (k, v) in envs {
            cmd.env(k, v);
        }
        let out = output(&mut cmd);
        assert_eq!(out.status.code(), Some(1), "{}", text(&out));
        String::from_utf8_lossy(&out.stderr).into_owned()
    };
    let a = first.path().join("hosts.json");
    let b = second.path().join("hosts.json");
    let both = read(&[("COWPROOF_HOSTS_FILE", &a), ("LANES_HOSTS_FILE", &b)]);
    assert!(both.contains(a.to_str().unwrap()), "{both}");
    let old_name = read(&[("LANES_HOSTS_FILE", &b)]);
    assert!(old_name.contains(b.to_str().unwrap()), "{old_name}");
    let user_file = read(&[]);
    assert!(
        user_file.contains(user.join("hosts.json").to_str().unwrap()),
        "{user_file}"
    );
}
