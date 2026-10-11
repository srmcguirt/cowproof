//! `cowproof run --host <alias>` end to end (D24, D27): the real `cowproof` binary on both
//! sides, a FAKE `claude`, and a FAKE `ssh` first on `PATH` (`tests/common/fake_ssh.py`) that
//! runs the "remote" commands on this machine in a fresh environment with a home of its own.
//! The real `ssh` is never started: the fake is on `PATH` ahead of it, and every test sets that.
//!
//! Needs the sandbox like `tests/run.rs` (skipped without it, a failure under
//! `COWPROOF_REQUIRE_SANDBOX=1`) and `python3`, which the fake ssh is written in.

mod common;

use common::{
    Lane, REAL_KEY, fork_lock, group_gone, output, run_checks, sandbox_available, signal_pid,
    spawn_to_file, text, unique_lane_id, var_tmp,
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

    /// `cowproof run --host fake` for a SECOND lane of the same repository, lanes root and
    /// host: the first lane's packet with `id` in place of its id.
    fn second_command(&self, id: &str) -> Command {
        let text = fs::read_to_string(&self.lane.packet)
            .unwrap()
            .replace(&self.lane.id, id);
        let packet = self.lane.packet.with_file_name(format!("packet-{id}.md"));
        fs::write(&packet, text).unwrap();
        let mut c = self.lane.cowproof_cmd();
        c.arg("run")
            .arg(&packet)
            .arg("--repo")
            .arg(&self.lane.repo)
            .arg("--lanes-root")
            .arg(self.lane.lanes.path())
            .arg("--claude-bin")
            .arg(self.lane.fake_claude())
            .args(["--host", "fake"])
            .env("ANTHROPIC_API_KEY", REAL_KEY);
        c
    }

    /// The first lane's `control/remote.json`.
    fn remote_json(&self) -> Value {
        let p = self.lane.lane_dir().join("control/remote.json");
        serde_json::from_str(
            &fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display())),
        )
        .unwrap()
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

/// Poll until the process `pid` is gone (`kill(2)` with signal 0 says ESRCH), at most 10 s.
fn assert_pid_gone(pid: i64) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if !pid_alive(pid) {
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
            "master", "doctor", "prepare", "forward", "builder", "check", "patch", "stderr",
            "cleanup", "exit"
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
    assert!(prepare.contains(" --protocol 2"), "{prepare}");
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

/// A remote whose ssh emulates a forced-command key (`command="<cowproof> host-agent
/// --forced"`): the hosts config names `named` as the host's cowproof, the key names the real
/// binary, and the fake ssh runs only the key's command with the director's as
/// SSH_ORIGINAL_COMMAND.
///
/// The host's owner has written `~/.config/cowproof/host.toml` in the remote home, naming the
/// `claude` and the lanes root the hosts config also names (a forced key takes both from it).
fn forced_remote(named: &'static str) -> Remote {
    let remote = forced_remote_without_config(named);
    write_host_config(&remote, remote.lane.fake_claude());
    remote
}

/// [`forced_remote`] before its owner has written the host config.
fn forced_remote_without_config(named: &'static str) -> Remote {
    let mut remote = Remote::with_host(&proving_builder(), checks(), |_, entry| {
        entry["cowproof"] = json!(named);
    });
    let real = remote.lane.cowproof.display().to_string();
    remote.lane.set_env(
        "FAKE_SSH_FORCED_COMMAND",
        format!("{real} host-agent --forced"),
    );
    remote
}

/// The owner's host config in the remote home: `claude`, and the remote root of the hosts
/// config. Its file is mode 0600 in a directory of mode 0700, as `host setup` makes it.
fn write_host_config(remote: &Remote, claude: &Path) {
    let dir = remote._home.path().join(".config/cowproof");
    fs::create_dir_all(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    let quoted = |p: &Path| toml::Value::String(p.to_str().unwrap().to_string()).to_string();
    let file = dir.join("host.toml");
    fs::write(
        &file,
        format!(
            "claude = {}\nroot = {}\n",
            quoted(claude),
            quoted(remote.root.path())
        ),
    )
    .unwrap();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
}

#[test]
fn a_remote_lane_is_proved_through_a_forced_command_key() {
    if !sandbox_available() {
        return;
    }
    // The director names a cowproof that does not exist on the host: the lane can only be
    // proved if the host ran the binary the KEY names, and only the verbs it asked for.
    let remote = forced_remote("/no/such/dir/cowproof");
    let out = finish(remote.command(&[]));
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert_eq!(remote.lane.verdict()["verdict"], "proved", "{}", text(&out));
    let patch = fs::read_to_string(remote.lane.lane_dir().join("control/lane.patch")).unwrap();
    assert!(
        patch.contains("+edited") && patch.contains("created.txt"),
        "{patch}"
    );
    assert_eq!(
        remote.steps(),
        [
            "master", "doctor", "prepare", "forward", "builder", "check", "patch", "stderr",
            "cleanup", "exit"
        ],
        "{:?}",
        remote.argvs()
    );
    // Every command the host ran went through the key's forced command, and carried the
    // director's own words; the master and the forwards ran no command at all.
    let log = remote.log();
    let started: Vec<&Value> = log
        .iter()
        .filter(|e| e["event"] == "command-started")
        .collect();
    assert_eq!(
        started.len(),
        8,
        "doctor prepare builder check*2 patch stderr cleanup"
    );
    for e in &started {
        assert_eq!(e["forced"], true, "{e}");
        let command = e["command"].as_str().unwrap();
        assert!(
            command.starts_with("/no/such/dir/cowproof host-agent "),
            "{command}"
        );
    }
    remote.assert_torn_down();
}

#[test]
fn a_forced_key_refuses_a_cowproof_that_is_not_named_cowproof_and_nothing_is_prepared() {
    if !sandbox_available() {
        return;
    }
    // The director's hosts config names a file called `cowproof-evil`: the key's host-agent
    // refuses the first command (doctor), which is an infrastructure error before any lane.
    let remote = forced_remote("/no/such/dir/cowproof-evil");
    let out = finish(remote.command(&[]));
    assert_eq!(out.status.code(), Some(4), "{}", text(&out));
    assert_eq!(
        remote.steps(),
        ["master", "doctor", "exit"],
        "{:?}",
        remote.argvs()
    );
    assert!(!remote.remote_lane().exists());
    assert_eq!(remote.run_json()["status"], "infrastructure");
    assert!(remote.log().iter().any(|e| e["event"] == "master-stopped"));
    assert_pid_gone(remote.master_pid());
}

#[test]
fn a_forced_key_on_a_host_without_the_owners_config_stops_at_doctor_and_says_what_to_run() {
    if !sandbox_available() {
        return;
    }
    let remote = forced_remote_without_config("/no/such/dir/cowproof");
    let out = finish(remote.command(&[]));
    assert_eq!(out.status.code(), Some(4), "{}", text(&out));
    let shown = text(&out);
    assert!(
        shown.contains("host.toml") && shown.contains("missing"),
        "{shown}"
    );
    assert!(shown.contains("host setup --write-config"), "{shown}");
    assert_eq!(
        remote.steps(),
        ["master", "doctor", "exit"],
        "{:?}",
        remote.argvs()
    );
    assert!(!remote.remote_lane().exists());
    assert_eq!(remote.run_json()["status"], "infrastructure");
    assert!(remote.log().iter().any(|e| e["event"] == "master-stopped"));
    assert_pid_gone(remote.master_pid());
}

#[test]
fn a_forced_key_refuses_a_claude_the_director_names_that_is_not_the_owners() {
    if !sandbox_available() {
        return;
    }
    // The owner's config names one claude; the director's hosts config names another.
    let remote = forced_remote_without_config("/no/such/dir/cowproof");
    write_host_config(&remote, Path::new("/opt/owner/claude"));
    let out = finish(remote.command(&[]));
    assert_eq!(out.status.code(), Some(4), "{}", text(&out));
    let shown = text(&out);
    assert!(
        shown.contains("--claude-bin") && shown.contains("host.toml"),
        "{shown}"
    );
    assert_eq!(
        remote.steps(),
        ["master", "doctor", "exit"],
        "{:?}",
        remote.argvs()
    );
    assert!(!remote.remote_lane().exists());
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

    assert!(signal_pid("INT", run.id()), "could not signal the run");
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
// The lifeline, the dirty base and the builder's stderr (R-4)
// ---------------------------------------------------------------------------

/// The `command-started` entry of the ssh that runs `host-agent <verb>`: the command's pid and
/// the fake ssh's own pid.
fn command_started(remote: &Remote, verb: &str) -> (i64, i64) {
    let needle = format!(" host-agent {verb} ");
    let event = remote
        .log()
        .into_iter()
        .find(|e| {
            e["event"] == "command-started"
                && e["command"].as_str().is_some_and(|c| c.contains(&needle))
        })
        .unwrap_or_else(|| panic!("no host-agent {verb} was started: {:?}", remote.log()));
    (
        event["pid"].as_i64().unwrap(),
        event["ssh_pid"].as_i64().unwrap(),
    )
}

/// Poll until the process `pid` is gone, at most `within`.
fn assert_pid_gone_within(pid: i64, within: Duration) {
    let deadline = Instant::now() + within;
    loop {
        if !pid_alive(pid) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "process {pid} is still alive after {within:?}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Wait for a run that was started with `spawn_to_file` to end, killing it by pid after a minute.
fn wait_run(run: &mut Child, stderr: &Path) -> std::process::ExitStatus {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if let Some(status) = run.try_wait().unwrap() {
            return status;
        }
        if Instant::now() > deadline {
            let _ = run.kill();
            let _ = run.wait();
            panic!(
                "the run outlived the builder's loss:\n{}",
                fs::read_to_string(stderr).unwrap_or_default()
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn killing_the_directors_ssh_ends_the_remote_builder() {
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
    let (host_agent, director_ssh) = command_started(&remote, "builder");

    // The director's ssh for the builder dies without a word, as a dropped link or a killed
    // laptop does. The fake relays no hangup (a real ssh without a pty sends none); all the host
    // sees is the end of its stdin.
    assert!(
        signal_pid("KILL", as_pid(director_ssh)),
        "could not signal the director's ssh"
    );
    let began = Instant::now();
    assert_pid_gone_within(host_agent, STOP_WITHIN);
    assert!(began.elapsed() < STOP_WITHIN);
    // The builder's group went with `host-agent` (the sandbox shares the pid space on macOS only).
    if cfg!(target_os = "macos") {
        assert!(group_gone(&builder.to_string()), "builder group is alive");
        assert!(!pid_alive(background), "the background child is alive");
    }

    // The director saw its builder's ssh die and finished the lane its usual way.
    let status = wait_run(&mut run, &stderr);
    assert_ne!(status.code(), Some(0));
    remote.assert_torn_down();
}

/// A pid read from a log or a file, as the `u32` the signalling helpers take.
fn as_pid(pid: i64) -> u32 {
    u32::try_from(pid).expect("a positive pid")
}

fn pid_alive(pid: i64) -> bool {
    common::pid_alive(as_pid(pid))
}

/// What the director may take as the grace a stopped remote builder gets: `TERM_GRACE` and five
/// seconds.
const STOP_WITHIN: Duration = Duration::from_secs(15);

#[test]
fn a_dirty_base_reaches_the_remote_lane() {
    if !sandbox_available() {
        return;
    }
    // `notes.txt` is committed, then changed and left uncommitted; no packet owns it. The
    // check runs on the host, in the clone the builder works in, and again in the proof here.
    let dirty_checks = json!([
        {"id": "dirty", "command": "grep -q two notes.txt"},
        {"id": "edit", "command": "grep -q edited README.md"},
        {"id": "made", "command": "test -f created.txt"},
    ]);
    let remote = Remote::new(&run_checks(&["dirty", "edit", "made"]), dirty_checks);
    remote.lane.commit_files(&[("notes.txt", "one\n")]);
    fs::write(remote.lane.repo.join("notes.txt"), "two\n").unwrap();

    let out = finish(remote.command(&["--allow-dirty"]));
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert_eq!(remote.lane.verdict()["verdict"], "proved", "{}", text(&out));

    // The local proof applied the base patch it recorded...
    let base_patch = fs::read(remote.lane.capsule_dir().join("base.patch")).unwrap();
    assert!(
        String::from_utf8_lossy(&base_patch).contains("+two"),
        "{}",
        String::from_utf8_lossy(&base_patch)
    );
    // ...and those are exactly the bytes the director sent to the host, after the header line
    // and before the bundle.
    let argvs = remote.log();
    let prepare = argvs
        .iter()
        .find(|e| {
            e["argv"]
                .as_array()
                .and_then(|a| a.last())
                .and_then(Value::as_str)
                .is_some_and(|c| c.contains(" host-agent prepare "))
        })
        .expect("no prepare was logged");
    let sent = fs::read(prepare["stdin"].as_str().unwrap()).unwrap();
    let newline = sent.iter().position(|b| *b == b'\n').unwrap();
    let header: Value = serde_json::from_slice(&sent[..newline]).unwrap();
    assert_eq!(header["patch_bytes"], base_patch.len());
    let patch_at = newline + 1;
    assert_eq!(
        &sent[patch_at..patch_at + base_patch.len()],
        base_patch.as_slice()
    );
    assert!(
        sent[patch_at + base_patch.len()..].starts_with(b"# v2 git bundle\n"),
        "the bundle does not follow the patch"
    );
    // The host never saw the director's working tree otherwise: no host-side file named the patch.
    assert!(!prepare["argv"].to_string().contains("base-patch"));
    remote.assert_torn_down();
}

/// A credential-shaped value made of letters only, built at run time: never a real token.
fn synthetic_secret() -> String {
    format!("sk-ant-api03-{}", "abcdefghij".repeat(3))
}

/// A fake builder that writes the synthetic credential to stderr, then does `rest`.
fn leaking_builder(rest: &str) -> String {
    format!("echo 'oops {} in the log' >&2\n{rest}", synthetic_secret())
}

fn local_stderr(remote: &Remote) -> String {
    fs::read_to_string(remote.lane.lane_dir().join("control/builder.stderr"))
        .expect("the lane has no builder.stderr")
}

#[test]
fn the_remote_stderr_is_fetched_and_redacted_again() {
    if !sandbox_available() {
        return;
    }
    let secret = synthetic_secret();
    // A proved run: the builder's own stderr was on the host only, and is here now. The host
    // redacted it; the line around the value is intact.
    let remote = Remote::new(&leaking_builder(&proving_builder()), checks());
    let out = finish(remote.command(&[]));
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let local = local_stderr(&remote);
    assert!(local.contains("oops [redacted] in the log"), "{local}");
    assert!(local.contains("stderr of the builder on fake"), "{local}");
    assert!(!local.contains(&secret), "{local}");
    assert!(!local.contains("abcdefghij"), "{local}");
    remote.assert_torn_down();

    // A refuted run keeps it too.
    let failing = json!([{"id": "edit", "command": "grep -q nothere README.md"}]);
    let remote = Remote::new(&leaking_builder(&run_checks(&["edit"])), failing);
    let out = finish(remote.command(&[]));
    assert_eq!(out.status.code(), Some(2), "{}", text(&out));
    let local = local_stderr(&remote);
    assert!(local.contains("oops [redacted] in the log"), "{local}");
    assert!(!local.contains(&secret), "{local}");
    remote.assert_torn_down();
}

/// A `cowproof` for the hosts config that runs the real one, except that `host-agent <verb>`
/// answers with `reply` (printed as is): a host that does not do what it should.
fn lying_cowproof(dir: &Path, real: &Path, verb: &str, reply: &str) -> PathBuf {
    let path = dir.join("cowproof");
    let script = format!(
        "#!/bin/sh\nif [ \"$1\" = host-agent ] && [ \"$2\" = {verb} ]; then\n  printf '%s\\n' '{reply}'\n  exit 0\nfi\nexec '{}' \"$@\"\n",
        real.display()
    );
    let _g = fork_lock();
    fs::write(&path, script).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    path
}

#[test]
fn a_host_that_returns_the_stderr_unredacted_is_redacted_again_by_the_director() {
    if !sandbox_available() {
        return;
    }
    let secret = synthetic_secret();
    let wrapper = var_tmp("cp-remote-lying-");
    let reply = format!("host said {secret} plainly");
    let remote = Remote::with_host(&proving_builder(), checks(), |lane, entry| {
        entry["cowproof"] = json!(lying_cowproof(
            wrapper.path(),
            &lane.cowproof,
            "stderr",
            &reply
        ));
    });
    let out = finish(remote.command(&[]));
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let local = local_stderr(&remote);
    assert!(local.contains("host said [redacted] plainly"), "{local}");
    assert!(!local.contains(&secret), "{local}");
    assert!(!local.contains("abcdefghij"), "{local}");
    remote.assert_torn_down();
}

#[test]
fn a_host_without_the_protocol_is_an_infrastructure_error_before_anything_is_prepared() {
    if !sandbox_available() {
        return;
    }
    let wrapper = var_tmp("cp-remote-old-");
    // What a cowproof of the older protocol answers: no `protocol` field.
    let old = r#"{"ok":true,"version":"0.1.0","claude":true,"sandbox":true}"#;
    let remote = Remote::with_host(&proving_builder(), checks(), |lane, entry| {
        entry["cowproof"] = json!(lying_cowproof(
            wrapper.path(),
            &lane.cowproof,
            "doctor",
            old
        ));
    });
    let out = finish(remote.command(&[]));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(4), "{}", text(&out));
    assert!(
        stderr.contains("host-agent protocol") && stderr.contains("older cowproof"),
        "{stderr}"
    );
    assert!(stderr.contains("nothing was started"), "{stderr}");
    assert_eq!(
        remote.steps(),
        ["master", "doctor", "exit"],
        "{:?}",
        remote.argvs()
    );
    assert!(!remote.remote_lane().exists());
    assert_eq!(remote.run_json()["status"], "infrastructure");
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
fn unsandboxed_is_refused_with_host() {
    let remote = Remote::new("true\n", checks());
    let out = finish(remote.command(&["--unsandboxed"]));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert!(
        stderr.contains("--unsandboxed cannot be combined with --host"),
        "{stderr}"
    );
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

// ---------------------------------------------------------------------------
// A director that dies (R-5): the orphans it leaves are swept by the next run
// ---------------------------------------------------------------------------

/// A builder that waits (and says so) until `flag/proceed` exists, and then proves like
/// [`proving_builder`]: the first run of a test hangs, the later ones prove.
fn hang_until_proceed(flag: &Path) -> String {
    format!(
        "if [ -e '{flag}/proceed' ]; then\n{proving}\nelse\necho up > \"$HOME/started\"\nsleep 600\nfi\n",
        flag = flag.display(),
        proving = proving_builder(),
    )
}

/// Kills what a failing test would leave: the fake master of the first lane, by the pid its
/// log holds.
struct MasterReaper(PathBuf);

impl Drop for MasterReaper {
    fn drop(&mut self) {
        let Ok(log) = fs::read_to_string(&self.0) else {
            return;
        };
        for line in log.lines() {
            if let Ok(e) = serde_json::from_str::<Value>(line)
                && e["event"] == "master-started"
                && let Some(pid) = e["pid"].as_i64()
                && let Ok(pid) = u32::try_from(pid)
            {
                signal_pid("KILL", pid);
            }
        }
    }
}

/// Start a run whose builder hangs, and wait until it does.
fn start_hanging_run(remote: &Remote) -> (Child, PathBuf) {
    let stderr = remote.ssh_dir.path().join("first.stderr");
    let mut run = spawn_to_file(&mut remote.command(&[]), &stderr);
    wait_for(&remote.remote_lane().join("home/started"), &mut run);
    (run, stderr)
}

#[test]
fn an_orphaned_remote_lane_is_swept_by_the_next_run() {
    if !sandbox_available() {
        return;
    }
    let flag = var_tmp("cp-remote-flag-");
    let remote = Remote::new(&hang_until_proceed(flag.path()), checks());
    let _reaper = MasterReaper(remote.ssh_dir.path().join("log.jsonl"));
    let (mut run, _stderr) = start_hanging_run(&remote);
    let (host_agent, _) = command_started(&remote, "builder");
    let master = remote.master_pid();

    // The director is killed with no chance to clean up. The host's builder still ends through
    // its lifeline; the master and the lane do not.
    run.kill().unwrap();
    let _ = run.wait();
    assert_pid_gone_within(host_agent, STOP_WITHIN);
    assert!(pid_alive(master), "the master went with the director");
    assert!(
        remote.remote_lane().is_dir(),
        "the host's lane went with the director"
    );
    let record = remote.remote_json();
    assert_eq!(record["host"], "fake");
    assert_eq!(record["lane_id"], remote.lane.id.as_str());
    assert_eq!(record["director_pid"].as_u64(), Some(u64::from(run.id())));
    assert_eq!(record["master_pid"].as_i64(), Some(master));
    assert_eq!(record["remote_root"], remote.root.path().to_str().unwrap());
    assert!(
        record["director_start"]
            .as_str()
            .is_some_and(|s| !s.is_empty())
    );
    assert!(
        record["master_start"]
            .as_str()
            .is_some_and(|s| !s.is_empty())
    );
    assert_eq!(record["finished"], false);

    // The next run, for the same host and lanes root.
    fs::write(flag.path().join("proceed"), "go\n").unwrap();
    let second = unique_lane_id();
    let out = finish(remote.second_command(&second));
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        stderr.contains(&format!(
            "swept the orphaned remote lane {}",
            remote.lane.id
        )),
        "{stderr}"
    );
    assert_eq!(
        stderr.matches("swept the orphaned remote lane").count(),
        1,
        "{stderr}"
    );

    assert_pid_gone(master);
    assert!(
        fs::symlink_metadata(remote.remote_lane()).is_err(),
        "the orphan's lane is still on the host"
    );
    // The local lane is evidence: it stays, and says it was swept.
    assert!(remote.lane.lane_dir().join("control").is_dir());
    let record = remote.remote_json();
    assert_eq!(record["swept"], true, "{record}");
    assert_eq!(record["finished"], false, "{record}");
    // And the second run proved.
    let verdict: Value = serde_json::from_str(
        &fs::read_to_string(
            remote
                .lane
                .lanes
                .path()
                .canonicalize()
                .unwrap()
                .join(&second)
                .join("control/verdict.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(verdict["verdict"], "proved", "{}", text(&out));
}

#[test]
fn a_live_directors_lane_is_never_swept() {
    if !sandbox_available() {
        return;
    }
    let flag = var_tmp("cp-remote-flag-");
    let remote = Remote::new(&hang_until_proceed(flag.path()), checks());
    let _reaper = MasterReaper(remote.ssh_dir.path().join("log.jsonl"));
    let (mut run, stderr) = start_hanging_run(&remote);
    let master = remote.master_pid();

    // A second director shares the lanes root while the first one is alive and busy.
    fs::write(flag.path().join("proceed"), "go\n").unwrap();
    let out = finish(remote.second_command(&unique_lane_id()));
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert!(
        !String::from_utf8_lossy(&out.stderr).contains("swept"),
        "{}",
        text(&out)
    );

    assert!(run.try_wait().unwrap().is_none(), "the first run ended");
    assert!(pid_alive(master), "the live director's master was stopped");
    assert!(
        remote.remote_lane().join("home/started").is_file(),
        "the live director's lane was removed from the host"
    );
    assert_ne!(remote.remote_json()["swept"], true);

    // End it the proper way; it cleans up after itself.
    assert!(signal_pid("TERM", run.id()), "could not signal the run");
    wait_run(&mut run, &stderr);
    remote.assert_torn_down();
}

/// The lane id a logged `... host-agent cleanup --lane-id <id> ...` command names, or `None`
/// for any other command.
fn cleanup_lane_id(command: &str) -> Option<&str> {
    let words: Vec<&str> = command.split_whitespace().collect();
    let verb = words
        .windows(2)
        .position(|w| w == ["host-agent", "cleanup"])?;
    let flag = words[verb + 2..].iter().position(|w| *w == "--lane-id")?;
    words.get(verb + 2 + flag + 1).copied()
}

/// How many `host-agent cleanup` commands the fake ssh ran for exactly `lane_id`. The id is
/// compared whole: the ids of one test process differ only by a counter, so `...-1` is a
/// prefix of `...-10`, and another run's cleanup must not be taken for this lane's.
fn cleanup_count(log: &[Value], lane_id: &str) -> usize {
    log.iter()
        .filter(|e| e["event"] == "command-started")
        .filter_map(|e| e["command"].as_str())
        .filter(|c| cleanup_lane_id(c) == Some(lane_id))
        .count()
}

#[test]
fn the_cleanup_count_matches_a_lane_id_whole_not_as_a_substring() {
    let entry = |id: &str| {
        json!({
            "event": "command-started",
            "command": format!("/opt/cp/cowproof host-agent cleanup --lane-id {id} --root /srv/lanes"),
        })
    };
    let log = vec![
        entry("t-ver-7-1"),
        entry("t-ver-7-10"),
        entry("t-ver-7-10"),
        json!({"event": "command-started", "command": "/opt/cp/cowproof host-agent prepare --lane-id t-ver-7-1"}),
        json!({"event": "invocation", "command": "host-agent cleanup --lane-id t-ver-7-1"}),
    ];
    assert_eq!(cleanup_count(&log, "t-ver-7-1"), 1);
    assert_eq!(cleanup_count(&log, "t-ver-7-10"), 2);
    assert_eq!(cleanup_count(&log, "t-ver-7"), 0);
    assert_eq!(cleanup_lane_id("host-agent cleanup"), None);
}

#[test]
fn a_finished_lane_is_never_swept() {
    if !sandbox_available() {
        return;
    }
    let (remote, _out) = proved_run();
    let record = remote.remote_json();
    assert_eq!(record["finished"], true, "{record}");
    assert_ne!(record["swept"], true);
    let cleanups = |remote: &Remote| cleanup_count(&remote.log(), &remote.lane.id);
    assert_eq!(cleanups(&remote), 1, "the run's own cleanup");

    let out = finish(remote.second_command(&unique_lane_id()));
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    assert!(
        !String::from_utf8_lossy(&out.stderr).contains("swept"),
        "{}",
        text(&out)
    );
    assert_eq!(
        cleanups(&remote),
        1,
        "a finished lane was cleaned up again by a sweep"
    );
    assert_ne!(remote.remote_json()["swept"], true);
}
