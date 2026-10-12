//! Class slots and port blocks (D12), end to end: the real `cowproof` binary against a
//! FAKE `claude`. Every test gives its lanes a slot directory of its own through
//! `COWPROOF_SLOT_DIR` (under /var/tmp), so no test touches the machine's slots, and every
//! wait is bounded: a process that outlives its bound is killed by pid and the test fails.
//! Needs the sandbox like `tests/run.rs` (skipped without it, a failure under
//! `COWPROOF_REQUIRE_SANDBOX=1`).

mod common;

use common::{
    Lane, fork_lock, output, run_checks, sandbox_available, signal_pid, spawn_to_file, text,
    var_tmp,
};
use cowproof_prove::Capsule;
use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus};
use std::time::{Duration, Instant};

/// The most a whole `cowproof run` may take in these tests, deadlocks included.
const RUN_WITHIN: Duration = Duration::from_secs(120);

fn checks() -> Value {
    json!([
        {"id": "edit", "command": "grep -q edited README.md"},
        {"id": "made", "command": "test -f created.txt"},
    ])
}

/// The default builder: records when it started, then runs both checks.
fn quick_builder() -> String {
    format!(
        "date +%s > \"$rec/started\"\n{}",
        run_checks(&["edit", "made"])
    )
}

/// A builder that records when it started, waits until the test creates `$HOME/go`
/// (at most 90 s), records when it ended, then runs both checks.
fn held_builder() -> String {
    format!(
        "date +%s > \"$rec/started\"\n\
         i=0\n\
         while [ ! -f \"$HOME/go\" ] && [ \"$i\" -lt 900 ]; do sleep 0.1; i=$((i+1)); done\n\
         date +%s > \"$rec/ended\"\n{}",
        run_checks(&["edit", "made"])
    )
}

/// A lane of `class` whose slots live in `slots`. `base_toml` is committed as the base's
/// `cowproof.toml` when given.
fn lane(slots: &Path, class: &str, base_toml: Option<&str>, body: &str, checks: Value) -> Lane {
    let mut lane = Lane::with_class(body, checks, class);
    if let Some(toml) = base_toml {
        lane.commit_files(&[("cowproof.toml", toml)]);
    }
    lane.set_env("COWPROOF_SLOT_DIR", slots);
    lane
}

/// The files a lane's builder wrote: `$HOME` in the sandbox is `<lane>/home`.
fn builder_file(lane: &Lane, name: &str) -> PathBuf {
    lane.lane_dir().join("home").join(name)
}

fn release_builder(lane: &Lane) {
    fs::write(builder_file(lane, "go"), "go\n").unwrap();
}

fn seconds(path: &Path) -> u64 {
    fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
        .trim()
        .parse()
        .unwrap()
}

fn run_json(lane: &Lane) -> Value {
    let p = lane.lane_dir().join("control/run.json");
    serde_json::from_str(&fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display())))
        .unwrap()
}

/// The names of the slots held in `dir`, sorted. A directory that is not there holds none.
fn held(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .map(|entries| {
            entries
                .flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names
}

/// A process this test started, killed by pid when the test ends. `stderr` is the file its
/// standard error goes to, readable while it runs.
struct Running {
    child: Child,
    stderr: PathBuf,
}

impl Running {
    fn start(cmd: &mut Command, stderr: &Path) -> Self {
        Running {
            child: spawn_to_file(cmd, stderr),
            stderr: stderr.to_path_buf(),
        }
    }

    fn stderr(&self) -> String {
        fs::read_to_string(&self.stderr).unwrap_or_default()
    }

    /// Wait until the process's stderr holds `needle`; a process that ends first, or a wait
    /// that runs out, fails the test.
    fn wait_for_stderr(&mut self, needle: &str, within: Duration) {
        let deadline = Instant::now() + within;
        while !self.stderr().contains(needle) {
            if let Some(status) = self.child.try_wait().unwrap() {
                panic!(
                    "the process ended ({status}) before {needle:?}:\n{}",
                    self.stderr()
                );
            }
            assert!(
                Instant::now() < deadline,
                "no {needle:?} within {within:?}:\n{}",
                self.stderr()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Wait for a file the builder writes; the process must still be running.
    fn wait_for_file(&mut self, path: &Path, within: Duration) {
        let deadline = Instant::now() + within;
        while !path.exists() {
            if let Some(status) = self.child.try_wait().unwrap() {
                panic!(
                    "the process ended ({status}) before {} appeared:\n{}",
                    path.display(),
                    self.stderr()
                );
            }
            assert!(
                Instant::now() < deadline,
                "{} never appeared:\n{}",
                path.display(),
                self.stderr()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Wait for the process to end within `within`; one that does not is killed and fails the
    /// test.
    fn wait_exit(&mut self, within: Duration) -> ExitStatus {
        let deadline = Instant::now() + within;
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status;
            }
            if Instant::now() > deadline {
                let _ = self.child.kill();
                let _ = self.child.wait();
                panic!("still going after {within:?}:\n{}", self.stderr());
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn still_running(&mut self) -> bool {
        self.child.try_wait().unwrap().is_none()
    }

    fn signal(&self, name: &str) {
        assert!(
            signal_pid(name, self.child.id()),
            "could not send {name} to the run"
        );
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

/// Start `cowproof run` for `lane`, its stderr in `<lanes root>/../run.err`-style file next
/// to the lane's own directories.
fn start_run(lane: &Lane, name: &str, extra: &[&Path]) -> Running {
    let stderr = lane.home.path().join(format!("{name}.err"));
    Running::start(&mut lane.run_command(extra), &stderr)
}

/// Run `lane` to its end and return its exit code.
fn run_to_end(lane: &Lane, name: &str) -> (Option<i32>, String) {
    let mut run = start_run(lane, name, &[]);
    let status = run.wait_exit(RUN_WITHIN);
    (status.code(), run.stderr())
}

/// A stand-in for another lane's holder: a live process (`sleep`) whose pid fills slot
/// `name` in `slots`. Killed (by pid) and reaped when dropped, which makes its slot a dead
/// holder's.
struct Holder {
    child: Child,
}

impl Holder {
    fn take(slots: &Path, name: &str) -> Self {
        let child = {
            let _g = fork_lock();
            Command::new("sleep")
                .arg("600")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .unwrap()
        };
        let dir = slots.join(name);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("pid"), child.id().to_string()).unwrap();
        Holder { child }
    }

    /// End the holder; its slot stays on disk, now a dead holder's.
    fn die(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for Holder {
    fn drop(&mut self) {
        self.die();
    }
}

// ---- The limit, the wait, and what the wait does not count -------------------

/// A limit of one for `light` in the base commit. A second run, started while the first
/// holds the slot, says so once and starts its builder only after the first has ended.
/// Its time limit (6 s) is shorter than its wait (8 s), and it still ends proved: the
/// wait counts toward neither the limit nor the cost.
#[test]
fn a_second_run_waits_for_the_slot_and_starts_its_builder_after_the_first_ends() {
    if !sandbox_available() {
        return;
    }
    let slots = var_tmp("cp-slots-");
    let base = Some("[classes]\nlight = 1\n");
    let a = lane(slots.path(), "light", base, &held_builder(), checks());
    let b = lane(slots.path(), "light", base, &quick_builder(), checks());

    let mut run_a = start_run(&a, "a", &[]);
    run_a.wait_for_file(&builder_file(&a, "fake/started"), Duration::from_secs(60));
    assert_eq!(held(slots.path()), ["light-0", "port-0"]);

    let mut run_b = start_run(&b, "b", &[Path::new("--timeout-secs"), Path::new("6")]);
    run_b.wait_for_stderr(
        "waiting for a light slot (limit 1)",
        Duration::from_secs(60),
    );
    std::thread::sleep(Duration::from_secs(8));
    assert!(
        run_b.still_running(),
        "b ended while a held the only slot:\n{}",
        run_b.stderr()
    );
    assert!(
        !builder_file(&b, "fake/started").exists(),
        "b's builder started while a held the only slot"
    );
    assert!(run_a.still_running());

    release_builder(&a);
    assert_eq!(
        run_a.wait_exit(RUN_WITHIN).code(),
        Some(0),
        "{}",
        run_a.stderr()
    );
    assert_eq!(
        run_b.wait_exit(RUN_WITHIN).code(),
        Some(0),
        "{}",
        run_b.stderr()
    );

    // By the clock as well: b's builder started at or after the second a's ended.
    let a_ended = seconds(&builder_file(&a, "fake/ended"));
    let b_started = seconds(&builder_file(&b, "fake/started"));
    assert!(
        a_ended <= b_started,
        "a ended at {a_ended}, b started at {b_started}"
    );

    assert_eq!(
        run_b.stderr().matches("waiting for a light slot").count(),
        1
    );
    assert!(
        !run_a.stderr().contains("waiting for"),
        "{}",
        run_a.stderr()
    );
    let b_run = run_json(&b);
    assert_eq!(b_run["status"], "finished", "not a timeout: {b_run}");
    assert_eq!(b.verdict()["verdict"], "proved");
    assert_eq!(b_run["classSlot"]["limit"], 1);
    assert!(
        b_run["classSlot"]["waitMs"].as_u64().unwrap() >= 7000,
        "{}",
        b_run["classSlot"]
    );
    assert!(
        b_run["activeMs"].as_u64().unwrap() < 6000,
        "the wait was counted as builder time: {}",
        b_run["activeMs"]
    );
    assert_eq!(held(slots.path()), Vec::<String>::new());
}

/// With nothing in `cowproof.toml`, a class has its default limit; the base's `[classes]`
/// replaces it.
#[test]
fn the_base_cowproof_toml_sets_the_class_limit_and_the_defaults_fill_the_rest() {
    if !sandbox_available() {
        return;
    }
    let slots = var_tmp("cp-slots-");
    let cases: [(&str, Option<&str>, u64); 4] = [
        ("light", None, 6),
        ("crate", None, 4),
        ("pg", Some("[classes]\nlight = 1\n"), 3),
        ("light", Some("[classes]\nlight = 1\n"), 1),
    ];
    for (class, toml, limit) in cases {
        let lane = lane(slots.path(), class, toml, &quick_builder(), checks());
        let (code, stderr) = run_to_end(&lane, "run");
        assert_eq!(code, Some(0), "{class}: {stderr}");
        let slot = &run_json(&lane)["classSlot"];
        assert_eq!(slot["class"], class);
        assert_eq!(slot["limit"], limit, "{class} with {toml:?}");
    }
}

// ---- The slot goes back on every end ------------------------------------------

/// After a run ended one way or another, nothing is held and a following run takes the
/// only slot without waiting. (The directory itself is checked, not only the next run: a
/// slot a dead process held would be reclaimed, which would hide a leak.)
fn assert_released_and_reusable(slots: &Path, ended: &str) {
    assert_eq!(
        held(slots),
        Vec::<String>::new(),
        "a slot is still held after {ended}"
    );
    let next = lane(
        slots,
        "light",
        Some("[classes]\nlight = 1\n"),
        &quick_builder(),
        checks(),
    );
    let (code, stderr) = run_to_end(&next, "next");
    assert_eq!(code, Some(0), "the run after {ended}: {stderr}");
    assert!(
        !stderr.contains("waiting for"),
        "the run after {ended} waited:\n{stderr}"
    );
    assert_eq!(
        run_json(&next)["classSlot"]["waitMs"]
            .as_u64()
            .map(|ms| ms < 1000),
        Some(true)
    );
}

#[test]
fn the_slot_is_released_after_a_proved_run() {
    if !sandbox_available() {
        return;
    }
    let slots = var_tmp("cp-slots-");
    let lane = lane(
        slots.path(),
        "light",
        Some("[classes]\nlight = 1\n"),
        &quick_builder(),
        checks(),
    );
    let (code, stderr) = run_to_end(&lane, "run");
    assert_eq!(code, Some(0), "{stderr}");
    assert_eq!(lane.verdict()["verdict"], "proved");
    assert_released_and_reusable(slots.path(), "a proved run");
}

#[test]
fn the_slot_is_released_after_a_refuted_run() {
    if !sandbox_available() {
        return;
    }
    let slots = var_tmp("cp-slots-");
    let failing = json!([{"id": "never", "command": "false"}]);
    let lane = lane(
        slots.path(),
        "light",
        Some("[classes]\nlight = 1\n"),
        &run_checks(&["never"]),
        failing,
    );
    let (code, stderr) = run_to_end(&lane, "run");
    assert_eq!(code, Some(2), "{stderr}");
    assert_eq!(lane.verdict()["verdict"], "refuted");
    assert_released_and_reusable(slots.path(), "a refuted run");
}

#[test]
fn the_slot_is_released_after_sigint_and_the_exit_is_130() {
    if !sandbox_available() {
        return;
    }
    let slots = var_tmp("cp-slots-");
    let lane = lane(
        slots.path(),
        "light",
        Some("[classes]\nlight = 1\n"),
        "date +%s > \"$rec/started\"\nsleep 120\n",
        checks(),
    );
    let mut run = start_run(&lane, "run", &[]);
    run.wait_for_file(
        &builder_file(&lane, "fake/started"),
        Duration::from_secs(60),
    );
    assert_eq!(held(slots.path()), ["light-0", "port-0"]);

    run.signal("INT");
    let status = run.wait_exit(Duration::from_secs(30));
    assert_eq!(status.code(), Some(130), "{}", run.stderr());
    assert_eq!(run_json(&lane)["status"], "interrupted");
    assert_released_and_reusable(slots.path(), "SIGINT");
}

/// A signal after the builder, in the proof, ends the run gracefully: the verifier's check
/// (a hold, told apart from the builder's run of it by its `TMPDIR`) is ended, `run.json` says
/// `interrupted` in the `proof` phase, both slots are given back by the run's own return (no
/// `process::exit` to skip a destructor) and the next run starts at once.
fn a_signal_in_the_proof_releases_the_slots(signal: &str, name: &str) {
    let slots = var_tmp("cp-slots-");
    let hold = "case \"$TMPDIR\" in */verify/tmp) echo $$ > \"$TMPDIR/held\"; sleep 300 ;; *) true ;; esac";
    let lane = lane(
        slots.path(),
        "light",
        Some("[classes]\nlight = 1\n"),
        &run_checks(&["hold"]),
        json!([{"id": "hold", "command": hold}]),
    );
    let mut run = start_run(&lane, "run", &[]);
    run.wait_for_file(
        &lane.lane_dir().join("scratch/verify/tmp/held"),
        Duration::from_secs(60),
    );
    // The proof holds the builder's two slots: it takes none of its own.
    assert_eq!(held(slots.path()), ["light-0", "port-0"]);

    run.signal(signal);
    let status = run.wait_exit(Duration::from_secs(30));
    assert_eq!(status.code(), Some(130), "{}", run.stderr());
    let record = run_json(&lane);
    assert_eq!(record["status"], "interrupted", "{record}");
    assert_eq!(record["phase"], "proof", "{record}");
    assert_eq!(record["signal"], name, "{record}");
    assert!(
        !lane.lane_dir().join("control/verdict.json").exists(),
        "a lane signalled in the proof has a verdict"
    );
    assert_released_and_reusable(slots.path(), name);
}

#[test]
fn the_slots_are_released_after_sigint_in_the_proof() {
    if !sandbox_available() {
        return;
    }
    a_signal_in_the_proof_releases_the_slots("INT", "SIGINT");
}

#[test]
fn the_slots_are_released_after_sigterm_in_the_proof() {
    if !sandbox_available() {
        return;
    }
    a_signal_in_the_proof_releases_the_slots("TERM", "SIGTERM");
}

/// A run still waiting for a slot ends on SIGINT too: 130, `interrupted`, no slot of its
/// own, and the run that holds the slot is not disturbed.
#[test]
fn sigint_while_waiting_for_a_slot_ends_the_waiter_and_leaves_the_holder() {
    if !sandbox_available() {
        return;
    }
    let slots = var_tmp("cp-slots-");
    let base = Some("[classes]\nlight = 1\n");
    let a = lane(slots.path(), "light", base, &held_builder(), checks());
    let b = lane(slots.path(), "light", base, &quick_builder(), checks());
    let mut run_a = start_run(&a, "a", &[]);
    run_a.wait_for_file(&builder_file(&a, "fake/started"), Duration::from_secs(60));
    let mut run_b = start_run(&b, "b", &[]);
    run_b.wait_for_stderr("waiting for a light slot", Duration::from_secs(60));

    run_b.signal("INT");
    assert_eq!(
        run_b.wait_exit(Duration::from_secs(30)).code(),
        Some(130),
        "{}",
        run_b.stderr()
    );
    assert_eq!(run_json(&b)["status"], "interrupted");
    assert!(!builder_file(&b, "fake/started").exists());
    assert!(run_a.still_running());
    assert_eq!(
        held(slots.path()),
        ["light-0", "port-0"],
        "the holder's slots must stay"
    );

    release_builder(&a);
    assert_eq!(
        run_a.wait_exit(RUN_WITHIN).code(),
        Some(0),
        "{}",
        run_a.stderr()
    );
    assert_eq!(held(slots.path()), Vec::<String>::new());
}

/// A slot file left by a process that is gone is taken over at once, not waited for.
#[test]
fn a_slot_held_by_a_dead_pid_is_reclaimed() {
    if !sandbox_available() {
        return;
    }
    let slots = var_tmp("cp-slots-");
    let mut dead = Holder::take(slots.path(), "light-0");
    dead.die();
    assert_eq!(held(slots.path()), ["light-0"]);

    let lane = lane(
        slots.path(),
        "light",
        Some("[classes]\nlight = 1\n"),
        &quick_builder(),
        checks(),
    );
    let (code, stderr) = run_to_end(&lane, "run");
    assert_eq!(code, Some(0), "{stderr}");
    assert!(
        !stderr.contains("waiting for"),
        "waited for a dead holder:\n{stderr}"
    );
    assert_eq!(held(slots.path()), Vec::<String>::new());
}

// ---- The port block ---------------------------------------------------------------

/// The builder, the lane's `run_check` and the verifier each see the block of the `port` slot
/// the lane holds. `port-0` is taken by another (live) process, so this lane holds `port-1`:
/// 57000 + 1 * 20. The declared check passes only with both variables set, and it runs
/// twice, once in `run_check` and once in the verifier.
#[test]
fn the_builder_run_check_and_verifier_get_the_port_block_of_the_slot() {
    if !sandbox_available() {
        return;
    }
    let slots = var_tmp("cp-slots-");
    let _other = Holder::take(slots.path(), "port-0");
    let ports = json!([{
        "id": "ports",
        "command": "test \"$COWPROOF_PORT_BASE\" = 57020 && test \"$COWPROOF_PORT_COUNT\" = 20",
    }]);
    let body = format!("env > \"$rec/env\"\n{}", run_checks(&["ports"]));
    let lane = lane(slots.path(), "light", None, &body, ports);

    let (code, stderr) = run_to_end(&lane, "run");
    assert_eq!(code, Some(0), "{stderr}");
    assert_eq!(lane.verdict()["verdict"], "proved");

    let env = fs::read_to_string(builder_file(&lane, "fake/env")).unwrap();
    let lines: Vec<&str> = env.lines().collect();
    assert!(lines.contains(&"COWPROOF_PORT_BASE=57020"), "{env}");
    assert!(lines.contains(&"COWPROOF_PORT_COUNT=20"), "{env}");
    let slot = &run_json(&lane)["portSlot"];
    assert_eq!(slot["portBase"], 57020);
    assert_eq!(slot["limit"], 50);

    // The block is its own thing: the bridge port is still the lane id's hash.
    let bridge = run_json(&lane)["bridgePort"].as_u64().unwrap();
    assert_eq!(
        bridge,
        u64::from(cowproof_run::bridge::bridge_port(&lane.id))
    );
    assert!(
        lines
            .iter()
            .any(|l| l.contains(&format!("127.0.0.1:{bridge}"))),
        "the builder's API endpoint is not the bridge port {bridge}:\n{env}"
    );
}

/// Two lanes of different classes running at once get different blocks: the block comes from
/// a machine-wide `port` slot, not from the class slot (`light-0` and `rust-0` would both
/// have been block 0).
#[test]
fn lanes_of_different_classes_running_at_once_get_different_port_blocks() {
    if !sandbox_available() {
        return;
    }
    let slots = var_tmp("cp-slots-");
    // Written whole under a temp name, then renamed: the test reads it while the builder
    // still runs, and `env > file` makes the file before it fills it.
    let body = format!(
        "env > \"$rec/env.tmp\" && mv \"$rec/env.tmp\" \"$rec/env\"\n{}",
        held_builder()
    );
    let a = lane(slots.path(), "light", None, &body, checks());
    let b = lane(slots.path(), "rust", None, &body, checks());
    let mut run_a = start_run(&a, "a", &[]);
    run_a.wait_for_file(&builder_file(&a, "fake/env"), Duration::from_secs(60));
    let mut run_b = start_run(&b, "b", &[]);
    run_b.wait_for_file(&builder_file(&b, "fake/env"), Duration::from_secs(60));
    assert_eq!(
        held(slots.path()),
        ["light-0", "port-0", "port-1", "rust-0"],
        "both lanes hold a class slot and a port slot"
    );

    let base = |lane: &Lane| {
        fs::read_to_string(builder_file(lane, "fake/env"))
            .unwrap()
            .lines()
            .find_map(|l| l.strip_prefix("COWPROOF_PORT_BASE=").map(str::to_string))
            .expect("the builder has no COWPROOF_PORT_BASE")
    };
    let (base_a, base_b) = (base(&a), base(&b));
    assert_ne!(base_a, base_b, "two live lanes share a port block");
    assert_eq!((base_a.as_str(), base_b.as_str()), ("57000", "57020"));

    release_builder(&a);
    release_builder(&b);
    assert_eq!(
        run_a.wait_exit(RUN_WITHIN).code(),
        Some(0),
        "{}",
        run_a.stderr()
    );
    assert_eq!(
        run_b.wait_exit(RUN_WITHIN).code(),
        Some(0),
        "{}",
        run_b.stderr()
    );
    assert_eq!(held(slots.path()), Vec::<String>::new());
}

/// With every `port` slot taken (`[classes] port = 1` and a live holder) a run waits for one
/// as it does for a class slot, after taking its class slot; a SIGINT in that wait gives the
/// class slot back, and the holder's port slot stays.
#[test]
fn a_run_waits_for_a_port_slot_and_a_sigint_there_gives_back_its_class_slot() {
    if !sandbox_available() {
        return;
    }
    let slots = var_tmp("cp-slots-");
    let mut other = Holder::take(slots.path(), "port-0");
    let base = Some("[classes]\nport = 1\n");
    let waiter = lane(slots.path(), "light", base, &quick_builder(), checks());
    let mut run = start_run(&waiter, "waiter", &[]);
    run.wait_for_stderr("waiting for a port slot (limit 1)", Duration::from_secs(60));
    assert_eq!(held(slots.path()), ["light-0", "port-0"]);
    assert!(!builder_file(&waiter, "fake/started").exists());

    run.signal("INT");
    assert_eq!(
        run.wait_exit(Duration::from_secs(30)).code(),
        Some(130),
        "{}",
        run.stderr()
    );
    assert_eq!(run_json(&waiter)["status"], "interrupted");
    assert_eq!(
        held(slots.path()),
        ["port-0"],
        "the class slot was not given back"
    );

    // And when the holder goes, a second run takes its slot at once and finishes.
    other.die();
    let next = lane(slots.path(), "light", base, &quick_builder(), checks());
    let (code, stderr) = run_to_end(&next, "next");
    assert_eq!(code, Some(0), "{stderr}");
    assert_eq!(run_json(&next)["portSlot"]["portBase"], 57000);
    assert_eq!(held(slots.path()), Vec::<String>::new());
}

// ---- The capsule and the standalone verifier -----------------------------------------

/// The capsule records the lane's class. A standalone `cowproof verify` takes a slot of
/// that class, with the limit in the capsule's base commit, and gives it back. `rust-0` is
/// held by another live process, so at the limit of one the verifier waits; when that
/// holder dies its slot is reclaimed and the replay runs, with the port block too (the
/// recorded check passes only with it).
#[test]
fn the_capsule_records_the_class_and_a_standalone_verify_holds_that_classs_slot() {
    if !sandbox_available() {
        return;
    }
    let slots = var_tmp("cp-slots-");
    let base = Some("[classes]\nrust = 1\n");
    let ports = json!([{
        "id": "ports",
        "command": "test \"$COWPROOF_PORT_BASE\" = 57000 && test \"$COWPROOF_PORT_COUNT\" = 20",
    }]);
    let lane = lane(slots.path(), "rust", base, &run_checks(&["ports"]), ports);
    let (code, stderr) = run_to_end(&lane, "run");
    assert_eq!(code, Some(0), "{stderr}");
    assert_eq!(held(slots.path()), Vec::<String>::new());

    let capsule = Capsule::read(&lane.capsule_dir()).unwrap();
    assert_eq!(capsule.class, "rust");
    let on_disk = fs::read_to_string(lane.capsule_dir().join("capsule.json")).unwrap();
    assert!(on_disk.contains("\"class\": \"rust\""), "{on_disk}");

    let fresh = var_tmp("cp-slots-fresh-");
    let clone = output(
        Command::new("git")
            .args(["clone", "-q"])
            .arg(&lane.repo)
            .arg(fresh.path().join("repo")),
    );
    assert!(clone.status.success(), "{}", text(&clone));
    let elsewhere = var_tmp("cp-slots-cwd-");
    let workdir = var_tmp("cp-slots-wd-");

    let mut holder = Holder::take(slots.path(), "rust-0");
    let mut verify_cmd = lane.cowproof_cmd();
    verify_cmd
        .current_dir(elsewhere.path())
        .arg("verify")
        .arg(lane.capsule_dir())
        .arg("--repo")
        .arg(fresh.path().join("repo"))
        .arg("--workdir")
        .arg(workdir.path());
    let mut verify = Running::start(&mut verify_cmd, &lane.home.path().join("verify.err"));
    verify.wait_for_stderr("waiting for a rust slot (limit 1)", Duration::from_secs(60));
    std::thread::sleep(Duration::from_secs(2));
    assert!(
        verify.still_running(),
        "verify did not wait for the rust slot:\n{}",
        verify.stderr()
    );

    holder.die();
    let status = verify.wait_exit(RUN_WITHIN);
    assert_eq!(status.code(), Some(0), "{}", verify.stderr());
    assert_eq!(
        held(slots.path()),
        Vec::<String>::new(),
        "verify kept its slot"
    );
}

// ---- No deadlock ----------------------------------------------------------------------

/// At a limit of one, the run holds the only slot while its verifier replays the checks.
/// If the verifier took a second slot it would wait for the first, the run's own, forever;
/// the bound turns that hang into a failure.
#[test]
fn at_a_limit_of_one_a_run_that_reaches_verify_finishes() {
    if !sandbox_available() {
        return;
    }
    let slots = var_tmp("cp-slots-");
    let lane = lane(
        slots.path(),
        "light",
        Some("[classes]\nlight = 1\n"),
        &quick_builder(),
        checks(),
    );
    let mut run = start_run(&lane, "run", &[]);
    let status = run.wait_exit(Duration::from_secs(90));
    assert_eq!(status.code(), Some(0), "{}", run.stderr());
    assert_eq!(lane.verdict()["verdict"], "proved");
    assert!(!run.stderr().contains("waiting for"), "{}", run.stderr());
    assert_eq!(held(slots.path()), Vec::<String>::new());
}
