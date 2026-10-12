//! `cowproof cache` and `cowproof cache prune`, end to end through the real binary.
//!
//! Every test names its own cache root and `HOME` under `/var/tmp` and sets nothing else,
//! so no test reads or touches the real home or the real cache. A "dead" pid is a child
//! that was started and reaped; a "live" one is a child still sleeping.

#[allow(dead_code)] // this file needs only a few of the shared helpers
mod common;

use common::{output, text, var_tmp};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, SystemTime};
use tempfile::TempDir;

const DAY: Duration = Duration::from_secs(86_400);

struct Fixture {
    _tmp: TempDir,
    root: PathBuf,
    home: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let tmp = var_tmp("cp-cache-cli-");
        let root = tmp.path().join("cache");
        let home = tmp.path().join("home");
        fs::create_dir_all(root.join("deps")).unwrap();
        fs::create_dir_all(&home).unwrap();
        Fixture {
            _tmp: tmp,
            root,
            home,
        }
    }

    fn cowproof(&self, args: &[&str]) -> Output {
        self.cowproof_in(&self.root, args)
    }

    fn cowproof_in(&self, root: &Path, args: &[&str]) -> Output {
        output(
            Command::new(env!("CARGO_BIN_EXE_cowproof"))
                .args(args)
                .current_dir(&self.home)
                .env("HOME", &self.home)
                .env("COWPROOF_CACHE_ROOT", root),
        )
    }

    /// An entry of `bytes` bytes, last used `days` days ago.
    fn entry(&self, key: &str, bytes: usize, days: u32) -> PathBuf {
        let dir = self.root.join("deps").join(key);
        fs::create_dir_all(dir.join("cargo/registry")).unwrap();
        fs::write(dir.join("cargo/registry/crate"), vec![b'x'; bytes]).unwrap();
        let marker = fs::File::create(dir.join(".last-used")).unwrap();
        marker.set_modified(SystemTime::now() - DAY * days).unwrap();
        dir
    }

    fn lease(&self, dir: &Path, pid: u32) {
        fs::create_dir_all(dir.join("leases")).unwrap();
        fs::write(dir.join("leases").join(pid.to_string()), "").unwrap();
    }

    fn has(&self, key: &str) -> bool {
        self.root.join("deps").join(key).exists()
    }
}

/// A pid that has exited and been reaped.
fn dead_pid() -> u32 {
    let mut child = Command::new("true").spawn().unwrap();
    let pid = child.id();
    child.wait().unwrap();
    pid
}

/// A running process: its pid is alive until the guard is dropped.
struct Sleeper(Child);

impl Sleeper {
    fn start() -> Self {
        Sleeper(
            Command::new("sleep")
                .arg("600")
                .stdout(Stdio::null())
                .spawn()
                .unwrap(),
        )
    }
    fn pid(&self) -> u32 {
        self.0.id()
    }
}

impl Drop for Sleeper {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn cache_alone_and_ls_show_the_size_the_count_and_the_oldest_use() {
    let f = Fixture::new();
    let empty = f.cowproof(&["cache"]);
    assert!(empty.status.success(), "{}", text(&empty));
    let out = String::from_utf8_lossy(&empty.stdout).into_owned();
    assert!(out.contains("entries: 0"), "{out}");
    assert!(out.contains("oldest last use: none"), "{out}");

    f.entry("aaa", 3000, 40);
    f.entry("bbb", 1000, 2);
    for args in [&["cache"][..], &["cache", "ls"][..]] {
        let o = f.cowproof(args);
        assert!(o.status.success(), "{}", text(&o));
        let out = String::from_utf8_lossy(&o.stdout).into_owned();
        assert!(out.contains(&format!("cache root: {}", f.root.display())));
        assert!(out.contains("entries: 2"), "{out}");
        assert!(out.contains("(4000 bytes)"), "{out}");
        assert!(out.contains("40 days ago"), "{out}");
    }
}

#[test]
fn prune_removes_old_entries_keeps_recent_ones_and_reports_the_bytes() {
    let f = Fixture::new();
    f.entry("old", 500, 40);
    f.entry("recent", 500, 2);
    let o = f.cowproof(&["cache", "prune"]);
    assert!(o.status.success(), "{}", text(&o));
    let out = String::from_utf8_lossy(&o.stdout).into_owned();
    assert!(out.contains("removed old"), "{out}");
    assert!(out.contains("removed 1 of 2 entries"), "{out}");
    assert!(!f.has("old") && f.has("recent"));

    let o = f.cowproof(&["cache", "prune", "--older-than", "1"]);
    assert!(o.status.success(), "{}", text(&o));
    assert!(!f.has("recent"), "--older-than 1 keeps a two-day-old entry");
}

#[test]
fn prune_max_size_removes_the_least_recently_used_first() {
    let f = Fixture::new();
    let kib = 1024;
    f.entry("a-oldest", kib, 10);
    f.entry("b-newest", kib, 1);
    // 1 KiB is 0.000000954 GiB: use a limit that holds one entry and not two.
    let o = f.cowproof(&["cache", "prune", "--max-size", "0.0000015"]);
    assert!(o.status.success(), "{}", text(&o));
    assert!(!f.has("a-oldest") && f.has("b-newest"), "{}", text(&o));
    let bad = f.cowproof(&["cache", "prune", "--max-size", "-1"]);
    assert!(!bad.status.success());
    assert!(f.has("b-newest"));
}

#[test]
fn a_dry_run_names_what_it_would_remove_and_removes_nothing() {
    let f = Fixture::new();
    f.entry("old", 500, 40);
    fs::create_dir_all(f.root.join("deps-work").join(format!("{}-1", dead_pid()))).unwrap();
    let o = f.cowproof(&["cache", "prune", "--dry-run"]);
    assert!(o.status.success(), "{}", text(&o));
    let out = String::from_utf8_lossy(&o.stdout).into_owned();
    assert!(out.contains("would remove old"), "{out}");
    assert!(out.contains("would remove 1 of 1 entries"), "{out}");
    assert!(out.contains("500 bytes would be freed"), "{out}");
    assert!(f.has("old"));
    assert_eq!(fs::read_dir(f.root.join("deps-work")).unwrap().count(), 1);
}

#[test]
fn a_live_lease_protects_an_old_entry_and_a_dead_one_does_not() {
    let f = Fixture::new();
    let sleeper = Sleeper::start();
    let held = f.entry("held", 100, 90);
    f.lease(&held, sleeper.pid());
    let stale = f.entry("stale", 100, 90);
    f.lease(&stale, dead_pid());
    let o = f.cowproof(&["cache", "prune", "--max-size", "0"]);
    assert!(o.status.success(), "{}", text(&o));
    let out = String::from_utf8_lossy(&o.stdout).into_owned();
    assert!(
        out.contains(&format!("kept held: in use by pid {}", sleeper.pid())),
        "{out}"
    );
    assert!(f.has("held") && !f.has("stale"), "{out}");
}

#[test]
fn work_directories_of_dead_processes_go_and_those_of_live_ones_stay() {
    let f = Fixture::new();
    let sleeper = Sleeper::start();
    let work = f.root.join("deps-work");
    let (dead, live) = (
        format!("{}-1700000000000", dead_pid()),
        format!("{}-1700000000001", sleeper.pid()),
    );
    for name in [&dead, &live] {
        fs::create_dir_all(work.join(name).join("tree")).unwrap();
    }
    let o = f.cowproof(&["cache", "prune"]);
    assert!(o.status.success(), "{}", text(&o));
    assert!(!work.join(&dead).exists());
    assert!(work.join(&live).join("tree").is_dir());
}

#[test]
fn a_cache_root_of_slash_or_the_home_directory_is_refused() {
    let f = Fixture::new();
    fs::create_dir_all(f.home.join("deps/victim")).unwrap();
    // (An empty COWPROOF_CACHE_ROOT means "unset": the default under HOME. The library
    // refuses an empty root itself, see the unit test.)
    for root in [Path::new("/"), f.home.as_path()] {
        for args in [&["cache", "prune", "--older-than", "0"][..], &["cache"][..]] {
            let o = f.cowproof_in(root, args);
            assert!(
                !o.status.success(),
                "root {:?} {args:?} was accepted: {}",
                root,
                text(&o)
            );
        }
    }
    assert!(f.home.join("deps/victim").is_dir());
}

#[test]
fn a_symlinked_entry_is_removed_as_a_link_and_its_target_survives() {
    let f = Fixture::new();
    let outside = f._tmp.path().join("outside");
    fs::create_dir_all(&outside).unwrap();
    fs::write(outside.join("precious"), vec![b'p'; 4000]).unwrap();
    std::os::unix::fs::symlink(&outside, f.root.join("deps/linked")).unwrap();
    let o = f.cowproof(&["cache"]);
    assert!(
        String::from_utf8_lossy(&o.stdout).contains("(0 bytes)") || {
            String::from_utf8_lossy(&o.stdout).contains("total size: 0 bytes")
        },
        "{}",
        text(&o)
    );
    let o = f.cowproof(&["cache", "prune", "--older-than", "0"]);
    assert!(o.status.success(), "{}", text(&o));
    assert!(!f.has("linked"));
    assert_eq!(fs::read(outside.join("precious")).unwrap().len(), 4000);
}
