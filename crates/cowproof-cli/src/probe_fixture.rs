//! Test support for the `--version` probes: a fake tool whose `--version` backgrounds a child
//! and then sleeps far longer than any probe timeout, and the checks that, after the probe
//! gave up, neither the fake nor its child is left running.

use cowproof_prove::runner::{group_exists, pid_exists, signal_group, signal_pid};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// Linux refuses to exec a file some process holds open for writing (ETXTBSY), and a fork on
/// another test thread can inherit that handle. A test that writes an executable and runs it
/// holds this lock for its whole length.
static FORK_LOCK: Mutex<()> = Mutex::new(());

pub(crate) struct HangingTool {
    _guard: MutexGuard<'static, ()>,
    _dir: tempfile::TempDir,
    bin: PathBuf,
    leader_file: PathBuf,
    child_file: PathBuf,
}

impl HangingTool {
    /// A tool named `name` in a directory under `/var/tmp`. Its `--version` writes its own pid
    /// to `leader.pid`, starts `sleep 120` in the background (pid in `child.pid`) and then
    /// sleeps 120 s itself. The sleeps end by themselves if a test fails.
    pub(crate) fn new(name: &str) -> HangingTool {
        let guard = FORK_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::Builder::new()
            .prefix("cp-probe-")
            .tempdir_in("/var/tmp")
            .unwrap();
        let (leader_file, child_file) =
            (dir.path().join("leader.pid"), dir.path().join("child.pid"));
        let bin = dir.path().join(name);
        let script = format!(
            "#!/bin/sh\n\
             if [ \"$1\" = \"--version\" ]; then\n\
             echo $$ > '{leader}.tmp' && mv '{leader}.tmp' '{leader}'\n\
             sleep 120 &\n\
             echo $! > '{child}.tmp' && mv '{child}.tmp' '{child}'\n\
             sleep 120\n\
             fi\n",
            leader = leader_file.display(),
            child = child_file.display(),
        );
        fs::write(&bin, script).unwrap();
        fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).unwrap();
        // The first run of a new executable can take seconds (macOS scans it); run it once,
        // harmlessly, so a timed probe measures the probe and not the scan.
        let warmed = std::process::Command::new(&bin)
            .arg("warm")
            .status()
            .unwrap();
        assert!(warmed.success());
        HangingTool {
            _guard: guard,
            _dir: dir,
            bin,
            leader_file,
            child_file,
        }
    }

    pub(crate) fn bin(&self) -> &Path {
        &self.bin
    }

    pub(crate) fn dir(&self) -> &Path {
        self._dir.path()
    }

    fn pid(file: &Path) -> Option<u32> {
        fs::read_to_string(file).ok()?.trim().parse().ok()
    }

    /// The pids the fake recorded (leader, background child). Both must exist: the probe ran
    /// the tool and it got as far as backgrounding its child.
    fn pids(&self) -> (u32, u32) {
        (
            Self::pid(&self.leader_file).expect("the fake recorded its pid"),
            Self::pid(&self.child_file).expect("the fake recorded its child's pid"),
        )
    }

    /// After the probe returned: the fake's group (the fake leads it) and its background child
    /// are both gone within `within`. The leader is the group's pgid because the probe runs it
    /// as a group leader.
    pub(crate) fn assert_all_ended(&self, within: Duration) {
        let (leader, child) = self.pids();
        let deadline = Instant::now() + within;
        let gone = |leader: u32, child: u32| {
            group_exists(leader) == Some(false) && pid_exists(child) == Some(false)
        };
        while !gone(leader, child) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        let leader_group_gone = group_exists(leader) == Some(false);
        let child_gone = pid_exists(child) == Some(false);
        assert!(
            leader_group_gone,
            "the probe's group {leader} is still running {within:?} after the probe returned"
        );
        assert!(
            child_gone,
            "the fake's background child {child} is still running {within:?} after the probe returned"
        );
    }
}

impl Drop for HangingTool {
    /// A test that failed must not leave the fake running. Only then, and only the pids this
    /// fake wrote seconds ago: a passed test has nothing to signal, and its pids may be reused.
    fn drop(&mut self) {
        if std::thread::panicking() {
            if let Some(leader) = Self::pid(&self.leader_file) {
                signal_group(leader, libc::SIGKILL);
            }
            if let Some(child) = Self::pid(&self.child_file) {
                signal_pid(child, libc::SIGKILL);
            }
        }
    }
}
