//! A watchdog that says why the runner answered late.
//!
//! The director reaches a lane over `director.sock` and gives up after ten seconds. When a
//! run's host is overloaded, "the lane did not answer" cannot be told apart from a runner
//! whose async runtime was blocked by its own code. This module measures both, so a late
//! answer explains itself:
//!
//! - an OS thread sleeps for [`TICK`] over and over and notes how late it wakes (the host
//!   did not run this process, or ran it late);
//! - a task on the runner's runtime does the same with `tokio::time::sleep` (the runtime's
//!   workers were busy or blocked).
//!
//! When the task is [`THRESHOLD`] or more late, one line goes to stderr with both numbers. A
//! runtime late while the OS thread was not is a blocked runtime (a defect in the runner);
//! both late is a starved host.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// How often each clock is read.
pub const TICK: Duration = Duration::from_millis(100);

/// How late the runtime's tick must be before a stall is reported.
pub const THRESHOLD: Duration = Duration::from_millis(1500);

/// One late tick of the runtime, with how late the OS thread was over the same time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stall {
    /// How much later than asked a task on the runtime woke.
    pub runtime_late: Duration,
    /// The latest an OS thread woke over that time (zero when it was on time).
    pub os_late: Duration,
}

impl Stall {
    /// The line the runner prints.
    pub fn describe(&self) -> String {
        self.describe_for("runner")
    }

    /// The same line for another watcher (`who` is "runner", "director thread", ...).
    pub fn describe_for(&self, who: &str) -> String {
        let cause = if self.os_late * 2 >= self.runtime_late {
            "the host did not run this process"
        } else {
            "the runner's runtime was blocked while the host was not"
        };
        format!(
            "{who} stall: a task on the async runtime woke {} ms late; an OS thread woke {} ms late over the same time ({cause})",
            self.runtime_late.as_millis(),
            self.os_late.as_millis()
        )
    }
}

/// Stops the watchdog when dropped.
pub struct StallWatch {
    stop: Arc<AtomicBool>,
}

impl Drop for StallWatch {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// Watch the runtime this is called in until the returned guard is dropped. `report` is
/// called, on the runtime's own task, with every stall of [`THRESHOLD`] or more.
pub fn watch(report: impl Fn(Stall) + Send + 'static) -> StallWatch {
    watch_with(TICK, THRESHOLD, report)
}

/// [`watch`] with its own tick and threshold (tests use short ones).
pub fn watch_with(
    tick: Duration,
    threshold: Duration,
    report: impl Fn(Stall) + Send + 'static,
) -> StallWatch {
    let stop = Arc::new(AtomicBool::new(false));
    let os_late_ms = Arc::new(AtomicU64::new(0));
    {
        let stop = stop.clone();
        let os_late_ms = os_late_ms.clone();
        // A watchdog that cannot start is not a reason to stop the run.
        let _ = std::thread::Builder::new()
            .name("cowproof-stall-os".into())
            .spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    let asked = Instant::now();
                    std::thread::sleep(tick);
                    let late = asked.elapsed().saturating_sub(tick);
                    os_late_ms.fetch_max(late.as_millis() as u64, Ordering::Relaxed);
                }
            });
    }
    let flag = stop.clone();
    tokio::spawn(async move {
        while !flag.load(Ordering::Relaxed) {
            let asked = Instant::now();
            tokio::time::sleep(tick).await;
            let late = asked.elapsed().saturating_sub(tick);
            // Read and reset the OS thread's worst lateness for the window just ended.
            let os_late = Duration::from_millis(os_late_ms.swap(0, Ordering::Relaxed));
            if late >= threshold {
                report(Stall {
                    runtime_late: late,
                    os_late,
                });
            }
        }
    });
    StallWatch { stop }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[test]
    fn the_line_names_whose_clock_stalled() {
        let ms = Duration::from_millis;
        let blocked = Stall {
            runtime_late: ms(4000),
            os_late: ms(10),
        };
        assert!(blocked.describe().contains("runtime was blocked"));
        assert!(blocked.describe().contains("4000 ms late"));
        let starved = Stall {
            runtime_late: ms(4000),
            os_late: ms(3900),
        };
        assert!(starved.describe().contains("host did not run this process"));
    }

    /// A task that blocks the runtime's only worker for 2.5 s is reported as a blocked
    /// runtime: the task on the runtime woke at least two seconds late while the OS thread
    /// (which nothing blocked) did not.
    #[test]
    fn a_blocked_runtime_is_reported_with_the_os_thread_on_time() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let seen: Arc<Mutex<Vec<Stall>>> = Arc::default();
        let sink = seen.clone();
        rt.block_on(async {
            let _watch = watch_with(
                Duration::from_millis(50),
                Duration::from_millis(1000),
                move |s| sink.lock().unwrap().push(s),
            );
            // Let the watchdog's task start its first sleep on the worker.
            tokio::time::sleep(Duration::from_millis(200)).await;
            tokio::spawn(async {
                std::thread::sleep(Duration::from_millis(2500));
            })
            .await
            .unwrap();
            tokio::time::sleep(Duration::from_millis(300)).await;
        });
        let seen = seen.lock().unwrap();
        assert!(!seen.is_empty(), "no stall was reported");
        assert!(
            seen.iter()
                .any(|s| s.runtime_late >= Duration::from_millis(2000)),
            "{seen:?}"
        );
    }
}
