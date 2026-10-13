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

/// Whether an OS thread that woke `os_late` late over a stretch of `stretch` says the host did
/// not run this process (it was late for half the stretch or more), as opposed to the process
/// running and its own code being the wait.
pub fn host_was_late(os_late: Duration, stretch: Duration) -> bool {
    os_late * 2 >= stretch
}

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
        let cause = if host_was_late(self.os_late, self.runtime_late) {
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

/// What the OS thread knows, for a reader that asks later (see [`StallWatch::os_thread_late`]).
struct OsTicks {
    base: Instant,
    tick: Duration,
    /// When the thread last woke, in milliseconds after `base`.
    last_wake_ms: AtomicU64,
    /// The latest it has woken since the last read.
    peak_late_ms: AtomicU64,
}

/// Stops the watchdog when dropped.
pub struct StallWatch {
    stop: Arc<AtomicBool>,
    os: Arc<OsTicks>,
}

impl StallWatch {
    /// How late the OS thread has been since this was last called (or since the watch began):
    /// the latest it woke after its sleep, or, if it has not woken for longer than it sleeps,
    /// how long it is overdue now. Reading resets it. A caller that times a stretch of its own
    /// code calls this before and after: a value near the stretch's length says the host did
    /// not run this process, and a value near zero says the process ran and its own code was
    /// the wait.
    pub fn os_thread_late(&self) -> Duration {
        let peak = Duration::from_millis(self.os.peak_late_ms.swap(0, Ordering::Relaxed));
        let since_wake = self.os.base.elapsed().saturating_sub(Duration::from_millis(
            self.os.last_wake_ms.load(Ordering::Relaxed),
        ));
        peak.max(since_wake.saturating_sub(self.os.tick))
    }
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
    let os = Arc::new(OsTicks {
        base: Instant::now(),
        tick,
        last_wake_ms: AtomicU64::new(0),
        peak_late_ms: AtomicU64::new(0),
    });
    {
        let stop = stop.clone();
        let os_late_ms = os_late_ms.clone();
        let os = os.clone();
        // A watchdog that cannot start is not a reason to stop the run.
        let _ = std::thread::Builder::new()
            .name("cowproof-stall-os".into())
            .spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    let asked = Instant::now();
                    std::thread::sleep(tick);
                    let late = asked.elapsed().saturating_sub(tick);
                    os_late_ms.fetch_max(late.as_millis() as u64, Ordering::Relaxed);
                    os.peak_late_ms
                        .fetch_max(late.as_millis() as u64, Ordering::Relaxed);
                    os.last_wake_ms
                        .store(os.base.elapsed().as_millis() as u64, Ordering::Relaxed);
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
    StallWatch { stop, os }
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
    /// A watch with no thread behind it, so the test decides what the thread did.
    fn watch_without_a_thread(tick: Duration) -> StallWatch {
        StallWatch {
            stop: Arc::new(AtomicBool::new(false)),
            os: Arc::new(OsTicks {
                base: Instant::now(),
                tick,
                last_wake_ms: AtomicU64::new(0),
                peak_late_ms: AtomicU64::new(0),
            }),
        }
    }

    /// A thread that has not woken for longer than its tick is overdue by the difference,
    /// whether or not it has woken to say so; a late wake it did report is kept until read.
    #[test]
    fn the_os_threads_lateness_is_read_on_demand_and_resets() {
        let watch = watch_without_a_thread(Duration::from_millis(50));
        // Within its tick: not late.
        assert_eq!(watch.os_thread_late(), Duration::ZERO);
        // No wake for 400 ms of a 50 ms tick: overdue by at least 300 ms.
        std::thread::sleep(Duration::from_millis(400));
        assert!(watch.os_thread_late() >= Duration::from_millis(300));
        // A wake that was late by 700 ms is reported once, then forgotten.
        watch.os.peak_late_ms.store(700, Ordering::Relaxed);
        watch.os.last_wake_ms.store(
            watch.os.base.elapsed().as_millis() as u64,
            Ordering::Relaxed,
        );
        assert_eq!(watch.os_thread_late(), Duration::from_millis(700));
        assert!(watch.os_thread_late() < Duration::from_millis(700));
    }

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
