//! A stopwatch for the steps of an exit, so a slow one names itself.
//!
//! A run that is signalled ends in a fixed order: the launcher's wait, the check groups, the
//! servers dropped, the remote host, then the socket removals and `run.json`. When that took
//! seconds on a loaded host the runner could say only how long the whole of it took
//! (`the interrupted run was recorded N ms after the SIGINT`), and the stall watchdog stayed
//! silent because the blocked thread was the one running `run_one`, not a worker. A
//! [`StepClock`] is read at the end of each step; [`StepClock::slow_line`] gives one line with
//! every step's time when the whole exit passed [`SLOW_EXIT`], and nothing when it did not.

use crate::hostload::Snapshot;
use std::time::{Duration, Instant};

/// An exit that takes longer than this prints its steps.
pub const SLOW_EXIT: Duration = Duration::from_secs(1);

/// The elapsed time of each step of an exit, from the moment the clock was started.
#[derive(Debug)]
pub struct StepClock {
    began: Instant,
    last: Instant,
    steps: Vec<(&'static str, Duration)>,
    /// The kernel's counters when the clock started, for what the host did over the exit.
    host: Snapshot,
}

impl StepClock {
    /// Start timing now.
    pub fn start() -> Self {
        Self::start_with(Snapshot::take())
    }

    /// [`start`](Self::start) with the host counters already read (the tests' fake host).
    pub fn start_with(host: Snapshot) -> Self {
        let now = Instant::now();
        StepClock {
            began: now,
            last: now,
            steps: Vec::new(),
            host,
        }
    }

    /// A step ends here: record `name` with the time since the previous step ended (or since
    /// the clock started, for the first).
    pub fn mark(&mut self, name: &'static str) {
        let now = Instant::now();
        self.steps
            .push((name, now.saturating_duration_since(self.last)));
        self.last = now;
    }

    /// Run `step` and [`mark`](Self::mark) it as `name`. The step is timed from the previous
    /// mark, so the code between the two marks counts as part of it.
    pub fn time<T>(&mut self, name: &'static str, step: impl FnOnce() -> T) -> T {
        let result = step();
        self.mark(name);
        result
    }

    /// Time since the clock started.
    pub fn elapsed(&self) -> Duration {
        self.began.elapsed()
    }

    /// The recorded steps, in order.
    pub fn steps(&self) -> &[(&'static str, Duration)] {
        &self.steps
    }

    /// The line to print when the whole exit took more than `threshold`, else `None`. It ends
    /// with the host's counters over the exit ([`Snapshot::since_waiting`], the same sentence
    /// the director's lines carry), when the kernel exposes any.
    pub fn slow_line(&self, threshold: Duration) -> Option<String> {
        self.slow_line_at(threshold, &Snapshot::take())
    }

    /// [`slow_line`](Self::slow_line) with the counters as they are now given by the caller.
    pub fn slow_line_at(&self, threshold: Duration, now: &Snapshot) -> Option<String> {
        let total = self.elapsed();
        (total > threshold).then(|| {
            let mut line = describe(total, &self.steps);
            let host = now.since_waiting(&self.host, total);
            if !host.is_empty() {
                line.push_str("; ");
                line.push_str(&host);
            }
            line
        })
    }
}

/// The line for an exit of `total` made of `steps`. Pure, so the format is tested without a
/// clock.
pub fn describe(total: Duration, steps: &[(&'static str, Duration)]) -> String {
    let listed = steps
        .iter()
        .map(|(name, took)| format!("{name} {} ms", took.as_millis()))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "slow exit: ending the run took {} ms; steps: {listed}",
        total.as_millis()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_line_names_every_step_with_its_time() {
        let ms = Duration::from_millis;
        let line = describe(
            ms(8480),
            &[
                ("raise", ms(0)),
                ("remove tools socket", ms(8470)),
                ("write run.json", ms(10)),
            ],
        );
        assert_eq!(
            line,
            "slow exit: ending the run took 8480 ms; steps: raise 0 ms, \
             remove tools socket 8470 ms, write run.json 10 ms"
        );
    }

    /// The host's counters over the exit come from `hostload`, not a second reader: a fake
    /// `/proc` whose io pressure grew by 7 s while the exit ran is in the line.
    #[test]
    fn the_line_ends_with_the_hosts_counters_over_the_exit() {
        use std::fs;
        let tmp = tempfile::tempdir().unwrap();
        let proc_root = tmp.path().join("proc");
        let cgroup = tmp.path().join("cgroup");
        fs::create_dir_all(proc_root.join("pressure")).unwrap();
        fs::create_dir_all(&cgroup).unwrap();
        fs::write(proc_root.join("loadavg"), "12.50 9.10 4.00 3/900 1234\n").unwrap();
        let io = |total: u64| {
            fs::write(
                proc_root.join("pressure/io"),
                format!(
                    "some avg10=0.00 avg60=0.00 avg300=0.00 total={total}\n\
                     full avg10=0.00 avg60=0.00 avg300=0.00 total={total}\n"
                ),
            )
            .unwrap();
        };
        io(1_000_000);
        let mut clock = StepClock::start_with(Snapshot::take_from(&proc_root, &cgroup));
        clock.time("slow", || std::thread::sleep(Duration::from_millis(60)));
        io(8_000_000);
        let line = clock
            .slow_line_at(
                Duration::from_millis(10),
                &Snapshot::take_from(&proc_root, &cgroup),
            )
            .expect("slow");
        assert!(line.contains("slow "), "{line}");
        assert!(line.contains("; host, over "), "{line}");
        assert!(line.contains("io 7000 ms (all tasks 7000 ms)"), "{line}");
        assert!(line.contains("load average 12.50 9.10 4.00"), "{line}");
        // A host that exposes nothing adds nothing.
        let bare = StepClock::start_with(Snapshot::default());
        std::thread::sleep(Duration::from_millis(20));
        let line = bare
            .slow_line_at(Duration::from_millis(5), &Snapshot::default())
            .unwrap();
        assert!(!line.contains("host,"), "{line}");
    }

    #[test]
    fn a_fast_exit_has_no_line() {
        let mut clock = StepClock::start();
        clock.mark("one");
        clock.mark("two");
        assert_eq!(clock.slow_line(Duration::from_secs(30)), None);
        assert_eq!(clock.steps().len(), 2);
    }

    #[test]
    fn a_slow_step_is_measured_and_makes_the_line() {
        let mut clock = StepClock::start();
        clock.mark("quick");
        clock.time("slow", || std::thread::sleep(Duration::from_millis(120)));
        let (name, took) = clock.steps()[1];
        assert_eq!(name, "slow");
        assert!(took >= Duration::from_millis(120), "{took:?}");
        let line = clock
            .slow_line(Duration::from_millis(100))
            .expect("the exit passed the threshold");
        assert!(line.contains("quick "), "{line}");
        assert!(line.contains("slow "), "{line}");
        // Steps are consecutive: their times add up to no more than the total.
        let summed: Duration = clock.steps().iter().map(|(_, d)| *d).sum();
        assert!(summed <= clock.elapsed());
    }
}
