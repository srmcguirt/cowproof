//! What the host was doing while something waited, for the message that says it waited.
//!
//! "The lane did not answer within 10 s" has two very different causes: the runner held the
//! answer back, or the machine did not run the runner (or the director's own process) for
//! seconds. The stall watchdog ([`crate::stall`]) sees a late timer; this sees *why* the
//! machine was late, on Linux, from the kernel's own counters:
//!
//! - pressure stall information (`cpu`, `memory`, `io`): the cumulative microseconds some or
//!   all tasks were stalled waiting for that resource, from the cgroup's files when they exist
//!   and from `/proc/pressure` otherwise;
//! - the cgroup's CPU throttling (`cpu.stat`: how long its quota held its tasks back);
//! - the load average.
//!
//! The pressure and throttling counters only grow, so a [`Snapshot`] taken before a wait and
//! one taken after it say how much of the wait the kernel spent stalling this container.
//! Off Linux (or where the files are absent) nothing is readable and every sentence is empty.

use std::path::Path;
use std::time::Duration;

/// One resource's pressure stall totals, in microseconds.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Pressure {
    /// Time at least one task was stalled.
    some: Option<u64>,
    /// Time every task was stalled.
    full: Option<u64>,
}

/// The kernel's stall counters at one moment.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Snapshot {
    cpu: Pressure,
    memory: Pressure,
    io: Pressure,
    /// Times the cgroup's CPU quota held its tasks back, and for how long (microseconds).
    nr_throttled: Option<u64>,
    throttled_us: Option<u64>,
    /// The first three fields of `/proc/loadavg`.
    load: Option<String>,
}

/// `total=` of the `some` and `full` lines of a pressure file.
fn parse_pressure(text: &str) -> Pressure {
    let mut out = Pressure::default();
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let kind = fields.next();
        let total = fields
            .find_map(|f| f.strip_prefix("total="))
            .and_then(|v| v.parse::<u64>().ok());
        match kind {
            Some("some") => out.some = total,
            Some("full") => out.full = total,
            _ => {}
        }
    }
    out
}

/// `(nr_throttled, throttled microseconds)` from a cgroup's `cpu.stat`, v2 or v1.
fn parse_cpu_stat(text: &str) -> (Option<u64>, Option<u64>) {
    let mut count = None;
    let mut micros = None;
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let (Some(key), Some(value)) = (fields.next(), fields.next()) else {
            continue;
        };
        let Ok(value) = value.parse::<u64>() else {
            continue;
        };
        match key {
            "nr_throttled" => count = Some(value),
            "throttled_usec" => micros = Some(value),
            // cgroup v1 counts nanoseconds.
            "throttled_time" => micros = micros.or(Some(value / 1000)),
            _ => {}
        }
    }
    (count, micros)
}

fn read(path: &Path) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

fn pressure_of(name: &str, proc_root: &Path, cgroup_root: &Path) -> Pressure {
    read(&cgroup_root.join(format!("{name}.pressure")))
        .or_else(|| read(&proc_root.join("pressure").join(name)))
        .map(|text| parse_pressure(&text))
        .unwrap_or_default()
}

impl Snapshot {
    /// The counters now, from `/proc` and `/sys/fs/cgroup`.
    pub fn take() -> Snapshot {
        Snapshot::take_from(Path::new("/proc"), Path::new("/sys/fs/cgroup"))
    }

    /// [`Snapshot::take`] from other roots (the tests' fake `/proc` and cgroup).
    pub fn take_from(proc_root: &Path, cgroup_root: &Path) -> Snapshot {
        let (nr_throttled, throttled_us) = read(&cgroup_root.join("cpu.stat"))
            .or_else(|| read(&cgroup_root.join("cpu").join("cpu.stat")))
            .map(|text| parse_cpu_stat(&text))
            .unwrap_or((None, None));
        let load = read(&proc_root.join("loadavg")).map(|text| {
            text.split_whitespace()
                .take(3)
                .collect::<Vec<_>>()
                .join(" ")
        });
        Snapshot {
            cpu: pressure_of("cpu", proc_root, cgroup_root),
            memory: pressure_of("memory", proc_root, cgroup_root),
            io: pressure_of("io", proc_root, cgroup_root),
            nr_throttled,
            throttled_us,
            load: load.filter(|l| !l.is_empty()),
        }
    }

    /// One sentence on what the kernel did between `earlier` and `self`; empty when it
    /// exposes no counters here.
    pub fn since(&self, earlier: &Snapshot) -> String {
        let ms = |now: Option<u64>, then: Option<u64>| -> Option<u64> {
            Some(now?.saturating_sub(then?) / 1000)
        };
        let mut parts: Vec<String> = Vec::new();
        for (name, now, then) in [
            ("cpu", self.cpu, earlier.cpu),
            ("memory", self.memory, earlier.memory),
            ("io", self.io, earlier.io),
        ] {
            let some = ms(now.some, then.some);
            let full = ms(now.full, then.full);
            parts.push(match (some, full) {
                (Some(some), Some(full)) => {
                    format!("{name} {some} ms (all tasks {full} ms)")
                }
                (Some(some), None) => format!("{name} {some} ms"),
                (None, Some(full)) => format!("{name} (all tasks) {full} ms"),
                (None, None) => continue,
            });
        }
        let mut sentence = if parts.is_empty() {
            String::new()
        } else {
            format!("kernel stall time over the wait: {}", parts.join(", "))
        };
        if let (Some(count), Some(micros)) = (
            self.nr_throttled
                .zip(earlier.nr_throttled)
                .map(|(now, then)| now.saturating_sub(then)),
            ms(self.throttled_us, earlier.throttled_us),
        ) {
            if !sentence.is_empty() {
                sentence.push_str("; ");
            }
            sentence.push_str(&format!(
                "the container's CPU quota held it back {count} times for {micros} ms"
            ));
        }
        if let Some(load) = &self.load {
            if !sentence.is_empty() {
                sentence.push_str("; ");
            }
            sentence.push_str(&format!("load average {load}"));
        }
        sentence
    }

    /// [`Snapshot::since`] for a wait of `waited`, with that length said first.
    pub fn since_waiting(&self, earlier: &Snapshot, waited: Duration) -> String {
        let sentence = self.since(earlier);
        if sentence.is_empty() {
            return sentence;
        }
        format!("host, over {} ms: {sentence}", waited.as_millis())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    const PSI: &str = "some avg10=0.00 avg60=0.00 avg300=0.00 total=";

    fn fake_host(root: &Path, cpu: u64, memory: (u64, u64), throttled: (u64, u64)) {
        let proc_root = root.join("proc");
        let cgroup = root.join("cgroup");
        fs::create_dir_all(proc_root.join("pressure")).unwrap();
        fs::create_dir_all(&cgroup).unwrap();
        fs::write(proc_root.join("loadavg"), "12.50 9.10 4.00 3/900 1234\n").unwrap();
        fs::write(proc_root.join("pressure/cpu"), format!("{PSI}{cpu}\n")).unwrap();
        // The cgroup's own file wins over /proc's.
        fs::write(
            cgroup.join("memory.pressure"),
            format!(
                "{PSI}{}\nfull avg10=0.00 avg60=0.00 avg300=0.00 total={}\n",
                memory.0, memory.1
            ),
        )
        .unwrap();
        fs::write(
            proc_root.join("pressure/memory"),
            format!("{PSI}999999999\n"),
        )
        .unwrap();
        fs::write(
            cgroup.join("cpu.stat"),
            format!(
                "usage_usec 1\nnr_periods 5\nnr_throttled {}\nthrottled_usec {}\n",
                throttled.0, throttled.1
            ),
        )
        .unwrap();
    }

    fn tmp() -> tempfile::TempDir {
        tempfile::Builder::new().tempdir_in("/var/tmp").unwrap()
    }

    #[test]
    fn the_sentence_is_the_difference_between_two_snapshots() {
        let root = tmp();
        let (p, c) = (root.path().join("proc"), root.path().join("cgroup"));
        fake_host(root.path(), 1_000_000, (2_000_000, 500_000), (3, 100_000));
        let before = Snapshot::take_from(&p, &c);
        fake_host(
            root.path(),
            1_250_000,
            (10_400_000, 8_500_000),
            (7, 2_400_000),
        );
        let after = Snapshot::take_from(&p, &c);
        let said = after.since_waiting(&before, Duration::from_secs(10));
        assert!(said.starts_with("host, over 10000 ms: "), "{said}");
        assert!(said.contains("cpu 250 ms"), "{said}");
        assert!(
            said.contains("memory 8400 ms (all tasks 8000 ms)"),
            "{said}"
        );
        // The cgroup's memory file was read, not /proc's 999999999.
        assert!(!said.contains("999999"), "{said}");
        assert!(said.contains("held it back 4 times for 2300 ms"), "{said}");
        assert!(said.contains("load average 12.50 9.10 4.00"), "{said}");
    }

    #[test]
    fn a_host_with_no_counters_says_nothing() {
        let root = tmp();
        let nothing = Snapshot::take_from(root.path(), root.path());
        assert_eq!(nothing, Snapshot::default());
        assert_eq!(nothing.since_waiting(&nothing, Duration::from_secs(10)), "");
    }

    #[test]
    fn cgroup_v1_throttling_is_read_in_nanoseconds() {
        assert_eq!(
            parse_cpu_stat("nr_periods 9\nnr_throttled 2\nthrottled_time 4000000\n"),
            (Some(2), Some(4000))
        );
        assert_eq!(parse_cpu_stat("garbage\nnr_throttled x\n"), (None, None));
    }

    #[test]
    fn the_real_host_is_readable_or_silent_never_a_panic() {
        let a = Snapshot::take();
        let b = Snapshot::take();
        let _ = b.since_waiting(&a, Duration::from_millis(1));
    }
}
