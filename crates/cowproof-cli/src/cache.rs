//! `cowproof cache`: the dependency cache at a glance (`ls`, the default) and its upkeep
//! (`prune`). The logic lives in `cowproof_run::cache`; this is the command line.

use anyhow::{Result, anyhow, bail};
use cowproof_prove::runner::pid_exists;
use cowproof_run::cache::{self, PruneOptions, PruneReport, Reason};
use cowproof_run::deps;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(clap::Args)]
pub struct CacheArgs {
    #[command(subcommand)]
    pub command: Option<CacheAction>,
}

#[derive(clap::Subcommand)]
pub enum CacheAction {
    /// The cache's total size, entry count and oldest last use (what `cowproof cache` alone prints)
    Ls,
    /// Remove cache entries that have not been used lately, and stale work directories
    ///
    /// An entry's last use is the last time a fetch hit it or a verifier was handed it.
    /// Entries unused for `--older-than` days go; with `--max-size`, least recently used
    /// entries then go until the cache fits. An entry a live `cowproof` holds a lease on
    /// is never removed, however old; a lease whose process is gone protects nothing.
    /// Directories left in `deps-work/` by a process that is gone are removed too. The cache
    /// root is `~/.cache/cowproof`, or `$COWPROOF_CACHE_ROOT`; a root that is `/` or the
    /// home directory is refused.
    Prune(PruneArgs),
}

#[derive(clap::Args)]
pub struct PruneArgs {
    /// Remove entries not used for this many days
    #[arg(long, value_name = "DAYS", default_value_t = 30)]
    pub older_than: u64,
    /// Then remove least recently used entries until the cache is at most this many GiB
    #[arg(long, value_name = "GIB")]
    pub max_size: Option<f64>,
    /// List what would be removed, and the bytes, and remove nothing
    #[arg(long)]
    pub dry_run: bool,
}

/// Whether a process is alive; "cannot tell" counts as alive.
pub(crate) fn alive(pid: u32) -> bool {
    pid_exists(pid) != Some(false)
}

/// Run the command; the return value is the exit code.
pub fn run(args: CacheArgs) -> Result<i32> {
    let home = PathBuf::from(std::env::var_os("HOME").ok_or_else(|| anyhow!("HOME is not set"))?);
    let root = deps::cache_root(&home);
    let now = SystemTime::now();
    match args.command.unwrap_or(CacheAction::Ls) {
        CacheAction::Ls => {
            let o = cache::overview(&root, &home, &alive)?;
            println!("{}", ls_text(&root, &o, now));
            Ok(0)
        }
        CacheAction::Prune(p) => {
            let max_bytes = match p.max_size {
                None => None,
                Some(gib) if gib.is_finite() && gib >= 0.0 => {
                    Some((gib * 1024.0 * 1024.0 * 1024.0) as u64)
                }
                Some(gib) => bail!("--max-size must be a number of GiB, 0 or more, not {gib}"),
            };
            let opts = PruneOptions {
                older_than: Duration::from_secs(p.older_than.saturating_mul(86_400)),
                max_bytes,
                dry_run: p.dry_run,
                now,
            };
            let report = cache::prune(&root, &home, &opts, &alive)?;
            println!("{}", prune_text(&root, &report, now));
            Ok(i32::from(!report.failed.is_empty()))
        }
    }
}

fn ls_text(root: &std::path::Path, o: &cache::Overview, now: SystemTime) -> String {
    let oldest = match o.oldest {
        Some(t) => format!("{} ({})", utc(t), ago(t, now)),
        None => "none".to_string(),
    };
    format!(
        "cache root: {}\nentries: {}\ntotal size: {}\noldest last use: {oldest}",
        root.display(),
        o.entries,
        size(o.bytes)
    )
}

fn prune_text(root: &std::path::Path, r: &PruneReport, now: SystemTime) -> String {
    let (go, tense) = if r.dry_run {
        ("would remove", "would be freed")
    } else {
        ("removed", "freed")
    };
    let mut out = vec![format!("cache root: {}", root.display())];
    for e in &r.removed {
        let why = match e.reason {
            Reason::Age => "not used lately",
            Reason::Size => "over the size limit",
        };
        out.push(format!(
            "{go} {}  {}  last used {} ({}; {why})",
            e.key,
            size(e.bytes),
            utc(e.last_used),
            ago(e.last_used, now)
        ));
    }
    for (key, pids) in &r.in_use {
        let pids: Vec<_> = pids.iter().map(u32::to_string).collect();
        out.push(format!("kept {key}: in use by pid {}", pids.join(", ")));
    }
    for name in &r.work_removed {
        out.push(format!(
            "{go} work directory deps-work/{name}: its process is gone"
        ));
    }
    for name in &r.work_kept {
        out.push(format!(
            "kept work directory deps-work/{name}: its process is alive"
        ));
    }
    for (key, why) in &r.failed {
        out.push(format!("could not remove {key}: {why}"));
    }
    out.push(format!(
        "{go} {} of {} entries, {} work directories; {} {tense}",
        r.removed.len(),
        r.entries_total,
        r.work_removed.len(),
        size(r.bytes_freed())
    ));
    out.join("\n")
}

/// `1.5 GiB (1610612736 bytes)`.
fn size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} bytes")
    } else {
        format!("{value:.1} {} ({bytes} bytes)", UNITS[unit])
    }
}

fn ago(t: SystemTime, now: SystemTime) -> String {
    let secs = now.duration_since(t).unwrap_or_default().as_secs();
    match secs {
        0..=3599 => "less than an hour ago".to_string(),
        3600..=86_399 => format!("{} hours ago", secs / 3600),
        _ => format!("{} days ago", secs / 86_400),
    }
}

/// `2026-09-01 12:30 UTC`.
fn utc(t: SystemTime) -> String {
    let secs = t
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    // Days since 1970-01-01 to a civil date (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02} UTC",
        rem / 3600,
        rem % 3600 / 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_time_prints_as_a_utc_date() {
        let at = |s: u64| UNIX_EPOCH + Duration::from_secs(s);
        assert_eq!(utc(at(0)), "1970-01-01 00:00 UTC");
        assert_eq!(
            utc(at(951_782_400 + 3600 * 12 + 60 * 30)),
            "2000-02-29 12:30 UTC"
        );
        assert_eq!(utc(at(1_788_265_800)), "2026-09-01 12:30 UTC");
    }

    #[test]
    fn sizes_and_ages_read_plainly() {
        assert_eq!(size(12), "12 bytes");
        assert_eq!(size(1_610_612_736), "1.5 GiB (1610612736 bytes)");
        let now = UNIX_EPOCH + Duration::from_secs(10 * 86_400);
        assert_eq!(ago(UNIX_EPOCH, now), "10 days ago");
        assert_eq!(ago(now - Duration::from_secs(7200), now), "2 hours ago");
        assert_eq!(ago(now, now), "less than an hour ago");
    }
}
