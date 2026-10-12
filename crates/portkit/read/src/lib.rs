//! A reader that returns only what the caller does not already have.
//!
//! Measured motivation, from 878 local sessions: `sed -n 'A,Bp' file` accounts
//! for 397 calls and 1.83 MB, the largest single shell fingerprint. Those are
//! not repeats of identical ranges — keying on the exact `(path, start, end)`
//! tuple finds **zero**. They are *overlapping* ranges: 53 of 113 consecutive
//! pairs cover territory already sent. Tracking line coverage rather than
//! ranges recovers 4.9% of those bytes.
//!
//! Not a large number, and worth saying so. What it buys beyond the bytes is a
//! verified rewrite path — the machinery a bigger replacement can then ride on.

pub mod state;

pub use state::{gaps, intersect, merge, FileState, Interval, SessionState};

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// Content hash of a file, or `None` when it cannot be read.
///
/// blake3 rather than the cheap hash used elsewhere in portkit: a collision
/// here means claiming the caller holds current content when it does not, and
/// that failure is silent.
pub fn hash_file(path: &Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    Some(blake3::hash(&bytes).to_hex().to_string())
}

/// Where session state lives: `~/.portkit/read/`, never the working directory.
/// The directory only; see [`session_state_path`] for the file.
///
/// `PORTKIT_STATE_DIR` overrides it. That exists so tests can isolate — moving
/// state out of the working directory also moved it out of reach of a tempdir
/// — and it lets anyone put state somewhere other than home.
pub fn state_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("PORTKIT_STATE_DIR") {
        return PathBuf::from(dir);
    }
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join(".portkit")
        .join("read")
}

pub fn now_rfc3339() -> String {
    use time::format_description::well_known::Rfc3339;
    time::OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_default()
}

/// Run pk-read with the given arguments.
///
/// Usage: `pk-read [--range A:B] [--ls] [--full] [--compacted] <path>`
///
/// Session identity comes from `PORTKIT_SESSION`, set by whatever launches the
/// agent session (the cowproof runner sets it to the lane id). The compaction
/// hooks key the watermark on the same variable through
/// [`session_state_path`]. Without it all calls share one `default` session,
/// which a compaction invalidates like any other.
pub fn run(args: Vec<String>) -> ExitCode {
    run_to(args, &mut std::io::stdout().lock())
}

/// [`run`] with the output stream given, so a caller (a test, or the hook's
/// own tests) can read what `pk-read` would have printed.
pub fn run_to(args: Vec<String>, out: &mut dyn Write) -> ExitCode {
    if args.is_empty() {
        eprintln!("usage: pk-read [--range A:B] [--ls] [--full] [--compacted] <path>");
        return ExitCode::FAILURE;
    }

    let mut range: Option<Interval> = None;
    let mut ls = false;
    let mut full = false;
    let mut compacted = false;
    let mut path: Option<String> = None;

    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--range" => match it.next().and_then(|r| parse_range(r)) {
                Some(r) => range = Some(r),
                None => {
                    eprintln!("--range takes A:B");
                    return ExitCode::FAILURE;
                }
            },
            "--ls" => ls = true,
            "--full" => full = true,
            "--compacted" => compacted = true,
            other => path = Some(other.to_string()),
        }
    }

    let state_path = session_state_path();
    if compacted {
        let mut state = SessionState::load(&state_path);
        state.mark_compacted(now_rfc3339());
        let _ = state.save(&state_path);
        return ExitCode::SUCCESS;
    }

    let Some(path) = path else {
        eprintln!("a path is required");
        return ExitCode::FAILURE;
    };

    if ls {
        return list(Path::new(&path), out);
    }
    read(Path::new(&path), range, full, &state_path, out)
}

fn parse_range(s: &str) -> Option<Interval> {
    let (a, b) = s.split_once(':').or_else(|| s.split_once(','))?;
    Some((a.trim().parse().ok()?, b.trim().parse().ok()?))
}

/// Per-session state file for the session named by `PORTKIT_SESSION`.
///
/// The one place that decides where session state lives, for the reader and
/// for the hooks that write the compaction watermark. They must agree, or the
/// reader never sees the watermark and keeps answering UNCHANGED for a file the
/// caller no longer has in context. Falls back to a shared `default` session
/// when none is set, which costs a little precision and never correctness:
/// the hook then invalidates that shared session too.
pub fn session_state_path() -> PathBuf {
    let session = std::env::var("PORTKIT_SESSION").unwrap_or_else(|_| "default".into());
    session_state_path_for(&session)
}

/// The state file for a named session, under [`state_dir`]. The name is
/// reduced to letters, digits, `-` and `_` and cut at 48 characters, so it can
/// never name another directory.
pub fn session_state_path_for(session: &str) -> PathBuf {
    let safe: String = session
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
        .take(48)
        .collect();
    state_dir().join(format!("{safe}.json"))
}

fn read(
    path: &Path,
    range: Option<Interval>,
    full: bool,
    state_path: &Path,
    out: &mut dyn Write,
) -> ExitCode {
    let Ok(text) = std::fs::read_to_string(path) else {
        eprintln!("cannot read {}", path.display());
        return ExitCode::FAILURE;
    };
    let lines: Vec<&str> = text.lines().collect();
    let total = lines.len() as u32;
    let want: Interval = range.unwrap_or((1, total.max(1)));
    let want = (want.0.max(1), want.1.min(total.max(1)));

    let key = path.to_string_lossy().to_string();
    let Some(hash) = hash_file(path) else {
        return ExitCode::FAILURE;
    };
    let short = &hash[..hash.len().min(8)];

    let mut state = SessionState::load(state_path);

    // --full is the recovery path named in every partial answer; it must
    // ignore session state entirely or the recovery does not recover.
    let held: Vec<Interval> = if full {
        Vec::new()
    } else {
        state.covered(&key, want, &hash)
    };

    let missing = if full { vec![want] } else { gaps(&held, want) };

    if missing.is_empty() {
        // The caller has all of it, the file is unchanged, and the delivery
        // survives the last compaction.
        let _ = writeln!(
            out,
            "UNCHANGED L{}-{} sha:{short} (recover: pk-read --range {}:{} {} --full)",
            want.0,
            want.1,
            want.0,
            want.1,
            path.display()
        );
        return ExitCode::SUCCESS;
    }

    // Say what is being withheld, and how to get it, before the content.
    for (lo, hi) in intersect(&held, want) {
        let _ = writeln!(
            out,
            "KNOWN L{lo}-{hi} sha:{short} (recover: pk-read --range {lo}:{hi} {} --full)",
            path.display()
        );
    }

    for (lo, hi) in &missing {
        for n in *lo..=*hi {
            if let Some(line) = lines.get((n - 1) as usize) {
                let _ = writeln!(out, "{n}\u{2502}{line}");
            }
        }
        state.deliver(&key, (*lo, *hi), hash.clone(), now_rfc3339());
    }

    let _ = state.save(state_path);
    ExitCode::SUCCESS
}

/// `ls -la` without the columns nobody reads back.
fn list(path: &Path, out: &mut dyn Write) -> ExitCode {
    let Ok(entries) = std::fs::read_dir(path) else {
        eprintln!("cannot list {}", path.display());
        return ExitCode::FAILURE;
    };
    let mut rows: Vec<(String, u64, bool)> = entries
        .filter_map(Result::ok)
        .filter_map(|e| {
            let meta = e.metadata().ok()?;
            Some((
                e.file_name().to_string_lossy().to_string(),
                meta.len(),
                meta.is_dir(),
            ))
        })
        .collect();
    rows.sort();

    for (name, size, is_dir) in &rows {
        if *is_dir {
            let _ = writeln!(out, "{name}/");
        } else {
            let _ = writeln!(out, "{name}\t{size}");
        }
    }
    let _ = writeln!(out, "({} entries)", rows.len());
    ExitCode::SUCCESS
}
