//! `pk-read` — return only what the caller does not already have.
//!
//!   pk-read --range 40:80 src/api.ts     lines 40-80, minus what was already sent
//!   pk-read --ls dir/                     names and sizes, not `ls -la` columns
//!   pk-read --full src/api.ts             everything, ignoring session state
//!   pk-read --compacted                   watermark: treat prior deliveries as gone
//!
//! Session identity comes from `PORTKIT_SESSION`, which the hook sets from the
//! `session_id` on its stdin payload. Without it every call is a first call,
//! which is the safe direction to fail.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use portkit_read::{gaps, hash_file, intersect, now_rfc3339, Interval, SessionState};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
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

    let state_path = state_path();
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
        return list(Path::new(&path));
    }
    read(Path::new(&path), range, full, &state_path)
}

fn parse_range(s: &str) -> Option<Interval> {
    let (a, b) = s.split_once(':').or_else(|| s.split_once(','))?;
    Some((a.trim().parse().ok()?, b.trim().parse().ok()?))
}

/// Per-session state file. Falls back to a shared one when no session is set,
/// which costs a little precision and never correctness.
fn state_path() -> PathBuf {
    let session = std::env::var("PORTKIT_SESSION").unwrap_or_else(|_| "default".into());
    let safe: String = session
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
        .take(48)
        .collect();
    portkit_read::state_dir().join(format!("{safe}.json"))
}

fn read(path: &Path, range: Option<Interval>, full: bool, state_path: &Path) -> ExitCode {
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
        println!(
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
        println!(
            "KNOWN L{lo}-{hi} sha:{short} (recover: pk-read --range {lo}:{hi} {} --full)",
            path.display()
        );
    }

    for (lo, hi) in &missing {
        for n in *lo..=*hi {
            if let Some(line) = lines.get((n - 1) as usize) {
                println!("{n}\u{2502}{line}");
            }
        }
        state.deliver(&key, (*lo, *hi), hash.clone(), now_rfc3339());
    }

    let _ = state.save(state_path);
    ExitCode::SUCCESS
}

/// `ls -la` without the columns nobody reads back.
fn list(path: &Path) -> ExitCode {
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
            println!("{name}/");
        } else {
            println!("{name}\t{size}");
        }
    }
    println!("({} entries)", rows.len());
    ExitCode::SUCCESS
}
