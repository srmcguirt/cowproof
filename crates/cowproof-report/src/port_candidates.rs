//! `cowproof report port-candidates <lanes-root>...`: which shell commands lanes run again
//! and again, ranked by how much they cost, and a draft `kind: port` packet for the top
//! ones (D23).
//!
//! # What is read
//!
//! Only portkit's trace files, `<lane>/portkit/traces/*.jsonl` (the lane's
//! `PORTKIT_STATE_DIR` is `<lane>/portkit` and `[trace] dir` resolves to `<state>/traces`,
//! G6). Each line is a `portkit_core::trace::CallRecord`. Nothing else in a lane is read,
//! and nothing is followed out of the root: a symlink for a lane, for its `portkit` or
//! `traces` directory or for a trace file is skipped and counted, exactly as the rollup
//! does. A line that is not a record is counted, not fatal.
//!
//! Only `Bash` calls observed through the hook (surface `agent`) are commands. The trace
//! keeps no arguments (`hook.rs` `target_of`, tested in `tests/hook.rs`): for `Bash` the
//! record's `target` is the first two whitespace-separated words of the command, cut at
//! 60 characters. That head is all a fingerprint can be made from.
//! A path that the trace's own cut lands inside keeps a partial last component, and
//! `cd dir && cmd` is `cd dir`: the trace cannot be read past its head.
//!
//! # The fingerprint
//!
//! A command's fingerprint is its program plus its stable arguments, from that head:
//!
//! 1. The head is redacted (`cowproof_core::redact`) and control characters become spaces,
//!    before anything else is done with it.
//! 2. Leading `NAME=value` words are environment assignments and are dropped whole: the
//!    name and the value never reach a fingerprint, an example or a draft.
//! 3. A word in quotes, or holding `://`, becomes `<str>` or `<url>`; any other word with
//!    `=` keeps the part before `=` when it is a flag (`--token=<v>`) and is `<kv>`
//!    otherwise, so a value after `=` is never kept; a word naming `.env`, `id_rsa`,
//!    `id_ed25519` or `credentials.json` becomes `<secret-file>`.
//! 4. The program keeps only the last component of its path (`/usr/bin/node` is `node`).
//! 5. A flag (a word starting with `-`) is kept as written. Any other argument that holds
//!    a `/` or starts with `~` is a path: a path under a temp directory (`/tmp`,
//!    `/var/tmp`, `/private/tmp`, `/var/folders`, `/private/var/folders`, `/dev/shm`)
//!    is `<tmp>`, any other keeps only its last component. So the same script run from
//!    two lane clones is one command, and so is a command on two temp files.
//! 6. In a non-flag argument, a UUID or a run of 7 to 64 hex digits holding a digit is
//!    `<id>`, a run of 3 or more digits is `<n>`, and an all-digit word is `<n>`.
//!
//! `portkit_core::rewrite::fingerprint` works on a whole command and is not reused: it
//! collapses an absolute path into `$P` even when it is the program, and it keeps
//! environment assignments, `=value` and numbers, which is what rule 2, 3 and 6 are for.
//!
//! # The score
//!
//! Per fingerprint: `calls`, the lanes it appeared in, the total and median wall time, and
//! the bytes delivered into context. Bytes into context exist: `delivered_bytes` is "what
//! actually reached the caller, the number context pays for"; for a hook record it equals
//! `produced_bytes`. Wall time does not exist for a hook record: the hook sees the result,
//! not the call, so `duration_ms` is `0.0` (`hook.rs` `record`). The report says so and
//! ranks by what it has.
//!
//! ```text
//! score = (calls / max calls) x (bytes / max bytes) x (time / max time)
//! ```
//!
//! where each maximum is over every candidate (a fingerprint with at least `min_calls`
//! calls), so no unit dominates and a factor is in `[0, 1]`. `time` is the fingerprint's
//! summed time with each call counting at least 1 ms, so a call with no measured time is
//! not free, and the factor is left out (1 for every candidate) when no candidate has any
//! measured time. Ties go to more calls, then more bytes, then the fingerprint.

use crate::rollup::{clip, median, wrap};
use crate::traces::{LaneState, read_lane_traces};
use anyhow::{Context, Result, bail};
use cowproof_core::redact;
use portkit_core::trace::{CallRecord, Surface};
use regex::Regex;
use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// The widest line `render` prints.
const WIDTH: usize = 80;
/// The most example invocations kept per fingerprint.
const MAX_EXAMPLES: usize = 3;
/// The longest text taken from a trace record, in characters, after redaction.
const MAX_TEXT: usize = 240;
/// The longest single word kept in a fingerprint or an example, in characters.
const MAX_WORD: usize = 48;
/// A call with no measured time counts as this many milliseconds in the score.
const MIN_CALL_MS: f64 = 1.0;
/// The widest lane id a draft packet can carry (`cowproof_core` allows 61).
const MAX_ID: usize = 48;

#[derive(Debug, Clone, Copy)]
pub struct Options {
    /// How many candidates to show.
    pub top: usize,
    /// A fingerprint run fewer times than this is not "again and again".
    pub min_calls: usize,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            top: 10,
            min_calls: 2,
        }
    }
}

/// Every directory entry and trace line examined lands in exactly one counter.
#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Counts {
    /// Lane directories and symlinks found one level under the roots.
    pub seen: usize,
    /// Lanes with at least one trace file read.
    pub lanes_traced: usize,
    /// Lanes with no `portkit/traces/*.jsonl` (Codex and OpenRouter lanes are untraced).
    pub lanes_untraced: usize,
    /// Symlinks skipped: a lane, its `portkit` or `traces` directory, or a trace file.
    pub symlinked: usize,
    /// Directories and files that could not be read, or were too large.
    pub unreadable: usize,
    pub trace_files: usize,
    /// Lines that parsed as records.
    pub records: usize,
    /// Lines that did not parse as records.
    pub malformed_lines: usize,
    /// Records that are not a command run through the hook (portkit's own tools, `Read`,
    /// `Grep`, and a `Bash` record with no usable head).
    pub not_commands: usize,
    /// `Bash` records counted toward a fingerprint.
    pub commands: usize,
    /// Distinct fingerprints, whatever their call count.
    pub fingerprints: usize,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Factors {
    pub calls: f64,
    pub bytes: f64,
    pub time: f64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Candidate {
    pub rank: usize,
    pub fingerprint: String,
    pub calls: usize,
    /// Lanes the command ran in.
    pub lanes: usize,
    /// Calls with a measured time (`duration_ms` above zero).
    pub timed_calls: usize,
    pub total_ms: f64,
    pub median_ms: Option<f64>,
    /// Bytes delivered into context, summed (`delivered_bytes`).
    pub delivered_bytes: u64,
    pub score: f64,
    pub factors: Factors,
    /// A few redacted heads of real invocations, as the trace stores them.
    pub examples: Vec<String>,
}

/// What the report found. Serializes (camelCase) as the `--json` document.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PortCandidates {
    pub roots: usize,
    pub counts: Counts,
    pub top: usize,
    pub min_calls: usize,
    /// Fingerprints with at least `min_calls` calls: the set the factors are normalized over.
    pub candidate_count: usize,
    /// Whether any candidate has a measured time; when not, the time factor is left out.
    pub time_recorded: bool,
    pub candidates: Vec<Candidate>,
}

/// A draft `kind: port` packet, not yet written.
#[derive(Debug, Clone)]
pub struct Draft {
    pub id: String,
    pub file_name: String,
    pub text: String,
}

impl PortCandidates {
    /// The `--json` document.
    pub fn to_json(&self) -> Value {
        serde_json::to_value(self).expect("a report is plain data")
    }
}

// ---- reading ----

#[derive(Default)]
struct Agg {
    calls: usize,
    lanes: BTreeSet<(usize, String)>,
    total_ms: f64,
    effective_ms: f64,
    timed: Vec<f64>,
    bytes: u64,
    examples: Vec<String>,
}

/// Rank the commands lanes ran again and again, over every lane one level under each of
/// `roots`.
pub fn port_candidates(roots: &[PathBuf], options: &Options) -> Result<PortCandidates> {
    let mut counts = Counts::default();
    let mut by_fingerprint: BTreeMap<String, Agg> = BTreeMap::new();
    for (root_index, root) in roots.iter().enumerate() {
        match fs::metadata(root) {
            Ok(m) if m.is_dir() => {}
            Ok(_) => bail!("lanes root {} is not a directory", root.display()),
            Err(e) => bail!("lanes root {}: {e}", root.display()),
        }
        let mut entries: Vec<_> = fs::read_dir(root)?.collect::<std::io::Result<_>>()?;
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            let kind = entry.file_type()?;
            if is_link(&kind) {
                counts.seen += 1;
                counts.symlinked += 1;
                continue;
            }
            if !kind.is_dir() {
                continue;
            }
            counts.seen += 1;
            let lane = (root_index, entry.file_name().to_string_lossy().into_owned());
            read_lane(&entry.path(), &lane, &mut counts, &mut by_fingerprint);
        }
    }
    counts.fingerprints = by_fingerprint.len();

    let mut found: Vec<(String, Agg)> = by_fingerprint
        .into_iter()
        .filter(|(_, agg)| agg.calls >= options.min_calls.max(1))
        .collect();
    let candidate_count = found.len();
    let time_recorded = found.iter().any(|(_, agg)| !agg.timed.is_empty());
    let max_calls = found.iter().map(|(_, a)| a.calls).max().unwrap_or(0) as f64;
    let max_bytes = found.iter().map(|(_, a)| a.bytes).max().unwrap_or(0) as f64;
    let max_time = found
        .iter()
        .map(|(_, a)| a.effective_ms)
        .fold(0.0_f64, f64::max);

    let mut candidates: Vec<Candidate> = found
        .drain(..)
        .map(|(fingerprint, agg)| {
            let factors = Factors {
                calls: ratio(agg.calls as f64, max_calls),
                bytes: ratio(agg.bytes as f64, max_bytes),
                time: if time_recorded {
                    ratio(agg.effective_ms, max_time)
                } else {
                    1.0
                },
            };
            Candidate {
                rank: 0,
                fingerprint,
                calls: agg.calls,
                lanes: agg.lanes.len(),
                timed_calls: agg.timed.len(),
                total_ms: agg.total_ms,
                median_ms: median(agg.timed),
                delivered_bytes: agg.bytes,
                score: factors.calls * factors.bytes * factors.time,
                factors,
                examples: agg.examples,
            }
        })
        .collect();
    candidates.sort_by(|a, b| {
        b.score
            .total_cmp(&a.score)
            .then(b.calls.cmp(&a.calls))
            .then(b.delivered_bytes.cmp(&a.delivered_bytes))
            .then_with(|| a.fingerprint.cmp(&b.fingerprint))
    });
    candidates.truncate(options.top);
    for (i, c) in candidates.iter_mut().enumerate() {
        c.rank = i + 1;
    }

    Ok(PortCandidates {
        roots: roots.len(),
        counts,
        top: options.top,
        min_calls: options.min_calls,
        candidate_count,
        time_recorded,
        candidates,
    })
}

fn ratio(value: f64, max: f64) -> f64 {
    if max > 0.0 { value / max } else { 0.0 }
}

/// Whether a directory entry is a symlink. `DirEntry::file_type` does not follow one.
fn is_link(kind: &fs::FileType) -> bool {
    kind.is_symlink()
}

/// One lane's trace, through the shared reader (`crate::traces`), into the counters and the
/// per-fingerprint aggregates.
fn read_lane(
    dir: &Path,
    lane: &(usize, String),
    counts: &mut Counts,
    by_fingerprint: &mut BTreeMap<String, Agg>,
) {
    let traces = read_lane_traces(dir);
    counts.symlinked += traces.symlinked;
    counts.unreadable += traces.unreadable;
    counts.trace_files += traces.files;
    counts.malformed_lines += traces.malformed_lines;
    match traces.state {
        LaneState::Skipped => return,
        LaneState::Untraced => {
            counts.lanes_untraced += 1;
            return;
        }
        LaneState::Traced => counts.lanes_traced += 1,
    }
    for record in &traces.records {
        read_record(record, lane, counts, by_fingerprint);
    }
}

fn read_record(
    record: &CallRecord,
    lane: &(usize, String),
    counts: &mut Counts,
    by_fingerprint: &mut BTreeMap<String, Agg>,
) {
    counts.records += 1;
    let target = match (&record.surface, record.tool.as_str(), &record.target) {
        (Surface::Agent, "Bash", Some(target)) => target,
        _ => {
            counts.not_commands += 1;
            return;
        }
    };
    let Some(fingerprint) = fingerprint(target) else {
        counts.not_commands += 1;
        return;
    };
    counts.commands += 1;
    let agg = by_fingerprint.entry(fingerprint).or_default();
    agg.calls += 1;
    agg.lanes.insert(lane.clone());
    agg.bytes = agg.bytes.saturating_add(record.delivered_bytes as u64);
    let ms = record.duration_ms;
    if ms.is_finite() && ms > 0.0 {
        agg.total_ms += ms;
        agg.effective_ms += ms.max(MIN_CALL_MS);
        agg.timed.push(ms);
    } else {
        agg.effective_ms += MIN_CALL_MS;
    }
    if agg.examples.len() < MAX_EXAMPLES {
        let example = head_tokens(target).join(" ").replace('`', "'");
        if !example.is_empty() && !agg.examples.contains(&example) {
            agg.examples.push(example);
        }
    }
}

// ---- the fingerprint ----

/// Text from a trace record made safe to print: secrets redacted first (a cut could
/// otherwise leave half of one), control characters (a terminal escape) turned into
/// spaces, the length bounded.
///
/// Everything the report prints or writes from a trace record goes through this.
fn scrub(text: &str) -> String {
    let redacted = redact(text);
    redacted
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(MAX_TEXT)
        .collect()
}

/// The words of a command head with the unsafe parts masked (rules 1 to 3), each cut to
/// `MAX_WORD`: what an example shows.
fn head_tokens(target: &str) -> Vec<String> {
    masked_words(target)
        .into_iter()
        .map(|w| w.chars().take(MAX_WORD).collect())
        .collect()
}

/// The same words uncut, so a long path still has its last component for the fingerprint.
fn masked_words(target: &str) -> Vec<String> {
    let clean = scrub(target);
    let mut words = Vec::new();
    let mut leading = true;
    for word in clean.split_whitespace() {
        if leading && is_env_assignment(word) {
            continue;
        }
        leading = false;
        words.push(mask_word(word));
    }
    words
}

fn is_env_assignment(word: &str) -> bool {
    let Some((name, _)) = word.split_once('=') else {
        return false;
    };
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn mask_word(word: &str) -> String {
    let lower = word.to_ascii_lowercase();
    let masked: String = if [".env", "id_rsa", "id_ed25519", "credentials.json"]
        .iter()
        .any(|name| lower.contains(name))
    {
        "<secret-file>".into()
    } else if word.starts_with(['"', '\'', '`']) {
        "<str>".into()
    } else if word.contains("://") {
        "<url>".into()
    } else if let Some((name, _)) = word.split_once('=') {
        if name.starts_with('-') {
            format!("{name}=<v>")
        } else {
            "<kv>".into()
        }
    } else {
        word.into()
    };
    masked
}

/// The fingerprint of a command head, or none when it holds no program.
pub fn fingerprint(target: &str) -> Option<String> {
    let words = masked_words(target);
    let (program, args) = words.split_first()?;
    let mut parts = vec![program_name(program)];
    parts.extend(args.iter().map(|arg| collapse_arg(arg)));
    let parts: Vec<String> = parts
        .iter()
        .map(|part| part.chars().take(MAX_WORD).collect())
        .collect();
    Some(parts.join(" "))
}

fn program_name(program: &str) -> String {
    if program.starts_with('<') {
        return program.to_string();
    }
    last_component(program)
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| program.to_string())
}

fn last_component(path: &str) -> Option<String> {
    path.rsplit('/')
        .find(|part| !part.is_empty())
        .map(str::to_string)
}

fn collapse_arg(arg: &str) -> String {
    // A mask (`<str>`, `<url>`, `<kv>`, `<secret-file>`) or a flag (`--token=<v>`).
    if arg.starts_with('<') || arg.starts_with('-') {
        return arg.to_string();
    }
    if arg.contains('/') || arg.starts_with('~') {
        if is_temp_path(arg) {
            return "<tmp>".into();
        }
        return last_component(arg).map_or_else(|| arg.to_string(), |last| collapse_digits(&last));
    }
    collapse_digits(arg)
}

fn is_temp_path(path: &str) -> bool {
    [
        "/tmp",
        "/var/tmp",
        "/private/tmp",
        "/var/folders",
        "/private/var/folders",
        "/dev/shm",
    ]
    .iter()
    .any(|temp| {
        path.strip_prefix(temp)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
    })
}

fn collapse_digits(word: &str) -> String {
    static UUID: OnceLock<Regex> = OnceLock::new();
    static HEX: OnceLock<Regex> = OnceLock::new();
    static DIGITS: OnceLock<Regex> = OnceLock::new();
    let uuid = UUID.get_or_init(|| {
        Regex::new(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b")
            .expect("uuid regex is valid")
    });
    let hex =
        HEX.get_or_init(|| Regex::new(r"(?i)\b[0-9a-f]{7,64}\b").expect("hex regex is valid"));
    let digits = DIGITS.get_or_init(|| Regex::new(r"[0-9]{3,}").expect("digits regex is valid"));
    if !word.is_empty() && word.bytes().all(|b| b.is_ascii_digit()) {
        return "<n>".into();
    }
    let word = uuid.replace_all(word, "<id>");
    let word = hex.replace_all(&word, |caps: &regex::Captures| {
        if caps[0].bytes().any(|b| b.is_ascii_digit()) {
            "<id>".to_string()
        } else {
            caps[0].to_string()
        }
    });
    digits.replace_all(&word, "<n>").into_owned()
}

// ---- the plain table ----

impl PortCandidates {
    /// The plain-text report, at most 80 columns wide.
    pub fn render(&self) -> String {
        let c = &self.counts;
        let mut out = String::new();
        out.push_str(&format!(
            "Port candidates: {} of {} commands run {}+ times; {} of {} lanes traced \
             ({} root{})\n",
            self.candidates.len(),
            self.candidate_count,
            self.min_calls,
            c.lanes_traced,
            c.seen,
            self.roots,
            if self.roots == 1 { "" } else { "s" },
        ));
        if self.candidates.is_empty() {
            out.push_str("\nno command was run often enough under the given roots.\n");
        } else {
            out.push_str(&format!(
                "\n{:>2} {:<28} {:>5} {:>5} {:>7} {:>7} {:>9} {:>6}\n",
                "#", "command", "calls", "lanes", "time", "median", "bytes", "score"
            ));
            for cand in &self.candidates {
                out.push_str(&format!(
                    "{:>2} {:<28} {:>5} {:>5} {:>7} {:>7} {:>9} {:>6.4}\n",
                    cand.rank,
                    clip(&cand.fingerprint, 28),
                    cand.calls,
                    cand.lanes,
                    if cand.timed_calls > 0 {
                        millis(cand.total_ms)
                    } else {
                        "-".into()
                    },
                    cand.median_ms.map_or("-".into(), millis),
                    bytes(cand.delivered_bytes),
                    cand.score,
                ));
            }
        }

        let mut notes: Vec<String> = vec![
            "calls is how often the command ran; bytes is what reached context \
             (delivered_bytes); time is wall time. score = calls x bytes x time, each divided \
             by the largest among the candidates."
                .into(),
            "A command is its program and stable arguments (the first two words the trace \
             keeps): paths, temp dirs, ids and numbers are collapsed, and values after = are \
             dropped."
                .into(),
        ];
        if !self.time_recorded && self.candidate_count > 0 {
            notes.push(
                "Time is not in these traces (the hook records duration_ms 0.0 for a Bash \
                 call), so time is left out and score = calls x bytes."
                    .into(),
            );
        }
        let skipped: Vec<String> = [
            ("untraced lane", c.lanes_untraced),
            ("symlink", c.symlinked),
            ("unreadable", c.unreadable),
            ("malformed line", c.malformed_lines),
        ]
        .iter()
        .filter(|(_, n)| *n > 0)
        .map(|(what, n)| format!("{what} {n}"))
        .collect();
        if !skipped.is_empty() {
            notes.push(format!("Left out: {}.", skipped.join(", ")));
        }
        out.push('\n');
        for note in notes {
            out.push_str(&wrap(&note, WIDTH));
        }
        out
    }

    /// One draft `kind: port` packet per shown candidate. Pure: nothing is written.
    pub fn drafts(&self) -> Vec<Draft> {
        let mut taken: BTreeSet<String> = BTreeSet::new();
        self.candidates
            .iter()
            .map(|cand| {
                let base = slug(&cand.fingerprint);
                let mut id = base.clone();
                let mut n = 2;
                while !taken.insert(id.clone()) {
                    id = format!("{base}-{n}");
                    n += 1;
                }
                Draft {
                    file_name: format!("{id}.md"),
                    text: draft_text(&id, cand, self),
                    id,
                }
            })
            .collect()
    }

    /// Write the drafts into `dir` (made if missing). A file that already exists is never
    /// overwritten: the call refuses before it writes any.
    pub fn write_drafts(&self, dir: &Path) -> Result<Vec<PathBuf>> {
        let drafts = self.drafts();
        fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        for draft in &drafts {
            let path = dir.join(&draft.file_name);
            if fs::symlink_metadata(&path).is_ok() {
                bail!("{} exists; drafts never overwrite", path.display());
            }
        }
        let mut written = Vec::new();
        for draft in &drafts {
            let path = dir.join(&draft.file_name);
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .with_context(|| format!("creating {}", path.display()))?;
            file.write_all(draft.text.as_bytes())
                .with_context(|| format!("writing {}", path.display()))?;
            written.push(path);
        }
        Ok(written)
    }
}

fn millis(ms: f64) -> String {
    if ms < 1000.0 {
        format!("{ms:.0}ms")
    } else if ms < 600_000.0 {
        format!("{:.1}s", ms / 1000.0)
    } else {
        format!("{:.0}m", ms / 60_000.0)
    }
}

fn bytes(n: u64) -> String {
    const KIB: f64 = 1024.0;
    let n = n as f64;
    if n < KIB {
        format!("{n:.0} B")
    } else if n < KIB * KIB {
        format!("{:.1} KiB", n / KIB)
    } else if n < KIB * KIB * KIB {
        format!("{:.1} MiB", n / (KIB * KIB))
    } else {
        format!("{:.1} GiB", n / (KIB * KIB * KIB))
    }
}

// ---- the draft packet ----

/// A lane id from a fingerprint: `port-` and its letters and digits, dash separated.
fn slug(fingerprint: &str) -> String {
    let mut out = String::from("port");
    let mut dash = false;
    for c in fingerprint.chars() {
        if c.is_ascii_alphanumeric() {
            if dash || out == "port" {
                out.push('-');
            }
            out.push(c.to_ascii_lowercase());
            dash = false;
        } else {
            dash = true;
        }
    }
    out.truncate(MAX_ID);
    out.trim_end_matches('-').to_string()
}

/// The language the reference is written in, from the program (`port.lang`).
fn lang_of(fingerprint: &str) -> &'static str {
    match fingerprint.split(' ').next().unwrap_or_default() {
        "node" => "node",
        "python" | "python3" => "python",
        "bash" | "sh" | "zsh" => "shell",
        _ => "other",
    }
}

fn draft_text(id: &str, cand: &Candidate, report: &PortCandidates) -> String {
    let header = serde_json::json!({
        "id": id,
        "kind": "port",
        "class": "rust",
        "owns": [
            "crates/pk-FILL-NAME/src/lib.rs",
            "FILL-FIXTURES-DIR/cases.jsonl",
            format!("docs/handoffs/handoff-{id}.md"),
        ],
        "allow": ["cargo test*", "cowproof pk port *"],
        "port": {
            "lang": lang_of(&cand.fingerprint),
            "adapter": "process",
            "cases": "FILL-FIXTURES-DIR/cases.jsonl",
            "fixtures": "FILL-FIXTURES-DIR/fixtures",
            "tools": ["FILL-TOOL-NAME"],
        },
        "checks": [
            {"id": "parity", "command":
                "cowproof pk port replay --fixtures FILL-FIXTURES-DIR/fixtures --surface both"},
            {"id": "tests", "command": "cargo test --locked -p pk-FILL-NAME"},
        ],
    });
    let header = serde_json::to_string_pretty(&header).expect("a header is plain data");
    let time = if cand.timed_calls > 0 {
        format!(
            "{} total over {} timed call{}, median {}",
            millis(cand.total_ms),
            cand.timed_calls,
            if cand.timed_calls == 1 { "" } else { "s" },
            cand.median_ms.map_or("-".into(), millis),
        )
    } else {
        "not recorded (the hook sees the result, not the call)".to_string()
    };
    let per_call = cand.delivered_bytes / cand.calls.max(1) as u64;
    let examples: String = cand.examples.iter().map(|e| format!("- `{e}`\n")).collect();
    format!(
        "<!-- lane {header} -->

# DRAFT: port `{fingerprint}` to a compact pk tool

DRAFT, written by `cowproof report port-candidates --draft`. It is not dispatched and
`cowproof run` must not be pointed at it until every `FILL-` placeholder is replaced and
`cowproof lint` is clean. Lint errors that name a `FILL-` path are the placeholders still
to fill.

## Why this command

Lanes ran `{fingerprint}` again and again. From the portkit traces under the lanes roots
(Bash calls seen by the hook, rank {rank} of {count} candidates):

- calls: {calls} in {lanes} lane{lanes_s}
- bytes delivered into context: {total} ({per_call} per call)
- wall time: {time}
- score: {score:.4} (calls x bytes x time, each over the largest candidate)

Example invocations, redacted. The trace keeps only the first two words of a command, so
these are heads, not full commands:

{examples}
Find the full invocations the lanes used, and the script or program behind them, before
dispatching. If this is a system tool (`git`, `cargo`, `rg`), it is probably not a port
target: look for a smaller question the lanes are really asking.

## Port target

A compact `pk` tool, registered as `FILL-TOOL-NAME` in a crate under `crates/` (named
`pk-FILL-NAME` in this draft), that answers what lanes ask of this command with a short
JSON answer in place of its full output. Decide what the answer holds from the example
invocations; the target is fewer bytes into context and less wall time on every call.

Reuse before building: search the workspace (`rg`) for an existing `pk` tool, helper or
script that already answers it, and say in the handoff what was reused. A second
implementation of an existing capability is a flaw.

## Parity first

The parity harness records the reference's behavior before any port is written. The
director records the fixtures first, with `cowproof pk port capture` against the original
command (`--cmd FILL-REFERENCE-COMMAND --cases FILL-FIXTURES-DIR/cases.jsonl --out
FILL-FIXTURES-DIR/fixtures`), then sets the `port.reference` and the held-out cases. The
builder does not write fixtures by hand and does not edit `accepted` or `epsilon`.

## Checks

- `cowproof pk port replay --fixtures FILL-FIXTURES-DIR/fixtures --surface both`
- `cargo test --locked -p pk-FILL-NAME`

## Handoff

Write `docs/handoffs/handoff-{id}.md`: files changed, each check with its result, what
was reused, and questions with a recommended answer.
",
        fingerprint = cand.fingerprint.replace('`', "'"),
        rank = cand.rank,
        count = report.candidate_count,
        calls = cand.calls,
        lanes = cand.lanes,
        lanes_s = if cand.lanes == 1 { "" } else { "s" },
        total = bytes(cand.delivered_bytes),
        score = cand.score,
    )
}
