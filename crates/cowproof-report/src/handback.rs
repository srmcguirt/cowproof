//! `cowproof report handback`: the per-lane handoff report. It reads a finished lane's
//! `summary.json`, `lane.patch` and handoff, parses the checks the builder reported, runs
//! the flaw rules over the patch and counts removed assertions, then says whether the
//! lane looks ready to apply. This was the standalone `cowproof-report` binary; the
//! command line is now `cowproof report handback <lane-dir> [--repo DIR] [--packet FILE]
//! [--baseline FILE] [--json]`, wired in `crates/cowproof-cli/src/report.rs`.

use anyhow::{Context, Result, bail};
use cowproof_prove::flaws::{FlawRule, PatchDelta, check_rules, parse_patch, parse_rules};
use regex::Regex;
use serde::Serialize;
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    sync::LazyLock,
};

#[derive(Debug, Serialize)]
struct Finding {
    file: String,
    line: Option<usize>,
    pattern: String,
    explanation: String,
}
#[derive(Debug, Serialize)]
struct Check {
    command: String,
    result: String,
    classification: String,
}
#[derive(Debug, Serialize)]
struct UnparsedLine {
    line: usize,
    text: String,
    reason: String,
}
#[derive(Debug, Serialize)]
struct AssertionChange {
    file: String,
    removed: usize,
    added: usize,
    net_loss: usize,
}
/// One lane's report; `serde_json::to_string_pretty` of it is what `--json` prints.
#[derive(Debug, Serialize)]
pub struct Report {
    lane_id: String,
    status: String,
    minutes: Option<u64>,
    files_changed: usize,
    lines_added: usize,
    lines_removed: usize,
    outside_ownership_count: usize,
    checks: Vec<Check>,
    packet_commands_unreported: Vec<String>,
    unparsed: Vec<UnparsedLine>,
    /// The flaw packs that ran, in load order (`generic` always first). Left out of the JSON
    /// when only `generic` ran, so a default report is byte for byte what it was before packs.
    #[serde(skip_serializing_if = "only_generic")]
    packs: Vec<String>,
    flaws: Vec<Finding>,
    removed_assertions: Vec<AssertionChange>,
    limits: Vec<String>,
    unverified: Vec<String>,
    questions: Vec<String>,
    verdict_hint: String,
    verdict_reasons: Vec<String>,
    sample_handoff: Option<String>,
}
fn only_generic(packs: &[String]) -> bool {
    packs.len() <= 1
}
fn value_str(v: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|k| v.get(*k).and_then(Value::as_str).map(str::to_owned))
}
fn value_num(v: &Value, keys: &[&str]) -> Option<u64> {
    keys.iter().find_map(|k| v.get(*k).and_then(Value::as_u64))
}
/// Which lines sit under a checks heading. A heading names the checks when it contains
/// "check", "command" or "verification"; a subheading under one inherits that (so
/// "## Unknown status" under "# Verification Checks" is still the checks section), and a
/// heading at the same or a higher level ends it. A `# comment` inside a fenced block is
/// not a heading.
fn checks_sections(lines: &[&str]) -> Vec<bool> {
    let mut out = Vec::with_capacity(lines.len());
    let mut stack: Vec<(usize, bool)> = Vec::new();
    let mut fenced = false;
    for line in lines {
        let t = line.trim();
        if t.starts_with("```") {
            fenced = !fenced;
        } else if !fenced && t.starts_with('#') {
            let level = t.chars().take_while(|c| *c == '#').count();
            let heading = t[level..].trim().to_ascii_lowercase();
            while stack.last().is_some_and(|(l, _)| *l >= level) {
                stack.pop();
            }
            let inherited = stack.last().is_some_and(|(_, f)| *f);
            let own = heading.contains("check")
                || heading.contains("command")
                || heading.contains("verification");
            stack.push((level, inherited || own));
        }
        out.push(stack.last().is_some_and(|(_, f)| *f));
    }
    out
}
fn unparsed_line(line: usize, text: &str, reason: &str) -> UnparsedLine {
    UnparsedLine {
        line,
        text: text.trim().chars().take(200).collect(),
        reason: reason.to_string(),
    }
}
/// A command with arguments that is not one of the known prefixes (`make test`, not
/// `src/main.rs` or one bare word). Only used inside a checks section, where a line
/// that pairs such a command with a result is a check claim we could not read.
fn looks_like_invocation(s: &str) -> bool {
    let mut words = s.split_whitespace();
    let Some(first) = words.next() else {
        return false;
    };
    words.next().is_some()
        && first.starts_with(|c: char| c.is_ascii_lowercase())
        && first
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}
/// The text after a list marker: `- `, `* `, `1. ` or `1) `.
fn list_item_body(trimmed: &str) -> Option<&str> {
    static MARKER: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^(?:[-*]|\d+[.)])\s+").expect("list marker pattern"));
    MARKER
        .find(trimmed)
        .map(|m| trimmed[m.end()..].trim_start())
}
/// Why a list item that starts like a check claim did not parse, if it does.
fn malformed_list_item(body: &str, in_checks: bool) -> Option<&'static str> {
    if let Some(after) = body.strip_prefix('`') {
        let span = after.split('`').next()?;
        if !after.contains('`') {
            return None;
        }
        if is_command(span) || (in_checks && looks_like_invocation(span)) {
            return Some(
                "list item has a command but no dash or em dash between it and its result",
            );
        }
        return None;
    }
    let separated = [" — ", " – ", " - ", ": ", " -> ", " => "]
        .iter()
        .any(|s| body.contains(s));
    (is_command(body) && (in_checks || separated))
        .then_some("list item starts with a command but not as `command` - result")
}
fn parse_checks(text: &str) -> (Vec<Check>, Vec<UnparsedLine>) {
    let lines: Vec<&str> = text.lines().collect();
    let in_checks = checks_sections(&lines);
    let mut checks = Vec::new();
    let mut unparsed = Vec::new();
    let mut table_header: Option<(usize, usize)> = None;
    let mut fenced = false;
    for (idx, line) in lines.iter().enumerate() {
        let number = idx + 1;
        let trimmed = line.trim();
        if trimmed.starts_with("```") {
            fenced = !fenced;
            table_header = None;
            continue;
        }
        if let Some((command, result)) = arrow_check(line) {
            if is_command(&command) {
                checks.push(Check {
                    command,
                    classification: classify(&result),
                    result,
                });
                continue;
            }
            if in_checks[idx] && looks_like_invocation(&command) {
                unparsed.push(unparsed_line(
                    number,
                    trimmed,
                    "arrow line names a command the report does not recognize",
                ));
                continue;
            }
        } else if is_command(trimmed.trim_start_matches('`')) && trimmed.contains("->") {
            unparsed.push(unparsed_line(
                number,
                trimmed,
                "arrow line needs two spaces before -> and a result after it",
            ));
            continue;
        }
        if fenced {
            continue;
        }

        let cells: Vec<_> = trimmed
            .trim_matches('|')
            .split('|')
            .map(str::trim)
            .collect();
        if trimmed.starts_with('|') {
            let low: Vec<_> = cells.iter().map(|s| s.to_ascii_lowercase()).collect();
            if let (Some(ci), Some(ri)) = (
                low.iter()
                    .position(|s| s.contains("command") || s == "check"),
                low.iter().position(|s| s.contains("result")),
            ) {
                table_header = Some((ci, ri));
                continue;
            }
        }
        if let Some((ci, ri)) = table_header {
            if !trimmed.starts_with('|') {
                table_header = None;
            } else {
                let separator = cells
                    .iter()
                    .all(|c| !c.is_empty() && c.chars().all(|x| x == '-' || x == ':' || x == ' '));
                if !separator {
                    match (cells.get(ci), cells.get(ri)) {
                        (Some(c), Some(r)) if c.is_empty() || r.is_empty() => {
                            unparsed.push(unparsed_line(
                                number,
                                trimmed,
                                "table row has empty cells",
                            ));
                        }
                        (Some(c), Some(r)) if is_command(&strip_code(c)) => {
                            checks.push(Check {
                                command: strip_code(c),
                                result: r.to_string(),
                                classification: classify(r),
                            });
                        }
                        (Some(_), Some(_)) => unparsed.push(unparsed_line(
                            number,
                            trimmed,
                            "table cell is not a recognized command",
                        )),
                        _ => unparsed.push(unparsed_line(
                            number,
                            trimmed,
                            "table row has fewer cells than its header",
                        )),
                    }
                }
                continue;
            }
        }
        if let Some(body) = list_item_body(trimmed) {
            if let Some((cmd, res)) = bullet_pair(line) {
                if is_command(&cmd) {
                    checks.push(Check {
                        command: cmd,
                        classification: classify(&res),
                        result: res,
                    });
                } else if in_checks[idx] && looks_like_invocation(&cmd) {
                    unparsed.push(unparsed_line(
                        number,
                        trimmed,
                        "list item names a command the report does not recognize",
                    ));
                }
            } else if let Some(reason) = malformed_list_item(body, in_checks[idx]) {
                unparsed.push(unparsed_line(number, trimmed, reason));
            }
        }
    }
    let (fenced_checks, fenced_unparsed) = parse_fenced_checks(&lines, &in_checks);
    checks.extend(fenced_checks);
    unparsed.extend(fenced_unparsed);
    unparsed.sort_by_key(|u| u.line);
    (checks, unparsed)
}
fn arrow_check(line: &str) -> Option<(String, String)> {
    static ARROW: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^\s*(.+?)\s{2,}->\s*(.+?)\s*$").expect("arrow pattern"));
    let captures = ARROW.captures(line)?;
    Some((
        captures[1].trim().to_string(),
        captures[2].trim().to_string(),
    ))
}
/// Fenced blocks of commands followed by one result line for all of them. Inside a
/// checks section the block is a claim, or an unparsed one when no result follows.
/// Outside it the block is only reported when a result that reads as pass, fail or
/// not run follows it: that is a claim in the wrong place, where a block followed by
/// ordinary prose is a usage example.
fn parse_fenced_checks(lines: &[&str], in_checks: &[bool]) -> (Vec<Check>, Vec<UnparsedLine>) {
    let mut checks = Vec::new();
    let mut unparsed = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        if !lines[i].trim().starts_with("```") {
            i += 1;
            continue;
        }
        let section = in_checks[i];
        i += 1;
        let mut commands: Vec<(usize, String)> = Vec::new();
        while i < lines.len() && !lines[i].trim().starts_with("```") {
            let cmd = lines[i].trim();
            if !cmd.contains("->") && is_command(cmd) {
                commands.push((i + 1, cmd.to_string()));
            }
            i += 1;
        }
        if i < lines.len() {
            i += 1;
        }
        let mut result = None;
        while i < lines.len() {
            let next = lines[i].trim();
            if next.starts_with('#') || next.starts_with("```") {
                break;
            }
            i += 1;
            if !next.is_empty() && !next.starts_with("Commands below") {
                result = Some(next.to_string());
                break;
            }
        }
        match (section, result) {
            (_, _) if commands.is_empty() => {}
            (true, Some(result)) => {
                for (_, command) in commands {
                    checks.push(Check {
                        command,
                        classification: classify(&result),
                        result: result.clone(),
                    });
                }
            }
            (true, None) => {
                for (line, command) in &commands {
                    unparsed.push(unparsed_line(
                        *line,
                        command,
                        "fenced command has no result line after its block",
                    ));
                }
            }
            (false, Some(result)) if classify(&result) != "unclear" => {
                for (line, command) in &commands {
                    unparsed.push(unparsed_line(
                        *line,
                        command,
                        "fenced command outside the checks section",
                    ));
                }
            }
            (false, _) => {}
        }
    }
    (checks, unparsed)
}
fn is_command(s: &str) -> bool {
    let s = s.trim_start();
    [
        "cargo ",
        "node ",
        "npm ",
        "pnpm ",
        "yarn ",
        "git ",
        "rustfmt ",
        "LANE_SCRATCH=",
    ]
    .iter()
    .any(|prefix| s.starts_with(prefix))
}
fn strip_code(s: &str) -> String {
    s.trim().trim_matches('`').to_string()
}
fn bullet_pair(line: &str) -> Option<(String, String)> {
    static PAIR: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^\s*(?:[-*]|\d+[.)])\s+`([^`]+)`\s*(?:—|–|-)\s*(.+?)\s*$")
            .expect("bullet pattern")
    });
    let c = PAIR.captures(line)?;
    Some((c[1].to_string(), c[2].to_string()))
}
/// Compile a pattern written in this file once.
macro_rules! pattern {
    ($name:ident, $re:expr) => {
        static $name: LazyLock<Regex> =
            LazyLock::new(|| Regex::new($re).expect(concat!(stringify!($name), " pattern")));
    };
}
// Everything below is matched against the lowercased result text.
//
// Statements that read as failure words but are not one: "fixed the failing test",
// "fixing the failures".
pattern!(
    FIXED,
    r"\b(?:fix(?:ed|es|ing)?|resolv(?:ed|es|ing)|repair(?:ed|s|ing)?|address(?:ed|es|ing)|correct(?:ed|s|ing)?)\s+(?:(?:the|a|an|all|that|this|those|these|some|two|three|\d+|previously|earlier|flaky|broken|remaining|old|known)\s+)*(?:fail(?:ed|ing|ures?)?|errors?|panic(?:ked|s)?)\b"
);
// Statements that nothing failed: "0 failed", "no errors", "no failing tests",
// "failures: none", "did not fail", "without errors", "error-free", "exit 0".
pattern!(
    CLEAN,
    r"\b(?:0|zero|no)\s+(?:(?:test|new|remaining|more|other)\s+)*(?:fail(?:ed|ing|ures?)?|errors?|panic(?:ked|s)?)\b|\b(?:did\s+not|didn't|does\s+not|doesn't|never|not)\s+(?:fail(?:ed|s)?|panic(?:ked)?|error(?:ed)?)\b|\bwithout(?:\s+any)?\s+(?:errors?|failures?|panics?)\b|\b(?:fail(?:ed|ing|ures?)?|errors?|panic(?:ked|s)?)\s*[:=]\s*(?:none|nil|zero|0|n/a)\b|\berror[- ]free\b|\bfree\s+of\s+(?:errors?|failures?)\b|\bexit(?:ed)?(?:\s+with)?(?:\s+code)?\s*[:=]?\s*0\b"
);
// "did not pass", "not passing", "failed to pass", "is not ok": success words that
// are denied.
pattern!(
    NEGATED_SUCCESS,
    r"\b(?:did\s+not|didn't|does\s+not|doesn't|do\s+not|don't|has\s+not|hasn't|have\s+not|haven't|never|not|cannot|can't|can\s+not|is\s+not|isn't|are\s+not|aren't|was\s+not|wasn't|were\s+not|weren't|no\s+longer|fail(?:ed|s)?\s+to|unable\s+to)\s+(?:(?:yet|successfully|all|fully)\s+)?(?:pass(?:es|ed|ing)?|succeed(?:s|ed)?|success(?:ful(?:ly)?)?|ok|clean)\b"
);
pattern!(
    SUCCESS,
    r"\b(?:pass(?:es|ed|ing)?|success(?:ful(?:ly)?)?|clean|ok)\b"
);
pattern!(
    FAILURE,
    r"\b(?:fail(?:ed|s|ure|ures|ing)?|errors?|errored|panic(?:ked|s)?|crash(?:ed|es)?|timed\s+out|unsuccessful(?:ly)?|aborted)\b"
);
// An explicit nonzero failure count, nonzero exit or panic is a failure no matter what
// else the line says: "suite a: 0 failed; suite b: 2 failed" and "no errors, 1 failed"
// must never read as a pass.
pattern!(
    HARD_FAILURE,
    r"\b[1-9]\d*\s+(?:failed|failures?|errors?|failing|panicked)\b|\b(?:failed|failures?|errors?)\s*[:=]\s*[1-9]|\bexit(?:ed)?(?:\s+with)?(?:\s+(?:code|status))?\s*[:=]?\s*[1-9]|\bstatus\s+[1-9]|\bpanicked\b"
);
pattern!(
    NOT_RUN,
    r"\bnot[ -]run\b|\bnot performed\b|\bnot executed\b"
);
pattern!(SKIPPED, r"\bskipped\b");
pattern!(NOT_SKIPPED, r"\b(?:0\s+skipped|no skips|not skipped)\b");
pattern!(FINAL_RERUN, r"\b(?:final\s+)?(?:re)?run\s+passed\b");

/// The text with every match of `re` replaced by spaces, so later matches keep their
/// positions.
fn blank(re: &Regex, text: &str) -> String {
    re.replace_all(text, |c: &regex::Captures| " ".repeat(c[0].len()))
        .into_owned()
}
fn last_start(re: &Regex, text: &str) -> Option<usize> {
    re.find_iter(text).last().map(|m| m.start())
}
/// pass, fail, not run or unclear, from the builder's words for a check's result. The
/// last of the failure and success statements wins ("failed once, then passed"), except
/// that a nonzero failure count, exit or panic is a failure unless the line says the
/// final rerun passed.
fn classify(s: &str) -> String {
    let lowered = s.to_ascii_lowercase();
    let l = blank(&FIXED, &lowered);
    let clean_at = last_start(&CLEAN, &l);
    let l = blank(&CLEAN, &l);
    let negated_at = last_start(&NEGATED_SUCCESS, &l);
    let affirmed = blank(&NEGATED_SUCCESS, &l);
    let success = last_start(&SUCCESS, &affirmed);
    let failure = last_start(&FAILURE, &l).max(negated_at);
    let proof = success.max(clean_at);
    let not_run = NOT_RUN.is_match(&l);
    let skipped = SKIPPED.is_match(&l) && !NOT_SKIPPED.is_match(&l);
    let final_rerun_passed = FINAL_RERUN.is_match(&l);
    let hard_failure = HARD_FAILURE.is_match(&l);
    if success.is_none() && (not_run || skipped) {
        "not run"
    } else if final_rerun_passed {
        "pass"
    } else if hard_failure {
        "fail"
    } else {
        match (failure, proof) {
            (Some(fail_at), Some(pass_at)) if pass_at > fail_at => "pass",
            (Some(_), _) => "fail",
            (None, Some(_)) => "pass",
            (None, None) => "unclear",
        }
    }
    .to_string()
}
fn packet_commands(text: &str) -> Vec<String> {
    let mut inside = false;
    let mut out = BTreeSet::new();
    for line in text.lines() {
        if line.trim_start().starts_with("```") {
            inside = !inside;
            continue;
        }
        if inside {
            let s = line.trim();
            if s.starts_with("cargo ")
                || s.starts_with("git ")
                || s.starts_with("npm ")
                || s.starts_with("pnpm ")
                || s.starts_with("yarn ")
            {
                out.insert(s.to_string());
            }
        }
    }
    out.into_iter().collect()
}
fn packet_has_lane_id(text: &str, id: &str) -> bool {
    Regex::new(&format!(r#""id"\s*:\s*"{}""#, regex::escape(id))).is_ok_and(|re| re.is_match(text))
}
fn handoff_from_patch(patch: &str, summary: &Value, repo: Option<&Path>) -> Option<String> {
    let path = value_str(summary, &["handoff"]).or_else(|| {
        let handoff_dir = repo
            .and_then(|r| fs::read_to_string(r.join("lanes.config.json")).ok())
            .and_then(|s| serde_json::from_str::<Value>(&s).ok())
            .and_then(|v| value_str(&v, &["handoffDir"]))
            .unwrap_or_else(|| "docs/handoffs".to_string());
        patch.lines().find_map(|l| {
            l.strip_prefix("+++ b/")
                .map(str::to_owned)
                .filter(|p| p.starts_with(&handoff_dir) && p.contains("handoff"))
        })
    })?;
    let mut capture = false;
    let mut text = String::new();
    let mut matching = false;
    for line in patch.lines() {
        if let Some(p) = line.strip_prefix("+++ b/") {
            matching = p == path;
            capture = false;
            continue;
        }
        if matching {
            if line.starts_with("@@") {
                capture = true;
                continue;
            }
            if capture
                && let Some(s) = line.strip_prefix('+')
                && !s.starts_with("+++")
            {
                text.push_str(s);
                text.push('\n');
            }
        }
    }
    if text.is_empty() {
        if let Some(r) = repo {
            fs::read_to_string(r.join(path)).ok()
        } else {
            None
        }
    } else {
        Some(text)
    }
}
fn extract_sections(text: &str, key: &str) -> Vec<String> {
    let mut on = false;
    let mut out = Vec::new();
    let mut cur = String::new();
    for line in text.lines() {
        if line.starts_with('#') {
            if on && !cur.trim().is_empty() {
                out.push(cur.trim_matches('\n').to_string());
                cur.clear();
            }
            let h = line.trim_start_matches('#').trim().to_ascii_lowercase();
            let question = h.contains("question");
            on = match key {
                "limits" => !question && (h.contains("limit") || h.contains("deferred")),
                "unverified" => {
                    !question && (h.contains("unverified") || h.contains("not verified"))
                }
                _ => question,
            };
            continue;
        }
        if on {
            if !cur.is_empty() {
                cur.push('\n');
            }
            cur.push_str(line);
        }
    }
    if on && !cur.trim().is_empty() {
        out.push(cur.trim_matches('\n').to_string());
    }
    out.into_iter()
        .map(|s| s.chars().take(1200).collect())
        .collect()
}
fn assertions(s: &str) -> usize {
    let re = Regex::new(r"(?i)\b(assert|expect|RAISE|must fail)\b|#\[test\]").unwrap();
    re.find_iter(s).count()
}
/// What `cowproof report handback` was asked to read.
#[derive(Debug, Default, Clone)]
pub struct Options {
    /// The lane directory (holds `summary.json` and `lane.patch`).
    pub lane: PathBuf,
    /// The repository to find the handoff and packet in.
    pub repo: Option<PathBuf>,
    /// The packet file; found by lane id under `--repo` when absent.
    pub packet: Option<PathBuf>,
    /// A migration file name: rules that only apply to new migrations skip this one.
    pub baseline: Option<String>,
    /// Flaw packs to load beside the generic one: a built-in name (`example-supabase`) or
    /// a path to a pack file (relative to the working directory). Also read from
    /// `[proof] packs` in `<repo>/cowproof.toml`.
    pub packs: Vec<String>,
}

/// The generic flaw pack: gaming patterns for any stack. It is the only pack that loads
/// when nothing asks for another.
pub const GENERIC_PACK: &str = include_str!("../rules/flaws.toml");
/// The example project pack: rules one Postgres/Supabase project added. Never loaded by
/// default.
pub const EXAMPLE_SUPABASE_PACK: &str = include_str!("../rules/example-supabase.toml");

/// The built-in pack called `name`, if there is one.
pub fn builtin_pack(name: &str) -> Option<&'static str> {
    match name {
        "generic" => Some(GENERIC_PACK),
        "example-supabase" => Some(EXAMPLE_SUPABASE_PACK),
        _ => None,
    }
}

/// `[proof] packs` from `<repo>/cowproof.toml`, as written. A missing file is no packs; a
/// file that does not parse is an error, not an empty list.
fn configured_packs(repo: &Path) -> Result<Vec<String>> {
    let Ok(text) = fs::read_to_string(repo.join("cowproof.toml")) else {
        return Ok(Vec::new());
    };
    let config: toml::Table = toml::from_str(&text).context("parse cowproof.toml")?;
    Ok(config
        .get("proof")
        .and_then(|p| p.as_table())
        .and_then(|p| p.get("packs"))
        .and_then(|p| p.as_array())
        .into_iter()
        .flatten()
        .filter_map(|p| p.as_str().map(str::to_owned))
        .collect())
}

/// Load the rules to run: the generic pack, then every pack named by `[proof] packs` in
/// the repository's `cowproof.toml`, then every `--pack`. Each name is a built-in pack or a
/// file (a `cowproof.toml` path is relative to the repository and may not leave it; a
/// `--pack` path is relative to the working directory). A pack named twice loads once;
/// a missing or malformed pack is an error.
fn load_packs(options: &Options) -> Result<(Vec<FlawRule>, Vec<String>)> {
    let mut wanted: Vec<(String, Option<PathBuf>)> = vec![("generic".into(), None)];
    if let Some(repo) = options.repo.as_deref() {
        for name in configured_packs(repo)? {
            wanted.push((name, Some(repo.to_path_buf())));
        }
    }
    for name in &options.packs {
        wanted.push((name.clone(), None));
    }
    let mut names = Vec::new();
    let mut rules = Vec::new();
    for (name, base) in wanted {
        let key = name.trim_start_matches("./").to_string();
        if names.contains(&key) {
            continue;
        }
        let text = match builtin_pack(&key) {
            Some(text) => text.to_string(),
            None => {
                let path = Path::new(&name);
                if base.is_some()
                    && (path.is_absolute()
                        || path
                            .components()
                            .any(|c| matches!(c, std::path::Component::ParentDir)))
                {
                    bail!("flaw pack {name} in cowproof.toml must be a path inside the repository");
                }
                let full = base
                    .as_ref()
                    .map_or_else(|| path.to_path_buf(), |b| b.join(path));
                // A pack named by the repository's own config stays inside it, symlinks
                // included: a parse error quotes the file, so an escaping link would print
                // part of a file from outside the repository into the report.
                if let Some(base) = base {
                    let root = base
                        .canonicalize()
                        .with_context(|| format!("resolve the repository {}", base.display()))?;
                    let real = full
                        .canonicalize()
                        .with_context(|| format!("read flaw pack {name} ({})", full.display()))?;
                    if !real.starts_with(&root) {
                        bail!(
                            "flaw pack {name} in cowproof.toml must be a path inside the repository"
                        );
                    }
                }
                fs::read_to_string(&full)
                    .with_context(|| format!("read flaw pack {name} ({})", full.display()))?
            }
        };
        let file = parse_rules(&text).map_err(|e| anyhow::anyhow!("flaw pack {name}: {e}"))?;
        rules.extend(file.rules);
        names.push(key);
    }
    Ok((rules, names))
}

/// Build the report for one lane.
pub fn handback(options: &Options) -> Result<Report> {
    let lane = options.lane.clone();
    let repo = options.repo.clone();
    let packet_arg = options.packet.clone();
    let baseline = options.baseline.clone();
    let summary: Value =
        serde_json::from_slice(&fs::read(lane.join("summary.json")).context("read summary.json")?)
            .context("parse summary.json")?;
    let patch = fs::read_to_string(lane.join("lane.patch")).context("read lane.patch")?;
    let outside = fs::read_to_string(lane.join("outside-ownership.patch")).unwrap_or_default();
    let deltas: Vec<PatchDelta> = parse_patch(&patch);
    let files = deltas
        .iter()
        .map(|d| d.path.as_str())
        .collect::<BTreeSet<_>>()
        .len();
    let added: usize = deltas.iter().map(|d| d.added.len()).sum();
    let removed: usize = deltas.iter().map(|d| d.removed.len()).sum();
    let mut handoff = handoff_from_patch(&patch, &summary, repo.as_deref());
    if handoff.is_none()
        && let Some(p) = value_str(&summary, &["handoff"])
        && let Some(r) = repo.as_deref()
    {
        handoff = fs::read_to_string(r.join(p)).ok();
    }
    if handoff.is_none() {
        handoff = fs::read_to_string(lane.join("handoff.md")).ok();
    }
    let handoff = handoff.unwrap_or_default();
    let (checks, unparsed) = parse_checks(&handoff);
    let packet = packet_arg
        .and_then(|p| fs::read_to_string(p).ok())
        .or_else(|| {
            let id = value_str(&summary, &["id", "lane_id"]).unwrap_or_default();
            let root = repo.as_deref().unwrap_or(Path::new("."));
            [root.join("packets"), root.join(".")].iter().find_map(|d| {
                fs::read_dir(d)
                    .ok()?
                    .filter_map(Result::ok)
                    .map(|e| e.path())
                    .find(|p| {
                        p.is_file()
                            && p.extension().is_some_and(|x| x == "md")
                            && fs::read_to_string(p).is_ok_and(|s| packet_has_lane_id(&s, &id))
                    })
                    .and_then(|p| fs::read_to_string(p).ok())
            })
        });
    let named = packet.as_deref().map(packet_commands).unwrap_or_default();
    let reported: BTreeSet<_> = checks.iter().map(|c| c.command.as_str()).collect();
    let missing: Vec<String> = named
        .into_iter()
        .filter(|c| !reported.contains(c.as_str()))
        .collect();
    // One matcher for the whole workspace: cowproof_prove::flaws.
    let (rules, packs) = load_packs(options)?;
    let (found, errors) = check_rules(&rules, &deltas, baseline.as_deref());
    if !errors.is_empty() {
        bail!("bad flaw rule: {}", errors.join("; "));
    }
    let flaws: Vec<Finding> = found
        .into_iter()
        .map(|f| Finding {
            file: f.file,
            line: f.line,
            pattern: f.pattern,
            explanation: f.explanation,
        })
        .collect();
    let mut ac = BTreeMap::<String, (usize, usize)>::new();
    for d in &deltas {
        let rem = d.removed.iter().filter(|(_, s)| assertions(s) > 0).count();
        let add = d.added.iter().filter(|(_, s)| assertions(s) > 0).count();
        if rem + add > 0 {
            ac.insert(d.path.clone(), (rem, add));
        }
    }
    let removed_assertions = ac
        .into_iter()
        .map(|(file, (removed, added))| AssertionChange {
            file,
            removed,
            added,
            net_loss: removed.saturating_sub(added),
        })
        .collect::<Vec<_>>();
    let mut reasons = Vec::new();
    let status = value_str(&summary, &["status"]).unwrap_or_else(|| "unknown".into());
    let mut verdict = if status.starts_with("failed") || status.starts_with("provider refused") {
        reasons.push(format!("lane status is {status}"));
        "rerun"
    } else if !missing.is_empty() {
        reasons.push(format!(
            "{} packet command(s) are not reported",
            missing.len()
        ));
        "escalate"
    } else if checks.iter().any(|c| c.classification == "fail")
        || !flaws.is_empty()
        || removed_assertions.iter().any(|a| a.net_loss > 0)
    {
        if !flaws.is_empty() {
            reasons.push(format!("{} flaw hit(s)", flaws.len()));
        }
        if removed_assertions.iter().any(|a| a.net_loss > 0) {
            reasons.push("assertions have a net loss".into());
        }
        if checks.iter().any(|c| c.classification == "fail") {
            reasons.push("a reported check failed".into());
        }
        "fix-then-apply"
    } else if checks
        .iter()
        .any(|c| c.classification == "not run" || c.classification == "unclear")
    {
        reasons.push("one or more reported checks are not run or unclear".into());
        "escalate"
    } else {
        reasons.push("no reported blocker found".into());
        "apply"
    };
    if !unparsed.is_empty() {
        if verdict == "apply" {
            // "no reported blocker found" would read as clean next to the warning.
            reasons.clear();
            verdict = "escalate";
        }
        reasons.push(format!(
            "{} handoff line(s) look like check claims but did not parse; the check list may be incomplete",
            unparsed.len()
        ));
    }
    Ok(Report {
        lane_id: value_str(&summary, &["id", "lane_id"]).unwrap_or_else(|| "unknown".into()),
        status,
        minutes: value_num(&summary, &["minutes"])
            .or_else(|| value_num(&summary, &["seconds"]).map(|s| (s + 30) / 60)),
        files_changed: files,
        lines_added: added,
        lines_removed: removed,
        outside_ownership_count: value_num(&summary, &["outsideCount", "outsideOwnershipCount"])
            .unwrap_or_else(|| outside.matches("diff --git ").count() as u64)
            as usize,
        checks,
        packet_commands_unreported: missing,
        unparsed,
        packs,
        flaws,
        removed_assertions,
        limits: extract_sections(&handoff, "limits"),
        unverified: extract_sections(&handoff, "unverified"),
        questions: extract_sections(&handoff, "questions"),
        verdict_hint: verdict.into(),
        verdict_reasons: reasons,
        sample_handoff: (!handoff.is_empty()).then(|| handoff.chars().take(6000).collect()),
    })
}
/// The text form of the report, printed when `--json` is not given.
pub fn print_report(r: &Report) {
    if !r.unparsed.is_empty() {
        println!(
            "WARNING: {} handoff line(s) look like check claims but did not parse. This report may be missing checks:",
            r.unparsed.len()
        );
        for u in &r.unparsed {
            println!("- line {}: {} ({})", u.line, u.text, u.reason);
        }
    }
    println!(
        "Lane: {} | status: {} | minutes: {}",
        r.lane_id,
        r.status,
        r.minutes.map_or("unknown".into(), |m| m.to_string())
    );
    println!(
        "Files changed: {} | lines: +{} -{} | outside ownership: {}",
        r.files_changed, r.lines_added, r.lines_removed, r.outside_ownership_count
    );
    println!("Checks:");
    for c in &r.checks {
        println!("- {}: {} ({})", c.command, c.classification, c.result);
    }
    println!(
        "Packet commands unreported: {}",
        r.packet_commands_unreported.len()
    );
    if r.packs.len() > 1 {
        println!("Flaws: {} (packs: {})", r.flaws.len(), r.packs.join(", "));
    } else {
        println!("Flaws: {}", r.flaws.len());
    }
    for f in &r.flaws {
        println!(
            "- {}:{} {}",
            f.file,
            f.line.map_or("path".into(), |n| n.to_string()),
            f.explanation
        );
    }
    println!("Removed assertions:");
    for a in &r.removed_assertions {
        println!(
            "- {}: removed {}, added {}, net loss {}",
            a.file, a.removed, a.added, a.net_loss
        );
    }
    println!(
        "Limits: {:?}\nUnverified: {:?}\nQuestions: {:?}",
        r.limits, r.unverified, r.questions
    );
    println!(
        "Verdict hint: {} ({})",
        r.verdict_hint,
        r.verdict_reasons.join("; ")
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mixed_fixture_reports_checks_assertion_loss_and_handoff_sections() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/mixed");
        let options = Options {
            lane: dir.clone(),
            packet: Some(dir.join("packet.md")),
            ..Options::default()
        };
        let r = handback(&options).unwrap();
        assert_eq!(r.lane_id, "fixture-lane");
        assert_eq!(r.minutes, Some(2));
        assert_eq!(
            r.checks
                .iter()
                .map(|c| c.classification.as_str())
                .collect::<Vec<_>>(),
            vec!["pass", "fail", "not run"]
        );
        assert_eq!(r.removed_assertions[0].net_loss, 2);
        assert_eq!(r.limits.len(), 1);
        assert_eq!(r.unverified.len(), 1);
        assert_eq!(r.questions.len(), 1);
        assert_eq!(r.verdict_hint, "fix-then-apply");
    }
    #[test]
    fn flaw_rules_cover_seeded_classes_and_detect_hits() {
        let generic = parse_rules(GENERIC_PACK).unwrap();
        let example = parse_rules(EXAMPLE_SUPABASE_PACK).unwrap();
        assert_eq!(generic.rules.len(), 5);
        assert_eq!(example.rules.len(), 8);
        let mut rules = generic;
        rules.rules.extend(example.rules);
        assert_eq!(rules.rules.len(), 13);
        let patch = fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/flaw-classes.patch"),
        )
        .unwrap();
        let deltas = parse_patch(&patch);
        let (hits, errors) = check_rules(&rules.rules, &deltas, Some("20260401_existing.sql"));
        assert!(errors.is_empty(), "{errors:?}");
        assert!(
            hits.len() >= 19,
            "detected only {} flaw examples",
            hits.len()
        );
        assert!(
            hits.iter()
                .any(|h| h.explanation.contains("current_setting('role')")),
            "the login-role guard rule must fire"
        );
        assert!(cowproof_core::glob_matches(
            "**/fixtures/**",
            "tests/fixtures/access.sql"
        ));
    }
    /// Words that tie a rule to one stack or project. None may appear in the generic pack.
    const STACK_WORDS: [&str; 10] = [
        "supabase",
        "postgres",
        "policy",
        "row level",
        "fetchimpl",
        "current_setting",
        "current_user",
        "grant",
        "concurrently",
        "migrations.lock",
    ];
    fn flaw_lane() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/flaws")
    }
    fn explanations(report: &Report) -> BTreeSet<String> {
        report.flaws.iter().map(|f| f.explanation.clone()).collect()
    }

    #[test]
    fn the_default_load_has_no_stack_specific_rule() {
        let generic = parse_rules(GENERIC_PACK).unwrap();
        for rule in &generic.rules {
            let text =
                format!("{} {} {:?}", rule.pattern, rule.explanation, rule.files).to_lowercase();
            for word in STACK_WORDS {
                assert!(!text.contains(word), "generic rule names {word}: {text}");
            }
        }
        let report = handback(&Options {
            lane: flaw_lane(),
            baseline: Some("20260401_existing.sql".into()),
            ..Options::default()
        })
        .unwrap();
        assert_eq!(report.packs, vec!["generic"]);
        assert!(!report.flaws.is_empty(), "the generic rules still fire");
        for f in &report.flaws {
            let text = f.explanation.to_lowercase();
            for word in STACK_WORDS {
                assert!(!text.contains(word), "default load reported {text}");
            }
        }
        assert!(
            !report
                .flaws
                .iter()
                .any(|f| f.file == "supabase/migrations.lock"),
            "the lock-file rule belongs to the example pack"
        );
    }

    #[test]
    fn the_example_pack_loads_when_asked_and_adds_its_rules() {
        let base = Options {
            lane: flaw_lane(),
            baseline: Some("20260401_existing.sql".into()),
            ..Options::default()
        };
        let default = handback(&base).unwrap();
        let with_pack = handback(&Options {
            packs: vec!["example-supabase".into()],
            ..base.clone()
        })
        .unwrap();
        assert_eq!(with_pack.packs, vec!["generic", "example-supabase"]);
        let extra: Vec<_> = explanations(&with_pack)
            .difference(&explanations(&default))
            .cloned()
            .collect();
        for expected in [
            "Placeholder or public policy broadens access.",
            "This weakens a row-level security or ownership boundary.",
            "The applied migrations lock file was edited.",
            "A fixture grants a privilege.",
        ] {
            assert!(extra.iter().any(|e| e == expected), "{expected}: {extra:?}");
        }
        assert!(
            with_pack
                .flaws
                .iter()
                .any(|f| f.file == "supabase/migrations.lock")
        );
        assert!(with_pack.flaws.len() > default.flaws.len());
    }

    #[test]
    fn a_pack_in_cowproof_toml_loads_and_a_pack_named_twice_loads_once() {
        let repo = tempfile::tempdir_in("/var/tmp").unwrap();
        fs::write(
            repo.path().join("cowproof.toml"),
            "[proof]\npacks = [\"generic\", \"example-supabase\", \"./mine.toml\"]\n",
        )
        .unwrap();
        fs::write(
            repo.path().join("mine.toml"),
            "[[rules]]\npattern = \"TODO_MARKER\"\nfiles = [\"**/*\"]\nexplanation = \"My own rule.\"\n",
        )
        .unwrap();
        let report = handback(&Options {
            lane: flaw_lane(),
            repo: Some(repo.path().to_path_buf()),
            packs: vec!["example-supabase".into()],
            ..Options::default()
        })
        .unwrap();
        assert_eq!(
            report.packs,
            vec!["generic", "example-supabase", "mine.toml"]
        );
        assert!(explanations(&report).contains("The applied migrations lock file was edited."));
    }

    #[test]
    fn a_missing_malformed_or_escaping_pack_is_an_error_not_an_empty_pack() {
        let lane = flaw_lane();
        let err = handback(&Options {
            lane: lane.clone(),
            packs: vec!["/var/tmp/fr1-no-such-pack.toml".into()],
            ..Options::default()
        })
        .unwrap_err();
        assert!(format!("{err:#}").contains("read flaw pack"), "{err:#}");

        let dir = tempfile::tempdir_in("/var/tmp").unwrap();
        let bad = dir.path().join("bad.toml");
        fs::write(&bad, "[[rules]]\npattern = \n").unwrap();
        let err = handback(&Options {
            lane: lane.clone(),
            packs: vec![bad.to_str().unwrap().into()],
            ..Options::default()
        })
        .unwrap_err();
        assert!(format!("{err:#}").contains("does not parse"), "{err:#}");

        fs::write(
            dir.path().join("cowproof.toml"),
            "[proof]\npacks = [\"../outside.toml\"]\n",
        )
        .unwrap();
        let err = handback(&Options {
            lane,
            repo: Some(dir.path().to_path_buf()),
            ..Options::default()
        })
        .unwrap_err();
        assert!(
            format!("{err:#}").contains("inside the repository"),
            "{err:#}"
        );

        // An absolute path, and a link inside the repository that leads out of it.
        let outside = tempfile::tempdir_in("/var/tmp").unwrap();
        let secret = outside.path().join("secret.toml");
        fs::write(&secret, "not = [toml\n").unwrap();
        std::os::unix::fs::symlink(&secret, dir.path().join("linked.toml")).unwrap();
        for named in [secret.to_str().unwrap(), "linked.toml"] {
            fs::write(
                dir.path().join("cowproof.toml"),
                format!("[proof]\npacks = [{named:?}]\n"),
            )
            .unwrap();
            let err = handback(&Options {
                lane: flaw_lane(),
                repo: Some(dir.path().to_path_buf()),
                ..Options::default()
            })
            .unwrap_err();
            assert!(
                format!("{err:#}").contains("inside the repository"),
                "{named}: {err:#}"
            );
        }
    }
    #[test]
    fn flaw_lane_fixture_runs_all_rules_including_baseline() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/flaws");
        let options = Options {
            lane: dir.clone(),
            baseline: Some("20260401_existing.sql".into()),
            packs: vec!["example-supabase".into()],
            ..Options::default()
        };
        let report = handback(&options).unwrap();
        assert_eq!(report.packs, vec!["generic", "example-supabase"]);
        assert!(
            report.flaws.len() >= 18,
            "reported {} flaws",
            report.flaws.len()
        );
        assert!(report.flaws.iter().any(|finding| {
            finding.file == "crates/demo/target/debug/demo"
                && finding.explanation == "Build output or scratch files appear in the patch."
        }));
        assert!(
            report
                .flaws
                .iter()
                .any(|f| f.file == "supabase/migrations/20260401_existing.sql")
        );
        assert!(
            !report
                .flaws
                .iter()
                .any(|f| f.file == "supabase/migrations/20260402_new.sql"
                    && f.pattern.starts_with("--baseline"))
        );
    }
    #[test]
    fn bullet_checks_and_packet_commands_parse() {
        let (checks, _) = parse_checks("- `cargo test` — PASS\n- `cargo build` — not run");
        assert_eq!(checks[1].classification, "not run");

        let (checks, _) = parse_checks("## Changed\n- `api/src/main.rs` — wired module");
        assert!(checks.is_empty());

        assert_eq!(classify("passed, 18 tests, 0 failed"), "pass");
        assert_eq!(classify("0 failed"), "pass");
        assert_eq!(classify("no failures"), "pass");
        assert_eq!(classify("exit 0"), "pass");
        assert_eq!(classify("failed once; final rerun passed"), "pass");
        assert_eq!(
            classify("passed, 6 passed tests; an earlier run failed before the passing run"),
            "pass"
        );
        assert_eq!(classify("Not run: unavailable"), "not run");
        assert_eq!(
            classify("passed: 6 passed, 0 failed; browser test skipped and not executed"),
            "pass"
        );

        let (checks, _) = parse_checks(
            "| Check | Result | Wall time |\n| --- | --- | --- |\n| `node --check` | exit 0 | 0.1s |",
        );
        assert_eq!(checks[0].classification, "pass");

        let (checks, _) =
            parse_checks("node scripts/check.mjs --flags  -> 4/4 scenarios passed (exit 0)");
        assert_eq!(checks.len(), 1);
        assert_eq!(checks[0].command, "node scripts/check.mjs --flags");
        assert_eq!(checks[0].classification, "pass");
        let sections = "## Limits and director question\nKeep migration.\n## Deferred\nLater.\n## Unverified\nBrowser.\n## Questions\nReview?";
        assert!(extract_sections(sections, "limits").contains(&"Later.".to_string()));
        assert_eq!(extract_sections(sections, "unverified"), vec!["Browser."]);
        assert_eq!(
            extract_sections(sections, "questions"),
            vec!["Keep migration.", "Review?"]
        );
        let p = fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/mixed/packet.md"),
        )
        .unwrap();
        assert_eq!(
            packet_commands(&p),
            vec!["cargo fmt".to_string(), "cargo test".to_string()]
        );
        assert!(packet_has_lane_id(
            "<!-- {\"id\":\"fixture-lane\"} -->",
            "fixture-lane"
        ));
    }
    #[test]
    fn table_format_fixture_matches_snapshot() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/table");
        let options = Options {
            lane: dir.clone(),
            ..Options::default()
        };
        let r = handback(&options).unwrap();
        let rendered = serde_json::to_string_pretty(&r).unwrap();
        let expected =
            fs::read_to_string(dir.join("expected.json")).expect("expected.json must exist");
        assert_eq!(
            rendered.trim(),
            expected.trim(),
            "rendered snapshot must match expected.json"
        );
        assert_eq!(r.lane_id, "fixture-table");
        assert_eq!(r.checks.len(), 3);
        assert_eq!(r.checks[0].classification, "pass");
        assert_eq!(r.checks[1].classification, "fail");
        assert_eq!(r.checks[2].classification, "unclear");
    }
    #[test]
    fn bullet_format_fixture_matches_snapshot() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/bullet");
        let options = Options {
            lane: dir.clone(),
            ..Options::default()
        };
        let r = handback(&options).unwrap();
        let rendered = serde_json::to_string_pretty(&r).unwrap();
        let expected =
            fs::read_to_string(dir.join("expected.json")).expect("expected.json must exist");
        assert_eq!(
            rendered.trim(),
            expected.trim(),
            "rendered snapshot must match expected.json"
        );
        assert_eq!(r.lane_id, "fixture-bullet");
        assert_eq!(r.checks.len(), 4);
        assert!(r.checks.iter().any(|c| c.classification == "pass"));
        assert!(r.checks.iter().any(|c| c.classification == "fail"));
        assert!(r.checks.iter().any(|c| c.classification == "unclear"));
    }
    #[test]
    fn fenced_format_fixture_matches_snapshot() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fenced");
        let options = Options {
            lane: dir.clone(),
            ..Options::default()
        };
        let r = handback(&options).unwrap();
        let rendered = serde_json::to_string_pretty(&r).unwrap();
        let expected =
            fs::read_to_string(dir.join("expected.json")).expect("expected.json must exist");
        assert_eq!(
            rendered.trim(),
            expected.trim(),
            "rendered snapshot must match expected.json"
        );
        assert_eq!(r.lane_id, "fixture-fenced");
        assert_eq!(r.checks.len(), 5, "the block under a subheading is a check");
        assert!(r.unparsed.is_empty());
        assert!(r.checks.iter().any(|c| c.classification == "pass"));
        assert!(r.checks.iter().any(|c| c.classification == "fail"));
    }
    #[test]
    fn arrow_format_fixture_matches_snapshot() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/arrow");
        let options = Options {
            lane: dir.clone(),
            ..Options::default()
        };
        let r = handback(&options).unwrap();
        let rendered = serde_json::to_string_pretty(&r).unwrap();
        let expected =
            fs::read_to_string(dir.join("expected.json")).expect("expected.json must exist");
        assert_eq!(
            rendered.trim(),
            expected.trim(),
            "rendered snapshot must match expected.json"
        );
        assert_eq!(r.lane_id, "fixture-arrow");
        assert_eq!(r.checks.len(), 3);
        assert!(r.checks.iter().any(|c| c.classification == "pass"));
        assert!(r.checks.iter().any(|c| c.classification == "unclear"));
    }
    #[test]
    fn questions_fixture_matches_snapshot() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/questions");
        let options = Options {
            lane: dir.clone(),
            ..Options::default()
        };
        let r = handback(&options).unwrap();
        let rendered = serde_json::to_string_pretty(&r).unwrap();
        let expected =
            fs::read_to_string(dir.join("expected.json")).expect("expected.json must exist");
        assert_eq!(
            rendered.trim(),
            expected.trim(),
            "rendered snapshot must match expected.json"
        );
        assert_eq!(r.lane_id, "fixture-questions");
        assert_eq!(r.questions.len(), 3);
    }
    #[test]
    fn limits_fixture_matches_snapshot() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/limits");
        let options = Options {
            lane: dir.clone(),
            ..Options::default()
        };
        let r = handback(&options).unwrap();
        let rendered = serde_json::to_string_pretty(&r).unwrap();
        let expected =
            fs::read_to_string(dir.join("expected.json")).expect("expected.json must exist");
        assert_eq!(
            rendered.trim(),
            expected.trim(),
            "rendered snapshot must match expected.json"
        );
        assert_eq!(r.lane_id, "fixture-limits");
        assert!(!r.limits.is_empty());
        assert!(!r.unverified.is_empty());
    }
    #[test]
    fn baseline_fixture_matches_snapshot() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/baseline");
        let options = Options {
            lane: dir.clone(),
            baseline: Some("20260401_existing.sql".into()),
            ..Options::default()
        };
        let r = handback(&options).unwrap();
        let rendered = serde_json::to_string_pretty(&r).unwrap();
        let expected =
            fs::read_to_string(dir.join("expected.json")).expect("expected.json must exist");
        assert_eq!(
            rendered.trim(),
            expected.trim(),
            "rendered snapshot must match expected.json"
        );
        assert_eq!(r.lane_id, "fixture-baseline");
    }
    fn fixture_report(name: &str) -> Report {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name);
        let report = handback(&Options {
            lane: dir.clone(),
            ..Options::default()
        })
        .unwrap();
        let expected =
            fs::read_to_string(dir.join("expected.json")).expect("expected.json must exist");
        assert_eq!(
            serde_json::to_string_pretty(&report).unwrap().trim(),
            expected.trim(),
            "{name}: rendered snapshot must match expected.json"
        );
        report
    }
    fn unparsed_at(report: &Report) -> Vec<(usize, &str)> {
        report
            .unparsed
            .iter()
            .map(|u| (u.line, u.reason.as_str()))
            .collect()
    }
    #[test]
    fn table_rows_with_empty_cells_are_unparsed_with_their_line_numbers() {
        let r = fixture_report("unparsed-table");
        assert_eq!(
            r.checks
                .iter()
                .map(|c| c.command.as_str())
                .collect::<Vec<_>>(),
            vec!["cargo test", "cargo fmt"]
        );
        assert_eq!(
            unparsed_at(&r),
            vec![
                (6, "table row has empty cells"),
                (7, "table row has empty cells")
            ]
        );
        assert_eq!(r.verdict_hint, "escalate");
        assert!(
            r.verdict_reasons
                .iter()
                .any(|x| x.contains("did not parse"))
        );
    }
    #[test]
    fn bullets_without_their_separator_are_unparsed_but_prose_bullets_are_not() {
        let r = fixture_report("unparsed-bullet");
        assert_eq!(
            r.checks
                .iter()
                .map(|c| c.command.as_str())
                .collect::<Vec<_>>(),
            vec!["cargo test"]
        );
        let lines: Vec<usize> = r.unparsed.iter().map(|u| u.line).collect();
        assert_eq!(lines, vec![4, 5, 6], "{:?}", r.unparsed);
        assert!(r.unparsed[0].reason.contains("no dash or em dash"));
    }
    #[test]
    fn arrow_lines_with_one_space_no_space_or_no_result_are_unparsed() {
        let r = fixture_report("unparsed-arrow");
        assert_eq!(r.checks.len(), 1);
        let lines: Vec<usize> = r.unparsed.iter().map(|u| u.line).collect();
        assert_eq!(lines, vec![4, 5, 6], "{:?}", r.unparsed);
        assert!(r.unparsed.iter().all(|u| u.reason.contains("two spaces")));
    }
    #[test]
    fn a_fenced_claim_outside_the_checks_heading_is_unparsed_a_usage_example_is_not() {
        let r = fixture_report("unparsed-fenced");
        assert_eq!(
            r.checks
                .iter()
                .map(|c| c.command.as_str())
                .collect::<Vec<_>>(),
            vec!["cargo test"]
        );
        assert_eq!(
            unparsed_at(&r),
            vec![(14, "fenced command outside the checks section")]
        );
        assert_eq!(r.unparsed[0].text, "cargo clippy --all-targets");
    }
    #[test]
    fn the_existing_fixtures_have_no_unparsed_lines() {
        for name in ["table", "bullet", "arrow", "fenced", "mixed"] {
            let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures")
                .join(name);
            let r = handback(&Options {
                lane: dir,
                ..Options::default()
            })
            .unwrap();
            assert!(r.unparsed.is_empty(), "{name}: {:?}", r.unparsed);
        }
    }
    #[test]
    fn ordinary_prose_is_never_unparsed() {
        let text = "# Summary\n\nI ran git rebase and cargo test locally -> it worked.\n- Ran `cargo test` twice\n- git history was rewritten\n- `src/main.rs` - wired the module\n| File | Change |\n| --- | --- |\n| `src/a.rs` | new |\n\n```\ncargo run\n```\n\nThen open the page.\n\n# Notes\n\nResult -> fine.\n";
        let (checks, unparsed) = parse_checks(text);
        assert!(checks.is_empty(), "{checks:?}");
        assert!(unparsed.is_empty(), "{unparsed:?}");
    }
    #[test]
    fn inside_a_checks_section_an_unknown_command_or_a_bare_command_bullet_is_unparsed() {
        let text = "# Checks\n- `make test` - passed\nmake lint  ->  passed\n- cargo test passed\n| Command | Result |\n| --- | --- |\n| `cargo test` |\n";
        let (checks, unparsed) = parse_checks(text);
        assert!(checks.is_empty(), "{checks:?}");
        let lines: Vec<usize> = unparsed.iter().map(|u| u.line).collect();
        assert_eq!(lines, vec![2, 3, 4, 7], "{unparsed:?}");
        assert!(unparsed[3].reason.contains("fewer cells"));
    }
    #[test]
    fn a_fenced_block_in_the_checks_section_without_a_result_is_unparsed() {
        let (checks, unparsed) = parse_checks("# Checks\n```\ncargo test\n```\n\n# Notes\n");
        assert!(checks.is_empty());
        assert_eq!(unparsed.len(), 1);
        assert_eq!(unparsed[0].line, 3);
        assert!(unparsed[0].reason.contains("no result line"));
    }
    #[test]
    fn a_subheading_under_a_checks_heading_is_still_the_checks_section() {
        let text = "# Verification\n## Unknown status\n```\ncargo build\n```\nBuild completed.\n";
        let (checks, unparsed) = parse_checks(text);
        assert!(unparsed.is_empty(), "{unparsed:?}");
        assert_eq!(checks.len(), 1);
        assert_eq!(checks[0].classification, "unclear");
    }
    #[test]
    fn numbered_checks_parse_like_bullets() {
        let (checks, unparsed) =
            parse_checks("1. `cargo test` - 12 passed\n2) `git diff --check` - failed");
        assert!(unparsed.is_empty(), "{unparsed:?}");
        assert_eq!(
            checks
                .iter()
                .map(|c| c.classification.as_str())
                .collect::<Vec<_>>(),
            vec!["pass", "fail"]
        );
    }
    #[test]
    fn a_report_with_unparsed_lines_is_not_applied_on_its_own() {
        let r = fixture_report("unparsed-table");
        assert_eq!(r.checks.len(), 2);
        assert!(r.checks.iter().all(|c| c.classification == "pass"));
        assert_ne!(r.verdict_hint, "apply");
    }
    #[test]
    fn extended_failure_vocabulary() {
        // Error phrases should classify as fail
        assert_eq!(classify("Errors detected in test suite"), "fail");
        assert_eq!(classify("3 failed tests"), "fail");
        assert_eq!(classify("exit 1"), "fail");
        assert_eq!(classify("exited with 2"), "fail");
        assert_eq!(classify("status 101"), "fail");
        assert_eq!(classify("panicked at line 42"), "fail");
        assert_eq!(classify("FAILED: compilation"), "fail");
        assert_eq!(classify("error occurred"), "fail");
        assert_eq!(classify("errored during compilation"), "fail");
        assert_eq!(classify("failing test"), "fail");
        assert_eq!(classify("failure in setup"), "fail");

        // Zero failures and "no errors" should still be pass
        assert_eq!(classify("0 failed"), "pass");
        // A nonzero count anywhere wins over a zero count elsewhere.
        assert_eq!(classify("suite a: 0 failed; suite b: 2 failed"), "fail");
        assert_eq!(classify("no errors, 1 failed"), "fail");
        assert_eq!(classify("exit 0 from setup, then 3 errors"), "fail");
        assert_eq!(classify("test result: ok. 12 passed; 0 failed"), "pass");
        assert_eq!(classify("status ok"), "pass");
        assert_eq!(
            classify("final rerun passed after 1 failed attempt"),
            "pass"
        );
        assert_eq!(classify("no errors"), "pass");
        assert_eq!(classify("0 errors"), "pass");
        assert_eq!(classify("no failures"), "pass");
        assert_eq!(classify("exit 0"), "pass");
    }
    #[test]
    fn plain_failure_statements_are_fail() {
        for text in [
            "Errors detected in test suite",
            "error: could not compile `demo`",
            "2 failed",
            "test result: FAILED. 10 passed; 2 failed",
            "failure",
            "failures in the db suite",
            "the suite fails",
            "panicked at src/lib.rs:4",
            "did not pass",
            "didn't pass",
            "does not pass",
            "not passing",
            "failed to pass",
            "the build is not ok",
            "unsuccessful",
            "timed out after 20 minutes",
            "crashed",
            "failures: 3",
            "errors: 1",
            "exit code: 2",
            "no errors in lint, but the build failed",
            "0 failed in suite a, build failed",
        ] {
            assert_eq!(classify(text), "fail", "{text}");
        }
    }
    #[test]
    fn statements_that_nothing_failed_are_not_fail() {
        for text in [
            "0 failed",
            "no errors",
            "failures: none",
            "errors: 0",
            "no failing tests",
            "zero failures",
            "did not fail",
            "without errors",
            "error-free",
            "all passed, no test failures",
            "exit code: 0",
            "passes",
            "ran clean",
        ] {
            assert_eq!(classify(text), "pass", "{text}");
        }
        // Fixing a failure is not a failure, and it is not a pass either.
        for text in [
            "fixed the failing test",
            "fixing the failures",
            "resolved 2 failed tests",
        ] {
            assert_eq!(classify(text), "unclear", "{text}");
        }
        assert_eq!(
            classify("fixed the failing test and re-ran: passed"),
            "pass"
        );
        assert_eq!(classify("fixed the formatter but tests failed"), "fail");
        assert_eq!(classify("did not pass at first, now passes"), "pass");
    }
}
