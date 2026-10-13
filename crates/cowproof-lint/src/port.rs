//! The lint rules of `kind: port` packets (portkit-integration.md, section 6.4).
//!
//! Eight rules, none of which runs anything: they read the header, the packet text and the
//! files a port names. `port-nondeterministic-output` is a heuristic and only warns.
//!
//! | Rule | Level | Fires when |
//! | --- | --- | --- |
//! | `port-cases-missing` | error | `port.cases` is not a file in the repository |
//! | `port-adapter-missing` | error | the script file `port.reference.cmd` runs (`node adapter.mjs ...`, `./run.sh`) is not a file in the repository, or its path is absolute or has `..` |
//! | `port-fixtures-not-owned` | error | `owns` does not cover `<port.fixtures>/<tool>/<id>.json` for every tool |
//! | `port-reference-not-allowed` | error | a `wide: false` packet has a check that runs `port.reference.cmd` and no `allow` entry matches the check |
//! | `port-tool-unregistered` | error | a tool in `port.tools` is not named in the packet text, or the text names no owned plugin manifest to register it in |
//! | `port-accepted-unruled` | error | a fixture's `accepted` entry has a reason that cites no `ruling:<id>`, or an id the lane's escalation log does not carry |
//! | `port-epsilon-loosened` | error | the packet or a fixture raises epsilon above the project default |
//! | `port-nondeterministic-output` | warn | a fixture's expected output has a time, a temp or home path, or a host name that no `ignore_paths`, `accepted` or `path_roots` entry covers |

use crate::{
    BASE_ALLOW, Finding, checks_section, command_matches, error, has_head, inline_list_commands,
    split_commands, warn,
};
use cowproof_core::port::{
    AcceptedEntry, RulingLog, Unruled, accepted_entries, project_epsilon,
    project_epsilon_at_commit, read_fixture_files, unruled,
};
use cowproof_core::{Header, PortSpec, glob_matches};
use regex::Regex;
use serde_json::Value;
use std::fs;
use std::path::{Component, Path};

/// The tokens a process capture substitutes for a run's directories (`PATH_ROOT_TOKENS`).
const ROOT_TOKENS: [&str; 4] = ["$ROOT", "$HOME", "$TMP", "$SRC"];

/// The most `port-nondeterministic-output` findings one packet reports.
const MAX_NONDETERMINISTIC: usize = 20;

/// What a port packet's lint can read beyond the packet and the repository.
#[derive(Clone, Copy, Debug, Default)]
pub struct LintOptions<'a> {
    /// The lane's `escalations.jsonl`. With it, `port-accepted-unruled` also requires each
    /// cited ruling id to be carried by a director's answer in it; without it the rule checks
    /// only that every reason cites a ruling.
    pub escalations: Option<&'a Path>,
}

/// The port rules for `header`, when it is a port packet.
pub(crate) fn lint_port(
    header: &Header,
    packet_text: &str,
    repo_root: &Path,
    options: &LintOptions,
    findings: &mut Vec<Finding>,
) {
    let Some(port) = &header.port else {
        return;
    };
    cases_missing(port, repo_root, findings);
    adapter_missing(port, repo_root, findings);
    fixtures_not_owned(header, port, findings);
    reference_not_allowed(header, port, packet_text, findings);
    tool_unregistered(header, port, packet_text, findings);
    accepted_unruled(port, repo_root, options, findings);
    epsilon_loosened(port, repo_root, findings);
    nondeterministic_output(port, repo_root, findings);
}

fn cases_missing(port: &PortSpec, repo_root: &Path, findings: &mut Vec<Finding>) {
    if !repo_root.join(&port.cases).is_file() {
        findings.push(error(
            "port-cases-missing",
            None,
            format!(
                "port.cases {:?} is not a file in the repository; commit the cases file the fixtures are captured from",
                port.cases
            ),
        ));
    }
}

/// Programs that run a script file they are given as an argument. A bare program that is not
/// one of these (`cargo`, `make`, `sh -c '...'` aside) has no file the lint can name.
const INTERPRETERS: [&str; 17] = [
    "node", "nodejs", "deno", "bun", "tsx", "ts-node", "python", "python3", "ruby", "perl", "php",
    "bash", "sh", "dash", "zsh", "ksh", "fish",
];

/// Flags that take code, a module or a command in place of a script file: with one of
/// these the command runs no file.
const INLINE_FLAGS: [&str; 8] = [
    "-c",
    "-e",
    "-p",
    "-m",
    "-E",
    "--eval",
    "--print",
    "--command",
];

/// Flags that take a value in the next word, so the value is not the script.
const VALUE_FLAGS: [&str; 10] = [
    "-r",
    "--require",
    "--import",
    "--loader",
    "--experimental-loader",
    "--env-file",
    "-W",
    "-X",
    "--conditions",
    "-C",
];

/// One word of a shell command line, and whether the shell would expand it (so its value is
/// not the text).
struct Word {
    text: String,
    dynamic: bool,
}

/// The words of the first simple command of `cmd`: quotes and backslashes are removed, and
/// the reading stops at an unquoted operator (`|`, `&`, `;`, `<`, `>`, `(`, `)`, a newline).
/// An unterminated quote gives no words.
fn shell_words(cmd: &str) -> Vec<Word> {
    let mut words = Vec::new();
    let mut text = String::new();
    let mut dynamic = false;
    let mut open = false;
    let mut chars = cmd.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\'' => {
                open = true;
                loop {
                    match chars.next() {
                        Some('\'') => break,
                        Some(c) => text.push(c),
                        None => return Vec::new(),
                    }
                }
            }
            '"' => {
                open = true;
                loop {
                    match chars.next() {
                        Some('"') => break,
                        Some('\\') if matches!(chars.peek(), Some('"' | '\\' | '$' | '`')) => {
                            text.push(chars.next().unwrap_or('\\'));
                        }
                        Some(c) => {
                            dynamic |= c == '$' || c == '`';
                            text.push(c);
                        }
                        None => return Vec::new(),
                    }
                }
            }
            '\\' => {
                open = true;
                match chars.next() {
                    Some(c) => text.push(c),
                    None => return Vec::new(),
                }
            }
            c if c.is_whitespace() && c != '\n' => {
                if open {
                    words.push(Word {
                        text: std::mem::take(&mut text),
                        dynamic,
                    });
                    open = false;
                    dynamic = false;
                }
            }
            '|' | '&' | ';' | '<' | '>' | '(' | ')' | '\n' => break,
            c => {
                open = true;
                dynamic |=
                    matches!(c, '$' | '`' | '*' | '?' | '[' | '{') || (c == '~' && text.is_empty());
                text.push(c);
            }
        }
    }
    if open {
        words.push(Word { text, dynamic });
    }
    words
}

/// The file the reference command runs, as written in the command: the first argument after
/// an interpreter (`node adapter.mjs`, `python3 -u reference/adapter.py`), or the command
/// itself when it is a path (`./adapter.sh`). `None` when there is no file to name: a bare
/// program on `PATH` (`cargo run`), inline code (`sh -c '...'`, `node -e ...`), or a word
/// the shell would expand.
fn adapter_script(cmd: &str) -> Option<String> {
    let words = shell_words(cmd);
    let mut words = words.iter().peekable();
    // Leading `NAME=value` assignments and an `env` in front of the program.
    while let Some(word) = words.peek() {
        let is_assignment = word.text.split_once('=').is_some_and(|(name, _)| {
            !name.is_empty()
                && !name.starts_with(|c: char| c.is_ascii_digit())
                && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        });
        if is_assignment || word.text == "env" {
            words.next();
        } else {
            break;
        }
    }
    let program = words.next()?;
    if program.dynamic {
        return None;
    }
    let basename = program.text.rsplit('/').next().unwrap_or_default();
    let versioned = basename
        .strip_prefix("python")
        .is_some_and(|v| !v.is_empty() && v.chars().all(|c| c.is_ascii_digit() || c == '.'));
    if !(INTERPRETERS.contains(&basename) || versioned) {
        // Not an interpreter: the command is the file when it is a path.
        return program.text.contains('/').then(|| program.text.clone());
    }
    while let Some(word) = words.next() {
        if word.dynamic {
            return None;
        }
        let flag = word.text.as_str();
        if INLINE_FLAGS.contains(&flag)
            || flag.starts_with("--eval=")
            || flag.starts_with("--print=")
        {
            return None;
        }
        if VALUE_FLAGS.contains(&flag) {
            words.next();
        } else if !flag.starts_with('-') {
            return Some(word.text.clone());
        }
    }
    None
}

fn adapter_missing(port: &PortSpec, repo_root: &Path, findings: &mut Vec<Finding>) {
    let Some(reference) = &port.reference else {
        return;
    };
    let Some(script) = adapter_script(&reference.cmd) else {
        return;
    };
    // The reference runs with the repository, or its `cwd` folder, as the working directory.
    let relative = match &reference.cwd {
        Some(cwd) if !Path::new(&script).is_absolute() => Path::new(cwd).join(&script),
        _ => Path::new(&script).to_path_buf(),
    };
    if relative.is_absolute()
        || relative
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::RootDir))
    {
        findings.push(error(
            "port-adapter-missing",
            None,
            format!(
                "port.reference.cmd runs {script:?}, a path outside the repository (absolute or with ..); commit the adapter inside the repository and name it relative"
            ),
        ));
    } else if !repo_root.join(&relative).is_file() {
        findings.push(error(
            "port-adapter-missing",
            None,
            format!(
                "port.reference.cmd runs {script:?}, which is not a file in the repository ({}); commit the adapter the reference command runs",
                relative.display()
            ),
        ));
    }
}

fn fixtures_not_owned(header: &Header, port: &PortSpec, findings: &mut Vec<Finding>) {
    let dir = port.fixtures.trim_end_matches('/');
    for tool in &port.tools {
        let probe = format!("{dir}/{tool}/case.json");
        if !header.owns.iter().any(|glob| glob_matches(glob, &probe)) {
            findings.push(error(
                "port-fixtures-not-owned",
                None,
                format!(
                    "owns does not cover the fixtures of tool {tool:?} ({dir}/{tool}/<id>.json); add \"{dir}/**\" to owns"
                ),
            ));
        }
    }
}

/// The commands a `## Checks` section lists: code spans of list items and the lines of
/// fenced blocks, the same reading `lint_checks` gives them.
fn section_commands(section: &str) -> Vec<String> {
    let mut in_fence = false;
    let mut commands = Vec::new();
    for line in section.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("```") {
            in_fence = !in_fence;
            continue;
        }
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if in_fence {
            commands.extend(
                split_commands(trimmed.trim_start_matches(['-', '*', ' ']).trim())
                    .into_iter()
                    .map(str::to_owned),
            );
        } else {
            commands.extend(inline_list_commands(trimmed));
        }
    }
    commands
}

fn squash(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn reference_not_allowed(
    header: &Header,
    port: &PortSpec,
    packet_text: &str,
    findings: &mut Vec<Finding>,
) {
    let Some(reference) = &port.reference else {
        return;
    };
    if header.is_wide() {
        return;
    }
    let needle = squash(&reference.cmd);
    let mut commands: Vec<String> = header.checks.iter().map(|c| c.command.clone()).collect();
    if let Some((_, section)) = checks_section(packet_text) {
        commands.extend(section_commands(section));
    }
    let mut reported = Vec::new();
    for command in commands {
        let normalized = squash(&command);
        if !normalized.contains(&needle) || reported.contains(&normalized) {
            continue;
        }
        let allowed = BASE_ALLOW
            .iter()
            .copied()
            .chain(header.allow.iter().map(String::as_str))
            .any(|pattern| command_matches(pattern, &normalized));
        if !allowed {
            findings.push(error(
                "port-reference-not-allowed",
                None,
                format!(
                    "check {normalized:?} runs the reference command {:?} and no allow entry matches it; add an allow entry for it or make the lane wide",
                    reference.cmd
                ),
            ));
        }
        reported.push(normalized);
    }
}

/// The packet text without its `<!-- lane {...} -->` header comment.
fn body(packet_text: &str) -> String {
    match (packet_text.find("<!--"), packet_text.find("-->")) {
        (Some(open), Some(close)) if close > open => {
            format!("{}{}", &packet_text[..open], &packet_text[close + 3..])
        }
        _ => packet_text.to_string(),
    }
}

/// Whether `text` has `word` with no letter, digit, `_`, `-` or `.` joined to either end.
fn names_word(text: &str, word: &str) -> bool {
    let joined = |c: char| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.');
    text.match_indices(word).any(|(at, _)| {
        let before = text[..at].chars().next_back();
        let after = text[at + word.len()..].chars().next();
        !before.is_some_and(joined) && !after.is_some_and(joined)
    })
}

fn tool_unregistered(
    header: &Header,
    port: &PortSpec,
    packet_text: &str,
    findings: &mut Vec<Finding>,
) {
    let body = body(packet_text);
    // A registration target is a plugin manifest the packet names and the lane owns: the
    // tool is a plugin entry in it, which is how `pk port replay` finds the port's tool.
    let manifests: Vec<&str> = body
        .split(|c: char| c.is_whitespace() || matches!(c, '`' | '\'' | '"' | '(' | ')' | ',' | ';'))
        .map(|token| token.trim_start_matches("./"))
        .filter(|token| token.ends_with("plugins.toml"))
        .collect();
    let owned = manifests
        .iter()
        .any(|m| header.owns.iter().any(|glob| glob_matches(glob, m)));
    for tool in &port.tools {
        let problem = if !names_word(&body, tool) {
            Some(format!("the packet text does not name tool {tool:?}"))
        } else if manifests.is_empty() {
            Some(format!(
                "the packet text names no registration target for tool {tool:?}; name the plugin manifest it is registered in (for example .portkit/plugins.toml)"
            ))
        } else if !owned {
            Some(format!(
                "the plugin manifest the packet names for tool {tool:?} is not covered by owns"
            ))
        } else {
            None
        };
        if let Some(problem) = problem {
            findings.push(error("port-tool-unregistered", None, problem));
        }
    }
}

fn accepted_unruled(
    port: &PortSpec,
    repo_root: &Path,
    options: &LintOptions,
    findings: &mut Vec<Finding>,
) {
    let entries = accepted_entries(&repo_root.join(&port.fixtures));
    let log = match options.escalations.map(RulingLog::read) {
        None => None,
        Some(Ok(log)) => Some(log),
        Some(Err(e)) => {
            findings.push(error(
                "port-accepted-unruled",
                None,
                format!("the escalation log cannot be read: {e:#}"),
            ));
            return;
        }
    };
    for (entry, why) in unruled(&entries, log.as_ref()) {
        findings.push(error(
            "port-accepted-unruled",
            None,
            describe_unruled(entry, &why),
        ));
    }
}

fn describe_unruled(entry: &AcceptedEntry, why: &Unruled) -> String {
    let what = match why {
        Unruled::NoCitation => "cites no ruling (write \"ruling:<id>\" in the reason)".to_string(),
        Unruled::NotInLog(id) => {
            format!("cites ruling:{id}, which no director answer in the escalation log carries")
        }
    };
    format!(
        "fixture {} accepts a difference at {:?} but its reason {what}",
        entry.file, entry.path
    )
}

fn epsilon_loosened(port: &PortSpec, repo_root: &Path, findings: &mut Vec<Finding>) {
    let default = if has_head(repo_root) {
        project_epsilon_at_commit(repo_root, "HEAD")
    } else {
        project_epsilon(
            fs::read_to_string(repo_root.join("cowproof.toml"))
                .ok()
                .as_deref(),
        )
    };
    let default = match default {
        Ok(default) => default,
        Err(e) => {
            findings.push(error(
                "port-epsilon-loosened",
                None,
                format!("the project's default epsilon cannot be read: {e:#}"),
            ));
            return;
        }
    };
    if let Some(epsilon) = port.parity.epsilon
        && epsilon > default
    {
        findings.push(error(
            "port-epsilon-loosened",
            None,
            format!(
                "port.parity.epsilon {epsilon} is above the project default {default} ([port] epsilon in cowproof.toml); an accepted difference with a ruling is the way to allow one"
            ),
        ));
    }
    for (file, value) in read_fixture_files(&repo_root.join(&port.fixtures)) {
        if let Some(epsilon) = value.get("epsilon").and_then(Value::as_f64)
            && epsilon > default
        {
            findings.push(error(
                "port-epsilon-loosened",
                None,
                format!(
                    "fixture {file} sets epsilon {epsilon}, above the project default {default}"
                ),
            ));
        }
    }
}

struct Heuristics {
    time: Regex,
    path: Regex,
    host: Regex,
}

impl Heuristics {
    fn new() -> Self {
        Self {
            time: Regex::new(
                r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?",
            )
            .expect("a fixed pattern"),
            path: Regex::new(
                r#"(?:/tmp/|/var/folders/|/private/tmp/|/var/tmp/|/Users/[^/\s"']+|/home/[^/\s"']+|/root/)"#,
            )
            .expect("a fixed pattern"),
            host: Regex::new(
                r"\b[A-Za-z0-9][A-Za-z0-9-]*\.(?:local|lan|internal|localdomain|home\.arpa)\b",
            )
            .expect("a fixed pattern"),
        }
    }
}

/// Whether the JSON Pointer `pointer` is `prefix` or under it.
fn covers(prefix: &str, pointer: &str) -> bool {
    pointer == prefix || pointer.starts_with(&format!("{prefix}/"))
}

/// Whether a `path_roots` entry covers the path text `found`: the entry is a prefix of the
/// match, or a `$TMP`, `$HOME` or `$ROOT` name for the kind of path it is.
fn root_covers(roots: &[String], found: &str) -> bool {
    roots.iter().any(|root| match root.as_str() {
        "$TMP" => ["/tmp/", "/var/folders/", "/private/tmp/", "/var/tmp/"]
            .iter()
            .any(|p| found.starts_with(p)),
        "$HOME" => ["/Users/", "/home/", "/root/"]
            .iter()
            .any(|p| found.starts_with(p)),
        "$ROOT" => true,
        other => found.starts_with(other),
    })
}

fn walk_strings(value: &Value, pointer: &str, out: &mut Vec<(String, String)>) {
    match value {
        Value::String(text) => out.push((pointer.to_string(), text.clone())),
        Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                walk_strings(item, &format!("{pointer}/{i}"), out);
            }
        }
        Value::Object(map) => {
            for (key, item) in map {
                let key = key.replace('~', "~0").replace('/', "~1");
                walk_strings(item, &format!("{pointer}/{key}"), out);
            }
        }
        _ => {}
    }
}

fn nondeterministic_output(port: &PortSpec, repo_root: &Path, findings: &mut Vec<Finding>) {
    let heuristics = Heuristics::new();
    let mut reported = 0usize;
    for (file, fixture) in read_fixture_files(&repo_root.join(&port.fixtures)) {
        let Some(expected) = fixture.get("expected") else {
            continue;
        };
        let accepted: Vec<String> = accepted_entries_of(&fixture);
        let mut strings = Vec::new();
        walk_strings(expected, "", &mut strings);
        for (pointer, text) in strings {
            let declared = port.parity.ignore_paths.iter().any(|p| covers(p, &pointer))
                || accepted.iter().any(|p| covers(p, &pointer));
            if declared {
                continue;
            }
            let found = if let Some(m) = heuristics.time.find(&text) {
                Some(("a time", m.as_str().to_string(), false))
            } else if let Some(m) = heuristics.path.find_iter(&text).find(|m| {
                // `$ROOT/home/a` is a process capture's own substitution (portkit's
                // `path-roots`), not a home directory: the heuristic reads the path after the
                // placeholder, so a placeholder in front of it is not a finding.
                !ROOT_TOKENS.iter().any(|t| text[..m.start()].ends_with(t))
            }) {
                Some(("a temp or home path", m.as_str().to_string(), true))
            } else {
                heuristics
                    .host
                    .find(&text)
                    .map(|m| ("a host name", m.as_str().to_string(), false))
            };
            let Some((what, sample, is_path)) = found else {
                continue;
            };
            if is_path && root_covers(&port.parity.path_roots, &sample) {
                continue;
            }
            if reported == MAX_NONDETERMINISTIC {
                findings.push(warn(
                    "port-nondeterministic-output",
                    None,
                    format!(
                        "more than {MAX_NONDETERMINISTIC} such outputs; the rest are not listed"
                    ),
                ));
                return;
            }
            reported += 1;
            findings.push(warn(
                "port-nondeterministic-output",
                None,
                format!(
                    "fixture {file}, {pointer:?}: the expected output holds {what} ({sample:?}) and no ignore_paths, accepted or path_roots entry covers it; a rerun will differ"
                ),
            ));
        }
    }
}

fn accepted_entries_of(fixture: &Value) -> Vec<String> {
    fixture
        .get("accepted")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|item| item.get("path").and_then(Value::as_str))
        .map(str::to_string)
        .collect()
}
