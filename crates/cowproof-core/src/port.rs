//! `kind: port` packets: the header's `port` object, the project's default epsilon, the
//! accepted differences a fixture carries and the ruling a director's answer must cite for
//! each of them.
//!
//! A port packet asks a builder to replace a script in another language with a Rust tool.
//! The proof is portkit's replay: the tool answers every captured fixture, and a tool the
//! registry does not answer is "not ported". The header says what the replay needs (the
//! tools, the fixtures, how tolerant the comparison is, how to run the reference to capture
//! the director's held-out cases). Everything here parses strictly: an unknown key in the
//! `port` object or in a nested object is an error, never silently dropped.
//!
//! The `port-accepted-unruled` rule and the proof's port gate both read accepted differences
//! and rulings through this module, so lint and the verifier agree on what counts as ruled.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Component, Path};

use crate::git_show_optional;
use crate::ladder::refuse_unknown_keys;

/// The source languages a port packet may name (`port.lang`).
pub const PORT_LANGS: [&str; 9] = [
    "python",
    "node",
    "typescript",
    "shell",
    "ruby",
    "perl",
    "powershell",
    "go",
    "other",
];

/// The capture adapters (`port.adapter`): `function` is an adapter file in the source
/// repository that makes a function speak portkit's JSON contract, so the reference command is
/// required; `process` captures a whole script or executable with `pk port exec` (the
/// reference command is the script's command line, the cases' `input` is `{argv, env, stdin,
/// files, shims}`, and the port is replayed through `pk port wrap`).
pub const PORT_ADAPTERS: [&str; 2] = ["function", "process"];

/// The `port.parity.path_roots` tokens a process capture substitutes in its output (portkit's
/// `path-roots` v1): `$ROOT` the directory the process ran in, `$HOME` and `$TMP` its `home/`
/// and `tmp/`, `$SRC` the directory the reference lives in. Any other entry is a plain path
/// prefix (read by lint only); an entry that starts with `$` and is not one of these is an error.
pub const PATH_ROOT_TOKENS: [&str; 4] = ["$ROOT", "$HOME", "$TMP", "$SRC"];

/// The project's default epsilon when `cowproof.toml` has no `[port] epsilon`: exact.
pub const DEFAULT_PORT_EPSILON: f64 = 0.0;

/// The file name, inside the capsule's `packets/`, of the director's held-out port cases.
pub const HELDOUT_PORT_CASES_FILE: &str = "packets/heldout.cases.jsonl";

/// What a packet is for (`kind`): ordinary work, or a port proved by replay.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PacketKind {
    #[default]
    Work,
    Port,
}

impl PacketKind {
    pub fn name(self) -> &'static str {
        match self {
            Self::Work => "work",
            Self::Port => "port",
        }
    }
}

/// `port.reference`: how to run the original, and what a machine must have to run it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortReference {
    /// The shell command that speaks portkit's contract: one `{"tool":..,"input":..}` request
    /// on stdin, one JSON result on stdout.
    pub cmd: String,
    /// The directory, relative to the repository, the command runs in. Default: the root.
    #[serde(default)]
    pub cwd: Option<String>,
    /// Environment the command runs with, on top of an otherwise empty one.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// What the verifier must have installed to run it, `node>=22` or `python3`. A verifier
    /// without it reports `held-out: skipped` and never passes silently.
    #[serde(default)]
    pub runtime: Option<String>,
}

/// `port.parity`: how the replay compares.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PortParity {
    /// Absolute float tolerance. Default: the project's `[port] epsilon` in the base
    /// `cowproof.toml` (0 when it has none). A value above the default is the lint error
    /// `port-epsilon-loosened`.
    pub epsilon: Option<f64>,
    /// JSON Pointer prefixes skipped by the comparison (timestamps, run ids).
    pub ignore_paths: Vec<String>,
    /// Compare arrays as multisets.
    pub unordered_arrays: bool,
    /// Path prefixes, or the tokens `$ROOT`, `$HOME`, `$TMP`, `$SRC`
    /// ([`PATH_ROOT_TOKENS`]). The tokens are what `pk port exec` substitutes in a process
    /// capture (`path-roots` v1) and what the port's `pk port wrap` substitutes the same way;
    /// lint reads all of them as declared paths.
    pub path_roots: Vec<String>,
}

/// The header's `port` object (`kind: port`), section 6.4 of portkit-integration.md.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortSpec {
    pub lang: String,
    pub adapter: String,
    #[serde(default)]
    pub reference: Option<PortReference>,
    /// The committed visible cases file (JSONL), relative to the repository.
    pub cases: String,
    /// The directory of fixtures the replay reads; the builder may write it, so `owns`
    /// covers it.
    pub fixtures: String,
    /// The tool names the Rust registry must answer. The replay's `not_ported` count must be 0.
    pub tools: Vec<String>,
    #[serde(default)]
    pub parity: PortParity,
}

impl PortSpec {
    /// The epsilon the replay uses: the packet's, else the project default.
    pub fn epsilon(&self, project_default: f64) -> f64 {
        self.parity.epsilon.unwrap_or(project_default)
    }

    /// Check the object's values. Unknown keys are already refused by the parser.
    pub fn validate(&self) -> Result<()> {
        if !PORT_LANGS.contains(&self.lang.as_str()) {
            bail!(
                "port.lang {:?} is not one of {}",
                self.lang,
                PORT_LANGS.join(", ")
            );
        }
        if !PORT_ADAPTERS.contains(&self.adapter.as_str()) {
            bail!(
                "port.adapter {:?} is not one of {}",
                self.adapter,
                PORT_ADAPTERS.join(", ")
            );
        }
        match &self.reference {
            None if self.adapter == "function" => {
                bail!("port.adapter \"function\" requires port.reference.cmd")
            }
            None => {}
            Some(reference) => reference.validate()?,
        }
        repo_relative("port.cases", &self.cases)?;
        repo_relative("port.fixtures", &self.fixtures)?;
        if self.tools.is_empty() {
            bail!("port.tools must name at least one tool");
        }
        for tool in &self.tools {
            // A tool is a directory name under the fixtures directory.
            if tool.is_empty()
                || tool.starts_with('.')
                || !tool
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
            {
                bail!(
                    "port.tools: {tool:?} is not a tool name ([A-Za-z0-9_.-], not starting with a dot)"
                );
            }
        }
        if let Some(epsilon) = self.parity.epsilon
            && !(epsilon.is_finite() && epsilon >= 0.0)
        {
            bail!("port.parity.epsilon must be a number of at least 0");
        }
        for pointer in &self.parity.ignore_paths {
            if !pointer.starts_with('/') {
                bail!(
                    "port.parity.ignore_paths: {pointer:?} is not a JSON Pointer (it starts with /)"
                );
            }
        }
        for root in &self.parity.path_roots {
            if root.is_empty() {
                bail!("port.parity.path_roots must not hold an empty entry");
            }
            if root.starts_with('$') && !PATH_ROOT_TOKENS.contains(&root.as_str()) {
                bail!(
                    "port.parity.path_roots: {root:?} is not a root this version substitutes ({}); a path prefix does not start with $",
                    PATH_ROOT_TOKENS.join(", ")
                );
            }
        }
        Ok(())
    }
}

impl PortReference {
    fn validate(&self) -> Result<()> {
        if self.cmd.trim().is_empty() {
            bail!("port.reference.cmd must not be empty");
        }
        if self.cmd.contains('\0') {
            bail!("port.reference.cmd contains a NUL");
        }
        if let Some(cwd) = &self.cwd {
            repo_relative("port.reference.cwd", cwd)?;
        }
        for (key, value) in &self.env {
            let mut chars = key.chars();
            let first_ok = chars
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic() || c == '_');
            if !first_ok || !chars.all(|c| c.is_ascii_alphanumeric() || c == '_') {
                bail!("port.reference.env: {key:?} is not an environment variable name");
            }
            if value.contains('\0') {
                bail!("port.reference.env: the value of {key} contains a NUL");
            }
        }
        if let Some(runtime) = &self.runtime {
            ReferenceRuntime::parse(runtime)
                .with_context(|| format!("port.reference.runtime {runtime:?}"))?;
        }
        Ok(())
    }
}

/// A path inside the repository: relative, no `..`, no NUL.
fn repo_relative(field: &str, path: &str) -> Result<()> {
    if path.is_empty() || path.contains('\0') {
        bail!("{field} must be a path");
    }
    let p = Path::new(path);
    if p.is_absolute()
        || p.components()
            .any(|c| matches!(c, Component::ParentDir | Component::RootDir))
    {
        bail!("{field} {path:?} must be a path inside the repository (relative, without ..)");
    }
    Ok(())
}

/// `port.reference.runtime`: a program and, optionally, the least version, `node>=22` or
/// `python3>=3.11`. Only a program name and a dotted number are accepted, so the text can
/// be run as `<program> --version` and nothing else.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReferenceRuntime {
    pub program: String,
    pub minimum: Option<Vec<u64>>,
}

impl ReferenceRuntime {
    pub fn parse(text: &str) -> Result<Self> {
        let (program, minimum) = match text.split_once(">=") {
            Some((program, version)) => (program, Some(version)),
            None => (text, None),
        };
        let mut chars = program.chars();
        let first_ok = chars.next().is_some_and(|c| c.is_ascii_alphabetic());
        if !first_ok
            || !chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '+'))
        {
            bail!("the program must be a plain name such as node or python3");
        }
        let minimum = match minimum {
            None => None,
            Some(version) => {
                let parts: Result<Vec<u64>, _> = version.split('.').map(str::parse).collect();
                match parts {
                    Ok(parts) if !parts.is_empty() => Some(parts),
                    _ => bail!("the version after >= must be a dotted number such as 22 or 3.11"),
                }
            }
        };
        Ok(Self {
            program: program.to_string(),
            minimum,
        })
    }

    /// Whether `output`, the text `<program> --version` printed, names a version at least the
    /// minimum. No minimum is always met. The first dotted number in the text is the version.
    pub fn is_met_by(&self, output: &str) -> bool {
        let Some(minimum) = &self.minimum else {
            return true;
        };
        let Some(found) = first_version(output) else {
            return false;
        };
        for (have, need) in found
            .iter()
            .chain(std::iter::repeat(&0))
            .zip(minimum.iter())
        {
            if have != need {
                return have > need;
            }
        }
        true
    }
}

/// The first run of digits and dots in `text` that starts with a digit, as numbers.
fn first_version(text: &str) -> Option<Vec<u64>> {
    let start = text.find(|c: char| c.is_ascii_digit())?;
    let run: String = text[start..]
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    let parts: Result<Vec<u64>, _> = run
        .trim_end_matches('.')
        .split('.')
        .map(str::parse)
        .collect();
    parts.ok()
}

/// The project's default epsilon in a `cowproof.toml` text: `[port] epsilon`, else 0. `None`
/// is a repository with no `cowproof.toml`. An unknown key in `[port]`, a value that is not
/// a number of at least 0 and a file that does not parse are errors.
pub fn project_epsilon(text: Option<&str>) -> Result<f64> {
    let Some(text) = text else {
        return Ok(DEFAULT_PORT_EPSILON);
    };
    let config: toml::Table = toml::from_str(text).context("cowproof.toml does not parse")?;
    let Some(port) = config.get("port") else {
        return Ok(DEFAULT_PORT_EPSILON);
    };
    let port = port
        .as_table()
        .context("cowproof.toml: [port] must be a table")?;
    refuse_unknown_keys("[port]", port, &["epsilon"])?;
    let Some(value) = port.get("epsilon") else {
        return Ok(DEFAULT_PORT_EPSILON);
    };
    let epsilon = value
        .as_float()
        .or_else(|| value.as_integer().map(|n| n as f64))
        .filter(|e| e.is_finite() && *e >= 0.0)
        .context("cowproof.toml: [port] epsilon must be a number of at least 0")?;
    Ok(epsilon)
}

/// [`project_epsilon`] at `commit` of `repo`: the lane's base commit, so a patch cannot raise it.
pub fn project_epsilon_at_commit(repo: &Path, commit: &str) -> Result<f64> {
    let text = git_show_optional(repo, commit, "cowproof.toml")?;
    project_epsilon(text.as_deref())
        .with_context(|| format!("reading the port epsilon at {commit}"))
}

// ---- accepted differences and rulings ----

/// One `accepted` entry of a fixture.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct AcceptedEntry {
    /// The fixture file, relative to the fixtures directory.
    pub file: String,
    /// The JSON Pointer the entry covers.
    pub path: String,
    pub reason: String,
}

/// Every fixture file (`*.json`, regular files only, no symlink followed) under `dir`, as
/// `(path relative to dir, parsed JSON)`, sorted by path. A file that does not parse is
/// skipped here: the replay reports it. A missing directory is empty.
pub fn read_fixture_files(dir: &Path) -> Vec<(String, Value)> {
    fn visit(root: &Path, dir: &Path, out: &mut Vec<(String, Value)>) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        let mut entries: Vec<_> = entries.flatten().collect();
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            let path = entry.path();
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            if kind.is_dir() {
                visit(root, &path, out);
            } else if kind.is_file()
                && path.extension().is_some_and(|e| e == "json")
                && let Ok(text) = fs::read_to_string(&path)
                && let Ok(value) = serde_json::from_str::<Value>(&text)
                && let Ok(rel) = path.strip_prefix(root)
            {
                out.push((rel.to_string_lossy().replace('\\', "/"), value));
            }
        }
    }
    let mut out = Vec::new();
    visit(dir, dir, &mut out);
    out
}

/// The `accepted` entries of the fixtures under `dir`, sorted. An entry that is not an object
/// with a string `path` and `reason` is kept with an empty reason, so it is never skipped.
pub fn accepted_entries(dir: &Path) -> Vec<AcceptedEntry> {
    accepted_from(&read_fixture_files(dir))
}

/// [`accepted_entries`] over fixtures already read.
pub fn accepted_from(files: &[(String, Value)]) -> Vec<AcceptedEntry> {
    let mut entries = Vec::new();
    for (file, value) in files {
        let Some(list) = value.get("accepted").and_then(Value::as_array) else {
            continue;
        };
        for item in list {
            let text = |key: &str| {
                item.get(key)
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string()
            };
            entries.push(AcceptedEntry {
                file: file.clone(),
                path: text("path"),
                reason: text("reason"),
            });
        }
    }
    entries.sort();
    entries
}

/// The ruling id a reason cites: `ruling:<id>`, the id being letters, digits, `.`, `_` and
/// `-`, starting with a letter or a digit.
pub fn cited_ruling(reason: &str) -> Option<&str> {
    let start = reason.find("ruling:")? + "ruling:".len();
    let rest = &reason[start..];
    let end = rest
        .find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')))
        .unwrap_or(rest.len());
    let id = &rest[..end];
    id.chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphanumeric())
        .then_some(id)
}

/// The director's answers in a lane's escalation log (`escalations.jsonl`): the text of every
/// escalation ruled with an `answer`. A ruling id is *present* when one of those texts says
/// `ruling:<id>`. The director writes the id; the builder cannot, so an accepted difference
/// that cites a present id was ruled by the director.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RulingLog {
    answers: Vec<String>,
}

impl RulingLog {
    pub fn from_answers(answers: Vec<String>) -> Self {
        Self { answers }
    }

    /// Read a queue file. A missing file is an empty log (no rulings); a line that is not a
    /// `ruled` event with an `answer` verdict is ignored.
    pub fn read(path: &Path) -> Result<Self> {
        let bytes = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        let mut answers = Vec::new();
        for line in bytes.split(|b| *b == b'\n') {
            let Ok(event) = serde_json::from_slice::<Value>(line) else {
                continue;
            };
            if event.get("event").and_then(Value::as_str) != Some("ruled") {
                continue;
            }
            let verdict = &event["verdict"];
            if verdict.get("verdict").and_then(Value::as_str) == Some("answer")
                && let Some(text) = verdict.get("text").and_then(Value::as_str)
            {
                answers.push(text.to_string());
            }
        }
        Ok(Self { answers })
    }

    /// Whether an answer cites `ruling:<id>` (the id must end there, so `ruling:r1` is not
    /// found in `ruling:r10`).
    pub fn contains(&self, id: &str) -> bool {
        self.answers.iter().any(|text| {
            let mut rest = text.as_str();
            while let Some(at) = rest.find("ruling:") {
                rest = &rest[at..];
                if cited_ruling(rest) == Some(id) {
                    return true;
                }
                rest = &rest["ruling:".len()..];
            }
            false
        })
    }
}

/// Why an accepted entry is unruled.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Unruled {
    /// The reason cites no `ruling:<id>`.
    NoCitation,
    /// The reason cites an id no answer in the escalation log carries.
    NotInLog(String),
}

/// The entries among `entries` that are unruled, with why. `log` is the lane's escalation
/// log; `None` (no log to check against) checks only that each reason cites a ruling.
pub fn unruled<'a>(
    entries: &'a [AcceptedEntry],
    log: Option<&RulingLog>,
) -> Vec<(&'a AcceptedEntry, Unruled)> {
    entries
        .iter()
        .filter_map(|entry| match cited_ruling(&entry.reason) {
            None => Some((entry, Unruled::NoCitation)),
            Some(id) => match log {
                Some(log) if !log.contains(id) => Some((entry, Unruled::NotInLog(id.to_string()))),
                _ => None,
            },
        })
        .collect()
}

// ---- the held-out cases ----

/// The `[port]` table of a held-out file: the director's cases for the port, kept beside the
/// checks and, like them, outside the repository.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeldOutPort {
    /// The JSONL cases file, a plain file name in the held-out file's own directory.
    pub cases: String,
}

impl HeldOutPort {
    pub fn validate(&self) -> Result<()> {
        let name = &self.cases;
        if name.is_empty()
            || name.contains(['/', '\\', '\0'])
            || name == "."
            || name == ".."
            || name.starts_with('.')
        {
            bail!(
                "the held-out [port] cases must be a plain file name beside the held-out file, not {name:?}"
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_versions_compare_by_number() {
        let node = ReferenceRuntime::parse("node>=22").unwrap();
        assert!(node.is_met_by("v22.1.0"));
        assert!(node.is_met_by("v24.0.0\n"));
        assert!(!node.is_met_by("v20.11.1"));
        assert!(!node.is_met_by("no digits here"));
        let py = ReferenceRuntime::parse("python3>=3.11").unwrap();
        assert!(py.is_met_by("Python 3.11.0"));
        assert!(py.is_met_by("Python 3.12.4"));
        assert!(!py.is_met_by("Python 3.9.18"));
        assert!(ReferenceRuntime::parse("sh").unwrap().is_met_by(""));
        for bad in ["", "node>=", "node>=x", "no de", "-node", "node>=1..2"] {
            assert!(ReferenceRuntime::parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_citation_is_found_and_ends_at_the_id() {
        assert_eq!(cited_ruling("ruling:r1 the float rounds"), Some("r1"));
        assert_eq!(cited_ruling("see ruling:a.b-c_d, then"), Some("a.b-c_d"));
        assert_eq!(cited_ruling("ruling: r1"), None);
        assert_eq!(cited_ruling("ruling:-x"), None);
        assert_eq!(cited_ruling("no citation"), None);
        let log = RulingLog::from_answers(vec!["Accept it. ruling:r10 because".into()]);
        assert!(log.contains("r10"));
        assert!(!log.contains("r1"));
    }

    #[test]
    fn the_project_epsilon_defaults_to_exact_and_is_strict() {
        assert_eq!(project_epsilon(None).unwrap(), 0.0);
        assert_eq!(project_epsilon(Some("[classes]\nrust = 2\n")).unwrap(), 0.0);
        assert_eq!(
            project_epsilon(Some("[port]\nepsilon = 1e-9\n")).unwrap(),
            1e-9
        );
        assert_eq!(project_epsilon(Some("[port]\nepsilon = 1\n")).unwrap(), 1.0);
        for bad in [
            "[port]\nepsilon = -1\n",
            "[port]\nepsilon = \"x\"\n",
            "[port]\nepsilons = 1\n",
            "port = 3\n",
        ] {
            assert!(project_epsilon(Some(bad)).is_err(), "{bad}");
        }
    }
}
