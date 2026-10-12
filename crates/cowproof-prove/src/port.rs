//! The proof of a `kind: port` packet: portkit's replay, run by the verifier.
//!
//! In the rebuilt tree, inside the verifier's sandbox, the verifier runs
//!
//! ```text
//! cowproof pk --config <pk.toml> port replay --fixtures <port.fixtures> --surface both \
//!     --epsilon <epsilon> --json > <report>
//! ```
//!
//! and judges the report itself, never the builder's account of it. The `port_replay` gate
//! passes only when the command exited 0, both surfaces replayed, every surface's
//! `ReplayReport::is_success()` holds, `not_ported` is 0 for every surface and every tool in
//! `port.tools` has fixtures that were replayed, and every outcome the report holds is for a
//! fixture on disk. The report is read the moment the replay's process group is gone. Two checks the replay cannot make for itself
//! come with it: a fixture of the base must still say what it said (`tool`, `id`, `input`,
//! `expected`), because the builder may write the fixtures directory and a changed expectation
//! is the easiest way to make a port pass; and an `accepted` difference the lane added must
//! cite a ruling a director's answer carries (`port-accepted-unruled`, at proof time).
//!
//! The director's held-out cases are captured against the reference at verification time and
//! replayed the same way. A verifier that lacks the reference's runtime reports
//! `held-out: skipped` with the reason; it does not pass silently, and does not fail either.

use crate::capsule::Capsule;
use crate::runner::{CheckRunner, InfraError};
use crate::verify::{VerifyError, git, infra};
use cowproof_core::heldout::HeldOut;
use cowproof_core::port::{
    AcceptedEntry, HELDOUT_PORT_CASES_FILE, ReferenceRuntime, RulingLog, Unruled, accepted_from,
    read_fixture_files, unruled,
};
use cowproof_core::{PortReference, PortSpec};
use portkit_port::{CaseOutcome, ReplayReport, Status};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// The directory, inside the verifier's work directory, the replay writes its files to.
const PORT_DIR: &str = "port";

/// The most outcomes (failing or accepted) one surface keeps in the capsule.
const MAX_OUTCOMES: usize = 50;
/// The most differences one kept outcome carries.
const MAX_DIFFERENCES: usize = 5;
/// The most bytes of a value kept in a difference.
const MAX_VALUE_BYTES: usize = 400;

/// What the capsule records for a port packet (section 3e of portkit-integration.md). The
/// first part is the spec the verifier replays from, written when the capsule is built; the
/// `result` is added after the verifier has run. The field is sealed in `capsule.json`, and a
/// capsule without it (every capsule before port packets) reads as `None` and still verifies.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PortCapsule {
    pub lang: String,
    pub adapter: String,
    /// The reference command, its directory, environment and runtime: how the director's
    /// held-out cases are captured, and what the fixtures were captured from.
    #[serde(default)]
    pub reference: Option<PortReference>,
    /// The fixtures directory, relative to the repository.
    pub fixtures: String,
    pub tools: Vec<String>,
    /// The epsilon the replay used: the packet's, else the project's `[port] epsilon` at the
    /// base commit.
    pub epsilon: f64,
    pub ignore_paths: Vec<String>,
    pub unordered_arrays: bool,
    /// The declared `path_roots` of a process capture: what the held-out cases are captured
    /// with (`--path-root`), so they are substituted the way the fixtures were.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub path_roots: Vec<String>,
    /// What the replay found. `None` until the verifier has run.
    #[serde(default)]
    pub result: Option<PortResult>,
}

impl PortCapsule {
    /// The spec half, from a packet's `port` object and the epsilon in force.
    pub fn from_spec(spec: &PortSpec, epsilon: f64) -> Self {
        Self {
            lang: spec.lang.clone(),
            adapter: spec.adapter.clone(),
            reference: spec.reference.clone(),
            fixtures: spec.fixtures.clone(),
            tools: spec.tools.clone(),
            epsilon,
            ignore_paths: spec.parity.ignore_paths.clone(),
            unordered_arrays: spec.parity.unordered_arrays,
            path_roots: spec.parity.path_roots.clone(),
            result: None,
        }
    }
}

/// What the verifier's replay of a port packet found.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PortResult {
    /// The commit the reference's source is read from: the lane's base commit. The fixtures
    /// themselves record the command they were captured with, not a commit.
    pub source_commit: String,
    /// `sha256` over the fixtures directory of the rebuilt tree (see [`fixture_set_hash`]).
    pub fixture_hash: String,
    /// How many fixture files the directory holds.
    pub fixture_count: usize,
    /// Whether the `port_replay` gate passed.
    pub success: bool,
    /// Per surface (`direct`, `mcp`): the counts, and only the failing and accepted outcomes.
    pub surfaces: BTreeMap<String, SurfaceSummary>,
    /// The director's held-out cases.
    pub held_out: PortHeldOut,
    /// Why the gate failed, one line each; empty when it passed.
    pub failures: Vec<String>,
}

/// One surface of a replay, trimmed: the counts in full, and of the outcomes only the ones that
/// are not plain passes. A reviewer sees every divergence without rerunning.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SurfaceSummary {
    pub passed: usize,
    pub accepted: usize,
    pub failed: usize,
    pub errored: usize,
    pub not_ported: usize,
    /// Failing and accepted outcomes, at most [`MAX_OUTCOMES`], values shortened.
    pub outcomes: Vec<CaseOutcome>,
    /// Failing and accepted outcomes left out of `outcomes` for the limit.
    pub omitted: usize,
}

/// The state of the director's held-out cases.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PortHeldOut {
    /// `none` (the lane has no held-out port cases), `passed`, `failed` or `skipped`.
    pub state: String,
    /// For `skipped`: what the verifier lacks. For `failed`: how many cases failed.
    #[serde(default)]
    pub reason: Option<String>,
    /// How many held-out cases were captured and replayed.
    #[serde(default)]
    pub cases: usize,
    /// The replay of the held-out cases, per surface, trimmed as above.
    #[serde(default)]
    pub surfaces: BTreeMap<String, SurfaceSummary>,
}

impl PortHeldOut {
    fn none() -> Self {
        Self {
            state: "none".into(),
            reason: None,
            cases: 0,
            surfaces: BTreeMap::new(),
        }
    }
}

/// What the verifier found, for [`VerifyReport`](crate::verify::VerifyReport).
#[derive(Clone, Debug)]
pub struct PortOutcome {
    pub result: PortResult,
}

impl PortOutcome {
    /// Whether the `port_replay` gate passed (held-out cases that were skipped do not fail it).
    pub fn passed(&self) -> bool {
        self.result.success
    }

    /// The `held-out: skipped` line, when the held-out cases were skipped.
    pub fn skipped_note(&self) -> Option<String> {
        (self.result.held_out.state == "skipped").then(|| {
            format!(
                "held-out: skipped ({})",
                self.result
                    .held_out
                    .reason
                    .as_deref()
                    .unwrap_or("no reason")
            )
        })
    }
}

/// `sha256` of every file under `dir`, its relative path and its bytes, in path order: a hash of
/// the fixture set that changes when any fixture is added, removed, renamed or edited. Files
/// are the regular files only; a symlink is not followed and does not count. A missing
/// directory is an error.
pub fn fixture_set_hash(dir: &Path) -> std::io::Result<(String, usize)> {
    fn collect(root: &Path, dir: &Path, out: &mut Vec<(String, PathBuf)>) -> std::io::Result<()> {
        let mut entries: Vec<_> = fs::read_dir(dir)?.collect::<Result<_, _>>()?;
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            let path = entry.path();
            let kind = entry.file_type()?;
            if kind.is_dir() {
                collect(root, &path, out)?;
            } else if kind.is_file() {
                let rel = path
                    .strip_prefix(root)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .replace('\\', "/");
                out.push((rel, path));
            }
        }
        Ok(())
    }
    let mut files = Vec::new();
    collect(dir, dir, &mut files)?;
    files.sort();
    let mut hasher = Sha256::new();
    for (rel, path) in &files {
        let bytes = fs::read(path)?;
        // Lengths first, so no path and content can run into each other.
        hasher.update((rel.len() as u64).to_le_bytes());
        hasher.update(rel.as_bytes());
        hasher.update((bytes.len() as u64).to_le_bytes());
        hasher.update(&bytes);
    }
    Ok((format!("{:x}", hasher.finalize()), files.len()))
}

/// `word` as one shell word, single-quoted.
pub(crate) fn sh_quote(word: &str) -> String {
    format!("'{}'", word.replace('\'', "'\\''"))
}

/// The pk configuration of a replay: the comparison options, nothing else. `epsilon_rel` is 0
/// so the only tolerance is the absolute epsilon the packet and the project allow.
fn pk_config(spec: &PortCapsule) -> String {
    let mut parity = toml::Table::new();
    parity.insert("epsilon".into(), toml::Value::Float(spec.epsilon));
    parity.insert("epsilon_rel".into(), toml::Value::Float(0.0));
    parity.insert(
        "ignore_paths".into(),
        toml::Value::Array(
            spec.ignore_paths
                .iter()
                .cloned()
                .map(toml::Value::String)
                .collect(),
        ),
    );
    parity.insert(
        "unordered_arrays".into(),
        toml::Value::Boolean(spec.unordered_arrays),
    );
    let mut table = toml::Table::new();
    table.insert("parity".into(), toml::Value::Table(parity));
    toml::to_string(&table).expect("a table of plain values serializes")
}

/// What every replay of one verification shares.
struct Replay<'a> {
    runner: &'a dyn CheckRunner,
    tree: &'a Path,
    pk_exe: &'a Path,
    config: PathBuf,
    spec: &'a PortCapsule,
    timeout: Duration,
}

/// What one replay left: the command's exit status and output, and the report it wrote.
struct Ran {
    exit_status: i32,
    output: String,
    /// The report file's text, read the moment the replay's process group was gone, or why it
    /// could not be read.
    report: Result<String, String>,
}

impl Replay<'_> {
    /// Run the replay of the fixtures at `fixtures` (a directory the sandbox can read),
    /// writing the JSON report to `report`.
    ///
    /// The runner puts the replay in its own process group (`run_in_group`) and returns only
    /// once everything in that group is dead, so nothing the replay or a plugin of the rebuilt
    /// tree started can write after this returns. The report is read into memory as the next
    /// step: the text judged is what the file held when the replay ended, and a file written
    /// later, or a report from before this run, is never what is read. A process that
    /// escaped the group (`setsid`) can still write the path afterwards; the copy already in
    /// memory is not the file, and on Linux the sandbox's pid namespace ends it with the group.
    async fn run(&self, fixtures: &Path, report: &Path) -> Result<Ran, VerifyError> {
        let command = format!(
            "{} pk --config {} port replay --fixtures {} --surface both --epsilon {} --json > {}",
            sh_quote(&self.pk_exe.to_string_lossy()),
            sh_quote(&self.config.to_string_lossy()),
            sh_quote(&fixtures.to_string_lossy()),
            self.spec.epsilon,
            sh_quote(&report.to_string_lossy()),
        );
        let outcome = self
            .runner
            .run(self.tree, &command, self.timeout)
            .await
            .map_err(|e: InfraError| infra(format!("port replay: {e}")))?;
        let report = fs::read_to_string(report).map_err(|e| e.to_string());
        // 126 and 127 are the shell saying it could not run the command: the verifier's own
        // trouble (the executable is not reachable in the sandbox), never a verdict on the
        // lane.
        if outcome.exit_status == 126 || outcome.exit_status == 127 {
            return Err(infra(format!(
                "port replay could not run `{}`: {}",
                self.pk_exe.display(),
                first_line(&outcome.output)
            )));
        }
        Ok(Ran {
            exit_status: outcome.exit_status,
            output: outcome.output,
            report,
        })
    }
}

fn first_line(text: &str) -> String {
    let line = text
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("no output");
    let mut line: String = line.chars().take(200).collect();
    line.retain(|c| !c.is_control());
    line
}

/// A replay as the verifier judges it: per-surface reports parsed from the file, and the
/// reasons it is not a success.
struct Replayed {
    reports: BTreeMap<String, ReplayReport>,
    failures: Vec<String>,
}

fn read_report(ran: &Ran) -> Replayed {
    let mut failures = Vec::new();
    let reports: BTreeMap<String, ReplayReport> = match ran
        .report
        .clone()
        .and_then(|text| serde_json::from_str(&text).map_err(|e| e.to_string()))
    {
        Ok(reports) => reports,
        Err(why) => {
            failures.push(format!(
                "the replay wrote no report ({why}); it said: {}",
                first_line(&ran.output)
            ));
            return Replayed {
                reports: BTreeMap::new(),
                failures,
            };
        }
    };
    if ran.exit_status != 0 {
        failures.push(format!("the replay exited with status {}", ran.exit_status));
    }
    Replayed { reports, failures }
}

/// The tools whose fixtures the directory holds: a tool is the directory name one level below
/// the fixtures directory, and it has fixtures when that directory holds a `.json` file.
fn tools_with_fixtures(dir: &Path) -> Vec<String> {
    read_fixture_files(dir)
        .into_iter()
        .filter_map(|(rel, _)| rel.split_once('/').map(|(tool, _)| tool.to_string()))
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// The `(tool, id)` of every fixture file the directory holds: the names a replay reports its
/// outcomes under (it reads them from the files, not from the directory names).
fn fixture_cases(dir: &Path) -> BTreeSet<(String, String)> {
    read_fixture_files(dir)
        .into_iter()
        .filter_map(|(_, value)| {
            let tool = value.get("tool")?.as_str()?.to_string();
            let id = value.get("id")?.as_str()?.to_string();
            Some((tool, id))
        })
        .collect()
}

/// Judge a replay: its failures in words, naming surface, tool and fixture.
fn judge(
    label: &str,
    replayed: &mut Replayed,
    tools: &[String],
    on_disk: &[String],
    cases: &BTreeSet<(String, String)>,
) {
    for surface in ["direct", "mcp"] {
        if !replayed.reports.contains_key(surface) {
            replayed
                .failures
                .push(format!("{label}the replay has no `{surface}` surface"));
        }
    }
    for (surface, report) in &replayed.reports {
        let count = |s: Status| report.outcomes.iter().filter(|o| o.status == s).count();
        if count(Status::Fail) != report.failed
            || count(Status::Error) != report.errored
            || count(Status::NotPorted) != report.not_ported
            || count(Status::Pass) != report.passed
            || count(Status::Accepted) != report.accepted
        {
            replayed.failures.push(format!(
                "{label}{surface}: the report's counts disagree with its outcomes"
            ));
        }
        let before = replayed.failures.len();
        // A report is the replay's own account; coverage it claims for a case that has no
        // fixture in the directory is invented, whatever its status.
        for outcome in &report.outcomes {
            if !cases.contains(&(outcome.tool.clone(), outcome.id.clone())) {
                replayed.failures.push(format!(
                    "{label}{surface} {}/{}: the report has an outcome for a case with no fixture on disk",
                    outcome.tool, outcome.id
                ));
            }
        }
        for outcome in &report.outcomes {
            let what = match outcome.status {
                Status::Pass | Status::Accepted => continue,
                Status::Fail => "differs from the reference",
                Status::Error => "the tool errored",
                Status::NotPorted => "not ported (no tool answers it)",
            };
            let detail = outcome
                .differences
                .first()
                .map(|d| format!(" at {:?}", d.path))
                .or_else(|| {
                    outcome
                        .error
                        .as_ref()
                        .map(|e| format!(": {}", first_line(e)))
                })
                .unwrap_or_default();
            replayed.failures.push(format!(
                "{label}{surface} {}/{}: {what}{detail}",
                outcome.tool, outcome.id
            ));
        }
        if report.not_ported != 0 {
            replayed.failures.push(format!(
                "{label}{surface}: {} fixture(s) are not ported",
                report.not_ported
            ));
        }
        if !report.is_success() && replayed.failures.len() == before {
            replayed
                .failures
                .push(format!("{label}{surface}: the replay did not succeed"));
        }
        for tool in tools {
            if !report.outcomes.iter().any(|o| &o.tool == tool) {
                replayed.failures.push(format!(
                    "{label}{surface}: no fixture of tool {tool:?} was replayed"
                ));
            }
        }
    }
    for tool in tools {
        if !on_disk.contains(tool) {
            replayed.failures.push(format!(
                "{label}tool {tool:?} has no fixtures in the fixtures directory"
            ));
        }
    }
}

fn shorten(value: &Value) -> Value {
    let text = value.to_string();
    if text.len() <= MAX_VALUE_BYTES {
        return value.clone();
    }
    let mut end = MAX_VALUE_BYTES;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    Value::String(format!("{}... ({} bytes)", &text[..end], text.len()))
}

/// The capsule's view of one surface: counts in full, outcomes only when failing or accepted,
/// differences limited and values shortened.
fn summarize(report: &ReplayReport) -> SurfaceSummary {
    let mut outcomes: Vec<CaseOutcome> = report
        .outcomes
        .iter()
        .filter(|o| o.status != Status::Pass)
        .cloned()
        .collect();
    let omitted = outcomes.len().saturating_sub(MAX_OUTCOMES);
    outcomes.truncate(MAX_OUTCOMES);
    for outcome in &mut outcomes {
        outcome.differences.truncate(MAX_DIFFERENCES);
        for difference in &mut outcome.differences {
            difference.expected = difference.expected.as_ref().map(shorten);
            difference.actual = difference.actual.as_ref().map(shorten);
        }
    }
    SurfaceSummary {
        passed: report.passed,
        accepted: report.accepted,
        failed: report.failed,
        errored: report.errored,
        not_ported: report.not_ported,
        outcomes,
        omitted,
    }
}

fn summaries(reports: &BTreeMap<String, ReplayReport>) -> BTreeMap<String, SurfaceSummary> {
    reports
        .iter()
        .map(|(surface, report)| (surface.clone(), summarize(report)))
        .collect()
}

/// The fixtures of the tree's HEAD (the base with `base.patch` and the launch baseline, before
/// `lane.patch`) under `fixtures`, as `(path relative to the directory, parsed JSON)`.
async fn base_fixtures(tree: &Path, fixtures: &str) -> Result<Vec<(String, Value)>, VerifyError> {
    let prefix = format!("{}/", fixtures.trim_end_matches('/'));
    let listing = git(
        tree,
        &["ls-tree", "-r", "--name-only", "-z", "HEAD", "--", fixtures],
    )
    .await?;
    let mut out = Vec::new();
    for path in listing.split('\0').filter(|p| !p.is_empty()) {
        let Some(rel) = path.strip_prefix(&prefix) else {
            continue;
        };
        if !rel.ends_with(".json") {
            continue;
        }
        let blob = git(tree, &["show", &format!("HEAD:{path}")]).await?;
        if let Ok(value) = serde_json::from_str::<Value>(&blob) {
            out.push((rel.to_string(), value));
        }
    }
    Ok(out)
}

/// What the lane did to the fixtures it was given: a base fixture deleted or with another
/// `tool`, `id`, `input` or `expected`, and the `accepted` entries it added without a ruling.
fn fixture_findings(
    base: &[(String, Value)],
    now: &[(String, Value)],
    log: &RulingLog,
) -> Vec<String> {
    let mut findings = Vec::new();
    let now_map: BTreeMap<&str, &Value> = now.iter().map(|(p, v)| (p.as_str(), v)).collect();
    for (path, before) in base {
        match now_map.get(path.as_str()) {
            None => findings.push(format!("fixture {path} of the base was deleted")),
            Some(after) => {
                for key in ["tool", "id", "input", "expected"] {
                    if before.get(key) != after.get(key) {
                        findings.push(format!(
                            "fixture {path}: the lane changed its {key:?}; only a director recaptures a fixture"
                        ));
                    }
                }
            }
        }
    }
    let before: Vec<AcceptedEntry> = accepted_from(base);
    let added: Vec<AcceptedEntry> = accepted_from(now)
        .into_iter()
        .filter(|entry| !before.contains(entry))
        .collect();
    for (entry, why) in unruled(&added, Some(log)) {
        let what = match why {
            Unruled::NoCitation => "cites no ruling".to_string(),
            Unruled::NotInLog(id) => format!("cites ruling:{id}, which no director answer carries"),
        };
        findings.push(format!(
            "port-accepted-unruled: fixture {} accepts a difference at {:?} and its reason {what}",
            entry.file, entry.path
        ));
    }
    findings
}

/// The wrapped reference command: its directory and environment, then the command.
fn reference_command(reference: &PortReference) -> String {
    let mut command = String::new();
    if let Some(cwd) = &reference.cwd {
        command.push_str(&format!("cd {} && ", sh_quote(cwd)));
    }
    for (key, value) in &reference.env {
        command.push_str(&format!("export {key}={} && ", sh_quote(value)));
    }
    command.push_str(&reference.cmd);
    command
}

/// Whether the verifier's sandbox has the runtime the reference needs: `Ok(())`, or why it does
/// not. The probe runs where the capture will run. A runtime with no minimum version is probed
/// with `command -v` (a POSIX shell builtin, so it works for `sh` too, whose `--version` dash
/// does not answer); one with a minimum is asked `<program> --version`.
async fn runtime_met(
    runner: &dyn CheckRunner,
    tree: &Path,
    runtime: &str,
    timeout: Duration,
) -> Result<std::result::Result<(), String>, VerifyError> {
    let need = ReferenceRuntime::parse(runtime)
        .map_err(|e| infra(format!("port.reference.runtime {runtime:?}: {e}")))?;
    let probe = if need.minimum.is_some() {
        format!("{} --version", need.program)
    } else {
        format!("command -v {}", need.program)
    };
    let outcome = runner
        .run(tree, &probe, timeout)
        .await
        .map_err(|e| infra(format!("port runtime probe: {e}")))?;
    if outcome.exit_status != 0 {
        return Ok(Err(format!(
            "the verifier's sandbox has no {} (needs {runtime})",
            need.program
        )));
    }
    if !need.is_met_by(&outcome.output) {
        return Ok(Err(format!(
            "the verifier's {} is too old: `{} --version` said {:?}, the packet needs {runtime}",
            need.program,
            need.program,
            first_line(&outcome.output)
        )));
    }
    Ok(Ok(()))
}

/// Everything [`run_port`] needs from the verification in progress.
pub(crate) struct PortRun<'a> {
    pub capsule_dir: &'a Path,
    pub capsule: &'a Capsule,
    pub spec: &'a PortCapsule,
    pub heldout: &'a HeldOut,
    pub tree: &'a Path,
    pub workdir: &'a Path,
    pub pk_exe: &'a Path,
    pub runner: &'a dyn CheckRunner,
    pub timeout: Duration,
}

/// Replay the packet's fixtures and the director's held-out cases in the rebuilt tree.
///
/// A visible-fixtures failure, an altered base fixture and an unruled accepted difference
/// fail the gate (`success` false, with `failures`); a replay that could not run, a reference
/// that failed on a held-out case and a missing reference command are infrastructure errors
/// (F-1: never a refutation of the lane).
pub(crate) async fn run_port(run: PortRun<'_>) -> Result<PortOutcome, VerifyError> {
    let PortRun {
        capsule_dir,
        capsule,
        spec,
        heldout,
        tree,
        workdir,
        pk_exe,
        runner,
        timeout,
    } = run;
    let out_dir = workdir.join(PORT_DIR);
    fs::create_dir_all(&out_dir).map_err(|e| infra(format!("port work directory: {e}")))?;
    let config = out_dir.join("pk.toml");
    fs::write(&config, pk_config(spec)).map_err(|e| infra(format!("pk.toml: {e}")))?;

    // The fixtures the lane leaves.
    let fixtures_dir = tree.join(&spec.fixtures);
    let mut failures: Vec<String> = Vec::new();
    let (fixture_hash, fixture_count) = match fixture_set_hash(&fixtures_dir) {
        Ok(found) => found,
        Err(e) => {
            failures.push(format!(
                "the fixtures directory {} cannot be read: {e}",
                spec.fixtures
            ));
            (String::new(), 0)
        }
    };

    let report_path = out_dir.join("replay.json");
    let replay = Replay {
        runner,
        tree,
        pk_exe,
        config,
        spec,
        timeout,
    };
    let ran = replay.run(&fixtures_dir, &report_path).await?;
    let mut visible = read_report(&ran);
    let on_disk = tools_with_fixtures(&fixtures_dir);
    judge(
        "",
        &mut visible,
        &spec.tools,
        &on_disk,
        &fixture_cases(&fixtures_dir),
    );
    failures.append(&mut visible.failures);

    // Base fixtures kept as they were, and accepted differences ruled.
    let base = base_fixtures(tree, &spec.fixtures).await?;
    let now = read_fixture_files(&fixtures_dir);
    let log = RulingLog::read(&capsule_dir.join("escalations.jsonl"))
        .map_err(|e| infra(format!("escalations.jsonl: {e:#}")))?;
    failures.extend(fixture_findings(&base, &now, &log));

    // The director's held-out cases.
    let held_out = held_out(&PortRun {
        capsule_dir,
        capsule,
        spec,
        heldout,
        tree,
        workdir,
        pk_exe,
        runner,
        timeout,
    })
    .await?;
    if held_out.state == "failed" {
        failures.push(format!(
            "held-out port cases failed: {}",
            held_out
                .reason
                .as_deref()
                .unwrap_or("see the held-out report")
        ));
    }

    let result = PortResult {
        source_commit: capsule.base_commit.clone(),
        fixture_hash,
        fixture_count,
        success: failures.is_empty(),
        surfaces: summaries(&visible.reports),
        held_out,
        failures,
    };
    Ok(PortOutcome { result })
}

async fn held_out(run: &PortRun<'_>) -> Result<PortHeldOut, VerifyError> {
    if run.heldout.port.is_none() {
        return Ok(PortHeldOut::none());
    }
    let Some(reference) = run
        .spec
        .reference
        .as_ref()
        .filter(|r| !r.cmd.trim().is_empty())
    else {
        return Err(infra(
            "the held-out file holds port cases but the packet has no port.reference.cmd to capture them from"
                .into(),
        ));
    };
    if let Some(runtime) = &reference.runtime
        && let Err(reason) = runtime_met(run.runner, run.tree, runtime, run.timeout).await?
    {
        return Ok(PortHeldOut {
            state: "skipped".into(),
            reason: Some(reason),
            cases: 0,
            surfaces: BTreeMap::new(),
        });
    }

    // Capture the held-out cases against the reference, inside the sandbox.
    let out_dir = run.workdir.join(PORT_DIR);
    let cases = out_dir.join("heldout.cases.jsonl");
    fs::copy(run.capsule_dir.join(HELDOUT_PORT_CASES_FILE), &cases)
        .map_err(|e| infra(format!("{HELDOUT_PORT_CASES_FILE}: {e}")))?;
    let fixtures = out_dir.join("heldout-fixtures");
    let _ = fs::remove_dir_all(&fixtures);
    let capture = if run.spec.adapter == "process" {
        // A script is captured whole, by `pk port exec` (port_exec.rs).
        crate::port_exec::capture_command(run.spec, reference, run.pk_exe, &cases, &fixtures)
    } else {
        format!(
            "{} pk port capture --cmd {} --cases {} --out {}",
            sh_quote(&run.pk_exe.to_string_lossy()),
            sh_quote(&reference_command(reference)),
            sh_quote(&cases.to_string_lossy()),
            sh_quote(&fixtures.to_string_lossy()),
        )
    };
    let outcome = run
        .runner
        .run(run.tree, &capture, run.timeout)
        .await
        .map_err(|e: InfraError| infra(format!("held-out capture: {e}")))?;
    if outcome.exit_status != 0 {
        return Err(infra(format!(
            "capturing the held-out port cases against the reference failed (exit {}): {}",
            outcome.exit_status,
            first_line(&outcome.output)
        )));
    }

    let report_path = out_dir.join("heldout-replay.json");
    let replay = Replay {
        runner: run.runner,
        tree: run.tree,
        pk_exe: run.pk_exe,
        config: out_dir.join("pk.toml"),
        spec: run.spec,
        timeout: run.timeout,
    };
    let ran = replay.run(&fixtures, &report_path).await?;
    let mut replayed = read_report(&ran);
    let held_tools = tools_with_fixtures(&fixtures);
    // The held-out cases may cover fewer tools than the packet names; each tool they do cover
    // must be ported, and the replay's own report says which are not.
    judge(
        "held-out ",
        &mut replayed,
        &[],
        &held_tools,
        &fixture_cases(&fixtures),
    );
    let cases_count = fixture_set_hash(&fixtures).map(|(_, n)| n).unwrap_or(0);
    let failed = !replayed.failures.is_empty();
    Ok(PortHeldOut {
        state: if failed { "failed" } else { "passed" }.into(),
        reason: failed.then(|| replayed.failures.join("; ")),
        cases: cases_count,
        surfaces: summaries(&replayed.reports),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use cowproof_core::port::{PortParity, PortSpec};
    use tempfile::TempDir;

    fn write(root: &Path, rel: &str, text: &str) {
        let path = root.join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }

    #[test]
    fn the_fixture_hash_covers_paths_and_contents() {
        let dir = TempDir::new().unwrap();
        write(dir.path(), "word/001.json", "{\"a\":1}");
        write(dir.path(), "word/002.json", "{\"a\":2}");
        let (first, count) = fixture_set_hash(dir.path()).unwrap();
        assert_eq!(count, 2);
        assert_eq!(first.len(), 64);
        // The same files hash the same.
        assert_eq!(fixture_set_hash(dir.path()).unwrap().0, first);
        // A changed byte changes it.
        write(dir.path(), "word/002.json", "{\"a\":3}");
        let changed = fixture_set_hash(dir.path()).unwrap().0;
        assert_ne!(changed, first);
        // A rename changes it even though the bytes are the same.
        fs::rename(
            dir.path().join("word/002.json"),
            dir.path().join("word/003.json"),
        )
        .unwrap();
        assert_ne!(fixture_set_hash(dir.path()).unwrap().0, changed);
        // A missing directory is an error, never the empty hash.
        assert!(fixture_set_hash(&dir.path().join("nope")).is_err());
    }

    #[test]
    fn the_spec_half_comes_from_the_header() {
        let spec = PortSpec {
            lang: "node".into(),
            adapter: "function".into(),
            reference: Some(PortReference {
                cmd: "node ref.mjs".into(),
                cwd: None,
                env: BTreeMap::new(),
                runtime: Some("node>=22".into()),
            }),
            cases: "c.jsonl".into(),
            fixtures: "fx".into(),
            tools: vec!["t".into()],
            parity: PortParity {
                epsilon: Some(0.5),
                ignore_paths: vec!["/at".into()],
                unordered_arrays: true,
                path_roots: vec![],
            },
        };
        let port = PortCapsule::from_spec(&spec, 0.25);
        assert_eq!(port.epsilon, 0.25);
        assert_eq!(port.ignore_paths, ["/at"]);
        assert!(port.unordered_arrays);
        assert!(port.result.is_none());
        let config = pk_config(&port);
        assert!(config.contains("epsilon = 0.25"), "{config}");
        assert!(config.contains("epsilon_rel = 0.0"), "{config}");
        assert!(config.contains("unordered_arrays = true"), "{config}");
    }

    #[test]
    fn reference_commands_carry_their_directory_and_environment() {
        let reference = PortReference {
            cmd: "node a.mjs".into(),
            cwd: Some("ref dir".into()),
            env: BTreeMap::from([("TZ".to_string(), "UTC".to_string())]),
            runtime: None,
        };
        assert_eq!(
            reference_command(&reference),
            "cd 'ref dir' && export TZ='UTC' && node a.mjs"
        );
        assert_eq!(sh_quote("it's"), "'it'\\''s'");
    }

    fn outcome(tool: &str, id: &str, status: Status) -> CaseOutcome {
        serde_json::from_value(serde_json::json!({
            "tool": tool, "id": id, "surface": "direct",
            "status": match status {
                Status::Pass => "pass",
                Status::Fail => "fail",
                Status::Accepted => "accepted",
                Status::Error => "error",
                Status::NotPorted => "not_ported",
            },
        }))
        .unwrap()
    }

    fn report(outcomes: Vec<CaseOutcome>) -> ReplayReport {
        let count = |s: Status| outcomes.iter().filter(|o| o.status == s).count();
        serde_json::from_value(serde_json::json!({
            "outcomes": outcomes,
            "passed": count(Status::Pass),
            "accepted": count(Status::Accepted),
            "failed": count(Status::Fail),
            "errored": count(Status::Error),
            "not_ported": count(Status::NotPorted),
        }))
        .unwrap()
    }

    fn cases(pairs: &[(&str, &str)]) -> BTreeSet<(String, String)> {
        pairs
            .iter()
            .map(|(t, i)| (t.to_string(), i.to_string()))
            .collect()
    }

    fn replayed(outcomes: Vec<CaseOutcome>) -> Replayed {
        let r = report(outcomes);
        Replayed {
            reports: BTreeMap::from([("direct".to_string(), r.clone()), ("mcp".to_string(), r)]),
            failures: Vec::new(),
        }
    }

    #[test]
    fn a_replay_with_only_passes_and_accepted_differences_succeeds() {
        let mut r = replayed(vec![
            outcome("t", "1", Status::Pass),
            outcome("t", "2", Status::Accepted),
        ]);
        judge(
            "",
            &mut r,
            &["t".to_string()],
            &["t".to_string()],
            &cases(&[("t", "1"), ("t", "2")]),
        );
        assert_eq!(r.failures, Vec::<String>::new());
    }

    #[test]
    fn not_ported_fails_by_name_even_if_the_command_exited_zero() {
        let mut r = replayed(vec![
            outcome("t", "1", Status::Pass),
            outcome("gone", "1", Status::NotPorted),
        ]);
        judge(
            "",
            &mut r,
            &["t".to_string()],
            &["t".to_string()],
            &cases(&[("t", "1"), ("gone", "1")]),
        );
        let text = r.failures.join("\n");
        assert!(text.contains("direct gone/1: not ported"), "{text}");
        assert!(text.contains("mcp gone/1: not ported"), "{text}");
        assert!(text.contains("1 fixture(s) are not ported"), "{text}");
    }

    #[test]
    fn a_tool_without_fixtures_is_not_proved_and_a_forged_count_is_caught() {
        let mut r = replayed(vec![outcome("t", "1", Status::Pass)]);
        judge(
            "",
            &mut r,
            &["t".to_string(), "silent".to_string()],
            &["t".to_string()],
            &cases(&[("t", "1")]),
        );
        let text = r.failures.join("\n");
        assert!(
            text.contains("no fixture of tool \"silent\" was replayed"),
            "{text}"
        );
        assert!(text.contains("tool \"silent\" has no fixtures"), "{text}");

        let mut forged = replayed(vec![outcome("t", "1", Status::Fail)]);
        for report in forged.reports.values_mut() {
            report.failed = 0;
            report.passed = 1;
        }
        judge(
            "",
            &mut forged,
            &["t".to_string()],
            &["t".to_string()],
            &cases(&[("t", "1")]),
        );
        let text = forged.failures.join("\n");
        assert!(text.contains("counts disagree"), "{text}");
        assert!(text.contains("t/1: differs"), "{text}");
    }

    #[test]
    fn a_missing_surface_fails() {
        let mut r = replayed(vec![outcome("t", "1", Status::Pass)]);
        r.reports.remove("mcp");
        judge(
            "",
            &mut r,
            &["t".to_string()],
            &["t".to_string()],
            &cases(&[("t", "1")]),
        );
        assert!(r.failures.join("\n").contains("no `mcp` surface"));
    }

    #[test]
    fn the_capsule_keeps_failing_and_accepted_outcomes_only_and_shortens_values() {
        let mut fail = outcome("t", "2", Status::Fail);
        fail.differences = serde_json::from_value(serde_json::json!([{
            "path": "/x", "kind": "value_mismatch",
            "expected": "e".repeat(2000), "actual": 7,
        }]))
        .unwrap();
        let r = report(vec![
            outcome("t", "1", Status::Pass),
            fail,
            outcome("t", "3", Status::Accepted),
        ]);
        let s = summarize(&r);
        assert_eq!((s.passed, s.failed, s.accepted), (1, 1, 1));
        let ids: Vec<&str> = s.outcomes.iter().map(|o| o.id.as_str()).collect();
        assert_eq!(ids, ["2", "3"]);
        let expected = s.outcomes[0].differences[0].expected.as_ref().unwrap();
        assert!(expected.as_str().unwrap().contains("bytes)"), "{expected}");
        assert!(expected.to_string().len() < 600);
    }

    #[test]
    fn base_fixtures_may_not_change_and_new_accepted_entries_need_a_ruling() {
        let base = vec![(
            "t/1.json".to_string(),
            serde_json::json!({"tool":"t","id":"1","input":{"a":1},"expected":{"r":1},
                "accepted":[{"path":"/old","reason":"ruling:r0 older lane"}]}),
        )];
        let log = RulingLog::from_answers(vec!["Fine. ruling:r7".into()]);

        // Untouched: nothing found.
        assert_eq!(fixture_findings(&base, &base, &log), Vec::<String>::new());

        // The expectation edited, and a second fixture deleted.
        let mut edited = base.clone();
        edited[0].1["expected"] = serde_json::json!({"r": 2});
        let found = fixture_findings(&base, &edited, &log).join("\n");
        assert!(found.contains("changed its \"expected\""), "{found}");
        let found = fixture_findings(&base, &[], &log).join("\n");
        assert!(
            found.contains("t/1.json of the base was deleted"),
            "{found}"
        );

        // A new accepted entry: unruled, wrong id, then ruled.
        for (reason, ok) in [
            ("close enough", false),
            ("ruling:r9 close enough", false),
            ("ruling:r7 float order", true),
        ] {
            let mut added = base.clone();
            added[0].1["accepted"]
                .as_array_mut()
                .unwrap()
                .push(serde_json::json!({"path":"/new","reason":reason}));
            let found = fixture_findings(&base, &added, &log);
            assert_eq!(found.is_empty(), ok, "{reason}: {found:?}");
            if !ok {
                assert!(found[0].contains("port-accepted-unruled"), "{found:?}");
            }
        }
    }

    // The replay and the report it leaves. The fake `pk` is a script the test writes under
    // /var/tmp; it stands in for the executable the verifier runs in the sandbox, and the
    // runner is the test runner, which is `run_in_group` as well.

    fn spec() -> PortCapsule {
        serde_json::from_value(serde_json::json!({
            "lang": "shell", "adapter": "process", "fixtures": "fx", "tools": ["t"],
            "epsilon": 0.0, "ignore_paths": [], "unordered_arrays": false,
            "path_roots": [],
        }))
        .unwrap()
    }

    fn fake_pk(dir: &Path, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join("fake-pk.sh");
        fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    async fn replay_with(dir: &Path, pk: &Path, report: &Path) -> Ran {
        let runner = crate::runner::ProcessRunner::new();
        let spec = spec();
        let fixtures = dir.join("fx");
        fs::create_dir_all(&fixtures).unwrap();
        Replay {
            runner: &runner,
            tree: dir,
            pk_exe: pk,
            config: dir.join("pk.toml"),
            spec: &spec,
            timeout: Duration::from_secs(30),
        }
        .run(&fixtures, report)
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn a_process_the_replay_leaves_behind_cannot_change_the_report_after_it_ends() {
        let dir = tempfile::TempDir::new_in("/var/tmp").unwrap();
        let report = dir.path().join("replay.json");
        let mark = dir.path().join("background-ran");
        // The replay prints its report, starts a background process that rewrites the report
        // 200 ms later and marks that it ran, and exits 0 at once.
        let pk = fake_pk(
            dir.path(),
            &format!(
                "printf '%s' '{{\"genuine\":true}}'\n\
                 ( sleep 0.2; printf '%s' forged > '{r}'; : > '{m}' ) &\n\
                 exit 0",
                r = report.display(),
                m = mark.display(),
            ),
        );
        let ran = replay_with(dir.path(), &pk, &report).await;
        assert_eq!(ran.exit_status, 0);
        assert_eq!(ran.report, Ok("{\"genuine\":true}".to_string()));
        // Well past the delay: the background process is gone, so it wrote nothing.
        tokio::time::sleep(Duration::from_millis(600)).await;
        assert!(!mark.exists(), "the background process outlived the replay");
        assert_eq!(
            fs::read_to_string(&report).unwrap(),
            "{\"genuine\":true}",
            "the report on disk changed after the replay ended"
        );
    }

    #[tokio::test]
    async fn a_report_that_claims_a_case_with_no_fixture_fails_the_gate() {
        let dir = tempfile::TempDir::new_in("/var/tmp").unwrap();
        let report = dir.path().join("replay.json");
        // The fixtures hold t/1 only; the report also passes `ghost/1` on both surfaces.
        let claimed = replayed(vec![
            outcome("t", "1", Status::Pass),
            outcome("ghost", "1", Status::Pass),
        ]);
        fs::write(
            dir.path().join("claimed.json"),
            serde_json::to_string(&claimed.reports).unwrap(),
        )
        .unwrap();
        let pk = fake_pk(
            dir.path(),
            &format!("cat '{}'", dir.path().join("claimed.json").display()),
        );
        let ran = replay_with(dir.path(), &pk, &report).await;
        let fixtures = dir.path().join("fx");
        write(
            &fixtures,
            "t/1.json",
            r#"{"tool":"t","id":"1","input":{},"expected":{}}"#,
        );
        let mut replayed = read_report(&ran);
        assert_eq!(replayed.failures, Vec::<String>::new());
        judge(
            "",
            &mut replayed,
            &["t".to_string()],
            &tools_with_fixtures(&fixtures),
            &fixture_cases(&fixtures),
        );
        let text = replayed.failures.join("\n");
        assert!(
            text.contains(
                "direct ghost/1: the report has an outcome for a case with no fixture on disk"
            ),
            "{text}"
        );
        assert!(text.contains("mcp ghost/1"), "{text}");
        assert!(!text.contains(" t/1"), "{text}");
    }

    #[test]
    fn an_outcome_for_an_unknown_id_of_a_known_tool_fails_too() {
        let mut r = replayed(vec![
            outcome("t", "1", Status::Pass),
            outcome("t", "9", Status::Accepted),
        ]);
        judge(
            "held-out ",
            &mut r,
            &[],
            &["t".to_string()],
            &cases(&[("t", "1")]),
        );
        let text = r.failures.join("\n");
        assert!(
            text.contains(
                "held-out direct t/9: the report has an outcome for a case with no fixture on disk"
            ),
            "{text}"
        );
        assert!(!text.contains("t/1"), "{text}");
    }

    #[test]
    fn the_fixture_cases_are_the_tool_and_id_the_files_hold() {
        let dir = tempfile::TempDir::new_in("/var/tmp").unwrap();
        write(dir.path(), "a/1.json", r#"{"tool":"a","id":"1"}"#);
        write(dir.path(), "a/two.json", r#"{"tool":"a","id":"2"}"#);
        write(dir.path(), "b/x.json", r#"{"tool":"renamed","id":"x"}"#);
        write(dir.path(), "b/bad.json", r#"{"tool":1}"#);
        assert_eq!(
            fixture_cases(dir.path()),
            cases(&[("a", "1"), ("a", "2"), ("renamed", "x")])
        );
    }
}
