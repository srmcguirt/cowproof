//! The on-disk record of what the reference implementation did.

use std::path::{Path, PathBuf};

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use portkit_core::{Error, Result};

/// One observed call: an input, and what the reference produced for it.
///
/// Fixtures are committed to the repo. They are the contract the port is held
/// to, and reviewing a change to one should feel like reviewing a change to a
/// test — because it is.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fixture {
    pub tool: String,
    /// Unique within a tool. Derived from the case index when not supplied.
    pub id: String,
    pub input: Value,
    /// What the reference implementation returned.
    pub expected: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub captured_at: Option<String>,
    /// The command that produced this, kept so a stale fixture can be regenerated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Free-form note, e.g. why this case matters or which bug it pins.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// Differences that are known, explained, and accepted.
    ///
    /// Real ports rarely end at byte equality. A Rust library will differ from
    /// its Python counterpart somewhere, and the honest outcome is a port that
    /// matches everywhere except a handful of places you have understood and
    /// written down. Those belong here, where review sees them, rather than in
    /// a lowered epsilon that hides everything else too.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accepted: Vec<AcceptedDifference>,
    /// The environment the case was captured with, on top of the capture's own (G2). Kept so
    /// a stale fixture can be regenerated without the capturing machine's shell.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
    /// The case is a "must reject" one (G4): the reference failed on it and `expected` is the
    /// error envelope (see [`crate::error_envelope`]). Replay turns the port's failure into the
    /// same envelope before it compares.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub expect_error: bool,
    /// A declared, versioned transform applied to the reference's output before it was
    /// recorded (G13). A replay refuses a fixture whose transform it does not know.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub normalized: Option<Normalized>,
}

/// The transform a fixture's `expected` went through, declared like the `normalized` fidelity
/// class: a name, a version, and what it was told. An unknown name or version is an error at
/// replay, never a silent pass: a fixture that means whatever the current binary does is not a
/// contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Normalized {
    pub name: String,
    pub version: u32,
    /// The declared roots (`$ROOT`, `$HOME`, `$TMP`, `$SRC`) for `path-roots`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roots: Vec<String>,
}

/// A difference the port is allowed to have, and the reason it is allowed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcceptedDifference {
    /// JSON Pointer prefix, e.g. `/words/0/share`. Covers descendants.
    pub path: String,
    /// Why this difference is acceptable. Required — an unexplained exemption
    /// is indistinguishable from an unnoticed bug six months later.
    pub reason: String,
}

impl AcceptedDifference {
    pub fn covers(&self, path: &str) -> bool {
        path == self.path || path.starts_with(&format!("{}/", self.path))
    }
}

impl Fixture {
    /// `<root>/<tool>/<id>.json` — grouped by tool so a partial port can
    /// replay just the tools it has finished.
    pub fn path_within(&self, root: &Path) -> PathBuf {
        root.join(&self.tool).join(format!("{}.json", self.id))
    }

    pub fn write(&self, root: &Path) -> Result<PathBuf> {
        let path = self.path_within(root);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut json = serde_json::to_string_pretty(self)?;
        json.push('\n');
        std::fs::write(&path, json)?;
        Ok(path)
    }

    pub fn read(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| Error::Fixture(format!("{}: {e}", path.display())))?;
        serde_json::from_str(&raw).map_err(|e| Error::Fixture(format!("{}: {e}", path.display())))
    }
}

/// A case to send to the reference implementation.
///
/// Cases files are JSONL — one object per line — so they append cleanly and
/// diff readably as the suite grows.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Case {
    pub tool: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub input: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// Environment for this case's reference, on top of the capture's (G2). Later wins.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
    /// The reference is expected to fail on this case (G4). Capture records the error envelope
    /// instead of failing, and fails if the reference succeeds.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub expect_error: bool,
}

/// Read a JSONL cases file, ignoring blank lines and `#` comments.
pub fn load_cases(path: &Path) -> Result<Vec<Case>> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| Error::Fixture(format!("{}: {e}", path.display())))?;

    let mut cases = Vec::new();
    for (i, line) in raw.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let case: Case = serde_json::from_str(line).map_err(|e| {
            // Line numbers matter here: a 400-case file with one bad line is
            // otherwise miserable to debug.
            Error::Fixture(format!("{}:{}: {e}", path.display(), i + 1))
        })?;
        cases.push(case);
    }

    if cases.is_empty() {
        return Err(Error::Fixture(format!(
            "{}: no cases found",
            path.display()
        )));
    }
    Ok(cases)
}

/// Load every fixture under `root`, sorted by tool then id.
pub fn load_fixtures(root: &Path) -> Result<Vec<Fixture>> {
    if !root.exists() {
        return Err(Error::Fixture(format!(
            "{}: no such directory",
            root.display()
        )));
    }

    let mut fixtures = Vec::new();
    collect(root, &mut fixtures)?;
    fixtures.sort_by(|a, b| (&a.tool, &a.id).cmp(&(&b.tool, &b.id)));
    Ok(fixtures)
}

fn collect(dir: &Path, out: &mut Vec<Fixture>) -> Result<()> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .map_err(|e| Error::Fixture(format!("{}: {e}", dir.display())))?
        .collect::<std::result::Result<_, _>>()?;
    entries.sort_by_key(std::fs::DirEntry::path);

    for entry in entries {
        let path = entry.path();
        if path.is_dir() {
            collect(&path, out)?;
        } else if path.extension().is_some_and(|e| e == "json") {
            out.push(Fixture::read(&path)?);
        }
    }
    Ok(())
}
