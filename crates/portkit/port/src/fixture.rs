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
    /// The platform the fixture was captured on and applies to: `linux` or `macos` (the
    /// names of `std::env::consts::OS`). Absent, the fixture applies on every platform, as
    /// every fixture did before this field. A tagged fixture's `id` ends with `@<platform>`,
    /// so a case's Linux and macOS versions sit in one directory under distinct ids; a replay
    /// on the other platform does not run it (see [`Fixture::applies_on`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
}

/// The platforms a fixture may be tagged for: the names `std::env::consts::OS` has on the two
/// hosts the harness supports.
pub const PLATFORMS: [&str; 2] = ["linux", "macos"];

/// The most bytes a fixture's `tool` or `id` may have.
pub const MAX_COMPONENT_BYTES: usize = 128;

/// Check that `value` (the `what` of a fixture or case: `"tool"` or `"id"`) can be one path
/// component: non-empty, at most [`MAX_COMPONENT_BYTES`] bytes, no `/`, no `\\`, no NUL, and
/// not `.` or `..`. A fixture is written to `<root>/<tool>/<id>.json`, so a value that is more
/// than one component would write outside the fixtures directory; the cases file is the
/// director's today, and this keeps it safe when it is not. An `@<platform>` id suffix is
/// ordinary text here.
pub fn check_path_component(what: &str, value: &str) -> std::result::Result<(), String> {
    let refuse = |why: &str| {
        Err(format!(
            "the {what} {value:?} {why}; a {what} is one path component (no `/`, `\\`, NUL, `.` or `..`, at most {MAX_COMPONENT_BYTES} bytes)"
        ))
    };
    if value.is_empty() {
        return Err(format!(
            "the {what} is empty; a {what} is one path component"
        ));
    }
    if value.len() > MAX_COMPONENT_BYTES {
        return Err(format!(
            "the {what} is {} bytes; a {what} is one path component of at most {MAX_COMPONENT_BYTES} bytes",
            value.len()
        ));
    }
    if value == "." || value == ".." {
        return refuse("is a directory reference");
    }
    if value.contains('/') || value.contains('\\') {
        return refuse("holds a path separator");
    }
    if value.contains('\0') {
        return refuse("holds a NUL");
    }
    Ok(())
}

/// The platform this process runs on, as a fixture's `platform` names it.
pub fn host_platform() -> &'static str {
    std::env::consts::OS
}

/// The platform an id is tagged for: the text after its last `@` when that is a platform name.
/// An `@` followed by anything else (`user@example`) is part of the id and tags nothing.
pub fn id_platform(id: &str) -> Option<&'static str> {
    let (_, suffix) = id.rsplit_once('@')?;
    PLATFORMS.iter().copied().find(|p| *p == suffix)
}

/// `id` tagged for `platform` (`<id>@<platform>`); an id already tagged for it is returned as
/// it is, and one tagged for another platform is an error.
pub fn tagged_id(id: &str, platform: &str) -> std::result::Result<String, String> {
    match id_platform(id) {
        Some(tag) if tag == platform => Ok(id.to_string()),
        Some(tag) => Err(format!(
            "the case id {id:?} is tagged for {tag}, and this host is {platform}"
        )),
        None => Ok(format!("{id}@{platform}")),
    }
}

/// This host's platform for tagging a capture (`--tag-platform`), or why it cannot be one.
pub fn host_platform_tag() -> std::result::Result<&'static str, String> {
    let host = host_platform();
    if PLATFORMS.contains(&host) {
        Ok(host)
    } else {
        Err(format!(
            "--tag-platform: this host's platform {host:?} is not one fixtures are tagged for ({})",
            PLATFORMS.join(", ")
        ))
    }
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
    /// Whether a replay on `platform` runs this fixture: an untagged one always, a tagged one
    /// only on its own platform.
    pub fn applies_on(&self, platform: &str) -> bool {
        self.platform.as_deref().is_none_or(|p| p == platform)
    }

    /// The tag and the id must agree: a `platform` is one of [`PLATFORMS`] and the id ends
    /// with `@<platform>`; an untagged fixture's id does not end with a platform tag (it would
    /// look tagged and replay everywhere).
    pub fn validate(&self) -> std::result::Result<(), String> {
        check_path_component("tool", &self.tool)?;
        check_path_component("id", &self.id)?;
        match (self.platform.as_deref(), id_platform(&self.id)) {
            (None, None) => Ok(()),
            (None, Some(tag)) => Err(format!(
                "the id {:?} ends with @{tag} but the fixture has no \"platform\"; set \"platform\": \"{tag}\" or rename the id",
                self.id
            )),
            (Some(platform), _) if !PLATFORMS.contains(&platform) => Err(format!(
                "\"platform\": {platform:?} is not one of {}",
                PLATFORMS.join(", ")
            )),
            (Some(platform), tag) if tag == Some(platform) => Ok(()),
            (Some(platform), _) => Err(format!(
                "\"platform\": {platform:?} but the id {:?} does not end with @{platform}",
                self.id
            )),
        }
    }

    /// `<root>/<tool>/<id>.json` — grouped by tool so a partial port can
    /// replay just the tools it has finished.
    ///
    /// An error, not a joined path, when `tool` or `id` is not one path component
    /// ([`check_path_component`]).
    pub fn path_within(&self, root: &Path) -> Result<PathBuf> {
        check_path_component("tool", &self.tool).map_err(Error::Fixture)?;
        check_path_component("id", &self.id).map_err(Error::Fixture)?;
        Ok(root.join(&self.tool).join(format!("{}.json", self.id)))
    }

    pub fn write(&self, root: &Path) -> Result<PathBuf> {
        let path = self.path_within(root)?;
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
        let fixture: Self = serde_json::from_str(&raw)
            .map_err(|e| Error::Fixture(format!("{}: {e}", path.display())))?;
        fixture
            .validate()
            .map_err(|e| Error::Fixture(format!("{}: {e}", path.display())))?;
        Ok(fixture)
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
        let bad_component = check_path_component("tool", &case.tool).and_then(|()| {
            case.id
                .as_deref()
                .map_or(Ok(()), |id| check_path_component("id", id))
        });
        bad_component.map_err(|e| Error::Fixture(format!("{}:{}: {e}", path.display(), i + 1)))?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn dir(name: &str) -> PathBuf {
        let dir = std::path::Path::new("/var/tmp")
            .join(format!("pk-fixture-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn read(dir: &Path, doc: Value) -> Result<Fixture> {
        let path = dir.join("f.json");
        std::fs::write(&path, doc.to_string()).unwrap();
        Fixture::read(&path)
    }

    fn doc(id: &str, platform: Option<&str>) -> Value {
        let mut doc = json!({"tool": "t", "id": id, "input": {}, "expected": {}});
        if let Some(platform) = platform {
            doc["platform"] = json!(platform);
        }
        doc
    }

    /// The other of the two platforms.
    fn other() -> &'static str {
        PLATFORMS
            .iter()
            .copied()
            .find(|p| *p != host_platform())
            .unwrap()
    }

    #[test]
    fn an_old_fixture_reads_applies_everywhere_and_writes_back_unchanged() {
        let base = dir("old");
        let raw = json!({
            "tool": "t", "id": "001", "input": {"a": 1}, "expected": {"b": 2},
            "captured_at": "2026-10-01T00:00:00Z", "source": "sh ref.sh",
        });
        let fixture = read(&base, raw).unwrap();
        assert_eq!(fixture.platform, None);
        assert!(fixture.applies_on("linux") && fixture.applies_on("macos"));
        let written = std::fs::read_to_string(fixture.write(&base.join("out")).unwrap()).unwrap();
        assert!(!written.contains("platform"), "{written}");
        // An `@` in an id that is not a platform name tags nothing.
        let at = read(&base, doc("user@example", None)).unwrap();
        assert!(at.applies_on("linux") && at.applies_on("macos"));
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn a_tagged_fixture_applies_on_its_own_platform_only() {
        let base = dir("tagged");
        for platform in PLATFORMS {
            let id = format!("001@{platform}");
            let fixture = read(&base, doc(&id, Some(platform))).unwrap();
            for host in PLATFORMS {
                assert_eq!(fixture.applies_on(host), host == platform, "{id} on {host}");
            }
            // It survives a write and a read.
            let path = fixture.write(&base.join("out")).unwrap();
            assert!(path.ends_with(format!("t/{id}.json")), "{path:?}");
            assert_eq!(
                Fixture::read(&path).unwrap().platform.as_deref(),
                Some(platform)
            );
        }
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn an_invalid_tag_is_a_parse_error() {
        let base = dir("invalid");
        let host = host_platform();
        let other = other();
        for (what, document, needle) in [
            (
                "an unknown platform",
                doc("001@windows", Some("windows")),
                "not one of",
            ),
            ("an empty platform", doc("001@", Some("")), "not one of"),
            (
                "a platform with no id suffix",
                doc("001", Some(host)),
                "does not end with",
            ),
            (
                "an id suffix that disagrees",
                doc(&format!("001@{other}"), Some(host)),
                "does not end with",
            ),
            (
                "an id suffix and no platform",
                doc(&format!("001@{host}"), None),
                "no \"platform\"",
            ),
            (
                "a platform that is not a string",
                json!({"tool": "t", "id": "001", "input": {}, "expected": {}, "platform": 3}),
                "expected a string",
            ),
        ] {
            let err = read(&base, document).expect_err(what).to_string();
            assert!(
                err.contains("f.json") && err.contains(needle),
                "{what}: {err}"
            );
        }
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn the_tag_helpers_agree_with_the_validation() {
        assert_eq!(id_platform("a@linux"), Some("linux"));
        assert_eq!(id_platform("a@macos"), Some("macos"));
        assert_eq!(id_platform("a@linux2"), None);
        assert_eq!(id_platform("linux"), None);
        assert_eq!(tagged_id("a", "linux").unwrap(), "a@linux");
        assert_eq!(tagged_id("a@linux", "linux").unwrap(), "a@linux");
        assert!(tagged_id("a@macos", "linux").unwrap_err().contains("macos"));
    }

    #[test]
    fn a_tool_or_id_that_is_not_one_path_component_is_refused() {
        let base = dir("component");
        let long = "x".repeat(200);
        for (what, bad, needle) in [
            ("a parent id", "../x", "path separator"),
            ("a nested id", "a/b", "path separator"),
            ("a backslash id", "a\\b", "path separator"),
            ("a dot id", ".", "directory reference"),
            ("a dot-dot id", "..", "directory reference"),
            ("an empty id", "", "is empty"),
            ("a 200-byte id", long.as_str(), "200 bytes"),
            ("a NUL id", "a\0b", "NUL"),
        ] {
            let fixture = Fixture {
                tool: "t".into(),
                id: bad.into(),
                input: json!({}),
                expected: json!({}),
                captured_at: None,
                source: None,
                note: None,
                accepted: Vec::new(),
                env: BTreeMap::new(),
                expect_error: false,
                normalized: None,
                platform: None,
            };
            let err = fixture.path_within(&base).expect_err(what).to_string();
            assert!(err.contains("id") && err.contains(needle), "{what}: {err}");
            assert!(fixture.write(&base).is_err(), "{what} was written");
            let err = read(&base, doc(bad, None)).expect_err(what).to_string();
            assert!(err.contains(needle), "{what} on read: {err}");
            // A tool name is held to the same rule.
            let mut doc = doc("001", None);
            doc["tool"] = json!(bad);
            let err = read(&base, doc).expect_err(what).to_string();
            assert!(
                err.contains("tool") && err.contains(needle),
                "{what} as tool: {err}"
            );
        }
        assert!(
            std::fs::read_dir(&base).unwrap().all(|e| {
                // Only the file the reads above wrote.
                e.unwrap().file_name() == "f.json"
            }),
            "a refused fixture wrote nothing"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn a_platform_tagged_id_and_a_128_byte_id_are_accepted() {
        let base = dir("accepted");
        let id = format!("id@{}", host_platform());
        let fixture = read(&base, doc(&id, Some(host_platform()))).unwrap();
        let path = fixture.path_within(&base).unwrap();
        assert!(path.ends_with(format!("t/{id}.json")), "{path:?}");
        let edge = "y".repeat(MAX_COMPONENT_BYTES);
        assert!(read(&base, doc(&edge, None)).is_ok());
        assert!(read(&base, doc(&format!("{edge}z"), None)).is_err());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn a_cases_file_with_a_bad_tool_or_id_is_refused_with_its_line() {
        let base = dir("cases");
        let file = base.join("cases.jsonl");
        for (line, needle) in [
            (r#"{"tool":"t","id":"../x","input":{}}"#, "path separator"),
            (r#"{"tool":"t","id":"","input":{}}"#, "is empty"),
            (r#"{"tool":"a/b","input":{}}"#, "path separator"),
            (r#"{"tool":"..","input":{}}"#, "directory reference"),
        ] {
            std::fs::write(&file, format!("# comment\n{line}\n")).unwrap();
            let err = load_cases(&file).expect_err(line).to_string();
            assert!(
                err.contains("cases.jsonl:2:") && err.contains(needle),
                "{line}: {err}"
            );
        }
        std::fs::write(&file, "{\"tool\":\"t\",\"id\":\"id@linux\",\"input\":{}}\n").unwrap();
        assert_eq!(load_cases(&file).unwrap().len(), 1);
        let _ = std::fs::remove_dir_all(&base);
    }
}
