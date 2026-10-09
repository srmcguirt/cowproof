//! A [`RefResolver`] backed by introspected snapshots.
//!
//! This is what turns `x-schema-ref` annotations into real checks: the
//! registry consults it before dispatch, so a tool never runs with a table
//! name that does not exist.

use std::collections::BTreeMap;
use std::path::Path;

use portkit_core::{RefOutcome, RefResolver, Result, SchemaRef};

use crate::resolve::{resolve_column, resolve_table, Resolution};
use crate::snapshot::Snapshot;

/// Named schema sources. Sources are always named explicitly — a system with
/// a workshop and a library database must never guess which one is meant.
#[derive(Default)]
pub struct SchemaRegistry {
    sources: BTreeMap<String, Snapshot>,
}

impl SchemaRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a snapshot under the source name recorded in its provenance.
    pub fn insert(&mut self, snapshot: Snapshot) -> &mut Self {
        self.sources
            .insert(snapshot.provenance.source.clone(), snapshot);
        self
    }

    #[must_use]
    pub fn with(mut self, snapshot: Snapshot) -> Self {
        self.insert(snapshot);
        self
    }

    /// Load a committed snapshot from disk.
    pub fn load(&mut self, path: &Path) -> Result<&mut Self> {
        let snapshot = Snapshot::load(path)?;
        self.insert(snapshot);
        Ok(self)
    }

    /// Load several committed snapshots.
    ///
    /// A snapshot that fails to load is reported and skipped rather than
    /// aborting startup: one bad file should not take the server down, and a
    /// missing source declines at check time rather than passing silently.
    pub fn from_paths<P: AsRef<Path>>(paths: &[P]) -> (Self, Vec<String>) {
        let mut registry = Self::new();
        let mut problems = Vec::new();
        for p in paths {
            match Snapshot::load(p.as_ref()) {
                Ok(s) => {
                    registry.insert(s);
                }
                Err(e) => problems.push(format!("{}: {e}", p.as_ref().display())),
            }
        }
        (registry, problems)
    }

    pub fn get(&self, source: &str) -> Option<&Snapshot> {
        self.sources.get(source)
    }

    pub fn names(&self) -> Vec<&str> {
        self.sources.keys().map(String::as_str).collect()
    }

    pub fn is_empty(&self) -> bool {
        self.sources.is_empty()
    }
}

fn outcome(r: Resolution) -> RefOutcome {
    match r {
        Resolution::Known { .. } => RefOutcome::Known,
        Resolution::Unknown { suggestions, .. } => RefOutcome::Unknown {
            suggestions: suggestions.into_iter().map(|s| s.name).collect(),
        },
    }
}

impl RefResolver for SchemaRegistry {
    fn resolve(&self, reference: &SchemaRef, value: &str, parent: Option<&str>) -> RefOutcome {
        // A source we have never loaded is not evidence that the name is wrong.
        let Some(snapshot) = self.sources.get(&reference.source) else {
            return RefOutcome::UnknownSource;
        };

        match reference.kind.as_str() {
            "table" => outcome(resolve_table(snapshot, value)),

            "column" => match parent {
                Some(table) => outcome(resolve_column(snapshot, table, value)),
                // The annotation named a sibling argument that is absent or
                // not a string. Checking every table for the name would invite
                // a false pass, so decline instead.
                None => RefOutcome::UnknownSource,
            },

            "function" => {
                if snapshot.functions.iter().any(|f| f == value) {
                    RefOutcome::Known
                } else {
                    RefOutcome::Unknown {
                        suggestions: near(value, snapshot.functions.iter()),
                    }
                }
            }

            "enum" => {
                if snapshot.enums.contains_key(value) {
                    RefOutcome::Known
                } else {
                    RefOutcome::Unknown {
                        suggestions: near(value, snapshot.enums.keys()),
                    }
                }
            }

            // An unknown kind is a tool-authoring mistake. Declining is safer
            // than passing: a check the author believes in should not silently
            // approve everything.
            _ => RefOutcome::UnknownSource,
        }
    }

    fn provenance(&self, source: &str) -> Option<String> {
        let s = self.sources.get(source)?;
        let at = &s.provenance.captured_at;
        Some(format!(
            "{} @ {:?}, captured {}",
            s.provenance.source,
            s.provenance.kind,
            &at[..at.len().min(19)]
        ))
    }
}

/// Cheap nearest-name suggestions for the flat kinds.
fn near<'a>(needle: &str, candidates: impl Iterator<Item = &'a String>) -> Vec<String> {
    let lower = needle.to_lowercase();
    let mut hits: Vec<&String> = candidates
        .filter(|c| {
            let c = c.to_lowercase();
            c.contains(&lower) || lower.contains(&c)
        })
        .collect();
    hits.sort_by_key(|c| c.len());
    hits.into_iter().take(3).cloned().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use portkit_core::refs;
    use serde_json::json;

    fn registry() -> SchemaRegistry {
        let snap = Snapshot::load(Path::new("tests/fixtures/fellwork.json")).unwrap();
        SchemaRegistry::new().with(snap)
    }

    /// The fixture's provenance says `fellwork`, so references use that source.
    fn schema() -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "table": { "type": "string", "x-schema-ref": "fellwork#table" },
                "columns": {
                    "type": "array",
                    "items": { "type": "string", "x-schema-ref": "fellwork#column(table)" }
                }
            }
        })
    }

    #[test]
    fn real_names_pass() {
        let input = json!({"table": "source.tokens", "columns": ["surface_form", "lemma"]});
        assert!(refs::check(&schema(), &input, &registry()).is_ok());
    }

    #[test]
    fn a_hallucinated_column_is_rejected_before_dispatch() {
        let input = json!({"table": "source.tokens", "columns": ["user_email"]});
        let err = refs::check(&schema(), &input, &registry())
            .unwrap_err()
            .to_string();
        assert!(err.contains("/columns/0"), "{err}");
        assert!(err.contains("not a known column"), "{err}");
    }

    #[test]
    fn a_typo_is_corrected() {
        let input = json!({"table": "source.tokens", "columns": ["surface_from"]});
        let err = refs::check(&schema(), &input, &registry())
            .unwrap_err()
            .to_string();
        assert!(err.contains("`surface_form`"), "{err}");
    }

    #[test]
    fn the_error_carries_provenance() {
        let input = json!({"table": "source.token", "columns": []});
        let err = refs::check(&schema(), &input, &registry())
            .unwrap_err()
            .to_string();
        assert!(err.contains("PostgresCatalog"), "{err}");
        assert!(err.contains("captured"), "{err}");
    }

    #[test]
    fn an_unloaded_source_declines_rather_than_rejecting() {
        let s = json!({"properties": {"t": {"x-schema-ref": "library#table"}}});
        let err = refs::check(&s, &json!({"t": "source.tokens"}), &registry())
            .unwrap_err()
            .to_string();
        assert!(err.contains("no schema snapshot loaded"), "{err}");
    }

    #[test]
    fn a_column_reference_without_its_parent_declines() {
        // Guessing across every table would risk a false pass.
        let s = json!({"properties": {"c": {"x-schema-ref": "fellwork#column(table)"}}});
        let err = refs::check(&s, &json!({"c": "lemma"}), &registry())
            .unwrap_err()
            .to_string();
        assert!(err.contains("cannot check"), "{err}");
    }
}
