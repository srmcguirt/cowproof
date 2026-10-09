//! Schema references: check that argument *values* name real things.
//!
//! JSON Schema validation ([`crate::validate`]) answers "is this call shaped
//! like the tool expects". It cannot answer "is `source.token` a real table",
//! because that fact lives in a database, not in the schema document.
//!
//! So a tool annotates the arguments that are references:
//!
//! ```json
//! {
//!   "table":   { "type": "string", "x-schema-ref": "workshop#table" },
//!   "columns": { "type": "array",
//!                "items": { "type": "string",
//!                           "x-schema-ref": "workshop#column(table)" } }
//! }
//! ```
//!
//! and a [`RefResolver`] — backed by an introspected snapshot — is consulted
//! before dispatch. The tool never runs with a hallucinated table name.
//!
//! `core` defines the contract; `portkit-schema` implements it. That keeps the
//! dependency pointing one way and lets a binary opt in by wiring a resolver.

use serde_json::Value;

use crate::error::{Error, Result};

/// The annotation keyword tools use.
pub const KEYWORD: &str = "x-schema-ref";

/// A parsed `source#kind` or `source#kind(parent_arg)` reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaRef {
    /// Named schema source, e.g. `workshop`. Never defaulted — a system with
    /// more than one database has to say which it means.
    pub source: String,
    /// What kind of name this is, e.g. `table`, `column`, `function`.
    pub kind: String,
    /// For dependent references: the sibling argument naming the parent.
    /// `workshop#column(table)` means "a column of whatever `table` holds".
    pub parent_arg: Option<String>,
}

impl SchemaRef {
    pub fn parse(raw: &str) -> Option<Self> {
        let (source, rest) = raw.split_once('#')?;
        if source.is_empty() || rest.is_empty() {
            return None;
        }
        let (kind, parent_arg) = match rest.split_once('(') {
            Some((kind, tail)) => (kind, Some(tail.strip_suffix(')')?.to_string())),
            None => (rest, None),
        };
        if kind.is_empty() || parent_arg.as_deref() == Some("") {
            return None;
        }
        Some(SchemaRef {
            source: source.to_string(),
            kind: kind.to_string(),
            parent_arg,
        })
    }
}

/// What a resolver concluded about one value.
#[derive(Debug, Clone)]
pub enum RefOutcome {
    /// The name exists.
    Known,
    /// It does not. Suggestions are ordered best-first and may be empty —
    /// an empty list is a real answer, not a failure to try.
    Unknown { suggestions: Vec<String> },
    /// No snapshot is loaded for this source. Distinct from `Unknown` so a
    /// missing snapshot never reads as a hallucinated name.
    UnknownSource,
}

/// Resolves schema references against known facts.
pub trait RefResolver: Send + Sync {
    fn resolve(&self, reference: &SchemaRef, value: &str, parent: Option<&str>) -> RefOutcome;

    /// Provenance for a source, appended to errors so a rejection can be
    /// audited rather than merely believed.
    fn provenance(&self, _source: &str) -> Option<String> {
        None
    }
}

/// Walk `schema` alongside `input`, checking every annotated value.
///
/// All problems are collected before returning: one round trip per bad name is
/// a poor trade when the model could fix them together.
pub fn check(schema: &Value, input: &Value, resolver: &dyn RefResolver) -> Result<()> {
    let mut problems = Vec::new();
    walk(schema, input, input, "", resolver, &mut problems);

    if problems.is_empty() {
        return Ok(());
    }
    problems.truncate(10);
    Err(Error::Other(problems.join("; ")))
}

fn walk(
    schema: &Value,
    value: &Value,
    root: &Value,
    path: &str,
    resolver: &dyn RefResolver,
    problems: &mut Vec<String>,
) {
    // A reference on this node applies to this node's value.
    if let Some(raw) = schema.get(KEYWORD).and_then(Value::as_str) {
        if let Some(reference) = SchemaRef::parse(raw) {
            if let Some(text) = value.as_str() {
                let parent = reference
                    .parent_arg
                    .as_deref()
                    .and_then(|arg| root.get(arg))
                    .and_then(Value::as_str);
                report(&reference, text, parent, path, resolver, problems);
            }
        } else {
            // A malformed annotation is the tool author's bug. Say so rather
            // than silently skipping the check the author thought they had.
            problems.push(format!(
                "{}: malformed {KEYWORD} `{raw}` (expected `source#kind` or `source#kind(arg)`)",
                loc(path)
            ));
        }
    }

    if let (Some(Value::Object(props)), Some(obj)) = (schema.get("properties"), value.as_object()) {
        for (key, sub) in props {
            if let Some(v) = obj.get(key) {
                walk(sub, v, root, &format!("{path}/{key}"), resolver, problems);
            }
        }
    }

    if let (Some(items), Some(arr)) = (schema.get("items"), value.as_array()) {
        for (i, v) in arr.iter().enumerate() {
            walk(items, v, root, &format!("{path}/{i}"), resolver, problems);
        }
    }
}

fn report(
    reference: &SchemaRef,
    text: &str,
    parent: Option<&str>,
    path: &str,
    resolver: &dyn RefResolver,
    problems: &mut Vec<String>,
) {
    match resolver.resolve(reference, text, parent) {
        RefOutcome::Known => {}
        RefOutcome::UnknownSource => problems.push(format!(
            "{}: cannot check `{text}` — no schema snapshot loaded for source `{}`",
            loc(path),
            reference.source
        )),
        RefOutcome::Unknown { suggestions } => {
            let mut msg = format!(
                "{}: `{text}` is not a known {} in `{}`",
                loc(path),
                reference.kind,
                reference.source
            );
            if let Some(p) = parent {
                msg.push_str(&format!(" ({p})"));
            }
            if !suggestions.is_empty() {
                msg.push_str(&format!("; did you mean {}?", quoted(&suggestions)));
            }
            if let Some(p) = resolver.provenance(&reference.source) {
                msg.push_str(&format!(" [{p}]"));
            }
            problems.push(msg);
        }
    }
}

fn loc(path: &str) -> &str {
    if path.is_empty() {
        "<root>"
    } else {
        path
    }
}

fn quoted(names: &[String]) -> String {
    names
        .iter()
        .map(|n| format!("`{n}`"))
        .collect::<Vec<_>>()
        .join(" or ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    struct Fake;

    impl RefResolver for Fake {
        fn resolve(&self, r: &SchemaRef, value: &str, parent: Option<&str>) -> RefOutcome {
            if r.source != "db" {
                return RefOutcome::UnknownSource;
            }
            match (r.kind.as_str(), value, parent) {
                ("table", "users", _) => RefOutcome::Known,
                ("column", "email", Some("users")) => RefOutcome::Known,
                ("column", _, _) => RefOutcome::Unknown {
                    suggestions: vec!["email".into()],
                },
                ("table", _, _) => RefOutcome::Unknown {
                    suggestions: vec!["users".into()],
                },
                _ => RefOutcome::Unknown {
                    suggestions: vec![],
                },
            }
        }
        fn provenance(&self, _s: &str) -> Option<String> {
            Some("db @ snapshot".into())
        }
    }

    fn schema() -> Value {
        json!({
            "type": "object",
            "properties": {
                "table": { "type": "string", "x-schema-ref": "db#table" },
                "columns": {
                    "type": "array",
                    "items": { "type": "string", "x-schema-ref": "db#column(table)" }
                }
            }
        })
    }

    #[test]
    fn parses_a_plain_reference() {
        let r = SchemaRef::parse("workshop#table").unwrap();
        assert_eq!(r.source, "workshop");
        assert_eq!(r.kind, "table");
        assert_eq!(r.parent_arg, None);
    }

    #[test]
    fn parses_a_dependent_reference() {
        let r = SchemaRef::parse("workshop#column(table)").unwrap();
        assert_eq!(r.kind, "column");
        assert_eq!(r.parent_arg.as_deref(), Some("table"));
    }

    #[test]
    fn rejects_malformed_references() {
        for bad in ["notaref", "#table", "db#", "db#column(", "db#column()"] {
            assert!(SchemaRef::parse(bad).is_none(), "should reject {bad}");
        }
    }

    #[test]
    fn valid_names_pass() {
        let input = json!({"table": "users", "columns": ["email"]});
        assert!(check(&schema(), &input, &Fake).is_ok());
    }

    #[test]
    fn a_bad_table_is_reported_with_a_suggestion() {
        let input = json!({"table": "user", "columns": []});
        let err = check(&schema(), &input, &Fake).unwrap_err().to_string();
        assert!(err.contains("/table"), "{err}");
        assert!(err.contains("`users`"), "{err}");
        assert!(
            err.contains("db @ snapshot"),
            "provenance must survive: {err}"
        );
    }

    #[test]
    fn a_dependent_column_reference_resolves_against_its_sibling() {
        // `columns` is only checkable because `table` says which table.
        let input = json!({"table": "users", "columns": ["emial"]});
        let err = check(&schema(), &input, &Fake).unwrap_err().to_string();
        assert!(err.contains("/columns/0"), "{err}");
        assert!(err.contains("`email`"), "{err}");
    }

    #[test]
    fn every_bad_value_in_an_array_is_reported_at_once() {
        let input = json!({"table": "users", "columns": ["a", "b"]});
        let err = check(&schema(), &input, &Fake).unwrap_err().to_string();
        assert!(
            err.contains("/columns/0") && err.contains("/columns/1"),
            "{err}"
        );
    }

    #[test]
    fn a_missing_snapshot_is_not_reported_as_a_bad_name() {
        // Otherwise an unconfigured source looks exactly like hallucination.
        let s = json!({"properties": {"t": {"x-schema-ref": "other#table"}}});
        let err = check(&s, &json!({"t": "users"}), &Fake)
            .unwrap_err()
            .to_string();
        assert!(err.contains("no schema snapshot loaded"), "{err}");
    }

    #[test]
    fn a_malformed_annotation_is_surfaced_not_skipped() {
        // Silently skipping would leave the author believing they had a check.
        let s = json!({"properties": {"t": {"x-schema-ref": "garbage"}}});
        let err = check(&s, &json!({"t": "x"}), &Fake)
            .unwrap_err()
            .to_string();
        assert!(err.contains("malformed"), "{err}");
    }

    #[test]
    fn unannotated_arguments_are_ignored() {
        let s = json!({"properties": {"limit": {"type": "integer"}}});
        assert!(check(&s, &json!({"limit": 5}), &Fake).is_ok());
    }
}
