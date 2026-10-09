//! Check agent-supplied names against known facts.
//!
//! The point is not to return a schema and hope it is read correctly. It is to
//! reject `user_email` with the observation that the closest real column is
//! `email` — turning a silent runtime error into an authoring-time one, and
//! giving the model something it can act on in one round trip.

use serde::Serialize;

use crate::snapshot::Snapshot;

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Resolution {
    /// The name exists.
    Known { name: String },
    /// It does not, and here is what was probably meant.
    Unknown {
        name: String,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        suggestions: Vec<Suggestion>,
    },
}

impl Resolution {
    pub fn is_known(&self) -> bool {
        matches!(self, Resolution::Known { .. })
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Suggestion {
    pub name: String,
    pub distance: usize,
}

/// How close a candidate must be to be worth suggesting.
///
/// Suggesting everything is as unhelpful as suggesting nothing: an agent that
/// receives five equally-bad guesses will pick one.
fn threshold(name: &str) -> usize {
    match name.len() {
        0..=4 => 1,
        5..=8 => 2,
        _ => 3,
    }
}

fn best_matches<'a>(name: &str, candidates: impl Iterator<Item = &'a str>) -> Vec<Suggestion> {
    let limit = threshold(name);
    let lower = name.to_lowercase();

    let mut scored: Vec<Suggestion> = candidates
        .filter_map(|c| {
            let d = edit_distance(&lower, &c.to_lowercase());
            // A containment match is often the real intent even at a large
            // edit distance — `tokens` vs `source.tokens`. But it has to be
            // substantial: `id` is contained in half the columns in any
            // schema, and suggesting it for `user_id` is noise the model
            // will act on.
            let other = c.to_lowercase();
            let (short, long) = if lower.len() <= other.len() {
                (lower.as_str(), other.as_str())
            } else {
                (other.as_str(), lower.as_str())
            };
            let contained =
                short.len() >= 4 && short.len() * 2 >= long.len() && long.contains(short);
            (d <= limit || contained).then(|| Suggestion {
                name: c.to_string(),
                distance: d,
            })
        })
        .collect();

    scored.sort_by(|a, b| {
        a.distance
            .cmp(&b.distance)
            .then_with(|| a.name.cmp(&b.name))
    });

    // When something is clearly the intended name, drop the distant
    // containment matches. A correct first guess followed by a bad second one
    // invites the model to pick the wrong branch.
    if let Some(best) = scored.first().map(|s| s.distance) {
        if best <= 2 {
            scored.retain(|s| s.distance <= best + 1);
        }
    }
    scored.truncate(3);
    scored
}

/// Does this table exist?
pub fn resolve_table(snapshot: &Snapshot, name: &str) -> Resolution {
    if snapshot.table(name).is_some() {
        return Resolution::Known {
            name: name.to_string(),
        };
    }
    // Compare against both qualified and bare names: an agent that says
    // `token` should be pointed at `source.tokens`.
    let mut candidates: Vec<&str> = snapshot.table_names();
    let bare: Vec<&str> = snapshot
        .tables
        .values()
        .filter_map(|t| t.name.rsplit('.').next())
        .collect();
    candidates.extend(bare);

    Resolution::Unknown {
        name: name.to_string(),
        suggestions: best_matches(name, candidates.into_iter()),
    }
}

/// Does this column exist on this table?
///
/// An unknown table is reported as such rather than as an unknown column: the
/// first error is the real one, and reporting the second would send the agent
/// looking in the wrong place.
pub fn resolve_column(snapshot: &Snapshot, table: &str, column: &str) -> Resolution {
    let Some(t) = snapshot.table(table) else {
        return resolve_table(snapshot, table);
    };
    if t.column(column).is_some() {
        return Resolution::Known {
            name: column.to_string(),
        };
    }
    Resolution::Unknown {
        name: column.to_string(),
        suggestions: best_matches(column, t.columns.iter().map(|c| c.name.as_str())),
    }
}

/// Levenshtein distance, two rows rather than a full matrix.
fn edit_distance(a: &str, b: &str) -> usize {
    let (a, b): (Vec<char>, Vec<char>) = (a.chars().collect(), b.chars().collect());
    if a.is_empty() {
        return b.len();
    }
    if b.is_empty() {
        return a.len();
    }

    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut cur = vec![0usize; b.len() + 1];

    for (i, ca) in a.iter().enumerate() {
        cur[0] = i + 1;
        for (j, cb) in b.iter().enumerate() {
            let cost = usize::from(ca != cb);
            cur[j + 1] = (prev[j + 1] + 1).min(cur[j] + 1).min(prev[j] + cost);
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    prev[b.len()]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot::{Column, Provenance, SourceKind, Table};
    use std::collections::BTreeMap;

    fn snap() -> Snapshot {
        let cols = |names: &[(&str, &str)]| {
            names
                .iter()
                .map(|(n, t)| Column {
                    name: n.to_string(),
                    data_type: t.to_string(),
                    nullable: false,
                    description: None,
                })
                .collect()
        };
        let mut tables = BTreeMap::new();
        tables.insert(
            "source.tokens".into(),
            Table {
                name: "source.tokens".into(),
                schema: "source".into(),
                kind: "table".into(),
                columns: cols(&[("ref", "text"), ("position", "int4"), ("surface", "text")]),
                primary_key: vec!["ref".into()],
            },
        );
        tables.insert(
            "usr.accounts".into(),
            Table {
                name: "usr.accounts".into(),
                schema: "usr".into(),
                kind: "table".into(),
                columns: cols(&[("id", "uuid"), ("email", "text")]),
                primary_key: vec!["id".into()],
            },
        );
        Snapshot {
            provenance: Provenance {
                source: "test".into(),
                kind: SourceKind::PostgresCatalog,
                locator: "localhost/test".into(),
                captured_at: "2026-09-09T00:00:00Z".into(),
                fingerprint: "0".into(),
            },
            tables,
            enums: BTreeMap::new(),
            functions: vec![],
        }
    }

    #[test]
    fn a_real_table_resolves() {
        assert!(resolve_table(&snap(), "source.tokens").is_known());
    }

    #[test]
    fn an_unambiguous_bare_name_resolves() {
        // Agents say `tokens`; refusing that helps nobody when only one
        // table can be meant.
        assert!(resolve_table(&snap(), "tokens").is_known());
    }

    #[test]
    fn a_hallucinated_column_is_rejected_with_the_likely_intent() {
        let r = resolve_column(&snap(), "usr.accounts", "user_email");
        match r {
            Resolution::Unknown { suggestions, .. } => {
                assert!(
                    suggestions.iter().any(|s| s.name == "email"),
                    "expected `email` to be suggested, got {suggestions:?}"
                );
            }
            other => panic!("expected rejection, got {other:?}"),
        }
    }

    #[test]
    fn a_real_column_resolves() {
        assert!(resolve_column(&snap(), "usr.accounts", "email").is_known());
    }

    #[test]
    fn an_unknown_table_reports_the_table_not_the_column() {
        // The first error is the real one; reporting a missing column on a
        // table that does not exist sends the agent to the wrong place.
        let r = resolve_column(&snap(), "usr.acounts", "email");
        match r {
            Resolution::Unknown { name, suggestions } => {
                assert_eq!(name, "usr.acounts");
                assert!(suggestions.iter().any(|s| s.name == "usr.accounts"));
            }
            other => panic!("expected the table error, got {other:?}"),
        }
    }

    #[test]
    fn nonsense_gets_no_suggestions_rather_than_bad_ones() {
        let r = resolve_column(&snap(), "source.tokens", "zzzzzzzzzzqqqq");
        match r {
            Resolution::Unknown { suggestions, .. } => assert!(
                suggestions.is_empty(),
                "five bad guesses are worse than none: {suggestions:?}"
            ),
            other => panic!("expected rejection, got {other:?}"),
        }
    }

    #[test]
    fn a_short_substring_is_not_offered_as_a_suggestion() {
        // Found against the real fellwork schema: `user_id` was answered with
        // "did you mean `id`?" because `id` is contained in it. `id` is
        // contained in half the columns of any schema, and the model acts on
        // whatever it is told.
        let r = resolve_column(&snap(), "usr.accounts", "user_id");
        match r {
            Resolution::Unknown { suggestions, .. } => assert!(
                !suggestions.iter().any(|s| s.name == "id"),
                "`id` is noise here: {suggestions:?}"
            ),
            other => panic!("expected rejection, got {other:?}"),
        }
    }

    #[test]
    fn a_substantial_containment_match_is_still_offered() {
        // The rule must not become so strict that it loses real intent.
        let r = resolve_table(&snap(), "tokens_extra");
        match r {
            Resolution::Unknown { suggestions, .. } => assert!(
                suggestions.iter().any(|s| s.name.contains("tokens")),
                "expected a tokens suggestion: {suggestions:?}"
            ),
            Resolution::Known { .. } => panic!("should not resolve"),
        }
    }

    #[test]
    fn edit_distance_is_correct() {
        assert_eq!(edit_distance("email", "user_email"), 5);
        assert_eq!(edit_distance("tokens", "token"), 1);
        assert_eq!(edit_distance("abc", "abc"), 0);
    }
}
