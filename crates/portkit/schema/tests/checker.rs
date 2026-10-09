//! Checker tests against a snapshot captured from real fellwork DDL.
//!
//! The snapshot is committed, so these run with no database — which is the
//! whole argument for materializing one. CI, offline work, and anyone without
//! production credentials get the same answers.

use portkit_schema::{resolve_column, resolve_table, Resolution, Snapshot};

fn snapshot() -> Snapshot {
    Snapshot::load(std::path::Path::new("tests/fixtures/fellwork.json"))
        .expect("committed fixture must load")
}

fn suggestions(r: &Resolution) -> Vec<String> {
    match r {
        Resolution::Unknown { suggestions, .. } => {
            suggestions.iter().map(|s| s.name.clone()).collect()
        }
        Resolution::Known { .. } => vec![],
    }
}

#[test]
fn a_real_table_resolves() {
    assert!(resolve_table(&snapshot(), "source.tokens").is_known());
}

#[test]
fn a_real_column_resolves() {
    assert!(resolve_column(&snapshot(), "source.tokens", "surface_form").is_known());
}

#[test]
fn a_transposition_typo_is_caught_and_corrected() {
    // The mistake agents actually make.
    let r = resolve_column(&snapshot(), "source.tokens", "surface_from");
    assert!(!r.is_known());
    assert!(
        suggestions(&r).contains(&"surface_form".to_string()),
        "{r:?}"
    );
}

#[test]
fn a_singular_plural_slip_is_corrected() {
    let r = resolve_table(&snapshot(), "source.token");
    assert!(!r.is_known());
    assert_eq!(
        suggestions(&r).first().map(String::as_str),
        Some("source.tokens")
    );
}

#[test]
fn an_invented_column_gets_no_misleading_suggestion() {
    // `user_email` has no near neighbour here. Offering a bad guess would be
    // worse than offering none — the model would take it.
    let r = resolve_column(&snapshot(), "source.tokens", "user_email");
    assert!(!r.is_known());
    assert!(suggestions(&r).is_empty(), "{r:?}");
}

#[test]
fn a_bare_table_name_resolves_when_unambiguous() {
    assert!(resolve_table(&snapshot(), "tokens").is_known());
}

#[test]
fn the_snapshot_carries_auditable_provenance() {
    // An answer without provenance cannot be distinguished from a stale one.
    let s = snapshot();
    assert!(s.provenance.kind.is_authoritative());
    assert!(!s.provenance.fingerprint.is_empty());
    assert!(!s.provenance.captured_at.is_empty());
}

#[test]
fn the_locator_carries_no_credentials() {
    // Provenance travels into agent context and into commits.
    let s = snapshot();
    assert!(
        !s.provenance.locator.contains('@'),
        "locator: {}",
        s.provenance.locator
    );
    assert!(!s.provenance.locator.to_lowercase().contains("password"));
}

#[test]
fn the_fingerprint_is_stable_across_reloads() {
    // Drift detection that fires on every run stops being read.
    let a = snapshot().compute_fingerprint();
    let b = snapshot().compute_fingerprint();
    assert_eq!(a, b);
}
