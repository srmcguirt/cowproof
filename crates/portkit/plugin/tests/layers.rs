//! Global and project manifests.
//!
//! The point of a tool "we can use across multiple repos" is not having to
//! re-declare it in each one — while still letting a repo override what it
//! inherits.

use std::path::PathBuf;

use portkit_core::Registry;
use portkit_plugin::register_layers;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

/// Write a manifest declaring one plugin, optionally renamed.
fn manifest(dir: &std::path::Path, file: &str, script: &str, name: Option<&str>) -> PathBuf {
    let path = dir.join(file);
    let rename = name
        .map(|n| format!("name = \"{n}\"\n"))
        .unwrap_or_default();
    std::fs::write(
        &path,
        format!(
            "[[plugin]]\ncommand = \"python3\"\nargs = [\"{}\"]\n{rename}",
            fixture(script).display()
        ),
    )
    .unwrap();
    path
}

#[tokio::test]
async fn tools_from_both_layers_are_available() {
    let dir = tempfile::tempdir().unwrap();
    let global = manifest(dir.path(), "global.toml", "greet.py", None);
    let project = manifest(dir.path(), "project.toml", "greet.py", Some("local_greet"));

    let mut r = Registry::new();
    let report = register_layers(&mut r, &[global, project]).await;

    assert!(report.problems.is_empty(), "{:?}", report.problems);
    assert_eq!(r.names(), ["greet", "local_greet"]);
}

#[tokio::test]
async fn the_project_layer_wins_a_name_collision() {
    // A repo overrides an inherited tool without editing the global manifest.
    let dir = tempfile::tempdir().unwrap();
    let global = manifest(dir.path(), "global.toml", "broken.py", Some("shared"));
    let project = manifest(dir.path(), "project.toml", "greet.py", Some("shared"));

    let mut r = Registry::new();
    register_layers(&mut r, &[global, project]).await;

    // The surviving `shared` is the project one, which actually answers.
    let out = r
        .call("shared", serde_json::json!({"who": "Ada"}))
        .await
        .unwrap();
    assert_eq!(out["greeting"], "hello Ada");
}

#[tokio::test]
async fn shadowing_is_reported_rather_than_silent() {
    // A tool quietly replaced is worse than one that failed loudly.
    let dir = tempfile::tempdir().unwrap();
    let global = manifest(dir.path(), "global.toml", "greet.py", Some("shared"));
    let project = manifest(dir.path(), "project.toml", "greet.py", Some("shared"));

    let mut r = Registry::new();
    let report = register_layers(&mut r, &[global.clone(), project]).await;

    assert_eq!(report.shadowed.len(), 1);
    let (name, previous) = &report.shadowed[0];
    assert_eq!(name, "shared");
    assert!(
        previous.contains("global.toml"),
        "should name what it replaced: {previous}"
    );
}

#[tokio::test]
async fn a_missing_layer_is_skipped_not_an_error() {
    // Having no global manifest is the normal case.
    let dir = tempfile::tempdir().unwrap();
    let project = manifest(dir.path(), "project.toml", "greet.py", None);

    let mut r = Registry::new();
    let report = register_layers(&mut r, &[dir.path().join("absent.toml"), project]).await;

    assert!(report.is_clean(), "{report:?}");
    assert_eq!(r.names(), ["greet"]);
}

#[tokio::test]
async fn a_malformed_manifest_is_reported_without_losing_the_other_layer() {
    let dir = tempfile::tempdir().unwrap();
    let bad = dir.path().join("bad.toml");
    std::fs::write(&bad, "this is not toml [[[").unwrap();
    let project = manifest(dir.path(), "project.toml", "greet.py", None);

    let mut r = Registry::new();
    let report = register_layers(&mut r, &[bad, project]).await;

    assert_eq!(report.problems.len(), 1);
    assert_eq!(r.names(), ["greet"], "the good layer still loaded");
}
