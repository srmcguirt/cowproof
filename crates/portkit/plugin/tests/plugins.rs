//! Plugins are external processes, so most of what can go wrong is a failure
//! mode rather than a wrong answer. These cover the ones that would otherwise
//! surface as a hung agent or an unreadable error.

use std::path::PathBuf;

use portkit_core::{Registry, Tool};
use portkit_plugin::{PluginEntry, PluginTool};
use serde_json::json;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn entry(script: &str) -> PluginEntry {
    PluginEntry {
        command: "python3".into(),
        args: vec![fixture(script).to_string_lossy().to_string()],
        name: None,
        timeout_secs: 30,
        cwd: None,
    }
}

#[tokio::test]
async fn a_plugin_describes_itself_and_answers() {
    let tool = PluginTool::discover(entry("greet.py"))
        .await
        .expect("discovery");
    assert_eq!(tool.spec().name, "greet");

    let mut r = Registry::new();
    r.register(tool);
    let out = r.call("greet", json!({"who": "Ada"})).await.unwrap();
    assert_eq!(out["greeting"], "hello Ada");
}

#[tokio::test]
async fn a_plugins_schema_is_enforced_by_the_registry() {
    // The point of registering rather than shelling out: a plugin inherits
    // argument validation it did not have to implement.
    let mut r = Registry::new();
    r.register(PluginTool::discover(entry("greet.py")).await.unwrap());

    let err = r
        .call("greet", json!({"who": "Ada", "bogus": 1}))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("bogus"), "{err}");
    assert!(err.is_caller_fault());
}

#[tokio::test]
async fn the_manifest_name_overrides_the_reported_one() {
    // So two plugins claiming one name can be separated without editing either.
    let mut e = entry("greet.py");
    e.name = Some("hello".into());
    assert_eq!(PluginTool::discover(e).await.unwrap().spec().name, "hello");
}

#[tokio::test]
async fn a_failing_plugin_surfaces_its_stderr() {
    // stderr is the only thing the model has to work out what went wrong.
    let tool = PluginTool::discover(entry("broken.py")).await.unwrap();
    let mut r = Registry::new();
    r.register(tool);

    let err = r.call("broken", json!({})).await.unwrap_err().to_string();
    assert!(err.contains("the backend was unreachable"), "{err}");
}

#[tokio::test]
async fn a_hanging_plugin_is_abandoned_rather_than_hanging_the_agent() {
    let mut e = entry("hangs.py");
    e.timeout_secs = 1;
    let tool = PluginTool::discover(e).await.unwrap();
    let mut r = Registry::new();
    r.register(tool);

    let started = std::time::Instant::now();
    let err = r.call("hangs", json!({})).await.unwrap_err().to_string();
    assert!(err.contains("timed out"), "{err}");
    assert!(
        started.elapsed().as_secs() < 10,
        "should not have waited for the child"
    );
}

#[tokio::test]
async fn non_json_output_is_reported_with_what_was_actually_returned() {
    // "invalid output" without the output is not debuggable.
    let tool = PluginTool::discover(entry("garbage.py")).await.unwrap();
    let mut r = Registry::new();
    r.register(tool);

    let err = r.call("garbage", json!({})).await.unwrap_err().to_string();
    assert!(err.contains("not JSON"), "{err}");
    assert!(
        err.contains("Sure! Here is your result"),
        "should quote it back: {err}"
    );
}

#[tokio::test]
async fn an_executable_that_cannot_describe_itself_is_refused_at_registration() {
    let err = PluginTool::discover(entry("nospec.py"))
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("--portkit-spec"), "{err}");
}

#[tokio::test]
async fn a_missing_executable_fails_clearly_rather_than_panicking() {
    let e = PluginEntry {
        command: "definitely-not-a-real-binary-xyz".into(),
        args: vec![],
        name: None,
        timeout_secs: 5,
        cwd: None,
    };
    let err = PluginTool::discover(e).await.unwrap_err().to_string();
    assert!(err.contains("could not run"), "{err}");
}

#[tokio::test]
async fn a_broken_plugin_does_not_stop_the_others_registering() {
    // One bad entry should cost you that tool, not the whole server.
    let dir = tempfile::tempdir().unwrap();
    let manifest = dir.path().join("plugins.toml");
    std::fs::write(
        &manifest,
        format!(
            "[[plugin]]\ncommand = \"python3\"\nargs = [\"{}\"]\n\n\
             [[plugin]]\ncommand = \"python3\"\nargs = [\"{}\"]\n",
            fixture("greet.py").display(),
            fixture("nospec.py").display()
        ),
    )
    .unwrap();

    let mut r = Registry::new();
    let problems = portkit_plugin::register_from(&mut r, &manifest)
        .await
        .unwrap();

    assert_eq!(r.names(), ["greet"], "the good plugin still registered");
    assert_eq!(problems.len(), 1, "and the bad one was reported");
}
