//! Reference binary for the portkit template.
//!
//! Serves the example tools from `portkit-demo`, plus the schema tools when
//! snapshots are configured. When you fork, swap the registry for your own —
//! this file should stay about this short.

use std::process::ExitCode;

use portkit_core::{Config, Registry};

#[tokio::main]
async fn main() -> ExitCode {
    portkit_cli::run_with(registry).await
}

/// Load declared plugins, reporting failures rather than refusing to start.
///
/// Blocking inside the builder because registration happens before the async
/// command runs; discovery is a handful of short-lived subprocesses.
fn load_plugins(registry: &mut Registry, config: &Config) {
    let layers: Vec<_> = config
        .plugins
        .layers()
        .iter()
        .map(|p| portkit_plugin::expand_home(p))
        .collect();
    if !layers.iter().any(|p| p.exists()) {
        return; // no manifests is the normal case, not an error
    }

    let report = tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current()
            .block_on(portkit_plugin::register_layers(registry, &layers))
    });

    for p in &report.problems {
        eprintln!("warning: plugin unavailable — {p}");
    }
    for (name, shadowed) in &report.shadowed {
        // A tool being silently replaced is worse than one that failed loudly.
        eprintln!("note: `{name}` overrides the one declared in {shadowed}");
    }
}

/// Built from the effective config, so snapshots are loaded before
/// `tools/list` is answered — an agent's first view of the interface should
/// already be grounded rather than corrected after its first wrong guess.
fn registry(config: &Config) -> Registry {
    let mut registry = portkit_demo::registry();

    if !config.schema.snapshots.is_empty() {
        let (sources, problems) =
            portkit_schema::SchemaRegistry::from_paths(&config.schema.snapshots);
        for p in &problems {
            eprintln!("warning: could not load schema snapshot {p}");
        }
        if !sources.is_empty() {
            portkit_schema::register(&mut registry, sources);
        }
    }

    if !config.index.root.trim().is_empty() {
        portkit_index::register(&mut registry, std::path::PathBuf::from(&config.index.root));
    }

    load_plugins(&mut registry, config);

    registry
}
