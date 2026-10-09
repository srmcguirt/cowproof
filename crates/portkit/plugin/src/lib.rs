//! Tools that live outside the binary.
//!
//! The contract already existed. `pk port capture` speaks JSON-on-stdin,
//! JSON-on-stdout to a reference implementation; a plugin is the same
//! conversation, plus a way to describe itself:
//!
//! ```text
//! $ mytool --portkit-spec
//! {"name":"mytool","description":"...","input_schema":{...}}
//!
//! $ echo '{"tool":"mytool","input":{...}}' | mytool
//! {"result":"..."}
//! ```
//!
//! That symmetry is the point. A Python tool can be a plugin today and a Rust
//! tool tomorrow, with the same fixtures proving the two agree:
//!
//! ```text
//! register as plugin → capture fixtures → port to Rust → replay → swap
//! ```
//!
//! # Discovery is explicit, never a PATH scan
//!
//! Plugins are listed in a manifest. Scanning a directory and executing what
//! it finds turns a dropped file into code execution; the convenience is not
//! worth it.

pub mod manifest;
pub mod tool;

pub use manifest::{expand_home, load_manifest, Manifest, PluginEntry, GLOBAL_PATH, PROJECT_PATH};
pub use tool::PluginTool;

use std::path::Path;

use portkit_core::{Registry, Result, Tool};

/// What happened while loading plugins.
///
/// Neither kind is fatal, and both are worth saying out loud: a tool that is
/// quietly absent, or quietly replaced, is worse than one that failed loudly.
#[derive(Debug, Default)]
pub struct LoadReport {
    /// Plugins that could not be registered, with why.
    pub problems: Vec<String>,
    /// Tools a later layer replaced, as `(name, shadowed manifest)`.
    pub shadowed: Vec<(String, String)>,
}

impl LoadReport {
    pub fn is_clean(&self) -> bool {
        self.problems.is_empty() && self.shadowed.is_empty()
    }
}

/// Load a manifest and register every plugin it declares.
pub async fn register_from(registry: &mut Registry, manifest: &Path) -> Result<Vec<String>> {
    Ok(register_layers(registry, &[manifest.to_path_buf()])
        .await
        .problems)
}

/// Load manifests in order, later layers winning on a name collision.
///
/// Global first, project second, so a repo can override a tool it inherits
/// without editing anyone else's manifest. Missing files are skipped: having
/// no plugins is the normal case, not an error.
pub async fn register_layers(
    registry: &mut Registry,
    manifests: &[std::path::PathBuf],
) -> LoadReport {
    let mut report = LoadReport::default();
    // Track which layer last claimed each name, so shadowing can be reported
    // with both sides rather than just noticed.
    let mut owner: std::collections::BTreeMap<String, String> = Default::default();

    for path in manifests {
        if !path.exists() {
            continue;
        }
        let manifest = match load_manifest(path) {
            Ok(m) => m,
            Err(err) => {
                report.problems.push(format!("{}: {err}", path.display()));
                continue;
            }
        };

        for entry in manifest.plugins {
            match PluginTool::discover(entry.clone()).await {
                Ok(tool) => {
                    let name = tool.spec().name.clone();
                    if let Some(previous) = owner.insert(name.clone(), path.display().to_string()) {
                        report.shadowed.push((name, previous));
                    }
                    registry.register(tool);
                }
                Err(err) => report.problems.push(format!("{}: {err}", entry.label())),
            }
        }
    }

    report
}
