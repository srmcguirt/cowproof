//! What plugins exist, declared rather than discovered.

use std::path::Path;

use serde::{Deserialize, Serialize};

use portkit_core::{Error, Result};

/// Tools available in every repo.
pub const GLOBAL_PATH: &str = "~/.portkit/plugins.toml";

/// Tools belonging to this repo. Wins on a name collision.
pub const PROJECT_PATH: &str = ".portkit/plugins.toml";

/// Expand a leading `~/`.
///
/// Only the leading form: `~user` needs passwd lookups, and a path containing
/// a literal tilde elsewhere is not a home reference.
pub fn expand_home(path: &str) -> std::path::PathBuf {
    match path.strip_prefix("~/") {
        Some(rest) => match std::env::var_os("HOME") {
            Some(home) => std::path::PathBuf::from(home).join(rest),
            None => std::path::PathBuf::from(path),
        },
        None => std::path::PathBuf::from(path),
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Manifest {
    #[serde(default, rename = "plugin")]
    pub plugins: Vec<PluginEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginEntry {
    /// Executable to run. Not looked up on `PATH` unless it has no separator,
    /// so a manifest can pin an absolute path.
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    /// Overrides the name the plugin reports. Useful when two plugins collide
    /// or a name needs a prefix.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Seconds before a call is abandoned. A plugin that hangs would otherwise
    /// hang the agent waiting on it.
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    /// Working directory for the subprocess.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
}

fn default_timeout() -> u64 {
    30
}

impl PluginEntry {
    /// Human-readable identifier for error messages.
    pub fn label(&self) -> String {
        match &self.name {
            Some(n) => n.clone(),
            None => self.command.clone(),
        }
    }
}

pub fn load_manifest(path: &Path) -> Result<Manifest> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| Error::Config(format!("{}: {e}", path.display())))?;
    toml::from_str(&raw).map_err(|e| Error::Config(format!("{}: {e}", path.display())))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Manifest {
        toml::from_str(s).unwrap()
    }

    #[test]
    fn a_leading_tilde_expands_to_home() {
        let home = std::env::var("HOME").unwrap();
        assert_eq!(
            expand_home("~/.portkit/plugins.toml"),
            std::path::PathBuf::from(&home).join(".portkit/plugins.toml")
        );
    }

    #[test]
    fn a_tilde_elsewhere_is_left_alone() {
        // `a~b` is a filename, not a home reference.
        assert_eq!(
            expand_home("/tmp/a~b"),
            std::path::PathBuf::from("/tmp/a~b")
        );
    }

    #[test]
    fn an_empty_manifest_is_valid() {
        assert!(parse("").plugins.is_empty());
    }

    #[test]
    fn a_minimal_entry_gets_a_timeout() {
        // A plugin without a timeout would hang the agent waiting on it.
        let m = parse("[[plugin]]\ncommand = \"mytool\"\n");
        assert_eq!(m.plugins[0].timeout_secs, 30);
        assert_eq!(m.plugins[0].label(), "mytool");
    }

    #[test]
    fn a_named_entry_reports_its_override() {
        let m = parse("[[plugin]]\ncommand = \"node\"\nargs = [\"t.js\"]\nname = \"browse\"\n");
        assert_eq!(m.plugins[0].label(), "browse");
        assert_eq!(m.plugins[0].args, ["t.js"]);
    }
}
