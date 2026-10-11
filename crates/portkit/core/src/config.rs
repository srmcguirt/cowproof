//! Layered configuration: embedded defaults, then a file, then environment.
//!
//! Later layers win. The environment layer is prefixed `PK_` and uses `__`
//! to descend, so `PK_PARITY__EPSILON=1e-6` sets `parity.epsilon`.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::diff::DiffOptions;
use crate::error::{Error, Result};

/// The defaults compiled into the binary, so it runs with no config file.
pub const DEFAULT_CONFIG: &str = include_str!("../resources/default_config.toml");

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub log: LogConfig,
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub parity: ParityConfig,
    #[serde(default)]
    pub output: OutputConfig,
    #[serde(default)]
    pub trace: TraceConfig,
    #[serde(default)]
    pub schema: SchemaConfig,
    #[serde(default)]
    pub plugins: PluginConfig,
    #[serde(default)]
    pub index: IndexConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexConfig {
    /// Register `sym` and `outline` over this root. Empty disables them.
    pub root: String,
}

impl Default for IndexConfig {
    fn default() -> Self {
        Self { root: ".".into() }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginConfig {
    /// Tools available in every repo. `~/` expands to the home directory.
    pub global: String,
    /// Tools belonging to this repo. Loaded after `global`, so a repo can
    /// override an inherited tool without editing anyone else's manifest.
    pub project: String,
}

impl Default for PluginConfig {
    fn default() -> Self {
        Self {
            global: "~/.portkit/plugins.toml".into(),
            project: ".portkit/plugins.toml".into(),
        }
    }
}

impl PluginConfig {
    /// Manifests in precedence order, least specific first.
    ///
    /// Declared, never discovered: scanning a directory and executing what it
    /// finds turns a dropped file into code execution.
    pub fn layers(&self) -> Vec<String> {
        vec![self.global.clone(), self.project.clone()]
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SchemaConfig {
    /// Committed snapshot files to load at startup. Each is registered under
    /// the source name in its own provenance, so tools name sources
    /// explicitly rather than guessing.
    ///
    /// Loaded before `tools/list` is answered: an agent's first view of the
    /// interface should already be grounded in real facts.
    #[serde(default)]
    pub snapshots: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceConfig {
    /// Record what each tool call cost in context. Off by default: writing a
    /// file per call is a side effect nobody asked for.
    pub enabled: bool,
    /// Directory for daily JSONL files, relative to the working directory, or
    /// to `PORTKIT_STATE_DIR` when that is set (see `resolve_dir`).
    pub dir: String,
}

impl Default for TraceConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            dir: ".portkit/traces".into(),
        }
    }
}

/// The shipped `[trace] dir`. Under `PORTKIT_STATE_DIR` it means `<state>/traces`.
const DEFAULT_TRACE_DIR: &str = ".portkit/traces";

/// Longest `PORTKIT_SESSION` kept in a trace file name, matching the hook's
/// own session-id truncation.
const MAX_SESSION_CHARS: usize = 48;

impl TraceConfig {
    /// Where trace files go, honouring `PORTKIT_STATE_DIR`.
    ///
    /// See [`TraceConfig::resolve_dir_in`] for the rules.
    pub fn resolve_dir(&self) -> PathBuf {
        let state = std::env::var_os("PORTKIT_STATE_DIR").filter(|v| !v.is_empty());
        self.resolve_dir_in(state.as_deref().map(Path::new))
    }

    /// Resolve the trace directory against an optional state dir.
    ///
    /// - An absolute `dir` is used as it is.
    /// - With a state dir, the shipped default (`.portkit/traces`) becomes
    ///   `<state>/traces`, and any other relative `dir` resolves against the
    ///   state dir, never the working directory. A lane's working directory is
    ///   the builder's clone, so a cwd-relative trace dir would land in its
    ///   patch.
    /// - Without a state dir, a relative `dir` stays relative to the working
    ///   directory, as before.
    pub fn resolve_dir_in(&self, state_dir: Option<&Path>) -> PathBuf {
        let dir = Path::new(&self.dir);
        if dir.is_absolute() {
            return dir.to_path_buf();
        }
        match state_dir {
            Some(state) if self.dir == DEFAULT_TRACE_DIR => state.join("traces"),
            Some(state) => state.join(dir),
            None => dir.to_path_buf(),
        }
    }

    /// Daily trace file name, with `PORTKIT_SESSION` in it when set.
    ///
    /// See [`TraceConfig::trace_filename_for`].
    pub fn trace_filename(date: &str) -> String {
        let session = std::env::var("PORTKIT_SESSION").ok();
        Self::trace_filename_for(date, session.as_deref())
    }

    /// `<date>.jsonl`, or `<date>-<session>.jsonl` when a session is given.
    ///
    /// Two lanes that share a state dir on the same day then write different
    /// files. The session is reduced to letters, digits, `-` and `_` and cut
    /// at 48 characters, so it can never name another directory.
    pub fn trace_filename_for(date: &str, session: Option<&str>) -> String {
        let safe: String = session
            .unwrap_or_default()
            .chars()
            .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
            .take(MAX_SESSION_CHARS)
            .collect();
        if safe.is_empty() {
            format!("{date}.jsonl")
        } else {
            format!("{date}-{safe}.jsonl")
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputConfig {
    /// Default cap on tool output, in bytes of serialized JSON. Roughly four
    /// bytes per token. A tool may declare a tighter budget of its own.
    pub max_bytes: usize,
    /// Smallest array left after trimming; keeps the shape of an answer even
    /// when most of it is dropped.
    pub min_items: usize,
}

impl Default for OutputConfig {
    fn default() -> Self {
        let d = crate::budget::Budget::default();
        Self {
            max_bytes: d.max_bytes,
            min_items: d.min_items,
        }
    }
}

impl From<&OutputConfig> for crate::budget::Budget {
    fn from(c: &OutputConfig) -> Self {
        crate::budget::Budget {
            max_bytes: c.max_bytes,
            min_items: c.min_items,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogConfig {
    /// A `tracing-subscriber` env-filter directive, e.g. `info` or `pk=debug`.
    pub level: String,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: "info".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Server name advertised to MCP clients during `initialize`.
    pub name: String,
    /// Instructions shown to the model alongside the tool list. Use it to say
    /// what this server is for; models read it before choosing a tool.
    #[serde(default)]
    pub instructions: Option<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            name: "portkit".into(),
            instructions: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParityConfig {
    /// Absolute float tolerance when comparing against reference fixtures.
    pub epsilon: f64,
    /// Relative float tolerance.
    pub epsilon_rel: f64,
    /// JSON Pointer prefixes excluded from comparison.
    #[serde(default)]
    pub ignore_paths: Vec<String>,
    /// Compare arrays as multisets rather than sequences.
    #[serde(default)]
    pub unordered_arrays: bool,
}

impl Default for ParityConfig {
    fn default() -> Self {
        Self {
            epsilon: 1e-9,
            epsilon_rel: 1e-9,
            ignore_paths: Vec::new(),
            unordered_arrays: false,
        }
    }
}

impl From<&ParityConfig> for DiffOptions {
    fn from(c: &ParityConfig) -> Self {
        DiffOptions {
            epsilon: c.epsilon,
            epsilon_rel: c.epsilon_rel,
            ignore_paths: c.ignore_paths.clone(),
            unordered_arrays: c.unordered_arrays,
        }
    }
}

impl Config {
    /// Build the effective config from defaults, an optional file, and `PK_*`.
    ///
    /// A missing file is not an error — the point of embedded defaults is that
    /// the binary works before anyone writes a config.
    pub fn load(path: Option<&std::path::Path>) -> Result<Self> {
        let mut builder = config::Config::builder().add_source(config::File::from_str(
            DEFAULT_CONFIG,
            config::FileFormat::Toml,
        ));

        if let Some(path) = path {
            builder = builder.add_source(
                config::File::from(path)
                    .required(true)
                    .format(config::FileFormat::Toml),
            );
        }

        let built = builder
            .add_source(
                config::Environment::with_prefix("PK")
                    // Without this, config-rs reuses `separator` to strip the
                    // prefix too, and would demand `PK__PARITY__EPSILON`.
                    .prefix_separator("_")
                    .separator("__")
                    // Env values arrive as strings; parse them so numeric and
                    // boolean fields deserialize instead of failing.
                    .try_parsing(true),
            )
            .build()?;

        built.try_deserialize().map_err(|err| {
            // `PK_LOG=debug` reads naturally but sets the whole `[log]` table
            // to a string. The raw serde error does not say so; this does.
            let message = err.to_string();
            if message.contains("expected struct") {
                Error::Config(format!(
                    "{message}\n\nHint: `PK_<SECTION>` names the whole table. \
                     To set one field use the `__` separator, e.g. \
                     PK_LOG__LEVEL=debug. For log verbosity prefer RUST_LOG."
                ))
            } else {
                Error::Config(message)
            }
        })
    }

    pub fn diff_options(&self) -> DiffOptions {
        DiffOptions::from(&self.parity)
    }

    pub fn budget(&self) -> crate::budget::Budget {
        crate::budget::Budget::from(&self.output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_defaults_parse_and_match_the_rust_defaults() {
        // Guards against resources/default_config.toml drifting away from the
        // `Default` impls, which would make `pk config` a liar.
        let cfg = Config::load(None).expect("embedded defaults must parse");
        assert_eq!(cfg.log.level, LogConfig::default().level);
        assert_eq!(cfg.server.name, ServerConfig::default().name);
        assert_eq!(cfg.parity.epsilon, ParityConfig::default().epsilon);
    }

    #[test]
    fn diff_options_are_derived_from_parity_config() {
        let mut cfg = Config::default();
        cfg.parity.epsilon = 1e-3;
        cfg.parity.ignore_paths = vec!["/meta".into()];
        let opts = cfg.diff_options();
        assert_eq!(opts.epsilon, 1e-3);
        assert_eq!(opts.ignore_paths, vec!["/meta".to_string()]);
    }

    #[test]
    fn trace_filename_includes_the_session() {
        assert_eq!(
            TraceConfig::trace_filename_for("2026-10-11", Some("lane-a")),
            "2026-10-11-lane-a.jsonl"
        );
    }

    #[test]
    fn trace_filename_without_a_session_is_the_plain_date() {
        assert_eq!(
            TraceConfig::trace_filename_for("2026-10-11", None),
            "2026-10-11.jsonl"
        );
        assert_eq!(
            TraceConfig::trace_filename_for("2026-10-11", Some("")),
            "2026-10-11.jsonl"
        );
        assert_eq!(
            TraceConfig::trace_filename_for("2026-10-11", Some("@#$/")),
            "2026-10-11.jsonl"
        );
    }

    #[test]
    fn trace_filename_cannot_escape_the_directory() {
        assert_eq!(
            TraceConfig::trace_filename_for("2026-10-11", Some("../x/lane_1@#")),
            "2026-10-11-xlane_1.jsonl"
        );
        let long = "a".repeat(200);
        let name = TraceConfig::trace_filename_for("2026-10-11", Some(&long));
        assert_eq!(name.len(), "2026-10-11-.jsonl".len() + 48);
    }

    #[test]
    fn default_dir_becomes_traces_under_the_state_dir() {
        let config = TraceConfig::default();
        assert_eq!(
            config.resolve_dir_in(Some(Path::new("/var/tmp/state"))),
            Path::new("/var/tmp/state/traces")
        );
    }

    #[test]
    fn a_relative_dir_resolves_against_the_state_dir_not_the_cwd() {
        let config = TraceConfig {
            enabled: true,
            dir: "my/traces".into(),
        };
        assert_eq!(
            config.resolve_dir_in(Some(Path::new("/var/tmp/state"))),
            Path::new("/var/tmp/state/my/traces")
        );
    }

    #[test]
    fn an_absolute_dir_ignores_the_state_dir() {
        let config = TraceConfig {
            enabled: true,
            dir: "/var/tmp/elsewhere".into(),
        };
        assert_eq!(
            config.resolve_dir_in(Some(Path::new("/var/tmp/state"))),
            Path::new("/var/tmp/elsewhere")
        );
    }

    #[test]
    fn without_a_state_dir_a_relative_dir_stays_cwd_relative() {
        let config = TraceConfig::default();
        assert_eq!(config.resolve_dir_in(None), Path::new(".portkit/traces"));
        let custom = TraceConfig {
            enabled: true,
            dir: "x/y".into(),
        };
        assert_eq!(custom.resolve_dir_in(None), Path::new("x/y"));
    }
}
