//! The Codex adapter (D28, step 3): the `codex` runtime with an API key.
//!
//! Codex CLI drives an OpenAI model through its Responses API. This module is the pure half of
//! the adapter, in two parts:
//!
//! * **Launch.** [`codex_command`] builds the invocation (argv, environment, working
//!   directory, stdin file) and [`write_lane_files`] writes the one file it reads from the lane
//!   home, `.codex/config.toml`. Nothing here spawns a process. The real OpenAI key is not a
//!   field of any type in this module: the builder is given the lane's placeholder and a
//!   `base_url` that points at the in-sandbox bridge, and the proxy swaps the credential (see
//!   `proxy.rs`).
//! * **Events.** [`parse_event`] reads one line of `codex exec --json`. The schema is not
//!   documented upstream; it was recorded from the real 0.157.0 binary against a fake server
//!   (`tests/fixtures/codex/`). The events are `thread.started` (its `thread_id` is the id a
//!   resume passes), `turn.started`, `item.started` / `item.updated` / `item.completed` (items
//!   of type `agent_message`, `reasoning`, `command_execution`, `file_change`,
//!   `mcp_tool_call`, `web_search`, `todo_list` and `error`), `turn.completed` (the token usage),
//!   `turn.failed` and `error`.
//!
//! What the launch does, and why:
//!
//! * **Codex's own sandbox is off** (`--dangerously-bypass-approvals-and-sandbox`, the flag
//!   `codex exec --help` documents "solely for running in environments that are externally
//!   sandboxed"). cowproof's OS sandbox is the boundary. Codex's own would be a second
//!   Seatbelt or Landlock layer inside the first: on macOS a sandbox cannot be applied inside a
//!   sandbox, and on Linux it needs privileges the lane does not have. It also puts the approval
//!   policy at `never`, which a non-interactive lane needs.
//! * **The provider** is a custom one (`cowproof`) with `wire_api = "responses"`, `base_url` at
//!   the bridge plus `/v1` and `env_key` naming the variable that holds the placeholder.
//!   Codex's built-in `openai` provider is not used, so no ChatGPT login, no `auth.json` and no
//!   ChatGPT backend are involved (D28 clause 6: an API-key lane keeps the key in the proxy).
//! * **Every network habit is off** (see [`pinned_config`]): update check, analytics, feedback,
//!   the plugin marketplace and connector sync, web search, unbounded connection retries.
//!   Measured against the real binary under a deny-all-but-loopback sandbox with an HTTPS proxy
//!   logging every attempt: with the defaults it reaches `chatgpt.com`, `ab.chatgpt.com`,
//!   `github.com` and `api.github.com` at startup; with these settings it reaches nothing.
//! * **The clone's own `.codex/config.toml` cannot redirect the model.** It is read, and Codex
//!   (0.157.0) ignores a project file's `model_provider` and provider tables, but it still
//!   starts the MCP servers such a file names. The redirect-critical keys are therefore also
//!   given as `-c` flags, which sit above every file, and `--strict-config` makes a Codex that
//!   no longer knows one of our keys fail instead of running without the switch. The MCP-server
//!   gap has no switch in 0.157.0; it runs inside the same OS sandbox as the builder's shell,
//!   which can already run anything.

use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};
use toml::Table;

use crate::LaneLayout;

/// The provider id in the lane's Codex config.
pub const PROVIDER: &str = "cowproof";
/// What the bridge's address is extended with: OpenAI's API prefix.
pub const API_PREFIX: &str = "/v1";
/// The name of the MCP server that carries `ask`, `check_ruling` and `run_check`. Codex reports
/// a call as `{server: "cowproof-tools", tool: "run_check"}`.
pub const MCP_SERVER: &str = "cowproof-tools";
/// The environment variable that holds the lane's placeholder credential. Codex itself reads it;
/// the commands Codex runs do not get it (`shell_environment_policy.exclude`).
pub const KEY_VAR: &str = "OPENAI_API_KEY";
/// How long Codex waits for the MCP server to start, and for one MCP call (a `run_check` can
/// run a long test suite), in seconds. Codex's defaults are 10 and 60.
const MCP_STARTUP_SECS: i64 = 60;
const MCP_TOOL_SECS: i64 = 3600;

/// The shape of a Codex thread id, which `codex exec resume` takes: a UUID.
pub fn valid_session_id(id: &str) -> bool {
    let groups: Vec<&str> = id.split('-').collect();
    groups.len() == 5
        && groups
            .iter()
            .zip([8, 4, 4, 4, 12])
            .all(|(g, n)| g.len() == n && g.chars().all(|c| c.is_ascii_hexdigit()))
}

/// What a model costs, in USD per million tokens, and where the figure came from. There is no
/// built-in table and no default: the director states it for the exact model id.
#[derive(Debug, Clone, PartialEq)]
pub struct CodexPrice {
    /// Plain (uncached) input tokens.
    pub input: f64,
    /// Cached input tokens (a part of the call's input).
    pub cached_input: f64,
    /// Output tokens, reasoning included.
    pub output: f64,
    /// Where the director got the figures (a URL and a date, say). Required, recorded.
    pub source: String,
}

impl CodexPrice {
    /// The record as `run.json` and the capsule hold it.
    pub fn to_json(&self) -> Value {
        json!({
            "inputPerMillion": self.input,
            "cachedInputPerMillion": self.cached_input,
            "outputPerMillion": self.output,
            "source": self.source,
        })
    }

    /// Estimated cost in USD of `input` plain input tokens, `cached` cached input tokens and
    /// `output` output tokens.
    pub fn cost_usd(&self, input: u64, cached: u64, output: u64) -> f64 {
        (input as f64 * self.input
            + cached as f64 * self.cached_input
            + output as f64 * self.output)
            / 1_000_000.0
    }
}

/// Everything that decides one Codex invocation. It has no field for the real key.
#[derive(Debug, Clone)]
pub struct CodexSpec {
    pub lane: LaneLayout,
    /// The OpenAI model id.
    pub model: String,
    /// The in-sandbox bridge, `http://127.0.0.1:<port>`, without the API prefix.
    pub proxy_base_url: String,
    /// The lane's placeholder credential.
    pub placeholder_key: String,
    /// Codex's home in the lane: `config.toml`, the sessions, its databases.
    pub codex_home: PathBuf,
    /// The prompt, written by the runner and attached to Codex's stdin.
    pub prompt_file: PathBuf,
    pub cowproof_exe: PathBuf,
    /// The builder tools socket the MCP server talks to.
    pub runner_socket: PathBuf,
    /// The thread to continue (`exec resume`), after a ruling.
    pub resume_session_id: Option<String>,
    /// The builder's PATH: absolute entries only, none under the real home.
    pub path: String,
}

/// A validated invocation.
#[derive(Debug)]
pub struct CodexInvocation {
    /// `codex`; the caller replaces it with the resolved executable.
    pub program: String,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    pub cwd: PathBuf,
    /// The file the process reads as stdin (`-` as the prompt): a multi-line prompt arrives
    /// there as is.
    pub stdin_file: PathBuf,
}

fn string(s: &str) -> toml::Value {
    toml::Value::String(s.to_string())
}

fn table(entries: Vec<(&str, toml::Value)>) -> toml::Value {
    toml::Value::Table(
        entries
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect(),
    )
}

/// The settings that must hold whatever a file in the clone says: where the model is, which
/// credential it presents, and every Codex feature that reaches the network or widens the tool
/// list. They are written to the config file AND passed as `-c` flags (which sit above every
/// file Codex reads).
///
/// Each switch, with what it stopped (0.157.0, measured; see the module docs):
///
/// * `check_for_update_on_startup`: the update check. (None seen in `exec`; off in case.)
/// * `analytics.enabled`: the experiments and analytics service, `ab.chatgpt.com`.
/// * `feedback.enabled`: the feedback uploader.
/// * `features.plugins`: the plugin marketplace and connector sync, `chatgpt.com`, `github.com`
///   and `api.github.com`, reached at every start.
/// * `features.apps`, `tool_suggest`, `remote_plugin`, `recommended_plugins`: more of the same
///   family.
/// * `features.unbounded_connection_retries`: with it on, an unreachable API is retried for
///   ever and the lane would hang; off, Codex gives up after its bounded retries and exits 1.
/// * `features.multi_agent`, `goals`, `image_generation`, `view_image`, `browser_use`,
///   `computer_use`, `hooks`: tools and commands the lane does not offer (a hook runs a
///   command; the others add tools the packet never asked for). For a model in Codex's own
///   catalog (the `gpt-6-*` models) a `collaboration` namespace with `spawn_agent` is offered
///   whatever these say; the proxy's model limit is what keeps a sub-agent on the lane's model.
/// * `features.enable_request_compression`: the proxy reads each request body to check its
///   model, so Codex sends plain JSON.
/// * `web_search = "disabled"`: the hosted web-search tool, which OpenAI would run on its side,
///   outside the sandbox.
/// * `allow_login_shell`: the builder's commands run in `zsh -c`, not `zsh -lc`, so no profile
///   file changes what a check sees.
/// * `shell_environment_policy.exclude`: the placeholder's variable is not passed to the
///   commands Codex runs.
/// * `skills.bundled` and `skills.include_instructions`: Codex's bundled skills are copied into
///   its home and described in every request; the lane gets its instructions from cowproof.
pub fn pinned_config(spec: &CodexSpec) -> Table {
    let bridge = format!("{}{API_PREFIX}", spec.proxy_base_url.trim_end_matches('/'));
    let mut root = Table::new();
    root.insert("model".into(), string(&spec.model));
    root.insert("model_provider".into(), string(PROVIDER));
    root.insert("check_for_update_on_startup".into(), false.into());
    root.insert("allow_login_shell".into(), false.into());
    root.insert("web_search".into(), string("disabled"));
    // Anything that still asks for the OpenAI or ChatGPT hosts asks the bridge instead, where
    // the proxy refuses it (and run.json records the refusal).
    root.insert("openai_base_url".into(), string(&bridge));
    root.insert(
        "chatgpt_base_url".into(),
        string(&format!(
            "{}/backend-api/",
            spec.proxy_base_url.trim_end_matches('/')
        )),
    );
    root.insert(
        "model_providers".into(),
        table(vec![(
            PROVIDER,
            table(vec![
                ("name", string(PROVIDER)),
                ("base_url", string(&bridge)),
                ("env_key", string(KEY_VAR)),
                ("wire_api", string("responses")),
                ("requires_openai_auth", false.into()),
                ("supports_websockets", false.into()),
            ]),
        )]),
    );
    // Codex's default policy does NOT leave a `*_API_KEY` variable out of the commands it runs
    // (measured), so the placeholder is excluded by name: the builder's commands and the code
    // they run have no business calling the proxy.
    root.insert(
        "shell_environment_policy".into(),
        table(vec![("exclude", toml::Value::Array(vec![string(KEY_VAR)]))]),
    );
    root.insert("analytics".into(), table(vec![("enabled", false.into())]));
    root.insert("feedback".into(), table(vec![("enabled", false.into())]));
    root.insert(
        "skills".into(),
        table(vec![
            ("include_instructions", false.into()),
            ("bundled", table(vec![("enabled", false.into())])),
        ]),
    );
    let features: Table = [
        "plugins",
        "apps",
        "tool_suggest",
        "remote_plugin",
        "recommended_plugins",
        "unbounded_connection_retries",
        "multi_agent",
        "goals",
        "image_generation",
        "view_image",
        "browser_use",
        "computer_use",
        "hooks",
        "enable_request_compression",
    ]
    .into_iter()
    .map(|name| (name.to_string(), toml::Value::Boolean(false)))
    .collect();
    root.insert("features".into(), toml::Value::Table(features));
    root
}

/// The whole config file for one launch: the pinned settings, the cowproof MCP server and the
/// builder's instructions.
pub fn config_table(spec: &CodexSpec, system_append: &str) -> Table {
    let mut root = pinned_config(spec);
    root.insert(
        "developer_instructions".into(),
        string(&format!("{system_append}{NOTES}")),
    );
    root.insert(
        "mcp_servers".into(),
        table(vec![(
            MCP_SERVER,
            table(vec![
                ("command", string(&spec.cowproof_exe.to_string_lossy())),
                (
                    "args",
                    toml::Value::Array(vec![
                        string("lane-tools"),
                        string("--socket"),
                        string(&spec.runner_socket.to_string_lossy()),
                    ]),
                ),
                ("startup_timeout_sec", MCP_STARTUP_SECS.into()),
                ("tool_timeout_sec", MCP_TOOL_SECS.into()),
            ]),
        )]),
    );
    root
}

/// What the builder is told that Codex's own prompt contradicts or leaves out.
const NOTES: &str = "\n\n## This runtime\n\nThe tools named `ask`, `check_ruling` and `run_check` above are the MCP tools of the `cowproof-tools` server; call them by those names. A model that works through the `exec` tool (code mode) finds them on the `tools` object as `tools.mcp__cowproof_tools__ask`, `tools.mcp__cowproof_tools__check_ruling` and `tools.mcp__cowproof_tools__run_check`. There is no network in this lane except the model API: shell commands that reach a host will fail, whatever the permission notes above say. Do not start sub-agents or use the `collaboration` tools: this lane has one agent, and a request for any other model is refused. Edit files with shell commands or `apply_patch`.\n";

/// Flatten `table` to the `key=value` strings `-c` takes: dotted paths to every leaf (a table
/// is never given whole, so a `-c` never replaces a table of the user's file, it sets a key).
fn flatten(prefix: &str, table: &Table, out: &mut Vec<String>) {
    for (key, value) in table {
        let path = if prefix.is_empty() {
            key.clone()
        } else {
            format!("{prefix}.{key}")
        };
        match value {
            toml::Value::Table(inner) => flatten(&path, inner, out),
            leaf => out.push(format!("{path}={leaf}")),
        }
    }
}

/// The `-c key=value` flags for the pinned settings.
pub fn pinned_flags(spec: &CodexSpec) -> Vec<String> {
    let mut leaves = Vec::new();
    flatten("", &pinned_config(spec), &mut leaves);
    leaves
        .into_iter()
        .flat_map(|leaf| ["-c".to_string(), leaf])
        .collect()
}

/// Write the files a Codex launch reads from the lane: the config and the prompt. The lane home
/// is writable by the builder, so a launch calls this before EVERY start (a resume must never
/// trust what the previous session left there).
pub fn write_lane_files(spec: &CodexSpec, system_append: &str, prompt: &str) -> Result<()> {
    fs::create_dir_all(&spec.codex_home)
        .with_context(|| format!("creating {}", spec.codex_home.display()))?;
    let config_file = spec.codex_home.join("config.toml");
    fs::write(
        &config_file,
        toml::to_string_pretty(&config_table(spec, system_append))?,
    )
    .with_context(|| format!("writing {}", config_file.display()))?;
    fs::write(&spec.prompt_file, prompt)
        .with_context(|| format!("writing {}", spec.prompt_file.display()))?;
    Ok(())
}

/// Build the invocation. Validates the model name, the session id and every path; the
/// environment is complete and explicit.
pub fn codex_command(spec: &CodexSpec) -> Result<CodexInvocation> {
    if !cowproof_core::valid_model_name(&spec.model) {
        bail!("{:?} is not an OpenAI model name", spec.model);
    }
    if let Some(id) = &spec.resume_session_id
        && !valid_session_id(id)
    {
        bail!("resume_session_id does not look like a Codex thread id: {id}");
    }
    for (what, path) in [
        ("codex_home", &spec.codex_home),
        ("prompt_file", &spec.prompt_file),
        ("cowproof_exe", &spec.cowproof_exe),
        ("runner_socket", &spec.runner_socket),
    ] {
        if !path.is_absolute() {
            bail!("{what} is not absolute: {}", path.display());
        }
    }
    if spec.path.is_empty() {
        bail!("path is empty");
    }
    for entry in spec.path.split(':') {
        if entry.is_empty() {
            bail!("path has an empty entry (it would search the current directory)");
        }
        let entry_path = Path::new(entry);
        if !entry_path.is_absolute() {
            bail!("path entry is not absolute: {entry}");
        }
        if entry_path.starts_with(&spec.lane.real_home) {
            bail!(
                "path entry is under real home ({}): {entry}",
                spec.lane.real_home.display()
            );
        }
    }

    let mut args = vec!["exec".to_string()];
    if let Some(id) = &spec.resume_session_id {
        args.push("resume".to_string());
        // Options of `resume` itself: it takes no `-C`; the working directory is the
        // process's, which is the clone.
        args.extend(
            [
                "--json",
                "--strict-config",
                "--skip-git-repo-check",
                "--ignore-rules",
                "--dangerously-bypass-approvals-and-sandbox",
            ]
            .map(String::from),
        );
        args.extend(pinned_flags(spec));
        args.push(id.clone());
        args.push("-".to_string());
    } else {
        args.extend(
            [
                "--json",
                "--strict-config",
                "--skip-git-repo-check",
                "--ignore-rules",
                "--dangerously-bypass-approvals-and-sandbox",
                "-C",
            ]
            .map(String::from),
        );
        args.push(spec.lane.clone.to_string_lossy().into_owned());
        args.extend(pinned_flags(spec));
        args.push("-".to_string());
    }

    let home = &spec.lane.home;
    let s = |p: &Path| p.to_string_lossy().into_owned();
    let env = vec![
        ("HOME".to_string(), s(home)),
        ("CODEX_HOME".to_string(), s(&spec.codex_home)),
        ("XDG_CONFIG_HOME".to_string(), s(&home.join(".config"))),
        ("XDG_DATA_HOME".to_string(), s(&home.join(".local/share"))),
        ("XDG_STATE_HOME".to_string(), s(&home.join(".local/state"))),
        ("XDG_CACHE_HOME".to_string(), s(&home.join(".cache"))),
        (KEY_VAR.to_string(), spec.placeholder_key.clone()),
        ("PATH".to_string(), spec.path.clone()),
        ("CARGO_HOME".to_string(), s(&home.join(".cargo"))),
    ];

    Ok(CodexInvocation {
        program: "codex".to_string(),
        args,
        env,
        cwd: spec.lane.clone.clone(),
        stdin_file: spec.prompt_file.clone(),
    })
}

/// The tool names the meter and the escalate-early observer know are Claude Code's. Codex's
/// items are typed, not named, so the names are fixed here: a command is `Bash`, a patch is
/// `Edit`, an MCP call is `mcp__<server>__<tool>`.
pub fn mcp_tool_name(server: &str, tool: &str) -> String {
    format!("mcp__{server}__{tool}")
}

/// The usage `turn.completed` carries. It is the thread's total since the thread began, not the
/// turn's: a resumed thread reports the earlier launches' tokens again. `input` includes
/// `cached`, `output` includes `reasoning`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ThreadUsage {
    pub input: u64,
    pub cached_input: u64,
    pub output: u64,
    pub reasoning_output: u64,
}

/// One item of a Codex turn, reduced to what the meter needs.
#[derive(Debug, Clone, PartialEq)]
pub enum Item {
    /// The model's text.
    AgentMessage {
        len: u64,
    },
    Reasoning,
    /// A shell command (`command_execution`).
    Command {
        id: String,
        command: String,
        output_bytes: u64,
        /// The command failed: a non-zero exit, or a status of `failed` or `declined`.
        is_error: bool,
    },
    /// A patch (`file_change`).
    FileChange {
        id: String,
        input_bytes: u64,
        is_error: bool,
    },
    /// A call to an MCP tool.
    Mcp {
        id: String,
        server: String,
        tool: String,
        input_bytes: u64,
        output_bytes: u64,
        is_error: bool,
    },
    /// The hosted web-search tool. Switched off, so seeing one is worth recording.
    WebSearch {
        id: String,
    },
    /// A warning Codex put in the stream as an `error` item (a model it has no metadata for).
    Warning {
        message: String,
    },
    Other,
}

/// When an item event happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Started,
    Updated,
    Completed,
}

/// One line of `codex exec --json`, reduced to what the meter needs.
#[derive(Debug, Clone, PartialEq)]
pub enum Event {
    /// A thread began (or was resumed): its id.
    Thread {
        id: String,
    },
    TurnStarted,
    Item {
        phase: Phase,
        item: Item,
    },
    /// The turn ended well: the thread's usage so far.
    TurnCompleted {
        usage: ThreadUsage,
    },
    /// The turn ended in an error (the last event before a non-zero exit).
    TurnFailed {
        message: String,
    },
    /// An `error` event: a retry notice (`retry`) or the error that ends the turn.
    Error {
        message: String,
        retry: bool,
    },
    /// Any other event (counted, not read).
    Other,
}

fn u64_at(v: &Value, key: &str) -> u64 {
    v.get(key).and_then(Value::as_u64).unwrap_or(0)
}

fn text_bytes(v: Option<&Value>) -> u64 {
    match v {
        None | Some(Value::Null) => 0,
        Some(Value::String(s)) => s.len() as u64,
        Some(other) => serde_json::to_string(other).unwrap_or_default().len() as u64,
    }
}

fn parse_item(item: &Value) -> Item {
    let id = item
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let status = item.get("status").and_then(Value::as_str).unwrap_or("");
    let failed_status = matches!(status, "failed" | "declined");
    match item.get("type").and_then(Value::as_str) {
        Some("agent_message") => Item::AgentMessage {
            len: text_bytes(item.get("text")),
        },
        Some("reasoning") => Item::Reasoning,
        Some("command_execution") => {
            let exit_failed = item
                .get("exit_code")
                .and_then(Value::as_i64)
                .is_some_and(|code| code != 0);
            Item::Command {
                id,
                command: item
                    .get("command")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                output_bytes: text_bytes(item.get("aggregated_output")),
                is_error: failed_status || exit_failed,
            }
        }
        Some("file_change") => Item::FileChange {
            id,
            input_bytes: text_bytes(item.get("changes")),
            is_error: failed_status,
        },
        Some("mcp_tool_call") => {
            let error = item.get("error").filter(|e| !e.is_null());
            let result = item.get("result").filter(|r| !r.is_null());
            let result_failed = result
                .and_then(|r| r.get("is_error"))
                .and_then(Value::as_bool)
                .unwrap_or(false);
            Item::Mcp {
                id,
                server: item
                    .get("server")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                tool: item
                    .get("tool")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                input_bytes: text_bytes(item.get("arguments")),
                output_bytes: text_bytes(result.or(error)),
                is_error: failed_status || error.is_some() || result_failed,
            }
        }
        Some("web_search") => Item::WebSearch { id },
        Some("error") => Item::Warning {
            message: item
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
        },
        _ => Item::Other,
    }
}

/// Read one event. A line that is not an event object of a known type is [`Event::Other`].
pub fn parse_event(json: &Value) -> Event {
    match json.get("type").and_then(Value::as_str) {
        Some("thread.started") => match json.get("thread_id").and_then(Value::as_str) {
            Some(id) => Event::Thread { id: id.to_string() },
            None => Event::Other,
        },
        Some("turn.started") => Event::TurnStarted,
        Some(kind @ ("item.started" | "item.updated" | "item.completed")) => {
            let Some(item) = json.get("item") else {
                return Event::Other;
            };
            let phase = match kind {
                "item.started" => Phase::Started,
                "item.updated" => Phase::Updated,
                _ => Phase::Completed,
            };
            Event::Item {
                phase,
                item: parse_item(item),
            }
        }
        Some("turn.completed") => {
            let usage = json.get("usage").unwrap_or(&Value::Null);
            Event::TurnCompleted {
                usage: ThreadUsage {
                    input: u64_at(usage, "input_tokens"),
                    cached_input: u64_at(usage, "cached_input_tokens"),
                    output: u64_at(usage, "output_tokens"),
                    reasoning_output: u64_at(usage, "reasoning_output_tokens"),
                },
            }
        }
        Some("turn.failed") => Event::TurnFailed {
            message: json
                .get("error")
                .and_then(|e| e.get("message"))
                .and_then(Value::as_str)
                .unwrap_or("the turn failed")
                .to_string(),
        },
        Some("error") => {
            let message = json
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            Event::Error {
                retry: message.starts_with("Reconnecting..."),
                message,
            }
        }
        _ => Event::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RUN: &str = include_str!("../tests/fixtures/codex/session-run.jsonl");
    const RESUME: &str = include_str!("../tests/fixtures/codex/session-resume.jsonl");
    const ERROR_401: &str = include_str!("../tests/fixtures/codex/error-401.jsonl");
    const CODE_MODE: &str = include_str!("../tests/fixtures/codex/code-mode.jsonl");

    fn events(text: &str) -> Vec<Event> {
        text.lines()
            .filter(|l| !l.is_empty())
            .map(|l| parse_event(&serde_json::from_str(l).unwrap()))
            .collect()
    }

    fn lane() -> LaneLayout {
        LaneLayout {
            clone: PathBuf::from("/nonexistent-cp/lanes/l1/clone"),
            home: PathBuf::from("/nonexistent-cp/lanes/l1/home"),
            scratch: PathBuf::from("/nonexistent-cp/lanes/l1/scratch"),
            control: PathBuf::from("/nonexistent-cp/lanes/l1/control"),
            real_home: PathBuf::from("/nonexistent-cp/realhome"),
            sock: PathBuf::from("/nonexistent-cp/lanes/l1/sock/runner.sock"),
            lanes_root: PathBuf::from("/nonexistent-cp/lanes"),
        }
    }

    fn spec() -> CodexSpec {
        CodexSpec {
            lane: lane(),
            model: "gpt-6-luna".to_string(),
            proxy_base_url: "http://127.0.0.1:41000".to_string(),
            placeholder_key: "placeholder-abc".to_string(),
            codex_home: PathBuf::from("/nonexistent-cp/lanes/l1/home/.codex"),
            prompt_file: PathBuf::from("/nonexistent-cp/lanes/l1/home/prompt.md"),
            cowproof_exe: PathBuf::from("/nonexistent-cp/bin/cowproof"),
            runner_socket: PathBuf::from("/nonexistent-cp/lanes/l1/sock/runner.sock"),
            resume_session_id: None,
            path: "/usr/bin:/bin".to_string(),
        }
    }

    fn env_of(inv: &CodexInvocation, key: &str) -> String {
        inv.env
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| panic!("{key} is not set"))
    }

    fn price() -> CodexPrice {
        CodexPrice {
            input: 1.25,
            cached_input: 0.125,
            output: 10.0,
            source: "test".to_string(),
        }
    }

    #[test]
    fn a_fresh_launch_is_exec_json_in_the_clone_with_codexs_own_sandbox_off() {
        let inv = codex_command(&spec()).unwrap();
        assert_eq!(
            &inv.args[..8],
            [
                "exec",
                "--json",
                "--strict-config",
                "--skip-git-repo-check",
                "--ignore-rules",
                "--dangerously-bypass-approvals-and-sandbox",
                "-C",
                "/nonexistent-cp/lanes/l1/clone"
            ]
        );
        // The prompt is read from stdin: `-` is the last argument.
        assert_eq!(inv.args.last().unwrap(), "-");
        assert_eq!(inv.stdin_file, spec().prompt_file);
        assert_eq!(inv.cwd, spec().lane.clone);
        // The model is named in the pinned config, not as a flag a clone could outrank.
        assert!(inv.args.iter().any(|a| a == "model=\"gpt-6-luna\""));
        assert!(!inv.args.iter().any(|a| a == "--full-auto" || a == "-s"));
    }

    #[test]
    fn a_resume_names_the_thread_and_takes_the_ruling_on_stdin() {
        let mut s = spec();
        s.resume_session_id = Some("01a12d9c-b587-7d70-b3bc-ec3bd1cb4130".to_string());
        let inv = codex_command(&s).unwrap();
        assert_eq!(&inv.args[..2], ["exec", "resume"]);
        assert_eq!(
            &inv.args[inv.args.len() - 2..],
            ["01a12d9c-b587-7d70-b3bc-ec3bd1cb4130", "-"]
        );
        // `resume` has no `-C`; its sandbox flag is still given.
        assert!(!inv.args.iter().any(|a| a == "-C"));
        assert!(
            inv.args
                .iter()
                .any(|a| a == "--dangerously-bypass-approvals-and-sandbox")
        );
        for bad in [
            "",
            "-s",
            "ses_ed38dc388ffeb9FMHqRuDEw3t7",
            "01a12d9c-b587-7d70-b3bc",
            "01a12d9c-b587-7d70-b3bc-ec3bd1cb413g",
            "01a12d9c-b587-7d70-b3bc-ec3bd1cb4130;rm",
        ] {
            s.resume_session_id = Some(bad.to_string());
            assert!(codex_command(&s).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn the_environment_keeps_every_directory_in_the_lane_home_and_carries_only_the_placeholder() {
        let inv = codex_command(&spec()).unwrap();
        let home = "/nonexistent-cp/lanes/l1/home";
        assert_eq!(env_of(&inv, "HOME"), home);
        assert_eq!(env_of(&inv, "CODEX_HOME"), format!("{home}/.codex"));
        for (key, rel) in [
            ("XDG_CONFIG_HOME", ".config"),
            ("XDG_DATA_HOME", ".local/share"),
            ("XDG_STATE_HOME", ".local/state"),
            ("XDG_CACHE_HOME", ".cache"),
        ] {
            assert_eq!(env_of(&inv, key), format!("{home}/{rel}"));
        }
        assert_eq!(env_of(&inv, KEY_VAR), "placeholder-abc");
        // The only credential variable is the placeholder's.
        for (key, _) in &inv.env {
            assert!(
                !key.contains("KEY") || key == KEY_VAR,
                "unexpected credential variable {key}"
            );
        }
    }

    #[test]
    fn the_pinned_config_points_at_the_bridge_with_the_placeholder_variable_and_no_other_host() {
        let pinned = pinned_config(&spec());
        let provider = &pinned["model_providers"][PROVIDER];
        assert_eq!(
            provider["base_url"].as_str(),
            Some("http://127.0.0.1:41000/v1")
        );
        assert_eq!(provider["env_key"].as_str(), Some("OPENAI_API_KEY"));
        assert_eq!(provider["wire_api"].as_str(), Some("responses"));
        assert_eq!(provider["requires_openai_auth"].as_bool(), Some(false));
        assert_eq!(pinned["model_provider"].as_str(), Some(PROVIDER));
        let text = toml::to_string(&pinned).unwrap();
        // The only host in the pinned config is the bridge.
        for line in text.lines().filter(|l| l.contains("http")) {
            assert!(line.contains("127.0.0.1:41000"), "{line}");
        }
        assert!(!text.contains("openai.com") && !text.contains("chatgpt.com"));
        // No key of any kind is written: only the variable's NAME.
        assert!(!text.contains("placeholder-abc"));
    }

    #[test]
    fn every_network_habit_and_extra_tool_is_switched_off() {
        let pinned = pinned_config(&spec());
        assert_eq!(pinned["check_for_update_on_startup"].as_bool(), Some(false));
        assert_eq!(pinned["analytics"]["enabled"].as_bool(), Some(false));
        assert_eq!(pinned["feedback"]["enabled"].as_bool(), Some(false));
        assert_eq!(pinned["web_search"].as_str(), Some("disabled"));
        assert_eq!(pinned["allow_login_shell"].as_bool(), Some(false));
        assert_eq!(
            pinned["shell_environment_policy"]["exclude"]
                .as_array()
                .unwrap(),
            &vec![toml::Value::from("OPENAI_API_KEY")]
        );
        let features = pinned["features"].as_table().unwrap();
        for name in [
            "plugins",
            "apps",
            "unbounded_connection_retries",
            "multi_agent",
            "hooks",
            "image_generation",
        ] {
            assert_eq!(features[name].as_bool(), Some(false), "{name}");
        }
        assert!(features.values().all(|v| v.as_bool() == Some(false)));
    }

    #[test]
    fn the_pinned_settings_are_also_flags_that_set_keys_and_never_replace_tables() {
        let flags = pinned_flags(&spec());
        let pairs: Vec<&str> = flags
            .chunks(2)
            .map(|c| {
                assert_eq!(c[0], "-c");
                c[1].as_str()
            })
            .collect();
        for expected in [
            "model_provider=\"cowproof\"",
            "model_providers.cowproof.base_url=\"http://127.0.0.1:41000/v1\"",
            "model_providers.cowproof.env_key=\"OPENAI_API_KEY\"",
            "analytics.enabled=false",
            "features.plugins=false",
            "web_search=\"disabled\"",
        ] {
            assert!(pairs.contains(&expected), "{expected} in {pairs:?}");
        }
        // Every flag is `dotted.key=leaf`: no inline table.
        assert!(pairs.iter().all(|p| !p.contains('{')), "{pairs:?}");
        // The flags and the file say the same thing about the pinned keys.
        let file = config_table(&spec(), "x");
        for (key, value) in pinned_config(&spec()) {
            assert_eq!(file[&key], value, "{key}");
        }
    }

    #[test]
    fn the_config_file_names_the_cowproof_tools_server_and_carries_the_instructions() {
        let file = config_table(&spec(), "PREAMBLE \"quoted\"\nline two");
        let server = &file["mcp_servers"][MCP_SERVER];
        assert_eq!(
            server["command"].as_str(),
            Some("/nonexistent-cp/bin/cowproof")
        );
        assert_eq!(
            server["args"].as_array().unwrap(),
            &vec![
                toml::Value::from("lane-tools"),
                toml::Value::from("--socket"),
                toml::Value::from("/nonexistent-cp/lanes/l1/sock/runner.sock"),
            ]
        );
        assert_eq!(server["tool_timeout_sec"].as_integer(), Some(3600));
        let instructions = file["developer_instructions"].as_str().unwrap();
        assert!(instructions.starts_with("PREAMBLE \"quoted\"\nline two"));
        assert!(instructions.contains("`cowproof-tools` server"));
        // And the file reads back as TOML.
        let text = toml::to_string_pretty(&file).unwrap();
        assert_eq!(text.parse::<Table>().unwrap(), file);
    }

    #[test]
    fn bad_inputs_are_refused() {
        let mut s = spec();
        s.model = "--auto".to_string();
        assert!(codex_command(&s).is_err());
        let mut s = spec();
        s.prompt_file = PathBuf::from("relative.md");
        assert!(codex_command(&s).is_err());
        let mut s = spec();
        s.path = "/usr/bin::/bin".to_string();
        assert!(codex_command(&s).is_err());
        let mut s = spec();
        s.path = "/nonexistent-cp/realhome/bin".to_string();
        assert!(codex_command(&s).is_err());
    }

    #[test]
    fn a_cost_is_priced_from_the_three_token_classes() {
        // 1M plain input + 1M cached + 1M output.
        let cost = price().cost_usd(1_000_000, 1_000_000, 1_000_000);
        assert!((cost - (1.25 + 0.125 + 10.0)).abs() < 1e-9, "{cost}");
        assert_eq!(price().cost_usd(0, 0, 0), 0.0);
    }

    #[test]
    fn session_ids_are_uuids() {
        assert!(valid_session_id("01a12d9c-b587-7d70-b3bc-ec3bd1cb4130"));
        assert!(valid_session_id("0A1B2C3D-1111-2222-3333-444455556666"));
        assert!(!valid_session_id("ses_ed38dc388ffeb9FMHqRuDEw3t7"));
        assert!(!valid_session_id("01a12d9cb5877d70b3bcec3bd1cb4130"));
        assert!(!valid_session_id(""));
    }

    #[test]
    fn mcp_calls_are_named_the_way_claude_reports_them() {
        assert_eq!(
            mcp_tool_name("cowproof-tools", "run_check"),
            "mcp__cowproof-tools__run_check"
        );
    }

    #[test]
    fn the_recorded_run_parses_into_threads_items_and_usage() {
        let events = events(RUN);
        assert_eq!(events.len(), 17);
        assert_eq!(
            events[0],
            Event::Thread {
                id: "01a12d9c-b587-7d70-b3bc-ec3bd1cb4130".to_string()
            }
        );
        // The model-metadata notice is a warning item, not an error.
        assert!(matches!(
            &events[1],
            Event::Item { phase: Phase::Completed, item: Item::Warning { message } }
                if message.starts_with("Model metadata for")
        ));
        assert_eq!(events[2], Event::TurnStarted);
        assert!(events.contains(&Event::Item {
            phase: Phase::Completed,
            item: Item::Reasoning
        }));
        // The failing command (exit 3) is an error; the one that worked is not.
        let commands: Vec<(&str, bool)> = events
            .iter()
            .filter_map(|e| match e {
                Event::Item {
                    phase: Phase::Completed,
                    item:
                        Item::Command {
                            command, is_error, ..
                        },
                } => Some((command.as_str(), *is_error)),
                _ => None,
            })
            .collect();
        assert_eq!(
            commands,
            [
                ("/bin/zsh -c 'exit 3'", true),
                ("/bin/zsh -c 'echo edited >> README.md'", false)
            ]
        );
        assert!(events.iter().any(|e| matches!(
            e,
            Event::Item {
                phase: Phase::Completed,
                item: Item::FileChange {
                    is_error: false,
                    ..
                }
            }
        )));
        assert!(events.iter().any(|e| matches!(
            e,
            Event::Item { phase: Phase::Completed, item: Item::Mcp { server, tool, is_error: false, output_bytes, .. } }
                if server == "cowproof-tools" && tool == "run_check" && *output_bytes > 0
        )));
        assert_eq!(
            events.last(),
            Some(&Event::TurnCompleted {
                usage: ThreadUsage {
                    input: 400,
                    cached_input: 40,
                    output: 80,
                    reasoning_output: 7
                }
            })
        );
    }

    #[test]
    fn a_resumed_thread_reports_the_same_id_and_the_threads_total_usage() {
        let events = events(RESUME);
        assert_eq!(
            events[0],
            Event::Thread {
                id: "01a12d9c-b587-7d70-b3bc-ec3bd1cb4130".to_string()
            }
        );
        // 400 from the first launch plus 100 from this one.
        assert_eq!(
            events.last(),
            Some(&Event::TurnCompleted {
                usage: ThreadUsage {
                    input: 500,
                    cached_input: 50,
                    output: 100,
                    reasoning_output: 7
                }
            })
        );
    }

    #[test]
    fn a_catalog_model_in_code_mode_reports_its_nested_calls_as_the_same_items() {
        // `gpt-6-luna` works through one `exec` tool that runs JavaScript; the commands and MCP
        // calls inside it arrive as ordinary `command_execution` and `mcp_tool_call` items, and
        // there is no model-metadata notice for a model Codex knows.
        let events = events(CODE_MODE);
        assert!(!events.iter().any(|e| matches!(
            e,
            Event::Item {
                item: Item::Warning { .. },
                ..
            }
        )));
        assert!(events.iter().any(|e| matches!(
            e,
            Event::Item { phase: Phase::Completed, item: Item::Command { command, is_error: false, .. } }
                if command.ends_with("'echo edited >> README.md'")
        )));
        assert!(events.iter().any(|e| matches!(
            e,
            Event::Item { phase: Phase::Completed, item: Item::Mcp { server, tool, is_error: false, .. } }
                if server == "cowproof-tools" && tool == "run_check"
        )));
        assert!(matches!(events.last(), Some(Event::TurnCompleted { .. })));
    }

    #[test]
    fn retry_notices_are_not_errors_and_the_turn_failure_is() {
        let events = events(ERROR_401);
        let retries = events
            .iter()
            .filter(|e| matches!(e, Event::Error { retry: true, .. }))
            .count();
        assert_eq!(retries, 5);
        assert!(events.iter().any(|e| matches!(
            e,
            Event::Error { retry: false, message } if message.contains("401")
        )));
        assert!(matches!(
            events.last(),
            Some(Event::TurnFailed { message }) if message.contains("401 Unauthorized")
        ));
    }

    #[test]
    fn a_line_that_is_not_an_event_is_other() {
        for line in [
            r#"{"type":"brand_new"}"#,
            r#"{"type":"thread.started"}"#,
            r#"{"type":"item.completed"}"#,
            r#"{"no":"type"}"#,
            "[]",
        ] {
            assert_eq!(
                parse_event(&serde_json::from_str(line).unwrap()),
                Event::Other,
                "{line}"
            );
        }
        // An unknown item type is an item we do not read.
        assert_eq!(
            parse_event(
                &serde_json::from_str(
                    r#"{"type":"item.completed","item":{"id":"i","type":"todo_list","items":[]}}"#
                )
                .unwrap()
            ),
            Event::Item {
                phase: Phase::Completed,
                item: Item::Other
            }
        );
    }

    #[test]
    fn an_mcp_call_with_an_error_or_a_failed_status_is_an_error() {
        let failed = parse_event(
            &serde_json::from_str(
                r#"{"type":"item.completed","item":{"id":"i","type":"mcp_tool_call","server":"s","tool":"t","arguments":{},"result":null,"error":{"message":"boom"},"status":"failed"}}"#,
            )
            .unwrap(),
        );
        assert!(matches!(
            failed,
            Event::Item {
                item: Item::Mcp { is_error: true, .. },
                ..
            }
        ));
    }
}
