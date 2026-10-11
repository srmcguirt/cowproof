//! The OpenCode adapter (D28, step 2): the `openrouter` runtime.
//!
//! OpenRouter's own Claude Code integration is only guaranteed with Anthropic models, so an
//! OpenRouter model is driven by OpenCode (`opencode run --format json`). This module is the
//! pure half of that adapter, in two parts:
//!
//! * **Launch.** [`opencode_command`] builds the invocation (argv, environment, working
//!   directory, stdin file) and [`write_lane_files`] writes the files it reads from the lane
//!   home. Nothing here spawns a process. The real OpenRouter key is not a field of any type in
//!   this module: the builder is given the lane's placeholder and a `baseURL` that points at the
//!   in-sandbox bridge, and the proxy swaps the credential (see `proxy.rs`).
//! * **Events.** [`parse_event`] reads one line of OpenCode's JSON event stream. The schema is
//!   not documented upstream; it was recorded from the real 1.18.33 binary against a fake
//!   server (`tests/fixtures/opencode/`). The events seen are `step_start`, `text`, `tool_use`
//!   (one event per finished tool call, carrying input and output), `step_finish` (tokens and
//!   cost of one model call) and `error`. Every event carries `sessionID`, the id a resume
//!   passes to `-s`.
//!
//! What the config does, and why it is written the way it is:
//!
//! * The provider is OpenCode's built-in `openrouter`, with `options.baseURL` at the bridge
//!   (`<bridge>/api/v1`) and `options.apiKey` the placeholder. OpenCode's bundled model catalog
//!   has no `openrouter` provider when its network fetch is off, so the config defines the one
//!   model it runs, with the limits and the price from this module's table.
//! * Permissions are `OPENCODE_PERMISSION` (default deny, then an allowlist), never `--auto`.
//!   The environment variable is applied after every config file. The same JSON is in the config
//!   file as well, for the record.
//! * The clone is the builder's: it can write an `opencode.json` or a `.opencode/opencode.json`
//!   there. `OPENCODE_DISABLE_PROJECT_CONFIG=1` makes OpenCode (1.18.33) ignore both. The config
//!   is also passed whole as `OPENCODE_CONFIG_CONTENT`, which OpenCode merges after any project
//!   file, and the permission block after that, so the endpoint, the key and the permissions
//!   hold even if a later version reads project files despite the flag.

use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};

use crate::LaneLayout;

/// OpenCode's provider id for OpenRouter, and so the first half of `-m <provider>/<model>`.
pub const PROVIDER: &str = "openrouter";
/// What the bridge's address is extended with: OpenRouter's API prefix.
pub const API_PREFIX: &str = "/api/v1";
/// The name of the MCP server that carries `ask`, `check_ruling` and `run_check`. OpenCode
/// names its tools `<server>_<tool>`, so `run_check` is `cowproof-tools_run_check`.
pub const MCP_SERVER: &str = "cowproof-tools";

/// What a context window and an output limit are when the price table has no entry. OpenCode
/// needs both to schedule compaction; they are conservative.
const DEFAULT_CONTEXT: u64 = 128_000;
const DEFAULT_OUTPUT: u64 = 16_000;

/// The shape of an OpenCode session id, which `-s` takes.
pub fn valid_session_id(id: &str) -> bool {
    id.strip_prefix("ses_").is_some_and(|rest| {
        (8..=64).contains(&rest.len()) && rest.chars().all(|c| c.is_ascii_alphanumeric())
    })
}

/// Token prices in USD per million tokens. An ESTIMATE, never a bill: written by hand, matched
/// by a substring of the model name, and unverified against OpenRouter's live list. A model
/// that matches no entry is priced as [`DEFAULT_PRICE`], which is dear on purpose, so an
/// unknown model escalates and hits its cost cap early rather than late.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ModelPrice {
    pub input: f64,
    pub output: f64,
    pub cache_read: f64,
    pub context: u64,
    pub output_limit: u64,
}

/// The price of a model nobody wrote down.
pub const DEFAULT_PRICE: ModelPrice = ModelPrice {
    input: 3.0,
    output: 15.0,
    cache_read: 0.3,
    context: DEFAULT_CONTEXT,
    output_limit: DEFAULT_OUTPUT,
};

/// Written from memory of OpenRouter's list prices; update from its `/models` before relying
/// on the figures. Entries are tried in order and the first substring match wins.
const PRICES: [(&str, ModelPrice); 3] = [
    (
        "glm",
        ModelPrice {
            input: 0.6,
            output: 2.2,
            cache_read: 0.11,
            context: 200_000,
            output_limit: 16_000,
        },
    ),
    (
        "deepseek",
        ModelPrice {
            input: 0.3,
            output: 1.2,
            cache_read: 0.03,
            context: 128_000,
            output_limit: 16_000,
        },
    ),
    (
        "qwen",
        ModelPrice {
            input: 0.4,
            output: 1.6,
            cache_read: 0.04,
            context: 128_000,
            output_limit: 16_000,
        },
    ),
];

/// The table entry for `model` (a name or an `vendor/name` id, case-insensitive), if any.
pub fn known_price(model: &str) -> Option<ModelPrice> {
    let lower = model.to_ascii_lowercase();
    PRICES
        .iter()
        .find(|(family, _)| lower.contains(family))
        .map(|(_, price)| *price)
}

/// The price used to estimate `model`: its entry, else [`DEFAULT_PRICE`].
pub fn price_for(model: &str) -> ModelPrice {
    known_price(model).unwrap_or(DEFAULT_PRICE)
}

/// Estimated cost in USD of one model call. Cache writes are priced as plain input: the
/// OpenAI-style providers behind OpenRouter do not charge more for them.
pub fn estimate_cost_usd(
    model: &str,
    input: u64,
    output: u64,
    cache_read: u64,
    cache_write: u64,
) -> f64 {
    let p = price_for(model);
    (input as f64 * p.input
        + output as f64 * p.output
        + cache_read as f64 * p.cache_read
        + cache_write as f64 * p.input)
        / 1_000_000.0
}

/// Everything that decides one OpenCode invocation. It has no field for the real key.
#[derive(Debug, Clone)]
pub struct OpencodeSpec {
    pub lane: LaneLayout,
    /// The OpenRouter model id, `vendor/name`.
    pub model: String,
    /// The in-sandbox bridge, `http://127.0.0.1:<port>`, without the API prefix.
    pub proxy_base_url: String,
    /// The lane's placeholder credential.
    pub placeholder_key: String,
    /// Where the config is written (in the lane home).
    pub config_file: PathBuf,
    /// The prompt, written by the runner and attached to OpenCode's stdin.
    pub prompt_file: PathBuf,
    /// Extra system instructions (the preamble and the project instructions).
    pub system_prompt_file: PathBuf,
    pub cowproof_exe: PathBuf,
    /// The builder tools socket the MCP server talks to.
    pub runner_socket: PathBuf,
    /// The session to continue (`-s`), after a ruling.
    pub resume_session_id: Option<String>,
    /// The most model calls in one session (`agent.build.steps`).
    pub max_turns: u32,
    /// The builder's PATH: absolute entries only, none under the real home.
    pub path: String,
}

/// A validated invocation.
#[derive(Debug)]
pub struct OpencodeInvocation {
    /// `opencode`; the caller replaces it with the resolved executable.
    pub program: String,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    pub cwd: PathBuf,
    /// The file the process reads as stdin: OpenCode quotes a message given as an argument
    /// that contains whitespace, so a multi-line prompt goes on stdin, where it arrives as is.
    pub stdin_file: PathBuf,
}

/// The permission block (OpenCode's `permission` config, and `OPENCODE_PERMISSION`).
///
/// Default deny, then: edit (which covers `write`), read, bash, glob and grep inside the
/// clone, the cowproof MCP tools, and reading the directory where OpenCode saves truncated tool
/// output. `external_directory` is denied, so the tools stay inside the clone as the OS
/// sandbox does. The web tools, subagents and skills are denied by name as well, so the intent
/// survives a change of OpenCode's defaults. In the tool list OpenCode offers the model, a
/// denied tool is not there at all: a call to one comes back as a failed `tool_use` event whose
/// error says the tool is unavailable (and one that a rule refuses at run time says "a rule
/// which prevents you from using this specific tool call").
pub fn permission_json(lane: &LaneLayout) -> Value {
    let tool_output = lane.home.join(".local/share/opencode/tool-output/*");
    json!({
        "*": "deny",
        "read": "allow",
        "edit": "allow",
        "bash": "allow",
        "glob": "allow",
        "grep": "allow",
        format!("{MCP_SERVER}_*"): "allow",
        "external_directory": {
            "*": "deny",
            tool_output.to_string_lossy(): "allow",
        },
        "webfetch": "deny",
        "websearch": "deny",
        "task": "deny",
        "skill": "deny",
    })
}

/// The OpenCode config for one launch.
pub fn config_json(spec: &OpencodeSpec) -> Value {
    let mut model = json!({
        "name": spec.model,
        "tool_call": true,
        "attachment": false,
        "limit": {
            "context": price_for(&spec.model).context,
            "output": price_for(&spec.model).output_limit,
        },
    });
    if let Some(price) = known_price(&spec.model) {
        model["cost"] = json!({
            "input": price.input,
            "output": price.output,
            "cache_read": price.cache_read,
            "cache_write": price.input,
        });
    }
    let full_model = format!("{PROVIDER}/{}", spec.model);
    json!({
        "$schema": "https://opencode.ai/config.json",
        "model": full_model,
        // Titles are generated with the "small model"; keep it on the lane's own model.
        "small_model": full_model,
        "autoupdate": false,
        "share": "disabled",
        "snapshot": false,
        "lsp": false,
        "formatter": false,
        "instructions": [spec.system_prompt_file],
        "provider": {
            PROVIDER: {
                "options": {
                    "baseURL": format!("{}{API_PREFIX}", spec.proxy_base_url.trim_end_matches('/')),
                    "apiKey": spec.placeholder_key,
                },
                "models": { spec.model.clone(): model },
            }
        },
        "mcp": {
            MCP_SERVER: {
                "type": "local",
                "command": [spec.cowproof_exe, "lane-tools", "--socket", spec.runner_socket],
                "enabled": true,
            }
        },
        "agent": { "build": { "steps": spec.max_turns } },
        "permission": permission_json(&spec.lane),
    })
}

/// What the builder is told about tool names that Claude's preamble spells another way.
const TOOL_NAME_NOTE: &str = "\n\n## Tool names in this runtime\n\nThe tools named `ask`, `check_ruling` and `run_check` above are called `cowproof-tools_ask`, `cowproof-tools_check_ruling` and `cowproof-tools_run_check` here. Use those names.\n";

/// Write the three files an OpenCode launch reads from the lane home: the config, the system
/// instructions and the prompt. The lane home is writable by the builder, so a launch calls this
/// before EVERY start (a resume must never trust what the previous session left there).
pub fn write_lane_files(spec: &OpencodeSpec, system_append: &str, prompt: &str) -> Result<()> {
    fs::write(
        &spec.config_file,
        serde_json::to_vec_pretty(&config_json(spec))?,
    )
    .with_context(|| format!("writing {}", spec.config_file.display()))?;
    fs::write(
        &spec.system_prompt_file,
        format!("{system_append}{TOOL_NAME_NOTE}"),
    )
    .with_context(|| format!("writing {}", spec.system_prompt_file.display()))?;
    fs::write(&spec.prompt_file, prompt)
        .with_context(|| format!("writing {}", spec.prompt_file.display()))?;
    Ok(())
}

/// Build the invocation. Validates the model name, the session id, the turn limit and every
/// path; the environment is complete and explicit.
pub fn opencode_command(spec: &OpencodeSpec) -> Result<OpencodeInvocation> {
    if !crate::opencode::valid_model(&spec.model) {
        bail!("{:?} is not an OpenRouter model name", spec.model);
    }
    if spec.max_turns == 0 {
        bail!("max_turns is 0");
    }
    if let Some(id) = &spec.resume_session_id
        && !valid_session_id(id)
    {
        bail!("resume_session_id does not look like an OpenCode session id: {id}");
    }
    for (what, path) in [
        ("config_file", &spec.config_file),
        ("prompt_file", &spec.prompt_file),
        ("system_prompt_file", &spec.system_prompt_file),
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

    let mut args = vec![
        "run".to_string(),
        "--format".to_string(),
        "json".to_string(),
        // A given title stops OpenCode asking a second model to write one.
        "--title".to_string(),
        "cowproof".to_string(),
        "-m".to_string(),
        format!("{PROVIDER}/{}", spec.model),
    ];
    if let Some(id) = &spec.resume_session_id {
        args.push("-s".to_string());
        args.push(id.clone());
    }

    let home = &spec.lane.home;
    let config = serde_json::to_string(&config_json(spec))?;
    let permission = serde_json::to_string(&permission_json(&spec.lane))?;
    let s = |p: &Path| p.to_string_lossy().into_owned();
    let env = vec![
        ("HOME".to_string(), s(home)),
        ("XDG_CONFIG_HOME".to_string(), s(&home.join(".config"))),
        ("XDG_DATA_HOME".to_string(), s(&home.join(".local/share"))),
        ("XDG_STATE_HOME".to_string(), s(&home.join(".local/state"))),
        ("XDG_CACHE_HOME".to_string(), s(&home.join(".cache"))),
        ("OPENCODE_CONFIG".to_string(), s(&spec.config_file)),
        ("OPENCODE_CONFIG_CONTENT".to_string(), config),
        ("OPENCODE_PERMISSION".to_string(), permission),
        // Nothing here may reach the internet or read the director's setup.
        ("OPENCODE_DISABLE_MODELS_FETCH".to_string(), "1".to_string()),
        ("OPENCODE_DISABLE_AUTOUPDATE".to_string(), "1".to_string()),
        ("OPENCODE_DISABLE_SHARE".to_string(), "1".to_string()),
        ("OPENCODE_DISABLE_LSP_DOWNLOAD".to_string(), "1".to_string()),
        (
            "OPENCODE_DISABLE_DEFAULT_PLUGINS".to_string(),
            "1".to_string(),
        ),
        ("OPENCODE_PURE".to_string(), "1".to_string()),
        (
            "OPENCODE_DISABLE_PROJECT_CONFIG".to_string(),
            "1".to_string(),
        ),
        (
            "OPENCODE_DISABLE_EXTERNAL_SKILLS".to_string(),
            "1".to_string(),
        ),
        ("OPENCODE_DISABLE_CLAUDE_CODE".to_string(), "1".to_string()),
        (
            "OPENCODE_DISABLE_TERMINAL_TITLE".to_string(),
            "1".to_string(),
        ),
        // OpenCode installs `@opencode-ai/plugin` into its config directory in the background,
        // and no flag turns that off; npm's own settings do: offline, against an address
        // nothing listens on.
        ("npm_config_offline".to_string(), "true".to_string()),
        (
            "npm_config_registry".to_string(),
            "http://127.0.0.1:9".to_string(),
        ),
        ("PATH".to_string(), spec.path.clone()),
        ("CARGO_HOME".to_string(), s(&home.join(".cargo"))),
    ];

    Ok(OpencodeInvocation {
        program: "opencode".to_string(),
        args,
        env,
        cwd: spec.lane.clone.clone(),
        stdin_file: spec.prompt_file.clone(),
    })
}

/// A model name goes into argv and a config key.
pub fn valid_model(model: &str) -> bool {
    cowproof_core::valid_model_name(model)
}

/// The tool names the meter and the escalate-early observer know are Claude Code's. OpenCode's
/// are lower case, and its MCP tools are `<server>_<tool>`; they are mapped so a lane's
/// summary reads the same whichever runtime built it.
pub fn canonical_tool_name(tool: &str) -> String {
    match tool {
        "bash" => "Bash".to_string(),
        "read" => "Read".to_string(),
        "edit" => "Edit".to_string(),
        "write" => "Write".to_string(),
        "glob" => "Glob".to_string(),
        "grep" => "Grep".to_string(),
        other => match other.split_once('_') {
            Some((server, name)) if server == MCP_SERVER => format!("mcp__{server}__{name}"),
            _ => other.to_string(),
        },
    }
}

/// One line of OpenCode's event stream, reduced to what the meter needs.
#[derive(Debug, Clone, PartialEq)]
pub enum Event {
    /// A model call begins.
    StepStart { session: String },
    /// Assistant text.
    Text { session: String, len: u64 },
    /// A finished tool call (completed or failed): OpenCode reports use and result together.
    Tool {
        session: String,
        call_id: String,
        /// OpenCode's own name for the tool (`bash`, `write`, `cowproof-tools_run_check`).
        tool: String,
        input_bytes: u64,
        /// The `command` input of a `bash` call.
        command: Option<String>,
        output_bytes: u64,
        is_error: bool,
        /// The call was refused: by a permission rule, or because the tool is not offered.
        denied: bool,
    },
    /// A model call ends: its tokens and the cost OpenCode reported for it.
    StepFinish {
        session: String,
        /// The assistant message this step belongs to; a repeated id replaces its snapshot.
        message: Option<String>,
        input: u64,
        /// Output tokens, reasoning tokens included.
        output: u64,
        cache_read: u64,
        cache_write: u64,
        /// The runtime's cost for the step, when it gave a positive one.
        cost: Option<f64>,
        reason: Option<String>,
    },
    /// The session failed (a provider error, say).
    Error {
        session: Option<String>,
        message: String,
    },
    /// Any other event (counted, not read).
    Other { session: Option<String> },
}

fn u64_at(v: &Value, path: &[&str]) -> u64 {
    path.iter()
        .try_fold(v, |v, k| v.get(k))
        .and_then(Value::as_u64)
        .unwrap_or(0)
}

fn text_bytes(v: Option<&Value>) -> u64 {
    match v {
        None | Some(Value::Null) => 0,
        Some(Value::String(s)) => s.len() as u64,
        Some(other) => serde_json::to_string(other).unwrap_or_default().len() as u64,
    }
}

/// Read one event. A line that is not an event object of a known type is [`Event::Other`].
pub fn parse_event(json: &Value) -> Event {
    let session = json
        .get("sessionID")
        .and_then(Value::as_str)
        .map(str::to_string);
    let part = json.get("part");
    let with_session = |f: &dyn Fn(String) -> Event| match &session {
        Some(s) => f(s.clone()),
        None => Event::Other { session: None },
    };
    match json.get("type").and_then(Value::as_str) {
        Some("step_start") => with_session(&|session| Event::StepStart { session }),
        Some("text") => with_session(&|session| Event::Text {
            session,
            len: text_bytes(part.and_then(|p| p.get("text"))),
        }),
        Some("tool_use") => {
            let Some(part) = part else {
                return Event::Other { session };
            };
            let state = part.get("state");
            let status = state
                .and_then(|s| s.get("status"))
                .and_then(Value::as_str)
                .unwrap_or("");
            // Only a finished call is reported; a pending or running one is not an event yet.
            if !matches!(status, "completed" | "error") {
                return Event::Other { session };
            }
            let tool = part
                .get("tool")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            let input = state.and_then(|s| s.get("input"));
            let command = (tool == "bash")
                .then(|| {
                    input
                        .and_then(|i| i.get("command"))
                        .and_then(Value::as_str)
                        .map(str::to_string)
                })
                .flatten();
            let output = state.and_then(|s| s.get("output").or_else(|| s.get("error")));
            let exit_failed = tool == "bash"
                && state
                    .and_then(|s| s.get("metadata"))
                    .and_then(|m| m.get("exit"))
                    .and_then(Value::as_i64)
                    .is_some_and(|code| code != 0);
            let denied = status == "error"
                && output.and_then(Value::as_str).is_some_and(|o| {
                    o.contains("specified a rule which prevents") || o.contains("unavailable tool")
                });
            Event::Tool {
                session: session.unwrap_or_default(),
                call_id: part
                    .get("callID")
                    .or_else(|| part.get("id"))
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                tool: tool.to_string(),
                input_bytes: input
                    .map(|i| serde_json::to_string(i).unwrap_or_default().len() as u64)
                    .unwrap_or(0),
                command,
                output_bytes: text_bytes(output),
                // A call to a tool OpenCode offers no longer fails as its own `invalid` tool,
                // which is a failed call whatever its status says.
                is_error: status == "error" || exit_failed || tool == "invalid",
                denied,
            }
        }
        Some("step_finish") => {
            let Some(part) = part else {
                return Event::Other { session };
            };
            let tokens = part.get("tokens").unwrap_or(&Value::Null);
            let cost = part
                .get("cost")
                .and_then(Value::as_f64)
                .filter(|c| c.is_finite() && *c > 0.0);
            Event::StepFinish {
                session: session.unwrap_or_default(),
                message: part
                    .get("messageID")
                    .and_then(Value::as_str)
                    .map(str::to_string),
                input: u64_at(tokens, &["input"]),
                output: u64_at(tokens, &["output"]) + u64_at(tokens, &["reasoning"]),
                cache_read: u64_at(tokens, &["cache", "read"]),
                cache_write: u64_at(tokens, &["cache", "write"]),
                cost,
                reason: part
                    .get("reason")
                    .and_then(Value::as_str)
                    .map(str::to_string),
            }
        }
        Some("error") => {
            let error = json.get("error");
            let name = error
                .and_then(|e| e.get("name"))
                .and_then(Value::as_str)
                .unwrap_or("error");
            let data = error.and_then(|e| e.get("data"));
            let status = data
                .and_then(|d| d.get("statusCode"))
                .and_then(Value::as_u64);
            let message = data
                .and_then(|d| d.get("message"))
                .and_then(Value::as_str)
                .unwrap_or("");
            let message = match status {
                Some(code) => format!("{name} {code}: {message}"),
                None => format!("{name}: {message}"),
            };
            Event::Error { session, message }
        }
        _ => Event::Other { session },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn spec() -> OpencodeSpec {
        OpencodeSpec {
            lane: lane(),
            model: "z-ai/glm-5.3-flash".to_string(),
            proxy_base_url: "http://127.0.0.1:41000".to_string(),
            placeholder_key: "placeholder-abc".to_string(),
            config_file: PathBuf::from("/nonexistent-cp/lanes/l1/home/opencode.json"),
            prompt_file: PathBuf::from("/nonexistent-cp/lanes/l1/home/prompt.md"),
            system_prompt_file: PathBuf::from("/nonexistent-cp/lanes/l1/home/system-prompt.md"),
            cowproof_exe: PathBuf::from("/nonexistent-cp/bin/cowproof"),
            runner_socket: PathBuf::from("/nonexistent-cp/lanes/l1/sock/runner.sock"),
            resume_session_id: None,
            max_turns: 60,
            path: "/usr/bin:/bin".to_string(),
        }
    }

    fn env_of(inv: &OpencodeInvocation, key: &str) -> String {
        inv.env
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| panic!("{key} is not set"))
    }

    #[test]
    fn a_fresh_launch_is_run_json_with_the_model_and_a_title() {
        let inv = opencode_command(&spec()).unwrap();
        assert_eq!(
            inv.args,
            [
                "run",
                "--format",
                "json",
                "--title",
                "cowproof",
                "-m",
                "openrouter/z-ai/glm-5.3-flash"
            ]
        );
        assert_eq!(inv.stdin_file, spec().prompt_file);
        assert_eq!(inv.cwd, spec().lane.clone);
    }

    #[test]
    fn a_resume_adds_the_session_and_only_a_well_formed_one() {
        let mut s = spec();
        s.resume_session_id = Some("ses_ed38dc388ffeb9FMHqRuDEw3t7".to_string());
        let inv = opencode_command(&s).unwrap();
        assert_eq!(
            &inv.args[inv.args.len() - 2..],
            ["-s", "ses_ed38dc388ffeb9FMHqRuDEw3t7"]
        );
        for bad in [
            "",
            "ses_",
            "ses_ab",
            "ses_a;b c d e f g",
            "0a1b2c3d-1111",
            "-s",
        ] {
            s.resume_session_id = Some(bad.to_string());
            assert!(opencode_command(&s).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn the_environment_keeps_every_directory_in_the_lane_home_and_the_net_off() {
        let inv = opencode_command(&spec()).unwrap();
        let home = "/nonexistent-cp/lanes/l1/home";
        assert_eq!(env_of(&inv, "HOME"), home);
        for (key, rel) in [
            ("XDG_CONFIG_HOME", ".config"),
            ("XDG_DATA_HOME", ".local/share"),
            ("XDG_STATE_HOME", ".local/state"),
            ("XDG_CACHE_HOME", ".cache"),
        ] {
            assert_eq!(env_of(&inv, key), format!("{home}/{rel}"));
        }
        for key in [
            "OPENCODE_DISABLE_MODELS_FETCH",
            "OPENCODE_DISABLE_AUTOUPDATE",
            "OPENCODE_PURE",
            "OPENCODE_DISABLE_PROJECT_CONFIG",
            "OPENCODE_DISABLE_SHARE",
        ] {
            assert_eq!(env_of(&inv, key), "1", "{key}");
        }
        assert_eq!(env_of(&inv, "npm_config_offline"), "true");
        assert_eq!(env_of(&inv, "npm_config_registry"), "http://127.0.0.1:9");
        // No credential variable of any provider.
        for (key, _) in &inv.env {
            assert!(!key.contains("API_KEY"), "{key}");
        }
    }

    #[test]
    fn the_config_points_at_the_bridge_with_the_placeholder_and_no_other_host() {
        let config = config_json(&spec());
        let options = &config["provider"]["openrouter"]["options"];
        assert_eq!(options["baseURL"], "http://127.0.0.1:41000/api/v1");
        assert_eq!(options["apiKey"], "placeholder-abc");
        let text = config.to_string();
        assert!(!text.contains("openrouter.ai"), "{text}");
        assert!(text.contains("\"enabled\":true"));
        assert_eq!(
            config["mcp"]["cowproof-tools"]["command"],
            json!([
                "/nonexistent-cp/bin/cowproof",
                "lane-tools",
                "--socket",
                "/nonexistent-cp/lanes/l1/sock/runner.sock"
            ])
        );
        assert_eq!(config["agent"]["build"]["steps"], 60);
        assert_eq!(config["model"], "openrouter/z-ai/glm-5.3-flash");
        assert_eq!(config["small_model"], config["model"]);
    }

    #[test]
    fn the_model_is_defined_with_its_price_only_when_the_table_knows_it() {
        let known = config_json(&spec());
        let model = &known["provider"]["openrouter"]["models"]["z-ai/glm-5.3-flash"];
        assert_eq!(model["tool_call"], true);
        assert_eq!(model["cost"]["input"], 0.6);
        assert_eq!(model["limit"]["context"], 200_000);
        let mut s = spec();
        s.model = "acme/mystery-9".to_string();
        let unknown = config_json(&s);
        let model = &unknown["provider"]["openrouter"]["models"]["acme/mystery-9"];
        assert!(model.get("cost").is_none(), "{model}");
        assert_eq!(model["limit"]["context"], DEFAULT_CONTEXT);
    }

    #[test]
    fn permissions_deny_by_default_and_allow_only_the_working_tools() {
        let permission = permission_json(&lane());
        assert_eq!(permission["*"], "deny");
        for allowed in ["read", "edit", "bash", "glob", "grep", "cowproof-tools_*"] {
            assert_eq!(permission[allowed], "allow", "{allowed}");
        }
        for denied in ["webfetch", "websearch", "task", "skill"] {
            assert_eq!(permission[denied], "deny", "{denied}");
        }
        assert_eq!(permission["external_directory"]["*"], "deny");
        assert_eq!(
            permission["external_directory"]["/nonexistent-cp/lanes/l1/home/.local/share/opencode/tool-output/*"],
            "allow"
        );
        // The config carries the same block as the environment.
        assert_eq!(config_json(&spec())["permission"], permission);
        let inv = opencode_command(&spec()).unwrap();
        let from_env: Value = serde_json::from_str(&env_of(&inv, "OPENCODE_PERMISSION")).unwrap();
        assert_eq!(from_env, permission);
        assert!(!inv.args.iter().any(|a| a == "--auto"));
    }

    #[test]
    fn bad_inputs_are_refused() {
        let mut s = spec();
        s.model = "--auto".to_string();
        assert!(opencode_command(&s).is_err());
        let mut s = spec();
        s.max_turns = 0;
        assert!(opencode_command(&s).is_err());
        let mut s = spec();
        s.config_file = PathBuf::from("relative.json");
        assert!(opencode_command(&s).is_err());
        let mut s = spec();
        s.path = "/usr/bin::/bin".to_string();
        assert!(opencode_command(&s).is_err());
        let mut s = spec();
        s.path = "/nonexistent-cp/realhome/bin".to_string();
        assert!(opencode_command(&s).is_err());
    }

    #[test]
    fn tool_names_are_mapped_to_the_ones_claude_reports() {
        assert_eq!(canonical_tool_name("bash"), "Bash");
        assert_eq!(canonical_tool_name("write"), "Write");
        assert_eq!(
            canonical_tool_name("cowproof-tools_run_check"),
            "mcp__cowproof-tools__run_check"
        );
        assert_eq!(canonical_tool_name("invalid"), "invalid");
        assert_eq!(canonical_tool_name("other_tool"), "other_tool");
    }

    #[test]
    fn session_ids_have_opencodes_shape() {
        assert!(valid_session_id("ses_ed38dc388ffeb9FMHqRuDEw3t7"));
        assert!(!valid_session_id("ed38dc388ffeb9FMHqRuDEw3t7"));
        assert!(!valid_session_id("ses_short"));
        assert!(!valid_session_id("ses_has space and more"));
    }

    #[test]
    fn the_price_table_matches_by_name_and_prices_the_unknown_dear() {
        assert_eq!(known_price("z-ai/GLM-5.3-flash").unwrap().input, 0.6);
        assert!(known_price("acme/mystery-9").is_none());
        assert_eq!(price_for("acme/mystery-9"), DEFAULT_PRICE);
        // 1M input + 1M output + 1M cache read + 1M cache write on glm.
        let cost = estimate_cost_usd(
            "z-ai/glm-5.3-flash",
            1_000_000,
            1_000_000,
            1_000_000,
            1_000_000,
        );
        assert!((cost - (0.6 + 2.2 + 0.11 + 0.6)).abs() < 1e-9, "{cost}");
    }

    fn event(line: &str) -> Event {
        parse_event(&serde_json::from_str(line).unwrap())
    }

    #[test]
    fn an_error_event_names_the_status_and_message() {
        let e = event(
            r#"{"type":"error","sessionID":"ses_x","error":{"name":"APIError","data":{"message":"No auth","statusCode":401,"isRetryable":false}}}"#,
        );
        assert_eq!(
            e,
            Event::Error {
                session: Some("ses_x".to_string()),
                message: "APIError 401: No auth".to_string()
            }
        );
    }

    #[test]
    fn a_pending_tool_call_and_an_unknown_type_are_not_reads() {
        assert!(matches!(
            event(
                r#"{"type":"tool_use","sessionID":"s","part":{"tool":"bash","state":{"status":"running"}}}"#
            ),
            Event::Other { .. }
        ));
        assert!(matches!(
            event(r#"{"type":"brand_new","sessionID":"s"}"#),
            Event::Other { .. }
        ));
        assert!(matches!(event(r#"{"type":"text"}"#), Event::Other { .. }));
    }
}
