//! The director's side of the `codex` runtime (D28, step 3): find Codex, read the key and the
//! prices, and build the sandboxed Codex command.
//!
//! The real OpenAI key is read once, from the director's `OPENAI_API_KEY`, and handed to the
//! egress proxy ([`crate::run::start_proxy`]). It is not a field of anything in this file that
//! reaches the builder: [`CodexLaunch`] carries the lane's placeholder only.
//!
//! The proxy's upstream for OpenAI is `https://api.openai.com`. The director may replace it with
//! `COWPROOF_OPENAI_UPSTREAM` (a test server, a gateway). It is read from the environment and
//! never from `cowproof.toml`, because repository content must not be able to redirect the key,
//! and it is written to `run.json` whenever it is set.
//!
//! **Prices.** OpenAI publishes no machine-readable price list (OpenRouter's `GET /models`, which
//! step 2 reads, has no counterpart), and Codex reports tokens but never a cost. The cost cap
//! acts on a price, so the director states one, per exact model id, in the BASE commit's
//! `cowproof.toml` (never the working tree, so a lane cannot lower its own price):
//!
//! ```toml
//! [runtimes.codex.prices."gpt-6-luna"]
//! input = 1.25          # USD per million uncached input tokens
//! cached_input = 0.125  # USD per million cached input tokens (default: the input price)
//! output = 10.0         # USD per million output tokens, reasoning included
//! source = "https://platform.openai.com/docs/pricing, read 2026-10-11"
//! ```
//!
//! `source` is required and is recorded with the lane. A `codex` rung whose model has no entry
//! is refused (exit 4): there is no built-in table and no default price. The same file may say
//! `[runtimes.codex] credential = "api-key"` (the only mode built); `"subscription"` is refused
//! by name (D28 clause 6).

use crate::openrouter::models_on_or_above;
use crate::root::resolve_executable;
use crate::run::{RuntimeProcess, RuntimeSandbox, runtime_command};
use anyhow::{Context, Result, anyhow, bail};
use cowproof_core::{Routing, Rung, Runtime, git_show_optional, valid_model_name};
use cowproof_run::{
    LaneLayout, NetworkMode,
    codex::{CodexPrice, CodexSpec, codex_command, write_lane_files},
    prefix::assemble_prompt,
    proxy::{Provider, ProxyConfig},
};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;

/// The director's environment variable that holds the real key.
pub(crate) const KEY_ENV: &str = "OPENAI_API_KEY";
/// The director-side override of the OpenAI upstream.
pub(crate) const UPSTREAM_ENV: &str = "COWPROOF_OPENAI_UPSTREAM";
/// OpenAI's API host.
pub(crate) const DEFAULT_UPSTREAM: &str = "https://api.openai.com";

/// How long `codex --version` may take.
const VERSION_TIMEOUT: Duration = Duration::from_secs(30);

/// The real OpenAI key: `None` when the variable is unset or empty. A value that is not UTF-8
/// is an error that never shows the value.
pub(crate) fn real_key() -> Result<Option<String>> {
    match std::env::var_os(KEY_ENV) {
        Some(k) if !k.is_empty() => k
            .into_string()
            .map(Some)
            .map_err(|_| anyhow!("{KEY_ENV} is not valid UTF-8")),
        _ => Ok(None),
    }
}

/// The OpenAI upstream the proxy forwards to, and whether the director replaced it. A
/// replacement that is not a usable `http(s)` base URL is an error.
pub(crate) fn upstream() -> Result<(String, bool)> {
    match std::env::var_os(UPSTREAM_ENV) {
        Some(v) if !v.is_empty() => {
            let url = v
                .into_string()
                .map_err(|_| anyhow!("{UPSTREAM_ENV} is not valid UTF-8"))?;
            // The proxy's own parser decides what a usable base URL is. A throwaway key is
            // enough for that; it is dropped at once.
            ProxyConfig::for_provider(Provider::Openai, "x", url.clone())
                .with_context(|| format!("{UPSTREAM_ENV} is not usable"))?;
            Ok((url, true))
        }
        _ => Ok((DEFAULT_UPSTREAM.to_string(), false)),
    }
}

/// The `codex` model ids a lane that starts on `first` could run, each once, in ladder order.
pub(crate) fn priced_models(first: &Rung, routing: &Routing) -> Vec<String> {
    models_on_or_above(Runtime::Codex, first, routing)
}

/// The base commit's `[runtimes.codex]` table.
#[derive(Debug, Default, PartialEq)]
pub(crate) struct CodexConfig {
    /// The director's prices, by exact model id.
    pub prices: BTreeMap<String, CodexPrice>,
}

const SUBSCRIPTION_REFUSAL: &str = "the `codex` runtime supports an API key only: a subscription (ChatGPT login) lane has to hand its login to the lane, and that is not built yet (D28 clause 6); remove `credential` from [runtimes.codex] in cowproof.toml or set it to \"api-key\"";

fn refuse_unknown_keys(what: &str, table: &toml::Table, known: &[&str]) -> Result<()> {
    if let Some(key) = table.keys().find(|k| !known.contains(&k.as_str())) {
        bail!(
            "cowproof.toml: {what}: unknown key {key:?} (known: {})",
            known.join(", ")
        );
    }
    Ok(())
}

/// A price figure: a positive, finite number of USD per million tokens (TOML integer or float).
fn price_number(what: &str, value: &toml::Value, allow_zero: bool) -> Result<f64> {
    let number = match value {
        toml::Value::Float(f) => *f,
        toml::Value::Integer(i) => *i as f64,
        _ => bail!("cowproof.toml: {what} must be a number (USD per million tokens)"),
    };
    if !number.is_finite() || number < 0.0 || (number == 0.0 && !allow_zero) {
        bail!(
            "cowproof.toml: {what} must be {} (USD per million tokens)",
            if allow_zero {
                "zero or more"
            } else {
                "more than zero"
            }
        );
    }
    Ok(number)
}

impl CodexConfig {
    /// The `[runtimes.codex]` table of a `cowproof.toml`. No file, no `[runtimes]` and no
    /// `codex` table all mean no prices. A file that does not parse, an unknown key, a
    /// subscription credential, and a price that is missing a figure or its source, is not a
    /// number or is not above zero are errors.
    pub(crate) fn parse(text: Option<&str>) -> Result<Self> {
        let Some(text) = text else {
            return Ok(Self::default());
        };
        let config: toml::Table = toml::from_str(text).context("cowproof.toml does not parse")?;
        let Some(runtimes) = config.get("runtimes") else {
            return Ok(Self::default());
        };
        let runtimes = runtimes
            .as_table()
            .context("cowproof.toml: [runtimes] must be a table")?;
        let Some(codex) = runtimes.get("codex") else {
            return Ok(Self::default());
        };
        let codex = codex
            .as_table()
            .context("cowproof.toml: [runtimes.codex] must be a table")?;
        refuse_unknown_keys("[runtimes.codex]", codex, &["credential", "prices"])?;
        if let Some(credential) = codex.get("credential") {
            match credential.as_str() {
                Some("api-key") => {}
                Some("subscription" | "chatgpt") => bail!("{SUBSCRIPTION_REFUSAL}"),
                _ => bail!(
                    "cowproof.toml: [runtimes.codex] credential must be \"api-key\" (the only mode built; subscription mode is not, D28 clause 6)"
                ),
            }
        }
        let mut prices = BTreeMap::new();
        if let Some(table) = codex.get("prices") {
            let table = table
                .as_table()
                .context("cowproof.toml: [runtimes.codex.prices] must be a table")?;
            for (model, entry) in table {
                if !valid_model_name(model) {
                    bail!("cowproof.toml: [runtimes.codex.prices] {model:?} is not a model name");
                }
                let what = format!("[runtimes.codex.prices.{model:?}]");
                let entry = entry
                    .as_table()
                    .with_context(|| format!("cowproof.toml: {what} must be a table"))?;
                refuse_unknown_keys(&what, entry, &["input", "cached_input", "output", "source"])?;
                let figure = |key: &str, required: bool, allow_zero: bool| -> Result<Option<f64>> {
                    match entry.get(key) {
                        Some(v) => price_number(&format!("{what} {key}"), v, allow_zero).map(Some),
                        None if required => {
                            bail!("cowproof.toml: {what} has no `{key}` (USD per million tokens)")
                        }
                        None => Ok(None),
                    }
                };
                let input = figure("input", true, false)?.unwrap_or_default();
                let output = figure("output", true, false)?.unwrap_or_default();
                let cached_input = figure("cached_input", false, true)?.unwrap_or(input);
                let source = entry
                    .get("source")
                    .and_then(toml::Value::as_str)
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .with_context(|| {
                        format!(
                            "cowproof.toml: {what} has no `source` (where the figures came from, recorded with the lane)"
                        )
                    })?;
                if source.len() > 300 {
                    bail!("cowproof.toml: {what} source is longer than 300 characters");
                }
                prices.insert(
                    model.clone(),
                    CodexPrice {
                        input,
                        cached_input,
                        output,
                        source: source.to_string(),
                    },
                );
            }
        }
        Ok(Self { prices })
    }

    /// The configuration at `commit` of `repo`: the base commit's `cowproof.toml`.
    pub(crate) fn at_commit(repo: &Path, commit: &str) -> Result<Self> {
        let text = git_show_optional(repo, commit, "cowproof.toml")?;
        Self::parse(text.as_deref())
            .with_context(|| format!("reading the codex configuration at {commit}"))
    }

    /// The price of each of `models`, or one message per model that has none.
    pub(crate) fn price_all(
        &self,
        models: &[String],
    ) -> Result<BTreeMap<String, CodexPrice>, Vec<String>> {
        let mut found = BTreeMap::new();
        let mut missing = Vec::new();
        for model in models {
            match self.prices.get(model) {
                Some(price) => {
                    found.insert(model.clone(), price.clone());
                }
                None => missing.push(format!(
                    "model {model:?} has no price: add [runtimes.codex.prices.{model:?}] with input, output and source to the base commit's cowproof.toml (the cost cap cannot be enforced without a price)"
                )),
            }
        }
        if missing.is_empty() {
            Ok(found)
        } else {
            Err(missing)
        }
    }
}

/// A Codex executable the runner can launch.
#[derive(Debug, Clone)]
pub(crate) struct Codex {
    /// Absolute and canonical; the native binary, never the Node wrapper.
    pub bin: PathBuf,
    /// The first line `--version` printed.
    pub version: String,
}

/// The native Codex binary behind an npm install. `npm i -g @openai/codex` installs a Node
/// script (`bin/codex.js`) that starts the platform package's binary; the sandbox hides the
/// director's Node, so the lane starts the binary itself. `None` when `script` is not an npm
/// install of Codex or its platform package is not beside it.
fn native_beside(script: &Path) -> Option<PathBuf> {
    let package = script.parent()?.parent()?;
    let (os, arch, triple) = match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => ("darwin", "arm64", "aarch64-apple-darwin"),
        ("macos", "x86_64") => ("darwin", "x64", "x86_64-apple-darwin"),
        ("linux", "aarch64") => ("linux", "arm64", "aarch64-unknown-linux-musl"),
        ("linux", "x86_64") => ("linux", "x64", "x86_64-unknown-linux-musl"),
        _ => return None,
    };
    [
        package
            .join("node_modules/@openai")
            .join(format!("codex-{os}-{arch}")),
        package.to_path_buf(),
    ]
    .into_iter()
    .map(|root| root.join("vendor").join(triple).join("bin/codex"))
    .find(|candidate| candidate.is_file())
}

/// Whether `bin` starts with a `#!` line, that is, is a script and not a binary.
fn is_script(bin: &Path) -> bool {
    use std::io::Read;
    let mut head = [0u8; 2];
    fs::File::open(bin)
        .and_then(|mut f| f.read_exact(&mut head))
        .is_ok_and(|()| &head == b"#!")
}

/// Find Codex on the director's `PATH` (or as a path relative to `cwd`) and ask its version.
/// The error is a line for the preflight to print. The environment is cleared first, so no key
/// reaches the process.
pub(crate) async fn locate(name: &str, director_path: &str, cwd: &Path) -> Result<Codex, String> {
    let found = resolve_executable(name, director_path, cwd).map_err(|e| format!("{e}"))?;
    let mut bin = found
        .canonicalize()
        .map_err(|e| format!("cannot resolve {}: {e}", found.display()))?;
    if is_script(&bin) {
        bin = native_beside(&bin)
            .and_then(|native| native.canonicalize().ok())
            .ok_or_else(|| {
                format!(
                    "{} is a script and the native Codex binary was not found beside it; the sandbox cannot run a Node wrapper, so name the binary with --codex-bin",
                    bin.display()
                )
            })?;
    }
    let mut command = Command::new(&bin);
    command
        .arg("--version")
        .env_clear()
        .env("PATH", director_path)
        .stdin(Stdio::null())
        .kill_on_drop(true);
    match tokio::time::timeout(VERSION_TIMEOUT, command.output()).await {
        Err(_) => Err(format!(
            "{} --version did not finish in {VERSION_TIMEOUT:?}",
            bin.display()
        )),
        Ok(Err(e)) => Err(format!("cannot run {}: {e}", bin.display())),
        Ok(Ok(out)) if !out.status.success() => Err(format!(
            "{} --version ended with {}",
            bin.display(),
            out.status
        )),
        Ok(Ok(out)) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let version: String = stdout
                .lines()
                .map(str::trim)
                .find(|l| !l.is_empty())
                .unwrap_or("no version printed")
                .chars()
                .take(60)
                .collect();
            Ok(Codex { bin, version })
        }
    }
}

/// Everything that decides one Codex launch.
pub(crate) struct CodexLaunch<'a> {
    pub layout: &'a LaneLayout,
    pub codex_bin: &'a Path,
    pub cowproof_exe: &'a Path,
    pub path: &'a str,
    /// The in-sandbox bridge, `http://127.0.0.1:<port>`.
    pub base_url: &'a str,
    pub bridge_port: u16,
    pub proxy_socket: &'a Path,
    pub placeholder_key: &'a str,
    pub network: NetworkMode,
    /// The builder tools socket, canonical (`COWPROOF_RUNNER_SOCKET`).
    pub runner_socket: &'a Path,
    pub port_base: u16,
    /// The OpenAI model id.
    pub model: &'a str,
    /// The packet this session works from; the preamble and the project instructions are
    /// assembled with it, as for Claude.
    pub packet: &'a str,
    pub project_instructions: Option<&'a str>,
    /// What the first message says: the packet, or the ruling a resume delivers.
    pub prompt: &'a str,
    pub resume: Option<&'a str>,
    /// Launch without the OS sandbox (trusted local experiments only).
    pub unsandboxed: bool,
}

/// The builder's command for a `codex` rung: the bridge wrapper, then Codex, under the builder
/// sandbox policy with exactly the lane's environment. Not yet started. Writes the config and
/// the prompt into the lane home first; a launch does so before EVERY start. The prompt file is
/// the command's stdin.
pub(crate) fn codex_builder_command(l: &CodexLaunch<'_>) -> Result<Command> {
    if !l.codex_bin.is_absolute() {
        bail!("the codex executable path is not absolute");
    }
    let home = &l.layout.home;
    let spec = CodexSpec {
        lane: l.layout.clone(),
        model: l.model.to_string(),
        proxy_base_url: l.base_url.to_string(),
        placeholder_key: l.placeholder_key.to_string(),
        codex_home: home.join(".codex"),
        prompt_file: home.join("prompt.md"),
        cowproof_exe: l.cowproof_exe.to_path_buf(),
        runner_socket: l.runner_socket.to_path_buf(),
        resume_session_id: l.resume.map(str::to_string),
        path: l.path.to_string(),
    };
    let assembled = assemble_prompt(l.project_instructions, l.packet);
    write_lane_files(&spec, &assembled.system_append, l.prompt)?;

    let invocation = codex_command(&spec)?;
    runtime_command(
        &RuntimeSandbox {
            layout: l.layout,
            cowproof_exe: l.cowproof_exe,
            bridge_port: l.bridge_port,
            proxy_socket: l.proxy_socket,
            network: l.network.clone(),
            runner_socket: l.runner_socket,
            port_base: l.port_base,
            unsandboxed: l.unsandboxed,
        },
        l.codex_bin,
        RuntimeProcess {
            args: invocation.args,
            env: invocation.env,
            cwd: invocation.cwd,
            stdin_file: invocation.stdin_file,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Result<CodexConfig> {
        CodexConfig::parse(Some(text))
    }

    fn err(text: &str) -> String {
        format!("{:#}", parse(text).unwrap_err())
    }

    const GOOD: &str = r#"
[runtimes.codex.prices."gpt-6-luna"]
input = 1.25
cached_input = 0.125
output = 10
source = "https://platform.openai.com/docs/pricing, read 2026-10-11"

[runtimes.codex.prices."gpt-6-sol"]
input = 5
output = 20.5
source = "a quote"
"#;

    #[test]
    fn prices_are_read_per_model_with_the_input_price_standing_in_for_a_cached_one() {
        let config = parse(GOOD).unwrap();
        let luna = &config.prices["gpt-6-luna"];
        assert_eq!(
            (luna.input, luna.cached_input, luna.output),
            (1.25, 0.125, 10.0)
        );
        assert_eq!(
            luna.source,
            "https://platform.openai.com/docs/pricing, read 2026-10-11"
        );
        let sol = &config.prices["gpt-6-sol"];
        assert_eq!((sol.input, sol.cached_input, sol.output), (5.0, 5.0, 20.5));
    }

    #[test]
    fn no_file_no_table_and_no_codex_table_mean_no_prices() {
        assert_eq!(CodexConfig::parse(None).unwrap(), CodexConfig::default());
        assert_eq!(
            parse("[ladder]\nrungs = []\n").unwrap(),
            CodexConfig::default()
        );
        assert_eq!(parse("[runtimes]\n").unwrap(), CodexConfig::default());
        assert_eq!(
            parse("[proof]\nrequire_heldout = true\n").unwrap(),
            CodexConfig::default()
        );
    }

    #[test]
    fn a_missing_wrong_or_zero_figure_and_a_missing_source_are_refused_naming_the_model() {
        for (text, needle) in [
            (
                "[runtimes.codex.prices.m]\noutput = 1\nsource = \"s\"\n",
                "no `input`",
            ),
            (
                "[runtimes.codex.prices.m]\ninput = 1\nsource = \"s\"\n",
                "no `output`",
            ),
            (
                "[runtimes.codex.prices.m]\ninput = 1\noutput = 1\n",
                "no `source`",
            ),
            (
                "[runtimes.codex.prices.m]\ninput = 1\noutput = 1\nsource = \"  \"\n",
                "no `source`",
            ),
            (
                "[runtimes.codex.prices.m]\ninput = 0\noutput = 1\nsource = \"s\"\n",
                "more than zero",
            ),
            (
                "[runtimes.codex.prices.m]\ninput = -1\noutput = 1\nsource = \"s\"\n",
                "more than zero",
            ),
            (
                "[runtimes.codex.prices.m]\ninput = \"1\"\noutput = 1\nsource = \"s\"\n",
                "must be a number",
            ),
            (
                "[runtimes.codex.prices.m]\ninput = 1\noutput = 1\ncached_input = -1\nsource = \"s\"\n",
                "zero or more",
            ),
            (
                "[runtimes.codex.prices.m]\ninput = 1\noutputt = 1\noutput = 1\nsource = \"s\"\n",
                "unknown key \"outputt\"",
            ),
            (
                "[runtimes.codex.prices.\"--auto\"]\ninput = 1\noutput = 1\nsource = \"s\"\n",
                "not a model name",
            ),
            ("[runtimes.codex.prices]\nm = 3\n", "must be a table"),
            ("[runtimes.codex]\nprice = {}\n", "unknown key \"price\""),
        ] {
            let message = err(text);
            assert!(message.contains(needle), "{text:?} gave {message}");
        }
        // The message names the model whose entry is wrong.
        assert!(err("[runtimes.codex.prices.m]\ninput = 1\nsource = \"s\"\n").contains("\"m\""));
    }

    #[test]
    fn subscription_mode_is_refused_by_name_citing_the_design() {
        for credential in ["subscription", "chatgpt"] {
            let message = err(&format!(
                "[runtimes.codex]\ncredential = \"{credential}\"\n"
            ));
            assert!(message.contains("API key only"), "{message}");
            assert!(message.contains("D28 clause 6"), "{message}");
        }
        assert!(parse("[runtimes.codex]\ncredential = \"api-key\"\n").is_ok());
        let other = err("[runtimes.codex]\ncredential = \"oauth\"\n");
        assert!(other.contains("must be \"api-key\""), "{other}");
        assert!(err("[runtimes.codex]\ncredential = 3\n").contains("must be \"api-key\""));
    }

    #[test]
    fn every_model_without_a_price_is_named_once() {
        let config = parse(GOOD).unwrap();
        let ok = config
            .price_all(&["gpt-6-luna".to_string(), "gpt-6-sol".to_string()])
            .unwrap();
        assert_eq!(ok.len(), 2);
        let missing = config
            .price_all(&[
                "gpt-6-luna".to_string(),
                "gpt-9".to_string(),
                "gpt-8".to_string(),
            ])
            .unwrap_err();
        assert_eq!(missing.len(), 2);
        assert!(missing[0].contains("\"gpt-9\"") && missing[0].contains("cannot be enforced"));
        assert!(missing[1].contains("\"gpt-8\""));
        // A model id is matched exactly, case included.
        assert!(config.price_all(&["GPT-6-LUNA".to_string()]).is_err());
    }

    fn routing(rungs: &[&str]) -> Routing {
        let list = rungs
            .iter()
            .map(|r| format!("{r:?}"))
            .collect::<Vec<_>>()
            .join(", ");
        Routing::parse(Some(&format!("[ladder]\nrungs = [{list}]\n"))).unwrap()
    }

    #[test]
    fn the_models_to_price_are_the_codex_rungs_from_the_start_up() {
        let ladder = [
            "openrouter:acme/low",
            "codex:gpt-6-luna",
            "claude:sonnet",
            "codex:gpt-6-sol",
        ];
        let at = |first: &str| priced_models(&Rung::parse(first).unwrap(), &routing(&ladder));
        assert_eq!(at("openrouter:acme/low"), ["gpt-6-luna", "gpt-6-sol"]);
        assert_eq!(at("codex:gpt-6-luna"), ["gpt-6-luna", "gpt-6-sol"]);
        assert_eq!(at("claude:sonnet"), ["gpt-6-sol"]);
        // A Claude lane on a ladder with no Codex rung above needs no price at all.
        assert!(
            priced_models(
                &Rung::parse("claude:haiku").unwrap(),
                &routing(&["claude:haiku", "claude:sonnet"])
            )
            .is_empty()
        );
    }

    #[test]
    fn the_native_binary_is_found_beside_an_npm_wrapper_and_only_there() {
        let dir = tempfile::tempdir().unwrap();
        let package = dir.path().join("lib/node_modules/@openai/codex");
        fs::create_dir_all(package.join("bin")).unwrap();
        fs::write(package.join("bin/codex.js"), "#!/usr/bin/env node\n").unwrap();
        let script = package.join("bin/codex.js");
        assert!(is_script(&script));
        assert_eq!(native_beside(&script), None, "no platform package yet");
        let (os, arch, triple) = match (std::env::consts::OS, std::env::consts::ARCH) {
            ("macos", "aarch64") => ("darwin", "arm64", "aarch64-apple-darwin"),
            ("macos", "x86_64") => ("darwin", "x64", "x86_64-apple-darwin"),
            ("linux", "aarch64") => ("linux", "arm64", "aarch64-unknown-linux-musl"),
            ("linux", "x86_64") => ("linux", "x64", "x86_64-unknown-linux-musl"),
            _ => return,
        };
        let native = package
            .join(format!(
                "node_modules/@openai/codex-{os}-{arch}/vendor/{triple}/bin"
            ))
            .join("codex");
        fs::create_dir_all(native.parent().unwrap()).unwrap();
        fs::write(&native, b"\x7fELF").unwrap();
        assert_eq!(native_beside(&script), Some(native.clone()));
        assert!(!is_script(&native));
    }
}
