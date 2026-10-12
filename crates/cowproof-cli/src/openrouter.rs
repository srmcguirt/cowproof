//! The director's side of the `openrouter` runtime (D28, step 2): find OpenCode, read the key,
//! and build the sandboxed OpenCode command.
//!
//! The real OpenRouter key is read once, from the director's `OPENROUTER_API_KEY`, and handed
//! to the egress proxy ([`crate::run::start_proxy`]). It is not a field of anything in this
//! file that reaches the builder: [`OpencodeLaunch`] carries the lane's placeholder only.
//!
//! The proxy's upstream for OpenRouter is `https://openrouter.ai`. The director may replace it
//! with `COWPROOF_OPENROUTER_UPSTREAM` (a test server, a self-hosted gateway). It is read from
//! the environment and never from `cowproof.toml`, because repository content must not be able
//! to redirect the key, and it is written to `run.json` whenever it is set.
//!
//! The same upstream and key serve one more request, the director's own: at preflight,
//! `GET <upstream>/api/v1/models` gives the exact price of every OpenRouter model the lane could
//! run ([`cowproof_run::models`]). That request does not go through the lane's proxy.

use crate::root::resolve_executable;
use crate::run::{RuntimeProcess, RuntimeSandbox, runtime_command};
use anyhow::{Context, Result, anyhow, bail};
use cowproof_core::{Routing, Rung, Runtime};
use cowproof_run::{
    LaneLayout, NetworkMode,
    models::{DEFAULT_TIMEOUT, ModelPrice},
    opencode::{OpencodeSpec, opencode_command, write_lane_files},
    prefix::assemble_prompt,
    proxy::{Provider, ProxyConfig},
};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;

/// The director's environment variable that holds the real key.
pub(crate) const KEY_ENV: &str = "OPENROUTER_API_KEY";
/// The director-side override of the OpenRouter upstream.
pub(crate) const UPSTREAM_ENV: &str = "COWPROOF_OPENROUTER_UPSTREAM";
/// OpenRouter's API host.
pub(crate) const DEFAULT_UPSTREAM: &str = "https://openrouter.ai";

/// TEST-ONLY: the director's environment variable that replaces the 15 s limit on the model-list
/// request, in milliseconds, so a test of a hanging upstream does not take 15 s. Nothing
/// documented for users sets it.
pub(crate) const MODELS_TIMEOUT_ENV: &str = "COWPROOF_OPENROUTER_MODELS_TIMEOUT_MS";

/// How long `opencode --version` may take.
const VERSION_TIMEOUT: Duration = Duration::from_secs(30);

/// The real OpenRouter key: `None` when the variable is unset or empty. A value that is not
/// UTF-8 is an error that never shows the value.
pub(crate) fn real_key() -> Result<Option<String>> {
    match std::env::var_os(KEY_ENV) {
        Some(k) if !k.is_empty() => k
            .into_string()
            .map(Some)
            .map_err(|_| anyhow!("{KEY_ENV} is not valid UTF-8")),
        _ => Ok(None),
    }
}

/// The OpenRouter upstream the proxy forwards to, and whether the director replaced it.
/// A replacement that is not a usable `http(s)` base URL is an error.
pub(crate) fn upstream() -> Result<(String, bool)> {
    match std::env::var_os(UPSTREAM_ENV) {
        Some(v) if !v.is_empty() => {
            let url = v
                .into_string()
                .map_err(|_| anyhow!("{UPSTREAM_ENV} is not valid UTF-8"))?;
            // The proxy's own parser decides what a usable base URL is. A throwaway key is
            // enough for that; it is dropped at once.
            ProxyConfig::for_provider(Provider::Openrouter, "x", url.clone())
                .with_context(|| format!("{UPSTREAM_ENV} is not usable"))?;
            Ok((url, true))
        }
        _ => Ok((DEFAULT_UPSTREAM.to_string(), false)),
    }
}

/// How long the model-list request may take: 15 s, or [`MODELS_TIMEOUT_ENV`] (test-only).
pub(crate) fn models_timeout() -> Result<Duration> {
    match std::env::var_os(MODELS_TIMEOUT_ENV) {
        Some(v) if !v.is_empty() => {
            let text = v
                .into_string()
                .map_err(|_| anyhow!("{MODELS_TIMEOUT_ENV} is not valid UTF-8"))?;
            parse_timeout(&text)
        }
        _ => Ok(DEFAULT_TIMEOUT),
    }
}

fn parse_timeout(text: &str) -> Result<Duration> {
    match text.parse::<u64>() {
        Ok(ms) if ms > 0 => Ok(Duration::from_millis(ms)),
        _ => bail!("{MODELS_TIMEOUT_ENV} must be a positive number of milliseconds"),
    }
}

/// The model ids of `runtime` that a lane which starts on `first` could run: `first` itself
/// and every rung above it on the ladder, where a `reassign` can land. Each id once, in ladder
/// order. A rung off the ladder is followed by nothing (`reassign` without a model has nowhere
/// to go). The runtimes that need a price (`openrouter`, `codex`) price exactly these.
pub(crate) fn models_on_or_above(runtime: Runtime, first: &Rung, routing: &Routing) -> Vec<String> {
    let mut rungs = vec![first];
    if let Some(at) = routing.position(first) {
        rungs.extend(&routing.rungs[at + 1..]);
    }
    let mut models: Vec<String> = Vec::new();
    for rung in rungs {
        if rung.runtime == runtime && !models.contains(&rung.model) {
            models.push(rung.model.clone());
        }
    }
    models
}

/// The OpenRouter model ids a lane that starts on `first` could run (see [`models_on_or_above`]).
pub(crate) fn priced_models(first: &Rung, routing: &Routing) -> Vec<String> {
    models_on_or_above(Runtime::Openrouter, first, routing)
}

/// An OpenCode executable the runner can launch.
#[derive(Debug, Clone)]
pub(crate) struct Opencode {
    /// Absolute and canonical.
    pub bin: PathBuf,
    /// The first line `--version` printed.
    pub version: String,
}

/// Find OpenCode on the director's `PATH` (or as a path relative to `cwd`) and ask its version.
/// The error is a line for the preflight to print. The environment is cleared first, so no key
/// reaches the process.
pub(crate) async fn locate(
    name: &str,
    director_path: &str,
    cwd: &Path,
) -> Result<Opencode, String> {
    let found = resolve_executable(name, director_path, cwd).map_err(|e| format!("{e}"))?;
    let bin = found
        .canonicalize()
        .map_err(|e| format!("cannot resolve {}: {e}", found.display()))?;
    let mut command = Command::new(&bin);
    command
        .arg("--version")
        .env_clear()
        .env("PATH", director_path)
        .stdin(Stdio::null())
        .kill_on_drop(true);
    if let Some(home) = std::env::var_os("HOME") {
        command.env("HOME", home);
    }
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
            Ok(Opencode { bin, version })
        }
    }
}

/// Everything that decides one OpenCode launch.
pub(crate) struct OpencodeLaunch<'a> {
    pub layout: &'a LaneLayout,
    pub opencode_bin: &'a Path,
    pub cowproof_exe: &'a Path,
    pub path: &'a str,
    /// The in-sandbox bridge, `http://127.0.0.1:<port>`.
    pub base_url: &'a str,
    pub bridge_port: u16,
    pub proxy_socket: &'a Path,
    pub placeholder_key: &'a str,
    pub network: NetworkMode,
    pub max_turns: u32,
    /// The builder tools socket, canonical (`COWPROOF_RUNNER_SOCKET`).
    pub runner_socket: &'a Path,
    pub port_base: u16,
    /// The OpenRouter model id.
    pub model: &'a str,
    /// Its price and limits from OpenRouter's model list.
    pub price: ModelPrice,
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

/// The builder's command for an OpenRouter rung: the bridge wrapper, then OpenCode, under the
/// builder sandbox policy with exactly the lane's environment. Not yet started. Writes the
/// config, the system instructions and the prompt into the lane home first; a launch does so
/// before EVERY start. The prompt file is the command's stdin.
pub(crate) fn opencode_builder_command(l: &OpencodeLaunch<'_>) -> Result<Command> {
    if !l.opencode_bin.is_absolute() {
        bail!("the opencode executable path is not absolute");
    }
    let home = &l.layout.home;
    let spec = OpencodeSpec {
        lane: l.layout.clone(),
        model: l.model.to_string(),
        price: l.price,
        proxy_base_url: l.base_url.to_string(),
        placeholder_key: l.placeholder_key.to_string(),
        config_file: home.join("opencode.json"),
        prompt_file: home.join("prompt.md"),
        system_prompt_file: home.join("system-prompt.md"),
        cowproof_exe: l.cowproof_exe.to_path_buf(),
        runner_socket: l.runner_socket.to_path_buf(),
        resume_session_id: l.resume.map(str::to_string),
        max_turns: l.max_turns,
        path: l.path.to_string(),
    };
    let assembled = assemble_prompt(l.project_instructions, l.packet);
    write_lane_files(&spec, &assembled.system_append, l.prompt)?;

    let invocation = opencode_command(&spec)?;
    runtime_command(
        &RuntimeSandbox {
            layout: l.layout,
            cowproof_exe: l.cowproof_exe,
            bridge_port: l.bridge_port,
            proxy_socket: l.proxy_socket,
            network: l.network.clone(),
            runner_socket: l.runner_socket,
            port_base: l.port_base,
            deny: &[],
            unsandboxed: l.unsandboxed,
        },
        l.opencode_bin,
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

    fn routing(rungs: &[&str]) -> Routing {
        let list = rungs
            .iter()
            .map(|r| format!("{r:?}"))
            .collect::<Vec<_>>()
            .join(", ");
        Routing::parse(Some(&format!("[ladder]\nrungs = [{list}]\n"))).unwrap()
    }

    fn models(first: &str, rungs: &[&str]) -> Vec<String> {
        priced_models(&Rung::parse(first).unwrap(), &routing(rungs))
    }

    #[test]
    fn the_models_to_price_are_the_start_rung_and_every_openrouter_rung_above_it() {
        let ladder = [
            "openrouter:acme/low",
            "claude:haiku",
            "openrouter:acme/mid",
            "claude:sonnet",
            "openrouter:acme/low-2",
        ];
        assert_eq!(
            models("openrouter:acme/low", &ladder),
            ["acme/low", "acme/mid", "acme/low-2"]
        );
        // A rung below the start is not reachable by reassign.
        assert_eq!(models("claude:haiku", &ladder), ["acme/mid", "acme/low-2"]);
        assert_eq!(models("claude:sonnet", &ladder), ["acme/low-2"]);
        // The top has nothing above it; a Claude lane on a ladder with no OpenRouter rung needs
        // no price at all.
        assert!(models("claude:haiku", &["claude:haiku", "claude:sonnet"]).is_empty());
        assert!(models("claude:opus", &["claude:haiku", "openrouter:acme/low"]).is_empty());
    }

    #[test]
    fn a_start_rung_off_the_ladder_is_priced_alone_and_a_model_is_listed_once() {
        let ladder = ["claude:haiku", "openrouter:acme/low", "claude:sonnet"];
        assert_eq!(models("openrouter:acme/other", &ladder), ["acme/other"]);
        // The same model twice (on the flag and as the rung above): one id.
        assert_eq!(
            models(
                "openrouter:acme/low",
                &["openrouter:acme/low", "openrouter:acme/hi"]
            ),
            ["acme/low", "acme/hi"]
        );
    }

    #[test]
    fn the_models_timeout_is_a_positive_number_of_milliseconds() {
        assert_eq!(parse_timeout("1500").unwrap(), Duration::from_millis(1500));
        for bad in ["0", "-5", "soon", "1.5", ""] {
            assert!(parse_timeout(bad).is_err(), "{bad:?}");
        }
        assert_eq!(DEFAULT_TIMEOUT, Duration::from_secs(15));
    }
}
