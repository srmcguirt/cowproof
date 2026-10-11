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

use crate::root::resolve_executable;
use crate::run::{builder_argv, sandboxed_command};
use anyhow::{Context, Result, anyhow, bail};
use cowproof_core::port_block_env;
use cowproof_run::{
    LaneLayout, NetworkMode, SandboxPolicy,
    opencode::{OpencodeSpec, opencode_command, write_lane_files},
    prefix::assemble_prompt,
    proxy::{Provider, ProxyConfig},
};
use std::fs;
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

    let mut invocation = opencode_command(&spec)?;
    invocation.env.push((
        "COWPROOF_RUNNER_SOCKET".to_string(),
        l.runner_socket.to_string_lossy().into_owned(),
    ));
    invocation.env.extend(port_block_env(l.port_base));
    invocation.program = l.opencode_bin.to_string_lossy().into_owned();
    let opencode: Vec<String> = std::iter::once(invocation.program.clone())
        .chain(invocation.args.iter().cloned())
        .collect();
    let argv = builder_argv(l.cowproof_exe, l.bridge_port, l.proxy_socket, &opencode);
    let stdin = fs::File::open(&invocation.stdin_file)
        .with_context(|| format!("opening {}", invocation.stdin_file.display()))?;

    // The builder may execute opencode and cowproof (the bridge wrapper and the MCP server).
    let executables = vec![l.opencode_bin.to_path_buf(), l.cowproof_exe.to_path_buf()];
    let policy =
        SandboxPolicy::builder_with_executables(l.layout, l.network.clone(), &executables)?;
    let mut command = if l.unsandboxed {
        let mut env = invocation.env;
        policy.apply_env(&mut env);
        let mut cmd = Command::new(&argv[0]);
        cmd.args(&argv[1..])
            .env_clear()
            .envs(env)
            .current_dir(&invocation.cwd)
            .kill_on_drop(true);
        cmd
    } else {
        sandboxed_command(
            &policy,
            &l.layout.control.join("builder.sb"),
            &argv,
            invocation.env,
            &invocation.cwd,
        )?
    };
    // The prompt, from a file the runner wrote: the descriptor is opened here, outside the
    // sandbox, so the sandbox needs no grant for the path.
    command.stdin(Stdio::from(stdin));
    command.process_group(0);
    Ok(command)
}
