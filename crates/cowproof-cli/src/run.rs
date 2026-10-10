//! `cowproof run <packet.md>`: the single-packet flow (D2, D19, D20, D22, D24).
//!
//! Order matters, and each step fails before the next one creates anything:
//!
//! 1. lint the packet (errors stop the run before any lane exists);
//! 2. read the real key from the director's `ANTHROPIC_API_KEY` and resolve
//!    the Claude Code executable once on the director's `PATH`;
//! 3. prepare the lane (isolated clone, launch baseline);
//! 4. start the egress proxy ([`start_proxy`], the one place the builder's
//!    endpoint is decided) and bind the builder tools socket, both BEFORE the
//!    builder starts (the Linux policy binds a socket only when the file
//!    exists, so a late bind would leave the builder without it, silently);
//! 5. launch the builder inside `SandboxPolicy::builder`, feeding its stdout
//!    to the stream meter and to `control/stream.jsonl`;
//! 6. stop the tools server and the proxy, capture `control/lane.patch` and
//!    write `control/run.json`.
//!
//! Every child process started here gets an explicit environment
//! (`env_clear`), so the director's `ANTHROPIC_API_KEY` is never inherited:
//! the builder sees only the proxy's placeholder key.

use anyhow::{Context, Result, anyhow, bail};
use cowproof_core::parse_header;
use cowproof_run::{
    LaneLayout, NetworkMode, SandboxPolicy,
    claude::{ClaudeSpec, claude_command},
    escalate::{Queue, SystemClock},
    lane::{PrepareOptions, prepare_lane},
    prefix::assemble_prompt,
    proxy::{ProxyConfig, ProxyServer},
    render_macos_profile, sandbox_command,
    stream::StreamMeter,
    tools::{self, CheckOutcome, CheckTable, RunCheck},
};
use serde_json::json;
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::process::Command;
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;

/// The provider the proxy forwards to.
const UPSTREAM: &str = "https://api.anthropic.com";

/// Where the builder is pointed on Linux until the D24 bridge exists. Nothing
/// listens here (port 0 is never connectable), so a Linux builder fails fast
/// instead of reaching some other local service.
const LINUX_UNBRIDGED_URL: &str = "http://127.0.0.1:0";

/// The longest one `run_check` may run before it is killed.
const CHECK_TIMEOUT: Duration = Duration::from_secs(20 * 60);

/// The longest builder stdout line the meter will parse, in bytes. A longer
/// line is still written to `stream.jsonl`, whole, but is not metered.
const MAX_STREAM_LINE: usize = 64 * 1024 * 1024;

/// What the builder is allowed to use, per R15 ("tool permissions are set
/// explicitly per policy; the OS sandbox is the boundary"). Web tools are
/// denied: the lane has no network except the proxy.
const BUILDER_ALLOW: [&str; 7] = [
    "Bash",
    "Read",
    "Edit",
    "Write",
    "Glob",
    "Grep",
    "mcp__cowproof-tools",
];
const BUILDER_DENY: [&str; 2] = ["WebFetch", "WebSearch"];

/// A running egress proxy and what the builder needs to reach it.
pub struct ProxyEndpoint {
    /// `ANTHROPIC_BASE_URL` for the builder.
    pub base_url: String,
    /// The network mode for the builder's sandbox policy.
    pub network: NetworkMode,
    /// The key the builder presents; the proxy swaps in the real one.
    pub placeholder_key: String,
    /// The serving task. Abort it when the lane ends.
    pub task: JoinHandle<()>,
}

/// Start the egress proxy for one lane.
///
/// This is the only place that decides how the builder reaches the proxy, so
/// the D24 in-sandbox bridge replaces exactly this function.
///
/// - macOS: a `127.0.0.1` TCP port chosen by the OS (the sandbox allows that
///   one port).
/// - Linux: a Unix socket at `<lane>/proxy.sock`. The builder's network
///   namespace is empty and no bridge exists yet, so a real builder cannot
///   reach it; a warning says so.
///
/// The real key goes only into the proxy's memory.
pub async fn start_proxy(layout: &LaneLayout, real_api_key: String) -> Result<ProxyEndpoint> {
    start_proxy_on(layout, real_api_key, cfg!(target_os = "macos")).await
}

async fn start_proxy_on(
    layout: &LaneLayout,
    real_api_key: String,
    tcp: bool,
) -> Result<ProxyEndpoint> {
    let config =
        ProxyConfig::new(real_api_key, UPSTREAM).context("configuring the egress proxy")?;
    let placeholder_key = config.placeholder_key().to_string();
    let server = ProxyServer::new(config);
    let socket = lane_dir(layout)?.join("proxy.sock");

    if tcp {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .context("binding the egress proxy port")?;
        let port = listener.local_addr()?.port();
        let task = tokio::spawn(async move {
            if let Err(e) = server.serve_tcp(listener).await {
                eprintln!("egress proxy stopped: {e:#}");
            }
        });
        Ok(ProxyEndpoint {
            base_url: format!("http://127.0.0.1:{port}"),
            network: NetworkMode::Proxy { port, socket },
            placeholder_key,
            task,
        })
    } else {
        let listener = tools::bind(&socket).context("binding the egress proxy socket")?;
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))
            .context("restricting the egress proxy socket")?;
        eprintln!(
            "warning: no in-sandbox bridge yet (D24): the Linux builder cannot reach the egress proxy at {}",
            socket.display()
        );
        let task = tokio::spawn(async move {
            if let Err(e) = server.serve_unix(listener).await {
                eprintln!("egress proxy stopped: {e:#}");
            }
        });
        Ok(ProxyEndpoint {
            base_url: LINUX_UNBRIDGED_URL.to_string(),
            network: NetworkMode::Proxy { port: 0, socket },
            placeholder_key,
            task,
        })
    }
}

/// Aborts a task when dropped, so no exit path leaves a server running.
struct AbortOnDrop(JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// The lane directory: the parent of the clone.
fn lane_dir(layout: &LaneLayout) -> Result<PathBuf> {
    layout
        .clone
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| anyhow!("lane clone {} has no parent", layout.clone.display()))
}

/// Resolve an executable once. A bare name is searched on `path` (absolute,
/// non-empty entries only: an empty entry means the current directory). The
/// result is absolute but not canonicalized, so a symlinked install keeps its
/// own name.
fn resolve_executable(name: &str, path: &str, cwd: &Path) -> Result<PathBuf> {
    let is_executable = |p: &Path| {
        fs::metadata(p)
            .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    };
    let candidates: Vec<PathBuf> = if name.contains('/') {
        vec![cwd.join(name)]
    } else {
        path.split(':')
            .filter(|d| !d.is_empty() && Path::new(d).is_absolute())
            .map(|d| Path::new(d).join(name))
            .collect()
    };
    candidates
        .into_iter()
        .find(|c| is_executable(c))
        .ok_or_else(|| anyhow!("cannot find an executable {name:?} on the director's PATH"))
}

/// The builder's `PATH`: the director's, minus empty, relative and
/// real-home entries (the home is hidden from the sandbox, and an empty entry
/// would search the builder's clone).
fn builder_path(director_path: &str, real_home: &Path) -> String {
    let kept: Vec<&str> = director_path
        .split(':')
        .filter(|e| {
            !e.is_empty() && Path::new(e).is_absolute() && !Path::new(e).starts_with(real_home)
        })
        .collect();
    if kept.is_empty() {
        "/usr/bin:/bin".to_string()
    } else {
        kept.join(":")
    }
}

fn platform() -> &'static str {
    if cfg!(target_os = "macos") {
        "darwin"
    } else {
        "linux"
    }
}

/// A command that runs `argv` under `policy`, with exactly `env` (plus the
/// policy's own variables) and nothing inherited.
fn sandboxed_command(
    policy: &SandboxPolicy,
    profile: &Path,
    argv: &[String],
    mut env: Vec<(String, String)>,
    cwd: &Path,
) -> Result<Command> {
    policy.apply_env(&mut env);
    if cfg!(target_os = "macos") {
        fs::write(profile, render_macos_profile(policy)?)
            .with_context(|| format!("writing {}", profile.display()))?;
    }
    let (program, args) = sandbox_command(policy, profile, argv, platform())?;
    let mut command = Command::new(program);
    command
        .args(args)
        .env_clear()
        .envs(env)
        .current_dir(cwd)
        .stdin(Stdio::null())
        .kill_on_drop(true);
    Ok(command)
}

/// What `run_check` needs, shared by every call of one lane.
struct CheckContext {
    layout: LaneLayout,
    path: String,
    commands: BTreeMap<String, String>,
    /// One check at a time per lane (a builder can open several connections).
    slot: Semaphore,
}

fn refused(output: impl Into<String>) -> CheckOutcome {
    CheckOutcome {
        exit_status: -1,
        output: output.into(),
    }
}

/// Run one declared check in a fresh `SandboxPolicy::run_check` sandbox.
/// Fails closed: if the sandbox cannot be built, nothing runs.
async fn run_declared_check(ctx: Arc<CheckContext>, id: String) -> CheckOutcome {
    let Some(command) = ctx.commands.get(&id) else {
        return refused(format!("no command is declared for check {id:?}"));
    };
    let Ok(_slot) = ctx.slot.acquire().await else {
        return refused("the check queue is closed");
    };
    let policy = SandboxPolicy::run_check(&ctx.layout);
    let argv = ["/bin/sh".to_string(), "-c".to_string(), command.clone()];
    let env = vec![
        ("PATH".to_string(), ctx.path.clone()),
        (
            "HOME".to_string(),
            ctx.layout.home.to_string_lossy().into_owned(),
        ),
    ];
    let mut child = match sandboxed_command(
        &policy,
        &ctx.layout.control.join("run_check.sb"),
        &argv,
        env,
        &ctx.layout.clone,
    ) {
        Ok(c) => c,
        Err(e) => return refused(format!("sandbox unavailable: {e:#}")),
    };
    match tokio::time::timeout(CHECK_TIMEOUT, child.output()).await {
        Err(_) => refused(format!("check {id:?} timed out after {CHECK_TIMEOUT:?}")),
        Ok(Err(e)) => refused(format!("could not start check {id:?}: {e}")),
        Ok(Ok(out)) => {
            let mut output = String::from_utf8_lossy(&out.stdout).into_owned();
            output.push_str(&String::from_utf8_lossy(&out.stderr));
            CheckOutcome {
                exit_status: out.status.code().unwrap_or(-1),
                output,
            }
        }
    }
}

/// What reading the builder's stdout saw.
#[derive(Debug, Default, PartialEq, Eq)]
struct PumpStats {
    /// Lines fed to the meter that it accepted.
    metered: u64,
    /// Lines the meter rejected (not JSON).
    unparsed: u64,
    /// Lines longer than the limit, written but not metered.
    oversized: u64,
}

/// Copy `reader` to `sink` byte for byte and feed each complete line to the
/// meter. Memory per line is bounded by `max_line`.
async fn pump_stream<R, W>(
    reader: R,
    sink: &mut W,
    meter: &mut StreamMeter,
    max_line: usize,
) -> io::Result<PumpStats>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut reader = BufReader::new(reader);
    let mut stats = PumpStats::default();
    let mut buf: Vec<u8> = Vec::new();
    let mut mid_oversized = false;
    loop {
        buf.clear();
        let n = (&mut reader)
            .take(max_line as u64)
            .read_until(b'\n', &mut buf)
            .await?;
        if n == 0 {
            break;
        }
        sink.write_all(&buf).await?;
        // A full buffer without a newline is a fragment of a longer line.
        let fragment = !buf.ends_with(b"\n") && n >= max_line;
        if fragment || mid_oversized {
            if !mid_oversized {
                stats.oversized += 1;
            }
            mid_oversized = fragment;
            continue;
        }
        let text = String::from_utf8_lossy(&buf);
        let line = text.trim_end_matches(['\n', '\r']);
        if line.trim().is_empty() {
            continue;
        }
        match meter.feed(line) {
            Ok(_) => stats.metered += 1,
            Err(_) => stats.unparsed += 1,
        }
    }
    sink.flush().await?;
    Ok(stats)
}

/// `control/lane.patch`: everything the builder changed since the launch
/// baseline, including new files.
///
/// The builder owns the clone's `.git` (config, attributes), and git can run
/// programs named there (`core.fsmonitor`, clean filters), so both git
/// commands run inside the `run_check` sandbox, never in the runner's own
/// privileges.
async fn capture_patch(layout: &LaneLayout, launch_commit: &str, path: &str) -> Result<Vec<u8>> {
    let policy = SandboxPolicy::run_check(layout);
    let profile = layout.control.join("capture.sb");
    let env = vec![
        ("PATH".to_string(), path.to_string()),
        (
            "HOME".to_string(),
            layout.home.to_string_lossy().into_owned(),
        ),
        ("GIT_CONFIG_NOSYSTEM".to_string(), "1".to_string()),
        ("GIT_CONFIG_GLOBAL".to_string(), "/dev/null".to_string()),
        ("GIT_TERMINAL_PROMPT".to_string(), "0".to_string()),
        ("LC_ALL".to_string(), "C".to_string()),
    ];
    let git = |rest: &[&str]| -> Vec<String> {
        [
            "git",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
        ]
        .into_iter()
        .chain(rest.iter().copied())
        .map(String::from)
        .collect()
    };
    for (what, argv) in [
        ("staging the builder's changes", git(&["add", "-A"])),
        (
            "computing the lane patch",
            git(&[
                "diff",
                "--cached",
                "--binary",
                "--no-ext-diff",
                "--no-textconv",
                launch_commit,
            ]),
        ),
    ] {
        let out = sandboxed_command(&policy, &profile, &argv, env.clone(), &layout.clone)?
            .output()
            .await
            .with_context(|| what.to_string())?;
        if !out.status.success() {
            bail!(
                "{what} failed ({}): {}",
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        if argv.contains(&"diff".to_string()) {
            return Ok(out.stdout);
        }
    }
    unreachable!("the diff step returns")
}

pub async fn run_one(args: super::RunOneArgs) -> Result<()> {
    let started = Instant::now();
    let cwd = std::env::current_dir().context("reading the current directory")?;

    // 1. Lint first: errors stop the run before any lane exists.
    let packet_path = cwd.join(&args.packet);
    let packet_text = fs::read_to_string(&packet_path)
        .with_context(|| format!("reading packet {}", packet_path.display()))?;
    let repo = cwd.join(args.repo.as_deref().unwrap_or(Path::new(".")));
    let repo = repo
        .canonicalize()
        .with_context(|| format!("opening repository {}", repo.display()))?;
    let plans = cowproof_plan::load_plans(&repo, &[])?;
    let findings = cowproof_lint::lint_packet(&packet_text, &repo, &plans);
    for finding in &findings {
        eprintln!("{finding}");
    }
    if findings
        .iter()
        .any(|f| f.severity == cowproof_lint::Severity::Error)
    {
        bail!("packet lint found errors");
    }
    let header = parse_header(&packet_text)?;
    let checks = &header.checks;
    if checks.is_empty() {
        eprintln!("warning: the packet declares no checks, so run_check will refuse every id");
    }

    // 2. The real key lives in this process and the proxy, nowhere else.
    let api_key = match std::env::var_os("ANTHROPIC_API_KEY") {
        Some(k) if !k.is_empty() => k
            .into_string()
            .map_err(|_| anyhow!("ANTHROPIC_API_KEY is not valid UTF-8"))?,
        _ => bail!("ANTHROPIC_API_KEY is not set; the proxy needs the real key"),
    };
    let director_path = std::env::var("PATH").unwrap_or_default();
    let claude_bin = resolve_executable(&args.claude_bin, &director_path, &cwd)?;
    let real_home =
        PathBuf::from(std::env::var_os("HOME").ok_or_else(|| anyhow!("HOME is not set"))?);
    let lanes_root = match args.lanes_root {
        Some(p) => cwd.join(p),
        None => real_home.join(".cache/cowproof/lanes"),
    };
    let path = builder_path(&director_path, &real_home);
    let claude_bin = claude_bin
        .canonicalize()
        .context("resolving the claude executable")?;
    let cowproof_exe = std::env::current_exe()
        .and_then(|p| p.canonicalize())
        .context("locating the cowproof executable")?;

    // 3. The lane.
    fs::create_dir_all(&lanes_root)
        .with_context(|| format!("creating {}", lanes_root.display()))?;
    let lanes_root = lanes_root.canonicalize()?;
    let prepared = prepare_lane(
        &repo,
        &lanes_root,
        &header.id,
        PrepareOptions {
            allow_dirty: args.allow_dirty,
        },
    )?;
    let layout = prepared.layout.clone();
    let lane = lane_dir(&layout)?;
    eprintln!("[{}] lane {}", header.id, lane.display());

    // 4. Proxy and tools, both live before the builder starts.
    let endpoint = start_proxy(&layout, api_key).await?;
    let _proxy = AbortOnDrop(endpoint.task);
    let queue = Arc::new(Mutex::new(
        Queue::new(&layout.control, Box::new(SystemClock))
            .context("opening the escalation queue")?,
    ));
    let tools_listener = tools::bind(&layout.sock).context("binding the builder tools socket")?;
    let socket = layout
        .sock
        .canonicalize()
        .context("resolving the tools socket")?;
    let table: CheckTable = checks.iter().map(|c| c.id.clone()).collect();
    let context = Arc::new(CheckContext {
        layout: layout.clone(),
        path: path.clone(),
        commands: checks
            .iter()
            .map(|c| (c.id.clone(), c.command.clone()))
            .collect(),
        slot: Semaphore::new(1),
    });
    let run_check: RunCheck =
        Arc::new(move |id: &str| Box::pin(run_declared_check(context.clone(), id.to_string())));
    let _tools = AbortOnDrop(tokio::spawn({
        let lane_id = header.id.clone();
        async move {
            if let Err(e) = tools::serve(tools_listener, lane_id, queue, table, run_check).await {
                eprintln!("builder tools stopped: {e}");
            }
        }
    }));

    // The builder's configuration (rewritten at every launch: home is
    // writable by the builder, so a resume must never trust these files).
    let settings_file = layout.home.join("settings.json");
    fs::write(
        &settings_file,
        serde_json::to_vec_pretty(&json!({
            "permissions": {"allow": BUILDER_ALLOW, "deny": BUILDER_DENY}
        }))?,
    )?;
    let mcp_config = layout.home.join("mcp.json");
    fs::write(
        &mcp_config,
        serde_json::to_vec_pretty(&json!({
            "mcpServers": {
                "cowproof-tools": {
                    "type": "stdio",
                    "command": cowproof_exe,
                    "args": ["lane-tools", "--socket", socket],
                }
            }
        }))?,
    )?;
    let project_instructions = fs::read_to_string(repo.join("CLAUDE.md")).ok();
    let assembled = assemble_prompt(project_instructions.as_deref(), &packet_text);
    let system_prompt = layout.home.join("system-prompt.md");
    fs::write(&system_prompt, &assembled.system_append)?;

    // 5. Launch inside the builder sandbox.
    let mut invocation = claude_command(&ClaudeSpec {
        lane: layout.clone(),
        model: args.model.clone(),
        proxy_base_url: endpoint.base_url,
        placeholder_key: endpoint.placeholder_key,
        settings_file,
        mcp_config,
        append_system_prompt_file: system_prompt,
        prompt: assembled.prompt,
        max_turns: args.max_turns,
        resume_session_id: None,
        cache_ttl: "1h".to_string(),
        path: path.clone(),
    })?;
    invocation.program = claude_bin.to_string_lossy().into_owned();
    let argv: Vec<String> = std::iter::once(invocation.program.clone())
        .chain(invocation.args.iter().cloned())
        .collect();
    let policy = SandboxPolicy::builder_with_executables(
        &layout,
        endpoint.network,
        &[claude_bin.clone(), cowproof_exe.clone()],
    )?;
    let stderr_file = fs::File::create(layout.control.join("builder.stderr"))?;
    let mut child = sandboxed_command(
        &policy,
        &layout.control.join("builder.sb"),
        &argv,
        invocation.env,
        &invocation.cwd,
    )?
    .stdout(Stdio::piped())
    .stderr(Stdio::from(stderr_file))
    .spawn()
    .context("launching the builder in its sandbox")?;
    let stdout = child.stdout.take().context("taking the builder's stdout")?;

    let mut meter = StreamMeter::new(false);
    let mut stream = tokio::fs::File::create(layout.control.join("stream.jsonl")).await?;
    let pumped = pump_stream(stdout, &mut stream, &mut meter, MAX_STREAM_LINE).await;
    let status = child.wait().await.context("waiting for the builder")?;
    let stats = pumped.context("reading the builder's stream")?;

    // 6. The lane is over: stop serving, then capture.
    drop(_tools);
    drop(_proxy);
    let patch = capture_patch(&layout, &prepared.launch_commit, &path).await;
    let patch_path = layout.control.join("lane.patch");
    let patch_bytes = match &patch {
        Ok(bytes) => {
            fs::write(&patch_path, bytes)?;
            Some(bytes.len())
        }
        Err(_) => None,
    };

    let summary = meter.summary();
    let run = json!({
        "id": header.id,
        "status": if status.success() { "finished" } else { "failed" },
        "exitCode": status.code(),
        "signal": status.signal(),
        "model": args.model,
        "turns": summary.turns.len(),
        "sessionId": summary.session_id,
        "meter": summary,
        "stream": {
            "metered": stats.metered,
            "unparsed": stats.unparsed,
            "oversized": stats.oversized,
        },
        "baseCommit": prepared.base_commit,
        "launchCommit": prepared.launch_commit,
        "patchBytes": patch_bytes,
        "patchError": patch.as_ref().err().map(|e| format!("{e:#}")),
        "durationMs": started.elapsed().as_millis() as u64,
        "lane": {
            "dir": lane,
            "clone": layout.clone,
            "control": layout.control,
            "stream": layout.control.join("stream.jsonl"),
            "patch": patch_path,
            "stderr": layout.control.join("builder.stderr"),
        },
    });
    fs::write(
        layout.control.join("run.json"),
        serde_json::to_vec_pretty(&run)?,
    )?;

    println!(
        "{}: {}, exit {}, {} turns, patch {} bytes, lane {}",
        header.id,
        run["status"].as_str().unwrap_or("unknown"),
        status
            .code()
            .map_or_else(|| "signal".to_string(), |c| c.to_string()),
        run["turns"],
        patch_bytes.map_or_else(|| "none".to_string(), |n| n.to_string()),
        lane.display()
    );
    patch?;
    if !status.success() {
        bail!("the builder exited with {status}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn layout_in(dir: &Path) -> LaneLayout {
        LaneLayout {
            clone: dir.join("lane/clone"),
            home: dir.join("lane/home"),
            scratch: dir.join("lane/scratch"),
            control: dir.join("lane/control"),
            real_home: dir.join("realhome"),
            sock: dir.join("lane/sock/runner.sock"),
            lanes_root: dir.to_path_buf(),
        }
    }

    #[test]
    fn header_checks_parses_ids_and_commands() {
        let packet = r#"# T
<!-- lane {"id":"test-id","owns":["a"],"checks":[{"id":"unit","command":"cargo test"},{"id":"fmt-all","command":"cargo fmt --check"}]} -->
body"#;
        let header = parse_header(packet).unwrap();
        assert_eq!(header.checks.len(), 2);
        assert_eq!(header.checks[0].id, "unit");
        assert_eq!(header.checks[0].command, "cargo test");
        assert!(!header.checks[0].flaky);
        assert_eq!(header.checks[1].id, "fmt-all");
        assert_eq!(header.checks[1].command, "cargo fmt --check");
        assert!(!header.checks[1].flaky);

        let none = r#"<!-- lane {"id":"test-id2","owns":["a"]} -->"#;
        let header = parse_header(none).unwrap();
        assert!(header.checks.is_empty());
    }

    #[test]
    fn header_checks_defaults_flaky_to_false() {
        let packet = r#"<!-- lane {"id":"test-id3","owns":["a"],"checks":[{"id":"c1","command":"cargo test"}]} -->"#;
        let header = parse_header(packet).unwrap();
        assert!(!header.checks[0].flaky);
    }

    #[test]
    fn builder_path_drops_empty_relative_and_home_entries() {
        let home = Path::new("/opt/home");
        assert_eq!(
            builder_path(
                "/usr/bin::rel/bin:/opt/home/.cargo/bin:/bin:/opt/homex/bin",
                home
            ),
            "/usr/bin:/bin:/opt/homex/bin"
        );
        assert_eq!(builder_path("::relative", home), "/usr/bin:/bin");
    }

    #[test]
    fn resolve_executable_searches_only_absolute_entries_and_needs_the_exec_bit() {
        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join("bin");
        fs::create_dir(&bin).unwrap();
        let tool = bin.join("tool");
        fs::write(&tool, "#!/bin/sh\n").unwrap();
        let path = format!(":rel:{}", bin.display());
        // Not executable yet.
        assert!(resolve_executable("tool", &path, tmp.path()).is_err());
        fs::set_permissions(&tool, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(resolve_executable("tool", &path, tmp.path()).unwrap(), tool);
        // An empty or relative entry never counts: the cwd has a "tool" too.
        fs::copy(&tool, tmp.path().join("tool")).unwrap();
        assert!(resolve_executable("tool", ":rel", tmp.path()).is_err());
        // A symlinked install keeps its own name.
        let link = bin.join("link");
        symlink(&tool, &link).unwrap();
        assert_eq!(resolve_executable("link", &path, tmp.path()).unwrap(), link);
        // A path with a slash is taken relative to the cwd.
        assert_eq!(
            resolve_executable("bin/tool", "", tmp.path()).unwrap(),
            tmp.path().join("bin/tool")
        );
    }

    #[tokio::test]
    async fn pump_stream_copies_bytes_exactly_and_meters_whole_lines() {
        let input: &[u8] = b"{\"type\":\"system\",\"session_id\":\"s1\"}\r\n\nnot json\n{\"type\":\"result\",\"subtype\":\"success\",\"result\":\"ok\"}";
        let mut sink: Vec<u8> = Vec::new();
        let mut meter = StreamMeter::new(false);
        let stats = pump_stream(input, &mut sink, &mut meter, 1024)
            .await
            .unwrap();
        assert_eq!(sink, input);
        assert_eq!(
            stats,
            PumpStats {
                metered: 2,
                unparsed: 1,
                oversized: 0
            }
        );
        assert_eq!(meter.summary().session_id.as_deref(), Some("s1"));
    }

    #[tokio::test]
    async fn pump_stream_writes_but_does_not_meter_an_oversized_line() {
        let long = format!(
            "{{\"type\":\"system\",\"session_id\":\"{}\"}}",
            "x".repeat(200)
        );
        let input = format!("{long}\n{{\"type\":\"system\",\"session_id\":\"after\"}}\n");
        let mut sink: Vec<u8> = Vec::new();
        let mut meter = StreamMeter::new(false);
        let stats = pump_stream(input.as_bytes(), &mut sink, &mut meter, 64)
            .await
            .unwrap();
        assert_eq!(sink, input.as_bytes());
        assert_eq!(
            stats,
            PumpStats {
                metered: 1,
                unparsed: 0,
                oversized: 1
            }
        );
        // Only the short line after the long one was metered.
        assert_eq!(meter.summary().session_id.as_deref(), Some("after"));
    }

    #[tokio::test]
    async fn start_proxy_tcp_listens_and_unix_binds_a_private_socket() {
        let tmp = tempfile::tempdir().unwrap();
        let layout = layout_in(tmp.path());
        fs::create_dir_all(&layout.clone).unwrap();

        let tcp = start_proxy_on(&layout, "sk-unit-real".into(), true)
            .await
            .unwrap();
        let NetworkMode::Proxy { port, socket } = &tcp.network else {
            panic!("expected a proxy network mode");
        };
        assert_eq!(tcp.base_url, format!("http://127.0.0.1:{port}"));
        assert_eq!(socket, &tmp.path().join("lane/proxy.sock"));
        assert!(!socket.exists(), "the TCP proxy creates no socket");
        tokio::net::TcpStream::connect(("127.0.0.1", *port))
            .await
            .expect("the proxy accepts connections");
        assert!(tcp.placeholder_key.starts_with("placeholder-"));
        assert!(!tcp.placeholder_key.contains("sk-unit-real"));
        tcp.task.abort();

        let unix = start_proxy_on(&layout, "sk-unit-real".into(), false)
            .await
            .unwrap();
        let socket = tmp.path().join("lane/proxy.sock");
        assert_eq!(
            unix.network,
            NetworkMode::Proxy {
                port: 0,
                socket: socket.clone()
            }
        );
        assert_eq!(unix.base_url, LINUX_UNBRIDGED_URL);
        let meta = fs::metadata(&socket).unwrap();
        assert!(std::os::unix::fs::FileTypeExt::is_socket(&meta.file_type()));
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        tokio::net::UnixStream::connect(&socket)
            .await
            .expect("the proxy accepts connections on its socket");
        unix.task.abort();
    }
}
