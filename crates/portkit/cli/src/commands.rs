//! Command implementations.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::CommandFactory;
use clap_complete::generate;
use serde_json::{Map, Value};

use portkit_core::budget::{self, Budget};
// Aliased: `portkit_port::Surface` names a replay surface, this one names
// where a call came from.
use portkit_core::trace::{
    self, CallRecord, JsonlRecorder, Outcome, Recorder, Summary, Surface as CallSurface, Timer,
};
use portkit_core::{Config, Error, Registry, Result};
use portkit_mcp::{McpServer, ServerInfo};
use portkit_port::process::exec::{capture_process, ExecConfig};
use portkit_port::{capture, replay, CaptureOptions, ReplayOptions, ReplayReport, Surface};

use crate::{Cli, PortCommand, Shell, SurfaceArg, Transport};

pub fn tools(registry: &Registry, json: bool) -> Result<ExitCode> {
    let specs = registry.specs();

    if json {
        println!("{}", serde_json::to_string_pretty(&specs)?);
        return Ok(ExitCode::SUCCESS);
    }

    if specs.is_empty() {
        println!("No tools registered.");
        return Ok(ExitCode::SUCCESS);
    }

    let width = specs.iter().map(|s| s.name.len()).max().unwrap_or(0);
    for spec in &specs {
        // Descriptions are written for models and can be long; the table shows
        // the first sentence and `pk schema` has the rest.
        let summary = spec
            .description
            .split_once(". ")
            .map_or(spec.description.as_str(), |(h, _)| h);
        println!(
            "  {:<width$}  {}",
            spec.name,
            summary.trim_end_matches('.'),
            width = width
        );
    }
    Ok(ExitCode::SUCCESS)
}

pub fn schema(registry: &Registry, tool: &str) -> Result<ExitCode> {
    let spec = registry
        .get(tool)
        .ok_or_else(|| unknown_tool(registry, tool))?
        .spec();
    println!("{}", serde_json::to_string_pretty(&spec)?);
    Ok(ExitCode::SUCCESS)
}

/// Arguments for `pk run`, grouped so the signature stays readable.
pub struct RunArgs<'a> {
    pub tool: &'a str,
    pub input: Option<PathBuf>,
    pub args: &'a [String],
    pub compact: bool,
    pub through_mcp: bool,
    pub budget: Option<usize>,
    pub full: bool,
}

pub async fn run_tool(registry: &Registry, config: &Config, run: RunArgs<'_>) -> Result<ExitCode> {
    let tool = run.tool;
    if registry.get(tool).is_none() {
        return Err(unknown_tool(registry, tool));
    }

    let arguments = build_arguments(run.input, run.args, tool)?;

    let value = if run.through_mcp {
        let server = McpServer::new(registry.clone(), server_info(config));
        let result = server.call_tool(tool, arguments).await;
        if result.is_error {
            let message = result
                .content
                .first()
                .map(|c| c.as_text())
                .unwrap_or("tool reported an error");
            return Err(Error::tool_failed(tool, message));
        }
        // The MCP surface already applied its budget.
        result
            .structured_content
            .ok_or_else(|| Error::tool_failed(tool, "MCP result carried no structuredContent"))?
    } else {
        let rec = recorder(config);
        let timer = Timer::start(tool, CallSurface::Cli, &arguments, trace::now_rfc3339());
        match registry.call(tool, arguments).await {
            Ok(raw) => {
                let produced = measure(&raw);
                let out = apply_budget(registry, config, tool, raw, run.budget, run.full);
                let delivered = measure(&out);
                if let Some(r) = &rec {
                    r.record(timer.finish(
                        Outcome::Ok,
                        produced,
                        delivered,
                        usize::from(delivered < produced),
                    ));
                }
                out
            }
            Err(err) => {
                if let Some(r) = &rec {
                    let outcome = if err.is_caller_fault() {
                        Outcome::Rejected
                    } else {
                        Outcome::Failed
                    };
                    r.record(timer.finish(outcome, 0, err.to_string().len(), 0));
                }
                return Err(err);
            }
        }
    };

    let rendered = if run.compact {
        serde_json::to_string(&value)?
    } else {
        serde_json::to_string_pretty(&value)?
    };
    println!("{rendered}");
    Ok(ExitCode::SUCCESS)
}

/// Precedence: an explicit flag, then the tool's own declaration, then config.
fn apply_budget(
    registry: &Registry,
    config: &Config,
    tool: &str,
    value: serde_json::Value,
    override_bytes: Option<usize>,
    full: bool,
) -> serde_json::Value {
    if full {
        return value;
    }
    let spec = registry.get(tool).map(|t| t.spec());
    let budget = match override_bytes {
        Some(bytes) => Budget::bytes(bytes),
        None => spec
            .as_ref()
            .and_then(|s| s.budget)
            .unwrap_or_else(|| config.budget()),
    };
    let schema = spec.as_ref().and_then(|s| s.output_schema.as_ref());
    let out = budget::apply_annotated(&value, schema, &budget);
    if out.was_trimmed() {
        // stderr: stdout is the result, and on `serve` it is the protocol.
        eprintln!(
            "note: output trimmed {} -> {} bytes to fit budget",
            out.original_bytes, out.final_bytes
        );
    }
    out.value
}

pub async fn serve(registry: Registry, config: &Config, transport: Transport) -> Result<ExitCode> {
    match transport {
        Transport::Stdio => {
            let mut server = McpServer::new(registry, server_info(config));
            if let Some(recorder) = recorder(config) {
                server = server.with_recorder(recorder);
            }
            portkit_mcp::serve_stdio(server).await?;
            Ok(ExitCode::SUCCESS)
        }
    }
}

pub async fn port(registry: &Registry, config: &Config, command: PortCommand) -> Result<ExitCode> {
    match command {
        PortCommand::Capture {
            cmd,
            cases,
            out,
            fail_fast,
            cwd,
            env,
            clear_env,
        } => {
            let mut opts = CaptureOptions::new(cmd).with_clear_env(clear_env);
            opts.fail_fast = fail_fast;
            opts.cwd = cwd;
            for pair in &env {
                let (key, value) = split_env(pair)?;
                opts = opts.with_env(key, value);
            }
            let report = capture(&cases, &out, &opts).await?;

            for case in &report.captured {
                println!("  captured  {}/{}", case.tool, case.id);
            }
            for failure in &report.failures {
                eprintln!(
                    "  FAILED    {}/{} — {}",
                    failure.tool, failure.id, failure.reason
                );
            }
            println!(
                "\n  {} captured, {} failed → {}",
                report.captured.len(),
                report.failures.len(),
                out.display()
            );

            Ok(exit_code(report.is_success()))
        }

        PortCommand::Exec(args) => port_exec(args).await,

        PortCommand::Wrap(args) => port_wrap(args).await,

        PortCommand::Shim {
            dir,
            state,
            program,
            args,
        } => {
            let status = portkit_port::process::shim::run_shim(&dir, &state, &program, &args)?;
            Ok(ExitCode::from(u8::try_from(status).unwrap_or(1)))
        }

        PortCommand::NetProbe { addr } => Ok(ExitCode::from(
            u8::try_from(portkit_port::process::exec::net_probe(&addr)).unwrap_or(1),
        )),

        PortCommand::Adapter { lang, out, force } => port_adapter(&lang, out, force),

        PortCommand::Replay {
            fixtures,
            tool,
            surface,
            epsilon,
            json,
        } => {
            let mut diff = config.diff_options();
            if let Some(epsilon) = epsilon {
                diff.epsilon = epsilon;
            }

            let surfaces: &[Surface] = match surface {
                SurfaceArg::Direct => &[Surface::Direct],
                SurfaceArg::Mcp => &[Surface::Mcp],
                SurfaceArg::Both => &[Surface::Direct, Surface::Mcp],
            };

            let mut reports: Vec<(Surface, ReplayReport)> = Vec::new();
            for &surface in surfaces {
                let opts = ReplayOptions {
                    diff: diff.clone(),
                    surface,
                    only_tool: tool.clone(),
                };
                reports.push((surface, replay(&fixtures, registry, &opts).await?));
            }

            if json {
                let payload: Map<String, Value> = reports
                    .iter()
                    .map(|(s, r)| Ok((s.to_string(), serde_json::to_value(r)?)))
                    .collect::<Result<_>>()?;
                println!("{}", serde_json::to_string_pretty(&payload)?);
            } else {
                for (surface, report) in &reports {
                    println!("\n  surface: {surface}");
                    print!("{}", portkit_port::render(report));
                }
            }

            Ok(exit_code(reports.iter().all(|(_, r)| r.is_success())))
        }
    }
}

fn measure(v: &serde_json::Value) -> usize {
    serde_json::to_vec(v).map(|b| b.len()).unwrap_or(0)
}

fn today() -> String {
    let d = time::OffsetDateTime::now_utc().date();
    format!("{:04}-{:02}-{:02}", d.year(), u8::from(d.month()), d.day())
}

/// A recorder when tracing is enabled, otherwise nothing.
///
/// A recorder that cannot open its file returns `None` rather than failing the
/// command: telemetry is never worth breaking the work it measures.
fn recorder(config: &Config) -> Option<Arc<dyn Recorder>> {
    if !config.trace.enabled {
        return None;
    }
    let path = config
        .trace
        .resolve_dir()
        .join(portkit_core::config::TraceConfig::trace_filename(&today()));
    match JsonlRecorder::create(&path) {
        Ok(r) => Some(Arc::new(r)),
        Err(err) => {
            eprintln!(
                "warning: tracing disabled — could not open {}: {err}",
                path.display()
            );
            None
        }
    }
}

pub fn trace(config: &Config, dir: Option<PathBuf>, json: bool) -> Result<ExitCode> {
    let dir = dir.unwrap_or_else(|| config.trace.resolve_dir());
    if !dir.exists() {
        println!(
            "no traces at {} (set [trace] enabled = true)",
            dir.display()
        );
        return Ok(ExitCode::SUCCESS);
    }

    let mut records: Vec<CallRecord> = Vec::new();
    let mut entries: Vec<_> = std::fs::read_dir(&dir)?
        .filter_map(std::result::Result::ok)
        .collect();
    entries.sort_by_key(std::fs::DirEntry::path);
    for e in entries {
        let p = e.path();
        if p.extension().is_some_and(|x| x == "jsonl") {
            records.extend(trace::read_jsonl(&p)?);
        }
    }

    if records.is_empty() {
        println!("no calls recorded in {}", dir.display());
        return Ok(ExitCode::SUCCESS);
    }

    // Per tool, so the biggest offender is obvious at a glance.
    let mut by_tool: BTreeMap<String, Summary> = BTreeMap::new();
    let mut overall = Summary::default();
    for r in &records {
        by_tool.entry(r.tool.clone()).or_default().add(r);
        overall.add(r);
    }

    if json {
        println!("{}", serde_json::to_string_pretty(&by_tool)?);
        return Ok(ExitCode::SUCCESS);
    }

    let width = by_tool.keys().map(String::len).max().unwrap_or(4).max(4);
    println!(
        "  {:<width$}  {:>6}  {:>10}  {:>10}  {:>9}  {:>8}",
        "TOOL", "CALLS", "DELIVERED", "SAVED", "AVG ms", "REJECTED"
    );
    println!("  {}", "-".repeat(width + 52));
    for (tool, s) in &by_tool {
        println!(
            "  {:<width$}  {:>6}  {:>10}  {:>10}  {:>9.2}  {:>8}",
            tool,
            s.calls,
            human(s.delivered_bytes),
            human(s.saved_bytes()),
            s.total_ms / s.calls.max(1) as f64,
            s.rejected
        );
    }
    println!(
        "\n  {} calls · {} delivered · {} kept out of context · {} rejected before dispatch",
        overall.calls,
        human(overall.delivered_bytes),
        human(overall.saved_bytes()),
        overall.rejected
    );
    Ok(ExitCode::SUCCESS)
}

fn human(bytes: usize) -> String {
    match bytes {
        b if b >= 1_000_000 => format!("{:.1} MB", b as f64 / 1e6),
        b if b >= 1_000 => format!("{:.1} KB", b as f64 / 1e3),
        b => format!("{b} B"),
    }
}

pub fn show_config(config: &Config) -> Result<ExitCode> {
    println!("{}", serde_json::to_string_pretty(config)?);
    Ok(ExitCode::SUCCESS)
}

pub fn completion(shell: Shell) {
    use clap_complete::shells;

    let mut cmd = Cli::command();
    let name = cmd.get_name().to_string();
    let out = &mut std::io::stdout();

    match shell {
        Shell::Bash => generate(shells::Bash, &mut cmd, name, out),
        Shell::Zsh => generate(shells::Zsh, &mut cmd, name, out),
        Shell::Fish => generate(shells::Fish, &mut cmd, name, out),
        Shell::Elvish => generate(shells::Elvish, &mut cmd, name, out),
        Shell::PowerShell => generate(shells::PowerShell, &mut cmd, name, out),
    }
}

fn server_info(config: &Config) -> ServerInfo {
    let info = ServerInfo::new(&config.server.name, env!("CARGO_PKG_VERSION"));
    match &config.server.instructions {
        Some(instructions) => info.with_instructions(instructions),
        None => info,
    }
}

/// Merge `--input` and repeated `--arg key=value` into one argument object.
///
/// `--arg` wins on conflict, so a file of defaults can be overridden inline.
fn build_arguments(input: Option<PathBuf>, args: &[String], tool: &str) -> Result<Value> {
    let mut object = match input {
        Some(path) => {
            let raw = if path.as_os_str() == "-" {
                let mut buf = String::new();
                std::io::stdin().read_to_string(&mut buf)?;
                buf
            } else {
                std::fs::read_to_string(&path)
                    .map_err(|e| Error::other(format!("{}: {e}", path.display())))?
            };
            match serde_json::from_str(&raw)? {
                Value::Object(map) => map,
                _ => return Err(Error::invalid_input(tool, "input JSON must be an object")),
            }
        }
        None => Map::new(),
    };

    for arg in args {
        let (key, raw) = arg.split_once('=').ok_or_else(|| {
            Error::invalid_input(tool, format!("`--arg {arg}` is not in key=value form"))
        })?;
        // Try JSON first so numbers, booleans, and arrays arrive typed; fall
        // back to a string so `--arg name=Ada` does not need quoting.
        let value = serde_json::from_str(raw).unwrap_or_else(|_| Value::String(raw.to_string()));
        object.insert(key.to_string(), value);
    }

    Ok(Value::Object(object))
}

/// Unknown tool errors name the alternatives — the list is short and it saves a round trip.
fn unknown_tool(registry: &Registry, tool: &str) -> Error {
    let known = registry.names().join(", ");
    if known.is_empty() {
        return Error::UnknownTool(tool.to_string());
    }
    Error::other(format!("unknown tool `{tool}`; registered tools: {known}"))
}

/// `pk port adapter`: the shipped capture adapter for `lang`, on stdout or in `out`.
fn split_env(pair: &str) -> Result<(String, String)> {
    match pair.split_once('=') {
        Some((key, value)) if !key.is_empty() => Ok((key.to_string(), value.to_string())),
        _ => Err(Error::other(format!(
            "--env {pair:?}: expected KEY=VALUE with a non-empty KEY"
        ))),
    }
}

/// The harness configuration the command line asks for.
fn harness_config(command: String, args: &crate::HarnessArgs) -> Result<ExecConfig> {
    use portkit_port::process::exec::{confinement_for, SandboxMode};

    let cwd = std::env::current_dir()?;
    let src = match &args.src {
        Some(src) if src.is_absolute() => src.clone(),
        Some(src) => cwd.join(src),
        None => cwd,
    };
    let src = src
        .canonicalize()
        .map_err(|e| Error::other(format!("--src {}: {e}", src.display())))?;
    let mode = match args.sandbox {
        crate::SandboxArg::Auto => SandboxMode::Auto,
        crate::SandboxArg::Own => SandboxMode::Own,
        crate::SandboxArg::Inherited => SandboxMode::Inherited,
    };
    let confinement = confinement_for(mode).map_err(Error::other)?;
    let mut cfg = ExecConfig::new(command, src, confinement);
    cfg.path = args.path.clone();
    cfg.path_roots = args.path_root.clone();
    for pair in &args.env {
        cfg.env.push(split_env(pair)?);
    }
    if let Some(dir) = &args.work_dir {
        cfg.work_parent = dir.clone();
    }
    if let Some(secs) = args.timeout {
        cfg.timeout = std::time::Duration::from_secs(secs.max(1));
    }
    cfg.keep_work = args.keep_work;
    cfg.validate().map_err(Error::other)?;
    Ok(cfg)
}

async fn port_exec(args: crate::ExecArgs) -> Result<ExitCode> {
    let cfg = harness_config(args.cmd.clone(), &args.harness)?;
    let report = capture_process(&args.cases, &args.out, &cfg, args.repeat, args.fail_fast).await?;
    for case in &report.captured {
        println!("  captured  {}/{}", case.tool, case.id);
    }
    for failure in &report.failures {
        eprintln!(
            "  FAILED    {}/{} — {}",
            failure.tool, failure.id, failure.reason
        );
    }
    println!(
        "\n  {} captured, {} failed → {}",
        report.captured.len(),
        report.failures.len(),
        args.out.display()
    );
    Ok(exit_code(report.is_success()))
}

async fn port_wrap(args: crate::WrapArgs) -> Result<ExitCode> {
    if args.portkit_spec {
        portkit_port::process::exec::print_json(&portkit_port::process::exec::wrap_spec(
            &args.tool,
            &args.harness.path_root,
        ))?;
        return Ok(ExitCode::SUCCESS);
    }
    let command = match (&args.exe, &args.cmd) {
        (Some(exe), None) => {
            let exe = exe
                .canonicalize()
                .map_err(|e| Error::other(format!("--exe {}: {e}", exe.display())))?;
            format!("'{}'", exe.to_string_lossy().replace('\'', "'\\''"))
        }
        (None, Some(cmd)) => cmd.clone(),
        _ => {
            return Err(Error::other(
                "pk port wrap needs the port: --exe <file> or --cmd <command>",
            ))
        }
    };
    let cfg = harness_config(command, &args.harness)?;
    let request = portkit_port::process::exec::read_stdin()?;
    let envelope = portkit_port::process::exec::serve_request(&cfg, &request).await?;
    portkit_port::process::exec::print_json(&envelope)?;
    Ok(ExitCode::SUCCESS)
}

fn port_adapter(lang: &str, out: Option<PathBuf>, force: bool) -> Result<ExitCode> {
    let Some(adapter) = portkit_port::adapters::adapter_for(lang) else {
        let known: Vec<&str> = portkit_port::adapters::ADAPTERS
            .iter()
            .map(|a| a.lang)
            .collect();
        return Err(Error::other(format!(
            "no capture adapter for `{lang}` (have: {}, and typescript through node)",
            known.join(", ")
        )));
    };
    match out {
        None => print!("{}", adapter.source),
        Some(path) => {
            if path.exists() && !force {
                return Err(Error::other(format!(
                    "{} already exists; pass --force to replace it",
                    path.display()
                )));
            }
            std::fs::write(&path, adapter.source)?;
            eprintln!(
                "wrote {}; capture with: pk port capture --cmd '{} {} <module>'",
                path.display(),
                adapter.runner,
                path.display()
            );
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn exit_code(success: bool) -> ExitCode {
    if success {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
