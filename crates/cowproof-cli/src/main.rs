#![forbid(unsafe_code)]

use anyhow::{Context, Result, anyhow, bail};
use clap::Parser;
use cowproof_core::{
    Header, PORT_BASE, codex_isolation_args, heldout, outside_ownership, parse_header,
    release_slot, remove_build_output, removed_lines, repo_rules, try_acquire_slot,
};
use cowproof_host::{
    SystemRunner, collect_facts, enforce_disk_floor, ensure_safe_to_stop, lane_status,
    parse_df_free, read_host_config, stop_lane,
};
use cowproof_lint::{Finding, Severity, lint_packet};
use cowproof_plan::{
    HostCapacity, LaneStateUpdate, PlanHostRunner, check_plans, choose_host, collect_running,
    duplicate_running_id, lanes as plan_lanes, load_plans, ready_next, set_lane_state,
};
use cowproof_run::{LaneLayout, NetworkMode, SandboxPolicy, render_macos_profile, sandbox_command};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::collections::HashSet;
use std::ffi::OsStr;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;

#[derive(Parser)]
#[command(name = "lanes", about = "Run isolated engineering lanes")]
struct Args {
    #[command(subcommand)]
    command: Action,
}
#[derive(clap::Subcommand)]
enum Action {
    Run(RunArgs),
    Lint(LintArgs),
    Host(HostArgs),
    Hosts,
    Plan(PlanArgs),
}
#[derive(Parser)]
struct PlanArgs {
    #[command(subcommand)]
    command: PlanAction,
}
#[derive(clap::Subcommand)]
enum PlanAction {
    Run {
        #[arg(long, default_value = ".")]
        repo: PathBuf,
        #[arg(long)]
        max: Option<usize>,
        #[arg(long)]
        dry_run: bool,
    },
    Collect {
        #[arg(long, default_value = ".")]
        repo: PathBuf,
    },
}
#[derive(Parser)]
struct RunArgs {
    #[arg(long)]
    quiet: bool,
    #[arg(long)]
    root: Option<PathBuf>,
    #[arg(long, default_value_t = 4)]
    concurrency: usize,
    #[arg(long)]
    key_file: Option<PathBuf>,
    #[arg(long)]
    keep_build: bool,
    #[arg(long)]
    allow_lint_errors: bool,
    #[arg(long)]
    host: Option<String>,
    #[arg(long)]
    heldout: Option<PathBuf>,
    #[arg(required = true)]
    packets: Vec<PathBuf>,
}

#[derive(Parser)]
struct LintArgs {
    #[arg(long)]
    repo: Option<PathBuf>,
    #[arg(required = true)]
    packets: Vec<PathBuf>,
}

#[derive(Parser)]
struct HostArgs {
    #[command(subcommand)]
    command: HostAction,
}
#[derive(clap::Subcommand)]
enum HostAction {
    Facts {
        #[arg(long)]
        json: bool,
    },
    Run {
        #[arg(long)]
        detach: bool,
        #[arg(long)]
        force_with_running_lanes: bool,
        packet: PathBuf,
    },
    Status {
        lane_dir: Option<PathBuf>,
    },
    Stop {
        lane_dir: PathBuf,
    },
    SafeToStop,
}

#[tokio::main]
async fn main() -> Result<()> {
    match Args::parse().command {
        Action::Run(args) => {
            lint_run_packets(&args)?;
            if let Some(host) = args.host.clone() {
                return remote_run(args, &host).await;
            }
            run(args).await
        }
        Action::Lint(args) => lint_command(args),
        Action::Host(args) => host_command(args.command),
        Action::Hosts => hosts_command(),
        Action::Plan(args) => match args.command {
            PlanAction::Run { repo, max, dry_run } => plan_run(&repo, max, dry_run),
            PlanAction::Collect { repo } => plan_collect(&repo),
        },
    }
}

fn lint_command(args: LintArgs) -> Result<()> {
    let mut errors = 0usize;
    for packet in args.packets {
        let explicit_repo = args
            .repo
            .as_ref()
            .map(|repo| {
                repo.canonicalize()
                    .with_context(|| format!("opening repository {}", repo.display()))
            })
            .transpose()?;
        let path = if packet.is_absolute() {
            packet
                .canonicalize()
                .with_context(|| format!("opening packet {}", packet.display()))?
        } else if let Some(repo) = explicit_repo.as_ref() {
            repo.join(&packet)
                .canonicalize()
                .with_context(|| format!("opening packet {}", packet.display()))?
        } else {
            std::env::current_dir()?
                .join(packet)
                .canonicalize()
                .with_context(|| "opening packet")?
        };
        let repo = if let Some(repo) = explicit_repo {
            repo
        } else {
            git_root_containing(&path)?
        };
        let text = fs::read_to_string(&path)
            .with_context(|| format!("reading packet {}", path.display()))?;
        let plans = load_plans(&repo, &[])?;
        let findings = lint_packet(&text, &repo, &plans);
        print_findings(&path, &findings);
        errors += findings
            .iter()
            .filter(|finding| finding.severity == Severity::Error)
            .count();
    }
    if errors > 0 {
        bail!("packet lint found {errors} error(s)");
    }
    Ok(())
}

fn git_root_containing(path: &Path) -> Result<PathBuf> {
    let start = if path.is_dir() {
        path
    } else {
        path.parent().unwrap_or_else(|| Path::new("."))
    };
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(start)
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .with_context(|| "starting git to locate packet repository")?;
    if !output.status.success() {
        bail!(
            "packet {} is not inside a git repository; pass --repo DIR",
            path.display()
        );
    }
    Ok(PathBuf::from(String::from_utf8_lossy(&output.stdout).trim()).canonicalize()?)
}

fn print_findings(packet: &Path, findings: &[Finding]) {
    for finding in findings {
        eprintln!("{}: {finding}", packet.display());
    }
}

fn format_age(seconds: u64) -> String {
    if seconds < 60 {
        format!("{seconds}s")
    } else if seconds < 3600 {
        format!("{}m", seconds / 60)
    } else if seconds < 86400 {
        format!("{}h", seconds / 3600)
    } else {
        format!("{}d", seconds / 86400)
    }
}

fn lint_run_packets(args: &RunArgs) -> Result<()> {
    let repo = std::env::current_dir()?.canonicalize()?;
    let plans = load_plans(&repo, &[])?;
    for packet in &args.packets {
        let text = fs::read_to_string(packet)
            .with_context(|| format!("reading packet {}", packet.display()))?;
        let findings = lint_packet(&text, &repo, &plans);
        print_findings(packet, &findings);
        if !args.allow_lint_errors && findings.iter().any(|f| f.severity == Severity::Error) {
            bail!(
                "packet {} has lint errors; fix them or pass --allow-lint-errors",
                packet.display()
            );
        }
    }
    Ok(())
}

fn configured_hosts() -> Result<serde_json::Map<String, Value>> {
    let explicit = std::env::var_os("LANES_HOSTS_FILE").map(PathBuf::from);
    let path = explicit.unwrap_or_else(|| {
        let private = PathBuf::from("hosts.json");
        if private.exists() {
            private
        } else {
            PathBuf::from("hosts.example.json")
        }
    });
    read_host_config(&path)
}
fn host_settings(alias: &str) -> Result<(PathBuf, f64, String)> {
    let hosts = configured_hosts()?;
    let value = hosts
        .get(alias)
        .ok_or_else(|| anyhow!("host alias {alias:?} is not in hosts.json"))?;
    let root = value
        .get("laneRoot")
        .or_else(|| value.get("lane_root"))
        .and_then(Value::as_str)
        .map(|s| {
            if s == "~" {
                home()
            } else if let Some(rest) = s.strip_prefix("~/") {
                home().join(rest)
            } else {
                PathBuf::from(s)
            }
        })
        .unwrap_or_else(|| home().join(".cache/cowproof"));
    let floor = value
        .get("floorGb")
        .or_else(|| value.get("floor_gb"))
        .and_then(Value::as_f64)
        .unwrap_or(80.0);
    let ssh = value
        .get("ssh")
        .and_then(Value::as_str)
        .unwrap_or(alias)
        .to_owned();
    Ok((root, floor, ssh))
}
fn host_command(action: HostAction) -> Result<()> {
    let (default_root, floor, _) = host_settings("local")
        .unwrap_or_else(|_| (home().join(".cache/cowproof"), 80.0, "local".into()));
    let floor = std::env::var("LANE_FLOOR_GB")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(floor);
    match action {
        HostAction::Facts { json: as_json } => {
            let root = std::env::var_os("LANE_ROOT")
                .map(PathBuf::from)
                .unwrap_or(default_root);
            let facts = collect_facts(&root, &SystemRunner);
            if as_json {
                println!("{}", serde_json::to_string(&facts)?);
            } else {
                println!("{}", cowproof_host::compact_facts(&facts));
            }
            Ok(())
        }
        HostAction::Run {
            detach,
            force_with_running_lanes,
            packet,
        } => host_run(
            packet,
            std::env::var_os("LANE_ROOT")
                .map(PathBuf::from)
                .unwrap_or(default_root),
            floor,
            detach,
            force_with_running_lanes,
        ),
        HostAction::Status { lane_dir } => {
            if let Some(lane_dir) = lane_dir {
                println!("{}", lane_status(&lane_dir, &SystemRunner)?.as_str());
            } else {
                let root = std::env::var_os("LANE_ROOT")
                    .map(PathBuf::from)
                    .unwrap_or(default_root);
                println!("ID\tSTATE\tAGE\tSUMMARY");
                for lane in cowproof_host::host_lane_statuses(&root) {
                    println!(
                        "{}\t{}\t{}\t{}",
                        lane.id,
                        lane.state,
                        format_age(lane.age_seconds),
                        lane.summary_path
                    );
                }
            }
            Ok(())
        }
        HostAction::Stop { lane_dir } => stop_lane(&lane_dir, &SystemRunner),
        HostAction::SafeToStop => {
            let root = std::env::var_os("LANE_ROOT")
                .map(PathBuf::from)
                .unwrap_or(default_root);
            let lanes = cowproof_host::running_lanes(&root);
            if lanes.is_empty() {
                println!("safe to stop: no running lanes");
                Ok(())
            } else {
                for lane in &lanes {
                    println!(
                        "{} pid={}",
                        lane.directory,
                        lane.pid
                            .map(|p| p.to_string())
                            .unwrap_or_else(|| "unknown".into())
                    );
                }
                ensure_safe_to_stop(&root)?;
                Ok(())
            }
        }
    }
}

fn host_run(
    packet: PathBuf,
    root: PathBuf,
    floor_gb: f64,
    detach: bool,
    force: bool,
) -> Result<()> {
    if !detach {
        bail!("host run requires --detach");
    }
    let text = fs::read_to_string(&packet)
        .with_context(|| format!("reading packet {}", packet.display()))?;
    let header = cowproof_core::parse_header(&text)?;
    fs::create_dir_all(&root)?;
    let root = root.canonicalize()?;
    let previous_dirs = fs::read_dir(&root)?
        .flatten()
        .map(|entry| entry.path())
        .collect::<std::collections::HashSet<_>>();
    let lane_free = std::process::Command::new("df")
        .args(["-Pk", root.to_str().unwrap_or(".")])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| parse_df_free(&String::from_utf8_lossy(&o.stdout)));
    let facts = collect_facts(&root, &SystemRunner);
    if lane_free.is_none() {
        bail!(
            "could not measure free space on lane root {}; refusing to start",
            root.display()
        );
    }
    if facts.wsl && facts.windows_drive_free_bytes.is_none() {
        bail!(
            "could not measure free space on the Windows drive backing this WSL distro; refusing to start"
        );
    }
    enforce_disk_floor(lane_free, facts.windows_drive_free_bytes, floor_gb, force)?;
    let exe = std::env::current_exe()?;
    let unit = format!("lanes-{}", header.id);
    let cwd = std::env::current_dir()?;
    let class_limits = std::env::var("LANE_CLASS_LIMITS").ok();
    let probe = std::process::Command::new("systemd-run")
        .args([
            "--user",
            "--unit",
            &unit,
            "--collect",
            "--working-directory",
            cwd.to_str().unwrap_or("."),
            "--quiet",
        ])
        .args(
            class_limits
                .iter()
                .map(|value| format!("--setenv=LANE_CLASS_LIMITS={value}")),
        )
        .arg(&exe)
        .args(["run", "--root"])
        .arg(&root)
        .args(["--concurrency", "1"])
        .arg(&packet)
        .output();
    let (backend, pid) = match probe {
        Ok(out) if out.status.success() => {
            let pid = std::process::Command::new("systemctl")
                .args(["--user", "show", "--property=MainPID", "--value", &unit])
                .output()
                .ok()
                .filter(|o| o.status.success())
                .and_then(|o| {
                    String::from_utf8_lossy(&o.stdout)
                        .trim()
                        .parse::<u32>()
                        .ok()
                })
                .filter(|p| *p > 0);
            ("systemd".to_owned(), pid)
        }
        _ => {
            let log = fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(root.join(format!("{}.host-run.log", header.id)))?;
            let err = log.try_clone()?;
            let child = std::process::Command::new("setsid")
                .arg(exe)
                .args(["run", "--root"])
                .arg(&root)
                .args(["--concurrency", "1"])
                .arg(&packet)
                .current_dir(cwd)
                .stdin(Stdio::null())
                .stdout(Stdio::from(log))
                .stderr(Stdio::from(err))
                .spawn()
                .context("starting detached lane with setsid")?;
            ("process-group".to_owned(), Some(child.id()))
        }
    };
    let deadline = Instant::now() + Duration::from_secs(15);
    let lane_dir = loop {
        let found = fs::read_dir(&root)?.flatten().map(|e| e.path()).find(|p| {
            p.is_dir()
                && p.file_name()
                    .and_then(OsStr::to_str)
                    .is_some_and(|n| n.starts_with(&format!("{}-", header.id)))
                && !previous_dirs.contains(p)
                && !p.join("summary.json").exists()
        });
        if let Some(path) = found {
            break path;
        }
        if Instant::now() >= deadline {
            bail!("detached lane did not create its lane directory within 15 seconds");
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let identifier = if backend == "systemd" {
        unit
    } else {
        pid.map(|p| p.to_string()).unwrap_or_default()
    };
    let record = cowproof_host::host_record(&backend, &identifier, pid, &header.id);
    cowproof_host::write_host_record(&lane_dir, &record)?;
    println!("{}", json!({"laneDir":lane_dir,"host":record}));
    Ok(())
}

fn configured_host_root(alias: &str, value: &Value) -> PathBuf {
    value
        .get("laneRoot")
        .or_else(|| value.get("lane_root"))
        .and_then(Value::as_str)
        .map(|s| {
            if s == "~" {
                home()
            } else if let Some(rest) = s.strip_prefix("~/") {
                home().join(rest)
            } else {
                PathBuf::from(s)
            }
        })
        .unwrap_or_else(|| {
            if alias == "local" {
                home().join(".cache/cowproof")
            } else {
                PathBuf::from("~/.cache/cowproof")
            }
        })
}
fn remote_host_root(alias: &str, value: &Value, ssh: &str) -> Result<PathBuf> {
    let configured = value
        .get("laneRoot")
        .or_else(|| value.get("lane_root"))
        .and_then(Value::as_str)
        .unwrap_or("~/.cache/cowproof");
    if configured == "~" || configured.starts_with("~/") {
        let output = std::process::Command::new("ssh")
            .arg(ssh)
            .arg("printf %s \"$HOME\"")
            .output()?;
        if !output.status.success() {
            bail!("could not read remote home for {alias}");
        }
        let home = PathBuf::from(String::from_utf8_lossy(&output.stdout).trim());
        return Ok(if configured == "~" {
            home
        } else {
            home.join(configured.trim_start_matches("~/"))
        });
    }
    Ok(PathBuf::from(configured))
}
fn host_floor(value: &Value) -> f64 {
    value
        .get("floorGb")
        .or_else(|| value.get("floor_gb"))
        .and_then(Value::as_f64)
        .unwrap_or(80.0)
}
fn host_limits(value: &Value) -> BTreeMap<String, usize> {
    value
        .get("classLimits")
        .or_else(|| value.get("class_limits"))
        .and_then(Value::as_object)
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| v.as_u64().map(|n| (k.clone(), n as usize)))
                .collect()
        })
        .unwrap_or_default()
}
fn get_host_facts(alias: &str, value: &Value) -> Result<cowproof_host::HostFacts> {
    if alias == "local" {
        let root = configured_host_root(alias, value);
        return Ok(collect_facts(&root, &SystemRunner));
    }
    let ssh = value.get("ssh").and_then(Value::as_str).unwrap_or(alias);
    let root = remote_host_root(alias, value, ssh)?;
    let output = std::process::Command::new("ssh")
        .arg(ssh)
        .arg(format!(
            "LANE_ROOT={} lanes host facts --json",
            shell_quote(&root.to_string_lossy())
        ))
        .output()?;
    if !output.status.success() {
        bail!(
            "could not get facts from {alias}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    serde_json::from_slice(&output.stdout).context("parsing remote host facts")
}

fn plan_run(repo: &Path, max: Option<usize>, dry_run: bool) -> Result<()> {
    let repo = repo
        .canonicalize()
        .with_context(|| format!("resolving repository {}", repo.display()))?;
    let plans = load_plans(&repo, &[])?;
    let problems = check_plans(&repo, &plans);
    if !problems.is_empty() {
        bail!(
            "plan validation failed: {}",
            problems
                .iter()
                .map(|p| format!("{} [{}]: {}", p.plan, p.lane, p.rule))
                .collect::<Vec<_>>()
                .join("; ")
        );
    }
    let all = plan_lanes(&plans);
    let ready = ready_next(&all);
    let configured = configured_hosts()?;
    let mut capacities = BTreeMap::new();
    let mut active_ids = HashSet::new();
    for (alias, value) in &configured {
        let facts = match get_host_facts(alias, value) {
            Ok(facts) => facts,
            Err(e) => {
                eprintln!("warning: host {alias} unavailable: {e:#}");
                continue;
            }
        };
        active_ids.extend(facts.running_lanes.iter().filter_map(|run| run.id.clone()));
        let floor = (host_floor(value).max(0.0) * 1024f64.powi(3)) as u64;
        let disk_ok = facts.lane_root_free_bytes.is_some_and(|n| n > floor)
            && (!facts.wsl || facts.windows_drive_free_bytes.is_some_and(|n| n > floor));
        let mut running = BTreeMap::<String, usize>::new();
        for lane in all
            .iter()
            .filter(|l| l.status == "running" && l.host == *alias)
        {
            *running.entry(lane.class.clone()).or_default() += 1;
        }
        for active in &facts.running_lanes {
            if let Some(lane) = all.iter().find(|l| {
                l.id == active.id.as_deref().unwrap_or("")
                    && !(l.status == "running" && l.host == *alias)
            }) {
                *running.entry(lane.class.clone()).or_default() += 1;
            } else {
                // An active lane outside the plan has an unknown class, so reserve all slots.
                for (class, limit) in host_limits(value) {
                    running
                        .entry(class)
                        .and_modify(|used| *used = (*used).max(limit))
                        .or_insert(limit);
                }
            }
        }
        capacities.insert(
            alias.clone(),
            HostCapacity {
                class_limits: host_limits(value),
                class_running: running,
                above_disk_floors: disk_ok,
            },
        );
    }
    let limit = max.unwrap_or(usize::MAX);
    let mut count = 0;
    for lane in ready {
        if count >= limit {
            break;
        }
        if duplicate_running_id(&all, &lane.id) || active_ids.contains(&lane.id) {
            bail!("refusing duplicate running lane id {}", lane.id);
        }
        let Some(alias) = choose_host(&lane, &capacities) else {
            continue;
        };
        let Some(packet) = &lane.packet else {
            continue;
        };
        let packet_path = repo.join(packet);
        if !packet_path.is_file() {
            bail!("packet does not exist: {}", packet_path.display());
        }
        let lint = std::process::Command::new(std::env::current_exe()?)
            .args(["lint", "--repo"])
            .arg(&repo)
            .arg(packet)
            .output();
        match lint {
            Ok(out) if out.status.success() => {}
            Ok(out) => {
                let err = String::from_utf8_lossy(&out.stderr);
                if err.contains("unrecognized subcommand") || err.contains("unknown command") {
                    eprintln!(
                        "warning: lanes lint is unavailable; skipping packet lint for {}",
                        lane.id
                    );
                } else {
                    bail!(
                        "packet lint failed for {}: {}{}",
                        lane.id,
                        String::from_utf8_lossy(&out.stdout),
                        err
                    );
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => eprintln!(
                "warning: lanes lint is unavailable; skipping packet lint for {}",
                lane.id
            ),
            Err(e) => return Err(e.into()),
        }
        println!("{}\t{}\t{}", lane.id, alias, packet);
        if !dry_run {
            start_planned_lane(&repo, &lane.id, packet, &alias, &configured[&alias])?;
            let latest = load_plans(&repo, &[])?;
            set_lane_state(
                &repo,
                &latest,
                &lane.id,
                LaneStateUpdate {
                    status: "running",
                    commit: None,
                    release: None,
                    packet: None,
                    host: Some(&alias),
                    notes: None,
                },
            )?;
        }
        if let Some(cap) = capacities.get_mut(&alias) {
            *cap.class_running.entry(lane.class).or_default() += 1;
        }
        count += 1;
    }
    Ok(())
}

fn start_planned_lane(
    repo: &Path,
    id: &str,
    packet: &str,
    alias: &str,
    host: &Value,
) -> Result<()> {
    let root = configured_host_root(alias, host);
    let floor = host_floor(host);
    let limits = serde_json::to_string(&host_limits(host))?;
    if alias == "local" {
        let output = std::process::Command::new(std::env::current_exe()?)
            .current_dir(repo)
            .env("LANE_ROOT", &root)
            .env("LANE_FLOOR_GB", floor.to_string())
            .env("LANE_CLASS_LIMITS", &limits)
            .args(["host", "run", "--detach"])
            .arg(repo.join(packet))
            .output()?;
        if !output.status.success() {
            bail!(
                "local start failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        return Ok(());
    }
    let ssh = host.get("ssh").and_then(Value::as_str).unwrap_or(alias);
    let home_output = std::process::Command::new("ssh")
        .arg(ssh)
        .arg("printf %s \"$HOME\"")
        .output()?;
    if !home_output.status.success() {
        bail!("could not read remote home for {alias}");
    }
    let remote_home = String::from_utf8_lossy(&home_output.stdout)
        .trim()
        .to_owned();
    let remote_root = remote_host_root(alias, host, ssh)?;
    let snapshot = format!(
        "{}/.cache/cowproof-plan-{}-{}",
        remote_home,
        id,
        now_stamp()
    );
    let create = std::process::Command::new("ssh")
        .arg(ssh)
        .arg(format!("mkdir -p {}", shell_quote(&snapshot)))
        .status()?;
    if !create.success() {
        bail!("could not create remote snapshot on {alias}");
    }
    let sync = std::process::Command::new("rsync")
        .args([
            "-a",
            "--delete",
            "--exclude=.env*",
            "--exclude=hosts.json",
            "--exclude=node_modules",
            "--exclude=target",
            "--exclude=dist",
            "--exclude=tmp-*",
            "--exclude=.git",
        ])
        .arg(format!("{}/", repo.display()))
        .arg(format!("{}:{}/", ssh, snapshot))
        .status()?;
    if !sync.success() {
        bail!("could not stage repository on {alias}");
    }
    let remote_packet = snapshot_path(&snapshot, Path::new(packet));
    let cmd = format!(
        "cd {} && LANE_ROOT={} LANE_FLOOR_GB={} LANE_CLASS_LIMITS={} lanes host run --detach {}",
        shell_quote(&snapshot),
        shell_quote(&remote_root.to_string_lossy()),
        floor,
        shell_quote(&limits),
        shell_quote(&remote_packet)
    );
    let start = std::process::Command::new("ssh")
        .arg(ssh)
        .arg(cmd)
        .output()?;
    if !start.status.success() {
        bail!(
            "remote start failed on {alias}: {}",
            String::from_utf8_lossy(&start.stderr).trim()
        );
    }
    let track_root = home().join(".cache/cowproof/.plan-run");
    fs::create_dir_all(&track_root)?;
    fs::write(
        track_root.join(format!("{id}.json")),
        serde_json::to_vec(
            &json!({"host":alias,"ssh":ssh,"snapshot":snapshot,"remoteRoot":root,"laneId":id}),
        )?,
    )?;
    Ok(())
}

fn plan_collect(repo: &Path) -> Result<()> {
    let repo = repo.canonicalize()?;
    let mut runner = CliPlanHostRunner {
        configured: configured_hosts()?,
    };
    for (id, status) in collect_running(&repo, &mut runner)? {
        println!("{id}\t{status}");
    }
    Ok(())
}

struct CliPlanHostRunner {
    configured: serde_json::Map<String, Value>,
}
impl CliPlanHostRunner {
    fn lane_dir(&self, lane: &cowproof_plan::LaneRef) -> Result<Option<PathBuf>> {
        let alias = if lane.host == "-" || lane.host.is_empty() {
            "local"
        } else {
            &lane.host
        };
        let Some(host) = self.configured.get(alias) else {
            bail!("unknown host {alias} for {}", lane.id)
        };
        if alias == "local" {
            let root = configured_host_root(alias, host);
            return Ok(fs::read_dir(&root)
                .ok()
                .into_iter()
                .flatten()
                .flatten()
                .map(|e| e.path())
                .find(|p| {
                    p.is_dir()
                        && p.file_name().is_some_and(|n| {
                            n.to_string_lossy().starts_with(&format!("{}-", lane.id))
                        })
                }));
        }
        let ssh = host.get("ssh").and_then(Value::as_str).unwrap_or(alias);
        let root = remote_host_root(alias, host, ssh)?;
        let query = format!(
            "find {} -maxdepth 1 -type d -name {} -print -quit",
            shell_quote(&root.to_string_lossy()),
            shell_quote(&format!("{}-*", lane.id))
        );
        let out = std::process::Command::new("ssh")
            .arg(ssh)
            .arg(query)
            .output()?;
        if !out.status.success() {
            bail!("could not locate {} on {alias}", lane.id);
        }
        let path = String::from_utf8_lossy(&out.stdout).trim().to_owned();
        Ok((!path.is_empty()).then(|| PathBuf::from(path)))
    }
}
impl PlanHostRunner for CliPlanHostRunner {
    fn status(&mut self, lane: &cowproof_plan::LaneRef) -> Result<cowproof_host::LaneStatus> {
        let alias = if lane.host == "-" || lane.host.is_empty() {
            "local"
        } else {
            &lane.host
        };
        let Some(dir) = self.lane_dir(lane)? else {
            return Ok(cowproof_host::LaneStatus::Lost);
        };
        if alias == "local" {
            return Ok(lane_status(&dir, &SystemRunner).unwrap_or(cowproof_host::LaneStatus::Lost));
        }
        let host = &self.configured[alias];
        let ssh = host.get("ssh").and_then(Value::as_str).unwrap_or(alias);
        let out = std::process::Command::new("ssh")
            .arg(ssh)
            .arg(format!(
                "lanes host status {}",
                shell_quote(&dir.to_string_lossy())
            ))
            .output()?;
        if !out.status.success() {
            bail!(
                "status query failed for {}: {}",
                lane.id,
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(match String::from_utf8_lossy(&out.stdout).trim() {
            "running" => cowproof_host::LaneStatus::Running,
            "finished" => cowproof_host::LaneStatus::Finished,
            "failed" => cowproof_host::LaneStatus::Failed,
            _ => cowproof_host::LaneStatus::Lost,
        })
    }
    fn collect(&mut self, lane: &cowproof_plan::LaneRef) -> Result<()> {
        let alias = if lane.host == "-" || lane.host.is_empty() {
            "local"
        } else {
            &lane.host
        };
        if alias == "local" {
            return Ok(());
        }
        let host = &self.configured[alias];
        let dir = self
            .lane_dir(lane)?
            .ok_or_else(|| anyhow!("completed lane directory vanished for {}", lane.id))?;
        copy_remote_result(&lane.id, host, &dir)
    }
}

fn copy_remote_result(id: &str, host: &Value, remote_dir: &Path) -> Result<()> {
    let ssh = host.get("ssh").and_then(Value::as_str).unwrap_or("local");
    let local_root = host_settings("local")
        .map(|s| s.0)
        .unwrap_or_else(|_| home().join(".cache/cowproof"));
    let local_dir = local_root.join(remote_dir.file_name().unwrap_or_default());
    fs::create_dir_all(&local_dir)?;
    let copy = std::process::Command::new("rsync")
        .args([
            "-a",
            "--exclude=repo",
            "--exclude=home",
            "--exclude=tmp",
            "--exclude=xdg",
        ])
        .arg(format!("{}:{}/", ssh, remote_dir.display()))
        .arg(format!("{}/", local_dir.display()))
        .status()?;
    if !copy.success() {
        bail!("rsync failed to collect {id}");
    }
    let track_root = home().join(".cache/cowproof/.plan-run");
    let track = track_root.join(format!("{id}.json"));
    let snapshot = fs::read(&track)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .and_then(|value| {
            value
                .get("snapshot")
                .and_then(Value::as_str)
                .map(str::to_owned)
        });
    let cleanup = if let Some(snapshot) = snapshot {
        std::process::Command::new("ssh")
            .arg(ssh)
            .arg(format!(
                "rm -rf {} {}/repo",
                shell_quote(&snapshot),
                shell_quote(&remote_dir.to_string_lossy())
            ))
            .status()?
    } else {
        std::process::Command::new("ssh")
            .arg(ssh)
            .arg(format!(
                "rm -rf {}/repo",
                shell_quote(&remote_dir.to_string_lossy())
            ))
            .status()?
    };
    if !cleanup.success() {
        bail!("could not clean remote workspaces for {id}");
    }
    let _ = fs::remove_file(track);
    Ok(())
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}
async fn remote_run(args: RunArgs, alias: &str) -> Result<()> {
    let (remote_lane_root, _, ssh) = host_settings(alias)?;
    if args.packets.is_empty() {
        bail!("at least one packet is required");
    }
    let repo = std::env::current_dir()?.canonicalize()?;
    let mut relative_packets = Vec::new();
    for packet in &args.packets {
        let input_path = if packet.is_absolute() {
            packet.clone()
        } else {
            repo.join(packet)
        };
        let absolute = input_path
            .canonicalize()
            .with_context(|| format!("resolving packet {}", packet.display()))?;
        let relative = absolute.strip_prefix(&repo).map_err(|_| {
            anyhow!(
                "packet must be inside the current repository: {}",
                packet.display()
            )
        })?;
        if !absolute.is_file() {
            bail!("packet does not exist: {}", absolute.display());
        }
        relative_packets.push(relative.to_path_buf());
    }
    let home_output = std::process::Command::new("ssh")
        .arg(&ssh)
        .arg("printf %s \"$HOME\"")
        .output()?;
    if !home_output.status.success() {
        bail!(
            "could not read remote home: {}",
            String::from_utf8_lossy(&home_output.stderr).trim()
        );
    }
    let remote_home = String::from_utf8_lossy(&home_output.stdout)
        .trim()
        .to_owned();
    let snapshot = format!(
        "{remote_home}/.cache/cowproof-dispatch-{}-{}",
        std::process::id(),
        now_stamp()
    );
    let mkdir = std::process::Command::new("ssh")
        .arg(&ssh)
        .arg(format!("mkdir -p {}", shell_quote(&snapshot)))
        .status()?;
    if !mkdir.success() {
        bail!("could not create remote snapshot");
    }
    let mut sync = std::process::Command::new("rsync");
    sync.args([
        "-a",
        "--delete",
        "--include=.env.example",
        "--exclude=.env*",
        "--exclude=hosts.json",
        "--exclude=node_modules",
        "--exclude=target",
        "--exclude=dist",
        "--exclude=tmp-*",
        "--exclude=.codemap",
        "--exclude=.DS_Store",
    ]);
    sync.arg(format!("{}/", repo.display()))
        .arg(format!("{}:{}/", ssh, snapshot));
    let synced = sync.status()?;
    if !synced.success() {
        bail!("rsync failed to stage repository on {alias}");
    }
    let local_root = args.root.unwrap_or_else(|| {
        host_settings("local")
            .map(|s| s.0)
            .unwrap_or_else(|_| home().join(".cache/cowproof"))
    });
    for packet in relative_packets {
        let remote_packet = snapshot_path(&snapshot, &packet);
        let configured = configured_hosts()?;
        let host_value = configured
            .get(alias)
            .ok_or_else(|| anyhow!("host alias {alias:?} is not in hosts.json"))?;
        let remote_floor = host_value
            .get("floorGb")
            .or_else(|| host_value.get("floor_gb"))
            .and_then(Value::as_f64)
            .unwrap_or(80.0);
        let limits = host_value
            .get("classLimits")
            .or_else(|| host_value.get("class_limits"))
            .cloned()
            .unwrap_or_else(|| json!({}));
        let start_cmd = format!(
            "cd {} && LANE_ROOT={} LANE_FLOOR_GB={} LANE_CLASS_LIMITS={} lanes host run --detach {}",
            shell_quote(&snapshot),
            shell_quote(&remote_lane_root.to_string_lossy()),
            remote_floor,
            shell_quote(&limits.to_string()),
            shell_quote(&remote_packet)
        );
        let start = std::process::Command::new("ssh")
            .arg(&ssh)
            .arg(start_cmd)
            .output()
            .context("starting remote detached lane")?;
        if !start.status.success() {
            bail!(
                "remote start failed: {}",
                String::from_utf8_lossy(&start.stderr).trim()
            );
        }
        let response: Value = serde_json::from_slice(&start.stdout)
            .context("remote host run returned invalid JSON")?;
        let remote_dir = response
            .get("laneDir")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("remote start response omitted laneDir"))?;
        loop {
            let status = std::process::Command::new("ssh")
                .arg(&ssh)
                .arg(format!("lanes host status {}", shell_quote(remote_dir)))
                .output()?;
            if !status.status.success() {
                bail!(
                    "remote status failed: {}",
                    String::from_utf8_lossy(&status.stderr).trim()
                );
            }
            let state = String::from_utf8_lossy(&status.stdout).trim().to_owned();
            if state == "running" {
                tokio::time::sleep(Duration::from_secs(10)).await;
                continue;
            }
            if state == "lost" {
                bail!("remote lane {remote_dir} was lost before it wrote summary.json");
            }
            let local_dir = local_root.join(
                Path::new(remote_dir)
                    .file_name()
                    .unwrap_or(OsStr::new("lane")),
            );
            fs::create_dir_all(&local_dir)?;
            let copy = std::process::Command::new("rsync")
                .args([
                    "-a",
                    "--exclude=repo",
                    "--exclude=home",
                    "--exclude=tmp",
                    "--exclude=xdg",
                    &format!("{}:{}/", ssh, remote_dir),
                    &format!("{}/", local_dir.display()),
                ])
                .status()?;
            if !copy.success() {
                bail!("rsync failed to copy completed lane directory");
            }
            let cleanup = std::process::Command::new("ssh")
                .arg(&ssh)
                .arg(format!("rm -rf {}/repo", shell_quote(remote_dir)))
                .status()?;
            if !cleanup.success() {
                bail!("could not remove the completed remote lane repository copy");
            }
            println!(
                "{}",
                json!({"id":packet.file_stem().and_then(OsStr::to_str).unwrap_or("lane"),"status":state,"host":alias,"remoteLaneDir":remote_dir,"laneDir":local_dir})
            );
            break;
        }
    }
    let _ = std::process::Command::new("ssh")
        .arg(&ssh)
        .arg(format!("rm -rf {}", shell_quote(&snapshot)))
        .status();
    Ok(())
}

fn snapshot_path(snapshot: &str, relative: &Path) -> String {
    format!(
        "{}/{}",
        snapshot.trim_end_matches('/'),
        relative.to_string_lossy()
    )
}

fn hosts_command() -> Result<()> {
    let hosts = configured_hosts()?;
    println!("HOST\tHOSTNAME\tOS\tCPUS\tLANES\tROOT FREE GB\tHOST DRIVE FREE GB");
    for (alias, value) in hosts {
        let root = value
            .get("laneRoot")
            .or_else(|| value.get("lane_root"))
            .and_then(Value::as_str)
            .map(|s| {
                if s == "~" {
                    home()
                } else if let Some(rest) = s.strip_prefix("~/") {
                    home().join(rest)
                } else {
                    PathBuf::from(s)
                }
            })
            .unwrap_or_else(|| home().join(".cache/cowproof"));
        let output = if alias == "local" {
            std::process::Command::new(std::env::current_exe()?)
                .args(["host", "facts", "--json"])
                .env("LANE_ROOT", root)
                .output()
                .with_context(|| format!("querying host {alias}"))?
        } else {
            let ssh = value.get("ssh").and_then(Value::as_str).unwrap_or(&alias);
            std::process::Command::new("ssh")
                .arg(ssh)
                .arg(format!(
                    "LANE_ROOT={} lanes host facts --json",
                    shell_quote(&root.to_string_lossy())
                ))
                .output()
                .with_context(|| format!("querying host {alias}"))?
        };
        if !output.status.success() {
            println!("{alias}\tunavailable\t?\t?\t?\t?\t?");
            continue;
        }
        let f: cowproof_host::HostFacts = serde_json::from_slice(&output.stdout)
            .with_context(|| format!("parsing facts from {alias}"))?;
        let gb = |n: Option<u64>| {
            n.map(|x| format!("{:.0}", x as f64 / 1e9))
                .unwrap_or_else(|| "?".into())
        };
        println!(
            "{alias}\t{}\t{}\t{}\t{}\t{}\t{}",
            f.hostname,
            f.os,
            f.cpu_count,
            f.running_lanes.len(),
            gb(f.lane_root_free_bytes),
            gb(f.windows_drive_free_bytes)
        );
    }
    Ok(())
}

async fn run(args: RunArgs) -> Result<()> {
    let repo = std::env::current_dir()?.canonicalize()?;

    // Check for held-out files in the repository
    let heldout_files = heldout::scan_base_for_heldout(&repo)?;
    if !heldout_files.is_empty() {
        eprintln!("error: found .heldout.* files tracked in the repository:");
        for file in &heldout_files {
            eprintln!("  {}", file.display());
        }
        bail!("held-out checks must not be in the repository; dispatch refused");
    }

    // Validate held-out checks path if provided
    if let Some(heldout_path) = &args.heldout {
        let home_dir = home();
        let repo_id = heldout::repo_id(&repo)?;
        // Validate that the explicit path is outside the repo
        let _resolved =
            heldout::resolve(Some(heldout_path), &home_dir, &repo, &repo_id, "validation")?;
    }

    let output_root = args.root.unwrap_or_else(|| home().join(".cache/cowproof"));
    fs::create_dir_all(&output_root)?;
    let output_root = output_root.canonicalize()?;
    let sccache = start_sccache();
    let mut jobs = Vec::new();
    let mut needs_key = false;
    for packet in &args.packets {
        let text = fs::read_to_string(packet)
            .with_context(|| format!("reading packet {}", packet.display()))?;
        let h = parse_header(&text)?;
        needs_key |= h.runner == "opencode";
        jobs.push((packet.clone(), text, h));
    }
    let mut key = std::env::var("OPENROUTER_API_KEY").unwrap_or_default();
    if let Some(file) = args.key_file {
        let data = fs::read_to_string(file)?;
        if let Some(line) = data.lines().find(|l| l.starts_with("OPENROUTER_API_KEY=")) {
            key = line["OPENROUTER_API_KEY=".len()..]
                .trim()
                .trim_matches(['\'', '\"'])
                .to_owned();
        }
    }
    if needs_key && key.is_empty() {
        bail!("no OpenRouter key: set OPENROUTER_API_KEY or pass --key-file");
    }
    let mut results = Vec::new();
    // Keep class limits and global concurrency in one scheduler. Slots themselves are machine-wide across Node/Rust.
    let mut pending = std::collections::VecDeque::from(jobs);
    let mut active = tokio::task::JoinSet::new();
    let mut running: BTreeMap<String, usize> = BTreeMap::new();
    let max = args.concurrency.max(1);
    loop {
        while active.len() < max {
            let Some(index) = pending.iter().position(|job| {
                running.get(&job.2.class_name).copied().unwrap_or(0)
                    < class_limit(&job.2.class_name)
            }) else {
                break;
            };
            let job = pending.remove(index).expect("selected pending job exists");
            if free_gb(&output_root).unwrap_or(0.0) < 20.0 {
                eprintln!("[{}] not started: low disk space, need 20 GB", job.2.id);
                results.push(json!({"id":job.2.id,"status":"not started: low disk"}));
                continue;
            }
            let id = job.2.id.clone();
            let class = job.2.class_name.clone();
            *running.entry(class.clone()).or_default() += 1;
            let repo = repo.clone();
            let root = output_root.clone();
            let key = key.clone();
            let sccache = sccache.clone();
            let keep_build = args.keep_build;
            active.spawn(async move {
                (
                    id,
                    class,
                    run_lane(job, repo, root, key, keep_build, sccache).await,
                )
            });
        }
        let Some(done) = active.join_next().await else {
            break;
        };
        match done {
            Ok((_id, class, Ok(r))) => {
                *running.entry(class).or_default() -= 1;
                results.push(r)
            }
            Ok((id, class, Err(e))) => {
                *running.entry(class).or_default() -= 1;
                eprintln!("[{id}] failed: {e:#}");
                results.push(json!({"id":id,"status":"error","error":format!("{e:#}")}));
            }
            Err(e) => eprintln!("[lanes] task failed: {e}"),
        }
    }
    if args.quiet {
        for r in results {
            println!("{}", quiet_row(&r));
        }
    } else {
        let rows: Vec<Value> = results
            .into_iter()
            .map(|mut r| {
                if let Some(o) = r.as_object_mut() {
                    o.remove("finalText");
                }
                r
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&rows)?);
    }
    Ok(())
}
fn quiet_row(r: &Value) -> Value {
    let mut o = serde_json::Map::new();
    for k in [
        "id",
        "status",
        "model",
        "estimateHours",
        "costUsd",
        "handoff",
        "laneDir",
    ] {
        if let Some(v) = r.get(k) {
            o.insert(k.into(), v.clone());
        }
    }
    if let Some(n) = r["seconds"].as_u64() {
        o.insert("minutes".into(), json!((n + 30) / 60));
    } else {
        o.insert("minutes".into(), Value::Null);
    }
    if let Some(n) = r["changed"].as_array() {
        o.insert("changed".into(), json!(n.len()));
    }
    if let Some(n) = r["outsideCount"].as_u64() {
        o.insert("outside".into(), json!(n));
    }
    Value::Object(o)
}

fn home() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/"))
}
fn sccache_dir() -> PathBuf {
    home().join(".cache/cowproof-sccache")
}
fn find_sccache() -> Option<PathBuf> {
    [
        PathBuf::from("/opt/homebrew/bin/sccache"),
        PathBuf::from("/usr/local/bin/sccache"),
        home().join(".cargo/bin/sccache"),
    ]
    .into_iter()
    .find(|p| p.is_file())
}
fn start_sccache() -> Option<PathBuf> {
    let binary = find_sccache()?;
    let dir = sccache_dir();
    if fs::create_dir_all(&dir).is_err() {
        return None;
    }
    let _ = std::process::Command::new(&binary)
        .arg("--start-server")
        .env("SCCACHE_DIR", &dir)
        .env("SCCACHE_CACHE_SIZE", "40G")
        .env("SCCACHE_IDLE_TIMEOUT", "0")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    match std::process::Command::new(binary)
        .arg("--show-stats")
        .env("SCCACHE_DIR", &dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
    {
        Ok(s) if s.success() => {
            eprintln!("sccache: shared compile cache at {}", dir.display());
            Some(dir)
        }
        _ => {
            eprintln!("sccache: server did not start; lanes compile without it");
            None
        }
    }
}
fn free_gb(path: &Path) -> Result<f64> {
    let out = std::process::Command::new("df")
        .args(["-Pk", path.to_str().unwrap_or(".")])
        .output()?;
    if !out.status.success() {
        bail!("df could not inspect {}", path.display());
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let line = text
        .lines()
        .last()
        .ok_or_else(|| anyhow!("df returned no filesystem row"))?;
    let fields: Vec<_> = line.split_whitespace().collect();
    let kb = fields
        .get(3)
        .ok_or_else(|| anyhow!("df returned malformed output"))?
        .parse::<f64>()?;
    Ok(kb / 1024.0 / 1024.0)
}
fn now_stamp() -> String {
    std::process::Command::new("date")
        .args(["-u", "+%Y%m%dT%H%M%S"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                .to_string()
        })
}
fn create_lane_dir(root: &Path, id: &str) -> Result<PathBuf> {
    let prefix = format!("{id}-{}-", now_stamp());
    for attempt in 0..100 {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path = root.join(format!(
            "{}{:#x}-{}",
            prefix,
            nanos + attempt,
            std::process::id()
        ));
        match fs::create_dir(&path) {
            Ok(()) => {
                #[cfg(unix)]
                fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o700))?;
                return Ok(path);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e.into()),
        }
    }
    bail!("could not allocate a unique lane directory for {id}")
}
fn class_limit(class: &str) -> usize {
    if let Ok(value) = std::env::var("LANE_CLASS_LIMITS")
        && let Ok(config) = serde_json::from_str::<Value>(&value)
        && let Some(limit) = config.get(class).and_then(Value::as_u64)
    {
        return limit.max(1) as usize;
    }
    if let Ok(hosts) = configured_hosts()
        && let Some(limit) = hosts
            .get("local")
            .and_then(|v| v.get("classLimits").or_else(|| v.get("class_limits")))
            .and_then(|v| v.get(class))
            .and_then(Value::as_u64)
    {
        return limit.max(1) as usize;
    }
    match class {
        "rust" => 2,
        "crate" => 4,
        "pg" => 3,
        "port" => 50,
        _ => 6,
    }
}
fn slot_dir() -> PathBuf {
    std::env::var_os("LANE_SLOT_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(cowproof_core::SLOT_DIR))
}
async fn acquire_slot(class: &str, limit: usize) -> Result<PathBuf> {
    let mut reported_wait = false;
    loop {
        if let Some(s) = try_acquire_slot(class, limit, &slot_dir())? {
            return Ok(s);
        }
        if !reported_wait {
            eprintln!("waiting for a machine-wide {class} slot (limit {limit})");
            reported_wait = true;
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

async fn command(
    cmd: &str,
    args: &[String],
    cwd: Option<&Path>,
    envs: &[(String, String)],
) -> Result<Vec<u8>> {
    let mut c = Command::new(cmd);
    c.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(d) = cwd {
        c.current_dir(d);
    }
    for (k, v) in envs {
        c.env(k, v);
    }
    let out = c
        .output()
        .await
        .with_context(|| format!("starting {cmd}"))?;
    if !out.status.success() {
        bail!(
            "{} {:?} failed ({}): {}",
            cmd,
            args.iter().take(2).collect::<Vec<_>>(),
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(out.stdout)
}
fn run_sync(cmd: &str, args: &[&str]) -> Result<String> {
    let o = std::process::Command::new(cmd).args(args).output()?;
    if !o.status.success() {
        bail!("{cmd} failed: {}", String::from_utf8_lossy(&o.stderr));
    }
    Ok(String::from_utf8_lossy(&o.stdout).trim().to_owned())
}

async fn run_lane(
    job: (PathBuf, String, Header),
    repo: PathBuf,
    root: PathBuf,
    key: String,
    keep_build: bool,
    sccache: Option<PathBuf>,
) -> Result<Value> {
    let (packet, text, h) = job;
    let slot = acquire_slot(&h.class_name, class_limit(&h.class_name)).await?;
    let port_slot = acquire_slot("port", 50).await?;
    let index = port_slot
        .file_name()
        .and_then(|x| x.to_str())
        .and_then(|s| s.split('-').nth(1))
        .and_then(|x| x.parse::<u16>().ok())
        .unwrap_or(0);
    let port = PORT_BASE + index * 20;
    let outcome = run_in_slot(packet, text, h, repo, root, key, port, keep_build, sccache).await;
    release_slot(Some(&port_slot));
    release_slot(Some(&slot));
    outcome
}

#[allow(clippy::too_many_arguments)]
async fn run_in_slot(
    _packet: PathBuf,
    text: String,
    h: Header,
    repo: PathBuf,
    root: PathBuf,
    key: String,
    port: u16,
    keep_build: bool,
    sccache: Option<PathBuf>,
) -> Result<Value> {
    let lane = create_lane_dir(&root, &h.id)?;
    let lane = lane.canonicalize()?;
    let copy = lane.join("repo");
    eprintln!("[{}] cloning into {}", h.id, copy.display());
    #[cfg(target_os = "macos")]
    let cp_args = vec![
        "-Rc".to_owned(),
        repo.display().to_string(),
        copy.display().to_string(),
    ];
    #[cfg(not(target_os = "macos"))]
    let cp_args = vec![
        "-a".into(),
        "--reflink=auto".into(),
        repo.display().to_string(),
        copy.display().to_string(),
    ];
    command("cp", &cp_args, None, &[]).await?;
    command(
        "find",
        &[
            copy.display().to_string(),
            "-name".into(),
            ".env*".into(),
            "-not".into(),
            "-name".into(),
            ".env.example".into(),
            "-exec".into(),
            "rm".into(),
            "-rf".into(),
            "{}".into(),
            "+".into(),
        ],
        None,
        &[],
    )
    .await?;
    let git = |args: Vec<String>| {
        let mut a = vec![
            "-C".into(),
            copy.display().to_string(),
            "-c".into(),
            "core.hooksPath=/dev/null".into(),
            "-c".into(),
            "user.name=lane".into(),
            "-c".into(),
            "user.email=lane@localhost".into(),
        ];
        a.extend(args);
        a
    };
    command("git", &git(vec!["add".into(), "-A".into()]), None, &[]).await?;
    command(
        "git",
        &git(vec![
            "commit".into(),
            "-q".into(),
            "--no-verify".into(),
            "--allow-empty".into(),
            "-m".into(),
            format!("lane baseline {}", h.id),
        ]),
        None,
        &[],
    )
    .await?;
    for d in [
        "home",
        "xdg/config",
        "xdg/data",
        "xdg/cache",
        "xdg/state",
        "tmp",
    ] {
        fs::create_dir_all(lane.join(d))?;
    }
    // D18: the builder's cargo home is lane-private and writable. The real
    // registry and git caches are linked in read-only (the policy grants them
    // read-only); the real ~/.cargo is never writable from the sandbox.
    let lane_cargo = lane.join("home/.cargo");
    fs::create_dir_all(&lane_cargo)?;
    #[cfg(unix)]
    {
        for d in ["registry", "git"] {
            let real = home().join(".cargo").join(d);
            if real.exists() {
                std::os::unix::fs::symlink(real, lane_cargo.join(d))?;
            }
        }
        std::os::unix::fs::symlink(home().join(".rustup"), lane.join("home/.rustup"))?;
    }
    #[cfg(not(unix))]
    fs::create_dir_all(lane.join("home/.rustup"))?;
    fs::create_dir_all(lane.join("control"))?;
    let scratch = PathBuf::from(format!("/tmp/cowproof/l{port}"));
    if scratch_busy(&scratch) {
        bail!(
            "port block {port} has a live PostgreSQL in {}; refusing to reuse it",
            scratch.display()
        );
    }
    let _ = fs::remove_dir_all(&scratch);
    fs::create_dir_all(&scratch)?;
    let (protected, handoff_dir) = repo_rules(&repo);
    let handoff_rel = format!("{handoff_dir}/handoff-{}.md", h.id);
    let owns = if h.is_wide() {
        vec!["**".into()]
    } else {
        let mut o = h.owns.clone();
        o.push(handoff_rel.clone());
        o
    };
    let config = opencode_config(&h.allow);
    fs::write(
        lane.join("opencode.json"),
        serde_json::to_vec_pretty(&config)?,
    )?;
    let codex_home = home().join(".codex");
    let mut extra = if h.runner == "codex" {
        vec![codex_home.clone()]
    } else {
        vec![]
    };
    if sccache.is_some() {
        extra.push(sccache_dir());
    }
    // Legacy runner layout: the whole lane directory is the clone grant until
    // the runner step moves to lane/clone + lane/control; `control` is already
    // denied inside it (A-3).
    let lane_layout = LaneLayout {
        clone: lane.clone(),
        home: lane.join("home"),
        scratch: scratch.clone(),
        control: lane.join("control"),
        real_home: home(),
    };
    let mut policy = SandboxPolicy::builder(&lane_layout, NetworkMode::Unrestricted);
    policy.rw_paths.extend(extra.clone());
    let profile = render_macos_profile(&policy)?;
    fs::write(lane.join("sandbox.sb"), profile)?;
    let branch = run_sync(
        "git",
        &["-C", repo.to_str().unwrap(), "branch", "--show-current"],
    )?;
    let head = run_sync(
        "git",
        &["-C", repo.to_str().unwrap(), "rev-parse", "--short", "HEAD"],
    )?;
    let prompt = format!(
        "{}{}",
        preamble(
            &h,
            &owns,
            &copy,
            &copy.join(&handoff_rel),
            &branch,
            &head,
            port,
            &protected,
            &scratch
        ),
        text
    );
    fs::write(lane.join("prompt.md"), prompt)?;
    let mut env = lane_env(
        &lane,
        &scratch,
        port,
        (h.runner == "opencode").then_some(key.as_str()),
        sccache.is_some(),
    );
    policy.apply_env(&mut env);
    let argv = if h.runner == "codex" {
        codex_argv(
            &h,
            &copy,
            &lane,
            &codex_home,
            port,
            &scratch,
            sccache.is_some(),
        )?
    } else {
        opencode_argv(&h, &copy, &lane)
    };
    let platform = if cfg!(target_os = "macos") {
        "darwin"
    } else {
        std::env::consts::OS
    };
    let profile_path = lane.join("sandbox.sb");
    let (program, argv) = sandbox_command(&policy, &profile_path, &argv, platform)?;
    eprintln!(
        "[{}] running {} {} (timeout {} min{})",
        h.id,
        h.runner,
        h.model(),
        h.timeout(),
        if h.runner == "opencode" {
            format!(", cost cap ${}", h.max_cost())
        } else {
            String::new()
        }
    );
    let started = Instant::now();
    let run_result = run_worker(
        &program,
        &argv,
        &copy,
        &env,
        &lane,
        h.timeout(),
        h.max_cost(),
        &h.runner,
    )
    .await?;
    let _ = stop_postgres(&scratch);
    let _ = fs::remove_dir_all(&scratch);
    command("git", &git(vec!["add".into(), "-A".into()]), None, &[]).await?;
    let changed_text = String::from_utf8(
        command(
            "git",
            &git(vec![
                "diff".into(),
                "--cached".into(),
                "--name-only".into(),
                "HEAD".into(),
            ]),
            None,
            &[],
        )
        .await?,
    )?;
    let changed: Vec<String> = changed_text
        .lines()
        .filter(|s| !s.is_empty() && !is_scratch(s))
        .map(str::to_owned)
        .collect();
    let violations = outside_ownership(&changed, &owns, &protected);
    let in_scope: Vec<String> = changed
        .iter()
        .filter(|f| !violations.contains(f))
        .cloned()
        .collect();
    let lane_patch = diff_paths(&git, &lane, &in_scope).await?;
    fs::write(lane.join("lane.patch"), &lane_patch)?;
    let breaches: Vec<Value> = h
        .append_only
        .iter()
        .filter_map(|(file, max)| {
            let removed = removed_lines(&lane_patch, file);
            (removed > *max).then(|| json!({"file":file,"removed":removed,"max":max}))
        })
        .collect();
    if !violations.is_empty() {
        let p = diff_paths(&git, &lane, &violations).await?;
        fs::write(lane.join("outside-ownership.patch"), p)?;
    }
    let handoff = copy.join(&handoff_rel).exists().then_some(handoff_rel);
    let mut status = run_result.status.clone();
    if let Some(refusal) = &run_result.refusal {
        status = format!("provider refused: {refusal}");
    } else if !breaches.is_empty() {
        status = format!(
            "failed: removed lines from append-only {}",
            breaches
                .iter()
                .map(|b| format!("{} ({} > {})", b["file"], b["removed"], b["max"]))
                .collect::<Vec<_>>()
                .join(", ")
        );
    } else if status == "finished" && handoff.is_none() {
        status = if run_result.truncated > 0 {
            "failed: cut off by the length limit, no handoff".into()
        } else {
            "failed: no handoff".into()
        };
    }
    if run_result.exit != Some(0) {
        status = format!(
            "{status} (exit {})",
            run_result
                .exit
                .map_or_else(|| "null".into(), |n| n.to_string())
        );
    }
    let seconds = (started.elapsed().as_secs_f64().round() as u64).max(1);
    let estimate = h.estimate_hours.map_or(Value::Null, |n| json!(n));
    let summary = json!({"id":h.id,"runner":h.runner,"model":h.model(),"estimateHours":estimate,"status":status,"seconds":seconds,"costUsd":if h.runner=="codex"{Value::Null}else{json!((run_result.cost*10000.0).round()/10000.0)},"tokens":run_result.tokens,"changed":in_scope,"outsideOwnership":violations.iter().take(50).collect::<Vec<_>>(),"outsideCount":violations.len(),"handoff":handoff,"laneDir":lane,"finalText":run_result.final_text.chars().take(2000).collect::<String>()});
    fs::write(
        lane.join("summary.json"),
        serde_json::to_vec_pretty(&summary)?,
    )?;
    if !keep_build && !h.keep_build {
        let removed = remove_build_output(&copy);
        if !removed.is_empty() {
            eprintln!("[{}] removed build output: {}", h.id, removed.join(", "));
        }
    }
    let ok = summary["status"]
        .as_str()
        .unwrap_or("")
        .starts_with("finished");
    let ledger = json!({"at":chrono_like_now(),"id":h.id,"model":h.model(),"ok":ok,"estimateHours":estimate,"actualHours":((seconds as f64/3600.0)*100.0).round()/100.0,"costUsd":summary["costUsd"],"tokens":run_result.token_total()});
    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(root.join("ledger.jsonl"))?;
    writeln!(f, "{}", ledger)?;
    eprintln!(
        "[{}] {} in {}s, {}",
        h.id,
        summary["status"],
        seconds,
        if h.runner == "codex" {
            format!("{} tokens (plan usage)", run_result.token_total())
        } else {
            format!("${:.4}", run_result.cost)
        }
    );
    Ok(summary)
}

/// Scratch directories, and build output at any depth (parity with the Node runner's SCRATCH pattern).
fn is_scratch(s: &str) -> bool {
    let top = s.split_once('/').is_some_and(|(root, _)| {
        ["tmp-", "mail-local-pg-", "mail-assert-"]
            .iter()
            .any(|p| root.starts_with(p))
    });
    top || s
        .split('/')
        .rev()
        .skip(1)
        .any(|dir| dir == "target" || dir == "node_modules")
}
fn scratch_busy(root: &Path) -> bool {
    fn check(p: &Path) -> bool {
        let Ok(s) = fs::read_to_string(p) else {
            return false;
        };
        let Some(pid) = s.lines().next().and_then(|n| n.parse::<u32>().ok()) else {
            return false;
        };
        #[cfg(unix)]
        {
            std::process::Command::new("kill")
                .args(["-0", pid.to_string().as_str()])
                .status()
                .is_ok_and(|s| s.success())
        }
        #[cfg(not(unix))]
        {
            let _ = pid;
            true
        }
    }
    fn walk(d: &Path, depth: u8) -> bool {
        if depth > 4 {
            return false;
        }
        let Ok(it) = fs::read_dir(d) else {
            return false;
        };
        for e in it.flatten() {
            let p = e.path();
            if p.file_name() == Some(std::ffi::OsStr::new("postmaster.pid")) && check(&p) {
                return true;
            }
            if p.is_dir() && walk(&p, depth + 1) {
                return true;
            }
        }
        false
    }
    walk(root, 0)
}
fn stop_postgres(root: &Path) -> Result<()> {
    fn walk(p: &Path, depth: u8) {
        if depth > 4 {
            return;
        }
        let Ok(it) = fs::read_dir(p) else { return };
        for e in it.flatten() {
            let q = e.path();
            if q.file_name() == Some(OsStr::new("postmaster.pid")) {
                if let Ok(s) = fs::read_to_string(q)
                    && let Some(pid) = s.lines().next()
                {
                    let _ = std::process::Command::new("kill")
                        .args(["-QUIT", pid])
                        .status();
                }
            } else if q.is_dir() {
                walk(&q, depth + 1);
            }
        }
    }
    walk(root, 0);
    Ok(())
}
fn opencode_config(allow: &[String]) -> Value {
    let base = [
        "ls*",
        "pwd",
        "cat *",
        "head *",
        "tail *",
        "wc *",
        "grep *",
        "rg *",
        "sed -n *",
        "diff *",
        "git status*",
        "git diff*",
        "git log*",
        "git show*",
        "node --check *",
        "node --test *",
        "rm -rf tmp-*",
        "rm -rf ./tmp-*",
    ];
    let mut bash = serde_json::Map::new();
    bash.insert("*".into(), json!("deny"));
    for p in base
        .iter()
        .map(|s| s.to_string())
        .chain(allow.iter().cloned())
    {
        bash.insert(p, json!("allow"));
    }
    json!({"$schema":"https://opencode.ai/config.json","autoupdate":false,"share":"disabled","plugin":[],"permission":{"edit":"allow","webfetch":"deny","external_directory":"deny","bash":bash}})
}
#[allow(clippy::too_many_arguments)]
fn preamble(
    h: &Header,
    owns: &[String],
    copy: &Path,
    handoff: &Path,
    branch: &str,
    head: &str,
    port: u16,
    protected: &[String],
    scratch: &Path,
) -> String {
    const BASE_ALLOW: [&str; 18] = [
        "ls*",
        "pwd",
        "cat *",
        "head *",
        "tail *",
        "wc *",
        "grep *",
        "rg *",
        "sed -n *",
        "diff *",
        "git status*",
        "git diff*",
        "git log*",
        "git show*",
        "node --check *",
        "node --test *",
        "rm -rf tmp-*",
        "rm -rf ./tmp-*",
    ];
    let rules = protected.join(", ");
    let body = if h.is_wide() {
        format!(
            "Your focus is: {}. You may change any file the work needs, except these protected paths, whose changes are discarded: {rules}. List every file you changed outside the focus in your handoff, with the reason.\nUse any shell commands you need, including pipes and &&, inside this copy.",
            h.owns.join(", ")
        )
    } else {
        format!(
            "You may create or change ONLY these paths: {}. Changes to any other file are discarded.\nOnly these commands run; everything else is refused: {}.",
            owns.join(", "),
            BASE_ALLOW
                .iter()
                .map(|s| s.to_string())
                .chain(h.allow.iter().cloned())
                .collect::<Vec<_>>()
                .join(" | ")
        )
    };
    let net = if h.network {
        "Do not run git commit, deploy, or read any .env file. You may reach package registries (npm, crates.io) to resolve and install dependencies; no other network service."
    } else {
        "Do not run git commit, deploy, contact any network service, or read any .env file."
    };
    let web = if h.web_search {
        " You may use your web search tool to read public documentation, pricing and specification pages. Cite each source with its URL and the date you read it. No sign-ins, uploads, forms or accounts."
    } else {
        ""
    };
    let scratch_note = if h.is_wide() {
        "Put scratch output in directories named tmp-* at the top of your working directory (never part of your patch), or under $LANE_SCRATCH."
    } else {
        "Run one command per call. Put scratch output in directories named tmp-* at the top of your working directory; they are never part of your patch and you may remove them with rm -rf tmp-<name>. Commands joined with &&, ; or | are refused."
    };
    let completion = if h.is_wide() {
        "Own the outcome. Keep working until every check the packet names passes: when a check fails, find the cause (read logs, add temporary diagnostics, rerun) and fix it, wherever in the repository the fix belongs. Do not hand back partial work while you still have time. Stop early only for a genuine design question the packet does not answer; then state the question, your recommended answer and why. Never weaken a test, a policy or a check to make it pass, and never leave placeholders."
    } else {
        "If the packet is ambiguous or a check fails in a way you cannot fix inside your paths, stop and explain it in the handoff. Do not guess."
    };
    format!(
        "You are an engineering worker lane named {}. A director reviews your work before anything is merged.\nYour working directory is {}. It is an isolated copy of the repository; nothing outside it is reachable.\n{}\nYour network port block is {} to {}; use only those ports for any database or server you start.\nFor database scratch space use the short directory in $LANE_SCRATCH ({}), for example --scratch-parent \"$LANE_SCRATCH\" or --work \"$LANE_SCRATCH/verify\": PostgreSQL socket paths are limited to 103 bytes, so paths inside your working directory are too long. The runner deletes it after you finish; you do not need to remove it.\n{scratch_note}\nThe real starting state is branch {branch} at {head}, with uncommitted work. The runner committed that whole tree as a baseline in your copy, so git shows it as clean; report the real starting state, not the baseline.\n{net}{web}\nWork alone: do not spawn subagents, reviewers or other models, and do not use orchestration skills (such as astra-orchestrator); the director reviews your work.\n{completion}\nFinish by writing your handoff to {}: what you changed and why, the exact commands you ran with their actual results, what is unverified, and any question for the director.\n\nThe full lane packet follows. Read all of it before acting.\n\n",
        h.id,
        copy.display(),
        body,
        port,
        port + 19,
        scratch.display(),
        handoff.display()
    )
}
/// The worker's PATH, with the real Node binary's directory first. Version-manager shims (proto, asdf, nvm)
/// resolve Node through files under HOME or the network, both closed inside the sandbox; the Node runner
/// escaped this only because it ran under the real binary. Found by the first live Rust lane, 2026-09-26.
fn worker_path() -> String {
    let path = std::env::var("PATH").unwrap_or_default();
    let real_node_dir = std::process::Command::new("node")
        .args(["-p", "process.execPath"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|p| {
            Path::new(p.trim())
                .parent()
                .map(|d| d.display().to_string())
        });
    match real_node_dir {
        Some(dir) if !path.split(':').next().is_some_and(|first| first == dir) => {
            format!("{dir}:{path}")
        }
        _ => path,
    }
}

fn lane_env(
    lane: &Path,
    scratch: &Path,
    port: u16,
    key: Option<&str>,
    has_sccache: bool,
) -> Vec<(String, String)> {
    let mut e = Vec::new();
    for (k, v) in [
        ("PATH", worker_path()),
        ("HOME", lane.join("home").display().to_string()),
        ("LANG", "en_US.UTF-8".into()),
        ("CARGO_HOME", home().join(".cargo").display().to_string()),
        ("RUSTUP_HOME", home().join(".rustup").display().to_string()),
        (
            "OPENCODE_CONFIG",
            lane.join("opencode.json").display().to_string(),
        ),
        ("TMPDIR", lane.join("tmp").display().to_string()),
        (
            "XDG_CONFIG_HOME",
            lane.join("xdg/config").display().to_string(),
        ),
        ("XDG_DATA_HOME", lane.join("xdg/data").display().to_string()),
        (
            "XDG_CACHE_HOME",
            lane.join("xdg/cache").display().to_string(),
        ),
        (
            "XDG_STATE_HOME",
            lane.join("xdg/state").display().to_string(),
        ),
        ("GIT_CONFIG_GLOBAL", "/dev/null".into()),
        ("GIT_CONFIG_NOSYSTEM", "1".into()),
        ("CARGO_NET_OFFLINE", "true".into()),
        ("CARGO_BUILD_JOBS", "4".into()),
        ("LANE_PORT_BASE", port.to_string()),
        ("LANE_SCRATCH", scratch.display().to_string()),
    ] {
        e.push((k.into(), v));
    }
    if let Some(key) = key {
        e.push(("OPENROUTER_API_KEY".into(), key.into()));
    }
    if has_sccache {
        if let Some(binary) = find_sccache() {
            e.push(("RUSTC_WRAPPER".into(), binary.display().to_string()));
        }
        e.push(("SCCACHE_DIR".into(), sccache_dir().display().to_string()));
        e.push(("CARGO_INCREMENTAL".into(), "0".into()));
    }
    e
}
fn opencode_argv(h: &Header, copy: &Path, lane: &Path) -> Vec<String> {
    let mut a = vec![
        "opencode".into(),
        "run".into(),
        "--pure".into(),
        "-m".into(),
        format!("openrouter/{}", h.model()),
    ];
    if let Some(v) = &h.variant {
        a.extend(["--variant".into(), v.clone()]);
    }
    a.extend([
        "--dir".into(),
        copy.display().to_string(),
        "--format".into(),
        "json".into(),
        lane.join("prompt.md").display().to_string(),
    ]);
    a
}
fn codex_argv(
    h: &Header,
    copy: &Path,
    lane: &Path,
    codex_home: &Path,
    port: u16,
    scratch: &Path,
    has_sccache: bool,
) -> Result<Vec<String>> {
    let mut a = vec![
        "codex".into(),
        "exec".into(),
        "--json".into(),
        "--ephemeral".into(),
        "-m".into(),
        h.model().into(),
    ];
    a.extend(codex_isolation_args(copy, codex_home));
    if h.web_search {
        a.extend(["-c".into(), "web_search=\"live\"".into()]);
    }
    a.extend([
        "-c".into(),
        format!("model_reasoning_effort=\"{}\"", h.effort()),
        "--dangerously-bypass-approvals-and-sandbox".into(),
        "-C".into(),
        copy.display().to_string(),
        "-c".into(),
        "notify=[]".into(),
        "-c".into(),
        "mcp_servers={}".into(),
    ]);
    let mut shell_env = vec![
        ("LANE_PORT_BASE", port.to_string()),
        ("LANE_SCRATCH", scratch.display().to_string()),
        ("CARGO_BUILD_JOBS", "4".into()),
        ("CARGO_NET_OFFLINE", "true".into()),
    ];
    if has_sccache {
        if let Some(binary) = find_sccache() {
            shell_env.push(("RUSTC_WRAPPER", binary.display().to_string()));
        }
        shell_env.push(("SCCACHE_DIR", sccache_dir().display().to_string()));
        shell_env.push(("CARGO_INCREMENTAL", "0".into()));
    }
    for (k, v) in shell_env {
        a.extend([
            "-c".into(),
            format!("shell_environment_policy.set.{k}=\"{v}\""),
        ]);
    }
    a.extend([
        "-o".into(),
        lane.join("last-message.txt").display().to_string(),
        lane.join("prompt.md").display().to_string(),
    ]);
    Ok(a)
}
async fn diff_paths(
    git: &impl Fn(Vec<String>) -> Vec<String>,
    lane: &Path,
    paths: &[String],
) -> Result<String> {
    if paths.is_empty() {
        return Ok(String::new());
    }
    let mut a = git(vec!["reset".into(), "-q".into()]);
    command("git", &a, None, &[]).await?;
    let f = lane.join("paths.txt");
    let mut file = tokio::fs::File::create(&f).await?;
    file.write_all(paths.join("\n").as_bytes()).await?;
    file.write_all(b"\n").await?;
    a = git(vec![
        "add".into(),
        "-A".into(),
        format!("--pathspec-from-file={}", f.display()),
    ]);
    command("git", &a, None, &[]).await?;
    let out = command(
        "git",
        &git(vec![
            "diff".into(),
            "--cached".into(),
            "--binary".into(),
            "HEAD".into(),
        ]),
        None,
        &[],
    )
    .await?;
    Ok(String::from_utf8_lossy(&out).to_string())
}
fn chrono_like_now() -> String {
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_millis();
    std::process::Command::new("date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%S.000Z"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .trim()
                .replace(".000Z", &format!(".{ms:03}Z"))
        })
        .unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                .to_string()
        })
}

#[derive(Default)]
struct WorkerResult {
    status: String,
    exit: Option<i32>,
    cost: f64,
    tokens: TokenStats,
    truncated: usize,
    refusal: Option<String>,
    final_text: String,
}
#[derive(Default, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct TokenStats {
    input: u64,
    output: u64,
    cache_read: u64,
}
impl WorkerResult {
    fn token_total(&self) -> u64 {
        self.tokens.input + self.tokens.output
    }
}
#[allow(clippy::too_many_arguments)]
async fn run_worker(
    program: &str,
    args: &[String],
    cwd: &Path,
    env: &[(String, String)],
    lane: &Path,
    timeout_min: u64,
    max_cost: f64,
    runner: &str,
) -> Result<WorkerResult> {
    let mut c = Command::new(program);
    c.args(args)
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in env {
        c.env(k, v);
    }
    if runner == "codex" {
        c.env("CODEX_HOME", home().join(".codex"));
    }
    let mut child = c.spawn().with_context(|| format!("starting {program}"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("worker stdout unavailable"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow!("worker stderr unavailable"))?;
    let mut result = WorkerResult {
        status: "finished".into(),
        ..Default::default()
    };
    let mut events = tokio::fs::File::create(lane.join("events.jsonl")).await?;
    let mut errfile = tokio::fs::File::create(lane.join("opencode.err")).await?;
    let stderr_task = tokio::spawn(async move {
        let mut r = BufReader::new(stderr);
        let mut b = Vec::new();
        let _ = r.read_to_end(&mut b).await;
        let s = String::from_utf8_lossy(&b).replace_regex_secrets();
        let _ = errfile.write_all(s.as_bytes()).await;
    });
    let mut lines = BufReader::new(stdout).lines();
    let future = async {
        while let Some(line) = lines.next_line().await? {
            events.write_all(line.as_bytes()).await?;
            events.write_all(b"\n").await?;
            let Ok(e) = serde_json::from_str::<Value>(&line) else {
                continue;
            };
            consume_event(&e, &line, &mut result, runner);
            if result.cost > max_cost && runner == "opencode" && result.status == "finished" {
                result.status = "cost-cap".into();
                terminate(&mut child);
                break;
            }
        }
        let status = child.wait().await?;
        Ok::<_, anyhow::Error>(status)
    };
    let exit =
        match tokio::time::timeout(Duration::from_secs(timeout_min.saturating_mul(60)), future)
            .await
        {
            Ok(v) => v?,
            Err(_) => {
                result.status = "timeout".into();
                terminate(&mut child);
                child.wait().await?
            }
        };
    result.exit = exit.code();
    let _ = stderr_task.await;
    Ok(result)
}
fn terminate(child: &mut tokio::process::Child) {
    if let Some(pid) = child.id() {
        #[cfg(unix)]
        {
            let _ = std::process::Command::new("kill")
                .args(["-TERM", &pid.to_string()])
                .status();
        }
        #[cfg(not(unix))]
        {
            let _ = child.start_kill();
        }
    }
}
trait Redact {
    fn replace_regex_secrets(&self) -> String;
}
impl Redact for str {
    fn replace_regex_secrets(&self) -> String {
        let mut s = self.to_owned();
        let marker = "sk-or-";
        let mut at = 0;
        while let Some(i) = s[at..].find(marker) {
            let start = at + i;
            let end = s[start..]
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '-'))
                .map_or(s.len(), |j| start + j);
            s.replace_range(start..end, "[redacted]");
            at = start + 10;
            if at >= s.len() {
                break;
            }
        }
        s
    }
}
fn consume_event(e: &Value, line: &str, r: &mut WorkerResult, runner: &str) {
    let p = &e["part"];
    match e["type"].as_str().unwrap_or("") {
        "step_finish" => {
            r.cost += p["cost"].as_f64().unwrap_or(0.);
            r.tokens.input += p["tokens"]["input"].as_u64().unwrap_or(0);
            r.tokens.output += p["tokens"]["output"].as_u64().unwrap_or(0)
                + p["tokens"]["reasoning"].as_u64().unwrap_or(0);
            r.tokens.cache_read += p["tokens"]["cache"]["read"].as_u64().unwrap_or(0);
            if p["reason"] == "length" {
                r.truncated += 1;
            }
        }
        "text" => {
            if let Some(t) = p["text"].as_str() {
                r.final_text = t.into()
            }
        }
        "turn.completed" if runner == "codex" => {
            r.tokens.input += e["usage"]["input_tokens"].as_u64().unwrap_or(0);
            r.tokens.output += e["usage"]["output_tokens"].as_u64().unwrap_or(0);
            r.tokens.cache_read += e["usage"]["cached_input_tokens"].as_u64().unwrap_or(0)
        }
        "item.completed" if runner == "codex" && e["item"]["type"] == "agent_message" => {
            if let Some(t) = e["item"]["text"].as_str() {
                r.final_text = t.into()
            }
        }
        _ => {}
    }
    let message = e["error"]["message"]
        .as_str()
        .or_else(|| e["message"].as_str())
        .unwrap_or(line);
    let lower = message.to_ascii_lowercase();
    if r.refusal.is_none()
        && (e["type"] == "error" || e["type"] == "turn.failed")
        && ["budget", "credit", "quota", "rate limit"]
            .iter()
            .any(|p| lower.contains(p))
        && ["exceed", "insufficient", "reached", "limit"]
            .iter()
            .any(|p| lower.contains(p))
    {
        r.refusal = Some(message.chars().take(500).collect());
    }
}

#[cfg(test)]
mod cli_tests {
    use super::*;

    #[test]
    fn lint_root_is_the_git_top_level_containing_the_packet() {
        let root = std::env::temp_dir().join(format!("lanes-cli-lint-root-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("docs/packets")).unwrap();
        let init = std::process::Command::new("git")
            .arg("init")
            .arg("-q")
            .arg(&root)
            .status()
            .unwrap();
        assert!(init.success());
        fs::write(root.join("docs/packets/lane.md"), "packet").unwrap();
        assert_eq!(
            git_root_containing(&root.join("docs/packets/lane.md")).unwrap(),
            root.canonicalize().unwrap()
        );
        let _ = fs::remove_dir_all(root);
    }
}
