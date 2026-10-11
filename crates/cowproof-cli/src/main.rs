#![forbid(unsafe_code)]

use anyhow::{Context, Result, anyhow, bail};
use clap::Parser;
use cowproof_host::{
    SystemRunner, collect_facts, enforce_disk_floor, ensure_safe_to_stop, lane_status,
    parse_df_free, read_host_config, stop_lane,
};
use cowproof_lint::{Finding, Severity, lint_packet};
use cowproof_plan::{
    HostCapacity, LaneStateUpdate, PlanHostRunner, check_plans, choose_host, collect_running,
    duplicate_running_id, lanes as plan_lanes, load_plans, ready_next, set_lane_state,
};
use cowproof_run::bridge::{bind_bridge, serve_bridge};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::collections::HashSet;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

mod director_tools;
mod doctor;
mod lane_tools;
mod preflight;
mod root;
mod run;
mod verify;
mod watch;

#[derive(Parser)]
#[command(name = "cowproof", about = "Run isolated engineering lanes", version)]
struct Args {
    #[command(subcommand)]
    command: Action,
}
#[derive(clap::Subcommand)]
enum Action {
    /// Run one packet: lint, prepare the lane, launch the sandboxed builder, then prove the lane.
    ///
    /// After the builder exits, the last result it recorded through `run_check` for each declared
    /// check is replayed by the verifier in a fresh sandbox, the gates run, and the verdict is
    /// written to `control/verdict.json` and printed on one line.
    ///
    /// Exit codes: 0 proved; 2 refuted (a recorded check failed, verify diverged, or a gate
    /// failed); 3 incomplete (a declared check was never run); 4 infrastructure (the proof could
    /// not run, never a refutation); 5 timeout (wall-clock limit exceeded, nothing is proved,
    /// `control/run.json` says `timeout`); 6 cost-cap (cost estimate reached 100% of the cap,
    /// nothing is proved, `control/run.json` says `cost-cap`); 1 the run itself failed before
    /// a verdict; 130 interrupted by SIGINT or SIGTERM (the builder's process group is ended,
    /// nothing is proved, and `control/run.json` says `interrupted`).
    Run(RunOneArgs),
    /// Replay a proof capsule against a repository, from any directory
    ///
    /// Rebuilds the capsule's base commit from `--repo`, applies its patches and re-runs
    /// every recorded check, then every held-out check, in the verifier sandbox. Exit
    /// codes: 0 reproduced; 2 diverged (a check named in the output); 4 infrastructure.
    Verify(verify::VerifyArgs),
    /// Check that this host can run lanes: sandbox, clone, disk, claude, key, git.
    ///
    /// `cowproof run` runs the same checks first and stops on any failure with exit 4.
    /// The sandbox check runs `true` through the runner's own sandbox, so it passes only
    /// when a lane could start. Exit codes: 0 no check failed (warnings do not count; a
    /// missing API key is a warning here and a failure for `run`); 1 a check failed.
    Doctor(doctor::DoctorArgs),
    Lint(LintArgs),
    Host(HostArgs),
    Hosts,
    Plan(PlanArgs),
    /// Observe lanes and their escalation events.
    Watch(watch::WatchArgs),
    /// Rule on an open escalation: `cowproof rule <lane-id> <escalation-id> (--answer <text> | --redirect <packet> | --reassign [--model <m>] | --stop) [--lanes-root <dir>]`
    Rule(RuleArgs),
    /// Send a note to a running lane: `cowproof note <lane-id> <text> [--lanes-root <dir>]`
    Note(NoteArgs),
    /// Ask the director a question (mirrors the MCP `ask` tool for runtimes without MCP).
    Ask(AskArgs),
    /// Check the status of an ask or retrieve notes (mirrors the MCP `check_ruling` tool).
    Ruling(RulingArgs),
    /// Run a declared check (mirrors the MCP `run_check` tool).
    Check(CheckArgs),
    /// The builder's tools (`ask`, `check_ruling`, `run_check`) as an MCP
    /// stdio server. It runs inside the sandbox and is only a client of the
    /// runner socket; the builder runtime launches it, people do not.
    #[command(hide = true)]
    LaneTools(LaneToolsArgs),
    /// The director's MCP server for Claude Code's `.mcp.json` (D4).
    ///
    /// `cowproof serve --director` serves the tools `lanes`, `events`, `rule` and
    /// `note` over stdio, for the director's own Claude Code session:
    /// `claude mcp add cowproof -- cowproof serve --director`. No tool waits for a
    /// lane; `events` returns what is there and a cursor to poll with.
    Serve(ServeArgs),
    /// The in-sandbox bridge from `127.0.0.1:<port>` to the lane's proxy
    /// socket (D24). Without a command it serves and prints `READY` on stderr
    /// once bound. With `-- <command>` it starts that bridge first, waits up to
    /// thirty seconds for `READY`, then replaces itself with the command, so the
    /// command's exit status is the process's own. The runtime launches it;
    /// people do not.
    #[command(hide = true)]
    NetBridge(NetBridgeArgs),
    /// Run portkit commands.
    #[command(disable_help_flag = true, disable_version_flag = true)]
    Pk {
        /// Arguments passed to pk.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Read file contents, tracking what the caller already has.
    #[command(disable_help_flag = true, disable_version_flag = true)]
    Read {
        /// Arguments passed to pk-read.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
}
#[derive(Parser)]
struct RuleArgs {
    /// The lane ID.
    lane_id: String,
    /// The escalation ID (e.g., "lane-id:E1").
    escalation_id: String,
    /// Answer the question with text.
    #[arg(long, group = "verdict")]
    answer: Option<String>,
    /// Redirect to a new packet.
    #[arg(long, group = "verdict")]
    redirect: Option<PathBuf>,
    /// Reassign to the next model on the ladder.
    #[arg(long, group = "verdict")]
    reassign: bool,
    /// Specific model to reassign to (optional, only with --reassign).
    #[arg(long, requires = "reassign")]
    model: Option<String>,
    /// Stop the lane.
    #[arg(long, group = "verdict")]
    stop: bool,
    /// Lanes root directory (auto-detected if not specified).
    #[arg(long)]
    lanes_root: Option<PathBuf>,
}

#[derive(Parser)]
struct NoteArgs {
    /// The lane ID.
    lane_id: String,
    /// The note text.
    text: String,
    /// Lanes root directory (auto-detected if not specified).
    #[arg(long)]
    lanes_root: Option<PathBuf>,
}

#[derive(Parser)]
struct AskArgs {
    /// The question kind: blocker, design, scope, or environment.
    #[arg(long)]
    kind: String,
    /// The question text (one paragraph); use `-` to read from stdin.
    #[arg(long)]
    question: String,
    /// What was attempted and what happened (repeatable).
    #[arg(long)]
    tried: Vec<String>,
    /// An option the director can choose from (repeatable, format: id:summary:cost).
    #[arg(long)]
    option: Vec<String>,
    /// The id of the recommended option.
    #[arg(long)]
    recommend: String,
    /// Whether this ask blocks the builder until ruled (default: false).
    #[arg(long, action = clap::ArgAction::SetTrue)]
    blocking: bool,
    /// The runner socket path (defaults to env var COWPROOF_RUNNER_SOCKET).
    #[arg(long)]
    socket: Option<PathBuf>,
}

#[derive(Parser)]
struct RulingArgs {
    /// The ask ID to check (optional; omit to check for notes only).
    id: Option<String>,
    /// The runner socket path (defaults to env var COWPROOF_RUNNER_SOCKET).
    #[arg(long)]
    socket: Option<PathBuf>,
}

#[derive(Parser)]
struct CheckArgs {
    /// The check ID declared in the packet.
    check_id: String,
    /// The runner socket path (defaults to env var COWPROOF_RUNNER_SOCKET).
    #[arg(long)]
    socket: Option<PathBuf>,
}

#[derive(Parser)]
struct LaneToolsArgs {
    /// The lane's runner socket, `<lane>/sock/runner.sock`.
    #[arg(long)]
    socket: PathBuf,
}

#[derive(Parser)]
struct ServeArgs {
    /// Serve the director's tools (`lanes`, `events`, `rule`, `note`).
    #[arg(long, required = true)]
    director: bool,
    /// Lanes root the tools use unless a call names its own `lanes_root`
    /// (default: ~/.cache/cowproof/lanes, as for `cowproof run` and `watch`).
    #[arg(long)]
    lanes_root: Option<PathBuf>,
}

#[derive(Parser)]
struct NetBridgeArgs {
    /// Port to bind on `127.0.0.1`.
    #[arg(long)]
    port: u16,
    /// Unix socket path to relay to.
    #[arg(long)]
    target: PathBuf,
    /// Exit when this process is no longer the parent (set by the wrapper, so
    /// the bridge never outlives the command it serves).
    #[arg(long, hide = true)]
    watch_parent: Option<u32>,
    /// The command to run once the bridge is ready, as argv (no shell).
    #[arg(last = true)]
    command: Vec<String>,
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
struct RunOneArgs {
    /// Packet file to run
    #[arg(value_name = "PACKET")]
    packet: PathBuf,
    /// Repository to run the packet against (default: the current directory)
    #[arg(long)]
    repo: Option<PathBuf>,
    /// Directory that holds the lanes (default: ~/.cache/cowproof/lanes)
    #[arg(long)]
    lanes_root: Option<PathBuf>,
    /// Builder model
    #[arg(long, default_value = "haiku")]
    model: String,
    /// Record uncommitted changes as the base patch instead of refusing a dirty tree
    #[arg(long)]
    allow_dirty: bool,
    /// The Claude Code executable, resolved once on the director's PATH
    #[arg(long, default_value = "claude")]
    claude_bin: String,
    /// Hard cap on builder turns per session, passed to the builder (`--max-turns`)
    #[arg(long, default_value_t = 60)]
    max_turns: u32,
    /// Escalate early when the builder reaches this many assistant turns (counted from the
    /// stream; once per segment, which restarts at a reassign). The runner then ends the session
    /// and parks the lane for a ruling, exactly like a blocking ask
    #[arg(long, default_value_t = 40)]
    turn_budget: u32,
    /// The lane's cost cap in US dollars. Escalate early when the running cost ESTIMATE (per-turn
    /// usage times a built-in price table for haiku, sonnet and opus; unknown models are priced
    /// as opus) reaches 40% of it, once per segment. At 100% the lane ends: the builder's group
    /// is ended, nothing is proved, `run.json` says `cost-cap` and the exit code is 6. The
    /// packet header's `maxCostUsd` wins over this flag. The figure is an estimate, not the bill
    #[arg(long, default_value_t = 5.0)]
    cost_cap_usd: f64,
    /// The lane's wall-clock limit in minutes, over every launch of the lane (resumes included)
    /// and not counting time parked waiting for a ruling. At the limit the builder's group is
    /// ended, nothing is proved, `run.json` says `timeout` and the exit code is 5. The packet
    /// header's `timeoutMin` wins over this flag
    #[arg(long, default_value_t = 45)]
    timeout_min: u64,
    /// The wall-clock limit in seconds, replacing `--timeout-min` (the header's `timeoutMin`
    /// still wins). It exists so tests can reach the limit in seconds, not in minutes
    #[arg(long, hide = true)]
    timeout_secs: Option<u64>,
    /// Free space, in GB, on the lanes filesystem below which the preflight fails the run
    /// (exit 4, before any lane exists)
    #[arg(long, default_value_t = 5.0)]
    disk_floor_gb: f64,
    /// Held-out checks file (D5). It must lie outside the repository; the runner copies it
    /// into the capsule's `packets/`, never into the lane's clone or home. Default:
    /// `~/.cowproof/heldout/<repo-id>/<lane-id>.toml`, used when that file exists
    #[arg(long)]
    heldout: Option<PathBuf>,
    /// Directory of the machine-wide class slots (D12), shared by every `cowproof run` and
    /// `cowproof verify` on this machine. Default: `$COWPROOF_SLOT_DIR`, else
    /// `~/.cache/cowproof/slots`. The run takes a slot of its packet's class before it starts
    /// the builder and waits when none is free (the wait counts toward neither the time limit
    /// nor the cost). The run also holds one `port` slot, whose number is its port block
    /// (`COWPROOF_PORT_BASE`). The limits are the base commit's `cowproof.toml` `[classes]`,
    /// else `light` 6, `crate` 4, `rust` 2, `pg` 3, `port` 50
    #[arg(long)]
    slot_dir: Option<PathBuf>,
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
async fn main() -> std::process::ExitCode {
    match Args::parse().command {
        // The portkit commands own their exit codes, so they bypass `dispatch`.
        Action::Pk { args } => cowproof_cli::pk::run(args).await,
        Action::Read { args } => portkit_read::run(args),
        command => match dispatch(command).await {
            Ok(()) => std::process::ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("Error: {err:?}");
                std::process::ExitCode::FAILURE
            }
        },
    }
}

async fn dispatch(command: Action) -> Result<()> {
    match command {
        Action::Run(args) => {
            let code = run::run_one(args).await?;
            if code != 0 {
                std::process::exit(code);
            }
            Ok(())
        }
        Action::Verify(args) => {
            let code = verify::verify_capsule(args).await?;
            if code != 0 {
                std::process::exit(code);
            }
            Ok(())
        }
        Action::Doctor(args) => {
            let code = doctor::doctor(args).await?;
            if code != 0 {
                std::process::exit(code);
            }
            Ok(())
        }
        Action::Lint(args) => lint_command(args),
        Action::Host(args) => host_command(args.command),
        Action::Hosts => hosts_command(),
        Action::Plan(args) => match args.command {
            PlanAction::Run { repo, max, dry_run } => plan_run(&repo, max, dry_run),
            PlanAction::Collect { repo } => plan_collect(&repo),
        },
        Action::Watch(args) => watch::watch(args).await,
        Action::Rule(args) => rule_command(args).await,
        Action::Note(args) => note_command(args).await,
        Action::Ask(args) => ask_command(args).await,
        Action::Ruling(args) => ruling_command(args).await,
        Action::Check(args) => check_command(args).await,
        Action::LaneTools(args) => lane_tools::run(args.socket).await,
        Action::Serve(args) => director_tools::run(args.lanes_root).await,
        Action::NetBridge(args) => net_bridge_command(args).await,
        Action::Pk { .. } | Action::Read { .. } => {
            unreachable!("pk and read return their own exit code from main")
        }
    }
}

/// How long the wrapper waits for its bridge to report `READY`.
/// 30 s because a first launch of a freshly linked binary took 10.4 s on macOS.
const BRIDGE_READY_TIMEOUT: Duration = Duration::from_secs(30);
/// How long a bridge retries a busy port before it gives up. Shorter than
/// [`BRIDGE_READY_TIMEOUT`], so the wrapper sees the failure, not a timeout.
const BRIDGE_BIND_RETRY: Duration = Duration::from_secs(3);

async fn net_bridge_command(args: NetBridgeArgs) -> Result<()> {
    if args.command.is_empty() {
        return serve_net_bridge(args).await;
    }
    exec_behind_bridge(args)
}

/// Bind, print `READY`, and serve until killed (or until the watched parent
/// is gone).
async fn serve_net_bridge(args: NetBridgeArgs) -> Result<()> {
    // A resumed builder reuses its lane's port while the previous launch's
    // bridge is still noticing that its parent is gone (a few tens of
    // milliseconds), so a busy port is retried briefly. A port held by
    // something else stays busy, and the bridge then fails: its command is
    // never started.
    let deadline = Instant::now() + BRIDGE_BIND_RETRY;
    let listener = loop {
        match bind_bridge(args.port).await {
            Ok(listener) => break listener,
            Err(e) if Instant::now() >= deadline => return Err(e),
            Err(_) => tokio::time::sleep(Duration::from_millis(25)).await,
        }
    };
    if let Some(parent) = args.watch_parent {
        std::thread::spawn(move || {
            while std::os::unix::process::parent_id() == parent {
                std::thread::sleep(Duration::from_millis(25));
            }
            std::process::exit(0);
        });
    }
    eprintln!("READY");
    serve_bridge(listener, args.target).await
}

/// Start the bridge as a child, wait for it to be ready, then exec the
/// command in this process. The command is argv, never a shell string.
fn exec_behind_bridge(args: NetBridgeArgs) -> Result<()> {
    use std::io::{BufRead, BufReader};
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};

    let exe = std::env::current_exe().context("locating the cowproof executable")?;
    let mut bridge = Command::new(exe)
        .arg("net-bridge")
        .arg("--port")
        .arg(args.port.to_string())
        .arg("--target")
        .arg(&args.target)
        .arg("--watch-parent")
        .arg(std::process::id().to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .context("starting the bridge")?;
    let stderr = bridge
        .stderr
        .take()
        .context("reading the bridge's stderr")?;
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut line = String::new();
        let _ = BufReader::new(stderr).read_line(&mut line);
        let _ = ready_tx.send(line);
    });
    match ready_rx.recv_timeout(BRIDGE_READY_TIMEOUT) {
        Ok(line) if line.trim() == "READY" => {}
        other => {
            let _ = bridge.kill();
            let _ = bridge.wait();
            let seen = other.map(|l| l.trim().to_string()).unwrap_or_default();
            bail!(
                "the bridge on 127.0.0.1:{} was not ready within {}s (saw {:?}); not starting the command",
                args.port,
                BRIDGE_READY_TIMEOUT.as_secs(),
                seen
            );
        }
    }
    // The bridge now outlives this call only while its parent (this process,
    // then the exec'd command, which keeps the pid) is alive.
    let error = Command::new(&args.command[0])
        .args(&args.command[1..])
        .exec();
    let _ = bridge.kill();
    bail!("cannot execute {}: {error}", args.command[0])
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

fn host_run_argv(
    exe: &std::path::Path,
    packet: &std::path::Path,
    repo: &std::path::Path,
    lanes_root: &std::path::Path,
) -> Vec<std::ffi::OsString> {
    vec![
        exe.as_os_str().to_os_string(),
        "run".into(),
        packet.as_os_str().to_os_string(),
        "--repo".into(),
        repo.as_os_str().to_os_string(),
        "--lanes-root".into(),
        lanes_root.as_os_str().to_os_string(),
    ]
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
    let argv = host_run_argv(&exe, &packet, &cwd, &root);
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
        .args(&argv[1..])
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
                .args(&argv)
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

fn home() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/"))
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

async fn rule_command(args: RuleArgs) -> Result<()> {
    // The same default as `cowproof run` and `cowproof watch`, or the
    // director could not reach a lane started without `--lanes-root`.
    let lanes_root = root::current_lanes_root(args.lanes_root.as_deref())?;

    let ruling = if let Some(answer) = args.answer {
        director_tools::Ruling::Answer(answer)
    } else if let Some(redirect) = args.redirect {
        director_tools::Ruling::Redirect(redirect.to_string_lossy().into_owned())
    } else if args.reassign {
        director_tools::Ruling::Reassign { model: args.model }
    } else if args.stop {
        director_tools::Ruling::Stop
    } else {
        return Err(anyhow!(
            "must specify one verdict: --answer, --redirect, --reassign, or --stop"
        ));
    };

    // The `rule` tool of `cowproof serve --director` calls the same function.
    print_sent(
        director_tools::send_rule(&lanes_root, &args.lane_id, &args.escalation_id, &ruling).await,
    )
}

async fn note_command(args: NoteArgs) -> Result<()> {
    let lanes_root = root::current_lanes_root(args.lanes_root.as_deref())?;
    // The `note` tool of `cowproof serve --director` calls the same function.
    print_sent(director_tools::send_note(&lanes_root, &args.lane_id, &args.text).await)
}

/// Print a lane's reply to `rule` or `note`, or exit 2 when the lane is not
/// running and 1 when it refused or could not be reached.
fn print_sent(result: Result<Value, director_tools::SendError>) -> Result<()> {
    match result {
        Ok(outcome) => {
            println!("{}", serde_json::to_string_pretty(&outcome)?);
            Ok(())
        }
        Err(e @ director_tools::SendError::NotRunning(_)) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
}

/// Get the runner socket path from --socket flag or COWPROOF_RUNNER_SOCKET env var.
fn get_runner_socket(explicit: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(socket) = explicit {
        return Ok(socket);
    }
    std::env::var("COWPROOF_RUNNER_SOCKET")
        .map(PathBuf::from)
        .map_err(|_| anyhow!("missing --socket or COWPROOF_RUNNER_SOCKET env var"))
}

/// Forward one builder-tool call to the runner and print its response as JSON.
async fn print_forwarded(op: lane_tools::Op, socket: &Path, input: &Value) -> Result<()> {
    match lane_tools::forward(op, socket, input).await {
        Ok(response) => {
            println!("{}", serde_json::to_string_pretty(&response)?);
            Ok(())
        }
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
}

async fn ask_command(args: AskArgs) -> Result<()> {
    use std::io::Read;

    let socket = get_runner_socket(args.socket)?;

    // Read question from stdin if needed (- means stdin)
    let question = if args.question == "-" {
        let mut q = String::new();
        std::io::stdin().read_to_string(&mut q)?;
        q
    } else {
        args.question
    };

    // Parse options from the repeatable --option flags (format: id:summary:cost)
    let mut options = Vec::new();
    for opt_str in args.option {
        let parts: Vec<&str> = opt_str.splitn(3, ':').collect();
        if parts.len() != 3 {
            return Err(anyhow!("each --option must be in format: id:summary:cost"));
        }
        options.push(json!({
            "id": parts[0],
            "summary": parts[1],
            "cost": parts[2],
        }));
    }

    // Build the ask request
    let input = json!({
        "kind": args.kind,
        "question": question,
        "tried": args.tried,
        "options": options,
        "recommend": args.recommend,
        "blocking": args.blocking,
    });

    print_forwarded(lane_tools::Op::Ask, &socket, &input).await
}

async fn ruling_command(args: RulingArgs) -> Result<()> {
    let socket = get_runner_socket(args.socket)?;

    let input = if let Some(id) = args.id {
        json!({ "id": id })
    } else {
        json!({})
    };

    print_forwarded(lane_tools::Op::CheckRuling, &socket, &input).await
}

async fn check_command(args: CheckArgs) -> Result<()> {
    let socket = get_runner_socket(args.socket)?;

    let input = json!({ "id": args.check_id });
    print_forwarded(lane_tools::Op::RunCheck, &socket, &input).await
}

#[cfg(test)]
mod cli_tests {
    use super::*;

    #[test]
    fn host_run_argv_constructs_correct_command() {
        let exe = std::path::Path::new("/path/to/cowproof");
        let packet = std::path::Path::new("/path/to/packet.md");
        let repo = std::path::Path::new("/path/to/repo");
        let lanes_root = std::path::Path::new("/path/to/lanes");

        let argv = host_run_argv(exe, packet, repo, lanes_root);

        assert_eq!(argv.len(), 7);
        assert_eq!(argv[0].to_string_lossy(), "/path/to/cowproof");
        assert_eq!(argv[1].to_string_lossy(), "run");
        assert_eq!(argv[2].to_string_lossy(), "/path/to/packet.md");
        assert_eq!(argv[3].to_string_lossy(), "--repo");
        assert_eq!(argv[4].to_string_lossy(), "/path/to/repo");
        assert_eq!(argv[5].to_string_lossy(), "--lanes-root");
        assert_eq!(argv[6].to_string_lossy(), "/path/to/lanes");

        // Verify no legacy-run
        for arg in &argv {
            assert_ne!(arg.to_string_lossy().as_ref(), "legacy-run");
        }
    }

    #[test]
    fn host_run_argv_includes_lanes_root_flag() {
        let exe = std::path::Path::new("cowproof");
        let packet = std::path::Path::new("packet.md");
        let repo = std::path::Path::new("repo");
        let lanes_root = std::path::Path::new("lanes");

        let argv = host_run_argv(exe, packet, repo, lanes_root);

        // Verify --lanes-root is present
        assert!(
            argv.iter()
                .any(|arg| arg.to_string_lossy() == "--lanes-root")
        );
    }

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
