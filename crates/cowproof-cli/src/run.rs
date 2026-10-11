//! `cowproof run <packet.md>`: the single-packet flow (D2, D19, D20, D22, D24).
//!
//! Order matters, and each step fails before the next one creates anything:
//!
//! 1. lint the packet (errors stop the run before any lane exists);
//! 2. read the real key from the director's `ANTHROPIC_API_KEY` and resolve
//!    the Claude Code executable once on the director's `PATH`;
//! 3. prepare the lane (isolated clone, launch baseline) and take a slot of the
//!    packet's class (D12), waiting while the class is full. The slot is held to the
//!    end of the run, on every exit, and the verifier reuses it;
//! 4. start the egress proxy ([`start_proxy`], the one place the builder's
//!    endpoint is decided) and bind the builder tools socket, both BEFORE the
//!    builder starts (the Linux policy binds a socket only when the file
//!    exists, so a late bind would leave the builder without it, silently);
//! 5. launch the builder inside `SandboxPolicy::builder`, feeding its stdout
//!    to the stream meter and to `control/stream.jsonl`. A builder that exits
//!    with a parked BLOCKING escalation is waited for and relaunched when the
//!    director rules (the resume loop, [`Drive`], D9): `answer` resumes the
//!    session, `redirect` and `reassign` start a fresh one, `stop` ends the
//!    lane. Each launch is one segment in `run.json`;
//! 6. stop the tools server and the proxy, capture `control/lane.patch` and
//!    write `control/run.json`;
//! 7. prove the lane: seal a capsule from the builder's last recorded
//!    `run_check` results, replay it in the verifier, run the gates and write
//!    `control/verdict.json`. The exit code is the verdict (0 proved, 2
//!    refuted, 3 incomplete, 4 infrastructure). A lane the director stopped,
//!    or one that hit the escalation limit, keeps its work and is not proved:
//!    `run.json` says how it ended and the exit code is 1. The two hard limits
//!    end a lane the same way, with its work kept and no proof: a wall-clock
//!    timeout (exit 5, status `timeout`) and a running cost ESTIMATE at 100% of
//!    the cap (exit 6, status `cost-cap`).
//!
//! Every child process started here gets an explicit environment
//! (`env_clear`), so the director's `ANTHROPIC_API_KEY` is never inherited:
//! the builder sees only the proxy's placeholder key.

use crate::preflight::{CheckStatus, PreflightOptions, preflight};
use crate::root::resolve_executable;
use crate::verify::{Rebuild, fetch_dependencies, verifier_runner};
use anyhow::{Context, Result, anyhow, bail};
use cowproof_core::{
    LinkedFile, PORT_CLASS, class_limit_at_commit, get_slot_dir, git_show_following_links,
    parse_header, port_base_for_slot, port_block_env, release_slot,
};
use cowproof_prove::{
    capsule::HELDOUT_FILE,
    capsule::{Capsule, CheckResult, EnvironmentFingerprint},
    gates::{GatePacket, base_requires_heldout, run_gates},
    runner::{acquire_slot_notifying, kill_process_group, terminate_process_group},
    verify::{VerifyOptions, verify},
};
use cowproof_run::{
    LaneLayout, NetworkMode, SandboxPolicy,
    bridge::bridge_port,
    claude::{ClaudeSpec, claude_command},
    deps::FetchOutcome,
    director::{self, VerdictEvent},
    escalate::{
        Ask, DEFAULT_COST_FRACTION, DEFAULT_MAX_ESCALATIONS, DEFAULT_PARK_LIMIT, Delivery,
        DeliveryError, DeliveryOutcome, DeliveryResult, EscalationId, LaneState, Queue,
        SystemClock, Verdict as EscalationVerdict,
    },
    lane::{PrepareOptions, prepare_lane},
    lane_tmp,
    prefix::{assemble_prompt, prefix_version},
    proxy::{ProxyConfig, ProxyServer},
    render_macos_profile, sandbox_command,
    stream::{MeterSummary, StreamMeter},
    tools::{self, CheckOutcome, CheckTable, RunCheck, SessionEnd, SessionEndSignal},
};
use serde_json::json;
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::signal::unix::{Signal, SignalKind, signal};
use tokio::sync::{Semaphore, mpsc::UnboundedReceiver, watch};
use tokio::task::JoinHandle;
use tokio::time::Instant as TokioInstant;

/// The provider the proxy forwards to.
const UPSTREAM: &str = "https://api.anthropic.com";

/// The longest one `run_check` may run before it is killed.
const CHECK_TIMEOUT: Duration = Duration::from_secs(20 * 60);

/// The longest builder stdout line the meter will parse, in bytes. A longer
/// line is still written to `stream.jsonl`, whole, but is not metered.
const MAX_STREAM_LINE: usize = 64 * 1024 * 1024;

/// After the tools server reports a parked (or forced) escalation, how long the
/// builder gets before the runner ends its session: enough for the tool reply to
/// reach it and for `claude` to flush its session to disk. A builder that exits
/// by itself in this time is not touched.
const PARK_GRACE: Duration = Duration::from_secs(2);

/// After SIGTERM to the builder's process group, how long the leader gets to
/// exit before the group is SIGKILLed.
const TERM_GRACE: Duration = Duration::from_secs(10);

/// Once the builder's leader has exited and its group has been killed, how long
/// the stream pump may still wait for EOF. A process that escaped the group
/// could hold the pipe open forever; the pump is abandoned after this.
const PUMP_DRAIN: Duration = Duration::from_secs(5);

/// The exit code when the run is interrupted by a signal (SIGINT or SIGTERM).
const INTERRUPTED_EXIT_CODE: i32 = 130;

/// The exit code for an infrastructure failure: a failed preflight check, or a lane that
/// could not be run (`Outcome::Infrastructure`).
const INFRASTRUCTURE_EXIT_CODE: i32 = 4;

/// The exit code when the wall-clock timeout ended the lane (`run.json` status `timeout`).
const TIMEOUT_EXIT_CODE: i32 = 5;

/// The exit code when the cost estimate reached 100% of the cap and ended the
/// lane (`run.json` status `cost-cap`).
const COST_CAP_EXIT_CODE: i32 = 6;

/// On the first SIGINT or SIGTERM, how long past [`TERM_GRACE`] the runner waits
/// for the launcher to finish ending the builder's group before it stops waiting.
const INTERRUPT_SLACK: Duration = Duration::from_secs(5);

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
    /// `ANTHROPIC_BASE_URL` for the builder: the in-sandbox bridge's
    /// `127.0.0.1` port.
    pub base_url: String,
    /// The bridge's port, recorded in `run.json`.
    pub bridge_port: u16,
    /// The proxy's Unix socket, `<lane>/proxy.sock`, the bridge's target.
    pub socket: PathBuf,
    /// The network mode for the builder's sandbox policy.
    pub network: NetworkMode,
    /// The key the builder presents; the proxy swaps in the real one.
    pub placeholder_key: String,
    /// The serving task. Abort it when the lane ends.
    pub task: JoinHandle<()>,
}

/// Start the egress proxy for one lane (D24).
///
/// This is the only place that decides how the builder reaches the proxy. The
/// proxy listens on a Unix socket, `<lane>/proxy.sock` (mode 0600), on macOS
/// and Linux alike. The builder reaches it through a bridge that
/// [`builder_argv`] starts inside the sandbox, listening on `127.0.0.1:<port>`
/// where the port is [`bridge_port`] of the lane id.
///
/// The real key goes only into the proxy's memory.
pub async fn start_proxy(
    layout: &LaneLayout,
    lane_id: &str,
    real_api_key: String,
) -> Result<ProxyEndpoint> {
    let config =
        ProxyConfig::new(real_api_key, UPSTREAM).context("configuring the egress proxy")?;
    let placeholder_key = config.placeholder_key().to_string();
    let server = ProxyServer::new(config);
    let socket = lane_dir(layout)?.join("proxy.sock");

    let listener = tools::bind(&socket).context("binding the egress proxy socket")?;
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))
        .context("restricting the egress proxy socket")?;
    let task = tokio::spawn(async move {
        if let Err(e) = server.serve_unix(listener).await {
            eprintln!("egress proxy stopped: {e:#}");
        }
    });

    let port = bridge_port(lane_id);
    Ok(ProxyEndpoint {
        base_url: format!("http://127.0.0.1:{port}"),
        bridge_port: port,
        network: NetworkMode::Proxy {
            port,
            socket: socket.clone(),
        },
        socket,
        placeholder_key,
        task,
    })
}

/// The builder's argv: the bridge wrapper first, then `claude`.
///
/// `cowproof net-bridge --port <P> --target <proxy.sock> -- <claude> <args>`
/// starts the bridge inside the sandbox, waits for it to be ready, and then
/// replaces itself with `claude`. It is argv end to end: no shell, no
/// interpolation. If the bridge cannot start, `claude` never does.
fn builder_argv(
    cowproof_exe: &Path,
    bridge_port: u16,
    proxy_socket: &Path,
    claude: &[String],
) -> Vec<String> {
    let mut argv = vec![
        cowproof_exe.to_string_lossy().into_owned(),
        "net-bridge".to_string(),
        "--port".to_string(),
        bridge_port.to_string(),
        "--target".to_string(),
        proxy_socket.to_string_lossy().into_owned(),
        "--".to_string(),
    ];
    argv.extend(claude.iter().cloned());
    argv
}

/// Aborts a task when dropped, so no exit path leaves a server running.
struct AbortOnDrop(JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// The model ladder a `reassign` without a named model climbs (design: next
/// model on the ladder).
const MODEL_LADDER: [&str; 3] = ["haiku", "sonnet", "opus"];

/// The rung above `current`, matched by name so full ids (`claude-haiku-5-5`)
/// work. `None` for the top rung and for a model that is not on the ladder.
fn next_model(current: &str) -> Option<&'static str> {
    let lower = current.to_ascii_lowercase();
    let rung = MODEL_LADDER.iter().position(|m| lower.contains(m))?;
    MODEL_LADDER.get(rung + 1).copied()
}

/// A model name the director named in a ruling goes into the builder's argv,
/// so it is held to a conservative alphabet (and never starts like a flag).
fn valid_model(model: &str) -> bool {
    !model.is_empty()
        && model.len() <= 64
        && !model.starts_with('-')
        && model
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ':' | '[' | ']'))
}

/// The shape `claude --resume` accepts, the same rule `claude_command`
/// enforces. A session id outside it is treated as "no session to resume".
fn resumable(session_id: &str) -> bool {
    (8..=64).contains(&session_id.len())
        && session_id
            .chars()
            .all(|c| c.is_ascii_hexdigit() || c == '-')
}

/// Text inside a fence longer than any run of backticks it contains, so it
/// cannot close the fence.
fn fenced(text: &str) -> String {
    let longest = text
        .split(|c| c != '`')
        .map(str::len)
        .max()
        .unwrap_or_default();
    let fence = "`".repeat((longest + 1).max(3));
    format!("{fence}\n{text}\n{fence}")
}

/// A resumed session that fails faster than this, with nothing on stdout, is
/// treated as a session that no longer exists.
const RESUME_FAILS_WITHIN: Duration = Duration::from_secs(60);

/// Did `claude --resume` fail because the session is gone (D9)?
///
/// `claude` has no stable, documented signal for this, so the test is
/// deliberately narrow: ALL of these must hold, and any work or any doubt
/// means "not gone":
///
/// - it exited with a non-zero exit CODE (a signal is a kill, not a refusal);
/// - it wrote no stdout line at all (a resumed session that started emits at
///   least its init event, so silence means it never got that far);
/// - the meter saw no turn;
/// - it all happened within [`RESUME_FAILS_WITHIN`] (a missing session fails
///   at once; an API outage retries for longer).
///
/// A false positive costs one fresh session and one escalation of the lane's
/// budget (a fallback is counted). A false negative leaves the lane `failed`
/// for the director to look at, with the resume's stderr kept in
/// `control/builder.stderr`.
fn resume_session_gone(seg: &SegmentRun) -> bool {
    seg.status.code().is_some_and(|c| c != 0)
        && seg.stats == PumpStats::default()
        && seg.summary.turns.is_empty()
        && seg.elapsed < RESUME_FAILS_WITHIN
}

/// What the runner already did about a ruling, handed to the queue's own
/// delivery path (`Queue::redeliver`) so the queue records `delivered`, or the
/// D9 `resume-fallback` and its carry-over summary.
///
/// The runner cannot launch the session INSIDE `Delivery::deliver`: that is a
/// synchronous call made with the queue locked, and the lane's own tool server
/// needs the same lock to answer the builder it is about to start. So the
/// runner launches (or decides not to) first, and reports the result here.
struct Observed {
    result: DeliveryResult,
    /// The queue's carry-over summary, set when the queue fell back to a fresh
    /// session. The runner launches that session.
    summary: Option<String>,
}

impl Observed {
    fn delivered() -> Self {
        Observed {
            result: DeliveryResult::Delivered,
            summary: None,
        }
    }

    fn session_gone() -> Self {
        Observed {
            result: DeliveryResult::SessionGone,
            summary: None,
        }
    }
}

impl Delivery for Observed {
    fn deliver(
        &mut self,
        _lane: &str,
        _id: &EscalationId,
        _verdict: &EscalationVerdict,
    ) -> Result<DeliveryResult, DeliveryError> {
        Ok(self.result)
    }

    fn deliver_fresh(
        &mut self,
        _lane: &str,
        _id: &EscalationId,
        _verdict: &EscalationVerdict,
        summary: &str,
    ) -> Result<(), DeliveryError> {
        self.summary = Some(summary.to_string());
        Ok(())
    }
}

/// How one builder launch began.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StartKind {
    /// A new session on the packet (the first launch, a redirect, a reassign).
    Fresh,
    /// `claude --resume` of the parked session with the ruling.
    Resumed,
    /// A new session because the parked one could not be resumed (D9).
    Fallback,
}

impl StartKind {
    fn name(self) -> &'static str {
        match self {
            StartKind::Fresh => "fresh",
            StartKind::Resumed => "resumed",
            StartKind::Fallback => "fallback",
        }
    }
}

/// One builder launch.
struct Launch {
    model: String,
    /// The packet this session works from (the system prompt is assembled
    /// from it).
    packet: String,
    prompt: String,
    resume: Option<String>,
    kind: StartKind,
    /// The escalation whose ruling started this launch.
    started_by: Option<EscalationId>,
}

/// What one builder launch did.
struct SegmentRun {
    status: ExitStatus,
    stats: PumpStats,
    summary: MeterSummary,
    elapsed: Duration,
    /// Why the tools server or the escalate-early observer asked the runner to
    /// end the session, if it did. The builder may still have exited first.
    session_end: Option<SessionEnd>,
    /// The runner sent SIGTERM to the builder's process group: the builder had
    /// not exited by itself within [`PARK_GRACE`] of the signal.
    killed: bool,
    /// The running cost ESTIMATE of this launch (per-message usage times the
    /// price table in `cowproof_run::stream`), never the bill.
    estimated_cost_usd: f64,
}

/// The first SIGINT or SIGTERM, shared between the signal handler in
/// [`run_one`] and the launcher.
///
/// The launcher records the builder's process group here when it spawns and
/// clears it when the launch is over, so `builder_pgid` is `Some` exactly while
/// a builder may be running. `raise` is the handler telling the launcher to end
/// that group (SIGTERM, then SIGKILL after [`TERM_GRACE`]) and stop.
struct Interrupt {
    builder_pgid: Mutex<Option<u32>>,
    raised: watch::Sender<bool>,
}

impl Interrupt {
    fn new() -> Arc<Self> {
        Arc::new(Interrupt {
            builder_pgid: Mutex::new(None),
            raised: watch::channel(false).0,
        })
    }

    fn builder_pgid(&self) -> Option<u32> {
        *self.builder_pgid.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn set_builder_pgid(&self, pgid: Option<u32>) {
        *self.builder_pgid.lock().unwrap_or_else(|e| e.into_inner()) = pgid;
    }

    fn raise(&self) {
        self.raised.send_replace(true);
    }

    fn subscribe(&self) -> watch::Receiver<bool> {
        self.raised.subscribe()
    }
}

/// What a launch (and so the resume loop) returns when the run was interrupted:
/// not a failure of the builder, and never to be proved.
#[derive(Debug)]
struct Interrupted;

impl std::fmt::Display for Interrupted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("interrupted by a signal")
    }
}

impl std::error::Error for Interrupted {}

/// SIGKILLs a process group when dropped, so no early return leaves a builder's
/// background children running. The group is also ended explicitly after every
/// launch; this is the safety net for the error paths between spawn and that.
///
/// Creating it records the group in [`Interrupt`]; dropping it clears the record.
struct GroupGuard {
    pgid: u32,
    interrupt: Arc<Interrupt>,
}

impl GroupGuard {
    fn new(pgid: u32, interrupt: Arc<Interrupt>) -> Self {
        interrupt.set_builder_pgid(Some(pgid));
        GroupGuard { pgid, interrupt }
    }
}

impl Drop for GroupGuard {
    fn drop(&mut self) {
        self.interrupt.set_builder_pgid(None);
        kill_process_group(self.pgid);
    }
}

/// Escalate-early on the live stream (design D9): each new assistant turn is a
/// `Queue::record_turn`, and the running cost estimate feeds
/// `Queue::record_cost`. A trigger forces a blocking escalation and signals the
/// run loop to end the session, exactly like a blocking `ask`.
struct LiveEscalation {
    queue: Arc<Mutex<Queue>>,
    lane: String,
    model: String,
    /// The estimate for earlier launches of this queue segment (a segment ends
    /// at `reassign`), so the share is the lane's, not one launch's.
    spent_before_usd: f64,
    /// The estimate for every earlier launch of the lane, `reassign` included:
    /// the hard stop is on the lane's total, not on one queue segment.
    lane_spent_before_usd: f64,
    cost_cap_usd: f64,
    seen_turns: usize,
    /// A trigger fired (or the lane ended): nothing more is recorded this launch.
    done: bool,
    end: SessionEndSignal,
}

impl LiveEscalation {
    fn observe(&mut self, meter: &StreamMeter) {
        if self.done {
            return;
        }
        // The hard stop: the lane's running estimate has reached the whole cap.
        // It is checked before the escalate-early triggers, so nothing below
        // can park a lane that is already over its cap.
        let estimate = meter.estimated_cost_usd(&self.model);
        if self.lane_spent_before_usd + estimate >= self.cost_cap_usd {
            self.done = true;
            let _ = self.end.send(SessionEnd::CostCap);
            return;
        }
        let shared = self.queue.clone();
        let Ok(mut queue) = shared.lock() else {
            return;
        };
        // An unruled blocking escalation is already parked and this session is
        // ending: do not open a second one. (A ruled one does not count: it is
        // the answer this very session was resumed with.)
        if queue
            .pending_blocking(&self.lane)
            .iter()
            .any(|p| p.verdict.is_none())
        {
            self.done = true;
            return;
        }
        let turns = meter.turn_count();
        while self.seen_turns < turns {
            self.seen_turns += 1;
            let fired = queue.record_turn(&self.lane);
            if self.finish(&queue, fired) {
                return;
            }
        }
        let spent = self.spent_before_usd + estimate;
        let fired = queue.record_cost(&self.lane, spent, self.cost_cap_usd);
        self.finish(&queue, fired);
    }

    /// Act on one `record_*` result; true when the session is ending.
    fn finish(&mut self, queue: &Queue, fired: Result<Option<EscalationId>, String>) -> bool {
        let end = match fired {
            Ok(Some(id)) => SessionEnd::Forced(id),
            Ok(None) => return false,
            Err(why) => {
                eprintln!(
                    "[{}] escalate-early could not open an escalation: {why}",
                    self.lane
                );
                if queue.lane_state(&self.lane) != Some(LaneState::EscalationLimit) {
                    return false;
                }
                SessionEnd::LimitReached
            }
        };
        self.done = true;
        // A closed receiver means the run loop is gone; nothing to end.
        let _ = self.end.send(end);
        true
    }
}

/// Sleep until `deadline`, or forever when there is none (for a `select!`
/// branch that is switched off by its precondition, whose future is still built).
async fn sleep_until_opt(deadline: Option<TokioInstant>) {
    match deadline {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}

/// Everything a launch needs that does not change between launches.
struct Launcher {
    layout: LaneLayout,
    claude_bin: PathBuf,
    cowproof_exe: PathBuf,
    path: String,
    base_url: String,
    /// The bridge's port and its target, the proxy's socket (D24).
    bridge_port: u16,
    proxy_socket: PathBuf,
    placeholder_key: String,
    network: NetworkMode,
    max_turns: u32,
    /// The builder tools socket, canonical.
    socket: PathBuf,
    queue: Arc<Mutex<Queue>>,
    lane_id: String,
    /// The lane's cost cap in USD; escalate-early fires at the queue's share of it.
    cost_cap_usd: f64,
    /// Session-end signals from the tools server and the live observer. The
    /// receiver is created BEFORE the tools server and the builder start, so
    /// no signal can be missed; the sender is cloned into the observer.
    end_tx: SessionEndSignal,
    end_rx: tokio::sync::Mutex<UnboundedReceiver<SessionEnd>>,
    /// The signal handler's side: the builder's group, and the order to end it.
    interrupt: Arc<Interrupt>,
    /// The version of the builder preamble (sha256 hash of PREAMBLE bytes),
    /// recorded in the capsule and run.json.
    prefix_version: String,
    /// The project instructions from the base commit (CLAUDE.md), or None if there
    /// were none. Passed to the builder in the preamble.
    project_instructions: Option<String>,
    /// The SHA256 hash of the project instructions from the base commit,
    /// or None if there were no project instructions. Recorded in the capsule
    /// and run.json.
    project_instructions_sha256: Option<String>,
    /// The wall-clock limit: the packet header's `timeoutMin`, else the flag.
    /// It covers every launch of the lane together.
    timeout: Duration,
    /// How much of `timeout` the finished launches used. This is the only clock
    /// the limit runs on, and it advances only inside [`Launcher::launch`], so
    /// the time between launches (parked, waiting for the director's ruling) is
    /// never counted.
    active: Mutex<Duration>,
    /// The first port of the lane's block, from the `port` slot it holds
    /// (`COWPROOF_PORT_BASE`). Not the D24 bridge port, which is `bridge_port` above.
    port_base: u16,
}

impl Launcher {
    /// Launch the builder once and wait for it to exit.
    ///
    /// The lane home is writable by the builder, so `settings.json`,
    /// `mcp.json` and `system-prompt.md` are rewritten before EVERY launch
    /// (a resume must never trust what the previous session left there).
    ///
    /// The builder runs as the leader of its own process group, and the runner
    /// ends that group, never only the leader. The stream pump, the child wait
    /// and the session-end signal are listened to together: a blocking `ask`
    /// (or a forced escalation) parks the lane, and [`PARK_GRACE`] later the
    /// runner sends SIGTERM to the group, waits up to [`TERM_GRACE`] for the
    /// leader, then SIGKILLs the group whether or not the leader has gone.
    /// `spent_before_usd` is the estimated cost of this queue segment so far,
    /// `lane_spent_before_usd` that of the whole lane (the hard cost stop).
    ///
    /// A third thing ends the launch the same way, at once: the director's
    /// wake channel (`rulings`). A stop, reassign or redirect ruling on a
    /// NON-blocking ask (the queue says which) ends the live session with no
    /// grace period, reported as [`SessionEnd::Ruled`]; the resume loop then
    /// acts on the ruling. An `answer`, or any ruling on a blocking ask, does
    /// not end it here. The channel only wakes the launch; the queue is the
    /// truth, so a wake that was consumed here never starves
    /// [`Drive::wait_for_ruling`], which reads the queue first.
    ///
    /// Two hard limits end the launch the same way (SIGTERM to the group, then
    /// SIGKILL after [`TERM_GRACE`], reported through `session_end`): the
    /// wall-clock timeout, for what is left of it after the earlier launches,
    /// and a cost estimate at the whole cap.
    async fn launch(
        &self,
        index: usize,
        launch: &Launch,
        spent_before_usd: f64,
        lane_spent_before_usd: f64,
        rulings: &mut UnboundedReceiver<VerdictEvent>,
    ) -> Result<SegmentRun> {
        let started = Instant::now();
        // Subscribed before anything else: an interrupt raised from here on is
        // seen, and one raised earlier stops the launch before a builder exists.
        let mut interrupted_rx = self.interrupt.subscribe();
        if *interrupted_rx.borrow_and_update() {
            return Err(Interrupted.into());
        }
        let layout = &self.layout;
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
                        "command": self.cowproof_exe,
                        "args": ["lane-tools", "--socket", self.socket],
                    }
                }
            }))?,
        )?;
        let assembled = assemble_prompt(self.project_instructions.as_deref(), &launch.packet);
        let system_prompt = layout.home.join("system-prompt.md");
        fs::write(&system_prompt, &assembled.system_append)?;

        let mut invocation = claude_command(&ClaudeSpec {
            lane: layout.clone(),
            model: launch.model.clone(),
            proxy_base_url: self.base_url.clone(),
            placeholder_key: self.placeholder_key.clone(),
            settings_file,
            mcp_config,
            append_system_prompt_file: system_prompt,
            prompt: launch.prompt.clone(),
            max_turns: self.max_turns,
            resume_session_id: launch.resume.clone(),
            cache_ttl: "1h".to_string(),
            path: self.path.clone(),
        })?;
        invocation.env.push((
            "COWPROOF_RUNNER_SOCKET".to_string(),
            self.socket.to_string_lossy().into_owned(),
        ));
        invocation.env.extend(port_block_env(self.port_base));
        invocation.program = self.claude_bin.to_string_lossy().into_owned();
        let claude: Vec<String> = std::iter::once(invocation.program.clone())
            .chain(invocation.args.iter().cloned())
            .collect();
        let argv = builder_argv(
            &self.cowproof_exe,
            self.bridge_port,
            &self.proxy_socket,
            &claude,
        );
        let policy = SandboxPolicy::builder_with_executables(
            layout,
            self.network.clone(),
            &[self.claude_bin.clone(), self.cowproof_exe.clone()],
        )?;
        // The first launch starts the lane's stream and stderr files; every
        // later one appends, so they hold the whole lane in order.
        let first = index == 0;
        let stderr_file = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .append(!first)
            .truncate(first)
            .open(layout.control.join("builder.stderr"))?;
        // Signals left over from an earlier launch (a second parked ask, say)
        // must not end this one. Drained before the builder exists, so nothing
        // this launch sends can be lost.
        let mut end_rx = self.end_rx.lock().await;
        while end_rx.try_recv().is_ok() {}

        // Only the builder gets its own process group (so the runner can end
        // it whole); `run_check` and the git steps keep the runner's group, so
        // a terminal Ctrl-C still reaches them.
        let mut child = sandboxed_command(
            &policy,
            &layout.control.join("builder.sb"),
            &argv,
            invocation.env,
            &invocation.cwd,
        )?
        .process_group(0)
        .stdout(Stdio::piped())
        .stderr(Stdio::from(stderr_file))
        .spawn()
        .context("launching the builder in its sandbox")?;
        // `process_group(0)` makes the child its own leader, so its pid is the pgid.
        let pgid = child.id().context("reading the builder's process id")?;
        let _group = GroupGuard::new(pgid, self.interrupt.clone());
        let stdout = child.stdout.take().context("taking the builder's stdout")?;

        let mut meter = StreamMeter::new(launch.resume.is_some());
        let mut stream = tokio::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .append(!first)
            .truncate(first)
            .open(layout.control.join("stream.jsonl"))
            .await?;
        let mut live = LiveEscalation {
            queue: self.queue.clone(),
            lane: self.lane_id.clone(),
            model: launch.model.clone(),
            spent_before_usd,
            lane_spent_before_usd,
            cost_cap_usd: self.cost_cap_usd,
            seen_turns: 0,
            done: false,
            end: self.end_tx.clone(),
        };

        let mut pump_result: Option<io::Result<PumpStats>> = None;
        let mut status: Option<ExitStatus> = None;
        let mut session_end: Option<SessionEnd> = None;
        let mut signals_open = true;
        let mut rulings_open = true;
        let mut killed = false;
        let mut term_at: Option<TokioInstant> = None;
        let mut kill_at: Option<TokioInstant> = None;
        let mut drain_until: Option<TokioInstant> = None;
        let mut abandoned = false;
        let mut interrupted = false;

        // What is left of the lane's wall-clock limit after the earlier launches.
        let left = self.timeout.saturating_sub(
            *self
                .active
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        );
        let mut timeout_at = Some(TokioInstant::now() + left);
        {
            let mut observe = |m: &StreamMeter| live.observe(m);
            let pump = pump_stream(
                stdout,
                &mut stream,
                &mut meter,
                MAX_STREAM_LINE,
                &mut observe,
            );
            tokio::pin!(pump);
            // The three events race for as long as any of them can still
            // matter: the pump reading the builder's stdout (never awaited to
            // EOF before listening for the rest), the builder exiting, and a
            // session-end signal.
            while !(status.is_some() && (pump_result.is_some() || abandoned)) {
                tokio::select! {
                    result = &mut pump, if pump_result.is_none() => {
                        pump_result = Some(result);
                    }
                    waited = child.wait(), if status.is_none() => {
                        status = Some(waited.context("waiting for the builder")?);
                        // The leader is gone: end whatever it left running, so
                        // no background child survives or holds the stream open.
                        kill_process_group(pgid);
                        term_at = None;
                        kill_at = None;
                        drain_until = Some(TokioInstant::now() + PUMP_DRAIN);
                    }
                    signal = end_rx.recv(), if session_end.is_none() && signals_open && status.is_none() => {
                        match signal {
                            Some(end) => {
                                eprintln!(
                                    "[{}] session ends in {:?}: {end:?}",
                                    self.lane_id, PARK_GRACE
                                );
                                // A park gets PARK_GRACE to flush its session; a
                                // lane over its cost cap is not given more spending.
                                let grace = if end == SessionEnd::CostCap {
                                    Duration::ZERO
                                } else {
                                    PARK_GRACE
                                };
                                session_end = Some(end);
                                term_at = Some(TokioInstant::now() + grace);
                            }
                            None => signals_open = false,
                        }
                    }
                    // A ruling wakes the launch. If it is a stop, reassign or
                    // redirect on a non-blocking ask that nothing has acted on,
                    // the session ends now (no PARK_GRACE: a fresh session or
                    // the end of the lane follows, so nothing needs flushing).
                    event = rulings.recv(), if session_end.is_none() && rulings_open && status.is_none() => {
                        match event {
                            Some(_) => {
                                let directive = self
                                    .queue
                                    .lock()
                                    .map(|q| q.pending_directive(&self.lane_id))
                                    .unwrap_or(None);
                                if let Some((id, verdict)) = directive {
                                    eprintln!(
                                        "[{}] ruling on {id} ({}): ending the builder now",
                                        self.lane_id,
                                        verdict.kind()
                                    );
                                    session_end = Some(SessionEnd::Ruled(id));
                                    term_at = Some(TokioInstant::now());
                                }
                            }
                            None => rulings_open = false,
                        }
                    }
                    // The first SIGINT or SIGTERM: end the builder's group the way a
                    // parked session is ended, without waiting out PARK_GRACE.
                    _ = interrupted_rx.changed(), if !interrupted => {
                        interrupted = true;
                        if status.is_none() {
                            eprintln!("[{}] interrupted: ending the builder", self.lane_id);
                            terminate_process_group(pgid);
                            killed = true;
                            term_at = None;
                            kill_at = Some(TokioInstant::now() + TERM_GRACE);
                        }
                    }
                    _ = sleep_until_opt(term_at), if term_at.is_some() => {
                        terminate_process_group(pgid);
                        killed = true;
                        term_at = None;
                        kill_at = Some(TokioInstant::now() + TERM_GRACE);
                    }
                    _ = sleep_until_opt(kill_at), if kill_at.is_some() => {
                        kill_process_group(pgid);
                        kill_at = None;
                    }
                    _ = sleep_until_opt(drain_until), if drain_until.is_some() && pump_result.is_none() => {
                        abandoned = true;
                    }
                    _ = sleep_until_opt(timeout_at), if timeout_at.is_some() && status.is_none() => {
                        eprintln!(
                            "[{}] wall-clock timeout: ending the builder",
                            self.lane_id
                        );
                        // The limit wins over whatever else was ending the session.
                        session_end = Some(SessionEnd::Timeout);
                        terminate_process_group(pgid);
                        killed = true;
                        timeout_at = None;
                        term_at = None;
                        kill_at = Some(TokioInstant::now() + TERM_GRACE);
                    }
                }
            }
        }
        // The group is already ended; the guard's drop is a second, harmless kill.
        if interrupted || *interrupted_rx.borrow() {
            return Err(Interrupted.into());
        }
        let status = status.context("the builder's exit status was never read")?;
        let stats = if abandoned {
            eprintln!(
                "[{}] the builder's stream stayed open {PUMP_DRAIN:?} after it exited; not waiting for it",
                self.lane_id
            );
            PumpStats::default()
        } else {
            pump_result
                .context("the stream pump never finished")?
                .context("reading the builder's stream")?
        };
        let estimated_cost_usd = meter.estimated_cost_usd(&launch.model);
        // Only the time this launch ran counts against the limit.
        *self
            .active
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) += started.elapsed();
        Ok(SegmentRun {
            status,
            stats,
            summary: meter.summary(),
            elapsed: started.elapsed(),
            session_end,
            killed,
            estimated_cost_usd,
        })
    }
}

/// How the lane's builder launches ended.
#[derive(Debug, PartialEq, Eq)]
enum LaneEnd {
    /// The builder exited with nothing parked: go on to the proof.
    Builder,
    /// The director ruled `stop`.
    Stopped,
    /// The park limit or the escalation limit ended the lane.
    EscalationLimit,
    /// The wall-clock timeout fired: the builder was terminated.
    Timeout,
    /// The cost cap at 100% fired: the builder was terminated.
    CostCap,
    /// A ruling could not be carried out; the work is kept.
    Refused(String),
}

impl LaneEnd {
    fn name(&self, builder_ok: bool) -> &'static str {
        match self {
            LaneEnd::Builder if builder_ok => "finished",
            LaneEnd::Builder | LaneEnd::Refused(_) => "failed",
            LaneEnd::Stopped => "stopped",
            LaneEnd::EscalationLimit => "escalation-limit",
            LaneEnd::Timeout => "timeout",
            LaneEnd::CostCap => "cost-cap",
        }
    }
}

/// Everything the launches did.
struct LaneRun {
    /// One entry per launch, for `run.json`.
    segments: Vec<serde_json::Value>,
    summaries: Vec<MeterSummary>,
    stats: PumpStats,
    /// How the last launch exited.
    status: ExitStatus,
    /// The model of the last launch.
    model: String,
    /// The newest session id the stream reported.
    session_id: Option<String>,
    end: LaneEnd,
}

/// What waiting for the director found.
enum Waited {
    /// No blocking escalation is parked and no non-blocking stop, reassign or
    /// redirect awaits action: the builder is simply done.
    Nothing,
    Ruling(EscalationId, EscalationVerdict),
    /// A parked escalation passed the park limit; the queue ended the lane.
    Expired,
    /// No ruling can arrive any more.
    Lost(String),
}

/// What the queue's D9 fallback decided.
enum Fallback {
    /// Start a fresh session with this carry-over summary.
    Fresh(String),
    /// The fallback would exceed the escalation limit; the lane ended.
    Limit,
}

/// The resume loop (D9, D22, D25): runs the builder, and while it exits with
/// a parked blocking escalation, waits for the director's ruling and carries
/// it out.
struct Drive<'a> {
    launcher: &'a Launcher,
    queue: &'a Arc<Mutex<Queue>>,
    lane_id: &'a str,
    cwd: &'a Path,
    repo: &'a Path,
    plans: &'a [cowproof_plan::Plan],
}

impl Drive<'_> {
    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Queue>> {
        self.queue
            .lock()
            .map_err(|_| anyhow!("the escalation queue is unavailable"))
    }

    /// Tell the queue the ruling reached the builder (`delivered`, no fallback).
    fn mark_delivered(&self, id: &EscalationId) -> Result<()> {
        let outcome = self
            .lock()?
            .redeliver(self.lane_id, id, &mut Observed::delivered())
            .map_err(|e| anyhow!("recording the delivery of {id}: {e}"))?;
        if outcome != DeliveryOutcome::Delivered {
            bail!("recording the delivery of {id} gave {outcome:?}");
        }
        Ok(())
    }

    /// The session cannot be resumed: let the queue run D9's fallback.
    fn fall_back(&self, id: &EscalationId) -> Result<Fallback> {
        let mut observed = Observed::session_gone();
        let outcome = self
            .lock()?
            .redeliver(self.lane_id, id, &mut observed)
            .map_err(|e| anyhow!("falling back for {id}: {e}"))?;
        match (outcome, observed.summary) {
            (DeliveryOutcome::FreshSession, Some(summary)) => Ok(Fallback::Fresh(summary)),
            (DeliveryOutcome::EscalationLimit, _) => Ok(Fallback::Limit),
            (outcome, _) => bail!("falling back for {id} gave {outcome:?} and no summary"),
        }
    }

    /// Wait for a ruling the lane must act on. A stop, reassign or redirect
    /// ruling on a non-blocking ask that nothing has acted on comes first (it
    /// ended the live session, or arrived as the builder exited, and either
    /// way is acted on once: carrying it out records it delivered). Then, on a
    /// parked blocking escalation, there is no timeout
    /// but the queue's own park limit: when that passes, the queue ends the
    /// lane as `escalation-limit` (a ruling would only be refused after it).
    async fn wait_for_ruling(&self, rx: &mut UnboundedReceiver<VerdictEvent>) -> Result<Waited> {
        loop {
            let (pending, directive) = {
                let queue = self.lock()?;
                (
                    queue.pending_blocking(self.lane_id),
                    queue.pending_directive(self.lane_id),
                )
            };
            if let Some((id, verdict)) = directive {
                return Ok(Waited::Ruling(id, verdict));
            }
            let Some(oldest) = pending.first() else {
                return Ok(Waited::Nothing);
            };
            if let Some((id, verdict)) = pending
                .iter()
                .find_map(|p| p.verdict.clone().map(|v| (p.id.clone(), v)))
            {
                return Ok(Waited::Ruling(id, verdict));
            }
            let left = pending
                .iter()
                .map(|p| p.time_left)
                .min()
                .unwrap_or_default();
            eprintln!(
                "[{}] parked on {}: waiting for the director (`cowproof rule`)",
                self.lane_id, oldest.id
            );
            // The channel only wakes this loop; the queue is the truth.
            match tokio::time::timeout(left + Duration::from_millis(10), rx.recv()).await {
                Ok(Some(_)) => {}
                Ok(None) => {
                    return Ok(Waited::Lost(format!(
                        "the director control socket stopped, so no ruling can arrive for {}",
                        oldest.id
                    )));
                }
                Err(_) => {
                    let expired = self
                        .lock()?
                        .expire_parked(self.lane_id)
                        .map_err(|e| anyhow!("ending the parked lane: {e}"))?;
                    if expired.is_some() {
                        return Ok(Waited::Expired);
                    }
                }
            }
        }
    }

    /// Read and lint a redirect packet. Anything wrong refuses the redirect.
    fn load_redirect(&self, packet_path: &str) -> Result<String, String> {
        const MAX_PACKET: u64 = 1024 * 1024;
        let path = self.cwd.join(packet_path);
        let meta = fs::metadata(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        if !meta.is_file() || meta.len() > MAX_PACKET {
            return Err(format!(
                "{} is not a regular file under 1 MiB",
                path.display()
            ));
        }
        let text = fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        let header = parse_header(&text).map_err(|e| format!("{}: {e:#}", path.display()))?;
        if header.id != self.lane_id {
            return Err(format!(
                "the packet's id is {:?}, not this lane's {:?}",
                header.id, self.lane_id
            ));
        }
        let errors: Vec<String> = cowproof_lint::lint_packet(&text, self.repo, self.plans)
            .iter()
            .filter(|f| f.severity == cowproof_lint::Severity::Error)
            .map(|f| one_line(&f.to_string()))
            .collect();
        if errors.is_empty() {
            Ok(text)
        } else {
            Err(format!("lint errors: {}", errors.join("; ")))
        }
    }

    fn segment_record(index: usize, launch: &Launch, seg: &SegmentRun) -> serde_json::Value {
        json!({
            "index": index,
            "model": launch.model,
            "start": launch.kind.name(),
            "resumedSession": launch.resume,
            "startedBy": launch.started_by.as_ref().map(|id| id.0.clone()),
            "sessionId": seg.summary.session_id,
            "status": if seg.killed {
                "ended-by-runner"
            } else if seg.status.success() {
                "finished"
            } else {
                "failed"
            },
            "exitCode": seg.status.code(),
            "signal": seg.status.signal(),
            "sessionEnd": seg.session_end.as_ref().map(|end| match end {
                SessionEnd::Parked(_) => "parked",
                SessionEnd::Forced(_) => "forced",
                SessionEnd::LimitReached => "escalation-limit",
                SessionEnd::Timeout => "timeout",
                SessionEnd::CostCap => "cost-cap",
                SessionEnd::Ruled(_) => "ruled",
            }),
            "killedByRunner": seg.killed,
            "turns": seg.summary.turns.len(),
            "estimatedCostUsd": seg.estimated_cost_usd,
            "costIsEstimate": true,
            "durationMs": seg.elapsed.as_millis() as u64,
            "endedBy": serde_json::Value::Null,
        })
    }

    /// Run the builder, and keep running it for as long as rulings say so.
    async fn run(
        &self,
        rx: &mut UnboundedReceiver<VerdictEvent>,
        first_model: &str,
        first_packet: &str,
    ) -> Result<LaneRun> {
        let mut model = first_model.to_string();
        let mut packet = first_packet.to_string();
        let mut launch = Launch {
            model: model.clone(),
            packet: packet.clone(),
            prompt: packet.clone(),
            resume: None,
            kind: StartKind::Fresh,
            started_by: None,
        };
        // The ruling a resumed launch is delivering: told to the queue once
        // we know whether the session was there.
        let mut resuming: Option<EscalationId> = None;
        let mut session_id: Option<String> = None;
        let mut segments = Vec::new();
        let mut summaries = Vec::new();
        let mut stats = PumpStats::default();
        // The estimated cost of the queue's current segment (it restarts at
        // `reassign`, as the queue's own counters do).
        let mut segment_cost_usd = 0.0_f64;
        // The estimate for the whole lane, which `reassign` does not restart:
        // the hard cost stop is on this.
        let mut lane_cost_usd = 0.0_f64;

        let (end, status) = loop {
            let seg = self
                .launcher
                .launch(segments.len(), &launch, segment_cost_usd, lane_cost_usd, rx)
                .await?;
            segment_cost_usd += seg.estimated_cost_usd;
            lane_cost_usd += seg.estimated_cost_usd;
            stats.add(&seg.stats);
            if let Some(id) = &seg.summary.session_id {
                session_id = Some(id.clone());
            }
            let status = seg.status;
            let mut record = Self::segment_record(segments.len(), &launch, &seg);
            // A hard limit ended the launch: no fallback, no relaunch, no proof.
            let hard_end = match seg.session_end {
                Some(SessionEnd::Timeout) => Some(LaneEnd::Timeout),
                Some(SessionEnd::CostCap) => Some(LaneEnd::CostCap),
                _ => None,
            };

            if let Some(id) = resuming.take() {
                let gone = resume_session_gone(&seg);
                if hard_end.is_none() && gone {
                    record["resumeFailed"] = json!("session-gone");
                    segments.push(record);
                    summaries.push(seg.summary);
                    launch = match self.fall_back(&id)? {
                        Fallback::Fresh(summary) => Launch {
                            model: model.clone(),
                            packet: packet.clone(),
                            prompt: format!("{packet}\n\n{summary}"),
                            resume: None,
                            kind: StartKind::Fallback,
                            started_by: Some(id),
                        },
                        Fallback::Limit => break (LaneEnd::EscalationLimit, status),
                    };
                    continue;
                }
                // A hard stop on a resume that never got going leaves the ruling
                // recorded and undelivered: the lane is over either way.
                if !gone {
                    self.mark_delivered(&id)?;
                }
            }

            let (parked, directive) = {
                let queue = self.lock()?;
                (
                    queue.pending_blocking(self.lane_id),
                    queue.pending_directive(self.lane_id),
                )
            };
            if let Some(first) = parked.first() {
                record["endedBy"] = json!(first.id.0);
            } else if let Some((id, _)) = &directive {
                record["endedBy"] = json!(id.0);
            }
            segments.push(record);
            summaries.push(seg.summary);

            if let Some(end) = hard_end {
                break (end, status);
            }

            if self.lock()?.lane_state(self.lane_id) == Some(LaneState::EscalationLimit) {
                break (LaneEnd::EscalationLimit, status);
            }
            let (id, verdict) = match self.wait_for_ruling(rx).await? {
                Waited::Nothing => break (LaneEnd::Builder, status),
                Waited::Expired => break (LaneEnd::EscalationLimit, status),
                Waited::Lost(why) => break (LaneEnd::Refused(why), status),
                Waited::Ruling(id, verdict) => (id, verdict),
            };
            eprintln!("[{}] ruling on {id}: {verdict:?}", self.lane_id);

            match verdict {
                EscalationVerdict::Stop => {
                    self.lock()?
                        .set_lane_state(self.lane_id, LaneState::Stopped);
                    self.mark_delivered(&id)?;
                    break (LaneEnd::Stopped, status);
                }
                EscalationVerdict::Answer { text } => {
                    let prompt = format!("Director ruling on {id}:\n{}", fenced(&text));
                    match session_id.clone().filter(|s| resumable(s)) {
                        Some(session) => {
                            launch = Launch {
                                model: model.clone(),
                                packet: packet.clone(),
                                prompt,
                                resume: Some(session),
                                kind: StartKind::Resumed,
                                started_by: Some(id.clone()),
                            };
                            resuming = Some(id);
                        }
                        // The stream never gave a session id we can resume.
                        None => match self.fall_back(&id)? {
                            Fallback::Fresh(summary) => {
                                launch = Launch {
                                    model: model.clone(),
                                    packet: packet.clone(),
                                    prompt: format!("{packet}\n\n{summary}"),
                                    resume: None,
                                    kind: StartKind::Fallback,
                                    started_by: Some(id),
                                };
                            }
                            Fallback::Limit => break (LaneEnd::EscalationLimit, status),
                        },
                    }
                }
                EscalationVerdict::Redirect { packet_path } => {
                    match self.load_redirect(&packet_path) {
                        Ok(text) => {
                            self.mark_delivered(&id)?;
                            packet = text;
                            launch = Launch {
                                model: model.clone(),
                                packet: packet.clone(),
                                prompt: packet.clone(),
                                resume: None,
                                kind: StartKind::Fresh,
                                started_by: Some(id),
                            };
                        }
                        Err(why) => {
                            break (
                                LaneEnd::Refused(format!(
                                    "redirect for {id} refused ({why}); the ruling stays recorded and undelivered"
                                )),
                                status,
                            );
                        }
                    }
                }
                EscalationVerdict::Reassign { model: named } => {
                    let to = match named {
                        Some(m) if valid_model(&m) => m,
                        Some(m) => {
                            break (
                                LaneEnd::Refused(format!(
                                    "reassign for {id} refused: {m:?} is not a model name"
                                )),
                                status,
                            );
                        }
                        None => match next_model(&model) {
                            Some(m) => m.to_string(),
                            None => {
                                break (
                                    LaneEnd::Refused(format!(
                                        "reassign for {id} refused: no model above {model:?} on the ladder; name one with --model"
                                    )),
                                    status,
                                );
                            }
                        },
                    };
                    let summary = {
                        let mut queue = self.lock()?;
                        let summary = queue
                            .get(&id)
                            .map(|(ask, _, _)| reassign_summary(&id, ask, &model, &to))
                            .ok_or_else(|| anyhow!("escalation {id} is unknown"))?;
                        queue
                            .reassign(self.lane_id)
                            .map_err(|e| anyhow!("reassigning {id}: {e}"))?;
                        summary
                    };
                    self.mark_delivered(&id)?;
                    segment_cost_usd = 0.0;
                    model = to;
                    launch = Launch {
                        model: model.clone(),
                        packet: packet.clone(),
                        prompt: format!("{packet}\n\n{summary}"),
                        resume: None,
                        kind: StartKind::Fresh,
                        started_by: Some(id),
                    };
                }
            }
        };
        Ok(LaneRun {
            segments,
            summaries,
            stats,
            status,
            model: launch.model,
            session_id,
            end,
        })
    }
}

/// What a session that takes over after `reassign` is told: the question, what
/// was tried and the ruling (the work itself is in the clone).
fn reassign_summary(id: &EscalationId, ask: &Ask, from: &str, to: &str) -> String {
    let mut out = format!(
        "You are taking over this lane from a previous session on {from}; the clone already holds its work. Escalation {id} was ruled: reassign to {to}.\n\nQuestion: {}\n",
        ask.question
    );
    if !ask.tried.is_empty() {
        out.push_str("Tried:\n");
        for tried in &ask.tried {
            out.push_str(&format!("- {tried}\n"));
        }
    }
    out
}

/// The lane directory: the parent of the clone.
fn lane_dir(layout: &LaneLayout) -> Result<PathBuf> {
    layout
        .clone
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| anyhow!("lane clone {} has no parent", layout.clone.display()))
}

/// The builder's `PATH`: the director's, minus empty, relative and
/// real-home entries (the home is hidden from the sandbox, and an empty entry
/// would search the builder's clone).
pub(crate) fn builder_path(director_path: &str, real_home: &Path) -> String {
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
pub(crate) fn sandboxed_command(
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
    /// The first port of the lane's block (`COWPROOF_PORT_BASE`), the same one the builder gets.
    port_base: u16,
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
    let mut env = vec![
        ("PATH".to_string(), ctx.path.clone()),
        (
            "HOME".to_string(),
            ctx.layout.home.to_string_lossy().into_owned(),
        ),
    ];
    env.extend(port_block_env(ctx.port_base));
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

impl PumpStats {
    fn add(&mut self, other: &PumpStats) {
        self.metered += other.metered;
        self.unparsed += other.unparsed;
        self.oversized += other.oversized;
    }
}

/// Copy `reader` to `sink` byte for byte and feed each complete line to the
/// meter. Memory per line is bounded by `max_line`. After every line the meter
/// accepts, `on_line` sees the meter, which is where escalate-early reads the
/// new turns and the running cost estimate.
async fn pump_stream<R, W, F>(
    reader: R,
    sink: &mut W,
    meter: &mut StreamMeter,
    max_line: usize,
    on_line: &mut F,
) -> io::Result<PumpStats>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    F: FnMut(&StreamMeter),
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
            Ok(_) => {
                stats.metered += 1;
                on_line(meter);
            }
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

/// The lanes root default lives in `root.rs`, which the director's tools in the
/// library crate share; this is the one function under its old name.
pub use crate::root::lanes_root;

/// The name of the next SIGINT or SIGTERM.
async fn next_signal(sigint: &mut Signal, sigterm: &mut Signal) -> &'static str {
    tokio::select! {
        _ = sigint.recv() => "SIGINT",
        _ = sigterm.recv() => "SIGTERM",
    }
}

/// What an interrupted run leaves behind, after the servers are stopped: the
/// builder's group ended for good (a no-op when the launcher already did it),
/// the three sockets removed and `run.json` saying `interrupted`. Nothing here
/// waits, so a second signal never has to cut it short.
fn record_interrupted(
    layout: &LaneLayout,
    lane_id: &str,
    signal_name: &str,
    builder_pgid: Option<u32>,
    proxy_socket: &Path,
    started: Instant,
) {
    if let Some(pgid) = builder_pgid {
        kill_process_group(pgid);
    }
    let _ = fs::remove_file(&layout.sock);
    let _ = fs::remove_file(layout.control.join("director.sock"));
    let _ = fs::remove_file(proxy_socket);
    let run = json!({
        "id": lane_id,
        "status": "interrupted",
        "signal": signal_name,
        "exitCode": INTERRUPTED_EXIT_CODE,
        "durationMs": started.elapsed().as_millis() as u64,
    });
    if let Err(e) = fs::write(
        layout.control.join("run.json"),
        serde_json::to_vec_pretty(&run).unwrap_or_default(),
    ) {
        eprintln!("[{lane_id}] writing run.json: {e}");
    }
}

/// The lane's wall-clock limit: the packet header's `timeoutMin` if it sets
/// one, else the hidden `--timeout-secs` (tests), else `--timeout-min`.
fn lane_timeout(header_min: Option<u64>, flag_secs: Option<u64>, flag_min: u64) -> Duration {
    match (header_min, flag_secs) {
        (Some(minutes), _) => Duration::from_secs(minutes.saturating_mul(60)),
        (None, Some(secs)) => Duration::from_secs(secs),
        (None, None) => Duration::from_secs(flag_min.saturating_mul(60)),
    }
}

pub async fn run_one(args: super::RunOneArgs) -> Result<i32> {
    let started = Instant::now();
    if args.turn_budget == 0 {
        bail!("--turn-budget must be at least 1");
    }
    if !args.cost_cap_usd.is_finite() || args.cost_cap_usd <= 0.0 {
        bail!("--cost-cap-usd must be a positive number of US dollars");
    }
    if args.timeout_min == 0 || args.timeout_secs == Some(0) {
        bail!("--timeout-min must be at least 1");
    }
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
    if header.timeout_min == Some(0) {
        bail!("the packet's timeoutMin must be at least 1");
    }
    if header
        .max_cost_usd
        .is_some_and(|c| !c.is_finite() || c <= 0.0)
    {
        bail!("the packet's maxCostUsd must be a positive number of US dollars");
    }
    let checks = &header.checks;
    if checks.is_empty() {
        eprintln!("warning: the packet declares no checks, so run_check will refuse every id");
    }

    // 2. Preflight: the host can sandbox, clone and has room, the builder runs, the key
    // is set and the repository has a commit. Any failure stops the run here, before
    // any lane directory, clone or socket exists (it probes under a throwaway
    // directory it removes, and does not create the lanes root).
    let director_path = std::env::var("PATH").unwrap_or_default();
    let real_home =
        PathBuf::from(std::env::var_os("HOME").ok_or_else(|| anyhow!("HOME is not set"))?);
    let lanes_root = lanes_root(args.lanes_root.as_deref(), &cwd, &real_home);
    let preflight_checks = preflight(&PreflightOptions {
        repo: &repo,
        lanes_root: &lanes_root,
        disk_floor_gb: args.disk_floor_gb,
        claude_bin: &args.claude_bin,
        director_path: &director_path,
        cwd: &cwd,
        real_home: &real_home,
        for_run: true,
    })
    .await;
    for check in &preflight_checks {
        match check.status {
            CheckStatus::Ok => {}
            CheckStatus::Warn => eprintln!("preflight warning: {}: {}", check.name, check.detail),
            CheckStatus::Fail => eprintln!("preflight failed: {}: {}", check.name, check.detail),
        }
    }
    if preflight_checks
        .iter()
        .any(|c| c.status == CheckStatus::Fail)
    {
        eprintln!("nothing was started; `cowproof doctor` shows every check");
        return Ok(INFRASTRUCTURE_EXIT_CODE);
    }

    // The real key lives in this process and the proxy, nowhere else.
    let api_key = match std::env::var_os("ANTHROPIC_API_KEY") {
        Some(k) if !k.is_empty() => k
            .into_string()
            .map_err(|_| anyhow!("ANTHROPIC_API_KEY is not valid UTF-8"))?,
        _ => bail!("ANTHROPIC_API_KEY is not set; the proxy needs the real key"),
    };
    let claude_bin = resolve_executable(&args.claude_bin, &director_path, &cwd)?;
    // The held-out checks (D5) are found before any lane exists: a path inside the
    // repository, or one that is unreadable, stops the run here.
    let heldout = resolve_heldout(args.heldout.as_deref(), &repo, &real_home, &header.id)?;
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
    // The builder's, `run_check`'s and the git steps' `TMPDIR`: inside the
    // scratch they are granted, because macOS denies every other write.
    fs::create_dir_all(lane_tmp(&layout.scratch)).context("creating the lane's temp directory")?;
    let lane = lane_dir(&layout)?;
    eprintln!("[{}] lane {}", header.id, lane.display());

    // The builder's slots (D12), before anything runs. First one of the packet's resource
    // class: this machine's `rust` lanes (or `pg`, `light`, `crate`) are capped, and the cap
    // is the base commit's, so a patch cannot raise it. Then one `port` slot, whose number
    // fixes the lane's port block, so blocks are unique across classes. Both are held to the
    // end of the run. The verifier of this same run reuses them (see
    // `ProofInput::builder_slot`) and never waits on its own run. SIGINT and SIGTERM are
    // caught from here on: a wait can last as long as the lanes ahead.
    let mut sigint = signal(SignalKind::interrupt()).context("installing the SIGINT handler")?;
    let mut sigterm = signal(SignalKind::terminate()).context("installing the SIGTERM handler")?;
    let class = header.class_name.as_str();
    let class_limit = class_limit_at_commit(&repo, &prepared.base_commit, class)?;
    let port_limit = class_limit_at_commit(&repo, &prepared.base_commit, PORT_CLASS)?;
    let slot_dir = args.slot_dir.clone().unwrap_or_else(get_slot_dir);
    let mut taken = Vec::new();
    for (slot_class, limit) in [(class, class_limit), (PORT_CLASS, port_limit)] {
        let wait_started = Instant::now();
        let slot = tokio::select! {
            slot = acquire_slot_notifying(slot_class, limit, &slot_dir, || {
                eprintln!("[{}] waiting for a {slot_class} slot (limit {limit})", header.id);
            }) => slot.with_context(|| {
                format!("taking a {slot_class} slot in {}", slot_dir.display())
            })?,
            name = next_signal(&mut sigint, &mut sigterm) => {
                eprintln!(
                    "[{}] {name} while waiting for a {slot_class} slot: ending the run",
                    header.id
                );
                // `taken` drops here and gives back the class slot, if it was held.
                record_interrupted(
                    &layout,
                    &header.id,
                    name,
                    None,
                    &layout.control.join("proxy.sock"),
                    started,
                );
                return Ok(INTERRUPTED_EXIT_CODE);
            }
        };
        taken.push((slot, wait_started.elapsed()));
    }
    let (port_slot, port_wait) = taken.pop().context("the port slot")?;
    let (slot, slot_wait) = taken.pop().context("the class slot")?;
    let slot_paths = [slot.path().to_path_buf(), port_slot.path().to_path_buf()];
    let port_base = port_base_for_slot(port_slot.path())
        .with_context(|| format!("the slot {} has no number", port_slot.path().display()))?;

    // 4. Proxy and tools, both live before the builder starts.
    let endpoint = start_proxy(&layout, &header.id, api_key).await?;
    let _proxy = AbortOnDrop(endpoint.task);
    // The session-end channel exists before the tools server and the builder
    // do, so no signal can be missed (D9: the runner ends the session).
    let (end_tx, end_rx) = tokio::sync::mpsc::unbounded_channel();
    let queue = Arc::new(Mutex::new(
        Queue::with_all_limits(
            &layout.control,
            Box::new(SystemClock),
            DEFAULT_PARK_LIMIT,
            DEFAULT_MAX_ESCALATIONS,
            args.turn_budget as usize,
            DEFAULT_COST_FRACTION,
        )
        .context("opening the escalation queue")?,
    ));
    let tools_listener = tools::bind(&layout.sock).context("binding the builder tools socket")?;
    let socket = layout
        .sock
        .canonicalize()
        .context("resolving the tools socket")?;
    let director_sock_path = layout.control.join("director.sock");
    let director_listener =
        director::bind(&director_sock_path).context("binding the director control socket")?;
    // Set mode to 0600 (read-write for owner only)
    let permissions = std::fs::Permissions::from_mode(0o600);
    std::fs::set_permissions(&director_sock_path, permissions)
        .context("setting director socket permissions")?;
    let tools_queue = queue.clone();
    let table: CheckTable = checks.iter().map(|c| c.id.clone()).collect();
    let context = Arc::new(CheckContext {
        layout: layout.clone(),
        path: path.clone(),
        commands: checks
            .iter()
            .map(|c| (c.id.clone(), c.command.clone()))
            .collect(),
        slot: Semaphore::new(1),
        port_base,
    });
    let run_check: RunCheck =
        Arc::new(move |id: &str| Box::pin(run_declared_check(context.clone(), id.to_string())));
    let _tools = AbortOnDrop(tokio::spawn({
        let lane_id = header.id.clone();
        let end_tx = end_tx.clone();
        async move {
            if let Err(e) = tools::serve_signalling(
                tools_listener,
                lane_id,
                tools_queue,
                table,
                run_check,
                Some(end_tx),
            )
            .await
            {
                eprintln!("builder tools stopped: {e}");
            }
        }
    }));

    // The director's rulings wake the resume loop below (D9, D25). The queue,
    // not the channel, is the truth: the loop re-reads it on every wake.
    let (verdict_tx, mut verdict_rx) = tokio::sync::mpsc::unbounded_channel();
    let _director = AbortOnDrop(tokio::spawn({
        let lane_id = header.id.clone();
        let director_queue = queue.clone();
        let verdict_tx = Some(verdict_tx);
        async move {
            if let Err(e) =
                director::serve(director_listener, lane_id, director_queue, verdict_tx).await
            {
                eprintln!("director control socket stopped: {e}");
            }
        }
    }));

    // 5. Launch inside the builder sandbox, and relaunch on the director's
    // rulings while a blocking escalation is parked.
    //
    // The prefix version, and the project instructions as they are in the base commit,
    // read once: neither a dirty working tree nor a later commit can reach the builder
    // (D20), and a relaunch after a ruling sends the same bytes. A missing `CLAUDE.md`
    // means no project-instructions section. A committed `CLAUDE.md -> AGENTS.md` is
    // followed inside the base tree; a link that cannot be used gives no instructions
    // and a warning, and the run goes on.
    let preamble_version = prefix_version();
    let project_instructions_content =
        match git_show_following_links(&repo, &prepared.base_commit, "CLAUDE.md")
            .context("reading CLAUDE.md from the base commit")?
        {
            LinkedFile::Text(text) => Some(text),
            LinkedFile::Absent => None,
            LinkedFile::Unusable(reason) => {
                eprintln!(
                    "[{}] warning: no project instructions for the builder: {reason}",
                    header.id
                );
                None
            }
        };
    let project_instructions_hash = project_instructions_content
        .as_ref()
        .map(|text| Capsule::hash_bytes(text.as_bytes()));

    let interrupt = Interrupt::new();
    // The proxy's socket, read before the endpoint is moved: removed if interrupted.
    let proxy_sock = endpoint.socket.clone();
    let timeout = lane_timeout(header.timeout_min, args.timeout_secs, args.timeout_min);
    // The cost cap is the header's `maxCostUsd`, else the flag; the escalate-early
    // share and the hard stop both use it.
    let cost_cap_usd = header.max_cost_usd.unwrap_or(args.cost_cap_usd);
    let launcher = Launcher {
        layout: layout.clone(),
        claude_bin: claude_bin.clone(),
        cowproof_exe: cowproof_exe.clone(),
        path: path.clone(),
        base_url: endpoint.base_url,
        bridge_port: endpoint.bridge_port,
        proxy_socket: endpoint.socket,
        placeholder_key: endpoint.placeholder_key,
        network: endpoint.network,
        max_turns: args.max_turns,
        socket,
        queue: queue.clone(),
        lane_id: header.id.clone(),
        cost_cap_usd,
        end_tx,
        end_rx: tokio::sync::Mutex::new(end_rx),
        interrupt: interrupt.clone(),
        prefix_version: preamble_version.clone(),
        project_instructions: project_instructions_content.clone(),
        project_instructions_sha256: project_instructions_hash.clone(),
        timeout,
        active: Mutex::new(Duration::ZERO),
        port_base,
    };
    let drive = Drive {
        launcher: &launcher,
        queue: &queue,
        lane_id: &header.id,
        cwd: &cwd,
        repo: &repo,
        plans: &plans,
    };

    // 5b. SIGINT and SIGTERM (caught since the slot wait). The builder is not in the
    // terminal's foreground group, so the default action would end the runner and leave
    // it running.
    // On the first signal: end the builder's group (the launcher sends SIGTERM,
    // then SIGKILL after TERM_GRACE, and gives up the launch), stop the tools,
    // director and proxy tasks, remove the three sockets, write `run.json` as
    // `interrupted`, skip the proof and exit 130. A second signal while that
    // waits skips the wait.
    let drive_run = drive.run(&mut verdict_rx, &args.model, &packet_text);
    tokio::pin!(drive_run);
    let first = tokio::select! {
        result = &mut drive_run => Ok(result?),
        name = next_signal(&mut sigint, &mut sigterm) => Err(name),
    };
    let lane_run = match first {
        Ok(run) => run,
        Err(signal_name) => {
            eprintln!("[{}] {signal_name}: ending the run", header.id);
            interrupt.raise();
            // A builder is running: the launcher ends its group and returns.
            // With none (waiting for a ruling, say) there is nothing to wait for.
            if interrupt.builder_pgid().is_some() {
                tokio::select! {
                    _ = &mut drive_run => {}
                    _ = tokio::time::sleep(TERM_GRACE + INTERRUPT_SLACK) => {}
                    second = next_signal(&mut sigint, &mut sigterm) => {
                        eprintln!("[{}] {second} again: not waiting", header.id);
                    }
                }
            }
            drop(_tools);
            drop(_director);
            drop(_proxy);
            record_interrupted(
                &layout,
                &header.id,
                signal_name,
                interrupt.builder_pgid(),
                &proxy_sock,
                started,
            );
            return Ok(INTERRUPTED_EXIT_CODE);
        }
    };
    // Past the builder, a signal ends the process at once, as it did before
    // the handlers existed (the tokio handlers would otherwise swallow it).
    tokio::spawn(async move {
        next_signal(&mut sigint, &mut sigterm).await;
        // `exit` runs no destructors: give both slots back first.
        for slot_path in &slot_paths {
            release_slot(Some(slot_path));
        }
        std::process::exit(INTERRUPTED_EXIT_CODE);
    });
    let status = lane_run.status;
    let stats = &lane_run.stats;
    let end = &lane_run.end;
    let status_name = end.name(status.success());

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

    // The last launch's meter stands for the single-launch fields; totals add
    // every launch up.
    let summary = lane_run
        .summaries
        .last()
        .context("the builder never ran")?
        .clone();
    let total_turns: usize = lane_run.summaries.iter().map(|s| s.turns.len()).sum();
    let total_tokens: u64 = lane_run
        .summaries
        .iter()
        .map(|s| {
            s.total_input_tokens
                + s.total_output_tokens
                + s.total_cache_read_tokens
                + s.total_cache_creation_tokens
        })
        .sum();
    let total_cost_usd: f64 = lane_run
        .summaries
        .iter()
        .filter_map(|s| s.total_cost_usd)
        .sum();
    let estimated_cost_usd: f64 = lane_run
        .segments
        .iter()
        .filter_map(|s| s["estimatedCostUsd"].as_f64())
        .sum();
    let run = json!({
        "id": header.id,
        "bridgePort": launcher.bridge_port,
        "status": status_name,
        "estimatedCostUsd": estimated_cost_usd,
        "costIsEstimate": true,
        "costCapUsd": launcher.cost_cap_usd,
        "timeoutSecs": launcher.timeout.as_secs(),
        "activeMs": launcher
            .active
            .lock()
            .map_or(0, |a| a.as_millis() as u64),
        "error": match end {
            LaneEnd::Refused(why) => json!(why),
            _ => serde_json::Value::Null,
        },
        "exitCode": status.code(),
        "signal": status.signal(),
        "model": lane_run.model,
        "turns": total_turns,
        "sessionId": lane_run.session_id,
        "meter": summary,
        "segments": lane_run.segments,
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
        "classSlot": {
            "class": class,
            "limit": class_limit,
            "waitMs": slot_wait.as_millis() as u64,
        },
        "portSlot": {
            "limit": port_limit,
            "portBase": port_base,
            "waitMs": port_wait.as_millis() as u64,
        },
        "lane": {
            "dir": lane,
            "clone": layout.clone,
            "control": layout.control,
            "stream": layout.control.join("stream.jsonl"),
            "patch": patch_path,
            "stderr": layout.control.join("builder.stderr"),
        },
        "prefixVersion": &launcher.prefix_version,
        "projectInstructionsSha256": &launcher.project_instructions_sha256,
    });
    fs::write(
        layout.control.join("run.json"),
        serde_json::to_vec_pretty(&run)?,
    )?;

    println!(
        "{}: {}, exit {}, {} turns, patch {} bytes, lane {}",
        header.id,
        status_name,
        status
            .code()
            .map_or_else(|| "signal".to_string(), |c| c.to_string()),
        total_turns,
        patch_bytes.map_or_else(|| "none".to_string(), |n| n.to_string()),
        lane.display()
    );
    patch?;
    match end {
        LaneEnd::Builder => {}
        LaneEnd::Stopped => bail!("the director stopped lane {}; its work is kept", header.id),
        LaneEnd::EscalationLimit => bail!(
            "lane {} ended as escalation-limit; its work is kept",
            header.id
        ),
        LaneEnd::Timeout => return Ok(TIMEOUT_EXIT_CODE),
        LaneEnd::CostCap => return Ok(COST_CAP_EXIT_CODE),
        LaneEnd::Refused(why) => bail!("{why}"),
    }
    if !status.success() {
        bail!("the builder exited with {status}");
    }

    // 7. Prove the lane: replay the recorded results, run the gates, judge.
    // The results come from the very `Queue` the tools server recorded into;
    // a second `Queue` on the same directory would know none of them.
    let results = queue
        .lock()
        .map(|q| q.check_results(&header.id))
        .map_err(|_| {
            "the escalation queue is unavailable, so the recorded check results are lost"
                .to_string()
        });
    let verdict = prove_lane(
        &ProofInput {
            layout: &layout,
            repo: &repo,
            prepared: &prepared,
            header: &header,
            model: &lane_run.model,
            cost_usd: total_cost_usd,
            tokens: total_tokens,
            heldout_path: heldout.as_deref(),
            prefix_version: launcher.prefix_version.clone(),
            project_instructions_sha256: launcher.project_instructions_sha256.clone(),
            builder_slot: slot.path(),
            slot_dir: &slot_dir,
            class_limit,
            port_base,
        },
        results,
    )
    .await?;
    Ok(verdict.outcome.exit_code())
}

/// How a lane ends. The exit code of `cowproof run` is the outcome's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Proved,
    Refuted,
    Incomplete,
    Infrastructure,
}

impl Outcome {
    fn name(self) -> &'static str {
        match self {
            Outcome::Proved => "proved",
            Outcome::Refuted => "refuted",
            Outcome::Incomplete => "incomplete",
            Outcome::Infrastructure => "infrastructure",
        }
    }

    fn exit_code(self) -> i32 {
        match self {
            Outcome::Proved => 0,
            Outcome::Refuted => 2,
            Outcome::Incomplete => 3,
            Outcome::Infrastructure => INFRASTRUCTURE_EXIT_CODE,
        }
    }
}

/// A check whose result in the verifier differs from the one the builder recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Divergence {
    id: String,
    recorded_passed: bool,
    verify_exit: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GateFailure {
    name: String,
    evidence: Vec<String>,
}

/// Everything the proof found, before it is judged.
#[derive(Debug, Default, PartialEq, Eq)]
struct Evidence {
    /// Declared checks the builder never ran through `run_check`.
    unrun: Vec<String>,
    /// Checks whose last recorded result failed.
    failed_checks: Vec<String>,
    diverged: Vec<Divergence>,
    failed_gates: Vec<GateFailure>,
    /// Anything that stopped the proof from running (F-1: never a refutation).
    infrastructure: Vec<String>,
    /// The packet declared no checks, so nothing was verified.
    no_checks_declared: bool,
    /// Held-out checks that failed on the verifier's rebuilt tree.
    heldout_failed: Vec<String>,
}

#[derive(Debug, PartialEq, Eq)]
struct Verdict {
    outcome: Outcome,
    reasons: Vec<String>,
}

/// Judge the evidence. Infrastructure wins over everything (a proof that could
/// not run proves and refutes nothing, F-1). A definite failure beats a
/// missing result, and unrun checks are still listed beside it. `Proved`
/// needs every declared check run, reproduced and passing, and no failed gate.
fn judge(e: &Evidence) -> Verdict {
    if !e.infrastructure.is_empty() {
        return Verdict {
            outcome: Outcome::Infrastructure,
            reasons: e.infrastructure.clone(),
        };
    }
    let mut reasons = Vec::new();
    for id in &e.failed_checks {
        reasons.push(format!("check {id:?} failed when the builder ran it"));
    }
    for d in &e.diverged {
        reasons.push(format!(
            "check {:?} diverged: the builder recorded {}, but verify got exit {}",
            d.id,
            if d.recorded_passed {
                "a pass"
            } else {
                "a failure"
            },
            d.verify_exit
        ));
    }
    for id in &e.heldout_failed {
        reasons.push(format!("held-out check {id:?} failed on the rebuilt tree"));
    }
    for g in &e.failed_gates {
        if g.evidence.is_empty() {
            reasons.push(format!("gate {} failed", g.name));
        } else {
            reasons.push(format!("gate {} failed: {}", g.name, g.evidence.join("; ")));
        }
    }
    let refuted = !reasons.is_empty();
    for id in &e.unrun {
        reasons.push(format!("check {id:?} was never run"));
    }
    if e.no_checks_declared {
        reasons.push("the packet declares no checks, so nothing was verified".to_string());
    }
    let outcome = if refuted {
        Outcome::Refuted
    } else if !e.unrun.is_empty() || e.no_checks_declared {
        Outcome::Incomplete
    } else {
        Outcome::Proved
    };
    Verdict { outcome, reasons }
}

/// Builder-controlled text (file names in gate evidence) reaches the
/// director's terminal: control characters are shown as escapes, and the
/// result is one line.
fn one_line(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c.is_control() {
                c.escape_default().to_string()
            } else {
                c.to_string()
            }
        })
        .collect()
}

/// What the proof needs from the run.
struct ProofInput<'a> {
    layout: &'a LaneLayout,
    repo: &'a Path,
    prepared: &'a cowproof_run::lane::PreparedLane,
    header: &'a cowproof_core::Header,
    model: &'a str,
    cost_usd: f64,
    tokens: u64,
    /// The director's held-out checks for this lane, outside the repository. `None`
    /// means the lane has none (the gate warns, or fails when the base requires them).
    heldout_path: Option<&'a Path>,
    /// The version of the builder preamble (sha256 hash of PREAMBLE bytes).
    prefix_version: String,
    /// The SHA256 hash of the project instructions from the base commit,
    /// or None if there were no project instructions.
    project_instructions_sha256: Option<String>,
    /// The class slot this run holds (D12). The verifier reuses it and never takes a
    /// second: at a class limit of one it would wait for the slot its own run holds. The
    /// run keeps holding it until the verdict is written.
    builder_slot: &'a Path,
    /// The slot directory and the class limit the slot came from: what the verifier would
    /// use if it ever had to take a slot itself.
    slot_dir: &'a Path,
    class_limit: usize,
    /// The first port of the run's `port` slot's block, which the verifier's checks get as
    /// well. The verifier takes no `port` slot of its own.
    port_base: u16,
}

/// Find the lane's held-out checks (D5): the explicit `--heldout` path, which must exist,
/// or the director store `~/.cowproof/heldout/<repo-id>/<lane-id>.toml` when that file
/// exists. Either way the path is canonical and outside the repository, and the file
/// parses; anything else is an error, before a lane is created.
fn resolve_heldout(
    explicit: Option<&Path>,
    repo: &Path,
    home: &Path,
    lane_id: &str,
) -> Result<Option<PathBuf>> {
    let repo_id = cowproof_core::heldout::repo_id(repo)?;
    let path = cowproof_core::heldout::resolve(explicit, home, repo, &repo_id, lane_id)?;
    if explicit.is_none() && !path.exists() {
        return Ok(None);
    }
    let checks = cowproof_core::heldout::load(&path)?;
    if checks.check.is_empty() {
        bail!(
            "the held-out checks file {} holds no checks",
            path.display()
        );
    }
    Ok(Some(path))
}

/// Prove the lane after the builder exits: capsule, gates, verify, verdict.
///
/// `results` is the builder's last `run_check` result per check id, from the
/// queue. Only a failure to write `verdict.json` is an error; every other
/// failure to prove is an `Infrastructure` verdict.
async fn prove_lane(
    input: &ProofInput<'_>,
    results: std::result::Result<BTreeMap<String, bool>, String>,
) -> Result<Verdict> {
    let header = input.header;
    let mut evidence = Evidence {
        no_checks_declared: header.checks.is_empty(),
        ..Evidence::default()
    };
    let results = results.unwrap_or_else(|e| {
        evidence.infrastructure.push(e);
        BTreeMap::new()
    });
    let mut ran: Vec<(&cowproof_core::Check, bool)> = Vec::new();
    for check in &header.checks {
        match results.get(&check.id) {
            Some(&passed) => {
                ran.push((check, passed));
                if !passed {
                    evidence.failed_checks.push(check.id.clone());
                }
            }
            None => evidence.unrun.push(check.id.clone()),
        }
    }

    if let Err(e) = replay_and_gate(input, &ran, &mut evidence).await {
        evidence.infrastructure.push(format!("{e:#}"));
    }
    let verdict = judge(&evidence);

    let control = &input.layout.control;
    let details = json!({
        "id": header.id,
        "verdict": verdict.outcome.name(),
        "exitCode": verdict.outcome.exit_code(),
        "reasons": verdict.reasons,
        "unrun": evidence.unrun,
        "failedChecks": evidence.failed_checks,
        "heldOutFailed": evidence.heldout_failed,
        "diverged": evidence.diverged.iter().map(|d| d.id.clone()).collect::<Vec<_>>(),
        "failedGates": evidence.failed_gates.iter().map(|g| g.name.clone()).collect::<Vec<_>>(),
    });
    fs::write(
        control.join("verdict.json"),
        serde_json::to_vec_pretty(&details)?,
    )
    .context("writing verdict.json")?;

    // The capsule was sealed as `finished` before verify read it; record how
    // the lane ended (a lane that could not be proved stays `finished`).
    if verdict.outcome != Outcome::Infrastructure {
        let dir = control.join("capsule");
        let sealed = Capsule::read(&dir).and_then(|mut c| {
            c.lane_state = verdict.outcome.name().to_string();
            c.write(&dir).map_err(|e| {
                cowproof_prove::CapsuleError::InvalidFormat(format!("rewriting capsule.json: {e}"))
            })
        });
        if let Err(e) = sealed {
            eprintln!("warning: could not record the verdict in the capsule: {e}");
        }
    }

    let line = if verdict.reasons.is_empty() {
        format!("{}: {}", header.id, verdict.outcome.name())
    } else {
        format!(
            "{}: {}: {}",
            header.id,
            verdict.outcome.name(),
            one_line(&verdict.reasons.join("; "))
        )
    };
    println!("{line}");
    Ok(verdict)
}

/// Gates, capsule, verify. Gate and verify findings go into `evidence`;
/// an `Err` means the proof itself could not be built.
async fn replay_and_gate(
    input: &ProofInput<'_>,
    ran: &[(&cowproof_core::Check, bool)],
    evidence: &mut Evidence,
) -> Result<()> {
    let (layout, header) = (input.layout, input.header);
    let capsule_dir = layout.control.join("capsule");
    fs::create_dir_all(&capsule_dir).context("creating the capsule directory")?;
    let lane_patch = fs::read(layout.control.join("lane.patch")).context("reading lane.patch")?;

    // Gates load their configuration from the base revision, not the patch.
    let packet = GatePacket {
        owns: header.owns.clone(),
        append_only: header.append_only.clone(),
        protected: vec![],
        // The repository's own setting, from the base commit: a patch cannot switch it off.
        require_heldout: base_requires_heldout(input.repo, &input.prepared.base_commit)?,
        heldout_path: input.heldout_path.map(Path::to_path_buf),
    };
    match run_gates(
        input.repo,
        &input.prepared.base_commit,
        &String::from_utf8_lossy(&lane_patch),
        &packet,
    ) {
        Ok(report) => {
            fs::write(
                capsule_dir.join("gates.json"),
                serde_json::to_vec_pretty(&report)?,
            )
            .context("writing gates.json")?;
            evidence
                .failed_gates
                .extend(
                    report
                        .gates
                        .iter()
                        .filter(|g| !g.passed)
                        .map(|g| GateFailure {
                            name: g.name.clone(),
                            evidence: g.evidence.clone(),
                        }),
                );
        }
        Err(e) => evidence
            .infrastructure
            .push(format!("the gates could not run: {e:#}")),
    }

    // The capsule: only results the builder actually recorded. A check never
    // run has no file, so the verifier never compares an invented result.
    // The queue keeps pass or fail only, so the stored exit status is 0 or 1
    // and replay compares pass or fail, as the design says.
    let base = &input.prepared.base_commit;
    let base_tree_hash = git_stdout(input.repo, &["rev-parse", &format!("{base}^{{tree}}")])
        .await
        .context("reading the base tree hash")?;
    let remote_reachable = !git_stdout(
        input.repo,
        &["for-each-ref", "--contains", base, "refs/remotes"],
    )
    .await
    .context("checking whether the base commit is on a remote")?
    .is_empty();
    let mut tools = HashMap::new();
    for tool in ["git", "cargo", "rustc"] {
        if let Some(version) = tool_version(tool).await {
            tools.insert(tool.to_string(), version);
        }
    }
    let mut capsule = Capsule::new(
        base.clone(),
        base_tree_hash,
        EnvironmentFingerprint {
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            tools,
        },
        input.model.to_string(),
        "api-key".to_string(),
    );
    capsule.estimated_cost_usd = input.cost_usd;
    capsule.estimated_tokens = input.tokens;
    capsule.unsandboxed = false;
    capsule.local_replay_only = !remote_reachable;
    capsule.flaky_checks = header
        .checks
        .iter()
        .filter(|c| c.flaky)
        .map(|c| c.id.clone())
        .collect();
    capsule.launch_removed = input.prepared.launch_removed.clone();
    capsule.prefix_version = Some(input.prefix_version.clone());
    capsule.project_instructions_sha256 = input.project_instructions_sha256.clone();
    capsule.class = header.class_name.clone();

    // Fetch the dependencies the checks need before verify runs (D6, D11, D14), on the
    // rebuilt tree, outside any builder. The capsule records the cache key and what the
    // fetch did, and a fetch that fails ends the lane as infrastructure, never
    // `refuted` (F-1): the checks would only fail for want of crates.
    let mut fetch_failed = false;
    let rebuild = Rebuild {
        repo: input.repo.to_path_buf(),
        base_commit: input.prepared.base_commit.clone(),
        base_patch: input.prepared.base_patch.clone(),
        launch_removed: input.prepared.launch_removed.clone(),
        lane_patch: lane_patch.clone(),
    };
    let mut deps_dir = None;
    match fetch_dependencies(rebuild, layout).await {
        Ok(None) => {}
        Ok(Some(fetch)) => {
            capsule.dependency_cache_key = Some(fetch.key.clone());
            capsule.dependency_fetch_outcome = Some(fetch.outcome.name().to_string());
            match fetch.outcome {
                FetchOutcome::Failed(why) => {
                    fetch_failed = true;
                    evidence.infrastructure.push(format!(
                        "dependency fetch (cargo fetch --locked) failed: {}",
                        one_line(&why)
                    ));
                }
                _ => deps_dir = Some(fetch.dir),
            }
        }
        Err(e) => {
            fetch_failed = true;
            evidence.infrastructure.push(format!(
                "dependency fetch (cargo fetch --locked) could not run: {}",
                one_line(&format!("{e:#}"))
            ));
        }
    }

    if let Some(base_patch) = &input.prepared.base_patch {
        fs::write(capsule_dir.join("base.patch"), base_patch)?;
    }
    fs::write(capsule_dir.join("lane.patch"), &lane_patch)?;
    // The held-out checks go into the capsule's `packets/` (hashed there, run by the
    // verifier), copied from the director's store. Never into the lane's clone or home.
    if let Some(heldout) = input.heldout_path {
        let dest = capsule_dir.join(HELDOUT_FILE);
        fs::create_dir_all(dest.parent().context("packets path has no parent")?)?;
        fs::copy(heldout, &dest)
            .with_context(|| format!("copying the held-out checks {}", heldout.display()))?;
    }
    let escalations = layout.control.join("escalations.jsonl");
    if escalations.is_file() {
        fs::copy(&escalations, capsule_dir.join("escalations.jsonl"))
            .context("copying escalations.jsonl")?;
    }
    let checks_dir = capsule_dir.join("checks");
    fs::create_dir_all(&checks_dir)?;
    for (check, passed) in ran {
        let recorded = CheckResult {
            command: check.command.clone(),
            exit_status: if *passed { 0 } else { 1 },
            // The queue keeps no run count, duration or output (backlog).
            attempts: 1,
            duration_ms: 0,
            output_sha256: String::new(),
        };
        fs::write(
            checks_dir.join(format!("{}.json", check.id)),
            serde_json::to_vec_pretty(&recorded)?,
        )?;
    }
    capsule.write(&capsule_dir).context("writing the capsule")?;

    // Verify in a fresh directory of its own. The verifier policy grants the
    // layout's scratch read and write, so the runner's layout names only that
    // directory: whatever the builder left in the lane's scratch is hidden, and
    // anything it left at `scratch/verify` is cleared first (`verifier_runner`).
    if fetch_failed {
        return Ok(());
    }
    let verify_dir = layout.scratch.join("verify");
    let runner =
        verifier_runner(layout, &verify_dir, deps_dir.as_deref())?.with_port_block(input.port_base);
    // The verifier holds the lane's class slot (D12) by reusing the one this run holds:
    // `verify` takes none of its own.
    let options = VerifyOptions {
        slot_dir: input.slot_dir.to_path_buf(),
        slot_class: header.class_name.clone(),
        slot_limit: input.class_limit,
        held_slot_path: Some(input.builder_slot.to_path_buf()),
        ..VerifyOptions::default()
    };
    match verify(&capsule_dir, input.repo, &verify_dir, &runner, options).await {
        Ok(report) => {
            evidence.heldout_failed.extend(
                report
                    .heldout
                    .iter()
                    .filter(|o| !o.passed)
                    .map(|o| o.check_id.clone()),
            );
            for (check, passed) in ran {
                match report.checks.iter().find(|m| m.check_id == check.id) {
                    None => evidence
                        .infrastructure
                        .push(format!("verify did not run check {:?}", check.id)),
                    Some(m) if !m.matched_capsule => evidence.diverged.push(Divergence {
                        id: check.id.clone(),
                        recorded_passed: *passed,
                        verify_exit: m.actual_exit_status,
                    }),
                    Some(_) => {}
                }
            }
        }
        Err(e) => evidence
            .infrastructure
            .push(format!("verify could not run: {e}")),
    }
    Ok(())
}

/// Trimmed stdout of a git command in the director's own repository.
async fn git_stdout(repo: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new("git")
        .args(["-c", "core.hooksPath=/dev/null", "-C"])
        .arg(repo)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .await
        .context("running git")?;
    if !output.status.success() {
        bail!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// First line of `<tool> --version`, when the tool runs.
async fn tool_version(tool: &str) -> Option<String> {
    let out = Command::new(tool)
        .arg("--version")
        .stdin(Stdio::null())
        .output()
        .await
        .ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .next()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
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
    fn the_headers_timeout_wins_over_both_flags_and_the_flag_default_is_minutes() {
        let min = |m: u64| Duration::from_secs(m * 60);
        assert_eq!(lane_timeout(Some(100), Some(2), 45), min(100));
        assert_eq!(lane_timeout(Some(100), None, 3), min(100));
        assert_eq!(lane_timeout(None, Some(2), 45), Duration::from_secs(2));
        assert_eq!(lane_timeout(None, None, 45), min(45));
        assert_eq!(lane_timeout(None, None, 7), min(7));
    }

    /// A live observer over an empty queue, and a meter holding one haiku turn
    /// of `input` input tokens ($1 per million).
    fn observed_turn(
        input: u64,
        spent_before_usd: f64,
        lane_spent_before_usd: f64,
    ) -> (
        tokio::sync::mpsc::UnboundedReceiver<SessionEnd>,
        LiveEscalation,
        StreamMeter,
        tempfile::TempDir,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let queue = Queue::new(dir.path(), Box::new(SystemClock)).unwrap();
        let (end, rx) = tokio::sync::mpsc::unbounded_channel();
        let mut meter = StreamMeter::new(false);
        meter
            .feed(
                &json!({"type":"assistant","message":{"id":"m1","usage":{"input_tokens":input,"output_tokens":0}}})
                    .to_string(),
            )
            .unwrap();
        let live = LiveEscalation {
            queue: Arc::new(Mutex::new(queue)),
            lane: "lane-x".to_string(),
            model: "haiku".to_string(),
            spent_before_usd,
            lane_spent_before_usd,
            cost_cap_usd: 1.0,
            seen_turns: 0,
            done: false,
            end,
        };
        (rx, live, meter, dir)
    }

    #[test]
    fn the_hard_cost_stop_is_on_the_lanes_total_and_a_reassign_does_not_restart_it() {
        // A reassign restarted the queue segment ($0) but the lane has spent $0.95:
        // another $0.10 reaches the whole cap.
        let (mut rx, mut live, meter, _dir) = observed_turn(100_000, 0.0, 0.95);
        live.observe(&meter);
        assert_eq!(rx.try_recv(), Ok(SessionEnd::CostCap));
        // Once is enough: the observer is done.
        live.observe(&meter);
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn the_hard_cost_stop_fires_exactly_at_the_cap_and_not_below_it() {
        let (mut rx, mut live, meter, _dir) = observed_turn(1_000_000, 0.0, 0.0);
        live.observe(&meter);
        assert_eq!(rx.try_recv(), Ok(SessionEnd::CostCap), "$1.00 of $1.00");
        let (mut rx, mut live, meter, _dir) = observed_turn(990_000, 0.0, 0.0);
        live.observe(&meter);
        // Past the 40% share but short of the cap: the escalate-early trigger,
        // not the stop.
        assert!(
            matches!(rx.try_recv(), Ok(SessionEnd::Forced(_))),
            "$0.99 of $1.00 is not the cap"
        );
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
        let stats = pump_stream(
            input,
            &mut sink,
            &mut meter,
            1024,
            &mut |_: &StreamMeter| {},
        )
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
        let stats = pump_stream(
            input.as_bytes(),
            &mut sink,
            &mut meter,
            64,
            &mut |_: &StreamMeter| {},
        )
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
    async fn start_proxy_binds_a_private_unix_socket_and_names_the_lanes_bridge_port() {
        let tmp = tempfile::tempdir().unwrap();
        let layout = layout_in(tmp.path());
        fs::create_dir_all(&layout.clone).unwrap();

        let proxy = start_proxy(&layout, "t-run", "sk-unit-real".into())
            .await
            .unwrap();
        let socket = tmp.path().join("lane/proxy.sock");
        // The stable hash of the id, never the OS's choice.
        assert_eq!(proxy.bridge_port, 51_003);
        assert_eq!(proxy.base_url, "http://127.0.0.1:51003");
        assert_eq!(proxy.socket, socket);
        assert_eq!(
            proxy.network,
            NetworkMode::Proxy {
                port: 51_003,
                socket: socket.clone()
            }
        );
        // The proxy is a Unix socket on every OS, mode 0600, and nothing
        // listens on the bridge port from the host's side.
        let meta = fs::metadata(&socket).unwrap();
        assert!(std::os::unix::fs::FileTypeExt::is_socket(&meta.file_type()));
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        tokio::net::UnixStream::connect(&socket)
            .await
            .expect("the proxy accepts connections on its socket");
        assert!(proxy.placeholder_key.starts_with("placeholder-"));
        assert!(!proxy.placeholder_key.contains("sk-unit-real"));
        proxy.task.abort();
    }

    #[test]
    fn the_builder_argv_is_the_bridge_wrapper_then_claude_with_every_value_a_single_argument() {
        // A prompt with spaces, quotes and a leading dash stays one argument.
        let claude = vec![
            "/bin/claude".to_string(),
            "-p".to_string(),
            "--x; rm -rf /".to_string(),
        ];
        let argv = builder_argv(
            Path::new("/opt/cowproof"),
            41_003,
            Path::new("/lanes/l1/proxy.sock"),
            &claude,
        );
        assert_eq!(
            argv,
            [
                "/opt/cowproof",
                "net-bridge",
                "--port",
                "41003",
                "--target",
                "/lanes/l1/proxy.sock",
                "--",
                "/bin/claude",
                "-p",
                "--x; rm -rf /",
            ]
        );
    }

    fn reasons_of(e: &Evidence) -> (Outcome, Vec<String>) {
        let v = judge(e);
        (v.outcome, v.reasons)
    }

    #[test]
    fn judge_proves_only_when_nothing_is_wrong() {
        assert_eq!(reasons_of(&Evidence::default()), (Outcome::Proved, vec![]));
        assert_eq!(Outcome::Proved.exit_code(), 0);
    }

    #[test]
    fn judge_a_packet_with_no_checks_is_incomplete_never_proved() {
        let e = Evidence {
            no_checks_declared: true,
            ..Evidence::default()
        };
        let (outcome, reasons) = reasons_of(&e);
        assert_eq!(outcome, Outcome::Incomplete);
        assert_eq!(
            reasons,
            vec!["the packet declares no checks, so nothing was verified".to_string()]
        );
    }

    #[test]
    fn judge_an_unrun_check_is_incomplete_and_named() {
        let e = Evidence {
            unrun: vec!["lint".into(), "unit".into()],
            ..Evidence::default()
        };
        let (outcome, reasons) = reasons_of(&e);
        assert_eq!(outcome, Outcome::Incomplete);
        assert_eq!(outcome.exit_code(), 3);
        assert_eq!(reasons.len(), 2, "{reasons:?}");
        assert!(reasons[0].contains("\"lint\"") && reasons[1].contains("\"unit\""));
    }

    #[test]
    fn judge_every_refuting_reason_is_named_and_unrun_checks_stay_listed() {
        let e = Evidence {
            unrun: vec!["late".into()],
            failed_checks: vec!["unit".into()],
            diverged: vec![Divergence {
                id: "marker".into(),
                recorded_passed: true,
                verify_exit: 1,
            }],
            failed_gates: vec![GateFailure {
                name: "ownership".into(),
                evidence: vec!["Files outside owns globs: x.txt".into()],
            }],
            infrastructure: vec![],
            no_checks_declared: false,
            heldout_failed: vec!["hidden-edge".into()],
        };
        let (outcome, reasons) = reasons_of(&e);
        assert_eq!(outcome, Outcome::Refuted);
        assert_eq!(outcome.exit_code(), 2);
        assert_eq!(reasons.len(), 5, "{reasons:?}");
        assert!(reasons[0].contains("\"unit\" failed"));
        assert!(reasons[1].contains("\"marker\" diverged") && reasons[1].contains("exit 1"));
        assert!(reasons[2].contains("held-out check \"hidden-edge\" failed"));
        assert!(reasons[3].contains("gate ownership failed") && reasons[3].contains("x.txt"));
        assert!(reasons[4].contains("\"late\" was never run"));
    }

    #[test]
    fn judge_infrastructure_is_never_a_refutation() {
        let e = Evidence {
            failed_checks: vec!["unit".into()],
            failed_gates: vec![GateFailure {
                name: "ownership".into(),
                evidence: vec![],
            }],
            infrastructure: vec!["verify could not run: sandbox".into()],
            ..Evidence::default()
        };
        let (outcome, reasons) = reasons_of(&e);
        assert_eq!(outcome, Outcome::Infrastructure);
        assert_eq!(outcome.exit_code(), 4);
        assert_eq!(reasons, vec!["verify could not run: sandbox".to_string()]);
    }

    #[test]
    fn judge_a_failed_held_out_check_alone_refutes() {
        let e = Evidence {
            heldout_failed: vec!["hidden-edge".into()],
            ..Evidence::default()
        };
        let (outcome, reasons) = reasons_of(&e);
        assert_eq!(outcome, Outcome::Refuted);
        assert_eq!(reasons.len(), 1, "{reasons:?}");
        assert!(reasons[0].contains("\"hidden-edge\""));
    }

    #[test]
    fn one_line_escapes_control_characters_from_builder_text() {
        let shown = one_line("a\nb\x1b[31mred\r");
        assert_eq!(shown, "a\\nb\\u{1b}[31mred\\r");
        assert!(!shown.chars().any(char::is_control));
    }

    fn segment(status_raw: i32, lines: u64, turns: bool, elapsed_secs: u64) -> SegmentRun {
        let mut meter = StreamMeter::new(true);
        if turns {
            meter
                .feed(r#"{"type":"assistant","message":{"id":"m1","usage":{"input_tokens":1,"output_tokens":1}}}"#)
                .unwrap();
        }
        SegmentRun {
            status: ExitStatus::from_raw(status_raw),
            stats: PumpStats {
                metered: lines,
                ..PumpStats::default()
            },
            summary: meter.summary(),
            elapsed: Duration::from_secs(elapsed_secs),
            session_end: None,
            killed: false,
            estimated_cost_usd: 0.0,
        }
    }

    #[test]
    fn a_resume_is_gone_only_when_it_fails_fast_with_no_output_and_no_turn() {
        // Exit code 1 (wait status 1 << 8), nothing printed, no turn, quick.
        assert!(resume_session_gone(&segment(1 << 8, 0, false, 1)));
        // Each condition alone breaks it.
        assert!(!resume_session_gone(&segment(0, 0, false, 1)), "exit 0");
        assert!(!resume_session_gone(&segment(9, 0, false, 1)), "SIGKILL");
        assert!(
            !resume_session_gone(&segment(1 << 8, 1, false, 1)),
            "output"
        );
        assert!(!resume_session_gone(&segment(1 << 8, 0, true, 1)), "a turn");
        assert!(
            !resume_session_gone(&segment(1 << 8, 0, false, 61)),
            "slow failures are outages, not missing sessions"
        );
        let unparsed = SegmentRun {
            stats: PumpStats {
                unparsed: 1,
                ..PumpStats::default()
            },
            ..segment(1 << 8, 0, false, 1)
        };
        assert!(!resume_session_gone(&unparsed), "any stdout line is output");
    }

    #[test]
    fn the_model_ladder_climbs_by_name_and_stops_at_the_top() {
        assert_eq!(next_model("haiku"), Some("sonnet"));
        assert_eq!(next_model("claude-haiku-5-5"), Some("sonnet"));
        assert_eq!(next_model("sonnet"), Some("opus"));
        assert_eq!(next_model("Opus"), None);
        assert_eq!(next_model("gpt-6"), None, "not on the ladder");
    }

    #[test]
    fn a_named_model_must_look_like_a_model_and_never_like_a_flag() {
        for ok in ["opus", "claude-haiku-5-5", "opus[1m]", "a.b_c:d"] {
            assert!(valid_model(ok), "{ok}");
        }
        for bad in ["", "-x", "--model", "a b", "a;b", "a\nb", &"x".repeat(65)] {
            assert!(!valid_model(bad), "{bad:?}");
        }
    }

    #[test]
    fn only_session_ids_claude_accepts_are_resumable() {
        assert!(resumable("0a1b2c3d-1111-2222-3333-444455556666"));
        assert!(!resumable("short"));
        assert!(!resumable("0a1b2c3d;rm -rf"));
        assert!(!resumable(&"a".repeat(65)));
    }

    #[test]
    fn a_fence_is_longer_than_any_run_of_backticks_in_the_text() {
        assert_eq!(fenced("plain"), "```\nplain\n```");
        let fenced_text = fenced("a ``` b ````` c");
        assert!(fenced_text.starts_with("``````\n"), "{fenced_text}");
        assert!(fenced_text.ends_with("\n``````"), "{fenced_text}");
    }
}
