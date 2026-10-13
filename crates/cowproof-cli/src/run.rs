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
//! 6. stop the tools server and the proxy, capture `control/lane.patch`, ask
//!    `pk doctor --json` (outside the sandbox) whether the builder's portkit hooks
//!    fired (D5), and write `control/run.json`, whose `trace` entry holds the answer;
//! 7. prove the lane: seal a capsule from the builder's last recorded
//!    `run_check` results, replay it in the verifier, run the gates and write
//!    `control/verdict.json`. The exit code is the verdict (0 proved, or 0
//!    finished for a `--unsandboxed` lane, which is checked the same way but
//!    never proved; 2 refuted, 3 incomplete, 4 infrastructure). The gates and the verifier
//!    judge by the header of the LAST packet version delivered to the builder (the packet it
//!    started with, or the latest `redirect`), never the original's. A lane the director
//!    stopped (exit 7), or one that hit the escalation limit (exit 8), keeps its work and is
//!    not proved: `run.json` says how it ended. The two hard limits
//!    end a lane the same way, with its work kept and no proof: a wall-clock
//!    timeout (exit 5, status `timeout`) and a running cost ESTIMATE at 100% of
//!    the cap (exit 6, status `cost-cap`).
//!
//! Every child process started here gets an explicit environment
//! (`env_clear`), so the director's `ANTHROPIC_API_KEY` is never inherited:
//! the builder sees only the proxy's placeholder key.

use crate::codex::{self, Codex, CodexConfig, CodexLaunch, codex_builder_command};
use crate::openrouter::{self, Opencode, OpencodeLaunch, opencode_builder_command};
use crate::preflight::{CheckStatus, PreflightOptions, preflight};
use crate::remote::{self, BuilderSpecParts, LocalSide, RemoteHost, RemoteLane};
use crate::root::resolve_executable;
use crate::verify::{Rebuild, fetch_dependencies, verifier_runner};
use anyhow::{Context, Result, anyhow, bail};
use cowproof_core::{
    LinkedFile, PORT_CLASS, Profiles, Routing, Rung, Runtime, class_limit_at_commit, get_slot_dir,
    git_show_following_links, parse_header, port_base_for_slot, port_block_env, redact,
    valid_model_name,
};
use cowproof_prove::{
    PortCapsule,
    capsule::HELDOUT_FILE,
    capsule::{Capsule, CheckResult, EnvironmentFingerprint, TraceTotals},
    gates::{GatePacket, base_requires_heldout, run_gates},
    runner::{
        GroupEnd, GroupSet, acquire_slot_notifying, kill_process_group, run_in_group,
        terminate_process_group,
    },
    verify::{VerifyOptions, verify},
};
use cowproof_run::{
    LaneLayout, NetworkMode, RustupEnv, SandboxPolicy,
    bridge::bridge_port,
    claude::{ClaudeSpec, Credential, claude_command},
    codex::CodexPrice,
    deps::FetchOutcome,
    director::{self, VerdictEvent},
    escalate::{
        Ask, CheckRunRecord, DEFAULT_COST_FRACTION, DEFAULT_MAX_ESCALATIONS, DEFAULT_PARK_LIMIT,
        Delivery, DeliveryError, DeliveryOutcome, DeliveryResult, EscalationId, LaneState, Queue,
        SystemClock, Verdict as EscalationVerdict,
    },
    lane::{PrepareOptions, prepare_lane},
    lane_tmp,
    models::{ModelPrice, PriceRecord},
    prefix::{assemble_prompt, prefix_version},
    proxy::{MetricsLog, Provider, ProxyConfig, ProxyServer},
    render_macos_profile, sandbox_command, stall,
    stream::{MeterSummary, StreamMeter, UsageProbe},
    tools::{
        self, CheckEnd, CheckOutcome, CheckTable, LiveChecks, RunCheck, SessionEnd,
        SessionEndSignal,
    },
};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::signal::unix::{Signal, SignalKind, signal};
use tokio::sync::{Semaphore, mpsc::UnboundedReceiver, watch};
use tokio::task::JoinHandle;
use tokio::time::Instant as TokioInstant;

/// The provider the proxy forwards to.
const UPSTREAM: &str = "https://api.anthropic.com";

/// The environment variable that replaces [`UPSTREAM`], for the director only: tests point it at
/// a fake on 127.0.0.1. It is never a `cowproof.toml` setting, so repository content cannot
/// redirect the director's credential, and a replacement is recorded in `run.json`.
const ANTHROPIC_UPSTREAM_ENV: &str = "COWPROOF_ANTHROPIC_UPSTREAM";

/// The Anthropic upstream the proxy forwards to, and whether the director replaced it. A
/// replacement that is not a usable `http(s)` base URL is an error.
fn anthropic_upstream() -> Result<(String, bool)> {
    match std::env::var_os(ANTHROPIC_UPSTREAM_ENV) {
        Some(v) if !v.is_empty() => {
            let url = v
                .into_string()
                .map_err(|_| anyhow!("{ANTHROPIC_UPSTREAM_ENV} is not valid UTF-8"))?;
            // The proxy's own parser decides what a usable base URL is; a throwaway key is
            // enough for that and is dropped at once.
            ProxyConfig::new("x", url.clone())
                .with_context(|| format!("{ANTHROPIC_UPSTREAM_ENV} is not usable"))?;
            Ok((url, true))
        }
        _ => Ok((UPSTREAM.to_string(), false)),
    }
}

/// `--credential`: which credential a Claude lane spends (D2, D28 clause 6).
///
/// It is a flag of the director's command and not a rung or `cowproof.toml` setting on purpose:
/// the choice decides whose bill the lane runs on, and repository content (the base commit's
/// `cowproof.toml`, a packet header) must not be able to move a lane from an API key onto the
/// owner's subscription. It applies to the whole lane, so a `reassign` never changes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum CredentialArg {
    /// `ANTHROPIC_API_KEY`, held by the proxy: the default.
    #[default]
    #[value(name = "api-key")]
    ApiKey,
    /// The owner's Claude subscription through `CLAUDE_CODE_OAUTH_TOKEN` (`claude setup-token`),
    /// held by the proxy. Claude rungs only, local lanes only.
    Subscription,
}

impl CredentialArg {
    pub fn mode(self) -> Credential {
        match self {
            Self::ApiKey => Credential::ApiKey,
            Self::Subscription => Credential::Subscription,
        }
    }
}

/// The longest one `run_check` may run before it is killed.
pub(crate) const CHECK_TIMEOUT: Duration = Duration::from_secs(20 * 60);

/// A check that has run out of time, or whose lane is ending, gets SIGTERM to its process
/// group; the group gets this long to finish before it is sent SIGKILL.
pub(crate) const CHECK_TERM_GRACE: Duration = Duration::from_secs(5);

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
pub(crate) const TERM_GRACE: Duration = Duration::from_secs(10);

/// Once the builder's leader has exited and its group has been killed, how long
/// the stream pump may still wait for EOF. A process that escaped the group
/// could hold the pipe open forever; the pump is abandoned after this.
pub(crate) const PUMP_DRAIN: Duration = Duration::from_secs(5);

/// The most builder stderr text held while it waits for a newline. A longer
/// unterminated line is redacted and written in pieces (cut at whitespace where
/// there is any), so memory stays bounded however the builder writes.
pub(crate) const MAX_STDERR_LINE: usize = 64 * 1024;

/// The exit code when the run is interrupted by a signal (SIGINT or SIGTERM).
pub(crate) const INTERRUPTED_EXIT_CODE: i32 = 130;

/// The exit code for an infrastructure failure: a failed preflight check, or a lane that
/// could not be run (`Outcome::Infrastructure`).
const INFRASTRUCTURE_EXIT_CODE: i32 = 4;

/// The exit code when the wall-clock timeout ended the lane (`run.json` status `timeout`).
const TIMEOUT_EXIT_CODE: i32 = 5;

/// The exit code when the cost estimate reached 100% of the cap and ended the
/// lane (`run.json` status `cost-cap`).
const COST_CAP_EXIT_CODE: i32 = 6;

/// The exit code when the director ruled `stop` (`run.json` status `stopped`): the work is
/// kept and nothing is proved. Not 77, which is the forced-key refusal of `host-agent`.
const STOPPED_EXIT_CODE: i32 = 7;

/// The exit code when the lane ended at the escalation limit (`run.json` status
/// `escalation-limit`): the work is kept and nothing is proved.
const ESCALATION_LIMIT_EXIT_CODE: i32 = 8;

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

/// The real credentials the proxy holds, one per provider it serves. They live in the
/// director's process and the proxy's memory, nowhere else.
pub struct ProxyKeys {
    /// The Anthropic credential, for `claude` rungs: an API key, or with `anthropic_subscription`
    /// the OAuth token of the owner's subscription.
    pub anthropic: Option<String>,
    /// `anthropic` is a subscription OAuth token: the route sends it as `Authorization: Bearer`
    /// and takes only a bearer placeholder from the lane (D2).
    pub anthropic_subscription: bool,
    /// The Anthropic upstream; `None` is the real one.
    pub anthropic_upstream: Option<String>,
    /// The OpenRouter key and the upstream to send it to, for `openrouter` rungs.
    pub openrouter: Option<(String, String)>,
    /// The OpenAI key, the upstream to send it to and the models a request may name, for `codex`
    /// rungs: the proxy refuses a request for any other model (Codex can start a sub-agent on a
    /// model of its own choosing, and the cost cap is priced for the lane's models only).
    pub openai: Option<(String, String, Vec<String>)>,
}

impl From<String> for ProxyKeys {
    /// An Anthropic key alone, as before D28 step 2.
    fn from(anthropic: String) -> Self {
        ProxyKeys {
            anthropic: Some(anthropic),
            anthropic_subscription: false,
            anthropic_upstream: None,
            openrouter: None,
            openai: None,
        }
    }
}

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
    /// What the proxy has seen: the model calls a Codex lane is metered from, live.
    pub metrics: MetricsLog,
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
/// The real keys go only into the proxy's memory. One proxy serves every provider the lane may
/// use (D28): it routes by path and holds the placeholder all of them accept, so a `reassign`
/// across runtimes needs no new endpoint.
pub async fn start_proxy(
    layout: &LaneLayout,
    lane_id: &str,
    keys: impl Into<ProxyKeys>,
) -> Result<ProxyEndpoint> {
    let keys = keys.into();
    let mut config: Option<ProxyConfig> = None;
    if let Some(key) = keys.anthropic {
        let upstream = keys.anthropic_upstream.as_deref().unwrap_or(UPSTREAM);
        let route = if keys.anthropic_subscription {
            ProxyConfig::for_subscription(key, upstream)
        } else {
            ProxyConfig::new(key, upstream)
        };
        config = Some(route.context("configuring the egress proxy")?);
    }
    if let Some((key, upstream)) = keys.openrouter {
        config = Some(
            match config {
                Some(config) => config.with_provider(Provider::Openrouter, key, upstream),
                None => ProxyConfig::for_provider(Provider::Openrouter, key, upstream),
            }
            .context("configuring the egress proxy")?,
        );
    }
    if let Some((key, upstream, models)) = keys.openai {
        config = Some(
            match config {
                Some(config) => config.with_provider(Provider::Openai, key, upstream),
                None => ProxyConfig::for_provider(Provider::Openai, key, upstream),
            }
            .and_then(|config| config.with_models(Provider::Openai, models))
            .context("configuring the egress proxy")?,
        );
    }
    let config = config.context("the egress proxy has no provider to forward to")?;
    let placeholder_key = config.placeholder_key().to_string();
    let server = ProxyServer::new(config);
    let metrics = server.metrics();
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
        metrics,
        task,
    })
}

/// The builder's argv: the bridge wrapper first, then `claude`.
///
/// `cowproof net-bridge --port <P> --target <proxy.sock> -- <claude> <args>`
/// starts the bridge inside the sandbox, waits for it to be ready, and then
/// replaces itself with `claude`. It is argv end to end: no shell, no
/// interpolation. If the bridge cannot start, `claude` never does.
pub(crate) fn builder_argv(
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

/// A model name the director named in a ruling goes into the builder's argv,
/// so it is held to a conservative alphabet (and never starts like a flag).
pub(crate) fn valid_model(model: &str) -> bool {
    valid_model_name(model)
}

/// A rung as the carry-over text and the refusals name it: a Claude rung by its model
/// (`sonnet`, as the old ladder did), any other runtime as `runtime:model`.
fn rung_label(rung: &Rung) -> String {
    match rung.runtime {
        Runtime::Claude => rung.model.clone(),
        _ => rung.to_string(),
    }
}

/// The shape `claude --resume` accepts, the same rule `claude_command`
/// enforces. A session id outside it is treated as "no session to resume".
pub(crate) fn resumable(session_id: &str) -> bool {
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

/// Whether `session_id` has the shape the runtime's resume flag accepts: Claude's `--resume` takes
/// hex and dashes, OpenCode's `-s` takes `ses_` and letters or digits, Codex's `exec resume`
/// takes a UUID.
pub(crate) fn resumable_for(runtime: Runtime, session_id: &str) -> bool {
    match runtime {
        Runtime::Openrouter => cowproof_run::opencode::valid_session_id(session_id),
        Runtime::Codex => cowproof_run::codex::valid_session_id(session_id),
        _ => resumable(session_id),
    }
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
    /// The runtime that drives this launch: `claude`, `openrouter` (OpenCode) or `codex`.
    runtime: Runtime,
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

    /// Whether the first signal has come. The proof reads it just before it writes its
    /// verdict, so a run signalled in the proof never leaves one.
    fn is_raised(&self) -> bool {
        *self.raised.borrow()
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
pub(crate) async fn sleep_until_opt(deadline: Option<TokioInstant>) {
    match deadline {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}

/// The three files a builder reads from its lane home.
pub(crate) struct LaneFiles {
    pub settings: PathBuf,
    pub mcp_config: PathBuf,
    pub system_prompt: PathBuf,
}

/// Write `settings.json`, `mcp.json` and `system-prompt.md` into the lane home.
///
/// The lane home is writable by the builder, so a launch calls this before EVERY start (a
/// resume must never trust what the previous session left there). `mcp.json` names one
/// stdio server, `cowproof lane-tools --socket <runner_socket>`. The local launcher and the
/// remote `host-agent builder` (D27) both call this, so the files are the same bytes.
pub(crate) fn write_lane_files(
    layout: &LaneLayout,
    settings: &Value,
    cowproof_exe: &Path,
    runner_socket: &Path,
    system_append: &str,
) -> Result<LaneFiles> {
    let settings_file = layout.home.join("settings.json");
    fs::write(&settings_file, serde_json::to_vec_pretty(settings)?)?;
    let mcp_config = layout.home.join("mcp.json");
    fs::write(
        &mcp_config,
        serde_json::to_vec_pretty(&json!({
            "mcpServers": {
                "cowproof-tools": {
                    "type": "stdio",
                    "command": cowproof_exe,
                    "args": ["lane-tools", "--socket", runner_socket],
                }
            }
        }))?,
    )?;
    let system_prompt = layout.home.join("system-prompt.md");
    fs::write(&system_prompt, system_append)?;
    Ok(LaneFiles {
        settings: settings_file,
        mcp_config,
        system_prompt,
    })
}

/// Everything that decides one builder invocation.
pub(crate) struct BuilderLaunch<'a> {
    pub layout: &'a LaneLayout,
    pub files: LaneFiles,
    /// The `claude` executable, absolute.
    pub claude_bin: &'a Path,
    pub cowproof_exe: &'a Path,
    /// The portkit CLI, when the settings carry its hooks: the builder may execute it.
    pub pk_exe: Option<&'a Path>,
    /// The lane's portkit state dir, which the builder may write.
    pub portkit_dir: &'a Path,
    pub path: &'a str,
    pub base_url: &'a str,
    pub bridge_port: u16,
    pub proxy_socket: &'a Path,
    pub placeholder_key: &'a str,
    pub network: NetworkMode,
    pub max_turns: u32,
    /// The builder tools socket, canonical (`COWPROOF_RUNNER_SOCKET`).
    pub runner_socket: &'a Path,
    pub lane_id: &'a str,
    pub port_base: u16,
    pub model: &'a str,
    pub prompt: &'a str,
    pub resume: Option<&'a str>,
    /// Launch without the OS sandbox (trusted local experiments only).
    pub unsandboxed: bool,
    /// Which variable carries the placeholder: the API key's or the subscription token's.
    pub credential: Credential,
}

/// The builder's command: the bridge wrapper, then `claude`, under the builder sandbox policy
/// with exactly the lane's environment. Not yet started; the caller picks the stdio. The
/// command makes the builder the leader of its own process group, so the caller can end
/// the whole group. The one place a builder command is built, for `cowproof run` and for
/// `host-agent builder`.
pub(crate) fn builder_command(l: &BuilderLaunch<'_>) -> Result<Command> {
    let mut invocation = claude_command(&ClaudeSpec {
        lane: l.layout.clone(),
        model: l.model.to_string(),
        proxy_base_url: l.base_url.to_string(),
        placeholder_key: l.placeholder_key.to_string(),
        settings_file: l.files.settings.clone(),
        mcp_config: l.files.mcp_config.clone(),
        append_system_prompt_file: l.files.system_prompt.clone(),
        prompt: l.prompt.to_string(),
        max_turns: l.max_turns,
        resume_session_id: l.resume.map(str::to_string),
        cache_ttl: "1h".to_string(),
        path: l.path.to_string(),
        credential: l.credential,
    })?;
    invocation.env.push((
        "COWPROOF_RUNNER_SOCKET".to_string(),
        l.runner_socket.to_string_lossy().into_owned(),
    ));
    invocation.env.extend(port_block_env(l.port_base));
    invocation.env.extend(portkit_env(l.portkit_dir, l.lane_id));
    invocation.program = l.claude_bin.to_string_lossy().into_owned();
    let claude: Vec<String> = std::iter::once(invocation.program.clone())
        .chain(invocation.args.iter().cloned())
        .collect();
    let argv = builder_argv(l.cowproof_exe, l.bridge_port, l.proxy_socket, &claude);
    // The builder may execute claude, cowproof and, when there is one, `pk`
    // (the hooks call it). It may write the lane's portkit state dir.
    let mut executables = vec![l.claude_bin.to_path_buf(), l.cowproof_exe.to_path_buf()];
    executables.extend(l.pk_exe.map(Path::to_path_buf));
    let mut policy =
        SandboxPolicy::builder_with_executables(l.layout, l.network.clone(), &executables)?;
    policy.rw_paths.push(l.portkit_dir.to_path_buf());
    let mut command = if l.unsandboxed {
        // The same argv and environment (the policy's own variables included), run
        // directly: only the OS sandbox is missing.
        let mut env = invocation.env;
        policy.apply_env(&mut env);
        let mut cmd = Command::new(&argv[0]);
        cmd.args(&argv[1..])
            .env_clear()
            .envs(env)
            .current_dir(&invocation.cwd)
            .stdin(Stdio::null())
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
    command.process_group(0);
    Ok(command)
}

/// What a runtime other than Claude hands the shared launcher: its argv after the executable,
/// its complete environment, where it runs and the file it reads as stdin.
pub(crate) struct RuntimeProcess {
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    pub cwd: PathBuf,
    pub stdin_file: PathBuf,
}

/// What the shared launcher needs to know about the lane.
pub(crate) struct RuntimeSandbox<'a> {
    pub layout: &'a LaneLayout,
    pub cowproof_exe: &'a Path,
    pub bridge_port: u16,
    pub proxy_socket: &'a Path,
    pub network: NetworkMode,
    /// The builder tools socket, canonical (`COWPROOF_RUNNER_SOCKET`).
    pub runner_socket: &'a Path,
    pub port_base: u16,
    /// Directories of the clone the runtime must not see, added to the builder policy's
    /// denied paths (neither readable nor writable). Each must exist.
    pub deny: &'a [PathBuf],
    /// Launch without the OS sandbox (trusted local experiments only).
    pub unsandboxed: bool,
}

/// The command for a runtime that is not Claude (OpenCode, Codex): the bridge wrapper, then the
/// runtime's executable `bin`, under the builder sandbox policy with exactly the lane's
/// environment. Not yet started. The prompt file the runtime reads is opened here, outside the
/// sandbox, so the sandbox needs no grant for the path. The command makes the builder the
/// leader of its own process group, so the caller can end the whole group.
pub(crate) fn runtime_command(
    s: &RuntimeSandbox<'_>,
    bin: &Path,
    mut process: RuntimeProcess,
) -> Result<Command> {
    if !bin.is_absolute() {
        bail!("the runtime executable path is not absolute");
    }
    process.env.push((
        "COWPROOF_RUNNER_SOCKET".to_string(),
        s.runner_socket.to_string_lossy().into_owned(),
    ));
    process.env.extend(port_block_env(s.port_base));
    let runtime: Vec<String> = std::iter::once(bin.to_string_lossy().into_owned())
        .chain(process.args.iter().cloned())
        .collect();
    let argv = builder_argv(s.cowproof_exe, s.bridge_port, s.proxy_socket, &runtime);
    let stdin = fs::File::open(&process.stdin_file)
        .with_context(|| format!("opening {}", process.stdin_file.display()))?;

    // The builder may execute the runtime and cowproof (the bridge wrapper and the MCP server).
    let executables = vec![bin.to_path_buf(), s.cowproof_exe.to_path_buf()];
    let mut policy =
        SandboxPolicy::builder_with_executables(s.layout, s.network.clone(), &executables)?;
    policy.deny_paths.extend(s.deny.iter().cloned());
    let mut command = if s.unsandboxed {
        let mut env = process.env;
        policy.apply_env(&mut env);
        let mut cmd = Command::new(&argv[0]);
        cmd.args(&argv[1..])
            .env_clear()
            .envs(env)
            .current_dir(&process.cwd)
            .kill_on_drop(true);
        cmd
    } else {
        sandboxed_command(
            &policy,
            &s.layout.control.join("builder.sb"),
            &argv,
            process.env,
            &process.cwd,
        )?
    };
    command.stdin(Stdio::from(stdin));
    command.process_group(0);
    Ok(command)
}

/// Everything a launch needs that does not change between launches.
struct Launcher {
    layout: LaneLayout,
    /// The Claude Code executable. `None` for a lane that starts on another runtime and found
    /// no `claude`: a `reassign` onto a Claude rung is then refused.
    claude_bin: Option<PathBuf>,
    /// OpenCode and its version, when the lane may use an `openrouter` rung and it was found.
    opencode: Option<Opencode>,
    /// Codex and its version, when the lane may use a `codex` rung and it was found.
    codex: Option<Codex>,
    /// The director holds an Anthropic key / an OpenRouter key / an OpenAI key. The proxy has
    /// the values; these only say which rungs can run.
    has_anthropic_key: bool,
    has_openrouter_key: bool,
    has_openai_key: bool,
    /// The credential the Claude rungs of this lane use (`--credential`). A subscription lane
    /// holds no key for any other runtime, so it runs Claude rungs only.
    credential: Credential,
    /// The director's price of every Codex model the lane may run, by exact model id, from the
    /// base commit's `cowproof.toml`. A launch on a `codex` rung with no entry here is refused:
    /// the cost cap cannot act without a price.
    codex_prices: BTreeMap<String, CodexPrice>,
    /// What the egress proxy sees; a Codex launch is metered from it.
    metrics: MetricsLog,
    /// The price and limits of every OpenRouter model the lane may run, by exact model id,
    /// fetched from OpenRouter's model list at preflight. A launch on an `openrouter` rung with
    /// no entry here is refused: the cost cap cannot act without a price.
    prices: BTreeMap<String, PriceRecord>,
    cowproof_exe: PathBuf,
    /// The portkit CLI `pk`, the sibling of the running `cowproof` executable
    /// (G8). Without it the builder gets no hooks and the lane is `untraced` (D5).
    pk_exe: Option<PathBuf>,
    /// The lane's portkit state dir, `<lane>/portkit`: the builder may write it
    /// (hook traces land there), it is outside the clone and so outside the patch,
    /// and the runner reads it back at lane end (D5).
    portkit_dir: PathBuf,
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
    /// The checks running now: when the builder is gone they are its orphans and are ended.
    checks: Arc<GroupSet>,
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
    /// Launch the builder without the OS sandbox (trusted local experiments only).
    unsandboxed: bool,
    /// The host that runs the builder, for `--host` (D27). The launch decisions stay here; the
    /// host gets them as a spec and runs `host-agent builder`.
    remote: Option<Arc<RemoteLane>>,
}

impl Launcher {
    /// Why this lane cannot start a builder of `runtime`, or `None` when it can. The same
    /// answer for the first rung (before any lane exists, by the caller's own checks) and for a
    /// `reassign` onto another runtime, which is refused with the work kept.
    fn runtime_refusal(&self, runtime: Runtime) -> Option<String> {
        if let Some(refusal) = runtime.adapter_refusal() {
            return Some(refusal);
        }
        if self.credential == Credential::Subscription && runtime != Runtime::Claude {
            return Some(format!(
                "this lane runs on a Claude subscription (--credential subscription), which holds \
                 no key for the `{}` runtime: subscription lanes run Claude rungs only",
                runtime.name()
            ));
        }
        match runtime {
            Runtime::Claude => {
                if self.claude_bin.is_none() {
                    return Some(
                        "`claude` was not found on this machine's PATH, so the lane has no Claude builder"
                            .to_string(),
                    );
                }
                (!self.has_anthropic_key).then(|| {
                    "ANTHROPIC_API_KEY is not set, so the proxy holds no Anthropic key".to_string()
                })
            }
            Runtime::Openrouter => {
                if self.remote.is_some() {
                    return Some(
                        "a remote lane (--host) runs Claude only; the `openrouter` runtime has no remote adapter"
                            .to_string(),
                    );
                }
                if self.opencode.is_none() {
                    return Some(
                        "`opencode` was not found on this machine's PATH, so the lane has no OpenCode builder"
                            .to_string(),
                    );
                }
                (!self.has_openrouter_key).then(|| {
                    format!(
                        "{} is not set, so the proxy holds no OpenRouter key",
                        openrouter::KEY_ENV
                    )
                })
            }
            Runtime::Codex => {
                if self.remote.is_some() {
                    return Some(
                        "a remote lane (--host) runs Claude only; the `codex` runtime has no remote adapter"
                            .to_string(),
                    );
                }
                if self.codex.is_none() {
                    return Some(
                        "`codex` was not found on this machine's PATH, so the lane has no Codex builder"
                            .to_string(),
                    );
                }
                (!self.has_openai_key).then(|| {
                    format!(
                        "{} is not set, so the proxy holds no OpenAI key",
                        codex::KEY_ENV
                    )
                })
            }
        }
    }

    /// The fetched price of `model` when `runtime` is `openrouter`; `None` for any other runtime.
    fn openrouter_price(&self, runtime: Runtime, model: &str) -> Option<&PriceRecord> {
        (runtime == Runtime::Openrouter)
            .then(|| self.prices.get(model))
            .flatten()
    }

    /// The director's price of `model` when `runtime` is `codex`; `None` for any other runtime.
    fn codex_price(&self, runtime: Runtime, model: &str) -> Option<&CodexPrice> {
        (runtime == Runtime::Codex)
            .then(|| self.codex_prices.get(model))
            .flatten()
    }

    /// The price record `run.json` and the capsule hold for a launch of `model` on `runtime`:
    /// OpenRouter's, fetched at preflight, or the director's for Codex; null for Claude.
    fn price_json(&self, runtime: Runtime, model: &str) -> Option<serde_json::Value> {
        self.openrouter_price(runtime, model)
            .map(PriceRecord::to_json)
            .or_else(|| self.codex_price(runtime, model).map(CodexPrice::to_json))
    }

    /// The version string the runner read from the runtime's executable, if it read one.
    fn runtime_version(&self, runtime: Runtime) -> Option<&str> {
        match runtime {
            Runtime::Openrouter => self.opencode.as_ref().map(|o| o.version.as_str()),
            Runtime::Codex => self.codex.as_ref().map(|c| c.version.as_str()),
            Runtime::Claude => None,
        }
    }

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
        // The callers refuse a rung that cannot run before they build a launch; this is the
        // last line, so no other runtime's rung is ever started as a `claude` process.
        if let Some(refusal) = self.runtime_refusal(launch.runtime) {
            bail!("{refusal}");
        }
        let layout = &self.layout;
        let assembled = assemble_prompt(self.project_instructions.as_deref(), &launch.packet);
        // An `openrouter` launch runs at the price OpenRouter listed for this exact model.
        let price: Option<ModelPrice> = if launch.runtime == Runtime::Openrouter {
            let record = self.openrouter_price(launch.runtime, &launch.model);
            Some(
                record
                    .with_context(|| {
                        format!(
                            "no price was fetched for openrouter model {:?}, so the cost cap cannot act on it",
                            launch.model
                        )
                    })?
                    .price,
            )
        } else {
            None
        };
        // A `codex` launch runs at the director's price for this exact model, and is metered from
        // the egress proxy: the probe counts the model calls reported from this moment on, so it
        // is made before the builder exists.
        let codex_price: Option<CodexPrice> = if launch.runtime == Runtime::Codex {
            Some(
                self.codex_price(launch.runtime, &launch.model)
                    .with_context(|| {
                        format!(
                            "no price is configured for codex model {:?}, so the cost cap cannot act on it",
                            launch.model
                        )
                    })?
                    .clone(),
            )
        } else {
            None
        };
        let probe = codex_price
            .is_some()
            .then(|| UsageProbe::new(self.metrics.clone()));
        let (mut child_cmd, spec) = if let Some(price) = price {
            // OpenCode, in the same sandbox, behind the same bridge. The refusal above has
            // made sure it exists and that the lane is local.
            let opencode = self.opencode.as_ref().context("opencode was not located")?;
            let command = opencode_builder_command(&OpencodeLaunch {
                layout,
                opencode_bin: &opencode.bin,
                cowproof_exe: &self.cowproof_exe,
                path: &self.path,
                base_url: &self.base_url,
                bridge_port: self.bridge_port,
                proxy_socket: &self.proxy_socket,
                placeholder_key: &self.placeholder_key,
                network: self.network.clone(),
                max_turns: self.max_turns,
                runner_socket: &self.socket,
                port_base: self.port_base,
                model: &launch.model,
                price,
                packet: &launch.packet,
                project_instructions: self.project_instructions.as_deref(),
                prompt: &launch.prompt,
                resume: launch.resume.as_deref(),
                unsandboxed: self.unsandboxed,
            })?;
            (command, None)
        } else if launch.runtime == Runtime::Codex {
            // Codex, in the same sandbox, behind the same bridge. The refusal above has made
            // sure it exists and that the lane is local.
            let codex = self.codex.as_ref().context("codex was not located")?;
            let command = codex_builder_command(&CodexLaunch {
                layout,
                codex_bin: &codex.bin,
                cowproof_exe: &self.cowproof_exe,
                path: &self.path,
                base_url: &self.base_url,
                bridge_port: self.bridge_port,
                proxy_socket: &self.proxy_socket,
                placeholder_key: &self.placeholder_key,
                network: self.network.clone(),
                runner_socket: &self.socket,
                port_base: self.port_base,
                model: &launch.model,
                packet: &launch.packet,
                project_instructions: self.project_instructions.as_deref(),
                prompt: &launch.prompt,
                resume: launch.resume.as_deref(),
                unsandboxed: self.unsandboxed,
            })?;
            (command, None)
        } else {
            match &self.remote {
                Some(remote) => {
                    // Everything the local branch decides, as a spec for `host-agent builder`; it
                    // holds the lane's placeholder key and never the real one. No portkit hooks:
                    // `pk` is not installed on the host (`builder_settings(None)`).
                    let settings = builder_settings(None);
                    let spec = remote::builder_spec(&BuilderSpecParts {
                        model: &launch.model,
                        prompt: &launch.prompt,
                        system_prompt: &assembled.system_append,
                        settings: &settings,
                        resume_session_id: launch.resume.as_deref(),
                        placeholder_key: &self.placeholder_key,
                        bridge_port: self.bridge_port,
                        port_base: self.port_base,
                        max_turns: self.max_turns,
                        claude_bin: remote.claude(),
                    });
                    (remote.builder_command(), Some(remote::spec_line(&spec)?))
                }
                None => {
                    let files = write_lane_files(
                        layout,
                        &builder_settings(self.pk_exe.as_deref()),
                        &self.cowproof_exe,
                        &self.socket,
                        &assembled.system_append,
                    )?;
                    let command = builder_command(&BuilderLaunch {
                        layout,
                        files,
                        claude_bin: self
                            .claude_bin
                            .as_deref()
                            .context("claude was not located")?,
                        cowproof_exe: &self.cowproof_exe,
                        pk_exe: self.pk_exe.as_deref(),
                        portkit_dir: &self.portkit_dir,
                        path: &self.path,
                        base_url: &self.base_url,
                        bridge_port: self.bridge_port,
                        proxy_socket: &self.proxy_socket,
                        placeholder_key: &self.placeholder_key,
                        network: self.network.clone(),
                        max_turns: self.max_turns,
                        runner_socket: &self.socket,
                        lane_id: &self.lane_id,
                        port_base: self.port_base,
                        model: &launch.model,
                        prompt: &launch.prompt,
                        resume: launch.resume.as_deref(),
                        unsandboxed: self.unsandboxed,
                        credential: self.credential,
                    })?;
                    (command, None)
                }
            }
        };
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

        // Only the builder gets its own process group (so the runner can end it whole;
        // `builder_command` sets it) and each `run_check` command (`run_in_group`); the git
        // steps keep the runner's group, so a terminal Ctrl-C still reaches them. The check
        // groups are ended by the runner itself, from `CheckContext::groups`.
        let mut child = child_cmd
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("launching the builder")?;
        // `process_group(0)` makes the child its own leader, so its pid is the pgid.
        let pgid = child.id().context("reading the builder's process id")?;
        let _group = GroupGuard::new(pgid, self.interrupt.clone());
        // The spec line, and then the pipe stays open for the builder's whole life: end of
        // input is how `host-agent builder` learns that the director is gone (an `ssh` without
        // a pty sends no hangup). Written on its own task so a spec larger than the pipe
        // cannot stall the stream pump; the pipe is released when this launch ends.
        let _lifeline = match (spec, child.stdin.take()) {
            (Some(spec), Some(stdin)) => Some(AbortOnDrop(tokio::spawn(remote::hold_lifeline(
                stdin, spec,
            )))),
            _ => None,
        };
        let stdout = child.stdout.take().context("taking the builder's stdout")?;
        // The builder never writes to `builder.stderr` itself: the runner reads
        // this pipe and writes the file, redacted, so a raw token is never on disk.
        let stderr = child.stderr.take().context("taking the builder's stderr")?;
        let mut stderr_sink = tokio::fs::File::from_std(stderr_file);
        // Text read but not yet written (a line still waiting for its newline).
        let mut stderr_pending: Vec<u8> = Vec::new();

        let mut meter = match (price, codex_price) {
            (Some(price), _) => StreamMeter::opencode(launch.resume.is_some(), price),
            (None, Some(price)) => StreamMeter::codex(launch.resume.is_some(), price, probe),
            (None, None) => StreamMeter::new(launch.resume.is_some()),
        };
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
        let mut stderr_result: Option<io::Result<()>> = None;
        let mut status: Option<ExitStatus> = None;
        let mut session_end: Option<SessionEnd> = None;
        let mut signals_open = true;
        let mut rulings_open = true;
        let mut killed = false;
        let mut term_at: Option<TokioInstant> = None;
        let mut kill_at: Option<TokioInstant> = None;
        let mut drain_until: Option<TokioInstant> = None;
        let mut abandoned = false;
        let mut stderr_abandoned = false;
        let mut interrupted = false;
        // When the group got SIGTERM and whether SIGKILL had to follow, for the one line
        // that says how long the builder took to go (see `ended_after_term_line`).
        let mut term_sent_at: Option<Instant> = None;
        let mut kill_sent = false;

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
            let stderr_pump = pump_stderr(
                stderr,
                &mut stderr_sink,
                &mut stderr_pending,
                MAX_STDERR_LINE,
            );
            tokio::pin!(stderr_pump);
            // The events race for as long as any of them can still matter:
            // the pumps reading the builder's stdout and stderr (never awaited
            // to EOF before listening for the rest), the builder exiting, and
            // a session-end signal.
            while !(status.is_some()
                && (pump_result.is_some() || abandoned)
                && (stderr_result.is_some() || stderr_abandoned))
            {
                tokio::select! {
                    result = &mut pump, if pump_result.is_none() => {
                        pump_result = Some(result);
                    }
                    result = &mut stderr_pump, if stderr_result.is_none() => {
                        stderr_result = Some(result);
                    }
                    waited = child.wait(), if status.is_none() => {
                        status = Some(waited.context("waiting for the builder")?);
                        if let Some(sent) = term_sent_at {
                            eprintln!(
                                "[{}] {}",
                                self.lane_id,
                                ended_after_term_line(sent.elapsed(), kill_sent)
                            );
                        }
                        // The leader is gone: end whatever it left running, so
                        // no background child survives or holds the stream open.
                        kill_process_group(pgid);
                        // A `run_check` the builder had running is an orphan now (its own
                        // group, so the kill above did not reach it): end it, politely first.
                        let checks = self.checks.clone();
                        tokio::spawn(async move { checks.end_all(CHECK_TERM_GRACE).await });
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
                            term_sent_at.get_or_insert_with(Instant::now);
                            killed = true;
                            term_at = None;
                            kill_at = Some(TokioInstant::now() + TERM_GRACE);
                        }
                    }
                    _ = sleep_until_opt(term_at), if term_at.is_some() => {
                        terminate_process_group(pgid);
                        term_sent_at.get_or_insert_with(Instant::now);
                        killed = true;
                        term_at = None;
                        kill_at = Some(TokioInstant::now() + TERM_GRACE);
                    }
                    _ = sleep_until_opt(kill_at), if kill_at.is_some() => {
                        kill_process_group(pgid);
                        kill_sent = true;
                        kill_at = None;
                    }
                    _ = sleep_until_opt(drain_until), if drain_until.is_some() && pump_result.is_none() && !abandoned => {
                        abandoned = true;
                    }
                    _ = sleep_until_opt(drain_until), if drain_until.is_some() && stderr_result.is_none() && !stderr_abandoned => {
                        stderr_abandoned = true;
                    }
                    _ = sleep_until_opt(timeout_at), if timeout_at.is_some() && status.is_none() => {
                        eprintln!(
                            "[{}] wall-clock timeout: ending the builder",
                            self.lane_id
                        );
                        // The limit wins over whatever else was ending the session.
                        session_end = Some(SessionEnd::Timeout);
                        terminate_process_group(pgid);
                        term_sent_at.get_or_insert_with(Instant::now);
                        killed = true;
                        timeout_at = None;
                        term_at = None;
                        kill_at = Some(TokioInstant::now() + TERM_GRACE);
                    }
                }
            }
        }
        // A stderr pump that was abandoned (an escaped process held the pipe)
        // still holds the text it had read; write it, redacted, before anything
        // else, so an interrupted run leaves no raw token either.
        if stderr_abandoned {
            eprintln!(
                "[{}] the builder's stderr stayed open {PUMP_DRAIN:?} after it exited; not waiting for it",
                self.lane_id
            );
            let rest = redact_ready(&mut stderr_pending, MAX_STDERR_LINE, true);
            if let Err(e) = stderr_sink.write_all(&rest).await {
                eprintln!("[{}] warning: writing builder.stderr: {e}", self.lane_id);
            }
        }
        if let Err(e) = stderr_sink.flush().await {
            eprintln!("[{}] warning: writing builder.stderr: {e}", self.lane_id);
        }
        if let Some(Err(e)) = &stderr_result {
            eprintln!("[{}] warning: builder.stderr: {e}", self.lane_id);
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

/// The runner's own account of how long the builder took to go once its group had been sent
/// SIGTERM, measured from the SIGTERM to the runner reading the leader's exit status. It does
/// not include anything the runner does after that (the patch, `pk doctor`, `run.json`), which
/// is where a loaded host spends its time on a stop. A builder that ignores SIGTERM shows up
/// here as about [`TERM_GRACE`] with `, after SIGKILL`. The tests read this line.
fn ended_after_term_line(took: Duration, after_sigkill: bool) -> String {
    let suffix = if after_sigkill { ", after SIGKILL" } else { "" };
    format!(
        "the builder ended {} ms after SIGTERM{suffix}",
        took.as_millis()
    )
}

/// The runner's own account of how long ending an interrupted run took, measured from the
/// moment the runner read the signal to `run.json` being written (the builder's group ended,
/// the check groups ended, the servers stopped, the sockets removed). A run with nothing left
/// to end takes milliseconds; one that waited out a grace shows about [`CHECK_TERM_GRACE`] or
/// [`TERM_GRACE`]. It does not include the signal reaching the runner or the process exiting
/// afterwards, which are the host's. The tests read this line.
fn interrupt_recorded_line(signal_name: &str, took: Duration) -> String {
    format!(
        "the interrupted run was recorded {} ms after the {signal_name}",
        took.as_millis()
    )
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
    /// The runtime and the model of the last launch.
    runtime: Runtime,
    model: String,
    /// The newest session id the stream reported.
    session_id: Option<String>,
    end: LaneEnd,
    /// Every version of the packet the lane ran under, in order: the packet it started with
    /// (`None`), then each redirect delivered, with the escalation whose ruling brought it.
    /// Sealed in the capsule's `packets/`.
    packet_versions: Vec<(Option<String>, String)>,
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
    /// The ladder `reassign` climbs: the base commit's, read once before the lane existed.
    routing: &'a Routing,
    /// The packet profiles of the base commit: what each rung needs from the packet (D28
    /// clause 5), checked again for every rung a `reassign` lands on.
    profiles: &'a Profiles,
    launcher: &'a Launcher,
    queue: &'a Arc<Mutex<Queue>>,
    lane_id: &'a str,
    cwd: &'a Path,
    repo: &'a Path,
    plans: &'a [cowproof_plan::Plan],
    /// The checks `run_check` accepts and runs; a delivered redirect replaces them.
    declared: &'a DeclaredChecks,
}

/// The checks the builder may run through `run_check`: the ids the tools server accepts and the
/// commands the runner executes for them. They start as the packet's and are replaced when a
/// `redirect` is delivered, because the lane is proved against the last delivered packet.
struct DeclaredChecks {
    ids: LiveChecks,
    context: Arc<CheckContext>,
}

impl DeclaredChecks {
    fn replace(&self, checks: &[cowproof_core::Check]) {
        *self
            .context
            .commands
            .write()
            .unwrap_or_else(|e| e.into_inner()) = checks
            .iter()
            .map(|c| (c.id.clone(), c.command.clone()))
            .collect();
        self.ids
            .replace(checks.iter().map(|c| c.id.clone()).collect());
    }
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

    /// Read and lint a redirect packet, and check it against the profile of `rung`, the rung the
    /// lane is on when the redirect is delivered (D28 clause 5; the redirect keeps that rung).
    /// Anything wrong refuses the redirect, which ends the lane refused with its work kept and
    /// the ruling left recorded and undelivered, as a refused reassign does.
    fn load_redirect(
        &self,
        packet_path: &str,
        rung: &Rung,
    ) -> Result<(String, cowproof_core::Header), String> {
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
        let errors: Vec<String> = lint_for_run(&text, self.repo, self.plans)
            .iter()
            .filter(|f| f.severity == cowproof_lint::Severity::Error)
            .map(|f| one_line(&f.to_string()))
            .collect();
        if !errors.is_empty() {
            return Err(format!("lint errors: {}", errors.join("; ")));
        }
        // `lint_for_run` drops the unmet-requirement `profile` findings, because lint resolves
        // a rung of its own; the rung that counts here is the one the lane is on.
        if let Some(refusal) = profile_refusal(self.profiles, rung, &text) {
            return Err(format!("{rung} is the rung this lane is on, but {refusal}"));
        }
        Ok((text, header))
    }

    fn segment_record(
        index: usize,
        launch: &Launch,
        seg: &SegmentRun,
        runtime_version: Option<&str>,
        price: Option<serde_json::Value>,
        profile: serde_json::Value,
    ) -> serde_json::Value {
        json!({
            "index": index,
            "runtime": launch.runtime.name(),
            // The packet profile of the segment's rung and whether the packet met it (D28
            // clause 5): null when the rung has none.
            "profile": profile,
            // The figures the lane's cost was computed at: what OpenRouter's model list said
            // (fetched at preflight) or what the director's cowproof.toml said for Codex, with
            // where they came from (null for Claude).
            "price": price,
            // Where a Codex lane's tokens came from (`proxy` or `events`), null otherwise.
            "usageSource": seg.summary.usage_source,
            // The version the runtime's executable reported (`opencode --version`), when the
            // runner read one.
            "runtimeVersion": runtime_version,
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
            // The runtime's own figure for the segment, when it gave one for every turn
            // (`costSource` says `reported`); otherwise null and the estimate stands.
            "reportedCostUsd": match seg.summary.cost_source.as_deref() {
                Some("reported") => seg.summary.total_cost_usd,
                _ => None,
            },
            "costSource": seg.summary.cost_source,
            "durationMs": seg.elapsed.as_millis() as u64,
            "endedBy": serde_json::Value::Null,
        })
    }

    /// Run the builder, and keep running it for as long as rulings say so.
    async fn run(
        &self,
        rx: &mut UnboundedReceiver<VerdictEvent>,
        first_rung: &Rung,
        first_packet: &str,
    ) -> Result<LaneRun> {
        let mut rung = first_rung.clone();
        let mut packet = first_packet.to_string();
        let mut packet_versions: Vec<(Option<String>, String)> = vec![(None, packet.clone())];
        let mut launch = Launch {
            runtime: rung.runtime,
            model: rung.model.clone(),
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
            let mut record = Self::segment_record(
                segments.len(),
                &launch,
                &seg,
                self.launcher.runtime_version(launch.runtime),
                self.launcher.price_json(launch.runtime, &launch.model),
                profile_record(self.profiles, &rung, &launch.packet),
            );
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
                            runtime: rung.runtime,
                            model: rung.model.clone(),
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
                    match session_id
                        .clone()
                        .filter(|s| resumable_for(rung.runtime, s))
                    {
                        Some(session) => {
                            launch = Launch {
                                runtime: rung.runtime,
                                model: rung.model.clone(),
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
                                    runtime: rung.runtime,
                                    model: rung.model.clone(),
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
                    match self.load_redirect(&packet_path, &rung) {
                        Ok((text, redirected)) => {
                            self.mark_delivered(&id)?;
                            // The redirect's checks are the ones the builder may run from here
                            // on, and the ones the proof will require.
                            self.declared.replace(&redirected.checks);
                            packet = text;
                            packet_versions.push((Some(id.to_string()), packet.clone()));
                            launch = Launch {
                                runtime: rung.runtime,
                                model: rung.model.clone(),
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
                        Some(m) if valid_model(&m) => match Rung::parse(&m) {
                            Ok(to) => to,
                            Err(e) => {
                                break (
                                    LaneEnd::Refused(format!("reassign for {id} refused: {e:#}")),
                                    status,
                                );
                            }
                        },
                        Some(m) => {
                            break (
                                LaneEnd::Refused(format!(
                                    "reassign for {id} refused: {m:?} is not a model name"
                                )),
                                status,
                            );
                        }
                        None => match self.routing.next_after(&rung) {
                            Some(next) => next.clone(),
                            None => {
                                break (
                                    LaneEnd::Refused(format!(
                                        "reassign for {id} refused: no model above {:?} on the ladder; name one with --model",
                                        rung_label(&rung)
                                    )),
                                    status,
                                );
                            }
                        },
                    };
                    // A rung that cannot run (no adapter, no executable, no key, or a remote
                    // lane) ends the lane exactly as the top of the ladder does: refused, the
                    // work kept, the ruling left recorded and undelivered.
                    if let Some(refusal) = self.launcher.runtime_refusal(to.runtime) {
                        break (
                            LaneEnd::Refused(format!(
                                "reassign for {id} refused: {to} is the next rung, but {refusal}"
                            )),
                            status,
                        );
                    }
                    // The packet must meet the profile of the rung it lands on (D28 clause 5), as
                    // it had to at the start: refused the same way, the work kept and the ruling
                    // left recorded and undelivered.
                    if let Some(refusal) = profile_refusal(self.profiles, &to, &packet) {
                        break (
                            LaneEnd::Refused(format!(
                                "reassign for {id} refused: {to} is the next rung, but {refusal}"
                            )),
                            status,
                        );
                    }
                    // An `openrouter` rung the preflight did not price (a model the ruling
                    // named, off the ladder) has no price, so the cost cap could not act on it.
                    if to.runtime == Runtime::Openrouter
                        && self
                            .launcher
                            .openrouter_price(to.runtime, &to.model)
                            .is_none()
                    {
                        break (
                            LaneEnd::Refused(format!(
                                "reassign for {id} refused: {to} was not priced at preflight (OpenRouter's model list is read once, for the rungs on the ladder), so the cost cap cannot act on it; add it to the ladder"
                            )),
                            status,
                        );
                    }
                    // Likewise a `codex` rung the director set no price for.
                    if to.runtime == Runtime::Codex
                        && self.launcher.codex_price(to.runtime, &to.model).is_none()
                    {
                        break (
                            LaneEnd::Refused(format!(
                                "reassign for {id} refused: {to} has no price in the base commit's cowproof.toml ([runtimes.codex.prices]), so the cost cap cannot act on it; add it there"
                            )),
                            status,
                        );
                    }
                    let summary = {
                        let mut queue = self.lock()?;
                        let summary = queue
                            .get(&id)
                            .map(|(ask, _, _)| {
                                reassign_summary(&id, ask, &rung_label(&rung), &rung_label(&to))
                            })
                            .ok_or_else(|| anyhow!("escalation {id} is unknown"))?;
                        queue
                            .reassign(self.lane_id)
                            .map_err(|e| anyhow!("reassigning {id}: {e}"))?;
                        summary
                    };
                    self.mark_delivered(&id)?;
                    segment_cost_usd = 0.0;
                    rung = to;
                    launch = Launch {
                        runtime: rung.runtime,
                        model: rung.model.clone(),
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
            runtime: launch.runtime,
            model: launch.model,
            session_id,
            end,
            packet_versions,
        })
    }
}

/// The lint findings that can stop a run. Lint resolves the starting rung without `--model`, so
/// its `profile` findings about unmet requirements may name a rung the lane will not use (a
/// `--model` onto a rung with no profile). Those are dropped here, and `run` checks the profile
/// of the rung it really resolved itself (`profile_refusal`). A `profile` finding about a broken
/// configuration (`FindingKind::ProfileConfig`) stays: it is wrong whichever rung is used.
/// `cowproof lint` on its own is unchanged.
fn lint_for_run(
    packet_text: &str,
    repo: &Path,
    plans: &[cowproof_plan::Plan],
) -> Vec<cowproof_lint::Finding> {
    cowproof_lint::lint_packet(packet_text, repo, plans)
        .into_iter()
        .filter(|f| f.kind != cowproof_lint::FindingKind::ProfileUnmet)
        .collect()
}

/// The text of the unmet requirements of `rung`'s profile for `packet`, or `None` when the rung
/// has no profile or the packet meets it. One checker for lint, the start and a reassign:
/// `cowproof_lint::check_profile`.
fn profile_refusal(profiles: &Profiles, rung: &Rung, packet: &str) -> Option<String> {
    let header = match parse_header(packet) {
        Ok(header) => header,
        Err(e) => return Some(format!("the packet's header does not parse ({e})")),
    };
    let check = cowproof_lint::check_profile(profiles, rung, packet, &header)?;
    if check.is_met() {
        return None;
    }
    let missing: Vec<String> = check
        .unmet
        .iter()
        .map(|(requirement, need)| format!("{requirement}: {need}"))
        .collect();
    Some(format!(
        "the packet does not meet profile \"{}\" for that rung ({})",
        check.name,
        missing.join("; ")
    ))
}

/// The `profile` entry of a segment in `run.json`: the rung checked, the profile, what it
/// requires and what the packet lacked. Null when the rung has no profile.
fn profile_record(profiles: &Profiles, rung: &Rung, packet: &str) -> serde_json::Value {
    let Ok(header) = parse_header(packet) else {
        return serde_json::Value::Null;
    };
    match cowproof_lint::check_profile(profiles, rung, packet, &header) {
        None => serde_json::Value::Null,
        Some(check) => json!({
            "rung": rung.to_string(),
            "name": check.name,
            "requires": check.required.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "met": check.is_met(),
            "missing": check.unmet.iter().map(|(r, _)| r.to_string()).collect::<Vec<_>>(),
        }),
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

/// The requests the egress proxy refused or could not forward, as `path -> status -> count`.
/// A Codex that kept a network habit would show up here (the bridge is the only place it can
/// reach), so the run record is where a stray request is seen.
fn proxy_refused(metrics: &MetricsLog) -> serde_json::Value {
    let mut refused: BTreeMap<String, BTreeMap<String, u64>> = BTreeMap::new();
    for record in metrics.snapshot() {
        if !(200..300).contains(&record.status) {
            *refused
                .entry(record.path)
                .or_default()
                .entry(record.status.to_string())
                .or_default() += 1;
        }
    }
    json!(refused)
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
/// would search the builder's clone). The one exception is the director's cargo bin
/// directory (the rustup proxies, `RustupEnv::cargo_bin`), which the policies grant
/// read-only: it stays, where the director has it.
pub(crate) fn builder_path(director_path: &str, real_home: &Path) -> String {
    let rustup = RustupEnv::from_director_env(real_home);
    builder_path_keeping(director_path, real_home, rustup.cargo_bin.as_deref())
}

/// [`builder_path`] with the exempt directory given: `keep`, resolved. An entry is that
/// directory only when it resolves to exactly it, so `~/.cargo/bin/..` and a sibling of
/// it under the home are dropped like any other home entry. The exempt entry is written
/// as its resolved path, the spelling the sandbox grants.
pub(crate) fn builder_path_keeping(
    director_path: &str,
    real_home: &Path,
    keep: Option<&Path>,
) -> String {
    let kept: Vec<String> = director_path
        .split(':')
        .filter_map(|e| {
            let entry = Path::new(e);
            if e.is_empty() || !entry.is_absolute() {
                return None;
            }
            if let Some(keep) = keep
                && std::fs::canonicalize(entry).is_ok_and(|c| c == keep)
            {
                return Some(keep.to_string_lossy().into_owned());
            }
            (!entry.starts_with(real_home)).then(|| e.to_string())
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
    commands: RwLock<BTreeMap<String, String>>,
    /// One check at a time per lane (a builder can open several connections).
    slot: Semaphore,
    /// The first port of the lane's block (`COWPROOF_PORT_BASE`), the same one the builder gets.
    port_base: u16,
    /// For a remote lane the checks run on the host, in the clone the builder works in
    /// (`host-agent check`), not here.
    remote: Option<Arc<RemoteLane>>,
    /// The process groups of the checks running now (each check is its own group leader, so a
    /// terminal Ctrl-C does not reach it): the runner ends exactly these when the lane stops
    /// or the runner is signalled.
    groups: Arc<GroupSet>,
    /// How long one check may run before its group is killed: `CHECK_TIMEOUT`, or the hidden
    /// `--check-timeout-secs` (tests).
    check_timeout: Duration,
}

fn refused(output: impl Into<String>) -> CheckOutcome {
    CheckOutcome::not_run(output)
}

/// Run one declared check in a fresh `SandboxPolicy::run_check` sandbox.
/// Fails closed: if the sandbox cannot be built, nothing runs.
async fn run_declared_check(ctx: Arc<CheckContext>, id: String) -> CheckOutcome {
    let command = ctx
        .commands
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .get(&id)
        .cloned();
    let Some(command) = command else {
        return refused(format!("no command is declared for check {id:?}"));
    };
    let command = &command;
    let Ok(_slot) = ctx.slot.acquire().await else {
        return refused("the check queue is closed");
    };
    if let Some(remote) = &ctx.remote {
        return remote
            .run_check(&id, command, Some(ctx.port_base), ctx.check_timeout)
            .await;
    }
    run_check_command(
        &ctx.layout,
        &ctx.path,
        command,
        Some(ctx.port_base),
        ctx.check_timeout,
        &id,
        &ctx.groups,
    )
    .await
    .outcome
}

/// What running one check command did.
pub(crate) struct CheckRun {
    pub outcome: CheckOutcome,
    /// The command ran past its timeout and was killed.
    pub timed_out: bool,
}

/// Run `command` (`sh -c`) in the lane's clone inside a fresh `SandboxPolicy::run_check`
/// sandbox, with `timeout`, and report what it did. `label` names the check in messages.
/// Fails closed: if the sandbox cannot be built, nothing runs. The one place a declared check
/// runs, for the local `run_check` tool and for `host-agent check` (D27).
///
/// The command is the leader of its own process group, listed in `groups` while it runs
/// (`cowproof_prove::runner::run_in_group`, the code the verifier runs its checks with). On
/// the timeout the group gets SIGTERM, [`CHECK_TERM_GRACE`] and then SIGKILL, so a background
/// process the shell left behind goes with it; when the shell exits by itself its leftovers are
/// SIGKILLed. Dropping the future (the lane stopped) SIGKILLs the group. A terminal Ctrl-C no
/// longer reaches the check, so the caller ends `groups` itself when it is signalled.
pub(crate) async fn run_check_command(
    layout: &LaneLayout,
    path: &str,
    command: &str,
    port_base: Option<u16>,
    timeout: Duration,
    label: &str,
    groups: &GroupSet,
) -> CheckRun {
    let done = |outcome| CheckRun {
        outcome,
        timed_out: false,
    };
    let policy = SandboxPolicy::run_check(layout);
    let started = Instant::now();
    let argv = ["/bin/sh".to_string(), "-c".to_string(), command.to_string()];
    let mut env = vec![
        ("PATH".to_string(), path.to_string()),
        (
            "HOME".to_string(),
            layout.home.to_string_lossy().into_owned(),
        ),
    ];
    env.extend(port_base.into_iter().flat_map(port_block_env));
    let child = match sandboxed_command(
        &policy,
        &layout.control.join("run_check.sb"),
        &argv,
        env,
        &layout.clone,
    ) {
        Ok(c) => c,
        Err(e) => return done(refused(format!("sandbox unavailable: {e:#}"))),
    };
    match run_in_group(child, timeout, CHECK_TERM_GRACE, Some(groups)).await {
        Ok(ran) => match ran.end {
            GroupEnd::TimedOut => CheckRun {
                outcome: CheckOutcome {
                    exit_status: -1,
                    output: format!("check {label:?} timed out after {timeout:?}"),
                    end: CheckEnd::TimedOut,
                    duration_ms: elapsed_ms(started),
                },
                timed_out: true,
            },
            GroupEnd::Exited(status) => {
                let mut output = String::from_utf8_lossy(&ran.stdout).into_owned();
                output.push_str(&String::from_utf8_lossy(&ran.stderr));
                done(CheckOutcome {
                    exit_status: status.code().unwrap_or(-1),
                    output,
                    end: check_end_of(status),
                    duration_ms: elapsed_ms(started),
                })
            }
        },
        Err(e) => done(refused(format!("could not start check {label:?}: {e}"))),
    }
}

/// How an exited check command ended: its exit code, or the signal that ended it.
pub(crate) fn check_end_of(status: ExitStatus) -> CheckEnd {
    match (status.code(), status.signal()) {
        (Some(code), _) => CheckEnd::Exited { code },
        (None, Some(signal)) => CheckEnd::Signaled { signal },
        (None, None) => CheckEnd::NotRun,
    }
}

/// Milliseconds since `started`, saturating.
pub(crate) fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
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

/// Redact JSON string values while preserving structure and numeric values.
/// If the line is valid JSON, walk it and redact every string value.
/// If not, redact the line as plain text.
/// Numbers, booleans, keys and structure are left unchanged.
fn redact_for_stream(line: &str) -> String {
    // A line with nothing to redact is written byte for byte: re-serializing it would
    // change spacing, escapes or number formatting that the builder emitted.
    if redact(line) == line {
        return line.to_string();
    }
    match serde_json::from_str::<Value>(line) {
        Ok(mut value) => {
            redact_json_strings(&mut value);
            value.to_string()
        }
        Err(_) => {
            // Not JSON, redact as text
            redact(line)
        }
    }
}

/// Walk a JSON value and redact all string values in place.
/// Numbers, booleans, keys and structure are unchanged.
fn redact_json_strings(value: &mut Value) {
    match value {
        Value::String(s) => {
            *s = redact(s);
        }
        Value::Array(arr) => {
            for item in arr {
                redact_json_strings(item);
            }
        }
        Value::Object(obj) => {
            for (_, val) in obj.iter_mut() {
                redact_json_strings(val);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {
            // Leave unchanged
        }
    }
}

impl PumpStats {
    fn add(&mut self, other: &PumpStats) {
        self.metered += other.metered;
        self.unparsed += other.unparsed;
        self.oversized += other.oversized;
    }
}

/// Copy `reader` to `sink` (redacted for stream.jsonl) and feed each complete
/// line to the meter (original, unredacted). Memory per line is bounded by
/// `max_line`. After every line the meter accepts, `on_line` sees the meter,
/// which is where escalate-early reads the new turns and the running cost
/// estimate. The meter reads the original values so costs and turns are accurate;
/// only what is written to stream.jsonl is redacted.
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
        // A full buffer without a newline is a fragment of a longer line.
        let fragment = !buf.ends_with(b"\n") && n >= max_line;
        if fragment || mid_oversized {
            if !mid_oversized {
                stats.oversized += 1;
            }
            mid_oversized = fragment;
            // Write oversized fragments as-is (they may be part of a line with secrets)
            sink.write_all(&buf).await?;
            continue;
        }
        let text = String::from_utf8_lossy(&buf);
        let line = text.trim_end_matches(['\n', '\r']);
        if line.trim().is_empty() {
            // Empty lines are written as-is (just whitespace/newline)
            sink.write_all(&buf).await?;
            continue;
        }
        // Feed the original line to the meter first, so it sees original numbers
        match meter.feed(line) {
            Ok(_) => {
                stats.metered += 1;
                on_line(meter);
            }
            Err(_) => stats.unparsed += 1,
        }
        // Redact and write the line to the file
        let redacted = redact_for_stream(line);
        sink.write_all(redacted.as_bytes()).await?;
        // Preserve the original line ending
        if text.ends_with("\r\n") {
            sink.write_all(b"\r\n").await?;
        } else if text.ends_with('\n') {
            sink.write_all(b"\n").await?;
        }
    }
    sink.flush().await?;
    Ok(stats)
}

/// Take the text of `pending` that is ready to be written, redacted line by
/// line with `cowproof_core::redact`, and leave the rest in `pending`.
///
/// Ready is everything through the last newline. A tail with no newline waits
/// for one, until it reaches `max` bytes: then it is cut at its last whitespace
/// byte (else at a character boundary near `max`) so memory stays bounded. A
/// secret that straddles such a forced cut can escape redaction; that needs a
/// single unterminated run of 64 KiB or more. With `eof` the whole buffer is
/// ready. Invalid UTF-8 becomes U+FFFD.
pub(crate) fn redact_ready(pending: &mut Vec<u8>, max: usize, eof: bool) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut cut = if eof {
            pending.len()
        } else {
            pending
                .iter()
                .rposition(|&b| b == b'\n')
                .map_or(0, |i| i + 1)
        };
        if !eof && pending.len() - cut >= max {
            let tail = &pending[cut..];
            let at = tail
                .iter()
                .rposition(|b| b.is_ascii_whitespace())
                .map(|i| i + 1)
                .unwrap_or_else(|| {
                    let mut c = max;
                    while c > 0 && tail.get(c).is_some_and(|b| b & 0xC0 == 0x80) {
                        c -= 1;
                    }
                    if c == 0 { max } else { c }
                });
            cut += at;
        }
        if cut == 0 {
            break;
        }
        let piece: Vec<u8> = pending.drain(..cut).collect();
        for line in piece.split_inclusive(|&b| b == b'\n') {
            out.extend_from_slice(redact(&String::from_utf8_lossy(line)).as_bytes());
        }
        if eof || pending.len() < max {
            break;
        }
    }
    out
}

/// Copy the builder's stderr to `sink`, redacted, as it arrives. Text is held
/// in `pending` (owned by the caller, so an abandoned pump loses nothing) until
/// its line is complete, so a token written in two pieces is still seen whole.
/// Each batch is flushed before the next read, so the file never lags the
/// builder by more than the line in progress. A write error stops writing but
/// not reading: the builder must never block on a full pipe or get SIGPIPE.
pub(crate) async fn pump_stderr<R, W>(
    mut reader: R,
    sink: &mut W,
    pending: &mut Vec<u8>,
    max_line: usize,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut chunk = vec![0u8; 8192];
    let mut write_error: Option<io::Error> = None;
    loop {
        let n = reader.read(&mut chunk).await?;
        let eof = n == 0;
        pending.extend_from_slice(&chunk[..n]);
        let ready = redact_ready(pending, max_line, eof);
        if write_error.is_none() && !ready.is_empty() {
            let wrote = async {
                sink.write_all(&ready).await?;
                sink.flush().await
            }
            .await;
            if let Err(e) = wrote {
                write_error = Some(e);
            }
        }
        if eof {
            return write_error.map_or(Ok(()), Err);
        }
    }
}

/// `control/lane.patch`: everything the builder changed since the launch
/// baseline, including new files.
///
/// The builder owns the clone's `.git` (config, attributes), and git can run
/// programs named there (`core.fsmonitor`, clean filters), so both git
/// commands run inside the `run_check` sandbox, never in the runner's own
/// privileges.
pub(crate) async fn capture_patch(
    layout: &LaneLayout,
    launch_commit: &str,
    path: &str,
) -> Result<Vec<u8>> {
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

/// How a run was set up, for the record an interrupted run leaves.
#[derive(Clone, Copy)]
struct RunKind<'a> {
    /// Where the run was when it was signalled.
    phase: Phase,
    unsandboxed: bool,
    /// The credential mode the lane was started with, recorded as `authMode` (D28 clause 6).
    credential: Credential,
    /// The remote host that ran the builder, if any.
    host: Option<&'a str>,
}

/// Where a run was when the signal came, recorded in `run.json` as `phase`: waiting for a
/// `slot`, setting up the `remote` host, with the `builder` running (or parked), capturing the
/// patch (`capture`) or proving the lane (`proof`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Phase {
    Slot,
    Remote,
    Builder,
    Capture,
    Proof,
}

impl Phase {
    fn name(self) -> &'static str {
        match self {
            Phase::Slot => "slot",
            Phase::Remote => "remote",
            Phase::Builder => "builder",
            Phase::Capture => "capture",
            Phase::Proof => "proof",
        }
    }
}

/// What an interrupted run leaves behind, after the servers are stopped: the
/// builder's group ended for good (a no-op when the launcher already did it),
/// the three sockets removed and `run.json` saying `interrupted` and in which
/// [`Phase`]. `run.json` is written whole to a temporary file and renamed over the
/// old one, so a reader sees the finished record of a run that got that far or this
/// one, never half of either. Nothing here waits, so a second signal never has to cut
/// it short.
fn record_interrupted(
    layout: &LaneLayout,
    lane_id: &str,
    signal_name: &str,
    builder_pgid: Option<u32>,
    proxy_socket: &Path,
    started: Instant,
    kind: RunKind<'_>,
) {
    if let Some(pgid) = builder_pgid {
        kill_process_group(pgid);
    }
    let _ = fs::remove_file(&layout.sock);
    let _ = fs::remove_file(layout.control.join("director.sock"));
    let _ = fs::remove_file(proxy_socket);
    let run = json!({
        "id": lane_id,
        "host": kind.host,
        "status": "interrupted",
        "unsandboxed": kind.unsandboxed,
        "authMode": kind.credential.name(),
        "credentialKind": kind.credential.kind(),
        // Every credential stays in the director's proxy (D24): no lane holds one.
        "credentialInLane": false,
        "signal": signal_name,
        "phase": kind.phase.name(),
        "exitCode": INTERRUPTED_EXIT_CODE,
        "durationMs": started.elapsed().as_millis() as u64,
    });
    if let Err(e) = write_atomically(
        &layout.control.join("run.json"),
        &serde_json::to_vec_pretty(&run).unwrap_or_default(),
    ) {
        eprintln!("[{lane_id}] writing run.json: {e}");
    }
}

/// Write `bytes` to `path` so no reader sees a partial file: to a sibling temporary file,
/// then renamed over `path` (one directory, so one filesystem).
fn write_atomically(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut temporary = path.as_os_str().to_owned();
    temporary.push(".tmp");
    let temporary = PathBuf::from(temporary);
    fs::write(&temporary, bytes)?;
    fs::rename(&temporary, path).inspect_err(|_| {
        let _ = fs::remove_file(&temporary);
    })
}

/// What a run that stopped before the builder started leaves behind: the sockets removed and
/// `run.json` holding `fields` (status, error, exit code) beside the id, the host and the
/// duration.
fn record_stopped(
    layout: &LaneLayout,
    lane_id: &str,
    fields: Value,
    proxy_socket: &Path,
    started: Instant,
    host: &str,
) {
    let _ = fs::remove_file(&layout.sock);
    let _ = fs::remove_file(layout.control.join("director.sock"));
    let _ = fs::remove_file(proxy_socket);
    let mut run = json!({
        "id": lane_id,
        "host": host,
        "durationMs": started.elapsed().as_millis() as u64,
    });
    if let (Some(run), Some(fields)) = (run.as_object_mut(), fields.as_object()) {
        run.extend(fields.clone());
    }
    if let Err(e) = write_atomically(
        &layout.control.join("run.json"),
        &serde_json::to_vec_pretty(&run).unwrap_or_default(),
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

/// The real OAuth token of a subscription lane (`--credential subscription`), or why the lane
/// cannot start: a remote host (not built, not tested) or no token in the director's
/// environment. `token` is the value of `CLAUDE_CODE_OAUTH_TOKEN`. It never falls back to an
/// API key: a refusal here stops the run before anything is created. For an API-key lane there
/// is nothing to read and the answer is `None`; the token is never looked at.
fn subscription_token(
    credential: Credential,
    host: Option<&str>,
    token: Option<std::ffi::OsString>,
) -> std::result::Result<Option<String>, String> {
    if credential != Credential::Subscription {
        return Ok(None);
    }
    if host.is_some() {
        return Err(
            "--credential subscription cannot be combined with --host: remote lanes run on an \
             API key held by the director's proxy (D27), and a subscription token has not been \
             built or tested for a remote host; cowproof never copies or relays a login"
                .to_string(),
        );
    }
    let var = Credential::Subscription.env_var();
    match token {
        Some(v) if !v.is_empty() => v
            .into_string()
            .map(Some)
            .map_err(|_| format!("{var} is not valid UTF-8")),
        _ => Err(format!(
            "{var} is not set: --credential subscription needs the long-lived token \
             `claude setup-token` prints, exported by you in this shell (cowproof never runs or \
             scripts a login), and it does not fall back to ANTHROPIC_API_KEY"
        )),
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
    if args.check_timeout_secs == Some(0) {
        bail!("--check-timeout-secs must be at least 1");
    }
    let cwd = std::env::current_dir().context("reading the current directory")?;
    // The credential mode (`--credential`, D2): a subscription lane that cannot run is refused
    // here, before anything else is read or created, and never falls back to an API key.
    let credential = args.credential.mode();
    let subscription_token = match subscription_token(
        credential,
        args.host.as_deref(),
        std::env::var_os(Credential::Subscription.env_var()),
    ) {
        Ok(token) => token,
        Err(refusal) => {
            eprintln!("preflight failed: key: {refusal}");
            eprintln!("nothing was started");
            return Ok(INFRASTRUCTURE_EXIT_CODE);
        }
    };
    let subscription = credential == Credential::Subscription;
    if subscription && std::env::var_os("ANTHROPIC_API_KEY").is_some_and(|k| !k.is_empty()) {
        eprintln!(
            "preflight note: ANTHROPIC_API_KEY is set and not used: --credential subscription \
             sends the subscription token only"
        );
    }
    // The host entry, read and checked before anything else (`--host`, D27).
    let remote_host = match args.host.as_deref() {
        None => None,
        Some(alias) => {
            if args.unsandboxed {
                bail!(
                    "--unsandboxed cannot be combined with --host: a remote builder is always sandboxed"
                );
            }
            Some(RemoteHost::from_config(alias, &super::host_entry(alias)?)?)
        }
    };

    // 1. Lint first: errors stop the run before any lane exists.
    let packet_path = cwd.join(&args.packet);
    let packet_text = fs::read_to_string(&packet_path)
        .with_context(|| format!("reading packet {}", packet_path.display()))?;
    let repo = cwd.join(args.repo.as_deref().unwrap_or(Path::new(".")));
    let repo = repo
        .canonicalize()
        .with_context(|| format!("opening repository {}", repo.display()))?;
    let plans = cowproof_plan::load_plans(&repo, &[])?;
    let findings = lint_for_run(&packet_text, &repo, &plans);
    for finding in &findings {
        eprintln!("{finding}");
    }
    // A header rung off the base commit's ladder is a lint error too, but the run refuses it
    // itself below (exit 4, naming the rung), so that one does not stop the run here.
    if findings
        .iter()
        .any(|f| f.severity == cowproof_lint::Severity::Error && f.rule != "rung")
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
    // A remote lane's `claude` runs on the host, whose own `doctor` checks it: a missing local
    // `claude` is no reason to stop. A lane that starts on an `openrouter` rung needs OpenCode
    // and the OpenRouter key instead, one that starts on a `codex` rung needs Codex, the OpenAI
    // key and a price (all checked below, once the rung is known), not `claude` or the
    // Anthropic key; either may be missing.
    let starts_on = Routing::at_commit(&repo, "HEAD")
        .ok()
        .and_then(|r| {
            r.start(
                args.model.as_deref(),
                header.rung.as_deref(),
                &header.class_name,
            )
            .ok()
        })
        .map(|(rung, _)| rung.runtime);
    let starts_on_other_runtime = starts_on.is_some_and(|r| r != Runtime::Claude);
    let needed = |c: &crate::preflight::Check| {
        !(remote_host.is_some() && c.name == "claude")
            && !(starts_on_other_runtime && matches!(c.name, "claude" | "key"))
            // A subscription lane holds no API key; its token was checked above.
            && !(subscription && c.name == "key")
    };
    for check in &preflight_checks {
        match check.status {
            CheckStatus::Ok => {}
            CheckStatus::Warn => eprintln!("preflight warning: {}: {}", check.name, check.detail),
            CheckStatus::Fail if !needed(check) => {
                let why = if subscription && check.name == "key" {
                    "the lane uses the subscription token, not an API key"
                } else if starts_on_other_runtime {
                    "the lane starts on a rung of another runtime"
                } else {
                    "the builder runs on the host"
                };
                eprintln!(
                    "preflight note: {}: {} (not needed: {why})",
                    check.name, check.detail
                );
            }
            CheckStatus::Fail => eprintln!("preflight failed: {}: {}", check.name, check.detail),
        }
    }
    if preflight_checks
        .iter()
        .any(|c| c.status == CheckStatus::Fail && needed(c))
    {
        eprintln!("nothing was started; `cowproof doctor` shows every check");
        return Ok(INFRASTRUCTURE_EXIT_CODE);
    }

    // 2b. The builder's starting rung (D28): from the BASE commit's `cowproof.toml`, never the
    // working tree, so a lane cannot rewrite its own routing. A ladder that does not parse, a
    // rung that is not on it, and a rung whose runtime has no adapter all stop the run here,
    // before any lane, slot, socket or proxy exists.
    let routing = match Routing::at_commit(&repo, "HEAD") {
        Ok(routing) => routing,
        Err(e) => {
            eprintln!("the builder ladder cannot be read: {e:#}");
            eprintln!("nothing was started");
            return Ok(INFRASTRUCTURE_EXIT_CODE);
        }
    };
    let (first_rung, rung_source) = match routing.start(
        args.model.as_deref(),
        header.rung.as_deref(),
        &header.class_name,
    ) {
        Ok(start) => start,
        Err(e) => {
            eprintln!("no starting rung: {e:#}");
            eprintln!("nothing was started");
            return Ok(INFRASTRUCTURE_EXIT_CODE);
        }
    };
    if let Some(refusal) = first_rung.runtime.adapter_refusal() {
        eprintln!(
            "rung {first_rung} refused ({} chose it): {refusal}",
            rung_source.name()
        );
        eprintln!("nothing was started");
        return Ok(INFRASTRUCTURE_EXIT_CODE);
    }

    // A subscription lane runs Claude rungs only (D2): the proxy holds the one token and no key
    // for any other runtime.
    if subscription && first_rung.runtime != Runtime::Claude {
        eprintln!(
            "rung {first_rung} refused ({} chose it): --credential subscription runs Claude rungs \
             only, and the {} runtime needs its own API key",
            rung_source.name(),
            first_rung.runtime.name()
        );
        eprintln!("nothing was started");
        return Ok(INFRASTRUCTURE_EXIT_CODE);
    }

    // 2b'. The packet profile of the rung the lane starts on, whichever source chose it
    // (`--model` included, which `cowproof lint` cannot see): the same checker as lint, on the
    // same base commit. An unmet profile stops the run here (exit 4), before any lane exists.
    let profiles = match Profiles::at_commit(&repo, "HEAD", &routing) {
        Ok(profiles) => profiles,
        Err(e) => {
            eprintln!("the packet profiles cannot be read: {e:#}");
            eprintln!("nothing was started");
            return Ok(INFRASTRUCTURE_EXIT_CODE);
        }
    };
    if let Some(refusal) = profile_refusal(&profiles, &first_rung, &packet_text) {
        eprintln!(
            "rung {first_rung} refused ({} chose it): {refusal}",
            rung_source.name()
        );
        eprintln!("nothing was started");
        return Ok(INFRASTRUCTURE_EXIT_CODE);
    }

    // The real keys live in this process and the proxy, nowhere else. A lane that starts on a
    // Claude rung needs the Anthropic key; one that starts on an `openrouter` rung needs the
    // OpenRouter key and OpenCode (exit 4, naming whichever is missing). The other provider's
    // key is optional: it only lets a later `reassign` cross runtimes.
    let anthropic_key = if subscription {
        // The token read above, and no API key: the director's `ANTHROPIC_API_KEY` stays
        // unread, so it can reach neither the proxy nor the lane (no fallback, D2).
        subscription_token
    } else {
        match std::env::var_os("ANTHROPIC_API_KEY") {
            Some(k) if !k.is_empty() => Some(
                k.into_string()
                    .map_err(|_| anyhow!("ANTHROPIC_API_KEY is not valid UTF-8"))?,
            ),
            _ if first_rung.runtime == Runtime::Claude => {
                bail!("ANTHROPIC_API_KEY is not set; the proxy needs the real key")
            }
            _ => None,
        }
    };
    let (anthropic_upstream, anthropic_upstream_overridden) = anthropic_upstream()?;
    // A subscription lane holds no key for another runtime: the keys stay unread, so a ladder
    // with an `openrouter` or `codex` rung above the start cannot be reached by a `reassign`.
    let openrouter_key = if subscription {
        None
    } else {
        openrouter::real_key()?
    };
    let (openrouter_upstream, openrouter_upstream_overridden) = openrouter::upstream()?;
    // OpenCode, found once on the director's PATH; its version goes into the record. A lane
    // that starts on an `openrouter` rung refuses to start without it, and without the key.
    let opencode = if remote_host.is_some()
        || (first_rung.runtime != Runtime::Openrouter && openrouter_key.is_none())
    {
        None
    } else {
        match openrouter::locate(&args.opencode_bin, &director_path, &cwd).await {
            Ok(found) => Some(found),
            Err(_) if first_rung.runtime != Runtime::Openrouter => None,
            Err(why) => {
                eprintln!("preflight failed: opencode: {why}");
                None
            }
        }
    };
    if first_rung.runtime == Runtime::Openrouter {
        let mut missing = Vec::new();
        if remote_host.is_some() {
            eprintln!(
                "rung {first_rung} refused ({} chose it): a remote lane (--host) runs Claude only; the `openrouter` runtime has no remote adapter yet",
                rung_source.name()
            );
            missing.push("--host");
        } else if opencode.is_none() {
            missing.push("opencode");
        }
        if openrouter_key.is_none() {
            eprintln!("preflight failed: key: {} is not set", openrouter::KEY_ENV);
            missing.push(openrouter::KEY_ENV);
        }
        if !missing.is_empty() {
            eprintln!("nothing was started");
            return Ok(INFRASTRUCTURE_EXIT_CODE);
        }
    }
    // 2c. The price of every OpenRouter model the lane could run: the start rung and each
    // OpenRouter rung above it. One request to OpenRouter's own model list, with the real key,
    // made here by the director and not by the lane. A model that is not listed, a list that
    // cannot be read and a price that cannot be used all stop the run (exit 4): the cost cap
    // acts on this price, so there is no guessed one to fall back to. A remote lane runs Claude
    // only, so it fetches nothing; without a key no `openrouter` rung can run, so nothing either.
    let mut prices: BTreeMap<String, PriceRecord> = BTreeMap::new();
    if remote_host.is_none()
        && let Some(key) = openrouter_key.as_deref()
    {
        let models = openrouter::priced_models(&first_rung, &routing);
        if !models.is_empty() {
            let timeout = openrouter::models_timeout()?;
            match cowproof_run::models::fetch_prices(&openrouter_upstream, key, &models, timeout)
                .await
            {
                Ok(found) => prices = found,
                Err(errors) => {
                    for error in errors {
                        eprintln!("preflight failed: openrouter price: {error}");
                    }
                    eprintln!("nothing was started");
                    return Ok(INFRASTRUCTURE_EXIT_CODE);
                }
            }
        }
    }
    // 2d. Codex, the OpenAI key and the director's prices, the same way. The price of every
    // `codex` model the lane could run (the start rung and each `codex` rung above it) is read
    // from the base commit's `cowproof.toml`: a model with no price, a figure that is not
    // above zero and a configuration that asks for a subscription login (D28 clause 6) all
    // stop the run (exit 4), whatever runtime the lane starts on, because the cost cap acts
    // on this price and a `reassign` may land there. A lane that starts on a `codex` rung also
    // needs Codex itself and the OpenAI key; each is named. A lane that starts elsewhere finds
    // Codex and the key only to let a later `reassign` land on a `codex` rung.
    let openai_key = if subscription {
        None
    } else {
        codex::real_key()?
    };
    let (openai_upstream, openai_upstream_overridden) = codex::upstream()?;
    let codex_models = codex::priced_models(&first_rung, &routing);
    let starts_on_codex = first_rung.runtime == Runtime::Codex;
    let codex_bin = if remote_host.is_some() || (!starts_on_codex && openai_key.is_none()) {
        None
    } else {
        match codex::locate(&args.codex_bin, &director_path, &cwd).await {
            Ok(found) => Some(found),
            Err(_) if !starts_on_codex => None,
            Err(why) => {
                eprintln!("preflight failed: codex: {why}");
                None
            }
        }
    };
    let mut codex_prices: BTreeMap<String, CodexPrice> = BTreeMap::new();
    let mut codex_missing: Vec<&str> = Vec::new();
    if starts_on_codex {
        if remote_host.is_some() {
            eprintln!(
                "rung {first_rung} refused ({} chose it): a remote lane (--host) runs Claude only; the `codex` runtime has no remote adapter yet",
                rung_source.name()
            );
            codex_missing.push("--host");
        } else if codex_bin.is_none() {
            codex_missing.push("codex");
        }
        if openai_key.is_none() {
            eprintln!("preflight failed: key: {} is not set", codex::KEY_ENV);
            codex_missing.push(codex::KEY_ENV);
        }
    }
    if !codex_models.is_empty() && remote_host.is_none() {
        // Read even when something above is missing, so one run names every problem at once.
        let priced = CodexConfig::at_commit(&repo, "HEAD")
            .map_err(|e| vec![format!("{e:#}")])
            .and_then(|config| config.price_all(&codex_models));
        match priced {
            Ok(found) => codex_prices = found,
            Err(errors) => {
                for error in errors {
                    eprintln!("preflight failed: codex price: {error}");
                }
                codex_missing.push("a price");
            }
        }
    }
    if !codex_missing.is_empty() {
        if starts_on_codex && remote_host.is_none() {
            eprintln!(
                "rung {first_rung} refused ({} chose it): missing {}",
                rung_source.name(),
                codex_missing.join(", ")
            );
        }
        eprintln!("nothing was started");
        return Ok(INFRASTRUCTURE_EXIT_CODE);
    }
    let claude_bin: Option<PathBuf> = match &remote_host {
        Some(host) => Some(PathBuf::from(&host.claude)),
        None => match resolve_executable(&args.claude_bin, &director_path, &cwd) {
            Ok(found) => Some(found),
            Err(e) if first_rung.runtime == Runtime::Claude => return Err(e),
            Err(_) => None,
        },
    };
    // The held-out checks (D5) are found before any lane exists: a path inside the
    // repository, or one that is unreadable, stops the run here.
    let heldout = resolve_heldout(args.heldout.as_deref(), &repo, &real_home, &header.id)?;
    check_heldout_port(heldout.as_deref(), &header)?;
    // `[proof] require_heldout = true` in the base commit: a lane with no held-out checks would
    // be refuted at the gate only after the builder had run and spent its budget, so refuse
    // here, before any lane exists. The gate keeps its own check as the backstop (a base that
    // does not parse is the gate's to report, as it was).
    if heldout.is_none() && matches!(base_requires_heldout(&repo, "HEAD"), Ok(true)) {
        bail!(
            "[proof] require_heldout = true in cowproof.toml at the base commit, but lane {} has \
             no held-out checks: pass --heldout <file>, or put them in the director store \
             (~/.cowproof/heldout/<repo-id>/{}.toml); nothing was started",
            header.id,
            header.id
        );
    }
    let path = builder_path(&director_path, &real_home);
    let claude_bin = match claude_bin {
        Some(bin) if remote_host.is_none() => Some(
            bin.canonicalize()
                .context("resolving the claude executable")?,
        ),
        other => other,
    };
    let cowproof_exe = std::env::current_exe()
        .and_then(|p| p.canonicalize())
        .context("locating the cowproof executable")?;
    // The portkit companion `pk`, beside the running executable (G8).
    // A remote builder has no `pk`: its hooks are not installed on the host.
    let pk_exe = if remote_host.is_some() {
        None
    } else {
        sibling_pk(&cowproof_exe)
    };

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
    // The portkit state dir: made by the runner, so the builder's hooks can write
    // their traces without creating anything in the clone (D5).
    let portkit_dir = lane.join("portkit");
    fs::create_dir(&portkit_dir).context("creating the lane's portkit directory")?;
    eprintln!("[{}] lane {}", header.id, lane.display());
    if args.unsandboxed {
        eprintln!(
            "[{}] WARNING: --unsandboxed: the builder runs with no OS sandbox and can read and \
             write anything you can; this lane can end finished but never proved",
            header.id
        );
    }

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
                            RunKind {
                                phase: Phase::Slot,
        unsandboxed: args.unsandboxed,
                                credential,
                                host: None,
                            },
                        );
                        return Ok(INTERRUPTED_EXIT_CODE);
                    }
                };
        taken.push((slot, wait_started.elapsed()));
    }
    let (port_slot, port_wait) = taken.pop().context("the port slot")?;
    let (slot, slot_wait) = taken.pop().context("the class slot")?;
    let port_base = port_base_for_slot(port_slot.path())
        .with_context(|| format!("the slot {} has no number", port_slot.path().display()))?;

    // 4. Proxy and tools, both live before the builder starts.
    let has_anthropic_key = anthropic_key.is_some();
    let has_openrouter_key = openrouter_key.is_some();
    let has_openai_key = openai_key.is_some();
    let endpoint = start_proxy(
        &layout,
        &header.id,
        ProxyKeys {
            anthropic: anthropic_key,
            anthropic_subscription: subscription,
            anthropic_upstream: anthropic_upstream_overridden.then(|| anthropic_upstream.clone()),
            openrouter: openrouter_key.map(|key| (key, openrouter_upstream.clone())),
            // Only a ladder with a `codex` rung on or above the start can use the key at all.
            openai: openai_key
                .filter(|_| !codex_models.is_empty())
                .map(|key| (key, openai_upstream.clone(), codex_models.clone())),
        },
    )
    .await?;
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
        director::bind_std(&director_sock_path).context("binding the director control socket")?;
    // Set mode to 0600 (read-write for owner only)
    let permissions = std::fs::Permissions::from_mode(0o600);
    std::fs::set_permissions(&director_sock_path, permissions)
        .context("setting director socket permissions")?;
    // The connection to the host (nothing is started yet): the checks and the launcher both
    // need it, and every exit path from here on stops it (`Drop`).
    let remote: Option<Arc<RemoteLane>> = remote_host
        .map(|host| RemoteLane::new(host, &header.id, &layout.control))
        .transpose()?;
    let tools_queue = queue.clone();
    let table: CheckTable = checks.iter().map(|c| c.id.clone()).collect();
    let live_ids = LiveChecks::from(table);
    let check_groups = Arc::new(GroupSet::new());
    let context = Arc::new(CheckContext {
        layout: layout.clone(),
        path: path.clone(),
        commands: RwLock::new(
            checks
                .iter()
                .map(|c| (c.id.clone(), c.command.clone()))
                .collect(),
        ),
        slot: Semaphore::new(1),
        port_base,
        remote: remote.clone(),
        groups: check_groups.clone(),
        check_timeout: args
            .check_timeout_secs
            .map_or(CHECK_TIMEOUT, Duration::from_secs),
    });
    let declared = DeclaredChecks {
        ids: live_ids.clone(),
        context: context.clone(),
    };
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
                live_ids,
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
    // On a thread of its own (`director::serve_on_thread`): a ruling, a stop or a note reaches
    // the lane whatever the main runtime's workers are doing.
    let _director = director::serve_on_thread(
        director_listener,
        header.id.clone(),
        queue.clone(),
        Some(verdict_tx),
    )
    .context("serving the director control socket")?;
    // Says so on stderr when the runtime (or the host) stops running this process for seconds.
    let _stall_watch = stall::watch({
        let lane_id = header.id.clone();
        move |stall| eprintln!("[{lane_id}] {}", stall.describe())
    });

    // 4b. A remote lane (D27): the host's setup, in the order that matters. Master, doctor
    // (a failing one stops here, before any lane exists on the host), prepare, then the two
    // socket forwards, which need the lane directory prepare made. A signal during it ends
    // the run like any other: the host's lane is removed and the master stopped.
    if let Some(remote) = &remote {
        eprintln!("[{}] remote lane on {}", header.id, remote.alias());
        let side = LocalSide {
            repo: &repo,
            base_commit: &prepared.base_commit,
            base_patch: prepared.base_patch.as_deref(),
            launch_removed: &prepared.launch_removed,
            proxy_socket: &endpoint.socket,
            runner_socket: &socket,
            lanes_root: &lanes_root,
        };
        let opened = tokio::select! {
            result = remote.open(&side) => Ok(result),
            name = next_signal(&mut sigint, &mut sigterm) => Err(name),
        };
        match opened {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                eprintln!("[{}] the remote lane could not be set up: {e:#}", header.id);
                eprintln!("nothing was started");
                remote.finish().await;
                drop(_tools);
                drop(_director);
                drop(_proxy);
                record_stopped(
                    &layout,
                    &header.id,
                    json!({
                        "status": "infrastructure",
                        "error": format!("{e:#}"),
                        "exitCode": INFRASTRUCTURE_EXIT_CODE,
                    }),
                    &endpoint.socket,
                    started,
                    remote.alias(),
                );
                return Ok(INFRASTRUCTURE_EXIT_CODE);
            }
            Err(signal_name) => {
                eprintln!("[{}] {signal_name}: ending the run", header.id);
                remote.finish().await;
                drop(_tools);
                drop(_director);
                drop(_proxy);
                record_interrupted(
                    &layout,
                    &header.id,
                    signal_name,
                    None,
                    &endpoint.socket,
                    started,
                    RunKind {
                        phase: Phase::Remote,
                        unsandboxed: args.unsandboxed,
                        credential,
                        host: Some(remote.alias()),
                    },
                );
                return Ok(INTERRUPTED_EXIT_CODE);
            }
        }
    }

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
        opencode: opencode.clone(),
        codex: codex_bin.clone(),
        has_anthropic_key,
        has_openrouter_key,
        has_openai_key,
        credential,
        codex_prices,
        metrics: endpoint.metrics.clone(),
        prices,
        cowproof_exe: cowproof_exe.clone(),
        pk_exe: pk_exe.clone(),
        portkit_dir: portkit_dir.clone(),
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
        checks: check_groups.clone(),
        prefix_version: preamble_version.clone(),
        project_instructions: project_instructions_content.clone(),
        project_instructions_sha256: project_instructions_hash.clone(),
        timeout,
        active: Mutex::new(Duration::ZERO),
        port_base,
        unsandboxed: args.unsandboxed,
        remote: remote.clone(),
    };
    let drive = Drive {
        routing: &routing,
        profiles: &profiles,
        launcher: &launcher,
        queue: &queue,
        lane_id: &header.id,
        cwd: &cwd,
        repo: &repo,
        plans: &plans,
        declared: &declared,
    };

    // 5b. SIGINT and SIGTERM (caught since the slot wait). The builder is not in the
    // terminal's foreground group, so the default action would end the runner and leave
    // it running.
    // On the first signal: end the builder's group (the launcher sends SIGTERM,
    // then SIGKILL after TERM_GRACE, and gives up the launch), stop the tools,
    // director and proxy tasks, remove the three sockets, write `run.json` as
    // `interrupted`, skip the proof and exit 130. A second signal while that
    // waits skips the wait.
    let drive_run = drive.run(&mut verdict_rx, &first_rung, &packet_text);
    tokio::pin!(drive_run);
    let first = tokio::select! {
        result = &mut drive_run => Ok(result?),
        name = next_signal(&mut sigint, &mut sigterm) => Err(name),
    };
    let lane_run = match first {
        Ok(run) => run,
        Err(signal_name) => {
            eprintln!("[{}] {signal_name}: ending the run", header.id);
            let signalled = Instant::now();
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
            // A check the builder had running is in a group of its own and did not get the
            // signal: end it the polite way, or at once on a second signal.
            tokio::select! {
                _ = check_groups.end_all(CHECK_TERM_GRACE) => {}
                second = next_signal(&mut sigint, &mut sigterm) => {
                    eprintln!("[{}] {second} again: not waiting", header.id);
                    check_groups.kill_all();
                }
            }
            drop(_tools);
            drop(_director);
            drop(_proxy);
            if let Some(remote) = &remote {
                remote.finish().await;
            }
            record_interrupted(
                &layout,
                &header.id,
                signal_name,
                interrupt.builder_pgid(),
                &proxy_sock,
                started,
                RunKind {
                    phase: Phase::Builder,
                    unsandboxed: args.unsandboxed,
                    credential,
                    host: remote.as_ref().map(|r| r.alias()),
                },
            );
            eprintln!(
                "[{}] {}",
                header.id,
                interrupt_recorded_line(signal_name, signalled.elapsed())
            );
            return Ok(INTERRUPTED_EXIT_CODE);
        }
    };
    // 6. and 7., the patch and the proof, as one future that is raced against the next
    // signal. Past the builder a signal used to end the process at once, without a record;
    // now it ends what is running (the proof's check groups, TERM then KILL), writes
    // `run.json` as `interrupted` with the phase it came in, gives the slots back by
    // returning, and exits 130. The future sets `phase` as it goes and the
    // signal arm reads it, both on this one task, so a `Cell` is enough.
    let phase = std::cell::Cell::new(Phase::Capture);
    let after_builder = async {
        let status = lane_run.status;
        let stats = &lane_run.stats;
        let end = &lane_run.end;
        let status_name = end.name(status.success());

        // 6. The lane is over (finished, stopped, out of time or cost): end any check still
        // running, then stop serving, then capture.
        check_groups.end_all(CHECK_TERM_GRACE).await;
        drop(_tools);
        drop(_proxy);
        // A remote lane's patch comes from the host (`host-agent patch`, the very same
        // `capture_patch` there), and the host is done with once it has it.
        let patch = match &remote {
            Some(remote) => remote.fetch_patch().await,
            None => capture_patch(&layout, &prepared.launch_commit, &path).await,
        };
        let remote_dir = remote.as_ref().and_then(|r| r.remote_dir());
        if let Some(remote) = &remote {
            remote.finish().await;
        }
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

        // The builder is gone: ask `pk doctor` whether its hooks fired (D5). The
        // verdict is information about the lane and never changes the proof's.
        let ran_other_runtime = lane_run
            .segments
            .iter()
            .any(|s| s["runtime"].as_str() != Some(Runtime::Claude.name()));
        let trace = if remote.is_some() {
            untraced(
                "the builder ran on a remote host, which has no portkit hooks".to_string(),
                json!([]),
            )
        } else if ran_other_runtime {
            untraced(
                "a segment ran on a runtime with no portkit hooks (openrouter or codex)"
                    .to_string(),
                json!([]),
            )
        } else {
            lane_trace_verdict(
                launcher.pk_exe.as_deref(),
                &layout,
                &portkit_dir,
                &header.id,
            )
            .await
        };

        // The usage monitor's totals (D5, D23): read from the lane's trace files, only for a lane
        // `pk doctor` found traced. They describe how the lane was watched and never change the
        // verdict.
        let trace_totals: Option<TraceTotals> = if trace["traced"].as_bool() == Some(true) {
            cowproof_report::traces::lane_trace_totals(&lane)
        } else {
            None
        };

        let mut run = json!({
            "id": header.id,
            "host": remote.as_ref().map(|r| r.alias()),
            "remoteLaneDir": remote_dir,
            "bridgePort": launcher.bridge_port,
            "status": status_name,
            "unsandboxed": launcher.unsandboxed,
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
            "runtime": lane_run.runtime.name(),
            "runtimeVersion": launcher.runtime_version(lane_run.runtime),
            // The OpenCode the lane could use, and the director's override of the OpenRouter
            // upstream when there is one (null otherwise: the default host is not a setting).
            "opencodeVersion": launcher.opencode.as_ref().map(|o| o.version.as_str()),
            "openrouterUpstream": openrouter_upstream_overridden.then_some(openrouter_upstream.as_str()),
            "model": lane_run.model,
            "startRung": first_rung.to_string(),
            "rungSource": rung_source.name(),
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
            "trace": trace,
            "traceTotals": trace_totals,
        });
        // The Codex the lane could use, and the director's override of the OpenAI upstream.
        run["codexVersion"] = json!(launcher.codex.as_ref().map(|c| c.version.as_str()));
        run["openaiUpstream"] =
            json!(openai_upstream_overridden.then_some(openai_upstream.as_str()));
        // The credential mode (D28 clause 6), recorded beside `unsandboxed`: the mode, the kind of
        // credential the proxy holds for a subscription lane, and whether any credential is inside
        // the lane. None is: the proxy holds the real one (D24).
        run["authMode"] = json!(launcher.credential.name());
        run["credentialKind"] = json!(launcher.credential.kind());
        run["credentialInLane"] = json!(false);
        // The director's override of the Anthropic upstream (null otherwise).
        run["anthropicUpstream"] =
            json!(anthropic_upstream_overridden.then_some(anthropic_upstream.as_str()));
        // What the egress proxy refused or could not forward: nothing but the allowed requests
        // should reach it, so an entry here is a runtime doing something it should not.
        run["proxyRefused"] = proxy_refused(&launcher.metrics);
        write_atomically(
            &layout.control.join("run.json"),
            &serde_json::to_vec_pretty(&run)?,
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
            LaneEnd::Stopped => {
                eprintln!(
                    "the director stopped lane {}; its work is kept and nothing is proved",
                    header.id
                );
                return Ok(STOPPED_EXIT_CODE);
            }
            LaneEnd::EscalationLimit => {
                eprintln!(
                    "lane {} ended as escalation-limit; its work is kept and nothing is proved",
                    header.id
                );
                return Ok(ESCALATION_LIMIT_EXIT_CODE);
            }
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
        let runs = queue
            .lock()
            .map(|q| q.check_runs(&header.id))
            .unwrap_or_default();
        // The gates, the checks and the capsule come from the header of the last packet version
        // delivered to the builder, never from the original when a redirect replaced it.
        let proof_header = final_header(&header, &lane_run.packet_versions)?;
        phase.set(Phase::Proof);
        let verdict = prove_lane(
            &ProofInput {
                interrupt: &interrupt,
                groups: check_groups.clone(),
                layout: &layout,
                repo: &repo,
                prepared: &prepared,
                header: &proof_header,
                runtime: lane_run.runtime.name(),
                runtime_version: launcher.runtime_version(lane_run.runtime),
                openrouter_price: launcher
                    .openrouter_price(lane_run.runtime, &lane_run.model)
                    .map(PriceRecord::to_json),
                codex_price: launcher
                    .codex_price(lane_run.runtime, &lane_run.model)
                    .map(CodexPrice::to_json),
                model: &lane_run.model,
                rung_source: rung_source.name(),
                cost_usd: total_cost_usd,
                tokens: total_tokens,
                heldout_path: heldout.as_deref(),
                prefix_version: launcher.prefix_version.clone(),
                project_instructions_sha256: launcher.project_instructions_sha256.clone(),
                builder_slot: slot.path(),
                slot_dir: &slot_dir,
                class_limit,
                port_base,
                unsandboxed: launcher.unsandboxed,
                credential: launcher.credential,
                trace: trace.clone(),
                trace_totals: trace_totals.clone(),
                host: remote.as_ref().map(|r| r.alias()),
                runs: &runs,
                packet_versions: &lane_run.packet_versions,
            },
            results,
        )
        .await?;
        Ok::<i32, anyhow::Error>(verdict.outcome.exit_code())
    };
    let mut after_builder = Box::pin(after_builder);
    let finished = tokio::select! {
        result = &mut after_builder => Ok(result),
        name = next_signal(&mut sigint, &mut sigterm) => Err(name),
    };
    let signal_name = match finished {
        Ok(result) => return result,
        Err(name) => name,
    };
    eprintln!(
        "[{}] {signal_name} in the {} phase: ending the run",
        header.id,
        phase.get().name()
    );
    interrupt.raise();
    // The proof's checks (and the builder's, if the capture was cut short) are groups of
    // their own: TERM, a grace, then KILL, or KILL at once on a second signal. The
    // future keeps being polled meanwhile, so each command's own code reaps its group and
    // delists it, which is what ends the wait early. Whatever the proof starts after
    // that is dropped with the future, and dropping SIGKILLs a group.
    tokio::select! {
        biased;
        second = next_signal(&mut sigint, &mut sigterm) => {
            eprintln!("[{}] {second} again: not waiting", header.id);
            check_groups.kill_all();
        }
        _ = check_groups.end_all(CHECK_TERM_GRACE) => {}
        _ = &mut after_builder => {}
    }
    drop(after_builder);
    check_groups.kill_all();
    drop(_director);
    if let Some(remote) = &remote {
        remote.finish().await;
    }
    record_interrupted(
        &layout,
        &header.id,
        signal_name,
        None,
        &proxy_sock,
        started,
        RunKind {
            phase: phase.get(),
            unsandboxed: args.unsandboxed,
            credential,
            host: remote.as_ref().map(|r| r.alias()),
        },
    );
    Ok(INTERRUPTED_EXIT_CODE)
}

/// The header the lane is proved by: the one in the last packet version delivered to the
/// builder, which is the packet it started with when no `redirect` was delivered. A redirect is
/// the director's own packet, so its header is trusted like the original (it was linted and
/// checked against the rung's profile before delivery). The held-out checks are not in any
/// packet: they come from the director's store alone.
///
/// The class stays the original's: the lane holds a slot of the class it started with, and the
/// capsule records that one.
fn final_header(
    original: &cowproof_core::Header,
    versions: &[(Option<String>, String)],
) -> Result<cowproof_core::Header> {
    let Some((Some(_), text)) = versions.last() else {
        return Ok(original.clone());
    };
    let mut header = parse_header(text).context("the last delivered packet version")?;
    header.class_name = original.class_name.clone();
    Ok(header)
}

/// How a lane ends. The exit code of `cowproof run` is the outcome's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Proved,
    Finished,
    Refuted,
    Incomplete,
    Infrastructure,
}

impl Outcome {
    fn name(self) -> &'static str {
        match self {
            Outcome::Proved => "proved",
            Outcome::Finished => "finished",
            Outcome::Refuted => "refuted",
            Outcome::Incomplete => "incomplete",
            Outcome::Infrastructure => "infrastructure",
        }
    }

    fn exit_code(self) -> i32 {
        match self {
            Outcome::Proved => 0,
            Outcome::Finished => 0,
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
    /// What the proof wants the director to see that is neither a failure nor a pass, for
    /// instance `held-out: skipped (...)` on a port packet. Printed after the verdict line.
    notes: Vec<String>,
}

#[derive(Debug, PartialEq, Eq)]
struct Verdict {
    outcome: Outcome,
    reasons: Vec<String>,
}

/// Judge the evidence. Infrastructure wins over everything (a proof that could
/// not run proves and refutes nothing, F-1). A definite failure beats a
/// missing result, and unrun checks are still listed beside it. `Proved`
/// needs every declared check run, reproduced and passing, and no failed gate. A lane whose
/// builder ran `--unsandboxed` that would be `Proved` is `Finished` instead (exit 0, and
/// the reason names the flag); every other outcome is as for any lane.
fn judge(e: &Evidence, unsandboxed: bool) -> Verdict {
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
    } else if unsandboxed {
        reasons.push(
            "the builder ran with --unsandboxed, so the lane is finished, not proved".to_string(),
        );
        Outcome::Finished
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
    /// Raised by the first signal. The proof stops short of writing a verdict once it is.
    interrupt: &'a Interrupt,
    /// The groups of the verifier's checks are listed here while they run, so a signal can
    /// end them (the same set the builder's `run_check` commands use).
    groups: Arc<GroupSet>,
    layout: &'a LaneLayout,
    repo: &'a Path,
    prepared: &'a cowproof_run::lane::PreparedLane,
    header: &'a cowproof_core::Header,
    /// The runtime and the model of the last segment, and where the starting rung came from
    /// (`flag`, `header`, `class`, `default`): recorded in the capsule (D28).
    runtime: &'a str,
    /// The version the last segment's runtime executable reported, when it was read.
    runtime_version: Option<&'a str>,
    /// What OpenRouter's model list said the last segment's model costs (`openrouter` lanes).
    openrouter_price: Option<serde_json::Value>,
    /// What the director's cowproof.toml said the last segment's model costs (`codex` lanes).
    codex_price: Option<serde_json::Value>,
    model: &'a str,
    rung_source: &'a str,
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
    /// Whether the builder ran without the OS sandbox.
    unsandboxed: bool,
    /// The credential mode of the lane (D28 clause 6), recorded in the capsule and the verdict.
    credential: Credential,
    /// The portkit trace verdict: whether the lane was traced (D5).
    trace: Value,
    /// What the lane's trace adds up to; `Some` exactly when `trace` says traced.
    trace_totals: Option<TraceTotals>,
    /// The remote host that ran the builder (D27); the proof itself is always local.
    host: Option<&'a str>,
    /// What the builder's `run_check` calls came to, per check id: attempts and the last run.
    runs: &'a BTreeMap<String, CheckRunRecord>,
    /// Every version of the packet the lane ran under (see `LaneRun::packet_versions`).
    packet_versions: &'a [(Option<String>, String)],
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
    if checks.is_empty() {
        bail!(
            "the held-out checks file {} holds no checks",
            path.display()
        );
    }
    Ok(Some(path))
}

/// Port cases in the held-out file need a `kind: port` packet with a reference command to
/// capture them from, and a cases file beside the held-out file; anything else stops the run
/// before a lane exists. A port packet without held-out cases is fine: the visible fixtures
/// are replayed, and the gate says it had no held-out cases.
fn check_heldout_port(heldout: Option<&Path>, header: &cowproof_core::Header) -> Result<()> {
    let Some(path) = heldout else {
        return Ok(());
    };
    let file = cowproof_core::heldout::load(path)?;
    let Some(cases) = file.port_cases_path(path) else {
        return Ok(());
    };
    let reference = header
        .port
        .as_ref()
        .and_then(|port| port.reference.as_ref());
    if reference.is_none() {
        bail!(
            "the held-out file {} has port cases, so the packet must be \"kind\": \"port\" with a port.reference.cmd to capture them from",
            path.display()
        );
    }
    let meta = fs::symlink_metadata(&cases)
        .with_context(|| format!("the held-out port cases file {}", cases.display()))?;
    if !meta.is_file() {
        bail!(
            "the held-out port cases file {} is not a regular file",
            cases.display()
        );
    }
    Ok(())
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
    // A redirect can change the packet's port kind; the held-out port cases still need a
    // reference command to capture them from. (Checked before launch for the first packet.)
    if let Err(e) = check_heldout_port(input.heldout_path, header) {
        evidence.infrastructure.push(format!(
            "the held-out checks do not fit the final packet: {e:#}"
        ));
    }
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
    // A signal ended a check, so what the verifier saw is not a result. Nothing is judged,
    // and nothing is written, once the run has been told to stop: the caller records
    // `interrupted`. (Nothing between this test and the write below can wait, so the signal
    // cannot arrive in between.)
    if input.interrupt.is_raised() {
        return Err(Interrupted.into());
    }
    let verdict = judge(&evidence, input.unsandboxed);

    let control = &input.layout.control;
    let details = json!({
        "id": header.id,
        "verdict": verdict.outcome.name(),
        "unsandboxed": input.unsandboxed,
        "authMode": input.credential.name(),
        "credentialKind": input.credential.kind(),
        "credentialInLane": false,
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
    for note in &evidence.notes {
        println!("{}: {}", header.id, one_line(note));
    }
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
    // Each check file carries the builder's last `run_check` run of it (exit code or
    // signal or timeout, attempts, duration, output hash and length); replay compares
    // pass or fail only, as the design says.
    let base = &input.prepared.base_commit;
    let base_tree_hash = git_stdout(input.repo, &["rev-parse", &format!("{base}^{{tree}}")])
        .await
        .context("reading the base tree hash")?;
    let containing_refs = git_stdout(
        input.repo,
        &[
            "for-each-ref",
            "--contains",
            base,
            "--format=%(refname:short)",
            "refs/remotes",
        ],
    )
    .await
    .context("checking whether the base commit is on a remote")?;
    let base_remote = base_remote_ref(&containing_refs);
    let remote_reachable = base_remote.is_some();
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
        input.credential.name().to_string(),
    );
    capsule.credential_kind = input.credential.kind().map(str::to_string);
    // No credential is inside any lane today: the proxy holds the real one (D24).
    capsule.credential_in_lane = false;
    capsule.builder_runtime = input.runtime.to_string();
    capsule.builder_runtime_version = input.runtime_version.map(str::to_string);
    capsule.openrouter_price = input.openrouter_price.clone();
    capsule.codex_price = input.codex_price.clone();
    capsule.rung_source = Some(input.rung_source.to_string());
    capsule.estimated_cost_usd = input.cost_usd;
    capsule.estimated_tokens = input.tokens;
    capsule.unsandboxed = input.unsandboxed;
    capsule.local_replay_only = !remote_reachable;
    capsule.base_remote = base_remote;
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
    capsule.traced = input.trace["traced"].as_bool().unwrap_or(false);
    capsule.trace_totals = input.trace_totals.clone();
    capsule.host = input.host.map(str::to_string);
    if let Some(port) = &header.port {
        // The packet's own epsilon, else the project's at the base commit: a patch cannot
        // raise it.
        let epsilon = match port.parity.epsilon {
            Some(epsilon) => epsilon,
            None => {
                cowproof_core::project_epsilon_at_commit(input.repo, &input.prepared.base_commit)?
            }
        };
        capsule.port = Some(PortCapsule::from_spec(port, epsilon));
    }

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
    match fetch_dependencies(rebuild, layout, Some(input.groups.clone())).await {
        Ok(None) => {}
        Ok(Some(fetch)) => {
            capsule.dependency_cache_key = Some(fetch.key.clone());
            capsule.dependency_fetch_outcome = Some(fetch.outcome.name().to_string());
            capsule.dependency_fetch_resolve = fetch.resolve_override.clone();
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
        // The director's port cases sit beside the held-out file; they are hashed in
        // `packets/` like it and, like it, never enter the lane.
        if let Some(cases) = cowproof_core::heldout::load(heldout)?.port_cases_path(heldout) {
            fs::copy(
                &cases,
                capsule_dir.join(cowproof_core::port::HELDOUT_PORT_CASES_FILE),
            )
            .with_context(|| format!("copying the held-out port cases {}", cases.display()))?;
        }
    }
    let escalations = layout.control.join("escalations.jsonl");
    if escalations.is_file() {
        fs::copy(&escalations, capsule_dir.join("escalations.jsonl"))
            .context("copying escalations.jsonl")?;
    }
    // Every packet version the lane ran under, written before the capsule hashes `packets/`.
    cowproof_prove::capsule::write_packet_versions(&capsule_dir, input.packet_versions)
        .context("writing the packet versions")?;
    let checks_dir = capsule_dir.join("checks");
    fs::create_dir_all(&checks_dir)?;
    for (check, passed) in ran {
        let recorded = check_result(check, *passed, input.runs.get(&check.id));
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
    let mut runner = verifier_runner(layout, &verify_dir, deps_dir.as_deref())?
        .with_port_block(input.port_base)
        .with_groups(input.groups.clone());
    // A port packet's replay runs `cowproof pk port replay` in the verifier's sandbox: this
    // executable must be reachable there.
    let pk_exe = if header.port.is_some() {
        let exe = std::env::current_exe()
            .and_then(|p| p.canonicalize())
            .context("locating the cowproof executable for the port replay")?;
        runner = runner.with_executable(exe.clone());
        Some(exe)
    } else {
        None
    };
    // The verifier holds the lane's class slot (D12) by reusing the one this run holds:
    // `verify` takes none of its own.
    let options = VerifyOptions {
        slot_dir: input.slot_dir.to_path_buf(),
        slot_class: header.class_name.clone(),
        slot_limit: input.class_limit,
        held_slot_path: Some(input.builder_slot.to_path_buf()),
        // This run's own check of its lane. The replay is sandboxed as always; only the
        // refusal of an unsandboxed capsule is skipped, which `cowproof verify` keeps.
        allow_unsandboxed: input.unsandboxed,
        pk_exe,
        ..VerifyOptions::default()
    };
    match verify(&capsule_dir, input.repo, &verify_dir, &runner, options).await {
        Ok(report) => {
            // The verifier's own run of each check goes into the sealed `checks/<id>.json`
            // beside the builder's, and the capsule is sealed again over it. Where the output
            // is not byte-identical to the builder's, a note says so; it is never a failure.
            if let Err(e) = record_verifier_runs(&capsule_dir, &mut capsule, &report) {
                evidence
                    .infrastructure
                    .push(format!("recording the verifier's runs failed: {e:#}"));
            }
            evidence
                .notes
                .extend(report.checks.iter().filter_map(|m| m.output_note()));
            if let Err(e) = record_verify_results(
                &capsule_dir,
                &mut capsule,
                &report,
                packet.require_heldout,
                evidence,
            ) {
                evidence
                    .infrastructure
                    .push(format!("recording the verifier's results failed: {e:#}"));
            }
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

/// The remote-tracking ref to record as the capsule's `base_remote`, from the short names of the
/// refs that contain the base commit (one per line): the first by name, a remote's `HEAD` alias
/// (`origin/HEAD`) only when nothing else contains it. `None` when no ref does.
fn base_remote_ref(containing: &str) -> Option<String> {
    let mut names: Vec<&str> = containing
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    names.sort_unstable_by_key(|n| (n.ends_with("/HEAD") || !n.contains('/'), *n));
    names.first().map(|n| (*n).to_string())
}

/// The capsule's record of one check the builder ran: the real run when the queue kept one, else
/// (which the runner's own bookkeeping should make impossible) the pass or fail alone, marked by
/// the lack of `end` so a reader can tell it from a measured run.
fn check_result(
    check: &cowproof_core::Check,
    passed: bool,
    run: Option<&CheckRunRecord>,
) -> CheckResult {
    match run {
        Some(run) => CheckResult {
            command: check.command.clone(),
            exit_status: run.exit_status,
            attempts: run.attempts,
            duration_ms: run.duration_ms,
            output_sha256: run.output_sha256.clone(),
            output_len: Some(run.output_len),
            end: Some(run.end),
            verifier: None,
        },
        None => CheckResult {
            command: check.command.clone(),
            exit_status: if passed { 0 } else { 1 },
            attempts: 1,
            duration_ms: 0,
            output_sha256: String::new(),
            output_len: None,
            end: None,
            verifier: None,
        },
    }
}

/// Write the verifier's own run of each check into that check's `checks/<id>.json`, as its
/// `verifier` object, and seal the capsule again over the new bytes. The builder's fields are
/// read and written back unchanged. The file is one `verify` already accepted, so it is one the
/// seal listed; a check the replay did not run keeps the record it had.
fn record_verifier_runs(
    capsule_dir: &Path,
    capsule: &mut Capsule,
    report: &cowproof_prove::VerifyReport,
) -> Result<()> {
    for m in &report.checks {
        let path = capsule_dir
            .join("checks")
            .join(format!("{}.json", m.check_id));
        let text = fs::read_to_string(&path)
            .with_context(|| format!("reading checks/{}.json", m.check_id))?;
        let mut record: CheckResult = serde_json::from_str(&text)
            .with_context(|| format!("parsing checks/{}.json", m.check_id))?;
        record.verifier = Some(m.run.clone());
        fs::write(&path, serde_json::to_vec_pretty(&record)?)
            .with_context(|| format!("writing checks/{}.json", m.check_id))?;
    }
    capsule
        .write(capsule_dir)
        .context("sealing the capsule again")?;
    Ok(())
}

/// Put what `verify` found into the sealed files: `gates.json` gets each held-out check's pass
/// or fail and, for a port packet, the `port_replay` gate; the capsule's `port` entry gets the
/// replay's result. The capsule is sealed again over the new bytes. A failed `port_replay`
/// joins the failed gates, so the verdict lists it; held-out failures stay where they were
/// (`heldOutFailed`), so `verdict.json` keeps its shape.
fn record_verify_results(
    capsule_dir: &Path,
    capsule: &mut Capsule,
    report: &cowproof_prove::VerifyReport,
    require_heldout: bool,
    evidence: &mut Evidence,
) -> Result<()> {
    if report.heldout.is_empty() && report.port.is_none() {
        return Ok(());
    }
    // `gates.json` is absent when the gates could not run, which is already infrastructure.
    let path = capsule_dir.join("gates.json");
    let Ok(text) = fs::read_to_string(&path) else {
        return Ok(());
    };
    let mut gates: cowproof_prove::GateReport =
        serde_json::from_str(&text).context("reading gates.json")?;
    cowproof_prove::record_verify_results(
        &mut gates,
        &report.heldout,
        report.port.as_ref(),
        require_heldout,
    );
    fs::write(&path, serde_json::to_vec_pretty(&gates)?).context("writing gates.json")?;
    if let Some(port) = &report.port {
        if let Some(entry) = capsule.port.as_mut() {
            entry.result = Some(port.result.clone());
        }
        if !port.passed() {
            evidence.failed_gates.push(GateFailure {
                name: "port_replay".to_string(),
                evidence: port.result.failures.clone(),
            });
        }
        evidence.notes.extend(port.skipped_note());
        // `[proof] require_heldout = true` in the base: held-out cases that were skipped gave
        // no evidence, so the lane is refused, not only warned.
        if require_heldout && let Some(note) = port.skipped_note() {
            evidence.failed_gates.push(GateFailure {
                name: "held_out".to_string(),
                evidence: vec![format!(
                    "{note}; [proof] require_heldout is set, so skipped held-out port cases refuse the lane"
                )],
            });
        }
    }
    capsule
        .write(capsule_dir)
        .context("sealing the capsule again")?;
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

/// How long `<tool> --version` may take for the capsule's tool list.
const TOOL_VERSION_TIMEOUT: Duration = Duration::from_secs(30);

/// First line of `<tool> --version`, when the tool runs (in its own process group, ended whole
/// at the timeout).
async fn tool_version(tool: &str) -> Option<String> {
    let mut command = Command::new(tool);
    command.arg("--version");
    let out = cowproof_prove::runner::run_probe(command, TOOL_VERSION_TIMEOUT)
        .await
        .ok()?;
    match out.end {
        cowproof_prove::runner::GroupEnd::Exited(status) if status.success() => {}
        _ => return None,
    }
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .next()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
}

/// The portkit companion `pk` beside the running `cowproof` executable (G8): a
/// regular, executable file named `pk` with a path that is valid UTF-8, because the
/// hook command strings in the settings file carry it. `exe` is canonical, so the
/// result is absolute and never relies on the builder's `PATH`.
pub(crate) fn sibling_pk(exe: &Path) -> Option<PathBuf> {
    let pk = exe.parent()?.join("pk");
    pk.to_str()?;
    let meta = fs::metadata(&pk).ok()?;
    (meta.is_file() && meta.permissions().mode() & 0o111 != 0).then_some(pk)
}

/// `word` as one shell word: unchanged when it holds only safe characters, else
/// single-quoted. Claude Code runs a hook command through a shell, so a `pk`
/// path with a space in it must not split. `pk doctor` reads both forms.
fn shell_word(word: &str) -> String {
    let safe = |c: char| c.is_ascii_alphanumeric() || "/._-+:@%,=".contains(c);
    if !word.is_empty() && word.chars().all(safe) {
        word.to_string()
    } else {
        format!("'{}'", word.replace('\'', "'\\''"))
    }
}

/// The settings file the builder gets: its permissions, plus the portkit hooks
/// when `pk` exists (D5). Each hook command starts with the absolute path of `pk`
/// (G8). Without `pk` there is no `hooks` key at all.
fn builder_settings(pk: Option<&Path>) -> Value {
    let mut settings = json!({
        "permissions": {"allow": BUILDER_ALLOW, "deny": BUILDER_DENY}
    });
    if let Some(pk) = pk.and_then(Path::to_str) {
        let hook = |event: &str| {
            json!([{"hooks": [{
                "type": "command",
                "command": format!("{} hook {event}", shell_word(pk)),
            }]}])
        };
        settings["hooks"] = json!({
            "PostToolUse": hook("post-tool-use"),
            "UserPromptSubmit": hook("user-prompt-submit"),
            "SessionEnd": hook("session-end"),
        });
    }
    settings
}

/// The portkit variables of the builder's environment (D5). The state dir keeps
/// traces out of the clone, the session names the trace file after the lane, and
/// tracing is off in portkit unless asked for, so the hooks would record nothing.
fn portkit_env(state_dir: &Path, lane_id: &str) -> Vec<(String, String)> {
    vec![
        (
            "PORTKIT_STATE_DIR".to_string(),
            state_dir.to_string_lossy().into_owned(),
        ),
        ("PORTKIT_SESSION".to_string(), lane_id.to_string()),
        ("PK_TRACE__ENABLED".to_string(), "true".to_string()),
    ]
}

/// How long `pk doctor` may take at lane end.
const DOCTOR_TIMEOUT: Duration = Duration::from_secs(30);

/// `{traced: false, reason, checks}`.
fn untraced(reason: String, checks: Value) -> Value {
    json!({"traced": false, "reason": reason, "checks": checks})
}

/// Run `pk doctor --json --settings <the lane's settings file>` outside the
/// sandbox, with the lane's state dir, and turn it into the lane's `trace` entry:
/// `{traced, reason?, checks}` (D5).
///
/// `pk doctor` exits non-zero whenever any check misses, so the exit status says
/// nothing; the JSON it prints is the verdict. Anything that stops the verdict
/// from being read (no `pk`, a spawn error, a timeout, output that is not JSON)
/// is `traced: false` with the reason. This never fails the lane: a lane's
/// verdict does not depend on whether it was watched.
async fn lane_trace_verdict(
    pk: Option<&Path>,
    layout: &LaneLayout,
    state_dir: &Path,
    session: &str,
) -> Value {
    let Some(pk) = pk else {
        return untraced(
            "pk was not found beside the cowproof executable, so the builder had no hooks"
                .to_string(),
            json!([]),
        );
    };
    let mut cmd = Command::new(pk);
    cmd.args(["doctor", "--json", "--settings"])
        .arg(layout.home.join("settings.json"))
        // An explicit environment, like every child the runner starts. The
        // working directory is the control directory, which the builder cannot
        // write: no file of the builder's clone can steer the doctor's config.
        .env_clear()
        .env("PATH", pk.parent().unwrap_or(Path::new("/")))
        .env("HOME", &layout.home)
        .envs(portkit_env(state_dir, session))
        .current_dir(&layout.control)
        .stdin(Stdio::null())
        .kill_on_drop(true);
    let out = match tokio::time::timeout(DOCTOR_TIMEOUT, cmd.output()).await {
        Ok(Ok(out)) => out,
        Ok(Err(e)) => return untraced(format!("pk doctor could not run: {e}"), json!([])),
        Err(_) => {
            return untraced(
                format!("pk doctor did not finish in {} s", DOCTOR_TIMEOUT.as_secs()),
                json!([]),
            );
        }
    };
    let Ok(doc) = serde_json::from_slice::<Value>(&out.stdout) else {
        return untraced(
            format!(
                "pk doctor printed no JSON (exit {})",
                out.status
                    .code()
                    .map_or("signal".to_string(), |c| c.to_string())
            ),
            json!([]),
        );
    };
    let checks = doc["checks"].clone();
    let checks = if checks.is_array() { checks } else { json!([]) };
    match doc["traced"].as_bool() {
        Some(true) => json!({"traced": true, "checks": checks}),
        Some(false) => {
            // The first missing check is the cause: registered hooks come before
            // enabled tracing, which comes before the evidence.
            let reason = checks
                .as_array()
                .and_then(|all| all.iter().find(|c| c["status"] == "miss"))
                .map_or_else(
                    || "no hook call was recorded".to_string(),
                    |c| {
                        format!(
                            "{}: {}",
                            c["name"].as_str().unwrap_or("check"),
                            c["detail"].as_str().unwrap_or("missed")
                        )
                    },
                );
            untraced(reason, checks)
        }
        None => untraced("pk doctor gave no traced verdict".to_string(), checks),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn a_pk_path_is_one_shell_word_in_its_hook_command() {
        assert_eq!(shell_word("/opt/cowproof/bin/pk"), "/opt/cowproof/bin/pk");
        assert_eq!(shell_word("/my tools/pk"), "'/my tools/pk'");
        assert_eq!(shell_word("/it's/pk"), "'/it'\\''s/pk'");
        let settings = builder_settings(Some(Path::new("/my tools/pk")));
        assert_eq!(
            settings["hooks"]["SessionEnd"][0]["hooks"][0]["command"],
            "'/my tools/pk' hook session-end"
        );
    }

    #[test]
    fn no_pk_means_no_hooks_key() {
        let settings = builder_settings(None);
        assert!(settings.get("hooks").is_none(), "{settings}");
        assert!(settings["permissions"]["deny"].is_array());
    }

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

    /// The director's cargo bin directory (the rustup proxies) is the one entry under the
    /// real home that survives, exactly as resolved; every other home entry is still
    /// dropped, spelling tricks and siblings included.
    #[test]
    fn builder_path_keeps_only_the_resolved_cargo_bin_under_the_home() {
        let tmp = tempfile::Builder::new()
            .prefix("cp-bp-")
            .tempdir_in("/var/tmp")
            .unwrap();
        let home = tmp.path().canonicalize().unwrap();
        for d in [".cargo/bin", ".cargo/other", ".local/bin"] {
            fs::create_dir_all(home.join(d)).unwrap();
        }
        let bin = home.join(".cargo/bin");
        std::os::unix::fs::symlink(&bin, home.join("link-to-bin")).unwrap();
        let h = |d: &str| home.join(d).display().to_string();
        let path = format!(
            "{}:/usr/bin:{}:{}:{}/..:{}:{}:/bin",
            h(".cargo/bin"),
            h(".cargo/other"),
            h(".local/bin"),
            h(".cargo/bin"),
            h(".cargo"),
            h("link-to-bin"),
        );
        // Without the exemption every home entry goes.
        assert_eq!(
            builder_path_keeping(&path, &home, None),
            "/usr/bin:/bin".to_string()
        );
        // With it, the resolved directory stays where the director had it, and the
        // symlinked spelling of that same directory is written as the resolved path.
        assert_eq!(
            builder_path_keeping(&path, &home, Some(&bin)),
            format!("{0}:/usr/bin:{0}:/bin", bin.display())
        );
        // A resolved directory outside the home changes nothing about the home rule.
        assert_eq!(
            builder_path_keeping("/usr/bin:/opt/x/bin", &home, Some(&bin)),
            "/usr/bin:/opt/x/bin"
        );
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
    async fn pump_stream_redacts_json_string_values_but_meters_original() {
        // Input with a secret in a JSON string value and numeric usage fields
        let input = r#"{"type":"assistant","message":{"id":"m1","content":"Bearer sk-secrettoken123","usage":{"input_tokens":100,"output_tokens":50}}}"#.to_owned() + "\n";
        let mut sink: Vec<u8> = Vec::new();
        let mut meter = StreamMeter::new(false);
        pump_stream(
            input.as_bytes(),
            &mut sink,
            &mut meter,
            1024,
            &mut |_: &StreamMeter| {},
        )
        .await
        .unwrap();

        // The meter sees the original data (100 input tokens)
        let summary = meter.summary();
        assert_eq!(summary.turns.len(), 1);
        assert_eq!(summary.turns[0].input_tokens, 100);
        assert_eq!(summary.turns[0].output_tokens, 50);

        // The file contains the redacted version
        let sink_str = String::from_utf8(sink).unwrap();
        let written: Value = serde_json::from_str(sink_str.trim()).unwrap();
        let content = written
            .get("message")
            .and_then(|m| m.get("content"))
            .and_then(|c| c.as_str())
            .unwrap();
        assert_eq!(content, "Bearer [redacted]");
        // Numeric values are unchanged
        let input_tokens = written
            .get("message")
            .and_then(|m| m.get("usage"))
            .and_then(|u| u.get("input_tokens"))
            .and_then(|t| t.as_u64())
            .unwrap();
        assert_eq!(input_tokens, 100);
    }

    #[tokio::test]
    async fn pump_stream_redacts_non_json_lines_but_meters_json() {
        // Input with both JSON and plain text lines
        let input = "Bearer sk-secrettoken123\n{\"type\":\"system\",\"session_id\":\"s1\"}\n";
        let mut sink: Vec<u8> = Vec::new();
        let mut meter = StreamMeter::new(false);
        let stats = pump_stream(
            input.as_bytes(),
            &mut sink,
            &mut meter,
            1024,
            &mut |_: &StreamMeter| {},
        )
        .await
        .unwrap();

        // One line was metered (the JSON), one was not
        assert_eq!(stats.metered, 1);
        assert_eq!(stats.unparsed, 1);

        // Both lines are redacted in the output
        let sink_str = String::from_utf8(sink).unwrap();
        assert!(sink_str.contains("Bearer [redacted]\n"));
        assert!(sink_str.contains("\"session_id\":\"s1\""));
    }

    #[test]
    fn redact_for_stream_handles_json_with_nested_secrets() {
        let input = r#"{"message":{"content":"sk-secrettoken123","nested":{"value":"Bearer tok123"}},"usage":{"tokens":100}}"#;
        let output = redact_for_stream(input);
        let parsed: Value = serde_json::from_str(&output).unwrap();

        // Strings are redacted
        let content = parsed
            .get("message")
            .and_then(|m| m.get("content"))
            .and_then(|c| c.as_str())
            .unwrap();
        assert_eq!(content, "[redacted]");

        let nested = parsed
            .get("message")
            .and_then(|m| m.get("nested"))
            .and_then(|n| n.get("value"))
            .and_then(|v| v.as_str())
            .unwrap();
        assert!(nested.contains("[redacted]"));

        // Numbers are unchanged
        let tokens = parsed
            .get("usage")
            .and_then(|u| u.get("tokens"))
            .and_then(|t| t.as_u64())
            .unwrap();
        assert_eq!(tokens, 100);
    }

    #[test]
    fn redact_for_stream_handles_non_json_text() {
        let input = "error: Bearer sk-secrettoken123 failed";
        let output = redact_for_stream(input);
        assert_eq!(output, "error: Bearer [redacted] failed");
    }

    #[test]
    fn redact_json_strings_preserves_structure() {
        let mut value: Value = serde_json::json!({
            "type": "system",
            "session_id": "sk-secret123",
            "nested": {
                "array": [1, true, "Bearer token456"],
                "number": 42
            }
        });
        redact_json_strings(&mut value);

        // Session ID should be redacted
        assert_eq!(
            value.get("session_id").and_then(|s| s.as_str()).unwrap(),
            "[redacted]"
        );
        // String in array should be redacted
        let array = value
            .get("nested")
            .and_then(|n| n.get("array"))
            .and_then(|a| a.as_array())
            .unwrap();
        assert_eq!(array[2].as_str().unwrap(), "Bearer [redacted]");
        // Numbers and booleans unchanged
        assert_eq!(array[0], 1);
        assert_eq!(array[1], true);
        assert_eq!(
            value
                .get("nested")
                .and_then(|n| n.get("number"))
                .and_then(|n| n.as_u64()),
            Some(42)
        );
    }

    #[test]
    fn redact_ready_holds_an_unterminated_line_until_its_newline() {
        let mut pending = b"first sk-aaaabbbb\nsecond sk-cccc".to_vec();
        let out = redact_ready(&mut pending, 1024, false);
        assert_eq!(out, b"first [redacted]\n");
        assert_eq!(pending, b"second sk-cccc");
        pending.extend_from_slice(b"dddd\n");
        let out = redact_ready(&mut pending, 1024, false);
        assert_eq!(out, b"second [redacted]\n");
        assert!(pending.is_empty());
    }

    #[test]
    fn redact_ready_cuts_a_full_unterminated_tail_at_whitespace_and_at_eof_writes_the_rest() {
        let mut pending = b"aaaa bbbb cccc dddd".to_vec();
        let out = redact_ready(&mut pending, 12, false);
        assert_eq!(out, b"aaaa bbbb cccc ");
        assert_eq!(pending, b"dddd");
        let out = redact_ready(&mut pending, 12, true);
        assert_eq!(out, b"dddd");
        assert!(pending.is_empty());
        // No whitespace at all: cut at a character boundary, never inside one.
        let mut pending = "\u{e9}".repeat(10).into_bytes();
        let out = redact_ready(&mut pending, 7, false);
        assert!(String::from_utf8(out).is_ok());
        assert!(String::from_utf8(pending).is_ok());
    }

    #[tokio::test]
    async fn pump_stderr_redacts_a_token_split_across_reads() {
        let (mut tx, rx) = tokio::io::duplex(64);
        let writer = tokio::spawn(async move {
            tx.write_all(b"leak sk-abcd").await.unwrap();
            tx.flush().await.unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
            tx.write_all(b"efgh1234 end\nBearer tok").await.unwrap();
            tx.flush().await.unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
            tx.write_all(b"en-no-newline").await.unwrap();
        });
        let mut sink: Vec<u8> = Vec::new();
        let mut pending = Vec::new();
        pump_stderr(rx, &mut sink, &mut pending, 1024)
            .await
            .unwrap();
        writer.await.unwrap();
        // The unterminated last line is redacted whole at EOF too.
        assert_eq!(
            String::from_utf8(sink).unwrap(),
            "leak [redacted] end\nBearer [redacted]"
        );
        assert!(pending.is_empty());
    }

    #[tokio::test]
    async fn start_proxy_binds_a_private_unix_socket_and_names_the_lanes_bridge_port() {
        let tmp = tempfile::tempdir().unwrap();
        let layout = layout_in(tmp.path());
        fs::create_dir_all(&layout.clone).unwrap();

        let proxy = start_proxy(&layout, "t-run", String::from("sk-unit-real"))
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
    fn a_subscription_token_is_read_only_for_a_subscription_lane_and_never_replaced_by_a_key() {
        use std::ffi::OsString;
        let token = || Some(OsString::from("tok-unit"));
        // An API-key lane never looks at the token.
        assert_eq!(
            subscription_token(Credential::ApiKey, None, token()),
            Ok(None)
        );
        assert_eq!(subscription_token(Credential::ApiKey, None, None), Ok(None));
        assert_eq!(
            subscription_token(Credential::Subscription, None, token()),
            Ok(Some("tok-unit".to_string()))
        );
        // No token, an empty one: refused, with the variable named and no key offered instead.
        for missing in [None, Some(OsString::new())] {
            let why = subscription_token(Credential::Subscription, None, missing).unwrap_err();
            assert!(why.contains("CLAUDE_CODE_OAUTH_TOKEN"), "{why}");
            assert!(why.contains("does not fall back"), "{why}");
        }
        // A remote host is refused first, even with a token, naming the flag.
        let why = subscription_token(Credential::Subscription, Some("box"), token()).unwrap_err();
        assert!(
            why.contains("--host") && why.contains("subscription"),
            "{why}"
        );
        assert!(!why.contains("tok-unit"));
    }

    #[tokio::test]
    async fn an_openrouter_only_proxy_starts_without_an_anthropic_key_and_a_proxy_needs_a_key() {
        let tmp = tempfile::tempdir().unwrap();
        let layout = layout_in(tmp.path());
        fs::create_dir_all(&layout.clone).unwrap();
        let proxy = start_proxy(
            &layout,
            "t-run",
            ProxyKeys {
                anthropic: None,
                anthropic_subscription: false,
                anthropic_upstream: None,
                openrouter: Some(("sk-or-unit-real".into(), "http://127.0.0.1:9".into())),
                openai: None,
            },
        )
        .await
        .unwrap();
        assert_eq!(proxy.base_url, "http://127.0.0.1:51003");
        assert!(!proxy.placeholder_key.contains("sk-or-unit-real"));
        proxy.task.abort();
        // With no key at all there is nothing to forward to.
        let Err(err) = start_proxy(
            &layout,
            "t-run2",
            ProxyKeys {
                anthropic: None,
                anthropic_subscription: false,
                anthropic_upstream: None,
                openrouter: None,
                openai: None,
            },
        )
        .await
        else {
            panic!("no provider is an error");
        };
        assert!(format!("{err:#}").contains("no provider"), "{err:#}");
    }

    #[test]
    fn a_session_is_resumable_in_the_shape_its_runtime_takes() {
        assert!(resumable_for(
            Runtime::Claude,
            "0a1b2c3d-1111-2222-3333-444455556666"
        ));
        assert!(!resumable_for(
            Runtime::Claude,
            "ses_ed38dc388ffeb9FMHqRuDEw3t7"
        ));
        assert!(resumable_for(
            Runtime::Openrouter,
            "ses_ed38dc388ffeb9FMHqRuDEw3t7"
        ));
        assert!(!resumable_for(
            Runtime::Openrouter,
            "0a1b2c3d-1111-2222-3333-444455556666"
        ));
        assert!(!resumable_for(Runtime::Openrouter, "ses_;rm -rf /"));
        // Codex takes a UUID, which is also the shape Claude takes, and not OpenCode's.
        assert!(resumable_for(
            Runtime::Codex,
            "01a12d9c-b587-7d70-b3bc-ec3bd1cb4130"
        ));
        assert!(!resumable_for(
            Runtime::Codex,
            "ses_ed38dc388ffeb9FMHqRuDEw3t7"
        ));
        assert!(!resumable_for(Runtime::Codex, "0a1b2c3d-1111"));
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
        let v = judge(e, false);
        (v.outcome, v.reasons)
    }

    #[test]
    fn judge_proves_only_when_nothing_is_wrong() {
        assert_eq!(reasons_of(&Evidence::default()), (Outcome::Proved, vec![]));
        assert_eq!(Outcome::Proved.exit_code(), 0);
    }

    #[test]
    fn judge_an_unsandboxed_lane_is_finished_never_proved_and_otherwise_judged_as_usual() {
        let finished = judge(&Evidence::default(), true);
        assert_eq!(finished.outcome, Outcome::Finished);
        assert_eq!(finished.outcome.exit_code(), 0);
        assert_eq!(finished.outcome.name(), "finished");
        assert_eq!(finished.reasons.len(), 1, "{:?}", finished.reasons);
        assert!(finished.reasons[0].contains("--unsandboxed"));

        let failed = Evidence {
            failed_checks: vec!["unit".into()],
            ..Evidence::default()
        };
        assert_eq!(judge(&failed, true).outcome, Outcome::Refuted);
        let unrun = Evidence {
            unrun: vec!["unit".into()],
            ..Evidence::default()
        };
        assert_eq!(judge(&unrun, true).outcome, Outcome::Incomplete);
        let none = Evidence {
            no_checks_declared: true,
            ..Evidence::default()
        };
        assert_eq!(judge(&none, true).outcome, Outcome::Incomplete);
        let infra = Evidence {
            infrastructure: vec!["verify could not run".into()],
            ..Evidence::default()
        };
        assert_eq!(judge(&infra, true).outcome, Outcome::Infrastructure);
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
            notes: vec![],
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
        let routing = Routing::default();
        let next = |current: &str| {
            routing
                .next_after(&Rung::parse(current).unwrap())
                .map(rung_label)
        };
        assert_eq!(next("haiku").as_deref(), Some("sonnet"));
        assert_eq!(next("claude-haiku-5-5").as_deref(), Some("sonnet"));
        assert_eq!(next("sonnet").as_deref(), Some("opus"));
        assert_eq!(next("Opus"), None);
        assert_eq!(next("gpt-6"), None, "not on the ladder");
    }

    #[test]
    fn a_rung_is_named_by_its_model_on_claude_and_in_full_elsewhere() {
        assert_eq!(rung_label(&Rung::parse("claude:sonnet").unwrap()), "sonnet");
        assert_eq!(
            rung_label(&Rung::parse("codex:gpt-6-luna").unwrap()),
            "codex:gpt-6-luna"
        );
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
    #[test]
    fn a_check_ends_as_its_exit_code_or_the_signal_that_ended_it() {
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(
            check_end_of(ExitStatus::from_raw(3 << 8)),
            CheckEnd::Exited { code: 3 }
        );
        assert_eq!(
            check_end_of(ExitStatus::from_raw(0)),
            CheckEnd::Exited { code: 0 }
        );
        // A raw wait status of 9 is "killed by signal 9": no exit code.
        let killed = ExitStatus::from_raw(9);
        assert_eq!(killed.code(), None);
        assert_eq!(check_end_of(killed), CheckEnd::Signaled { signal: 9 });
    }

    #[test]
    fn the_recorded_base_remote_is_the_first_real_ref_and_never_a_head_alias() {
        assert_eq!(base_remote_ref(""), None);
        assert_eq!(base_remote_ref("\n"), None);
        assert_eq!(
            base_remote_ref("origin/main\n").as_deref(),
            Some("origin/main")
        );
        assert_eq!(
            base_remote_ref("origin/HEAD\norigin/main\nupstream/main\n").as_deref(),
            Some("origin/main")
        );
        assert_eq!(
            base_remote_ref("upstream/zeta\norigin/main\n").as_deref(),
            Some("origin/main")
        );
        // Only the alias contains it: better than nothing, and still a ref name.
        assert_eq!(
            base_remote_ref("origin/HEAD\n").as_deref(),
            Some("origin/HEAD")
        );
    }

    #[test]
    fn a_check_file_holds_the_real_run_and_falls_back_to_pass_or_fail_alone() {
        let check = cowproof_core::Check {
            id: "unit".into(),
            command: "cargo test".into(),
            flaky: false,
        };
        let run = CheckRunRecord {
            attempts: 3,
            exit_status: 101,
            end: CheckEnd::Exited { code: 101 },
            duration_ms: 4321,
            output_sha256: "ab".repeat(32),
            output_len: 99,
        };
        let real = check_result(&check, false, Some(&run));
        assert_eq!(
            (real.exit_status, real.attempts, real.duration_ms),
            (101, 3, 4321)
        );
        assert_eq!(real.output_sha256, "ab".repeat(32));
        assert_eq!(real.output_len, Some(99));
        assert_eq!(real.end, Some(CheckEnd::Exited { code: 101 }));

        let bare = check_result(&check, true, None);
        assert_eq!(
            (bare.exit_status, bare.attempts, bare.duration_ms),
            (0, 1, 0)
        );
        assert_eq!((bare.output_len, bare.end), (None, None));
        assert_eq!(check_result(&check, false, None).exit_status, 1);
    }
}
