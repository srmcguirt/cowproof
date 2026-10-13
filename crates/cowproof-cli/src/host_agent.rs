//! `cowproof host-agent`: the remote side of remote lanes (D27, hidden).
//!
//! The director keeps the runner (queue, rulings, proxy, key, proof, held-out checks); a remote
//! host runs only the sandboxed processes. This is the closed set of verbs the director may
//! run there over SSH. `prepare`, `patch`, `stderr`, `doctor` and `cleanup` need no sockets;
//! `builder` and `check` run sandboxed processes in a prepared lane:
//!
//! - `prepare --lane-id <id> --base <sha> --director-version <v> --protocol <n>`: stdin is
//!   one JSON header line `{"patch_bytes":M}`, then exactly M bytes of the director's
//!   `base.patch` (M may be 0), then a git bundle that contains `<sha>`, to end of file. The
//!   patch is the only part whose length the director knows before it starts sending (the
//!   bundle is streamed from `git bundle create -`), so only it is counted and the bundle is
//!   delimited by end of file: no temporary file on the director and nothing ambiguous. The
//!   lane is built by the local runner's own `prepare_lane` (same layout, permissions,
//!   isolated clone, launch baseline and `control/lane.json`) from a throwaway source
//!   repository made out of the bundle, with the base patch applied there as uncommitted work,
//!   so there is no second clone implementation.
//! - `patch --lane-id <id>`: the lane patch, the bytes `cowproof run` writes to `lane.patch`,
//!   from the same `capture_patch` (run in the check sandbox, because the builder owns the
//!   clone's `.git`). A builder group still alive in the lane is ended first (see below), so the
//!   patch is taken from a lane nothing is writing to.
//! - `stderr --lane-id <id>`: the last [`MAX_STDERR_FETCH`] bytes of `control/builder.stderr`
//!   (already redacted here; the director redacts them again), raw, empty when there is none.
//! - `doctor [--claude-bin <name>]`: the preflight's `sandbox` and `claude` checks, and the
//!   protocol this binary speaks. Under `--forced` it also reports `"config": "ok"`.
//! - `cleanup --lane-id <id>`: ends the lane's builder group if one is still alive (see below),
//!   then removes `<root>/<id>`; idempotent; never follows a link. The JSON reports what it
//!   ended in `group`.
//! - `builder --lane-id <id>`: stdin is one JSON launch spec ([`BuilderSpec`]) on ONE line
//!   ended by `\n`, and then the director's lifeline: it keeps stdin open for as long as the
//!   builder should live, and end of file on it ends the builder like SIGHUP does (an `ssh`
//!   without a pty sends no hangup when the director's `ssh` dies, but `sshd` does close the
//!   command's stdin). It starts the builder in the lane's sandbox, through the same
//!   `write_lane_files` and `builder_command` as `cowproof run`. The builder's stdout is this
//!   process's stdout, byte for byte; a stdout that breaks ends the builder too. Its stderr
//!   goes redacted to `control/builder.stderr` (appended, so a lane's launches follow each
//!   other); the exit code is the builder's (130 after SIGINT, SIGTERM, SIGHUP, end of stdin
//!   or a broken stdout, which end the builder's whole process group). It needs
//!   `<lane>/proxy.sock` and `<lane>/sock/runner.sock` to exist already (forwarded with
//!   `ssh -R`, D24). A refusal, before anything starts, is the usual JSON error and exit 1.
//!   It first ends any group a previous launch of the same lane left alive (see below).
//! - `check --lane-id <id> --check-id <id>`: one JSON check spec on stdin ([`CheckSpec`]),
//!   read to end of file; runs the command through the same `run_check_command` as the local
//!   `run_check` tool and prints `{ok, exit_code, timed_out, output_tail}`. It exits 0
//!   whenever the check ran (`ok` says whether it passed) and 1, with the JSON error, when it
//!   could not be run.
//!
//! Every verb prints one JSON object (`{"ok": true, ...}` or `{"ok": false, "error": "..."}`)
//! and exits 0 or 1, with two exceptions: `patch` and `stderr` print raw bytes on success (a
//! patch need not be UTF-8, and JSON would change it), and the JSON error only on failure.
//! The lanes root is `--root`, or `~/.cache/cowproof/remote-lanes`.
//!
//! The builder's group (R-5). `builder` records the group it launched in the lane's
//! `control/builder.group.json` (the pgid, the leader's pid and the leader's start time) and
//! removes the file once the group is gone. `cleanup`, `patch` and a new `builder` for the same
//! lane first end a group that is still recorded: SIGTERM to the group, the runner's grace
//! (`TERM_GRACE`), then SIGKILL. It is signalled only when it is provably the recorded one: the
//! leader is the same process (same pid AND same start time), or the leader is gone but a
//! group with its number still exists (a pid is not reused while a process group of that
//! number lives, so those members are the old group's). A leader pid that now belongs to
//! another process (a different start time) is never signalled. This closes the race between a
//! builder that is slow to stop and a director that already takes the patch, removes the lane or
//! relaunches, and it ends a group whose `host-agent builder` died before it could.
//!
//! `--forced` (the form an `authorized_keys` `command="<cowproof> host-agent --forced"` names).
//! sshd runs it for every session of the director's key and puts the client's command in
//! `SSH_ORIGINAL_COMMAND`. That text must be `<path>/cowproof host-agent <verb> <args>` in the
//! form `remote::agent_command` writes ([`split_command`] reads exactly `sh_quote`'s output and
//! refuses everything else), with a verb of the closed set; the arguments go through the same
//! clap definitions as a direct call, and the verb runs in this process. No shell is started and
//! word 0 is never executed. A refusal (also: no command at all, an interactive login) prints one
//! JSON error line and exits [`FORCED_REFUSED_EXIT`] (77), which a verb never returns on its own
//! account; `--forced` inside the command is refused. The wire is unchanged.
//!
//! What the director may choose under `--forced` is narrower than a direct call: the host
//! owner's `host.toml` ([`config`]) names the `claude` and the lanes `root`. `doctor` runs that
//! `claude`, and a `--claude-bin` that differs is refused (77, naming the argument and never its
//! value); the builder spec's `claude_bin` must equal it, else the launch is refused before the
//! lane is touched; `--root` must equal the configured root and, left out, is the configured
//! root. With no usable config (missing, or a file or directory someone else could write, a
//! link, a bad key) every verb but `doctor` is refused, and `doctor` reports `"config":
//! "missing"` or `"invalid"` with the owner's command in `fix` and runs no `claude`. A direct
//! call does not read the file and behaves as it always did.
//!
//! The protocol ([`HOST_PROTOCOL`]) names the stdin framings above. A director sends it to
//! `prepare` and reads it from `doctor`; either side refuses a mismatch with a message naming
//! both numbers, before any lane exists or any builder starts. Protocol 1 (no number) had a
//! builder spec that ended at end of file and a base patch passed as a host file name. The
//! group record is not part of the wire, so it did not change the number.

pub(crate) mod config;

use self::config::{HostConfig, Loaded};
use crate::preflight::{Check, CheckStatus, PreflightOptions, preflight};
use crate::remote::is_bare_char;
use crate::run::{
    BuilderLaunch, CHECK_TERM_GRACE, CheckEnv, INTERRUPTED_EXIT_CODE, MAX_STDERR_LINE, PUMP_DRAIN,
    TERM_GRACE, builder_command, builder_path, capture_patch, pump_stderr, redact_ready, resumable,
    run_check_command, sibling_pk, sleep_until_opt, valid_model, write_lane_files,
};
use anyhow::{Context, Result, anyhow, bail};
use cowproof_core::{PORT_BASE, PORT_BLOCK_SIZE, redact};
use cowproof_prove::runner::{
    GroupSet, group_exists, kill_process_group, pid_exists, terminate_process_group,
};
use cowproof_run::bridge::bridge_port;
use cowproof_run::lane::{LaneControl, PrepareOptions, prepare_lane, validate_lane_id};
use cowproof_run::tools::CheckEnd;
use cowproof_run::tools::MAX_OUTPUT;
use cowproof_run::{LaneLayout, NetworkMode, lane_tmp};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fs;
use std::io::{BufRead, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::oneshot;
use tokio::time::Instant as TokioInstant;

/// The remote host's side of D27.
#[derive(clap::Parser)]
#[command(args_conflicts_with_subcommands = true)]
pub struct HostAgentArgs {
    /// Run the verb the client asked for in `SSH_ORIGINAL_COMMAND`, if it is one of the verbs
    /// below, in the form `cowproof` writes it. This is what a forced-command key names
    /// (`cowproof host setup` prints the line); nothing else is accepted.
    #[arg(long)]
    forced: bool,
    #[command(subcommand)]
    command: Option<HostAgentAction>,
}

#[derive(clap::Subcommand)]
enum HostAgentAction {
    /// Receive the base as a git bundle on stdin and build the lane.
    Prepare {
        #[arg(long)]
        lane_id: String,
        /// The full commit id the lane starts from; the bundle must contain it
        #[arg(long)]
        base: String,
        /// The director's cowproof version; this binary must be the same
        #[arg(long)]
        director_version: String,
        /// The host-agent protocol the director speaks; this binary must speak the same
        #[arg(long)]
        protocol: Option<u32>,
        /// Directory that holds the lanes (default: ~/.cache/cowproof/remote-lanes)
        #[arg(long)]
        root: Option<PathBuf>,
    },
    /// Print the lane patch (raw bytes) against the launch baseline.
    Patch {
        #[arg(long)]
        lane_id: String,
        #[arg(long)]
        root: Option<PathBuf>,
    },
    /// Print the builder's redacted stderr (raw bytes, the last megabyte).
    Stderr {
        #[arg(long)]
        lane_id: String,
        #[arg(long)]
        root: Option<PathBuf>,
    },
    /// Report the version, `claude` and the sandbox.
    Doctor {
        /// The Claude Code executable to check, resolved on PATH (default: `claude`). Under
        /// `--forced` it must be the host's configured `claude`, which is also the default.
        #[arg(long)]
        claude_bin: Option<String>,
        #[arg(long)]
        root: Option<PathBuf>,
    },
    /// Remove a lane (idempotent).
    Cleanup {
        #[arg(long)]
        lane_id: String,
        #[arg(long)]
        root: Option<PathBuf>,
    },
    /// Run the builder from the launch spec line on stdin; its stdout is ours. End of stdin ends it.
    Builder {
        #[arg(long)]
        lane_id: String,
        #[arg(long)]
        root: Option<PathBuf>,
    },
    /// Run one declared check from the check spec on stdin and report how it ended.
    Check {
        #[arg(long)]
        lane_id: String,
        /// The check's id, for messages
        #[arg(long)]
        check_id: String,
        #[arg(long)]
        root: Option<PathBuf>,
    },
}

/// Run one verb, print its output, and return the exit code (0 or 1).
pub async fn run(args: HostAgentArgs) -> Result<i32> {
    match (args.forced, args.command) {
        (true, None) => forced().await,
        (false, Some(action)) => run_action(action, None).await,
        (forced, command) => {
            // `args_conflicts_with_subcommands` keeps `--forced` and a verb apart; this is
            // the case with neither.
            debug_assert!(!forced && command.is_none());
            <HostAgentArgs as clap::CommandFactory>::command()
                .error(
                    clap::error::ErrorKind::MissingSubcommand,
                    "a verb or --forced is required",
                )
                .exit()
        }
    }
}

impl HostAgentAction {
    /// The verb's `--root`, whichever verb it is.
    fn root_mut(&mut self) -> &mut Option<PathBuf> {
        match self {
            HostAgentAction::Prepare { root, .. }
            | HostAgentAction::Patch { root, .. }
            | HostAgentAction::Stderr { root, .. }
            | HostAgentAction::Doctor { root, .. }
            | HostAgentAction::Cleanup { root, .. }
            | HostAgentAction::Builder { root, .. }
            | HostAgentAction::Check { root, .. } => root,
        }
    }
}

/// Run a verb. `pins` is the host owner's config under `--forced` (`None` for a direct call):
/// [`pin`] has already made `--root` and `doctor`'s claude agree with it, and the builder's
/// spec is checked against it here, where the spec is read.
async fn run_action(action: HostAgentAction, pins: Option<&HostConfig>) -> Result<i32> {
    let outcome = match action {
        HostAgentAction::Prepare {
            lane_id,
            base,
            director_version,
            protocol,
            root,
        } => remote_root(root)
            .and_then(|root| prepare(&lane_id, &base, &director_version, protocol, &root)),
        HostAgentAction::Doctor { claude_bin, root } => match remote_root(root) {
            Ok(root) => {
                let claude_bin = claude_bin.as_deref().unwrap_or("claude");
                doctor(claude_bin, &root).await.map(|mut report| {
                    if pins.is_some() {
                        report["config"] = json!("ok");
                    }
                    report
                })
            }
            Err(e) => Err(e),
        },
        HostAgentAction::Cleanup { lane_id, root } => {
            remote_root(root).and_then(|root| cleanup(&lane_id, &root))
        }
        HostAgentAction::Builder { lane_id, root } => {
            let launched = match remote_root(root) {
                Ok(root) => builder_launch(&lane_id, &root, pins.map(|c| c.claude.as_path())),
                Err(e) => Err(e),
            };
            return match launched {
                Ok(launched) => match drive_builder(launched, watch_stdin()).await {
                    Ok(code) => Ok(code),
                    Err(e) => print_outcome(Err(e)),
                },
                // The spec asked for an executable the owner did not configure.
                Err(e) => match e.downcast_ref::<Pin>() {
                    Some(pin) => refuse(pin),
                    None => print_outcome(Err(e)),
                },
            };
        }
        HostAgentAction::Check {
            lane_id,
            check_id,
            root,
        } => {
            let ran = match remote_root(root) {
                Ok(root) => check(&lane_id, &check_id, &root).await,
                Err(e) => Err(e),
            };
            return match ran {
                Ok(report) => {
                    println!("{}", serde_json::to_string(&report)?);
                    Ok(0)
                }
                Err(e) => print_outcome(Err(e)),
            };
        }
        HostAgentAction::Patch { lane_id, root } => {
            let bytes = match remote_root(root) {
                Ok(root) => patch(&lane_id, &root).await,
                Err(e) => Err(e),
            };
            return raw_outcome(bytes);
        }
        HostAgentAction::Stderr { lane_id, root } => {
            let bytes = remote_root(root).and_then(|root| builder_stderr(&lane_id, &root));
            return raw_outcome(bytes);
        }
    };
    print_outcome(outcome)
}

/// The raw bytes of a verb that prints them (`patch`, `stderr`), or its JSON error.
fn raw_outcome(bytes: Result<Vec<u8>>) -> Result<i32> {
    Ok(match bytes {
        Ok(bytes) => {
            let mut out = std::io::stdout().lock();
            out.write_all(&bytes)?;
            out.flush()?;
            0
        }
        Err(e) => print_outcome(Err(e))?,
    })
}

/// Print a verb's JSON and return its exit code. A returned error becomes `ok: false`.
fn print_outcome(outcome: Result<Value>) -> Result<i32> {
    let value = outcome.unwrap_or_else(|e| json!({"ok": false, "error": format!("{e:#}")}));
    println!("{}", serde_json::to_string(&value)?);
    Ok(if value["ok"] == true { 0 } else { 1 })
}

/// The exit code of `host-agent --forced` when it refuses the client's command (or has none):
/// the JSON error is printed and nothing runs. Distinct from 0 and 1 (the verbs' own), from 2
/// (clap's usage error) and from 255 (ssh's own failure). A verb that was accepted exits with
/// its own code, as a direct call does.
pub(crate) const FORCED_REFUSED_EXIT: i32 = 77;

/// The closed set of verbs, as they are written on the command line. A test keeps it equal to
/// [`HostAgentAction`], so a new verb cannot be added to one and not the other.
const VERBS: [&str; 7] = [
    "prepare", "builder", "check", "patch", "stderr", "doctor", "cleanup",
];

/// Why `--forced` refused a command. The message names what was wrong and never quotes the
/// command, which may be long or hostile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Refusal {
    /// `SSH_ORIGINAL_COMMAND` is not set (an interactive login) or is empty.
    NoCommand,
    /// It is not valid UTF-8.
    NotUtf8,
    /// A control character (a newline, a tab, NUL, escape...) anywhere in it.
    Control,
    /// Not the form `cowproof` writes: a word that is neither bare nor single-quoted, or
    /// words not separated by one space.
    Syntax,
    /// `--forced` is among the words.
    ForcedFlag,
    /// Word 0 is not a path whose file name is `cowproof`.
    Program,
    /// Word 1 is not `host-agent`.
    NotHostAgent,
    /// Word 2 is missing or not a verb.
    Verb,
    /// The words after the verb do not fit it, by the same clap code as a direct call.
    Arguments(clap::error::ErrorKind),
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refusal::NoCommand => f.write_str(
                "no command was requested: this key runs only `cowproof host-agent <verb>`, \
                 so an interactive login is refused",
            ),
            Refusal::NotUtf8 => f.write_str("the requested command is not valid UTF-8"),
            Refusal::Control => {
                f.write_str("the requested command contains a control character or a newline")
            }
            Refusal::Syntax => f.write_str(
                "the requested command is not in the form cowproof writes: bare words of \
                 letters, digits and _./:=@%+,- or single-quoted words, separated by single spaces",
            ),
            Refusal::ForcedFlag => f.write_str("--forced is not accepted inside the command"),
            Refusal::Program => {
                f.write_str("the first word is not a path to a file named cowproof")
            }
            Refusal::NotHostAgent => f.write_str("the second word is not host-agent"),
            Refusal::Verb => f.write_str("the third word is not a host-agent verb"),
            Refusal::Arguments(kind) => write!(
                f,
                "the arguments do not fit the verb ({kind:?}); this host speaks host-agent \
                 protocol {HOST_PROTOCOL}"
            ),
        }
    }
}

/// `host-agent --forced`: run the verb the client asked for, in this process.
///
/// `sshd` ran this because the key's `command=` names it, and put what the client asked for
/// in `SSH_ORIGINAL_COMMAND`. That text is split by [`split_command`] (no shell is involved,
/// here or anywhere below), must name `<...>/cowproof host-agent <verb> ...` with a verb of
/// the closed set, and its arguments go through the same clap definitions as a direct call.
/// Word 0 only has to look like cowproof: it is never executed, the binary that runs is the
/// one the key names.
///
/// What the verbs may be told to run or to touch is then decided by the host owner's
/// `host.toml` ([`config`]), not by the director: see [`pin`]. Without a usable config only
/// `doctor` runs, and it reports that and runs nothing.
async fn forced() -> Result<i32> {
    let action = match forced_action(std::env::var_os("SSH_ORIGINAL_COMMAND")) {
        Ok(action) => action,
        Err(refusal) => return refuse(refusal),
    };
    let path = match config::forced_config_path() {
        Ok(path) => path,
        Err(e) => return refuse(format!("{e:#}")),
    };
    match config::load(&path) {
        Loaded::Ok(cfg) => match pin(action, &cfg) {
            Ok(action) => run_action(action, Some(&cfg)).await,
            Err(pin) => refuse(pin),
        },
        unusable => {
            let (state, detail) = match unusable {
                Loaded::Invalid(problem) => ("invalid", problem),
                _ => ("missing", format!("there is no {}", path.display())),
            };
            let fix = setup_command(state == "invalid");
            if matches!(action, HostAgentAction::Doctor { .. }) {
                // Nothing is run, whatever `--claude-bin` says: the owner has not said what may be.
                return print_outcome(Ok(json!({
                    "ok": false,
                    "version": env!("CARGO_PKG_VERSION"),
                    "protocol": HOST_PROTOCOL,
                    "config": state,
                    "config_detail": detail,
                    "fix": fix,
                })));
            }
            refuse(format!(
                "this host's config is {state} ({detail}); its owner runs `{fix}` on this host"
            ))
        }
    }
}

/// The owner's command that writes the host config, for a message: with the path of this
/// binary, which is the one the key names.
fn setup_command(replace: bool) -> String {
    let exe = std::env::current_exe()
        .ok()
        .and_then(|p| p.to_str().map(crate::remote::sh_quote))
        .unwrap_or_else(|| "cowproof".to_string());
    let force = if replace { " --force" } else { "" };
    format!("{exe} host setup --write-config{force}")
}

/// Print `refused: <why>` as the one JSON error line of a forced refusal and return its exit
/// code. `why` names what was wrong and never quotes what the client sent.
fn refuse(why: impl std::fmt::Display) -> Result<i32> {
    println!(
        "{}",
        serde_json::to_string(&json!({"ok": false, "error": format!("refused: {why}")}))?
    );
    Ok(FORCED_REFUSED_EXIT)
}

/// An argument that the host owner's config decides and the director did not repeat. The
/// message names the argument and never echoes what the director gave.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pin {
    /// `--root` is not the configured `root`.
    Root,
    /// `doctor --claude-bin` is not the configured `claude`.
    ClaudeBin,
    /// The builder spec's `claude_bin` is not the configured `claude`.
    SpecClaudeBin,
}

impl std::fmt::Display for Pin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Pin::Root => {
                "--root is not this host's configured root: leave it out, or give the path \
                 its owner put in host.toml"
            }
            Pin::ClaudeBin => {
                "--claude-bin is not this host's configured claude: leave it out, or give the \
                 path its owner put in host.toml"
            }
            Pin::SpecClaudeBin => {
                "the launch spec's claude_bin is not this host's configured claude (host.toml)"
            }
        })
    }
}

impl std::error::Error for Pin {}

/// Make the verb's `--root` and `doctor`'s `--claude-bin` the owner's, or refuse. A value the
/// director gives must equal the configured one (compared as paths, lexically: no `..`, no
/// link is followed); one it leaves out becomes the configured one. The builder's spec is
/// checked where it is read, in [`builder_launch`].
fn pin(mut action: HostAgentAction, cfg: &HostConfig) -> Result<HostAgentAction, Pin> {
    let given = action.root_mut().take();
    if let Some(root) = given {
        // The same reading of a relative `--root` as `remote_root`.
        let cwd = std::env::current_dir().map_err(|_| Pin::Root)?;
        if cwd.join(root) != cfg.root {
            return Err(Pin::Root);
        }
    }
    *action.root_mut() = Some(cfg.root.clone());
    if let HostAgentAction::Doctor { claude_bin, .. } = &mut action {
        if let Some(given) = claude_bin.as_deref()
            && Path::new(given) != cfg.claude
        {
            return Err(Pin::ClaudeBin);
        }
        *claude_bin = cfg.claude.to_str().map(str::to_string);
    }
    Ok(action)
}

/// What `host-agent --forced` accepts for `SSH_ORIGINAL_COMMAND`, or why not.
fn forced_action(original: Option<std::ffi::OsString>) -> Result<HostAgentAction, Refusal> {
    let text = original
        .ok_or(Refusal::NoCommand)?
        .into_string()
        .map_err(|_| Refusal::NotUtf8)?;
    let words = split_command(&text)?;
    if words.iter().any(|w| w == "--forced") {
        return Err(Refusal::ForcedFlag);
    }
    // The file name, cut at the last `/`: `Path::file_name` would accept `x/cowproof/`.
    if words[0].rsplit('/').next() != Some("cowproof") {
        return Err(Refusal::Program);
    }
    if words.get(1).map(String::as_str) != Some("host-agent") {
        return Err(Refusal::NotHostAgent);
    }
    match words.get(2) {
        Some(verb) if VERBS.contains(&verb.as_str()) => {}
        _ => return Err(Refusal::Verb),
    }
    <ForcedVerb as clap::Parser>::try_parse_from(&words[2..])
        .map(|parsed| parsed.command)
        .map_err(|e| Refusal::Arguments(e.kind()))
}

/// A verb and its arguments, parsed by the same definitions as `host-agent <verb> ...`; the
/// first word is the verb itself, there is no program name.
#[derive(clap::Parser)]
#[command(no_binary_name = true, disable_help_subcommand = true)]
struct ForcedVerb {
    #[command(subcommand)]
    command: HostAgentAction,
}

/// Split `text` into words, accepting exactly what `remote::sh_quote` produces, joined by
/// single spaces: a bare word (only [`is_bare_char`] characters), or a single-quoted word in
/// which each `'` of the text is written `'\''`. Everything else is refused, because it would
/// mean something to a shell: `"`, `$`, backticks, `;`, `|`, `&`, `<`, `>`, `(`, `)`, `*`, `?`,
/// `[`, `~`, `#`, `!`, `{`, a backslash outside `'\''`, a tab, a newline, a second space, a
/// space at either end, and any control character even inside quotes. Nothing here expands or
/// substitutes anything: the words come out exactly as `sh_quote` was given them.
fn split_command(text: &str) -> Result<Vec<String>, Refusal> {
    if text.is_empty() {
        return Err(Refusal::NoCommand);
    }
    if text.chars().any(char::is_control) {
        return Err(Refusal::Control);
    }
    let chars: Vec<char> = text.chars().collect();
    let mut words = Vec::new();
    let mut at = 0;
    loop {
        let (word, next) = split_word(&chars, at)?;
        words.push(word);
        at = next;
        if at == chars.len() {
            return Ok(words);
        }
        // One space, and a word after it.
        if chars[at] != ' ' || at + 1 == chars.len() {
            return Err(Refusal::Syntax);
        }
        at += 1;
    }
}

/// One word starting at `chars[start]`, and the index just past it. The caller checks what
/// follows (a space or the end).
fn split_word(chars: &[char], start: usize) -> Result<(String, usize), Refusal> {
    match chars.get(start) {
        Some(&c) if is_bare_char(c) => {
            let end = start
                + chars[start..]
                    .iter()
                    .take_while(|c| is_bare_char(**c))
                    .count();
            Ok((chars[start..end].iter().collect(), end))
        }
        Some('\'') => {
            let mut word = String::new();
            let mut at = start;
            loop {
                // `chars[at]` is an opening quote.
                at += 1;
                let close = at
                    + chars[at..]
                        .iter()
                        .position(|&c| c == '\'')
                        .ok_or(Refusal::Syntax)?;
                word.extend(&chars[at..close]);
                at = close + 1;
                // `'\''`: the closing quote, a quote of the text, and an opening quote.
                if chars[at..].starts_with(&['\\', '\'', '\'']) {
                    word.push('\'');
                    at += 2;
                    continue;
                }
                return Ok((word, at));
            }
        }
        _ => Err(Refusal::Syntax),
    }
}

/// `--root`, or `~/.cache/cowproof/remote-lanes`; a relative `--root` is taken from the
/// working directory.
pub(crate) fn remote_root(arg: Option<PathBuf>) -> Result<PathBuf> {
    match arg {
        Some(p) => Ok(std::env::current_dir()?.join(p)),
        None => Ok(real_home()?.join(".cache/cowproof/remote-lanes")),
    }
}

fn real_home() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| anyhow!("HOME is not set"))
}

/// A full object name: 40 (SHA-1) or 64 (SHA-256) lowercase hex digits. Anything else could
/// be a ref name, an abbreviation or an option.
fn validate_commit_id(base: &str) -> Result<()> {
    let hex = base
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if !hex || !(base.len() == 40 || base.len() == 64) {
        bail!("--base must be a full commit id (40 or 64 lowercase hex digits)");
    }
    Ok(())
}

/// A directory this verb made, removed when dropped.
struct Throwaway(PathBuf);

impl Drop for Throwaway {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// A git command in `dir`, with its failure turned into the error.
fn git(dir: &Path, args: &[&str]) -> Result<()> {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .with_context(|| format!("running git {}", args.join(" ")))?;
    if !out.status.success() {
        bail!(
            "git {} failed: {}",
            args.first().copied().unwrap_or(""),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// The host-agent protocol this binary speaks (see the module doc). Bump it whenever a stdin
/// framing or a verb's meaning changes: the director sends it to `prepare` and reads it from
/// `doctor`, and either side refuses a different number before anything runs.
pub(crate) const HOST_PROTOCOL: u32 = 2;

/// The most a `prepare` header line may hold.
const MAX_HEADER_BYTES: u64 = 1024;
/// The most a base patch may hold.
const MAX_BASE_PATCH_BYTES: u64 = 256 * 1024 * 1024;
/// How much of `control/builder.stderr` the `stderr` verb returns (its end).
pub(crate) const MAX_STDERR_FETCH: u64 = 1024 * 1024;

/// The first line of `prepare`'s stdin.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrepareHeader {
    /// How many bytes of the director's `base.patch` follow the header line; the git bundle
    /// follows them, to end of file.
    patch_bytes: u64,
}

/// Read `prepare`'s stdin: the header line, the base patch (into `patch_file`, when it has
/// bytes) and the bundle (into `bundle_file`). Returns whether there is a base patch.
fn read_prepare_input(patch_file: &Path, bundle_file: &Path) -> Result<bool> {
    let mut stdin = std::io::stdin().lock();
    let mut line = Vec::new();
    (&mut stdin)
        .take(MAX_HEADER_BYTES + 1)
        .read_until(b'\n', &mut line)
        .context("reading the header line from stdin")?;
    if line.last() != Some(&b'\n') {
        bail!(
            "stdin must start with a one-line JSON header ended by a newline (this host speaks \
             host-agent protocol {HOST_PROTOCOL})"
        );
    }
    let header: PrepareHeader =
        serde_json::from_slice(&line).context("the header line is not a valid prepare header")?;
    if header.patch_bytes > MAX_BASE_PATCH_BYTES {
        bail!("the base patch is larger than {MAX_BASE_PATCH_BYTES} bytes");
    }
    if header.patch_bytes > 0 {
        let mut file = fs::File::create(patch_file).context("creating the base patch file")?;
        let copied = std::io::copy(&mut (&mut stdin).take(header.patch_bytes), &mut file)
            .context("reading the base patch from stdin")?;
        if copied != header.patch_bytes {
            bail!(
                "stdin ended inside the base patch ({copied} of {} bytes)",
                header.patch_bytes
            );
        }
    }
    let mut file = fs::File::create(bundle_file).context("creating the bundle file")?;
    std::io::copy(&mut stdin, &mut file).context("reading the bundle from stdin")?;
    Ok(header.patch_bytes > 0)
}

/// Build the lane `<root>/<id>` from the framed stdin (header, base patch, bundle).
fn prepare(
    lane_id: &str,
    base: &str,
    director_version: &str,
    protocol: Option<u32>,
    root: &Path,
) -> Result<Value> {
    validate_lane_id(lane_id)?;
    let version = env!("CARGO_PKG_VERSION");
    if director_version != version {
        bail!(
            "version mismatch: the director runs cowproof {director_version}, this host runs {version}"
        );
    }
    match protocol {
        Some(p) if p == HOST_PROTOCOL => {}
        Some(p) => bail!(
            "protocol mismatch: the director speaks host-agent protocol {p}, this host speaks \
             protocol {HOST_PROTOCOL}; install the same cowproof build on both"
        ),
        None => bail!(
            "protocol mismatch: the director named no host-agent protocol (it is older than this \
             host's protocol {HOST_PROTOCOL}); install the same cowproof build on both"
        ),
    }
    validate_commit_id(base)?;

    fs::create_dir_all(root).with_context(|| format!("creating {}", root.display()))?;
    let root = root.canonicalize().context("resolving the lanes root")?;
    let lane_dir = root.join(lane_id);
    if fs::symlink_metadata(&lane_dir).is_ok() {
        bail!("lane {lane_id} already exists in {}", root.display());
    }

    // The throwaway source repository sits beside the root, never inside it:
    // `prepare_lane` refuses a lanes root that contains its source.
    let incoming = root.with_file_name(format!(
        "{}.incoming-{lane_id}-{}",
        root.file_name()
            .ok_or_else(|| anyhow!("the lanes root must not be /"))?
            .to_string_lossy(),
        std::process::id()
    ));
    fs::create_dir(&incoming).with_context(|| format!("creating {}", incoming.display()))?;
    let incoming = Throwaway(incoming);
    let src = incoming.0.join("src");
    let bundle = incoming.0.join("in.bundle");
    let patch_file = incoming.0.join("base.patch");
    let has_base_patch = read_prepare_input(&patch_file, &bundle)?;
    git(&incoming.0, &["init", "-q", "src"])?;
    git(&src, &["bundle", "unbundle", &bundle.to_string_lossy()]).context("reading the bundle")?;
    if git(&src, &["cat-file", "-e", &format!("{base}^{{commit}}")]).is_err() {
        bail!("the bundle does not contain commit {base}");
    }
    git(&src, &["checkout", "-q", "--detach", base])?;
    if has_base_patch {
        git(&src, &["apply", "--", &patch_file.to_string_lossy()])
            .context("applying the base patch")?;
    }

    let prepared = prepare_lane(
        &src,
        &root,
        lane_id,
        PrepareOptions {
            allow_dirty: has_base_patch,
        },
    )?;
    // As the runner does right after `prepare_lane`: the builder's and the checks' TMPDIR.
    fs::create_dir_all(cowproof_run::lane_tmp(&prepared.layout.scratch))
        .context("creating the lane's temp directory")?;
    Ok(json!({
        "ok": true,
        "lane_id": lane_id,
        "lane_dir": lane_dir,
        "version": version,
        "base_commit": prepared.base_commit,
        "launch_commit": prepared.launch_commit,
        "removed": prepared.launch_removed,
        "base_patch": prepared.base_patch.is_some(),
    }))
}

/// The lane at `<root>/<id>`, resolved: a real directory under the real root, never a link.
fn lane_dir_of(lane_id: &str, root: &Path) -> Result<PathBuf> {
    validate_lane_id(lane_id)?;
    let root = root
        .canonicalize()
        .with_context(|| format!("no lanes root at {}", root.display()))?;
    let lane_dir = root.join(lane_id);
    let meta = fs::symlink_metadata(&lane_dir)
        .map_err(|_| anyhow!("no lane {lane_id} in {}", root.display()))?;
    if !meta.is_dir() {
        bail!("{} is not a lane directory", lane_dir.display());
    }
    Ok(lane_dir)
}

/// The lane patch: everything changed since the launch baseline, as `cowproof run` writes it
/// to `lane.patch` (the very same `capture_patch`).
async fn patch(lane_id: &str, root: &Path) -> Result<Vec<u8>> {
    patch_with_home(lane_id, root, real_home()?).await
}

async fn patch_with_home(lane_id: &str, root: &Path, home: PathBuf) -> Result<Vec<u8>> {
    let lane_dir = lane_dir_of(lane_id, root)?;
    // A builder still stopping (the director let go and the host is in its grace period) must
    // not write while the patch is taken.
    if let Some(g) = end_recorded_group(&lane_dir.join("control"))?
        && g.state == GroupState::Survived
    {
        bail!(
            "the builder's process group {} did not end after SIGKILL; the patch was not taken",
            g.pgid
        );
    }
    let control_file = lane_dir.join("control/lane.json");
    let control: LaneControl = serde_json::from_slice(
        &fs::read(&control_file).with_context(|| format!("reading {}", control_file.display()))?,
    )
    .context("parsing control/lane.json")?;
    let layout = LaneLayout::for_lane_dir(&lane_dir, home.clone())?;
    fs::create_dir_all(cowproof_run::lane_tmp(&layout.scratch))
        .context("creating the lane's temp directory")?;
    let path = builder_path(&std::env::var("PATH").unwrap_or_default(), &home);
    capture_patch(&layout, &control.launch_commit, &path).await
}

/// The end of `control/builder.stderr`, at most [`MAX_STDERR_FETCH`] bytes of it. The runner's
/// pump wrote it redacted; a lane whose builder never ran has none, which is an empty answer.
fn builder_stderr(lane_id: &str, root: &Path) -> Result<Vec<u8>> {
    let lane_dir = lane_dir_of(lane_id, root)?;
    let path = lane_dir.join("control/builder.stderr");
    match fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => bail!("cannot look at {}: {e}", path.display()),
        Ok(meta) if !meta.is_file() => bail!("{} is not a regular file", path.display()),
        Ok(_) => {}
    }
    let mut file = fs::File::open(&path).with_context(|| format!("opening {}", path.display()))?;
    let len = file.metadata()?.len();
    file.seek(SeekFrom::Start(len.saturating_sub(MAX_STDERR_FETCH)))?;
    let mut bytes = Vec::new();
    file.take(MAX_STDERR_FETCH)
        .read_to_end(&mut bytes)
        .with_context(|| format!("reading {}", path.display()))?;
    Ok(bytes)
}

/// The preflight's `sandbox` and `claude` checks. `ok` means both pass; the key is not
/// checked, because a remote host must not have one (D27).
pub(crate) async fn doctor(claude_bin: &str, root: &Path) -> Result<Value> {
    let cwd = std::env::current_dir()?;
    let home = real_home()?;
    let director_path = std::env::var("PATH").unwrap_or_default();
    let checks = preflight(&PreflightOptions {
        repo: &cwd,
        lanes_root: root,
        disk_floor_gb: 0.0,
        claude_bin,
        director_path: &director_path,
        cwd: &cwd,
        real_home: &home,
        for_run: false,
    })
    .await;
    let find = |name: &str| -> Result<&Check> {
        checks
            .iter()
            .find(|c| c.name == name)
            .ok_or_else(|| anyhow!("the preflight has no {name} check"))
    };
    let (sandbox, claude) = (find("sandbox")?, find("claude")?);
    let passed = |c: &Check| c.status != CheckStatus::Fail;
    Ok(json!({
        "ok": passed(sandbox) && passed(claude),
        "version": env!("CARGO_PKG_VERSION"),
        "protocol": HOST_PROTOCOL,
        "claude": passed(claude),
        "claude_detail": claude.detail,
        "sandbox": passed(sandbox),
        "sandbox_detail": sandbox.detail,
    }))
}

/// Remove `<root>/<id>`, after ending the lane's builder group if it is still alive. A missing
/// lane is success. A link at that path is unlinked and its target is left alone;
/// `remove_dir_all` does not follow links inside the lane either. A group that outlives SIGKILL
/// stops the removal: the lane is kept, and the error says so.
fn cleanup(lane_id: &str, root: &Path) -> Result<Value> {
    validate_lane_id(lane_id)?;
    let target = root.join(lane_id);
    let group = match fs::symlink_metadata(&target) {
        Ok(meta) if meta.is_dir() => end_recorded_group(&target.join("control"))?,
        _ => None,
    };
    if let Some(g) = &group
        && g.state == GroupState::Survived
    {
        bail!(
            "the builder's process group {} did not end after SIGKILL; the lane was not removed",
            g.pgid
        );
    }
    let removed = match fs::symlink_metadata(&target) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => bail!("cannot look at {}: {e}", target.display()),
        Ok(meta) if meta.file_type().is_symlink() => {
            fs::remove_file(&target)
                .with_context(|| format!("removing the link {}", target.display()))?;
            true
        }
        Ok(meta) if meta.is_dir() => {
            fs::remove_dir_all(&target)
                .with_context(|| format!("removing {}", target.display()))?;
            true
        }
        Ok(_) => bail!("{} is not a lane directory", target.display()),
    };
    Ok(json!({
        "ok": true,
        "lane_id": lane_id,
        "removed": removed,
        "group": group.map(|g| g.to_json()),
    }))
}

/// The most a spec read from stdin may hold.
const MAX_SPEC_BYTES: u64 = 16 * 1024 * 1024;

/// Read one JSON spec from stdin to end of file (`check`).
fn read_spec<T: for<'de> Deserialize<'de>>() -> Result<T> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .lock()
        .take(MAX_SPEC_BYTES + 1)
        .read_to_end(&mut bytes)
        .context("reading the spec from stdin")?;
    if bytes.len() as u64 > MAX_SPEC_BYTES {
        bail!("the spec is larger than {MAX_SPEC_BYTES} bytes");
    }
    parse_spec(&bytes)
}

/// Read one JSON spec that is one line ended by a newline (`builder`), and leave the rest of
/// stdin alone: it is the director's lifeline, and its end is a stop signal ([`watch_stdin`]).
/// A spec that ends at end of file instead of a newline comes from a director that speaks an
/// older protocol, and is refused as such.
fn read_spec_line<T: for<'de> Deserialize<'de>>() -> Result<T> {
    let mut bytes = Vec::new();
    let mut stdin = std::io::stdin().lock();
    (&mut stdin)
        .take(MAX_SPEC_BYTES + 2)
        .read_until(b'\n', &mut bytes)
        .context("reading the spec from stdin")?;
    if bytes.last() != Some(&b'\n') {
        if bytes.len() as u64 > MAX_SPEC_BYTES {
            bail!("the spec is larger than {MAX_SPEC_BYTES} bytes");
        }
        bail!(
            "the spec must be one JSON line ended by a newline, with stdin kept open after it \
             (this host speaks host-agent protocol {HOST_PROTOCOL}; the director may be older)"
        );
    }
    bytes.pop();
    if bytes.len() as u64 > MAX_SPEC_BYTES {
        bail!("the spec is larger than {MAX_SPEC_BYTES} bytes");
    }
    parse_spec(&bytes)
}

/// Parse one JSON spec, refuse one that holds a credential, then read it as `T`.
fn parse_spec<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T> {
    let raw: Value = serde_json::from_slice(bytes).context("the spec is not one JSON value")?;
    if let Some(at) = find_secret(&raw, "") {
        // The place only: the value is never repeated.
        bail!("the spec contains an API key or credential (at {at}); a remote host never gets one");
    }
    serde_json::from_value(raw).context("the spec is not a valid spec")
}

/// Whether a JSON object key names a credential.
fn credential_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase().replace(['-', ' '], "_");
    [
        "api_key",
        "apikey",
        "auth_token",
        "secret",
        "password",
        "credential",
        "private_key",
    ]
    .iter()
    .any(|word| lower.contains(word))
}

/// `text` with every `Bearer` made harmless, so the redactor's bearer rule, which would match a
/// packet that merely explains HTTP auth, does not count.
fn without_bearer(text: &str) -> String {
    let lower = text.to_ascii_lowercase();
    let mut out = String::with_capacity(text.len());
    let mut at = 0;
    while let Some(i) = lower[at..].find("bearer") {
        out.push_str(&text[at..at + i]);
        out.push_str("bxarer");
        at += i + "bearer".len();
    }
    out.push_str(&text[at..]);
    out
}

/// Where in `value` a credential sits: a key named like one, or a string the redactor would
/// change (an `sk-` token, a JWT, a `ghp_` or `xox` token, an `OPENROUTER_API_KEY=` value). The
/// launch spec's two free-text fields are checked without the bearer rule.
fn find_secret(value: &Value, at: &str) -> Option<String> {
    match value {
        Value::String(text) => {
            let probe = if at == ".prompt" || at == ".system_prompt" {
                without_bearer(text)
            } else {
                text.clone()
            };
            (redact(&probe) != probe).then(|| if at.is_empty() { ".".into() } else { at.into() })
        }
        Value::Array(items) => items
            .iter()
            .enumerate()
            .find_map(|(i, v)| find_secret(v, &format!("{at}[{i}]"))),
        Value::Object(map) => map.iter().find_map(|(k, v)| {
            let here = format!("{at}.{k}");
            if credential_name(k) {
                Some(here)
            } else {
                find_secret(v, &here)
            }
        }),
        _ => None,
    }
}

/// Whether `port_base` can be the first port of a lane's block.
fn valid_port_base(port_base: u16) -> bool {
    port_base >= PORT_BASE && u32::from(port_base) + u32::from(PORT_BLOCK_SIZE) <= 65_536
}

/// What the director decided for one builder launch (D27): everything `Launcher::launch` decides
/// on the director, and no credential. `placeholder_key` is the lane's own `placeholder-...`
/// value that the director's proxy checks and swaps for the real key; a spec that holds
/// anything else that looks like a key is refused. The `mcp.json` is not part of the spec: its
/// only content is `cowproof lane-tools` on this host's runner socket, so `write_lane_files`
/// writes it from the paths here.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BuilderSpec {
    model: String,
    /// This launch's user prompt.
    prompt: String,
    /// The text for `--append-system-prompt-file`, assembled on the director.
    system_prompt: String,
    /// The contents of `settings.json`: permissions, and hooks when there are any.
    settings: Value,
    #[serde(default)]
    resume_session_id: Option<String>,
    placeholder_key: String,
    /// Must be [`bridge_port`] of the lane id (D24).
    bridge_port: u16,
    /// The first port of the lane's block (`COWPROOF_PORT_BASE`).
    port_base: u16,
    max_turns: u32,
    /// The `claude` executable on this host, absolute.
    claude_bin: PathBuf,
}

/// A launch that passed every check, ready to start.
struct BuilderLaunched {
    command: tokio::process::Command,
    stderr_file: PathBuf,
    /// The lane's `control` directory, where the builder's group is recorded.
    control: PathBuf,
}

/// The lane's forwarded socket must already exist: the Linux policy binds a socket only when
/// the file is there, so a late forward would leave the builder without it, silently.
fn forwarded_socket(path: &Path, what: &str) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_socket() => Ok(()),
        Ok(_) => bail!("{} ({what}) is not a socket", path.display()),
        Err(_) => bail!(
            "{} ({what}) does not exist; the director forwards it with ssh -R before the builder starts",
            path.display()
        ),
    }
}

/// Read and check the spec, write the lane files and build the builder's command. A refusal
/// happens before anything runs and before any lane file changes, except when the resume id is
/// the thing refused (the files are then written but nothing starts).
fn builder_launch(
    lane_id: &str,
    root: &Path,
    claude_pin: Option<&Path>,
) -> Result<BuilderLaunched> {
    let spec: BuilderSpec = read_spec_line()?;
    // Under `--forced` the executable is the owner's choice (`host.toml`): the first thing
    // refused, before the lane is looked at.
    if let Some(pinned) = claude_pin
        && spec.claude_bin != pinned
    {
        return Err(anyhow::Error::new(Pin::SpecClaudeBin));
    }
    let lane_dir = lane_dir_of(lane_id, root)?;
    let home = real_home()?;
    let layout = LaneLayout::for_lane_dir(&lane_dir, home.clone())?;
    if !layout.clone.is_dir() {
        bail!("lane {lane_id} has no clone; it was not prepared");
    }
    if !valid_model(&spec.model) {
        bail!("the model name is not acceptable");
    }
    if spec.prompt.is_empty() || spec.max_turns == 0 {
        bail!("the spec needs a prompt and at least one turn");
    }
    if !spec.settings.is_object() {
        bail!("settings must be a JSON object");
    }
    let placeholder = &spec.placeholder_key;
    if !placeholder.starts_with("placeholder-")
        || placeholder.len() > 128
        || !placeholder
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        bail!("placeholder_key must be the lane's placeholder-... value");
    }
    if spec.bridge_port != bridge_port(lane_id) {
        bail!("bridge_port is not the bridge port of lane {lane_id}");
    }
    if !valid_port_base(spec.port_base) {
        bail!("port_base is outside the lanes' port blocks");
    }
    if spec
        .resume_session_id
        .as_deref()
        .is_some_and(|id| !resumable(id))
    {
        bail!("resume_session_id is not a session id");
    }
    let claude_bin = &spec.claude_bin;
    if !claude_bin.is_absolute()
        || !fs::metadata(claude_bin)
            .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
    {
        bail!(
            "claude_bin {} is not an absolute path to an executable file on this host",
            claude_bin.display()
        );
    }
    let claude_bin = claude_bin
        .canonicalize()
        .context("resolving the claude executable")?;
    let proxy_socket = lane_dir.join("proxy.sock");
    forwarded_socket(&proxy_socket, "the egress proxy")?;
    forwarded_socket(&layout.sock, "the builder tools")?;
    let runner_socket = layout
        .sock
        .canonicalize()
        .context("resolving the builder tools socket")?;
    // The last refusal point: from here the launch changes the lane. A group a previous launch
    // left alive (the director relaunched after a ruling while the old builder was still
    // stopping) is ended first, so two builders never overlap in one lane.
    if let Some(g) = end_recorded_group(&layout.control)? {
        if g.state == GroupState::Survived {
            bail!(
                "the previous builder's process group {} did not end after SIGKILL; nothing was started",
                g.pgid
            );
        }
        if !g.signals.is_empty() {
            eprintln!(
                "ended the previous builder group {} ({})",
                g.pgid,
                g.state.name()
            );
        }
    }

    let cowproof_exe = std::env::current_exe()
        .and_then(|p| p.canonicalize())
        .context("locating the cowproof executable")?;
    let pk_exe = sibling_pk(&cowproof_exe);
    let portkit_dir = lane_dir.join("portkit");
    fs::create_dir_all(&portkit_dir).context("creating the lane's portkit directory")?;
    fs::create_dir_all(lane_tmp(&layout.scratch)).context("creating the lane's temp directory")?;
    let path = builder_path(&std::env::var("PATH").unwrap_or_default(), &home);

    let files = write_lane_files(
        &layout,
        &spec.settings,
        &cowproof_exe,
        &runner_socket,
        &spec.system_prompt,
    )?;
    let command = builder_command(&BuilderLaunch {
        layout: &layout,
        files,
        claude_bin: &claude_bin,
        cowproof_exe: &cowproof_exe,
        pk_exe: pk_exe.as_deref(),
        portkit_dir: &portkit_dir,
        path: &path,
        base_url: &format!("http://127.0.0.1:{}", spec.bridge_port),
        bridge_port: spec.bridge_port,
        proxy_socket: &proxy_socket,
        placeholder_key: &spec.placeholder_key,
        network: NetworkMode::Proxy {
            port: spec.bridge_port,
            socket: proxy_socket.clone(),
        },
        max_turns: spec.max_turns,
        runner_socket: &runner_socket,
        lane_id,
        port_base: spec.port_base,
        model: &spec.model,
        prompt: &spec.prompt,
        resume: spec.resume_session_id.as_deref(),
        unsandboxed: false,
        // Remote lanes run on an API key held by the director's proxy (D27).
        credential: cowproof_run::claude::Credential::ApiKey,
    })?;
    Ok(BuilderLaunched {
        command,
        stderr_file: layout.control.join("builder.stderr"),
        control: layout.control.clone(),
    })
}

// ---------------------------------------------------------------------------------------------
// Process identity and the recorded builder group (R-5)
// ---------------------------------------------------------------------------------------------

/// Where a builder's group is recorded, relative to the lane's `control` directory.
const GROUP_FILE: &str = "builder.group.json";
/// How often a wait for a process or a group to go looks again.
const POLL: Duration = Duration::from_millis(100);
/// How long `Group`'s drop waits for a SIGKILLed group to disappear before it leaves the record.
const GROUP_SETTLE: Duration = Duration::from_secs(3);
/// How long a group gets to disappear after SIGKILL before `cleanup` reports it survived.
const KILL_WAIT: Duration = Duration::from_secs(5);

/// The group `host-agent builder` launched. `leader` is the pid of the group's first process,
/// which is also the pgid (the launch makes the child a group leader); `leader_start` says which
/// process that pid was, see [`process_start`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GroupRecord {
    pgid: u32,
    leader: u32,
    leader_start: String,
}

/// Write `value` as JSON to `path` through a temporary file in the same directory, so a reader
/// sees the old file or the new one and never half of either. Mode 0600.
pub(crate) fn write_json_atomic(path: &Path, value: &impl Serialize) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = path.with_extension(format!("tmp{}", std::process::id()));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)
        .with_context(|| format!("creating {}", tmp.display()))?;
    let written = file
        .write_all(&serde_json::to_vec_pretty(value)?)
        .and_then(|()| file.flush());
    drop(file);
    if let Err(e) = written.and_then(|()| fs::rename(&tmp, path)) {
        let _ = fs::remove_file(&tmp);
        return Err(anyhow!(e)).with_context(|| format!("writing {}", path.display()));
    }
    Ok(())
}

/// What is known about a process.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Proc {
    Gone,
    /// Ended but not yet reaped: it can run nothing, and its pid is still taken.
    Zombie,
    /// Running; its start time when it could be read.
    Live(Option<String>),
}

/// The state letter and a start-time token of `pid` from `/proc/<pid>/stat` (Linux). The start
/// time is field 22, in clock ticks since boot; the fields after the command name, which may
/// hold spaces and parentheses, are counted from its last `)`.
fn proc_stat_info(pid: u32) -> Option<(char, String)> {
    parse_proc_stat(&fs::read_to_string(format!("/proc/{pid}/stat")).ok()?)
}

fn parse_proc_stat(stat: &str) -> Option<(char, String)> {
    let fields: Vec<&str> = stat[stat.rfind(')')? + 1..].split_whitespace().collect();
    // `fields[0]` is field 3, the state, so field 22 is `fields[19]`.
    Some((
        fields.first()?.chars().next()?,
        format!("proc:{}", fields.get(19)?),
    ))
}

/// The same from `ps -o stat= -o lstart=` (macOS, and any system without `/proc`): the start
/// time to the second, in the C locale so the text does not depend on the caller's.
fn ps_info(pid: u32) -> Option<(char, String)> {
    let out = Command::new("ps")
        .args(["-o", "stat=", "-o", "lstart=", "-p", &pid.to_string()])
        .env("LC_ALL", "C")
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let (state, started) = text.trim().split_once(char::is_whitespace)?;
    let started = started.split_whitespace().collect::<Vec<_>>().join(" ");
    (!started.is_empty()).then(|| (state.chars().next().unwrap_or('?'), format!("ps:{started}")))
}

/// Look at `pid` now.
pub(crate) fn probe(pid: u32) -> Proc {
    // `None` (cannot ask) is taken as there, which never leads to a signal.
    if pid_exists(pid) == Some(false) {
        return Proc::Gone;
    }
    match proc_stat_info(pid).or_else(|| ps_info(pid)) {
        Some(('Z' | 'X', _)) => Proc::Zombie,
        Some((_, start)) => Proc::Live(Some(start)),
        None => Proc::Live(None),
    }
}

/// A token that tells this process from any other that ever has the same pid: the start time.
/// `None` when the process is gone or its start cannot be read.
pub(crate) fn process_start(pid: u32) -> Option<String> {
    match probe(pid) {
        Proc::Live(start) => start,
        _ => None,
    }
}

/// Whether the process now at `pid` is the one recorded with `recorded_start`.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Identity {
    /// No process, or one that has ended.
    Gone,
    /// The same pid and the same start time.
    Same,
    /// Another process has the pid (the start time differs).
    Other,
    /// Running, but it cannot be told: no start time recorded, or none readable.
    Unknown,
}

pub(crate) fn identity(pid: u32, recorded_start: Option<&str>) -> Identity {
    match probe(pid) {
        Proc::Gone | Proc::Zombie => Identity::Gone,
        Proc::Live(Some(now)) => match recorded_start {
            Some(then) if then == now => Identity::Same,
            Some(_) => Identity::Other,
            None => Identity::Unknown,
        },
        Proc::Live(None) => Identity::Unknown,
    }
}

/// How a recorded group stands, from what the process table says now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GroupState {
    /// The leader is the recorded process and the group is up.
    Live,
    /// The leader is gone, but a group with its number still has members. Those are the old
    /// group's: the system does not hand a pid out while a process group of that number lives.
    Orphans,
    /// Nothing is left of it.
    Gone,
    /// It was signalled and is gone now.
    Ended,
    /// The leader's pid belongs to another process now, so the recorded group is over and its
    /// number must not be signalled.
    Replaced,
    /// The leader cannot be told from another process: nothing is signalled.
    Unverified,
    /// Signalled, SIGKILL included, and still there.
    Survived,
}

impl GroupState {
    fn name(self) -> &'static str {
        match self {
            GroupState::Live | GroupState::Orphans => "live",
            GroupState::Ended => "ended",
            GroupState::Gone => "already_gone",
            GroupState::Replaced => "replaced",
            GroupState::Unverified => "unverified",
            GroupState::Survived => "survived",
        }
    }
}

/// What ending a recorded group did.
struct GroupEnd {
    pgid: u32,
    /// `Gone` (nothing to do), `Replaced`, `Unverified`, `Ended` or `Survived`.
    state: GroupState,
    /// `TERM` and `KILL`, in the order sent. Empty when nothing was signalled.
    signals: Vec<&'static str>,
}

impl GroupEnd {
    fn to_json(&self) -> Value {
        json!({"pgid": self.pgid, "state": self.state.name(), "signals": self.signals})
    }
}

fn group_state(record: &GroupRecord) -> GroupState {
    match identity(record.leader, Some(&record.leader_start)) {
        Identity::Same => GroupState::Live,
        Identity::Other => GroupState::Replaced,
        Identity::Unknown => GroupState::Unverified,
        Identity::Gone => {
            if group_exists(record.pgid) == Some(false) {
                GroupState::Gone
            } else {
                GroupState::Orphans
            }
        }
    }
}

/// Look at the group until it is `Gone` or `Replaced`, at most `limit`. Whether it is.
fn wait_group_over(record: &GroupRecord, limit: Duration) -> bool {
    let deadline = Instant::now() + limit;
    loop {
        if matches!(group_state(record), GroupState::Gone | GroupState::Replaced) {
            return true;
        }
        if Instant::now() > deadline {
            return false;
        }
        std::thread::sleep(POLL);
    }
}

/// Remove the record file when it still holds `record`: a launch that follows an older one must
/// not lose the file to the older `host-agent` finishing late.
fn remove_record_if_ours(file: &Path, record: &GroupRecord) {
    let ours = fs::read(file)
        .ok()
        .and_then(|b| serde_json::from_slice::<GroupRecord>(&b).ok())
        .is_some_and(|on_disk| on_disk == *record);
    if ours {
        let _ = fs::remove_file(file);
    }
}

/// End the builder group recorded in `<control>/builder.group.json`, if there is one and it is
/// still the recorded group: SIGTERM, the runner's grace, SIGKILL. `None` when there is no
/// record (or one that cannot be read, which names nothing to signal). The record is removed
/// once the group is over, and kept when it survived or could not be verified.
fn end_recorded_group(control: &Path) -> Result<Option<GroupEnd>> {
    let file = control.join(GROUP_FILE);
    match fs::symlink_metadata(&file) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => bail!("cannot look at {}: {e}", file.display()),
        Ok(meta) if !meta.is_file() => return Ok(None),
        Ok(_) => {}
    }
    let record: GroupRecord = match fs::read(&file)
        .map_err(anyhow::Error::from)
        .and_then(|b| serde_json::from_slice(&b).map_err(anyhow::Error::from))
    {
        Ok(record) => record,
        Err(e) => {
            eprintln!(
                "warning: {} is not a group record, ignored: {e:#}",
                file.display()
            );
            return Ok(None);
        }
    };
    // A record that could name a process of ours or of everyone: not a group of ours.
    if record.pgid < 2 || record.leader != record.pgid || record.pgid == std::process::id() {
        eprintln!(
            "warning: {} names no builder group, ignored",
            file.display()
        );
        return Ok(None);
    }
    let mut signals = Vec::new();
    let first = group_state(&record);
    if matches!(first, GroupState::Live | GroupState::Orphans) {
        terminate_process_group(record.pgid);
        signals.push("TERM");
        if !wait_group_over(&record, TERM_GRACE) {
            // Looked at again before the second signal: the pid may have changed hands meanwhile.
            if matches!(group_state(&record), GroupState::Live | GroupState::Orphans) {
                kill_process_group(record.pgid);
                signals.push("KILL");
                wait_group_over(&record, KILL_WAIT);
            }
        }
    }
    let last = group_state(&record);
    let state = match last {
        GroupState::Gone | GroupState::Replaced => {
            remove_record_if_ours(&file, &record);
            // Said as it was found when nothing was signalled, else as ended.
            if signals.is_empty() {
                last
            } else {
                GroupState::Ended
            }
        }
        GroupState::Live | GroupState::Orphans => GroupState::Survived,
        other => other,
    };
    Ok(Some(GroupEnd {
        pgid: record.pgid,
        state,
        signals,
    }))
}

/// The builder's process group while `host-agent builder` runs it: recorded in the lane's
/// `control/builder.group.json` when it starts, SIGKILLed when dropped (so no early return
/// leaves a builder's background children running), and the record removed once the group is
/// gone.
struct Group {
    pgid: u32,
    record: Option<(PathBuf, GroupRecord)>,
}

impl Group {
    /// `pgid` is the pid of the just-spawned leader, which `builder_command` made a group
    /// leader. A leader that is already gone has nothing worth recording.
    fn start(pgid: u32, control: &Path) -> Group {
        let record = process_start(pgid).and_then(|leader_start| {
            let record = GroupRecord {
                pgid,
                leader: pgid,
                leader_start,
            };
            let file = control.join(GROUP_FILE);
            match write_json_atomic(&file, &record) {
                Ok(()) => Some((file, record)),
                Err(e) => {
                    eprintln!("warning: recording the builder's process group: {e:#}");
                    None
                }
            }
        });
        Group { pgid, record }
    }
}

impl Drop for Group {
    fn drop(&mut self) {
        kill_process_group(self.pgid);
        let Some((file, record)) = &self.record else {
            return;
        };
        let deadline = Instant::now() + GROUP_SETTLE;
        while group_exists(self.pgid) != Some(false) {
            if Instant::now() > deadline {
                // Still there (a process that cannot be killed yet): the record stays, so
                // `cleanup` finds the group.
                return;
            }
            std::thread::sleep(POLL);
        }
        remove_record_if_ours(file, record);
    }
}

/// The next SIGINT, SIGTERM or SIGHUP (the last is what a pty hangup sends).
async fn stop_signal(
    sigint: &mut tokio::signal::unix::Signal,
    sigterm: &mut tokio::signal::unix::Signal,
    sighup: &mut tokio::signal::unix::Signal,
) {
    tokio::select! {
        _ = sigint.recv() => {}
        _ = sigterm.recv() => {}
        _ = sighup.recv() => {}
    }
}

/// The director's lifeline: resolves when stdin reaches end of file or fails. It is called after
/// the spec line was read, so what is left of stdin is the open pipe the director keeps for the
/// builder's whole life; `sshd` closes it when the director's `ssh` dies, and an `ssh` without
/// a pty sends no hangup, so this is the only way the host learns. Anything the director sends
/// on it is read and ignored. A plain thread, because a blocking read cannot be cancelled and
/// must not keep the process from exiting.
fn watch_stdin() -> oneshot::Receiver<()> {
    let (tx, rx) = oneshot::channel();
    std::thread::spawn(move || {
        let mut stdin = std::io::stdin().lock();
        let mut buf = [0u8; 4096];
        loop {
            match stdin.read(&mut buf) {
                Ok(0) => break,
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => break,
            }
        }
        let _ = tx.send(());
    });
    rx
}

/// Copy the builder's stdout to ours, byte for byte, flushing each piece. Only a failure to
/// write is an error (our stdout is the SSH channel, and a broken one means the director is
/// gone); a failure to read just ends the copy.
async fn forward_stdout(mut from: tokio::process::ChildStdout) -> std::io::Result<()> {
    let mut out = tokio::io::stdout();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = match from.read(&mut buf).await {
            Ok(0) => return Ok(()),
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Ok(()),
        };
        out.write_all(&buf[..n]).await?;
        out.flush().await?;
    }
}

/// Run the launched builder to its end. Its stdout is this process's stdout; its stderr is
/// written redacted to `control/builder.stderr` by the runner's own pump. The first stop ends
/// the builder's whole process group (SIGTERM, then SIGKILL after the same grace the local
/// runner gives): a SIGINT, SIGTERM or SIGHUP, end of file on `lifeline` (the director let go
/// of stdin, or its `ssh` died), or a stdout that cannot be written. When the leader exits,
/// whatever it left running is killed. Returns the builder's exit code, or the runner's
/// interrupted code (130) after a stop.
async fn drive_builder(
    launched: BuilderLaunched,
    mut lifeline: oneshot::Receiver<()>,
) -> Result<i32> {
    use std::os::unix::process::ExitStatusExt;
    // Handlers first, so a signal between here and the spawn is not lost to the default.
    let mut sigint = signal(SignalKind::interrupt()).context("installing the SIGINT handler")?;
    let mut sigterm = signal(SignalKind::terminate()).context("installing the SIGTERM handler")?;
    let mut sighup = signal(SignalKind::hangup()).context("installing the SIGHUP handler")?;
    // Appended: a lane's launches (a resume after a park) follow each other in one file, which
    // the director fetches once at the end.
    let stderr_file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&launched.stderr_file)
        .with_context(|| format!("opening {}", launched.stderr_file.display()))?;
    let mut command = launched.command;
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("launching the builder")?;
    // `builder_command` made the child its own group leader, so its pid is the pgid.
    let pgid = child.id().context("reading the builder's process id")?;
    let _group = Group::start(pgid, &launched.control);
    let stdout = child.stdout.take().context("taking the builder's stdout")?;
    let stderr = child.stderr.take().context("taking the builder's stderr")?;
    let mut sink = tokio::fs::File::from_std(stderr_file);
    let mut pending: Vec<u8> = Vec::new();

    let mut status = None;
    let mut stderr_done = false;
    let mut stdout_done = false;
    let mut abandoned = false;
    let mut stdout_abandoned = false;
    let mut interrupted = false;
    let mut kill_at: Option<TokioInstant> = None;
    let mut drain_until: Option<TokioInstant> = None;
    {
        let pump = pump_stderr(stderr, &mut sink, &mut pending, MAX_STDERR_LINE);
        tokio::pin!(pump);
        let forward = forward_stdout(stdout);
        tokio::pin!(forward);
        while !(status.is_some() && (stderr_done || abandoned) && (stdout_done || stdout_abandoned))
        {
            tokio::select! {
                waited = child.wait(), if status.is_none() => {
                    status = Some(waited.context("waiting for the builder")?);
                    // The leader is gone: end whatever it left running, so no background
                    // child survives or holds the stderr pipe open.
                    kill_process_group(pgid);
                    kill_at = None;
                    drain_until = Some(TokioInstant::now() + PUMP_DRAIN);
                }
                result = &mut pump, if !stderr_done => {
                    stderr_done = true;
                    if let Err(e) = result {
                        eprintln!("warning: builder.stderr: {e}");
                    }
                }
                result = &mut forward, if !stdout_done => {
                    stdout_done = true;
                    if let Err(e) = result {
                        // Nobody is reading: the director is gone, so end the builder.
                        eprintln!("the builder's output cannot be delivered ({e}): ending the builder");
                        if !interrupted {
                            interrupted = true;
                            if status.is_none() {
                                terminate_process_group(pgid);
                                kill_at = Some(TokioInstant::now() + TERM_GRACE);
                            }
                        }
                    }
                }
                why = async {
                    tokio::select! {
                        _ = stop_signal(&mut sigint, &mut sigterm, &mut sighup) => "interrupted",
                        _ = &mut lifeline => "the director's stdin closed",
                    }
                }, if !interrupted => {
                    interrupted = true;
                    if status.is_none() {
                        eprintln!("{why}: ending the builder");
                        terminate_process_group(pgid);
                        kill_at = Some(TokioInstant::now() + TERM_GRACE);
                    }
                }
                _ = sleep_until_opt(kill_at), if kill_at.is_some() => {
                    kill_process_group(pgid);
                    kill_at = None;
                }
                _ = sleep_until_opt(drain_until), if drain_until.is_some() && !stderr_done && !abandoned => {
                    abandoned = true;
                }
                _ = sleep_until_opt(drain_until), if drain_until.is_some() && !stdout_done && !stdout_abandoned => {
                    stdout_abandoned = true;
                }
            }
        }
    }
    if abandoned {
        // An escaped process held the pipe: write what was read, redacted.
        let rest = redact_ready(&mut pending, MAX_STDERR_LINE, true);
        if let Err(e) = sink.write_all(&rest).await {
            eprintln!("warning: writing builder.stderr: {e}");
        }
    }
    if let Err(e) = sink.flush().await {
        eprintln!("warning: writing builder.stderr: {e}");
    }
    if interrupted {
        return Ok(INTERRUPTED_EXIT_CODE);
    }
    let status = status.context("the builder's exit status was never read")?;
    Ok(status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(0)))
}

/// What `check` reads on stdin.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckSpec {
    /// The `sh -c` command of the declared check.
    command: String,
    /// How long it may run, in seconds (at most the local `run_check` limit).
    timeout_secs: u64,
    /// The first port of the lane's block, when the lane has one.
    #[serde(default)]
    port_base: Option<u16>,
}

/// The last `max` bytes of `text`, cut at a character boundary and marked when cut.
fn tail(text: &str, max: usize) -> String {
    if text.len() <= max {
        return text.to_string();
    }
    let mut start = text.len() - max;
    while !text.is_char_boundary(start) {
        start += 1;
    }
    format!("[output truncated]\n{}", &text[start..])
}

/// Run one declared check in the lane's check sandbox, through the same `run_check_command` the
/// local `run_check` tool uses, and report it. The output is redacted whole first (so a token
/// cut by the cap cannot escape) and then capped at the local `run_check` limit, keeping the end.
async fn check(lane_id: &str, check_id: &str, root: &Path) -> Result<Value> {
    if check_id.is_empty() || check_id.len() > 128 || check_id.chars().any(char::is_control) {
        bail!("--check-id must be 1 to 128 printable characters");
    }
    let spec: CheckSpec = read_spec()?;
    if spec.command.is_empty() || spec.command.contains('\0') {
        bail!("the check command is empty or holds a NUL");
    }
    // A check may declare its own limit (up to the packet header's maximum), so the host
    // accepts what the header allows; the runner decides which limit applies.
    if spec.timeout_secs == 0 || spec.timeout_secs > cowproof_core::MAX_CHECK_TIMEOUT.as_secs() {
        bail!(
            "timeout_secs must be 1 to {} (the longest limit a check may declare)",
            cowproof_core::MAX_CHECK_TIMEOUT.as_secs()
        );
    }
    if spec.port_base.is_some_and(|p| !valid_port_base(p)) {
        bail!("port_base is outside the lanes' port blocks");
    }
    let lane_dir = lane_dir_of(lane_id, root)?;
    let home = real_home()?;
    let layout = LaneLayout::for_lane_dir(&lane_dir, home.clone())?;
    if !layout.clone.is_dir() {
        bail!("lane {lane_id} has no clone; it was not prepared");
    }
    fs::create_dir_all(lane_tmp(&layout.scratch)).context("creating the lane's temp directory")?;
    let path = builder_path(&std::env::var("PATH").unwrap_or_default(), &home);
    // Handlers first, so a signal between here and the spawn is not lost to the default.
    let mut sigint = signal(SignalKind::interrupt()).context("installing the SIGINT handler")?;
    let mut sigterm = signal(SignalKind::terminate()).context("installing the SIGTERM handler")?;
    let mut sighup = signal(SignalKind::hangup()).context("installing the SIGHUP handler")?;
    // The check is the leader of its own process group, so a signal to this process does not
    // reach it: the group set lets this process end exactly the group it started.
    let groups = GroupSet::new();
    // A remote lane takes no runtime directories (`cowproof run` refuses the combination).
    let ran = run_check_command(
        &layout,
        CheckEnv {
            path: &path,
            runtime: &[],
        },
        &spec.command,
        spec.port_base,
        Duration::from_secs(spec.timeout_secs),
        check_id,
        &groups,
    );
    tokio::pin!(ran);
    let mut interrupted = false;
    let run = tokio::select! {
        run = &mut ran => run,
        _ = stop_signal(&mut sigint, &mut sigterm, &mut sighup) => {
            // SIGTERM to the check's group, the grace, SIGKILL; the check's own future ends
            // once its shell is gone.
            interrupted = true;
            let (_, run) = tokio::join!(groups.end_all(CHECK_TERM_GRACE), &mut ran);
            run
        }
    };
    let exit_code = run.outcome.exit_status;
    let signal = match run.outcome.end {
        CheckEnd::Signaled { signal } => Some(signal),
        _ => None,
    };
    let mut output = redact(&run.outcome.output);
    if interrupted {
        output.push_str("\n[the host agent was signalled: the check was ended]\n");
    }
    Ok(json!({
        "ok": exit_code == 0 && !run.timed_out && !interrupted,
        "exit_code": exit_code,
        "timed_out": run.timed_out,
        // How the command ended and how long it ran, for the capsule's record of the check
        // (older agents lack both and the director measures the call itself).
        "signal": signal,
        "duration_ms": run.outcome.duration_ms,
        "output_tail": tail(&output, MAX_OUTPUT),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cowproof_run::lane::prepare_lane;

    fn git_in(dir: &Path, args: &[&str]) {
        git(dir, args).unwrap();
    }

    /// Whether this host can run the check sandbox (`doctor` uses the same code).
    fn can_sandbox() -> bool {
        cfg!(target_os = "macos")
            || Command::new("bwrap")
                .args(["--ro-bind", "/", "/", "true"])
                .output()
                .is_ok_and(|o| o.status.success())
    }

    /// The remote `patch` and the local runner's `capture_patch` give the same bytes for the
    /// same tree, and the remote one finds the launch commit by itself in `lane.json`.
    #[tokio::test]
    async fn patch_is_byte_identical_to_the_local_runners_capture() {
        if !can_sandbox() {
            return;
        }
        let tmp = tempfile::Builder::new()
            .prefix("cp-hostagent-unit-")
            .tempdir_in("/var/tmp")
            .unwrap();
        let home = tmp.path().join("home");
        let repo = tmp.path().join("repo");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir(&repo).unwrap();
        git_in(&repo, &["init", "-q"]);
        git_in(&repo, &["config", "user.email", "t@example.com"]);
        git_in(&repo, &["config", "user.name", "T"]);
        fs::write(repo.join("a.txt"), "one\n").unwrap();
        fs::write(repo.join("b.bin"), [0u8, 1, 2, 255]).unwrap();
        git_in(&repo, &["add", "."]);
        git_in(&repo, &["commit", "-q", "-m", "base"]);

        let root = tmp.path().join("lanes");
        let prepared =
            prepare_lane(&repo, &root, "unit", PrepareOptions { allow_dirty: false }).unwrap();
        let layout = prepared.layout.clone();
        fs::create_dir_all(cowproof_run::lane_tmp(&layout.scratch)).unwrap();
        fs::write(layout.clone.join("a.txt"), "one\ntwo\n").unwrap();
        fs::write(layout.clone.join("b.bin"), [9u8, 8, 7, 0]).unwrap();
        fs::write(layout.clone.join("c.txt"), "new\n").unwrap();

        let path = builder_path(&std::env::var("PATH").unwrap_or_default(), &home);
        let local = capture_patch(&layout, &prepared.launch_commit, &path)
            .await
            .unwrap();
        let remote = patch_with_home("unit", &root, home).await.unwrap();
        assert!(!local.is_empty());
        assert!(String::from_utf8_lossy(&local).contains("GIT binary patch"));
        assert_eq!(remote, local);
    }

    #[test]
    fn a_process_is_told_from_another_by_pid_and_start_time() {
        let me = std::process::id();
        let start = process_start(me).expect("a running process has a start time");
        assert_eq!(identity(me, Some(&start)), Identity::Same);
        assert_eq!(identity(me, Some("not-my-start")), Identity::Other);
        assert_eq!(identity(me, None), Identity::Unknown);

        let mut gone = Command::new("true").spawn().unwrap();
        let pid = gone.id();
        gone.wait().unwrap();
        assert_eq!(identity(pid, Some(&start)), Identity::Gone);
        assert_eq!(probe(pid), Proc::Gone);
        assert_eq!(process_start(pid), None);

        // Ended but not reaped: it runs nothing, so it counts as gone.
        let mut zombie = Command::new("true").spawn().unwrap();
        std::thread::sleep(Duration::from_millis(500));
        assert_eq!(identity(zombie.id(), Some(&start)), Identity::Gone);
        zombie.wait().unwrap();
    }

    #[test]
    fn a_reaped_childs_pid_probes_as_gone_whatever_the_shell() {
        let mut child = Command::new("true").spawn().unwrap();
        let pid = child.id();
        child.wait().unwrap();
        assert_eq!(probe(pid), Proc::Gone);
        assert_eq!(identity(pid, Some("proc:1")), Identity::Gone);
        assert_eq!(group_exists(pid), Some(false));
    }

    /// The shell line this crate used to ask "is it there" with. Its `--` is an error in dash
    /// (Ubuntu's `/bin/sh`): the answer is "Illegal number", never "No such process", so every
    /// dead pid read as alive. Run for the system `sh` (either message) and for `dash` itself
    /// where it is installed.
    #[test]
    fn the_old_shell_line_cannot_tell_a_dead_pid_under_dash() {
        let mut child = Command::new("true").spawn().unwrap();
        let pid = child.id().to_string();
        child.wait().unwrap();
        let ask = |shell: &Path| -> String {
            let out = Command::new(shell)
                .args(["-c", r#"kill -0 -- "$0" 2>&1"#, &pid])
                .output()
                .unwrap();
            String::from_utf8_lossy(&out.stdout).into_owned()
        };
        let sh = ask(Path::new("/bin/sh"));
        assert!(
            sh.contains("No such process") || sh.contains("Illegal number"),
            "unexpected /bin/sh answer: {sh:?}"
        );
        let dash = std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
            .map(|d| d.join("dash"))
            .find(|p| p.is_file());
        match dash {
            Some(dash) => {
                let said = ask(&dash);
                assert!(said.contains("Illegal number"), "dash said {said:?}");
                assert!(!said.contains("No such process"), "dash said {said:?}");
            }
            None => eprintln!("note: dash is not on PATH, so its kill is not exercised"),
        }
    }

    #[test]
    fn the_start_time_is_field_22_counted_after_the_last_parenthesis() {
        // A command name may hold spaces and parentheses.
        let stat = "123 (my (odd) name) S 1 123 123 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 987654 \
                    1000 100 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0";
        assert_eq!(
            parse_proc_stat(stat),
            Some(('S', "proc:987654".to_string()))
        );
        assert_eq!(parse_proc_stat("no parenthesis here"), None);
        assert_eq!(parse_proc_stat("1 (short) S 1 2"), None);
    }

    #[test]
    fn a_credential_is_found_by_key_name_or_by_shape_and_never_repeated() {
        let real = "sk-test-real-xyz-0123456789";
        for (value, at) in [
            (
                json!({"settings": {"env": {"ANTHROPIC_API_KEY": "x"}}}),
                ".settings.env.ANTHROPIC_API_KEY",
            ),
            (json!({"a": [{"note": format!("k={real}")}]}), ".a[0].note"),
            (json!({"x-auth-token": "t"}), ".x-auth-token"),
            (json!({"prompt": format!("key {real}")}), ".prompt"),
            (json!({"settings": {"h": "Bearer abcdef"}}), ".settings.h"),
            (
                json!({"placeholder_key": "sk-aaaabbbbcccc"}),
                ".placeholder_key",
            ),
        ] {
            assert_eq!(find_secret(&value, "").as_deref(), Some(at), "{value}");
        }
        for clean in [
            json!({"placeholder_key": "placeholder-0123abcd", "max_turns": 5}),
            json!({"prompt": "Send Authorization: Bearer <token> to the API."}),
            json!({"system_prompt": "bearer BEARER Bearer tokens are explained here"}),
            json!({"settings": {"permissions": {"allow": ["Bash"]}}}),
        ] {
            assert_eq!(find_secret(&clean, ""), None, "{clean}");
        }
    }

    #[test]
    fn without_bearer_rewrites_every_case_and_keeps_the_rest() {
        assert_eq!(
            without_bearer("a Bearer b BEARER c bearer"),
            "a bxarer b bxarer c bxarer"
        );
        assert_eq!(without_bearer("nothing here é"), "nothing here é");
    }

    #[test]
    fn the_output_tail_keeps_the_end_on_a_character_boundary_and_says_when_it_cut() {
        assert_eq!(tail("short", 100), "short");
        assert_eq!(tail("abcdef", 3), "[output truncated]\ndef");
        // 'é' is two bytes: a cut inside it moves forward to the next boundary.
        assert_eq!(tail("aéb", 2), "[output truncated]\nb");
    }

    #[test]
    fn a_port_block_must_start_in_the_lanes_range_and_fit() {
        assert!(valid_port_base(PORT_BASE));
        assert!(valid_port_base(PORT_BASE + PORT_BLOCK_SIZE * 3));
        assert!(!valid_port_base(PORT_BASE - 1));
        assert!(!valid_port_base(65_530));
    }

    #[test]
    fn commit_ids_are_full_lowercase_hex() {
        assert!(validate_commit_id(&"a".repeat(40)).is_ok());
        assert!(validate_commit_id(&"0".repeat(64)).is_ok());
        for bad in [
            "",
            "HEAD",
            "--upload-pack=x",
            &"A".repeat(40),
            &"a".repeat(39),
        ] {
            assert!(validate_commit_id(bad).is_err(), "{bad}");
        }
    }
}

/// `--forced`: the parser reads back exactly what the director's `agent_command` writes, and
/// refuses everything else (see `tests/host_agent.rs` for the real binary).
#[cfg(test)]
mod forced_tests {
    use super::*;
    use crate::remote::{RemoteHost, agent_command, sh_quote};
    use clap::CommandFactory;
    use clap::error::ErrorKind;
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    fn host() -> RemoteHost {
        RemoteHost {
            alias: "h".into(),
            ssh: "h".into(),
            cowproof: "/opt/my bin/it's/cowproof".into(),
            claude: "/usr/bin/claude".into(),
            root: Some("lanes dir/é \"x\"".into()),
        }
    }

    fn awkward() -> Vec<String> {
        [
            "plain",
            "with space",
            "it's",
            "'",
            "''",
            "a'b'c",
            "é ü 日本",
            "$(id)",
            "`id`",
            "a;b|c&d",
            "say \"hi\"",
            "back\\slash",
            "*?[x]",
            "~/x",
            "",
            "-x=y",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect()
    }

    fn forced(text: &str) -> Result<HostAgentAction, Refusal> {
        forced_action(Some(OsString::from(text)))
    }

    #[test]
    fn what_agent_command_writes_is_read_back_word_for_word_for_every_verb() {
        let host = host();
        for verb in VERBS {
            let line = agent_command(&host, verb, &awkward());
            let words = split_command(&line).unwrap_or_else(|e| panic!("{verb}: {e:?}: {line}"));
            let mut expect = vec![host.cowproof.clone(), "host-agent".into(), verb.to_string()];
            expect.extend(awkward());
            expect.push("--root".into());
            expect.push(host.root.clone().unwrap());
            assert_eq!(words, expect, "{verb}: {line}");
        }
        // No `--root`, no arguments.
        let bare = RemoteHost { root: None, ..host };
        assert_eq!(
            split_command(&agent_command(&bare, "doctor", &[])).unwrap(),
            vec![
                bare.cowproof.clone(),
                "host-agent".to_string(),
                "doctor".to_string()
            ]
        );
    }

    #[test]
    fn sh_quote_and_the_parser_agree_on_any_text() {
        // Every pair of characters from a set that holds the bare ones, every quote-like one
        // and a multi-byte one.
        let set: Vec<char> = "aZ09_./:=@%+,- '\"\\$`;|&<>*?é".chars().collect();
        for a in &set {
            for b in &set {
                let text = format!("{a}{b}");
                assert_eq!(
                    split_command(&sh_quote(&text)).unwrap(),
                    vec![text.clone()],
                    "{text:?}"
                );
            }
        }
        assert_eq!(split_command("''").unwrap(), vec![String::new()]);
        assert_eq!(split_command("'a b' c").unwrap(), vec!["a b", "c"]);
    }

    #[test]
    fn a_character_a_shell_would_read_is_never_part_of_a_bare_word() {
        for c in ";|&<>$`\"\\*?[]{}()~#!^'\t\n\r\0\u{7f}é".chars() {
            for text in [format!("a{c}b"), format!("{c}ab"), format!("ab{c}")] {
                assert!(split_command(&text).is_err(), "{text:?} was accepted");
            }
        }
        // Quoted, the same characters are plain text (except a control character).
        assert_eq!(
            split_command("'a;b|c$d`e\"f\\g*h'").unwrap(),
            vec!["a;b|c$d`e\"f\\g*h"]
        );
        assert_eq!(split_command("'a\nb'"), Err(Refusal::Control));
        assert_eq!(split_command("'a\tb'"), Err(Refusal::Control));
    }

    #[test]
    fn a_command_that_is_not_one_cowproof_wrote_is_refused_for_the_right_reason() {
        let cases: [(&str, Refusal); 32] = [
            ("bash", Refusal::Program),
            ("cowproof host-agent prepare; rm -rf ~", Refusal::Syntax),
            ("cowproof host-agent prepare && id", Refusal::Syntax),
            ("cowproof host-agent doctor | sh", Refusal::Syntax),
            ("cowproof host-agent doctor > /x", Refusal::Syntax),
            ("cowproof host-agent doctor *", Refusal::Syntax),
            ("$(id)", Refusal::Syntax),
            ("`id`", Refusal::Syntax),
            ("cowproof host-agent doctor $HOME", Refusal::Syntax),
            ("cowproof run x", Refusal::NotHostAgent),
            ("cowproof", Refusal::NotHostAgent),
            ("cowproof host-agent", Refusal::Verb),
            ("cowproof host-agent shell", Refusal::Verb),
            ("cowproof host-agent help", Refusal::Verb),
            ("cowproof host-agent --forced doctor", Refusal::ForcedFlag),
            ("cowproof host-agent doctor --forced", Refusal::ForcedFlag),
            ("cowproof host-agent doctor '--forced'", Refusal::ForcedFlag),
            ("", Refusal::NoCommand),
            ("cowproof-evil host-agent doctor", Refusal::Program),
            ("/x/cowproof/ host-agent doctor", Refusal::Program),
            ("/x/notcowproof host-agent doctor", Refusal::Program),
            ("cowproof host-agent \"doctor\"", Refusal::Syntax),
            ("cowproof host-agent doctor 'open", Refusal::Syntax),
            ("cowproof host-agent doctor 'a'b", Refusal::Syntax),
            ("cowproof  host-agent doctor", Refusal::Syntax),
            (" cowproof host-agent doctor", Refusal::Syntax),
            ("cowproof host-agent doctor ", Refusal::Syntax),
            ("cowproof host-agent doctor\nid", Refusal::Control),
            ("cowproof\thost-agent doctor", Refusal::Control),
            (
                "cowproof host-agent cleanup",
                Refusal::Arguments(ErrorKind::MissingRequiredArgument),
            ),
            (
                "cowproof host-agent doctor --nonsense",
                Refusal::Arguments(ErrorKind::UnknownArgument),
            ),
            (
                "cowproof host-agent doctor --help",
                Refusal::Arguments(ErrorKind::DisplayHelp),
            ),
        ];
        for (text, why) in cases {
            assert_eq!(forced(text).err(), Some(why), "{text:?}");
        }
        assert_eq!(forced_action(None).err(), Some(Refusal::NoCommand));
        assert_eq!(
            forced_action(Some(OsString::from_vec(
                b"cowproof host-agent \xff".to_vec()
            )))
            .err(),
            Some(Refusal::NotUtf8)
        );
    }

    #[test]
    fn a_refusal_never_quotes_the_command() {
        let hostile = "cowproof host-agent doctor; echo SECRET-MARKER-12345";
        let message = forced(hostile).err().unwrap().to_string();
        assert!(!message.contains("SECRET-MARKER"), "{message}");
        let message = forced("cowproof host-agent doctor --SECRET-MARKER-12345")
            .err()
            .unwrap()
            .to_string();
        assert!(!message.contains("SECRET-MARKER"), "{message}");
    }

    #[test]
    fn each_verb_in_the_form_the_director_writes_parses_to_that_verb() {
        let host = host();
        let sha = "a".repeat(40);
        let line = |verb: &str, args: &[&str]| {
            let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
            agent_command(&host, verb, &args)
        };
        let root = host.root.clone().map(PathBuf::from);
        match forced(&line("doctor", &["--claude-bin", "/o k/it's/claude"])).unwrap() {
            HostAgentAction::Doctor {
                claude_bin,
                root: r,
            } => {
                assert_eq!(claude_bin.as_deref(), Some("/o k/it's/claude"));
                assert_eq!(r, root);
            }
            _ => panic!("not doctor"),
        }
        match forced(&line(
            "prepare",
            &[
                "--lane-id",
                "l-1",
                "--base",
                &sha,
                "--director-version",
                "0.1.0",
                "--protocol",
                "2",
            ],
        ))
        .unwrap()
        {
            HostAgentAction::Prepare {
                lane_id,
                base,
                protocol,
                ..
            } => {
                assert_eq!(
                    (lane_id.as_str(), base.as_str(), protocol),
                    ("l-1", sha.as_str(), Some(2))
                );
            }
            _ => panic!("not prepare"),
        }
        assert!(matches!(
            forced(&line("builder", &["--lane-id", "l-1"])).unwrap(),
            HostAgentAction::Builder { .. }
        ));
        assert!(matches!(
            forced(&line("check", &["--lane-id", "l-1", "--check-id", "c 1"])).unwrap(),
            HostAgentAction::Check { .. }
        ));
        assert!(matches!(
            forced(&line("patch", &["--lane-id", "l-1"])).unwrap(),
            HostAgentAction::Patch { .. }
        ));
        assert!(matches!(
            forced(&line("stderr", &["--lane-id", "l-1"])).unwrap(),
            HostAgentAction::Stderr { .. }
        ));
        assert!(matches!(
            forced(&line("cleanup", &["--lane-id", "l-1"])).unwrap(),
            HostAgentAction::Cleanup { .. }
        ));
    }

    fn owners_config() -> HostConfig {
        HostConfig {
            claude: PathBuf::from("/opt/cp/claude"),
            root: PathBuf::from("/srv/cp lanes"),
        }
    }

    fn doctor_args(claude_bin: Option<&str>, root: Option<&str>) -> HostAgentAction {
        HostAgentAction::Doctor {
            claude_bin: claude_bin.map(str::to_string),
            root: root.map(PathBuf::from),
        }
    }

    #[test]
    fn a_pin_fills_in_what_the_director_left_out_and_accepts_only_the_owners_value() {
        let cfg = owners_config();
        // Left out: the owner's.
        match pin(doctor_args(None, None), &cfg).unwrap() {
            HostAgentAction::Doctor { claude_bin, root } => {
                assert_eq!(claude_bin.as_deref(), Some("/opt/cp/claude"));
                assert_eq!(root, Some(cfg.root.clone()));
            }
            _ => panic!("not doctor"),
        }
        // Repeated, in any spelling that is the same path: accepted.
        assert!(
            pin(
                doctor_args(Some("/opt/cp/claude"), Some("/srv/cp lanes")),
                &cfg
            )
            .is_ok()
        );
        assert!(
            pin(
                doctor_args(Some("/opt/cp//claude"), Some("/srv/cp lanes/")),
                &cfg
            )
            .is_ok()
        );
        // Anything else is refused, each naming its own argument.
        for (claude_bin, root, why) in [
            (Some("claude"), None, Pin::ClaudeBin),
            (Some("/opt/cp/claude2"), None, Pin::ClaudeBin),
            (Some("/opt/cp/../cp/claude"), None, Pin::ClaudeBin),
            (None, Some("/srv/other"), Pin::Root),
            (None, Some("/srv/cp lanes/../x"), Pin::Root),
            (None, Some("lanes"), Pin::Root),
        ] {
            assert_eq!(
                pin(doctor_args(claude_bin, root), &cfg).err(),
                Some(why),
                "{claude_bin:?} {root:?}"
            );
        }
        // The other verbs get the owner's root, and refuse another.
        let patch = |root: Option<&str>| HostAgentAction::Patch {
            lane_id: "l".to_string(),
            root: root.map(PathBuf::from),
        };
        assert!(matches!(
            pin(patch(None), &cfg).unwrap(),
            HostAgentAction::Patch { root: Some(r), .. } if r == cfg.root
        ));
        assert_eq!(pin(patch(Some("/x")), &cfg).err(), Some(Pin::Root));
    }

    #[test]
    fn a_pin_refusal_names_the_argument_and_never_the_value() {
        for pin in [Pin::Root, Pin::ClaudeBin, Pin::SpecClaudeBin] {
            let text = pin.to_string();
            assert!(text.contains("host.toml"), "{text}");
        }
        assert!(Pin::Root.to_string().contains("--root"));
        assert!(Pin::ClaudeBin.to_string().contains("--claude-bin"));
        assert!(Pin::SpecClaudeBin.to_string().contains("claude_bin"));
    }

    #[test]
    fn the_closed_set_is_the_set_of_verbs_clap_knows() {
        let mut known: Vec<String> = HostAgentArgs::command()
            .get_subcommands()
            .map(|c| c.get_name().to_string())
            .filter(|n| n != "help")
            .collect();
        known.sort();
        let mut closed: Vec<String> = VERBS.iter().map(|v| v.to_string()).collect();
        closed.sort();
        assert_eq!(known, closed);
    }
}
