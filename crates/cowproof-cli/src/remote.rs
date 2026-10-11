//! The SSH transport of a remote lane (D24, D27), director side.
//!
//! `cowproof run --host <alias>` keeps everything that decides on the director (the queue and
//! its rulings, the egress proxy and so the real API key, the proof) and sends only the
//! sandboxed processes to another machine. This module is the one place that talks to `ssh`:
//!
//! - one control master per lane, started in the background and stopped at the lane's end
//!   whatever the outcome;
//! - every remote step is `ssh -S <control>/ssh.ctl <target> '<cowproof>' host-agent <verb> ...`,
//!   a verb of the closed set in `host_agent.rs`, through that master;
//! - the lane's `proxy.sock` and `sock/runner.sock` are forwarded to the remote lane with
//!   `ssh -O forward -R <remote>:<local>`, after `prepare` has made the remote lane directory
//!   (the Linux sandbox binds a socket only when the file exists, so they must exist before the
//!   builder starts);
//! - the remote cowproof is told what to do by a JSON spec on stdin, never by the environment.
//!   A spec holds the lane's own `placeholder-...` key, which only the director's proxy
//!   accepts; the real key is not in any argv, spec, bundle or environment sent to the host;
//! - the builder's stdin is a lifeline: the spec is one line, and the director keeps the pipe
//!   open for as long as the builder should live. An `ssh` without a pty sends no hangup when
//!   it dies, but the host's `sshd` closes the command's stdin, and `host-agent builder` ends
//!   its process group when it sees end of file ([`hold_lifeline`]);
//! - the director's `base.patch` (an `--allow-dirty` lane) travels with the git bundle on
//!   `prepare`'s stdin, so the host's lane starts from the same tree as the local one;
//! - before the host's lane is removed, its redacted `control/builder.stderr` is fetched
//!   (`host-agent stderr`), redacted again here, and appended to the lane's own, whatever the
//!   outcome ([`RemoteLane::finish_blocking`]).
//!
//! Every ssh argument list is built by [`ssh_argv`] and every remote command line by
//! [`agent_command`], so the exact bytes are unit-tested here.

use crate::host_agent::{HOST_PROTOCOL, MAX_STDERR_FETCH};
use anyhow::{Context, Result, anyhow, bail};
use cowproof_core::redact;
use cowproof_run::tools::CheckOutcome;
use serde_json::{Value, json};
use std::fs;
use std::io::{Read as _, Write as _};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

/// How long a new control master may take to be usable (authentication included).
const MASTER_READY: Duration = Duration::from_secs(30);
/// `host-agent doctor` runs a sandboxed `true` and `claude --version`.
const DOCTOR_TIMEOUT: Duration = Duration::from_secs(120);
/// Sending the bundle and building the remote lane (clone, launch baseline).
const PREPARE_TIMEOUT: Duration = Duration::from_secs(30 * 60);
/// `host-agent patch` stages the lane and prints the diff.
const PATCH_TIMEOUT: Duration = Duration::from_secs(10 * 60);
/// One `-O forward` or `-O check` request to the master.
const CONTROL_TIMEOUT: Duration = Duration::from_secs(30);
/// Removing the remote lane at the end.
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(60);
/// Fetching the builder's stderr before that: a dead link must not hold the lane's end.
const STDERR_TIMEOUT: Duration = Duration::from_secs(20);
/// Stopping the master: the request, then how long the process gets before it is killed.
const EXIT_TIMEOUT: Duration = Duration::from_secs(10);
const MASTER_EXIT_WAIT: Duration = Duration::from_secs(5);
/// What a remote check may take beyond its own timeout, which `host-agent check` enforces:
/// a link that has died must not hold the lane forever.
const CHECK_SLACK: Duration = Duration::from_secs(60);
/// The longest a Unix socket path may be on macOS, with ssh's own suffix on the control path
/// (a dot and sixteen random characters) added while it sets the master up.
const SOCKET_PATH_MAX: usize = 104;
const SSH_SUFFIX: usize = 17;

/// One entry of the hosts config, as `cowproof run --host` needs it (D27).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RemoteHost {
    pub alias: String,
    /// The ssh destination (`ssh` in the entry, else the alias): a `Host` from the user's ssh
    /// config or `user@host`.
    pub ssh: String,
    /// The absolute path of `cowproof` on the host.
    pub cowproof: String,
    /// The absolute path of `claude` on the host.
    pub claude: String,
    /// `--root` for `host-agent`, or `None` for its own default
    /// (`~/.cache/cowproof/remote-lanes`). Absolute, or relative to the host's home directory,
    /// where ssh starts every command.
    pub root: Option<String>,
}

fn field<'a>(value: &'a Value, names: &[&str]) -> Option<&'a Value> {
    names.iter().find_map(|n| value.get(*n))
}

/// A config string that goes into a command line: present, printable, no NUL or newline.
fn clean(alias: &str, name: &str, value: &Value) -> Result<String> {
    let text = value
        .as_str()
        .ok_or_else(|| anyhow!("host {alias:?}: {name} must be a string"))?;
    if text.is_empty() || text.chars().any(char::is_control) {
        bail!("host {alias:?}: {name} must be a non-empty printable string");
    }
    Ok(text.to_string())
}

fn absolute(alias: &str, name: &str, value: Option<&Value>) -> Result<String> {
    let value = value.ok_or_else(|| {
        anyhow!("host {alias:?} has no {name}: add the absolute path of {name} on that host to the hosts config")
    })?;
    let text = clean(alias, name, value)?;
    if !text.starts_with('/') {
        bail!("host {alias:?}: {name} must be an absolute path on the host, not {text:?}");
    }
    Ok(text)
}

impl RemoteHost {
    /// Read and check one entry. Nothing is run and no host is reached.
    pub(crate) fn from_config(alias: &str, entry: &Value) -> Result<Self> {
        if alias == "local" {
            bail!("host \"local\" is this machine: leave out --host to run a lane here");
        }
        if !entry.is_object() {
            bail!("host {alias:?}: the entry must be a JSON object");
        }
        let ssh = match entry.get("ssh") {
            Some(v) => clean(alias, "ssh", v)?,
            None => alias.to_string(),
        };
        // A destination is a word: one that starts with `-` would be read by ssh as an option
        // (`-oProxyCommand=...`), and one with a space is not a destination.
        if ssh.starts_with('-') || ssh.chars().any(char::is_whitespace) {
            bail!("host {alias:?}: ssh must be a destination, not {ssh:?}");
        }
        let root = match field(entry, &["remoteRoot", "remote_root"]) {
            None => None,
            Some(v) => Some(root_arg(alias, &clean(alias, "remoteRoot", v)?)?),
        };
        Ok(RemoteHost {
            alias: alias.to_string(),
            ssh,
            cowproof: absolute(alias, "cowproof", entry.get("cowproof"))?,
            claude: absolute(alias, "claude", entry.get("claude"))?,
            root,
        })
    }
}

/// `remoteRoot` as `--root`: ssh starts a command in the host's home directory, and
/// `host-agent` takes a relative root from there, so `~/x` is sent as `x`.
fn root_arg(alias: &str, root: &str) -> Result<String> {
    if root == "~" {
        return Ok(".".to_string());
    }
    if let Some(rest) = root.strip_prefix("~/") {
        let rest = rest.trim_end_matches('/');
        let rest = if rest.is_empty() { "." } else { rest };
        return Ok(rest.to_string());
    }
    if root.starts_with('/') {
        return Ok(root.to_string());
    }
    bail!("host {alias:?}: remoteRoot must be absolute or start with ~/, not {root:?}")
}

/// `text` as one shell word for the host's login shell, which re-parses what ssh sends.
pub(crate) fn sh_quote(text: &str) -> String {
    let safe = |c: char| {
        c.is_ascii_alphanumeric()
            || matches!(c, '_' | '.' | '/' | ':' | '=' | '@' | '%' | '+' | ',' | '-')
    };
    if !text.is_empty() && text.chars().all(safe) {
        text.to_string()
    } else {
        format!("'{}'", text.replace('\'', "'\\''"))
    }
}

/// The command line the host's shell runs for one `host-agent` verb:
/// `'<cowproof>' host-agent <verb> <args> [--root <root>]`, every word quoted. ssh joins its
/// trailing arguments with spaces and hands the result to the shell, so one quoted string is
/// sent and nothing in a lane id, a path or a check id can add a word or a command.
pub(crate) fn agent_command(host: &RemoteHost, verb: &str, args: &[String]) -> String {
    let mut words = vec![
        sh_quote(&host.cowproof),
        "host-agent".to_string(),
        verb.to_string(),
    ];
    words.extend(args.iter().map(|a| sh_quote(a)));
    if let Some(root) = &host.root {
        words.push("--root".to_string());
        words.push(sh_quote(root));
    }
    words.join(" ")
}

/// One thing the director asks of ssh.
pub(crate) enum Step<'a> {
    /// The lane's control master.
    Master,
    /// Is the master up?
    Check,
    /// Stop the master.
    Exit,
    /// Forward the host's socket `remote` to the director's socket `local`.
    Forward { remote: &'a str, local: &'a str },
    /// Run one `host-agent` verb on the host.
    Agent { verb: &'a str, args: &'a [String] },
}

/// The arguments of the one `ssh` invocation a step is (everything after the program name).
/// Every ssh the director starts is built here.
pub(crate) fn ssh_argv(host: &RemoteHost, control: &Path, step: &Step<'_>) -> Vec<String> {
    let ctl = control.to_string_lossy().into_owned();
    let words = |list: &[&str]| list.iter().map(|w| (*w).to_string()).collect::<Vec<_>>();
    match step {
        // `-M` with `-N`: a master that runs no command and stays until it is stopped.
        // BatchMode so a master that needs a password fails instead of asking (the owner signs
        // in on the host beforehand; cowproof never types a secret), and keep-alive so a link
        // that dies is noticed instead of hanging a lane.
        Step::Master => {
            let mut argv = words(&["-M", "-S"]);
            argv.push(ctl);
            argv.extend(words(&[
                "-o",
                "ControlPersist=no",
                "-o",
                "StreamLocalBindUnlink=yes",
                "-o",
                "ExitOnForwardFailure=yes",
                "-o",
                "BatchMode=yes",
                "-o",
                "ServerAliveInterval=15",
                "-o",
                "ServerAliveCountMax=4",
                "-N",
            ]));
            argv.push(host.ssh.clone());
            argv
        }
        Step::Check | Step::Exit => {
            let mut argv = words(&["-S"]);
            argv.push(ctl);
            argv.extend(words(&[
                "-O",
                if matches!(step, Step::Check) {
                    "check"
                } else {
                    "exit"
                },
            ]));
            argv.push(host.ssh.clone());
            argv
        }
        Step::Forward { remote, local } => {
            let mut argv = words(&["-S"]);
            argv.push(ctl);
            argv.extend(words(&["-O", "forward", "-R"]));
            argv.push(format!("{remote}:{local}"));
            argv.push(host.ssh.clone());
            argv
        }
        Step::Agent { verb, args } => {
            let mut argv = words(&["-S"]);
            argv.push(ctl);
            argv.extend(words(&["-o", "BatchMode=yes", "-T"]));
            argv.push(host.ssh.clone());
            argv.push(agent_command(host, verb, args));
            argv
        }
    }
}

/// Everything about one builder launch that the director decides: `host-agent builder`'s
/// `BuilderSpec`, without a credential.
pub(crate) struct BuilderSpecParts<'a> {
    pub model: &'a str,
    pub prompt: &'a str,
    pub system_prompt: &'a str,
    pub settings: &'a Value,
    pub resume_session_id: Option<&'a str>,
    /// The lane's own placeholder key, which the director's proxy swaps for the real one.
    pub placeholder_key: &'a str,
    pub bridge_port: u16,
    pub port_base: u16,
    pub max_turns: u32,
    /// The `claude` executable on the host.
    pub claude_bin: &'a str,
}

pub(crate) fn builder_spec(p: &BuilderSpecParts<'_>) -> Value {
    let mut spec = json!({
        "model": p.model,
        "prompt": p.prompt,
        "system_prompt": p.system_prompt,
        "settings": p.settings,
        "placeholder_key": p.placeholder_key,
        "bridge_port": p.bridge_port,
        "port_base": p.port_base,
        "max_turns": p.max_turns,
        "claude_bin": p.claude_bin,
    });
    if let Some(id) = p.resume_session_id {
        spec["resume_session_id"] = json!(id);
    }
    spec
}

/// The spec as `host-agent builder` reads it: one line of compact JSON (which holds no raw
/// newline) ended by `\n`. The pipe must stay open after it (see [`hold_lifeline`]).
pub(crate) fn spec_line(spec: &Value) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec(spec).context("serializing the builder spec")?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// Write the spec line to the builder's ssh and then hold its stdin open until the task is
/// aborted or dropped, which is when the builder's launch ends: the host takes end of file on
/// it as the order to stop the builder, whether the director let go on purpose or its `ssh`
/// died. If the write fails, `ssh` is already gone and the pipe is released at once.
pub(crate) async fn hold_lifeline(mut stdin: tokio::process::ChildStdin, line: Vec<u8>) {
    if stdin.write_all(&line).await.is_ok() && stdin.flush().await.is_ok() {
        std::future::pending::<()>().await;
    }
}

/// The header line that starts `prepare`'s stdin: how many bytes of base patch follow it
/// (the bundle follows those, to end of file).
fn prepare_header(patch_bytes: usize) -> Vec<u8> {
    format!("{}\n", json!({"patch_bytes": patch_bytes})).into_bytes()
}

/// `host-agent check`'s `CheckSpec`.
pub(crate) fn check_spec(command: &str, timeout_secs: u64, port_base: Option<u16>) -> Value {
    let mut spec = json!({"command": command, "timeout_secs": timeout_secs});
    if let Some(port) = port_base {
        spec["port_base"] = json!(port);
    }
    spec
}

/// The last non-empty line of `stdout` as JSON. A login shell may print before the verb does.
fn last_json(stdout: &[u8]) -> Option<Value> {
    String::from_utf8_lossy(stdout)
        .lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .and_then(|l| serde_json::from_str(l).ok())
}

/// The last few lines of ssh's stderr, for a message.
fn stderr_tail(stderr: &[u8]) -> String {
    let text = String::from_utf8_lossy(stderr);
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    lines[lines.len().saturating_sub(5)..].join("; ")
}

fn exit_text(status: &std::process::ExitStatus) -> String {
    status
        .code()
        .map_or_else(|| "a signal".to_string(), |c| format!("exit {c}"))
}

/// A finished ssh, with its output.
struct Ran {
    status: std::process::ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

impl Ran {
    /// The verb's `{"ok": true, ...}`, or the reason it was not.
    fn verb_json(&self, what: &str) -> Result<Value> {
        let Some(value) = last_json(&self.stdout) else {
            bail!(
                "{what}: the host gave no JSON ({}): {}",
                exit_text(&self.status),
                stderr_tail(&self.stderr)
            );
        };
        if value["ok"] != true {
            bail!(
                "{what}: {}",
                value["error"].as_str().unwrap_or("the host refused")
            );
        }
        Ok(value)
    }
}

/// Start `ssh <args>` with `input` (if any) on stdin, and wait at most `timeout`.
async fn run_ssh(args: &[String], input: Option<Vec<u8>>, timeout: Duration) -> Result<Ran> {
    let mut child = Command::new("ssh")
        .args(args)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .context("starting ssh")?;
    if let Some(bytes) = input
        && let Some(mut stdin) = child.stdin.take()
    {
        // Written on its own task: a spec larger than the pipe must not wait for ssh to read
        // it before the output is collected.
        tokio::spawn(async move {
            let _ = stdin.write_all(&bytes).await;
            let _ = stdin.shutdown().await;
        });
    }
    let out = tokio::time::timeout(timeout, child.wait_with_output())
        .await
        .map_err(|_| anyhow!("ssh did not finish in {timeout:?}"))?
        .context("waiting for ssh")?;
    Ok(Ran {
        status: out.status,
        stdout: out.stdout,
        stderr: out.stderr,
    })
}

/// What the director tells `RemoteLane::open` about its own side of the lane.
pub(crate) struct LocalSide<'a> {
    /// The repository the lane is cut from.
    pub repo: &'a Path,
    /// The lane's base commit (the repository's HEAD when the lane was prepared).
    pub base_commit: &'a str,
    /// The lane's `base.patch` (an `--allow-dirty` lane with changes), the same bytes the local
    /// proof applies. The host applies it on top of the base before its launch baseline.
    pub base_patch: Option<&'a [u8]>,
    /// The files the local launch baseline removed. The host must remove the same ones, or the
    /// patch it returns would not apply to the tree the proof rebuilds.
    pub launch_removed: &'a [String],
    /// The egress proxy's socket, `<lane>/proxy.sock`.
    pub proxy_socket: &'a Path,
    /// The builder tools socket, `<lane>/sock/runner.sock`.
    pub runner_socket: &'a Path,
}

#[derive(Default)]
struct State {
    master: Option<std::process::Child>,
    /// `prepare` was started, so `cleanup` must run (it is idempotent).
    prepare_attempted: bool,
    /// The absolute lane directory on the host, as `prepare` reported it.
    remote_dir: Option<PathBuf>,
    /// A builder was started there, so it has a `builder.stderr` worth fetching.
    builder_started: bool,
    finished: bool,
}

/// One lane's connection to its host.
pub(crate) struct RemoteLane {
    host: RemoteHost,
    lane_id: String,
    /// `<control>/ssh.ctl`
    ctl: PathBuf,
    control: PathBuf,
    state: Mutex<State>,
}

impl RemoteLane {
    pub(crate) fn new(host: RemoteHost, lane_id: &str, control: &Path) -> Result<Arc<Self>> {
        let ctl = control.join("ssh.ctl");
        if ctl.as_os_str().len() + SSH_SUFFIX >= SOCKET_PATH_MAX {
            bail!(
                "the control socket path {} is too long for a Unix socket; use a shorter --lanes-root",
                ctl.display()
            );
        }
        if ctl.to_str().is_none() {
            bail!(
                "the control socket path {} is not valid UTF-8",
                ctl.display()
            );
        }
        Ok(Arc::new(RemoteLane {
            host,
            lane_id: lane_id.to_string(),
            ctl,
            control: control.to_path_buf(),
            state: Mutex::new(State::default()),
        }))
    }

    pub(crate) fn alias(&self) -> &str {
        &self.host.alias
    }

    /// The `claude` the host runs.
    pub(crate) fn claude(&self) -> &str {
        &self.host.claude
    }

    /// The lane directory on the host, once `prepare` has reported it.
    pub(crate) fn remote_dir(&self) -> Option<PathBuf> {
        self.lock().remote_dir.clone()
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn argv(&self, step: &Step<'_>) -> Vec<String> {
        ssh_argv(&self.host, &self.ctl, step)
    }

    fn lane_args(&self) -> Vec<String> {
        vec!["--lane-id".to_string(), self.lane_id.clone()]
    }

    /// The whole setup, in the order that matters: master, doctor, prepare, forwards. A failing
    /// doctor stops it before any lane exists on the host. On an error the caller calls
    /// [`RemoteLane::finish`].
    pub(crate) async fn open(&self, side: &LocalSide<'_>) -> Result<()> {
        self.start_master().await?;
        self.doctor().await?;
        self.prepare(side).await?;
        self.forward(side).await
    }

    async fn start_master(&self) -> Result<()> {
        let log = fs::File::create(self.control.join("ssh-master.log"))
            .context("creating ssh-master.log")?;
        let child = std::process::Command::new("ssh")
            .args(self.argv(&Step::Master))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(log))
            // Its own group: a terminal's Ctrl-C ends the run through the runner's signal
            // handling, which stops the master last, not through the master dying first.
            .process_group(0)
            .spawn()
            .context("starting the ssh control master")?;
        self.lock().master = Some(child);
        let deadline = Instant::now() + MASTER_READY;
        loop {
            let exited = self
                .lock()
                .master
                .as_mut()
                .map(|m| m.try_wait())
                .transpose()
                .context("watching the ssh control master")?
                .flatten();
            if let Some(status) = exited {
                let log = fs::read(self.control.join("ssh-master.log")).unwrap_or_default();
                bail!(
                    "the ssh control master to {} ended ({}): {}",
                    self.host.ssh,
                    exit_text(&status),
                    stderr_tail(&log)
                );
            }
            if let Ok(ran) = run_ssh(&self.argv(&Step::Check), None, CONTROL_TIMEOUT).await
                && ran.status.success()
            {
                return Ok(());
            }
            if Instant::now() > deadline {
                bail!(
                    "the ssh control master to {} was not ready in {MASTER_READY:?}",
                    self.host.ssh
                );
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// `host-agent doctor`: the host's version, `claude` and sandbox. A failure is an
    /// infrastructure failure, before a lane exists there.
    async fn doctor(&self) -> Result<()> {
        let args = vec!["--claude-bin".to_string(), self.host.claude.clone()];
        let ran = run_ssh(
            &self.argv(&Step::Agent {
                verb: "doctor",
                args: &args,
            }),
            None,
            DOCTOR_TIMEOUT,
        )
        .await?;
        let Some(report) = last_json(&ran.stdout) else {
            bail!(
                "remote doctor on {}: the host gave no JSON ({}): {}",
                self.host.alias,
                exit_text(&ran.status),
                stderr_tail(&ran.stderr)
            );
        };
        if report["error"].as_str().is_none() {
            let theirs = report["protocol"].as_u64();
            if theirs != Some(u64::from(HOST_PROTOCOL)) {
                bail!(
                    "remote doctor on {}: the host speaks host-agent protocol {} and this cowproof \
                     speaks {HOST_PROTOCOL}; install the same cowproof build on both",
                    self.host.alias,
                    theirs.map_or("1 (it reports none: an older cowproof)".to_string(), |p| p
                        .to_string())
                );
            }
        }
        if report["ok"] == true {
            return Ok(());
        }
        let detail = |ok: &str, text: &str| -> String {
            format!(
                "{}: {}",
                ok,
                report[text].as_str().unwrap_or("not reported")
            )
        };
        if let Some(error) = report["error"].as_str() {
            bail!("remote doctor on {}: {error}", self.host.alias);
        }
        bail!(
            "remote doctor on {} failed: {}; {}",
            self.host.alias,
            detail("claude", "claude_detail"),
            detail("sandbox", "sandbox_detail")
        )
    }

    /// `host-agent prepare`: the base patch and the base as a git bundle on stdin (a header
    /// line with the patch's length, the patch, then the bundle to end of file). The lane the
    /// host builds must agree with the local one about the base, the base patch and the launch
    /// baseline, or the patch it returns would not apply to the tree the proof rebuilds.
    async fn prepare(&self, side: &LocalSide<'_>) -> Result<()> {
        self.lock().prepare_attempted = true;
        // `git bundle create` takes a ref, not a bare object name, and the lane's base is the
        // repository's HEAD at the time the lane was prepared: say so if it has moved.
        let head = git_output(side.repo, &["rev-parse", "HEAD"]).await?;
        if head != side.base_commit {
            bail!(
                "the repository's HEAD is {head}, not the lane's base {}; it moved during the run",
                side.base_commit
            );
        }
        let mut args = self.lane_args();
        args.extend(
            [
                "--base",
                side.base_commit,
                "--director-version",
                env!("CARGO_PKG_VERSION"),
            ]
            .map(String::from),
        );
        args.extend(["--protocol".to_string(), HOST_PROTOCOL.to_string()]);
        let patch: Vec<u8> = side.base_patch.map(<[u8]>::to_vec).unwrap_or_default();
        let header = prepare_header(patch.len());
        let ssh_args = self.argv(&Step::Agent {
            verb: "prepare",
            args: &args,
        });

        let mut git = Command::new("git")
            .arg("-C")
            .arg(side.repo)
            .args(["bundle", "create", "-", "HEAD"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .context("starting git bundle")?;
        let mut ssh = Command::new("ssh")
            .args(&ssh_args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .context("starting ssh")?;
        let mut bundle = git.stdout.take().context("taking git's stdout")?;
        let mut git_stderr = git.stderr.take().context("taking git's stderr")?;
        let mut ssh_stdin = ssh.stdin.take().context("taking ssh's stdin")?;
        let copy = async move {
            let copied = async {
                ssh_stdin.write_all(&header).await?;
                ssh_stdin.write_all(&patch).await?;
                tokio::io::copy(&mut bundle, &mut ssh_stdin).await
            }
            .await;
            let _ = ssh_stdin.shutdown().await;
            copied
        };
        let git_log = async move {
            let mut text = Vec::new();
            let _ = git_stderr.read_to_end(&mut text).await;
            text
        };
        let (copied, git_text, git_status, out) = tokio::time::timeout(PREPARE_TIMEOUT, async {
            tokio::join!(copy, git_log, git.wait(), ssh.wait_with_output())
        })
        .await
        .map_err(|_| anyhow!("prepare did not finish in {PREPARE_TIMEOUT:?}"))?;
        let git_status = git_status.context("waiting for git bundle")?;
        if !git_status.success() {
            bail!(
                "git bundle create failed ({}): {}",
                exit_text(&git_status),
                stderr_tail(&git_text)
            );
        }
        let out = out.context("waiting for ssh")?;
        let ran = Ran {
            status: out.status,
            stdout: out.stdout,
            stderr: out.stderr,
        };
        let reply = match ran.verb_json("remote prepare") {
            Ok(reply) => reply,
            // A broken pipe on the bundle is a symptom of the host refusing early.
            Err(e) => match &copied {
                Err(sending) => bail!("{e:#} (sending the bundle: {sending})"),
                Ok(_) => return Err(e),
            },
        };
        let dir = reply["lane_dir"]
            .as_str()
            .filter(|d| d.starts_with('/'))
            .ok_or_else(|| anyhow!("remote prepare reported no absolute lane_dir"))?;
        if reply["base_commit"].as_str() != Some(side.base_commit) {
            bail!(
                "remote prepare built the lane on {}, not on {}",
                reply["base_commit"],
                side.base_commit
            );
        }
        let removed: Vec<String> = reply["removed"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        if removed != side.launch_removed {
            bail!(
                "the host removed {removed:?} for the launch baseline, the director {:?}: the \
                 patch would not apply to the tree the proof rebuilds",
                side.launch_removed
            );
        }
        self.lock().remote_dir = Some(PathBuf::from(dir));
        Ok(())
    }

    /// Forward `proxy.sock` and `sock/runner.sock` into the remote lane (D24), after `prepare`
    /// made the directory they live in.
    async fn forward(&self, side: &LocalSide<'_>) -> Result<()> {
        let dir = self
            .remote_dir()
            .ok_or_else(|| anyhow!("the remote lane directory is not known yet"))?;
        let pairs = [
            (dir.join("proxy.sock"), side.proxy_socket),
            (dir.join("sock/runner.sock"), side.runner_socket),
        ];
        for (remote, local) in pairs {
            let (Some(remote), Some(local)) = (remote.to_str(), local.to_str()) else {
                bail!("a forwarded socket path is not valid UTF-8");
            };
            // `-R` splits on `:`.
            if remote.contains(':') || local.contains(':') {
                bail!("a forwarded socket path holds a colon: {remote} or {local}");
            }
            let ran = run_ssh(
                &self.argv(&Step::Forward { remote, local }),
                None,
                CONTROL_TIMEOUT,
            )
            .await?;
            if !ran.status.success() {
                bail!(
                    "forwarding {remote} failed ({}): {}",
                    exit_text(&ran.status),
                    stderr_tail(&ran.stderr)
                );
            }
        }
        Ok(())
    }

    /// The command that runs the builder on the host: `host-agent builder` with the spec line
    /// on stdin (the caller writes it with [`spec_line`] and keeps the pipe open with
    /// [`hold_lifeline`]), its stdout the builder's stream. The builder's ssh is the leader of
    /// its own process group, as a local builder is, so ending that group ends the ssh; the
    /// host sees its stdin close and ends the remote builder's group (`host-agent builder`
    /// does the same on SIGHUP, SIGINT and SIGTERM).
    pub(crate) fn builder_command(&self) -> Command {
        self.lock().builder_started = true;
        let args = self.lane_args();
        let mut command = Command::new("ssh");
        command
            .args(self.argv(&Step::Agent {
                verb: "builder",
                args: &args,
            }))
            .stdin(Stdio::piped())
            .kill_on_drop(true)
            .process_group(0);
        command
    }

    /// Run one declared check on the host, in the remote lane's clone, through
    /// `host-agent check`. A failure to run it is a refused check, like a local one.
    pub(crate) async fn run_check(
        &self,
        check_id: &str,
        command: &str,
        port_base: Option<u16>,
        timeout: Duration,
    ) -> CheckOutcome {
        let refused = |why: String| CheckOutcome {
            exit_status: -1,
            output: format!("the check could not be run on {}: {why}", self.host.alias),
        };
        let mut args = self.lane_args();
        args.extend(["--check-id".to_string(), check_id.to_string()]);
        let spec = check_spec(command, timeout.as_secs().max(1), port_base);
        let ran = run_ssh(
            &self.argv(&Step::Agent {
                verb: "check",
                args: &args,
            }),
            Some(spec.to_string().into_bytes()),
            timeout + CHECK_SLACK,
        )
        .await;
        let report = match ran.and_then(|r| r.verb_json_check()) {
            Ok(v) => v,
            Err(e) => return refused(format!("{e:#}")),
        };
        CheckOutcome {
            exit_status: report["exit_code"]
                .as_i64()
                .and_then(|c| i32::try_from(c).ok())
                .unwrap_or(-1),
            output: report["output_tail"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
        }
    }

    /// `host-agent patch`: the lane patch, byte for byte.
    pub(crate) async fn fetch_patch(&self) -> Result<Vec<u8>> {
        let args = self.lane_args();
        let ran = run_ssh(
            &self.argv(&Step::Agent {
                verb: "patch",
                args: &args,
            }),
            None,
            PATCH_TIMEOUT,
        )
        .await?;
        if !ran.status.success() {
            return Err(match ran.verb_json("remote patch") {
                Err(e) => e,
                Ok(_) => anyhow!("remote patch: ssh failed ({})", exit_text(&ran.status)),
            });
        }
        // `git diff --binary` output always starts with `diff --git`; anything else is a login
        // shell's chatter or another failure, and must not become the proof's patch.
        if !ran.stdout.is_empty() && !ran.stdout.starts_with(b"diff --git ") {
            bail!("remote patch: the host's output is not a patch");
        }
        Ok(ran.stdout)
    }

    /// Remove the remote lane, then stop the master. Idempotent; runs on a blocking thread
    /// because it is also what `Drop` does.
    pub(crate) async fn finish(self: &Arc<Self>) {
        let lane = self.clone();
        let _ = tokio::task::spawn_blocking(move || lane.finish_blocking()).await;
    }

    /// The blocking form of [`RemoteLane::finish`], safe to call from any exit path: the
    /// builder's stderr (when one was started), `host-agent cleanup` (when `prepare` was
    /// attempted), then `-O exit`, then the master process itself, killed if it will not go.
    pub(crate) fn finish_blocking(&self) {
        let (cleanup, fetch, master) = {
            let mut state = self.lock();
            if state.finished {
                return;
            }
            state.finished = true;
            (
                state.prepare_attempted,
                state.builder_started,
                state.master.take(),
            )
        };
        let Some(mut master) = master else {
            return;
        };
        if cleanup {
            if fetch {
                self.fetch_stderr();
            }
            let args = self.lane_args();
            let argv = self.argv(&Step::Agent {
                verb: "cleanup",
                args: &args,
            });
            if let Err(e) = self.blocking_ssh(&argv, CLEANUP_TIMEOUT) {
                eprintln!(
                    "[{}] warning: removing the lane on {} did not finish: {e:#}",
                    self.lane_id, self.host.alias
                );
            }
        }
        let _ = self.blocking_ssh(&self.argv(&Step::Exit), EXIT_TIMEOUT);
        let deadline = Instant::now() + MASTER_EXIT_WAIT;
        while master.try_wait().ok().flatten().is_none() {
            if Instant::now() > deadline {
                let _ = master.kill();
                let _ = master.wait();
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Best effort, on every outcome: copy the host's `control/builder.stderr` (redacted there)
    /// to the end of the lane's own, redacted again here, because the director does not trust
    /// the host's redaction. Bounded in size and time; a failure is a warning, never an error.
    fn fetch_stderr(&self) {
        let args = self.lane_args();
        let argv = self.argv(&Step::Agent {
            verb: "stderr",
            args: &args,
        });
        let fetched = self
            .blocking_ssh_output(&argv, STDERR_TIMEOUT, MAX_STDERR_FETCH as usize)
            .and_then(|bytes| {
                if bytes.is_empty() {
                    return Ok(());
                }
                self.append_stderr(&bytes)
            });
        if let Err(e) = fetched {
            eprintln!(
                "[{}] warning: the builder's stderr on {} was not fetched: {e:#}",
                self.lane_id, self.host.alias
            );
        }
    }

    /// Append the fetched stderr, whole-text redacted, under a header that says where it ran.
    fn append_stderr(&self, bytes: &[u8]) -> Result<()> {
        let text = redact(&String::from_utf8_lossy(bytes));
        let path = self.control.join("builder.stderr");
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .with_context(|| format!("opening {}", path.display()))?;
        write!(
            file,
            "\n--- stderr of the builder on {} ---\n{text}",
            self.host.alias
        )?;
        if !text.ends_with('\n') {
            writeln!(file)?;
        }
        Ok(())
    }

    /// One ssh to completion, blocking, with `timeout`; its stdout, at most `max` bytes (more is
    /// an error), is returned and its stderr is appended to `control/ssh-finish.log`.
    fn blocking_ssh_output(
        &self,
        argv: &[String],
        timeout: Duration,
        max: usize,
    ) -> Result<Vec<u8>> {
        let log = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.control.join("ssh-finish.log"))
            .context("opening ssh-finish.log")?;
        let mut child = std::process::Command::new("ssh")
            .args(argv)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::from(log))
            .spawn()
            .context("starting ssh")?;
        let out = child.stdout.take().context("taking ssh's stdout")?;
        let reader = std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let _ = out.take(max as u64 + 1).read_to_end(&mut bytes);
            bytes
        });
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = child.try_wait()? {
                let bytes = reader.join().unwrap_or_default();
                if bytes.len() > max {
                    bail!("the host sent more than {max} bytes");
                }
                if !status.success() {
                    // A refusing verb prints its reason as JSON on stdout.
                    let why = last_json(&bytes)
                        .and_then(|v| v["error"].as_str().map(String::from))
                        .unwrap_or_default();
                    bail!("ssh ended with {}: {why}", exit_text(&status));
                }
                return Ok(bytes);
            }
            if Instant::now() > deadline {
                let _ = child.kill();
                let _ = child.wait();
                bail!("ssh did not finish in {timeout:?}");
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// One ssh to completion, blocking, with `timeout`; its stderr is appended to
    /// `control/ssh-finish.log`.
    fn blocking_ssh(&self, argv: &[String], timeout: Duration) -> Result<()> {
        let log = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.control.join("ssh-finish.log"))
            .context("opening ssh-finish.log")?;
        let mut child = std::process::Command::new("ssh")
            .args(argv)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(log))
            .spawn()
            .context("starting ssh")?;
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = child.try_wait()? {
                if status.success() {
                    return Ok(());
                }
                bail!("ssh ended with {}", exit_text(&status));
            }
            if Instant::now() > deadline {
                let _ = child.kill();
                let _ = child.wait();
                bail!("ssh did not finish in {timeout:?}");
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Drop for RemoteLane {
    fn drop(&mut self) {
        self.finish_blocking();
    }
}

impl Ran {
    /// A check's report: it exits 0 whenever the check ran (`ok` says whether it passed), so
    /// only a missing `exit_code` or an error means it could not be run.
    fn verb_json_check(&self) -> Result<Value> {
        let Some(value) = last_json(&self.stdout) else {
            bail!(
                "the host gave no JSON ({}): {}",
                exit_text(&self.status),
                stderr_tail(&self.stderr)
            );
        };
        if let Some(error) = value["error"].as_str() {
            bail!("{error}");
        }
        if !value["exit_code"].is_number() {
            bail!("the host's report has no exit_code");
        }
        Ok(value)
    }
}

/// Trimmed stdout of a git command in the director's repository.
async fn git_output(repo: &Path, args: &[&str]) -> Result<String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .await
        .context("running git")?;
    if !out.status.success() {
        bail!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host() -> RemoteHost {
        RemoteHost::from_config(
            "box",
            &json!({"ssh": "me@box.example", "cowproof": "/opt/cp/cowproof", "claude": "/opt/bin/claude"}),
        )
        .unwrap()
    }

    fn strs(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn the_master_is_one_background_connection_with_a_control_path_and_no_command() {
        let argv = ssh_argv(
            &host(),
            Path::new("/lanes/a/control/ssh.ctl"),
            &Step::Master,
        );
        assert_eq!(
            argv,
            strs(&[
                "-M",
                "-S",
                "/lanes/a/control/ssh.ctl",
                "-o",
                "ControlPersist=no",
                "-o",
                "StreamLocalBindUnlink=yes",
                "-o",
                "ExitOnForwardFailure=yes",
                "-o",
                "BatchMode=yes",
                "-o",
                "ServerAliveInterval=15",
                "-o",
                "ServerAliveCountMax=4",
                "-N",
                "me@box.example",
            ])
        );
    }

    #[test]
    fn control_requests_and_forwards_name_the_control_path_and_the_target() {
        let ctl = Path::new("/c/ssh.ctl");
        assert_eq!(
            ssh_argv(&host(), ctl, &Step::Check),
            strs(&["-S", "/c/ssh.ctl", "-O", "check", "me@box.example"])
        );
        assert_eq!(
            ssh_argv(&host(), ctl, &Step::Exit),
            strs(&["-S", "/c/ssh.ctl", "-O", "exit", "me@box.example"])
        );
        assert_eq!(
            ssh_argv(
                &host(),
                ctl,
                &Step::Forward {
                    remote: "/r/lane/proxy.sock",
                    local: "/l/lane/proxy.sock"
                }
            ),
            strs(&[
                "-S",
                "/c/ssh.ctl",
                "-O",
                "forward",
                "-R",
                "/r/lane/proxy.sock:/l/lane/proxy.sock",
                "me@box.example"
            ])
        );
    }

    #[test]
    fn a_verb_is_one_quoted_command_line_through_the_master() {
        let args = strs(&[
            "--lane-id",
            "lane-1",
            "--check-id",
            "it's a check; rm -rf /",
        ]);
        let argv = ssh_argv(
            &host(),
            Path::new("/c/ssh.ctl"),
            &Step::Agent {
                verb: "check",
                args: &args,
            },
        );
        assert_eq!(
            argv,
            strs(&[
                "-S",
                "/c/ssh.ctl",
                "-o",
                "BatchMode=yes",
                "-T",
                "me@box.example",
                "/opt/cp/cowproof host-agent check --lane-id lane-1 --check-id 'it'\\''s a check; rm -rf /'",
            ])
        );
    }

    #[test]
    fn a_configured_root_goes_last_and_a_default_root_is_left_to_the_host() {
        let mut with_root = host();
        with_root.root = Some("/srv/cp lanes".to_string());
        assert_eq!(
            agent_command(&with_root, "cleanup", &strs(&["--lane-id", "x"])),
            "/opt/cp/cowproof host-agent cleanup --lane-id x --root '/srv/cp lanes'"
        );
        assert_eq!(
            agent_command(&host(), "cleanup", &strs(&["--lane-id", "x"])),
            "/opt/cp/cowproof host-agent cleanup --lane-id x"
        );
        // A path with a space is one word.
        let mut spaced = host();
        spaced.cowproof = "/opt/my tools/cowproof".to_string();
        assert!(
            agent_command(&spaced, "doctor", &[])
                .starts_with("'/opt/my tools/cowproof' host-agent doctor")
        );
    }

    #[test]
    fn quoting_keeps_safe_words_and_wraps_the_rest() {
        assert_eq!(sh_quote("a-b_c.d/e:f=g@h"), "a-b_c.d/e:f=g@h");
        assert_eq!(sh_quote(""), "''");
        assert_eq!(sh_quote("a b"), "'a b'");
        assert_eq!(sh_quote("$(x)"), "'$(x)'");
        assert_eq!(sh_quote("it's"), "'it'\\''s'");
    }

    #[test]
    fn a_host_entry_needs_absolute_paths_and_a_destination_that_is_not_an_option() {
        let ok = json!({"cowproof": "/a/cowproof", "claude": "/a/claude"});
        let host = RemoteHost::from_config("box", &ok).unwrap();
        assert_eq!(host.ssh, "box", "the alias is the destination by default");
        assert_eq!(host.root, None);

        for (entry, why) in [
            (json!({"claude": "/a/claude"}), "has no cowproof"),
            (json!({"cowproof": "/a/cowproof"}), "has no claude"),
            (
                json!({"cowproof": "cowproof", "claude": "/a/claude"}),
                "absolute",
            ),
            (
                json!({"cowproof": "/a/cowproof", "claude": "claude"}),
                "absolute",
            ),
            (
                json!({"ssh": "-oProxyCommand=x", "cowproof": "/a/c", "claude": "/a/d"}),
                "destination",
            ),
            (
                json!({"ssh": "a b", "cowproof": "/a/c", "claude": "/a/d"}),
                "destination",
            ),
            (
                json!({"remoteRoot": "rel", "cowproof": "/a/c", "claude": "/a/d"}),
                "remoteRoot",
            ),
            (json!(["x"]), "JSON object"),
        ] {
            let err = RemoteHost::from_config("box", &entry).unwrap_err();
            assert!(format!("{err:#}").contains(why), "{entry}: {err:#}");
        }
        let err = RemoteHost::from_config("local", &ok).unwrap_err();
        assert!(format!("{err:#}").contains("leave out --host"), "{err:#}");
    }

    #[test]
    fn remote_root_is_absolute_or_relative_to_the_hosts_home() {
        let entry = |root: &str| {
            RemoteHost::from_config(
                "box",
                &json!({"remoteRoot": root, "cowproof": "/a/c", "claude": "/a/d"}),
            )
            .unwrap()
            .root
        };
        assert_eq!(entry("/srv/lanes").as_deref(), Some("/srv/lanes"));
        assert_eq!(entry("~/work/lanes/").as_deref(), Some("work/lanes"));
        assert_eq!(entry("~").as_deref(), Some("."));
        // The snake_case spelling other fields accept.
        let host = RemoteHost::from_config(
            "box",
            &json!({"remote_root": "~/x", "cowproof": "/a/c", "claude": "/a/d"}),
        )
        .unwrap();
        assert_eq!(host.root.as_deref(), Some("x"));
    }

    #[test]
    fn the_builder_spec_names_exactly_the_launch_fields_and_no_credential() {
        let settings = json!({"permissions": {"allow": ["Bash"]}});
        let parts = BuilderSpecParts {
            model: "haiku",
            prompt: "Do it.",
            system_prompt: "You are a builder.",
            settings: &settings,
            resume_session_id: None,
            placeholder_key: "placeholder-0123abcd",
            bridge_port: 41234,
            port_base: 57040,
            max_turns: 60,
            claude_bin: "/opt/bin/claude",
        };
        let spec = builder_spec(&parts);
        let mut keys: Vec<&str> = spec
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "bridge_port",
                "claude_bin",
                "max_turns",
                "model",
                "placeholder_key",
                "port_base",
                "prompt",
                "settings",
                "system_prompt"
            ]
        );
        assert_eq!(spec["placeholder_key"], "placeholder-0123abcd");
        let resumed = builder_spec(&BuilderSpecParts {
            resume_session_id: Some("0a1b2c3d-1111"),
            ..parts
        });
        assert_eq!(resumed["resume_session_id"], "0a1b2c3d-1111");
    }

    #[test]
    fn a_builder_spec_is_one_line_ended_by_a_newline_even_when_its_text_has_newlines() {
        let spec = json!({"prompt": "line one\nline two\r\n", "system_prompt": "a\n\nb"});
        let line = spec_line(&spec).unwrap();
        assert_eq!(line.last(), Some(&b'\n'));
        assert_eq!(
            line.iter().filter(|b| **b == b'\n').count(),
            1,
            "a raw newline inside the line: {}",
            String::from_utf8_lossy(&line)
        );
        let back: Value = serde_json::from_slice(&line[..line.len() - 1]).unwrap();
        assert_eq!(back, spec);
    }

    #[test]
    fn the_prepare_header_counts_the_patch_and_nothing_else() {
        assert_eq!(prepare_header(0), b"{\"patch_bytes\":0}\n");
        assert_eq!(prepare_header(1234), b"{\"patch_bytes\":1234}\n");
    }

    #[test]
    fn the_check_spec_carries_the_command_the_limit_and_the_port_block() {
        assert_eq!(
            check_spec("true", 90, Some(57040)),
            json!({"command": "true", "timeout_secs": 90, "port_base": 57040})
        );
        assert_eq!(
            check_spec("true", 90, None),
            json!({"command": "true", "timeout_secs": 90})
        );
    }

    #[test]
    fn the_last_json_line_is_the_verbs_answer_even_after_a_chatty_shell() {
        let out = b"Welcome to the box\n{\"ok\":true,\"lane_dir\":\"/x\"}\n\n";
        assert_eq!(last_json(out).unwrap()["lane_dir"], "/x");
        assert!(last_json(b"no json here\n").is_none());
        assert!(last_json(b"").is_none());
    }

    #[test]
    fn a_control_path_too_long_for_a_unix_socket_is_refused_up_front() {
        let long = PathBuf::from(format!("/{}", "x".repeat(90)));
        let err = RemoteLane::new(host(), "lane", &long)
            .err()
            .expect("too long");
        assert!(format!("{err:#}").contains("too long"), "{err:#}");
        assert!(RemoteLane::new(host(), "lane", Path::new("/var/tmp/c")).is_ok());
    }
}
