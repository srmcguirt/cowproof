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
//!   clone's `.git`).
//! - `stderr --lane-id <id>`: the last [`MAX_STDERR_FETCH`] bytes of `control/builder.stderr`
//!   (already redacted here; the director redacts them again), raw, empty when there is none.
//! - `doctor [--claude-bin <name>]`: the preflight's `sandbox` and `claude` checks, and the
//!   protocol this binary speaks.
//! - `cleanup --lane-id <id>`: removes `<root>/<id>`; idempotent; never follows a link.
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
//! The protocol ([`HOST_PROTOCOL`]) names the stdin framings above. A director sends it to
//! `prepare` and reads it from `doctor`; either side refuses a mismatch with a message naming
//! both numbers, before any lane exists or any builder starts. Protocol 1 (no number) had a
//! builder spec that ended at end of file and a base patch passed as a host file name.

use crate::preflight::{Check, CheckStatus, PreflightOptions, preflight};
use crate::run::{
    BuilderLaunch, CHECK_TIMEOUT, INTERRUPTED_EXIT_CODE, MAX_STDERR_LINE, PUMP_DRAIN, TERM_GRACE,
    builder_command, builder_path, capture_patch, pump_stderr, redact_ready, resumable,
    run_check_command, sibling_pk, sleep_until_opt, valid_model, write_lane_files,
};
use anyhow::{Context, Result, anyhow, bail};
use cowproof_core::{PORT_BASE, PORT_BLOCK_SIZE, redact};
use cowproof_prove::runner::{kill_process_group, terminate_process_group};
use cowproof_run::bridge::bridge_port;
use cowproof_run::lane::{LaneControl, PrepareOptions, prepare_lane, validate_lane_id};
use cowproof_run::tools::MAX_OUTPUT;
use cowproof_run::{LaneLayout, NetworkMode, lane_tmp};
use serde::Deserialize;
use serde_json::{Value, json};
use std::fs;
use std::io::{BufRead, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::oneshot;
use tokio::time::Instant as TokioInstant;

/// The remote host's side of D27.
#[derive(clap::Parser)]
pub struct HostAgentArgs {
    #[command(subcommand)]
    command: HostAgentAction,
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
        /// The Claude Code executable to check, resolved on PATH
        #[arg(long, default_value = "claude")]
        claude_bin: String,
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
    let outcome = match args.command {
        HostAgentAction::Prepare {
            lane_id,
            base,
            director_version,
            protocol,
            root,
        } => remote_root(root)
            .and_then(|root| prepare(&lane_id, &base, &director_version, protocol, &root)),
        HostAgentAction::Doctor { claude_bin, root } => match remote_root(root) {
            Ok(root) => doctor(&claude_bin, &root).await,
            Err(e) => Err(e),
        },
        HostAgentAction::Cleanup { lane_id, root } => {
            remote_root(root).and_then(|root| cleanup(&lane_id, &root))
        }
        HostAgentAction::Builder { lane_id, root } => {
            let launched = match remote_root(root) {
                Ok(root) => builder_launch(&lane_id, &root),
                Err(e) => Err(e),
            };
            return match launched {
                Ok(launched) => match drive_builder(launched, watch_stdin()).await {
                    Ok(code) => Ok(code),
                    Err(e) => print_outcome(Err(e)),
                },
                Err(e) => print_outcome(Err(e)),
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

/// `--root`, or `~/.cache/cowproof/remote-lanes`; a relative `--root` is taken from the
/// working directory.
fn remote_root(arg: Option<PathBuf>) -> Result<PathBuf> {
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
async fn doctor(claude_bin: &str, root: &Path) -> Result<Value> {
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

/// Remove `<root>/<id>`. A missing lane is success. A link at that path is unlinked and its
/// target is left alone; `remove_dir_all` does not follow links inside the lane either.
fn cleanup(lane_id: &str, root: &Path) -> Result<Value> {
    validate_lane_id(lane_id)?;
    let target = root.join(lane_id);
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
    Ok(json!({"ok": true, "lane_id": lane_id, "removed": removed}))
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
fn builder_launch(lane_id: &str, root: &Path) -> Result<BuilderLaunched> {
    let spec: BuilderSpec = read_spec_line()?;
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
    })?;
    Ok(BuilderLaunched {
        command,
        stderr_file: layout.control.join("builder.stderr"),
    })
}

/// SIGKILLs a process group when dropped, so no early return leaves a builder's background
/// children running.
struct Group(u32);

impl Drop for Group {
    fn drop(&mut self) {
        kill_process_group(self.0);
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
    let _group = Group(pgid);
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
    if spec.timeout_secs == 0 || spec.timeout_secs > CHECK_TIMEOUT.as_secs() {
        bail!(
            "timeout_secs must be 1 to {} (the local run_check limit)",
            CHECK_TIMEOUT.as_secs()
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
    let run = run_check_command(
        &layout,
        &path,
        &spec.command,
        spec.port_base,
        Duration::from_secs(spec.timeout_secs),
        check_id,
    )
    .await;
    let exit_code = run.outcome.exit_status;
    Ok(json!({
        "ok": exit_code == 0 && !run.timed_out,
        "exit_code": exit_code,
        "timed_out": run.timed_out,
        "output_tail": tail(&redact(&run.outcome.output), MAX_OUTPUT),
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
