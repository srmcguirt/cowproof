use anyhow::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::path::Path;
use thiserror::Error;

pub use cowproof_run::tools::CheckEnd;

/// The launch baseline: a JSON array of the relative paths the runner removed from
/// the clone before the builder started. Paths only, never content (R15). It lives in
/// its own hashed file, listed in `capsule.json`'s `file_hashes`.
const LAUNCH_REMOVED_FILE: &str = "launch_removed.json";

/// The seal: the SHA256 of `capsule.json`'s raw bytes, exactly as written. `capsule.json`
/// cannot carry its own hash, so the seal is a separate file, and `read` checks it
/// before it parses a byte of `capsule.json`. Nothing is re-serialized to compute it.
/// This catches edits and damage, not a forger who also rewrites the seal; signing
/// comes later.
pub const SEAL_FILE: &str = "capsule.sha256";

/// The held-out checks a lane was proved against, copied in from the director's store
/// (D5). It sits among the packets, so it is hashed like them, and `verify` runs it.
pub const HELDOUT_FILE: &str = "packets/heldout.toml";

/// Files at the capsule root whose hashes `write` records.
const CAPSULE_TOP_FILES: &[&str] = &[
    "base.patch",
    LAUNCH_REMOVED_FILE,
    "lane.patch",
    "gates.json",
    "escalations.jsonl",
];

/// Capsule subdirectories whose files `write` hashes.
const CAPSULE_SUBDIRS: &[&str] = &["packets", "checks", "applied"];

/// Errors that can occur when reading/writing a capsule.
#[derive(Error, Debug)]
pub enum CapsuleError {
    #[error("Missing file in capsule: {0}")]
    MissingFile(String),

    #[error("Hash mismatch for file {0}: expected {1}, got {2}")]
    HashMismatch(String, String, String),

    /// A file is on disk in the capsule but is not among `capsule.json`'s `file_hashes`,
    /// so the seal does not cover it. The seal covers exactly the listed files, and
    /// `verify` acts only on those, so an extra file is refused rather than skipped:
    /// skipping it would hide that someone added to a sealed capsule.
    #[error("{}", unsealed_message(.0))]
    UnsealedFile(String),

    #[error("Invalid capsule.json format: {0}")]
    InvalidFormat(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::error::Error),
}

/// The message for a file the seal does not cover. macOS `tar` stores extended
/// attributes as AppleDouble `._<name>` siblings, the usual way an unsealed file
/// reaches a capsule that was archived and unpacked, so those get a hint.
fn unsealed_message(path: &str) -> String {
    let base = path.rsplit('/').next().unwrap_or(path);
    let mut msg = format!("File in the capsule is not sealed (not listed in capsule.json): {path}");
    if base.starts_with("._") {
        msg.push_str(
            "; macOS tar adds ._ files when it archives, so recreate the archive with COPYFILE_DISABLE=1",
        );
    }
    msg
}

/// Fail closed on anything `verify` could read that the seal does not list: an entry
/// of a sealed subdirectory (`packets`, `checks`, `applied`) that is not in
/// `file_hashes`, and a top-level capsule file (`base.patch` and the rest) that is
/// present but unlisted. `write` hashes every file it finds, so a file that is not
/// listed was added afterwards. A directory or symlink counts as an entry: `write`
/// never leaves one in a sealed subdirectory.
fn refuse_unsealed(dir: &Path, hashes: &HashMap<String, String>) -> Result<(), CapsuleError> {
    for name in CAPSULE_TOP_FILES {
        if !hashes.contains_key(*name) && fs::symlink_metadata(dir.join(name)).is_ok() {
            return Err(CapsuleError::UnsealedFile((*name).to_string()));
        }
    }
    for sub in CAPSULE_SUBDIRS {
        let sub_dir = dir.join(sub);
        match fs::symlink_metadata(&sub_dir) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(CapsuleError::IoError(e)),
        }
        for entry in fs::read_dir(&sub_dir)? {
            check_entry_is_sealed(sub, &entry?.file_name(), hashes)?;
        }
    }
    Ok(())
}

/// One entry of the sealed subdirectory `sub`: its name must be UTF-8 (it is a key in
/// `file_hashes`, so one that is not cannot be listed) and the key `<sub>/<name>` must be
/// listed.
pub(crate) fn check_entry_is_sealed(
    sub: &str,
    file_name: &std::ffi::OsStr,
    hashes: &HashMap<String, String>,
) -> Result<(), CapsuleError> {
    let Some(name) = file_name.to_str() else {
        return Err(CapsuleError::InvalidFormat(format!(
            "{sub}/ holds a file whose name is not UTF-8: {}",
            file_name.to_string_lossy()
        )));
    };
    let key = format!("{sub}/{name}");
    if hashes.contains_key(&key) {
        Ok(())
    } else {
        Err(CapsuleError::UnsealedFile(key))
    }
}

/// Environment fingerprint: OS, architecture, and tool versions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentFingerprint {
    pub os: String,
    pub arch: String,
    pub tools: HashMap<String, String>,
}

/// What the capsule records about one check: its command and the builder's last `run_check` run
/// of it (`checks/<id>.json`). `cowproof verify` compares only pass or fail (`exit_status` equal
/// to zero or not) and never the other fields, which vary between runs.
///
/// A capsule from before the run was recorded in full has `exit_status` 0 or 1, `attempts` 1,
/// `duration_ms` 0, an empty `output_sha256` and neither `output_len` nor `end`; those two
/// read as `None` and the capsule verifies as before.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    pub command: String,
    /// The last run's exit code, or -1 when the command had none (a signal, the timeout, never
    /// started): `end` says which.
    pub exit_status: i32,
    /// How many times the builder ran this check in the lane, the recorded run included.
    pub attempts: u32,
    /// The recorded run's wall-clock time in milliseconds.
    pub duration_ms: u64,
    /// SHA-256 (hex) of the recorded run's combined stdout and stderr. The output itself is
    /// never kept in the capsule. Empty in a capsule from before runs were recorded.
    pub output_sha256: String,
    /// Length in bytes of that output.
    #[serde(default)]
    pub output_len: Option<u64>,
    /// How the recorded run ended: exited with a code, signalled, timed out, or never started.
    #[serde(default)]
    pub end: Option<CheckEnd>,
    /// The verifier's own run of this check (`cowproof run` records it after the replay and
    /// seals the capsule again). Absent from a capsule the replay has not been recorded in:
    /// every capsule from before this field, and a lane whose proof did not reach the replay.
    /// It is never compared: `cowproof verify` compares pass or fail against the fields above.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verifier: Option<VerifierRun>,
    /// The time limit, in milliseconds, the builder's run of this check was held to: the check's
    /// own `timeout` from the packet header, else the runner's default. `cowproof verify` replays
    /// the check under this limit, not the current default, and refuses a capsule whose limit
    /// differs from the one the header declares. Absent from a capsule written before the field
    /// existed, which is replayed under the verifier's default as before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
}

/// The verifier's own run of one check, the values `cowproof run`'s replay measured and the
/// capsule keeps beside the builder's. The same fields as the builder's record, minus `attempts`
/// (the verifier's retries of a flaky check are not counted: this is the last attempt's run).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifierRun {
    /// The command's exit code, or -1 when it had none (it was ended by a signal).
    pub exit_status: i32,
    /// How the command ended. A timeout never appears: the verifier treats it as infrastructure.
    pub end: CheckEnd,
    /// Wall-clock time of the run in milliseconds, from just before the sandboxed command was
    /// started to just after its output was collected. The slot wait is not in it.
    pub duration_ms: u64,
    /// SHA-256 (hex) of the run's stdout then stderr, the same bytes the builder's
    /// `output_sha256` covers. The output itself is never kept.
    pub output_sha256: String,
    /// Length in bytes of that output.
    pub output_len: u64,
}

/// What the verifier's compile cache did for a verification (R3, D11): informational, and never
/// part of a verdict. The seed is a cargo target directory built from the BASE commit
/// (`cowproof_run::verify_target`); each verification checks against a private copy of it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyCache {
    /// `hit` (a seed was there), `built` (this verification built it), `off`
    /// (`COWPROOF_VERIFY_CACHE=off`), `failed` (the seed could not be made or copied, and the
    /// verification ran as if there were none; `note` says why) or `not_cargo` (the base tree
    /// has no `Cargo.toml` at its root).
    pub status: String,
    /// The seed's key, when one was computed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// How the private copy was made: `clone` (copy-on-write) or `copy` (bytes). Present exactly
    /// when the verification used a seed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub copy: Option<String>,
    /// Why the seed was not used, for `failed`; absent otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// One entry of `packets/versions.json`: a version of the packet the lane ran under.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PacketVersion {
    /// 1 for the packet the lane started with, then one more for each redirect.
    pub version: u32,
    /// The file in `packets/` holding this version's text, byte for byte.
    pub file: String,
    /// The escalation whose redirect ruling introduced this version; null for version 1.
    pub introduced_by: Option<String>,
}

/// The index of the packet versions, inside the capsule's `packets/`.
pub const PACKET_VERSIONS_FILE: &str = "packets/versions.json";

/// Write every packet version the lane ran under into `<dir>/packets/`: `v1.md`, `v2.md` and so
/// on, byte for byte, and `versions.json` listing them. `versions` is `(introduced_by, text)` in
/// order, the first being the packet the lane started with. Call it before [`Capsule::write`],
/// which hashes what is in `packets/`.
pub fn write_packet_versions(
    dir: &Path,
    versions: &[(Option<String>, String)],
) -> std::io::Result<()> {
    fs::create_dir_all(dir.join("packets"))?;
    let mut index = Vec::new();
    for (i, (introduced_by, text)) in versions.iter().enumerate() {
        let version = u32::try_from(i + 1).unwrap_or(u32::MAX);
        let file = format!("v{version}.md");
        fs::write(dir.join("packets").join(&file), text)?;
        index.push(PacketVersion {
            version,
            file,
            introduced_by: introduced_by.clone(),
        });
    }
    fs::write(
        dir.join(PACKET_VERSIONS_FILE),
        serde_json::to_vec_pretty(&index)?,
    )
}

/// Read the packet versions of a capsule directory: each entry of `versions.json` with the text
/// of its file. Empty when the capsule has no `versions.json` (a capsule from before they were
/// written). Call it on a capsule [`Capsule::read`] accepted, which has checked the hashes.
pub fn read_packet_versions(dir: &Path) -> Result<Vec<(PacketVersion, String)>, CapsuleError> {
    let path = dir.join(PACKET_VERSIONS_FILE);
    let raw = match fs::read(&path) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(CapsuleError::IoError(e)),
    };
    let index: Vec<PacketVersion> = serde_json::from_slice(&raw)
        .map_err(|e| CapsuleError::InvalidFormat(format!("{PACKET_VERSIONS_FILE}: {e}")))?;
    let mut out = Vec::new();
    for entry in index {
        if entry.file.is_empty() || entry.file.contains('/') || entry.file.contains("..") {
            return Err(CapsuleError::InvalidFormat(format!(
                "{PACKET_VERSIONS_FILE}: {:?} is not a file name inside packets/",
                entry.file
            )));
        }
        let text = fs::read_to_string(dir.join("packets").join(&entry.file))
            .map_err(CapsuleError::IoError)?;
        out.push((entry, text));
    }
    Ok(out)
}

/// Calls and the bytes they delivered into context, for one tool.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolTotals {
    pub calls: u64,
    pub delivered_bytes: u64,
}

/// What portkit's trace of one lane adds up to (D5, D23): the usage monitor's totals. They are
/// read from `<lane>/portkit/traces/*.jsonl` at lane end and describe how the lane was
/// watched; they never enter the verdict. The builder can write its own trace directory, so
/// the figures are the builder's own account, not a measurement the runner made.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TraceTotals {
    /// Always true when the runner writes it: every figure below comes from a trace the
    /// builder can write, so none is a measurement the runner made (audit S-6). It travels
    /// with the figures into `run.json`, the capsule, the `lanes` tool and the rollup. A
    /// capsule written before it reads as true: its figures were builder-written too.
    #[serde(default = "builder_written_default")]
    pub builder_written: bool,
    /// Records read.
    pub calls: u64,
    /// Bytes that reached the builder's context (`delivered_bytes`), summed.
    pub delivered_bytes: u64,
    /// Bytes the tools produced before any budget (`produced_bytes`), summed.
    pub produced_bytes: u64,
    /// Bytes the budget kept out of context: `produced_bytes` minus `delivered_bytes` of the
    /// sums, floored at zero, as portkit's `Summary::saved_bytes` has it. Absent in capsules
    /// written before it, which read as 0.
    #[serde(default)]
    pub saved_bytes: u64,
    /// Calls that ended `rejected` (refused before the tool ran), as portkit's `Summary`
    /// counts them. Absent in older capsules, which read as 0.
    #[serde(default)]
    pub rejected: u64,
    /// Of the calls that name a target, the share whose `(tool, target)` an earlier call of the
    /// lane already named: a ratio in 0..=1. Null when no call names a target (portkit stores
    /// only a target, never the arguments, so a call without one cannot be told from another).
    /// Absent in older capsules, which read as null.
    #[serde(default)]
    pub reread_rate: Option<f64>,
    /// Calls and delivered bytes by tool name.
    pub by_tool: BTreeMap<String, ToolTotals>,
    /// `Bash` calls whose command head is `pk-read`, and what they delivered. The trace keeps
    /// no output, so an `UNCHANGED` answer cannot be told from a full read: only the totals
    /// are known.
    pub pk_read: ToolTotals,
    /// Lines of a trace file that were not records.
    pub malformed_lines: u64,
    /// Tool names folded into the `other` entry of `by_tool` because the lane named more than
    /// 64 (audit S-5). Absent in older capsules, which read as 0.
    #[serde(default)]
    pub folded_tool_names: u64,
    /// Trace files the walk left unread because the lane's trace passed the aggregate bound
    /// on bytes or files (audit S-5): the totals cover the files before them. Absent in older
    /// capsules, which read as 0.
    #[serde(default)]
    pub unread_files: u64,
}

fn builder_written_default() -> bool {
    true
}

impl Default for TraceTotals {
    fn default() -> Self {
        Self {
            builder_written: true,
            calls: 0,
            delivered_bytes: 0,
            produced_bytes: 0,
            saved_bytes: 0,
            rejected: 0,
            reread_rate: None,
            by_tool: BTreeMap::new(),
            pk_read: ToolTotals::default(),
            malformed_lines: 0,
            folded_tool_names: 0,
            unread_files: 0,
        }
    }
}

/// The main capsule structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capsule {
    pub format_version: u32,
    pub base_commit: String,
    /// The remote-tracking ref (`origin/main`) that contained the base commit when the capsule
    /// was made, or null when none did. The ref's name, never a URL, which can carry
    /// credentials. It is read from the director's own remote-tracking refs, as
    /// `local_replay_only` is, so it says what those refs said at the time, not that the remote
    /// still has the commit. Absent in older capsules, which read as null.
    #[serde(default)]
    pub base_remote: Option<String>,
    pub base_tree_hash: String,
    pub environment: EnvironmentFingerprint,
    pub lane_state: String,
    pub builder_model: String,
    /// The runtime of the builder's last segment (D28): `claude`, `openrouter` or `codex`.
    /// Sealed in `capsule.json`. A capsule from before D28 has no such field and reads as
    /// `claude`, the only runtime there was.
    #[serde(default = "default_runtime")]
    pub builder_runtime: String,
    /// The version the runtime's executable reported (`opencode --version` for `openrouter`
    /// lanes, `codex --version` for `codex` lanes), when the runner read one. Sealed in `capsule.json`; absent in older capsules
    /// and in lanes whose runtime version is not recorded, which read as null.
    #[serde(default)]
    pub builder_runtime_version: Option<String>,
    /// What OpenRouter's model list said the last segment's model costs, fetched at preflight
    /// and the figures the lane's cost was computed at (`openrouter` lanes only; null for any
    /// other runtime): `inputPerMillion`, `outputPerMillion`, `cacheReadPerMillion` and
    /// `cacheWritePerMillion` in USD, `contextLength`, `maxOutput`, `defaulted` (the fields the
    /// list did not give), `source` (the path fetched, never the key) and `fetchedAt` (UTC).
    /// Sealed in `capsule.json`; absent in older capsules, which read as null.
    #[serde(default)]
    pub openrouter_price: Option<serde_json::Value>,
    /// What the director's `cowproof.toml` said the last segment's model costs (`codex` lanes
    /// only; null for any other runtime): `inputPerMillion`, `cachedInputPerMillion` and
    /// `outputPerMillion` in USD, and `source`, the director's note on where the figures came
    /// from. Sealed in `capsule.json`; absent in older capsules, which read as null.
    #[serde(default)]
    pub codex_price: Option<serde_json::Value>,
    /// Where the lane's starting rung came from (D28): `flag`, `header`, `class` or
    /// `default`. Sealed in `capsule.json`; absent in older capsules, which read as null.
    #[serde(default)]
    pub rung_source: Option<String>,
    pub auth_mode: String,
    /// The kind of credential the proxy held for the lane when it is not an API key (D2, D28
    /// clause 6): `claude-oauth-token` for a Claude subscription lane, null for an API-key lane.
    /// Sealed in `capsule.json`; absent in older capsules, which read as null.
    #[serde(default)]
    pub credential_kind: Option<String>,
    /// Whether a credential was readable inside the lane (D28 clause 6). Always false today: the
    /// proxy holds every credential, the subscription token included, and the lane holds a
    /// placeholder. It is recorded so a lane that ever did hold one says so everywhere it
    /// appears, as `unsandboxed` does. Sealed in `capsule.json`; absent in older capsules, which
    /// read as false.
    #[serde(default)]
    pub credential_in_lane: bool,
    pub estimated_cost_usd: f64,
    pub estimated_tokens: u64,
    pub parked_seconds: u64,
    /// True when no remote-tracking ref in the director's repository contained the base commit
    /// (`git for-each-ref --contains <base> refs/remotes` was empty). It is a statement about
    /// those local refs: a stale or never-fetched ref makes it wrong in either direction, and
    /// the remote itself is never asked.
    pub local_replay_only: bool,
    pub unsandboxed: bool,
    pub file_hashes: HashMap<String, String>,
    #[serde(default)]
    pub flaky_checks: HashSet<String>,
    /// Dependency cache key computed on the rebuilt tree (D11, D14).
    #[serde(default)]
    pub dependency_cache_key: Option<String>,
    /// Dependency fetch outcome: "hit", "fetched", "not_fetched" (the tree has dependency
    /// files this runner does not fetch, and `dependency_fetch_notes` says which), or
    /// "failed" (D6, F-1).
    #[serde(default)]
    pub dependency_fetch_outcome: Option<String>,
    /// The ecosystems the dependency cache entry holds (`cargo`, `npm`) when the outcome is
    /// "hit" or "fetched". Absent when none, so capsules made before npm was fetched, and
    /// their seals, are unchanged.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dependency_ecosystems: Vec<String>,
    /// What the dependency fetch left out or did not use, one line each: lockfiles and
    /// manifests that are not fetched (yarn, pnpm, Bundler, a `package.json` with no npm
    /// lockfile) and the credential lines of the base `.npmrc` that were dropped. Absent when
    /// there are none.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dependency_fetch_notes: Vec<String>,
    /// Set only when the dependency fetch ran with the `COWPROOF_FETCH_RESOLVE` testing hook:
    /// its `host=ip:port,...` text. A capsule that carries it was made against a fake, not a
    /// real registry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dependency_fetch_resolve: Option<String>,
    /// What the verifier's compile cache did when `cowproof run` replayed this lane: the seed's
    /// key, `hit`/`built`/`off`/`failed`/`not_cargo`, and how the private copy was made. Written
    /// when the replay ran and the capsule was sealed again; absent from a capsule the replay
    /// did not reach and from every capsule from before the field, which still read and verify.
    /// Informational: it never enters a verdict or a gate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verify_cache: Option<VerifyCache>,
    /// The reference-runtime directories the director granted the verifier (`--runtime-dir`
    /// or `COWPROOF_RUNTIME_DIRS`), canonical, read-only: what this proof saw beyond the
    /// system directories. Absent when none was granted, so existing capsules and their seals
    /// are unchanged. `cowproof verify` of the capsule needs the same directories again, else
    /// the held-out cases that need them are skipped and the skip names this list.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub runtime_dirs: Vec<String>,
    /// The version of the builder preamble (sha256 hash of PREAMBLE bytes).
    /// Used to detect when the protocol has changed.
    #[serde(default)]
    pub prefix_version: Option<String>,
    /// The SHA256 hash of the project instructions (CLAUDE.md from the base commit),
    /// or null if the base had no project instructions. Used to show which CLAUDE.md
    /// the builder saw.
    #[serde(default)]
    pub project_instructions_sha256: Option<String>,
    /// The class of the lane (rust, crate, pg, light, port), recorded so that
    /// `cowproof verify` uses the same class slot. Defaults to "light".
    #[serde(default = "default_class")]
    pub class: String,
    /// Whether the lane was traced: `pk doctor` found at least one recorded hook
    /// call in the lane's portkit state dir at lane end (D5). Sealed in
    /// `capsule.json`. A lane without `pk`, without hooks or whose doctor failed is
    /// untraced, as are Codex and OpenRouter lanes by construction. It is builder-side,
    /// informational data: portkit's hooks and state dir run inside the lane's writable
    /// area, so the builder can write the records it rests on. It says how the lane was
    /// watched and never enters the verdict or any gate. Absent in older capsules, which
    /// read as false.
    #[serde(default)]
    pub traced: bool,
    /// What the lane's portkit trace adds up to (calls by tool, bytes delivered into context),
    /// present exactly when `traced` is true. Read from the lane's portkit state dir, which
    /// the builder can write: builder-written, informational data, never a measurement the
    /// runner made, and never read by a verdict or a gate. Sealed in `capsule.json` (the seal
    /// covers the figures as recorded, not their truth); absent in older capsules, which read
    /// as null and still verify.
    #[serde(default)]
    pub trace_totals: Option<TraceTotals>,
    /// The alias of the remote host that ran the builder (D27), or null for a lane run on the
    /// director's own machine. The proof is always local: the director rebuilt the tree from
    /// the base and the patch the host returned, so this says where the work was done and
    /// nothing else. Sealed in `capsule.json`; absent in older capsules, which read as null.
    #[serde(default)]
    pub host: Option<String>,
    /// For a `kind: port` packet: how the fixtures are replayed (tools, fixtures directory,
    /// reference command, epsilon) and, once the verifier has run, what the replay found:
    /// the fixture-set hash, the source commit, the failing and accepted outcomes per
    /// surface and the held-out state. Sealed in `capsule.json`; absent in older capsules and
    /// in every capsule of ordinary work, which read as null and still verify.
    #[serde(default)]
    pub port: Option<crate::port::PortCapsule>,
    /// Paths removed during the launch baseline, relative and sorted. Verify replays
    /// them by deleting these exact paths from the rebuilt tree. Stored in the hashed
    /// `launch_removed.json`, not in `capsule.json`, so editing it after `write`
    /// makes `read` fail.
    #[serde(skip)]
    pub launch_removed: Vec<String>,
}

fn default_class() -> String {
    "light".to_string()
}

fn default_runtime() -> String {
    "claude".to_string()
}

impl Capsule {
    /// Create a new capsule with the given parameters.
    pub fn new(
        base_commit: String,
        base_tree_hash: String,
        environment: EnvironmentFingerprint,
        builder_model: String,
        auth_mode: String,
    ) -> Self {
        Self {
            format_version: 1,
            base_commit,
            base_remote: None,
            base_tree_hash,
            environment,
            lane_state: "finished".to_string(),
            builder_model,
            builder_runtime: default_runtime(),
            builder_runtime_version: None,
            openrouter_price: None,
            codex_price: None,
            rung_source: None,
            auth_mode,
            credential_kind: None,
            credential_in_lane: false,
            estimated_cost_usd: 0.0,
            estimated_tokens: 0,
            parked_seconds: 0,
            local_replay_only: false,
            unsandboxed: false,
            file_hashes: HashMap::new(),
            flaky_checks: HashSet::new(),
            dependency_cache_key: None,
            dependency_fetch_outcome: None,
            dependency_ecosystems: Vec::new(),
            dependency_fetch_notes: Vec::new(),
            dependency_fetch_resolve: None,
            verify_cache: None,
            runtime_dirs: Vec::new(),
            prefix_version: None,
            project_instructions_sha256: None,
            class: "light".to_string(),
            traced: false,
            trace_totals: None,
            host: None,
            port: None,
            launch_removed: Vec::new(),
        }
    }

    /// Write the capsule to a directory. Writes `launch_removed.json`, then records
    /// the SHA256 of every capsule file present in `dir` (patches, the launch
    /// baseline, packets, checks, gates, escalations, applied records) in
    /// `file_hashes` before writing `capsule.json`, then seals `capsule.json` itself by
    /// writing the hash of its raw bytes to `capsule.sha256`.
    pub fn write(&mut self, dir: &Path) -> Result<()> {
        fs::create_dir_all(dir)?;
        fs::write(
            dir.join(LAUNCH_REMOVED_FILE),
            serde_json::to_vec_pretty(&self.launch_removed)?,
        )?;
        for sub in CAPSULE_SUBDIRS {
            fs::create_dir_all(dir.join(sub))?;
        }

        for name in CAPSULE_TOP_FILES {
            let path = dir.join(name);
            if path.is_file() {
                self.file_hashes
                    .insert((*name).to_string(), Self::hash_file(&path)?);
            }
        }
        for sub in CAPSULE_SUBDIRS {
            for entry in fs::read_dir(dir.join(sub))? {
                let path = entry?.path();
                if path.is_file() {
                    let name = path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .ok_or_else(|| anyhow::anyhow!("non-UTF-8 file name in {sub}"))?;
                    self.file_hashes
                        .insert(format!("{sub}/{name}"), Self::hash_file(&path)?);
                }
            }
        }

        // The seal covers the exact bytes on disk, so hash what was written.
        let capsule_path = dir.join("capsule.json");
        fs::write(&capsule_path, serde_json::to_vec_pretty(self)?)?;
        fs::write(dir.join(SEAL_FILE), Self::hash_file(&capsule_path)?)?;

        Ok(())
    }

    /// Read a capsule from a directory. `capsule.json` is checked against its seal
    /// before it is parsed, then every file it lists is checked against its hash.
    pub fn read(dir: &Path) -> Result<Self, CapsuleError> {
        let capsule_path = dir.join("capsule.json");

        if !capsule_path.exists() {
            return Err(CapsuleError::MissingFile("capsule.json".to_string()));
        }
        let raw = fs::read(&capsule_path).map_err(CapsuleError::IoError)?;
        let expected = match fs::read_to_string(dir.join(SEAL_FILE)) {
            Ok(text) => text.trim().to_string(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(CapsuleError::MissingFile(SEAL_FILE.to_string()));
            }
            Err(e) => return Err(CapsuleError::IoError(e)),
        };
        let actual = Self::hash_bytes(&raw);
        if actual != expected {
            return Err(CapsuleError::HashMismatch(
                "capsule.json".to_string(),
                expected,
                actual,
            ));
        }

        let mut capsule: Capsule = serde_json::from_slice(&raw).map_err(CapsuleError::JsonError)?;

        for (file_path, expected_hash) in &capsule.file_hashes {
            let full_path = dir.join(file_path);

            if !full_path.exists() {
                return Err(CapsuleError::MissingFile(file_path.clone()));
            }

            let actual_hash = Self::hash_file(&full_path)
                .map_err(|e| CapsuleError::InvalidFormat(format!("{file_path}: {e}")))?;

            if actual_hash != *expected_hash {
                return Err(CapsuleError::HashMismatch(
                    file_path.clone(),
                    expected_hash.clone(),
                    actual_hash,
                ));
            }
        }

        refuse_unsealed(dir, &capsule.file_hashes)?;

        // The launch baseline must be present and hashed: a capsule without it would
        // replay as "nothing was removed".
        if !capsule.file_hashes.contains_key(LAUNCH_REMOVED_FILE) {
            return Err(CapsuleError::InvalidFormat(format!(
                "{LAUNCH_REMOVED_FILE} is not among the hashed files"
            )));
        }
        let removed = fs::read(dir.join(LAUNCH_REMOVED_FILE)).map_err(CapsuleError::IoError)?;
        capsule.launch_removed = serde_json::from_slice(&removed)
            .map_err(|e| CapsuleError::InvalidFormat(format!("{LAUNCH_REMOVED_FILE}: {e}")))?;

        Ok(capsule)
    }

    /// Compute the SHA256 hash of a file and return it as hex.
    pub fn hash_file(path: &Path) -> Result<String> {
        Ok(Self::hash_bytes(&fs::read(path)?))
    }

    /// The SHA256 of `bytes`, as hex.
    pub fn hash_bytes(bytes: &[u8]) -> String {
        format!("{:x}", Sha256::digest(bytes))
    }
}
