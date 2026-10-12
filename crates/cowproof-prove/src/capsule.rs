use anyhow::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::path::Path;
use thiserror::Error;

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

/// Check result from the verifier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    pub command: String,
    pub exit_status: i32,
    pub attempts: u32,
    pub duration_ms: u64,
    pub output_sha256: String,
}

/// A packet version with the verdict that introduced it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketVersion {
    pub version: u32,
    pub verdict_id: Option<String>,
    pub packet_json: String,
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
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TraceTotals {
    /// Records read.
    pub calls: u64,
    /// Bytes that reached the builder's context (`delivered_bytes`), summed.
    pub delivered_bytes: u64,
    /// Bytes the tools produced before any budget (`produced_bytes`), summed.
    pub produced_bytes: u64,
    /// Calls and delivered bytes by tool name.
    pub by_tool: BTreeMap<String, ToolTotals>,
    /// `Bash` calls whose command head is `pk-read`, and what they delivered. The trace keeps
    /// no output, so an `UNCHANGED` answer cannot be told from a full read: only the totals
    /// are known.
    pub pk_read: ToolTotals,
    /// Lines of a trace file that were not records.
    pub malformed_lines: u64,
}

/// The main capsule structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capsule {
    pub format_version: u32,
    pub base_commit: String,
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
    pub local_replay_only: bool,
    pub unsandboxed: bool,
    pub file_hashes: HashMap<String, String>,
    #[serde(default)]
    pub flaky_checks: HashSet<String>,
    /// Dependency cache key computed on the rebuilt tree (D11, D14).
    #[serde(default)]
    pub dependency_cache_key: Option<String>,
    /// Dependency fetch outcome: "hit", "fetched", or an error message (D6, F-1).
    #[serde(default)]
    pub dependency_fetch_outcome: Option<String>,
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
    /// untraced, as are Codex and OpenRouter lanes by construction. It says how the
    /// lane was watched and never enters the verdict. Absent in older capsules, which
    /// read as false.
    #[serde(default)]
    pub traced: bool,
    /// What the lane's portkit trace adds up to (calls by tool, bytes delivered into context),
    /// present exactly when `traced` is true. Sealed in `capsule.json`; absent in older
    /// capsules, which read as null and still verify.
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
