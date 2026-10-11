use anyhow::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
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
    /// Where the lane's starting rung came from (D28): `flag`, `header`, `class` or
    /// `default`. Sealed in `capsule.json`; absent in older capsules, which read as null.
    #[serde(default)]
    pub rung_source: Option<String>,
    pub auth_mode: String,
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
    /// The alias of the remote host that ran the builder (D27), or null for a lane run on the
    /// director's own machine. The proof is always local: the director rebuilt the tree from
    /// the base and the patch the host returned, so this says where the work was done and
    /// nothing else. Sealed in `capsule.json`; absent in older capsules, which read as null.
    #[serde(default)]
    pub host: Option<String>,
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
            rung_source: None,
            auth_mode,
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
            host: None,
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
