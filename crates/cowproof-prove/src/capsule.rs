use anyhow::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;
use thiserror::Error;

/// The launch baseline: a JSON array of the relative paths the runner removed from
/// the clone before the builder started. Paths only, never content (R15). It lives in
/// its own hashed file, not in `capsule.json`, which is itself never hashed.
const LAUNCH_REMOVED_FILE: &str = "launch_removed.json";

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

    #[error("Invalid capsule.json format: {0}")]
    InvalidFormat(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::error::Error),
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
    pub auth_mode: String,
    pub estimated_cost_usd: f64,
    pub estimated_tokens: u64,
    pub parked_seconds: u64,
    pub local_replay_only: bool,
    pub unsandboxed: bool,
    pub file_hashes: HashMap<String, String>,
    #[serde(default)]
    pub flaky_checks: HashSet<String>,
    /// Paths removed during the launch baseline, relative and sorted. Verify replays
    /// them by deleting these exact paths from the rebuilt tree. Stored in the hashed
    /// `launch_removed.json`, not in `capsule.json`, so editing it after `write`
    /// makes `read` fail.
    #[serde(skip)]
    pub launch_removed: Vec<String>,
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
            auth_mode,
            estimated_cost_usd: 0.0,
            estimated_tokens: 0,
            parked_seconds: 0,
            local_replay_only: false,
            unsandboxed: false,
            file_hashes: HashMap::new(),
            flaky_checks: HashSet::new(),
            launch_removed: Vec::new(),
        }
    }

    /// Write the capsule to a directory. Writes `launch_removed.json`, then records
    /// the SHA256 of every capsule file present in `dir` (patches, the launch
    /// baseline, packets, checks, gates, escalations, applied records) in
    /// `file_hashes` before writing `capsule.json`, which is itself never hashed.
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

        let capsule_json = serde_json::to_string_pretty(self)?;
        fs::write(dir.join("capsule.json"), &capsule_json)?;

        Ok(())
    }

    /// Read a capsule from a directory and verify all file hashes.
    pub fn read(dir: &Path) -> Result<Self, CapsuleError> {
        let capsule_path = dir.join("capsule.json");

        if !capsule_path.exists() {
            return Err(CapsuleError::MissingFile("capsule.json".to_string()));
        }

        let capsule_content = fs::read_to_string(&capsule_path).map_err(CapsuleError::IoError)?;

        let mut capsule: Capsule =
            serde_json::from_str(&capsule_content).map_err(CapsuleError::JsonError)?;

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
        let content = fs::read(path)?;
        let mut hasher = Sha256::new();
        hasher.update(&content);
        Ok(format!("{:x}", hasher.finalize()))
    }
}
