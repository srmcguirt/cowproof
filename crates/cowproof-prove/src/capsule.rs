use anyhow::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;
use thiserror::Error;

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
        }
    }

    /// Write the capsule to a directory, computing and recording hashes of all files.
    pub fn write(&mut self, dir: &Path) -> Result<()> {
        fs::create_dir_all(dir)?;

        // Create subdirectories
        fs::create_dir_all(dir.join("packets"))?;
        fs::create_dir_all(dir.join("checks"))?;
        fs::create_dir_all(dir.join("applied"))?;

        // file_hashes should only contain hashes of OTHER files, not capsule.json itself
        // (to avoid circular dependency in serialization)
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

        let capsule: Capsule =
            serde_json::from_str(&capsule_content).map_err(CapsuleError::JsonError)?;

        // Verify all hashes in file_hashes
        for (file_path, expected_hash) in &capsule.file_hashes {
            let full_path = dir.join(file_path);

            if !full_path.exists() {
                return Err(CapsuleError::MissingFile(file_path.clone()));
            }

            let content = fs::read_to_string(&full_path).map_err(CapsuleError::IoError)?;
            let actual_hash = Self::hash_string(&content);

            if actual_hash != *expected_hash {
                return Err(CapsuleError::HashMismatch(
                    file_path.clone(),
                    expected_hash.clone(),
                    actual_hash,
                ));
            }
        }

        Ok(capsule)
    }

    /// Compute the SHA256 hash of a string and return it as hex.
    fn hash_string(content: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    /// Compute the SHA256 hash of a file and return it as hex.
    pub fn hash_file(path: &Path) -> Result<String> {
        let content = fs::read(path)?;
        let mut hasher = Sha256::new();
        hasher.update(&content);
        Ok(format!("{:x}", hasher.finalize()))
    }
}
