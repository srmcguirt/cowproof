//! Builder for Claude Code headless invocation (R15: isolation recipe, D19: communication/cache).
//!
//! A pure builder of the headless Claude Code invocation, taking a complete specification
//! and producing an invocation with validated arguments, environment, and working directory.
//! The builder does not spawn processes or perform any I/O except validation of paths.

use anyhow::{Result, bail};
use std::fmt;
use std::path::PathBuf;

/// Complete specification for a Claude Code invocation.
///
/// Contains lane configuration, model selection, credentials, paths to configuration files,
/// and prompt parameters. Never holds the real API key; the spec type cannot even have
/// a field for it. PATH is passed in explicitly (never read from the process environment).
#[derive(Debug, Clone)]
pub struct ClaudeSpec {
    /// Lane filesystem layout.
    pub lane: crate::LaneLayout,
    /// Model name (e.g., "haiku", "sonnet", "opus").
    pub model: String,
    /// Proxy base URL (e.g., "http://localhost:4123").
    pub proxy_base_url: String,
    /// Placeholder API key for the builder.
    pub placeholder_key: String,
    /// Absolute path to settings file to load.
    pub settings_file: PathBuf,
    /// Absolute path to MCP config file to load.
    pub mcp_config: PathBuf,
    /// Absolute path to system prompt file to append.
    pub append_system_prompt_file: PathBuf,
    /// The actual prompt text for Claude.
    pub prompt: String,
    /// Maximum number of turns (must be > 0).
    pub max_turns: u32,
    /// Session ID to resume (if any). Must match `[0-9a-f-]{8,64}` if provided.
    pub resume_session_id: Option<String>,
    /// Prompt cache TTL: "5m" or "1h" (default "1h").
    pub cache_ttl: String,
    /// PATH environment variable (colon-separated absolute paths, never read from process).
    pub path: String,
}

/// A complete, validated invocation of Claude Code.
///
/// Contains the program name, arguments in stable order, environment variables as
/// explicit key-value pairs, and working directory. All paths are absolute.
/// The builder ensures args order is stable for testing and reproducibility.
pub struct ClaudeInvocation {
    /// The executable name (usually "claude").
    pub program: String,
    /// Arguments in stable order, never including `--bare`.
    pub args: Vec<String>,
    /// Complete environment: HOME, CLAUDE_CONFIG_DIR, CLAUDE_CODE_PROMPT_CACHE_TTL,
    /// ANTHROPIC_BASE_URL, ANTHROPIC_API_KEY (placeholder), PATH, CARGO_HOME.
    pub env: Vec<(String, String)>,
    /// Working directory (the lane clone).
    pub cwd: PathBuf,
}

impl fmt::Debug for ClaudeInvocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Redact the placeholder key in the environment.
        let redacted_env: Vec<(String, String)> = self
            .env
            .iter()
            .map(|(k, v)| {
                if k == "ANTHROPIC_API_KEY" {
                    (k.clone(), "***REDACTED***".to_string())
                } else {
                    (k.clone(), v.clone())
                }
            })
            .collect();
        f.debug_struct("ClaudeInvocation")
            .field("program", &self.program)
            .field("args", &self.args)
            .field("env", &redacted_env)
            .field("cwd", &self.cwd)
            .finish()
    }
}

/// Build a Claude Code invocation from a specification.
///
/// Validates:
/// - prompt is not empty
/// - max_turns > 0
/// - resume_session_id (if provided) matches [0-9a-f-]{8,64}
/// - cache_ttl is "5m" or "1h"
/// - all paths are absolute
///
/// Returns errors for each distinct violation.
pub fn claude_command(spec: &ClaudeSpec) -> Result<ClaudeInvocation> {
    // Validate prompt
    if spec.prompt.is_empty() {
        bail!("prompt is empty");
    }

    // Validate max_turns
    if spec.max_turns == 0 {
        bail!("max_turns is 0");
    }

    // Validate resume_session_id format
    if let Some(ref resume_id) = spec.resume_session_id
        && (!resume_id.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
            || resume_id.len() < 8
            || resume_id.len() > 64)
    {
        bail!(
            "resume_session_id does not match [0-9a-f-]{{8,64}}: {}",
            resume_id
        );
    }

    // Validate cache_ttl
    if spec.cache_ttl != "5m" && spec.cache_ttl != "1h" {
        bail!("cache_ttl must be '5m' or '1h', got '{}'", spec.cache_ttl);
    }

    // Validate all paths are absolute
    if !spec.settings_file.is_absolute() {
        bail!(
            "settings_file is not absolute: {}",
            spec.settings_file.display()
        );
    }
    if !spec.mcp_config.is_absolute() {
        bail!("mcp_config is not absolute: {}", spec.mcp_config.display());
    }
    if !spec.append_system_prompt_file.is_absolute() {
        bail!(
            "append_system_prompt_file is not absolute: {}",
            spec.append_system_prompt_file.display()
        );
    }

    // Validate PATH: must be non-empty, all entries absolute, no entries under real_home
    if spec.path.is_empty() {
        bail!("path is empty");
    }
    for entry in spec.path.split(':') {
        if entry.is_empty() {
            // An empty entry means the current directory, which is the builder's
            // clone: a builder could plant a fake `git` or `cargo` there.
            bail!("path has an empty entry (it would search the current directory)");
        }
        let entry_path = PathBuf::from(entry);
        if !entry_path.is_absolute() {
            bail!("path entry is not absolute: {}", entry);
        }
        if entry_path.starts_with(&spec.lane.real_home) {
            bail!(
                "path entry is under real home ({}): {}",
                spec.lane.real_home.display(),
                entry
            );
        }
    }

    // Build args in stable order
    let mut args = vec![
        "-p".to_string(),
        "--model".to_string(),
        spec.model.clone(),
        "--output-format".to_string(),
        "stream-json".to_string(),
        "--verbose".to_string(),
        "--setting-sources".to_string(),
        "".to_string(), // Empty string argument
        "--settings".to_string(),
        spec.settings_file.to_string_lossy().into_owned(),
        "--mcp-config".to_string(),
        spec.mcp_config.to_string_lossy().into_owned(),
        "--strict-mcp-config".to_string(),
        "--append-system-prompt-file".to_string(),
        spec.append_system_prompt_file
            .to_string_lossy()
            .into_owned(),
        "--max-turns".to_string(),
        spec.max_turns.to_string(),
    ];

    // Add resume session ID only when given
    if let Some(ref resume_id) = spec.resume_session_id {
        args.push("--resume".to_string());
        args.push(resume_id.clone());
    }

    // Prompt as final argument
    args.push(spec.prompt.clone());

    // Build environment: complete and explicit
    let mut env = vec![
        (
            "HOME".to_string(),
            spec.lane.home.to_string_lossy().into_owned(),
        ),
        (
            "CLAUDE_CONFIG_DIR".to_string(),
            spec.lane
                .home
                .join(".claude-config")
                .to_string_lossy()
                .into_owned(),
        ),
        (
            "CLAUDE_CODE_PROMPT_CACHE_TTL".to_string(),
            spec.cache_ttl.clone(),
        ),
        (
            "ANTHROPIC_BASE_URL".to_string(),
            spec.proxy_base_url.clone(),
        ),
        (
            "ANTHROPIC_API_KEY".to_string(),
            spec.placeholder_key.clone(),
        ),
    ];

    // Add PATH from the spec (never from process environment)
    env.push(("PATH".to_string(), spec.path.clone()));

    // Add CARGO_HOME from the policy
    let cargo_home = spec.lane.home.join(".cargo");
    env.push((
        "CARGO_HOME".to_string(),
        cargo_home.to_string_lossy().into_owned(),
    ));

    Ok(ClaudeInvocation {
        program: "claude".to_string(),
        args,
        env,
        cwd: spec.lane.clone.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_lane() -> crate::LaneLayout {
        crate::LaneLayout {
            clone: PathBuf::from("/nonexistent-cp/lanes/l1/clone"),
            home: PathBuf::from("/nonexistent-cp/lanes/l1/home"),
            scratch: PathBuf::from("/nonexistent-cp/lanes/l1/scratch"),
            control: PathBuf::from("/nonexistent-cp/lanes/l1/control"),
            real_home: PathBuf::from("/nonexistent-cp/realhome"),
        }
    }

    fn test_spec() -> ClaudeSpec {
        ClaudeSpec {
            lane: test_lane(),
            model: "haiku".to_string(),
            proxy_base_url: "http://localhost:4123".to_string(),
            placeholder_key: "placeholder-key-123".to_string(),
            settings_file: PathBuf::from("/nonexistent-cp/settings.json"),
            mcp_config: PathBuf::from("/nonexistent-cp/mcp.json"),
            append_system_prompt_file: PathBuf::from("/nonexistent-cp/system-prompt.txt"),
            prompt: "Test prompt".to_string(),
            max_turns: 5,
            resume_session_id: None,
            cache_ttl: "1h".to_string(),
            path: "/usr/local/bin:/usr/bin:/bin".to_string(),
        }
    }

    #[test]
    fn fresh_run_args_vector() {
        let spec = test_spec();
        let inv = claude_command(&spec).unwrap();

        let expected = vec![
            "-p",
            "--model",
            "haiku",
            "--output-format",
            "stream-json",
            "--verbose",
            "--setting-sources",
            "",
            "--settings",
            "/nonexistent-cp/settings.json",
            "--mcp-config",
            "/nonexistent-cp/mcp.json",
            "--strict-mcp-config",
            "--append-system-prompt-file",
            "/nonexistent-cp/system-prompt.txt",
            "--max-turns",
            "5",
            "Test prompt",
        ];

        assert_eq!(inv.args.len(), expected.len(), "args length mismatch");
        for (i, (got, want)) in inv.args.iter().zip(expected.iter()).enumerate() {
            assert_eq!(
                got, want,
                "arg {} mismatch: got {:?}, want {:?}",
                i, got, want
            );
        }
    }

    #[test]
    fn resume_run_args_vector() {
        let mut spec = test_spec();
        spec.resume_session_id = Some("abc123def456".to_string());
        let inv = claude_command(&spec).unwrap();

        let expected = vec![
            "-p",
            "--model",
            "haiku",
            "--output-format",
            "stream-json",
            "--verbose",
            "--setting-sources",
            "",
            "--settings",
            "/nonexistent-cp/settings.json",
            "--mcp-config",
            "/nonexistent-cp/mcp.json",
            "--strict-mcp-config",
            "--append-system-prompt-file",
            "/nonexistent-cp/system-prompt.txt",
            "--max-turns",
            "5",
            "--resume",
            "abc123def456",
            "Test prompt",
        ];

        assert_eq!(inv.args.len(), expected.len(), "args length mismatch");
        for (i, (got, want)) in inv.args.iter().zip(expected.iter()).enumerate() {
            assert_eq!(
                got, want,
                "arg {} mismatch: got {:?}, want {:?}",
                i, got, want
            );
        }
    }

    #[test]
    fn bare_flag_never_present() {
        let spec = test_spec();
        let inv = claude_command(&spec).unwrap();
        assert!(
            !inv.args.contains(&"--bare".to_string()),
            "args must never contain --bare: {:?}",
            inv.args
        );
    }

    #[test]
    fn env_contains_exactly_required_keys() {
        let spec = test_spec();
        let inv = claude_command(&spec).unwrap();

        let keys: Vec<&str> = inv.env.iter().map(|(k, _)| k.as_str()).collect();
        let required_keys = vec![
            "HOME",
            "CLAUDE_CONFIG_DIR",
            "CLAUDE_CODE_PROMPT_CACHE_TTL",
            "ANTHROPIC_BASE_URL",
            "ANTHROPIC_API_KEY",
            "PATH",
            "CARGO_HOME",
        ];

        for key in &required_keys {
            assert!(keys.contains(key), "env missing required key: {}", key);
        }

        assert_eq!(
            keys.len(),
            required_keys.len(),
            "env has unexpected keys: {:?}",
            keys
        );
    }

    #[test]
    fn env_values_are_correct() {
        let spec = test_spec();
        let inv = claude_command(&spec).unwrap();

        let env_map: std::collections::HashMap<_, _> = inv.env.iter().cloned().collect();

        assert_eq!(
            env_map.get("HOME").unwrap(),
            "/nonexistent-cp/lanes/l1/home"
        );
        assert_eq!(
            env_map.get("CLAUDE_CONFIG_DIR").unwrap(),
            "/nonexistent-cp/lanes/l1/home/.claude-config"
        );
        assert_eq!(env_map.get("CLAUDE_CODE_PROMPT_CACHE_TTL").unwrap(), "1h");
        assert_eq!(
            env_map.get("ANTHROPIC_BASE_URL").unwrap(),
            "http://localhost:4123"
        );
        assert_eq!(
            env_map.get("ANTHROPIC_API_KEY").unwrap(),
            "placeholder-key-123"
        );
        assert_eq!(
            env_map.get("CARGO_HOME").unwrap(),
            "/nonexistent-cp/lanes/l1/home/.cargo"
        );
    }

    #[test]
    fn env_never_contains_real_api_key_string() {
        let spec = test_spec();
        let inv = claude_command(&spec).unwrap();

        // Ensure no real key string leaks (test would use a real-sounding pattern)
        for (_, v) in &inv.env {
            assert!(!v.contains("sk-"), "env value contains real key pattern");
            assert!(!v.contains("pk-"), "env value contains real key pattern");
        }
    }

    #[test]
    fn validation_empty_prompt() {
        let mut spec = test_spec();
        spec.prompt = String::new();
        let err = claude_command(&spec).unwrap_err();
        assert!(err.to_string().contains("prompt is empty"));
    }

    #[test]
    fn validation_zero_max_turns() {
        let mut spec = test_spec();
        spec.max_turns = 0;
        let err = claude_command(&spec).unwrap_err();
        assert!(err.to_string().contains("max_turns is 0"));
    }

    #[test]
    fn validation_invalid_resume_id_too_short() {
        let mut spec = test_spec();
        spec.resume_session_id = Some("abc".to_string());
        let err = claude_command(&spec).unwrap_err();
        assert!(err.to_string().contains("resume_session_id does not match"));
    }

    #[test]
    fn validation_invalid_resume_id_too_long() {
        let mut spec = test_spec();
        spec.resume_session_id = Some("a".repeat(65));
        let err = claude_command(&spec).unwrap_err();
        assert!(err.to_string().contains("resume_session_id does not match"));
    }

    #[test]
    fn validation_invalid_resume_id_bad_chars() {
        let mut spec = test_spec();
        spec.resume_session_id = Some("abc123xyz!@#".to_string());
        let err = claude_command(&spec).unwrap_err();
        assert!(err.to_string().contains("resume_session_id does not match"));
    }

    #[test]
    fn validation_valid_resume_id_at_boundaries() {
        let mut spec = test_spec();

        // 8 chars minimum
        spec.resume_session_id = Some("abcdef01".to_string());
        assert!(claude_command(&spec).is_ok());

        // 64 chars maximum
        spec.resume_session_id = Some("a".repeat(64));
        assert!(claude_command(&spec).is_ok());
    }

    #[test]
    fn validation_invalid_cache_ttl() {
        let mut spec = test_spec();
        spec.cache_ttl = "2h".to_string();
        let err = claude_command(&spec).unwrap_err();
        assert!(err.to_string().contains("cache_ttl must be '5m' or '1h'"));
    }

    #[test]
    fn validation_cache_ttl_5m() {
        let mut spec = test_spec();
        spec.cache_ttl = "5m".to_string();
        assert!(claude_command(&spec).is_ok());
    }

    #[test]
    fn validation_cache_ttl_1h() {
        let mut spec = test_spec();
        spec.cache_ttl = "1h".to_string();
        assert!(claude_command(&spec).is_ok());
    }

    #[test]
    fn validation_settings_file_not_absolute() {
        let mut spec = test_spec();
        spec.settings_file = PathBuf::from("relative/path");
        let err = claude_command(&spec).unwrap_err();
        assert!(err.to_string().contains("settings_file is not absolute"));
    }

    #[test]
    fn validation_mcp_config_not_absolute() {
        let mut spec = test_spec();
        spec.mcp_config = PathBuf::from("relative/path");
        let err = claude_command(&spec).unwrap_err();
        assert!(err.to_string().contains("mcp_config is not absolute"));
    }

    #[test]
    fn validation_append_system_prompt_file_not_absolute() {
        let mut spec = test_spec();
        spec.append_system_prompt_file = PathBuf::from("relative/path");
        let err = claude_command(&spec).unwrap_err();
        assert!(
            err.to_string()
                .contains("append_system_prompt_file is not absolute")
        );
    }

    #[test]
    fn cwd_is_lane_clone() {
        let spec = test_spec();
        let inv = claude_command(&spec).unwrap();
        assert_eq!(inv.cwd, PathBuf::from("/nonexistent-cp/lanes/l1/clone"));
    }

    #[test]
    fn program_is_claude() {
        let spec = test_spec();
        let inv = claude_command(&spec).unwrap();
        assert_eq!(inv.program, "claude");
    }

    #[test]
    fn debug_redacts_placeholder_key() {
        let spec = test_spec();
        let inv = claude_command(&spec).unwrap();
        let debug_str = format!("{:?}", inv);
        assert!(
            !debug_str.contains("placeholder-key-123"),
            "Debug output must not contain placeholder key: {}",
            debug_str
        );
        assert!(
            debug_str.contains("***REDACTED***"),
            "Debug output must contain redaction marker: {}",
            debug_str
        );
    }

    #[test]
    fn setting_sources_is_empty_string() {
        let spec = test_spec();
        let inv = claude_command(&spec).unwrap();

        // Find --setting-sources in args
        let idx = inv
            .args
            .iter()
            .position(|a| a == "--setting-sources")
            .expect("--setting-sources not found");
        assert_eq!(
            inv.args[idx + 1],
            "",
            "--setting-sources value must be empty string"
        );
    }

    #[test]
    fn path_from_spec_not_process_env() {
        let spec = test_spec();
        let inv = claude_command(&spec).unwrap();

        let env_map: std::collections::HashMap<_, _> = inv.env.iter().cloned().collect();
        assert_eq!(env_map.get("PATH").unwrap(), "/usr/local/bin:/usr/bin:/bin");
    }

    #[test]
    fn validation_path_empty() {
        let mut spec = test_spec();
        spec.path = String::new();
        let err = claude_command(&spec).unwrap_err();
        assert!(err.to_string().contains("path is empty"));
    }

    #[test]
    fn validation_path_entry_relative() {
        let mut spec = test_spec();
        spec.path = "/usr/bin:relative/path:/bin".to_string();
        let err = claude_command(&spec).unwrap_err();
        assert!(
            err.to_string().contains("path entry is not absolute"),
            "{}",
            err
        );
    }

    #[test]
    fn validation_path_entry_under_real_home() {
        let mut spec = test_spec();
        let real_home = spec.lane.real_home.to_string_lossy().to_string();
        spec.path = format!("/usr/bin:{}/.local/bin:/bin", real_home);
        let err = claude_command(&spec).unwrap_err();
        assert!(
            err.to_string().contains("path entry is under real home"),
            "{}",
            err
        );
    }

    #[test]
    fn validation_path_with_empty_entries() {
        // Empty entries search the current directory (the builder's clone); rejected.
        for path in ["/usr/bin::/bin", ":/usr/bin", "/usr/bin:"] {
            let mut spec = test_spec();
            spec.path = path.to_string();
            let err = claude_command(&spec).unwrap_err();
            assert!(err.to_string().contains("empty entry"), "{path}: {err}");
        }
    }
}
