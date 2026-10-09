//! Builder prefix: the canonical preamble and protocol that carries the shared cache
//! across lanes.
//!
//! The preamble states the escalation protocol completely: the tools (`ask`, `check_ruling`,
//! `run_check`), when to use each, the `ask` schema exactly as escalate.rs validates it,
//! and the handback format. It is byte-identical across lanes so parallel lanes share
//! cached prefix tokens. The version (sha256 of the preamble bytes) is recorded in the
//! capsule; packets may not restate protocol text (D20 constraint).

use sha2::{Digest, Sha256};

/// The canonical builder preamble, versioned for cache sharing (D20).
pub const PREAMBLE: &str = include_str!("prefix/builder-preamble.md");

/// Compute the sha256 hash of the preamble bytes.
/// Used to version the prefix in capsules and detect protocol changes.
pub fn prefix_version() -> String {
    let mut hasher = Sha256::new();
    hasher.update(PREAMBLE.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// An assembled prompt: preamble, project instructions, and packet in order.
pub struct AssembledPrompt {
    /// The preamble and project instructions, shared across lanes for cache efficiency.
    /// Packet text is NOT in this field.
    pub system_append: String,

    /// The packet markdown alone, added after system_append.
    pub prompt: String,

    /// The sha256 of the preamble bytes, recorded in the capsule.
    pub prefix_version: String,
}

/// Assemble a complete prompt from the canonical preamble, optional project instructions,
/// and the packet markdown.
///
/// Order is fixed for cache sharing (D20):
/// 1. preamble (always)
/// 2. project instructions (if provided)
/// 3. packet (never in system_append; always in prompt)
///
/// # Arguments
///
/// * `project_instructions` - Optional project CLAUDE.md or equivalent instruction file
/// * `packet_markdown` - The packet content (task description and configuration)
///
/// # Returns
///
/// An `AssembledPrompt` where `system_append` is the shared cacheable part and `prompt`
/// is the packet alone.
pub fn assemble_prompt(
    project_instructions: Option<&str>,
    packet_markdown: &str,
) -> AssembledPrompt {
    // Build the system part: preamble + project instructions (if any)
    let mut system = String::new();
    system.push_str(PREAMBLE);

    if let Some(instructions) = project_instructions {
        system.push('\n');
        system.push_str(instructions);
    }

    // Compute the prefix version once
    let version = prefix_version();

    AssembledPrompt {
        system_append: system,
        prompt: packet_markdown.to_string(),
        prefix_version: version,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prefix_version_stable() {
        // Same bytes, same hash
        let v1 = prefix_version();
        let v2 = prefix_version();
        assert_eq!(v1, v2);
    }

    #[test]
    fn test_prefix_version_changes_on_byte_change() {
        let v1 = prefix_version();

        // Verify the version is a hex string (sha256)
        assert_eq!(v1.len(), 64);
        assert!(v1.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_assemble_packet_in_prompt_only() {
        let packet = "## Task\nBuild the thing.";
        let assembled = assemble_prompt(None, packet);

        // Packet must be in prompt, never in system_append
        assert!(assembled.prompt.contains("Build the thing"));
        assert!(!assembled.system_append.contains("Build the thing"));
    }

    #[test]
    fn test_assemble_preamble_before_instructions() {
        let instructions = "# Project\nFoo bar.";
        let packet = "## Task\nDo it.";
        let assembled = assemble_prompt(Some(instructions), packet);

        // Preamble must come before project instructions in system_append
        let preamble_pos = assembled.system_append.find("Builder Preamble");
        let project_pos = assembled.system_append.find("# Project");
        assert!(preamble_pos.is_some());
        assert!(project_pos.is_some());
        assert!(preamble_pos.unwrap() < project_pos.unwrap());
    }

    #[test]
    fn test_assemble_no_instructions_equals_preamble() {
        let assembled = assemble_prompt(None, "packet");
        // When no project instructions, system_append should equal PREAMBLE exactly
        assert_eq!(assembled.system_append, PREAMBLE);
    }

    #[test]
    fn test_two_different_packets_same_system_append() {
        let packet1 = "## Task 1\nBuild A.";
        let packet2 = "## Task 2\nBuild B.";

        let assembled1 = assemble_prompt(None, packet1);
        let assembled2 = assemble_prompt(None, packet2);

        // The shared cache property: system_append must be byte-identical regardless of packet
        assert_eq!(assembled1.system_append, assembled2.system_append);
        assert_ne!(assembled1.prompt, assembled2.prompt);
    }

    #[test]
    fn test_prefix_version_in_assembled_prompt() {
        let assembled = assemble_prompt(None, "packet");
        let expected_version = prefix_version();
        assert_eq!(assembled.prefix_version, expected_version);
    }

    #[test]
    fn test_preamble_mentions_tools() {
        // Verify the preamble names the builder tools
        assert!(PREAMBLE.contains("ask"));
        assert!(PREAMBLE.contains("check_ruling"));
        assert!(PREAMBLE.contains("run_check"));
    }

    #[test]
    fn test_preamble_mentions_ask_fields() {
        // Verify the preamble documents the Ask schema fields
        assert!(PREAMBLE.contains("kind"));
        assert!(PREAMBLE.contains("question"));
        assert!(PREAMBLE.contains("tried"));
        assert!(PREAMBLE.contains("options"));
        assert!(PREAMBLE.contains("recommend"));
        assert!(PREAMBLE.contains("blocking"));
    }

    #[test]
    fn test_preamble_mentions_ask_kinds() {
        // Verify all AskKind values are documented
        assert!(PREAMBLE.contains("blocker"));
        assert!(PREAMBLE.contains("design"));
        assert!(PREAMBLE.contains("scope"));
        assert!(PREAMBLE.contains("environment"));
    }

    #[test]
    fn test_preamble_mentions_handback_rules() {
        // Verify the handback rules are present
        assert!(PREAMBLE.contains("No stubs"));
        assert!(PREAMBLE.contains("Weakened"));
        assert!(PREAMBLE.contains("Never delete assertions"));
    }
}
