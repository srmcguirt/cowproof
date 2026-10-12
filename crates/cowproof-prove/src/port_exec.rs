//! The held-out capture of a `process` port: `pk port exec` instead of `pk port capture`.
//!
//! A port whose adapter is `process` has a script as its reference. The verifier captures the
//! director's held-out cases from it the way the visible fixtures were captured: one process
//! per case, in a fresh root, with the declared `path_roots` substituted, inside the
//! verifier's own sandbox (`COWPROOF_SANDBOXED=1`, so `pk port exec` inherits it and shows the
//! network is gone instead of nesting a second sandbox). The reference's environment goes in
//! as `--env` flags (the harness builds its environment, it does not inherit one) and its
//! directory as `--src`.

use crate::port::{PortCapsule, sh_quote};
use cowproof_core::PortReference;
use std::path::Path;

/// The command the verifier runs to capture the held-out cases of a `process` port.
pub(crate) fn capture_command(
    spec: &PortCapsule,
    reference: &PortReference,
    pk_exe: &Path,
    cases: &Path,
    fixtures: &Path,
) -> String {
    let mut command = format!(
        "{} pk port exec --cmd {} --cases {} --out {}",
        sh_quote(&pk_exe.to_string_lossy()),
        sh_quote(&reference.cmd),
        sh_quote(&cases.to_string_lossy()),
        sh_quote(&fixtures.to_string_lossy()),
    );
    if let Some(cwd) = &reference.cwd {
        command.push_str(&format!(" --src {}", sh_quote(cwd)));
    }
    for (key, value) in &reference.env {
        command.push_str(&format!(" --env {}", sh_quote(&format!("{key}={value}"))));
    }
    for root in &spec.path_roots {
        // Only the tokens are substitutions; a plain prefix is a declaration for lint.
        if root.starts_with('$') {
            command.push_str(&format!(" --path-root {}", sh_quote(root)));
        }
    }
    command
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn spec(path_roots: &[&str]) -> PortCapsule {
        serde_json::from_value(serde_json::json!({
            "lang": "shell", "adapter": "process", "fixtures": "fx", "tools": ["t"],
            "epsilon": 0.0, "ignore_paths": [], "unordered_arrays": false,
            "path_roots": path_roots,
        }))
        .unwrap()
    }

    #[test]
    fn the_capture_carries_the_reference_the_environment_and_the_declared_roots() {
        let reference = PortReference {
            cmd: "sh \"$PORTKIT_SRC/ref/it's.sh\"".into(),
            cwd: Some("tools dir".into()),
            env: BTreeMap::from([(
                "PORTKIT_NOW".to_string(),
                "2026-01-02T03:04:05Z".to_string(),
            )]),
            runtime: None,
        };
        let command = capture_command(
            &spec(&["$ROOT", "$HOME", "/usr/lib"]),
            &reference,
            Path::new("/opt/bin/cowproof"),
            Path::new("/w/cases.jsonl"),
            Path::new("/w/out"),
        );
        assert_eq!(
            command,
            "'/opt/bin/cowproof' pk port exec --cmd 'sh \"$PORTKIT_SRC/ref/it'\\''s.sh\"' \
             --cases '/w/cases.jsonl' --out '/w/out' --src 'tools dir' \
             --env 'PORTKIT_NOW=2026-01-02T03:04:05Z' --path-root '$ROOT' --path-root '$HOME'"
        );
    }

    #[test]
    fn a_reference_with_no_directory_runs_from_the_tree() {
        let reference = PortReference {
            cmd: "sh ref.sh".into(),
            cwd: None,
            env: BTreeMap::new(),
            runtime: None,
        };
        let command = capture_command(
            &spec(&[]),
            &reference,
            Path::new("/x/cowproof"),
            Path::new("/c"),
            Path::new("/o"),
        );
        assert!(
            !command.contains("--src") && !command.contains("--path-root"),
            "{command}"
        );
    }

    #[test]
    fn the_tokens_cowproof_accepts_are_the_ones_portkit_substitutes() {
        let mut ours: Vec<&str> = cowproof_core::port::PATH_ROOT_TOKENS.to_vec();
        let mut theirs: Vec<&str> = portkit_port::process::ROOT_TOKENS.to_vec();
        ours.sort_unstable();
        theirs.sort_unstable();
        assert_eq!(ours, theirs);
    }
}
