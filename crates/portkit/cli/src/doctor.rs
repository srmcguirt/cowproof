//! `pk doctor` — is this session actually being watched?
//!
//! Hooks fail silently by design: a hook that breaks the session it measures
//! is worse than one that measures nothing. The cost of that choice is that a
//! misconfigured setup looks exactly like a quiet one, and you find out weeks
//! later that the ledger is empty.
//!
//! So this reports the three things that have to be true, separately — whether
//! the hooks are *registered*, whether they are *able* to record, and whether
//! they have *actually fired*. The third is the only one that is evidence.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use portkit_core::trace::{self, Surface};
use portkit_core::{Config, Result};
use serde_json::json;

/// One thing that is either true or not, with what to do if it is not.
struct Check {
    label: &'static str,
    ok: bool,
    detail: String,
    fix: Option<String>,
}

impl Check {
    fn status(&self) -> &'static str {
        if self.ok {
            "pass"
        } else {
            "miss"
        }
    }
}

pub fn run(config: &Config, json_output: bool, settings_file: Option<PathBuf>) -> Result<ExitCode> {
    let mut checks = Vec::new();

    // 1. Reachable. Hooks invoke `pk` by name, so a binary that only exists in
    //    target/release is not wired even if the settings say it is.
    let on_path = which("pk");
    checks.push(Check {
        label: "pk on PATH",
        ok: on_path.is_some(),
        detail: on_path.clone().unwrap_or_else(|| "not found".into()),
        fix: Some("hooks invoke `pk` by name; install it or use an absolute path".into()),
    });

    // 2. Registered.
    let settings = match settings_file {
        Some(file) => vec![file],
        None => settings_files(),
    };
    let registered: Vec<&PathBuf> = settings.iter().filter(|p| mentions_hook(p)).collect();
    checks.push(Check {
        label: "hooks registered",
        ok: !registered.is_empty(),
        detail: if registered.is_empty() {
            format!("not in any of {} settings files", settings.len())
        } else {
            registered
                .iter()
                .map(|p| short(p))
                .collect::<Vec<_>>()
                .join(", ")
        },
        fix: Some("add `pk hook post-tool-use` under PostToolUse in .claude/settings.json".into()),
    });

    // 3. Able to record. A registered hook with tracing off records nothing,
    //    which is the most confusing of the failure modes.
    checks.push(Check {
        label: "tracing enabled",
        ok: config.trace.enabled,
        detail: format!(
            "[trace] enabled = {}, dir = {}",
            config.trace.enabled,
            config.trace.resolve_dir().display()
        ),
        fix: Some("set `[trace] enabled = true` in your config".into()),
    });

    // 4. Actually fired. The only check that is evidence rather than intent.
    let observed = observed_records(config);
    checks.push(Check {
        label: "hooks have fired",
        ok: observed.0 > 0,
        detail: match observed {
            (0, _) => "no agent-surface records — nothing has been observed".into(),
            (n, Some(last)) => format!("{n} observed calls, most recent {last}"),
            (n, None) => format!("{n} observed calls"),
        },
        fix: Some("run any tool in a hooked session, then re-check".into()),
    });

    // Same exit code in both modes: non-zero when any check is missing, so a
    // setup script can gate on it. `--json` only changes what is printed.
    let all_ok = checks.iter().all(|c| c.ok);
    let exit = if all_ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    };

    if json_output {
        // `traced` is the evidence check alone: tracing configured and a
        // registered hook are intent, a recorded agent-surface call is proof.
        let traced = observed.0 > 0;
        let checks: Vec<_> = checks
            .iter()
            .map(|c| json!({ "name": c.label, "status": c.status(), "detail": c.detail }))
            .collect();
        println!("{}", json!({ "checks": checks, "traced": traced }));
        return Ok(exit);
    }

    let width = checks.iter().map(|c| c.label.len()).max().unwrap_or(0);
    for c in &checks {
        println!(
            "  {}  {:<width$}  {}",
            if c.ok { "OK  " } else { "MISS" },
            c.label,
            c.detail,
            width = width
        );
    }

    let failed: Vec<&Check> = checks.iter().filter(|c| !c.ok).collect();
    if failed.is_empty() {
        println!("\n  this session is being watched");
        return Ok(exit);
    }

    println!();
    for c in &failed {
        if let Some(fix) = &c.fix {
            println!("  {} -> {fix}", c.label);
        }
    }
    Ok(exit)
}

/// Settings files Claude Code reads, most general first.
fn settings_files() -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Some(dir) = std::env::var_os("CLAUDE_CONFIG_DIR") {
        out.push(PathBuf::from(dir).join("settings.json"));
    }
    if let Some(home) = std::env::var_os("HOME") {
        out.push(PathBuf::from(home).join(".claude/settings.json"));
    }
    out.push(PathBuf::from(".claude/settings.json"));
    out.push(PathBuf::from(".claude/settings.local.json"));
    out
}

fn mentions_hook(path: &Path) -> bool {
    std::fs::read_to_string(path).is_ok_and(|s| text_mentions_hook(&s))
}

/// Does this settings text register a `pk hook` command?
///
/// Matches `pk hook ...`, `cowproof pk hook ...`, and an absolute or quoted
/// path to the executable (`/opt/bin/pk hook ...`, `"/my tools/pk" hook ...`,
/// also as it appears inside a JSON string, `\"/my tools/pk\" hook`). The
/// word before `hook` must be `pk` itself: `spk hook`, `pk-read hook` and
/// `pk hooks` do not count.
fn text_mentions_hook(text: &str) -> bool {
    text.match_indices("hook").any(|(at, word)| {
        let after = &text[at + word.len()..];
        let word_ends = after
            .chars()
            .next()
            .is_none_or(|c| c.is_whitespace() || c == '"' || c == '\'');
        if !word_ends {
            return false;
        }
        // Walk back over the space, and over the closing quote of a quoted
        // executable, to the end of its name.
        let before = text[..at]
            .trim_end_matches(char::is_whitespace)
            .trim_end_matches(['"', '\'', '\\']);
        let before = before.strip_suffix(".exe").unwrap_or(before);
        before.strip_suffix("pk").is_some_and(|head| {
            head.chars()
                .next_back()
                .is_none_or(|c| c.is_whitespace() || matches!(c, '/' | '\\' | '"' | '\''))
        })
    })
}

fn short(path: &Path) -> String {
    let s = path.display().to_string();
    match std::env::var("HOME") {
        Ok(home) if s.starts_with(&home) => s.replacen(&home, "~", 1),
        _ => s,
    }
}

/// Count records the hook wrote, and when the last one landed.
fn observed_records(config: &Config) -> (usize, Option<String>) {
    let dir = config.trace.resolve_dir();
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return (0, None);
    };

    let mut count = 0usize;
    let mut latest: Option<String> = None;
    for entry in entries.filter_map(std::result::Result::ok) {
        let path = entry.path();
        if !path.extension().is_some_and(|e| e == "jsonl") {
            continue;
        }
        let Ok(records) = trace::read_jsonl(&path) else {
            continue;
        };
        for r in records.iter().filter(|r| r.surface == Surface::Agent) {
            count += 1;
            if latest.as_ref().is_none_or(|l| &r.at > l) {
                latest = Some(r.at.clone());
            }
        }
    }
    (count, latest)
}

/// First match for a bare command name on PATH.
fn which(name: &str) -> Option<String> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|p| p.is_file())
        .map(|p| p.display().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_status_is_pass_or_miss() {
        let mut check = Check {
            label: "x",
            ok: true,
            detail: String::new(),
            fix: None,
        };
        assert_eq!(check.status(), "pass");
        check.ok = false;
        assert_eq!(check.status(), "miss");
    }

    #[test]
    fn the_plain_and_the_cowproof_forms_are_registered() {
        assert!(text_mentions_hook(
            r#"{"hooks":{"PostToolUse":[{"command":"pk hook post-tool-use"}]}}"#
        ));
        assert!(text_mentions_hook(
            r#"{"command":"cowproof pk hook post-tool-use"}"#
        ));
    }

    #[test]
    fn an_absolute_path_to_pk_is_registered() {
        for text in [
            r#"{"command":"/opt/cowproof/bin/pk hook post-tool-use"}"#,
            r#"{"command":"/opt/cowproof/bin/cowproof pk hook post-tool-use"}"#,
            r#"{"command":"\"/opt/my tools/bin/pk\" hook post-tool-use"}"#,
            r#"{"command":"'/opt/my tools/bin/pk' hook post-tool-use"}"#,
            r#"{"command":"C:\\tools\\pk.exe hook post-tool-use"}"#,
            "/opt/bin/pk hook session-end",
        ] {
            assert!(text_mentions_hook(text), "should register: {text}");
        }
    }

    #[test]
    fn near_misses_are_not_registered() {
        for text in [
            "",
            r#"{"command":"echo hook"}"#,
            r#"{"command":"spk hook post-tool-use"}"#,
            r#"{"command":"/opt/bin/pk-read hook"}"#,
            r#"{"command":"pk hooks list"}"#,
            r#"{"command":"pk status # no hook here"}"#,
            r#"{"hook":"pk"}"#,
        ] {
            assert!(!text_mentions_hook(text), "should not register: {text}");
        }
    }
}
