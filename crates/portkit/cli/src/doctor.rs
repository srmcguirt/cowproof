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

/// One thing that is either true or not, with what to do if it is not.
struct Check {
    label: &'static str,
    ok: bool,
    detail: String,
    fix: Option<String>,
}

pub fn run(config: &Config) -> Result<ExitCode> {
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
    let settings = settings_files();
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
            config.trace.enabled, config.trace.dir
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
        return Ok(ExitCode::SUCCESS);
    }

    println!();
    for c in &failed {
        if let Some(fix) = &c.fix {
            println!("  {} -> {fix}", c.label);
        }
    }
    // Non-zero so a setup script can gate on it.
    Ok(ExitCode::FAILURE)
}

/// Settings files Claude Code reads, most general first.
fn settings_files() -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Some(home) = std::env::var_os("HOME") {
        out.push(PathBuf::from(home).join(".claude/settings.json"));
    }
    out.push(PathBuf::from(".claude/settings.json"));
    out.push(PathBuf::from(".claude/settings.local.json"));
    out
}

fn mentions_hook(path: &Path) -> bool {
    std::fs::read_to_string(path).is_ok_and(|s| s.contains("pk hook"))
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
    let dir = PathBuf::from(&config.trace.dir);
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
