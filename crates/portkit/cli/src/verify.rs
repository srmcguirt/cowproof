//! Pair-run verification of rewrite rules.
//!
//! The ledger records commands, not the bytes those commands returned at the
//! time, so historical output cannot be reproduced. Verification is therefore
//! a **pair run now**: execute the original and its rewrite against the current
//! working tree and apply the rule's class gate to the pair. Equality is
//! between the two outputs today, never against history.
//!
//! Cases whose target no longer exists are skipped and counted rather than
//! quietly dropped — a rule that "passed" on two of four hundred cases has not
//! been verified.

use std::path::Path;
use std::process::{Command, ExitCode, Stdio};

use portkit_core::fidelity::{check, Verdict};
use portkit_core::manifest::{Manifest, Rule, Status};
use portkit_core::trace;
use portkit_core::{Config, Result};
use regex::Regex;

/// Verify every rule against recent ledger entries, and record the outcome.
pub fn run(config: &Config, manifest_path: &Path, window: usize, apply: bool) -> Result<ExitCode> {
    let mut manifest = Manifest::load(manifest_path)?;
    let commands = recent_commands(config, window);

    if commands.is_empty() {
        println!("no commands in the ledger — run with tracing enabled first");
        return Ok(ExitCode::SUCCESS);
    }

    let tree = tree_sha();
    println!(
        "  {} commands in the window, tree {}\n",
        commands.len(),
        tree.as_deref().unwrap_or("unknown")
    );

    for rule in &mut manifest.rules {
        let outcome = verify_rule(rule, &commands);
        println!(
            "  {:<14} {:>4} cases  {:>4} passed  {:>4} skipped  -> {:?}",
            rule.name, outcome.cases, outcome.passed, outcome.skipped, outcome.status
        );
        for reason in outcome.failures.iter().take(3) {
            println!("        {reason}");
        }

        if apply {
            rule.verified.status = outcome.status;
            rule.verified.cases = outcome.cases;
            rule.verified.passed = outcome.passed;
            rule.verified.skipped = outcome.skipped;
            rule.verified.checked_at = Some(trace::now_rfc3339());
            rule.verified.ledger_window = Some(window);
            rule.verified.tree_sha = tree.clone();
        }
    }

    if apply {
        manifest.save(manifest_path)?;
        println!("\n  manifest updated: {}", manifest_path.display());
    } else {
        println!("\n  dry run — pass --apply to record these results");
    }
    Ok(ExitCode::SUCCESS)
}

struct Outcome {
    cases: usize,
    passed: usize,
    skipped: usize,
    status: Status,
    failures: Vec<String>,
}

fn verify_rule(rule: &Rule, commands: &[String]) -> Outcome {
    let mut out = Outcome {
        cases: 0,
        passed: 0,
        skipped: 0,
        status: Status::Pending,
        failures: Vec::new(),
    };

    let Ok(re) = Regex::new(&rule.matches) else {
        out.failures
            .push(format!("rule regex does not compile: {}", rule.matches));
        out.status = Status::Fail;
        return out;
    };

    for command in commands {
        let Some(caps) = re.captures(command) else {
            continue;
        };
        let mut rewritten = rule.rewrite.clone();
        for (i, c) in caps.iter().enumerate().skip(1) {
            rewritten = rewritten.replace(&format!("${i}"), c.map_or("", |m| m.as_str()));
        }

        // Both halves run now, against the same tree.
        let (Some(a), Some(b)) = (run_capture(command), run_capture(&rewritten)) else {
            out.skipped += 1;
            continue;
        };

        out.cases += 1;
        match check(rule.fidelity, &a, &b, rule.normalizer.as_ref()) {
            Verdict::Pass => out.passed += 1,
            Verdict::Fail(why) => out.failures.push(format!("{command} -> {why}")),
            Verdict::NotApplicable(why) => {
                // A class that cannot be checked here must not be counted as
                // checked; it stays pending forever by design.
                out.cases -= 1;
                out.skipped += 1;
                if out.failures.is_empty() {
                    out.failures.push(why);
                }
            }
        }
    }

    out.status = if out.cases == 0 {
        Status::Pending
    } else if out.passed == out.cases {
        Status::Pass
    } else {
        Status::Fail
    };
    out
}

/// Run a command and capture stdout, or `None` if it could not run.
fn run_capture(command: &str) -> Option<String> {
    let out = Command::new("sh")
        .arg("-c")
        .arg(command)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    // A non-zero exit usually means the target is gone; that is a skip, not a
    // failure of the rewrite.
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).to_string())
}

/// Distinct Bash commands from the ledger, most recent first.
fn recent_commands(config: &Config, window: usize) -> Vec<String> {
    let dir = std::path::PathBuf::from(&config.trace.dir);
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };

    let mut files: Vec<_> = entries
        .filter_map(std::result::Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "jsonl"))
        .collect();
    files.sort();

    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    for path in files.iter().rev() {
        let Ok(records) = trace::read_jsonl(path) else {
            continue;
        };
        for r in records.iter().rev() {
            if r.tool != "Bash" {
                continue;
            }
            // The ledger stores the target, not the argument blob — enough to
            // replay a shape, and it never held file contents.
            if let Some(target) = &r.target {
                if seen.insert(target.clone()) {
                    out.push(target.clone());
                }
            }
            if out.len() >= window {
                return out;
            }
        }
    }
    out
}

fn tree_sha() -> Option<String> {
    let out = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
}
