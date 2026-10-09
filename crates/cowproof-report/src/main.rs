#![forbid(unsafe_code)]
use anyhow::{Context, Result, bail};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    path::{Path, PathBuf},
};

#[derive(Debug, Deserialize)]
struct RuleFile {
    rules: Vec<Rule>,
}
#[derive(Debug, Deserialize)]
struct Rule {
    pattern: String,
    files: Vec<String>,
    explanation: String,
    #[serde(default)]
    added_only: bool,
    #[serde(default)]
    path_only: bool,
    #[serde(default)]
    path_or_content: bool,
    requires: Option<String>,
    #[serde(default)]
    applied_migration: bool,
}
#[derive(Debug, Clone)]
struct Delta {
    path: String,
    added: Vec<(usize, String)>,
    removed: Vec<(usize, String)>,
    context: Vec<String>,
}
#[derive(Debug, Serialize)]
struct Finding {
    file: String,
    line: Option<usize>,
    pattern: String,
    explanation: String,
}
#[derive(Debug, Serialize)]
struct Check {
    command: String,
    result: String,
    classification: String,
}
#[derive(Debug, Serialize)]
struct AssertionChange {
    file: String,
    removed: usize,
    added: usize,
    net_loss: usize,
}
#[derive(Debug, Serialize)]
struct Report {
    lane_id: String,
    status: String,
    minutes: Option<u64>,
    files_changed: usize,
    lines_added: usize,
    lines_removed: usize,
    outside_ownership_count: usize,
    checks: Vec<Check>,
    packet_commands_unreported: Vec<String>,
    flaws: Vec<Finding>,
    removed_assertions: Vec<AssertionChange>,
    limits: Vec<String>,
    unverified: Vec<String>,
    questions: Vec<String>,
    verdict_hint: String,
    verdict_reasons: Vec<String>,
    sample_handoff: Option<String>,
}
fn value_str(v: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|k| v.get(*k).and_then(Value::as_str).map(str::to_owned))
}
fn value_num(v: &Value, keys: &[&str]) -> Option<u64> {
    keys.iter().find_map(|k| v.get(*k).and_then(Value::as_u64))
}
fn parse_patch(patch: &str) -> Vec<Delta> {
    let mut out: Vec<Delta> = Vec::new();
    let mut new_line = 1usize;
    for line in patch.lines() {
        if let Some(rest) = line.strip_prefix("diff --git a/") {
            let path = rest
                .split_once(" b/")
                .map(|(_, b)| b.to_string())
                .unwrap_or_default();
            out.push(Delta {
                path,
                added: Vec::new(),
                removed: Vec::new(),
                context: Vec::new(),
            });
            new_line = 1;
            continue;
        }
        if out.is_empty() {
            continue;
        }
        let d = out.last_mut().unwrap();
        if line.starts_with("+++") || line.starts_with("---") || line.starts_with("\\") {
            continue;
        }
        if line.starts_with("@@") {
            if let Some((_, rest)) = line.split_once('+') {
                new_line = rest
                    .split([',', ' '])
                    .next()
                    .and_then(|x| x.parse().ok())
                    .unwrap_or(1);
            }
            continue;
        }
        if let Some(s) = line.strip_prefix('+') {
            d.added.push((new_line, s.to_string()));
            new_line += 1;
        } else if let Some(s) = line.strip_prefix('-') {
            d.removed.push((0, s.to_string()));
        } else if let Some(s) = line.strip_prefix(' ') {
            d.context.push(s.to_string());
            new_line += 1;
        }
    }
    out
}
fn glob_match(pattern: &str, text: &str) -> bool {
    let mut re = String::from("^");
    let chars: Vec<char> = pattern.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '*' if i + 1 < chars.len() && chars[i + 1] == '*' => {
                re.push_str(".*");
                i += 1;
            }
            '*' => re.push_str("[^/]*"),
            '?' => re.push_str("[^/]"),
            c => re.push_str(&regex::escape(&c.to_string())),
        }
        i += 1;
    }
    re.push('$');
    Regex::new(&re).map(|r| r.is_match(text)).unwrap_or(false)
}
fn parse_checks(text: &str) -> Vec<Check> {
    let mut checks = Vec::new();
    let mut table_header: Option<(usize, usize)> = None;
    for line in text.lines() {
        if let Some((command, result)) = arrow_check(line)
            && is_command(&command)
        {
            checks.push(Check {
                command,
                classification: classify(&result),
                result,
            });
            continue;
        }
        let cells: Vec<_> = line
            .trim()
            .trim_matches('|')
            .split('|')
            .map(str::trim)
            .collect();
        let low: Vec<_> = cells.iter().map(|s| s.to_ascii_lowercase()).collect();
        if let (Some(ci), Some(ri)) = (
            low.iter()
                .position(|s| s.contains("command") || s == "check"),
            low.iter().position(|s| s.contains("result")),
        ) {
            table_header = Some((ci, ri));
            continue;
        }
        if let Some((ci, ri)) = table_header {
            if line.trim_start().starts_with('|')
                && !cells
                    .iter()
                    .all(|c| c.chars().all(|x| x == '-' || x == ':' || x == ' '))
            {
                if let (Some(c), Some(r)) = (cells.get(ci), cells.get(ri))
                    && !c.is_empty()
                    && !r.is_empty()
                    && is_command(&strip_code(c))
                {
                    checks.push(Check {
                        command: strip_code(c),
                        result: r.to_string(),
                        classification: classify(r),
                    });
                }
            } else if !line.trim_start().starts_with('|') {
                table_header = None;
            }
        }
        if (line.trim_start().starts_with('-') || line.trim_start().starts_with('*'))
            && let Some((cmd, res)) = bullet_pair(line)
            && is_command(&cmd)
        {
            checks.push(Check {
                command: cmd,
                classification: classify(&res),
                result: res,
            });
        }
    }
    checks.extend(parse_fenced_checks(text));
    checks
}
fn arrow_check(line: &str) -> Option<(String, String)> {
    let re = Regex::new(r"^\s*(.+?)\s{2,}->\s*(.+?)\s*$").ok()?;
    let captures = re.captures(line)?;
    Some((
        captures[1].trim().to_string(),
        captures[2].trim().to_string(),
    ))
}
fn parse_fenced_checks(text: &str) -> Vec<Check> {
    let lines: Vec<_> = text.lines().collect();
    let mut section = false;
    let mut checks = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i].trim();
        if line.starts_with('#') {
            let heading = line.trim_start_matches('#').trim().to_ascii_lowercase();
            section = heading.contains("check")
                || heading.contains("command")
                || heading.contains("verification");
            i += 1;
            continue;
        }
        if !section || !line.starts_with("```") {
            i += 1;
            continue;
        }
        i += 1;
        let mut commands = Vec::new();
        while i < lines.len() && !lines[i].trim().starts_with("```") {
            let cmd = lines[i].trim();
            if arrow_check(cmd).is_none() && is_command(cmd) {
                commands.push(cmd.to_string());
            }
            i += 1;
        }
        if i < lines.len() {
            i += 1;
        }
        let mut result = None;
        while i < lines.len() {
            let next = lines[i].trim();
            if next.starts_with('#') || next.starts_with("```") {
                break;
            }
            i += 1;
            if !next.is_empty() && !next.starts_with("Commands below") {
                result = Some(next.to_string());
                break;
            }
        }
        if let Some(result) = result {
            for command in commands {
                checks.push(Check {
                    command,
                    classification: classify(&result),
                    result: result.clone(),
                });
            }
        }
    }
    checks
}
fn is_command(s: &str) -> bool {
    let s = s.trim_start();
    [
        "cargo ",
        "node ",
        "npm ",
        "pnpm ",
        "yarn ",
        "git ",
        "rustfmt ",
        "LANE_SCRATCH=",
    ]
    .iter()
    .any(|prefix| s.starts_with(prefix))
}
fn strip_code(s: &str) -> String {
    s.trim().trim_matches('`').to_string()
}
fn bullet_pair(line: &str) -> Option<(String, String)> {
    let re = Regex::new(r"^\s*[-*]\s+`([^`]+)`\s*(?:—|–|-)\s*(.+?)\s*$").ok()?;
    let c = re.captures(line)?;
    Some((c[1].to_string(), c[2].to_string()))
}
fn classify(s: &str) -> String {
    let l = s.to_ascii_lowercase();
    let failure = Regex::new(r"\b(?:fail(?:ed|ure)?|error)\b")
        .unwrap()
        .find_iter(&l)
        .map(|m| m.start())
        .last();
    let success = Regex::new(r"\b(?:pass(?:ed|ing)?|success(?:ful)?|clean|ok)\b")
        .unwrap()
        .find_iter(&l)
        .map(|m| m.start())
        .last();
    let not_run = Regex::new(r"\bnot[ -]run\b|\bnot performed\b|\bnot executed\b")
        .unwrap()
        .find_iter(&l)
        .map(|m| m.start())
        .last();
    let skipped = Regex::new(r"\bskipped\b").is_ok_and(|re| re.is_match(&l))
        && !Regex::new(r"\b(?:0\s+skipped|no skips|not skipped)\b").is_ok_and(|re| re.is_match(&l));
    let final_rerun_passed =
        Regex::new(r"\b(?:final\s+)?(?:re)?run\s+passed\b").is_ok_and(|re| re.is_match(&l));
    let no_failures =
        Regex::new(r"\b(?:0\s+fail(?:ed|ures?)?|no\s+failures?|exit(?:\s+code)?\s*[:=]?\s*0)\b")
            .is_ok_and(|re| re.is_match(&l));
    if success.is_none() && (not_run.is_some() || skipped) {
        "not run"
    } else if final_rerun_passed
        || no_failures
        || success.is_some_and(|pass_at| failure.is_none_or(|fail_at| pass_at > fail_at))
    {
        "pass"
    } else if failure.is_some() {
        "fail"
    } else if success.is_some() {
        "pass"
    } else {
        "unclear"
    }
    .to_string()
}
fn packet_commands(text: &str) -> Vec<String> {
    let mut inside = false;
    let mut out = BTreeSet::new();
    for line in text.lines() {
        if line.trim_start().starts_with("```") {
            inside = !inside;
            continue;
        }
        if inside {
            let s = line.trim();
            if s.starts_with("cargo ")
                || s.starts_with("git ")
                || s.starts_with("npm ")
                || s.starts_with("pnpm ")
                || s.starts_with("yarn ")
            {
                out.insert(s.to_string());
            }
        }
    }
    out.into_iter().collect()
}
fn packet_has_lane_id(text: &str, id: &str) -> bool {
    Regex::new(&format!(r#""id"\s*:\s*"{}""#, regex::escape(id))).is_ok_and(|re| re.is_match(text))
}
fn handoff_from_patch(patch: &str, summary: &Value, repo: Option<&Path>) -> Option<String> {
    let path = value_str(summary, &["handoff"]).or_else(|| {
        let handoff_dir = repo
            .and_then(|r| fs::read_to_string(r.join("lanes.config.json")).ok())
            .and_then(|s| serde_json::from_str::<Value>(&s).ok())
            .and_then(|v| value_str(&v, &["handoffDir"]))
            .unwrap_or_else(|| "docs/handoffs".to_string());
        patch.lines().find_map(|l| {
            l.strip_prefix("+++ b/")
                .map(str::to_owned)
                .filter(|p| p.starts_with(&handoff_dir) && p.contains("handoff"))
        })
    })?;
    let mut capture = false;
    let mut text = String::new();
    let mut matching = false;
    for line in patch.lines() {
        if let Some(p) = line.strip_prefix("+++ b/") {
            matching = p == path;
            capture = false;
            continue;
        }
        if matching {
            if line.starts_with("@@") {
                capture = true;
                continue;
            }
            if capture
                && let Some(s) = line.strip_prefix('+')
                && !s.starts_with("+++")
            {
                text.push_str(s);
                text.push('\n');
            }
        }
    }
    if text.is_empty() {
        if let Some(r) = repo {
            fs::read_to_string(r.join(path)).ok()
        } else {
            None
        }
    } else {
        Some(text)
    }
}
fn extract_sections(text: &str, key: &str) -> Vec<String> {
    let mut on = false;
    let mut out = Vec::new();
    let mut cur = String::new();
    for line in text.lines() {
        if line.starts_with('#') {
            if on && !cur.trim().is_empty() {
                out.push(cur.trim_matches('\n').to_string());
                cur.clear();
            }
            let h = line.trim_start_matches('#').trim().to_ascii_lowercase();
            let question = h.contains("question");
            on = match key {
                "limits" => !question && (h.contains("limit") || h.contains("deferred")),
                "unverified" => {
                    !question && (h.contains("unverified") || h.contains("not verified"))
                }
                _ => question,
            };
            continue;
        }
        if on {
            if !cur.is_empty() {
                cur.push('\n');
            }
            cur.push_str(line);
        }
    }
    if on && !cur.trim().is_empty() {
        out.push(cur.trim_matches('\n').to_string());
    }
    out.into_iter()
        .map(|s| s.chars().take(1200).collect())
        .collect()
}
fn assertions(s: &str) -> usize {
    let re = Regex::new(r"(?i)\b(assert|expect|RAISE|must fail)\b|#\[test\]").unwrap();
    re.find_iter(s).count()
}
fn main_report(args: &[String]) -> Result<Report> {
    if args.is_empty() {
        bail!(
            "usage: lanes-report <lane-dir> [--repo DIR] [--packet FILE] [--baseline FILE] [--json]"
        );
    }
    let lane = PathBuf::from(&args[0]);
    let mut repo = None;
    let mut packet_arg = None;
    let mut baseline = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--repo" => {
                i += 1;
                repo = Some(PathBuf::from(
                    args.get(i).context("--repo needs a directory")?,
                ));
            }
            "--packet" => {
                i += 1;
                packet_arg = Some(PathBuf::from(args.get(i).context("--packet needs a file")?));
            }
            "--baseline" => {
                i += 1;
                baseline = Some(args.get(i).context("--baseline needs a file")?.clone());
            }
            "--json" => {}
            x => bail!("unknown option: {x}"),
        }
        i += 1;
    }
    let summary: Value =
        serde_json::from_slice(&fs::read(lane.join("summary.json")).context("read summary.json")?)
            .context("parse summary.json")?;
    let patch = fs::read_to_string(lane.join("lane.patch")).context("read lane.patch")?;
    let outside = fs::read_to_string(lane.join("outside-ownership.patch")).unwrap_or_default();
    let deltas = parse_patch(&patch);
    let files = deltas
        .iter()
        .map(|d| d.path.as_str())
        .collect::<BTreeSet<_>>()
        .len();
    let added: usize = deltas.iter().map(|d| d.added.len()).sum();
    let removed: usize = deltas.iter().map(|d| d.removed.len()).sum();
    let mut handoff = handoff_from_patch(&patch, &summary, repo.as_deref());
    if handoff.is_none()
        && let Some(p) = value_str(&summary, &["handoff"])
        && let Some(r) = repo.as_deref()
    {
        handoff = fs::read_to_string(r.join(p)).ok();
    }
    if handoff.is_none() {
        handoff = fs::read_to_string(lane.join("handoff.md")).ok();
    }
    let handoff = handoff.unwrap_or_default();
    let checks = parse_checks(&handoff);
    let packet = packet_arg
        .and_then(|p| fs::read_to_string(p).ok())
        .or_else(|| {
            let id = value_str(&summary, &["id", "lane_id"]).unwrap_or_default();
            let root = repo.as_deref().unwrap_or(Path::new("."));
            [root.join("packets"), root.join(".")].iter().find_map(|d| {
                fs::read_dir(d)
                    .ok()?
                    .filter_map(Result::ok)
                    .map(|e| e.path())
                    .find(|p| {
                        p.is_file()
                            && p.extension().is_some_and(|x| x == "md")
                            && fs::read_to_string(p).is_ok_and(|s| packet_has_lane_id(&s, &id))
                    })
                    .and_then(|p| fs::read_to_string(p).ok())
            })
        });
    let named = packet.as_deref().map(packet_commands).unwrap_or_default();
    let reported: BTreeSet<_> = checks.iter().map(|c| c.command.as_str()).collect();
    let missing: Vec<String> = named
        .into_iter()
        .filter(|c| !reported.contains(c.as_str()))
        .collect();
    let rules: RuleFile =
        toml::from_str(include_str!("../rules/flaws.toml")).context("parse flaw rules")?;
    let mut flaws = Vec::new();
    for d in &deltas {
        for rule in &rules.rules {
            if !rule.files.iter().any(|g| glob_match(g, &d.path)) {
                continue;
            }
            let re = Regex::new(&rule.pattern)
                .with_context(|| format!("bad rule pattern {}", rule.pattern))?;
            if rule.applied_migration {
                if let Some(base) = baseline.as_deref()
                    && let Some(file) = d.path.split("/migrations/").nth(1)
                    && let Some(file) = file.rsplit('/').next()
                    && file <= base.rsplit('/').next().unwrap_or(base)
                {
                    flaws.push(Finding {
                        file: d.path.clone(),
                        line: None,
                        pattern: format!("--baseline {base}"),
                        explanation: rule.explanation.clone(),
                    });
                }
                continue;
            }
            if rule.path_only {
                if re.is_match(&d.path) {
                    flaws.push(Finding {
                        file: d.path.clone(),
                        line: None,
                        pattern: rule.pattern.clone(),
                        explanation: rule.explanation.clone(),
                    });
                }
                continue;
            }
            if rule.path_or_content && re.is_match(&d.path) {
                flaws.push(Finding {
                    file: d.path.clone(),
                    line: None,
                    pattern: rule.pattern.clone(),
                    explanation: rule.explanation.clone(),
                });
            }
            let lines: Vec<_> = if rule.path_or_content || rule.added_only {
                d.added.to_vec()
            } else {
                d.added.iter().chain(d.removed.iter()).cloned().collect()
            };
            let requires_match = rule.requires.as_ref().is_none_or(|r| {
                Regex::new(r).is_ok_and(|x| {
                    x.is_match(
                        &d.added
                            .iter()
                            .map(|(_, s)| s.as_str())
                            .chain(d.context.iter().map(String::as_str))
                            .collect::<Vec<_>>()
                            .join("\n"),
                    )
                })
            });
            if requires_match {
                for (n, line) in lines {
                    if re.is_match(&line) {
                        flaws.push(Finding {
                            file: d.path.clone(),
                            line: Some(n),
                            pattern: rule.pattern.clone(),
                            explanation: rule.explanation.clone(),
                        });
                    }
                }
            }
        }
    }
    let mut ac = BTreeMap::<String, (usize, usize)>::new();
    for d in &deltas {
        let rem = d.removed.iter().filter(|(_, s)| assertions(s) > 0).count();
        let add = d.added.iter().filter(|(_, s)| assertions(s) > 0).count();
        if rem + add > 0 {
            ac.insert(d.path.clone(), (rem, add));
        }
    }
    let removed_assertions = ac
        .into_iter()
        .map(|(file, (removed, added))| AssertionChange {
            file,
            removed,
            added,
            net_loss: removed.saturating_sub(added),
        })
        .collect::<Vec<_>>();
    let mut reasons = Vec::new();
    let status = value_str(&summary, &["status"]).unwrap_or_else(|| "unknown".into());
    let verdict = if status.starts_with("failed") || status.starts_with("provider refused") {
        reasons.push(format!("lane status is {status}"));
        "rerun"
    } else if !missing.is_empty() {
        reasons.push(format!(
            "{} packet command(s) are not reported",
            missing.len()
        ));
        "escalate"
    } else if checks.iter().any(|c| c.classification == "fail")
        || !flaws.is_empty()
        || removed_assertions.iter().any(|a| a.net_loss > 0)
    {
        if !flaws.is_empty() {
            reasons.push(format!("{} flaw hit(s)", flaws.len()));
        }
        if removed_assertions.iter().any(|a| a.net_loss > 0) {
            reasons.push("assertions have a net loss".into());
        }
        if checks.iter().any(|c| c.classification == "fail") {
            reasons.push("a reported check failed".into());
        }
        "fix-then-apply"
    } else if checks
        .iter()
        .any(|c| c.classification == "not run" || c.classification == "unclear")
    {
        reasons.push("one or more reported checks are not run or unclear".into());
        "escalate"
    } else {
        reasons.push("no reported blocker found".into());
        "apply"
    };
    Ok(Report {
        lane_id: value_str(&summary, &["id", "lane_id"]).unwrap_or_else(|| "unknown".into()),
        status,
        minutes: value_num(&summary, &["minutes"])
            .or_else(|| value_num(&summary, &["seconds"]).map(|s| (s + 30) / 60)),
        files_changed: files,
        lines_added: added,
        lines_removed: removed,
        outside_ownership_count: value_num(&summary, &["outsideCount", "outsideOwnershipCount"])
            .unwrap_or_else(|| outside.matches("diff --git ").count() as u64)
            as usize,
        checks,
        packet_commands_unreported: missing,
        flaws,
        removed_assertions,
        limits: extract_sections(&handoff, "limits"),
        unverified: extract_sections(&handoff, "unverified"),
        questions: extract_sections(&handoff, "questions"),
        verdict_hint: verdict.into(),
        verdict_reasons: reasons,
        sample_handoff: (!handoff.is_empty()).then(|| handoff.chars().take(6000).collect()),
    })
}
fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let json = args.iter().any(|a| a == "--json");
    match main_report(&args) {
        Ok(r) => {
            if json {
                println!("{}", serde_json::to_string_pretty(&r).unwrap());
            } else {
                print_report(&r);
            }
        }
        Err(e) => {
            eprintln!("lanes-report: {e:#}");
            std::process::exit(2)
        }
    }
}
fn print_report(r: &Report) {
    println!(
        "Lane: {} | status: {} | minutes: {}",
        r.lane_id,
        r.status,
        r.minutes.map_or("unknown".into(), |m| m.to_string())
    );
    println!(
        "Files changed: {} | lines: +{} -{} | outside ownership: {}",
        r.files_changed, r.lines_added, r.lines_removed, r.outside_ownership_count
    );
    println!("Checks:");
    for c in &r.checks {
        println!("- {}: {} ({})", c.command, c.classification, c.result);
    }
    println!(
        "Packet commands unreported: {}",
        r.packet_commands_unreported.len()
    );
    println!("Flaws: {}", r.flaws.len());
    for f in &r.flaws {
        println!(
            "- {}:{} {}",
            f.file,
            f.line.map_or("path".into(), |n| n.to_string()),
            f.explanation
        );
    }
    println!("Removed assertions:");
    for a in &r.removed_assertions {
        println!(
            "- {}: removed {}, added {}, net loss {}",
            a.file, a.removed, a.added, a.net_loss
        );
    }
    println!(
        "Limits: {:?}\nUnverified: {:?}\nQuestions: {:?}",
        r.limits, r.unverified, r.questions
    );
    println!(
        "Verdict hint: {} ({})",
        r.verdict_hint,
        r.verdict_reasons.join("; ")
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mixed_fixture_reports_checks_assertion_loss_and_handoff_sections() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/mixed");
        let args = vec![
            dir.to_string_lossy().to_string(),
            "--packet".into(),
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/mixed/packet.md")
                .to_string_lossy()
                .to_string(),
        ];
        let r = main_report(&args).unwrap();
        assert_eq!(r.lane_id, "fixture-lane");
        assert_eq!(r.minutes, Some(2));
        assert_eq!(
            r.checks
                .iter()
                .map(|c| c.classification.as_str())
                .collect::<Vec<_>>(),
            vec!["pass", "fail", "not run"]
        );
        assert_eq!(r.removed_assertions[0].net_loss, 2);
        assert_eq!(r.limits.len(), 1);
        assert_eq!(r.unverified.len(), 1);
        assert_eq!(r.questions.len(), 1);
        assert_eq!(r.verdict_hint, "fix-then-apply");
    }
    #[test]
    fn flaw_rules_cover_seeded_classes_and_detect_hits() {
        let rules: RuleFile = toml::from_str(include_str!("../rules/flaws.toml")).unwrap();
        assert_eq!(rules.rules.len(), 13);
        let patch = fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/flaw-classes.patch"),
        )
        .unwrap();
        let deltas = parse_patch(&patch);
        let mut hits = Vec::new();
        for d in &deltas {
            for rule in &rules.rules {
                if !rule.files.iter().any(|g| glob_match(g, &d.path)) {
                    continue;
                }
                if rule.path_only && Regex::new(&rule.pattern).unwrap().is_match(&d.path) {
                    hits.push(rule.explanation.clone());
                    continue;
                }
                if rule.applied_migration
                    && let Some(file) = d.path.split("/migrations/").nth(1)
                    && let Some(file) = file.rsplit('/').next()
                    && file <= "20260401_existing.sql"
                {
                    hits.push(rule.explanation.clone());
                    continue;
                }
                let re = Regex::new(&rule.pattern).unwrap();
                if rule.path_or_content && re.is_match(&d.path) {
                    hits.push(rule.explanation.clone());
                }
                let requires = rule.requires.as_ref().is_none_or(|r| {
                    Regex::new(r).unwrap().is_match(
                        &d.added
                            .iter()
                            .map(|(_, s)| s.as_str())
                            .collect::<Vec<_>>()
                            .join("\n"),
                    )
                });
                if requires {
                    for (_, line) in &d.added {
                        if re.is_match(line) {
                            hits.push(rule.explanation.clone());
                        }
                    }
                }
            }
        }
        assert!(
            hits.len() >= 19,
            "detected only {} flaw examples",
            hits.len()
        );
        assert!(
            hits.iter().any(|h| h.contains("current_setting('role')")),
            "the login-role guard rule must fire"
        );
        assert!(glob_match("**/fixtures/**", "tests/fixtures/access.sql"));
    }
    #[test]
    fn flaw_lane_fixture_runs_all_rules_including_baseline() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/flaws");
        let args = vec![
            dir.to_string_lossy().to_string(),
            "--baseline".into(),
            "20260401_existing.sql".into(),
        ];
        let report = main_report(&args).unwrap();
        assert!(
            report.flaws.len() >= 18,
            "reported {} flaws",
            report.flaws.len()
        );
        assert!(report.flaws.iter().any(|finding| {
            finding.file == "crates/demo/target/debug/demo"
                && finding.explanation == "Build output or scratch files appear in the patch."
        }));
        assert!(
            report
                .flaws
                .iter()
                .any(|f| f.file == "supabase/migrations/20260401_existing.sql")
        );
        assert!(
            !report
                .flaws
                .iter()
                .any(|f| f.file == "supabase/migrations/20260402_new.sql"
                    && f.pattern.starts_with("--baseline"))
        );
    }
    #[test]
    fn bullet_checks_and_packet_commands_parse() {
        assert_eq!(
            parse_checks("- `cargo test` — PASS\n- `cargo build` — not run")[1].classification,
            "not run"
        );
        assert!(parse_checks("## Changed\n- `api/src/main.rs` — wired module").is_empty());
        assert_eq!(classify("passed, 18 tests, 0 failed"), "pass");
        assert_eq!(classify("0 failed"), "pass");
        assert_eq!(classify("no failures"), "pass");
        assert_eq!(classify("exit 0"), "pass");
        assert_eq!(classify("failed once; final rerun passed"), "pass");
        assert_eq!(
            classify("passed, 6 passed tests; an earlier run failed before the passing run"),
            "pass"
        );
        assert_eq!(classify("Not run: unavailable"), "not run");
        assert_eq!(
            classify("passed: 6 passed, 0 failed; browser test skipped and not executed"),
            "pass"
        );
        assert_eq!(
            parse_checks("| Check | Result | Wall time |\n| --- | --- | --- |\n| `node --check` | exit 0 | 0.1s |")[0]
                .classification,
            "pass"
        );
        let plain_arrow =
            parse_checks("node scripts/check.mjs --flags  -> 4/4 scenarios passed (exit 0)");
        assert_eq!(plain_arrow.len(), 1);
        assert_eq!(plain_arrow[0].command, "node scripts/check.mjs --flags");
        assert_eq!(plain_arrow[0].classification, "pass");
        let sections = "## Limits and director question\nKeep migration.\n## Deferred\nLater.\n## Unverified\nBrowser.\n## Questions\nReview?";
        assert!(extract_sections(sections, "limits").contains(&"Later.".to_string()));
        assert_eq!(extract_sections(sections, "unverified"), vec!["Browser."]);
        assert_eq!(
            extract_sections(sections, "questions"),
            vec!["Keep migration.", "Review?"]
        );
        let p = fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/mixed/packet.md"),
        )
        .unwrap();
        assert_eq!(
            packet_commands(&p),
            vec!["cargo fmt".to_string(), "cargo test".to_string()]
        );
        assert!(packet_has_lane_id(
            "<!-- {\"id\":\"fixture-lane\"} -->",
            "fixture-lane"
        ));
    }
}
