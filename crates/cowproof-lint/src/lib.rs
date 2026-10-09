#![forbid(unsafe_code)]

use cowproof_core::{Header, parse_header};
use cowproof_plan::{Plan, check_packet_reservations};
use globset::Glob;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Severity {
    Error,
    Warn,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Error => "error",
            Self::Warn => "warn",
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    pub severity: Severity,
    pub rule: &'static str,
    pub line: Option<usize>,
    pub message: String,
}

impl std::fmt::Display for Finding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} [{}]", self.severity, self.rule)?;
        if let Some(line) = self.line {
            write!(f, " line {line}")?;
        }
        write!(f, ": {}", self.message)
    }
}

/// Lint a lane packet against its target repository and any loaded plan files.
pub fn lint_packet(packet_text: &str, repo_root: &Path, plans: &[Plan]) -> Vec<Finding> {
    let mut findings = Vec::new();
    let header = match parse_header(packet_text) {
        Ok(header) => Some(header),
        Err(parse_error) => {
            findings.push(error("header", None, parse_error.to_string()));
            None
        }
    };

    if let Some(header) = header.as_ref() {
        lint_ownership(header, repo_root, &mut findings);
        lint_migrations(packet_text, header, repo_root, plans, &mut findings);
        lint_header_checks(header, packet_text, &mut findings);
    }
    lint_secrets(packet_text, &mut findings);
    if let Some((start, section)) = checks_section(packet_text) {
        lint_checks(
            packet_text,
            section,
            start,
            header.as_ref(),
            repo_root,
            &mut findings,
        );
    }
    lint_packet_restates_protocol(packet_text, &mut findings);
    findings
}

fn error(rule: &'static str, line: Option<usize>, message: impl Into<String>) -> Finding {
    Finding {
        severity: Severity::Error,
        rule,
        line,
        message: message.into(),
    }
}

fn warn(rule: &'static str, line: Option<usize>, message: impl Into<String>) -> Finding {
    Finding {
        severity: Severity::Warn,
        rule,
        line,
        message: message.into(),
    }
}

fn lint_header_checks(header: &Header, packet_text: &str, findings: &mut Vec<Finding>) {
    if header.checks.is_empty() {
        findings.push(warn(
            "no-checks",
            None,
            "header declares no checks; a packet with no checks cannot be proven",
        ));
    } else {
        // Check for duplicate check ids
        let mut seen_ids = BTreeSet::new();
        for check in &header.checks {
            if !seen_ids.insert(&check.id) {
                findings.push(error(
                    "duplicate-check-id",
                    None,
                    format!("check id {:?} is duplicated", check.id),
                ));
            }
            // Check id format: [a-z0-9][a-z0-9_-]{0,63}
            if !is_valid_check_id(&check.id) {
                findings.push(error(
                    "invalid-check-id",
                    None,
                    format!(
                        "check id {:?} must match [a-z0-9][a-z0-9_-]{{0,63}}",
                        check.id
                    ),
                ));
            }
            // Check for empty command
            if check.command.is_empty() {
                findings.push(error(
                    "empty-check-command",
                    None,
                    format!("check {:?} has an empty command", check.id),
                ));
            }
            // Check for masked pipe in command
            if has_masking_pipe(&check.command) {
                findings.push(error(
                    "masked-pipe-status",
                    None,
                    format!(
                        "check {:?}: pipeline uses head, tail, or grep, which can hide the check command's exit status",
                        check.id
                    ),
                ));
            }
        }

        // Check that header checks match markdown section
        if let Some((_start, section)) = checks_section(packet_text) {
            for check in &header.checks {
                if !section.contains(&check.command) {
                    findings.push(warn(
                        "check-section-mismatch",
                        None,
                        format!(
                            "check {:?} command {:?} does not appear in ## Checks markdown section",
                            check.id, check.command
                        ),
                    ));
                }
            }
        }
    }
}

fn is_valid_check_id(id: &str) -> bool {
    if id.is_empty() || id.len() > 64 {
        return false;
    }
    let first = id.as_bytes()[0];
    if !(first.is_ascii_lowercase() || first.is_ascii_digit()) {
        return false;
    }
    id.bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

fn lint_ownership(header: &Header, root: &Path, findings: &mut Vec<Finding>) {
    if header.is_wide() {
        return;
    }
    for pattern in &header.owns {
        if matches_any(root, pattern) {
            continue;
        }
        if has_glob(pattern) {
            if glob_parent_exists(root, pattern) {
                continue;
            }
            findings.push(error(
                "owns-unmatched",
                None,
                format!("owns pattern {pattern:?} matches no existing path while wide is false; add its existing parent directory to owns or make the lane wide"),
            ));
        } else if !root.join(pattern).exists() {
            let parent = Path::new(pattern)
                .parent()
                .filter(|p| !p.as_os_str().is_empty());
            let parent_exists = parent.is_some_and(|p| root.join(p).is_dir());
            if parent_exists || parent.is_none() {
                continue;
            }
            let suggested = parent
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| ".".into());
            findings.push(error(
                "owns-parent-missing",
                None,
                format!("owned path {pattern:?} does not exist and its parent folder is missing ({suggested:?}); create the folder or make the lane wide"),
            ));
        }
    }
}

fn glob_parent_exists(root: &Path, pattern: &str) -> bool {
    let wildcard = pattern
        .char_indices()
        .find(|(_, character)| matches!(character, '*' | '?' | '[' | '{'))
        .map(|(index, _)| index)
        .unwrap_or(pattern.len());
    let prefix = &pattern[..wildcard];
    let directory = prefix
        .rfind('/')
        .map(|index| &prefix[..index])
        .filter(|directory| !directory.is_empty())
        .unwrap_or(".");
    root.join(directory).is_dir()
}

fn matches_any(root: &Path, pattern: &str) -> bool {
    let Ok(glob) = Glob::new(pattern) else {
        return false;
    };
    let matcher = glob.compile_matcher();
    walk(root).iter().any(|path| {
        path.strip_prefix(root)
            .ok()
            .is_some_and(|relative| matcher.is_match(relative))
    })
}

fn walk(root: &Path) -> Vec<PathBuf> {
    fn visit(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            out.push(path.clone());
            if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                let name = entry.file_name();
                if name != ".git" && name != "target" && name != "node_modules" {
                    visit(&path, out);
                }
            }
        }
    }
    let mut out = Vec::new();
    visit(root, &mut out);
    out
}

fn has_glob(pattern: &str) -> bool {
    pattern.contains(['*', '?', '[', '{'])
}

fn checks_section(text: &str) -> Option<(usize, &str)> {
    let mut offset = 0;
    let mut start = None;
    for line in text.split_inclusive('\n') {
        let trimmed = line.trim();
        if let Some(heading) = trimmed.strip_prefix("## ") {
            if start.is_some() {
                return Some((start?, &text[start?..offset]));
            }
            if heading.to_ascii_lowercase().starts_with("checks") {
                start = Some(offset + line.len());
            }
        }
        offset += line.len();
    }
    start.map(|s| (s, &text[s..]))
}

fn lint_checks(
    packet_text: &str,
    section: &str,
    section_offset: usize,
    header: Option<&Header>,
    root: &Path,
    findings: &mut Vec<Finding>,
) {
    let mut in_fence = false;
    for (offset, line) in section.split_inclusive('\n').scan(0usize, |at, line| {
        let current = *at;
        *at += line.len();
        Some((current, line))
    }) {
        let trimmed = line.trim();
        if trimmed.starts_with("```") {
            in_fence = !in_fence;
            continue;
        }
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let line_number = Some(packet_text[..section_offset + offset].matches('\n').count() + 1);
        let commands = if in_fence {
            split_commands(trimmed.trim_start_matches(['-', '*', ' ']).trim())
                .into_iter()
                .map(str::to_owned)
                .collect()
        } else {
            inline_list_commands(trimmed)
        };
        if commands.is_empty() {
            continue;
        }
        let masks_status = if in_fence {
            has_masking_pipe(trimmed)
        } else {
            inline_list_spans(trimmed)
                .iter()
                .any(|command| has_masking_pipe(command))
        };
        if masks_status {
            findings.push(error(
                "masked-pipe-status",
                line_number,
                "pipeline uses head, tail, or grep, which can hide the check command's exit status",
            ));
        }
        for command in &commands {
            let words = shell_words(command);
            if words.is_empty() {
                continue;
            }
            lint_command_permission(command, header, line_number, findings);
            if words.first().is_some_and(|word| word == "node")
                && words.get(1).is_some_and(|word| word == "--test")
                && words.get(2).is_some_and(|path| root.join(path).is_dir())
            {
                findings.push(error(
                    "node-test-directory",
                    line_number,
                    format!(
                        "node --test receives directory {:?}; pass a test-file glob instead",
                        words[2]
                    ),
                ));
            }
            lint_paths(&words, root, header, line_number, findings);
        }
    }
}

fn inline_list_commands(line: &str) -> Vec<String> {
    inline_list_spans(line)
        .into_iter()
        .flat_map(split_commands)
        .map(str::to_owned)
        .collect()
}

fn inline_list_spans(line: &str) -> Vec<&str> {
    let trimmed = line.trim_start();
    let digit_count = trimmed.chars().take_while(char::is_ascii_digit).count();
    let list_content = if digit_count > 0 {
        trimmed[digit_count..]
            .strip_prefix('.')
            .map(str::trim_start)
    } else {
        ["- ", "* ", "+ "]
            .iter()
            .find_map(|prefix| trimmed.strip_prefix(prefix))
    };
    let Some(mut content) = list_content else {
        return Vec::new();
    };
    let mut commands = Vec::new();
    while let Some(open) = content.find('`') {
        let after_open = &content[open + 1..];
        let Some(close) = after_open.find('`') else {
            break;
        };
        let code = after_open[..close].trim();
        if !code.is_empty() {
            commands.push(code);
        }
        content = &after_open[close + 1..];
    }
    commands
}

fn split_commands(line: &str) -> Vec<&str> {
    line.split('|')
        .flat_map(|part| part.split("&&"))
        .flat_map(|part| part.split(';'))
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .collect()
}

fn shell_words(command: &str) -> Vec<String> {
    command
        .split_whitespace()
        .map(|word| {
            word.trim_matches(['`', '\'', '"', ',', ';', ')', '('])
                .to_owned()
        })
        .filter(|word| !word.is_empty())
        .collect()
}

const BASE_ALLOW: [&str; 18] = [
    "ls*",
    "pwd",
    "cat *",
    "head *",
    "tail *",
    "wc *",
    "grep *",
    "rg *",
    "sed -n *",
    "diff *",
    "git status*",
    "git diff*",
    "git log*",
    "git show*",
    "node --check *",
    "node --test *",
    "rm -rf tmp-*",
    "rm -rf ./tmp-*",
];

fn lint_command_permission(
    command: &str,
    header: Option<&Header>,
    line: Option<usize>,
    findings: &mut Vec<Finding>,
) {
    let Some(header) = header.filter(|h| !h.is_wide()) else {
        return;
    };
    let normalized = command.trim();
    let allowed = BASE_ALLOW
        .iter()
        .copied()
        .chain(header.allow.iter().map(String::as_str))
        .any(|pattern| command_matches(pattern, normalized));
    if !allowed {
        findings.push(error(
            "check-command-not-allowed",
            line,
            format!("check command {normalized:?} is outside wide:false lane command permissions; add a matching allow entry or enable wide access"),
        ));
    }
}

fn command_matches(pattern: &str, command: &str) -> bool {
    if pattern.ends_with('*') {
        command.starts_with(pattern.trim_end_matches('*').trim_end())
    } else {
        command == pattern
    }
}

fn has_masking_pipe(line: &str) -> bool {
    line.split('|').count() > 1
        && line.split('|').any(|part| {
            matches!(
                shell_words(part).first().map(String::as_str),
                Some("head" | "tail" | "grep")
            )
        })
}

fn lint_paths(
    words: &[String],
    root: &Path,
    header: Option<&Header>,
    line: Option<usize>,
    findings: &mut Vec<Finding>,
) {
    for (index, word) in words.iter().enumerate() {
        let candidate = word.trim_matches(['`', '\'', '"', ',', ';', ')', '(']);
        if is_git_revision_path(words, index) {
            continue;
        }
        // Runtime paths (shell variables, absolute scratch and temp paths) are created by the lane, not the repo.
        if candidate.starts_with('-')
            || candidate.contains("{n}")
            || candidate.contains('$')
            || candidate.starts_with('/')
        {
            continue;
        }
        if candidate.split('/').any(|component| component == "target") {
            continue;
        }
        if candidate.contains('*') || candidate.contains('?') {
            if (candidate.contains('/') || has_path_extension(candidate))
                && !glob_exists(root, candidate)
                && !owned_by_glob(header, candidate)
            {
                findings.push(error(
                    "check-path-missing",
                    line,
                    format!("check path or glob {candidate:?} matches no file in the repository"),
                ));
            }
        } else if (candidate.contains('/') || has_path_extension(candidate))
            && !root.join(candidate).exists()
            && !owned_by_glob(header, candidate)
        {
            findings.push(error(
                "check-path-missing",
                line,
                format!("check references missing file {candidate:?}"),
            ));
        }
    }
}

fn is_git_revision_path(words: &[String], index: usize) -> bool {
    if index < 2 || words[index - 1] != "show" {
        return false;
    }
    if index > 2 && words[index - 2] != "git" && !words[index - 2].ends_with("(git") {
        return false;
    }
    if index == 2 && words[0] != "git" {
        return false;
    }
    let token = words[index].as_str();
    let Some((revision, path)) = token.split_once(':') else {
        return false;
    };
    !revision.is_empty() && path.contains('/') && !path.starts_with('/')
}

fn owned_by_glob(header: Option<&Header>, candidate: &str) -> bool {
    header.is_some_and(|header| {
        header.owns.iter().any(|pattern| {
            has_glob(pattern)
                && Glob::new(pattern)
                    .ok()
                    .is_some_and(|glob| glob.compile_matcher().is_match(candidate))
        })
    })
}

fn has_path_extension(path: &str) -> bool {
    Path::new(path).extension().is_some_and(|ext| {
        matches!(
            ext.to_string_lossy().as_ref(),
            "rs" | "js"
                | "mjs"
                | "cjs"
                | "ts"
                | "tsx"
                | "jsx"
                | "json"
                | "md"
                | "sql"
                | "sh"
                | "toml"
                | "yml"
                | "yaml"
                | "css"
                | "html"
        )
    })
}

fn glob_exists(root: &Path, pattern: &str) -> bool {
    let Ok(glob) = Glob::new(pattern) else {
        return false;
    };
    let matcher = glob.compile_matcher();
    walk(root).iter().any(|path| {
        path.strip_prefix(root)
            .ok()
            .is_some_and(|rel| matcher.is_match(rel))
    })
}

fn lint_migrations(
    text: &str,
    header: &Header,
    root: &Path,
    plans: &[Plan],
    findings: &mut Vec<Finding>,
) {
    let owned = header.owns.join("\n");
    let combined = format!("{owned}\n{text}");
    let migrations = migration_numbers(&combined);
    let requested_contracts = text
        .lines()
        .filter(|line| {
            let line = line.to_ascii_lowercase();
            line.contains("reserve contract")
                || line.contains("reserves.contract")
                || line.contains("contract reservation")
                || line.contains("request contract")
        })
        .collect::<Vec<_>>()
        .join("\n");
    let contracts = contract_versions(&format!("{owned}\n{requested_contracts}"));
    for problem in check_packet_reservations(root, plans, &header.id, &migrations, &contracts) {
        findings.push(error("plan-reservation", None, problem.rule));
    }
}

fn migration_numbers(text: &str) -> Vec<i64> {
    let mut found = BTreeSet::new();
    let bytes = text.as_bytes();
    for (start, _) in text.match_indices("2026092000") {
        let end = bytes[start..]
            .iter()
            .position(|byte| !byte.is_ascii_digit())
            .map_or(bytes.len(), |length| start + length);
        if end - start >= 13
            && let Ok(number) = text[start..end].parse()
        {
            found.insert(number);
        }
    }
    found.into_iter().collect()
}

fn contract_versions(text: &str) -> Vec<String> {
    let mut found = BTreeSet::new();
    let bytes = text.as_bytes();
    let mut i = 0;
    while i + 2 < bytes.len() {
        if bytes[i] == b'C' && bytes[i + 1].is_ascii_digit() {
            let start = i;
            i += 1;
            while i < bytes.len() && (bytes[i].is_ascii_digit() || bytes[i] == b'.') {
                i += 1;
            }
            let value = &text[start..i];
            if value.contains('.')
                && value.split('.').all(|part| {
                    part.trim_start_matches('C')
                        .chars()
                        .all(|c| c.is_ascii_digit())
                })
            {
                found.insert(value.to_owned());
            }
        } else {
            i += 1;
        }
    }
    found.into_iter().collect()
}

fn lint_secrets(text: &str, findings: &mut Vec<Finding>) {
    for (index, line) in text.lines().enumerate() {
        let lower = line.to_ascii_lowercase();
        if contains_secret_material(&lower, line) {
            findings.push(error(
                "secret-reference",
                Some(index + 1),
                "packet contains a secret file reference or credential value; remove the path/value and describe the requirement generically",
            ));
        }
    }
}

fn contains_secret_material(lower: &str, original: &str) -> bool {
    let env_path = !lower.contains(".env*")
        && lower
            .split(|c: char| !c.is_ascii_alphanumeric() && c != '.' && c != '_' && c != '-')
            .any(|token| token == ".env" || token.starts_with(".env."));
    let secret_file = ["id_rsa", "id_ed25519", "credentials.json"]
        .iter()
        .any(|name| lower.contains(name));
    let private_key = lower.contains("-----begin ") && lower.contains("private key-----");
    let known_prefix = [
        "sk-",
        "ghp_",
        "github_pat_",
        "gho_",
        "ghu_",
        "ghs_",
        "ghr_",
        "xoxb-",
        "xoxp-",
        "xoxa-",
        "glpat-",
    ]
    .iter()
    .any(|prefix| contains_token_prefix(lower, prefix));
    let bearer = lower.split_once("bearer ").is_some_and(|(_, value)| {
        let value = value.trim_start();
        let prose_word = value
            .split(|c: char| !c.is_ascii_alphanumeric())
            .next()
            .unwrap_or_default();
        let punctuation = value
            .chars()
            .next()
            .is_some_and(|c| !c.is_ascii_alphanumeric());
        !punctuation
            && !matches!(
                prose_word,
                "header"
                    | "token"
                    | "tokens"
                    | "auth"
                    | "authorization"
                    | "value"
                    | "credential"
                    | "credentials"
            )
            && has_credential_value(value)
    });
    // The rule's own explanatory sentence names `.env` as an example; that
    // mention is documentation, not a referenced credential file.
    let rule_description = lower.contains("a packet that names a secret file")
        && lower.contains("a token or a key value")
        || lower.contains("tighten the rule")
            && lower.contains("file paths")
            && lower.contains("assignment with a value");
    !rule_description
        && (env_path
            || secret_file
            || private_key
            || known_prefix
            || bearer
            || has_secret_assignment(original))
}

fn contains_token_prefix(line: &str, prefix: &str) -> bool {
    line.match_indices(prefix).any(|(start, _)| {
        if start > 0
            && line[..start]
                .chars()
                .next_back()
                .is_some_and(|c| c.is_ascii_alphanumeric())
        {
            return false;
        }
        let tail = &line[start + prefix.len()..];
        has_credential_value(tail)
            && tail
                .trim_start_matches(|c: char| !c.is_ascii_alphanumeric())
                .chars()
                .take_while(char::is_ascii_alphanumeric)
                .count()
                >= 8
    })
}

fn has_secret_assignment(line: &str) -> bool {
    line.split_whitespace().any(|part| {
        let Some((key, value)) = part.split_once('=') else {
            return false;
        };
        let key = key
            .trim_matches(['`', '\'', '"', '*', '_'])
            .to_ascii_uppercase();
        let is_secret_name = key == "KEY"
            || key == "TOKEN"
            || key.ends_with("_KEY")
            || key.ends_with("_TOKEN")
            || key.ends_with("_SECRET");
        is_secret_name && has_credential_value(value)
    })
}

fn has_credential_value(value: &str) -> bool {
    let value = value
        .trim()
        .trim_matches(['"', '\'', '`', ',', ';', '.', ')', ']']);
    !value.is_empty()
        && !value.starts_with(['<', '[', '{'])
        && !value.starts_with("YOUR_")
        && !value.starts_with("your_")
        && !value.eq_ignore_ascii_case("redacted")
        && !value.eq_ignore_ascii_case("placeholder")
}

/// Lint rule: detect when a packet restates the builder preamble's protocol text.
/// Per D20 constraint, packets must not include the preamble's distinctive protocol phrases,
/// because per-lane copies break the shared prompt cache and drift from the canonical protocol.
fn lint_packet_restates_protocol(packet_text: &str, findings: &mut Vec<Finding>) {
    use cowproof_core::PROTOCOL_MARKERS;

    // Skip the JSON header (everything before the first blank line)
    let packet_body = if let Some(pos) = packet_text.find("\n\n") {
        &packet_text[pos + 2..]
    } else {
        packet_text
    };

    for marker in PROTOCOL_MARKERS {
        if packet_body.contains(marker) {
            findings.push(Finding {
                severity: Severity::Error,
                rule: "packet-restates-protocol",
                line: None,
                message: format!(
                    "packet restates preamble protocol text: '{}' found in packet body. \
                     The preamble states the protocol once and is shared across lanes for cache efficiency. \
                     Do not paste Ask schema, escalate-early rules, or other protocol text into the packet.",
                    marker
                ),
            });
            return; // Report once per packet
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn root() -> PathBuf {
        // A counter, not only the clock: parallel tests could get the same timestamp and delete each other's folder.
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "lanes-lint-{}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn packet(header: &str, checks: &str) -> String {
        format!("<!-- lane {header} -->\n\n## Checks\n\n```\n{checks}\n```\n")
    }

    fn has(findings: &[Finding], rule: &str) -> bool {
        findings.iter().any(|finding| finding.rule == rule)
    }

    #[test]
    fn narrow_codex_lane_cannot_run_unallowed_checks() {
        let dir = root();
        let text = packet(
            r#"{"id":"lane-x","runner":"codex","wide":false,"owns":["docs/x.md"]}"#,
            "cargo test --locked",
        );
        assert!(has(
            &lint_packet(&text, &dir, &[]),
            "check-command-not-allowed"
        ));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn node_test_directory_is_rejected() {
        let dir = root();
        fs::create_dir_all(dir.join("scripts/staging")).unwrap();
        let text = packet(
            r#"{"id":"lane-x","owns":["x"]}"#,
            "node --test scripts/staging/",
        );
        assert!(has(&lint_packet(&text, &dir, &[]), "node-test-directory"));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn masking_pipe_is_rejected() {
        let dir = root();
        let text = packet(r#"{"id":"lane-x","owns":["x"]}"#, "cargo test | tail -5");
        assert!(has(&lint_packet(&text, &dir, &[]), "masked-pipe-status"));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn missing_check_script_is_rejected() {
        let dir = root();
        let text = packet(
            r#"{"id":"lane-x","owns":["x"]}"#,
            "node --check scripts/missing.mjs",
        );
        assert!(has(&lint_packet(&text, &dir, &[]), "check-path-missing"));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn missing_check_path_owned_by_creation_glob_is_allowed() {
        let dir = root();
        fs::create_dir_all(dir.join("supabase/migrations")).unwrap();
        fs::create_dir_all(dir.join("scripts/schema")).unwrap();
        fs::write(dir.join("scripts/schema/check-migration-safety.mjs"), "").unwrap();
        fs::write(
            dir.join("supabase/migrations/20260920000489_previous.sql"),
            "",
        )
        .unwrap();
        let text = packet(
            r#"{"id":"lane-x","owns":["supabase/migrations/20260920000490_*.sql"]}"#,
            "node scripts/schema/check-migration-safety.mjs supabase/migrations/20260920000490_add_widgets.sql",
        );
        let findings = lint_packet(&text, &dir, &[]);
        assert!(!has(&findings, "check-path-missing"), "{findings:?}");
        assert!(!has(&findings, "owns-unmatched"), "{findings:?}");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn runtime_scratch_paths_are_not_missing_files() {
        let dir = std::env::temp_dir().join(format!("lanes-lint-runtime-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("scripts")).unwrap();
        std::fs::write(dir.join("scripts/verify.mjs"), "").unwrap();
        let text = "<!-- lane {\"id\": \"lane-x\", \"runner\": \"codex\", \"owns\": [\"scripts/**\"]} -->\n\n## Checks\n\n```\nnode scripts/verify.mjs --scratch-parent /tmp/cowproof-$LANE_PORT_BASE --work \"$LANE_SCRATCH/v\"\n```\n";
        let findings = lint_packet(text, &dir, &[]);
        assert!(!has(&findings, "check-path-missing"), "{findings:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn git_show_revision_paths_are_not_missing_files() {
        let dir = root();
        let text = packet(
            r#"{"id":"lane-x","owns":["x"]}"#,
            "git show HEAD:contract/snapshot.txt > \"$LANE_SCRATCH/x\"\ncat <(git show HEAD:contract/snapshot.txt)",
        );
        let findings = lint_packet(&text, &dir, &[]);
        assert!(!has(&findings, "check-path-missing"), "{findings:?}");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn packet_reservations_reuse_plan_checks() {
        let dir = root();
        let plan = Plan {
            path: dir.join("plan.lanes.json"),
            document: json!({
                "plan":"p", "baseline":{"migration":2026092000124i64},
                "lanes":[
                    {"id":"lane-x","status":"planned","priority":2},
                    {"id":"other-lane","status":"planned","priority":1,
                    "reserves":{"migration":2026092000123i64,"contract":"C1.34"}}
                ]
            }),
        };
        let text = packet(
            r#"{"id":"lane-x","owns":["supabase/migrations/2026092000123_add.sql"]}"#,
            "git diff --check",
        ) + "\nReserve contract C1.34\n";
        let findings = lint_packet(&text, &dir, &[plan]);
        assert!(has(&findings, "plan-reservation"));
        assert!(findings.iter().any(|f| f.message.contains("baseline")));
        assert!(
            findings
                .iter()
                .any(|f| f.message.contains("unique across plans"))
        );
        assert!(
            findings
                .iter()
                .any(|f| f.message.contains("reserved contract C1.34"))
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn unmatched_owned_glob_is_rejected_for_narrow_lane() {
        let dir = root();
        let text = packet(
            r#"{"id":"lane-x","runner":"codex","wide":false,"owns":["new/folder/**/*.rs"]}"#,
            "git diff --check",
        );
        assert!(has(&lint_packet(&text, &dir, &[]), "owns-unmatched"));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn missing_owned_file_is_ok_when_its_parent_exists() {
        let dir = root();
        fs::create_dir_all(dir.join("docs/handoffs")).unwrap();
        let text = packet(
            r#"{"id":"lane-x","runner":"codex","wide":false,"owns":["docs/handoffs/new.md"]}"#,
            "git diff --check",
        );
        assert!(!has(&lint_packet(&text, &dir, &[]), "owns-parent-missing"));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn explicit_secret_path_and_key_value_are_rejected() {
        let dir = root();
        let text = format!(
            "{}\nDo not read .env.local or set API_TOKEN=abc123\n",
            packet(r#"{"id":"lane-x","owns":["x"]}"#, "git diff --check")
        );
        assert!(has(&lint_packet(&text, &dir, &[]), "secret-reference"));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn descriptive_bearer_token_words_are_not_credentials() {
        let dir = root();
        let text = format!(
            "{}\nThe rule detects a bearer token but never stores it.\n",
            packet(r#"{"id":"lane-x","owns":["x"]}"#, "git diff --check")
        );
        assert!(!has(&lint_packet(&text, &dir, &[]), "secret-reference"));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn bearer_header_and_authorization_prose_are_not_credentials() {
        let dir = root();
        let text = format!(
            "{}\nSent only as a bearer header. A bearer auth token is expected. The bearer authorization, then expires.\n",
            packet(r#"{"id":"lane-x","owns":["x"]}"#, "git diff --check")
        );
        assert!(!has(&lint_packet(&text, &dir, &[]), "secret-reference"));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn explanatory_secret_rule_examples_are_not_credentials() {
        let dir = root();
        let text = format!(
            "{}\nTighten the rule to actual secret material: `.env` file paths and a `KEY=value` assignment with a value.\n",
            packet(r#"{"id":"lane-x","owns":["x"]}"#, "git diff --check")
        );
        assert!(!has(&lint_packet(&text, &dir, &[]), "secret-reference"));
        fs::remove_dir_all(dir).unwrap();
    }

    fn signatures(findings: &[Finding]) -> Vec<String> {
        findings
            .iter()
            .map(|finding| {
                format!(
                    "{} [{}]{}: {}",
                    finding.severity,
                    finding.rule,
                    finding
                        .line
                        .map(|line| format!(" line {line}"))
                        .unwrap_or_default(),
                    finding.message
                )
            })
            .collect()
    }

    fn repository_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap()
    }

    #[test]
    fn synthetic_wide_false_fixture_finds_inline_checks_and_missing_paths() {
        let root = repository_root();
        let findings = lint_packet(
            include_str!("../tests/fixtures/synthetic-wide-false-no-allow.md"),
            &root,
            &[],
        );
        assert_eq!(
            signatures(&findings),
            vec![
                "error [owns-parent-missing]: owned path \"tools/widget/cache.mjs\" does not exist and its parent folder is missing (\"tools/widget\"); create the folder or make the lane wide",
                "error [owns-parent-missing]: owned path \"tools/widget/cache.test.mjs\" does not exist and its parent folder is missing (\"tools/widget\"); create the folder or make the lane wide",
                "error [owns-parent-missing]: owned path \"tools/widget/evict.mjs\" does not exist and its parent folder is missing (\"tools/widget\"); create the folder or make the lane wide",
                "error [owns-unmatched]: owns pattern \"tools/report/*.test.mjs\" matches no existing path while wide is false; add its existing parent directory to owns or make the lane wide",
                "error [owns-parent-missing]: owned path \"docs/handoffs/handoff-lane-widget-cache.md\" does not exist and its parent folder is missing (\"docs/handoffs\"); create the folder or make the lane wide",
                "warn [no-checks]: header declares no checks; a packet with no checks cannot be proven",
                "error [check-path-missing] line 9: check references missing file \"tools/widget/cache.test.mjs\"",
                "error [check-command-not-allowed] line 10: check command \"node tools/widget/evict.mjs --dry-run --scratch-parent /tmp/cowproof-$LANE_PORT_BASE\" is outside wide:false lane command permissions; add a matching allow entry or enable wide access",
                "error [check-path-missing] line 10: check references missing file \"tools/widget/evict.mjs\"",
                "error [check-command-not-allowed] line 11: check command \"cargo test --locked --offline --manifest-path tools/widget/Cargo.toml\" is outside wide:false lane command permissions; add a matching allow entry or enable wide access",
                "error [check-path-missing] line 11: check references missing file \"tools/widget/Cargo.toml\"",
            ]
        );
    }

    #[test]
    fn synthetic_missing_output_fixture_reports_missing_parent_in_temporary_repo() {
        let dir = root();
        let findings = lint_packet(
            include_str!("../tests/fixtures/synthetic-missing-output-dir.md"),
            &dir,
            &[],
        );
        assert_eq!(
            signatures(&findings),
            vec![
                "error [owns-parent-missing]: owned path \"docs/reviews/2026-10-09/challenge/challenge-cache-design.md\" does not exist and its parent folder is missing (\"docs/reviews/2026-10-09/challenge\"); create the folder or make the lane wide",
                "warn [no-checks]: header declares no checks; a packet with no checks cannot be proven"
            ]
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn synthetic_clean_secret_name_fixture_has_no_findings() {
        let findings = lint_packet(
            include_str!("../tests/fixtures/synthetic-clean-names-secret-variable.md"),
            &repository_root(),
            &[],
        );
        assert_eq!(
            signatures(&findings),
            vec![
                "warn [no-checks]: header declares no checks; a packet with no checks cannot be proven"
            ]
        );
    }

    #[test]
    fn packet_restates_protocol_when_pasting_ask_schema() {
        let dir = root();
        let text = format!(
            "{}\n\nThe ask schema looks like this:\n```json\n{{\n  \"kind\": \"blocker | design | scope | environment\",\n  \"question\": \"a clear, specific question in one paragraph (max 4000 chars)\",\n  \"tried\": [\"what you attempted and what happened\"],\n  \"options\": [{{\"id\": \"option_id\", \"summary\": \"...\", \"cost\": \"...\"}}],\n  \"recommend\": \"option_id\",\n  \"blocking\": true\n}}\n```\n\nThe schema is strict and must be followed.",
            packet(r#"{"id":"lane-x","owns":["x"]}"#, "cargo test")
        );
        assert!(has(
            &lint_packet(&text, &dir, &[]),
            "packet-restates-protocol"
        ));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn packet_restates_protocol_not_triggered_by_normal_usage() {
        let dir = root();
        let text = format!(
            "{}\n\nRun each check with run_check to ensure it passes. Use blocking true or false as needed for your asks.",
            packet(r#"{"id":"lane-x","owns":["x"]}"#, "cargo test")
        );
        assert!(!has(
            &lint_packet(&text, &dir, &[]),
            "packet-restates-protocol"
        ));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn protocol_markers_all_occur_in_the_preamble() {
        // A marker that is not in the preamble can never match a pasted protocol section.
        let preamble = include_str!("../../cowproof-run/src/prefix/builder-preamble.md");
        for marker in cowproof_core::PROTOCOL_MARKERS {
            assert!(
                preamble.contains(marker),
                "marker {marker:?} does not occur in the builder preamble"
            );
        }
    }

    #[test]
    fn protocol_markers_are_distinctive_phrases() {
        // Verify markers are multi-word phrases, not bare tool names or common words
        // that would create false positives in normal packets.
        for marker in cowproof_core::PROTOCOL_MARKERS {
            // Each marker should be multiple words or a distinctive phrase
            let word_count = marker.split_whitespace().count();
            assert!(
                word_count >= 4,
                "marker '{}' is too short ({} words); must be distinctive multi-word phrase",
                marker,
                word_count
            );
            // Markers should not be bare tool names
            assert!(
                !marker.eq_ignore_ascii_case("ask")
                    && !marker.eq_ignore_ascii_case("check_ruling")
                    && !marker.eq_ignore_ascii_case("run_check")
                    && !marker.eq_ignore_ascii_case("pk-read")
                    && !marker.eq_ignore_ascii_case("sym")
                    && !marker.eq_ignore_ascii_case("outline"),
                "marker '{}' is a bare tool name; must be a distinctive phrase",
                marker
            );
        }
    }
}
