//! Flaw rule types and matching logic shared by gates and report.
//!
//! This module defines the rule format and matching algorithm so both
//! cowproof-prove gates and cowproof-report use the same code.

use regex::Regex;
use serde::Deserialize;

/// A flaw rule as defined in a flaws.toml file.
#[derive(Clone, Debug, Deserialize)]
pub struct FlawRule {
    pub pattern: String,
    pub files: Vec<String>,
    pub explanation: String,
    #[serde(default)]
    pub added_only: bool,
    #[serde(default)]
    pub path_only: bool,
    #[serde(default)]
    pub path_or_content: bool,
    #[serde(default)]
    pub applied_migration: bool,
    #[serde(default)]
    pub requires: Option<String>,
}

/// Wrapper for parsing flaws.toml files.
#[derive(Debug, Deserialize)]
pub struct RuleFile {
    pub rules: Vec<FlawRule>,
}

/// A parsed flaw finding from a rule match.
#[derive(Clone, Debug)]
pub struct FlawFinding {
    pub file: String,
    pub line: Option<usize>,
    pub pattern: String,
    pub explanation: String,
}

/// A parsed delta from a unified diff patch.
#[derive(Clone, Debug)]
pub struct PatchDelta {
    pub path: String,
    pub added: Vec<(usize, String)>,
    pub removed: Vec<(usize, String)>,
}

/// Match a file path against a glob pattern.
pub fn glob_match(pattern: &str, text: &str) -> bool {
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

/// Parse a unified diff patch into deltas per file.
pub fn parse_patch(patch: &str) -> Vec<PatchDelta> {
    let mut out = Vec::new();
    let mut current: Option<PatchDelta> = None;
    let mut new_line = 1usize;

    for line in patch.lines() {
        if let Some(rest) = line.strip_prefix("diff --git a/") {
            if let Some(c) = current {
                out.push(c);
            }
            let path = rest
                .split_once(" b/")
                .map(|(_, b)| b.to_string())
                .unwrap_or_default();
            current = Some(PatchDelta {
                path,
                added: Vec::new(),
                removed: Vec::new(),
            });
            new_line = 1;
            continue;
        }

        if current.is_none() {
            continue;
        }

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

        if let Some(c) = &mut current {
            if let Some(s) = line.strip_prefix('+') {
                c.added.push((new_line, s.to_string()));
                new_line += 1;
            } else if let Some(s) = line.strip_prefix('-') {
                c.removed.push((0, s.to_string()));
            } else if let Some(_s) = line.strip_prefix(' ') {
                new_line += 1;
            }
        }
    }

    if let Some(c) = current {
        out.push(c);
    }

    out
}

/// Check a single flaw rule against a patch delta.
/// Returns findings if the rule matches, or an error if the pattern is invalid.
pub fn check_rule(rule: &FlawRule, delta: &PatchDelta) -> Result<Vec<FlawFinding>, String> {
    // Check if rule applies to this file
    if !rule.files.iter().any(|g| glob_match(g, &delta.path)) {
        return Ok(Vec::new());
    }

    // Skip applied_migration rules (would need baseline context)
    if rule.applied_migration {
        return Ok(Vec::new());
    }

    // Compile pattern - MUST NOT SILENTLY FAIL
    let re = Regex::new(&rule.pattern)
        .map_err(|e| format!("Invalid pattern in rule: {} (error: {})", rule.pattern, e))?;

    // Check path-only rule
    if rule.path_only {
        if re.is_match(&delta.path) {
            return Ok(vec![FlawFinding {
                file: delta.path.clone(),
                line: None,
                pattern: rule.pattern.clone(),
                explanation: rule.explanation.clone(),
            }]);
        }
        return Ok(Vec::new());
    }

    let mut findings = Vec::new();

    // Check path_or_content rule on path
    if rule.path_or_content && re.is_match(&delta.path) {
        findings.push(FlawFinding {
            file: delta.path.clone(),
            line: None,
            pattern: rule.pattern.clone(),
            explanation: rule.explanation.clone(),
        });
    }

    // Determine which lines to check
    let lines_to_check: Vec<(usize, &str)> = if rule.path_or_content || rule.added_only {
        delta.added.iter().map(|(n, s)| (*n, s.as_str())).collect()
    } else {
        delta
            .added
            .iter()
            .map(|(n, s)| (*n, s.as_str()))
            .chain(delta.removed.iter().map(|(_, s)| (0, s.as_str())))
            .collect()
    };

    // Check if rule's requirement is met
    let requires_match = rule.requires.as_ref().is_none_or(|r| {
        Regex::new(r).is_ok_and(|x| {
            let context = delta
                .added
                .iter()
                .map(|(_, s)| s.as_str())
                .collect::<Vec<_>>()
                .join("\n");
            x.is_match(&context)
        })
    });

    if !requires_match {
        return Ok(findings);
    }

    // Check lines
    for (line_num, line_text) in lines_to_check {
        if re.is_match(line_text) {
            findings.push(FlawFinding {
                file: delta.path.clone(),
                line: if line_num > 0 { Some(line_num) } else { None },
                pattern: rule.pattern.clone(),
                explanation: rule.explanation.clone(),
            });
        }
    }

    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_match_basic_patterns() {
        assert!(glob_match("**/*", "anything/anywhere"));
        assert!(glob_match("*.rs", "test.rs"));
        assert!(!glob_match("*.rs", "test.toml"));
        assert!(glob_match(
            "**/migrations/**",
            "api/migrations/001_init.sql"
        ));
        assert!(!glob_match("**/migrations/**", "api/src/init.sql"));
    }

    #[test]
    fn parse_patch_basic() {
        let patch = "diff --git a/test.rs b/test.rs\n--- a/test.rs\n+++ b/test.rs\n@@ -1 +1,2 @@\n fn test() {\n+    assert!(x);\n";
        let deltas = parse_patch(patch);
        assert_eq!(deltas.len(), 1);
        assert_eq!(deltas[0].path, "test.rs");
        assert_eq!(deltas[0].added.len(), 1);
        assert_eq!(deltas[0].added[0].1, "    assert!(x);");
    }

    #[test]
    fn check_rule_invalid_pattern_returns_error() {
        let rule = FlawRule {
            pattern: "[invalid(regex".to_string(),
            files: vec!["*.rs".into()],
            explanation: "test".to_string(),
            added_only: true,
            path_only: false,
            path_or_content: false,
            applied_migration: false,
            requires: None,
        };

        let delta = PatchDelta {
            path: "test.rs".into(),
            added: vec![(1, "test line".into())],
            removed: vec![],
        };

        let result = check_rule(&rule, &delta);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid pattern"));
    }

    #[test]
    fn check_rule_matching_pattern_returns_finding() {
        let rule = FlawRule {
            pattern: "EXCEPTION".to_string(),
            files: vec!["**/*.sql".into()],
            explanation: "Swallowed exception".to_string(),
            added_only: true,
            path_only: false,
            path_or_content: false,
            applied_migration: false,
            requires: None,
        };

        let delta = PatchDelta {
            path: "migrations/001.sql".into(),
            added: vec![(5, "    EXCEPTION WHEN OTHERS".into())],
            removed: vec![],
        };

        let result = check_rule(&rule, &delta).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].file, "migrations/001.sql");
        assert_eq!(result[0].line, Some(5));
    }

    #[test]
    fn rule_file_deserializes_from_toml() {
        let toml = r#"[[rules]]
pattern = "(?i)EXCEPTION\\s+WHEN\\s+OTHERS"
files = ["**/*"]
explanation = "Swallowed exception"

[[rules]]
pattern = "GRANT"
files = ["**/fixtures/**"]
explanation = "Fixture grants privilege"
"#;

        let rule_file: RuleFile = toml::from_str(toml).unwrap();
        assert_eq!(rule_file.rules.len(), 2);
        assert_eq!(
            rule_file.rules[0].pattern,
            "(?i)EXCEPTION\\s+WHEN\\s+OTHERS"
        );
        assert_eq!(rule_file.rules[1].explanation, "Fixture grants privilege");
    }
}
