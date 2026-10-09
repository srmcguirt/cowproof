//! Flaw rule types and the single rule matcher shared by the gates and
//! `cowproof-report`.
//!
//! This is the only implementation of flaw rule matching in the workspace.
//! Rule globs use `cowproof_core::glob_matches`, the same matcher as the
//! ownership and protected-path gates, so `**/*` matches a root-level file.

use cowproof_core::glob_matches;
use regex::Regex;
use serde::Deserialize;

/// A flaw rule as defined in a flaws.toml file.
#[derive(Clone, Debug, Deserialize)]
pub struct FlawRule {
    /// Optional stable name, used in evidence. Rules without one are named
    /// by their position in the pack.
    #[serde(default)]
    pub id: Option<String>,
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

/// Parse a flaw pack. A malformed pack is an error, never an empty pack.
pub fn parse_rules(text: &str) -> Result<RuleFile, String> {
    toml::from_str(text).map_err(|e| format!("flaw pack does not parse: {e}"))
}

/// A parsed flaw finding from a rule match.
#[derive(Clone, Debug)]
pub struct FlawFinding {
    /// The rule's id, or `rule #N` when it has none.
    pub rule: String,
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
    /// Unchanged lines shown in hunks, consulted by `requires`.
    pub context: Vec<String>,
}

/// Parse a unified diff patch into deltas per file.
pub fn parse_patch(patch: &str) -> Vec<PatchDelta> {
    let mut out: Vec<PatchDelta> = Vec::new();
    let mut new_line = 1usize;
    // `---`/`+++` are file headers only before the first hunk. Inside a hunk
    // an added line such as `++ x` renders as `+++ x` and must still count.
    let mut in_hunk = false;
    for line in patch.lines() {
        if let Some(rest) = line.strip_prefix("diff --git a/") {
            in_hunk = false;
            let path = rest
                .split_once(" b/")
                .map(|(_, b)| b.to_string())
                .unwrap_or_default();
            out.push(PatchDelta {
                path,
                added: Vec::new(),
                removed: Vec::new(),
                context: Vec::new(),
            });
            new_line = 1;
            continue;
        }
        let Some(d) = out.last_mut() else {
            continue;
        };
        if line.starts_with('\\') {
            continue;
        }
        if !in_hunk && !line.starts_with("@@") {
            continue;
        }
        if line.starts_with("@@") {
            in_hunk = true;
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

fn finding(rule: &FlawRule, label: &str, file: &str, line: Option<usize>) -> FlawFinding {
    FlawFinding {
        rule: label.to_string(),
        file: file.to_string(),
        line,
        pattern: rule.pattern.clone(),
        explanation: rule.explanation.clone(),
    }
}

/// Check one rule against one file's delta.
///
/// `label` names the rule in errors and findings. `baseline` is the last
/// applied migration file name; an `applied_migration` rule fires only when a
/// baseline is supplied and the patch touches a migration at or before it.
/// A pattern (or `requires` pattern) that does not compile is an `Err`, never
/// a silent skip.
pub fn check_rule(
    rule: &FlawRule,
    label: &str,
    delta: &PatchDelta,
    baseline: Option<&str>,
) -> Result<Vec<FlawFinding>, String> {
    if !rule.files.iter().any(|g| glob_matches(g, &delta.path)) {
        return Ok(Vec::new());
    }
    let re = Regex::new(&rule.pattern)
        .map_err(|e| format!("{label}: pattern {:?} does not compile: {e}", rule.pattern))?;
    let requires = match &rule.requires {
        Some(r) => Some(
            Regex::new(r)
                .map_err(|e| format!("{label}: requires pattern {r:?} does not compile: {e}"))?,
        ),
        None => None,
    };

    if rule.applied_migration {
        let hit = baseline.is_some_and(|base| {
            delta
                .path
                .split("/migrations/")
                .nth(1)
                .and_then(|f| f.rsplit('/').next())
                .is_some_and(|f| f <= base.rsplit('/').next().unwrap_or(base))
        });
        if hit {
            let mut f = finding(rule, label, &delta.path, None);
            f.pattern = format!("--baseline {}", baseline.unwrap_or_default());
            return Ok(vec![f]);
        }
        return Ok(Vec::new());
    }

    if rule.path_only {
        if re.is_match(&delta.path) {
            return Ok(vec![finding(rule, label, &delta.path, None)]);
        }
        return Ok(Vec::new());
    }

    let mut findings = Vec::new();
    if rule.path_or_content && re.is_match(&delta.path) {
        findings.push(finding(rule, label, &delta.path, None));
    }

    if let Some(x) = &requires {
        let haystack = delta
            .added
            .iter()
            .map(|(_, s)| s.as_str())
            .chain(delta.context.iter().map(String::as_str))
            .collect::<Vec<_>>()
            .join("\n");
        if !x.is_match(&haystack) {
            return Ok(findings);
        }
    }

    let removed_too = !(rule.path_or_content || rule.added_only);
    let lines = delta.added.iter().chain(if removed_too {
        delta.removed.iter()
    } else {
        [].iter()
    });
    for (n, text) in lines {
        if re.is_match(text) {
            findings.push(finding(rule, label, &delta.path, (*n > 0).then_some(*n)));
        }
    }
    Ok(findings)
}

/// Run every rule over every delta. Returns the findings and one error string
/// per rule that failed to compile (reported once per rule, not per file).
pub fn check_rules(
    rules: &[FlawRule],
    deltas: &[PatchDelta],
    baseline: Option<&str>,
) -> (Vec<FlawFinding>, Vec<String>) {
    let mut findings = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    for delta in deltas {
        for (i, rule) in rules.iter().enumerate() {
            let label = rule
                .id
                .clone()
                .unwrap_or_else(|| format!("rule #{}", i + 1));
            match check_rule(rule, &label, delta, baseline) {
                Ok(mut f) => findings.append(&mut f),
                Err(e) if !errors.contains(&e) => errors.push(e),
                Err(_) => {}
            }
        }
    }
    (findings, errors)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(pattern: &str, files: &[&str]) -> FlawRule {
        FlawRule {
            id: None,
            pattern: pattern.to_string(),
            files: files.iter().map(|s| s.to_string()).collect(),
            explanation: "explained".to_string(),
            added_only: false,
            path_only: false,
            path_or_content: false,
            applied_migration: false,
            requires: None,
        }
    }

    fn delta(path: &str, added: &[(usize, &str)], removed: &[&str]) -> PatchDelta {
        PatchDelta {
            path: path.into(),
            added: added.iter().map(|(n, s)| (*n, s.to_string())).collect(),
            removed: removed.iter().map(|s| (0, s.to_string())).collect(),
            context: vec![],
        }
    }

    #[test]
    fn root_level_file_matches_double_star_glob() {
        // The regression behind the three failing gates tests: a private glob
        // turned `**/*` into `^.*/[^/]*$`, which cannot match `test.rs`.
        let r = rule("EXCEPTION", &["**/*"]);
        let d = delta("test.rs", &[(1, "EXCEPTION WHEN OTHERS")], &[]);
        assert_eq!(check_rule(&r, "r", &d, None).unwrap().len(), 1);
    }

    #[test]
    fn parse_patch_reads_added_removed_and_context() {
        let patch = "diff --git a/test.rs b/test.rs\n--- a/test.rs\n+++ b/test.rs\n@@ -1,2 +1,2 @@\n fn test() {\n-    old();\n+    assert!(x);\n";
        let deltas = parse_patch(patch);
        assert_eq!(deltas.len(), 1);
        assert_eq!(deltas[0].path, "test.rs");
        assert_eq!(deltas[0].added, vec![(2, "    assert!(x);".to_string())]);
        assert_eq!(deltas[0].removed, vec![(0, "    old();".to_string())]);
        assert_eq!(deltas[0].context, vec!["fn test() {".to_string()]);
    }

    #[test]
    fn added_line_starting_with_plus_signs_is_not_mistaken_for_a_header() {
        let patch = "diff --git a/a.sql b/a.sql\n--- a/a.sql\n+++ b/a.sql\n@@ -1,2 +1,2 @@\n keep\n--- old comment\n+++ EXCEPTION WHEN OTHERS\n";
        let d = &parse_patch(patch)[0];
        assert_eq!(d.added, vec![(2, "++ EXCEPTION WHEN OTHERS".to_string())]);
        assert_eq!(d.removed, vec![(0, "-- old comment".to_string())]);
    }

    #[test]
    fn invalid_pattern_is_an_error_naming_the_rule() {
        let r = rule("[invalid(regex", &["*.rs"]);
        let d = delta("test.rs", &[(1, "test line")], &[]);
        let err = check_rule(&r, "my-rule", &d, None).unwrap_err();
        assert!(err.contains("my-rule"), "{err}");
        assert!(err.contains("does not compile"), "{err}");
    }

    #[test]
    fn invalid_requires_pattern_is_an_error() {
        let mut r = rule("x", &["**/*"]);
        r.requires = Some("(unclosed".into());
        let d = delta("a.rs", &[(1, "x")], &[]);
        let err = check_rule(&r, "needs", &d, None).unwrap_err();
        assert!(err.contains("requires pattern"), "{err}");
    }

    #[test]
    fn invalid_pattern_is_ignored_when_file_not_in_scope() {
        let r = rule("[invalid(regex", &["*.sql"]);
        let d = delta("a.rs", &[(1, "x")], &[]);
        assert!(check_rule(&r, "r", &d, None).unwrap().is_empty());
    }

    #[test]
    fn matching_pattern_returns_finding_with_line() {
        let mut r = rule("EXCEPTION", &["**/*.sql"]);
        r.added_only = true;
        let d = delta(
            "migrations/001.sql",
            &[(5, "    EXCEPTION WHEN OTHERS")],
            &[],
        );
        let found = check_rule(&r, "swallow", &d, None).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].rule, "swallow");
        assert_eq!(found[0].file, "migrations/001.sql");
        assert_eq!(found[0].line, Some(5));
    }

    #[test]
    fn added_only_ignores_removed_lines_and_default_checks_both() {
        let d = delta("a.rs", &[], &["#[ignore]"]);
        let mut r = rule("#\\[ignore\\]", &["**/*.rs"]);
        assert_eq!(check_rule(&r, "r", &d, None).unwrap().len(), 1);
        r.added_only = true;
        assert!(check_rule(&r, "r", &d, None).unwrap().is_empty());
    }

    #[test]
    fn requires_consults_added_and_context_lines() {
        let mut r = rule("CONCURRENTLY", &["**/*.sql"]);
        r.requires = Some("--\\s*transactional".into());
        let mut d = delta("m.sql", &[(2, "CREATE INDEX CONCURRENTLY i ON t(c);")], &[]);
        assert!(check_rule(&r, "r", &d, None).unwrap().is_empty());
        d.context.push("-- transactional".into());
        assert_eq!(check_rule(&r, "r", &d, None).unwrap().len(), 1);
    }

    #[test]
    fn path_only_rule_matches_the_path_not_the_content() {
        let mut r = rule("target/", &["**/*"]);
        r.path_only = true;
        let on_path = delta("crates/x/target/debug/x", &[], &[]);
        assert_eq!(check_rule(&r, "r", &on_path, None).unwrap().len(), 1);
        let in_content = delta("a.rs", &[(1, "target/")], &[]);
        assert!(check_rule(&r, "r", &in_content, None).unwrap().is_empty());
    }

    #[test]
    fn applied_migration_needs_a_baseline() {
        let mut r = rule(".*", &["**/*"]);
        r.applied_migration = true;
        let d = delta("supabase/migrations/20260401_existing.sql", &[], &["x"]);
        assert!(check_rule(&r, "r", &d, None).unwrap().is_empty());
        let hit = check_rule(&r, "r", &d, Some("20260401_existing.sql")).unwrap();
        assert_eq!(hit.len(), 1);
        assert!(hit[0].pattern.starts_with("--baseline"));
        let newer = delta("supabase/migrations/20260402_new.sql", &[], &["x"]);
        assert!(
            check_rule(&r, "r", &newer, Some("20260401_existing.sql"))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn check_rules_labels_by_id_then_position_and_dedupes_errors() {
        let mut named = rule("EXCEPTION", &["**/*"]);
        named.id = Some("swallow".into());
        let broken = rule("[bad(", &["**/*"]);
        let deltas = vec![
            delta("a.rs", &[(1, "EXCEPTION")], &[]),
            delta("b.rs", &[(1, "EXCEPTION")], &[]),
        ];
        let (found, errors) = check_rules(&[named, broken], &deltas, None);
        assert_eq!(found.len(), 2);
        assert!(found.iter().all(|f| f.rule == "swallow"));
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(errors[0].starts_with("rule #2"), "{errors:?}");
    }

    #[test]
    fn rule_file_deserializes_from_toml() {
        let toml = r#"[[rules]]
id = "swallow"
pattern = "(?i)EXCEPTION\\s+WHEN\\s+OTHERS"
files = ["**/*"]
explanation = "Swallowed exception"

[[rules]]
pattern = "GRANT"
files = ["**/fixtures/**"]
explanation = "Fixture grants privilege"
"#;
        let rule_file = parse_rules(toml).unwrap();
        assert_eq!(rule_file.rules.len(), 2);
        assert_eq!(rule_file.rules[0].id.as_deref(), Some("swallow"));
        assert_eq!(rule_file.rules[1].id, None);
        assert_eq!(rule_file.rules[1].explanation, "Fixture grants privilege");
    }

    #[test]
    fn malformed_pack_is_an_error() {
        assert!(parse_rules("[[rules]]\npattern = ").is_err());
        assert!(parse_rules("[[rules]]\npattern = \"x\"\n").is_err());
    }
}
