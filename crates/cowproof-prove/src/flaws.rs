//! Flaw rule types and the single rule matcher shared by the gates and
//! `cowproof-report`.
//!
//! This is the only implementation of flaw rule matching in the workspace.
//! Rule globs use `cowproof_core::glob_matches`, the same matcher as the
//! ownership and protected-path gates, so `**/*` matches a root-level file.

use cowproof_core::glob_matches;
use regex::Regex;
use serde::Deserialize;

pub use cowproof_core::{PatchDelta, parse_patch};

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

fn finding(rule: &FlawRule, label: &str, file: &str, line: Option<usize>) -> FlawFinding {
    FlawFinding {
        rule: label.to_string(),
        file: file.to_string(),
        line,
        pattern: rule.pattern.clone(),
        explanation: rule.explanation.clone(),
    }
}

/// The file name of `path` when it lies under a `migrations/` directory (a root-level one
/// counts), else `None`. This is what makes a path a migration for the `applied_migration`
/// rules and for the gate's decision to warn about a missing baseline.
pub fn migration_file_name(path: &str) -> Option<&str> {
    // A leading slash lets a root-level `migrations/` directory match too.
    let at = if path.starts_with("migrations/") {
        "migrations/".len()
    } else {
        path.find("/migrations/")? + "/migrations/".len()
    };
    path[at..].rsplit('/').next()
}

/// Order two migration file names: by the leading number when both names start
/// with digits (so `9_x` sorts before `10_x`, `009_x` before `010_x`, and
/// timestamp names by their timestamp), by the whole name otherwise. Names whose
/// leading numbers are equal fall back to the whole name, so `20261012T0900_a`
/// sorts before `20261012T1000_a`.
pub fn migration_order(a: &str, b: &str) -> std::cmp::Ordering {
    fn digits(name: &str) -> Option<&str> {
        let end = name
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(name.len());
        (end > 0).then(|| &name[..end])
    }
    if let (Some(x), Some(y)) = (digits(a), digits(b)) {
        // Compare as numbers without parsing, so a very long number cannot overflow.
        let (x, y) = (x.trim_start_matches('0'), y.trim_start_matches('0'));
        let by_number = x.len().cmp(&y.len()).then_with(|| x.cmp(y));
        if by_number != std::cmp::Ordering::Equal {
            return by_number;
        }
    }
    a.cmp(b)
}

/// Whether the migration file `file` is the baseline or sorts before it, by
/// [`migration_order`]: an applied migration.
pub fn migration_at_or_before(file: &str, baseline: &str) -> bool {
    migration_order(file, baseline) != std::cmp::Ordering::Greater
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
        let file = migration_file_name(&delta.path);
        let hit = baseline.is_some_and(|base| {
            file.is_some_and(|f| migration_at_or_before(f, base.rsplit('/').next().unwrap_or(base)))
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
    fn migration_order_compares_leading_numbers_as_numbers() {
        use std::cmp::Ordering::{Equal, Greater, Less};
        assert_eq!(migration_order("9_x.sql", "10_x.sql"), Less);
        assert_eq!(migration_order("10_x.sql", "9_x.sql"), Greater);
        assert_eq!(migration_order("009_x.sql", "010_x.sql"), Less);
        assert_eq!(migration_order("010_x.sql", "009_x.sql"), Greater);
        // Zero padding of different widths is the same number, so the rest of the name
        // decides (and the same name is equal).
        assert_eq!(migration_order("9_a.sql", "009_b.sql"), Greater);
        assert_eq!(migration_order("009_a.sql", "9_b.sql"), Less);
        assert_eq!(migration_order("0009_a.sql", "9_a.sql"), Less);
        assert_eq!(migration_order("9_a.sql", "9_a.sql"), Equal);
        assert_eq!(migration_order("9_a.sql", "10_a.sql"), Less);
        assert_eq!(migration_order("10_a.sql", "9_a.sql"), Greater);
        // Timestamps: by date, then by the rest of the name.
        assert_eq!(
            migration_order("20261012T090000_a.sql", "20261012T100000_a.sql"),
            Less
        );
        assert_eq!(
            migration_order("20261011T235959_z.sql", "20261012T000000_a.sql"),
            Less
        );
        assert_eq!(
            migration_order("20261012120000_a.sql", "20261012120000_a.sql"),
            Equal
        );
        // A number longer than any integer type still compares.
        assert_eq!(
            migration_order("99999999999999999999999_a", "100000000000000000000000_a"),
            Less
        );
    }

    #[test]
    fn migration_order_falls_back_to_strings_without_a_leading_number() {
        use std::cmp::Ordering::{Greater, Less};
        assert_eq!(migration_order("init.sql", "setup.sql"), Less);
        assert_eq!(migration_order("setup.sql", "init.sql"), Greater);
        // One side numeric, the other not: plain string order ("1" < "a").
        assert_eq!(migration_order("1_x.sql", "base.sql"), Less);
        assert_eq!(migration_order("base.sql", "1_x.sql"), Greater);
    }

    #[test]
    fn applied_migration_compares_numbers_not_strings() {
        let mut r = rule(".*", &["**/*"]);
        r.applied_migration = true;
        // "9_add.sql" > "10_add.sql" as strings; as numbers it is applied.
        let nine = delta("db/migrations/9_add.sql", &[], &["x"]);
        assert_eq!(
            check_rule(&r, "r", &nine, Some("10_add.sql"))
                .unwrap()
                .len(),
            1
        );
        let eleven = delta("db/migrations/11_add.sql", &[], &["x"]);
        assert!(
            check_rule(&r, "r", &eleven, Some("10_add.sql"))
                .unwrap()
                .is_empty()
        );
        let padded = delta("db/migrations/009_add.sql", &[], &["x"]);
        assert_eq!(
            check_rule(&r, "r", &padded, Some("010_add.sql"))
                .unwrap()
                .len(),
            1
        );
        let after = delta("db/migrations/011_add.sql", &[], &["x"]);
        assert!(
            check_rule(&r, "r", &after, Some("010_add.sql"))
                .unwrap()
                .is_empty()
        );
        // The baseline may be given as a path.
        assert_eq!(
            check_rule(&r, "r", &nine, Some("db/migrations/10_add.sql"))
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn migration_file_name_needs_a_migrations_directory() {
        assert_eq!(
            migration_file_name("migrations/001_a.sql"),
            Some("001_a.sql")
        );
        assert_eq!(
            migration_file_name("db/migrations/sub/002_b.sql"),
            Some("002_b.sql")
        );
        assert_eq!(migration_file_name("src/lib.rs"), None);
        assert_eq!(migration_file_name("docs/migrations.md"), None);
        assert_eq!(migration_file_name("my_migrations/001.sql"), None);
    }

    #[test]
    fn applied_migration_matches_a_root_level_migrations_directory() {
        let mut r = rule(".*", &["**/*"]);
        r.applied_migration = true;
        let d = delta("migrations/001_init.sql", &[], &["x"]);
        assert_eq!(
            check_rule(&r, "r", &d, Some("002_next.sql")).unwrap().len(),
            1
        );
        let outside = delta("docs/001_init.sql", &[], &["x"]);
        assert!(
            check_rule(&r, "r", &outside, Some("002_next.sql"))
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
