//! Rewriting a shell command into a cheaper call that answers the same question.
//!
//! Suggesting costs tokens on every fire and guarantees nothing; the measured
//! failure was never that a better tool was missing. codemap's MCP surface
//! took 0 of 78 calls while agents reached for `grep`. A `PreToolUse` rewrite
//! costs nothing and does not depend on the agent choosing to listen.
//!
//! # Not an equivalence-preserving port
//!
//! Porting `grep` to Rust and gating on byte-equal stdout saves no tokens at
//! all — identical bytes are identical tokens, by construction. Measured, the
//! one case where equivalence does save something (a cache returning a pointer
//! instead of the content) covers **0.5%** of bytes.
//!
//! The savings come from answering the question instead of reproducing the
//! output: a symbol lookup returns 40-63x less than the file it lives in.
//! That is not byte-equal, and cannot be. So the gate here is *"contains the
//! text the original would have matched"*, which is checkable, rather than
//! *"produces the same bytes"*, which forecloses the win.
//!
//! # Conservative by construction
//!
//! Only read-only shapes are considered, by allowlist rather than denylist: a
//! rewrite that alters a command with side effects is unrecoverable, and a
//! denylist is a bet that you thought of everything.

use serde::{Deserialize, Serialize};

/// A command reduced to its shape, so repeats can be counted across differing
/// paths and literals.
///
/// `grep -n "TODO" /a/b.rs` and `grep -n "FIXME" /c/d.rs` share a fingerprint;
/// the point is to notice the *habit*, not the instance.
pub fn fingerprint(command: &str) -> String {
    let mut out = String::with_capacity(command.len());
    let mut chars = command.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            // Quoted literals collapse to one token.
            '"' | '\'' => {
                let quote = c;
                for n in chars.by_ref() {
                    if n == quote {
                        break;
                    }
                }
                out.push_str("$S");
            }
            // A path is a path whatever it points at.
            '/' if out.chars().last().is_none_or(|p| p.is_whitespace()) => {
                while chars.peek().is_some_and(|n| !n.is_whitespace()) {
                    chars.next();
                }
                out.push_str("$P");
            }
            c if c.is_whitespace() => {
                if !out.ends_with(' ') {
                    out.push(' ');
                }
            }
            c => out.push(c),
        }
    }
    out.trim().chars().take(120).collect()
}

/// Anything that could change the world, or whose output feeds something else.
///
/// A rewrite has to be safe to apply without understanding the whole line, so
/// the presence of any of these disqualifies the command outright.
const DISQUALIFYING: &[&str] = &[
    ">",
    ">>",
    "|",
    "&&",
    "||",
    ";",
    "$(",
    "`",
    "&",
    " rm ",
    " mv ",
    " cp ",
    " dd ",
    " chmod ",
    " chown ",
    " kill ",
    "sudo",
    "git push",
    "git commit",
    "git reset",
    "git checkout",
    "git clean",
    "npm publish",
    "cargo publish",
    "docker",
    "kubectl",
    "curl",
    "wget",
];

/// Whether a command is safe to consider rewriting at all.
///
/// Deliberately blunt. A pipeline might be safe, but proving it is per-command
/// work, and being wrong once is worse than every missed rewrite combined.
pub fn is_rewritable(command: &str) -> bool {
    let padded = format!(" {} ", command.trim());
    if DISQUALIFYING.iter().any(|bad| padded.contains(bad)) {
        return false;
    }
    // Allowlist the head: only commands that read.
    matches!(
        padded.split_whitespace().next(),
        Some("grep" | "rg" | "ag" | "egrep")
    )
}

/// A cheaper call that answers the same question.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Rewrite {
    /// The command to run instead.
    pub command: String,
    /// The symbol being sought, so the result can be checked against it.
    pub verify_contains: String,
    /// Shown to the agent once, so it learns the tool exists.
    pub note: String,
}

/// Recognise a search for a definition.
///
/// The one intent with an unambiguous cheaper answer: an agent grepping for
/// `fn parse_config` wants the definition, and a symbol lookup returns it in
/// a fraction of the bytes. Anything less clear is left alone.
pub fn detect_definition_search(command: &str) -> Option<Rewrite> {
    if !is_rewritable(command) {
        return None;
    }

    let literal = quoted_literal(command)?;
    let name = symbol_in(&literal)?;

    Some(Rewrite {
        command: format!("pk run sym -a name={name}"),
        verify_contains: name.clone(),
        note: format!(
            "`pk run sym -a name={name}` returns the definition's span directly, \
             typically 40-60x smaller than the file it lives in."
        ),
    })
}

/// The first quoted argument, which for a grep is the pattern.
fn quoted_literal(command: &str) -> Option<String> {
    for quote in ['"', '\''] {
        if let Some(start) = command.find(quote) {
            if let Some(len) = command[start + 1..].find(quote) {
                return Some(command[start + 1..start + 1 + len].to_string());
            }
        }
    }
    None
}

/// Pull a symbol name out of a search pattern, when the pattern is clearly
/// looking for a declaration.
///
/// Requires a declaration keyword. A bare identifier could be a search for
/// usages, which a definition lookup would answer wrongly.
fn symbol_in(pattern: &str) -> Option<String> {
    const KEYWORDS: &[&str] = &[
        "fn ",
        "struct ",
        "enum ",
        "trait ",
        "impl ",
        "type ",
        "class ",
        "interface ",
        "function ",
        "def ",
        "func ",
    ];

    let lowered = pattern.to_lowercase();
    let keyword = KEYWORDS
        .iter()
        .find(|k| lowered.starts_with(*k) || lowered.contains(*k))?;
    let after = pattern[lowered.find(*keyword)? + keyword.len()..].trim_start();

    let name: String = after
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '$')
        .collect();

    // Regex metacharacters mean the agent wants a pattern, not one symbol.
    if name.len() < 2 || pattern.contains(['*', '+', '[', '(', '|', '\\']) {
        return None;
    }
    Some(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprints_collapse_paths_and_literals() {
        assert_eq!(fingerprint("grep -n \"TODO\" /repo/a.rs"), "grep -n $S $P");
        assert_eq!(
            fingerprint("grep -n \"FIXME\" /other/b.ts"),
            "grep -n $S $P"
        );
    }

    #[test]
    fn different_shapes_stay_different() {
        assert_ne!(fingerprint("grep -n $S $P"), fingerprint("grep -rn $S $P"));
    }

    #[test]
    fn anything_with_side_effects_is_refused() {
        // Being wrong once here is worse than every missed rewrite combined.
        for cmd in [
            "rm -rf /tmp/x",
            "git push origin main",
            "grep x file > out.txt",
            "grep x file | head",
            "grep x file && rm y",
            "sudo grep x /etc/passwd",
            "grep x $(cat list)",
        ] {
            assert!(!is_rewritable(cmd), "should refuse: {cmd}");
        }
    }

    #[test]
    fn only_reading_commands_are_considered() {
        assert!(is_rewritable("grep -n \"fn x\" src"));
        assert!(!is_rewritable("cat file"));
        assert!(!is_rewritable("sed -n '1,10p' file"));
    }

    #[test]
    fn a_definition_search_is_recognised() {
        let r = detect_definition_search("grep -rn \"fn parse_config\" src/").unwrap();
        assert_eq!(r.command, "pk run sym -a name=parse_config");
        assert_eq!(r.verify_contains, "parse_config");
    }

    #[test]
    fn other_languages_are_recognised_too() {
        for (cmd, want) in [
            ("grep -n \"class Registry\" src", "Registry"),
            ("grep -n \"def load_config\" .", "load_config"),
            ("grep -n \"interface Config\" src", "Config"),
            ("grep -n \"func Handle\" .", "Handle"),
        ] {
            let r = detect_definition_search(cmd).unwrap_or_else(|| panic!("missed: {cmd}"));
            assert_eq!(r.verify_contains, want);
        }
    }

    #[test]
    fn a_bare_identifier_is_left_alone() {
        // Could be a search for usages, which a definition lookup answers
        // wrongly — and wrongly is worse than not at all.
        assert!(detect_definition_search("grep -rn \"parse_config\" src/").is_none());
    }

    #[test]
    fn a_regex_pattern_is_left_alone() {
        assert!(detect_definition_search("grep -rn \"fn parse_.*\" src/").is_none());
        assert!(detect_definition_search("grep -rn \"fn (a|b)\" src/").is_none());
    }

    #[test]
    fn an_unquoted_grep_is_left_alone() {
        // Without a quoted pattern there is nothing reliable to extract.
        assert!(detect_definition_search("grep -rn fn src/").is_none());
    }
}
