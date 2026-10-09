//! What "verified" means for a tool that is lossy on purpose.
//!
//! Byte-equality forecloses the win: identical bytes are identical tokens.
//! But "semantically equivalent" is too vague to implement — a range reader
//! and a directory lister fail it in completely different ways. So fidelity is
//! declared **per rule**, and each class carries a gate that can actually be
//! checked.

use serde::{Deserialize, Serialize};

/// The equivalence a rule promises.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Fidelity {
    /// Byte-identical. For rules that do not reshape anything.
    Exact,
    /// Equal after a declared, versioned transform.
    Normalized,
    /// An ordered subset, with the omission declared and counted.
    SubsetDeclared,
    /// The identifying set is preserved; supplementary fields may be dropped.
    Keyset,
    /// A pointer to content the caller already holds.
    ///
    /// Cannot be verified at registration time: the claim is about the
    /// caller's context, not about output, and both the file and the context
    /// can change afterwards. Checked at emit, every time.
    Reference,
}

/// Why a pair failed its gate. Kept specific so a failing rule says what is
/// wrong rather than that something is.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Verdict {
    Pass,
    Fail(String),
    /// Not checkable here — `Reference` is a runtime property.
    NotApplicable(String),
}

impl Verdict {
    pub fn passed(&self) -> bool {
        matches!(self, Verdict::Pass)
    }
}

/// The declared normalizer, versioned so a future change cannot silently
/// redefine what a past verification meant.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Normalizer {
    pub name: String,
    pub version: u32,
}

impl Normalizer {
    pub fn apply(&self, text: &str) -> Option<String> {
        match (self.name.as_str(), self.version) {
            ("trim-trailing-ws+collapse-blank-runs", 1) => {
                let mut out: Vec<&str> = Vec::new();
                let mut blanks = 0;
                for line in text.lines() {
                    let line = line.trim_end();
                    if line.is_empty() {
                        blanks += 1;
                        if blanks > 1 {
                            continue;
                        }
                    } else {
                        blanks = 0;
                    }
                    out.push(line);
                }
                Some(out.join("\n"))
            }
            // An unknown normalizer must not silently pass. The alternative is
            // a verification that means whatever the current binary does.
            _ => None,
        }
    }
}

/// Apply a class gate to one original/rewritten pair.
pub fn check(
    fidelity: Fidelity,
    original: &str,
    rewritten: &str,
    normalizer: Option<&Normalizer>,
) -> Verdict {
    match fidelity {
        Fidelity::Exact => {
            if original == rewritten {
                Verdict::Pass
            } else {
                Verdict::Fail("output differs".into())
            }
        }

        Fidelity::Normalized => {
            let Some(n) = normalizer else {
                return Verdict::Fail("normalized rules must declare a normalizer".into());
            };
            match (n.apply(original), n.apply(rewritten)) {
                (Some(a), Some(b)) if a == b => Verdict::Pass,
                (Some(_), Some(_)) => Verdict::Fail(format!("differs after {}", n.name)),
                _ => Verdict::Fail(format!("unknown normalizer `{}` v{}", n.name, n.version)),
            }
        }

        Fidelity::SubsetDeclared => subset_declared(original, rewritten),

        Fidelity::Keyset => {
            // Every identifying name in the original has to appear somewhere in
            // the rewrite. Deliberately format-agnostic: `ls -la` puts the name
            // last and a two-column listing puts it first, and the gate should
            // not have to know which shape it is looking at.
            let got: Vec<String> = rewritten.split_whitespace().map(tidy).collect();
            let missing: Vec<String> = key_tokens(original)
                .into_iter()
                .filter(|k| !got.contains(k))
                .collect();
            if missing.is_empty() {
                Verdict::Pass
            } else {
                Verdict::Fail(format!(
                    "{} identifying names dropped, e.g. {:?}",
                    missing.len(),
                    missing.first()
                ))
            }
        }

        Fidelity::Reference => Verdict::NotApplicable(
            "reference is a claim about caller state; checked at emit, not registration".into(),
        ),
    }
}

/// Retained content must be an ordered subset, and what is missing must be
/// declared. Silence about an omission is the failure this class exists to
/// prevent.
fn subset_declared(original: &str, rewritten: &str) -> Verdict {
    let declares_omission = rewritten.contains('…')
        || rewritten.contains("...")
        || rewritten.contains("KNOWN ")
        || rewritten.contains("UNCHANGED ")
        || rewritten.contains(" more");

    // Strip any line-number gutter the rewrite added, so content compares.
    let kept: Vec<&str> = rewritten
        .lines()
        .filter(|l| !is_marker(l))
        .map(|l| {
            l.split_once('\u{2502}')
                .map_or(l, |(_, rest)| rest)
                .trim_end()
        })
        .collect();
    let source: Vec<&str> = original.lines().map(str::trim_end).collect();

    // Ordered containment: every kept line appears in the original, in order.
    let mut cursor = 0usize;
    for line in &kept {
        if line.trim().is_empty() {
            continue;
        }
        match source[cursor..].iter().position(|s| s == line) {
            Some(i) => cursor += i + 1,
            None => return Verdict::Fail(format!("line not present in the original: {line:?}")),
        }
    }

    if kept.len() < source.len() && !declares_omission {
        return Verdict::Fail("content was dropped without declaring it".into());
    }
    Verdict::Pass
}

fn is_marker(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with("KNOWN ") || t.starts_with("UNCHANGED ") || t.starts_with('(')
}

/// The identifying name on each line of a listing.
///
/// `ls -la` puts it last, after the columns the rewrite is allowed to drop.
///
/// Three things are excluded because they are not entries: the `total N`
/// block-count header, and the `.` / `..` links, which `read_dir` does not
/// yield and which no caller is asking about. This is a stated convention of
/// the keyset class rather than a special case for one command — a listing
/// gate compares entries.
fn key_tokens(text: &str) -> Vec<String> {
    text.lines()
        .filter(|l| !l.trim_start().starts_with("total "))
        .filter_map(|l| l.split_whitespace().last())
        .filter(|t| !t.is_empty() && !t.starts_with('('))
        .map(tidy)
        .filter(|t| t != "." && t != "..")
        .collect()
}

/// Normalize a token for comparison: a trailing `/` marks a directory in one
/// format and is absent in another.
fn tidy(token: &str) -> String {
    token.trim_end_matches('/').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn norm() -> Normalizer {
        Normalizer {
            name: "trim-trailing-ws+collapse-blank-runs".into(),
            version: 1,
        }
    }

    #[test]
    fn exact_demands_byte_equality() {
        assert!(check(Fidelity::Exact, "a\nb", "a\nb", None).passed());
        assert!(!check(Fidelity::Exact, "a\nb", "a\nc", None).passed());
    }

    #[test]
    fn normalized_ignores_only_what_the_transform_declares() {
        assert!(check(
            Fidelity::Normalized,
            "a   \n\n\n\nb",
            "a\n\nb",
            Some(&norm())
        )
        .passed());
        assert!(!check(Fidelity::Normalized, "a\nb", "a\nc", Some(&norm())).passed());
    }

    #[test]
    fn an_unknown_normalizer_fails_rather_than_passing() {
        // Otherwise verification means whatever the current binary happens to do.
        let bogus = Normalizer {
            name: "mystery".into(),
            version: 9,
        };
        assert!(!check(Fidelity::Normalized, "a", "a", Some(&bogus)).passed());
    }

    #[test]
    fn normalized_without_a_declared_transform_fails() {
        assert!(!check(Fidelity::Normalized, "a", "a", None).passed());
    }

    #[test]
    fn subset_declared_accepts_a_declared_omission() {
        let original = "one\ntwo\nthree\nfour";
        let rewritten = "KNOWN L1-2 sha:ab (recover: --full)\n3\u{2502}three\n4\u{2502}four";
        assert!(check(Fidelity::SubsetDeclared, original, rewritten, None).passed());
    }

    #[test]
    fn subset_declared_rejects_a_silent_omission() {
        // The failure this class exists to catch.
        let v = check(
            Fidelity::SubsetDeclared,
            "one\ntwo\nthree",
            "one\ntwo",
            None,
        );
        assert!(!v.passed(), "{v:?}");
    }

    #[test]
    fn subset_declared_rejects_invented_content() {
        let v = check(
            Fidelity::SubsetDeclared,
            "one\ntwo",
            "one\nINVENTED\n…more",
            None,
        );
        assert!(!v.passed(), "{v:?}");
    }

    #[test]
    fn subset_declared_rejects_reordering() {
        // Ordered containment: a reordered subset is not a subset of a file.
        let v = check(
            Fidelity::SubsetDeclared,
            "one\ntwo\nthree",
            "three\none\n…more",
            None,
        );
        assert!(!v.passed(), "{v:?}");
    }

    #[test]
    fn keyset_ignores_the_total_header_and_dot_entries() {
        // Caught by the verifier on its first real run: `ls -la` emits a
        // block-count header and `.`/`..`, none of which are entries.
        let ls = "total 24\n                  drwxr-xr-x  4 me staff  128 Sep  9 10:00 .\n                  drwxr-xr-x 10 me staff  320 Sep  9 10:00 ..\n                  -rw-r--r--  1 me staff  120 Sep  9 10:00 a.txt";
        assert!(check(Fidelity::Keyset, ls, "a.txt\t120\n(1 entries)", None).passed());
    }

    #[test]
    fn keyset_allows_dropped_columns_but_not_dropped_names() {
        let ls = "-rw-r--r--  1 me  staff   120 Sep  9 10:00 a.txt\n\
                  -rw-r--r--  1 me  staff   340 Sep  9 10:00 b.txt";
        assert!(check(Fidelity::Keyset, ls, "a.txt\t120\nb.txt\t340", None).passed());
        assert!(!check(Fidelity::Keyset, ls, "a.txt\t120", None).passed());
    }

    #[test]
    fn reference_declines_registration_time_verification() {
        let v = check(
            Fidelity::Reference,
            "content",
            "UNCHANGED L1-9 sha:ab",
            None,
        );
        assert!(matches!(v, Verdict::NotApplicable(_)), "{v:?}");
        assert!(!v.passed(), "not applicable is not a pass");
    }
}
