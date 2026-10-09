//! The rewrite manifest: which commands may be replaced, and by what.
//!
//! A rule is only allowed to rewrite once its `verified.status` is `pass`.
//! Verification is per **rule**, not per binary, so `--range` can go live while
//! `--ls` is still pending — they will not be ready at the same time.

use serde::{Deserialize, Serialize};

use crate::fidelity::{Fidelity, Normalizer};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Manifest {
    #[serde(default)]
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    /// Human name, for reports.
    pub name: String,
    /// Regex over the whole command. Anchored by convention.
    pub matches: String,
    /// Replacement, with `$1`-style captures from `matches`.
    pub rewrite: String,
    pub fidelity: Fidelity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub normalizer: Option<Normalizer>,
    /// How to get back what the rewrite withholds. Required for every lossy
    /// class: an omission the caller cannot undo is a silent loss.
    pub recovery: String,
    #[serde(default)]
    pub verified: Verified,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verified {
    pub status: Status,
    #[serde(default)]
    pub cases: usize,
    #[serde(default)]
    pub passed: usize,
    /// Cases whose target no longer exists. Counted, not silently dropped: a
    /// rule that "passed" on two of four hundred cases is not verified.
    #[serde(default)]
    pub skipped: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checked_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ledger_window: Option<usize>,
    /// Working tree the pair-run was performed against. A rewrite verified on
    /// one tree says little about another.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tree_sha: Option<String>,
}

impl Default for Verified {
    fn default() -> Self {
        Self {
            status: Status::Pending,
            cases: 0,
            passed: 0,
            skipped: 0,
            checked_at: None,
            ledger_window: None,
            tree_sha: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    /// Never verified. Suggest-only.
    Pending,
    Pass,
    Fail,
}

impl Rule {
    /// May this rule rewrite a command?
    ///
    /// Only on `pass`. Pending and failing rules fall through to the
    /// suggest-only path, which costs tokens but cannot be wrong.
    pub fn may_rewrite(&self) -> bool {
        self.verified.status == Status::Pass
    }
}

impl Manifest {
    pub fn load(path: &std::path::Path) -> crate::Result<Self> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| crate::Error::Config(format!("{}: {e}", path.display())))?;
        serde_json::from_str(&raw)
            .map_err(|e| crate::Error::Config(format!("{}: {e}", path.display())))
    }

    pub fn save(&self, path: &std::path::Path) -> crate::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut json = serde_json::to_vec_pretty(self)?;
        json.push(b'\n');
        Ok(std::fs::write(path, json)?)
    }

    /// The rules cleared to rewrite.
    pub fn active(&self) -> impl Iterator<Item = &Rule> {
        self.rules.iter().filter(|r| r.may_rewrite())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(status: Status) -> Rule {
        Rule {
            name: "range".into(),
            matches: r"^sed -n '?(\d+),(\d+)p'? (\S+)$".into(),
            rewrite: "pk-read --range $1:$2 $3".into(),
            fidelity: Fidelity::SubsetDeclared,
            normalizer: None,
            recovery: "pk-read --range $1:$2 $3 --full".into(),
            verified: Verified {
                status,
                ..Default::default()
            },
        }
    }

    #[test]
    fn a_new_rule_is_pending_and_may_not_rewrite() {
        assert_eq!(Verified::default().status, Status::Pending);
        assert!(!rule(Status::Pending).may_rewrite());
    }

    #[test]
    fn only_a_passing_rule_may_rewrite() {
        assert!(rule(Status::Pass).may_rewrite());
        assert!(!rule(Status::Fail).may_rewrite());
    }

    #[test]
    fn active_filters_to_verified_rules() {
        let m = Manifest {
            rules: vec![rule(Status::Pass), rule(Status::Pending)],
        };
        assert_eq!(m.active().count(), 1);
    }

    #[test]
    fn a_manifest_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("m.json");
        let m = Manifest {
            rules: vec![rule(Status::Pass)],
        };
        m.save(&path).unwrap();
        let back = Manifest::load(&path).unwrap();
        assert_eq!(back.rules.len(), 1);
        assert!(back.rules[0].may_rewrite());
    }
}
