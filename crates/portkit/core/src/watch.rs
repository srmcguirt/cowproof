//! Detecting waste in an agent's own tool use.
//!
//! The patterns here are not guesses. They were measured across 878 local
//! sessions — 59,077 calls, 353 MB — and each threshold is fitted to what that
//! data actually showed:
//!
//! - `read_file → read_file` occurred **10,013** times consecutively, one in
//!   six of all consecutive pairs. An agent that reads, then reads again, is
//!   usually searching.
//! - **818** reads were of a file already read in the same session.
//! - **3,214** consecutive `web → web` pairs.
//! - 711 image reads carried **262 MB**, 74% of all bytes.
//!
//! # Suggesting costs tokens too
//!
//! A nudge is only worth making if it is cheaper than the waste it prevents.
//! A 200-byte suggestion that saves 2 KB is a good trade once; fired on every
//! call it is a loss, and an agent learns to skip advice that is always there.
//! So detection is deliberately reluctant: thresholds, one suggestion at a
//! time, and never the same suggestion twice for the same target.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::trace::CallRecord;

/// A specific, cheaper call to make instead.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Suggestion {
    /// Why it fired, for the session summary.
    pub pattern: String,
    /// What it is about — the file, URL, or command repeated.
    pub target: String,
    /// Shown to the agent. Names a concrete call, never general advice.
    pub message: String,
    /// Bytes already spent on this pattern, so the trade is visible.
    pub wasted_bytes: usize,
}

/// Thresholds, all fitted to measured behaviour rather than chosen.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Thresholds {
    /// Reads of one file in a session before it is worth saying something.
    /// Two can be legitimate — re-checking after an edit. Three is searching.
    pub repeat_reads: usize,
    /// Consecutive reads of *different* files before suggesting an index.
    pub read_chain: usize,
    /// Fetches of one URL before suggesting a cache.
    pub repeat_fetches: usize,
    /// A single result this large is worth narrowing.
    pub large_output_bytes: usize,
    /// Never suggest more often than this many observed calls.
    pub min_calls_between: usize,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            repeat_reads: 3,
            read_chain: 5,
            repeat_fetches: 2,
            large_output_bytes: 32_768,
            min_calls_between: 20,
        }
    }
}

/// Which tools count as reading a file.
fn is_read(tool: &str) -> bool {
    matches!(tool, "Read" | "NotebookRead" | "mcp__oc__read")
}

fn is_fetch(tool: &str) -> bool {
    matches!(tool, "WebFetch")
}

/// Examine a session's calls and return at most one thing worth saying.
///
/// `already_said` carries the targets suggested earlier in the session, so the
/// same advice is never repeated — repetition is what teaches an agent to
/// ignore the channel.
pub fn inspect(
    records: &[CallRecord],
    already_said: &[String],
    t: &Thresholds,
) -> Option<Suggestion> {
    if records.is_empty() {
        return None;
    }

    // Rate limit: quiet unless enough has happened since the last suggestion.
    let since = records
        .len()
        .saturating_sub(last_suggestion_index(records, already_said));
    if !already_said.is_empty() && since < t.min_calls_between {
        return None;
    }

    let said = |target: &str| already_said.iter().any(|s| s == target);

    // Ordered by how much each pattern actually cost in the measured data.
    repeated_read(records, t, &said)
        .or_else(|| oversized_output(records, t, &said))
        .or_else(|| repeated_fetch(records, t, &said))
        .or_else(|| read_chain(records, t, &said))
}

/// Approximate position of the last suggestion, for rate limiting.
fn last_suggestion_index(records: &[CallRecord], already_said: &[String]) -> usize {
    if already_said.is_empty() {
        return 0;
    }
    records
        .iter()
        .rposition(|r| {
            r.target
                .as_deref()
                .is_some_and(|t| already_said.iter().any(|s| s == t))
        })
        .unwrap_or(0)
}

/// The 818-re-reads pattern: the same file, again.
fn repeated_read(
    records: &[CallRecord],
    t: &Thresholds,
    said: &impl Fn(&str) -> bool,
) -> Option<Suggestion> {
    let mut counts: BTreeMap<&str, (usize, usize)> = BTreeMap::new();
    for r in records.iter().filter(|r| is_read(&r.tool)) {
        if let Some(target) = r.target.as_deref() {
            let e = counts.entry(target).or_insert((0, 0));
            e.0 += 1;
            e.1 += r.delivered_bytes;
        }
    }

    // Worst offender first: one file read ten times matters more than three
    // read three times.
    let (target, (n, bytes)) = counts
        .into_iter()
        .filter(|(target, (n, _))| *n >= t.repeat_reads && !said(target))
        .max_by_key(|(_, (n, bytes))| (*n, *bytes))?;

    Some(Suggestion {
        pattern: "repeated-read".into(),
        target: target.to_string(),
        wasted_bytes: bytes.saturating_sub(bytes / n.max(1)),
        message: format!(
            "`{target}` has been read {n} times this session ({} KB). \
             If you are looking for one definition, `pk run sym` returns just \
             its span instead of the whole file.",
            bytes / 1000
        ),
    })
}

/// One result large enough to be worth narrowing.
fn oversized_output(
    records: &[CallRecord],
    t: &Thresholds,
    said: &impl Fn(&str) -> bool,
) -> Option<Suggestion> {
    let r = records
        .iter()
        .filter(|r| r.delivered_bytes >= t.large_output_bytes)
        .filter(|r| r.target.as_deref().is_some_and(|x| !said(x)))
        .max_by_key(|r| r.delivered_bytes)?;

    let target = r.target.clone()?;
    Some(Suggestion {
        pattern: "oversized-output".into(),
        target: target.clone(),
        wasted_bytes: r.delivered_bytes,
        message: format!(
            "`{}` on `{target}` returned {} KB in one call. Narrowing the \
             request keeps the rest of the context available for the work.",
            r.tool,
            r.delivered_bytes / 1000
        ),
    })
}

/// The 3,214 `web → web` pairs: the same URL, twice.
fn repeated_fetch(
    records: &[CallRecord],
    t: &Thresholds,
    said: &impl Fn(&str) -> bool,
) -> Option<Suggestion> {
    let mut counts: BTreeMap<&str, (usize, usize)> = BTreeMap::new();
    for r in records.iter().filter(|r| is_fetch(&r.tool)) {
        if let Some(target) = r.target.as_deref() {
            let e = counts.entry(target).or_insert((0, 0));
            e.0 += 1;
            e.1 += r.delivered_bytes;
        }
    }

    let (target, (n, bytes)) = counts
        .into_iter()
        .filter(|(target, (n, _))| *n >= t.repeat_fetches && !said(target))
        .max_by_key(|(_, (n, bytes))| (*n, *bytes))?;

    Some(Suggestion {
        pattern: "repeated-fetch".into(),
        target: target.to_string(),
        wasted_bytes: bytes.saturating_sub(bytes / n.max(1)),
        message: format!("`{target}` has been fetched {n} times. The earlier result is above."),
    })
}

/// The 10,013-pair pattern: reading file after file, which is searching.
fn read_chain(
    records: &[CallRecord],
    t: &Thresholds,
    said: &impl Fn(&str) -> bool,
) -> Option<Suggestion> {
    let mut run = 0usize;
    let mut bytes = 0usize;
    for r in records.iter().rev() {
        if !is_read(&r.tool) {
            break;
        }
        run += 1;
        bytes += r.delivered_bytes;
    }
    if run < t.read_chain || said("read-chain") {
        return None;
    }

    Some(Suggestion {
        pattern: "read-chain".into(),
        target: "read-chain".into(),
        wasted_bytes: bytes,
        message: format!(
            "{run} files read in a row ({} KB). If you are searching for \
             something rather than reading these files, a symbol lookup \
             answers in one call.",
            bytes / 1000
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::{Outcome, Surface};

    fn rec(tool: &str, target: &str, bytes: usize) -> CallRecord {
        CallRecord {
            tool: tool.into(),
            session: "s".into(),
            target: Some(target.into()),
            surface: Surface::Agent,
            outcome: Outcome::Ok,
            at: "2026-09-09T00:00:00Z".into(),
            duration_ms: 1.0,
            input_bytes: 20,
            produced_bytes: bytes,
            delivered_bytes: bytes,
            elisions: 0,
        }
    }

    fn t() -> Thresholds {
        Thresholds::default()
    }

    #[test]
    fn silence_when_nothing_is_wrong() {
        let rs = vec![rec("Read", "a.rs", 500), rec("Edit", "a.rs", 20)];
        assert!(inspect(&rs, &[], &t()).is_none());
    }

    #[test]
    fn two_reads_of_a_file_are_not_worth_mentioning() {
        // Re-reading after an edit is legitimate.
        let rs = vec![
            rec("Read", "a.rs", 500),
            rec("Edit", "a.rs", 20),
            rec("Read", "a.rs", 500),
        ];
        assert!(inspect(&rs, &[], &t()).is_none());
    }

    #[test]
    fn a_third_read_of_the_same_file_is() {
        let rs = vec![rec("Read", "a.rs", 4000); 3];
        let s = inspect(&rs, &[], &t()).expect("should fire");
        assert_eq!(s.pattern, "repeated-read");
        assert_eq!(s.target, "a.rs");
        assert!(
            s.message.contains("pk run sym"),
            "must name a concrete call: {}",
            s.message
        );
    }

    #[test]
    fn the_worst_offender_is_reported_not_the_first() {
        let mut rs = vec![rec("Read", "small.rs", 100); 3];
        rs.extend(vec![rec("Read", "huge.rs", 40_000); 8]);
        // `huge.rs` also trips the oversized rule, so check the ordering holds
        // on the repeated-read pattern specifically.
        let s = inspect(&rs, &[], &t()).unwrap();
        assert_eq!(s.target, "huge.rs");
    }

    #[test]
    fn the_same_advice_is_never_given_twice() {
        // Repetition is what teaches an agent to ignore the channel.
        let rs = vec![rec("Read", "a.rs", 4000); 5];
        assert!(inspect(&rs, &["a.rs".to_string()], &t()).is_none());
    }

    #[test]
    fn suggestions_are_rate_limited_after_the_first() {
        let mut rs = vec![rec("Read", "a.rs", 4000); 3];
        rs.extend(vec![rec("Read", "b.rs", 4000); 3]);
        // `a.rs` was already mentioned and only a few calls have passed since.
        assert!(inspect(&rs, &["a.rs".to_string()], &t()).is_none());
    }

    #[test]
    fn a_long_chain_of_distinct_reads_suggests_an_index() {
        let rs: Vec<_> = (0..6)
            .map(|i| rec("Read", &format!("f{i}.rs"), 3000))
            .collect();
        let s = inspect(&rs, &[], &t()).unwrap();
        assert_eq!(s.pattern, "read-chain");
    }

    #[test]
    fn a_chain_broken_by_other_work_does_not_fire() {
        let mut rs: Vec<_> = (0..6)
            .map(|i| rec("Read", &format!("f{i}.rs"), 3000))
            .collect();
        rs.push(rec("Edit", "f0.rs", 20));
        assert!(inspect(&rs, &[], &t()).is_none());
    }

    #[test]
    fn one_very_large_result_is_worth_narrowing() {
        let rs = vec![rec("Bash", "grep -rn x .", 200_000)];
        let s = inspect(&rs, &[], &t()).unwrap();
        assert_eq!(s.pattern, "oversized-output");
        assert!(s.message.contains("200 KB"), "{}", s.message);
    }

    #[test]
    fn refetching_a_url_points_at_the_earlier_answer() {
        let rs = vec![rec("WebFetch", "https://x.dev/a", 9000); 2];
        let s = inspect(&rs, &[], &t()).unwrap();
        assert_eq!(s.pattern, "repeated-fetch");
    }
}
