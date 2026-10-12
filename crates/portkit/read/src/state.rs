//! What the caller already has.
//!
//! Two things make this harder than a cache. The claim is about *the caller's
//! context*, not about a stored value, so it can be falsified by something
//! this process never sees — a file edit, or a context compaction. And the
//! ranges an agent asks for do not repeat exactly: measured over 397 recorded
//! `sed -n` calls, keying on the exact `(path, start, end)` tuple found **zero**
//! repeats, while keying on line coverage found 53 overlapping pairs and a
//! 4.9% saving. So deliveries are tracked as merged line intervals, never as
//! the ranges that produced them.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

/// A closed line interval, 1-based.
pub type Interval = (u32, u32);

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FileState {
    /// Content hash when these lines were delivered. A different hash means
    /// everything recorded here describes a file that no longer exists.
    pub hash: String,
    /// Merged, sorted, non-overlapping.
    pub intervals: Vec<Interval>,
    pub delivered_at: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SessionState {
    pub files: BTreeMap<String, FileState>,
    /// Everything delivered before this is treated as gone.
    ///
    /// Compaction drops old tool results, so "we sent it" stops implying "they
    /// still have it" — and it stops implying that exactly when a re-read
    /// matters most.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compacted_at: Option<String>,
}

impl SessionState {
    pub fn load(path: &Path) -> Self {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_vec(self)?;
        // Write-then-rename: a half-written state file would be read as "we
        // delivered nothing", which is safe, but losing the whole file to a
        // crash mid-write is avoidable.
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, json)?;
        std::fs::rename(tmp, path)
    }

    /// Forget everything delivered before now.
    pub fn mark_compacted(&mut self, now: String) {
        self.compacted_at = Some(now);
    }

    /// Whether a delivery timestamp survives the last compaction.
    fn survives_compaction(&self, delivered_at: &str) -> bool {
        let Some(at) = &self.compacted_at else {
            return true;
        };
        // Compare instants, not strings. RFC3339 sorts lexicographically only
        // at a fixed width, and the fractional part is as short as it can be:
        // ".5Z" sorts after ".51Z", so a delivery just before a compaction in
        // the same second could be taken as surviving it. A stamp that does not
        // parse is treated as gone, which only ever costs a re-send.
        match (parse_instant(delivered_at), parse_instant(at)) {
            (Some(delivered), Some(compacted)) => delivered > compacted,
            _ => false,
        }
    }

    /// Which of `want` the caller still has, given the file's current hash.
    ///
    /// Returns nothing whenever anything is uncertain. Claiming wrongly here
    /// is the one failure mode that is silent: the agent proceeds on stale
    /// content believing it is current.
    pub fn covered(&self, path: &str, want: Interval, current_hash: &str) -> Vec<Interval> {
        let Some(state) = self.files.get(path) else {
            return Vec::new();
        };
        if state.hash != current_hash || !self.survives_compaction(&state.delivered_at) {
            return Vec::new();
        }
        intersect(&state.intervals, want)
    }

    /// Record what was just sent.
    pub fn deliver(&mut self, path: &str, sent: Interval, hash: String, now: String) {
        // `delivered_at` is one stamp for the whole file, so intervals that
        // predate a compaction must go before this delivery refreshes it.
        // Otherwise a range sent after the watermark would carry older ranges
        // across it, and they would be reported UNCHANGED for lines the
        // caller no longer holds.
        let stale = self
            .files
            .get(path)
            .is_some_and(|f| !self.survives_compaction(&f.delivered_at));
        let entry = self.files.entry(path.to_string()).or_default();
        // A changed file invalidates every earlier interval for it.
        if stale || entry.hash != hash {
            entry.intervals.clear();
            entry.hash = hash;
        }
        entry.intervals.push(sent);
        entry.intervals = merge(std::mem::take(&mut entry.intervals));
        entry.delivered_at = now;
    }
}

fn parse_instant(stamp: &str) -> Option<time::OffsetDateTime> {
    time::OffsetDateTime::parse(stamp, &time::format_description::well_known::Rfc3339).ok()
}

/// Merge overlapping and touching intervals.
pub fn merge(mut v: Vec<Interval>) -> Vec<Interval> {
    if v.is_empty() {
        return v;
    }
    v.sort_unstable();
    let mut out = vec![v[0]];
    for (a, b) in v.into_iter().skip(1) {
        let last = out.last_mut().expect("non-empty");
        // `a <= last.1 + 1` so adjacent intervals join: lines 1-10 and 11-20
        // are one delivery of 1-20.
        if a <= last.1.saturating_add(1) {
            last.1 = last.1.max(b);
        } else {
            out.push((a, b));
        }
    }
    out
}

/// The parts of `want` present in `have`.
pub fn intersect(have: &[Interval], want: Interval) -> Vec<Interval> {
    have.iter()
        .filter_map(|&(a, b)| {
            let lo = a.max(want.0);
            let hi = b.min(want.1);
            (lo <= hi).then_some((lo, hi))
        })
        .collect()
}

/// The parts of `want` NOT in `have` — what still has to be sent.
pub fn gaps(have: &[Interval], want: Interval) -> Vec<Interval> {
    let mut out = Vec::new();
    let mut cursor = want.0;
    for (a, b) in intersect(have, want) {
        if cursor < a {
            out.push((cursor, a - 1));
        }
        cursor = cursor.max(b.saturating_add(1));
    }
    if cursor <= want.1 {
        out.push((cursor, want.1));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adjacent_intervals_merge_into_one() {
        assert_eq!(merge(vec![(1, 10), (11, 20)]), vec![(1, 20)]);
    }

    #[test]
    fn separated_intervals_stay_separate() {
        assert_eq!(merge(vec![(1, 10), (20, 30)]), vec![(1, 10), (20, 30)]);
    }

    #[test]
    fn overlapping_intervals_merge() {
        assert_eq!(merge(vec![(1, 20), (10, 30), (5, 8)]), vec![(1, 30)]);
    }

    #[test]
    fn gaps_are_what_still_has_to_be_sent() {
        // The measured case: asked 40-80, then 60-100. Only 81-100 is new.
        assert_eq!(gaps(&[(40, 80)], (60, 100)), vec![(81, 100)]);
    }

    #[test]
    fn a_fully_held_range_has_no_gaps() {
        assert!(gaps(&[(1, 100)], (40, 80)).is_empty());
    }

    #[test]
    fn a_hole_in_the_middle_is_found() {
        assert_eq!(gaps(&[(1, 20), (40, 60)], (1, 60)), vec![(21, 39)]);
    }

    #[test]
    fn a_changed_file_invalidates_every_earlier_interval() {
        let mut s = SessionState::default();
        s.deliver(
            "a.rs",
            (1, 50),
            "hash-a".into(),
            "2026-01-01T00:00:00Z".into(),
        );
        assert_eq!(s.covered("a.rs", (1, 50), "hash-a").len(), 1);
        // Same lines, different content: nothing the caller holds is current.
        assert!(s.covered("a.rs", (1, 50), "hash-b").is_empty());
    }

    #[test]
    fn compaction_invalidates_earlier_deliveries() {
        // "We sent it" stops implying "they still have it".
        let mut s = SessionState::default();
        s.deliver("a.rs", (1, 50), "h".into(), "2026-01-01T00:00:00Z".into());
        s.mark_compacted("2026-01-02T00:00:00Z".into());
        assert!(s.covered("a.rs", (1, 50), "h").is_empty());
    }

    #[test]
    fn a_delivery_after_compaction_still_counts() {
        let mut s = SessionState::default();
        s.mark_compacted("2026-01-01T00:00:00Z".into());
        s.deliver("a.rs", (1, 50), "h".into(), "2026-01-02T00:00:00Z".into());
        assert_eq!(s.covered("a.rs", (1, 50), "h").len(), 1);
    }

    #[test]
    fn a_delivery_after_compaction_drops_ranges_from_before_it() {
        let mut s = SessionState::default();
        s.deliver("a.rs", (1, 10), "h".into(), "2026-01-01T00:00:00Z".into());
        s.mark_compacted("2026-01-02T00:00:00Z".into());
        s.deliver("a.rs", (20, 30), "h".into(), "2026-01-03T00:00:00Z".into());
        assert!(s.covered("a.rs", (1, 10), "h").is_empty());
        assert_eq!(s.covered("a.rs", (20, 30), "h"), vec![(20, 30)]);
    }

    #[test]
    fn timestamps_compare_as_instants_not_strings() {
        // As strings ".5Z" > ".51Z", which would let a delivery at .5s
        // survive a compaction at .51s in the same second.
        let mut s = SessionState::default();
        s.deliver("a.rs", (1, 5), "h".into(), "2026-01-01T00:00:00.5Z".into());
        s.mark_compacted("2026-01-01T00:00:00.51Z".into());
        assert!(s.covered("a.rs", (1, 5), "h").is_empty());

        // And the other way round, a whole-second stamp against a fractional one.
        let mut t = SessionState::default();
        t.mark_compacted("2026-01-01T00:00:00Z".into());
        t.deliver("a.rs", (1, 5), "h".into(), "2026-01-01T00:00:00.5Z".into());
        assert_eq!(t.covered("a.rs", (1, 5), "h"), vec![(1, 5)]);
    }

    #[test]
    fn an_unparseable_stamp_is_treated_as_gone() {
        let mut s = SessionState::default();
        s.deliver("a.rs", (1, 5), "h".into(), "not a time".into());
        s.mark_compacted("2026-01-01T00:00:00Z".into());
        assert!(s.covered("a.rs", (1, 5), "h").is_empty());
    }

    #[test]
    fn an_unknown_file_is_never_claimed_as_held() {
        let s = SessionState::default();
        assert!(s.covered("never-seen.rs", (1, 10), "h").is_empty());
    }
}
