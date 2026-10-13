//! `cowproof report rollup <lanes-root>...`: how each starting rung does, per packet
//! class, over every lane in the given lanes roots (D23, D28 clause 4).
//!
//! The data is what a lane already leaves behind and nothing else: `control/run.json`
//! (per segment `runtime`, `model`, turns and cost; top level `runtime`, `model`,
//! `startRung`, `rungSource`, `classSlot.class`, `host`, `unsandboxed`, `status`) and
//! `control/verdict.json` (`verdict`). Nothing in a lane is read but those two files, and
//! nothing is followed out of the root: a symlink for a lane, for its `control`
//! directory, or for either file is skipped and counted.
//!
//! Definitions, so the numbers can be argued with:
//!
//! - The **start rung** is the first segment's `runtime:model`, the **final rung** is the
//!   top-level `runtime:model` (the last launch). A lane before D28 step 1 has no
//!   `runtime` and counts as `claude:<model>`.
//! - A **reassign** is a segment on a different rung than the segment before it. A
//!   resume or a redirect keeps the rung, so it is not one.
//! - A lane is **proved** when its verdict is `proved`, or, with `include_unsandboxed`,
//!   `finished` for an unsandboxed lane (it passed what a sandboxed lane is proved by,
//!   and `finished` is the most such a lane can be).
//! - A lane is a **first-try pass** when it is proved, has zero reassigns, and its first
//!   rung equals its final rung.
//! - A lane that ended without a verdict (`timeout`, `cost-cap`, `failed`, `stopped`,
//!   `escalation-limit`) is counted, not proved. A lane with no verdict that has not ended
//!   yet is `running`, and is in no rate.

use anyhow::{Result, bail};
use serde::Serialize;
use serde_json::Value;
use std::cell::Cell;
use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

/// The widest line `render` prints.
const WIDTH: usize = 80;
/// A `run.json` or `verdict.json` larger than this is malformed (the real ones are KBs).
const MAX_FILE_BYTES: u64 = 32 * 1024 * 1024;
/// The longest label from a lane's files that is shown, in characters.
const MAX_LABEL: usize = 64;

#[derive(Debug, Clone, Copy, Default)]
pub struct Options {
    /// Count unsandboxed lanes in the rates (default: leave them out), and count a
    /// `finished` verdict from one as proved.
    pub include_unsandboxed: bool,
}

/// What the rollup found. Serializes (camelCase) as the `--json` document.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Rollup {
    pub include_unsandboxed: bool,
    pub roots: usize,
    pub counts: Counts,
    pub groups: Vec<Group>,
    pub climbed: Vec<Climbed>,
    /// Context bytes delivered per proved traced lane, by start rung (D23).
    pub delivered: Vec<Delivered>,
    pub lanes: Vec<LaneRow>,
}

/// Every directory entry examined lands in exactly one of `counted`, `running`,
/// `never_started`, `unreadable`, `malformed`, `symlinked` and `excluded_unsandboxed`.
#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Counts {
    pub seen: usize,
    pub counted: usize,
    pub running: usize,
    pub never_started: usize,
    pub unreadable: usize,
    pub malformed: usize,
    pub symlinked: usize,
    pub excluded_unsandboxed: usize,
    /// Among the counted lanes: from before D28 step 1.
    pub legacy: usize,
    /// Among the counted lanes: ran on a remote host.
    pub remote: usize,
    /// Among the counted lanes: whether any cost is the runner's estimate.
    pub cost_is_estimate: bool,
    /// Among the counted lanes: where the starting rung came from, by `rungSource`.
    pub rung_sources: BTreeMap<String, usize>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Group {
    pub start_rung: String,
    pub class: String,
    pub lanes: usize,
    pub first_try_passed: usize,
    pub first_try_rate: f64,
    pub proved: usize,
    pub proved_rate: f64,
    /// Lanes whose cost is known; the median and the total are over these.
    pub costed_lanes: usize,
    pub median_cost_usd: Option<f64>,
    pub total_cost_usd: f64,
    /// The group's total cost over its proved lanes; none when none was proved.
    pub cost_per_proved_usd: Option<f64>,
    pub median_turns: Option<f64>,
    pub mean_reassigns: f64,
    /// Whether any lane of the group is from before D28 step 1.
    pub legacy: bool,
}

/// Of the lanes that started on a rung, where they ended.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Climbed {
    pub start_rung: String,
    pub lanes: usize,
    /// Lanes whose final rung is not the start rung.
    pub climbed: usize,
    pub ended_on: BTreeMap<String, usize>,
}

/// The usage monitor's figure for the lanes that started on a rung: of the proved lanes whose
/// `run.json` carries `traceTotals` (traced Claude lanes), the mean `deliveredBytes`, the
/// bytes that reached the builder's context. Untraced proved lanes are not in it.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Delivered {
    pub start_rung: String,
    /// Proved lanes of the rung, traced or not.
    pub proved_lanes: usize,
    /// Of those, the lanes with trace totals: the mean is over these.
    pub traced_proved_lanes: usize,
    pub mean_delivered_bytes: Option<f64>,
}

/// One lane that was read (not running, not skipped).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LaneRow {
    pub id: String,
    pub root: String,
    /// `counted`, or `excludedUnsandboxed`.
    pub state: &'static str,
    pub first_rung: String,
    pub final_rung: String,
    pub class: String,
    /// The verdict (`proved`, `refuted`, ...), or `run.json`'s status when there is none.
    pub outcome: String,
    pub proved: bool,
    pub first_try: bool,
    pub cost_usd: Option<f64>,
    pub cost_is_estimate: bool,
    pub turns: Option<u64>,
    /// `traceTotals.deliveredBytes` of `run.json`, for a traced lane.
    pub delivered_bytes: Option<u64>,
    pub reassigns: usize,
    pub rung_source: Option<String>,
    pub remote: bool,
    pub host: Option<String>,
    pub unsandboxed: bool,
    /// From before D28 step 1: no `runtime`, so `claude` was assumed.
    pub legacy: bool,
}

impl Rollup {
    /// The `--json` document.
    pub fn to_json(&self) -> Value {
        serde_json::to_value(self).expect("a rollup is plain data")
    }
}

/// Roll up every lane one level under each of `roots`.
pub fn rollup(roots: &[PathBuf], options: &Options) -> Result<Rollup> {
    let mut counts = Counts::default();
    let mut rows: Vec<LaneRow> = Vec::new();
    for root in roots {
        match fs::metadata(root) {
            Ok(m) if m.is_dir() => {}
            Ok(_) => bail!("lanes root {} is not a directory", root.display()),
            Err(e) => bail!("lanes root {}: {e}", root.display()),
        }
        let mut entries: Vec<_> = fs::read_dir(root)?.collect::<std::io::Result<_>>()?;
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            // `DirEntry::file_type` does not follow a symlink.
            let kind = entry.file_type()?;
            if kind.is_symlink() {
                counts.seen += 1;
                counts.symlinked += 1;
                continue;
            }
            if !kind.is_dir() {
                continue;
            }
            counts.seen += 1;
            let id = sanitize(&entry.file_name().to_string_lossy());
            match read_lane(&entry.path(), &id, root, options) {
                Found::Row(row) => rows.push(*row),
                Found::Running => counts.running += 1,
                Found::NeverStarted => counts.never_started += 1,
                Found::Unreadable => counts.unreadable += 1,
                Found::Malformed => counts.malformed += 1,
                Found::Symlinked => counts.symlinked += 1,
            }
        }
    }

    let mut buckets: BTreeMap<(String, String), Vec<&LaneRow>> = BTreeMap::new();
    for row in &rows {
        if row.state == "excludedUnsandboxed" {
            counts.excluded_unsandboxed += 1;
            continue;
        }
        counts.counted += 1;
        counts.legacy += usize::from(row.legacy);
        counts.remote += usize::from(row.remote);
        counts.cost_is_estimate |= row.cost_is_estimate && row.cost_usd.is_some();
        let source = row.rung_source.clone().unwrap_or_else(|| "unknown".into());
        *counts.rung_sources.entry(source).or_default() += 1;
        buckets
            .entry((row.first_rung.clone(), row.class.clone()))
            .or_default()
            .push(row);
    }

    let groups: Vec<Group> = buckets
        .iter()
        .map(|((rung, class), lanes)| group(rung, class, lanes))
        .collect();

    let mut by_start: BTreeMap<&str, Climbed> = BTreeMap::new();
    for row in rows.iter().filter(|r| r.state == "counted") {
        let c = by_start
            .entry(row.first_rung.as_str())
            .or_insert_with(|| Climbed {
                start_rung: row.first_rung.clone(),
                lanes: 0,
                climbed: 0,
                ended_on: BTreeMap::new(),
            });
        c.lanes += 1;
        c.climbed += usize::from(row.final_rung != row.first_rung);
        *c.ended_on.entry(row.final_rung.clone()).or_default() += 1;
    }

    let mut delivered: BTreeMap<&str, (usize, Vec<u64>)> = BTreeMap::new();
    for row in rows.iter().filter(|r| r.state == "counted" && r.proved) {
        let entry = delivered.entry(row.first_rung.as_str()).or_default();
        entry.0 += 1;
        entry.1.extend(row.delivered_bytes);
    }
    let delivered: Vec<Delivered> = delivered
        .into_iter()
        .map(|(rung, (proved, bytes))| Delivered {
            start_rung: rung.to_string(),
            proved_lanes: proved,
            traced_proved_lanes: bytes.len(),
            mean_delivered_bytes: (!bytes.is_empty())
                .then(|| bytes.iter().sum::<u64>() as f64 / bytes.len() as f64),
        })
        .collect();

    Ok(Rollup {
        include_unsandboxed: options.include_unsandboxed,
        roots: roots.len(),
        counts,
        groups,
        climbed: by_start.into_values().collect(),
        delivered,
        lanes: rows,
    })
}

fn group(rung: &str, class: &str, lanes: &[&LaneRow]) -> Group {
    let n = lanes.len();
    let first_try_passed = lanes.iter().filter(|l| l.first_try).count();
    let proved = lanes.iter().filter(|l| l.proved).count();
    let costs: Vec<f64> = lanes.iter().filter_map(|l| l.cost_usd).collect();
    let total: f64 = costs.iter().sum();
    let turns: Vec<f64> = lanes
        .iter()
        .filter_map(|l| l.turns)
        .map(|t| t as f64)
        .collect();
    let reassigns: usize = lanes.iter().map(|l| l.reassigns).sum();
    Group {
        start_rung: rung.to_string(),
        class: class.to_string(),
        lanes: n,
        first_try_passed,
        first_try_rate: first_try_passed as f64 / n as f64,
        proved,
        proved_rate: proved as f64 / n as f64,
        costed_lanes: costs.len(),
        median_cost_usd: median(costs),
        total_cost_usd: total,
        cost_per_proved_usd: (proved > 0).then(|| total / proved as f64),
        median_turns: median(turns),
        mean_reassigns: reassigns as f64 / n as f64,
        legacy: lanes.iter().any(|l| l.legacy),
    }
}

pub(crate) fn median(mut values: Vec<f64>) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    values.sort_by(|a, b| a.total_cmp(b));
    let mid = values.len() / 2;
    Some(if values.len() % 2 == 1 {
        values[mid]
    } else {
        (values[mid - 1] + values[mid]) / 2.0
    })
}

// ---- reading one lane ----

enum Found {
    Row(Box<LaneRow>),
    Running,
    NeverStarted,
    Unreadable,
    Malformed,
    Symlinked,
}

/// One of the two files, read without following a link.
enum Slot {
    Absent,
    Linked,
    Unreadable,
    Malformed,
    Json(serde_json::Map<String, Value>),
}

fn read_file(path: &Path) -> Slot {
    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Slot::Absent,
        Err(_) => return Slot::Unreadable,
    };
    if meta.file_type().is_symlink() {
        return Slot::Linked;
    }
    if !meta.is_file() {
        return Slot::Unreadable;
    }
    if meta.len() > MAX_FILE_BYTES {
        return Slot::Malformed;
    }
    let mut text = String::new();
    // Bound the read as well as the stat: the file can grow between the two.
    let read =
        fs::File::open(path).and_then(|f| f.take(MAX_FILE_BYTES + 1).read_to_string(&mut text));
    if read.is_err() {
        // Not UTF-8 is malformed content; anything else is a file we cannot read.
        return if fs::read(path).is_ok() {
            Slot::Malformed
        } else {
            Slot::Unreadable
        };
    }
    if text.len() as u64 > MAX_FILE_BYTES {
        return Slot::Malformed;
    }
    match serde_json::from_str::<Value>(&text) {
        Ok(Value::Object(map)) => Slot::Json(map),
        _ => Slot::Malformed,
    }
}

fn read_lane(dir: &Path, id: &str, root: &Path, options: &Options) -> Found {
    let control = dir.join("control");
    match fs::symlink_metadata(&control) {
        Ok(m) if m.file_type().is_symlink() => return Found::Symlinked,
        Ok(m) if m.is_dir() => {}
        _ => return Found::Unreadable,
    }
    let run = read_file(&control.join("run.json"));
    let verdict = read_file(&control.join("verdict.json"));
    if matches!(run, Slot::Linked) || matches!(verdict, Slot::Linked) {
        return Found::Symlinked;
    }
    if matches!(run, Slot::Malformed) || matches!(verdict, Slot::Malformed) {
        return Found::Malformed;
    }
    if matches!(run, Slot::Unreadable) || matches!(verdict, Slot::Unreadable) {
        return Found::Unreadable;
    }
    let run = match (run, &verdict) {
        (Slot::Json(run), _) => run,
        // The runner writes `run.json` when the builder exits, so a lane whose builder is
        // still going has neither file (`cowproof watch` calls that `running` too). A
        // control directory with nothing in it never held a lane.
        (_, Slot::Absent) => {
            let started = fs::read_dir(&control).is_ok_and(|mut d| d.next().is_some());
            return if started {
                Found::Running
            } else {
                Found::Unreadable
            };
        }
        // A verdict with no run.json says nothing about the rung.
        _ => return Found::Unreadable,
    };
    let verdict = match verdict {
        Slot::Json(v) => match v.get("verdict").and_then(Value::as_str) {
            Some(name) => Some((name.to_string(), v)),
            None => return Found::Malformed,
        },
        _ => None,
    };
    let status = str_of(&run, "status");
    // No verdict yet: `finished` is a builder that exited and a proof still running; any
    // other status is a lane that ended without being proved.
    if verdict.is_none() && matches!(status.as_deref(), None | Some("finished")) {
        return Found::Running;
    }
    let outcome = match &verdict {
        Some((name, _)) => sanitize(name),
        None => status.clone().unwrap_or_default(),
    };

    let rungs = rungs_of(&run);
    let Some(rungs) = rungs else {
        return if verdict.is_none() {
            Found::NeverStarted
        } else {
            // Proved or refuted, but nothing says by whom: it cannot be placed.
            Found::Unreadable
        };
    };

    let unsandboxed = bool_of(&run, "unsandboxed")
        || verdict
            .as_ref()
            .is_some_and(|(_, v)| bool_of(v, "unsandboxed"));
    let proved = outcome == "proved"
        || (options.include_unsandboxed && unsandboxed && outcome == "finished");
    let first_try = proved && rungs.reassigns == 0 && rungs.first == rungs.last;
    let (cost_usd, cost_is_estimate) = cost_of(&run);
    let host = str_of(&run, "host").filter(|h| !h.is_empty());
    Found::Row(Box::new(LaneRow {
        id: id.to_string(),
        root: root.display().to_string(),
        state: if unsandboxed && !options.include_unsandboxed {
            "excludedUnsandboxed"
        } else {
            "counted"
        },
        first_rung: rungs.first.clone(),
        final_rung: rungs.last.clone(),
        class: class_of(&run),
        outcome,
        proved,
        first_try,
        cost_usd,
        cost_is_estimate,
        turns: turns_of(&run),
        delivered_bytes: run
            .get("traceTotals")
            .and_then(|t| t.get("deliveredBytes"))
            .and_then(Value::as_u64),
        reassigns: rungs.reassigns,
        rung_source: str_of(&run, "rungSource"),
        remote: host.is_some(),
        host,
        unsandboxed,
        legacy: rungs.legacy,
    }))
}

struct Rungs {
    first: String,
    last: String,
    reassigns: usize,
    legacy: bool,
}

/// The first rung, the final rung and the reassign count, or none when the file names no
/// model anywhere.
fn rungs_of(run: &serde_json::Map<String, Value>) -> Option<Rungs> {
    let legacy = Cell::new(false);
    let rung = |runtime: Option<String>, model: Option<String>| -> Option<String> {
        let model = model?;
        let runtime = runtime.unwrap_or_else(|| {
            legacy.set(true);
            "claude".to_string()
        });
        Some(format!("{runtime}:{model}"))
    };
    let segments: Vec<&serde_json::Map<String, Value>> = run
        .get("segments")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_object).collect())
        .unwrap_or_default();
    let seg_rungs: Vec<String> = segments
        .iter()
        .filter_map(|s| rung(str_of(s, "runtime"), str_of(s, "model")))
        .collect();
    let top = rung(str_of(run, "runtime"), str_of(run, "model"));
    let start_rung = str_of(run, "startRung").map(|s| {
        // "runtime:model"; a bare model is a pre-D28 `claude` rung.
        if s.contains(':') {
            s
        } else {
            legacy.set(true);
            format!("claude:{s}")
        }
    });
    let first = seg_rungs
        .first()
        .cloned()
        .or(start_rung)
        .or_else(|| top.clone())?;
    let last = top
        .or_else(|| seg_rungs.last().cloned())
        .unwrap_or_else(|| first.clone());
    let reassigns = seg_rungs.windows(2).filter(|w| w[0] != w[1]).count();
    Some(Rungs {
        first,
        last,
        reassigns,
        legacy: legacy.get(),
    })
}

fn class_of(run: &serde_json::Map<String, Value>) -> String {
    run.get("classSlot")
        .and_then(|c| c.get("class"))
        .and_then(Value::as_str)
        .map(sanitize)
        .or_else(|| str_of(run, "class"))
        .unwrap_or_else(|| "unknown".to_string())
}

/// The lane's total cost and whether it is an estimate (the runner's always is).
fn cost_of(run: &serde_json::Map<String, Value>) -> (Option<f64>, bool) {
    let cost = run
        .get("estimatedCostUsd")
        .and_then(Value::as_f64)
        .or_else(|| {
            let costs: Vec<f64> = run
                .get("segments")?
                .as_array()?
                .iter()
                .filter_map(|s| s.get("estimatedCostUsd")?.as_f64())
                .collect();
            (!costs.is_empty()).then(|| costs.iter().sum())
        })
        .filter(|c| c.is_finite() && *c >= 0.0);
    let estimate = run
        .get("costIsEstimate")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    (cost, estimate)
}

fn turns_of(run: &serde_json::Map<String, Value>) -> Option<u64> {
    run.get("turns").and_then(Value::as_u64).or_else(|| {
        let turns: Vec<u64> = run
            .get("segments")?
            .as_array()?
            .iter()
            .filter_map(|s| s.get("turns")?.as_u64())
            .collect();
        (!turns.is_empty()).then(|| turns.iter().sum())
    })
}

fn str_of(map: &serde_json::Map<String, Value>, key: &str) -> Option<String> {
    map.get(key).and_then(Value::as_str).map(sanitize)
}

fn bool_of(map: &serde_json::Map<String, Value>, key: &str) -> bool {
    map.get(key).and_then(Value::as_bool).unwrap_or(false)
}

/// A label out of a file or a directory name, safe to print: control characters (a
/// terminal escape in a model name) are replaced and the length is bounded.
fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .take(MAX_LABEL)
        .collect()
}

// ---- the plain table ----

impl Rollup {
    /// The plain-text report, at most 80 columns wide.
    pub fn render(&self) -> String {
        let c = &self.counts;
        let mut out = String::new();
        out.push_str(&format!(
            "Lane rollup: {} counted of {} lanes in {} root{}\n",
            c.counted,
            c.seen,
            self.roots,
            if self.roots == 1 { "" } else { "s" }
        ));
        if self.groups.is_empty() {
            out.push_str("\nno lanes to count under the given roots.\n");
        }

        let mut last_rung: Option<&str> = None;
        for g in &self.groups {
            if last_rung != Some(g.start_rung.as_str()) {
                let legacy = self
                    .groups
                    .iter()
                    .any(|o| o.start_rung == g.start_rung && o.legacy);
                out.push_str(&format!(
                    "\n{}{}\n",
                    clip(&g.start_rung, WIDTH - 2),
                    if legacy { " *" } else { "" }
                ));
                out.push_str(&format!(
                    "  {:<12} {:>5} {:>10} {:>10} {:>6} {:>7} {:>7} {:>5} {:>5}\n",
                    "class",
                    "lanes",
                    "1st-try",
                    "proved",
                    "med $",
                    "total $",
                    "$/prov",
                    "turns",
                    "reasg"
                ));
                last_rung = Some(g.start_rung.as_str());
            }
            out.push_str(&format!(
                "  {:<12} {:>5} {:>10} {:>10} {:>6} {:>7} {:>7} {:>5} {:>5.2}\n",
                clip(&g.class, 12),
                g.lanes,
                rate(g.first_try_passed, g.lanes),
                rate(g.proved, g.lanes),
                g.median_cost_usd.map_or("-".into(), money),
                money(g.total_cost_usd),
                g.cost_per_proved_usd.map_or("-".into(), money),
                g.median_turns.map_or("-".into(), number),
                g.mean_reassigns,
            ));
        }

        if !self.climbed.is_empty() {
            out.push_str("\nClimbed to (lanes by the rung they started on)\n");
            for k in &self.climbed {
                out.push_str(&format!(
                    "{}: {} lane{}, {} climbed\n",
                    clip(&k.start_rung, 50),
                    k.lanes,
                    if k.lanes == 1 { "" } else { "s" },
                    k.climbed
                ));
                // The rung it stayed on first, then where the rest ended.
                let stayed = k
                    .ended_on
                    .get(&k.start_rung)
                    .map(|n| (format!("stayed on {}", clip(&k.start_rung, 40)), *n));
                let moved = k
                    .ended_on
                    .iter()
                    .filter(|(rung, _)| **rung != k.start_rung)
                    .map(|(rung, n)| (format!("-> {}", clip(rung, 50)), *n));
                let ends: Vec<(String, usize)> = stayed.into_iter().chain(moved).collect();
                let wide = ends
                    .iter()
                    .map(|(l, _)| l.chars().count())
                    .max()
                    .unwrap_or(0);
                for (label, n) in ends {
                    out.push_str(&format!("  {label:<wide$} {n:>4}\n"));
                }
            }
        }

        if self.delivered.iter().any(|d| d.traced_proved_lanes > 0) {
            out.push_str(
                "\nContext delivered (mean bytes per proved traced lane)\n  \
                 builder-written, informational: the builder can write its trace\n",
            );
            for d in &self.delivered {
                let mean = d
                    .mean_delivered_bytes
                    .map_or("-".to_string(), |m| format!("{m:.0}"));
                out.push_str(&format!(
                    "  {:<36} {:>9} bytes, {} of {} proved traced\n",
                    clip(&d.start_rung, 36),
                    mean,
                    d.traced_proved_lanes,
                    d.proved_lanes
                ));
            }
        }

        let mut notes: Vec<String> = Vec::new();
        notes.push(
            "1st-try is proved with no reassign; proved is proved at all; $/prov is the \
             group's cost over its proved lanes; reasg is the mean reassigns per lane."
                .into(),
        );
        let skipped: Vec<String> = [
            ("running", c.running),
            ("unreadable", c.unreadable),
            ("malformed", c.malformed),
            ("symlink", c.symlinked),
            ("never started", c.never_started),
        ]
        .iter()
        .filter(|(_, n)| *n > 0)
        .map(|(what, n)| format!("{what} {n}"))
        .collect();
        if !skipped.is_empty() {
            notes.push(format!("Left out of every rate: {}.", skipped.join(", ")));
        }
        if c.excluded_unsandboxed > 0 {
            notes.push(format!(
                "{} unsandboxed lane{} left out; --include-unsandboxed counts them \
                 (a finished unsandboxed lane then counts as proved).",
                c.excluded_unsandboxed,
                if c.excluded_unsandboxed == 1 { "" } else { "s" }
            ));
        } else if self.include_unsandboxed && self.lanes.iter().any(|l| l.unsandboxed) {
            notes.push(
                "Unsandboxed lanes are counted; a finished unsandboxed lane counts as proved."
                    .into(),
            );
        }
        if c.legacy > 0 {
            notes.push(format!(
                "* {} from before D28 step 1 (no runtime field) {} as claude:<model>.",
                if c.legacy == 1 {
                    "1 lane".to_string()
                } else {
                    format!("{} lanes", c.legacy)
                },
                if c.legacy == 1 { "counts" } else { "count" }
            ));
        }
        if c.cost_is_estimate {
            notes.push("Cost is the runner's estimate, not a bill.".into());
        }
        if c.remote > 0 {
            notes.push(format!(
                "{} of {} counted lanes ran on a remote host.",
                c.remote, c.counted
            ));
        }
        if !c.rung_sources.is_empty() {
            let sources: Vec<String> = c
                .rung_sources
                .iter()
                .map(|(s, n)| format!("{s} {n}"))
                .collect();
            notes.push(format!("Starting rung came from: {}.", sources.join(", ")));
        }
        out.push('\n');
        for note in notes {
            out.push_str(&wrap(&note, WIDTH));
        }
        out
    }
}

fn rate(n: usize, of: usize) -> String {
    format!("{n}/{of} {:.0}%", 100.0 * n as f64 / of as f64)
}

fn money(v: f64) -> String {
    if v < 10.0 {
        format!("{v:.3}")
    } else if v < 1000.0 {
        format!("{v:.2}")
    } else {
        format!("{v:.0}")
    }
}

fn number(v: f64) -> String {
    if v.fract() == 0.0 {
        format!("{v:.0}")
    } else {
        format!("{v:.1}")
    }
}

/// `s` cut to `width` characters, a `~` marking the cut.
pub(crate) fn clip(s: &str, width: usize) -> String {
    if s.chars().count() <= width {
        return s.to_string();
    }
    let mut cut: String = s.chars().take(width.saturating_sub(1)).collect();
    cut.push('~');
    cut
}

/// `text` wrapped to `width` columns, continuation lines indented two spaces.
pub(crate) fn wrap(text: &str, width: usize) -> String {
    let mut out = String::new();
    let mut line = String::new();
    for word in text.split_whitespace() {
        let word = clip(word, width - 2);
        if !line.is_empty() && line.chars().count() + 1 + word.chars().count() > width {
            out.push_str(&line);
            out.push('\n');
            line = String::from("  ");
            line.push_str(&word);
        } else {
            if !line.is_empty() {
                line.push(' ');
            }
            line.push_str(&word);
        }
    }
    out.push_str(&line);
    out.push('\n');
    out
}
