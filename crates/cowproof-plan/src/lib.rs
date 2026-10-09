#![forbid(unsafe_code)]

use anyhow::{Context, Result, anyhow};
use globset::Glob;
use serde_json::{Map, Value};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub struct Plan {
    pub path: PathBuf,
    pub document: Value,
}

#[derive(Clone, Debug)]
pub struct LaneRef {
    pub plan_path: PathBuf,
    pub plan_name: String,
    pub id: String,
    pub title: String,
    pub status: String,
    pub priority: i64,
    pub host: String,
    pub class: String,
    pub estimate: f64,
    pub migration: Option<i64>,
    pub contract: Option<String>,
    pub deps: Vec<String>,
    pub packet: Option<String>,
    pub decision: Option<String>,
    pub notes: Option<String>,
    pub commit: Option<String>,
    pub release: Option<String>,
}

#[derive(Clone, Debug)]
pub struct Problem {
    pub plan: String,
    pub lane: String,
    pub rule: String,
}

fn object(v: &Value) -> Option<&Map<String, Value>> {
    v.as_object()
}
fn string(v: Option<&Value>) -> Option<&str> {
    v.and_then(Value::as_str)
}
fn num(v: Option<&Value>) -> Option<i64> {
    v.and_then(Value::as_i64)
}
fn nonnull_string(v: Option<&Value>) -> Option<String> {
    string(v).map(str::to_owned)
}
fn get<'a>(v: &'a Value, key: &str) -> Option<&'a Value> {
    v.get(key)
}
fn valid_pattern(s: &str, pattern: &str) -> bool {
    match pattern {
        "plan" => {
            !s.is_empty()
                && s.len() <= 64
                && s.bytes().enumerate().all(|(i, b)| {
                    b.is_ascii_lowercase() || b.is_ascii_digit() || (i > 0 && b == b'-')
                })
        }
        "lane" => {
            !s.is_empty()
                && s.len() <= 80
                && s.bytes().enumerate().all(|(i, b)| {
                    b.is_ascii_lowercase() || b.is_ascii_digit() || (i > 0 && b == b'-')
                })
        }
        _ => true,
    }
}

fn schema_problems(plan: &Plan) -> Vec<Problem> {
    let mut out = Vec::new();
    let file = plan.path.display().to_string();
    let mut add = |lane: &str, rule: String| {
        out.push(Problem {
            plan: file.clone(),
            lane: lane.to_owned(),
            rule,
        })
    };
    let Some(root) = object(&plan.document) else {
        add("<plan>", "schema: expected object".into());
        return out;
    };
    let allowed: HashSet<&str> = [
        "$schema",
        "version",
        "plan",
        "goal",
        "owner",
        "baseline",
        "numbering",
        "stage",
        "lanes",
    ]
    .into_iter()
    .collect();
    for key in root.keys() {
        if !allowed.contains(key.as_str()) {
            add("<plan>", format!("schema: unknown property {key}"));
        }
    }
    if let Some(stage) = root.get("stage")
        && !stage.as_str().is_some_and(valid_stage)
    {
        add(
            "<plan>",
            "schema: stage must be foundation, alpha, beta, ga or later".into(),
        );
    }
    for key in ["version", "plan", "lanes"] {
        if !root.contains_key(key) {
            add("<plan>", format!("schema: missing required property {key}"));
        }
    }
    if get(&plan.document, "version").and_then(Value::as_i64) != Some(1) {
        add("<plan>", "schema: version must be 1".into());
    }
    if let Some(v) = string(get(&plan.document, "plan")) {
        if !valid_pattern(v, "plan") {
            add(
                "<plan>",
                "schema: plan must match ^[a-z0-9][a-z0-9-]{0,63}$".into(),
            );
        }
    } else if root.contains_key("plan") {
        add("<plan>", "schema: plan must be a string".into());
    }
    for (key, max) in [("goal", 500usize), ("owner", usize::MAX)] {
        if let Some(v) = get(&plan.document, key)
            && (!v.is_string() || string(Some(v)).is_some_and(|s| s.chars().count() > max))
        {
            add("<plan>", format!("schema: {key} must be a string"));
        }
    }
    for (key, props) in [
        ("baseline", ["migration", "contract"].as_slice()),
        ("numbering", ["migrationGlob", "contractPrefix"].as_slice()),
    ] {
        if let Some(v) = get(&plan.document, key) {
            if let Some(m) = object(v) {
                for k in m.keys() {
                    if !props.contains(&k.as_str()) {
                        add("<plan>", format!("schema: unknown {key} property {k}"));
                    }
                }
                for (field, typ) in if key == "baseline" {
                    vec![("migration", "integer"), ("contract", "string")]
                } else {
                    vec![("migrationGlob", "string"), ("contractPrefix", "string")]
                } {
                    if let Some(value) = m.get(field) {
                        let okay = if typ == "integer" {
                            value.as_i64().is_some_and(|n| n >= 0)
                        } else {
                            value.is_string()
                        };
                        if !okay {
                            add("<plan>", format!("schema: {key}.{field} must be {typ}"));
                        }
                    }
                }
            } else {
                add("<plan>", format!("schema: {key} must be an object"));
            }
        }
    }
    let Some(lanes) = get(&plan.document, "lanes").and_then(Value::as_array) else {
        if root.contains_key("lanes") {
            add("<plan>", "schema: lanes must be an array".into());
        }
        return out;
    };
    for lane in lanes {
        let id = string(get(lane, "id")).unwrap_or("<unknown>").to_owned();
        let mut lane_add = |s: String| {
            out.push(Problem {
                plan: file.clone(),
                lane: id.clone(),
                rule: s,
            })
        };
        let Some(lane_obj) = object(lane) else {
            lane_add("schema: lane must be an object".into());
            continue;
        };
        let lane_allowed: HashSet<&str> = [
            "id",
            "title",
            "area",
            "packet",
            "priority",
            "status",
            "dependsOn",
            "class",
            "host",
            "estimateHours",
            "reserves",
            "decision",
            "notes",
            "commit",
            "release",
            "stage",
        ]
        .into_iter()
        .collect();
        for key in lane_obj.keys() {
            if !lane_allowed.contains(key.as_str()) {
                lane_add(format!("schema: unknown lane property {key}"));
            }
        }
        if let Some(stage) = lane_obj.get("stage")
            && !stage.as_str().is_some_and(valid_stage)
        {
            lane_add("schema: stage must be foundation, alpha, beta, ga or later".into());
        }
        for key in ["id", "title", "priority", "status"] {
            if !lane_obj.contains_key(key) {
                lane_add(format!("schema: missing required property {key}"));
            }
        }
        if let Some(s) = string(get(lane, "id")) {
            if !valid_pattern(s, "lane") {
                lane_add("schema: id must match ^[a-z0-9][a-z0-9-]{0,79}$".into());
            }
        } else if lane_obj.contains_key("id") {
            lane_add("schema: id must be a string".into());
        }
        for (key, max) in [
            ("title", 200usize),
            ("area", usize::MAX),
            ("host", usize::MAX),
            ("decision", usize::MAX),
            ("notes", 2000usize),
        ] {
            if let Some(v) = get(lane, key)
                && (!v.is_string() || string(Some(v)).is_some_and(|s| s.chars().count() > max))
            {
                lane_add(format!(
                    "schema: {key} must be a string within its length limit"
                ));
            }
        }
        if let Some(v) = get(lane, "packet")
            && !(v.is_string() || v.is_null())
        {
            lane_add("schema: packet must be a string or null".into());
        }
        if let Some(v) = get(lane, "priority").and_then(Value::as_i64) {
            if !(1..=9).contains(&v) {
                lane_add("schema: priority must be between 1 and 9".into());
            }
        } else if lane_obj.contains_key("priority") {
            lane_add("schema: priority must be an integer".into());
        }
        if let Some(s) = string(get(lane, "status")) {
            if ![
                "idea", "planned", "packet", "running", "review", "held", "applied", "shipped",
                "dropped",
            ]
            .contains(&s)
            {
                lane_add(format!("schema: invalid status {s}"));
            }
        } else if lane_obj.contains_key("status") {
            lane_add("schema: status must be a string".into());
        }
        if let Some(v) = get(lane, "dependsOn") {
            if let Some(a) = v.as_array() {
                let mut seen = HashSet::new();
                for d in a {
                    if !d.is_string() {
                        lane_add("schema: dependsOn entries must be strings".into());
                    } else if !seen.insert(d.as_str().unwrap_or_default()) {
                        lane_add("schema: dependsOn entries must be unique".into());
                    }
                }
            } else {
                lane_add("schema: dependsOn must be an array".into());
            }
        }
        if let Some(s) = string(get(lane, "class")) {
            if !["light", "crate", "pg", "rust"].contains(&s) {
                lane_add(format!("schema: invalid class {s}"));
            }
        } else if lane_obj.contains_key("class") {
            lane_add("schema: class must be a valid string".into());
        }
        if let Some(v) = get(lane, "estimateHours")
            && !v.as_f64().is_some_and(|n| n >= 0.0)
        {
            lane_add("schema: estimateHours must be a non-negative number".into());
        }
        for key in ["commit", "release"] {
            if let Some(v) = get(lane, key)
                && !(v.is_string() || v.is_null())
            {
                lane_add(format!("schema: {key} must be a string or null"));
            }
        }
        if let Some(v) = get(lane, "reserves") {
            if let Some(m) = object(v) {
                for k in m.keys() {
                    if !["migration", "contract"].contains(&k.as_str()) {
                        lane_add(format!("schema: unknown reserves property {k}"));
                    }
                }
                if let Some(x) = m.get("migration")
                    && !x.as_i64().is_some_and(|n| n >= 1)
                {
                    lane_add("schema: reserves.migration must be a positive integer".into());
                }
                if let Some(x) = m.get("contract")
                    && !x.is_string()
                {
                    lane_add("schema: reserves.contract must be a string".into());
                }
            } else {
                lane_add("schema: reserves must be an object".into());
            }
        }
    }
    out
}

pub fn discover_plan_paths(repo: &Path, explicit: &[PathBuf]) -> Result<Vec<PathBuf>> {
    if !explicit.is_empty() {
        return Ok(explicit
            .iter()
            .map(|p| {
                if p.is_absolute() {
                    p.clone()
                } else {
                    repo.join(p)
                }
            })
            .collect());
    }
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
        for entry in fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
            let entry = entry?;
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            if entry.file_type()?.is_dir() {
                if name == "node_modules"
                    || name == "target"
                    || name.starts_with("tmp-")
                    || name == ".git"
                {
                    continue;
                }
                walk(&path, out)?;
            } else if name.ends_with(".lanes.json") {
                out.push(path);
            }
        }
        Ok(())
    }
    let mut out = Vec::new();
    walk(repo, &mut out)?;
    out.sort();
    Ok(out)
}

pub fn load_plans(repo: &Path, explicit: &[PathBuf]) -> Result<Vec<Plan>> {
    discover_plan_paths(repo, explicit)?
        .into_iter()
        .map(|path| {
            let text = fs::read_to_string(&path)
                .with_context(|| format!("reading plan {}", path.display()))?;
            let document = serde_json::from_str(&text)
                .with_context(|| format!("parsing plan {}", path.display()))?;
            Ok(Plan { path, document })
        })
        .collect()
}

pub fn lanes(plans: &[Plan]) -> Vec<LaneRef> {
    let mut out = Vec::new();
    for plan in plans {
        let plan_name = string(get(&plan.document, "plan"))
            .unwrap_or("<unknown>")
            .to_owned();
        for lane in get(&plan.document, "lanes")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let Some(id) = string(get(lane, "id")) else {
                continue;
            };
            let reserves = get(lane, "reserves");
            let deps = get(lane, "dependsOn")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect();
            out.push(LaneRef {
                plan_path: plan.path.clone(),
                plan_name: plan_name.clone(),
                id: id.into(),
                title: string(get(lane, "title")).unwrap_or("").into(),
                status: string(get(lane, "status")).unwrap_or("").into(),
                priority: num(get(lane, "priority")).unwrap_or(99),
                host: string(get(lane, "host")).unwrap_or("-").into(),
                class: string(get(lane, "class")).unwrap_or("light").into(),
                estimate: get(lane, "estimateHours")
                    .and_then(Value::as_f64)
                    .unwrap_or(f64::INFINITY),
                migration: num(reserves.and_then(|v| get(v, "migration"))),
                contract: string(reserves.and_then(|v| get(v, "contract"))).map(str::to_owned),
                deps,
                packet: nonnull_string(get(lane, "packet")),
                decision: nonnull_string(get(lane, "decision")),
                notes: nonnull_string(get(lane, "notes")),
                commit: nonnull_string(get(lane, "commit")),
                release: nonnull_string(get(lane, "release")),
            });
        }
    }
    out
}

fn rel_name(repo: &Path, file: &Path) -> String {
    file.strip_prefix(repo)
        .unwrap_or(file)
        .display()
        .to_string()
}

fn migration_paths(repo: &Path, pattern: &str) -> Result<Vec<PathBuf>> {
    let glob = Glob::new(pattern)
        .with_context(|| format!("invalid migration glob {pattern}"))?
        .compile_matcher();
    let mut found = Vec::new();
    for path in discover_files(repo)? {
        if glob.is_match(path.strip_prefix(repo).unwrap_or(&path)) {
            found.push(path);
        }
    }
    Ok(found)
}
fn discover_files(repo: &Path) -> Result<Vec<PathBuf>> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
        for entry in fs::read_dir(dir)? {
            let e = entry?;
            let p = e.path();
            let n = e.file_name().to_string_lossy().to_string();
            if e.file_type()?.is_dir() {
                if [".git", "target", "node_modules"].contains(&n.as_str()) || n.starts_with("tmp-")
                {
                    continue;
                }
                walk(&p, out)?;
            } else {
                out.push(p);
            }
        }
        Ok(())
    }
    let mut paths = Vec::new();
    walk(repo, &mut paths)?;
    Ok(paths)
}

pub fn check_plans(repo: &Path, plans: &[Plan]) -> Vec<Problem> {
    let mut problems: Vec<Problem> = plans.iter().flat_map(schema_problems).collect();
    let all_lanes = lanes(plans);
    let mut ids: HashMap<String, Vec<&LaneRef>> = HashMap::new();
    for lane in &all_lanes {
        ids.entry(lane.id.clone()).or_default().push(lane);
    }
    for refs in ids.values().filter(|v| v.len() > 1) {
        for lane in refs {
            problems.push(Problem {
                plan: rel_name(repo, &lane.plan_path),
                lane: lane.id.clone(),
                rule: "id must be unique across all plans".into(),
            });
        }
    }
    let idset: HashSet<&str> = all_lanes.iter().map(|l| l.id.as_str()).collect();
    for lane in &all_lanes {
        let plan_file = rel_name(repo, &lane.plan_path);
        for dep in &lane.deps {
            if !idset.contains(dep.as_str()) {
                problems.push(Problem {
                    plan: plan_file.clone(),
                    lane: lane.id.clone(),
                    rule: format!("dependsOn references missing lane {dep}"),
                });
            }
        }
        if lane.status == "packet" {
            match &lane.packet {
                Some(packet) if repo.join(packet).is_file() => {}
                _ => problems.push(Problem {
                    plan: plan_file.clone(),
                    lane: lane.id.clone(),
                    rule: "packet status requires an existing packet file".into(),
                }),
            }
        }
        if lane.status == "applied" && lane.commit.as_deref().unwrap_or("").is_empty() {
            problems.push(Problem {
                plan: plan_file.clone(),
                lane: lane.id.clone(),
                rule: "applied status requires commit".into(),
            });
        }
        if lane.status == "applied"
            && let Some(migration) = lane.migration
        {
            for previous in all_lanes.iter().filter(|other| {
                other.migration.is_some_and(|n| n < migration)
                    && other.status != "dropped"
                    && !["applied", "shipped"].contains(&other.status.as_str())
            }) {
                problems.push(Problem { plan: plan_file.clone(), lane: lane.id.clone(), rule: format!("migration {migration} cannot be applied before predecessor {} ({}); mark it held", previous.migration.unwrap_or_default(), previous.id) });
            }
        }
        if lane.status == "shipped" && lane.release.as_deref().unwrap_or("").is_empty() {
            problems.push(Problem {
                plan: plan_file.clone(),
                lane: lane.id.clone(),
                rule: "shipped status requires release".into(),
            });
        }
        if let Some(migration) = lane.migration {
            let baseline = plans
                .iter()
                .find(|p| p.path == lane.plan_path)
                .and_then(|p| num(get(get(&p.document, "baseline")?, "migration")))
                .unwrap_or(0);
            if migration <= baseline {
                problems.push(Problem {
                    plan: plan_file.clone(),
                    lane: lane.id.clone(),
                    rule: format!(
                        "reserved migration {migration} must be above baseline {baseline}"
                    ),
                });
            }
            if let Some(p) = plans.iter().find(|p| p.path == lane.plan_path)
                && let Some(pattern) = string(get(
                    get(&p.document, "numbering").unwrap_or(&Value::Null),
                    "migrationGlob",
                ))
            {
                let concrete = pattern.replace("{n}", &migration.to_string());
                if let Ok(matches) = migration_paths(repo, &concrete)
                    && !matches.is_empty()
                    && !lane.packet.as_ref().is_some_and(|packet| {
                        fs::read_to_string(repo.join(packet))
                            .map(|text| {
                                matches.iter().any(|path| {
                                    text.contains(&rel_name(repo, path))
                                        || text.contains(
                                            path.file_name()
                                                .unwrap_or_default()
                                                .to_string_lossy()
                                                .as_ref(),
                                        )
                                })
                            })
                            .unwrap_or(false)
                    })
                    && lane.status == "packet"
                {
                    problems.push(Problem {
                        plan: plan_file.clone(),
                        lane: lane.id.clone(),
                        rule: format!("packet migration file must match reservation {migration}"),
                    });
                }
            }
        }
    }
    let migration_owners: BTreeMap<i64, Vec<&LaneRef>> = grouped(&all_lanes, |l| l.migration);
    for (n, owners) in migration_owners {
        if owners.len() > 1 {
            for lane in owners {
                problems.push(Problem {
                    plan: rel_name(repo, &lane.plan_path),
                    lane: lane.id.clone(),
                    rule: format!("reserved migration {n} must be unique across plans"),
                });
            }
        }
    }
    let contract_owners: BTreeMap<String, Vec<&LaneRef>> =
        grouped(&all_lanes, |l| l.contract.clone());
    for (contract, owners) in &contract_owners {
        if owners.len() > 1 {
            for lane in owners {
                problems.push(Problem {
                    plan: rel_name(repo, &lane.plan_path),
                    lane: lane.id.clone(),
                    rule: format!("reserved contract {contract} must be unique across plans"),
                });
            }
        }
    }
    for plan in plans {
        let prefix = string(get(
            get(&plan.document, "numbering").unwrap_or(&Value::Null),
            "contractPrefix",
        ))
        .unwrap_or("");
        let base_contract = string(get(
            get(&plan.document, "baseline").unwrap_or(&Value::Null),
            "contract",
        ));
        let mut reservations: Vec<(&LaneRef, i64, String)> = all_lanes
            .iter()
            .filter(|l| l.plan_path == plan.path)
            .filter_map(|l| Some((l, l.migration?, l.contract.clone()?)))
            .collect();
        reservations.sort_by_key(|(_, m, _)| *m);
        for pair in reservations.windows(2) {
            if contract_index(&pair[0].2, prefix)
                .zip(contract_index(&pair[1].2, prefix))
                .is_some_and(|(a, b)| a >= b)
            {
                problems.push(Problem {
                    plan: rel_name(repo, &pair[1].0.plan_path),
                    lane: pair[1].0.id.clone(),
                    rule: format!(
                        "contract versions must increase with migration numbers ({} before {})",
                        pair[0].2, pair[1].2
                    ),
                });
            }
        }
        if let Some(base) = base_contract.and_then(|s| contract_index(s, prefix))
            && let Some((lane, _, contract)) = reservations.first()
            && contract_index(contract, prefix).is_some_and(|i| i <= base)
        {
            problems.push(Problem {
                plan: rel_name(repo, &lane.plan_path),
                lane: lane.id.clone(),
                rule: format!(
                    "reserved contract {contract} must be above baseline contract {}",
                    base_contract.unwrap_or("")
                ),
            });
        }
    }
    // Cycle detection reports every lane participating in a dependency cycle.
    let by_id: HashMap<&str, &LaneRef> = all_lanes.iter().map(|l| (l.id.as_str(), l)).collect();
    let mut state: HashMap<&str, u8> = HashMap::new();
    let mut stack: Vec<&str> = Vec::new();
    let mut cycle_nodes = HashSet::new();
    fn visit<'a>(
        id: &'a str,
        by_id: &HashMap<&'a str, &'a LaneRef>,
        state: &mut HashMap<&'a str, u8>,
        stack: &mut Vec<&'a str>,
        cycles: &mut HashSet<String>,
    ) {
        match state.get(id).copied().unwrap_or(0) {
            2 => return,
            1 => {
                if let Some(start) = stack.iter().position(|v| *v == id) {
                    for node in &stack[start..] {
                        cycles.insert((*node).to_owned());
                    }
                }
                return;
            }
            _ => {}
        }
        state.insert(id, 1);
        stack.push(id);
        if let Some(l) = by_id.get(id) {
            for d in &l.deps {
                if by_id.contains_key(d.as_str()) {
                    visit(d, by_id, state, stack, cycles);
                }
            }
        }
        stack.pop();
        state.insert(id, 2);
    }
    for id in by_id.keys() {
        visit(id, &by_id, &mut state, &mut stack, &mut cycle_nodes);
    }
    for id in cycle_nodes {
        if let Some(l) = by_id.get(id.as_str()) {
            problems.push(Problem {
                plan: rel_name(repo, &l.plan_path),
                lane: id,
                rule: "dependsOn graph must not contain a cycle".into(),
            });
        }
    }
    problems.sort_by(|a, b| (&a.plan, &a.lane, &a.rule).cmp(&(&b.plan, &b.lane, &b.rule)));
    problems
}

/// Check migration and contract reservations proposed by a packet against the loaded plans.
/// The packet linter calls this so reservation rules stay owned by the plan validator.
pub fn check_packet_reservations(
    repo: &Path,
    plans: &[Plan],
    lane_id: &str,
    migrations: &[i64],
    contracts: &[String],
) -> Vec<Problem> {
    let all = lanes(plans);
    let owning_plan = all
        .iter()
        .find(|lane| lane.id == lane_id)
        .and_then(|lane| plans.iter().find(|plan| plan.path == lane.plan_path));
    let baseline = owning_plan
        .and_then(|plan| num(get(get(&plan.document, "baseline")?, "migration")))
        .unwrap_or(0);
    let mut out = Vec::new();
    for migration in migrations {
        if *migration <= baseline {
            out.push(Problem {
                plan: owning_plan.map_or_else(|| "<plan>".into(), |p| rel_name(repo, &p.path)),
                lane: lane_id.into(),
                rule: format!("reserved migration {migration} must be above baseline {baseline}"),
            });
        }
        if all
            .iter()
            .any(|lane| lane.migration == Some(*migration) && lane.id != lane_id)
        {
            out.push(Problem {
                plan: "<plans>".into(),
                lane: lane_id.into(),
                rule: format!("reserved migration {migration} must be unique across plans"),
            });
        }
    }
    for contract in contracts {
        if all
            .iter()
            .any(|lane| lane.contract.as_deref() == Some(contract) && lane.id != lane_id)
        {
            out.push(Problem {
                plan: "<plans>".into(),
                lane: lane_id.into(),
                rule: format!("reserved contract {contract} must be unique across plans"),
            });
        }
    }
    out
}
fn grouped<T: Ord + Clone>(
    lanes: &[LaneRef],
    f: impl Fn(&LaneRef) -> Option<T>,
) -> BTreeMap<T, Vec<&LaneRef>> {
    let mut out = BTreeMap::new();
    for lane in lanes {
        if let Some(k) = f(lane) {
            out.entry(k).or_insert_with(Vec::new).push(lane);
        }
    }
    out
}
fn contract_index(s: &str, prefix: &str) -> Option<u64> {
    let rest = s.strip_prefix(prefix)?;
    rest.split('.').try_fold(0u64, |acc, p| {
        p.parse::<u64>()
            .ok()
            .map(|v| acc.saturating_mul(1000).saturating_add(v))
    })
}

pub fn ready_next(all: &[LaneRef]) -> Vec<LaneRef> {
    let by_id: HashMap<&str, &LaneRef> = all.iter().map(|l| (l.id.as_str(), l)).collect();
    let mut ready: Vec<LaneRef> = all
        .iter()
        .filter(|l| {
            l.status == "packet"
                && l.deps.iter().all(|d| {
                    by_id
                        .get(d.as_str())
                        .is_some_and(|dep| ["applied", "shipped"].contains(&dep.status.as_str()))
                })
        })
        .cloned()
        .collect();
    ready.sort_by(|a, b| {
        a.priority
            .cmp(&b.priority)
            .then_with(|| {
                a.migration
                    .unwrap_or(i64::MAX)
                    .cmp(&b.migration.unwrap_or(i64::MAX))
            })
            .then_with(|| a.estimate.total_cmp(&b.estimate))
            .then_with(|| a.id.cmp(&b.id))
    });
    ready
}

#[derive(Clone, Debug)]
pub struct HostCapacity {
    pub class_limits: BTreeMap<String, usize>,
    pub class_running: BTreeMap<String, usize>,
    pub above_disk_floors: bool,
}

/// Choose an eligible host, honoring a lane's explicit host preference first.
pub fn choose_host(lane: &LaneRef, capacities: &BTreeMap<String, HostCapacity>) -> Option<String> {
    let eligible = |cap: &HostCapacity| {
        cap.above_disk_floors
            && cap.class_limits.get(&lane.class).is_some_and(|limit| {
                cap.class_running.get(&lane.class).copied().unwrap_or(0) < *limit
            })
    };
    if !lane.host.is_empty()
        && lane.host != "-"
        && lane.host != "any"
        && capacities.get(&lane.host).is_some_and(eligible)
    {
        return Some(lane.host.clone());
    }
    capacities
        .iter()
        .find_map(|(alias, cap)| eligible(cap).then(|| alias.clone()))
}

pub fn duplicate_running_id(all: &[LaneRef], id: &str) -> bool {
    all.iter()
        .any(|lane| lane.id == id && lane.status == "running")
}

pub trait PlanHostRunner {
    fn status(&mut self, lane: &LaneRef) -> Result<cowproof_host::LaneStatus>;
    fn collect(&mut self, lane: &LaneRef) -> Result<()>;
}

/// Poll running entries through an injected host runner and record completed or lost work.
pub fn collect_running(
    repo: &Path,
    runner: &mut impl PlanHostRunner,
) -> Result<Vec<(String, String)>> {
    let initial = load_plans(repo, &[])?;
    let ids: Vec<String> = lanes(&initial)
        .into_iter()
        .filter(|lane| lane.status == "running")
        .map(|lane| lane.id)
        .collect();
    let mut changes = Vec::new();
    for id in ids {
        let fresh = load_plans(repo, &[])?;
        let Some(lane) = lanes(&fresh)
            .into_iter()
            .find(|lane| lane.id == id && lane.status == "running")
        else {
            continue;
        };
        match runner.status(&lane)? {
            cowproof_host::LaneStatus::Running => continue,
            cowproof_host::LaneStatus::Finished | cowproof_host::LaneStatus::Failed => {
                runner.collect(&lane)?;
                set_lane_state(
                    repo,
                    &fresh,
                    &lane.id,
                    LaneStateUpdate {
                        status: "review",
                        commit: None,
                        release: None,
                        packet: None,
                        host: None,
                        notes: None,
                    },
                )?;
                changes.push((lane.id, "review".into()));
            }
            cowproof_host::LaneStatus::Lost => {
                let note = match lane.notes.as_deref().filter(|n| !n.is_empty()) {
                    Some(old) => {
                        format!("{old}\nDispatch host lost; lane returned to packet for retry.")
                    }
                    None => "Dispatch host lost; lane returned to packet for retry.".into(),
                };
                let note: String = note.chars().take(2000).collect();
                set_lane_state(
                    repo,
                    &fresh,
                    &lane.id,
                    LaneStateUpdate {
                        status: "packet",
                        commit: None,
                        release: None,
                        packet: None,
                        host: None,
                        notes: Some(Some(&note)),
                    },
                )?;
                changes.push((lane.id, "packet".into()));
            }
        }
    }
    Ok(changes)
}
pub fn blocked_by(lane: &LaneRef, all: &[LaneRef]) -> Vec<String> {
    let by_id: HashMap<&str, &LaneRef> = all.iter().map(|l| (l.id.as_str(), l)).collect();
    lane.deps
        .iter()
        .filter(|d| {
            !by_id
                .get(d.as_str())
                .is_some_and(|dep| ["applied", "shipped"].contains(&dep.status.as_str()))
        })
        .cloned()
        .collect()
}

pub fn waiting_on_founder(all: &[LaneRef]) -> Vec<String> {
    let mut waiting: Vec<String> = all
        .iter()
        .filter(|lane| ["idea", "planned", "packet", "held"].contains(&lane.status.as_str()))
        .filter(|lane| {
            [lane.decision.as_deref(), lane.notes.as_deref()]
                .into_iter()
                .flatten()
                .any(|text| {
                    let words = text.to_lowercase();
                    words.contains("founder")
                        && ["wait", "await", "need", "ask"]
                            .iter()
                            .any(|needle| words.contains(needle))
                })
        })
        .map(|lane| lane.id.clone())
        .collect();
    waiting.sort();
    waiting.dedup();
    waiting
}

pub fn set_status(
    repo: &Path,
    plans: &[Plan],
    id: &str,
    status: &str,
    commit: Option<&str>,
    release: Option<&str>,
    packet: Option<&str>,
) -> Result<PathBuf> {
    set_lane_state(
        repo,
        plans,
        id,
        LaneStateUpdate {
            status,
            commit,
            release,
            packet,
            host: None,
            notes: None,
        },
    )
}

pub struct LaneStateUpdate<'a> {
    pub status: &'a str,
    pub commit: Option<&'a str>,
    pub release: Option<&'a str>,
    pub packet: Option<&'a str>,
    pub host: Option<&'a str>,
    pub notes: Option<Option<&'a str>>,
}

/// Update lifecycle state and dispatch metadata while retaining plan validation.
/// `host` is applied only when supplied; `notes` replaces or removes notes when supplied.
pub fn set_lane_state(
    repo: &Path,
    plans: &[Plan],
    id: &str,
    update: LaneStateUpdate<'_>,
) -> Result<PathBuf> {
    let LaneStateUpdate {
        status,
        commit,
        release,
        packet,
        host,
        notes,
    } = update;
    if ![
        "idea", "planned", "packet", "running", "review", "held", "applied", "shipped", "dropped",
    ]
    .contains(&status)
    {
        return Err(anyhow!("invalid status {status}"));
    }
    let found: Vec<&Plan> = plans
        .iter()
        .filter(|p| {
            get(&p.document, "lanes")
                .and_then(Value::as_array)
                .is_some_and(|a| a.iter().any(|l| string(get(l, "id")) == Some(id)))
        })
        .collect();
    if found.len() != 1 {
        return Err(anyhow!(
            "lane id {id} must identify exactly one lane; found {}",
            found.len()
        ));
    }
    let plan = found[0];
    let existing = lanes(plans)
        .into_iter()
        .find(|lane| lane.id == id)
        .ok_or_else(|| anyhow!("lane {id} disappeared"))?;
    let shipping_from_review =
        status == "shipped" && matches!(existing.status.as_str(), "held" | "review");
    let allowed: &[&str] = match existing.status.as_str() {
        "idea" => &["planned", "dropped"],
        "planned" => &["packet", "dropped"],
        "packet" => &["running", "dropped"],
        // `packet` is also the recovery state when a dispatched host is lost.
        "running" => &["review", "packet", "dropped"],
        "review" => &["held", "applied", "shipped", "dropped"],
        "held" => &["applied", "shipped", "dropped"],
        "applied" => &["shipped"],
        "shipped" | "dropped" => &[],
        _ => &[],
    };
    if status == "running" && existing.status == "planned" && packet.is_none() {
        return Err(anyhow!("planned -> running requires --packet"));
    }
    let packet_dispatch = existing.status == "planned" && status == "running" && packet.is_some();
    if existing.status != status && !allowed.contains(&status) && !packet_dispatch {
        return Err(anyhow!(
            "refusing transition {} -> {} for {}; allowed: {}",
            existing.status,
            status,
            id,
            allowed.join(", ")
        ));
    }
    if status == "shipped"
        && matches!(existing.status.as_str(), "held" | "review")
        && (commit.is_none_or(str::is_empty) || release.is_none_or(str::is_empty))
    {
        return Err(anyhow!(
            "{} -> shipped requires both --commit and --release",
            existing.status
        ));
    }
    let mut next = plan.document.clone();
    let lane = next
        .get_mut("lanes")
        .and_then(Value::as_array_mut)
        .and_then(|a| a.iter_mut().find(|l| string(get(l, "id")) == Some(id)))
        .ok_or_else(|| anyhow!("lane {id} disappeared"))?;
    lane.as_object_mut()
        .ok_or_else(|| anyhow!("lane {id} is not an object"))?
        .insert("status".into(), Value::String(status.into()));
    if let Some(c) = commit {
        lane.as_object_mut()
            .unwrap()
            .insert("commit".into(), Value::String(c.into()));
    }
    if let Some(r) = release {
        lane.as_object_mut()
            .unwrap()
            .insert("release".into(), Value::String(r.into()));
    }
    if let Some(packet) = packet {
        lane.as_object_mut()
            .unwrap()
            .insert("packet".into(), Value::String(packet.into()));
    }
    if let Some(host) = host {
        lane.as_object_mut()
            .unwrap()
            .insert("host".into(), Value::String(host.into()));
    }
    if let Some(notes) = notes {
        let object = lane.as_object_mut().unwrap();
        if let Some(notes) = notes {
            object.insert("notes".into(), Value::String(notes.into()));
        } else {
            object.remove("notes");
        }
    }
    if shipping_from_review {
        let mut applied = next.clone();
        let applied_lane = applied
            .get_mut("lanes")
            .and_then(Value::as_array_mut)
            .and_then(|a| a.iter_mut().find(|l| string(get(l, "id")) == Some(id)))
            .ok_or_else(|| anyhow!("lane {id} disappeared"))?;
        applied_lane
            .as_object_mut()
            .ok_or_else(|| anyhow!("lane {id} is not an object"))?
            .insert("status".into(), Value::String("applied".into()));
        let applied_candidate = Plan {
            path: plan.path.clone(),
            document: applied,
        };
        let mut applied_plans = plans.to_vec();
        if let Some(p) = applied_plans.iter_mut().find(|p| p.path == plan.path) {
            *p = applied_candidate;
        }
        let applied_errors = check_plans(repo, &applied_plans);
        if !applied_errors.is_empty() {
            return Err(anyhow!(
                "refusing applied step before shipping: {}",
                applied_errors
                    .iter()
                    .map(|p| format!("{} {}: {}", p.plan, p.lane, p.rule))
                    .collect::<Vec<_>>()
                    .join("; ")
            ));
        }
    }
    let candidate = Plan {
        path: plan.path.clone(),
        document: next.clone(),
    };
    let mut candidate_plans = plans.to_vec();
    if let Some(p) = candidate_plans.iter_mut().find(|p| p.path == plan.path) {
        *p = candidate;
    }
    let errors = check_plans(repo, &candidate_plans);
    if !errors.is_empty() {
        return Err(anyhow!(
            "refusing status change: {}",
            errors
                .iter()
                .map(|p| format!("{} {}: {}", p.plan, p.lane, p.rule))
                .collect::<Vec<_>>()
                .join("; ")
        ));
    }
    let text = serde_json::to_string_pretty(&next)? + "\n";
    fs::write(&plan.path, text).with_context(|| format!("writing {}", plan.path.display()))?;
    Ok(plan.path.clone())
}

pub fn parse_json(path: &Path) -> Result<Value> {
    serde_json::from_slice(&fs::read(path)?).map_err(Into::into)
}

/// A plan is a workstream; the release stage is a property of the plan (default) or the lane.
fn valid_stage(stage: &str) -> bool {
    matches!(stage, "foundation" | "alpha" | "beta" | "ga" | "later")
}
