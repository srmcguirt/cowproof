#![forbid(unsafe_code)]

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use cowproof_plan::{
    blocked_by, check_plans, lanes, load_plans, ready_next, set_status, waiting_on_founder,
};
use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

#[derive(Parser)]
#[command(
    name = "lanes-plan",
    version,
    about = "Check and prioritize lanes plan files"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    Check {
        #[arg(long, default_value = ".")]
        repo: PathBuf,
        #[arg(value_name = "PLAN")]
        plans: Vec<PathBuf>,
    },
    Next {
        #[arg(long, default_value = ".")]
        repo: PathBuf,
        #[arg(long)]
        json: bool,
    },
    Board {
        #[arg(long, default_value = ".")]
        repo: PathBuf,
        #[arg(long)]
        json: bool,
    },
    Brief {
        #[arg(long, default_value = ".")]
        repo: PathBuf,
        #[arg(long)]
        root: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    Set {
        id: String,
        status: String,
        #[arg(long)]
        commit: Option<String>,
        #[arg(long)]
        release: Option<String>,
        #[arg(long)]
        packet: Option<PathBuf>,
        #[arg(long, default_value = ".")]
        repo: PathBuf,
    },
}
fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}
fn run() -> Result<()> {
    match Cli::parse().command {
        Command::Check { repo, plans } => {
            let plans = load_plans(&repo, &plans)?;
            let problems = check_plans(&repo, &plans);
            if problems.is_empty() {
                println!(
                    "{}: ok",
                    plans
                        .iter()
                        .map(|p| p
                            .path
                            .strip_prefix(&repo)
                            .unwrap_or(&p.path)
                            .display()
                            .to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            } else {
                for p in &problems {
                    println!("{} [{}]: {}", p.plan, p.lane, p.rule);
                }
                std::process::exit(1);
            }
        }
        Command::Next {
            repo,
            json: as_json,
        } => {
            let plans = load_plans(&repo, &[])?;
            let all = lanes(&plans);
            let next = ready_next(&all);
            if as_json {
                println!("{}",serde_json::to_string_pretty(&next.iter().map(|l|json!({"id":l.id,"plan":l.plan_name,"status":l.status,"priority":l.priority,"migration":l.migration,"estimateHours":if l.estimate.is_finite(){Some(l.estimate)}else{None}})).collect::<Vec<_>>())?);
            } else if next.is_empty() {
                for line in no_ready_report(&all) {
                    println!("{line}");
                }
            } else {
                for l in next {
                    println!(
                        "{}  priority={}  migration={}  estimate={}h",
                        l.id,
                        l.priority,
                        l.migration.map_or("-".into(), |v| v.to_string()),
                        if l.estimate.is_finite() {
                            l.estimate.to_string()
                        } else {
                            "-".into()
                        }
                    );
                }
            }
        }
        Command::Board {
            repo,
            json: as_json,
        } => {
            let plans = load_plans(&repo, &[])?;
            let all = lanes(&plans);
            if as_json {
                let rows:Vec<Value>=all.iter().map(|l|json!({"plan":l.plan_name,"id":l.id,"status":l.status,"priority":l.priority,"host":l.host,"reserves": {"migration":l.migration,"contract":l.contract},"blockedBy":blocked_by(l,&all)})).collect();
                println!("{}", serde_json::to_string_pretty(&rows)?);
            } else {
                println!("PLAN\tID\tSTATUS\tPRI\tHOST\tRESERVES\tBLOCKED-BY");
                for l in &all {
                    let reserves = match (&l.migration, &l.contract) {
                        (Some(m), Some(c)) => format!("{m} / {c}"),
                        (Some(m), None) => m.to_string(),
                        (None, Some(c)) => c.clone(),
                        _ => "-".into(),
                    };
                    println!(
                        "{}\t{}\t{}\t{}\t{}\t{}\t{}",
                        l.plan_name,
                        l.id,
                        l.status,
                        l.priority,
                        l.host,
                        reserves,
                        blocked_by(l, &all).join(", ").as_str().if_empty_dash()
                    );
                }
            }
        }
        Command::Brief {
            repo,
            root,
            json: as_json,
        } => brief(&repo, root.as_deref(), as_json)?,
        Command::Set {
            id,
            status,
            commit,
            release,
            packet,
            repo,
        } => {
            let plans = load_plans(&repo, &[])?;
            let packet_value = if let Some(path) = packet.as_deref() {
                let assigned_packet = lanes(&plans)
                    .into_iter()
                    .find(|lane| lane.id == id)
                    .and_then(|lane| lane.packet);
                Some(validate_packet_path(
                    &repo,
                    &id,
                    path,
                    assigned_packet.as_deref(),
                )?)
            } else {
                None
            };
            let path = set_status(
                &repo,
                &plans,
                &id,
                &status,
                commit.as_deref(),
                release.as_deref(),
                packet_value.as_deref(),
            )?;
            println!("{}: {} -> {}", path.display(), id, status);
        }
    }
    Ok(())
}

fn no_ready_report(all: &[cowproof_plan::LaneRef]) -> Vec<String> {
    let mut lines = vec!["No ready lanes.".into()];
    let mut unpacketized: Vec<_> = all
        .iter()
        .filter(|lane| lane.status == "planned" && lane.packet.is_none())
        .collect();
    unpacketized.sort_by_key(|lane| (lane.priority, lane.plan_name.clone(), lane.id.clone()));
    lines.push(format!("Planned without a packet: {}", unpacketized.len()));
    lines.extend(unpacketized.iter().take(5).map(|lane| {
        format!(
            "  {}  plan={}  priority={}",
            lane.id, lane.plan_name, lane.priority
        )
    }));
    let mut blocked: Vec<_> = all
        .iter()
        .filter_map(|lane| {
            let dependencies = blocked_by(lane, all);
            (!dependencies.is_empty()).then_some((lane, dependencies))
        })
        .collect();
    blocked.sort_by_key(|(lane, _)| (lane.priority, lane.plan_name.clone(), lane.id.clone()));
    lines.push(format!("Blocked: {}", blocked.len()));
    lines.extend(blocked.iter().take(5).map(|(lane, dependencies)| {
        format!("  {}  blocked by {}", lane.id, dependencies.join(", "))
    }));
    lines
}

fn validate_packet_path(
    repo: &Path,
    id: &str,
    path: &Path,
    assigned_packet: Option<&str>,
) -> Result<String> {
    let resolved = if path.is_absolute() {
        path.to_path_buf()
    } else {
        repo.join(path)
    };
    let text = fs::read_to_string(&resolved)
        .with_context(|| format!("reading packet {}", resolved.display()))?;
    let header = cowproof_core::parse_header(&text)
        .with_context(|| format!("parsing packet header {}", resolved.display()))?;
    let packet_name = resolved
        .strip_prefix(repo)
        .unwrap_or(&resolved)
        .to_string_lossy()
        .replace('\\', "/");
    let is_lane_prefix_alias = header.id.strip_prefix("lane-") == Some(id)
        || id.strip_prefix("lane-") == Some(header.id.as_str());
    let is_assigned_packet = assigned_packet.is_some_and(|assigned| {
        Path::new(assigned)
            .components()
            .eq(Path::new(&packet_name).components())
    });
    if header.id != id && !is_lane_prefix_alias && !is_assigned_packet {
        anyhow::bail!(
            "packet header id {:?} does not match lane id {:?}; packet must match the id, differ only by a lane- prefix, or be the packet already assigned to this plan entry",
            header.id,
            id
        );
    }
    Ok(packet_name)
}
trait EmptyDash {
    fn if_empty_dash(&self) -> &str;
}
impl EmptyDash for str {
    fn if_empty_dash(&self) -> &str {
        if self.is_empty() { "-" } else { self }
    }
}
fn brief(repo: &Path, root: Option<&Path>, as_json: bool) -> Result<()> {
    let plans = load_plans(repo, &[])?;
    let all = lanes(&plans);
    let ready = ready_next(&all);
    let mut running: Vec<String> = all
        .iter()
        .filter(|l| l.status == "running")
        .map(|l| l.id.clone())
        .collect();
    let mut awaiting = Vec::new();
    let mut held: Vec<String> = all
        .iter()
        .filter(|l| l.status == "held")
        .map(|l| l.id.clone())
        .collect();
    if let Some(root) = root
        && root.exists()
    {
        for entry in
            fs::read_dir(root).with_context(|| format!("reading lane root {}", root.display()))?
        {
            let e = entry?;
            if !e.file_type()?.is_dir() {
                continue;
            }
            let dir = e.path();
            let name = e.file_name().to_string_lossy().into_owned();
            let summary = dir.join("summary.json");
            if !summary.exists() {
                if !running.iter().any(|id| name.starts_with(&format!("{id}-"))) {
                    running.push(name);
                }
            } else {
                let summary_time = fs::metadata(&summary)?
                    .modified()
                    .unwrap_or(SystemTime::UNIX_EPOCH);
                for lane in &all {
                    if name.starts_with(&format!("{}-", lane.id))
                        && fs::metadata(&lane.plan_path)
                            .and_then(|m| m.modified())
                            .unwrap_or(SystemTime::UNIX_EPOCH)
                            < summary_time
                    {
                        awaiting.push(lane.id.clone());
                    }
                }
            }
        }
    }
    let waiting = waiting_on_founder(&all);
    running.sort();
    running.dedup();
    awaiting.sort();
    awaiting.dedup();
    held.sort();
    let mut lines = Vec::new();
    lines.push(format!("Running: {}", dash(&running)));
    lines.push(format!("Awaiting review: {}", dash(&awaiting)));
    lines.push(format!("Held: {}", dash(&held)));
    lines.push(format!(
        "Ready next: {}",
        dash(&ready.iter().map(|l| l.id.clone()).collect::<Vec<_>>())
    ));
    lines.push(format!("Waiting on founder: {}", dash(&waiting)));
    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(
                &json!({"running":running,"awaitingReview":awaiting,"held":held,"readyNext":ready.iter().map(|l|l.id.clone()).collect::<Vec<_>>(),"waitingOnFounder":waiting,"lines":lines})
            )?
        );
    } else {
        for line in lines.into_iter().take(25) {
            println!("{line}");
        }
    }
    Ok(())
}
fn dash(items: &[String]) -> String {
    if items.is_empty() {
        "-".into()
    } else {
        items.join(", ")
    }
}

#[cfg(test)]
mod cli_tests {
    use super::*;

    #[test]
    fn packet_argument_requires_a_parseable_matching_header() {
        let root = std::env::temp_dir().join(format!("lanes-plan-packet-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        fs::write(
            root.join("ok.md"),
            "<!-- lane {\"id\":\"worker\",\"owns\":[\"src/**\"]} -->\n",
        )
        .unwrap();
        fs::write(
            root.join("wrong.md"),
            "<!-- lane {\"id\":\"other\",\"owns\":[\"src/**\"]} -->\n",
        )
        .unwrap();
        fs::write(root.join("invalid.md"), "no lane header\n").unwrap();
        assert_eq!(
            validate_packet_path(&root, "worker", Path::new("ok.md"), None).unwrap(),
            "ok.md"
        );
        let mismatch = validate_packet_path(&root, "worker", Path::new("wrong.md"), None)
            .unwrap_err()
            .to_string();
        assert!(mismatch.contains("does not match lane id"));
        assert!(validate_packet_path(&root, "worker", Path::new("invalid.md"), None).is_err());
        assert!(validate_packet_path(&root, "worker", Path::new("missing.md"), None).is_err());
        assert_eq!(
            validate_packet_path(&root, "worker", Path::new("wrong.md"), Some("wrong.md")).unwrap(),
            "wrong.md"
        );
        fs::write(
            root.join("alias.md"),
            "<!-- lane {\"id\":\"lane-worker\",\"owns\":[\"src/**\"]} -->\n",
        )
        .unwrap();
        assert_eq!(
            validate_packet_path(&root, "worker", Path::new("alias.md"), None).unwrap(),
            "alias.md"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn empty_next_report_explains_unpacketized_and_blocked_lanes() {
        let plan = cowproof_plan::Plan {
            path: PathBuf::from("work.lanes.json"),
            document: json!({
                "version": 1,
                "plan": "work",
                "lanes": [
                    {"id":"planned-one","title":"planned","priority":1,"status":"planned"},
                    {"id":"blocked-one","title":"blocked","priority":2,"status":"packet","dependsOn":["planned-one"]}
                ]
            }),
        };
        let report = no_ready_report(&lanes(&[plan]));
        assert!(
            report
                .iter()
                .any(|line| line == "Planned without a packet: 1")
        );
        assert!(
            report
                .iter()
                .any(|line| line.contains("planned-one") && line.contains("plan=work"))
        );
        assert!(report.iter().any(|line| line == "Blocked: 1"));
        assert!(
            report
                .iter()
                .any(|line| line.contains("blocked-one") && line.contains("planned-one"))
        );
    }
}
