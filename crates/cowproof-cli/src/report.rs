//! `cowproof report`: the handoff report for one lane (`handback`) and the aggregate
//! reports over many (`rollup`, `port-candidates`). The reports themselves live in
//! `cowproof_report`; this is their command line. `handback` was the standalone
//! `cowproof-report` binary until D2 folded it in, so the release ships one `cowproof`
//! binary (plus `pk` and `pk-read`, which hooks call by name).

use anyhow::Result;
use cowproof_report::handback::{self, handback};
use cowproof_report::port_candidates::{self, port_candidates};
use cowproof_report::rollup::{Options, rollup};
use std::path::PathBuf;

#[derive(clap::Args)]
pub struct ReportArgs {
    #[command(subcommand)]
    pub command: ReportAction,
}

#[derive(clap::Subcommand)]
pub enum ReportAction {
    /// The handoff report for one finished lane: checks, flaws, assertion loss, verdict hint
    ///
    /// Reads `summary.json`, `lane.patch` and the lane's handoff from the lane directory
    /// (the handoff is found in the patch, at the path `summary.json` names under
    /// `--repo`, or as `handoff.md` in the lane directory), parses the checks the builder
    /// reported, runs the flaw rules over the patch and counts removed assertions. The
    /// verdict hint is one of `apply`, `fix-then-apply`, `escalate` and `rerun`; it is a
    /// hint for the director, not a ruling. This was the standalone `cowproof-report`
    /// binary.
    ///
    /// Exit codes: 0 printed; 2 the lane could not be read (or a usage error).
    Handback(HandbackArgs),
    /// First-try pass rate, proved rate and cost per start rung and class, over lanes roots
    ///
    /// Reads only `control/run.json` and `control/verdict.json` one level under each root
    /// and follows no symlink out of it. A lane with neither file, or an empty `control`,
    /// is counted as unreadable; a malformed file is counted, not fatal; a lane whose
    /// builder has not finished is `running` and in no rate. Unsandboxed lanes are left
    /// out of the rates unless `--include-unsandboxed`. A lane from before D28 step 1
    /// counts as `claude:<model>`.
    ///
    /// Exit codes: 0 printed; 1 a root is not a directory.
    Rollup(RollupArgs),
    /// The commands lanes run again and again, ranked by calls x context bytes x time (D23)
    ///
    /// Reads only `<lane>/portkit/traces/*.jsonl` one level under each root (portkit's
    /// traces of a lane; Codex and OpenRouter lanes have none) and follows no symlink out
    /// of it; a line that is not a record is counted, not fatal. A command is its program
    /// and stable arguments from the first two words the trace keeps, with paths, temp
    /// dirs, ids and numbers collapsed and `=value` dropped. Everything printed or written
    /// is redacted first. `--draft DIR` writes a DRAFT `kind: port` packet per shown
    /// candidate; a draft is never dispatched and never overwrites a file.
    ///
    /// Also spelled `cowproof report --port-candidates`, as the design names it.
    ///
    /// Exit codes: 0 printed; 1 a root is not a directory or a draft file exists.
    #[command(name = "port-candidates", long_flag = "port-candidates")]
    PortCandidates(PortCandidatesArgs),
}

#[derive(clap::Args)]
pub struct HandbackArgs {
    /// The lane directory (holds `summary.json` and `lane.patch`)
    #[arg(value_name = "LANE_DIR")]
    pub lane_dir: PathBuf,
    /// The repository to find the handoff and the packet in
    #[arg(long, value_name = "DIR")]
    pub repo: Option<PathBuf>,
    /// The packet file (default: the packet under `--repo` whose header names the lane)
    #[arg(long, value_name = "FILE")]
    pub packet: Option<PathBuf>,
    /// A migration file name; flaw rules about new migrations skip it
    #[arg(long, value_name = "FILE")]
    pub baseline: Option<String>,
    /// Print one JSON document instead of the text report
    #[arg(long)]
    pub json: bool,
}

#[derive(clap::Args)]
pub struct PortCandidatesArgs {
    /// One or more lanes roots (each holds `<lane>/portkit/traces/*.jsonl`)
    #[arg(required = true, value_name = "LANES_ROOT")]
    pub roots: Vec<PathBuf>,
    /// How many candidates to show
    #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u32).range(1..=1000))]
    pub top: u32,
    /// Fewest runs for a command to be a candidate
    #[arg(long, default_value_t = 2, value_parser = clap::value_parser!(u32).range(1..))]
    pub min_calls: u32,
    /// Print one JSON document instead of the table
    #[arg(long)]
    pub json: bool,
    /// Write a DRAFT `kind: port` packet for each shown candidate into DIR
    #[arg(long, value_name = "DIR")]
    pub draft: Option<PathBuf>,
}

#[derive(clap::Args)]
pub struct RollupArgs {
    /// One or more lanes roots (each holds `<lane>/control/run.json`)
    #[arg(required = true, value_name = "LANES_ROOT")]
    pub roots: Vec<PathBuf>,
    /// Count unsandboxed lanes in the rates (a finished one counts as proved)
    #[arg(long)]
    pub include_unsandboxed: bool,
    /// Print one JSON document instead of the table
    #[arg(long)]
    pub json: bool,
}

pub fn run(args: ReportArgs) -> Result<()> {
    match args.command {
        ReportAction::Handback(args) => {
            let report = handback(&handback::Options {
                lane: args.lane_dir,
                repo: args.repo,
                packet: args.packet,
                baseline: args.baseline,
            });
            match report {
                Ok(report) if args.json => {
                    println!("{}", serde_json::to_string_pretty(&report)?);
                    Ok(())
                }
                Ok(report) => {
                    handback::print_report(&report);
                    Ok(())
                }
                Err(err) => {
                    // The old binary's exit code, so a script that tells "cannot read the
                    // lane" (2) from a runner failure (1) keeps working.
                    eprintln!("cowproof report handback: {err:#}");
                    std::process::exit(2);
                }
            }
        }
        ReportAction::Rollup(args) => {
            let rolled = rollup(
                &args.roots,
                &Options {
                    include_unsandboxed: args.include_unsandboxed,
                },
            )?;
            if args.json {
                println!("{}", serde_json::to_string_pretty(&rolled.to_json())?);
            } else {
                print!("{}", rolled.render());
            }
            Ok(())
        }
        ReportAction::PortCandidates(args) => {
            let found = port_candidates(
                &args.roots,
                &port_candidates::Options {
                    top: args.top as usize,
                    min_calls: args.min_calls as usize,
                },
            )?;
            let written = match &args.draft {
                Some(dir) => found.write_drafts(dir)?,
                None => Vec::new(),
            };
            if args.json {
                let mut doc = found.to_json();
                doc["drafts"] = written
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .into();
                println!("{}", serde_json::to_string_pretty(&doc)?);
            } else {
                print!("{}", found.render());
                if args.draft.is_some() {
                    println!();
                    println!(
                        "{} draft packet{} written (DRAFT, not dispatched):",
                        written.len(),
                        if written.len() == 1 { "" } else { "s" }
                    );
                    for path in &written {
                        println!("  {}", path.display());
                    }
                }
            }
            Ok(())
        }
    }
}
