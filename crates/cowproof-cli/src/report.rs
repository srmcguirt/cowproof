//! `cowproof report`: aggregate reports over many lanes. The rollup itself lives in
//! `cowproof_report::rollup`; this is its command line, so the three binaries keep
//! folding into one (`docs/backlog.md`) instead of a fourth entry point appearing.

use anyhow::Result;
use cowproof_report::rollup::{Options, rollup};
use std::path::PathBuf;

#[derive(clap::Args)]
pub struct ReportArgs {
    #[command(subcommand)]
    pub command: ReportAction,
}

#[derive(clap::Subcommand)]
pub enum ReportAction {
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
    }
}
