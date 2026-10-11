//! `cowproof doctor`: the preflight checks, printed.
//!
//! One line per check (`name: status - detail`), or one JSON object per line with
//! `--json`. Exit 0 when no check fails, 1 when one does. A warning (no copy-on-write,
//! no `ANTHROPIC_API_KEY`) does not fail the doctor; the key is a failure only for
//! `cowproof run`, which runs the same checks and stops on any failure.

use crate::preflight::{CheckStatus, PreflightOptions, preflight};
use crate::root;
use anyhow::{Result, anyhow};
use std::path::PathBuf;

#[derive(clap::Parser)]
pub struct DoctorArgs {
    /// Repository to check (default: the current directory)
    #[arg(long)]
    pub repo: Option<PathBuf>,
    /// Directory that holds the lanes (default: ~/.cache/cowproof/lanes). It is not created
    #[arg(long)]
    pub lanes_root: Option<PathBuf>,
    /// Free space, in GB, below which the disk check fails
    #[arg(long, default_value_t = 5.0)]
    pub disk_floor_gb: f64,
    /// The Claude Code executable to check, resolved on the director's PATH
    #[arg(long, default_value = "claude")]
    pub claude_bin: String,
    /// Print one JSON object per check, one per line (name, status, detail)
    #[arg(long)]
    pub json: bool,
}

/// Print the checks and return the exit code: 0, or 1 when a check failed.
pub async fn doctor(args: DoctorArgs) -> Result<i32> {
    let cwd = std::env::current_dir()?;
    let repo = cwd.join(args.repo.as_deref().unwrap_or(std::path::Path::new(".")));
    let real_home =
        PathBuf::from(std::env::var_os("HOME").ok_or_else(|| anyhow!("HOME is not set"))?);
    let lanes_root = root::lanes_root(args.lanes_root.as_deref(), &cwd, &real_home);
    let director_path = std::env::var("PATH").unwrap_or_default();
    let checks = preflight(&PreflightOptions {
        repo: &repo,
        lanes_root: &lanes_root,
        disk_floor_gb: args.disk_floor_gb,
        claude_bin: &args.claude_bin,
        director_path: &director_path,
        cwd: &cwd,
        real_home: &real_home,
        for_run: false,
    })
    .await;
    for check in &checks {
        if args.json {
            println!("{}", serde_json::to_string(check)?);
        } else {
            println!(
                "{}: {} - {}",
                check.name,
                check.status.label(),
                check.detail
            );
        }
    }
    Ok(if checks.iter().any(|c| c.status == CheckStatus::Fail) {
        1
    } else {
        0
    })
}
