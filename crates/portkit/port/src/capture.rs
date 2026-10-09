//! Record what the reference implementation does, so the port has a target.
//!
//! The contract with the reference process is deliberately minimal, because
//! it has to be implementable in five lines of Python in a repo you are trying
//! to leave: read one JSON request on stdin, write one JSON result on stdout.

use std::path::Path;
use std::process::Stdio;

use serde_json::{json, Value};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tracing::{debug, info};

use portkit_core::{Error, Result};

use crate::fixture::{load_cases, Case, Fixture};

/// How to invoke the reference implementation.
#[derive(Debug, Clone)]
pub struct CaptureOptions {
    /// Shell command, run once per case. Receives `{"tool":…,"input":…}` on
    /// stdin and must print the result as JSON on stdout.
    pub command: String,
    /// Stop at the first case the reference fails on, rather than collecting
    /// every failure. Off by default: one broken case should not hide the rest.
    pub fail_fast: bool,
}

impl CaptureOptions {
    pub fn new(command: impl Into<String>) -> Self {
        Self {
            command: command.into(),
            fail_fast: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CaptureReport {
    pub captured: Vec<CapturedCase>,
    pub failures: Vec<CaptureFailure>,
}

#[derive(Debug, Clone)]
pub struct CapturedCase {
    pub tool: String,
    pub id: String,
    pub path: std::path::PathBuf,
}

#[derive(Debug, Clone)]
pub struct CaptureFailure {
    pub tool: String,
    pub id: String,
    pub reason: String,
}

impl CaptureReport {
    pub fn is_success(&self) -> bool {
        self.failures.is_empty()
    }
}

/// Run every case in `cases_path` through the reference and write fixtures.
pub async fn capture(
    cases_path: &Path,
    out_root: &Path,
    opts: &CaptureOptions,
) -> Result<CaptureReport> {
    let cases = load_cases(cases_path)?;
    info!(cases = cases.len(), command = %opts.command, "capturing reference behaviour");

    let mut report = CaptureReport {
        captured: Vec::new(),
        failures: Vec::new(),
    };

    for (index, case) in cases.iter().enumerate() {
        let id = case
            .id
            .clone()
            .unwrap_or_else(|| format!("{:03}", index + 1));

        match run_case(case, opts).await {
            Ok(expected) => {
                let fixture = Fixture {
                    tool: case.tool.clone(),
                    id: id.clone(),
                    input: case.input.clone(),
                    expected,
                    captured_at: OffsetDateTime::now_utc().format(&Rfc3339).ok(),
                    source: Some(opts.command.clone()),
                    note: case.note.clone(),
                    // Capture records what the reference did; any accepted
                    // divergence is a judgement a human adds afterwards.
                    accepted: Vec::new(),
                };
                let path = fixture.write(out_root)?;
                debug!(tool = %case.tool, %id, path = %path.display(), "captured");
                report.captured.push(CapturedCase {
                    tool: case.tool.clone(),
                    id,
                    path,
                });
            }
            Err(err) => {
                report.failures.push(CaptureFailure {
                    tool: case.tool.clone(),
                    id,
                    reason: err.to_string(),
                });
                if opts.fail_fast {
                    break;
                }
            }
        }
    }

    Ok(report)
}

async fn run_case(case: &Case, opts: &CaptureOptions) -> Result<Value> {
    let request = json!({ "tool": case.tool, "input": case.input });

    let mut child = Command::new("sh")
        .arg("-c")
        .arg(&opts.command)
        // Also exposed as an env var so a reference script can dispatch on the
        // tool name without parsing stdin twice.
        .env("PORTKIT_TOOL", &case.tool)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| Error::other(format!("could not start `{}`: {e}", opts.command)))?;

    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| Error::other("could not open stdin on the reference process"))?;
    stdin.write_all(request.to_string().as_bytes()).await?;
    stdin.write_all(b"\n").await?;
    // Dropping stdin sends EOF; without it a reference that reads to end hangs.
    drop(stdin);

    let output = child.wait_with_output().await?;
    let stderr = String::from_utf8_lossy(&output.stderr);

    if !output.status.success() {
        return Err(Error::other(format!(
            "reference exited with {}: {}",
            output.status,
            first_line(&stderr).unwrap_or("no stderr output")
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return Err(Error::other("reference produced no output on stdout"));
    }

    serde_json::from_str(trimmed).map_err(|e| {
        Error::other(format!(
            "reference output was not JSON ({e}); got: {}",
            truncate(trimmed, 200)
        ))
    })
}

fn first_line(s: &str) -> Option<&str> {
    s.lines().map(str::trim).find(|l| !l.is_empty())
}

fn truncate(s: &str, limit: usize) -> String {
    if s.chars().count() <= limit {
        return s.to_string();
    }
    s.chars().take(limit).collect::<String>() + "…"
}
