//! Record what the reference implementation does, so the port has a target.
//!
//! The contract with the reference process is deliberately minimal, because
//! it has to be implementable in five lines of Python in a repo you are trying
//! to leave: read one JSON request on stdin, write one JSON result on stdout.

use std::path::{Path, PathBuf};
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
    /// Directory the reference runs in (G2). `None` inherits the capturing process's, which
    /// makes a fixture depend on where the director happened to stand.
    pub cwd: Option<PathBuf>,
    /// Environment set for every case (G2), on top of the inherited one (or of the empty one,
    /// with [`clear_env`](Self::clear_env)). A case's own `env` is set after these and wins.
    pub env: Vec<(String, String)>,
    /// Start the reference from an empty environment holding only `PATH` (inherited unless
    /// `env` or the case sets one) and what `env` and the case set (G2). Without it a fixture
    /// can depend on the capturing shell's `HOME`, `TZ`, locale or a stray `PORTKIT_NOW`.
    pub clear_env: bool,
}

impl CaptureOptions {
    pub fn new(command: impl Into<String>) -> Self {
        Self {
            command: command.into(),
            fail_fast: false,
            cwd: None,
            env: Vec::new(),
            clear_env: false,
        }
    }

    /// Run the reference in `cwd`.
    pub fn with_cwd(mut self, cwd: impl Into<PathBuf>) -> Self {
        self.cwd = Some(cwd.into());
        self
    }

    /// Set `key` for every case.
    pub fn with_env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.push((key.into(), value.into()));
        self
    }

    /// Start from an empty environment (see [`clear_env`](Self::clear_env)).
    pub fn with_clear_env(mut self, clear: bool) -> Self {
        self.clear_env = clear;
        self
    }
}

/// The record of a reference that failed on a case that was meant to fail (G4): its exit
/// status and the first line it wrote to stderr, as `{"error": {"exit": N, "message": ".."}}`.
/// A port's failure is turned into the same shape at replay
/// ([`error_envelope_of`](crate::error_envelope_of)).
pub fn error_envelope(exit: Option<i32>, stderr: &str) -> Value {
    json!({
        "error": {
            "exit": exit,
            "message": first_line(stderr).unwrap_or(NO_STDERR),
        }
    })
}

/// What the message of an error envelope says when the process wrote nothing to stderr.
pub(crate) const NO_STDERR: &str = "no stderr output";

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
                    env: case.env.clone(),
                    expect_error: case.expect_error,
                    normalized: None,
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

    let mut command = Command::new("sh");
    command.arg("-c").arg(&opts.command);
    if let Some(cwd) = &opts.cwd {
        command.current_dir(cwd);
    }
    if opts.clear_env {
        command.env_clear();
        if let Some(path) = std::env::var_os("PATH") {
            command.env("PATH", path);
        }
    }
    for (key, value) in &opts.env {
        command.env(key, value);
    }
    // The case's own variables come last, so they win over the capture's.
    for (key, value) in &case.env {
        command.env(key, value);
    }
    let mut child = command
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
        // A "must reject" case records the failure as its fixture (G4).
        if case.expect_error {
            return Ok(error_envelope(output.status.code(), &stderr));
        }
        return Err(Error::other(format!(
            "reference exited with {}: {}",
            output.status,
            first_line(&stderr).unwrap_or(NO_STDERR)
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return Err(Error::other("reference produced no output on stdout"));
    }

    let value: Value = serde_json::from_str(trimmed).map_err(|e| {
        Error::other(format!(
            "reference output was not JSON ({e}); got: {}",
            truncate(trimmed, 200)
        ))
    })?;
    // A case meant to fail must fail: either the reference exits non-zero (above) or it
    // answers in the adapters' convention, `{"error": ..}` with exit 0. Anything else is a
    // reference that accepted what it should have rejected, and recording it would pin the
    // wrong behaviour.
    if case.expect_error && value.get("error").is_none() {
        return Err(Error::other(format!(
            "the case expects an error but the reference succeeded; got: {}",
            truncate(trimmed, 200)
        )));
    }
    Ok(value)
}

pub(crate) fn first_line(s: &str) -> Option<&str> {
    s.lines().map(str::trim).find(|l| !l.is_empty())
}

fn truncate(s: &str, limit: usize) -> String {
    if s.chars().count() <= limit {
        return s.to_string();
    }
    s.chars().take(limit).collect::<String>() + "…"
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("pk-capture-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir.canonicalize().unwrap()
    }

    fn cases(dir: &Path, lines: &[Value]) -> PathBuf {
        let path = dir.join("cases.jsonl");
        let text: Vec<String> = lines.iter().map(Value::to_string).collect();
        std::fs::write(&path, text.join("\n")).unwrap();
        path
    }

    fn fixture(out: &Path, tool: &str, id: &str) -> Fixture {
        Fixture::read(&out.join(tool).join(format!("{id}.json"))).unwrap()
    }

    const ECHO_ENV: &str = r#"printf '{"cwd":"%s","a":"%s","b":"%s","home":"%s"}' "$(pwd -P)" "$A" "$B" "${HOME-unset}""#;

    #[tokio::test]
    async fn the_capture_sets_the_directory_and_the_environment() {
        let base = dir("env");
        let work = base.join("work");
        std::fs::create_dir_all(&work).unwrap();
        let path = cases(
            &base,
            &[
                json!({"tool": "t", "id": "plain", "input": {}}),
                json!({"tool": "t", "id": "case", "input": {}, "env": {"B": "from-case", "A": "from-case"}}),
            ],
        );
        let out = base.join("out");
        let opts = CaptureOptions::new(ECHO_ENV)
            .with_cwd(&work)
            .with_env("A", "from-capture")
            .with_env("B", "from-capture")
            .with_clear_env(true);
        let report = capture(&path, &out, &opts).await.unwrap();
        assert!(report.is_success(), "{:?}", report.failures);

        // The reference ran in the directory the capture named, not where the test stands.
        let plain = fixture(&out, "t", "plain");
        assert_eq!(plain.expected["cwd"], work.to_string_lossy().as_ref());
        // The capture's variables reach it; a cleared environment does not carry HOME.
        assert_eq!(plain.expected["a"], "from-capture");
        assert_eq!(plain.expected["home"], "unset");
        assert!(plain.env.is_empty());
        // The case's own variables win, and are recorded with the fixture.
        let case = fixture(&out, "t", "case");
        assert_eq!(case.expected["a"], "from-case");
        assert_eq!(case.expected["b"], "from-case");
        assert_eq!(case.env["A"], "from-case");

        // Without `clear_env` the caller's environment is inherited (HOME is there).
        let inherited = CaptureOptions::new(ECHO_ENV);
        let report = capture(&path, &base.join("out2"), &inherited)
            .await
            .unwrap();
        assert!(report.is_success());
        assert_ne!(
            fixture(&base.join("out2"), "t", "plain").expected["home"],
            "unset"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[tokio::test]
    async fn a_must_reject_case_records_the_error_envelope() {
        let base = dir("expect");
        let path = cases(
            &base,
            &[
                json!({"tool": "t", "id": "bad", "input": {}, "expect_error": true}),
                json!({"tool": "t", "id": "unmarked", "input": {}}),
            ],
        );
        let out = base.join("out");
        let report = capture(
            &path,
            &out,
            &CaptureOptions::new("echo 'no such flag' >&2; exit 2"),
        )
        .await
        .unwrap();
        // The marked case is a fixture, the unmarked one still fails the capture.
        let bad = fixture(&out, "t", "bad");
        assert_eq!(
            bad.expected,
            json!({"error": {"exit": 2, "message": "no such flag"}})
        );
        assert!(bad.expect_error);
        assert_eq!(report.captured.len(), 1);
        assert_eq!(report.failures.len(), 1);
        assert_eq!(report.failures[0].id, "unmarked");
        assert!(
            report.failures[0].reason.contains("exited with"),
            "{:?}",
            report.failures
        );

        // A reference that succeeds where an error was expected is refused, not recorded.
        let path = cases(
            &base,
            &[json!({"tool": "t", "id": "ok", "input": {}, "expect_error": true})],
        );
        let report = capture(
            &path,
            &base.join("out2"),
            &CaptureOptions::new("echo '{\"fine\": 1}'"),
        )
        .await
        .unwrap();
        assert_eq!(report.captured.len(), 0);
        assert!(
            report.failures[0].reason.contains("expects an error"),
            "{:?}",
            report.failures
        );

        // The adapters' own convention, `{"error": ..}` with exit 0, is a recorded error too.
        let report = capture(
            &path,
            &base.join("out3"),
            &CaptureOptions::new("echo '{\"error\": \"nope\"}'"),
        )
        .await
        .unwrap();
        assert!(report.is_success());
        assert_eq!(
            fixture(&base.join("out3"), "t", "ok").expected,
            json!({"error": "nope"})
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn the_error_envelope_takes_the_first_line_of_stderr() {
        assert_eq!(
            error_envelope(Some(2), "\n  first  \nsecond\n"),
            json!({"error": {"exit": 2, "message": "first"}})
        );
        assert_eq!(
            error_envelope(None, ""),
            json!({"error": {"exit": null, "message": "no stderr output"}})
        );
    }
}
