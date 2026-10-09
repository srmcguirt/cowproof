//! A [`Tool`] backed by an external process.

use std::process::Stdio;
use std::time::Duration;

use portkit_core::{async_trait, Error, Result, Tool, ToolSpec};
use serde_json::{json, Value};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tracing::debug;

use crate::manifest::PluginEntry;

/// Flag a plugin answers with its [`ToolSpec`].
pub const SPEC_FLAG: &str = "--portkit-spec";

/// An executable registered as a tool.
///
/// The spec is read once at registration, not per call: `tools/list` must be
/// cheap, and a plugin that changes its own schema between calls would make
/// validation meaningless.
pub struct PluginTool {
    entry: PluginEntry,
    spec: ToolSpec,
}

impl std::fmt::Debug for PluginTool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PluginTool")
            .field("tool", &self.spec.name)
            .field("command", &self.entry.command)
            .finish()
    }
}

impl PluginTool {
    /// Ask the executable to describe itself.
    pub async fn discover(entry: PluginEntry) -> Result<Self> {
        let output = command(&entry)
            .arg(SPEC_FLAG)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .map_err(|e| Error::Config(format!("could not run `{}`: {e}", entry.command)))?;

        if !output.status.success() {
            return Err(Error::Config(format!(
                "`{} {SPEC_FLAG}` exited with {}: {}",
                entry.command,
                output.status,
                first_line(&output.stderr).unwrap_or_else(|| "no stderr".into())
            )));
        }

        let mut spec: ToolSpec = serde_json::from_slice(&output.stdout).map_err(|e| {
            Error::Config(format!(
                "`{} {SPEC_FLAG}` did not return a ToolSpec ({e}); got: {}",
                entry.command,
                truncate(&String::from_utf8_lossy(&output.stdout), 160)
            ))
        })?;

        // The manifest wins, so two plugins claiming one name can be separated
        // without editing either of them.
        if let Some(name) = &entry.name {
            spec.name = name.clone();
        }
        if spec.name.trim().is_empty() {
            return Err(Error::Config(format!(
                "`{}` reported an empty tool name",
                entry.command
            )));
        }

        debug!(tool = %spec.name, command = %entry.command, "registered plugin");
        Ok(Self { entry, spec })
    }
}

fn command(entry: &PluginEntry) -> Command {
    let mut cmd = Command::new(&entry.command);
    cmd.args(&entry.args);
    if let Some(cwd) = &entry.cwd {
        cmd.current_dir(cwd);
    }
    cmd
}

#[async_trait]
impl Tool for PluginTool {
    fn spec(&self) -> ToolSpec {
        self.spec.clone()
    }

    async fn call(&self, input: Value) -> Result<Value> {
        let name = &self.spec.name;
        // The same envelope `pk port capture` sends a reference implementation,
        // so a Python tool can be a plugin now and a fixture source later.
        let request = json!({ "tool": name, "input": input });

        let mut child = command(&self.entry)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| Error::tool_failed(name, format!("could not start: {e}")))?;

        {
            let mut stdin = child
                .stdin
                .take()
                .ok_or_else(|| Error::tool_failed(name, "could not open stdin"))?;
            stdin
                .write_all(request.to_string().as_bytes())
                .await
                .map_err(|e| Error::tool_failed(name, format!("could not write request: {e}")))?;
            let _ = stdin.write_all(b"\n").await;
            // Dropping stdin sends EOF; a plugin that reads to end hangs without it.
        }

        let timeout = Duration::from_secs(self.entry.timeout_secs.max(1));
        let output = match tokio::time::timeout(timeout, child.wait_with_output()).await {
            Ok(Ok(o)) => o,
            Ok(Err(e)) => return Err(Error::tool_failed(name, format!("process error: {e}"))),
            Err(_) => {
                // The child is detached at this point; the timeout is what
                // protects the caller, not the process table.
                return Err(Error::tool_failed(
                    name,
                    format!("timed out after {}s", self.entry.timeout_secs),
                ));
            }
        };

        if !output.status.success() {
            // stderr is the plugin's channel for saying what went wrong, and
            // it is the only thing the model has to work with.
            return Err(Error::tool_failed(
                name,
                format!(
                    "exited with {}: {}",
                    output.status,
                    first_line(&output.stderr).unwrap_or_else(|| "no stderr output".into())
                ),
            ));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let trimmed = stdout.trim();
        if trimmed.is_empty() {
            return Err(Error::tool_failed(name, "produced no output on stdout"));
        }

        serde_json::from_str(trimmed).map_err(|e| {
            Error::tool_failed(
                name,
                format!("output was not JSON ({e}); got: {}", truncate(trimmed, 200)),
            )
        })
    }
}

fn first_line(bytes: &[u8]) -> Option<String> {
    String::from_utf8_lossy(bytes)
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .map(str::to_string)
}

fn truncate(s: &str, limit: usize) -> String {
    if s.chars().count() <= limit {
        return s.to_string();
    }
    s.chars().take(limit).collect::<String>() + "…"
}
