//! The one error type shared by every portkit crate.

use thiserror::Error;

/// Convenience alias used throughout portkit.
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("unknown tool `{0}`")]
    UnknownTool(String),

    /// The input did not satisfy the tool's schema or preconditions.
    ///
    /// Prefer this over [`Error::ToolFailed`] for bad callers: the MCP layer
    /// reports it back to the model so it can correct itself and retry.
    #[error("invalid input for `{tool}`: {message}")]
    InvalidInput { tool: String, message: String },

    /// The tool was called correctly but could not complete.
    #[error("tool `{tool}` failed: {message}")]
    ToolFailed { tool: String, message: String },

    #[error("configuration error: {0}")]
    Config(String),

    #[error("fixture error: {0}")]
    Fixture(String),

    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("{0}")]
    Other(String),
}

impl Error {
    pub fn invalid_input(tool: impl Into<String>, message: impl Into<String>) -> Self {
        Error::InvalidInput {
            tool: tool.into(),
            message: message.into(),
        }
    }

    pub fn tool_failed(tool: impl Into<String>, message: impl Into<String>) -> Self {
        Error::ToolFailed {
            tool: tool.into(),
            message: message.into(),
        }
    }

    pub fn other(message: impl Into<String>) -> Self {
        Error::Other(message.into())
    }

    /// Whether the caller could plausibly fix this by changing its arguments.
    ///
    /// The MCP layer uses this to decide how loudly to complain.
    pub fn is_caller_fault(&self) -> bool {
        matches!(self, Error::InvalidInput { .. } | Error::UnknownTool(_))
    }
}

impl From<config::ConfigError> for Error {
    fn from(err: config::ConfigError) -> Self {
        Error::Config(err.to_string())
    }
}
