//! The `Tool` trait — the single definition each surface is generated from.
//!
//! Implement it once and the tool is reachable three ways: as a CLI
//! subcommand (`pk run <name>`), as an MCP tool (`pk serve`), and as a
//! parity fixture the harness can replay against the Python original.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::Result;

/// The self-description a tool hands to the CLI, to MCP clients, and to docs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ToolSpec {
    pub name: String,
    pub description: String,
    /// JSON Schema for the argument object. MCP clients use this to build
    /// calls, so keep it accurate — it is the model's only guide.
    pub input_schema: Value,
    /// Optional JSON Schema for the result. Not required by MCP, but it
    /// documents intent and gives the parity harness a shape to check.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_schema: Option<Value>,
    /// How much context this tool's output may occupy, applied at the CLI and
    /// MCP boundaries. A tool that can return an unbounded list should set
    /// this rather than trusting callers to ask for less.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget: Option<crate::budget::Budget>,
}

impl ToolSpec {
    pub fn new(
        name: impl Into<String>,
        description: impl Into<String>,
        input_schema: Value,
    ) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            input_schema,
            output_schema: None,
            budget: None,
        }
    }

    pub fn with_output_schema(mut self, schema: Value) -> Self {
        self.output_schema = Some(schema);
        self
    }

    /// Cap this tool's output. Prefer declaring it here over hoping callers
    /// pass `--budget`: the tool author knows which results can run away.
    pub fn with_budget(mut self, budget: crate::budget::Budget) -> Self {
        self.budget = Some(budget);
        self
    }
}

/// One unit of agentic work.
///
/// Implementations must be deterministic given the same input, or the parity
/// harness cannot check them. Push nondeterminism (clocks, RNG, network) into
/// constructor-injected dependencies so tests can pin them.
#[async_trait]
pub trait Tool: Send + Sync + 'static {
    fn spec(&self) -> ToolSpec;

    async fn call(&self, input: Value) -> Result<Value>;

    /// Convenience accessor; `spec().name` allocates, this usually does not.
    fn name(&self) -> String {
        self.spec().name
    }
}
