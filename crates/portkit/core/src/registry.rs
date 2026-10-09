//! A name-addressed set of tools, shared by the CLI, MCP, and parity surfaces.

use std::collections::BTreeMap;
use std::sync::Arc;

use serde_json::Value;

use crate::error::{Error, Result};
use crate::refs;
use crate::refs::RefResolver;
use crate::tool::{Tool, ToolSpec};
use crate::validate::InputValidator;

/// The set of tools a binary exposes.
///
/// `BTreeMap` rather than `HashMap` so `pk tools`, MCP `tools/list`, and
/// generated docs all agree on ordering run to run.
#[derive(Default, Clone)]
pub struct Registry {
    tools: BTreeMap<String, Arc<dyn Tool>>,
    /// Compiled once at registration. Every surface — CLI, MCP, replay —
    /// reaches tools through `call`, so validating here validates everywhere.
    validators: BTreeMap<String, Arc<InputValidator>>,
    /// Optional. When set, argument values annotated with `x-schema-ref` are
    /// checked against known facts before the tool runs, so a hallucinated
    /// table name never reaches a query.
    resolver: Option<Arc<dyn RefResolver>>,
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a tool, replacing any previous tool of the same name.
    pub fn register<T: Tool>(&mut self, tool: T) -> &mut Self {
        let tool: Arc<dyn Tool> = Arc::new(tool);
        let spec = tool.spec();
        self.validators.insert(
            spec.name.clone(),
            Arc::new(InputValidator::compile(&spec.name, &spec.input_schema)),
        );
        self.tools.insert(spec.name, tool);
        self
    }

    /// Builder-style [`Registry::register`], for `Registry::new().with(A).with(B)`.
    #[must_use]
    pub fn with<T: Tool>(mut self, tool: T) -> Self {
        self.register(tool);
        self
    }

    /// Check `x-schema-ref` annotations against a source of known facts.
    ///
    /// Wired here rather than inside tools so that every surface gets the
    /// check, and so a tool cannot forget it.
    #[must_use]
    pub fn with_resolver(mut self, resolver: Arc<dyn RefResolver>) -> Self {
        self.resolver = Some(resolver);
        self
    }

    pub fn set_resolver(&mut self, resolver: Arc<dyn RefResolver>) -> &mut Self {
        self.resolver = Some(resolver);
        self
    }

    pub fn get(&self, name: &str) -> Option<&Arc<dyn Tool>> {
        self.tools.get(name)
    }

    pub fn names(&self) -> Vec<&str> {
        self.tools.keys().map(String::as_str).collect()
    }

    pub fn specs(&self) -> Vec<ToolSpec> {
        self.tools.values().map(|t| t.spec()).collect()
    }

    pub fn len(&self) -> usize {
        self.tools.len()
    }

    pub fn is_empty(&self) -> bool {
        self.tools.is_empty()
    }

    /// Look up and invoke a tool by name, validating the arguments first.
    ///
    /// Validation happens here rather than in each tool so that a tool cannot
    /// drift from its published schema, and so every surface reports the same
    /// error shape.
    pub async fn call(&self, name: &str, input: Value) -> Result<Value> {
        if let Some(validator) = self.validators.get(name) {
            // Shape first: a reference check on a malformed call would report
            // confusing follow-on errors.
            validator.check(&input)?;

            if let Some(resolver) = &self.resolver {
                refs::check(validator.schema(), &input, resolver.as_ref())
                    .map_err(|e| Error::invalid_input(name, e.to_string()))?;
            }
        }
        self.call_unchecked(name, input).await
    }

    /// Invoke without schema validation.
    ///
    /// For callers that have already validated, or that deliberately need to
    /// exercise a tool's own error handling.
    pub async fn call_unchecked(&self, name: &str, input: Value) -> Result<Value> {
        let tool = self
            .get(name)
            .ok_or_else(|| Error::UnknownTool(name.to_string()))?
            .clone();
        tool.call(input).await
    }
}

impl std::fmt::Debug for Registry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Registry")
            .field("tools", &self.names())
            .finish()
    }
}
