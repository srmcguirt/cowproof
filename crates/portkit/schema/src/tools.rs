//! The schema capability as registered [`Tool`]s.
//!
//! Everything here already worked from `pks`, but a separate binary is not
//! reachable from an agent: `pk serve` could not see it, and shelling out
//! bypasses argument validation, budgets, provenance and tracing. Registering
//! it means the capability inherits all of that.

use std::sync::Arc;

use portkit_core::{async_trait, Budget, Error, Registry, Result, Tool, ToolSpec};
use serde_json::{json, Value};

use crate::resolve::{resolve_column, resolve_table, Resolution};
use crate::resolver::SchemaRegistry;
use crate::snapshot::Snapshot;

/// Register the schema tools over a set of snapshots.
///
/// The same [`SchemaRegistry`] is also wired in as the reference resolver, so
/// a tool that declares `x-schema-ref` is checked against the very snapshots
/// these tools report on.
pub fn register(registry: &mut Registry, sources: SchemaRegistry) {
    let shared = Arc::new(sources);
    registry.register(SchemaTables {
        sources: shared.clone(),
    });
    registry.register(SchemaColumns {
        sources: shared.clone(),
    });
    registry.register(SchemaCheck {
        sources: shared.clone(),
    });
    registry.set_resolver(shared);
}

/// Shared lookup with a consistent error when a source is not loaded.
fn snapshot<'a>(sources: &'a SchemaRegistry, source: &str, tool: &str) -> Result<&'a Snapshot> {
    sources.get(source).ok_or_else(|| {
        let known = sources.names().join(", ");
        Error::invalid_input(
            tool,
            if known.is_empty() {
                "no schema snapshots are loaded".to_string()
            } else {
                format!("unknown source `{source}`; loaded: {known}")
            },
        )
    })
}

fn arg<'a>(input: &'a Value, key: &str, tool: &str) -> Result<&'a str> {
    input
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| Error::invalid_input(tool, format!("`{key}` is required")))
}

/// Provenance, attached to every answer so it can be audited not just believed.
fn provenance(s: &Snapshot) -> Value {
    json!({
        "source": s.provenance.source,
        "kind": s.provenance.kind,
        "captured_at": s.provenance.captured_at,
        "fingerprint": s.provenance.fingerprint,
    })
}

fn source_property() -> Value {
    json!({
        "type": "string",
        "description": "Named schema source. Never defaulted — a deployment with more than one database must say which it means."
    })
}

/// List tables, optionally filtered by schema.
pub struct SchemaTables {
    sources: Arc<SchemaRegistry>,
}

#[async_trait]
impl Tool for SchemaTables {
    fn spec(&self) -> ToolSpec {
        ToolSpec::new(
            "schema_tables",
            "List tables known to a schema snapshot, optionally filtered to one schema.",
            json!({
                "type": "object",
                "properties": {
                    "source": source_property(),
                    "schema": { "type": "string", "description": "Restrict to one schema, e.g. `source`." }
                },
                "required": ["source"],
                "additionalProperties": false
            }),
        )
        .with_output_schema(json!({
            "type": "object",
            "properties": {
                "tables": {
                    "type": "array",
                    "x-page-hint": "pass `schema` to narrow to one schema",
                    "items": { "type": "string" }
                }
            }
        }))
        // A real database has hundreds of tables; a full list would crowd out
        // the conversation that asked for it.
        .with_budget(Budget::bytes(4_096))
    }

    async fn call(&self, input: Value) -> Result<Value> {
        const TOOL: &str = "schema_tables";
        let source = arg(&input, "source", TOOL)?;
        let snap = snapshot(&self.sources, source, TOOL)?;

        let filter = input.get("schema").and_then(Value::as_str);
        let tables: Vec<&str> = snap
            .tables
            .values()
            .filter(|t| filter.is_none_or(|f| t.schema == f))
            .map(|t| t.name.as_str())
            .collect();

        Ok(json!({
            "tables": tables,
            "count": tables.len(),
            "provenance": provenance(snap),
        }))
    }
}

/// The columns of one table — the answer that stops a guessed column name.
pub struct SchemaColumns {
    sources: Arc<SchemaRegistry>,
}

#[async_trait]
impl Tool for SchemaColumns {
    fn spec(&self) -> ToolSpec {
        ToolSpec::new(
            "schema_columns",
            "Report the real columns of a table, with types and nullability.",
            json!({
                "type": "object",
                "properties": {
                    "source": source_property(),
                    "table": {
                        "type": "string",
                        "description": "Schema-qualified, e.g. `source.tokens`. A bare name resolves when unambiguous."
                    }
                },
                "required": ["source", "table"],
                "additionalProperties": false
            }),
        )
        .with_budget(Budget::bytes(8_192))
    }

    async fn call(&self, input: Value) -> Result<Value> {
        const TOOL: &str = "schema_columns";
        let source = arg(&input, "source", TOOL)?;
        let table = arg(&input, "table", TOOL)?;
        let snap = snapshot(&self.sources, source, TOOL)?;

        // An unknown table is reported the way the checker reports it, with
        // suggestions, rather than as a bare miss.
        let Some(t) = snap.table(table) else {
            return Ok(rejection(resolve_table(snap, table), snap, "table"));
        };

        let columns: Vec<Value> = t
            .columns
            .iter()
            .map(|c| json!({ "name": c.name, "type": c.data_type, "nullable": c.nullable }))
            .collect();

        Ok(json!({
            "table": t.name,
            "columns": columns,
            "count": columns.len(),
            "provenance": provenance(snap),
        }))
    }
}

/// Check a name before using it.
pub struct SchemaCheck {
    sources: Arc<SchemaRegistry>,
}

#[async_trait]
impl Tool for SchemaCheck {
    fn spec(&self) -> ToolSpec {
        ToolSpec::new(
            "schema_check",
            "Check that a table, or a column of a table, actually exists. Returns the nearest real names when it does not.",
            json!({
                "type": "object",
                "properties": {
                    "source": source_property(),
                    "table": { "type": "string" },
                    "column": {
                        "type": "string",
                        "description": "Omit to check only the table."
                    }
                },
                "required": ["source", "table"],
                "additionalProperties": false
            }),
        )
        .with_budget(Budget::bytes(2_048))
    }

    async fn call(&self, input: Value) -> Result<Value> {
        const TOOL: &str = "schema_check";
        let source = arg(&input, "source", TOOL)?;
        let table = arg(&input, "table", TOOL)?;
        let snap = snapshot(&self.sources, source, TOOL)?;

        let (resolution, kind) = match input.get("column").and_then(Value::as_str) {
            Some(col) => (resolve_column(snap, table, col), "column"),
            None => (resolve_table(snap, table), "table"),
        };

        Ok(match resolution {
            Resolution::Known { name } => json!({
                "exists": true,
                "name": name,
                "provenance": provenance(snap),
            }),
            other => rejection(other, snap, kind),
        })
    }
}

/// A miss, shaped so the model can act on it in one step.
fn rejection(resolution: Resolution, snap: &Snapshot, kind: &str) -> Value {
    match resolution {
        Resolution::Known { name } => json!({ "exists": true, "name": name }),
        Resolution::Unknown { name, suggestions } => json!({
            "exists": false,
            "kind": kind,
            "name": name,
            "suggestions": suggestions.iter().map(|s| &s.name).collect::<Vec<_>>(),
            "provenance": provenance(snap),
        }),
    }
}
