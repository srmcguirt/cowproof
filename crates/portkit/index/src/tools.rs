//! The symbol index as a registered [`Tool`].
//!
//! This is what the watcher's advice points at. When a hook says a file has
//! been read three times and suggests `pk run sym`, this is what answers —
//! and it has to be genuinely cheaper than the read it replaces, or the advice
//! is worse than silence.
//!
//! Measured on this repo: 0.48 ms to load an index of 816 symbols, then ~60 ns
//! per lookup, returning a span rather than a file.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use portkit_core::{async_trait, Budget, Error, Registry, Result, Tool, ToolSpec};
use serde_json::{json, Value};

use crate::index::Index;

/// Register the symbol tools for a repository root.
pub fn register(registry: &mut Registry, root: PathBuf) {
    let shared = Arc::new(root);
    registry.register(SymTool {
        root: shared.clone(),
    });
    registry.register(OutlineTool { root: shared });
}

/// Load the index, building it if there is none yet.
///
/// Building on demand rather than erroring: an agent asking for a symbol
/// should get one, not a lecture about running `pkx index` first.
fn index_for(root: &Path, tool: &str) -> Result<Index> {
    if let Ok(index) = Index::load(root) {
        return Ok(index);
    }
    let (index, _) = Index::build(root).map_err(|e| {
        Error::tool_failed(tool, format!("could not index {}: {e}", root.display()))
    })?;
    // Best-effort persist; a read-only checkout should still answer queries.
    let _ = index.save(root);
    Ok(index)
}

fn arg<'a>(input: &'a Value, key: &str, tool: &str) -> Result<&'a str> {
    input
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| Error::invalid_input(tool, format!("`{key}` is required")))
}

/// Read the source lines a symbol occupies.
fn body_of(root: &Path, file: &str, start: u32, end: u32) -> Option<String> {
    let text = std::fs::read_to_string(root.join(file)).ok()?;
    let lines: Vec<&str> = text.lines().collect();
    let (s, e) = (
        start.saturating_sub(1) as usize,
        (end as usize).min(lines.len()),
    );
    (s < e).then(|| lines[s..e].join("\n"))
}

/// Find a definition by name.
pub struct SymTool {
    root: Arc<PathBuf>,
}

#[async_trait]
impl Tool for SymTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec::new(
            "sym",
            "Find where a symbol is defined and return its span, or its source. Cheaper than reading the file it lives in.",
            json!({
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Symbol name. Falls back to a substring search when there is no exact match."
                    },
                    "file": {
                        "type": "string",
                        "description": "Restrict to one file, as a path suffix."
                    },
                    "body": {
                        "type": "boolean",
                        "default": false,
                        "description": "Include the source. Leave false to get just the location, which is usually enough."
                    }
                },
                "required": ["name"],
                "additionalProperties": false
            }),
        )
        .with_output_schema(json!({
            "type": "object",
            "properties": {
                "symbols": {
                    "type": "array",
                    "x-page-hint": "pass `file` to narrow, or a more specific `name`",
                    "items": { "type": "object" }
                }
            }
        }))
        // A body can be long; a location is ~70 bytes. This bounds the
        // difference between the two.
        .with_budget(Budget::bytes(8_192))
    }

    async fn call(&self, input: Value) -> Result<Value> {
        const TOOL: &str = "sym";
        let name = arg(&input, "name", TOOL)?;
        let want_body = input.get("body").and_then(Value::as_bool).unwrap_or(false);
        let file_filter = input.get("file").and_then(Value::as_str);

        let index = index_for(&self.root, TOOL)?;
        let mut hits = index.lookup(name);
        let fuzzy = hits.is_empty();
        if fuzzy {
            hits = index.search(name, 10);
        }
        if let Some(f) = file_filter {
            hits.retain(|s| index.file(s).ends_with(f));
        }

        let symbols: Vec<Value> = hits
            .iter()
            .map(|s| {
                let file = index.file(s);
                let mut v = json!({
                    "name": s.name,
                    "kind": s.kind.as_str(),
                    "file": file,
                    "line_start": s.line_start,
                    "line_end": s.line_end,
                    "signature": s.signature,
                });
                if want_body {
                    if let Some(body) = body_of(&self.root, file, s.line_start, s.line_end) {
                        v["body"] = json!(body);
                    }
                }
                v
            })
            .collect();

        Ok(json!({
            "symbols": symbols,
            "count": symbols.len(),
            // Said plainly: a fuzzy hit is a guess, and the caller should know.
            "exact": !fuzzy,
            "indexed_symbols": index.symbols.len(),
        }))
    }
}

/// Every symbol in a file, signatures only.
pub struct OutlineTool {
    root: Arc<PathBuf>,
}

#[async_trait]
impl Tool for OutlineTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec::new(
            "outline",
            "List what a file defines, with signatures but no bodies. Answers 'what is in here' without reading it.",
            json!({
                "type": "object",
                "properties": {
                    "file": { "type": "string", "description": "Path, or a suffix of one." }
                },
                "required": ["file"],
                "additionalProperties": false
            }),
        )
        .with_output_schema(json!({
            "type": "object",
            "properties": {
                "symbols": {
                    "type": "array",
                    "x-page-hint": "name a more specific file",
                    "items": { "type": "object" }
                }
            }
        }))
        .with_budget(Budget::bytes(8_192))
    }

    async fn call(&self, input: Value) -> Result<Value> {
        const TOOL: &str = "outline";
        let file = arg(&input, "file", TOOL)?;
        let index = index_for(&self.root, TOOL)?;

        let mut symbols: Vec<&crate::extract::Symbol> = index
            .symbols
            .iter()
            .filter(|s| index.file(s).ends_with(file))
            .collect();
        symbols.sort_by_key(|s| s.line_start);

        if symbols.is_empty() {
            // Distinguish "no such file" from "a file with nothing in it";
            // they need different next steps.
            let known = index.files.iter().any(|f| f.ends_with(file));
            return Err(Error::invalid_input(
                TOOL,
                if known {
                    format!("`{file}` defines no indexed symbols")
                } else {
                    format!("`{file}` is not in the index ({} files)", index.files.len())
                },
            ));
        }

        Ok(json!({
            "file": index.file(symbols[0]),
            "symbols": symbols.iter().map(|s| json!({
                "name": s.name,
                "kind": s.kind.as_str(),
                "line_start": s.line_start,
                "line_end": s.line_end,
                "signature": s.signature,
            })).collect::<Vec<_>>(),
            "count": symbols.len(),
        }))
    }
}
