//! Bounded output: cap what a tool result costs in context.
//!
//! codemap answers a 134 MB repository in 18 KB, and that property — the
//! answer size being roughly constant while the input varies by orders of
//! magnitude — is most of why it is cheap to ask. Nothing here enforces that
//! by itself, so this module makes it structural instead of leaving it to each
//! tool's discipline.
//!
//! # Trimming has to teach
//!
//! "truncated 411 items" tells an agent nothing, so it falls back to reading
//! the whole thing anyway and the budget has only relocated the cost. Every
//! elision therefore records what was dropped *and* how to ask for the rest;
//! a tool supplies the second half by annotating the array in its schema:
//!
//! ```json
//! "chunks": { "type": "array", "x-page-hint": "call with offset=<n>" }
//! ```
//!
//! # Not applied inside `Registry::call`
//!
//! Budgeting is presentation, not truth. [`crate::Registry::call`] returns the
//! full value so the parity harness compares what a tool actually produced;
//! the CLI and MCP surfaces apply the budget on the way out. Trimming before
//! the harness sees it would make fixtures agree with a summary rather than
//! with the port.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Roughly four bytes per token. Real tokenization needs a tokenizer and a
/// model-specific vocabulary; this is close enough to reason about and is
/// stated rather than hidden.
pub const BYTES_PER_TOKEN: usize = 4;

/// How much serialized JSON a result may occupy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Budget {
    pub max_bytes: usize,
    /// Smallest array left after trimming. Cutting an array to nothing loses
    /// the shape of the answer, which is usually the part worth keeping.
    pub min_items: usize,
}

impl Default for Budget {
    fn default() -> Self {
        // ~4k tokens: large enough for a real answer, small enough that a
        // handful of calls do not crowd out the conversation.
        Self {
            max_bytes: 16_384,
            min_items: 3,
        }
    }
}

impl Budget {
    pub fn bytes(max_bytes: usize) -> Self {
        Self {
            max_bytes,
            ..Default::default()
        }
    }

    pub fn tokens(max_tokens: usize) -> Self {
        Self::bytes(max_tokens * BYTES_PER_TOKEN)
    }

    /// No limit — for library callers that want the whole value.
    pub fn unlimited() -> Self {
        Self {
            max_bytes: usize::MAX,
            min_items: usize::MAX,
        }
    }
}

/// One thing that was dropped, and how to get it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Elision {
    /// JSON Pointer to what was trimmed.
    pub path: String,
    pub kept: usize,
    pub total: usize,
    /// From the tool's `x-page-hint` annotation. Without it the agent knows
    /// something is missing but not how to ask for it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
}

/// The result of applying a budget.
#[derive(Debug, Clone)]
pub struct Budgeted {
    pub value: Value,
    pub elisions: Vec<Elision>,
    pub original_bytes: usize,
    pub final_bytes: usize,
}

impl Budgeted {
    pub fn was_trimmed(&self) -> bool {
        !self.elisions.is_empty()
    }
}

/// Annotation a tool uses to say how to page an array.
pub const PAGE_HINT: &str = "x-page-hint";

/// Trim `value` to fit `budget`, largest offender first.
///
/// `schema` is optional and only supplies paging hints. Trimming works without
/// it; the results are just less actionable.
pub fn apply(value: &Value, schema: Option<&Value>, budget: &Budget) -> Budgeted {
    let original_bytes = measure(value);
    if original_bytes <= budget.max_bytes {
        return Budgeted {
            value: value.clone(),
            elisions: Vec::new(),
            original_bytes,
            final_bytes: original_bytes,
        };
    }

    let mut out = value.clone();
    let mut elisions = Vec::new();

    // Trim the biggest array repeatedly rather than trimming everything a
    // little: one oversized list is the usual cause, and halving every array
    // would damage small ones for no gain.
    loop {
        let current = measure(&out);
        if current <= budget.max_bytes {
            break;
        }
        let Some(target) = largest_array(&out, "") else {
            break;
        };

        let over = current - budget.max_bytes;
        let Some(trimmed) = trim_at(&mut out, &target.path, over, budget.min_items) else {
            break;
        };

        let hint = schema.and_then(|s| page_hint(s, &target.path));
        // A path trimmed twice should read as one elision, not two.
        if let Some(prev) = elisions
            .iter_mut()
            .find(|e: &&mut Elision| e.path == target.path)
        {
            prev.kept = trimmed.kept;
        } else {
            elisions.push(Elision {
                path: target.path.clone(),
                kept: trimmed.kept,
                total: trimmed.total,
                hint,
            });
        }

        if trimmed.kept <= budget.min_items {
            break; // nothing further to give at this path
        }
    }

    let final_bytes = measure(&out);
    Budgeted {
        value: out,
        elisions,
        original_bytes,
        final_bytes,
    }
}

fn measure(v: &Value) -> usize {
    serde_json::to_vec(v).map(|b| b.len()).unwrap_or(0)
}

struct Target {
    path: String,
    bytes: usize,
}

/// The array contributing the most bytes, anywhere in the document.
fn largest_array(v: &Value, path: &str) -> Option<Target> {
    let mut best: Option<Target> = None;

    let mut consider = |candidate: Option<Target>| {
        if let Some(c) = candidate {
            if best.as_ref().is_none_or(|b| c.bytes > b.bytes) {
                best = Some(c);
            }
        }
    };

    match v {
        Value::Array(items) if items.len() > 1 => {
            consider(Some(Target {
                path: path.to_string(),
                bytes: measure(v),
            }));
            for (i, item) in items.iter().enumerate() {
                consider(largest_array(item, &format!("{path}/{i}")));
            }
        }
        Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                consider(largest_array(item, &format!("{path}/{i}")));
            }
        }
        Value::Object(map) => {
            for (k, sub) in map {
                consider(largest_array(sub, &format!("{path}/{}", escape(k))));
            }
        }
        _ => {}
    }
    best
}

struct Trimmed {
    kept: usize,
    total: usize,
}

/// Drop items from the array at `path` until roughly `over` bytes are freed.
fn trim_at(root: &mut Value, path: &str, over: usize, min_items: usize) -> Option<Trimmed> {
    let node = pointer_mut(root, path)?;
    let items = node.as_array_mut()?;
    let total = items.len();
    if total <= min_items {
        return None;
    }

    // Estimate from the average element rather than measuring after each pop.
    let per_item = (measure(node) / total.max(1)).max(1);
    let drop = (over / per_item + 1).min(total - min_items);
    let keep = total - drop;

    let items = node.as_array_mut()?;
    items.truncate(keep);
    Some(Trimmed { kept: keep, total })
}

/// `serde_json::Value::pointer_mut` for our escaped paths.
fn pointer_mut<'a>(root: &'a mut Value, path: &str) -> Option<&'a mut Value> {
    if path.is_empty() {
        return Some(root);
    }
    let mut cur = root;
    for raw in path.trim_start_matches('/').split('/') {
        let token = raw.replace("~1", "/").replace("~0", "~");
        cur = match cur {
            Value::Object(map) => map.get_mut(&token)?,
            Value::Array(items) => items.get_mut(token.parse::<usize>().ok()?)?,
            _ => return None,
        };
    }
    Some(cur)
}

/// Follow the schema to the node covering `path` and read its paging hint.
fn page_hint(schema: &Value, path: &str) -> Option<String> {
    let mut node = schema;
    for raw in path.trim_start_matches('/').split('/') {
        if raw.is_empty() {
            continue;
        }
        let token = raw.replace("~1", "/").replace("~0", "~");
        node = if token.parse::<usize>().is_ok() {
            node.get("items")?
        } else {
            node.get("properties")?.get(&token)?
        };
    }
    node.get(PAGE_HINT)
        .and_then(Value::as_str)
        .map(str::to_string)
}

fn escape(key: &str) -> String {
    key.replace('~', "~0").replace('/', "~1")
}

/// Trim to budget and attach the note, keeping the whole thing under budget.
///
/// [`apply`] alone overshoots: the `_elided` note is added after trimming, so
/// the note's own bytes escape the cap. This reserves room for it first — a
/// budget that overshoots is a suggestion, not a budget.
pub fn apply_annotated(value: &Value, schema: Option<&Value>, budget: &Budget) -> Budgeted {
    let first = apply(value, schema, budget);
    if !first.was_trimmed() {
        return first;
    }

    // Cost the real note rather than guessing at it.
    let note_bytes = measure(&annotate(Value::Object(Map::new()), &first.elisions));
    let reserved = Budget {
        max_bytes: budget.max_bytes.saturating_sub(note_bytes),
        ..*budget
    };

    let second = apply(value, schema, &reserved);
    let annotated = annotate(second.value, &second.elisions);
    let final_bytes = measure(&annotated);

    Budgeted {
        value: annotated,
        elisions: second.elisions,
        original_bytes: first.original_bytes,
        final_bytes,
    }
}

/// Attach elisions to a result object under `_elided`.
///
/// Kept out of the payload's own namespace so a tool's fields are never
/// shadowed, and rendered as a note the model can act on.
pub fn annotate(value: Value, elisions: &[Elision]) -> Value {
    if elisions.is_empty() {
        return value;
    }
    let notes: Vec<Value> = elisions
        .iter()
        .map(|e| {
            let mut o = Map::new();
            o.insert("path".into(), Value::String(e.path.clone()));
            o.insert("kept".into(), Value::from(e.kept));
            o.insert("total".into(), Value::from(e.total));
            o.insert(
                "retry".into(),
                Value::String(
                    e.hint
                        .clone()
                        .unwrap_or_else(|| "narrow the request to see the rest".to_string()),
                ),
            );
            Value::Object(o)
        })
        .collect();

    match value {
        Value::Object(mut map) => {
            map.insert("_elided".into(), Value::Array(notes));
            Value::Object(map)
        }
        // A non-object result cannot carry a sibling key, so wrap it.
        other => {
            let mut map = Map::new();
            map.insert("result".into(), other);
            map.insert("_elided".into(), Value::Array(notes));
            Value::Object(map)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn rows(n: usize) -> Value {
        json!({
            "rows": (0..n).map(|i| json!({"id": i, "name": format!("row-{i:04}")}))
                .collect::<Vec<_>>(),
            "total": n
        })
    }

    #[test]
    fn a_small_result_is_returned_untouched() {
        let v = rows(3);
        let out = apply(&v, None, &Budget::bytes(10_000));
        assert!(!out.was_trimmed());
        assert_eq!(out.value, v);
    }

    #[test]
    fn an_oversized_result_is_brought_under_budget() {
        let out = apply(&rows(5_000), None, &Budget::bytes(2_000));
        assert!(out.final_bytes <= 2_000, "still {} bytes", out.final_bytes);
        assert!(out.original_bytes > 100_000);
    }

    #[test]
    fn trimming_reports_what_was_dropped() {
        // "Truncated" with no numbers gives the agent nothing to act on.
        let out = apply(&rows(1_000), None, &Budget::bytes(1_000));
        let e = &out.elisions[0];
        assert_eq!(e.path, "/rows");
        assert_eq!(e.total, 1_000);
        assert!(e.kept < e.total && e.kept > 0, "kept {}", e.kept);
    }

    #[test]
    fn a_paging_hint_from_the_schema_survives_into_the_elision() {
        let schema = json!({
            "properties": { "rows": { "type": "array", "x-page-hint": "call with offset=<n>" } }
        });
        let out = apply(&rows(1_000), Some(&schema), &Budget::bytes(1_000));
        assert_eq!(
            out.elisions[0].hint.as_deref(),
            Some("call with offset=<n>")
        );
    }

    #[test]
    fn fields_beside_the_trimmed_array_are_preserved() {
        // The count is often the most useful part; trimming must not lose it.
        let out = apply(&rows(2_000), None, &Budget::bytes(1_000));
        assert_eq!(out.value["total"], 2_000);
    }

    #[test]
    fn the_biggest_array_is_trimmed_not_the_first_one() {
        let v = json!({
            "small": (0..3).map(|i| json!({"i": i})).collect::<Vec<_>>(),
            "huge": (0..4_000).map(|i| json!({"i": i, "pad": "x".repeat(40)})).collect::<Vec<_>>()
        });
        let out = apply(&v, None, &Budget::bytes(2_000));
        assert_eq!(
            out.value["small"].as_array().unwrap().len(),
            3,
            "small array untouched"
        );
        assert_eq!(out.elisions[0].path, "/huge");
    }

    #[test]
    fn a_nested_array_is_found_and_trimmed() {
        let v = json!({"a": {"b": {"c": (0..2_000).map(|i| json!({"i": i})).collect::<Vec<_>>()}}});
        let out = apply(&v, None, &Budget::bytes(1_000));
        assert_eq!(out.elisions[0].path, "/a/b/c");
        assert!(out.final_bytes <= 1_000);
    }

    #[test]
    fn min_items_keeps_the_shape_of_the_answer() {
        // An empty array tells the agent less than three examples do.
        let budget = Budget {
            max_bytes: 10,
            min_items: 2,
        };
        let out = apply(&rows(500), None, &budget);
        assert!(out.value["rows"].as_array().unwrap().len() >= 2);
    }

    #[test]
    fn unlimited_never_trims() {
        let v = rows(5_000);
        let out = apply(&v, None, &Budget::unlimited());
        assert!(!out.was_trimmed());
        assert_eq!(out.value, v);
    }

    #[test]
    fn annotation_is_actionable_and_does_not_shadow_tool_fields() {
        let out = apply(&rows(1_000), None, &Budget::bytes(1_000));
        let annotated = annotate(out.value, &out.elisions);
        assert_eq!(annotated["total"], 1_000, "tool's own fields survive");
        let note = &annotated["_elided"][0];
        assert!(
            note["retry"].is_string(),
            "every elision says how to get more"
        );
        assert!(note["total"].as_u64().unwrap() > note["kept"].as_u64().unwrap());
    }

    #[test]
    fn a_non_object_result_is_wrapped_rather_than_losing_its_note() {
        let v = json!((0..1_000).map(|i| json!({"i": i})).collect::<Vec<_>>());
        let out = apply(&v, None, &Budget::bytes(500));
        let annotated = annotate(out.value, &out.elisions);
        assert!(annotated["result"].is_array());
        assert!(annotated["_elided"].is_array());
    }

    #[test]
    fn the_annotation_itself_stays_inside_the_budget() {
        // apply() alone overshoots, because the note is added after trimming.
        for cap in [500usize, 1_000, 4_000, 16_384] {
            let out = apply_annotated(&rows(5_000), None, &Budget::bytes(cap));
            assert!(
                out.final_bytes <= cap,
                "budget {cap} exceeded: {} bytes",
                out.final_bytes
            );
            assert!(
                out.value.get("_elided").is_some(),
                "note must survive the reservation"
            );
        }
    }

    #[test]
    fn an_untrimmed_result_is_not_annotated() {
        let out = apply_annotated(&rows(2), None, &Budget::bytes(10_000));
        assert!(out.value.get("_elided").is_none());
    }

    #[test]
    fn tokens_convert_to_bytes_at_the_documented_rate() {
        assert_eq!(Budget::tokens(1_000).max_bytes, 4_000);
    }
}
