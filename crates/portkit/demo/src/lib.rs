//! Worked examples for the template. Delete this crate when you fork.
//!
//! Both tools are deliberately deterministic and float-producing: they exercise
//! the parity harness on the case that actually bites when porting Python —
//! numbers that agree to twelve places and not to sixteen.
//!
//! `examples/python/agent.py` implements the same two tools, so
//! `just demo-parity` captures from Python and replays against these.

use portkit_core::{async_trait, Error, Registry, Result, Tool, ToolSpec};
use serde_json::{json, Map, Value};

/// The registry the reference `pk` binary serves. Replace with your own tools.
pub fn registry() -> Registry {
    Registry::new().with(ChunkText).with(WordFrequency)
}

/// Split text into overlapping chunks — the first step of most RAG pipelines.
pub struct ChunkText;

#[async_trait]
impl Tool for ChunkText {
    fn spec(&self) -> ToolSpec {
        ToolSpec::new(
            "chunk_text",
            "Split text into fixed-size overlapping chunks, as a retrieval pipeline would before embedding.",
            json!({
                "type": "object",
                "properties": {
                    "text": { "type": "string", "description": "The text to split." },
                    "size": {
                        "type": "integer", "minimum": 1, "default": 120,
                        "description": "Chunk length in characters."
                    },
                    "overlap": {
                        "type": "integer", "minimum": 0, "default": 20,
                        "description": "Characters each chunk repeats from the previous one. Must be less than size."
                    }
                },
                "required": ["text"],
                "additionalProperties": false
            }),
        )
        .with_output_schema(json!({
            "type": "object",
            "properties": {
                "chunks": {
                    "type": "array",
                    "x-page-hint": "raise `size` or pass a shorter `text` to see fewer, larger chunks",
                    "items": {
                        "type": "object",
                        "properties": {
                            "index": { "type": "integer" },
                            "start": { "type": "integer" },
                            "end":   { "type": "integer" },
                            "text":  { "type": "string" }
                        }
                    }
                },
                "count": { "type": "integer" }
            }
        }))
    }

    async fn call(&self, input: Value) -> Result<Value> {
        const TOOL: &str = "chunk_text";

        let text = input
            .get("text")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::invalid_input(TOOL, "`text` is required and must be a string"))?;

        let size = usize_arg(&input, "size", 120, TOOL)?;
        let overlap = usize_arg(&input, "overlap", 20, TOOL)?;

        if size == 0 {
            return Err(Error::invalid_input(TOOL, "`size` must be at least 1"));
        }
        // Without this the stride is zero and the loop never terminates —
        // exactly the kind of edge a fixture should pin.
        if overlap >= size {
            return Err(Error::invalid_input(
                TOOL,
                format!("`overlap` ({overlap}) must be less than `size` ({size})"),
            ));
        }

        // Index by char, not byte: the Python reference counts characters, and
        // byte slicing would both disagree with it and panic on non-ASCII.
        let chars: Vec<char> = text.chars().collect();
        let stride = size - overlap;

        let mut chunks = Vec::new();
        let mut start = 0usize;
        while start < chars.len() {
            let end = (start + size).min(chars.len());
            chunks.push(json!({
                "index": chunks.len(),
                "start": start,
                "end": end,
                "text": chars[start..end].iter().collect::<String>(),
            }));
            if end == chars.len() {
                break;
            }
            start += stride;
        }

        Ok(json!({ "chunks": chunks, "count": chunks.len() }))
    }
}

/// Relative word frequencies — a float-producing tool, to exercise tolerance.
pub struct WordFrequency;

#[async_trait]
impl Tool for WordFrequency {
    fn spec(&self) -> ToolSpec {
        ToolSpec::new(
            "word_frequency",
            "Count words in a text and report each one's share of the total, most frequent first.",
            json!({
                "type": "object",
                "properties": {
                    "text": { "type": "string", "description": "The text to analyse." },
                    "top_k": {
                        "type": "integer", "minimum": 1, "default": 10,
                        "description": "How many of the most frequent words to return."
                    }
                },
                "required": ["text"],
                "additionalProperties": false
            }),
        )
    }

    async fn call(&self, input: Value) -> Result<Value> {
        const TOOL: &str = "word_frequency";

        let text = input
            .get("text")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::invalid_input(TOOL, "`text` is required and must be a string"))?;

        let top_k = usize_arg(&input, "top_k", 10, TOOL)?;

        let words: Vec<String> = text
            .split(|c: char| !c.is_alphanumeric() && c != '\'')
            .filter(|w| !w.is_empty())
            .map(str::to_lowercase)
            .collect();

        let total = words.len();
        if total == 0 {
            return Ok(json!({ "total": 0, "unique": 0, "words": [] }));
        }

        // BTreeMap so ties break alphabetically in both languages rather than
        // by hash order, which would make the port look wrong at random.
        let mut counts: std::collections::BTreeMap<&str, usize> = Default::default();
        for word in &words {
            *counts.entry(word.as_str()).or_default() += 1;
        }
        let unique = counts.len();

        let mut ranked: Vec<(&str, usize)> = counts.into_iter().collect();
        ranked.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
        ranked.truncate(top_k);

        let words: Vec<Value> = ranked
            .into_iter()
            .map(|(word, count)| {
                json!({
                    "word": word,
                    "count": count,
                    "share": count as f64 / total as f64,
                })
            })
            .collect();

        Ok(json!({ "total": total, "unique": unique, "words": words }))
    }
}

/// Read an optional non-negative integer argument, rejecting nonsense loudly.
fn usize_arg(input: &Value, key: &str, default: usize, tool: &str) -> Result<usize> {
    let Some(value) = input.get(key) else {
        return Ok(default);
    };
    if value.is_null() {
        return Ok(default);
    }
    value.as_u64().map(|n| n as usize).ok_or_else(|| {
        Error::invalid_input(tool, format!("`{key}` must be a non-negative integer"))
    })
}

/// Helper for tests and callers building arguments by hand.
pub fn args(pairs: impl IntoIterator<Item = (&'static str, Value)>) -> Value {
    Value::Object(
        pairs
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect::<Map<_, _>>(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn chunking_covers_the_whole_input() {
        let out = ChunkText
            .call(json!({"text": "abcdefghij", "size": 4, "overlap": 1}))
            .await
            .unwrap();
        let chunks = out["chunks"].as_array().unwrap();
        assert_eq!(chunks[0]["text"], "abcd");
        assert_eq!(chunks.last().unwrap()["end"], 10);
    }

    #[tokio::test]
    async fn chunking_counts_characters_not_bytes() {
        let out = ChunkText
            .call(json!({"text": "héllo wörld", "size": 5, "overlap": 0}))
            .await
            .unwrap();
        assert_eq!(out["chunks"][0]["text"], "héllo");
    }

    #[tokio::test]
    async fn overlap_at_or_above_size_is_rejected_not_hung() {
        let err = ChunkText
            .call(json!({"text": "abc", "size": 4, "overlap": 4}))
            .await
            .unwrap_err();
        assert!(
            err.is_caller_fault(),
            "the caller can fix this by changing arguments"
        );
    }

    #[tokio::test]
    async fn frequency_shares_sum_to_one() {
        let out = WordFrequency
            .call(json!({"text": "a b a c a b", "top_k": 10}))
            .await
            .unwrap();
        let sum: f64 = out["words"]
            .as_array()
            .unwrap()
            .iter()
            .map(|w| w["share"].as_f64().unwrap())
            .sum();
        assert!((sum - 1.0).abs() < 1e-12, "shares summed to {sum}");
        assert_eq!(out["words"][0]["word"], "a");
    }

    #[tokio::test]
    async fn frequency_ties_break_alphabetically() {
        // Guards the ordering the Python reference also promises.
        let out = WordFrequency.call(json!({"text": "z y x"})).await.unwrap();
        let words: Vec<&str> = out["words"]
            .as_array()
            .unwrap()
            .iter()
            .map(|w| w["word"].as_str().unwrap())
            .collect();
        assert_eq!(words, ["x", "y", "z"]);
    }

    #[tokio::test]
    async fn empty_text_is_not_an_error() {
        let out = WordFrequency.call(json!({"text": "   "})).await.unwrap();
        assert_eq!(out["total"], 0);
    }

    #[test]
    fn the_demo_registry_exposes_both_tools() {
        assert_eq!(registry().names(), ["chunk_text", "word_frequency"]);
    }
}
