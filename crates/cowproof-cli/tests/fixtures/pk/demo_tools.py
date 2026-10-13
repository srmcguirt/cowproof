#!/usr/bin/env python3
"""Two deterministic tools for the `pk` end-to-end tests, as a pk plugin.

portkit's own tests used to run against two built-in demo tools
(`chunk_text`, `word_frequency`). This workspace ships no demo tools, so the
restored tests register this script as a plugin instead: `demo_tools.py
chunk_text` and `demo_tools.py word_frequency` are two plugin entries.

Plugin contract: `--portkit-spec` prints the tool's spec; otherwise one
`{"tool": ..., "input": {...}}` request arrives on stdin and one JSON result
goes to stdout. A failure exits non-zero with the reason on stderr.

`word_frequency` counts words and reports each one's share. `chunk_text`
splits text into overlapping character windows. Both are the reference
implementations the committed fixtures under `parity/` were captured from.
"""

import json
import sys

CHUNK_TEXT_SPEC = {
    "name": "chunk_text",
    "description": "Split text into fixed-size overlapping chunks, as a retrieval pipeline would before embedding.",
    "input_schema": {
        "type": "object",
        "properties": {
            "text": {"type": "string", "description": "The text to split."},
            "size": {
                "type": "integer",
                "minimum": 1,
                "default": 120,
                "description": "Chunk length in characters.",
            },
            "overlap": {
                "type": "integer",
                "minimum": 0,
                "default": 20,
                "description": "Characters each chunk repeats from the previous one. Must be less than size.",
            },
        },
        "required": ["text"],
        "additionalProperties": False,
    },
    "output_schema": {
        "type": "object",
        "properties": {
            "chunks": {
                "type": "array",
                "x-page-hint": "raise `size` or pass a shorter `text` to see fewer, larger chunks",
                "items": {
                    "type": "object",
                    "properties": {
                        "index": {"type": "integer"},
                        "start": {"type": "integer"},
                        "end": {"type": "integer"},
                        "text": {"type": "string"},
                    },
                },
            },
            "count": {"type": "integer"},
        },
    },
}

WORD_FREQUENCY_SPEC = {
    "name": "word_frequency",
    "description": "Count words in a text and report each one's share of the total, most frequent first.",
    "input_schema": {
        "type": "object",
        "properties": {
            "text": {"type": "string", "description": "The text to analyse."},
            "top_k": {
                "type": "integer",
                "minimum": 1,
                "default": 10,
                "description": "How many of the most frequent words to return.",
            },
        },
        "required": ["text"],
        "additionalProperties": False,
    },
}


def chunk_text(text, size=120, overlap=20):
    """Split text into fixed-size overlapping chunks."""
    if size < 1:
        raise ValueError("`size` must be at least 1")
    if overlap >= size:
        raise ValueError(f"`overlap` ({overlap}) must be less than `size` ({size})")

    chunks = []
    start = 0
    stride = size - overlap
    while start < len(text):
        end = min(start + size, len(text))
        chunks.append(
            {"index": len(chunks), "start": start, "end": end, "text": text[start:end]}
        )
        if end == len(text):
            break
        start += stride

    return {"chunks": chunks, "count": len(chunks)}


def _split_words(text):
    """Split on runs of non-alphanumeric characters, keeping apostrophes."""
    words, current = [], []
    for ch in text:
        if ch.isalnum() or ch == "'":
            current.append(ch)
        elif current:
            words.append("".join(current))
            current = []
    if current:
        words.append("".join(current))
    return words


def word_frequency(text, top_k=10):
    """Count words and report each one's share of the total."""
    words = [w.lower() for w in _split_words(text)]
    total = len(words)
    if total == 0:
        return {"total": 0, "unique": 0, "words": []}

    counts = {}
    for word in words:
        counts[word] = counts.get(word, 0) + 1

    # Ties break alphabetically so the ordering is reproducible.
    ranked = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:top_k]

    return {
        "total": total,
        "unique": len(counts),
        "words": [
            {"word": word, "count": count, "share": count / total}
            for word, count in ranked
        ],
    }


TOOLS = {
    "chunk_text": (chunk_text, CHUNK_TEXT_SPEC),
    "word_frequency": (word_frequency, WORD_FREQUENCY_SPEC),
}


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in TOOLS:
        print(f"usage: demo_tools.py <{'|'.join(sorted(TOOLS))}> [--portkit-spec]", file=sys.stderr)
        return 2
    function, spec = TOOLS[sys.argv[1]]

    if "--portkit-spec" in sys.argv[2:]:
        json.dump(spec, sys.stdout)
        return 0

    try:
        request = json.load(sys.stdin)
        result = function(**request.get("input", {}))
    except Exception as err:  # noqa: BLE001 - surface any failure to the caller
        print(f"{type(err).__name__}: {err}", file=sys.stderr)
        return 1

    # stdout carries the result and nothing else; diagnostics go to stderr.
    json.dump(result, sys.stdout)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
