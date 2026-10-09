#!/usr/bin/env python3
"""Reference implementation of the demo tools, standing in for the Python
agentic process you are porting away from.

The contract with `pk port capture` is one JSON request on stdin and one JSON
result on stdout — small enough to bolt onto an existing codebase without
restructuring it. Adapt `dispatch` to call your real functions; you should not
need to change anything else.

    pk port capture --cmd 'python3 examples/python/agent.py' \
                    --cases examples/cases.jsonl --out fixtures/
"""

import json
import sys


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
    """Split on runs of non-alphanumeric characters, keeping apostrophes.

    Written character by character rather than with a regex so it matches the
    Rust port exactly — `\\w` would also admit underscores, which
    `char::is_alphanumeric` does not.
    """
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

    # Ties break alphabetically so the ordering is reproducible across
    # languages; relying on insertion or hash order would make the port look
    # broken at random.
    ranked = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:top_k]

    return {
        "total": total,
        "unique": len(counts),
        "words": [
            {"word": word, "count": count, "share": count / total}
            for word, count in ranked
        ],
    }


TOOLS = {"chunk_text": chunk_text, "word_frequency": word_frequency}


def dispatch(request):
    tool = request.get("tool")
    if tool not in TOOLS:
        raise KeyError(f"unknown tool {tool!r}; known: {', '.join(sorted(TOOLS))}")
    return TOOLS[tool](**request.get("input", {}))


def main():
    try:
        request = json.load(sys.stdin)
    except json.JSONDecodeError as err:
        print(f"could not parse request: {err}", file=sys.stderr)
        return 1

    try:
        result = dispatch(request)
    except Exception as err:  # noqa: BLE001 — surface any failure to the harness
        print(f"{type(err).__name__}: {err}", file=sys.stderr)
        return 1

    # stdout carries the result and nothing else; diagnostics go to stderr.
    json.dump(result, sys.stdout)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
