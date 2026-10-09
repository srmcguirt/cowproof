# portkit-index — PROTOTYPE

Answers one question: **can a persistent symbol index beat `grep` on both
latency and payload, and does it need a daemon?**

Answer: yes, and no.

## Measured

Cold load = read the index from disk in a fresh process. Warm query = lookup in
an already-loaded index.

| repo | symbols | index | cold load | warm query |
| --- | ---: | ---: | ---: | ---: |
| portkit | 270 | 43 KB | 0.24 ms | 0.05 µs |
| magna | 1,446 | 237 KB | 0.91 ms | 0.05 µs |
| fellwork-data | 3,664 | 618 KB | 2.10 ms | 0.07 µs |
| mlh | 4,068 | 704 KB | 2.23 ms | 0.06 µs |

Against the alternatives, 10 symbol lookups in fellwork-data:

| approach | total | bytes/query |
| --- | ---: | ---: |
| broad `grep -rn <name>` | 1,900 ms | 3,690 B |
| definition-targeted `grep -rnE "(fn\|struct) <name>"` | 2,835 ms | 202 B |
| **index (cold load + 10 queries)** | **4.2 ms** | **181 B** |

Index build is 10–170 ms for these repos, amortized across every later query.

## What this settles

**No daemon is needed.** A cold CLI invocation loads the whole index in ~2 ms,
already 15–100× faster than one `grep`. The lifecycle complexity of a watcher
process — codemap runs one, and it is not running right now — buys a further
2 ms that nobody will notice.

**The win is latency and precision, not raw bytes.** Against a *perfectly
targeted* grep the payload is about the same (181 B vs 202 B). The index wins
because the agent does not have to know the perfect pattern, gets exact spans
(`file:179-261`) instead of a blind ±50 lines, and pays no process spawn.

**Negatives become authoritative.** "No symbol named `x` among 3,664 indexed"
is a real answer in ~60 bytes. `grep` returning nothing is not, which is why
agents re-check it two more ways.

## Known limits

- **The extractor is a line scanner, not a parser.** It was built this way on
  purpose: extraction quality affects index *build* time, which is amortized,
  and not the query latency or payload this prototype measures. Swapping in
  tree-sitter would not move the numbers above.
- 100% recall against a regex ground truth on this repo's Rust — but that
  compares one regex to another. It says nothing about macro-generated code,
  braces inside strings, or conditional compilation, all of which will fool it.
- JSON index at ~3.2 µs/KB load. Fine to ~1 MB; past roughly 20k symbols a
  binary format starts to matter.
- Definitions only. No references, no call graph, no cross-file resolution —
  that is what LSP-backed tools do better.

## Usage

```bash
pkx index <repo>      # build + persist to <repo>/.portkit/cache/
pkx sym <name> [repo] # cold query
pkx bench <repo>      # comparison harness vs grep
pkx serve <repo>      # warm loop; names on stdin, for steady-state timing
```
