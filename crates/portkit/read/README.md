# portkit-read

`pk-read` returns only what the caller does not already have.

## Why this and not a `sed` port

`sed -n 'A,Bp' file` is the largest single shell fingerprint in 878 measured
sessions: **397 calls, 1.83 MB**. Porting it to Rust would save nothing —
`sed` is already C, and a byte-equal port returns byte-equal tokens.

The saving is in what comes back. But the first measurement said 0.0%, because
keying on the exact `(path, start, end)` tuple found **zero** repeats. Keying
on line *coverage* found the real pattern: **53 of 113 consecutive range pairs
overlap**. The agent re-reads territory it has, with shifted boundaries.

Corpus-wide projection on that basis: **4.9%**. Small, and worth saying so.
What it also buys is a verified rewrite path for bigger replacements to ride on.

## Emit contract

| case | emitted |
| --- | --- |
| Fully held, file fresh, after the watermark | `UNCHANGED L40-80 sha:ab12` + recovery |
| Partially held | `KNOWN L60-80` per covered sub-interval, then only the uncovered lines |
| File changed, or before the watermark | Full content, intervals reset |

Every withheld answer names its recovery (`--full`), for the same reason the
output budget does: "truncated" with no next step sends the caller to get it
another way, and the saving is only relocated.

## The dangerous class

`UNCHANGED` is a claim about **the caller's context**, not about a stored
value, and it is the one fidelity class that can produce a *silent* wrong
answer — the agent proceeds on stale content believing it is current. Every
other class degrades to "less than you asked for", which is recoverable.

So it is emitted only when all three hold:

```
blake3(current file) == recorded hash      file has not changed
AND the range is covered by prior delivery
AND delivered_at > compacted_at             still in the caller's context
```

Freshness is **file-level**, not per range: range hashes do not compose across
overlaps, a whole-file hash does. Any doubt sends the content.

## Compaction

`delivered` means "sent", not "still in context" — context compaction drops old
tool results, so a reference becomes wrong exactly when a re-read matters most.
`pk hook pre-compact` (and `session-start`, for resumed sessions) writes a
watermark; anything delivered before it stops counting. The reference class is
unsafe without this, so it shipped in the same change.

## Usage

```bash
pk-read --range 40:80 src/api.ts    # minus what was already sent
pk-read --ls dir/                    # names and sizes, not `ls -la` columns
pk-read --range 40:80 f.ts --full    # everything, ignoring session state
pk-read --compacted                  # watermark
```

Session identity comes from `PORTKIT_SESSION`, which the hook sets from the
payload's `session_id`. Unset means every call is a first call — the safe
direction to fail.

## Status

`--range` and `--ls` are implemented and tested. The `normalized` rule was
dropped: it measured 366 bytes of 639 KB, because source code is already
formatted.
