# Capture adapter examples

Worked examples for portkit's function-level capture adapters (`pk port adapter node|python`), run by `crates/cowproof-cli/tests/port_adapters.rs` against the real `node`, `python3`, `pk` and `rustc`.

- `node/`: `tally.mjs` (and the same module as `tally.ts`) counts words into an object. The trap is key order: JavaScript lists integer-like keys first whatever the insertion order, and the adapter prints keys sorted, so fixtures do not depend on the engine. `cases.jsonl` are the cases to capture with `node adapter.mjs tally.mjs`.
- `python/project/`: the repository a `kind: port` lane starts from. `reference/shipping.py` is the module, `reference/adapter.py` is portkit's Python adapter unchanged (a test checks the copy against the shipped file), `ports/shipping/fixtures/` was captured through it. The trap is a float: Python's `round(0.125, 2)` is 0.12 (an exact tie rounds to even) and `0.1 + 0.2` is `0.30000000000000004`; a port that rounds half away from zero is refuted at epsilon 0.
- `python/heldout/`: the director's held-out cases, passed to `cowproof run` with `--heldout`.
- `python/packet.md`: the packet (`"lang":"python"`, `"adapter":"function"`), with the clock and seed pinned through `port.reference.env`.
