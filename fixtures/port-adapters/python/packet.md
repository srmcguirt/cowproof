# Port the shipping calculator to Rust

<!-- lane {"id":"port-1","kind":"port","class":"light","owns":["tools/**",".portkit/plugins.toml","ports/shipping/cases.jsonl","ports/shipping/fixtures/**"],"allow":["mkdir*","rustc*","cowproof pk port*"],"maxCostUsd":1.0,"timeoutMin":15,"port":{"lang":"python","adapter":"function","reference":{"cmd":"python3 reference/adapter.py reference/shipping.py","env":{"PORTKIT_NOW":"2026-01-02T03:04:05Z","PORTKIT_SEED":"1"},"runtime":"python3"},"cases":"ports/shipping/cases.jsonl","fixtures":"ports/shipping/fixtures","tools":["quote","total","__defaults"]},"checks":[{"id":"build","command":"mkdir -p target && rustc --edition 2021 tools/ship.rs -o target/ship"}]} -->

## Task

`reference/shipping.py` is a Python module with two functions, `quote` and `total`, and two constants. `reference/adapter.py` (portkit's Python adapter, unchanged) makes it speak portkit's contract, so the fixtures under `ports/shipping/fixtures/` hold exactly what the module did, with its clock and randomness pinned: `quote` charges `kg` times the rate and rounds to cents the way Python's `round` does, `total` sums the `charges`, and `__defaults` answers the module's constants.

Port all three to one Rust program, `tools/ship.rs`, that speaks portkit's plugin contract: `target/ship <tool> --portkit-spec` prints the tool's spec, and `target/ship <tool>` reads one request on stdin and prints one JSON result. Register `quote`, `total` and `__defaults` in `.portkit/plugins.toml`, one `[[plugin]]` entry each with `command = "target/ship"` and the tool name as its only argument. The port must answer every fixture exactly: parity is checked with epsilon 0.

## Checks

- `mkdir -p target && rustc --edition 2021 tools/ship.rs -o target/ship`
