# Port the text tools to Rust

<!-- lane {"id":"port-1","kind":"port","class":"light","owns":["tools/**",".portkit/plugins.toml","ports/upper/cases.jsonl","ports/upper/fixtures/**"],"allow":["mkdir*","rustc*","cowproof pk port*"],"maxCostUsd":1.0,"timeoutMin":15,"port":{"lang":"shell","adapter":"function","reference":{"cmd":"sh reference/text.sh","runtime":"sh"},"cases":"ports/upper/cases.jsonl","fixtures":"ports/upper/fixtures","tools":["upper","shout"]},"checks":[{"id":"build","command":"mkdir -p target && rustc --edition 2021 tools/text.rs -o target/text"}]} -->

## Task

`reference/text.sh` answers two tools: `upper` upper-cases the `text` of its input, and `shout` does the same and adds `!`. Port both to one Rust program, `tools/text.rs`, that speaks portkit's plugin contract: `target/text <tool> --portkit-spec` prints the tool's spec, and `target/text <tool>` reads one request on stdin and prints one JSON result.

Register the tools `upper` and `shout` in `.portkit/plugins.toml`, one `[[plugin]]` entry each with `command = "target/text"` and the tool name as its only argument. The fixtures under `ports/upper/fixtures/` hold what the reference did; the port must answer every one of them exactly.

## Checks

- `mkdir -p target && rustc --edition 2021 tools/text.rs -o target/text`
