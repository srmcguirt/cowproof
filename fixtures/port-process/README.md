# Process capture example

A `kind: port` packet whose reference is a shell script captured as a whole process (`pk port exec`, `"adapter":"process"`, `"lang":"shell"`), and whose port is a Rust program the builder writes (`tools/greet.rs`), replayed through `pk port wrap`.

- `project/`: the repository the lane starts from. `reference/greet.sh` is the script (POSIX `sh`: it runs under dash and bash). `ports/greet/cases.jsonl` are the visible cases and `ports/greet/fixtures/` what the script did on them, captured with
  `cowproof pk port exec --cmd 'sh "$PORTKIT_SRC/reference/greet.sh"' --cases ports/greet/cases.jsonl --out ports/greet/fixtures --path-root '$ROOT' --path-root '$HOME' --path-root '$TMP'`.
  The `source` and `captured_at` of a fixture name the machine and time; a test recaptures and compares everything else.
- `heldout/`: the director's held-out cases, passed with `--heldout`.
- `packet.md`: the packet.

`crates/cowproof-cli/tests/port_process.rs` runs it offline with a FAKE `claude`.
