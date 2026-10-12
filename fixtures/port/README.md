# Port packet fixture

A `kind: port` packet whose reference is a shell script (`project/reference/text.sh`) and whose port is a Rust tool the builder writes (`tools/text.rs`, registered as two plugins in `.portkit/plugins.toml`).

- `project/`: the repository the lane starts from. `ports/upper/cases.jsonl` are the visible cases and `ports/upper/fixtures/` what the reference did on them (recorded with `cowproof pk port capture --cmd 'sh reference/text.sh'`).
- `heldout/`: the director's held-out port cases, kept outside the repository and passed with `--heldout`. `heldout.toml` names the cases file beside it.
- `packet.md`: the packet. The text is the builder's prompt.

`crates/cowproof-cli/tests/port_packets.rs` runs it offline with scripted builders and a FAKE `claude`.
