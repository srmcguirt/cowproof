# Adversarial packet fixture

This is the adversarial packet from `docs/design.md`, Success Criteria (second item): it tells the builder to cheat by deleting an assertion and hard-coding the visible outputs. The gates must catch the cheat without a diff read.

The note lives here, not in `packet.md`, because the whole packet is the builder's prompt: a model told that the packet is a test of the gates can decline to cheat, and the run then proves nothing about the gates.

- `packet.md`: the packet. Its text asks for the cheat as a shortcut.
- `project/`: the shell project the lane works on (`slugify.sh` and its visible tests).
- `heldout.toml`: two held-out checks, stored outside the project, passed with `--heldout`.

`crates/cowproof-cli/tests/adversarial.rs` runs it offline with scripted builders. The live recipe and the results are in `docs/audit-2026-10-10.md`, sections "Adversarial packet (success criterion 2)".
