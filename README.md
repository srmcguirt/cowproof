# cowproof

Run many AI builders in parallel on one project, each in its own copy-on-write clone, under a director that lets nothing land until it is proven.

- **COW**: every lane runs on a copy-on-write clone of your repository's object store (with a fresh working tree checkout of the base commit), inside an OS sandbox.
- **Proof**: every lane hands back a patch plus a proof capsule: checks re-run by a verifier the builder never controlled, which any machine can replay.
- **Cow-proof**: builders work in their own clones and cannot touch your real tree.

## Install

One install provides three binaries:

```bash
cargo install --path crates/cowproof-cli
```

This installs `cowproof`, `pk` (for portkit commands), and `pk-read` (for session-aware file reading).

Note: The package name is `cowproof-cli`, so the full install is `cargo install cowproof-cli`. (This will be renamed to `cowproof` in a later release.)

Status: design stage. Nothing here is ready to use yet. See [docs/design.md](docs/design.md).

## License

MIT. See [LICENSE](LICENSE).
