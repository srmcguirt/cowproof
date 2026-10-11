# cowproof

Run many AI builders in parallel on one project, each in its own copy-on-write clone, under a director that lets nothing land until it is proven.

- **COW**: every lane runs on a copy-on-write clone of your repository's object store (with a fresh working tree checkout of the base commit), inside an OS sandbox.
- **Proof**: every lane hands back a patch plus a proof capsule: checks re-run by a verifier the builder never controlled, which any machine can replay.
- **Cow-proof**: builders work in their own clones and cannot touch your real tree.

## Install

One install provides three binaries:

```bash
cargo install --git https://github.com/srmcguirt/cowproof cowproof-cli
```

or, from a checkout, `cargo install --path crates/cowproof-cli`. This installs `cowproof`, `pk` (for portkit commands), and `pk-read` (for session-aware file reading).

The package is named `cowproof-cli` and is not on crates.io yet; renaming it to `cowproof` is in the backlog.

Status: design stage. Nothing here is ready to use yet. See [docs/design.md](docs/design.md).

## Install as a Claude Code plugin

Inside Claude Code:

```text
/plugin marketplace add srmcguirt/cowproof
/plugin install cowproof@cowproof
```

The plugin adds three skills for directing lanes: `cowproof-dispatch` (write a packet and launch a lane), `cowproof-escalate` (watch and rule on escalations) and `cowproof-handback` (judge, verify and apply a lane's result). A session-start hook tells you when the binary is missing or out of date.

It works in the Claude Code CLI, the desktop app's Code tab and the IDE extensions. Cloud sessions are not supported yet, because lanes need a local sandbox.

The plugin does not include the binaries. Install them as described under Install above:

```sh
cargo install --git https://github.com/srmcguirt/cowproof cowproof-cli
```

See [plugin/README.md](plugin/README.md) for details.

## License

MIT. See [LICENSE](LICENSE).
