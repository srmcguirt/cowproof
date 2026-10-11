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

`cowproof doctor` checks that this host can run lanes (the sandbox actually starts a program, copy-on-write cloning, free disk, the `claude` binary, `ANTHROPIC_API_KEY`, a committed repository) and exits 1 when a check fails; `cowproof run` runs the same checks first and stops with exit 4 before it creates a lane.

## What a builder trusts

A builder trusts what its repository tells it, and that can be hostile.

- **The repository's `CLAUDE.md` steers the builder.** The runner passes the root `CLAUDE.md`, as committed in the lane's base commit, to the builder as its project instructions. A hostile repository can therefore tell a builder to do something harmful, and the builder may obey. The instructions are not vetted, trusted or harmless.
- **Only the committed file reaches it.** The runner reads `CLAUDE.md` from the base commit, never from the director's working tree. Uncommitted edits, and commits made after the lane started, never reach the builder. A base commit with no `CLAUDE.md` gives the builder no project instructions. A committed symlink such as `CLAUDE.md -> AGENTS.md` is followed inside the base commit (a few hops, no loops), and the builder gets the target file's committed bytes. A link that is absolute, leaves the repository, dangles or points at a directory gives no instructions and a warning, and the run goes on. The working tree is never consulted.
- **The gates contain the effect, not the prompt.** Nothing filters what the instructions say. The ownership gate, the protected paths, the held-out checks and the verifier decide whether the resulting patch is accepted. A builder that obeys a hostile `CLAUDE.md` and writes outside its lane is refuted by the gates, as it was in a live run.
- **The global Claude config is isolated.** A live run with a global `CLAUDE.md` and a global hook in the director's home showed that neither reached the builder. Only the repository's committed `CLAUDE.md` does.

Each run records what the builder was given. `run.json` has `prefixVersion`, the SHA-256 of the builder preamble, and `projectInstructionsSha256`, the SHA-256 of the instructions the builder received (null when there were none). The capsule records the same two values as `prefix_version` and `project_instructions_sha256` in `capsule.json`, which the capsule's seal covers.

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
