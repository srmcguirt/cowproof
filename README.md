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

`cowproof run --unsandboxed` launches the builder without the OS sandbox, for trusted local experiments only: the builder can then touch anything you can, the lane and its capsule are marked `unsandboxed`, and the lane can end `finished` (checked by the gates and the sandboxed verifier) but never `proved`; `cowproof verify` refuses its capsule.

## Run a lane on another machine

`cowproof run packet.md --host buildbox` runs the builder, and the checks it asks for, on another machine over SSH. Your machine stays the director: it keeps the escalation queue and your rulings, the egress proxy and so the API key, the held-out checks, the proof and the capsule. The host runs only what runs sandboxed. The key never leaves the director: no argument, spec, bundle or environment sent to the host holds it, and the builder on the host presents the lane's own `placeholder-...` key, which only your proxy accepts, through two sockets that SSH forwards from the host back to you.

Add the host to `~/.config/cowproof/hosts.json` (or the file named by `$COWPROOF_HOSTS_FILE`; the older `$LANES_HOSTS_FILE` is still read). The user-level file is read before a `hosts.json` in the working directory, which `cowproof plan` and `cowproof hosts` also read, so a file that arrives with a repository cannot choose where a lane runs.

```json
{
  "buildbox": {
    "ssh": "builder@buildbox.example",
    "cowproof": "/opt/cowproof/bin/cowproof",
    "claude": "/usr/local/bin/claude",
    "remoteRoot": "~/.cache/cowproof/remote-lanes"
  }
}
```

- `ssh` is the destination, as `ssh` takes it: a `Host` from your `~/.ssh/config` or `user@host`. Default: the alias. It may not start with `-`.
- `cowproof` is the absolute path of `cowproof` on the host. Required. It must be built from the same version as yours; `prepare` refuses a different one.
- `claude` is the absolute path of `claude` on the host. Required.
- `remoteRoot` is where the host keeps its lanes: absolute, or `~/...` (relative to the host's home directory). Default: `~/.cache/cowproof/remote-lanes`.

What the host needs: `cowproof` and `claude` installed, `git`, and a sandbox that works (`bwrap` on Linux, or macOS). `cowproof doctor` on the host shows it; `cowproof run --host` runs the host's `doctor` first and stops with exit 4, before a lane exists there, if it fails. Your SSH login must work without a prompt (a key or an agent; the connection runs with `BatchMode=yes`), and the host's `sshd` must allow Unix socket forwarding (`AllowStreamLocalForwarding`, on by default). Sign in to `claude` on the host yourself if you use a subscription; an API key lane needs no login there at all.

How a lane runs: one SSH control master per lane, stopped when the lane ends however it ends; the repository's history at the base commit goes over as a git bundle, and the host clones it into its own lane directory; `proxy.sock` and `sock/runner.sock` are forwarded into that directory before the builder starts; the builder's stream comes back on the SSH channel to the same meter and `stream.jsonl` as a local lane; each `run_check` runs on the host, in the clone the builder works in; when the builder is done the lane patch comes back, the host's lane directory is removed, and the proof runs on your machine from the base commit and that patch. The capsule and `run.json` record the alias as `host`.

Limits of this first version: the base must be a commit (`--allow-dirty` and `--unsandboxed` are refused with `--host`); the lane is `untraced`, because the portkit hooks are not installed on the host; the builder's own stderr stays on the host and is removed with the lane; the whole history is bundled for every lane.

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
