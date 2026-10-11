---
name: cowproof-dispatch
description: Write a self-contained cowproof lane packet, lint it, and launch it with `cowproof run` as a tracked background command. Use when you have a bounded coding task to hand to an isolated builder and want proof, not a claim, that it works.
---

# cowproof-dispatch

Hand one bounded task to a builder that works in its own copy-on-write clone of the repository, under an OS sandbox. When the builder stops, cowproof replays the checks it recorded in a fresh sandbox, runs the gates, and writes a verdict. You judge the result with `cowproof-handback`.

## Before you launch

- The `cowproof` binary is installed and `claude` (Claude Code, the builder's runtime) is on the PATH, or named with `--claude-bin`.
- `ANTHROPIC_API_KEY` is set in the environment that runs `cowproof run`. The run stops at once without it.
- The repository's working tree is clean. A dirty tree is refused unless you pass `--allow-dirty`, which records the uncommitted changes as the lane's base patch. A dirty `.env*` file is refused even then: commit it or add it to `.gitignore`.
- Dispatch from a committed tree, and do not send two lanes at the same files.
- The lane id is new. A lane directory that already exists for that id is refused and left alone.

## Packet format

A packet is a Markdown file. It starts with a JSON header inside an HTML comment, then plain task text, then a `## Checks` section.

```markdown
<!-- lane {
  "id": "add-greeting",
  "owns": ["src/greeting.rs", "tests/greeting.rs", "docs/handoffs/add-greeting.md"],
  "allow": ["cargo *"],
  "checks": [
    { "id": "build", "command": "cargo build --locked" },
    { "id": "test", "command": "cargo test --locked" }
  ]
} -->

# Add a greeting function

Add `src/greeting.rs` with a public `greeting(name: &str) -> String` that
returns `Hello, <name>!`, and declare the module from the crate root.
Cover it with a test in `tests/greeting.rs` that calls the real function.
Write your handoff to `docs/handoffs/add-greeting.md`.

## Checks

- `cargo build --locked`
- `cargo test --locked`
```

Header fields, camelCase:

- `id`: lowercase letters, digits and dashes, 2 to 61 characters. It names the lane directory and prefixes every escalation id.
- `owns`: required, at least one path or glob. The ownership gate fails any patch that touches a path outside it. `.env*` is never ownable.
- Put the handoff path in `owns`. The builder is told to write a handoff in its clone, and the ownership gate counts that file like any other, so an unowned handoff fails the lane. Say in the task text where it goes.
- `checks`: each has an `id` (`[a-z0-9][a-z0-9_-]{0,63}`, unique), a `command`, and optionally `"flaky": true`. These are the proof gates. The builder runs them through its `run_check` tool, and the verifier replays them.
- `allow`: command patterns (for example `"cargo *"`). While the lane is not wide, `cowproof lint` rejects a check command in the `## Checks` section that no pattern matches.
- `appendOnly`: optional map of path to the most lines the patch may remove from it.
- `class`: optional, one of `rust`, `crate`, `pg`, `light` (default `light`).

The model, turn limit and cost cap are not header fields: they are `cowproof run` flags. The builder gets its tools (`ask`, `check_ruling`, `run_check`) and the protocol rules from cowproof itself, so a packet must not restate them (lint rejects it). It states the task, the reuse you expect, what is out of scope, and the checks.

Lint refuses secrets and `.env` paths in a packet, a check pipeline that ends in `head`, `tail` or `grep` (it hides the command's exit status), an owned path whose parent folder does not exist, and a check that names a file missing from the repository (unless the lane owns it).

## Lint, then launch

```sh
cowproof lint packet.md --repo <repo-path>
```

Exit 0 means no errors. Warnings, such as a check command missing from the `## Checks` section, print but do not fail it.

```sh
cowproof run packet.md --repo <repo-path>
```

`cowproof run` lints first, makes the lane directory, starts the builder and blocks until the lane is proved. Run it with the Bash tool's `run_in_background` option, so a lane that takes an hour does not hold your session. Do not add a trailing `&`.

Useful flags, with their defaults from `cowproof run --help`:

- `--model <name>`: the builder model (default `haiku`).
- `--max-turns <n>`: hard cap on builder turns per session (60).
- `--turn-budget <n>`: escalate early when the builder reaches this many assistant turns (40).
- `--cost-cap-usd <usd>`: the lane's cost cap (5). It is a trigger, not a hard stop: at 40% of it, on an estimate, the lane escalates.
- `--allow-dirty`: record uncommitted changes as the base patch.
- `--lanes-root <dir>`: where lanes live (default `~/.cache/cowproof/lanes`). Pass the same value to `watch`, `rule` and `note`.
- `--heldout <file>`: held-out checks, kept outside the repository and never shown to the builder. The runner copies the file into the capsule, and `cowproof verify` runs it.

Escalations arrive while the lane runs. Rule on them with `cowproof-escalate`.

## What the run writes

The lane is `<lanes-root>/<id>/`, holding `clone/` (the builder's repository), `home/`, `scratch/`, `sock/` and `control/`. When the run ends, `control/` holds:

- `run.json`: how the builder ended (`finished`, `failed`, `stopped`, `escalation-limit` or `interrupted`), turns, estimated cost and the paths of the other files.
- `lane.patch`: the builder's changes against the launch baseline.
- `verdict.json` and `capsule/`: written when the builder ended cleanly and the proof step ran. A lane that was stopped, failed or hit its escalation limit has `run.json` and `lane.patch` but no verdict.

The command prints a builder summary line, then a one-line verdict such as `add-greeting: proved`. Exit codes:

- 0 proved
- 2 refuted (a recorded check failed, verify diverged, or a gate failed)
- 3 incomplete (a declared check was never run)
- 4 infrastructure (the proof could not run; never a refutation)
- 1 the run failed before a verdict
- 130 interrupted

Continue with `cowproof-handback`.
