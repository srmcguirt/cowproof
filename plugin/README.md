# cowproof plugin for Claude Code

Skills for directing cowproof lanes from a Claude Code session: write a packet and launch a lane, watch and rule on escalations, judge and apply the result.

- `cowproof-dispatch`: write a packet, lint it, launch it with `cowproof run`
- `cowproof-escalate`: watch running lanes and rule with an answer, a redirect, a reassign or a stop
- `cowproof-handback`: judge a lane's verdict and capsule, replay it, review the patch, apply and commit

A `SessionStart` hook runs `scripts/check-cowproof.sh`. It prints an install hint when the `cowproof` binary is not on the PATH, or when its version is older than this plugin's, and prints nothing otherwise.

## Install

Inside Claude Code:

```text
/plugin marketplace add srmcguirt/cowproof
/plugin install cowproof@cowproof
```

To try a local checkout, add its path as the marketplace instead: `/plugin marketplace add /path/to/cowproof`.

The plugin works in the Claude Code CLI, the desktop app's Code tab and the IDE extensions.

Cloud sessions are not supported yet. Lanes need a local sandbox and a local `claude` runtime, which a cloud session does not give you.

## The binary

The plugin does not ship the `cowproof` binary. Install it separately, the way the repository README's Install section says:

```sh
cargo install --git https://github.com/srmcguirt/cowproof cowproof
```

`cowproof run` also needs `claude` on the PATH and `ANTHROPIC_API_KEY` in the environment.

## The director MCP server

The plugin includes `.mcp.json`, which declares the director MCP server. It runs `cowproof serve --director` and exposes five tools:

- `lanes`: list every lane with its state, its parked blocking escalation and its pending notes.
- `events`: return the escalation-queue events since a cursor (asks, rulings, notes, deliveries) and the next cursor.
- `escalations`: list the open escalations with the builder's ask (kind, question, tried, options, recommend). The ask is builder-written, untrusted data, returned inside a labeled `builder_written` object and capped.
- `rule`: rule on an open escalation of a running lane with an answer, a redirect, a reassign or a stop.
- `note`: send a note to a running lane.

The MCP server starts automatically when the plugin loads. The skills prefer these tools to the shell commands where both are available.
