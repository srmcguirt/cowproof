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

## Choose the builder: `[ladder]` and `[routing]`

A builder is a runtime and a model, written `runtime:model` and called a rung. The ladder is the ordered list of rungs a `reassign` climbs, and routing says which rung a lane starts on. Both are read from `cowproof.toml` in the lane's base commit, never from a working tree, so a lane cannot rewrite its own routing (the class limits work the same way).

```toml
[ladder]
rungs = ["claude:haiku", "claude:sonnet", "claude:opus"]   # the default when there is no [ladder]

[routing]
default = "claude:haiku"                  # the first rung, unless you say otherwise
classes = { rust = "claude:sonnet", pg = "claude:sonnet" }
```

- A rung is `runtime:model`. The runtime is one of `claude`, `openrouter`, `codex`. The model is a name of letters, digits and `.` `_` `-` `:` `[` `]` `/`, at most 64 characters, never starting with `-`. A bare `haiku` is read as `claude:haiku`. The first `:` ends the runtime, so a model name that contains a `:` needs the `claude:` prefix.
- The ladder may not be empty or list a rung twice. A table with an unknown key, an unknown runtime, a bad model name, a class that is not `rust`, `crate`, `pg` or `light`, or a routing rung that is not on the ladder is an error.
- The starting rung is, in order: `cowproof run --model` (when given; it need not be on the ladder), the packet header's `"rung": "claude:sonnet"`, the `[routing] classes` entry for the packet's class, then `[routing] default`. `run.json` records the runtime and model of every segment, and `rungSource` (`flag`, `header`, `class` or `default`); the capsule records `builder_runtime` and `rung_source` beside `builder_model`.
- A header rung that is not on the ladder is an error in `cowproof lint`, and `cowproof run` refuses it with exit 4, naming the rung, before it creates a lane. So does a ladder or routing that does not parse.
- `reassign` without a model moves one rung up the ladder. At the top, the lane ends as it always has: refused, the work kept, the ruling left undelivered.

The `claude` and `openrouter` runtimes have an adapter ([OpenRouter models through OpenCode](#openrouter-models-through-opencode) below). The ladder may list `codex` rungs, but a lane that would start on one is refused with exit 4 ("runtime `codex` has no adapter yet (D28 step 1)"), and a `reassign` that would land on one ends the lane the way the top of the ladder does. So does a `reassign` onto a rung that cannot run here: no `opencode` on `PATH`, no `OPENROUTER_API_KEY`, no `claude` or `ANTHROPIC_API_KEY`, or a remote lane.

## Packet profiles per rung

A cheaper model needs more from its packet: the exact tests to write, the exact mutations to try, and a numbered list that says when it is done. A *profile* is a named list of requirements, and `[routing.profiles]` maps a rung to one. `cowproof lint` then requires that rung's profile of a packet. A profile shapes the packet only: the gates and the proof are the same whichever model wrote the patch. Like the ladder, profiles are read from `cowproof.toml` in the lane's base commit, never from a working tree.

```toml
[profiles.strict]
require = ["tests", "mutations", "done-checklist"]
[profiles.standard]
require = ["checks"]
[routing.profiles]
"claude:haiku" = "strict"
"openrouter:z-ai/glm-5.3-flash" = "strict"
```

With no `[profiles]` and no `[routing.profiles]` nothing is required, as before. A rung with no route is required nothing, even when profiles exist. The parse is strict: an unknown key, an unknown requirement name, a requirement listed twice, a route for a rung that is not on the ladder (or the same rung twice), and a route naming a profile that `[profiles]` does not define are all errors, reported by `cowproof lint` as rule `profile`.

The requirements are a closed set. Each is a plain check of the packet text, with no model involved, and none grades quality. A heading is a Markdown line of `#` marks and a space (not inside a fenced block); a section runs to the next heading of the same or a higher level.

| Requirement | The packet needs |
| --- | --- |
| `tests` | A section whose heading starts with the word "Tests" (for example `## Tests`) holding a list item or paragraph that names a test in backticks (an identifier, or `module::name`) and has at least four other words, the sentence that says what it asserts. |
| `mutations` | A section whose heading starts with the word "Mutations" holding at least one list item with text, or a non-blank line inside a fenced block (the exact mutation command). |
| `done-checklist` | A numbered list item (`1.` or `1)`) under a heading that contains the word "Done", for example `## Done checklist`. A bulleted list does not count. |
| `checks` | The header's `checks` is not empty. |

`cowproof lint` resolves the packet's starting rung the way `cowproof run` does: the header's `rung`, else the `[routing] classes` entry for its class, else the default. It reports each requirement of that rung's profile the packet does not meet as an error, naming the requirement and what to add:

```
error [profile]: mutations: profile "strict" for rung claude:haiku (the header chose it) requires mutations; add a "## Mutations" section with at least one item: ...
```

`cowproof run` lints first and stops on a lint error, so a packet that lacks a requirement of its rung's profile does not start: no lane directory exists. Lint has no `--model`, so it checks the rung the header, the class route or the default names. `cowproof run --model` can start the lane on another rung, and lint does not check that rung's profile. A `reassign` onto a higher rung does not re-lint the packet either.

## OpenRouter models through OpenCode

A rung `openrouter:<model>` (for example `openrouter:z-ai/glm-5.3-flash`) runs the model through [OpenCode](https://opencode.ai), not Claude Code: OpenRouter's own Claude Code integration is only guaranteed to work with Anthropic models. The runner, the sandbox, the queue, the checks and the proof are the same as for a Claude lane; only the builder's launcher, its event parser and the provider the proxy forwards to differ.

**Setup.** Install `opencode` (tested against 1.18.33), then put your OpenRouter key in the environment of the shell that runs `cowproof`:

```sh
export OPENROUTER_API_KEY=sk-or-v1-...       # yours; read once, held by the proxy
cowproof run packet.md --model openrouter:z-ai/glm-5.3-flash
```

or name the rung in the ladder, the header or a class route (`openrouter:z-ai/glm-5.3-flash` is a valid model name: `/` is allowed). `--opencode-bin <path>` names the executable when it is not `opencode` on `PATH`. A lane that starts on an `openrouter` rung needs `opencode` and `OPENROUTER_API_KEY` and does not need `claude` or `ANTHROPIC_API_KEY`; the other provider's key only lets a later `reassign` cross runtimes, because one proxy per lane serves both.

**What the lane sees.** A placeholder, never your key. The lane's `home/opencode.json` points OpenCode's `openrouter` provider at the in-sandbox bridge (`http://127.0.0.1:<port>/api/v1`) with the lane's `placeholder-...` as its API key. The proxy accepts that placeholder on `POST /api/v1/chat/completions`, the one path OpenCode uses, replaces it with `Authorization: Bearer <your key>` and forwards to `https://openrouter.ai`. Any other path or method, and any request that carries a credential other than the placeholder, is refused with 403 and goes nowhere. The OS sandbox is the same as for Claude, so the lane reaches no other host either.

- **Permissions.** OpenCode is configured, never run with `--auto`. The permission block is default-deny, then allows `edit` (which covers `write`), `read`, `bash`, `glob` and `grep` inside the clone, and the three cowproof tools (`cowproof-tools_ask`, `cowproof-tools_check_ruling`, `cowproof-tools_run_check`); `external_directory` is denied, and `webfetch`, `websearch`, `task` and `skill` are denied by name. The model is not even offered a denied tool. OpenCode is told to ignore the clone's own `opencode.json` and `.opencode/` (`OPENCODE_DISABLE_PROJECT_CONFIG`), so nothing the builder writes there can change the endpoint or loosen the permissions; as a second line the block is passed as `OPENCODE_PERMISSION` and the config as `OPENCODE_CONFIG_CONTENT`, which OpenCode applies after any project file, and the config file is rewritten before every launch.
- **Offline.** OpenCode's own network habits are switched off: no model catalog fetch (the config defines the one model it runs, with its fetched context limit and price), no update check, no sharing, no LSP downloads, no title request to a second model. Its background install of `@opencode-ai/plugin` has no flag; it is pointed at an offline npm configuration instead, so it never leaves the machine.
- **Prompt and session.** The packet is OpenCode's first message, sent on stdin (OpenCode would quote and escape a multi-line argument). A ruling resumes the same OpenCode session with `-s <session id>` and the ruling as the message; the session id is the `sessionID` every event carries. If the session is gone, the existing D9 fallback starts a fresh session with a carry-over summary.
- **Price and cost.** OpenCode computes the cost of each model call from the price in its config, and the cost cap acts on that figure, so the price must be true. `cowproof run` fetches it from OpenRouter itself: once, at preflight, `GET <upstream>/api/v1/models` with your `OPENROUTER_API_KEY` (a request the director makes directly, not through the lane's proxy, with a 15 s limit and an 8 MiB cap on the answer). It does this when the lane starts on an `openrouter` rung, and also when an `openrouter` rung sits above the start rung on the ladder, because a `reassign` can land there. The model's `id` is matched exactly and case-sensitively (no family or substring match). From the entry it reads `pricing.prompt`, `pricing.completion`, and `pricing.input_cache_read` and `pricing.input_cache_write` when listed (decimal strings in USD per token, converted to USD per million tokens by moving the decimal point, so `"0.00000123"` is exactly `1.23`), `context_length` and `top_provider.max_completion_tokens`. A cache price that is not listed is priced as the plain input price; a missing context or output limit becomes 128k or 16k. Each such fallback is named in the record's `defaulted` list. These figures are written into the lane's config and used for any turn whose cost OpenCode did not report, and `run.json` says `costSource: "reported"` when OpenCode computed every turn's cost from them and `"estimate"` otherwise. There is no built-in price table and no fallback price, so the run stops (exit 4, "nothing was started") when:
  - a model is not in the list, naming the id (a list that has `z-ai/glm-5.3` does not satisfy `z-ai/glm-5.3-flash`);
  - the list cannot be had: a network error, an HTTP status other than 200 (a wrong key is a 403), a body that is not a model list, an answer over 8 MiB, or no answer in 15 s. The message says the cost cap cannot be enforced without a price;
  - the entry has no `pricing.prompt` or `pricing.completion`, or a price that is negative or not a decimal number (the router models list `-1`), or a limit that is present but not a positive whole number.

  A `reassign` ruling that names an `openrouter` model that was not on the ladder at preflight is refused the way the top of the ladder is: the lane ends with its work kept, because its price was never read. Your key is not in the request's URL, the record or any message. (`COWPROOF_OPENROUTER_MODELS_TIMEOUT_MS` replaces the 15 s limit in milliseconds; it exists for the tests and is not otherwise supported.)
- **Recording.** `run.json` records `runtime: "openrouter"`, the OpenRouter model id, `runtimeVersion` (the output of `opencode --version`) and `price` for every segment, and `opencodeVersion` at the top. `price` holds `inputPerMillion`, `outputPerMillion`, `cacheReadPerMillion` and `cacheWritePerMillion` (USD), `contextLength`, `maxOutput`, `defaulted`, `source` (the path fetched, `/api/v1/models`; never the host or the key) and `fetchedAt` (UTC, to the second). The capsule records `builder_runtime`, `builder_runtime_version` and, for the last segment, the same record as `openrouter_price` (absent in older capsules, which still verify). If you set `COWPROOF_OPENROUTER_UPSTREAM`, `run.json` records `openrouterUpstream`.

`COWPROOF_OPENROUTER_UPSTREAM` replaces `https://openrouter.ai` as the proxy's upstream, for a test server or a self-hosted gateway. It is read from the environment and never from `cowproof.toml`, so repository content cannot redirect your key.

**Limits.** Remote lanes (`--host`) run Claude only: `--host` with an `openrouter` rung is refused with exit 4, naming the rung. OpenCode has no hooks, so an `openrouter` lane is untraced by portkit. The model's context limit and output limit come from the same fetched entry (128k and 16k when it lists none, recorded in `defaulted`), because OpenCode's bundled catalog does not list OpenRouter offline. The price is read once per run: a rate change during a long lane is not seen. The builder preamble names the tools `ask`, `check_ruling` and `run_check`; in OpenCode they are `cowproof-tools_ask` and so on, which the lane's instructions say. A provider that is unreachable makes OpenCode retry silently, so the lane ends at its wall-clock limit rather than at once. The Codex adapter and subscription logins are still to come.

## Tune the ladder from data: `cowproof report rollup`

Routing should come from measurement (D28 clause 4). `cowproof report rollup <lanes-root>...` reads every lane one level under each root and prints, for each starting rung and packet class, how the lanes did: first-try pass rate, proved rate, median and total cost, cost per proved lane, median turns and mean reassigns, then where the lanes that started on each rung ended. The numbers below come from synthetic lanes made by hand, not from real runs:

```text
Lane rollup: 12 counted of 14 lanes in 1 root

claude:haiku *
  class        lanes    1st-try     proved  med $ total $  $/prov turns reasg
  light            2   2/2 100%   2/2 100%  0.055   0.110   0.055   3.5  0.00
  rust             7    5/7 71%    6/7 86%  0.080   1.250   0.208     6  0.14

claude:sonnet
  class        lanes    1st-try     proved  med $ total $  $/prov turns reasg
  pg               1     0/1 0%   1/1 100%  2.400   2.400   2.400    21  1.00
  rust             1   1/1 100%   1/1 100%  0.500   0.500   0.500     8  0.00

openrouter:glm-5.3-flash
  class        lanes    1st-try     proved  med $ total $  $/prov turns reasg
  light            1     0/1 0%   1/1 100%  0.210   0.210   0.210    13  1.00

Climbed to (lanes by the rung they started on)
claude:haiku: 9 lanes, 1 climbed
  stayed on claude:haiku    8
  -> claude:sonnet          1
claude:sonnet: 2 lanes, 1 climbed
  stayed on claude:sonnet    1
  -> claude:opus             1
openrouter:glm-5.3-flash: 1 lane, 1 climbed
  -> claude:haiku    1

1st-try is proved with no reassign; proved is proved at all; $/prov is the
  group's cost over its proved lanes; reasg is the mean reassigns per lane.
Left out of every rate: running 1.
1 unsandboxed lane left out; --include-unsandboxed counts them (a finished
  unsandboxed lane then counts as proved).
* 1 lane from before D28 step 1 (no runtime field) counts as claude:<model>.
Cost is the runner's estimate, not a bill.
Starting rung came from: class 10, header 1, unknown 1.
```

What it reads and how it counts:

- **Only two files per lane:** `control/run.json` and `control/verdict.json`, one level under each root. No symlink is followed: a lane directory, its `control` directory or either file that is a link is skipped and counted as `symlink`. A lane with neither file (or an empty `control`) is `unreadable`, a malformed file is `malformed`, and neither stops the rollup. Text from the files is stripped of control characters before it is printed.
- **A lane before D28 step 1** has no `runtime`; it counts as `claude:<model>` and the table says so (the `*`).
- **A lane whose builder has not exited** has no `run.json` yet (a lane that exited and is being proved has one and no verdict), and is counted as `running`. It is in no rate. A lane that ended without a verdict (`timeout`, `cost-cap`, `failed`, `stopped`, `escalation-limit`) is counted as not proved. A `run.json` from a run that never started a builder is `never started` and is in no rate.
- **Start rung and final rung:** the start rung is the first segment's `runtime:model` and the final rung is the top-level `runtime:model`. A **reassign** is a segment on a different rung than the one before it, so a resume or a redirect on the same rung is not one.
- **First-try pass** means the lane is proved, has zero reassigns, and ended on the rung it started on. **Proved** means the verdict is `proved`. Lanes are grouped by the rung they started on, so a lane that climbed from haiku to sonnet counts against haiku.
- **Unsandboxed lanes** (they can end `finished`, never `proved`) are left out of the rates and counted. `--include-unsandboxed` counts them, and a `finished` verdict from an unsandboxed lane then counts as proved.
- **Cost** is the runner's estimate (`estimatedCostUsd`), not a bill. `$/prov` is the group's whole cost, failures included, over its proved lanes.
- **Remote lanes** are counted in the rates like any other and noted in the footer; `rungSource` shows how many starting rungs came from a flag, a header, a class route or the default.

`--json` prints the same numbers as one document (`counts`, `groups`, `climbed`, and one `lanes` row per counted lane with its first and final rung, class, cost, turns, reassigns, `host` and `unsandboxed`). Exit 0 when it prints; exit 1 when a root is not a directory. The plain table is at most 80 columns wide.

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

What the host needs: `cowproof` and `claude` installed, `git`, and a sandbox that works (`bwrap` on Linux, or macOS). `cowproof doctor` on the host shows it; `cowproof run --host` runs the host's `doctor` first and stops with exit 4, before a lane exists there, if it fails. Your SSH login must work without a prompt (a key or an agent; the connection runs with `BatchMode=yes`), and the host's `sshd` must allow Unix socket forwarding (`AllowStreamLocalForwarding`, on by default). To lock the director's key to `cowproof host-agent` instead of a full login, see "Locking the director's key to cowproof" below. Sign in to `claude` on the host yourself if you use a subscription; an API key lane needs no login there at all.

How a lane runs: one SSH control master per lane, stopped when the lane ends however it ends; the repository's history at the base commit goes over as a git bundle, and the host clones it into its own lane directory (with `--allow-dirty`, your uncommitted changes go with it as the same `base.patch` the proof applies, ahead of the bundle on the same stream); `proxy.sock` and `sock/runner.sock` are forwarded into that directory before the builder starts; the builder's stream comes back on the SSH channel to the same meter and `stream.jsonl` as a local lane, and your end keeps the builder's input open for as long as it should live, so a builder whose link dies (a closed laptop, a dropped connection) is ended on the host instead of left running; each `run_check` runs on the host, in the clone the builder works in; when the builder is done the lane patch comes back, the builder's stderr is fetched (the host redacted it, and your machine redacts it again) and appended to the lane's `control/builder.stderr`, the host's lane directory is removed, and the proof runs on your machine from the base commit and that patch. The capsule and `run.json` record the alias as `host`.

If your machine dies mid-run (SIGKILL, a crash, power loss), cleanup cannot run, and two things are left: the lane's SSH control master on your machine and the lane directory on the host. The remote builder itself still ends, because the host sees your input to it close. Each lane records its director and master (pid and start time) in `control/remote.json`, and the next `cowproof run --host <alias>` on the same lanes root sweeps what a dead director left: it stops the old master, has the host's `host-agent cleanup` remove the lane, marks the old lane `swept` in its `remote.json` (the local lane directory stays, as evidence) and prints one line for it. It never touches a lane whose director is still running (so two directors can share a lanes root), a lane of another alias, or a lane that finished. If the sweep fails it warns and your run goes on. On the host, `host-agent` records each builder's process group, and `cleanup`, `patch` and the next launch of the same lane end a group that is still stopping (SIGTERM, the same ten seconds of grace, then SIGKILL) before they go on, so a slow builder cannot write into a lane being removed or overlap a relaunch. A recorded group is signalled only when its leader is provably the same process (same pid and start time), never because a pid was reused.

Limits of this first version: `--unsandboxed` is refused with `--host`; the lane is `untraced`, because the portkit hooks are not installed on the host; the whole history is bundled for every lane. Your `cowproof` and the host's must speak the same host-agent protocol, which is part of being the same build: a host that does not stops the run with exit 4, before a lane exists there.

## Locking the director's key to cowproof

By default the key the director logs in with is an ordinary login key: whoever holds it can run any command on the host. The host's owner can lock it so that it runs `cowproof host-agent <verb>` and nothing else. This is done on the host, by its owner; the director never does it, and `cowproof` never edits `authorized_keys` for you.

Owner steps, on the host, as the user the director logs in as:

1. Get the director's PUBLIC key (the `.pub` file). Never copy a private key anywhere; `cowproof host setup` refuses one.
2. Run `cowproof host setup --key director.pub --ssh user@host --alias buildbox --write-config` (`--claude <path>` if `claude` is not on `PATH`). It prints the line for `~/.ssh/authorized_keys`, the `hosts.json` entry for the director with this machine's absolute paths, the host config below and this host's `host-agent doctor`, so you see whether `claude` and the sandbox work before the director tries. Without `--write-config` it writes nothing and only shows the config. It exits 1 when the doctor fails or the key file is not exactly one OpenSSH public key line.
3. Append the line to `~/.ssh/authorized_keys` (mode 600, `~/.ssh` mode 700). Remove any other line that holds the same key: an ordinary line for it still gives a full login.
4. Send the `hosts.json` entry to the director, who adds it to `~/.config/cowproof/hosts.json` and sets `ssh` to what its `ssh` calls this machine.

The host config in step 2 is what makes the key useful: see "The host config" below. Until it exists, the forced key refuses every verb except `doctor`.

The line looks like this:

```
command="/opt/cowproof/bin/cowproof host-agent --forced",restrict,port-forwarding,permitopen="127.0.0.1:1",permitlisten="127.0.0.1:1" ssh-ed25519 AAAA... director@laptop
```

`command=` makes `sshd` run `host-agent --forced` for every session of that key, whatever the client asked for, and put what it asked for in `SSH_ORIGINAL_COMMAND`. `host-agent --forced` accepts that text only if it is `<path>/cowproof host-agent <verb> <arguments>` in the form the director writes (words of letters, digits and `_./:=@%+,-`, or single-quoted words), with a verb from the closed set (`prepare`, `builder`, `check`, `patch`, `stderr`, `doctor`, `cleanup`), and then runs that verb itself. It never starts a shell and never runs the program named in the first word: the binary that runs is the one the key names. `$`, backticks, `;`, `|`, `&`, redirections, double quotes, globs, newlines and `--forced` inside the command are refused. A refusal, and an interactive login with no command, print one JSON error line (`{"ok":false,"error":"refused: ..."}`, which says what was wrong and never repeats the command) and exit 77. A verb that runs exits with its own code (0 or 1). `restrict` turns off the pty, agent and X11 forwarding, port forwarding and `~/.ssh/rc`; `port-forwarding` turns port forwarding back on, which the director needs for the two socket forwards.

What the director can do with the key: run those seven verbs, and open the control connection and the two Unix socket forwards. What it cannot: get a shell, run any other command, copy files with `scp` or `sftp` (a subsystem is replaced by the forced command too), get a terminal, or forward its agent or X11. What the key does not narrow, so do not read it as more than it is:

- The verbs still do their job. `check` runs the lane's declared check command and `builder` runs the configured `claude`, both inside the sandbox, as the host user. The sandbox, not the key, limits those. (The director no longer chooses which executable runs outside the sandbox or which directory is the lanes root: see "The host config".)
- `port-forwarding` on its own would let the key open any forward the host's `sshd` allows, TCP included. The two pins `permitopen="127.0.0.1:1",permitlisten="127.0.0.1:1"` take TCP away. A `-L` forward may only reach port 1 on the host, where nothing listens, and a `-R` forward may only listen there, which only root can bind. The director needs only Unix-socket forwards, and the pins do not apply to those.

### The host config

A forced key limits the director to seven verbs, but three of their arguments used to reach outside the sandbox or across the host user's files: `doctor --claude-bin <path>` runs `<path> --version` as the host user, the builder's launch spec names the executable the sandbox runs, and `--root` names the lanes directory (`cleanup` removes under it). So under `--forced`, the host's owner decides them, in `~/.config/cowproof/host.toml`, where `~` is the `HOME` that `sshd` sets from the passwd entry:

```toml
claude = "/home/u/.local/bin/claude"
root = "/home/u/.cache/cowproof/remote-lanes"
```

`cowproof host setup --write-config` writes it from the paths `setup` resolved (mode 0600, in a directory of mode 0700, and never over an existing file unless you also pass `--force`); you can edit it by hand. A forced key ignores `XDG_CONFIG_HOME` entirely, because a client can pass `XDG_*` variables through `sshd`'s `AcceptEnv` and cannot change `HOME`; `setup` does honour `XDG_CONFIG_HOME`, so when it is set to somewhere else `setup` writes there and prints a warning that the forced key will not read that file. Run it without `XDG_CONFIG_HOME`, or copy the file to `~/.config/cowproof/host.toml`. `root` is optional and defaults to the remote root a direct call uses. No other key is accepted.

- `doctor` checks the configured `claude`. A `--claude-bin` that is not that path is refused with exit 77, and nothing runs.
- The builder's launch spec must name that `claude` as its `claude_bin`, or the launch is refused (exit 77) before any lane file changes.
- `--root` must be the configured `root`; left out, it is the configured `root`. Another directory is refused (exit 77), so `cleanup` cannot be pointed at one.
- The refusal names the argument and never repeats the value the director sent.
- Without the file, every verb except `doctor` is refused, and `doctor` runs nothing: it reports `"config": "missing"` and the exact command for you to run on the host (`<cowproof> host setup --write-config`). A forced key with no config does nothing until you opt in. The director's `run --host` stops at its doctor, before any lane exists, with exit 4 and that message.
- The file is trusted only if it is a regular file (not a link) owned by the user running `host-agent`, with no group or world write bit, in a directory with no group or world write bit either. Otherwise it is not trusted: the key refuses as it does without the file, and the message names the problem (for example "writable by its group or by others (mode 0666)").
- The file is also refused when it lies under the configured `root` or under the default remote root (compared by canonical path, links resolved): whatever a lane directory holds, the director filled, so a config there is not yours. Keep `root` away from `~/.config`.
- A direct call (your own shell, not the forced key) does not read the file.

The director's `hosts.json` must repeat what the file says: its `claude` is the configured `claude`, and its `remoteRoot` is the configured `root`, or is left out when `root` is the default. If you change the file, send the director the new entry.

Still not narrowed by the key: `check` and `builder` run what the director asks inside the sandbox, and the forwards are as above.

Tested on 2026-10-11 against OpenSSH 9.6p1 (Ubuntu), with a throwaway `sshd` holding exactly this line:
- the Unix-socket `-R` forward through the control master carried data both ways;
- a TCP `-L` and a TCP `-R` were both refused by `sshd` ("administratively prohibited", "the request was denied");
- `id`, a command with `;`, `cowproof verify` and an interactive login were refused with exit 77;
- `host-agent doctor` ran.

`permitopen="none"` is not valid in `authorized_keys`: `sshd` rejects the whole line, and the key stops working. `none` is only valid in `sshd_config`.

The host-agent wire did not change (`HOST_PROTOCOL` stays 2): a director and a host that spoke before still speak. `doctor` only gained the fields `config`, `config_detail` and `fix`.

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
