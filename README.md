# cowproof

Run many AI builders in parallel on one project, each in its own copy-on-write clone, under a director that lets nothing land until it is proven.

- **COW**: every lane runs on a copy-on-write clone of your repository's object store (with a fresh working tree checkout of the base commit), inside an OS sandbox.
- **Proof**: every lane hands back a patch plus a proof capsule: checks re-run by a verifier the builder never controlled, which any machine can replay.
- **Cow-proof**: builders work in their own clones and cannot touch your real tree.

## Install

One install provides three binaries: `cowproof`, `pk` (portkit commands) and `pk-read` (session-aware file reading). Everything else is a `cowproof` subcommand (`cowproof report`, `cowproof plan`, `cowproof lint`, ...); `pk` and `pk-read` stay separate because hooks and shells call them by name.

Nothing is published yet. The first release is cut by hand (see [docs/releasing.md](docs/releasing.md)); until then, build from git or from source.

**From crates.io** (after the first release is published):

```bash
cargo install cowproof
```

**From a release tarball** (after the first release; macOS arm64 and x86_64, Linux x86_64 and arm64). Download the tarball for your platform and its `.sha256` file from the [GitHub Releases](https://github.com/srmcguirt/cowproof/releases) page, then check and unpack it:

```bash
shasum -a 256 -c cowproof-v0.1.0-aarch64-apple-darwin.tar.gz.sha256
tar -xzf cowproof-v0.1.0-aarch64-apple-darwin.tar.gz
cp cowproof-v0.1.0-aarch64-apple-darwin/{cowproof,pk,pk-read} ~/.local/bin/
```

The Linux binaries need glibc 2.35 or newer.

**From git, today:**

```bash
cargo install --git https://github.com/srmcguirt/cowproof cowproof
```

**From a checkout:** `cargo install --path crates/cowproof-cli` (the package is `cowproof`; its directory keeps the old name), or `cargo build --release` and take the three binaries from `target/release/`.

After installing, run `cowproof doctor`.

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

Every runtime has an adapter: `claude`, `openrouter` ([OpenRouter models through OpenCode](#openrouter-models-through-opencode) below) and `codex` ([Codex models with an API key](#codex-models-with-an-api-key) below). A lane that would start on a rung that cannot run here is refused with exit 4 before anything exists, naming what is missing, and a `reassign` that would land on one ends the lane the way the top of the ladder does (the work kept, the ruling left undelivered): no `opencode` on `PATH`, no `OPENROUTER_API_KEY`, no `codex` on `PATH`, no `OPENAI_API_KEY`, no `claude` or `ANTHROPIC_API_KEY`, or a remote lane.

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

`cowproof run` lints first and stops on lint errors, with one exception. Lint has no `--model`, so its `profile` findings about unmet requirements may name a rung the lane will not use (`--model sonnet` onto a rung with no profile, while the header names a strict one). Inside `run` those findings are dropped, and `run` checks the profile of the rung it actually uses, with the same checker, in two places. A `profile` finding about a broken configuration (a `[profiles]` or `[routing.profiles]` that does not parse, or a route naming an undefined profile) is still a lint error that stops the run, whichever rung it would use. `cowproof lint` run directly reports both, as before.

- **At the start.** After the starting rung is resolved from every source (`--model` included), that rung's profile is checked against the packet text. An unmet profile is exit 4 with "nothing was started", naming the rung, who chose it, the profile and each missing requirement: `rung claude:sonnet refused (flag chose it): the packet does not meet profile "strict" for that rung (tests: add a "## Tests" section ...; mutations: ...)`.
- **On a reassign.** Before the lane launches on the rung a `reassign` picks (the next on the ladder, or the one the ruling names), that rung's profile is checked against the packet the lane is running. An unmet profile refuses the reassign like a rung with no adapter: the lane ends `failed`, its work is kept, the ruling stays recorded and undelivered, and `run.json`'s `error` names the rung, the profile and the missing requirements.

`run.json` records the check per segment as `profile`: `{rung, name, requires, met, missing}`, or null for a rung with no profile.

## A time limit per check

A check in the packet header may carry its own time limit, for the one slow suite among quick ones:

```json
"checks": [
  {"id": "unit", "command": "cargo test --lib"},
  {"id": "slow", "command": "cargo test --test e2e", "timeout": "45m"}
]
```

`timeout` is `"<n>s"` or `"<n>m"` (a bare integer is seconds), from `"1s"` to `"360m"` (6 hours). A value that is unparseable or outside that range is the lint error `invalid-check-timeout`, naming the check, and `cowproof run` refuses it before a lane exists. A check with no `timeout` keeps the default, 20 minutes.

The builder's `run_check` and the verifier both honour the limit; a run that reaches it ends `timed_out`, and the verifier's timeout is an infrastructure end, never a divergence. The capsule records the limit each run was held to as `timeout_ms` in `checks/<id>.json` (the default included), and `cowproof verify` replays every check under the limit recorded there, not under its own default. The header is what was proved: a recorded `timeout_ms` that differs from the limit the capsule's last packet header declares for that check (or is missing when the header declares one) is refused before anything runs, as is a recorded limit outside 1 second to 6 hours. A capsule written before the field has no `timeout_ms` and is replayed under the default as before. Codex lanes cap one MCP tool call at an hour, so a `run_check` limit above `"60m"` does not outlast that cap for a builder on a `codex` rung; the verifier is not affected.

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

## Codex models with an API key

A rung `codex:<model>` (for example `codex:gpt-6-luna`) runs the model through [Codex CLI](https://github.com/openai/codex) (`codex exec --json`, tested against 0.157.0), with an OpenAI API key. The runner, the sandbox, the queue, the checks and the proof are the same as for a Claude lane; only the builder's launcher, its event parser and the provider the proxy forwards to differ. A ChatGPT subscription login is not supported: a `cowproof.toml` that asks for one (`[runtimes.codex] credential = "subscription"`) is refused with exit 4, citing D28 clause 6.

**Setup.** Install `codex`, put your OpenAI key in the environment of the shell that runs `cowproof`, and state what the model costs in the base commit's `cowproof.toml`:

```toml
[runtimes.codex.prices."gpt-6-luna"]
input = 1.25          # USD per million uncached input tokens
cached_input = 0.125  # USD per million cached input tokens (default: the input price)
output = 10.0         # USD per million output tokens, reasoning included
source = "https://platform.openai.com/docs/pricing, read 2026-10-11"
```

```sh
export OPENAI_API_KEY=sk-proj-...            # yours; read once, held by the proxy
cowproof run packet.md --model codex:gpt-6-luna
```

or name the rung in the ladder, the header or a class route. `--codex-bin <path>` names the executable when it is not `codex` on `PATH`; an npm install's Node wrapper is replaced by the native binary beside it, because the sandbox hides your Node. A lane that starts on a `codex` rung needs `codex`, `OPENAI_API_KEY` and a price, and does not need `claude` or `ANTHROPIC_API_KEY`. The other providers' keys only let a later `reassign` cross runtimes, because one proxy per lane serves all of them.

**What the lane sees.** A placeholder, never your key. The lane's `home/.codex/config.toml` defines a model provider `cowproof` (`wire_api = "responses"`) whose `base_url` is the in-sandbox bridge (`http://127.0.0.1:<port>/v1`) and whose `env_key` names `OPENAI_API_KEY`, which holds the lane's `placeholder-...` in Codex's environment only (`shell_environment_policy.exclude` keeps it out of the commands Codex runs; Codex's default policy would pass it). The proxy accepts that placeholder on `POST /v1/responses`, the one path Codex calls, replaces it with `Authorization: Bearer <your key>` and forwards to `https://api.openai.com`; a long thread's compaction is one more request to the same path. Any other path or method, and any request that carries a credential other than the placeholder, is refused with 403 and goes nowhere.

- **Codex's own sandbox is off.** `--dangerously-bypass-approvals-and-sandbox` is the flag `codex exec --help` documents "solely for running in environments that are externally sandboxed". cowproof's OS sandbox is the boundary; a second Seatbelt or Landlock layer inside it cannot be applied (macOS) or needs privileges the lane lacks (Linux), and the flag also sets the approval policy to `never`, which a non-interactive lane needs.
- **Offline.** With its defaults, Codex reaches `chatgpt.com`, `ab.chatgpt.com`, `github.com` and `api.github.com` at startup (measured against 0.157.0 under a sandbox that denied everything but loopback, with an HTTPS proxy logging each attempt). The config turns off the update check, analytics, feedback, the plugin marketplace and connector sync (`features.plugins`, `apps`, `tool_suggest`, ...), the hosted web search, the unbounded connection retries and the bundled skills, and runs commands in `zsh -c`, not a login shell; with these it reached nothing. The settings that decide where the model is and what credential it presents are written to the file and also given as `-c` flags, which outrank any file in the clone, and `--strict-config` makes a Codex that no longer knows one of them fail instead of running without it. `ChatGPT` and `OpenAI` base URLs are pointed at the bridge, where the proxy refuses them: `run.json` records everything the proxy refused as `proxyRefused`, which is `{}` for a lane that behaved.
- **Models.** The proxy forwards a Codex request only if its body names a model on the ladder from the start rung up. Codex offers a model in its own catalog (the `gpt-6-*` models) a `collaboration` namespace with `spawn_agent`, which takes a `model`, and `features.multi_agent` does not remove it; a sub-agent on a dearer model would be billed at a price you never set. Such a request gets 403 and the upstream never hears of it (the proxy reads the body whole for this, once per call). The builder is also told not to start sub-agents.
- **Prompt and session.** The packet is Codex's first message, sent on stdin (`-`). A ruling resumes the same thread with `codex exec resume <thread id> -` and the ruling as the message; the thread id is the `thread_id` of the `thread.started` event, a UUID. If the thread is gone, Codex exits 1 at once with nothing on stdout, and the existing D9 fallback starts a fresh session with a carry-over summary. The cowproof tools reach Codex as an MCP server (`[mcp_servers.cowproof-tools]` in the same config, the command and arguments of Claude's `mcp.json`); the builder preamble's `ask`, `check_ruling` and `run_check` are those tools, and a code-mode model finds them as `tools.mcp__cowproof_tools__run_check`.
- **Events and meter.** `codex exec --json` prints `thread.started`, `turn.started`, `item.started` / `item.updated` / `item.completed`, `turn.completed`, `turn.failed` and `error`. A tool call is a finished item: `command_execution` is `Bash`, `file_change` is `Edit`, `mcp_tool_call` is `mcp__<server>__<tool>`. Codex retries a failing API call five times and says so with `error` events ("Reconnecting... 2/5"); those are not errors, and a `turn.failed` with a non-zero exit is the same failed builder as Claude's. The notice that Codex has no metadata for a model is an `error` item and is ignored.
- **Tokens and cost.** `turn.completed` carries the thread's token usage only once, at the end, and as the thread's running total (a resumed thread reports the earlier launches again), so a cost cap cannot act on it. The tokens come from the egress proxy, which reads `usage` from each call's `response.completed` event as it passes: each model call is one turn, the running cost is live, and the cost cap, the escalate-early share and `--turn-budget` act while the lane runs. Codex's own total stands in only when the proxy saw nothing. Uncached input, cached input and output are priced at your figures; the cost is always an estimate (`costSource: "estimate"`), because Codex reports none. A model with no price is refused with exit 4 (it names the model and says the cost cap cannot be enforced), and so is a price entry without `source`, with a figure that is not above zero, or with an unknown key. The prices are read from the base commit, not the working tree, for the start rung and every `codex` rung above it. OpenAI publishes no machine-readable price list to read instead.
- **Recording.** `run.json` records `runtime: "codex"`, the model, `runtimeVersion` (the output of `codex --version`) and `price` (with your `source`) for every segment, `usageSource` (`proxy` or `events`), `codexVersion` and, when you replaced it, `openaiUpstream` at the top. The capsule records `builder_runtime`, `builder_runtime_version` and, for the last segment, the same price record as `codex_price`.

`COWPROOF_OPENAI_UPSTREAM` replaces `https://api.openai.com` as the proxy's upstream, for a test server or a gateway. It is read from the environment and never from `cowproof.toml`, so repository content cannot redirect your key.

**Limits.** Remote lanes (`--host`) run Claude only: `--host` with a `codex` rung is refused with exit 4, naming the rung. Codex has no hooks cowproof uses, so a `codex` lane is untraced by portkit. Codex has no flag for a turn limit, so `--max-turns` does not apply to it; the cost cap, `--turn-budget` and the wall-clock timeout do. The clone's own `.codex/` directory is hidden from the builder: Codex 0.157.0 ignores a project `config.toml`'s model and provider settings but still starts the MCP servers it names (and reads that directory's `hooks.json`, `agents`, `rules` and `skills`), and no switch turns that off, so the builder's sandbox denies the directory, read and write, and Codex runs as if the clone had none (a lane cannot edit files under `.codex/`; the checks and the verifier still see them). A `.codex` that is a symlink is refused, and an `--unsandboxed` lane cannot hide anything. A request body of more than 64 MiB is refused. The price and the model list are read once per run.

## Claude with a subscription: `--credential subscription`

By default a Claude lane spends an Anthropic API key that only the proxy holds. `cowproof run --credential subscription` runs it on your Claude subscription instead, through the long-lived token `claude setup-token` prints. You run that command yourself and export the result as `CLAUDE_CODE_OAUTH_TOKEN` in the shell that runs `cowproof`; cowproof never performs, scripts or relays a login.

What changes, and what does not:

- **The token stays out of the lane.** Claude Code sends that token as `Authorization: Bearer <token>`, so the proxy handles it the way it handles an API key. The lane gets a placeholder in `CLAUDE_CODE_OAUTH_TOKEN`, the proxy swaps in the real token on the way upstream, and the token is in no file of the lane, in no environment the builder can read and in no log. `credential_in_lane` is `false`.
- **One credential, never two.** Claude Code prefers an API key to the token when both are set, so a subscription lane's environment has no `ANTHROPIC_API_KEY` at all, and the subscription route of the proxy refuses any request that carries an `x-api-key`. Your own `ANTHROPIC_API_KEY` is neither read nor sent in this mode. The reverse holds too: a default (API-key) lane ignores `CLAUDE_CODE_OAUTH_TOKEN`.
- **A missing token is a refusal, not a fallback.** With the token unset or empty the run stops before anything is created (exit 4, "nothing was started"), even when `ANTHROPIC_API_KEY` is set. With the default mode and no API key it stops the same way, even when the token is set.
- **Claude rungs, on this machine.** `--credential subscription` with a start rung of another runtime is refused with exit 4, and a `reassign` onto an `openrouter` or `codex` rung ends the lane like the top of the ladder (the work is kept), because the proxy holds no key for them. `--host` is refused with exit 4, naming the flag: remote lanes run on an API key for now.
- **A flag, not a setting.** The choice decides whose bill the lane runs on, so it is a flag of your command and not something the repository's `cowproof.toml` or a packet header can set.
- **The same isolation.** The launch is the API-key launch with the other variable: `--setting-sources ""` (no user, project or local settings are loaded, so the clone's `.claude/settings*.json` cannot change the builder; only cowproof's `--settings` file applies), `--strict-mcp-config` (only the MCP servers of cowproof's own `--mcp-config` run), and no `--bare`, which would not read the token. `CLAUDE.md` auto-discovery is not covered by those flags and is handled by the launch baseline, as before.
- **Where it shows.** `run.json` and `verdict.json` carry `authMode: "subscription"`, `credentialKind: "claude-oauth-token"` and `credentialInLane: false`; the capsule carries `auth_mode`, `credential_kind` and `credential_in_lane`; `cowproof watch` adds a `CREDENTIAL` column (only when some lane is not on the default API key, so the usual table is unchanged), and the `lanes` director tool adds a `credential` object.

`COWPROOF_ANTHROPIC_UPSTREAM` replaces `https://api.anthropic.com` as the proxy's Anthropic upstream, for a test server or a gateway. Like the OpenRouter and OpenAI ones it is read from the environment and never from `cowproof.toml`, and `run.json` records it as `anthropicUpstream` when it is set.

**Limits.** The cost in `run.json` is still an estimate priced like an API call, which says nothing about your plan's allowance; a subscription has rate limits the runner does not model, and Anthropic's terms for using a subscription token outside the Claude apps are yours to check. Claude Code also tries a few requests of its own to `api.anthropic.com` (one more in this mode than with a key); the sandbox refuses them and a lane runs without them. The behavior above was measured against Claude Code 2.1.296 with a fake upstream and a synthetic token; it has not been run against the real service from a lane (that bills your plan and needs your approval). A Codex subscription (ChatGPT login) lane is still refused.

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
- **Context per proved traced lane** is read from `traceTotals` of `run.json` (see [Trace totals](#trace-totals-per-lane)): the mean `deliveredBytes`, `savedBytes`, `rejected` calls and `rereadRate`, over the proved lanes of each start rung that were traced. It is printed under the table as `Context per proved traced lane (means)` with one row per start rung (`delivered`, `saved`, `rejected`, `re-read`, and how many proved lanes it covers), under the line `builder-written, informational`. An untraced proved lane (Codex, OpenRouter, a remote host, or no hooks) is not in the means; a traced lane whose `run.json` predates a figure, or whose calls named no target (no `rereadRate`), is left out of that one mean only; a mean with no lane shows `-`. The section is left out when no proved lane was traced.
- **Remote lanes** are counted in the rates like any other and noted in the footer; `rungSource` shows how many starting rungs came from a flag, a header, a class route or the default.

`--json` prints the same numbers as one document (`counts`, `groups`, `climbed`, `delivered` with `meanDeliveredBytes`, `meanSavedBytes`, `meanRejected` and `meanRereadRate`, and one `lanes` row per counted lane with its first and final rung, class, cost, turns, reassigns, its trace figures, `host` and `unsandboxed`). Exit 0 when it prints; exit 1 when a root is not a directory. The plain table is at most 80 columns wide.

## Trace totals per lane

A Claude lane's builder runs with portkit's hooks, which record every tool call it makes to `<lane>/portkit/traces/*.jsonl`. When the builder has exited and `pk doctor` finds the lane traced, the runner adds those records up and writes the totals to `control/run.json` as `traceTotals` and to the capsule as `trace_totals` (sealed with the rest of `capsule.json`; an older capsule has none, or has totals without `savedBytes`, `rejected` and `rereadRate`, and still verifies, reading them as 0, 0 and null):

```json
"traceTotals": {
  "calls": 6, "deliveredBytes": 1145, "producedBytes": 1645,
  "savedBytes": 500, "rejected": 1, "rereadRate": 0.1667,
  "byTool": {"Bash": {"calls": 3, "deliveredBytes": 110}, "Read": {"calls": 3, "deliveredBytes": 1035}},
  "pkRead": {"calls": 2, "deliveredBytes": 10},
  "malformedLines": 1
}
```

`deliveredBytes` is what reached the builder's context. `savedBytes` is what the budget kept out of it: `producedBytes` minus `deliveredBytes` of the sums, never below zero, as portkit's own `Summary` has it (the sums saturate, so an absurd trace cannot stop the runner). `rejected` counts the calls that ended `rejected` (refused before the tool ran). `rereadRate` is the share of the calls that name a target whose tool and target an earlier call of the lane already named, a ratio from 0 to 1; it is `null` when no call names a target. portkit stores only a target (a path, a URL, a pattern, or the first two words of a `Bash` command), never the arguments, so a re-read is the same tool on the same target, and a repeated `cargo test` counts. The hook records (surface `agent`) have `produced` equal to `delivered` and outcome `ok`, because the hook sees only the result, so `savedBytes` and `rejected` are 0 for a lane unless portkit's own tools (CLI or MCP surface) wrote records to the same trace. `pkRead` counts the `Bash` calls whose command head is `pk-read` and the bytes they delivered. The trace keeps no output, so an `UNCHANGED` answer from `pk-read` cannot be told from a full read; only the totals are known, not the split. An untraced lane (no hooks, a remote host, a Codex or OpenRouter segment) records `null`, with no error. The totals describe how the lane was watched and never enter the verdict; the builder can write its own trace directory, so they are its own account. The walk is the same safe one `port-candidates` uses: no symlink is followed and a line that is not a record is counted, not fatal.

`cowproof watch` adds a `CTX-SAVED` column (after `LAST EVENT`, before `CREDENTIAL`) when some lane has trace totals, so the table of lanes without them is unchanged. It shows `savedBytes` as a short figure (`950`, `12.3k`, `4.5M`), `0` for a traced lane that saved nothing, and `-` for a lane with no figure: an untraced lane, a `run.json` from before the figure, and a lane that is still running. The runner reads the trace once, at lane end, and writes the totals into `run.json` then, so a running lane shows `-` until it ends. `watch` reads `run.json` only and never opens the trace files, so a missing or malformed trace cannot fail it. The `lanes` director tool carries the same figure as `ctx_saved_bytes`, left out when there is none.

## Find what to port: `cowproof report port-candidates`

Lanes run the same few shell commands again and again, and every run puts its output into context. `cowproof report port-candidates <lanes-root>...` (the design, D23, also spells it `cowproof report --port-candidates`) reads the portkit traces of every lane one level under each root and ranks those commands by how often they ran, how many bytes they delivered into context and how long they took. The numbers below come from synthetic traces made by hand, not from real runs:

```text
$ cowproof report port-candidates ~/.cache/cowproof/lanes
Port candidates: 5 of 5 commands run 2+ times; 3 of 4 lanes traced (1 root)

 # command                      calls lanes    time  median     bytes  score
 1 cargo test                      11     3       -       - 213.9 KiB 0.6471
 2 node gate.mjs                    7     2       -       -  64.9 KiB 0.1250
 3 rg TODO                          4     2       -       -  24.2 KiB 0.0266
 4 git status                      17     3       -       -   5.0 KiB 0.0233
 5 sed -n                           3     1       -       -   7.0 KiB 0.0058

calls is how often the command ran; bytes is what reached context
  (delivered_bytes); time is wall time. score = calls x bytes x time, each
  divided by the largest among the candidates.
A command is its program and stable arguments (the first two words the trace
  keeps): paths, temp dirs, ids and numbers are collapsed, and values after =
  are dropped.
Time is not in these traces (the hook records duration_ms 0.0 for a Bash call),
  so time is left out and score = calls x bytes.
Left out: untraced lane 1.
```

`--top N` shows more or fewer than 10, `--min-calls N` changes how many runs make a command a candidate (default 2), and `--json` prints the same numbers as one document. With `--draft DIR` it also writes one DRAFT `kind: port` packet per shown candidate (`port-cargo-test.md` and so on): the header in the packet format, the observed command with its call statistics and a few redacted example invocations, the compact `pk` tool to port it to, and a `## Checks` section that says the fixtures must be recorded first with `cowproof pk port capture`. A draft is marked DRAFT, is never dispatched by anything, and never overwrites a file. Its placeholders are `FILL-` names, so `cowproof lint` on an unedited draft reports only the paths that still have to be filled in (the crate's source file, the cases file and the fixtures directory), and a draft with them filled lints clean.

What it reads and how it counts:

- **Only the traces:** `<lane>/portkit/traces/*.jsonl`, the lane's `PORTKIT_STATE_DIR` being `<lane>/portkit`. No symlink is followed: a lane directory, its `portkit` or `traces` directory or a trace file that is a link is skipped and counted. A lane with no trace (a Codex or OpenRouter lane is untraced) is counted, and a line that is not a record is counted as `malformed line`; neither stops the report.
- **A command is a `Bash` call seen by the hook.** The hook stores no arguments: a record's `target` is the first two words of the command, cut at 60 characters, so that head is all there is to fingerprint. The fingerprint is the program and its stable arguments: environment assignments are dropped whole, a value after `=` is never kept, a quoted word or a URL is masked, a path keeps its last component (a path under a temp directory is `<tmp>`), and ids and numbers are collapsed. `cargo test --workspace` and `cargo test -p x` are both `cargo test`; a command that starts with `cd dir && ...` is `cd dir`, which the trace cannot see past.
- **Bytes into context** is the record's `delivered_bytes`, what actually reached the caller; for a hook record it equals the bytes the tool produced. **Wall time** is `duration_ms`, which the hook cannot measure (it sees the result, not the call), so it is `0.0` today and the report leaves time out of the score and says so. When a trace does carry times, a call counts for at least 1 ms.
- **Score** = (calls / most calls) x (bytes / most bytes) x (time / most time), each maximum over all candidates, so no unit dominates. Ties go to more calls, more bytes, then the name.
- **Nothing sensitive is printed or written:** the head is redacted (`cowproof_core::redact`) and its control characters turned into spaces before anything else is done with it, and a word naming `.env`, an SSH key or `credentials.json` is masked. Example invocations are those redacted heads.

## Port packets: `kind: port`

A port packet asks a builder to replace a script (shell, Node, Python, anything that can answer a JSON request on stdin) with a Rust tool, and proves it with portkit's parity replay instead of a claim. The director records what the original does on a set of cases (`cowproof pk port capture`), commits those fixtures, and writes the packet. The builder writes the Rust tool and registers it as a plugin in `.portkit/plugins.toml`; the verifier then replays every fixture against the rebuilt tree, in its sandbox, on both the direct and the MCP surface.

```text
<!-- lane {
  "id": "port-lanes", "kind": "port", "class": "rust",
  "owns": ["crates/pk-lanes/**", "ports/lanes/fixtures/**", ".portkit/plugins.toml"],
  "allow": ["cargo test*", "cowproof pk port *"],
  "port": {
    "lang": "node",
    "adapter": "function",
    "reference": {"cmd": "node reference/adapter.mjs", "cwd": ".", "env": {"TZ": "UTC"}, "runtime": "node>=22"},
    "cases": "ports/lanes/cases.jsonl",
    "fixtures": "ports/lanes/fixtures",
    "tools": ["parse_header", "glob_matches"],
    "parity": {"epsilon": 0, "ignore_paths": ["/meta/generated_at"], "unordered_arrays": false, "path_roots": ["$ROOT"]}
  },
  "checks": [{"id": "tests", "command": "cargo test --locked -p pk-lanes"}]
} -->
```

The header parses strictly: `kind` is `work` (the default) or `port`, a `port` object belongs to a `port` packet and only to one, and an unknown key in `port`, `port.reference` or `port.parity` is an error, not a dropped field.

| Field | Meaning |
| --- | --- |
| `port.lang` | `python`, `node`, `typescript`, `shell`, `ruby`, `perl`, `powershell`, `go` or `other` |
| `port.adapter` | `function` (an adapter file in the source repository makes a function speak the contract; needs `port.reference.cmd`) or `process` (a whole script or executable captured by `pk port exec`, see "Process capture"; `port.reference.cmd` is then the script's command line). Both are checked and recorded. |
| `port.reference` | `cmd` (run with `sh -c`; one `{"tool":..,"input":..}` request on stdin, one JSON result on stdout), `cwd`, `env`, and `runtime`, what the verifier must have installed (`node>=22`, `python3`) |
| `port.cases`, `port.fixtures` | the committed cases file and the fixtures directory (`<tool>/<id>.json`); the builder may write the directory, so `owns` covers it |
| `port.tools` | the tool names the registry must answer; `not_ported` must be 0 for every one |
| `port.parity` | `epsilon` (default: `[port] epsilon` in the base `cowproof.toml`, 0 when it has none), `ignore_paths` (JSON Pointers), `unordered_arrays`, `path_roots` (the tokens `$ROOT`, `$HOME`, `$TMP`, `$SRC` a process capture substitutes, or plain path prefixes; any other word starting with `$` is an error) |

`cowproof lint` checks ten more rules for a port packet (`--escalations <lane>/control/escalations.jsonl` adds the lane's rulings to `port-accepted-unruled`; `--heldout <file>` names the held-out file, and without it the director store is read, as `cowproof run` does, for `port-no-base-fixtures`):

| Rule | Level | Fires when |
| --- | --- | --- |
| `port-cases-missing` | error | `port.cases` is not a file in the repository |
| `port-adapter-missing` | error | the script file `port.reference.cmd` runs (`node adapter.mjs ...`, `python3 reference/adapter.py ...`, `./run.sh`) is not a file in the repository (under `port.reference.cwd` when set), or its path is absolute or has `..`; a bare program (`cargo run`) or inline code (`sh -c '...'`, `node -e`) names no file and is skipped |
| `port-fixtures-not-owned` | error | `owns` does not reach `<fixtures>/<tool>/<id>.json` for some tool |
| `port-reference-not-allowed` | error | a `wide: false` packet has a check that runs `port.reference.cmd` and no `allow` entry (or base allowlist entry) matches it |
| `port-tool-unregistered` | error | the packet text does not name a tool in `port.tools`, or names no plugin manifest (`.portkit/plugins.toml`) that `owns` covers |
| `port-accepted-unruled` | error | an `accepted` entry in a fixture has a `reason` with no `ruling:<id>`; given the escalation log, also one whose id no director answer in it carries |
| `port-epsilon-loosened` | error | the packet, or a fixture, sets epsilon above the project default |
| `port-wrap-roots-mismatch` | error | the repository's `.portkit/plugins.toml` registers a `pk port wrap` entry for a tool of the packet whose `--path-root` flags are not `port.parity.path_roots` (compared as sets; a missing manifest, or no wrap entry for the tool, is not an error) |
| `port-no-base-fixtures` | error, or warn | the base commit (`HEAD`; the working tree when the repository has no commit) holds no `<port.fixtures>/<tool>/*.json` for a tool of `port.tools`: record the fixtures in the base first. It is a warning only when the held-out file's `[port] cases` JSONL has a line whose `tool` is that tool, so the director's held-out cases do check the port against the reference. A held-out file that cannot be read, or has no port cases, leaves it an error. `cowproof run` runs the same lint with the same held-out file and refuses on the error, before any lane exists |
| `port-nondeterministic-output` | warn | a fixture's expected output has an RFC 3339 time, a temp or home path or a `.local`-style host name that no `ignore_paths`, `accepted` or `path_roots` entry covers |

**The proof.** After the packet's recorded checks, in the same rebuilt tree and sandbox, the verifier runs `cowproof pk --config <pk.toml> port replay --fixtures <port.fixtures> --surface both --epsilon <e> --json` and judges the report itself. The `port_replay` gate in `gates.json` passes only if the command exited 0, both surfaces replayed, every surface's `ReplayReport::is_success()` holds, `not_ported` is 0, every tool in `port.tools` has fixtures that were replayed, and the lane left the fixtures alone: a fixture of the base keeps its `tool`, `id`, `input`, `expected` and `platform` (the builder may add fixtures and, with a ruling, `accepted` entries; only a director recaptures), and each `accepted` difference the lane added cites `ruling:<id>` in the reason with the id carried by an `answer` in the lane's escalation log. A refusal names the surface, the tool and the fixture, for instance `direct shout/hi: differs from the reference at "/result"`, or `not ported (no tool answers it)`.

**Platform-tagged fixtures.** The utilities a script calls are the host's (BSD on macOS, GNU on Linux), so one case can have a different fixture on each platform. A fixture may carry an optional top-level `"platform": "linux"` or `"macos"` (the names of `std::env::consts::OS`), and then its `id` ends with `@<platform>` (`greet/basic@linux`, `greet/basic@macos`), so both versions sit in one directory. `pk port capture --tag-platform` and `pk port exec --tag-platform` write the host's platform into each fixture and add the suffix (a case id that already ends with this host's tag is kept; one tagged for the other platform fails the case). An untagged fixture applies on every platform, exactly as before, and an old fixture replays unchanged. A tag that is not `linux` or `macos`, a `platform` whose id does not end with `@<platform>`, and an untagged fixture whose id ends with a platform tag are fixture parse errors, so the replay prints no report and the gate fails. `pk port replay` and the `port_replay` gate replay the untagged fixtures and the running platform's. The others are not replayed: they are counted as `other_platform` in the replay report, in each surface of the capsule's `port` entry and in the `port_replay` gate's evidence, and are never counted as passed (nor in `total`). A tool whose replayed fixtures end up at zero on this platform while it has fixtures tagged for another fails the replay (`ReplayReport::is_success()`) and the gate, naming the tool and the platforms its fixtures cover (`tool "shout" has no fixture for linux (its fixtures cover macos), so it was never proved on this platform`): a port is never proved on a platform it was not captured on. The verifier checks this from the files, not from the report: an outcome reported for another platform's fixture, an `other_platform` count that differs from the tagged fixtures on disk, and a tool whose base fixtures are all for other platforms all fail the gate, and retagging a fixture of the base changes its `platform` and is refused like any other change to it. Only the base's fixtures (the director's, read from the base commit) count as coverage: a fixture the lane adds is replayed and judged like any other, but it cannot stand in for a base fixture captured on another platform, so one untagged fixture of the lane's own does not hide the gap. `pk port replay` has no notion of the base and counts every fixture on disk; a caller that knows which fixtures are vouched for uses `ReplayReport::platform_gaps_among`. A tool with no base fixture at all is the `port-no-base-fixtures` lint's case, not this rule's. The held-out cases are captured on the verifier's own platform, judged by the same code, and count as coverage for the tools they cover. `pk port wrap` writes no fixtures and has no such flag.

**Protected paths.** A repository adds its own protected globs in the base commit's `cowproof.toml`: `[proof] protected = ["secret/**", "infra/**"]`, next to `packs`, `require_heldout` and `migration_baseline`. They add to the built-in list (test and build configuration, CI files, `cowproof.toml`, `cowproof/**`, the packs) and to the default instruction files (`AGENTS.md`, `CLAUDE.md`, `.github/**`, `.claude/**`, `.agents/**`, `.codex/**`). The older `lanes.config.json` `protected` list is still read; when both files exist the gate protects the union, so a repository mid-migration keeps everything it had. When `lanes.config.json` supplies globs, the gate evidence says so once and points at `[proof] protected`. Both files are read from the base commit only, so a patch that edits either one is still judged by the base's globs, and both stay protected paths themselves. A `protected` value that is not a list of strings, or a file that does not parse, is an error, never "no extra globs".

**Flaw packs and the handoff directory.** The generic flaw pack (swallowed exceptions, an added `#[ignore]`, string-built HTML, an edit to an applied migration, build output in the patch) is built into cowproof and always runs, in the proof gates and in `cowproof report handback` alike; a repository needs no file for it. `[proof] packs = ["example-supabase", "./cowproof/flaws.toml"]` in the base `cowproof.toml` adds more: a built-in name, or a path inside the repository (no absolute path, no `..`, no symlink out). The gates read those files from the base commit and the report reads them from the repository you name with `--repo`, through the same loader, and a pack that is missing, malformed or outside the repository is an error, never an empty pack. A patch that edits a named pack is judged by the base version and fails the protected-path gate. The handoff directory is `[paths] handoffs` in `cowproof.toml`, else `handoffDir` in `lanes.config.json`, else `docs/handoffs`; when both files set it and differ, `cowproof.toml` wins and the report carries a warning saying so. The ownership gate also reads it from the base: a new file under it whose name carries the lane id as a whole token, set off by `-`, `_`, `.` or the ends of the name (`docs/handoffs/<lane-id>.md`) passes without being in `owns`, and the gate's evidence names it; editing, deleting or renaming an existing handoff, a name without the lane id and a symlink still need `owns`.

**Held-out cases.** The director's second set of cases lives outside the repository, beside the held-out file: `cowproof run packet.md --heldout ~/.cowproof/heldout/<repo-id>/<lane>.toml`, with `[port] cases = "<lane>.cases.jsonl"` in it naming a JSONL file in the same directory (the same `{"tool":..,"id":..,"input":..}` lines as `port.cases`). The cases file is copied into the capsule's `packets/` (hashed there, never in the clone). At verification the verifier captures them against the reference (`port.reference`, run in the sandbox) and replays them, so a port that only matches the visible fixtures fails. If `port.reference.runtime` is not in the verifier's sandbox, or is older than asked, the held-out cases are not run: `cowproof run` and `cowproof verify` print `held-out: skipped (<why>)`, `gates.json` records it with `warned: true`, and the capsule says `skipped`. It is never a silent pass. A repository that wants a skip to refuse sets `[proof] require_heldout = true` in `cowproof.toml` at the base commit: the held-out gate then fails (the `held_out` gate, with the skip and the setting named) and the lane is `refuted`, the same as a lane with no held-out file at all. Without the setting a skip stays a warning. A held-out file with port cases needs a `kind: port` packet with a `port.reference.cmd`; `cowproof run` refuses anything else before a lane exists.

**Reference runtimes: `--runtime-dir`.** The verifier's `PATH` is the system directories plus the `cargo` directory, and its sandbox hides your home, so a reference runtime installed elsewhere (nvm, pyenv, Homebrew under a prefix the sandbox does not show) reads as missing and its held-out cases are skipped. Name the runtime's directory, by absolute path, on `cowproof run` and `cowproof verify`: `--runtime-dir ~/.nvm/versions/node/v22.3.0` (repeatable), or `COWPROOF_RUNTIME_DIRS=/dir1:/dir2` (colon-separated, read once at startup; flags come first). Each directory is granted READ-ONLY to the verifier and to the builder's `run_check` sandbox (so the builder's checks and the verifier's agree), and its `bin` subdirectory, or the directory itself when it is named `bin`, goes on their `PATH` ahead of the system directories; a directory with neither is refused. Only you name them: never `cowproof.toml`, the base commit or a patch, so a repository cannot choose what of your machine the sandbox can read. Refused, with exit 4 before anything exists: a relative path or one that is missing or not a directory; `/`, your home or any ancestor of it; a directory that is, or directly holds, `.ssh`, `.aws`, `.gnupg`, `.config`, `.claude`, `.codex`, `.docker`, `.kube`, `.netrc`, `.cargo/credentials*` or `Library/Keychains`; and the lanes root, the repository and the cowproof cache. Not combined with `--host` (the checks of a remote lane run on the host). `run.json` records them as `runtimeDirs` and the capsule as `runtime_dirs`, so a proof says what extra it saw; `cowproof verify` of that capsule needs the same directories again, and without them the held-out cases are skipped as before, the `held-out: skipped` line naming the capsule's list.

**The capsule.** A port capsule carries a sealed `port` entry (older capsules have none and still verify): the reference command, the source commit (the lane's base commit), a `sha256` over the fixtures directory of the rebuilt tree (every file path and its bytes, in path order), per surface the counts and only the failing and accepted outcomes, and the held-out state. `gates.json` lists each held-out check with its pass or fail on any lane, not only on port packets.

### Capture adapters: Node, TypeScript and Python

A reference that is a module with functions needs a few lines to speak the contract. cowproof ships those lines as one standard-library-only file per language, so the module is not restructured:

```sh
cowproof pk port adapter python --out reference/adapter.py     # or: node, typescript
cowproof pk port capture --cmd 'python3 reference/adapter.py reference/shipping.py' \
  --cases ports/shipping/cases.jsonl --out ports/shipping/fixtures
```

`pk port adapter <lang>` prints the adapter, or writes it with `--out` (it will not replace a file without `--force`). Commit it beside the source, name the command in `port.reference.cmd` and the language in `port.lang`, with `"adapter": "function"`. The source is `crates/portkit/port/adapters/{node,python}/`.

| | Node (`node adapter.mjs <module> [<function>]`) | Python (`python3 adapter.py <module> [<function>]`) |
| --- | --- | --- |
| Dispatch | the function named on the command line, else the request's `tool` (else `$PORTKIT_TOOL`) | the same |
| Call | `fn(input)`; an input that is exactly `{"args": [...]}` is `fn(...args)`; promises are awaited | the same; coroutines are run |
| `__defaults` | the module's `__defaults` export, else every exported non-function value | the module's `__defaults`, else its UPPER_CASE constants |
| A thrown error | `{"error": message}`, exit 0, so it is a fixture | the same |
| An adapter fault (no such function, bad request, a result that is not JSON, a bad `PORTKIT_*` value) | stderr, exit 2: the capture fails instead of recording a mistake | the same |
| Output | one line of canonical JSON: keys sorted by UTF-16 code unit, numbers as ECMAScript prints them (`3.0` is `3`, `-0` is `0`), NaN and Infinity refused | byte-identical to Node's for equivalent data |
| Clock (`PORTKIT_NOW`, RFC 3339) | `Date.now()`, `new Date()`, `Date()`; `performance.now`, `process.hrtime` and `process.hrtime.bigint` start at 0 and move only with `setTimeout`/`setInterval` (global, `node:timers`, `timers/promises` `setTimeout`): they still wait in real time, but a callback finds every pinned clock, the wall clock included, at its due time | `time.time()`, `time.time_ns()`, `localtime`/`gmtime`/`ctime`/`strftime` without a time, `datetime.now()`/`utcnow()`/`today()`, `date.today()`; `time.monotonic`, `monotonic_ns`, `perf_counter` and `perf_counter_ns` start at 0; `time.sleep(s)` does not sleep, it advances those clocks and the wall clock by `s`; `uuid.uuid1()` is built from the pinned time, the fixed node `01:00:00:00:00:01` and clock sequence 0 (a repeat at the same instant takes the next 100 ns tick); `asyncio` keeps its real clock |
| Randomness (`PORTKIT_SEED`, an integer) | `Math.random` is a seeded generator (mulberry32); `crypto.randomBytes`, `randomFillSync`, `randomFill`, `getRandomValues` (`node:crypto` and `globalThis.crypto`), `randomUUID` and `randomInt` draw from one seeded byte stream | `random.seed(seed)`; `os.urandom`, `secrets` (`token_bytes`, `token_hex`, `token_urlsafe`, `randbelow`, `choice`), `random.SystemRandom` and `uuid.uuid4` draw from one seeded byte stream; when `numpy` imports, `numpy.random.seed(seed % 2**32)` and a seed for each `numpy.random.default_rng()` made without one (nothing happens, and nothing fails, without numpy) |
| Environment | `TZ=UTC` when unset | `TZ=UTC` when unset; `PYTHONHASHSEED=0` when unset, by restarting once, so `set` and `dict` order of strings repeats |
| Module output | stdout writes go to stderr | the same |

The byte stream is the same in both adapters: block *i* is SHA-256 of `"portkit-bytes\0"`, the seed in decimal (so `042` is `42`), `"\0"` and *i* as 8 bytes big-endian, consumed byte by byte; the same seed gives `randomBytes(16)` in Node and `secrets.token_bytes(16)` in Python the same bytes. The pinned clocks move only through the pinned sleep and timers, so a loop that waits for one to advance by itself (a busy-wait on `time.monotonic()` or `performance.now()`) never ends. What an adapter cannot pin: file times and CPU times (`process_time`), `timers/promises` `setInterval` and `scheduler`, `setImmediate`, `Intl`'s own clock, `crypto` keys, primes and `subtle`, `numpy.random.RandomState()` made without a seed, generators a module builds from its own entropy, native extensions, and anything that waits on a real clock (threads, sockets, `asyncio`). A seeded generator makes a capture repeatable, not portable: Python's Mersenne Twister and Node's mulberry32 differ from each other and from any Rust generator, so a module whose output depends on random draws takes the draws as input. Python 3.12 made `sum()` of floats compensated; capture with the Python version the reference runs on. Effects (files, subprocesses) are not captured by a function adapter; that is process capture, below.

Pin the clock and seed for the held-out capture in the packet: `"reference": {"cmd": "...", "env": {"PORTKIT_NOW": "2026-01-02T03:04:05Z", "PORTKIT_SEED": "1"}, "runtime": "python3"}` (the verifier exports `env` before the command). The director pins the same way at capture time: `cowproof pk port capture --clear-env --env PORTKIT_NOW=2026-01-02T03:04:05Z --cwd reference ...` (`--cwd`, `--env` and `--clear-env` keep a fixture from depending on the capturing shell; a case's own `"env"` is set last and recorded with the fixture). Parity stays exact: the adapter normalizes the reference's output, not the comparison. `epsilon` is still the project default, usually 0.

TypeScript runs through the Node adapter when Node strips types itself: `node adapter.mjs ./module.ts` on Node 22.18+ or 23.6+, `node --experimental-strip-types adapter.mjs ./module.ts` on 22.6 to 22.17 (erasable syntax only: annotations and interfaces, not enums or namespaces). On an older Node, compile and name the output. The runtime a packet asks for is `node>=22` (or `python3`); a verifier without it reports `held-out: skipped`.

`fixtures/port-adapters/` is the worked example, run by `crates/cowproof-cli/tests/port_adapters.rs` against the real `node`, `python3`, `pk` and `rustc`, and for Python through a whole `cowproof run`: a Node module and a Python module each with one trap (JavaScript lists integer-like keys first; Python rounds the tie 0.125 to 0.12 and sums `0.1 + 0.2` to `0.30000000000000004`), the fixtures captured through the adapters, a right Rust port that passes at epsilon 0 and a wrong one that is refuted. Those tests skip with a printed note when `node` or `python3` is missing, and fail under `COWPROOF_REQUIRE_RUNTIMES=1`. The tests that read `fixtures/port-adapters/` run in the workspace only (the published crate does not contain it): without the workspace they print a skip, and fail under `COWPROOF_WORKSPACE_TESTS=1`, which CI sets. The adapter-alone tests take the adapter from the embedded copy (`pk port adapter --out`) and run in the published crate too.

### Process capture: shell scripts and other executables

A script has no function to call, so it is captured as a whole process. `pk port exec` runs the reference once per case in a fresh directory, network denied, and the fixture records everything the process did; `pk port wrap` runs the Rust port in the same harness and answers the same record, so `pk port replay` compares like with like.

```sh
# reference/greet.sh: reads a file, asks git for a revision, writes a file, deletes one.
cowproof pk port exec --cmd 'sh "$PORTKIT_SRC/reference/greet.sh"' \
  --cases ports/greet/cases.jsonl --out ports/greet/fixtures \
  --path-root '$ROOT' --path-root '$HOME' --path-root '$TMP'
```

One line of `cases.jsonl`, and what the fixture's `expected` holds for it:

```json
{"tool":"greet","id":"basic","input":{"argv":["name.txt"],"files":{"name.txt":"world\n","stale.txt":"old\n"},"shims":{"git":[{"argv":["rev-parse","--short","HEAD"],"stdout":"abc1234\n"}]}}}
{"exit":0,"stdout":"wrote $ROOT/greeting.txt\n","stderr":"",
 "files_after":{"greeting.txt":{"sha256":"bd3b...","mode":420,"size":24,"content":"hello world\nrev abc1234\n"},"name.txt":{"...":"..."}},
 "deleted":["stale.txt"],
 "calls":[{"program":"git","argv":["rev-parse","--short","HEAD"],"env":{},"stdin":null}]}
```

| `input` field | Meaning |
| --- | --- |
| `argv` | arguments after the command (the command is a shell fragment; the arguments are appended as `"$@"`) |
| `env` | variables on top of the pinned environment (below). `env` on the case itself (outside `input`) is capture-only, recorded beside the fixture |
| `stdin` | text on the process's stdin |
| `files` | files written into the root before the run: `"path": "text"` or `"path": {"content": "..", "mode": 493}` (mode defaults to 0o644; paths are relative, no `..`) |
| `shims` | the external programs the case declares, each with scripted responses `{argv?, exit, stdout, stderr, read_stdin, repeat}` |
| `record_env` | variable names each recorded call carries |

| `expected` field | Meaning |
| --- | --- |
| `exit`, `stdout`, `stderr` | the process's, with the declared path roots substituted |
| `files_after` | every file in the root after the run: `{sha256, mode, size}` and, up to 4096 bytes of UTF-8, `content`. A symlink is `{"link": target}`, an empty directory `{"dir": true}`. A text file is hashed after the substitution (a file that holds the root's path hashes the same in every run); a binary file as it is. SHA-256, lowercase hex |
| `deleted` | the files the case materialised that are gone |
| `calls` | `{program, argv, env, stdin}` for each call to a declared program, in order |

**The harness.** The reference runs with `cwd = $ROOT`, `HOME = $ROOT/home`, `TMPDIR = $ROOT/tmp`, `umask 022`, and an environment that is built, not inherited: `PATH` (the shims, then `/usr/bin:/bin`; `--path` changes the second part), `TZ=UTC`, `LANG=C.UTF-8`, `LC_ALL=C.UTF-8`, `PYTHONHASHSEED=0`, `NODE_OPTIONS=`, `PORTKIT_SRC` (the directory the reference lives in, `--src`), then `--env KEY=VALUE`, the case's `env`, the input's `env`, later winning. It runs under cowproof's own sandbox (the capture policy: writes only to its root, network denied: Seatbelt `(deny network*)` on macOS, bubblewrap `--unshare-net` on Linux), or, when `pk` is already inside one (`COWPROOF_SANDBOXED=1`, as in the verifier), inside that one. Before any case the harness shows the network is gone: a listener on `127.0.0.1` is held outside, and a probe run the way a case is run tries to connect (inside an existing sandbox it checks what that sandbox leaves: no socket on macOS, no interface but loopback on Linux). If the network is reachable, or the probe cannot run, nothing is captured. `--sandbox auto|own|inherited` chooses; there is no way to run unconfined.

**Shims.** Each program a case declares is a small `sh` script first on `PATH` that logs the call to `calls` and answers from the next unused scripted response whose `argv`, when it names one, equals the call's (`repeat: true` never uses a response up). A call nothing answers exits 127 and fails the capture. `date` is shimmed unless the case scripts it: with `PORTKIT_NOW` (RFC 3339) in the case's `env` it answers from that instant in UTC (`date [-u] [+FORMAT]`, with the usual `%Y %m %d %H %M %S %j %a %b %s %F %T` and a few more); without it it fails and the capture is refused. `mktemp` is shimmed the same way (unless the case scripts it): it makes the file or directory as the real one does (exclusive create, mode 0600, or 0700 with `-d`) but numbers the name in the order of the calls within a case instead of choosing it at random: `$TMPDIR/tmp.0001`, `tmp.0002`, and so on, so the name is under the case's `$TMP` root and a script that prints it is captured. A template's trailing `XXX` run is the counter, zero-padded to the run's length (`mktemp "$TMPDIR/job.XXXXXX"` is `job.000003` on the third call). Supported: `mktemp`, `-d`/`--directory`, `-q`/`--quiet`, `-t` (a template, or a prefix as BSD reads it), `-p DIR`, `--tmpdir[=DIR]`, and a template whose `X`s are at its end (at least three). Anything else (`-u`, `--suffix`, `--help`, ...) exits 2 with a message and is never answered wrongly; a template with fewer than three trailing `X`s, or text after them, exits 1 as the real one does. The counter is claimed with an exclusively created file in the state directory, so calls made at the same moment by background jobs get different names (which job gets which is not fixed; print them sorted). `mktemp` is not recorded in `calls`. `$RANDOM` and process ids (`$$`) are not pinned.

**Never a flaky fixture.** Each case runs twice (`--repeat N`), in two roots, and is refused if the runs differ after the substitution, naming the first field (`not deterministic: run 1 and run 2 differ at "/stdout"`). A case is also refused if the reference called a program the case did not script, read the clock through `date` with no `PORTKIT_NOW`, exited non-zero without `expect_error`, or exited 0 with it. `expect_error: true` on a case records the failure as its fixture (G4); on `pk port capture` it records `{"error": {"exit": N, "message": "<first line of stderr>"}}`, and a port that fails is compared as the same envelope (`exited with exit status: N: <first stderr line>` read back from the plugin's failure).

**`path_roots`.** `--path-root $ROOT|$HOME|$TMP|$SRC` (declared in a packet as `port.parity.path_roots`) replaces that run's directory with the token wherever it stands as a whole path in stdout, stderr, file text and call arguments. The fixture records `"normalized": {"name": "path-roots", "version": 1, "roots": [..]}`; a replay refuses a fixture whose normalizer or version it does not know (an error, not a pass). `port-nondeterministic-output` does not flag a path written under a token. **A port must replay with the roots its fixtures were captured with.** `pk port wrap` reports its `--path-root` flags in its tool spec, and `pk port replay` (so the verifier's `port_replay` gate too) fails a case whose fixture's `normalized.roots` are not the same set, naming both (`the port's wrap substitutes the roots [$ROOT] but the fixture was captured with [$HOME, $ROOT, $TMP]`); a wrap that omits a root or adds one is a failure before any output is compared. `port-wrap-roots-mismatch` is the lint for the same fault, read from `.portkit/plugins.toml` before the replay.

**The port.** The Rust port is a normal program that takes the same arguments and works in its current directory. Register it as a plugin that is `pk port wrap`:

```toml
[[plugin]]
command = "cowproof"
args = ["pk", "port", "wrap", "--tool", "greet", "--exe", "target/greet",
        "--path-root", "$ROOT", "--path-root", "$HOME", "--path-root", "$TMP"]
```

`wrap` materialises the case's `files`, puts the same shims first on `PATH` (so the port must call `git` through `PATH`), runs the port once, and prints the envelope. A port that writes another file, calls `git` with other arguments or exits with another status is refuted on `/files_after/...`, `/calls/0/argv/...` or `/exit`. A packet that uses it: `"lang": "shell"`, `"adapter": "process"`, `"reference": {"cmd": "sh \"$PORTKIT_SRC/reference/greet.sh\""}`, `"parity": {"path_roots": ["$ROOT", "$HOME", "$TMP"]}`; the verifier captures the director's held-out cases with `pk port exec` in its own sandbox and replays them through the plugin.

**Platforms.** Linux and macOS, the same flow. What differs: the utilities are the host's (BSD on macOS, GNU on Linux; the shell is `/bin/sh`, dash on Debian and Ubuntu), so a script that depends on their output is captured on the platform it will be verified on (each fixture's `source` names the OS); on macOS the clock cannot be pinned for system binaries (System Integrity Protection blocks interposition), so only the `date` shim pins it and a script that reads the clock any other way (`find -newer`, `ls -l`, `printf '%(..)T'`, a program that calls `time()`) is caught only by the run-twice comparison, which can miss a clock that moves slowly; `sandbox-exec` cannot nest, so inside the verifier the run inherits the sandbox. `$RANDOM` and process ids (`$$`) are not pinned: a script that prints or stores one is refused by the run-twice comparison (`mktemp` names are numbered by the shim, above). Windows is not supported.

Tests: `crates/cowproof-cli/tests/port_process.rs`, on `fixtures/port-process/` (the script, its three cases and fixtures, a held-out set and the packet): capture with files, deletions, a scripted `git`, a substituted path and a must-reject case; a right Rust port passing on both surfaces and wrong ones refuted on `files_after`, `calls` and `exit`; the network probe; the refusals; and a whole `cowproof run` that proves the packet and one that refutes a wrong port. They need `sandbox-exec` or `bwrap` (skipped with a note without; `COWPROOF_REQUIRE_SANDBOX=1` makes that a failure), and the example runs in the workspace only. `fixtures/port/` is the older worked example with a shell reference captured as a function (`pk port capture`) that `crates/cowproof-cli/tests/port_packets.rs` runs end to end.

## The dependency cache: `cowproof cache`

Before verify runs, `cowproof run` and `cowproof verify` fetch a lane's Cargo, npm, yarn, pnpm and Bundler dependencies into a cache that the verifier mounts read-only: `~/.cache/cowproof/deps/<key>/`, or `$COWPROOF_CACHE_ROOT/deps/<key>/`. Nothing else removes an entry, so prune it. The verifier's own compile output is cached in the same root, in its own way: see [the verifier's compile cache](#the-verifiers-compile-cache).

- **Cargo.** A tree with a `Cargo.lock` gets `<key>/cargo/{registry,git}`, from `cargo fetch --locked`. The verifier links them into its own `CARGO_HOME`.
- **npm.** A tree with a `package-lock.json` or `npm-shrinkwrap.json` at its root gets `<key>/npm/node_modules` and `<key>/npm/cache`, from `npm ci --ignore-scripts --no-audit --no-fund` run in a scratch copy of `package.json`, the lockfile and the base's `.npmrc`. Every credential line of that `.npmrc` (`_authToken`, `_auth`, `_password`, `user:pass@` in a URL, and the client-certificate settings `key`, `keyfile`, `cert` and `certfile`, plain or scoped) is dropped first and the capsule says how many; the fetch never receives a token, a private key or a certificate, so a private registry that needs a token or a client certificate is out of reach by design and fails as infrastructure. No lifecycle script runs, in the fetch or in the verifier (`npm_config_ignore_scripts=true`). The verifier finds the install at `<tree>/node_modules` (a link to the entry, re-made before every check) with npm offline and `npm_config_cache` pointing at the entry's cache; both are read-only, so a check can read the install and cannot write into it. A package a check needs that is not in `node_modules` fails as before. `npm` is `$COWPROOF_NPM` or the first `npm` on your `PATH` (a Homebrew or system npm; one that lives under your home, such as nvm's, is not reachable from the fetch sandbox).
- **yarn.** A `yarn.lock` is installed into the same layout (`<key>/npm/node_modules`, `<key>/npm/cache`, the cache being yarn's cache folder). Classic yarn (v1) runs `yarn install --frozen-lockfile --ignore-scripts --non-interactive`. Yarn Berry (v2+; a `.yarnrc.yml` is present, or `yarn.lock` has a `__metadata` header) runs `yarn install --immutable --mode=skip-build` and needs `nodeLinker: node-modules` in `.yarnrc.yml`; Plug'n'Play (any other linker, or no `.yarnrc.yml`) leaves no `node_modules`, so it is `not_fetched` with a note, never `fetched`. `yarn` is `$COWPROOF_YARN` or the first `yarn` on your `PATH`.
- **pnpm.** A `pnpm-lock.yaml` runs `pnpm install --frozen-lockfile --ignore-scripts --config.node-linker=hoisted` (a plain `node_modules`; pnpm's store is the entry's cache). `pnpm` is `$COWPROOF_PNPM` or the first `pnpm` on your `PATH`.
- **Bundler.** A tree with a `Gemfile.lock` (or `gems.locked`) gets `<key>/bundler/cache`, the `.gem` files of every locked gem. A `Gemfile` is Ruby code, so the fetch never runs `bundle` and never evaluates one: `cowproof` reads the lockfile itself (the `GEM` sections' `remote:` and `specs:`, `PLATFORMS`, and `CHECKSUMS` when present) and runs one sandboxed `gem fetch NAME --version V --platform P --clear-sources --source <remote>` per gem, in an empty `HOME`, `GEM_HOME` and `GEM_SPEC_CACHE`. **Platforms:** only `ruby` and the host's variants are downloaded, matched by CPU and OS (`x86_64`/`x64`/`amd64` or `aarch64`/`arm64`, and `linux` or `darwin`; a libc suffix or a macOS version is ignored), so `java`, `mswin`, `x64-mingw-ucrt` and another CPU are skipped. **Checksums:** a `sha256` in `CHECKSUMS` is compared with each download, and a mismatch, or a gem `gem fetch` did not produce, is `infrastructure` (exit 4) naming the gem. The verifier finds the gems at `<tree>/vendor/cache` (a link to the entry, read-only, re-made before every check) with `BUNDLE_FROZEN=true`, `BUNDLE_PATH` at its own scratch, `BUNDLE_DISABLE_SHARED_GEMS=true` and `BUNDLE_IGNORE_CONFIG=true`, and runs `bundle install --local --no-cache` once before the first check, no network (native extensions compile there, under the trust of the lane's own tests). The step is recorded in the capsule's `dependency_fetch_notes`; if it fails, every check fails with its text, the lane is refuted (exit 2) and the reason names the step and Bundler's first error line (`cowproof verify` reports it as a divergence). The builder gets no gems, as for npm. `gem` and `bundle` are `$COWPROOF_GEM` and `$COWPROOF_BUNDLE`, or the first on your `PATH`.
- **One JavaScript lockfile.** Exactly one tool's lockfile is expected (`package-lock.json` and `npm-shrinkwrap.json` are both npm's). A tree with lockfiles of two tools is `not_fetched`, and the note names them; no tool is guessed.
- **Credentials.** A `remote:` URL of the lockfile loses its `user:pass@` before `gem` sees it, and the capsule counts them (`bundler: N remote URL(s) of Gemfile.lock carried credentials`); the base's `.bundle/config` and `.gemrc` are never read or passed, so a private gem server that needs a token is out of reach by design. The base `.npmrc` is stripped as above for every tool. For yarn the base `.yarnrc.yml` loses `npmAuthToken`, `npmAuthIdent` and `npmAlwaysAuth` (top level and under `npmRegistries` and `npmScopes`), the client-certificate keys `key`, `keyfile`, `cert`, `certfile`, `httpsKeyFilePath` and `httpsCertFilePath`, `user:pass@` in a URL, and any flow-style line that holds one; the base `.yarnrc` loses `_authToken`, `_auth`, `_password` (also in the `"//host/:_authToken"` form) and the same certificate keys. `yarnPath`, `yarn-path` and `plugins` (code in the tree, which the fetch does not copy) are dropped too. The capsule counts them (`yarn: N credential line(s) of .yarnrc.yml were not used`).
- **No lifecycle script runs**, in the fetch or in the verifier: the flags above, plus `npm_config_ignore_scripts=true` and `YARN_ENABLE_SCRIPTS=false` in both. The verifier also gets `npm_config_offline`, `YARN_ENABLE_NETWORK=false`, and the entry's cache as `npm_config_cache`, `YARN_CACHE_FOLDER` and `npm_config_store_dir`, whichever tool filled the entry.
- A tree with a `Cargo.lock` too fetches both into one entry. The capsule records `dependency_ecosystems` (`cargo`, `npm`, `yarn`, `pnpm` or `bundler`) and `dependency_fetch_notes`. A failed install is `infrastructure` (exit 4), naming the tool and its first error line.
- **Not fetched:** a Bundler lockfile with a `GIT`, `PATH` or `PLUGIN SOURCE` section, one that does not parse (a merge conflict, say), two Bundler lockfiles, one whose gems come from a remote that is not https with no `sha256` in `CHECKSUMS`, or a tree that already has a `vendor/cache`; a `package.json` with no JavaScript lockfile, two JavaScript lockfiles, and Yarn Berry on Plug'n'Play. The outcome is `not_fetched`, never `fetched`, and the notes name the file; a check that needs those dependencies still fails offline in verify. Only the root `package.json` is copied, so a yarn or pnpm workspace with members in subdirectories fails as infrastructure.

The fetch's network is `COWPROOF_FETCH_NETWORK`: `registry` (the default), `open` (full outbound network, an explicit opt-in) or `none`. In `registry` mode `cargo fetch --locked`, `npm ci`, `yarn install`, `pnpm install` and `gem fetch` run in a sandbox with no network of its own and reaches a small CONNECT proxy that `cowproof` runs outside it. The proxy tunnels only to port 443 of an allowlist built from the base commit. For cargo: `index.crates.io`, `static.crates.io` and `crates.io`, the https hosts of the registries and git sources in the base's `.cargo/config.toml`, and the base `cowproof.toml`'s `[proof] fetch_hosts = ["git.example"]` for the hosts of git dependencies you allow. For npm and pnpm: `registry.npmjs.org`, the https hosts of the base `.npmrc`'s `registry` and `@scope:registry`, and `fetch_hosts`. For yarn: `registry.yarnpkg.com` and `registry.npmjs.org`, the same `.npmrc` hosts, the `registry` and `"@scope:registry"` of the base `.yarnrc`, the `npmRegistryServer` of the base `.yarnrc.yml` (top level or under `npmScopes`), and `fetch_hosts`. For Bundler: `rubygems.org` and `index.rubygems.org`, the https hosts of the `remote:` lines of the BASE's `Gemfile.lock` (a lane that repoints a `remote:` adds nothing), and `fetch_hosts`; the hosts the real RubyGems service redirects downloads to were not tested live, so name one in `fetch_hosts` if a fetch is refused at a CDN host. A patch never adds to it. A fetch that needs any other host fails as infrastructure (exit 4) and the message names the host. A signal during the fetch ends it with the run.

```
cowproof cache                 # same as `cache ls`: root, entry count, total size, oldest last use
cowproof cache ls
cowproof cache prune [--older-than <days>] [--max-size <GiB>] [--dry-run]
```

- `prune` removes entries (fetched dependencies and compile-cache seeds, see below) not used for `--older-than` days (default 30). With `--max-size`, it then removes the least recently used entries until the cache fits (fractions of a GiB are fine). `--dry-run` prints what it would remove and the bytes, and removes nothing.
- An entry's **last use** is the modification time of `deps/<key>/.last-used` (`verify-target/<key>/.last-used` for a seed), touched whenever a fetch hits the entry, installs it, or hands it to a verifier. An entry from before the marker counts as last used when its directory was modified.
- **A live run is never pruned.** Each use also writes a lease, `deps/<key>/leases/<pid>` (`verify-target/<key>/leases/<pid>` for a seed), kept for the life of that `cowproof` process. `prune` skips an entry whose lease pid is alive (it prints `kept <key>: in use by pid N`), and a lease whose process is gone protects nothing. If the system cannot say whether a pid is alive, the lease counts as alive.
- **Interrupted runs.** A directory in `deps-work/` is named `<pid>-<time>`. `prune` removes the ones whose pid is gone, and so does every fetch before it starts; one whose pid is alive is never touched.
- **Only a cache cowproof made.** A fetch writes `<root>/.cowproof-cache` (a fixed header and a version) when it creates a cache root. `cache`, `cache ls` and `cache prune` refuse a root without it, with exit 1 and an error naming the path (to make a cache there, run a lane with `COWPROOF_CACHE_ROOT` set to it), so a root set by mistake to a directory with an unrelated `deps/` loses nothing; the fetch's stale-work sweep skips such a root with a warning. A cache made before the marker is adopted, and the marker written, only when every name in `deps/` and `verify-target/` is a cache key (64 lowercase hex digits) and every name in `deps-work/` is `<pid>-<digits>[-prune]`; a root with nothing in `deps/`, `verify-target/` or `deps-work/` is not refused. Even in a marked root, prune touches only names of that shape.
- Safety: it removes only under `<root>/deps`, `<root>/verify-target` and `<root>/deps-work`, never follows a symlink (a link is removed as a link and its target is left alone), and refuses a cache root that is `/`, the home directory or not an absolute path. Exit 0 done; 1 refused or an entry could not be removed.

## The verifier's compile cache

The verifier used to compile the whole tree from scratch in the rebuilt tree's own `target/` for every verification. For a tree whose **base commit** has a `Cargo.toml` at its root it now starts from a cargo target directory of its own, a **seed**, and never from anything a builder or an earlier verification wrote.

- **Why not a shared, writable cache.** A lane's tree is untrusted: its `build.rs`, proc macros and tests run in the verifier. A compile cache that one verification writes and a later one reads would let a lane plant an artifact (a rebuilt dependency `.rlib`, a fingerprint) that a later lane's proof silently uses, and that proof would no longer be of the code it names. So no verification writes a cache another reads, and the builders' shared sccache is never used.
- **The seed** is the `target/` left by `cargo test --workspace --locked --offline --no-run`, run as one step in the verifier's sandbox (no network, the lane's dependency cache read-only, the verifier's time limit per command) on the BASE commit's tree alone: no `base.patch`, no launch baseline, no `lane.patch`. It is kept at `<cache root>/verify-target/<key>/target`, with the same `.last-used` marker and per-pid leases as a dependency entry; `cowproof cache` counts it and `cowproof cache prune` removes it by the same rules (`verify-target/<key>` in its output). The key is the SHA-256 of the base tree hash, the dependency cache key, the output of `rustc -vV`, the host triple and the seed command, so a new toolchain or a new base is a new seed.
- **A miss** builds in a private `deps-work/<pid>-<nanos>` and moves the finished directory into place with one rename, so a concurrent verification sees no seed or a whole one. Two that race for one key keep the first: the other drops its copy and uses the winner's.
- **Every verification checks against a private copy.** Before the first check the verifier copies the seed into its own scratch (`scratch/verify/target`) and sets `CARGO_TARGET_DIR` to the copy for every check, the held-out checks included. The copy is made outside any sandbox with copy-on-write where the filesystem has it (`clonefile` on macOS APFS; `FICLONE` on a Linux reflink filesystem) and byte by byte otherwise, never a hardlink, since cargo rewrites files in place. The seed is not granted to any sandbox, readable or writable, and the copy goes with the verifier's scratch. A check that writes into `$CARGO_TARGET_DIR` changes only its copy. The copy is also linked at `<tree>/target` before every check (replacing whatever stood there, a directory or file a patch committed or a symlink, which is unlinked and never followed), so a check that runs `./target/debug/<name>` finds cargo's output where it always did; `CARGO_TARGET_DIR` overrides a `build.target-dir` in `.cargo/config.toml`. With the cache off, failed or not applicable, nothing is linked.
- **It is an optimisation, never a verdict.** A seed that cannot be built (the base does not compile offline, the build times out, `rustc` is missing, the copy fails) is not a failure: the verification runs without a seed, exactly as before, and says so. A tree without a `Cargo.toml` at its root gets no seed and no `CARGO_TARGET_DIR`. `COWPROOF_VERIFY_CACHE=off` (read once at startup; `on` is the default; anything else is refused with exit 4 before anything exists) turns the whole thing off, and the verifier behaves exactly as it did before the cache.
- **Recorded, informationally.** `cowproof run` writes the capsule's `verify_cache` (sealed with it, never read by a verdict or a gate; absent from older capsules, which still read and verify): `status` is `hit`, `built`, `off`, `failed` (with `note` saying why; the verdict output carries a `compile cache: no seed was used` note) or `not_cargo`, `key` is the seed's key, and `copy` is `clone` or `copy`. `cowproof verify` writes nothing to the capsule and prints `compile cache: hit (clone)`, `built` or `failed` to stderr.
- **Limits.** A `rust-toolchain` file in a tree is not consulted when the key is made: `rustc -vV` is the verifier's `PATH`'s, and a pinned toolchain in the base changes the base tree hash. The seed is built from the base commit only, so a lane whose `base.patch` changes `Cargo.lock` finds its dependencies missing for the base build: that seed build fails (`failed`) and the lane is verified without one. The seed is a debug build; a check that builds `--release` reuses only what is shared. The workspace's own members always rebuild, since the checked-out tree is newer than the seed; the saving is the dependencies.

## Run a lane on another machine

`cowproof run packet.md --host buildbox` runs the builder, and the checks it asks for, on another machine over SSH. Your machine stays the director: it keeps the escalation queue and your rulings, the egress proxy and so the API key, the held-out checks, the proof and the capsule. The host runs only what runs sandboxed. The key never leaves the director: no argument, spec, bundle or environment sent to the host holds it, and the builder on the host presents the lane's own `placeholder-...` key, which only your proxy accepts, through two sockets that SSH forwards from the host back to you.

Add the host to `~/.config/cowproof/hosts.json` (or the file named by `$COWPROOF_HOSTS_FILE`; the older `$LANES_HOSTS_FILE` is still read). For the free-space probe of the Windows drive on a WSL host, `$WSL_DISTRO_NAME` names the distribution; over SSH, where it is unset, `$COWPROOF_WSL_DISTRO` is read, then the older `$LANES_WSL_DISTRO`. The user-level file is read before a `hosts.json` in the working directory, which `cowproof plan` and `cowproof hosts` also read, so a file that arrives with a repository cannot choose where a lane runs.

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
cargo install --git https://github.com/srmcguirt/cowproof cowproof
```

See [plugin/README.md](plugin/README.md) for details.

## License

MIT. See [LICENSE](LICENSE).
