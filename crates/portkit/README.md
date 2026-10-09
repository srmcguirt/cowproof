# portkit

A Rust CLI template for porting tested Python agentic processes to Rust tooling —
usable as a **CLI**, an **MCP server**, and a **library**, with a parity harness
that proves the port is faithful.

Define a tool once. Get three surfaces and a regression test for free.

```
                         ┌─────────────────┐
   impl Tool for Mine ──▶│    Registry     │
                         └────────┬────────┘
              ┌───────────────────┼───────────────────┐
              ▼                   ▼                   ▼
        pk run mine          pk serve            pk port replay
       (CLI, humans)      (MCP, agents)      (parity vs. Python)
```

## Why

Porting an agentic process from Python to Rust is easy to start and hard to
finish, because "it looks equivalent" is not a claim CI can check. portkit makes
equivalence a build artifact: capture what the Python implementation actually
returns, commit those fixtures, and fail the build when the Rust port drifts.

It checks that through the **MCP surface** as well as direct calls — a tool that
is correct in Rust but wrong through `tools/call` is still broken for the agent
that has to use it.

## Quickstart

```bash
git clone https://github.com/srmcguirt/portkit && cd portkit
cargo build

pk tools                                    # what is registered
pk run word_frequency -a text='a b a b c'   # call one
pk run word_frequency -a text='a b' --through-mcp   # call it as an agent would
pk serve                                    # speak MCP on stdio
```

The demo tools ship with a matching Python reference, so the whole porting loop
runs out of the box:

```bash
just capture   # run examples/python/agent.py over examples/cases.jsonl
just replay    # replay the captured fixtures against the Rust port
```

```
  surface: direct
  chunk_text                       5/5    PASS
  word_frequency                   5/5    PASS

  surface: mcp
  chunk_text                       5/5    PASS
  word_frequency                   5/5    PASS

  10 passed, 0 failed, 0 errored, 0 not ported (10 total)
```

## The porting workflow

**1. Write cases** — a JSONL file of inputs worth pinning. Include the edge cases
your Python tests already cover.

```jsonl
{"tool": "word_frequency", "id": "shares-are-thirds", "input": {"text": "a b c a b c"}}
```

**2. Capture what Python does.** The contract is one JSON request on stdin, one
JSON result on stdout — small enough to bolt onto an existing codebase without
restructuring it. See [`examples/python/agent.py`](examples/python/agent.py).

```bash
pk port capture --cmd 'python3 agent.py' --cases cases.jsonl --out fixtures/
```

**3. Implement the tool in Rust**, then replay until it matches.

```bash
pk port replay --fixtures fixtures/
```

**4. Wire it into CI** with a test, so drift fails the build:

```rust
#[tokio::test]
async fn matches_the_python_reference() {
    portkit_port::assert_parity("fixtures", &registry()).await;
}
```

### Floating point

Python and Rust sum in different orders and round differently at the last place.
Demanding bit equality flags every port as broken, so comparison is tolerant by
default (`epsilon = 1e-9`, absolute and relative), while **integers compare
exactly** — an off-by-one count is a bug, not rounding.

```bash
pk port replay --epsilon 1e-6        # loosen for a noisy pipeline
PK_PARITY__EPSILON=0 pk port replay  # demand exactness
```

### Differences you accept on purpose

Real ports rarely end at byte equality: a Rust library will differ from its
Python counterpart somewhere. The honest outcome is a port that matches
everywhere except a few places you have understood and written down.

Record those on the fixture, and they stop failing the build without going
silent — the reason shows up in every report, where review can audit it:

```json
{
  "tool": "format_markdown",
  "id": "escaped-hyphen",
  "input": { "text": "a \\- b" },
  "expected": { "out": "a \\- b" },
  "accepted": [
    {
      "path": "/out",
      "reason": "comrak drops the escape during parsing; not recoverable post-hoc"
    }
  ]
}
```

Exemptions are scoped to a JSON Pointer path, so accepting one field never
quietly excuses a regression in another. This pattern comes from the
[Rust Porting Playbook](https://github.com/jlevy/rust-porting-playbook)'s
[flowmark case study](https://github.com/jlevy/rust-porting-playbook/tree/main/case-studies/flowmark),
where the finished port was byte-identical to Python *except* for a documented
set of parser differences.

## Bounded output

Tool results are capped at the CLI and MCP boundaries, so one runaway list
cannot crowd out a conversation. The largest array is trimmed first, summary
fields beside it are kept, and the note says how to get the rest:

```json
{
  "chunks": [ ...230 of them... ],
  "count": 1000,
  "_elided": [{
    "path": "/chunks", "kept": 230, "total": 1000,
    "retry": "raise `size` or pass a shorter `text` to see fewer, larger chunks"
  }]
}
```

The `retry` text comes from the tool's own output schema:

```json
"chunks": { "type": "array", "x-page-hint": "call with offset=<n>" }
```

That half matters. "Truncated 770 items" tells an agent nothing, so it reads
the whole thing another way and the budget has only moved the cost.

Precedence is `--budget <bytes>` → the tool's `ToolSpec::with_budget` → config
`[output] max_bytes` (16 KB by default, ~4 bytes per token). `--full` prints
everything.

**Budget is presentation, not truth.** `Registry::call` always returns the
whole value, so the parity harness compares what the tool actually produced.
Trimming before the harness saw it would make fixtures agree with a summary
rather than with the port.

## Plugins

Any executable that can describe itself is a tool. Declare it:

```toml
# .portkit/plugins.toml
[[plugin]]
command = "python3"
args = ["tools/wordcount.py"]
timeout_secs = 30
```

Implement two things — a `--portkit-spec` flag, and one JSON request on stdin:

```python
if "--portkit-spec" in sys.argv:
    json.dump({"name": "wordcount", "description": "...",
               "input_schema": {...}}, sys.stdout); sys.exit(0)

words = json.load(sys.stdin)["input"]["text"].split()
json.dump({"words": len(words), "unique": len(set(words))}, sys.stdout)
```

It now appears in `pk tools`, answers over CLI and MCP, and **inherits argument
validation, output budgets, provenance and tracing it never implemented**.

### The contract is the porting on-ramp

That stdin/stdout envelope is the one `pk port capture` already speaks to a
reference implementation, so a plugin is also a fixture source:

```text
register as plugin  →  pk port capture  →  port to Rust  →  pk port replay  →  swap
   works today          records what        write the         proves they      same tool,
                        it does             native tool       agree            now native
```

Nothing has to be rewritten before it becomes useful.

### Costs and constraints

A subprocess call is **~40 ms** against **~0.05 ms** for a native tool — spawn
cost, and the reason to port the hot ones eventually. Every entry has a
timeout, because a plugin that hangs would otherwise hang the agent waiting on
it. A plugin that fails to register is reported and skipped rather than taking
the server down.

**Discovery is a manifest, never a PATH scan.** Scanning a directory and
executing what it finds turns a dropped file into code execution, and the
convenience is not worth it.

### Global and project layers

```
~/.portkit/plugins.toml    tools available in every repo
.portkit/plugins.toml      tools belonging to this repo — wins on a name collision
```

A tool used across repos is declared once. A repo can override one it inherits
without editing anyone else's manifest, and the override is reported rather
than silent — a tool quietly replaced is worse than one that failed loudly.
Missing manifests are skipped; having no plugins is the normal case.

## Schema tools

Point the config at a captured snapshot and `pk serve` exposes the schema
capability as real tools:

```toml
[schema]
snapshots = [".portkit/schema/fellwork.json"]
```

```
$ pk tools
  chunk_text      ...
  schema_check    Check that a table, or a column of a table, actually exists
  schema_columns  Report the real columns of a table, with types and nullability
  schema_tables   List tables known to a schema snapshot

$ pk run schema_check -a source=fellwork -a table=source.tokens -a column=verse_ref
{"exists":false,"kind":"column","name":"verse_ref","suggestions":["verse_id"],
 "provenance":{"source":"fellwork","kind":"postgres_catalog",
               "captured_at":"2026-09-09T19:42:44Z","fingerprint":"37902a5df4df512c"}}
```

Registering matters beyond convenience: a tool in the registry inherits
argument validation, output budgets, provenance and tracing. Shelling out to a
separate binary bypasses all four. Registration also wires the same snapshots
in as the `x-schema-ref` resolver, so the tools reporting on a schema and the
gate checking against it can never disagree.

Snapshots load **before** `tools/list` is answered — an agent's first view of
the interface should already be grounded rather than corrected after its first
wrong guess. That is why `portkit_cli::run_with` takes a builder rather than a
finished registry: tools that depend on configuration cannot exist before
`--config` is parsed.

## Measuring what tools cost

Claude Code exports OpenTelemetry — counts, latencies, token totals per
session. What it does not export is **bytes returned per tool call**, and that
is the number that decides whether a tool earns its place. Finding it otherwise
means parsing session transcripts after the fact.

Turn tracing on and portkit records it as it happens:

```toml
[trace]
enabled = true
dir = ".portkit/traces"
```

```
$ pk trace
  TOOL             CALLS   DELIVERED       SAVED     AVG ms  REJECTED
  ------------------------------------------------------------------
  chunk_text           3     30.5 KB    120.3 KB       3.06         1
  word_frequency       2       327 B         0 B       0.05         0

  5 calls · 30.9 KB delivered · 120.3 KB kept out of context · 1 rejected
```

`SAVED` is what the budget kept out of context; `REJECTED` counts calls the
schema gate stopped before the tool ran. A gate that fires often is working; a
gate that never fires may be misconfigured, and collapsing rejections into
failures would hide both.

Recorded at the CLI and MCP surfaces rather than in `Registry::call`, because
only the surfaces know what was *delivered* after budgeting — and delivered is
what context pays for. Off by default; JSONL, one object per line, so a crash
costs at most one record.

## Is this session actually watched?

Hooks fail silently by design — one that breaks the session it measures is
worse than one that measures nothing. The cost is that a misconfigured setup
looks exactly like a quiet one, and you find out weeks later that the ledger
is empty.

```
$ pk doctor
  MISS  pk on PATH        not found
  MISS  hooks registered  not in any of 3 settings files
  MISS  tracing enabled   [trace] enabled = false
  MISS  hooks have fired  no agent-surface records
```

Four checks, reported separately because they fail for different reasons and
need different fixes. The last is the only one that is *evidence* rather than
intent: registered hooks that never fire look identical to no hooks at all.
Exits non-zero, so a setup script can gate on it.

State — the symbol index and `pk-read`'s delivery ledger — lives in
`~/.portkit/`, never the working directory. `PORTKIT_STATE_DIR` overrides it.

## Rewrite rules and verification

A rule may only rewrite once its own `verified.status` is `pass` — per rule,
not per binary, since `--range` and `--ls` are never ready at the same time.
Everything else falls through to suggest-only, which costs tokens but cannot
be wrong.

```json
{ "name": "sed-range",
  "matches": "^sed -n '?(\\d+),(\\d+)p'? (\\S+)$",
  "rewrite": "pk-read --range $1:$2 $3",
  "fidelity": "subset-declared",
  "recovery": "pk-read --range $1:$2 $3 --full",
  "verified": { "status": "pending" } }
```

### Fidelity classes

Byte-equality forecloses the win — identical bytes are identical tokens — but
"semantically equivalent" is too vague to implement. So each class carries a
gate that can actually be checked:

| class | gate |
| --- | --- |
| `exact` | byte-identical |
| `normalized` | equal after a **declared, versioned** transform |
| `subset-declared` | ordered subset, and the omission is declared |
| `keyset` | identifying names preserved; columns may drop |
| `reference` | *not registration-verifiable* — a claim about caller state |

An unknown normalizer fails rather than passing, or a verification means
whatever the current binary happens to do.

### Pair-run verification

The ledger records commands, not the bytes they returned, so history cannot be
reproduced. `pk verify` runs the original and its rewrite **now**, against the
same tree, and applies the class gate to the pair:

```
$ pk verify --window 500
  sed-range         1 cases     1 passed     0 skipped  -> Pass
  ls-keyset         1 cases     1 passed     0 skipped  -> Pass
  cat-outline       0 cases     0 passed     0 skipped  -> Pending
```

Cases whose target no longer exists are **skipped and counted**, never quietly
dropped: a rule that passed two of four hundred has not been verified. The
recorded result carries `tree_sha`, because a rewrite verified against one
working tree says little about another.

## Watching the agent

portkit's own traces only ever saw portkit's own tools, while the expensive
calls — `Read`, `Grep`, `Bash` — happen outside it. Hooks close that gap:

```json
{ "hooks": {
    "PostToolUse":      [{ "hooks": [{ "type": "command", "command": "pk hook post-tool-use" }] }],
    "UserPromptSubmit": [{ "hooks": [{ "type": "command", "command": "pk hook user-prompt-submit" }] }],
    "SessionEnd":       [{ "hooks": [{ "type": "command", "command": "pk hook session-end" }] }]
} }
```

Now the trace bank measures the agent rather than measuring portkit measuring
itself — and when the data warrants it, says so:

```
portkit: `/repo/index.ts` has been read 3 times this session (12 KB). If you
are looking for one definition, `pk run sym` returns just its span instead of
the whole file.
```

### Thresholds are measured, not chosen

Each pattern was fitted to 878 local sessions — 59,077 calls, 353 MB:

| pattern | what the data showed |
| --- | --- |
| same file read 3+ times | 818 re-reads, 3.1 MB |
| 5+ files read in a row | `read_file → read_file` **10,013** consecutive pairs |
| one result over 32 KB | images were 74% of all bytes |
| same URL fetched twice | 3,214 consecutive `web → web` pairs |

Two reads of a file draw no comment — re-reading after an edit is legitimate.
Three is searching.

### Restraint is the feature

Suggesting costs tokens too. A 200-byte nudge that saves 2 KB is a good trade
once; fired on every call it is a loss, and an agent learns to skip advice
that is always there. So: one suggestion at a time, never the same advice
twice, and a rate limit between them.

A hook also **never breaks the session it measures** — a malformed payload, an
unwritable file, an unknown event all exit 0 silently. And only the *target* of
a call is stored, never its arguments, so file contents never reach the trace
bank.

## Using it in your repo

**As a template** — clone, delete `demo/`, point `src/main.rs` at your own
registry, and replace the fixtures.

**As a library** — depend on the crates and keep your own binary:

```toml
[dependencies]
portkit-core = "0.1"
portkit-cli  = "0.1"   # optional: the whole command surface
portkit-mcp  = "0.1"   # optional: MCP server
```

```rust
#[tokio::main]
async fn main() -> std::process::ExitCode {
    portkit_cli::run(my_registry()).await
}
```

## Defining a tool

```rust
use portkit_core::{async_trait, Error, Registry, Result, Tool, ToolSpec};
use serde_json::{json, Value};

struct Summarize;

#[async_trait]
impl Tool for Summarize {
    fn spec(&self) -> ToolSpec {
        ToolSpec::new(
            "summarize",
            "Summarize a document to at most `max_words` words.",
            json!({
                "type": "object",
                "properties": {
                    "text": {"type": "string"},
                    "max_words": {"type": "integer", "default": 100}
                },
                "required": ["text"]
            }),
        )
    }

    async fn call(&self, input: Value) -> Result<Value> {
        let text = input.get("text").and_then(Value::as_str)
            .ok_or_else(|| Error::invalid_input("summarize", "`text` is required"))?;
        Ok(json!({ "summary": text }))
    }
}

pub fn registry() -> Registry {
    Registry::new().with(Summarize)
}
```

The `input_schema` is the model's only guide to calling your tool — MCP clients
build calls from it. Keep it accurate.

Return `Error::invalid_input` when the caller could fix the problem by changing
its arguments: the MCP layer tells the model to retry rather than reporting a
dead end.

## Using it as an MCP server

```bash
claude mcp add portkit -- /path/to/pk serve
```

Or in `claude_desktop_config.json`:

```json
{ "mcpServers": { "portkit": { "command": "/path/to/pk", "args": ["serve"] } } }
```

> **On a stdio transport, stdout is the protocol channel.** A stray `println!`
> corrupts the stream and the host drops the connection, with an error that
> points nowhere near the print. All diagnostics go to stderr; there is a test
> that runs the server with `RUST_LOG=debug` and fails if anything but JSON
> reaches stdout.

## Commands

| Command | Purpose |
| --- | --- |
| `pk tools [--json]` | List registered tools |
| `pk schema <tool>` | Print a tool's JSON Schema |
| `pk run <tool>` | Call a tool (`--input`, `-a k=v`, `--through-mcp`) |
| `pk serve` | Serve MCP over stdio |
| `pk port capture` | Record fixtures from the reference implementation |
| `pk port replay` | Replay fixtures (`--surface`, `--epsilon`, `--json`) |
| `pk config` | Show effective configuration |
| `pk completion <shell>` | Generate a completion script |

## Configuration

Layered: embedded defaults → `--config <file>` → `PK_*` environment.
Use `__` to descend, e.g. `PK_PARITY__EPSILON=1e-6`. Log verbosity is `RUST_LOG`,
because the config layer claims the whole `PK_` namespace.

## Layout

| Crate | Role |
| --- | --- |
| `core/` | `Tool`, `Registry`, config, errors, the tolerant JSON differ |
| `mcp/` | MCP server — JSON-RPC 2.0 over stdio |
| `port/` | Parity harness — capture, replay, reporting |
| `cli/` | Clap surface; `run(registry)` for downstream binaries |
| `demo/` | Worked examples. Delete when you fork. |

## Credits

Shape borrowed from [rust-starter](https://github.com/rust-starter/rust-starter).
The porting methodology — and the accepted-differences pattern in particular —
draws on [jlevy/rust-porting-playbook](https://github.com/jlevy/rust-porting-playbook).

## License

MIT OR Apache-2.0
