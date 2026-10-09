# portkit

A template for porting tested Python agentic processes to Rust tooling exposed as
a CLI, an MCP server, and a library. Cargo workspace, no runtime services.

## Commands

```bash
cargo check --workspace          # typecheck
cargo test  --workspace          # all tests
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all
just capture                     # re-record fixtures from the Python reference
just replay                      # replay fixtures against the Rust port
```

## Hard rules (violations are bugs)

- **Never write to stdout outside a command's actual output.** On the MCP stdio
  transport stdout is the protocol channel; one stray `println!` corrupts the
  stream and the host drops the connection. Diagnostics go to stderr via
  `tracing`. `tests/mcp_stdio.rs` runs the server with `RUST_LOG=debug` and fails
  if anything but JSON frames reach stdout.
- **A tool is defined once, in one `impl Tool`.** The CLI, MCP, and parity
  surfaces are all generated from it. Never special-case a surface — if MCP and
  the CLI can disagree about what a tool returns, the parity harness is lying.
- **Tools must be deterministic given their input.** Clocks, RNG, and network
  calls get injected through the constructor so fixtures can pin them. A
  nondeterministic tool cannot be parity-checked, which defeats the point.
- **`input_schema` is load-bearing.** It is the only guide a model has to calling
  the tool. Changing a tool's arguments without updating its schema breaks agent
  callers silently.
- **Return `Error::invalid_input` when the caller can fix it** by changing
  arguments, and `Error::tool_failed` when it cannot. The MCP layer reads
  `is_caller_fault()` to decide whether to tell the model to retry.
- **Never loosen `parity.epsilon` to make a test pass.** Epsilon exists for
  last-place float rounding between languages. A real disagreement gets fixed, or
  recorded as an `accepted` difference on the fixture with a written reason —
  scoped to a JSON Pointer path, never a blanket pass.
- **Integers compare exactly regardless of epsilon.** An off-by-one count is a
  bug, not rounding. Do not "fix" a count mismatch by widening tolerance.
- **Fixtures are committed and reviewed like tests.** Regenerate them with
  `just capture` only for an intentional behaviour change, and say so in the
  commit message — a fixture diff is a behaviour diff.

## Architecture

`core/` defines `Tool` and `Registry`; everything else consumes them.
`mcp/` serves a registry over JSON-RPC 2.0. `port/` captures and replays
fixtures. `cli/` is the clap surface and exposes `run(registry)` so downstream
binaries are a few lines. `demo/` holds worked examples and is meant to be
deleted on fork.

Dependency direction is one-way: `core` ← {`mcp`, `port`, `cli`}. `port` depends
on `mcp` so it can replay through the agent surface. Nothing depends on `demo`
except the reference binary.

## Adding a tool

1. `impl Tool` in your tools crate, with an accurate `input_schema`.
2. Register it in `registry()`.
3. Add cases to `examples/cases.jsonl`, `just capture`, `just replay`.
4. Unit-test the edges that fixtures cannot reach (errors, invalid input).

## Config

Layered: embedded `core/resources/default_config.toml` → `--config` → `PK_*` env
with `__` to descend. Note that a bare `PK_<SECTION>` sets the whole table and
will fail to deserialize; log level is `RUST_LOG`, not `PK_LOG`.

## Git conventions

Branch `main`; commits `type(scope): description` (feat, fix, chore, docs, refactor, test).

## Roadmap

Porting tool suites from existing Python and Rust projects — browser automation
and QA (gstack), and other agentic tooling — onto this registry so they are
reachable as both CLI commands and MCP tools. When adding those, keep tools
narrow and composable rather than porting a whole workflow as one tool: agents
choose better from a list of small, well-described tools.

## References

- [rust-porting-playbook](https://github.com/jlevy/rust-porting-playbook) —
  Python-to-Rust porting methodology; the `accepted` differences model comes from
  its flowmark case study.
- [MCP specification](https://modelcontextprotocol.io/specification) — the wire
  format `mcp/` implements.
