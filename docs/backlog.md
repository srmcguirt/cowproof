# Backlog

Work the crate port (2026-10-09) deferred or exposed. Newest first.

- **Restore portkit's stdout-protocol test.** The portkit import (D15) dropped portkit's root package and its root tests, including `tests/mcp_stdio.rs`, which runs the MCP server with `RUST_LOG=debug` and fails if anything but JSON frames reaches stdout. Re-target it at the `pk` / `cowproof serve` binary when that lands (step 8), along with `tests/{cli,hook,trace,parity}.rs` (portkit-integration.md section 4.1).

- **Recurring: track sandbox-runtime upstream fixes** (eng review D16). cowproof's sandbox and egress proxy follow anthropics/sandbox-runtime's design (D4). Record the ported upstream commit in NOTICE when step 4 lands, and at every cowproof release review sandbox-runtime's releases and security advisories, mapping each fix to `SandboxPolicy` and the proxy.

- **Rebuild handback-report snapshot fixtures synthetically.** The original `lanes-report` tests snapshot-checked reports for five real lane handbacks (four full snapshots and one fenced "arrow-format" check parse). Those fixtures were lane patches of the source platform's product code, which the relicensing does not cover, so they and their tests were not ported. Recreate the same coverage with synthetic handbacks: a checks table, bullet checks, fenced commands with the result in the following paragraph, the arrow format (`command -> result`), questions, limits, unverified and deferred sections, and a migration-baseline case.
- **Node parity test is opt-in.** `cowproof-core`'s `parity_with_node_if_available` now runs only when `COWPROOF_REFERENCE_RUNNER` points at a `run-lane.mjs`. It passed against the source runner on 2026-10-09. Replace it with portkit parity fixtures captured from that runner (design step 3), committed here, so parity no longer needs the runner present.
- **Config file rename.** The crates still read `lanes.config.json` and the `LANES_HOSTS_FILE` and `LANES_WSL_DISTRO` variables. Move to `cowproof.toml` and `COWPROOF_*` names with a compatibility read of the old ones.
- **"Waiting on founder" in plans.** `cowproof-plan` reports lanes waiting on "the founder" by matching that word in notes. Generalize to an owner or approver role for outside users.
- **Split the flaw rules.** `cowproof-report/rules/flaws.toml` still mixes generic gaming patterns with rules specific to one stack (Supabase migration locks, Postgres policies). Split into the generic pack and an example project pack, as the design says.
- **Binaries.** The port keeps three binaries (`cowproof`, `cowproof-report`, `cowproof-plan`). The design ships one; fold the other two in as subcommands.
- **Bring over the tool documentation** (`hosts.md`, `packet-lint.md`, `plan-files.md`, `handback-report.md`) after scrubbing, and the source runner as the parity reference if the opt-in test is kept.
