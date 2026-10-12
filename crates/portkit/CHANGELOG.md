# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `pk port exec`: capture a script or any executable as a whole process, in a fresh
  root with the network denied, a built environment, `umask 022`, PATH shims with
  scripted responses for the external programs a case declares, and a `date` shim
  pinned by `PORTKIT_NOW`. The fixture records
  `{exit, stdout, stderr, files_after, deleted, calls}`. Each case runs twice and a
  case whose runs differ is refused. `pk port wrap` runs a Rust port in the same
  harness as a plugin, so `pk port replay` compares like with like.
- `path_roots` substitution for process captures (`path-roots` v1: `$ROOT`, `$HOME`,
  `$TMP`, `$SRC`), recorded in the fixture as `normalized` and refused at replay when
  the name or version is unknown.
- `pk port capture --cwd`, `--env` and `--clear-env`, and `env` on a case (recorded
  with the fixture), so a fixture does not depend on the capturing shell.
- `expect_error` on a case: a reference that fails on a "must reject" case is recorded
  as `{"error": {"exit": N, "message": ".."}}`, and a port's failure is compared as the
  same envelope.

### Changed

- The commands that never read the registry (`port capture`, `port exec`, `port wrap`,
  `port adapter` and the harness's own) no longer build it, so a plugin that is
  `pk port wrap` cannot discover itself.

## [0.1.0]

Initial release.

### Added

- `Tool` trait and `Registry` — one definition, three surfaces.
- MCP server over JSON-RPC 2.0 on stdio, supporting protocol revisions
  2025-06-18, 2025-03-26, and 2024-11-05.
- Parity harness: capture fixtures from a reference implementation, replay them
  against the Rust port through either the registry or the MCP envelope.
- Tolerant JSON differ with absolute and relative float tolerance, exact integer
  comparison, JSON Pointer paths, and ignorable paths.
- `accepted` differences on fixtures — scoped, reason-carrying exemptions that
  stay visible in reports instead of failing the build.
- CLI: `tools`, `schema`, `run`, `serve`, `port capture`, `port replay`,
  `config`, `completion`.
- Layered configuration (embedded defaults, file, `PK_*` environment).
- Worked demo tools with a matching Python reference implementation.
