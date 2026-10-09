# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
