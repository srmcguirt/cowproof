# portkit development tasks

default:
    @just --list

check:
    cargo check --workspace --all-targets

test:
    cargo test --workspace

lint:
    cargo clippy --workspace --all-targets -- -D warnings

fmt:
    cargo fmt --all

# Everything CI runs, in the order CI runs it.
ci: fmt-check lint test

fmt-check:
    cargo fmt --all -- --check

# Re-record fixtures from the Python reference. Review the diff: a fixture
# change is a behaviour change.
capture:
    cargo run --bin pk -- port capture \
        --cmd 'python3 examples/python/agent.py' \
        --cases examples/cases.jsonl \
        --out fixtures

# Replay fixtures against the Rust port, on both surfaces.
replay:
    cargo run --bin pk -- port replay --fixtures fixtures

# Prove the MCP server answers a real handshake.
mcp-probe:
    #!/usr/bin/env bash
    set -euo pipefail
    printf '%s\n' \
      '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}' \
      '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
    | cargo run --quiet --bin pk -- serve

clean:
    cargo clean

# Fail if the committed fixtures no longer match the Python reference.
check-fixtures:
    #!/usr/bin/env bash
    set -euo pipefail
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT
    cargo run --quiet --bin pk -- port capture \
        --cmd 'python3 examples/python/agent.py' \
        --cases examples/cases.jsonl --out "$tmp"
    python3 scripts/check_fixtures_fresh.py fixtures "$tmp"
