# cowproof: agent instructions

cowproof runs untrusted builders and their commands on the user's machine, so a careless line
here is a hole in someone else's sandbox. Read [README.md](README.md#what-a-builder-trusts) for
the trust model and [docs/design.md](docs/design.md) for the architecture. The vendored port
toolkit has its own rules in [crates/portkit/CLAUDE.md](crates/portkit/CLAUDE.md).

## Checks

Run before you hand work back:

```bash
cargo fmt --all
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo deny --locked check
```

What gates a pull request, and where it is set:

| Gate | Config | Fails on |
| --- | --- | --- |
| clippy | `[workspace.lints]` in `Cargo.toml` | any warning, including the deny set below |
| cargo-deny | `deny.toml` | a RustSec advisory (vulnerable, unsound, unmaintained), a licence outside the allow list, an unknown source |
| Semgrep | `.semgrep/cowproof.yml` + registry packs | a NEW project finding at WARNING or ERROR; a project ERROR anywhere |
| gitleaks | `.gitleaks.toml` | a credential in the change's commits or the tree |
| scrub-check | `scripts/scrub-check` | home paths, private hosts, personal addresses |
| actionlint, zizmor | `.github/workflows/` | a workflow error or a weak workflow pattern |
| shellcheck | | a warning in a script outside `fixtures/` |

Locally, `lefthook install` once per machine runs the fast ones before each commit and clippy
and cargo-deny before each push. In Claude Code, `scripts/hooks/lint-edited.sh` runs the
project Semgrep rules on each file you write and tells you what your edit introduced.

## Rules the gates enforce

- **Never build an `sh -c` string with `format!`.** Pass values as arguments.
- **Never print or log a credential, never disable TLS verification, never create a
  world-writable path.** Use `tempfile` for temporary paths, not a fixed name under `/tmp`.
- **Every `unsafe` block has a `// SAFETY:` comment** naming the one operation it covers.
- **Every `#[allow(...)]` has a `reason = "..."`** and sits on the one item that needs it.
  Never a crate-wide `#![allow]`, and never an allow of `warnings`, `unsafe_code` or the
  workspace deny set.
- **No `dbg!`, `todo!` or `unimplemented!`.** An ignored test says why:
  `#[ignore = "why, and when it comes back"]`.
- **Do not loosen a gate to make a change pass.** No new `deny.toml` ignore, Semgrep exclusion
  or gitleaks allowlist entry without a reason in the file and in the pull request.
- **No em dashes** in code, comments or docs. Use a colon, a comma, or two sentences.
