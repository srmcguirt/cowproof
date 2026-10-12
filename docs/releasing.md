# Releasing cowproof

The exact steps for cutting a release. Tagging builds and publishes the binaries on GitHub
(`.github/workflows/release.yml`); publishing to crates.io is a separate, manual step that
only the repository owner does. Nothing in CI or in the release workflow publishes a crate.

## What a release is

- **One install, three binaries:** `cowproof`, `pk` and `pk-read`, all built by the
  `cowproof` package (`crates/cowproof-cli`). `cowproof report ...` and `cowproof plan ...`
  are subcommands; there is no `cowproof-report` or `cowproof-plan` binary.
  `crates/cowproof-cli/tests/binaries.rs` fails if the workspace builds any other binary.
- **Four tarballs** on the GitHub Release, each with a `.sha256` file, plus `SHA256SUMS`:

  | Target | Built on | Notes |
  | --- | --- | --- |
  | `aarch64-apple-darwin` | `macos-14` (Apple silicon) | native |
  | `x86_64-apple-darwin` | `macos-14` | cross-built; smoke-tested under Rosetta when the runner has it |
  | `x86_64-unknown-linux-gnu` | `ubuntu-22.04` | needs glibc 2.35 or newer |
  | `aarch64-unknown-linux-gnu` | `ubuntu-22.04-arm` | native arm64 runner (free for public repositories), so the binary is tested on the architecture it ships for |

  A tarball is `cowproof-<tag>-<target>.tar.gz` and unpacks to a directory of the same name
  holding the three binaries, `LICENSE`, `NOTICE` and `README.md`.
- **Fifteen workspace packages, fourteen published** (`portkit-index` is `publish = false`).
  `cargo install cowproof` fetches the `cowproof` package and compiles it, and cargo needs
  every library it depends on to be on crates.io too, so they are published first.
- The macOS binaries are not code-signed or notarized. A tarball fetched with `curl` runs
  as is; one downloaded in a browser carries the quarantine flag
  (`xattr -d com.apple.quarantine cowproof pk pk-read`).

## Before tagging

1. `main` is green on CI (formatting, clippy, tests on macOS and Linux, MSRV, scrub check).
2. Pick the version, `X.Y.Z` (or `X.Y.Z-rc.1` for a pre-release; the workflow marks any tag
   with a `-` as a pre-release on GitHub). Set it in all of these, in one commit:
   - `[workspace.package] version` in `Cargo.toml`;
   - the seven `cowproof-*` entries in `[workspace.dependencies]` in `Cargo.toml` (their
     `version = "..."` must match: cargo publish checks them against crates.io);
   - the `portkit-*` entries in `[workspace.dependencies]` and the `version` in each
     `crates/portkit/*/Cargo.toml` (portkit versions independently; leave them if they did
     not change, but a changed portkit crate needs its own bump and a re-publish);
   - `plugin/.claude-plugin/plugin.json` `version` (the plugin's session-start hook tells
     the user to update `cowproof` when the binary is older than this).
3. `cargo build --release --workspace --locked && ./scripts/check-release-binaries`
   prints `ok (cowproof pk pk-read )`.
4. `cargo test --workspace --locked` and `./scripts/scrub-check` pass.
5. Push the commit to `main` and wait for CI to finish green on that exact commit.

## Tag and check the workflow

```bash
git tag -a vX.Y.Z -m "cowproof X.Y.Z"
git push origin vX.Y.Z
```

The tag name must be `v` plus the workspace version, exactly; the workflow's first step
fails the build otherwise. In the repository's Actions tab, the `Release` run has four
`Build <target>` jobs and one `GitHub Release` job. Each build job builds with
`--locked`, checks the build made exactly the three binaries, smoke-tests them
(`--version`, `report --help`, `plan --help`), packs and uploads. The release job checks
all four checksums and creates the release with eight files plus `SHA256SUMS`.

If a build fails, fix it on `main`, delete the tag and the (draft or partial) release, and
tag again. A tag is safe to move only until crates.io has the version: crates.io versions
are immutable (they can be yanked, not replaced).

## Verify a downloaded tarball

On a machine that is not the build machine, for the platform you are on:

```bash
mkdir /tmp/cowproof-check && cd /tmp/cowproof-check
gh release download vX.Y.Z --repo srmcguirt/cowproof \
  --pattern 'cowproof-vX.Y.Z-aarch64-apple-darwin.tar.gz*'
shasum -a 256 -c cowproof-vX.Y.Z-aarch64-apple-darwin.tar.gz.sha256   # prints: ...tar.gz: OK
tar -xzf cowproof-vX.Y.Z-aarch64-apple-darwin.tar.gz
./cowproof-vX.Y.Z-aarch64-apple-darwin/cowproof --version             # cowproof X.Y.Z
./cowproof-vX.Y.Z-aarch64-apple-darwin/cowproof doctor
./cowproof-vX.Y.Z-aarch64-apple-darwin/pk --version
```

`cowproof doctor` exits 0 when this host can run lanes (sandbox, clone, disk, `claude`,
key, git; a missing API key is only a warning there). A failed check is the answer to "does
this binary work here"; fix or note it before announcing.

## Publish to crates.io (manual)

Only after the GitHub Release is verified. This is the step that cannot be undone: a
published version can be yanked but its name and number are used up. Log in once with your
own token (`cargo login`); never put the token in the repository, CI or an agent session.

Publish in dependency order. Each crate must be on the index before the next one that
needs it will verify (cargo waits for the index by itself). Use `--dry-run` first on the
first crate; a dry run of a later crate fails until its dependencies are really published.

```bash
cargo publish -p portkit-core
cargo publish -p portkit-mcp
cargo publish -p portkit-port
cargo publish -p portkit-read
cargo publish -p portkit-cli
cargo publish -p portkit-plugin
cargo publish -p cowproof-core
cargo publish -p cowproof-run
cargo publish -p cowproof-prove
cargo publish -p cowproof-host
cargo publish -p cowproof-plan
cargo publish -p cowproof-lint
cargo publish -p cowproof-report
cargo publish -p cowproof
```

Then, from a clean shell (no checkout), check that what users get works:

```bash
cargo install cowproof
cowproof --version
cowproof doctor
```

## Notes

- The seven `cowproof-*` library crates are published only because `cargo install cowproof`
  needs them. They are internal: their APIs are not stable and may change in any release.
- `crates/cowproof-lint` has one test that reads `../cowproof-run/...`, so `cargo test`
  inside the published `cowproof-lint` tarball does not compile; building it (what
  `cargo publish` and `cargo install` do) is unaffected. The same is true of the CLI's
  tests that read the repository's `fixtures/`, `plugin/` and `README.md`. Tests run from
  the repository.
- Release builds do not run the test suite; the tagged commit's CI run is the gate.
- The workflow pins actions by exact version tag (`actions/checkout@v4.2.2`,
  `actions/upload-artifact@v4.6.2`, `actions/download-artifact@v4.3.0`) and uses the
  runners' preinstalled `rustup` and `gh`. Pinning to commit SHAs is a follow-up.
- A Homebrew tap follows the first release (`docs/design.md`, Distribution Plan).
