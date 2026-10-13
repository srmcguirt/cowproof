//! Dependency prefetch before verify runs (D6, D11, D14, F-1).
//!
//! The verifier runs a lane's checks offline, so the dependencies they need are fetched
//! first, by the runner, outside any builder, into a cache the verifier gets read-only.
//!
//! * **Key** ([`dependency_cache_key`]): lockfile, registry configuration and target,
//!   computed on the REBUILT tree: the base commit, then `base.patch`, then the launch
//!   baseline, then `lane.patch`. The registry configuration is the one the tree had
//!   BEFORE `lane.patch` (see [`RegistryConfigSnapshot`]): a builder never chooses
//!   where its dependencies come from.
//! * **Cache**: `<cache root>/deps/<key>/cargo/{registry,git}`. A hit is a complete
//!   directory. A miss runs `cargo fetch --locked` in a sandbox into a private work
//!   directory and renames it into place, so a concurrent lane sees either no entry or a
//!   whole one, never half of one.
//! * **The fetch sandbox** ([`SandboxPolicy::dependency_fetch`]): it may write only its
//!   own work directory (the `CARGO_HOME` it fills and a private `HOME`) and read the
//!   rebuilt tree, the toolchain and the one `cargo` executable. It holds no key (its
//!   environment is `PATH`, `CARGO_HOME`, `RUSTUP_HOME`, `HOME` and the proxy variables
//!   below, nothing inherited), cannot see the lane's control directory, the other lanes or
//!   the real home, and `cargo fetch` runs no `build.rs` and no procedural macro. Its
//!   NETWORK is the one knob: [`FetchNetwork`], `COWPROOF_FETCH_NETWORK`, read by
//!   `FetchNetwork::from_env` (called by `fetch_dependencies` in `cowproof-cli`, which both
//!   `cowproof run` and `cowproof verify` use).
//!   * `registry` (the default): no network of its own. The sandbox reaches one Unix socket
//!     through the in-sandbox bridge (`cowproof net-bridge`, as a builder does for its model
//!     proxy), and `CARGO_HTTP_PROXY` / `HTTPS_PROXY` point `cargo` at the bridge. The
//!     runner serves that socket with a CONNECT proxy ([`crate::fetch_proxy`]) that tunnels
//!     only to `host:443` of an allowlist built from the base: the crates.io hosts, the https
//!     hosts of the registries and git sources the base's cargo configuration names, and
//!     the base `cowproof.toml`'s `[proof] fetch_hosts`. A refused host fails the fetch as
//!     infrastructure (F-1) and is named in the message.
//!   * `open`: full outbound network, an explicit opt-in. The sandbox still holds no key,
//!     no control directory and no home.
//!   * `none`: a sandbox with no network at all, enough for a registry that is a directory
//!     in the repository (the tests use it).
//! * **Process group**: the fetch command is its own process group, listed in the run's
//!   `cowproof_prove::runner::GroupSet` when the caller has one (the caller's `exec`), so
//!   a signal ends it with the run instead of leaving it to run out [`FETCH_TIMEOUT`].
//! * **Cache root**: `~/.cache/cowproof`, or the directory named by the environment
//!   variable `COWPROOF_CACHE_ROOT` ([`CACHE_ROOT_ENV`]). Tests set it so they never touch
//!   the real cache.
//! * **Upkeep**: every hit and install takes a lease and touches a use marker in the entry,
//!   and `cowproof cache prune` removes the unused (see [`crate::cache`]); a fetch also
//!   clears the stale work directories of interrupted runs.
//! * **What is covered**: Cargo, npm, yarn and pnpm.
//!   * A tree with a `Cargo.lock` gets `<entry>/cargo/{registry,git}`.
//!   * A tree with a `package-lock.json` or `npm-shrinkwrap.json` at its root gets
//!     `<entry>/npm/node_modules` and `<entry>/npm/cache`. The fetch runs
//!     `npm ci --ignore-scripts --no-audit --no-fund` in a scratch directory that holds
//!     copies of `package.json`, the lockfile and the base's `.npmrc` with every auth line
//!     (`_authToken`, `_auth`, `_password`, and credentials in a URL) removed, with
//!     `npm_config_cache` inside the entry, and the sandbox environment is `PATH`, `HOME`,
//!     the proxy variables and `npm_config_*` settings, nothing inherited. The allowlist is
//!     `registry.npmjs.org`, the https hosts of the base `.npmrc`'s `registry` and
//!     `@scope:registry`, and the base `cowproof.toml`'s `[proof] fetch_hosts`. No lifecycle
//!     script of any package runs, at fetch or in the verifier. A tree with a `Cargo.lock`
//!     too fetches both into the one entry.
//!   * A `yarn.lock` or `pnpm-lock.yaml` is installed the same way into the same layout
//!     ([`JsTool`]): classic yarn with `yarn install --frozen-lockfile --ignore-scripts
//!     --non-interactive`, Yarn Berry with `yarn install --immutable --mode=skip-build` (only
//!     with `nodeLinker: node-modules`; Plug'n'Play is [`FetchOutcome::NotFetched`]), pnpm with
//!     `pnpm install --frozen-lockfile --ignore-scripts --config.node-linker=hoisted`. The
//!     base's `.yarnrc.yml` and `.yarnrc` are stripped of credentials, certificate keys and
//!     code-in-the-tree settings ([`strip_yarnrc_yml`], [`strip_yarnrc`]) like the `.npmrc`.
//!     Exactly one tool's lockfile is expected: two are `NotFetched`, naming both.
//!   * Nothing else is fetched. A tree whose only dependency file is a `package.json` with no
//!     lockfile, a `Gemfile.lock`, two tools' lockfiles or a Berry Plug'n'Play `yarn.lock` has
//!     no entry; the outcome is [`FetchOutcome::NotFetched`] and says why in
//!     [`Prefetch::notes`], and is never "fetched". Bundler is in the backlog.
//!   * `npm`, `yarn` and `pnpm` are found by `COWPROOF_NPM`, `COWPROOF_YARN` and
//!     `COWPROOF_PNPM` (an absolute path, the test hook the way `CARGO` is for cargo) or the
//!     first one on the director's `PATH`; its directory is put on the fetch's `PATH` so its
//!     `node` is found. A tool that needs files under the hidden home (nvm) is not reachable
//!     from the sandbox.

use crate::bridge::bridge_port;
use crate::cache::{self, Alive};
use crate::fetch_proxy::{self, FetchAllowlist, FetchProxy, Resolver};
use crate::{
    LaneLayout, NPM_CACHE, NPM_ENTRY_DIR, NPM_LOCKFILES, NPM_MANIFEST, NPM_MODULES, NetworkMode,
    PNPM_LOCKFILE, REGISTRY_CONFIGS, SandboxPolicy, YARN_LOCKFILE, dependency_cache_key,
    render_macos_profile, sandbox_command,
};
use anyhow::{Context, Result, bail};
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// The environment variable that overrides the cache root.
pub const CACHE_ROOT_ENV: &str = "COWPROOF_CACHE_ROOT";

/// The environment variable that picks the fetch's network: `registry` (default), `open`
/// or `none`.
pub const FETCH_NETWORK_ENV: &str = "COWPROOF_FETCH_NETWORK";

/// A TESTING HOOK: fixes the address of allowed registry hosts, as
/// `host=ip:port[,host=ip:port...]` ([`Resolver::parse`]). Every address must be a loopback
/// `ip:port` (`127.0.0.0/8`, `::1`), so it can send an allowed name to a fake on this
/// machine and nowhere else; it never admits a name the allowlist refuses. When set, the
/// runner warns on stderr and the capsule records it (`dependency_fetch_resolve`).
pub const FETCH_RESOLVE_ENV: &str = "COWPROOF_FETCH_RESOLVE";

/// The environment variable that names the `npm` to fetch with (an absolute path to a file).
/// Without it the first `npm` on the director's `PATH` is used. Tests point it at a fake.
pub const NPM_ENV: &str = "COWPROOF_NPM";

/// The environment variable that names the `yarn` to fetch with, as [`NPM_ENV`] does for npm.
pub const YARN_ENV: &str = "COWPROOF_YARN";

/// The environment variable that names the `pnpm` to fetch with, as [`NPM_ENV`] does for npm.
pub const PNPM_ENV: &str = "COWPROOF_PNPM";

/// How long one `cargo fetch`, `npm ci`, `yarn install` or `pnpm install` may take.
pub const FETCH_TIMEOUT: Duration = Duration::from_secs(15 * 60);

/// The cache root: `$COWPROOF_CACHE_ROOT` when set and non-empty, else `~/.cache/cowproof`.
pub fn cache_root(home: &Path) -> PathBuf {
    cache_root_from(std::env::var_os(CACHE_ROOT_ENV), home)
}

fn cache_root_from(value: Option<OsString>, home: &Path) -> PathBuf {
    match value {
        Some(v) if !v.is_empty() => PathBuf::from(v),
        _ => home.join(".cache/cowproof"),
    }
}

/// The directory of one cache entry.
pub fn cache_dir(cache_root: &Path, key: &str) -> PathBuf {
    cache_root.join("deps").join(key)
}

/// What network the fetch sandbox gets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchNetwork {
    /// Registry-only: the sandbox reaches a CONNECT proxy, run by the runner, that tunnels
    /// only to `host:443` of the base's allowlist ([`crate::fetch_proxy`]). The default.
    Registry,
    /// Full outbound network, an explicit opt-in. The sandbox still holds no key, no
    /// control directory and no home.
    Open,
    /// No network at all.
    None,
}

impl FetchNetwork {
    /// From `COWPROOF_FETCH_NETWORK`: unset or empty is `registry`.
    pub fn from_env() -> Result<Self> {
        Self::parse(std::env::var(FETCH_NETWORK_ENV).ok().as_deref())
    }

    fn parse(value: Option<&str>) -> Result<Self> {
        match value {
            None | Some("") | Some("registry") => Ok(Self::Registry),
            Some("open") => Ok(Self::Open),
            Some("none") => Ok(Self::None),
            Some(other) => {
                bail!("{FETCH_NETWORK_ENV} must be `registry`, `open` or `none`, not {other:?}")
            }
        }
    }
}

/// What it takes to serve the registry-only mode.
#[derive(Debug, Clone)]
pub struct FetchEgress {
    /// The `cowproof` executable that runs `net-bridge` inside the fetch sandbox. It is
    /// granted read-only there, like a builder's.
    pub bridge_exe: PathBuf,
    /// Where an allowed name connects.
    pub resolver: Resolver,
}

/// How the fetch's command ended, as the caller's runner reports it.
#[derive(Debug)]
pub enum FetchEnd {
    /// The command exited; its group is gone. `output` is its stdout then stderr.
    Exited { status: ExitStatus, output: Vec<u8> },
    /// It did not finish within the limit and its group was ended.
    TimedOut,
}

/// Runs the fetch's command as the leader of its own process group, listed wherever the
/// caller keeps its groups, and ends the whole group when the command is over or the time
/// is up. `cowproof-cli` supplies it (`cowproof_prove::runner::run_in_group_blocking` with
/// the run's `GroupSet`); this crate cannot, because the verifier depends on it.
pub type Exec<'a> = &'a dyn Fn(Command, Duration) -> Result<FetchEnd>;

/// What one [`prefetch`] call runs with.
pub struct FetchConfig<'a> {
    pub network: FetchNetwork,
    pub tools: &'a FetchTools,
    pub timeout: Duration,
    pub alive: Alive<'a>,
    pub exec: Exec<'a>,
    /// Needed by [`FetchNetwork::Registry`]; the other modes ignore it.
    pub egress: Option<&'a FetchEgress>,
}

/// The platform part of the cache key (D14): what the fetch is for.
pub fn host_target() -> String {
    format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS)
}

/// How a prefetch ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchOutcome {
    /// The cache entry was already complete.
    Hit,
    /// This call fetched it.
    Fetched,
    /// The tree has dependency files this runner does not fetch (a `package.json` with no
    /// JavaScript lockfile, lockfiles of two tools, a Yarn Plug'n'Play tree, a Bundler
    /// lockfile) and nothing it does: no entry, and
    /// [`Prefetch::notes`] says what was left out. Never reported as fetched.
    NotFetched,
    /// The fetch could not run or failed; the reason is for the director.
    Failed(String),
}

impl FetchOutcome {
    /// The word the capsule records: `hit`, `fetched`, `not_fetched` or `failed`.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Hit => "hit",
            Self::Fetched => "fetched",
            Self::NotFetched => "not_fetched",
            Self::Failed(_) => "failed",
        }
    }
}

/// The result of [`prefetch`] for a tree that has something to fetch.
#[derive(Debug, Clone)]
pub struct Prefetch {
    /// The cache key (D11, D14).
    pub key: String,
    pub outcome: FetchOutcome,
    /// `<cache root>/deps/<key>`: valid when the outcome is not `Failed`.
    pub dir: PathBuf,
    /// The ecosystems the entry holds (`cargo`, `npm`, `yarn` or `pnpm`) when the outcome is a hit or a fetch,
    /// else empty: what the capsule records as fetched.
    pub ecosystems: Vec<&'static str>,
    /// What was left out or changed, one line each: dependency files that are not fetched,
    /// and the auth lines of the base `.npmrc` that were not used. The capsule records them.
    pub notes: Vec<String>,
    /// The `COWPROOF_FETCH_RESOLVE` testing hook's addresses (`host=ip:port,...`) when the
    /// fetch ran with it set, else `None`. The capsule records it, so a proof made with it
    /// is visibly not a real fetch.
    pub resolve_override: Option<String>,
}

/// The `PATH` for the fetch and the `cargo`, `npm`, `yarn` and `pnpm` executables it runs.
#[derive(Debug, Clone)]
pub struct FetchTools {
    /// The fetch's `PATH`, as the verifier's is.
    pub path: String,
    /// The `cargo` to run, granted read-only when it lives under the hidden home.
    pub cargo: Option<PathBuf>,
    /// The `npm` to run ([`resolve_tool`]), granted read-only like `cargo`; its directory is
    /// added to the fetch's `PATH` so the `node` beside it is found.
    pub npm: Option<PathBuf>,
    /// The `yarn` to run, found and granted the same way.
    pub yarn: Option<PathBuf>,
    /// The `pnpm` to run, found and granted the same way.
    pub pnpm: Option<PathBuf>,
}

impl FetchTools {
    /// The executable for `tool`, when one was found.
    fn js(&self, tool: JsTool) -> Option<&Path> {
        match tool {
            JsTool::Npm => self.npm.as_deref(),
            JsTool::YarnClassic | JsTool::YarnBerry => self.yarn.as_deref(),
            JsTool::Pnpm => self.pnpm.as_deref(),
        }
    }
}

/// The `name` executable (`npm`, `yarn` or `pnpm`) a fetch runs: the file `tool_env` names
/// (`$COWPROOF_NPM`, `$COWPROOF_YARN`, `$COWPROOF_PNPM`) when it is an existing absolute
/// file, else the first absolute `PATH` entry that holds a `name`. Empty and relative `PATH`
/// entries are skipped, as for cargo: they would search the tree.
pub fn resolve_tool(
    name: &str,
    tool_env: Option<&std::ffi::OsStr>,
    path_env: Option<&std::ffi::OsStr>,
) -> Option<PathBuf> {
    if let Some(tool) = tool_env.map(Path::new)
        && tool.is_absolute()
        && tool.is_file()
    {
        return Some(tool.to_path_buf());
    }
    std::env::split_paths(path_env?)
        .filter(|dir| dir.is_absolute())
        .map(|dir| dir.join(name))
        .find(|tool| tool.is_file())
}

/// The Node package tool a tree's lockfile names, and the way it installs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsTool {
    /// `npm ci --ignore-scripts --no-audit --no-fund` for a `package-lock.json` or
    /// `npm-shrinkwrap.json`.
    Npm,
    /// `yarn install --frozen-lockfile --ignore-scripts --non-interactive` for a classic
    /// (v1) `yarn.lock`.
    YarnClassic,
    /// `yarn install --immutable --mode=skip-build` for a Yarn Berry (v2+) `yarn.lock` whose
    /// `.yarnrc.yml` sets `nodeLinker: node-modules`.
    YarnBerry,
    /// `pnpm install --frozen-lockfile --ignore-scripts --config.node-linker=hoisted` for a
    /// `pnpm-lock.yaml`.
    Pnpm,
}

impl JsTool {
    /// The tool's name: the ecosystem the capsule records and the executable looked for.
    pub fn name(self) -> &'static str {
        match self {
            Self::Npm => "npm",
            Self::YarnClassic | Self::YarnBerry => "yarn",
            Self::Pnpm => "pnpm",
        }
    }

    /// Names the command in messages.
    fn label(self) -> &'static str {
        match self {
            Self::Npm => "npm ci --ignore-scripts",
            Self::YarnClassic => "yarn install --frozen-lockfile --ignore-scripts",
            Self::YarnBerry => "yarn install --immutable --mode=skip-build",
            Self::Pnpm => "pnpm install --frozen-lockfile --ignore-scripts",
        }
    }

    /// The arguments: a frozen install from the lockfile that runs no lifecycle script of any
    /// package and leaves a plain `node_modules`.
    fn args(self) -> &'static [&'static str] {
        match self {
            Self::Npm => &["ci", "--ignore-scripts", "--no-audit", "--no-fund"],
            Self::YarnClassic => &[
                "install",
                "--frozen-lockfile",
                "--ignore-scripts",
                "--non-interactive",
            ],
            Self::YarnBerry => &["install", "--immutable", "--mode=skip-build"],
            Self::Pnpm => &[
                "install",
                "--frozen-lockfile",
                "--ignore-scripts",
                "--config.node-linker=hoisted",
            ],
        }
    }

    /// The lockfiles the tool's install reads.
    fn lockfiles(self) -> &'static [&'static str] {
        match self {
            Self::Npm => &NPM_LOCKFILES,
            Self::YarnClassic | Self::YarnBerry => &[YARN_LOCKFILE],
            Self::Pnpm => &[PNPM_LOCKFILE],
        }
    }

    /// The executable's file name.
    fn program(self) -> &'static str {
        self.name()
    }

    /// The variables that point the tool at the bridge.
    fn proxy_env(self) -> &'static [&'static str] {
        match self {
            Self::Npm | Self::Pnpm => &[
                "npm_config_https_proxy",
                "npm_config_proxy",
                "HTTPS_PROXY",
                "https_proxy",
            ],
            Self::YarnClassic | Self::YarnBerry => &[
                "npm_config_https_proxy",
                "npm_config_proxy",
                "YARN_HTTPS_PROXY",
                "YARN_HTTP_PROXY",
                "HTTPS_PROXY",
                "https_proxy",
            ],
        }
    }

    /// Builds the allowlist from the base tree.
    fn allowlist(self) -> fn(&Path) -> Result<FetchAllowlist> {
        match self {
            Self::Npm => FetchAllowlist::npm_from_tree,
            Self::YarnClassic | Self::YarnBerry => FetchAllowlist::yarn_from_tree,
            Self::Pnpm => FetchAllowlist::pnpm_from_tree,
        }
    }

    /// What to say of a failed command's output.
    fn describe(self) -> fn(&[u8]) -> String {
        match self {
            Self::Npm => npm_failure,
            Self::YarnClassic | Self::YarnBerry => yarn_failure,
            Self::Pnpm => pnpm_failure,
        }
    }
}

/// What a tree's JavaScript lockfiles ask for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsPlan {
    /// No JavaScript lockfile.
    Nothing,
    /// Exactly one tool's lockfile, and the tool can install it.
    Fetch(JsTool),
    /// A lockfile this runner does not install: the line for [`Prefetch::notes`].
    NotFetched(String),
}

/// What the JavaScript lockfiles of `tree` (the rebuilt tree) ask for. Exactly one tool's
/// lockfile is expected: `package-lock.json` and `npm-shrinkwrap.json` are npm's (a shrinkwrap
/// wins), `yarn.lock` is yarn's and `pnpm-lock.yaml` is pnpm's, and lockfiles of two tools
/// are never resolved by picking one. A Yarn Berry tree (a `.yarnrc.yml`, or a `__metadata`
/// header in `yarn.lock`) installs only with `nodeLinker: node-modules`; Plug'n'Play leaves no
/// `node_modules` to mount. Every file is read as a regular file: a symlink could point
/// anywhere.
pub fn js_plan(tree: &Path) -> JsPlan {
    let has = |name: &str| is_regular(&tree.join(name));
    let npm = NPM_LOCKFILES.iter().any(|n| has(n));
    let yarn = has(YARN_LOCKFILE);
    let pnpm = has(PNPM_LOCKFILE);
    if usize::from(npm) + usize::from(yarn) + usize::from(pnpm) > 1 {
        let present: Vec<&str> = NPM_LOCKFILES
            .iter()
            .copied()
            .filter(|n| has(n))
            .chain([YARN_LOCKFILE].into_iter().filter(|_| yarn))
            .chain([PNPM_LOCKFILE].into_iter().filter(|_| pnpm))
            .collect();
        return JsPlan::NotFetched(format!(
            "{}: more than one JavaScript lockfile, so no tool is guessed and node_modules is not available to the verifier",
            present.join(", ")
        ));
    }
    if npm {
        return JsPlan::Fetch(JsTool::Npm);
    }
    if pnpm {
        return JsPlan::Fetch(JsTool::Pnpm);
    }
    if !yarn {
        return JsPlan::Nothing;
    }
    let lock = fs::read_to_string(tree.join(YARN_LOCKFILE)).unwrap_or_default();
    let rc = read_config(tree, ".yarnrc.yml").ok().flatten();
    if rc.is_none() && !lock.lines().any(|l| l.starts_with("__metadata:")) {
        return JsPlan::Fetch(JsTool::YarnClassic);
    }
    if rc.as_deref().is_some_and(yarnrc_yml_uses_node_modules) {
        JsPlan::Fetch(JsTool::YarnBerry)
    } else {
        JsPlan::NotFetched(
            "yarn.lock: Yarn Berry without `nodeLinker: node-modules` in .yarnrc.yml (Plug'n'Play) is not supported, so node_modules is not available to the verifier"
                .to_string(),
        )
    }
}

/// Whether a `.yarnrc.yml` sets the top-level `nodeLinker` to `node-modules`.
fn yarnrc_yml_uses_node_modules(text: &str) -> bool {
    text.lines().any(|line| {
        line.strip_prefix("nodeLinker:").is_some_and(|value| {
            value
                .split(" #")
                .next()
                .unwrap_or("")
                .trim()
                .trim_matches(['"', '\''])
                == "node-modules"
        })
    })
}

/// Which ecosystems a rebuilt tree has something to fetch for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Needs {
    pub cargo: bool,
    /// The Node tool that installs the tree's one JavaScript lockfile ([`js_plan`]).
    pub js: Option<JsTool>,
}

impl Needs {
    /// What `tree` (the rebuilt tree) asks for: a `Cargo.lock`, and one JavaScript lockfile
    /// that is a regular file (a symlink in the tree could point anywhere) and that a tool
    /// installs.
    pub fn of(tree: &Path) -> Self {
        Self {
            cargo: tree.join("Cargo.lock").is_file(),
            js: match js_plan(tree) {
                JsPlan::Fetch(tool) => Some(tool),
                _ => None,
            },
        }
    }

    fn any(self) -> bool {
        self.cargo || self.js.is_some()
    }

    fn ecosystems(self) -> Vec<&'static str> {
        let mut names = Vec::new();
        if self.cargo {
            names.push("cargo");
        }
        if let Some(tool) = self.js {
            names.push(tool.name());
        }
        names
    }
}

fn is_regular(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|m| m.is_file())
}

/// The dependency files of `tree` this runner does not fetch, one line each, so the capsule
/// says what a check may be missing. A `package.json` with a lockfile an installed tool
/// reads is fetched; a lockfile no tool installs (two tools' lockfiles, a Yarn Plug'n'Play
/// tree) gets its own line; a `package.json` with no lockfile gets that one.
pub fn unfetched_notes(tree: &Path) -> Vec<String> {
    let has = |name: &str| is_regular(&tree.join(name));
    let mut notes = Vec::new();
    match js_plan(tree) {
        JsPlan::NotFetched(note) => notes.push(note),
        JsPlan::Nothing if has(NPM_MANIFEST) => notes.push(format!(
            "{NPM_MANIFEST} without a package-lock.json, npm-shrinkwrap.json, yarn.lock or pnpm-lock.yaml: nothing is fetched, so node_modules is not available to the verifier"
        )),
        _ => {}
    }
    if has("Gemfile.lock") {
        notes.push("Gemfile.lock: Bundler is not fetched".to_string());
    }
    notes
}

/// `.npmrc` with every credential removed, and how many lines had one. A line is dropped when
/// its key ends in `_authToken`, `_auth` or `_password` (the forms `_authToken=`,
/// `//host/:_authToken=` and `@scope:_password=`) or in npm's client-certificate settings
/// `key` (which can hold an inline PEM private key), `keyfile`, `cert` and `certfile`, plain
/// or scoped, in any case. A PEM block that continues over the following lines goes with its
/// first line. A `registry=` URL with `user:pass@` in it keeps the URL without the
/// credentials. The fetch gets this copy and nothing from the original, and the entry holds
/// none of it: a registry that needs a token or a client certificate is out of reach.
pub fn strip_npmrc_auth(text: &str) -> (String, usize) {
    let mut out = String::new();
    let mut stripped = 0;
    // Inside a PEM block that a dropped line opened and did not close.
    let mut in_pem = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if in_pem {
            in_pem = !trimmed.contains("-----END");
            continue;
        }
        let Some((key, value)) = trimmed.split_once('=') else {
            out.push_str(line);
            out.push('\n');
            continue;
        };
        if trimmed.starts_with(['#', ';']) {
            out.push_str(line);
            out.push('\n');
            continue;
        }
        let last = key
            .trim()
            .rsplit(':')
            .next()
            .unwrap_or("")
            .to_ascii_lowercase();
        if matches!(
            last.as_str(),
            "_auth" | "_authtoken" | "_password" | "key" | "keyfile" | "cert" | "certfile"
        ) {
            stripped += 1;
            in_pem = value.contains("-----BEGIN") && !value.contains("-----END");
            continue;
        }
        match drop_url_credentials(value) {
            Some(clean) => {
                stripped += 1;
                out.push_str(&format!("{}={clean}\n", key.trim()));
            }
            None => {
                out.push_str(line);
                out.push('\n');
            }
        }
    }
    (out, stripped)
}

/// `value` without the `user:pass@` of a URL in it, or `None` when it has none.
fn drop_url_credentials(value: &str) -> Option<String> {
    let (scheme, rest) = value.split_once("://")?;
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (_userinfo, host) = rest[..authority_end].rsplit_once('@')?;
    Some(format!("{scheme}://{host}{}", &rest[authority_end..]))
}

/// A yarn configuration file with what the fetch must not get removed, and the counts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YarnrcStripped {
    pub text: String,
    /// Lines that held a credential or a client-certificate setting.
    pub credentials: usize,
    /// Lines that named code in the tree to run (`yarnPath`, `yarn-path`, `plugins`).
    pub code: usize,
}

/// The settings of a yarn configuration file that hold a credential: the npm auth keys, and
/// the client-certificate keys of npm and Berry. Lower case, compared in any case.
const YARN_CREDENTIAL_KEYS: [&str; 12] = [
    "npmauthtoken",
    "npmauthident",
    "npmalwaysauth",
    "_authtoken",
    "_auth",
    "_password",
    "key",
    "keyfile",
    "cert",
    "certfile",
    "httpskeyfilepath",
    "httpscertfilepath",
];

/// Credential setting names that give a flow-style line away whatever its shape.
const YARN_CREDENTIAL_WORDS: [&str; 4] = [
    "npmauthtoken",
    "npmauthident",
    "httpskeyfilepath",
    "httpscertfilepath",
];

/// The settings that make yarn run code from the tree. The fetch does not copy the tree's
/// `.yarn` directory, so a release or plugin named there is not available and the host's yarn
/// is used instead.
const YARN_CODE_KEYS: [&str; 3] = ["yarnpath", "yarn-path", "plugins"];

/// What a yarn configuration line sets: its key as written, the setting's name (the last
/// `:` part of the key, lower case, without a leading `-`/`--`) and the value text.
fn yarn_setting(line: &str, yml: bool) -> Option<(String, String, String)> {
    let t = line.trim().trim_start_matches("- ");
    let (raw, key, value) = if let Some(rest) = t.strip_prefix('"') {
        let (key, rest) = rest.split_once('"')?;
        (&t[..key.len() + 2], key, rest.trim_start_matches(':'))
    } else if yml {
        let (key, value) = t.split_once(':')?;
        (key, key, value)
    } else {
        let (key, value) = t
            .split_once(|c: char| c.is_whitespace() || c == '=')
            .unwrap_or((t, ""));
        (key, key, value)
    };
    // `//host/:_authToken` and `@scope:registry` carry a scope: the setting is the last part.
    let name = key.trim().rsplit(':').next().unwrap_or("");
    Some((
        raw.to_string(),
        name.trim_start_matches('-').to_ascii_lowercase(),
        value.trim().to_string(),
    ))
}

/// A yarn setting's value text without its quotes or a trailing ` # comment`, and the same
/// with a URL's `user:pass@` removed (`None` when it has none).
fn yarn_value_without_url_credentials(value: &str) -> Option<String> {
    let value = value.split(" #").next().unwrap_or("").trim();
    drop_url_credentials(value.trim_matches(['"', '\'']))
}

fn strip_yarn_config(text: &str, yml: bool) -> YarnrcStripped {
    let mut out = String::new();
    let (mut credentials, mut code) = (0, 0);
    // Inside a PEM block, or the lines under a dropped key: skipped until they end.
    let mut in_pem = false;
    let mut below: Option<usize> = None;
    for line in text.lines() {
        let trimmed = line.trim();
        let indent = line.len() - line.trim_start().len();
        if in_pem {
            in_pem = !trimmed.contains("-----END");
            continue;
        }
        if let Some(parent) = below {
            let item = trimmed.starts_with('-') && indent == parent;
            if trimmed.is_empty() || indent > parent || item {
                continue;
            }
            below = None;
        }
        let keep = |out: &mut String| {
            out.push_str(line);
            out.push('\n');
        };
        if trimmed.is_empty() || trimmed.starts_with('#') {
            keep(&mut out);
            continue;
        }
        let Some((raw, name, value)) = yarn_setting(line, yml) else {
            keep(&mut out);
            continue;
        };
        let is_credential = YARN_CREDENTIAL_KEYS.contains(&name.as_str());
        let is_code = YARN_CODE_KEYS.contains(&name.as_str());
        if is_credential || is_code {
            if is_credential {
                credentials += 1;
                in_pem = value.contains("-----BEGIN") && !value.contains("-----END");
            } else {
                code += 1;
            }
            // A key with no value, or a block scalar, owns the lines indented below it.
            let bare = value.is_empty() || value.starts_with(['|', '>']);
            if yml && bare {
                below = Some(indent);
            }
            continue;
        }
        let lower = line.to_ascii_lowercase();
        if YARN_CREDENTIAL_WORDS.iter().any(|w| lower.contains(w)) {
            // A flow-style mapping that holds a credential setting: dropped whole.
            credentials += 1;
            continue;
        }
        match yarn_value_without_url_credentials(&value) {
            Some(clean) => {
                credentials += 1;
                let pad = &line[..indent];
                let dash = if trimmed.starts_with("- ") { "- " } else { "" };
                if yml {
                    out.push_str(&format!("{pad}{dash}{raw}: {clean}\n"));
                } else {
                    out.push_str(&format!("{pad}{dash}{raw} \"{clean}\"\n"));
                }
            }
            None => keep(&mut out),
        }
    }
    YarnrcStripped {
        text: out,
        credentials,
        code,
    }
}

/// `.yarnrc.yml` (Yarn Berry) with every credential removed: `npmAuthToken`, `npmAuthIdent`
/// and `npmAlwaysAuth`, at the top level and under `npmRegistries` and `npmScopes` entries;
/// the client-certificate keys `key`, `keyfile`, `cert`, `certfile`, `httpsKeyFilePath` and
/// `httpsCertFilePath`; and the `user:pass@` of a URL value. A line with such a key anywhere
/// in a flow-style mapping goes whole. `yarnPath` and `plugins` (code in the tree) go too. A
/// key with no value takes the lines indented below it with it.
pub fn strip_yarnrc_yml(text: &str) -> YarnrcStripped {
    strip_yarn_config(text, true)
}

/// Classic `.yarnrc` with every credential removed: `_authToken`, `_auth`, `_password` (also
/// as `"//host/:_authToken"`), the client-certificate keys, and the `user:pass@` of a URL
/// value; `yarn-path` goes too.
pub fn strip_yarnrc(text: &str) -> YarnrcStripped {
    strip_yarn_config(text, false)
}

/// The registry configuration files of a tree, and its `cowproof.toml` (whose
/// `[proof] fetch_hosts` the fetch's allowlist reads), as they were at one moment.
///
/// Take it after the base is rebuilt and before `lane.patch` is applied, and
/// [`restore`](Self::restore) it afterwards: whatever the patch did to those files, the
/// key and the fetch see the base's (D14).
#[derive(Debug)]
pub struct RegistryConfigSnapshot(Vec<(&'static str, Option<Vec<u8>>)>);

impl RegistryConfigSnapshot {
    /// Read every registry configuration file of `tree` (`None` for an absent one).
    pub fn take(tree: &Path) -> Result<Self> {
        let mut files = Vec::new();
        // The registry configuration, and the `cowproof.toml` whose `[proof] fetch_hosts`
        // widens the fetch's allowlist: both the base's, whatever the patch did.
        for name in REGISTRY_CONFIGS.iter().chain(&[fetch_proxy::POLICY_FILE]) {
            let path = tree.join(name);
            let content = match fs::symlink_metadata(&path) {
                Ok(m) if m.is_file() => {
                    Some(fs::read(&path).with_context(|| format!("reading {}", path.display()))?)
                }
                // A directory or a symlink is not a configuration file cargo or npm
                // would read as one: treat it as absent.
                Ok(_) => None,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
            };
            files.push((*name, content));
        }
        Ok(Self(files))
    }

    /// Put the snapshot back: rewrite the files that existed, remove the ones that did
    /// not. A patch can have replaced a parent directory or the file with a symlink; the
    /// symlink is removed itself and never followed.
    pub fn restore(&self, tree: &Path) -> Result<()> {
        for (name, content) in &self.0 {
            let path = tree.join(name);
            if let Some(parent) = path.parent()
                && parent != tree
                && fs::symlink_metadata(parent).is_ok_and(|m| !m.is_dir())
            {
                fs::remove_file(parent)
                    .with_context(|| format!("removing {}", parent.display()))?;
            }
            match fs::symlink_metadata(&path) {
                Ok(m) if m.is_dir() => fs::remove_dir_all(&path),
                Ok(_) => fs::remove_file(&path),
                Err(_) => Ok(()),
            }
            .with_context(|| format!("clearing {}", path.display()))?;
            if let Some(content) = content {
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::write(&path, content)
                    .with_context(|| format!("restoring {}", path.display()))?;
            }
        }
        Ok(())
    }
}

/// Prefetch the dependencies of the tree that `rebuild` builds (D6, D11, D14).
///
/// `rebuild` receives an empty directory and must leave the rebuilt tree in it, with
/// registry configuration from the base (see [`RegistryConfigSnapshot`]). It runs in a
/// private work directory under the cache root, which is removed before this returns.
///
/// `Ok(None)`: the tree has no `Cargo.lock`, so there is nothing to fetch. `Ok(Some)`:
/// the key, and whether the cache was hit, fetched or the fetch failed. `Err`: the
/// rebuild or the key could not be made; the caller treats it like a failed fetch.
pub fn prefetch(
    rebuild: impl FnOnce(&Path) -> Result<()>,
    cache_root: &Path,
    lane: &LaneLayout,
    config: &FetchConfig,
) -> Result<Option<Prefetch>> {
    let alive = config.alive;
    // Ask first, create after: a root that already holds things cowproof did not make is
    // not swept (below), though the fetch still works there.
    let owned = cache::require_owned(cache_root, &lane.real_home);
    let work_root = cache_root.join("deps-work");
    fs::create_dir_all(&work_root).context("creating the dependency work directory")?;
    fs::create_dir_all(cache_root.join("deps")).context("creating the dependency cache")?;
    // The one place a cache root is first created: mark it as cowproof's.
    cache::write_marker(cache_root).context("marking the dependency cache root")?;
    // A `cowproof` that was interrupted left its work directory behind (nothing removes it
    // but the run that made it): clear the ones whose process is gone. Best effort, and
    // never a directory whose process is alive, nor one in a root cowproof did not make.
    match owned {
        Ok(()) => {
            let _ = cache::remove_stale_work(cache_root, &lane.real_home, alive);
        }
        Err(e) => eprintln!("warning: not sweeping stale dependency work directories: {e:#}"),
    }
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let work = work_root.join(format!("{}-{stamp}", std::process::id()));
    fs::create_dir(&work).context("creating the dependency work directory")?;
    let result = prefetch_in(&work, rebuild, cache_root, lane, config);
    let _ = fs::remove_dir_all(&work);
    result
}

fn prefetch_in(
    work: &Path,
    rebuild: impl FnOnce(&Path) -> Result<()>,
    cache_root: &Path,
    lane: &LaneLayout,
    config: &FetchConfig,
) -> Result<Option<Prefetch>> {
    let alive = config.alive;
    let tree = work.join("tree");
    fs::create_dir(&tree)?;
    rebuild(&tree).context("rebuilding the tree to fetch dependencies for")?;
    let needs = Needs::of(&tree);
    let mut notes = unfetched_notes(&tree);
    if !needs.any() && notes.is_empty() {
        return Ok(None);
    }
    let key = dependency_cache_key(&tree, &host_target()).context("computing the cache key")?;
    let dir = cache_dir(cache_root, &key);
    if !needs.any() {
        return Ok(Some(Prefetch {
            key,
            outcome: FetchOutcome::NotFetched,
            dir,
            ecosystems: Vec::new(),
            notes,
            resolve_override: None,
        }));
    }
    if let Some(tool) = needs.js {
        for file in stripped_configs(tool, &tree)? {
            if file.credentials > 0 {
                notes.push(format!(
                    "{}: {} credential line(s) of {} were not used (the fetch never receives a token)",
                    tool.name(),
                    file.credentials,
                    file.name
                ));
            }
            if file.code > 0 {
                notes.push(format!(
                    "{}: {} setting(s) of {} naming code in the tree (yarnPath, plugins) were not used",
                    tool.name(),
                    file.code,
                    file.name
                ));
            }
        }
    }
    let done = |outcome: FetchOutcome| {
        let ecosystems = match outcome {
            FetchOutcome::Hit | FetchOutcome::Fetched => needs.ecosystems(),
            _ => Vec::new(),
        };
        Ok(Some(Prefetch {
            key: key.clone(),
            outcome,
            dir: dir.clone(),
            ecosystems,
            notes: notes.clone(),
            resolve_override: config.egress.and_then(|e| e.resolver.spec()),
        }))
    };

    // A hit or an install is a USE of the entry: it takes this process's lease and
    // touches the use marker (`cache::claim`), so a prune neither removes an entry a run is
    // about to mount nor mistakes it for unused. `cowproof run` and `cowproof verify` both
    // mount what this function returns, so this is the one place.
    let claim = || cache::claim(&dir, std::process::id(), alive);
    // An entry a prune removed between the look and the claim is looked at again.
    for _ in 0..3 {
        match entry_state(&dir, needs) {
            EntryState::Complete => match claim() {
                Ok(()) => return done(FetchOutcome::Hit),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return done(FetchOutcome::Failed(claim_failure(&dir, &e))),
            },
            EntryState::Absent => break,
            EntryState::Incomplete => {
                return done(FetchOutcome::Failed(format!(
                    "the cache entry {} exists but is incomplete; remove it",
                    dir.display()
                )));
            }
        }
    }

    let fresh = work.join("new");
    let fetched = (|| -> Result<()> {
        if needs.cargo {
            fetch_cargo(work, &tree, &fresh, lane, config)?;
        }
        if let Some(tool) = needs.js {
            fetch_js(tool, work, &tree, &fresh, lane, config)?;
        }
        Ok(())
    })();
    let outcome = match fetched {
        Ok(()) => match install(&fresh, &dir, needs) {
            Ok(outcome) => match claim() {
                Ok(()) => outcome,
                Err(e) => FetchOutcome::Failed(claim_failure(&dir, &e)),
            },
            Err(e) => FetchOutcome::Failed(format!("{e:#}")),
        },
        Err(e) => FetchOutcome::Failed(format!("{e:#}")),
    };
    done(outcome)
}

fn claim_failure(dir: &Path, e: &std::io::Error) -> String {
    format!(
        "could not record the use of the cache entry {}: {e}",
        dir.display()
    )
}

#[derive(Debug, PartialEq, Eq)]
enum EntryState {
    Absent,
    Complete,
    Incomplete,
}

/// An entry is complete when it holds the part of every ecosystem the tree asks for. The key
/// covers the lockfiles, so the same key always asks for the same ecosystems; an entry made
/// before npm was fetched, for a tree that has both lockfiles, lacks the npm part and is
/// incomplete (the message tells the director to remove it).
fn entry_state(dir: &Path, needs: Needs) -> EntryState {
    match fs::symlink_metadata(dir) {
        Err(_) => EntryState::Absent,
        Ok(_)
            if (!needs.cargo || dir.join("cargo/registry").is_dir())
                && (needs.js.is_none() || dir.join(NPM_ENTRY_DIR).join(NPM_MODULES).is_dir()) =>
        {
            EntryState::Complete
        }
        Ok(_) => EntryState::Incomplete,
    }
}

/// Move a finished fetch into the cache. The rename is the only moment the entry
/// appears, so it is whole or absent. If another lane installed the same key first the
/// rename fails, the entry is complete, and this lane's copy is dropped: a hit.
fn install(fresh: &Path, dir: &Path, needs: Needs) -> Result<FetchOutcome> {
    match fs::rename(fresh, dir) {
        Ok(()) => Ok(FetchOutcome::Fetched),
        Err(e) => {
            if entry_state(dir, needs) == EntryState::Complete {
                let _ = fs::remove_dir_all(fresh);
                Ok(FetchOutcome::Hit)
            } else {
                Err(e).with_context(|| format!("moving the fetched cache to {}", dir.display()))
            }
        }
    }
}

/// A configuration file of the base (`.npmrc`, `.yarnrc`, `.yarnrc.yml`) as text (`None` when
/// it is absent, a directory or a symlink).
fn read_config(tree: &Path, name: &str) -> Result<Option<String>> {
    let path = tree.join(name);
    if !is_regular(&path) {
        return Ok(None);
    }
    fs::read_to_string(&path)
        .map(Some)
        .with_context(|| format!("reading {}", path.display()))
}

/// One configuration file the fetch gets, stripped of what it must not receive.
struct StrippedConfig {
    name: &'static str,
    text: String,
    credentials: usize,
    code: usize,
}

/// The configuration files `tool` reads, from the base tree, each with its credentials removed:
/// the `.npmrc` (npm, pnpm and yarn), and for yarn the `.yarnrc` and `.yarnrc.yml` too.
fn stripped_configs(tool: JsTool, tree: &Path) -> Result<Vec<StrippedConfig>> {
    let mut files = Vec::new();
    if let Some(text) = read_config(tree, ".npmrc")? {
        let (text, credentials) = strip_npmrc_auth(&text);
        files.push(StrippedConfig {
            name: ".npmrc",
            text,
            credentials,
            code: 0,
        });
    }
    if matches!(tool, JsTool::YarnClassic | JsTool::YarnBerry) {
        for (name, strip) in [
            (".yarnrc", strip_yarnrc as fn(&str) -> YarnrcStripped),
            (".yarnrc.yml", strip_yarnrc_yml),
        ] {
            if let Some(text) = read_config(tree, name)? {
                let s = strip(&text);
                files.push(StrippedConfig {
                    name,
                    text: s.text,
                    credentials: s.credentials,
                    code: s.code,
                });
            }
        }
    }
    Ok(files)
}

/// What one sandboxed fetch command is: the same sandbox, proxy and process group for cargo
/// and npm, with only these parts differing.
struct Job<'a> {
    /// Names the command in messages: `cargo fetch --locked`.
    label: &'static str,
    /// The program, absolute when the tool was found, else the bare name.
    program: String,
    args: Vec<String>,
    /// The executable to grant read-only (it may live under the hidden home).
    exe: Option<&'a Path>,
    /// The sandboxed command's working directory.
    cwd: &'a Path,
    path: String,
    /// The private `HOME`.
    home: &'a Path,
    /// Granted read-write besides the entry being filled.
    rw: Vec<PathBuf>,
    /// Granted read-only.
    ro: Vec<PathBuf>,
    /// Set in the sandbox before the proxy variables.
    env: Vec<(String, String)>,
    /// The variables that point the tool at the bridge.
    proxy_env: &'static [&'static str],
    /// Builds the allowlist from the base tree.
    allowlist: fn(&Path) -> Result<FetchAllowlist>,
    /// The tree the allowlist is read from (the base's configuration).
    tree: &'a Path,
    /// What to say of a failed command's output.
    describe: fn(&[u8]) -> String,
}

/// `cargo fetch --locked` in `tree`, filling `<fresh>/cargo`, under
/// [`SandboxPolicy::dependency_fetch`].
fn fetch_cargo(
    work: &Path,
    tree: &Path,
    fresh: &Path,
    lane: &LaneLayout,
    config: &FetchConfig,
) -> Result<()> {
    let cargo_home = fresh.join("cargo");
    let home = work.join("home");
    fs::create_dir_all(&cargo_home).context("creating the fetch CARGO_HOME")?;
    // The verifier mounts `registry` whether or not this fetch left one (a project with
    // only path dependencies has none): the mount point always exists.
    fs::create_dir_all(cargo_home.join("registry"))?;
    fs::create_dir_all(&home)?;
    let tools = config.tools;
    let program = match &tools.cargo {
        Some(c) if c.is_absolute() => c.to_string_lossy().into_owned(),
        _ => "cargo".to_string(),
    };
    run_fetch(
        work,
        lane,
        fresh,
        config,
        Job {
            label: "cargo fetch --locked",
            program,
            args: vec!["fetch".to_string(), "--locked".to_string()],
            exe: tools
                .cargo
                .as_deref()
                .filter(|c| c.is_absolute() && c.is_file()),
            cwd: tree,
            path: tools.path.clone(),
            home: &home,
            rw: Vec::new(),
            ro: vec![tree.to_path_buf()],
            env: vec![(
                "CARGO_HOME".to_string(),
                cargo_home.to_string_lossy().into_owned(),
            )],
            proxy_env: &["CARGO_HTTP_PROXY", "HTTPS_PROXY", "https_proxy"],
            allowlist: FetchAllowlist::from_tree,
            tree,
            describe: |output| tail(output, 1500),
        },
    )
}

/// The tool's frozen install (`npm ci`, `yarn install --frozen-lockfile` or `--immutable`,
/// `pnpm install --frozen-lockfile`; see [`JsTool`]) in a scratch copy of the tree's
/// `package.json`, lockfile and credential-free configuration, filling `<fresh>/npm`: the
/// tool's cache or store in `cache` (it writes there while it runs) and the install in
/// `node_modules`, moved out of the scratch directory when the command succeeds.
fn fetch_js(
    tool: JsTool,
    work: &Path,
    tree: &Path,
    fresh: &Path,
    lane: &LaneLayout,
    config: &FetchConfig,
) -> Result<()> {
    let tools = config.tools;
    let label = tool.label();
    let project = work.join(format!("{}-project", tool.name()));
    let home = work.join("home");
    let entry = fresh.join(NPM_ENTRY_DIR);
    let cache = entry.join(NPM_CACHE);
    fs::create_dir_all(&project).context("creating the install directory")?;
    fs::create_dir_all(&home)?;
    fs::create_dir_all(&cache).context("creating the cache directory")?;

    // Only the manifest, the lockfile(s) and the credential-free configuration go in. Each is
    // read from the rebuilt tree as a regular file: a symlink there could point anywhere.
    let manifest = tree.join(NPM_MANIFEST);
    if !is_regular(&manifest) {
        bail!(
            "{label} cannot run: the tree has a {} lockfile but no {NPM_MANIFEST} at its root",
            tool.name()
        );
    }
    fs::copy(&manifest, project.join(NPM_MANIFEST))
        .with_context(|| format!("copying {NPM_MANIFEST}"))?;
    for name in tool.lockfiles() {
        let from = tree.join(name);
        if is_regular(&from) {
            fs::copy(&from, project.join(name)).with_context(|| format!("copying {name}"))?;
        }
    }
    for file in stripped_configs(tool, tree)? {
        fs::write(project.join(file.name), file.text)
            .with_context(|| format!("writing the credential-free {}", file.name))?;
    }
    // A global npm configuration of the host is not read: an empty one stands in for it.
    let global = home.join("npmrc-global");
    fs::write(&global, "").context("writing the empty global npm configuration")?;

    let found = tools.js(tool);
    let program = match found {
        Some(t) if t.is_absolute() => t.to_string_lossy().into_owned(),
        _ => tool.program().to_string(),
    };
    // The tool is a script that finds `node` on `PATH`: its own directory comes along.
    let mut path = tools.path.clone();
    if let Some(dir) = found.and_then(Path::parent).and_then(Path::to_str)
        && Path::new(dir).is_absolute()
        && !dir.contains(':')
        && !path.split(':').any(|e| e == dir)
    {
        path = if path.is_empty() {
            dir.to_string()
        } else {
            format!("{path}:{dir}")
        };
    }
    let cache_text = cache.to_string_lossy().into_owned();
    let mut env: Vec<(&str, String)> = vec![
        (
            "npm_config_globalconfig",
            global.to_string_lossy().into_owned(),
        ),
        ("npm_config_ignore_scripts", "true".to_string()),
        ("npm_config_update_notifier", "false".to_string()),
    ];
    match tool {
        JsTool::Npm => {
            env.push(("npm_config_cache", cache_text));
            env.push(("npm_config_logs_max", "0".to_string()));
        }
        JsTool::YarnClassic | JsTool::YarnBerry => {
            env.push(("YARN_CACHE_FOLDER", cache_text));
            env.push(("YARN_ENABLE_SCRIPTS", "false".to_string()));
            env.push(("YARN_ENABLE_TELEMETRY", "false".to_string()));
            env.push((
                "YARN_GLOBAL_FOLDER",
                home.join("yarn-global").to_string_lossy().into_owned(),
            ));
            if tool == JsTool::YarnBerry {
                // The cache is the entry's, not a global one under the home.
                env.push(("YARN_ENABLE_GLOBAL_CACHE", "false".to_string()));
            }
        }
        JsTool::Pnpm => {
            env.push(("npm_config_store_dir", cache_text));
            env.push((
                "npm_config_cache_dir",
                home.join("pnpm-cache").to_string_lossy().into_owned(),
            ));
            env.push((
                "PNPM_HOME",
                home.join("pnpm").to_string_lossy().into_owned(),
            ));
            // pnpm may otherwise fetch the release a `packageManager` field names.
            env.push((
                "npm_config_manage_package_manager_versions",
                "false".to_string(),
            ));
        }
    }
    run_fetch(
        work,
        lane,
        fresh,
        config,
        Job {
            label,
            program,
            args: tool.args().iter().map(|a| (*a).to_string()).collect(),
            exe: found.filter(|t| t.is_absolute() && t.is_file()),
            cwd: &project,
            path,
            home: &home,
            rw: vec![project.clone()],
            ro: Vec::new(),
            env: env.into_iter().map(|(k, v)| (k.to_string(), v)).collect(),
            proxy_env: tool.proxy_env(),
            allowlist: tool.allowlist(),
            tree,
            describe: tool.describe(),
        },
    )?;

    // The install moves out of the scratch directory into the entry. A lockfile with no
    // packages leaves no `node_modules`; the mount point exists all the same.
    let modules = entry.join(NPM_MODULES);
    match fs::rename(project.join("node_modules"), &modules) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(&modules).with_context(|| format!("creating {}", modules.display()))
        }
        Err(e) => Err(e).with_context(|| format!("moving node_modules into {}", entry.display())),
    }
}

/// The first line of `output` that starts (after any leading symbols, such as Berry's `➤`)
/// with one of `prefixes`, in any case, else its first line, cut to a sensible length.
fn first_error_line(output: &[u8], prefixes: &[&str]) -> String {
    let text = String::from_utf8_lossy(output);
    let lines = || text.lines().map(str::trim).filter(|l| !l.is_empty());
    let line = lines()
        .find(|l| {
            let l = l
                .trim_start_matches(|c: char| !c.is_alphanumeric())
                .to_ascii_lowercase();
            prefixes.iter().any(|p| l.starts_with(p))
        })
        .or_else(|| lines().next())
        .unwrap_or("no output");
    line.chars().take(300).collect()
}

/// The first line npm reported as an error (`npm ERR!` or `npm error`), else its first line
/// of output, cut to a sensible length.
fn npm_failure(output: &[u8]) -> String {
    first_error_line(output, &["npm err", "npm error"])
}

/// The first error line of yarn: classic's `error ...`, or one of Berry's `YN0001`, `YN0028`
/// and `YN0035` lines.
fn yarn_failure(output: &[u8]) -> String {
    first_error_line(output, &["error", "yn0001", "yn0028", "yn0035"])
}

/// The first error line of pnpm: its `ERR_PNPM_*` code line, or an `ERROR` line.
fn pnpm_failure(output: &[u8]) -> String {
    first_error_line(output, &["err_pnpm", "error", "err "])
}

/// Run one fetch command under the fetch sandbox with the registry-only proxy (or the other
/// network modes), and judge how it ended.
fn run_fetch(
    work: &Path,
    lane: &LaneLayout,
    fresh: &Path,
    config: &FetchConfig,
    job: Job,
) -> Result<()> {
    let FetchConfig {
        network,
        timeout,
        exec,
        egress,
        ..
    } = *config;

    // The registry-only mode: serve the allowlist's proxy on a socket in the work
    // directory before the sandbox is rendered (the policy names the socket), and stop it
    // when the fetch is over, whatever the fetch came to.
    let registry = match network {
        FetchNetwork::Registry => {
            let egress = egress.context(
                "the registry-only fetch needs the cowproof executable that runs the bridge",
            )?;
            // Read from the tree, which the caller rebuilt with the BASE's configuration and
            // `cowproof.toml` (see `RegistryConfigSnapshot`), never the patch's.
            let allow = (job.allowlist)(job.tree)
                .context("building the fetch's host allowlist from the base")?;
            let socket = work.join("fetch.sock");
            let seed = format!(
                "{}-{}",
                work.file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                job.label
            );
            let port = free_bridge_port(&seed)?;
            let proxy = FetchProxy::new(allow.clone(), egress.resolver.clone())
                .start(&socket)
                .context("starting the registry-only fetch proxy")?;
            Some((proxy, allow, socket, port, egress.bridge_exe.clone()))
        }
        _ => None,
    };

    let sandbox_network = match (&registry, network) {
        (Some((_, _, socket, port, _)), _) => NetworkMode::RegistryReadOnly {
            port: *port,
            socket: socket.clone(),
        },
        (None, FetchNetwork::Open) => NetworkMode::Unrestricted,
        (None, _) => NetworkMode::None,
    };
    let mut policy = SandboxPolicy::dependency_fetch(lane, fresh, sandbox_network);
    policy.rw_paths.push(job.home.to_path_buf());
    policy.rw_paths.extend(job.rw.iter().cloned());
    policy.ro_paths.extend(job.ro.iter().cloned());
    if let Some(exe) = job.exe {
        policy.executables.push(exe.to_path_buf());
    }
    // `RUSTUP_HOME` (the director's rustup home) comes from the policy, with its grant.
    let mut env = vec![
        ("PATH".to_string(), job.path.clone()),
        ("HOME".to_string(), job.home.to_string_lossy().into_owned()),
    ];
    policy.env_set = job.env.clone();
    let mut argv = vec![job.program.clone()];
    argv.extend(job.args.iter().cloned());
    if let Some((_, _, socket, port, bridge_exe)) = &registry {
        // The tool cannot speak to a Unix socket: the bridge, started inside the sandbox by
        // the wrapper, listens on 127.0.0.1:<port> and copies bytes to the proxy's socket.
        let url = format!("http://127.0.0.1:{port}");
        for key in job.proxy_env {
            policy.env_set.push((key.to_string(), url.clone()));
        }
        policy.executables.push(bridge_exe.clone());
        let mut wrapped = vec![
            bridge_exe.to_string_lossy().into_owned(),
            "net-bridge".to_string(),
            "--port".to_string(),
            port.to_string(),
            "--target".to_string(),
            socket.to_string_lossy().into_owned(),
            "--".to_string(),
        ];
        wrapped.append(&mut argv);
        argv = wrapped;
    }
    policy.apply_env(&mut env);

    let profile = work.join("fetch.sb");
    let platform = if cfg!(target_os = "macos") {
        "darwin"
    } else {
        "linux"
    };
    if platform == "darwin" {
        fs::write(&profile, render_macos_profile(&policy)?)
            .context("writing the fetch sandbox profile")?;
    }
    let (sandbox_bin, sandbox_args) = sandbox_command(&policy, &profile, &argv, platform)?;

    let mut command = Command::new(sandbox_bin);
    command
        .args(sandbox_args)
        .env_clear()
        .envs(env)
        .current_dir(job.cwd);
    let label = job.label;
    let ended = exec(command, timeout).with_context(|| format!("running the sandboxed {label}"));
    // Stop the proxy before judging the fetch: a host it refused is the likely reason a
    // fetch failed, and the message names it first.
    let refused = match registry {
        Some((proxy, allow, ..)) => (proxy.stop(), allow.hosts().join(", ")),
        None => (Vec::new(), String::new()),
    };
    let named = if refused.0.is_empty() {
        String::new()
    } else {
        format!(
            "the registry-only fetch refused a connection to {} (allowed: {}; name the host in \
             `[proof] fetch_hosts` of the base cowproof.toml, or set {FETCH_NETWORK_ENV}=open): ",
            refused.0.join(", "),
            refused.1
        )
    };
    match ended? {
        FetchEnd::TimedOut => bail!("{named}{label} timed out after {}s", timeout.as_secs()),
        FetchEnd::Exited { status, output } if !status.success() => {
            bail!(
                "{named}{label} failed ({status}): {}",
                (job.describe)(&output)
            )
        }
        FetchEnd::Exited { .. } => Ok(()),
    }
}

/// A bridge port that is free on this host now, drawn from the bridge range by a hash of
/// `seed` (a name unique to this fetch). On macOS the sandbox shares the host's loopback,
/// so two bridges must not share a port; on Linux the sandbox has a network namespace of its
/// own and the port is only an address in it. The first of a few draws that binds wins.
fn free_bridge_port(seed: &str) -> Result<u16> {
    for n in 0..16 {
        let port = bridge_port(&format!("fetch-{seed}-{n}"));
        if std::net::TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return Ok(port);
        }
    }
    bail!("no free bridge port for the registry-only fetch")
}

/// The last `max` bytes of a log, on one line.
fn tail(bytes: &[u8], max: usize) -> String {
    let from = bytes.len().saturating_sub(max);
    String::from_utf8_lossy(&bytes[from..])
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    const CARGO: Needs = Needs {
        cargo: true,
        js: None,
    };

    /// A fetch configuration for a test that never reaches the command: running one is a
    /// failure of the test.
    fn config<'a>(tools: &'a FetchTools, alive: Alive<'a>) -> FetchConfig<'a> {
        FetchConfig {
            network: FetchNetwork::None,
            tools,
            timeout: Duration::from_secs(5),
            alive,
            exec: &|_, _| bail!("this test must not run the fetch command"),
            egress: None,
        }
    }

    fn complete_entry(dir: &Path) {
        fs::create_dir_all(dir.join("cargo/registry")).unwrap();
    }

    #[test]
    fn the_cache_root_is_the_variable_when_set_and_the_home_default_otherwise() {
        let home = Path::new("/home/x");
        assert_eq!(
            cache_root_from(Some("/var/tmp/c".into()), home),
            PathBuf::from("/var/tmp/c")
        );
        assert_eq!(
            cache_root_from(None, home),
            PathBuf::from("/home/x/.cache/cowproof")
        );
        assert_eq!(
            cache_root_from(Some("".into()), home),
            PathBuf::from("/home/x/.cache/cowproof")
        );
        assert_eq!(
            cache_dir(Path::new("/r"), "abc"),
            PathBuf::from("/r/deps/abc")
        );
    }

    #[test]
    fn the_fetch_network_defaults_to_registry_and_open_and_none_are_opt_ins() {
        assert_eq!(FetchNetwork::parse(None).unwrap(), FetchNetwork::Registry);
        assert_eq!(
            FetchNetwork::parse(Some("")).unwrap(),
            FetchNetwork::Registry
        );
        assert_eq!(
            FetchNetwork::parse(Some("registry")).unwrap(),
            FetchNetwork::Registry
        );
        assert_eq!(
            FetchNetwork::parse(Some("open")).unwrap(),
            FetchNetwork::Open
        );
        assert_eq!(
            FetchNetwork::parse(Some("none")).unwrap(),
            FetchNetwork::None
        );
        let e = FetchNetwork::parse(Some("proxy")).unwrap_err().to_string();
        assert!(
            e.contains(FETCH_NETWORK_ENV)
                && e.contains("proxy")
                && e.contains("registry")
                && e.contains("open")
                && e.contains("none"),
            "{e}"
        );
    }

    #[test]
    fn outcome_names_are_the_three_capsule_words() {
        assert_eq!(FetchOutcome::Hit.name(), "hit");
        assert_eq!(FetchOutcome::Fetched.name(), "fetched");
        assert_eq!(FetchOutcome::Failed("why".into()).name(), "failed");
    }

    #[test]
    fn install_puts_the_whole_entry_in_place_and_leaves_no_work_copy() {
        let tmp = TempDir::new().unwrap();
        let fresh = tmp.path().join("new");
        complete_entry(&fresh);
        fs::write(fresh.join("cargo/registry/crate"), "x").unwrap();
        let dir = tmp.path().join("deps/key");
        fs::create_dir_all(dir.parent().unwrap()).unwrap();
        assert_eq!(install(&fresh, &dir, CARGO).unwrap(), FetchOutcome::Fetched);
        assert_eq!(entry_state(&dir, CARGO), EntryState::Complete);
        assert_eq!(
            fs::read_to_string(dir.join("cargo/registry/crate")).unwrap(),
            "x"
        );
        assert!(!fresh.exists(), "the work copy moved, it was not copied");
    }

    #[test]
    fn install_loses_a_race_as_a_hit_and_keeps_the_winners_entry_untouched() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("deps/key");
        complete_entry(&dir);
        fs::write(dir.join("cargo/registry/winner"), "w").unwrap();
        let fresh = tmp.path().join("new");
        complete_entry(&fresh);
        fs::write(fresh.join("cargo/registry/loser"), "l").unwrap();
        assert_eq!(install(&fresh, &dir, CARGO).unwrap(), FetchOutcome::Hit);
        assert!(dir.join("cargo/registry/winner").is_file());
        assert!(!dir.join("cargo/registry/loser").exists());
        assert!(!fresh.exists(), "the losing copy is removed");
    }

    #[test]
    fn two_threads_installing_one_key_leave_one_whole_entry_and_one_fetched() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("deps/key");
        fs::create_dir_all(dir.parent().unwrap()).unwrap();
        let outcomes: Vec<FetchOutcome> = std::thread::scope(|s| {
            let handles: Vec<_> = (0..8)
                .map(|i| {
                    let fresh = tmp.path().join(format!("new{i}"));
                    complete_entry(&fresh);
                    fs::write(fresh.join("cargo/registry/who"), i.to_string()).unwrap();
                    let dir = dir.clone();
                    s.spawn(move || install(&fresh, &dir, CARGO).unwrap())
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        assert_eq!(
            outcomes
                .iter()
                .filter(|o| **o == FetchOutcome::Fetched)
                .count(),
            1,
            "{outcomes:?}"
        );
        assert_eq!(entry_state(&dir, CARGO), EntryState::Complete);
        for i in 0..8 {
            assert!(!tmp.path().join(format!("new{i}")).exists());
        }
    }

    #[test]
    fn a_directory_without_a_registry_is_incomplete_not_a_hit() {
        let tmp = TempDir::new().unwrap();
        assert_eq!(
            entry_state(&tmp.path().join("nope"), CARGO),
            EntryState::Absent
        );
        fs::create_dir_all(tmp.path().join("half/cargo")).unwrap();
        assert_eq!(
            entry_state(&tmp.path().join("half"), CARGO),
            EntryState::Incomplete
        );
        complete_entry(&tmp.path().join("whole"));
        assert_eq!(
            entry_state(&tmp.path().join("whole"), CARGO),
            EntryState::Complete
        );
    }

    #[test]
    fn restoring_the_snapshot_undoes_what_a_patch_did_to_registry_config() {
        let tmp = TempDir::new().unwrap();
        let t = tmp.path();
        fs::create_dir_all(t.join(".cargo")).unwrap();
        fs::write(t.join(".cargo/config.toml"), "base config\n").unwrap();
        let snapshot = RegistryConfigSnapshot::take(t).unwrap();
        // The patch edits one config and adds another.
        fs::write(t.join(".cargo/config.toml"), "builder config\n").unwrap();
        fs::write(t.join(".npmrc"), "registry=http://evil\n").unwrap();
        snapshot.restore(t).unwrap();
        assert_eq!(
            fs::read_to_string(t.join(".cargo/config.toml")).unwrap(),
            "base config\n"
        );
        assert!(
            !t.join(".npmrc").exists(),
            "a config the base lacked is removed"
        );
    }

    #[test]
    fn the_allowlist_of_the_restored_tree_is_the_bases_whatever_the_patch_did() {
        let tmp = TempDir::new().unwrap();
        let t = tmp.path();
        fs::write(
            t.join("cowproof.toml"),
            "[proof]\nfetch_hosts = [\"git.example\"]\n",
        )
        .unwrap();
        let snapshot = RegistryConfigSnapshot::take(t).unwrap();
        // The patch swaps the host for its own and adds a registry in the cargo config.
        fs::write(
            t.join("cowproof.toml"),
            "[proof]\nfetch_hosts = [\"evil.example\"]\n",
        )
        .unwrap();
        fs::create_dir_all(t.join(".cargo")).unwrap();
        fs::write(
            t.join(".cargo/config.toml"),
            "[source.x]\nregistry = \"sparse+https://evil2.example/\"\n",
        )
        .unwrap();
        snapshot.restore(t).unwrap();
        let allow = FetchAllowlist::from_tree(t).unwrap();
        assert!(allow.allows("git.example", 443), "{:?}", allow.hosts());
        assert!(!allow.allows("evil.example", 443), "{:?}", allow.hosts());
        assert!(!allow.allows("evil2.example", 443), "{:?}", allow.hosts());

        // A base without the file: the patch's new one is removed.
        let bare = TempDir::new().unwrap();
        let snapshot = RegistryConfigSnapshot::take(bare.path()).unwrap();
        fs::write(
            bare.path().join("cowproof.toml"),
            "[proof]\nfetch_hosts = [\"evil.example\"]\n",
        )
        .unwrap();
        snapshot.restore(bare.path()).unwrap();
        assert!(!bare.path().join("cowproof.toml").exists());
        assert_eq!(
            FetchAllowlist::from_tree(bare.path()).unwrap(),
            FetchAllowlist::defaults()
        );
    }

    #[test]
    fn restoring_never_follows_a_symlinked_parent_out_of_the_tree() {
        let tmp = TempDir::new().unwrap();
        let t = tmp.path().join("tree");
        let outside = tmp.path().join("outside");
        fs::create_dir_all(&t).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("config.toml"), "must survive\n").unwrap();
        let snapshot = RegistryConfigSnapshot::take(&t).unwrap();
        std::os::unix::fs::symlink(&outside, t.join(".cargo")).unwrap();
        snapshot.restore(&t).unwrap();
        assert_eq!(
            fs::read_to_string(outside.join("config.toml")).unwrap(),
            "must survive\n",
            "the file behind the symlink was removed"
        );
        assert!(
            !t.join(".cargo").exists(),
            "the symlink itself is gone: the base had no .cargo"
        );
    }

    #[test]
    fn a_symlinked_config_file_is_taken_as_absent() {
        let tmp = TempDir::new().unwrap();
        let t = tmp.path();
        fs::write(t.join("real"), "x").unwrap();
        std::os::unix::fs::symlink(t.join("real"), t.join(".npmrc")).unwrap();
        let snapshot = RegistryConfigSnapshot::take(t).unwrap();
        snapshot.restore(t).unwrap();
        assert!(!t.join(".npmrc").exists());
        assert!(t.join("real").exists());
    }

    fn lane_in(tmp: &Path) -> LaneLayout {
        LaneLayout {
            clone: tmp.join("lane/clone"),
            home: tmp.join("lane/home"),
            scratch: tmp.join("lane/scratch"),
            control: tmp.join("lane/control"),
            real_home: tmp.join("home"),
            sock: tmp.join("lane/sock/runner.sock"),
            lanes_root: tmp.to_path_buf(),
        }
    }

    fn no_tools() -> FetchTools {
        FetchTools {
            path: "/usr/bin:/bin".into(),
            cargo: None,
            npm: None,
            yarn: None,
            pnpm: None,
        }
    }

    #[test]
    fn a_tree_with_no_dependency_file_has_nothing_to_fetch_and_no_cache_entry() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("cache");
        let lane = lane_in(tmp.path());
        let tools = no_tools();
        let got = prefetch(
            |tree| {
                fs::write(tree.join("README.md"), "hello")?;
                Ok(())
            },
            &root,
            &lane,
            &config(&tools, &|_| true),
        )
        .unwrap();
        assert!(got.is_none());
        assert_eq!(
            fs::read_dir(root.join("deps")).unwrap().count(),
            0,
            "no entry was made"
        );
        assert_eq!(
            fs::read_dir(root.join("deps-work")).unwrap().count(),
            0,
            "the work directory is removed"
        );
    }

    #[test]
    fn dependency_files_that_are_not_fetched_are_not_fetched_and_say_so() {
        for (files, expect) in [
            (
                &["package.json"][..],
                "package.json without a package-lock.json",
            ),
            (
                &["package.json", "package-lock.json", "yarn.lock"][..],
                "package-lock.json, yarn.lock: more than one JavaScript lockfile",
            ),
            (
                &["package.json", "yarn.lock", "pnpm-lock.yaml"][..],
                "yarn.lock, pnpm-lock.yaml: more than one JavaScript lockfile",
            ),
            (
                &["Gemfile.lock"][..],
                "Gemfile.lock: Bundler is not fetched",
            ),
        ] {
            let tmp = TempDir::new().unwrap();
            let root = tmp.path().join("cache");
            let lane = lane_in(tmp.path());
            let tools = no_tools();
            let got = prefetch(
                |tree| {
                    for f in files {
                        fs::write(tree.join(f), "{}")?;
                    }
                    Ok(())
                },
                &root,
                &lane,
                &config(&tools, &|_| true),
            )
            .unwrap()
            .unwrap_or_else(|| panic!("{files:?}: the omission is reported"));
            assert_eq!(got.outcome, FetchOutcome::NotFetched, "{files:?}");
            assert_eq!(got.outcome.name(), "not_fetched");
            assert!(got.ecosystems.is_empty(), "{files:?}: {:?}", got.ecosystems);
            assert!(
                got.notes.iter().any(|n| n.contains(expect)),
                "{files:?}: {:?}",
                got.notes
            );
            assert!(!got.dir.exists(), "{files:?}: no entry was made");
        }
    }

    #[test]
    fn a_package_json_beside_an_npm_lockfile_is_not_reported_as_unfetched() {
        let tmp = TempDir::new().unwrap();
        for files in [
            &["package.json", "package-lock.json"][..],
            &["package.json", "npm-shrinkwrap.json"][..],
        ] {
            let t = tmp.path().join(files[1]);
            fs::create_dir_all(&t).unwrap();
            for f in files {
                fs::write(t.join(f), "{}").unwrap();
            }
            assert_eq!(Needs::of(&t).js, Some(JsTool::Npm), "{files:?}");
            assert!(
                unfetched_notes(&t).is_empty(),
                "{files:?}: {:?}",
                unfetched_notes(&t)
            );
        }
        // A lockfile that is a symlink is not a lockfile: it could point anywhere.
        let linked = tmp.path().join("linked");
        fs::create_dir_all(&linked).unwrap();
        fs::write(linked.join("real"), "{}").unwrap();
        std::os::unix::fs::symlink(linked.join("real"), linked.join("package-lock.json")).unwrap();
        assert_eq!(Needs::of(&linked).js, None);
    }

    #[test]
    fn an_entry_must_hold_every_part_the_tree_asks_for() {
        let tmp = TempDir::new().unwrap();
        let both = Needs {
            cargo: true,
            js: Some(JsTool::Npm),
        };
        let npm = Needs {
            cargo: false,
            js: Some(JsTool::Pnpm),
        };
        let old = tmp.path().join("old");
        complete_entry(&old);
        assert_eq!(entry_state(&old, CARGO), EntryState::Complete);
        assert_eq!(
            entry_state(&old, both),
            EntryState::Incomplete,
            "a cargo-only entry is not a hit for a tree with an npm lockfile too"
        );
        assert_eq!(entry_state(&old, npm), EntryState::Incomplete);
        let full = tmp.path().join("full");
        complete_entry(&full);
        fs::create_dir_all(full.join("npm/node_modules")).unwrap();
        assert_eq!(entry_state(&full, both), EntryState::Complete);
        let only = tmp.path().join("only");
        fs::create_dir_all(only.join("npm/node_modules")).unwrap();
        assert_eq!(entry_state(&only, npm), EntryState::Complete);
        assert_eq!(entry_state(&only, CARGO), EntryState::Incomplete);
    }

    #[test]
    fn the_npmrc_the_fetch_gets_has_no_credential_in_it() {
        let rc = "registry=https://reg.example/npm/\n\
                  //reg.example/npm/:_authToken=SECRET-1\n\
                  //reg.example/:_auth=SECRET-2\n\
                  @corp:_password=SECRET-3\n\
                  _authToken=SECRET-4\n\
                  ; _authToken=commented\n\
                  @corp:registry=https://user:SECRET-5@corp.example/\n\
                  always-auth=true\n";
        let (clean, stripped) = strip_npmrc_auth(rc);
        for secret in ["SECRET-1", "SECRET-2", "SECRET-3", "SECRET-4", "SECRET-5"] {
            assert!(!clean.contains(secret), "{secret} survived:\n{clean}");
        }
        assert_eq!(stripped, 5, "{clean}");
        for kept in [
            "registry=https://reg.example/npm/",
            "@corp:registry=https://corp.example/",
            "always-auth=true",
            "; _authToken=commented",
        ] {
            assert!(clean.contains(kept), "{kept} was lost:\n{clean}");
        }
    }

    #[test]
    fn the_npmrc_the_fetch_gets_has_no_client_certificate_setting_in_it() {
        // The PEM header is built, not written, so the source holds no key-shaped literal.
        let (begin, end) = (
            concat!("-----BEGIN ", "PRIVATE KEY-----"),
            "-----END PRIVATE KEY-----",
        );
        let rc = format!(
            "registry=https://reg.example/npm/\n\
             key=\"{begin}\\nPEMBODY1\\n{end}\"\n\
             //reg.example/:KeyFile=/secret/KEYPATH\n\
             //reg.example:8443/:key={begin}\n\
             PEMBODY2\n\
             {end}\n\
             certfile=/CERTPATH\n\
             @corp:cert=CERTPEM\n\
             always-auth=true\n"
        );
        let (clean, stripped) = strip_npmrc_auth(&rc);
        for gone in [
            "PEMBODY1",
            "PEMBODY2",
            "KEYPATH",
            "CERTPATH",
            "CERTPEM",
            "PRIVATE KEY",
        ] {
            assert!(!clean.contains(gone), "{gone} survived:\n{clean}");
        }
        assert_eq!(stripped, 5, "{clean}");
        assert_eq!(
            clean,
            "registry=https://reg.example/npm/\nalways-auth=true\n"
        );
    }

    #[test]
    fn a_tool_is_found_by_the_hook_variable_or_the_path_and_never_by_a_relative_entry() {
        let tmp = TempDir::new().unwrap();
        let bin = tmp.path().join("bin");
        fs::create_dir_all(&bin).unwrap();
        for name in ["npm", "yarn", "pnpm"] {
            fs::write(bin.join(name), "#!/bin/sh\n").unwrap();
        }
        let path = std::env::join_paths([Path::new(""), Path::new("rel"), bin.as_path()]).unwrap();
        for name in ["npm", "yarn", "pnpm"] {
            assert_eq!(
                resolve_tool(name, None, Some(&path)),
                Some(bin.join(name)),
                "{name}"
            );
        }
        assert_eq!(resolve_tool("bundler", None, Some(&path)), None);
        let hook = tmp.path().join("hook-yarn");
        fs::write(&hook, "x").unwrap();
        assert_eq!(
            resolve_tool("yarn", Some(hook.as_os_str()), Some(&path)),
            Some(hook.clone())
        );
        // A hook that is not an existing absolute file falls back to the PATH.
        assert_eq!(
            resolve_tool("pnpm", Some("relative-pnpm".as_ref()), Some(&path)),
            Some(bin.join("pnpm"))
        );
        assert_eq!(resolve_tool("npm", None, Some("".as_ref())), None);
        assert_eq!(resolve_tool("npm", None, None), None);
    }

    #[test]
    fn an_npm_failure_is_named_by_its_first_error_line() {
        let out = b"npm WARN deprecated x\nnpm ERR! code E404\nnpm ERR! 404 Not Found\n";
        assert_eq!(npm_failure(out), "npm ERR! code E404");
        assert_eq!(
            npm_failure(b"npm error code ETARGET\n"),
            "npm error code ETARGET"
        );
        assert_eq!(npm_failure(b"\n  boom\n"), "boom");
        assert_eq!(npm_failure(b""), "no output");
    }

    #[test]
    fn yarn_and_pnpm_failures_are_named_by_their_first_error_line() {
        assert_eq!(
            yarn_failure(b"warning x\ninfo y\nerror Couldn't find package \"z\"\nerror two\n"),
            "error Couldn't find package \"z\""
        );
        assert_eq!(
            yarn_failure(
                "\u{27a4} YN0000: info\n\u{27a4} YN0001: \u{2502} Error: boom\n".as_bytes()
            ),
            "\u{27a4} YN0001: \u{2502} Error: boom"
        );
        assert_eq!(
            pnpm_failure(
                b"Progress: resolved 1\n ERR_PNPM_FETCH_404  GET https://r/x: Not Found\n"
            ),
            "ERR_PNPM_FETCH_404  GET https://r/x: Not Found"
        );
        assert_eq!(pnpm_failure(b""), "no output");
    }

    #[test]
    fn the_tool_a_javascript_lockfile_names_is_one_and_never_a_guess() {
        let plan = |files: &[(&str, &str)]| {
            let tmp = TempDir::new().unwrap();
            for (name, text) in files {
                fs::write(tmp.path().join(name), text).unwrap();
            }
            js_plan(tmp.path())
        };
        assert_eq!(plan(&[("package.json", "{}")]), JsPlan::Nothing);
        assert_eq!(
            plan(&[("package-lock.json", "{}")]),
            JsPlan::Fetch(JsTool::Npm)
        );
        assert_eq!(plan(&[("pnpm-lock.yaml", "")]), JsPlan::Fetch(JsTool::Pnpm));
        assert_eq!(
            plan(&[("yarn.lock", "# yarn lockfile v1\n")]),
            JsPlan::Fetch(JsTool::YarnClassic)
        );
        let berry_lock = "__metadata:\n  version: 8\n";
        let node_modules = "nodeLinker: node-modules\n";
        assert_eq!(
            plan(&[("yarn.lock", berry_lock), (".yarnrc.yml", node_modules)]),
            JsPlan::Fetch(JsTool::YarnBerry)
        );
        // A `.yarnrc.yml` makes it Berry whatever the lockfile says.
        assert_eq!(
            plan(&[
                ("yarn.lock", "# v1\n"),
                (".yarnrc.yml", "nodeLinker: \"node-modules\" # x\n")
            ]),
            JsPlan::Fetch(JsTool::YarnBerry)
        );
        // Plug'n'Play, spelled out, by default, or another linker: nothing to mount.
        for (lock, rc) in [
            (berry_lock, Some("nodeLinker: pnp\n")),
            (berry_lock, Some("enableTelemetry: false\n")),
            (berry_lock, Some("nodeLinker: pnpm\n")),
            (berry_lock, Some("  nodeLinker: node-modules\n")),
            (berry_lock, None),
        ] {
            let mut files = vec![("yarn.lock", lock)];
            files.extend(rc.map(|r| (".yarnrc.yml", r)));
            match plan(&files) {
                JsPlan::NotFetched(note) => {
                    assert!(
                        note.contains("Plug'n'Play is not") || note.contains("Plug'n'Play)"),
                        "{note}"
                    );
                    assert!(note.starts_with("yarn.lock: "), "{note}");
                }
                other => panic!("{files:?}: {other:?}"),
            }
        }
        // Two tools' lockfiles are named, and none is picked.
        match plan(&[
            ("package-lock.json", "{}"),
            ("yarn.lock", ""),
            ("pnpm-lock.yaml", ""),
        ]) {
            JsPlan::NotFetched(note) => assert!(
                note.starts_with("package-lock.json, yarn.lock, pnpm-lock.yaml: more than one"),
                "{note}"
            ),
            other => panic!("{other:?}"),
        }
        // npm's two lockfiles are one tool's.
        assert_eq!(
            plan(&[("package-lock.json", "{}"), ("npm-shrinkwrap.json", "{}")]),
            JsPlan::Fetch(JsTool::Npm)
        );
    }

    #[test]
    fn the_yarnrc_yml_the_fetch_gets_has_no_credential_and_no_code_in_it() {
        let begin = concat!("-----BEGIN ", "PRIVATE KEY-----");
        let rc = format!(
            "# kept comment\n\
             nodeLinker: node-modules\n\
             npmRegistryServer: \"https://user:pw@reg.example/\"\n\
             npmAuthToken: TOP-TOKEN\n\
             npmAlwaysAuth: true\n\
             yarnPath: .yarn/releases/yarn-4.js\n\
             plugins:\n  - path: .yarn/plugins/x.cjs\n    spec: \"x\"\n\
             npmScopes:\n  corp:\n    npmRegistryServer: \"https://corp.example\"\n    npmAuthIdent: \"user:IDENT\"\n\
             npmRegistries:\n  \"//reg.example\":\n    npmAuthToken: REG-TOKEN\n    httpsKeyFilePath: /k/KEYPATH\n\
             \x20 \"//other.example\": {{ npmAuthToken: FLOW-TOKEN }}\n\
             cert: |\n    {begin}\n    PEMBODY\n\
             enableTelemetry: false\n"
        );
        let got = strip_yarnrc_yml(&rc);
        for gone in [
            "TOP-TOKEN",
            "user:pw",
            "yarnPath",
            "yarn-4.js",
            "plugins",
            "x.cjs",
            "IDENT",
            "REG-TOKEN",
            "KEYPATH",
            "FLOW-TOKEN",
            "PEMBODY",
            "PRIVATE KEY",
            "npmAlwaysAuth",
        ] {
            assert!(!got.text.contains(gone), "{gone} survived:\n{}", got.text);
        }
        for kept in [
            "# kept comment",
            "nodeLinker: node-modules",
            "npmRegistryServer: https://reg.example/",
            "npmScopes:",
            "npmRegistryServer: \"https://corp.example\"",
            "enableTelemetry: false",
        ] {
            assert!(got.text.contains(kept), "{kept} lost:\n{}", got.text);
        }
        // token, alwaysAuth, ident, token, key path, flow line, cert, url = 8; yarnPath, plugins = 2
        assert_eq!((got.credentials, got.code), (8, 2), "{}", got.text);
    }

    #[test]
    fn the_classic_yarnrc_the_fetch_gets_has_no_credential_in_it() {
        let rc = "# kept\n\
                  registry \"https://user:pw@reg.example/\"\n\
                  \"//reg.example/:_authToken\" \"CLASSIC-TOKEN\"\n\
                  //bare.example/:_auth BARE-AUTH\n\
                  \"@corp:registry\" \"https://corp.example/\"\n\
                  keyfile /k/KEYFILE\n\
                  yarn-path \".yarn/releases/yarn-1.js\"\n\
                  lastUpdateCheck 1\n";
        let got = strip_yarnrc(rc);
        for gone in [
            "user:pw",
            "CLASSIC-TOKEN",
            "BARE-AUTH",
            "KEYFILE",
            "yarn-1.js",
        ] {
            assert!(!got.text.contains(gone), "{gone} survived:\n{}", got.text);
        }
        assert_eq!(
            got.text,
            "# kept\nregistry \"https://reg.example/\"\n\"@corp:registry\" \"https://corp.example/\"\nlastUpdateCheck 1\n"
        );
        assert_eq!((got.credentials, got.code), (4, 1));
    }

    #[test]
    fn a_complete_entry_is_a_hit_and_nothing_runs() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("cache");
        let lane = LaneLayout {
            clone: tmp.path().join("lane/clone"),
            home: tmp.path().join("lane/home"),
            scratch: tmp.path().join("lane/scratch"),
            control: tmp.path().join("lane/control"),
            real_home: tmp.path().join("home"),
            sock: tmp.path().join("lane/sock/runner.sock"),
            lanes_root: tmp.path().to_path_buf(),
        };
        // No cargo and no sandbox are available to this test: a hit must not need them.
        let tools = FetchTools {
            path: String::new(),
            cargo: None,
            npm: None,
            yarn: None,
            pnpm: None,
        };
        let build = |tree: &Path| -> Result<()> {
            fs::write(tree.join("Cargo.lock"), "# lock\n")?;
            Ok(())
        };
        let key = {
            let t = tmp.path().join("probe");
            fs::create_dir(&t).unwrap();
            build(&t).unwrap();
            dependency_cache_key(&t, &host_target()).unwrap()
        };
        complete_entry(&cache_dir(&root, &key));
        let got = prefetch(build, &root, &lane, &config(&tools, &|_| true))
            .unwrap()
            .unwrap();
        assert_eq!(got.outcome, FetchOutcome::Hit);
        assert_eq!(got.key, key);
        assert_eq!(got.dir, cache_dir(&root, &key));
        // The hit is a use: this process holds a lease and the marker is fresh.
        let entry = cache_dir(&root, &key);
        assert!(
            entry
                .join(cache::LEASES)
                .join(std::process::id().to_string())
                .is_file()
        );
        let used = fs::metadata(entry.join(cache::LAST_USED))
            .unwrap()
            .modified()
            .unwrap();
        assert!(SystemTime::now().duration_since(used).unwrap() < Duration::from_secs(60));
    }

    #[test]
    fn a_fetch_does_not_sweep_a_root_that_holds_something_else_but_still_works() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("cache");
        let lane = LaneLayout {
            clone: tmp.path().join("lane/clone"),
            home: tmp.path().join("lane/home"),
            scratch: tmp.path().join("lane/scratch"),
            control: tmp.path().join("lane/control"),
            real_home: tmp.path().join("home"),
            sock: tmp.path().join("lane/sock/runner.sock"),
            lanes_root: tmp.path().to_path_buf(),
        };
        let dead = 4_000_002u32;
        fs::create_dir_all(root.join("deps/old-project")).unwrap();
        fs::create_dir_all(root.join(format!("deps-work/{dead}-1"))).unwrap();
        let tools = FetchTools {
            path: String::new(),
            cargo: None,
            npm: None,
            yarn: None,
            pnpm: None,
        };
        let got = prefetch(|_| Ok(()), &root, &lane, &config(&tools, &|_| false)).unwrap();
        assert!(got.is_none(), "the fetch itself ran");
        assert!(
            root.join(format!("deps-work/{dead}-1")).is_dir(),
            "the sweep ran in an unmarked root that holds something else"
        );
        assert!(root.join("deps/old-project").is_dir());
    }

    #[test]
    fn a_fetch_into_a_new_root_marks_it_as_cowproofs() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("cache");
        let lane = LaneLayout {
            clone: tmp.path().join("lane/clone"),
            home: tmp.path().join("lane/home"),
            scratch: tmp.path().join("lane/scratch"),
            control: tmp.path().join("lane/control"),
            real_home: tmp.path().join("home"),
            sock: tmp.path().join("lane/sock/runner.sock"),
            lanes_root: tmp.path().to_path_buf(),
        };
        let tools = FetchTools {
            path: String::new(),
            cargo: None,
            npm: None,
            yarn: None,
            pnpm: None,
        };
        prefetch(|_| Ok(()), &root, &lane, &config(&tools, &|_| true)).unwrap();
        assert_eq!(
            fs::read_to_string(root.join(cache::MARKER)).unwrap(),
            cache::MARKER_BODY
        );
    }

    #[test]
    fn a_fetch_clears_the_work_directory_of_an_interrupted_run_and_only_that() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("cache");
        let lane = LaneLayout {
            clone: tmp.path().join("lane/clone"),
            home: tmp.path().join("lane/home"),
            scratch: tmp.path().join("lane/scratch"),
            control: tmp.path().join("lane/control"),
            real_home: tmp.path().join("home"),
            sock: tmp.path().join("lane/sock/runner.sock"),
            lanes_root: tmp.path().to_path_buf(),
        };
        let (dead, live) = (4_000_002u32, std::process::id());
        let work = root.join("deps-work");
        for name in [format!("{dead}-1"), format!("{live}-1")] {
            fs::create_dir_all(work.join(name).join("tree")).unwrap();
        }
        let tools = FetchTools {
            path: String::new(),
            cargo: None,
            npm: None,
            yarn: None,
            pnpm: None,
        };
        let got = prefetch(
            |_| Ok(()),
            &root,
            &lane,
            &config(&tools, &|pid| pid == live),
        )
        .unwrap();
        assert!(got.is_none());
        assert!(!work.join(format!("{dead}-1")).exists());
        assert!(work.join(format!("{live}-1/tree")).is_dir());
    }
}
