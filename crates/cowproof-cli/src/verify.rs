//! `cowproof verify <capsule-dir> --repo <path>`: replay a capsule on a second machine.
//!
//! It reads only the capsule directory and the repository it is given, so it works from
//! any working directory and a fresh clone: the base commit is rebuilt from `--repo`, the
//! capsule's patches are applied, and every recorded check, then every held-out check the
//! capsule carries, runs in the same no-network verifier sandbox `cowproof run` uses
//! ([`verifier_runner`] is the one constructor both call).

use crate::compile_cache;
use anyhow::{Context, Result, anyhow, bail};
use clap::Parser;
use cowproof_core::{
    PORT_CLASS, class_limit_at_commit, get_slot_dir, one_line, port_base_for_slot,
};
use cowproof_prove::{
    Capsule, VerifyError,
    runner::{
        GroupEnd, GroupSet, SandboxedRunner, SlotGuard, acquire_slot_notifying, host_platform,
        run_in_group_blocking, verifier_toolchain,
    },
    verify::{VerifyOptions, VerifyReport, VerifyResult, remove_launch_paths, verify},
};
use cowproof_run::{
    LaneLayout,
    deps::{
        self, FETCH_RESOLVE_ENV, FETCH_TIMEOUT, FetchConfig, FetchEgress, FetchEnd, FetchNetwork,
        FetchOutcome, FetchTools, Prefetch,
    },
    fetch_proxy::Resolver,
    lane_tmp, link_dependency_cache,
    runtime_dirs::{self, Protected, RUNTIME_DIRS_ENV, RuntimeDir},
    verify_target,
};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Parser)]
#[command(after_help = "\
Exit codes: 0 reproduced (every recorded check matched and every held-out check passed); \
2 diverged (a recorded check's pass or fail differs, or a held-out check failed; the check \
is named); 4 infrastructure (the capsule was refused as tampered, unsandboxed or unreadable, \
or the replay could not run, or the dependency fetch the checks need failed; never a \
refutation).

Dependencies: a capsule whose tree has a Cargo.lock, one of package-lock.json, \
npm-shrinkwrap.json, yarn.lock or pnpm-lock.yaml, or a Gemfile.lock (or gems.locked), names a \
dependency cache key. The cache is <cache root>/deps/<key>, the \
cache root being ~/.cache/cowproof or $COWPROOF_CACHE_ROOT; verify fetches it (cargo fetch \
--locked, npm ci --ignore-scripts, yarn install --frozen-lockfile --ignore-scripts (classic) or \
--immutable --mode=skip-build (Berry, node-modules linker only), or pnpm install --frozen-lockfile \
--ignore-scripts, in a sandbox; the tool is $COWPROOF_NPM, $COWPROOF_YARN or $COWPROOF_PNPM, or the \
first on PATH; the network is $COWPROOF_FETCH_NETWORK: `registry` by default, a proxy that tunnels only \
to the base's registry hosts and the base cowproof.toml's [proof] fetch_hosts; `open` for full \
outbound network; or `none`) when it is absent, and mounts it read-only for the checks \
(node_modules appears in the tree, read-only). A Gemfile.lock is fetched as `.gem` files by `gem \
fetch` (no Gemfile is evaluated and `bundle` is not run; the tool is $COWPROOF_GEM or the first on \
PATH), which appear as vendor/cache, read-only, and the verifier runs `bundle install --local` \
once ($COWPROOF_BUNDLE or the first on PATH) before the first check.

Compile cache: for a base commit with a Cargo.toml at its root the verifier compiles the BASE \
commit's tree once, with `cargo test --workspace --locked --offline --no-run` in the same \
sandbox, into <cache root>/verify-target/<key> (never from the capsule's patches, and never \
written by a check), and gives the checks a private copy of that target directory as \
CARGO_TARGET_DIR (copy-on-write where the filesystem has it). A seed that cannot be built \
changes nothing: the checks run as without one. $COWPROOF_VERIFY_CACHE=off turns it off.")]
pub struct VerifyArgs {
    /// The capsule directory (`control/capsule` of a lane)
    capsule_dir: PathBuf,
    /// A repository that holds the capsule's base commit (a fresh clone is enough)
    #[arg(long)]
    repo: PathBuf,
    /// Directory to rebuild in. Default: a new directory under `~/.cache/cowproof/verify`,
    /// removed when the capsule reproduces
    #[arg(long)]
    workdir: Option<PathBuf>,
    /// Directory of the machine-wide class slots (D12). Default: `$COWPROOF_SLOT_DIR`, else
    /// `~/.cache/cowproof/slots`. The verifier holds one slot of the class the capsule
    /// records and one `port` slot while it replays, waiting when none is free; the limits
    /// are the capsule's base commit's `cowproof.toml` `[classes]`
    #[arg(long)]
    slot_dir: Option<PathBuf>,
    /// A reference-runtime directory to grant the verifier, by absolute path; repeatable, and
    /// `COWPROOF_RUNTIME_DIRS` (colon-separated) adds more. Read-only, with its `bin` on the
    /// verifier's `PATH`, exactly as for `cowproof run --runtime-dir`. A capsule made with
    /// runtime directories names them (`runtime_dirs`); pass the same ones here, or the
    /// held-out cases that need them are skipped and the skip names the capsule's list
    #[arg(long = "runtime-dir", value_name = "DIR")]
    runtime_dir: Vec<PathBuf>,
}

/// The sandboxed check runner the verifier uses, for both `cowproof run` and
/// `cowproof verify`. `verify_dir` is the directory `verify` rebuilds in: the runner's
/// layout names only it as scratch, so nothing else the lane left in its own scratch is
/// visible to a check. Clears any earlier `verify_dir` (the builder owned the lane's
/// scratch), then creates it with the verifier's own `CARGO_HOME` inside. `deps` is the
/// fetched dependency cache (D6): its `registry` (and `git`) are linked into that
/// `CARGO_HOME` and mounted read-only, and nothing else of it is visible. `runtime` is the
/// director's granted runtime directories (`--runtime-dir`): read-only, on the checks' `PATH`.
pub(crate) fn verifier_runner(
    layout: &LaneLayout,
    verify_dir: &Path,
    deps: Option<&Path>,
    runtime: &[RuntimeDir],
) -> Result<SandboxedRunner> {
    remove_path(verify_dir).context("clearing the verify directory")?;
    let cache = verify_dir.join("cache");
    fs::create_dir_all(cache.join(".cargo")).context("creating the verify directory")?;
    // The verifier's `TMPDIR` (a check that runs `mktemp`); macOS denies the rest.
    fs::create_dir_all(lane_tmp(verify_dir)).context("creating the verifier's temp directory")?;
    let mut verify_layout = layout.clone();
    verify_layout.scratch = verify_dir.to_path_buf();
    let mut runner =
        SandboxedRunner::new(verify_layout, cache.clone(), host_platform().to_string())
            .with_runtime_dirs(runtime.to_vec());
    if let Some(deps) = deps {
        link_dependency_cache(deps, &cache.join(".cargo"))?;
        // The `bundle` of a Bundler entry's install step: `$COWPROOF_BUNDLE` or the first on
        // `PATH`. Only a tree whose entry has a Bundler part runs it.
        runner = runner
            .with_dependency_cache(deps.to_path_buf())
            .with_bundle_exe(find_tool("bundle", deps::BUNDLE_ENV));
    }
    Ok(runner)
}

/// The absolute `name` executable the hook variable `hook` names, else the first `name` on the
/// director's `PATH` ([`deps::resolve_tool`]).
fn find_tool(name: &str, hook: &str) -> Option<PathBuf> {
    deps::resolve_tool(
        name,
        std::env::var_os(hook).as_deref(),
        std::env::var_os("PATH").as_deref(),
    )
}

/// The runtime directories the director grants (`--runtime-dir` flags, then
/// `COWPROOF_RUNTIME_DIRS`), read once at startup and checked: an error names the first
/// refused directory and the rule. `protected` is what no grant may touch.
pub(crate) fn director_runtime_dirs(
    flags: &[PathBuf],
    real_home: &Path,
    protected: &[Protected<'_>],
) -> Result<Vec<RuntimeDir>> {
    let env = std::env::var_os(RUNTIME_DIRS_ENV);
    let asked = runtime_dirs::requested(flags, env.as_deref())?;
    runtime_dirs::resolve(&asked, real_home, protected)
}

/// What rebuilds the tree a lane's dependencies are fetched for: the same four steps
/// `verify` takes (base commit, `base.patch`, launch baseline, `lane.patch`).
pub(crate) struct Rebuild {
    pub repo: PathBuf,
    pub base_commit: String,
    pub base_patch: Option<Vec<u8>>,
    pub launch_removed: Vec<String>,
    pub lane_patch: Vec<u8>,
}

impl Rebuild {
    /// Build the tree in `tree`, an empty directory. The registry configuration is the
    /// tree's BEFORE `lane.patch` (D14): a patch that touches it changes nothing here.
    pub(crate) fn build(&self, tree: &Path) -> Result<()> {
        git(
            None,
            &["clone", "--quiet", "--no-checkout", "--"],
            &[self.repo.as_os_str(), tree.as_os_str()],
            None,
        )
        .context("cloning the repository")?;
        git(
            Some(tree),
            &["checkout", "--quiet", "--detach", &self.base_commit],
            &[],
            None,
        )
        .context("checking out the base commit")?;
        if let Some(patch) = &self.base_patch {
            apply(tree, patch).context("applying base.patch")?;
        }
        remove_launch_paths(tree, &self.launch_removed).map_err(|e| anyhow!("{e}"))?;
        let config = deps::RegistryConfigSnapshot::take(tree)?;
        apply(tree, &self.lane_patch).context("applying lane.patch")?;
        config.restore(tree)
    }
}

/// `git` with hooks off, in `dir` or at the top, with `stdin` when given.
fn git(
    dir: Option<&Path>,
    args: &[&str],
    paths: &[&std::ffi::OsStr],
    stdin: Option<&[u8]>,
) -> Result<()> {
    let mut command = Command::new("git");
    command.args(["-c", "core.hooksPath=/dev/null"]);
    if let Some(dir) = dir {
        command.arg("-C").arg(dir);
    }
    command.args(args).args(paths);
    command
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let mut child = command.spawn().context("starting git")?;
    if let (Some(bytes), Some(mut pipe)) = (stdin, child.stdin.take()) {
        pipe.write_all(bytes).context("writing to git")?;
    }
    let out = child.wait_with_output().context("waiting for git")?;
    if !out.status.success() {
        bail!(
            "git {} failed: {}",
            args.first().copied().unwrap_or(""),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

fn apply(tree: &Path, patch: &[u8]) -> Result<()> {
    if patch.iter().all(u8::is_ascii_whitespace) {
        return Ok(());
    }
    git(Some(tree), &["apply", "-"], &[], Some(patch))
}

/// Fetch (or find in the cache) the dependencies of the tree `rebuild` describes, before
/// verify runs (D6, D11, D14). `Ok(None)`: nothing to fetch. The fetch is blocking work,
/// so it runs off the async threads.
///
/// `groups` is the run's [`GroupSet`] (`cowproof run`; `cowproof verify` has none): the
/// `cargo fetch` command is its own process group, listed there while it runs, so a signal
/// that ends the run's groups ends the fetch with them. A fetch that has not started its
/// command when this future is dropped (the signal came during the rebuild) never starts it.
pub(crate) async fn fetch_dependencies(
    rebuild: Rebuild,
    layout: &LaneLayout,
    groups: Option<Arc<GroupSet>>,
) -> Result<Option<Prefetch>> {
    let network = FetchNetwork::from_env()?;
    let resolver = match std::env::var(FETCH_RESOLVE_ENV) {
        Ok(spec) => {
            let resolver = Resolver::parse(&spec)
                .with_context(|| format!("{FETCH_RESOLVE_ENV} is not usable"))?;
            if let Some(fixed) = resolver.spec() {
                eprintln!(
                    "warning: {FETCH_RESOLVE_ENV} is set: {fixed} (testing only); the dependency \
                     fetch connects those registry names to these loopback addresses and the \
                     capsule records it"
                );
            }
            resolver
        }
        Err(_) => Resolver::system(),
    };
    let (path, cargo) = verifier_toolchain(&layout.real_home).map_err(|e| anyhow!("{e}"))?;
    // The executable that runs `net-bridge` inside the registry-only fetch sandbox, resolved
    // as the proof does for the port replay.
    let bridge_exe = std::env::current_exe()
        .and_then(|p| p.canonicalize())
        .context("locating the cowproof executable for the fetch's bridge")?;
    // `$COWPROOF_NPM`, `$COWPROOF_YARN`, `$COWPROOF_PNPM`, `$COWPROOF_GEM` and
    // `$COWPROOF_BUNDLE` (test hooks, as `$CARGO` is for cargo) or the first `npm`, `yarn`,
    // `pnpm`, `gem` and `bundle` on `PATH`.
    let npm = find_tool("npm", deps::NPM_ENV);
    let yarn = find_tool("yarn", deps::YARN_ENV);
    let pnpm = find_tool("pnpm", deps::PNPM_ENV);
    let gem = find_tool("gem", deps::GEM_ENV);
    let bundle = find_tool("bundle", deps::BUNDLE_ENV);
    let root = deps::cache_root(&layout.real_home);
    let layout = layout.clone();
    let cancelled = Arc::new(AtomicBool::new(false));
    let _cancel = CancelOnDrop(cancelled.clone());
    tokio::task::spawn_blocking(move || {
        let tools = FetchTools {
            path,
            cargo,
            npm,
            yarn,
            pnpm,
            gem,
            bundle,
        };
        let egress = FetchEgress {
            bridge_exe,
            resolver,
        };
        let exec = |command: Command, timeout: Duration| -> Result<FetchEnd> {
            if cancelled.load(Ordering::SeqCst) {
                bail!("the run was interrupted before the fetch command started");
            }
            let ran = run_in_group_blocking(command, timeout, Duration::ZERO, groups.as_deref())
                .map_err(|e| anyhow!("{e}"))?;
            Ok(match ran.end {
                GroupEnd::Exited(status) => {
                    let mut output = ran.stdout;
                    output.extend_from_slice(&ran.stderr);
                    FetchEnd::Exited { status, output }
                }
                GroupEnd::TimedOut => FetchEnd::TimedOut,
            })
        };
        deps::prefetch(
            |tree| rebuild.build(tree),
            &root,
            &layout,
            &FetchConfig {
                network,
                tools: &tools,
                timeout: FETCH_TIMEOUT,
                alive: &crate::cache::alive,
                exec: &exec,
                egress: Some(&egress),
            },
        )
    })
    .await
    .context("the dependency fetch task died")?
}

/// Sets a flag when dropped: the future that holds it was dropped (the run was signalled), or
/// finished, and the blocking fetch must not start a command after that.
struct CancelOnDrop(Arc<AtomicBool>);

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

/// The dependency cache a capsule's checks need, for `cowproof verify`: the capsule's
/// key, fetched here when this machine lacks it. `Err` is an infrastructure reason.
async fn capsule_dependencies(
    capsule_dir: &Path,
    repo: &Path,
    layout: &LaneLayout,
) -> std::result::Result<Option<PathBuf>, String> {
    // An unreadable or tampered capsule is `verify`'s to refuse, with its own message.
    let Ok(capsule) = Capsule::read(capsule_dir) else {
        return Ok(None);
    };
    let Some(key) = capsule.dependency_cache_key.clone() else {
        return Ok(None);
    };
    let read = |name: &str| fs::read(capsule_dir.join(name)).ok();
    let rebuild = Rebuild {
        repo: repo.to_path_buf(),
        base_commit: capsule.base_commit.clone(),
        base_patch: read("base.patch"),
        launch_removed: capsule.launch_removed.clone(),
        lane_patch: read("lane.patch").unwrap_or_default(),
    };
    match fetch_dependencies(rebuild, layout, None).await {
        Err(e) => Err(format!("dependency fetch could not run: {e:#}")),
        Ok(None) => Err(format!(
            "the capsule names dependency cache {key}, but the rebuilt tree has no Cargo.lock, \
             JavaScript lockfile or Bundler lockfile to fetch"
        )),
        Ok(Some(Prefetch {
            outcome: FetchOutcome::NotFetched,
            ..
        })) => Err(format!(
            "the capsule names dependency cache {key}, but the rebuilt tree has nothing to fetch"
        )),
        Ok(Some(p)) if p.key != key => Err(format!(
            "the rebuilt tree's dependency cache key {} is not the capsule's {key}",
            p.key
        )),
        Ok(Some(Prefetch {
            outcome: FetchOutcome::Failed(why),
            ..
        })) => Err(format!("dependency fetch failed: {why}")),
        Ok(Some(p)) => Ok(Some(p.dir)),
    }
}

/// Remove `path` whatever it is, without following a symlink.
fn remove_path(path: &Path) -> std::io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(m) if m.is_dir() => fs::remove_dir_all(path),
        Ok(_) => fs::remove_file(path),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Replay the capsule; the return value is the process exit code.
pub async fn verify_capsule(args: VerifyArgs) -> Result<i32> {
    if !args.capsule_dir.is_dir() {
        bail!(
            "capsule directory does not exist: {}",
            args.capsule_dir.display()
        );
    }
    if !args.repo.is_dir() {
        bail!("repository does not exist: {}", args.repo.display());
    }
    // Read once, before anything is created: a typo is refused, never taken for `on`.
    let compile_cache_mode = match verify_target::Mode::from_env() {
        Ok(mode) => mode,
        Err(e) => {
            eprintln!("refused: {e:#}");
            eprintln!("nothing was started");
            return Ok(4);
        }
    };
    let capsule_dir = args.capsule_dir.canonicalize()?;
    let repo = args.repo.canonicalize()?;
    let real_home =
        PathBuf::from(std::env::var_os("HOME").ok_or_else(|| anyhow!("HOME is not set"))?);

    // The runtime directories the director grants (`--runtime-dir`, `COWPROOF_RUNTIME_DIRS`),
    // checked before anything is created: a refusal ends here, with no workdir, slot or sandbox.
    let cache_root = deps::cache_root(&real_home);
    let verify_area = real_home.join(".cache/cowproof/verify");
    let mut protected = vec![
        Protected {
            what: "the repository",
            path: &repo,
        },
        Protected {
            what: "the capsule",
            path: &capsule_dir,
        },
        Protected {
            what: "the cowproof cache",
            path: &cache_root,
        },
        Protected {
            what: "the verify directory",
            path: &verify_area,
        },
    ];
    if let Some(dir) = &args.workdir {
        protected.push(Protected {
            what: "the workdir",
            path: dir,
        });
    }
    let runtime = match director_runtime_dirs(&args.runtime_dir, &real_home, &protected) {
        Ok(dirs) => dirs,
        Err(e) => {
            eprintln!("refused: {e:#}");
            eprintln!("nothing was started");
            return Ok(4);
        }
    };

    // The workdir is laid out like a lane (`<root>/lane/{clone,home,scratch,control}`,
    // lanes root `<root>`), so the sandbox policy sees the shape it sees in `run`.
    let (root, ours) = match args.workdir {
        Some(dir) => {
            fs::create_dir_all(&dir)
                .with_context(|| format!("creating workdir {}", dir.display()))?;
            (dir.canonicalize()?, false)
        }
        None => {
            let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
            let dir = real_home.join(format!(
                ".cache/cowproof/verify/{}-{stamp}",
                std::process::id()
            ));
            fs::create_dir_all(&dir)
                .with_context(|| format!("creating workdir {}", dir.display()))?;
            (dir.canonicalize()?, true)
        }
    };
    let lane = root.join("lane");
    let layout = LaneLayout {
        clone: lane.join("clone"),
        home: lane.join("home"),
        scratch: lane.join("scratch"),
        control: lane.join("control"),
        real_home,
        sock: lane.join("sock/runner.sock"),
        lanes_root: root.clone(),
    };
    for dir in [
        &layout.clone,
        &layout.home,
        &layout.scratch,
        &layout.control,
        &lane.join("sock"),
    ] {
        fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    let verify_dir = layout.scratch.join("verify");
    let deps_dir = match capsule_dependencies(&capsule_dir, &repo, &layout).await {
        Ok(dir) => dir,
        Err(why) => {
            eprintln!("infrastructure: {}", one_line(&why));
            if ours {
                let _ = fs::remove_dir_all(&root);
            }
            return Ok(4);
        }
    };
    // The verifier holds one slot of the lane's class for the replay (D12), and one `port`
    // slot whose number is the checks' port block. Both are taken here, class first, and not
    // inside `verify`, because the port slot decides the environment the runner is built
    // with. A capsule that cannot be read is refused by `verify` below, as it always was,
    // without a slot.
    let capsule = Capsule::read(&capsule_dir).ok();
    let mut options = VerifyOptions {
        runtime_dirs: runtime_dirs::names(&runtime),
        ..VerifyOptions::default()
    };
    let mut runner = verifier_runner(&layout, &verify_dir, deps_dir.as_deref(), &runtime)?;
    // A port capsule's replay runs `cowproof pk port replay` in the sandbox: this executable
    // must be reachable there.
    if capsule.as_ref().is_some_and(|c| c.port.is_some()) {
        let exe = std::env::current_exe()
            .and_then(|p| p.canonicalize())
            .context("locating the cowproof executable for the port replay")?;
        runner = runner.with_executable(exe.clone());
        options.pk_exe = Some(exe);
    }
    let _slot = match &capsule {
        Some(capsule) => {
            let slot_dir = args.slot_dir.clone().unwrap_or_else(get_slot_dir);
            let held = async {
                let (class_slot, class_limit) =
                    hold_slot(&repo, capsule, &capsule.class, &slot_dir).await?;
                let (port_slot, _) = hold_slot(&repo, capsule, PORT_CLASS, &slot_dir).await?;
                Ok::<_, String>((class_slot, class_limit, port_slot))
            };
            match held.await {
                Ok((class_slot, class_limit, port_slot)) => {
                    options.slot_dir = slot_dir;
                    options.slot_limit = class_limit;
                    options.slot_class = capsule.class.clone();
                    options.held_slot_path = Some(class_slot.path().to_path_buf());
                    if let Some(base) = port_base_for_slot(port_slot.path()) {
                        runner = runner.with_port_block(base);
                    }
                    Some((class_slot, port_slot))
                }
                Err(why) => {
                    eprintln!("infrastructure: {}", one_line(&why));
                    if ours {
                        let _ = fs::remove_dir_all(&root);
                    }
                    return Ok(4);
                }
            }
        }
        None => None,
    };

    // The verifier's compile cache (R3): a private copy of the base commit's seed, made now
    // that the slots are held, before the first check. A capsule `verify` is about to refuse
    // gets none.
    if let Some(capsule) = &capsule {
        let (with_cache, record) = compile_cache::attach(
            runner,
            &compile_cache::Request {
                mode: compile_cache_mode,
                repo: &repo,
                base_commit: &capsule.base_commit,
                base_tree_hash: &capsule.base_tree_hash,
                layout: &layout,
                deps: deps_dir.as_deref(),
                runtime: &runtime,
                groups: None,
                verify_dir: &verify_dir,
                timeout: options.default_timeout,
            },
        )
        .await;
        runner = with_cache;
        // A seed in use, or one that was wanted and could not be made, is said; the rest
        // changes nothing the director sees.
        match record.status.as_str() {
            "hit" | "built" => eprintln!(
                "compile cache: {} ({})",
                record.status,
                one_line(record.copy.as_deref().unwrap_or(""))
            ),
            "failed" => eprintln!(
                "compile cache: failed, the checks ran without a seed: {}",
                one_line(record.note.as_deref().unwrap_or(""))
            ),
            _ => {}
        }
    }

    let code = match verify(&capsule_dir, &repo, &verify_dir, &runner, options).await {
        Ok(report) => {
            // A Bundler tree whose `bundle install --local` failed in the verifier fails every
            // check with the same text: it is a divergence even when the capsule's own record
            // was a failure too.
            let (code, lines) = result_lines(&report, &runner.setup_failures());
            for line in lines {
                println!("{line}");
            }
            code
        }
        Err(VerifyError::Capsule(e)) => {
            eprintln!(
                "refused: the capsule was tampered with or is damaged: {}",
                one_line(&e.to_string())
            );
            4
        }
        Err(e) => {
            eprintln!("infrastructure: {}", one_line(&e.to_string()));
            4
        }
    };
    if ours && code == 0 {
        // The directory was created here and holds only the rebuilt tree.
        let _ = fs::remove_dir_all(&root);
    } else {
        eprintln!("rebuilt tree kept in {}", verify_dir.join("tree").display());
    }
    Ok(code)
}

/// The lines `cowproof verify` prints to stdout for `report`, and its exit code. Every line
/// that holds text from the lane (a fixture's tool and id, a Bundler error, a check's output
/// note) goes through [`one_line`] here, whatever escaping the text had before: the terminal
/// is the last place to be sure of it (S-1).
fn result_lines(report: &VerifyReport, setup_failures: &[String]) -> (i32, Vec<String>) {
    let mut lines = Vec::new();
    // A skipped held-out port case is said out loud, whatever else is.
    if let Some(note) = report.port.as_ref().and_then(|p| p.skipped_note()) {
        lines.push(one_line(&note));
    }
    // Printed after the result line, whatever it is: a note, never a failure. Only pass
    // or fail is compared with the builder's record.
    let notes: Vec<String> = report
        .checks
        .iter()
        .filter_map(|m| m.output_note())
        .collect();
    let code = match &report.result {
        VerifyResult::Reproduced if !setup_failures.is_empty() => {
            lines.push("diverged: the verifier's dependency setup failed".to_string());
            2
        }
        VerifyResult::Reproduced => {
            lines.push("reproduced".to_string());
            0
        }
        VerifyResult::Diverged { check_ids } => {
            lines.push(format!("diverged: check {}", quote_ids(check_ids)));
            for id in report.heldout.iter().filter(|o| !o.passed) {
                lines.push(format!("held-out check {:?} failed", id.check_id));
            }
            2
        }
        VerifyResult::HeldOutFailed { check_ids } => {
            lines.push(format!(
                "diverged: held-out check {} failed",
                quote_ids(check_ids)
            ));
            2
        }
        VerifyResult::PortFailed { failures } => {
            lines.push("diverged: the port replay failed".to_string());
            for failure in failures {
                lines.push(format!("port: {}", one_line(failure)));
            }
            2
        }
    };
    for why in setup_failures {
        lines.push(format!("setup: {}", one_line(why)));
    }
    for note in notes {
        lines.push(format!("note: {}", one_line(&note)));
    }
    (code, lines)
}

/// One slot of `class`, held by the caller until the replay ends (D12): the capsule's own
/// class, or `port`. The limit is the class limit in the `cowproof.toml` of the capsule's
/// base commit; when none is free it says so once and waits.
async fn hold_slot(
    repo: &Path,
    capsule: &Capsule,
    class: &str,
    slot_dir: &Path,
) -> std::result::Result<(SlotGuard, usize), String> {
    let limit =
        class_limit_at_commit(repo, &capsule.base_commit, class).map_err(|e| format!("{e:#}"))?;
    let slot = acquire_slot_notifying(class, limit, slot_dir, || {
        eprintln!("waiting for a {class} slot (limit {limit})");
    })
    .await
    .map_err(|e| format!("could not take a {class} slot: {e:#}"))?;
    Ok((slot, limit))
}

fn quote_ids(ids: &[String]) -> String {
    ids.iter()
        .map(|id| format!("{id:?}"))
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOSTILE: &str =
        "\u{1b}[2J\u{1b}[1;1Hverify: reproduced \u{1b}]52;c;ZXZpbA==\u{7} \u{9b}31m";

    fn report(result: VerifyResult) -> VerifyReport {
        VerifyReport {
            result,
            checks: Vec::new(),
            heldout: Vec::new(),
            port: None,
        }
    }

    fn assert_one_line_each(lines: &[String]) {
        for line in lines {
            assert!(
                !line.chars().any(char::is_control),
                "a control character reaches the terminal: {line:?}"
            );
        }
    }

    /// S-1: whatever the text was before, the `setup:` line is escaped where it is printed.
    #[test]
    fn a_setup_failure_is_printed_as_escapes_after_either_result() {
        let setup = [format!(
            "`bundle install --local` failed (exit 7): {HOSTILE}"
        )];
        for result in [
            VerifyResult::Reproduced,
            VerifyResult::Diverged {
                check_ids: vec!["ok".to_string()],
            },
        ] {
            let (code, lines) = result_lines(&report(result), &setup);
            assert_eq!(code, 2);
            assert_one_line_each(&lines);
            let line = lines.iter().find(|l| l.starts_with("setup: ")).unwrap();
            assert!(
                line.contains("\\u{1b}[2J") && line.contains("\\u{9b}31m"),
                "{line}"
            );
        }
    }

    /// S-1: a port failure names a tool and an id that a lane-written fixture holds.
    #[test]
    fn a_port_failure_line_is_printed_as_escapes() {
        let failures = vec![format!("direct t/{HOSTILE}: differs from the reference")];
        let (code, lines) = result_lines(&report(VerifyResult::PortFailed { failures }), &[]);
        assert_eq!(code, 2);
        assert_one_line_each(&lines);
        assert_eq!(lines[0], "diverged: the port replay failed");
        assert!(
            lines[1].starts_with("port: direct t/\\u{1b}[2J"),
            "{}",
            lines[1]
        );
    }

    #[test]
    fn a_clean_reproduction_prints_one_word_and_exits_zero() {
        let (code, lines) = result_lines(&report(VerifyResult::Reproduced), &[]);
        assert_eq!((code, lines), (0, vec!["reproduced".to_string()]));
    }
}
