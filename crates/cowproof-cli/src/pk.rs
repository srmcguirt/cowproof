//! The `pk` command tree, shared by the `pk` binary and `cowproof pk`.

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use cowproof_run::{LaneLayout, NetworkMode, SandboxPolicy, render_macos_profile, sandbox_command};
use portkit_core::{Config, Registry};
use portkit_plugin::{expand_home, register_layers};
use portkit_port::process::exec::{Host, WrapRequest, install_host, set_invocation};

/// Run the `pk` command tree with `args` as its arguments (argv[0] excluded).
///
/// The one entry point for both `pk` and `cowproof pk`. The registry is built
/// inside `portkit_cli`'s builder, from the config that `portkit_cli` resolved
/// from `--config` and `PK_*`, so plugin discovery follows the config the user
/// actually passed. Needs a multi-thread tokio runtime (see [`build_registry`]).
pub async fn run<I, T>(args: I) -> ExitCode
where
    I: IntoIterator<Item = T>,
    T: Into<OsString>,
{
    run_invoked_as(None, args).await
}

/// [`run`] for `cowproof pk ...`: the process harness re-enters this tree through shims, and
/// it must do it as `cowproof pk`, not as `cowproof`.
pub async fn run_via_cowproof<I, T>(args: I) -> ExitCode
where
    I: IntoIterator<Item = T>,
    T: Into<OsString>,
{
    let exe = std::env::current_exe().ok();
    run_invoked_as(
        exe.map(|e| vec![e.to_string_lossy().into_owned(), "pk".to_string()]),
        args,
    )
    .await
}

async fn run_invoked_as<I, T>(invocation: Option<Vec<String>>, args: I) -> ExitCode
where
    I: IntoIterator<Item = T>,
    T: Into<OsString>,
{
    if let Some(command) = invocation {
        set_invocation(command);
    }
    install_host(Arc::new(CowproofHost));
    let mut argv: Vec<OsString> = vec!["pk".into()];
    argv.extend(args.into_iter().map(Into::into));
    portkit_cli::run_from(argv, build_registry).await
}

/// Build the registry for `pk` and `cowproof pk` from the effective config.
///
/// Starts empty and loads the plugins declared in the global and project
/// manifests. Problems and shadowed tools go to stderr as warnings; a bad
/// plugin never stops `pk` from starting.
///
/// `portkit_cli`'s builder is synchronous and plugin discovery is async, so
/// this blocks with `block_in_place`, as the original portkit binary did.
/// That requires the multi-thread runtime that `#[tokio::main]` provides here;
/// discovery is a handful of short-lived subprocesses.
pub fn build_registry(config: &Config) -> Registry {
    let mut registry = Registry::new();

    let manifests: Vec<PathBuf> = config
        .plugins
        .layers()
        .iter()
        .map(|p| expand_home(p))
        .collect();

    let report = tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(register_layers(&mut registry, &manifests))
    });

    for problem in &report.problems {
        eprintln!("warning: plugin unavailable: {problem}");
    }
    for (name, shadowed) in &report.shadowed {
        // A tool being silently replaced is worse than one that failed loudly.
        eprintln!("note: `{name}` overrides the one declared in {shadowed}");
    }

    registry
}

/// The sandbox the process harness (`pk port exec`, `pk port wrap`) runs a reference in: the
/// policy cowproof builds for a port capture ([`SandboxPolicy::capture`], network denied),
/// narrowed to the run's own directories. No second sandbox.
struct CowproofHost;

/// The signal that ends a timed-out run's process group.
const SIGKILL: i32 = 9;

/// Where `name` is on this process's own `PATH` (the run's `PATH` starts with its shims).
fn find_on_path(name: &str) -> Option<PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|dir| dir.join(name))
        .find(|candidate| candidate.is_file())
}

impl Host for CowproofHost {
    fn wrap(&self, req: &WrapRequest<'_>) -> Result<Vec<String>, String> {
        let real_home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .filter(|h| h.is_absolute())
            .ok_or("HOME is not set to an absolute path, so there is no home to hide")?;
        let work = req.work;
        let control = work.join("control");
        std::fs::create_dir_all(&control).map_err(|e| e.to_string())?;
        let layout = LaneLayout {
            clone: work.join("root"),
            home: work.join("home"),
            scratch: work.join("scratch"),
            control,
            real_home,
            sock: work.join("sock").join("runner.sock"),
            // The work directory is the one place the sandbox hides and re-grants.
            lanes_root: work.to_path_buf(),
        };
        let mut policy = SandboxPolicy::capture(&layout);
        policy.network = NetworkMode::None;
        policy.rw_paths = req.rw.clone();
        policy.ro_paths = req.ro.clone();
        policy.executables = req.executables.clone();
        let profile = work.join("profile.sb");
        if cfg!(target_os = "macos") {
            let text = render_macos_profile(&policy).map_err(|e| format!("{e:#}"))?;
            std::fs::write(&profile, text).map_err(|e| e.to_string())?;
        }
        let platform = if cfg!(target_os = "macos") {
            "darwin"
        } else {
            "linux"
        };
        let (launcher, mut args) =
            sandbox_command(&policy, &profile, req.argv, platform).map_err(|e| format!("{e:#}"))?;
        // An absolute launcher: the run's own `PATH` starts with its shims.
        let launcher =
            find_on_path(&launcher).ok_or_else(|| format!("{launcher} is not on PATH"))?;
        let mut full = vec![launcher.to_string_lossy().into_owned()];
        full.append(&mut args);
        Ok(full)
    }

    fn kill_group(&self, pgid: u32) {
        cowproof_prove::runner::signal_group(pgid, SIGKILL);
    }

    fn describe(&self) -> String {
        let launcher = if cfg!(target_os = "macos") {
            "sandbox-exec"
        } else {
            "bwrap"
        };
        format!("{launcher}, network denied")
    }
}
