//! The `pk` command tree, shared by the `pk` binary and `cowproof pk`.

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

use portkit_core::{Config, Registry};
use portkit_plugin::{expand_home, register_layers};

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
