//! The command surface. Turns a [`Registry`] into a complete CLI.
//!
//! Downstream binaries are a few lines:
//!
//! ```no_run
//! # use portkit_core::Registry;
//! #[tokio::main]
//! async fn main() -> std::process::ExitCode {
//!     portkit_cli::run(my_registry()).await
//! }
//! # fn my_registry() -> Registry { Registry::new() }
//! ```

mod commands;
mod doctor;
mod hook;
mod logging;
mod verify;

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};

use portkit_core::{Config, Registry};

/// Handle one Claude Code hook event from a payload already read, as
/// `pk hook <event>` does with stdin. For tests and embedders that drive the
/// hooks without a subprocess.
pub fn handle_hook(event: &str, payload: &str, config: &Config) {
    hook::handle(event, payload, config);
}

/// Parse arguments, run the requested command, and map the result to an exit code.
///
/// Errors are printed to stderr — stdout stays reserved for command output and
/// for the MCP protocol stream.
pub async fn run(registry: Registry) -> ExitCode {
    run_with(|_| registry).await
}

/// Build the registry from the effective config, then run.
///
/// Tools that depend on configuration — schema snapshots, index paths — cannot
/// be constructed before `--config` and `PK_*` have been resolved. Taking a
/// builder rather than a finished registry is what lets them exist at all,
/// and keeps argument parsing in one place.
pub async fn run_with<F>(build: F) -> ExitCode
where
    F: FnOnce(&Config) -> Registry,
{
    run_from(std::env::args_os(), build).await
}

/// Run with explicit arguments, for embedding in other binaries.
///
/// Parse arguments from the provided iterator and run the requested command.
/// The first argument should be argv[0] (the program name).
pub async fn run_from<I, T, F>(args: I, build: F) -> ExitCode
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
    F: FnOnce(&Config) -> Registry,
{
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(err) => {
            // Help and version are not failures: clap routes them to stdout
            // and exit code 0, and real usage errors to stderr and code 2.
            let _ = err.print();
            return ExitCode::from(u8::try_from(err.exit_code()).unwrap_or(2));
        }
    };

    let config = match Config::load(cli.config.as_deref()) {
        Ok(mut config) => {
            if let Some(level) = &cli.log_level {
                config.log.level = level.clone();
            }
            config
        }
        Err(err) => {
            eprintln!("error: {err}");
            return ExitCode::FAILURE;
        }
    };

    logging::init(&config.log.level);

    // Built here, after config: `tools/list` must already be grounded. Not for the commands
    // that never look at it: the process harness re-enters `pk` once per shimmed call, and a
    // plugin that is `pk port wrap` would otherwise discover itself, forever.
    let registry = if cli.command.needs_registry() {
        build(&config)
    } else {
        Registry::new()
    };

    match cli.command.execute(registry, &config).await {
        Ok(code) => code,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

#[derive(Parser, Debug)]
#[command(
    name = "pk",
    author,
    version,
    about = "Port tested Python agentic processes to Rust tooling — as a CLI, an MCP server, and a library.",
    long_about = None,
    propagate_version = true
)]
pub struct Cli {
    /// Config file to layer over the built-in defaults.
    #[arg(short, long, value_name = "FILE", global = true)]
    pub config: Option<PathBuf>,

    /// Log filter, e.g. `debug` or `pk=trace`. Logs always go to stderr.
    #[arg(
        short,
        long,
        value_name = "FILTER",
        global = true,
        env = "PK_LOG_LEVEL"
    )]
    pub log_level: Option<String>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// List the registered tools.
    Tools {
        /// Emit JSON instead of a table.
        #[arg(long)]
        json: bool,
    },

    /// Print a tool's JSON Schema.
    Schema {
        /// Tool name, as shown by `pk tools`.
        tool: String,
    },

    /// Call a tool directly.
    Run {
        /// Tool name, as shown by `pk tools`.
        tool: String,

        /// Arguments as a JSON file, or `-` to read stdin.
        #[arg(short, long, value_name = "FILE")]
        input: Option<PathBuf>,

        /// Inline argument as `key=value`. Values parse as JSON when they can,
        /// and stay strings when they cannot. Repeatable.
        #[arg(short = 'a', long = "arg", value_name = "KEY=VALUE")]
        args: Vec<String>,

        /// Print compact JSON rather than indented.
        #[arg(long)]
        compact: bool,

        /// Route the call through the MCP envelope, as an agent would.
        #[arg(long)]
        through_mcp: bool,

        /// Cap output at N bytes of JSON (~4 bytes/token). Overrides the
        /// tool's own budget and the config default.
        #[arg(long, value_name = "BYTES")]
        budget: Option<usize>,

        /// Print the whole result, however large.
        #[arg(long, conflicts_with = "budget")]
        full: bool,
    },

    /// Serve the tools over MCP on stdio.
    Serve {
        /// Transport. Only stdio is supported today.
        #[arg(long, value_enum, default_value_t = Transport::Stdio)]
        transport: Transport,
    },

    /// Capture reference fixtures and replay them against this port.
    Port {
        #[command(subcommand)]
        command: PortCommand,
    },

    /// Handle a Claude Code hook event. Reads the payload on stdin.
    Hook {
        /// One of: pre-tool-use, post-tool-use, user-prompt-submit,
        /// session-end, pre-compact, session-start.
        event: String,
    },

    /// Pair-run rewrite rules against the ledger and record the outcome.
    Verify {
        /// Manifest of rewrite rules.
        #[arg(
            short,
            long,
            value_name = "FILE",
            default_value = ".portkit/rewrites.json"
        )]
        manifest: PathBuf,

        /// How many recent ledger commands to replay.
        #[arg(short, long, default_value_t = 500)]
        window: usize,

        /// Record the results. Without it this is a dry run.
        #[arg(long)]
        apply: bool,
    },

    /// Summarize recorded tool-call costs.
    Trace {
        /// Directory of JSONL trace files. Defaults to the configured dir.
        #[arg(short, long, value_name = "DIR")]
        dir: Option<PathBuf>,

        /// Emit JSON instead of a table.
        #[arg(long)]
        json: bool,
    },

    /// Check whether this session is actually being watched.
    Doctor {
        /// Emit JSON instead of a table.
        #[arg(long)]
        json: bool,

        /// Settings file to check instead of searching the default locations.
        #[arg(long, value_name = "FILE")]
        settings: Option<PathBuf>,
    },

    /// Show the effective configuration after all layers are applied.
    Config,

    /// Generate a shell completion script.
    Completion {
        #[arg(value_enum)]
        shell: Shell,
    },
}

#[derive(Subcommand, Debug)]
pub enum PortCommand {
    /// Run cases through the reference implementation and record the results.
    Capture {
        /// Shell command running the reference. It receives
        /// `{"tool":…,"input":…}` on stdin and must print JSON on stdout.
        #[arg(short = 'C', long, value_name = "COMMAND")]
        cmd: String,

        /// JSONL file of cases, one `{"tool":…,"input":…}` per line.
        #[arg(long, value_name = "FILE", default_value = "cases.jsonl")]
        cases: PathBuf,

        /// Directory to write fixtures into.
        #[arg(short, long, value_name = "DIR", default_value = "fixtures")]
        out: PathBuf,

        /// Stop at the first case the reference fails on.
        #[arg(long)]
        fail_fast: bool,

        /// Directory the reference runs in. Default: where `pk` was started.
        #[arg(long, value_name = "DIR")]
        cwd: Option<PathBuf>,

        /// Set a variable for every case, `KEY=VALUE`. Repeatable. A case's own `env` wins.
        #[arg(long = "env", value_name = "KEY=VALUE")]
        env: Vec<String>,

        /// Start the reference from an empty environment (only `PATH` is kept) so a fixture
        /// does not depend on the capturing shell.
        #[arg(long)]
        clear_env: bool,
    },

    /// Capture a script (or any executable) as a whole process, in a sandbox with the network denied.
    ///
    /// Each case's `input` is `{argv, env, stdin, files, shims, record_env}`; its fixture
    /// holds `{exit, stdout, stderr, files_after, deleted, calls}`. The command is a shell
    /// fragment the case's `argv` is appended to; `$PORTKIT_SRC` is the directory the
    /// reference lives in (`--src`).
    Exec(ExecArgs),

    /// The Rust port's side of `exec`: run a binary in the same harness and answer the same
    /// envelope, as a plugin (`[[plugin]] command = "pk", args = ["port", "wrap", ...]`).
    Wrap(WrapArgs),

    /// Used by the PATH shims the process harness writes. Not for people.
    #[command(hide = true)]
    Shim {
        #[arg(long)]
        dir: PathBuf,
        #[arg(long)]
        state: PathBuf,
        #[arg(long)]
        program: String,
        #[arg(last = true)]
        args: Vec<String>,
    },

    /// Used by the harness to show the sandbox denies the network. Not for people.
    #[command(hide = true)]
    NetProbe { addr: String },

    /// Print or write the capture adapter for a reference language (node, typescript, python).
    ///
    /// The adapter is one standard-library-only file to commit beside the source module. A
    /// reference command is then `node adapter.mjs ./module.mjs` or
    /// `python3 adapter.py ./module.py`, optionally followed by a function name.
    Adapter {
        /// Language of the reference: `node`, `typescript` or `python`.
        #[arg(value_name = "LANG")]
        lang: String,

        /// Write the adapter to this file instead of printing it.
        #[arg(short, long, value_name = "FILE")]
        out: Option<PathBuf>,

        /// Replace `--out` when it already exists.
        #[arg(long, requires = "out")]
        force: bool,
    },

    /// Replay fixtures against the registry and report any drift.
    Replay {
        /// Directory holding the fixtures.
        #[arg(short, long, value_name = "DIR", default_value = "fixtures")]
        fixtures: PathBuf,

        /// Replay only this tool.
        #[arg(short, long, value_name = "TOOL")]
        tool: Option<String>,

        /// Which surface to call through.
        #[arg(long, value_enum, default_value_t = SurfaceArg::Both)]
        surface: SurfaceArg,

        /// Absolute float tolerance. Overrides `parity.epsilon` from config.
        #[arg(long, value_name = "EPS")]
        epsilon: Option<f64>,

        /// Emit the report as JSON.
        #[arg(long)]
        json: bool,
    },
}

/// Options shared by `port exec` and `port wrap`.
#[derive(clap::Args, Debug)]
pub struct HarnessArgs {
    /// Directory the reference lives in (`$PORTKIT_SRC`). Default: where `pk` was started.
    #[arg(long, value_name = "DIR")]
    pub src: Option<PathBuf>,

    /// Set a variable for every case, `KEY=VALUE`. Repeatable.
    #[arg(long = "env", value_name = "KEY=VALUE")]
    pub env: Vec<String>,

    /// Substitute a run's directory in the output: `$ROOT`, `$HOME`, `$TMP` or `$SRC`.
    /// Repeatable. Declared in a packet as `port.parity.path_roots`.
    #[arg(long = "path-root", value_name = "ROOT")]
    pub path_root: Vec<String>,

    /// The `PATH` after the shims.
    #[arg(long, value_name = "PATH", default_value = "/usr/bin:/bin")]
    pub path: String,

    /// How the run is confined: `auto` inherits inside a cowproof sandbox and otherwise uses
    /// cowproof's own; `own` always uses cowproof's; `inherited` trusts the caller's.
    #[arg(long, value_enum, default_value_t = SandboxArg::Auto)]
    pub sandbox: SandboxArg,

    /// Where work directories are made. Default: the system temp directory.
    #[arg(long, value_name = "DIR")]
    pub work_dir: Option<PathBuf>,

    /// The longest one run may take, in seconds.
    #[arg(long, value_name = "SECS")]
    pub timeout: Option<u64>,

    /// Keep the work directories (to look at what a run did).
    #[arg(long)]
    pub keep_work: bool,
}

#[derive(clap::Args, Debug)]
pub struct ExecArgs {
    /// Shell fragment running the reference; the case's `argv` is appended as `"$@"`.
    #[arg(short = 'C', long, value_name = "COMMAND")]
    pub cmd: String,

    /// JSONL file of cases, one `{"tool":…,"input":…}` per line.
    #[arg(long, value_name = "FILE", default_value = "cases.jsonl")]
    pub cases: PathBuf,

    /// Directory to write fixtures into.
    #[arg(short, long, value_name = "DIR", default_value = "fixtures")]
    pub out: PathBuf,

    /// Stop at the first case that fails.
    #[arg(long)]
    pub fail_fast: bool,

    /// How many times to run each case, in separate roots; a case whose runs differ is refused.
    #[arg(long, value_name = "N", default_value_t = 2)]
    pub repeat: usize,

    #[command(flatten)]
    pub harness: HarnessArgs,
}

#[derive(clap::Args, Debug)]
pub struct WrapArgs {
    /// The tool name this plugin answers.
    #[arg(long, value_name = "TOOL")]
    pub tool: String,

    /// The port's executable (relative paths are taken from where `pk` was started).
    #[arg(long, value_name = "FILE", conflicts_with = "cmd")]
    pub exe: Option<PathBuf>,

    /// A shell fragment running the port, as for `exec`.
    #[arg(short = 'C', long, value_name = "COMMAND")]
    pub cmd: Option<String>,

    /// Print the tool's spec and exit (the plugin discovery protocol).
    #[arg(long = "portkit-spec")]
    pub portkit_spec: bool,

    #[command(flatten)]
    pub harness: HarnessArgs,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum SandboxArg {
    /// Inherit inside a cowproof sandbox, else use cowproof's own.
    Auto,
    /// Always use cowproof's own sandbox.
    Own,
    /// The caller has sandboxed this process; the network probe checks it.
    Inherited,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    Stdio,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum SurfaceArg {
    /// Call the registry directly.
    Direct,
    /// Call through MCP `tools/call`.
    Mcp,
    /// Check both, which is what CI should do.
    Both,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shell {
    Bash,
    Zsh,
    Fish,
    Elvish,
    PowerShell,
}

impl Command {
    /// Whether the command reads the tool registry. The process harness commands do not.
    fn needs_registry(&self) -> bool {
        !matches!(
            self,
            Command::Port {
                command: PortCommand::Capture { .. }
                    | PortCommand::Exec(_)
                    | PortCommand::Wrap(_)
                    | PortCommand::Shim { .. }
                    | PortCommand::NetProbe { .. }
                    | PortCommand::Adapter { .. }
            }
        )
    }

    pub async fn execute(
        self,
        registry: Registry,
        config: &Config,
    ) -> portkit_core::Result<ExitCode> {
        match self {
            Command::Tools { json } => commands::tools(&registry, json),
            Command::Schema { tool } => commands::schema(&registry, &tool),
            Command::Run {
                tool,
                input,
                args,
                compact,
                through_mcp,
                budget,
                full,
            } => {
                commands::run_tool(
                    &registry,
                    config,
                    commands::RunArgs {
                        tool: &tool,
                        input,
                        args: &args,
                        compact,
                        through_mcp,
                        budget,
                        full,
                    },
                )
                .await
            }
            Command::Serve { transport } => commands::serve(registry, config, transport).await,
            Command::Port { command } => commands::port(&registry, config, command).await,
            Command::Hook { event } => Ok(hook::run(&event, config)),
            Command::Verify {
                manifest,
                window,
                apply,
            } => verify::run(config, &manifest, window, apply),
            Command::Trace { dir, json } => commands::trace(config, dir, json),
            Command::Doctor { json, settings } => doctor::run(config, json, settings),
            Command::Config => commands::show_config(config),
            Command::Completion { shell } => {
                commands::completion(shell);
                Ok(ExitCode::SUCCESS)
            }
        }
    }
}
