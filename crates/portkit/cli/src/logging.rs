//! Logging setup.
//!
//! Everything goes to **stderr**. On an MCP stdio transport stdout carries the
//! protocol, and a single log line written there corrupts the stream and drops
//! the connection — with an error that points nowhere near the print.

use tracing_subscriber::EnvFilter;

pub fn init(default_filter: &str) {
    // `RUST_LOG` rather than a `PK_`-prefixed name: the config layer claims
    // the whole `PK_` namespace, and `PK_LOG` there means the `[log]` section.
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(default_filter))
        .unwrap_or_else(|_| EnvFilter::new("info"));

    // `try_init` rather than `init`: downstream binaries and tests may have
    // installed a subscriber already, and that should not be fatal.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(false)
        .try_init();
}
