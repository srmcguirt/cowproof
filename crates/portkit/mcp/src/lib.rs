//! Model Context Protocol server for portkit.
//!
//! Exposes a [`portkit_core::Registry`] over JSON-RPC 2.0 on stdio, which is
//! what Claude Code, Claude Desktop, and other MCP hosts speak.
//!
//! # The stdout rule
//!
//! On a stdio transport **stdout is the protocol channel**. A stray `println!`
//! injects a non-JSON line into the stream and the host drops the connection,
//! usually with an error that points nowhere near the print. All diagnostics
//! go to stderr via `tracing`; see [`serve_stdio`].

pub mod protocol;
pub mod server;

pub use protocol::{
    Content, Request, Response, ServerInfo, ToolCallResult, LATEST_PROTOCOL_VERSION,
    SUPPORTED_PROTOCOL_VERSIONS,
};
pub use server::McpServer;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tracing::{debug, info};

use portkit_core::Result;

/// Serve MCP over stdio until the client closes stdin.
///
/// Messages are newline-delimited JSON. Nothing but protocol frames is ever
/// written to stdout.
pub async fn serve_stdio(server: McpServer) -> Result<()> {
    info!(
        server = %server.info().name,
        tools = server.registry().len(),
        "serving MCP on stdio"
    );

    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let mut stdout = tokio::io::stdout();

    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }

        if let Some(response) = server.handle_line(&line).await {
            stdout.write_all(response.as_bytes()).await?;
            stdout.write_all(b"\n").await?;
            // Hosts block waiting on the reply; an unflushed buffer reads to
            // them as a hung server.
            stdout.flush().await?;
        }
    }

    debug!("stdin closed; shutting down");
    Ok(())
}
