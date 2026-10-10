//! Shared newline-delimited JSON framing for builder tools and director control sockets.

use serde_json::{Value, json};
use std::io;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWriteExt};

/// The longest request line accepted, in bytes, not counting the newline.
pub const MAX_LINE: usize = 64 * 1024;

/// Drain settings after an over-long line.
pub const DRAIN_LIMIT: usize = 4 * 1024 * 1024;
pub const DRAIN_TIME: std::time::Duration = std::time::Duration::from_millis(500);

/// Result of reading a line from the stream.
pub enum Read {
    Eof,
    Line(Vec<u8>),
    TooLong,
}

/// Read one line of at most `cap` bytes (not counting the newline).
pub async fn read_line_capped<R: AsyncBufRead + Unpin>(r: &mut R, cap: usize) -> io::Result<Read> {
    let mut buf: Vec<u8> = Vec::new();
    loop {
        let chunk = r.fill_buf().await?;
        if chunk.is_empty() {
            // EOF: an unterminated final line still counts as a line.
            return Ok(if buf.is_empty() {
                Read::Eof
            } else {
                Read::Line(buf)
            });
        }
        match chunk.iter().position(|b| *b == b'\n') {
            Some(i) => {
                if buf.len() + i > cap {
                    r.consume(i + 1);
                    return Ok(Read::TooLong);
                }
                buf.extend_from_slice(&chunk[..i]);
                r.consume(i + 1);
                return Ok(Read::Line(buf));
            }
            None => {
                let n = chunk.len();
                if buf.len() + n > cap {
                    r.consume(n);
                    return Ok(Read::TooLong);
                }
                buf.extend_from_slice(chunk);
                r.consume(n);
            }
        }
    }
}

/// Send a JSON response over the wire.
pub async fn send<W: AsyncWriteExt + Unpin>(w: &mut W, response: &Value) -> io::Result<()> {
    let mut line = serde_json::to_vec(response).map_err(io::Error::other)?;
    line.push(b'\n');
    w.write_all(&line).await?;
    w.flush().await
}

/// Create a failure response.
pub fn failure(message: &str) -> Value {
    json!({ "ok": false, "error": message })
}
