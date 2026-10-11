//! The in-sandbox TCP-to-Unix bridge (D24).
//!
//! Every lane's egress proxy listens on a Unix socket, `<lane>/proxy.sock`,
//! on macOS and Linux alike. The builder's HTTP client cannot speak to a Unix
//! socket, and Linux's empty network namespace has no host loopback to reach
//! a host-wide TCP port, so a bridge runs INSIDE the builder sandbox: it
//! listens on `127.0.0.1:<port>` and copies bytes, both ways, to a fresh
//! connection on the proxy socket. The builder's `ANTHROPIC_BASE_URL` points
//! at that port.
//!
//! The bridge parses nothing and logs nothing: it never sees a header or a
//! body as anything but bytes, and it holds no credential.

use anyhow::{Context, Result, bail};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, UnixStream};
use tokio::sync::Semaphore;

/// The most connections the bridge relays at once. The 65th is closed at
/// accept, so a builder cannot exhaust the proxy's file descriptors.
pub const MAX_CONNECTIONS: usize = 64;

/// The first port of the bridge range.
const PORT_BASE: u16 = 40_000;
/// The number of ports in the range: 40000 up to, not including, the first port of the
/// lanes' port blocks (`cowproof_core::PORT_BASE`, 57000), so a bridge port is never inside
/// a lane's block. That is 40000 to 56999.
const PORT_SPAN: u64 = (cowproof_core::PORT_BASE - PORT_BASE) as u64;

/// The bridge port for a lane: `40000 + FNV-1a(lane id) % 17000`.
///
/// The hash is FNV-1a over the id's UTF-8 bytes, written out here rather than
/// taken from `DefaultHasher`, whose output may change between Rust versions:
/// a port recorded in `run.json` must still be the port the id maps to.
/// Distinct lanes can collide (about one pair in 17000); the second bridge
/// then fails to bind and its builder never starts, which is a safe failure.
pub fn bridge_port(lane_id: &str) -> u16 {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut hash = OFFSET;
    for byte in lane_id.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(PRIME);
    }
    PORT_BASE + (hash % PORT_SPAN) as u16
}

/// Bind the bridge's listener. The one place a bridge socket is created: it
/// is `127.0.0.1` and nothing else, so no other host on the network can reach
/// the proxy through it.
pub async fn bind_bridge(port: u16) -> Result<TcpListener> {
    TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
        .await
        .with_context(|| format!("binding the bridge to 127.0.0.1:{port}"))
}

/// Relay every connection on `listener` to `target`, a Unix socket, until the
/// task is dropped.
///
/// - Refuses a listener that is not bound to `127.0.0.1`.
/// - Opens a fresh `UnixStream` to `target` for each connection and copies
///   bytes both ways until both sides close.
/// - Relays at most [`MAX_CONNECTIONS`] at a time; any more are closed.
/// - Logs nothing: not an error, an address or a byte.
pub async fn serve_bridge(listener: TcpListener, target: PathBuf) -> Result<()> {
    let local = listener
        .local_addr()
        .context("reading the bridge listener's address")?;
    if local.ip() != IpAddr::V4(Ipv4Addr::LOCALHOST) {
        bail!(
            "the bridge must listen on 127.0.0.1 only, not {}",
            local.ip()
        );
    }
    let target = Arc::new(target);
    let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    loop {
        let (mut tcp, _) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(_) => {
                // A transient accept error (file descriptors exhausted, a
                // connection reset before accept) must not end the bridge.
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let Ok(slot) = slots.clone().try_acquire_owned() else {
            drop(tcp);
            continue;
        };
        let target = target.clone();
        tokio::spawn(async move {
            let _slot = slot;
            if let Ok(mut unix) = UnixStream::connect(target.as_path()).await {
                let _ = tokio::io::copy_bidirectional(&mut tcp, &mut unix).await;
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpStream, UnixListener};

    const WAIT: Duration = Duration::from_secs(10);

    /// A Unix server that greets each connection with `hello-from-server\n`
    /// and then echoes what it reads.
    fn greeting_echo_server(path: &Path) {
        let listener = UnixListener::bind(path).unwrap();
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    if socket.write_all(b"hello-from-server\n").await.is_err() {
                        return;
                    }
                    let mut buf = [0u8; 1024];
                    while let Ok(n) = socket.read(&mut buf).await {
                        if n == 0 || socket.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
    }

    /// A bridge on a loopback port to `target`; returns the port.
    async fn start_bridge(target: &Path) -> u16 {
        let listener = bind_bridge(0).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let target = target.to_path_buf();
        tokio::spawn(async move {
            let _ = serve_bridge(listener, target).await;
        });
        port
    }

    async fn read_exactly(stream: &mut TcpStream, n: usize) -> Vec<u8> {
        let mut buf = vec![0u8; n];
        tokio::time::timeout(WAIT, stream.read_exact(&mut buf))
            .await
            .expect("timed out reading through the bridge")
            .expect("reading through the bridge");
        buf
    }

    #[tokio::test]
    async fn the_relay_carries_bytes_in_both_directions() {
        let tmp = tempfile::tempdir().unwrap();
        let sock = tmp.path().join("echo.sock");
        greeting_echo_server(&sock);
        let port = start_bridge(&sock).await;

        let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        // Server to client: the greeting arrives with nothing sent.
        assert_eq!(read_exactly(&mut client, 18).await, b"hello-from-server\n");
        // Client to server and back: the echo proves both directions.
        client.write_all(b"ping-through-bridge").await.unwrap();
        assert_eq!(read_exactly(&mut client, 19).await, b"ping-through-bridge");
    }

    #[tokio::test]
    async fn the_65th_concurrent_connection_is_closed_and_a_freed_slot_is_reusable() {
        let tmp = tempfile::tempdir().unwrap();
        let sock = tmp.path().join("echo.sock");
        greeting_echo_server(&sock);
        let port = start_bridge(&sock).await;

        // 64 connections, each proven live by reading the server's greeting.
        let mut held = Vec::new();
        for _ in 0..MAX_CONNECTIONS {
            let mut c = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            assert_eq!(read_exactly(&mut c, 18).await, b"hello-from-server\n");
            held.push(c);
        }

        // The 65th is accepted by the OS and closed by the bridge: it reads
        // end of file (or a reset) and never sees a greeting.
        let mut extra = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let mut buf = [0u8; 18];
        let got = tokio::time::timeout(WAIT, extra.read(&mut buf))
            .await
            .expect("the 65th connection was neither served nor closed");
        assert!(
            matches!(got, Ok(0) | Err(_)),
            "the 65th connection was served: {got:?}"
        );

        // The first 64 still work.
        held[0].write_all(b"still-up").await.unwrap();
        assert_eq!(read_exactly(&mut held[0], 8).await, b"still-up");

        // Closing one frees its slot for a new connection.
        held.pop();
        let mut reused = None;
        for _ in 0..100 {
            let mut c = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            let mut greeting = [0u8; 18];
            if let Ok(Ok(18)) =
                tokio::time::timeout(Duration::from_millis(200), c.read(&mut greeting)).await
            {
                reused = Some(c);
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(reused.is_some(), "a freed slot was never reused");
    }

    #[tokio::test]
    async fn the_bridge_binds_loopback_and_refuses_to_serve_any_other_address() {
        let listener = bind_bridge(0).await.unwrap();
        assert_eq!(
            listener.local_addr().unwrap().ip(),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            "bind_bridge must bind 127.0.0.1"
        );

        let tmp = tempfile::tempdir().unwrap();
        let wide = TcpListener::bind("0.0.0.0:0").await.unwrap();
        let err = serve_bridge(wide, tmp.path().join("none.sock"))
            .await
            .expect_err("a 0.0.0.0 listener must be refused")
            .to_string();
        assert!(err.contains("127.0.0.1 only"), "{err}");
    }

    #[tokio::test]
    async fn an_unreachable_target_closes_the_connection() {
        let tmp = tempfile::tempdir().unwrap();
        let port = start_bridge(&tmp.path().join("missing.sock")).await;
        let mut c = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let mut buf = [0u8; 1];
        let got = tokio::time::timeout(WAIT, c.read(&mut buf))
            .await
            .expect("the connection was left open");
        assert!(matches!(got, Ok(0) | Err(_)), "{got:?}");
    }

    #[test]
    fn the_port_is_stable_for_a_lane_id_and_in_range() {
        // Known values from FNV-1a 64 (checked against an independent
        // implementation). A change of hash would fail here, which is the
        // point: ports recorded in earlier run.json files must stay valid.
        assert_eq!(bridge_port("t-run"), 51_003);
        assert_eq!(bridge_port("lane-1"), 46_765);
        assert_eq!(bridge_port(""), 48_037);
        for id in [
            "a",
            "b",
            "t-run",
            "a-much-longer-lane-identifier-0123456789",
        ] {
            let p = bridge_port(id);
            assert!((40_000..57_000).contains(&p), "{id}: {p}");
            assert_eq!(p, bridge_port(id));
        }
    }

    /// The bridge port never falls in the lanes' port blocks: the default 50 `port` slots
    /// are 57000 to 57999, and the bridge range ends below 57000 whatever the limit.
    #[test]
    fn the_bridge_port_is_never_in_a_port_block() {
        let (mut lowest, mut highest) = (u16::MAX, 0);
        for n in 0..10_000u32 {
            for id in [format!("lane-{n}"), format!("t-ver-{n}-{}", n * 7919)] {
                let p = bridge_port(&id);
                assert!(
                    !(57_000..58_000).contains(&p) && p < cowproof_core::PORT_BASE,
                    "{id}: {p}"
                );
                lowest = lowest.min(p);
                highest = highest.max(p);
            }
        }
        // The ids do spread over the range (the check above is not vacuous).
        assert!(lowest < 40_100 && highest > 56_900, "{lowest}..{highest}");
    }
}
