//! Behavior tests for the egress proxy (D4). Everything runs on loopback: a fake upstream that
//! counts requests and records headers, the proxy, and a raw-socket client. No internet.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use cowproof_run::proxy::{MetricsLog, ProxyConfig, ProxyServer, RequestMetrics};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UnixStream};

const REAL_KEY: &str = "real-upstream-key-SECRET-0123456789";
const JSON_BODY: &str = r#"{"id":"msg_1","usage":{"input_tokens":11,"output_tokens":22}}"#;
const REQUEST_BODY: &str = r#"{"model":"m","messages":[]}"#;

// ---------------------------------------------------------------- fake upstream

#[derive(Clone, Copy)]
enum Reply {
    /// 200 with a JSON body and a Content-Length.
    Json,
    /// 200 event-stream: head, then three chunks 300 ms apart.
    Sse,
}

#[derive(Clone, Debug)]
struct Seen {
    request_line: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Seen {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

struct Fake {
    addr: SocketAddr,
    seen: Arc<Mutex<Vec<Seen>>>,
    chunk3_sent: Arc<Mutex<Option<Instant>>>,
}

impl Fake {
    fn count(&self) -> usize {
        self.seen.lock().unwrap().len()
    }
    fn first(&self) -> Seen {
        self.seen.lock().unwrap()[0].clone()
    }
    fn base(&self) -> String {
        format!("http://{}", self.addr)
    }
}

async fn read_until_head_end<S: AsyncRead + Unpin>(stream: &mut S) -> Option<(String, Vec<u8>)> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") {
        if stream.read(&mut byte).await.ok()? == 0 {
            return None;
        }
        buf.push(byte[0]);
    }
    Some((String::from_utf8_lossy(&buf).into_owned(), buf))
}

async fn read_request_body<S: AsyncRead + Unpin>(
    stream: &mut S,
    headers: &[(String, String)],
) -> Vec<u8> {
    let find = |n: &str| headers.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    if let Some(len) = find("content-length").and_then(|v| v.parse::<usize>().ok()) {
        let mut body = vec![0u8; len];
        stream.read_exact(&mut body).await.unwrap();
        return body;
    }
    let mut body = Vec::new();
    if find("transfer-encoding").is_some_and(|v| v.contains("chunked")) {
        // Read until the terminating chunk; the tests never need the decoded body.
        let mut tail = Vec::new();
        let mut byte = [0u8; 1];
        while !tail.ends_with(b"0\r\n\r\n") {
            if stream.read(&mut byte).await.unwrap() == 0 {
                break;
            }
            tail.push(byte[0]);
        }
        body = tail;
    }
    body
}

async fn fake_upstream(reply: Reply) -> Fake {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let chunk3_sent = Arc::new(Mutex::new(None));
    let (seen_task, chunk3_task) = (Arc::clone(&seen), Arc::clone(&chunk3_sent));
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (seen, chunk3) = (Arc::clone(&seen_task), Arc::clone(&chunk3_task));
            tokio::spawn(async move {
                let Some((head, _)) = read_until_head_end(&mut stream).await else {
                    return;
                };
                let mut lines = head.split("\r\n");
                let request_line = lines.next().unwrap_or_default().to_string();
                let headers: Vec<(String, String)> = lines
                    .filter(|l| !l.is_empty())
                    .filter_map(|l| l.split_once(':'))
                    .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
                    .collect();
                let body = read_request_body(&mut stream, &headers).await;
                seen.lock().unwrap().push(Seen {
                    request_line,
                    headers,
                    body,
                });
                match reply {
                    Reply::Json => {
                        let response = format!(
                            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{JSON_BODY}",
                            JSON_BODY.len()
                        );
                        stream.write_all(response.as_bytes()).await.unwrap();
                    }
                    Reply::Sse => {
                        stream
                            .write_all(b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n")
                            .await
                            .unwrap();
                        for (i, event) in ["one", "two", "three"].iter().enumerate() {
                            if i > 0 {
                                tokio::time::sleep(Duration::from_millis(300)).await;
                            }
                            let data = format!("data: {event}\n\n");
                            if i == 2 {
                                *chunk3.lock().unwrap() = Some(Instant::now());
                            }
                            let chunk = format!("{:x}\r\n{data}\r\n", data.len());
                            if stream.write_all(chunk.as_bytes()).await.is_err() {
                                return;
                            }
                            let _ = stream.flush().await;
                        }
                        let _ = stream.write_all(b"0\r\n\r\n").await;
                    }
                }
                let _ = stream.shutdown().await;
            });
        }
    });
    Fake {
        addr,
        seen,
        chunk3_sent,
    }
}

// ---------------------------------------------------------------- proxy and client

struct Proxy {
    addr: SocketAddr,
    placeholder: String,
    metrics: MetricsLog,
}

async fn start_proxy(upstream_base: &str) -> Proxy {
    let config = ProxyConfig::new(REAL_KEY, upstream_base).unwrap();
    let placeholder = config.placeholder_key().to_string();
    let server = ProxyServer::new(config);
    let metrics = server.metrics();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(server.serve_tcp(listener));
    Proxy {
        addr,
        placeholder,
        metrics,
    }
}

fn request(method: &str, target: &str, headers: &[(&str, &str)], body: &str) -> Vec<u8> {
    let mut text = format!(
        "{method} {target} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (k, v) in headers {
        text.push_str(&format!("{k}: {v}\r\n"));
    }
    text.push_str("\r\n");
    text.push_str(body);
    text.into_bytes()
}

struct Resp {
    status: u16,
    head: String,
    body: String,
}

async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S, request: &[u8]) -> Resp {
    stream.write_all(request).await.unwrap();
    let mut raw = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut raw))
        .await
        .expect("response timed out")
        .unwrap();
    let text = String::from_utf8_lossy(&raw).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .expect("status line");
    Resp {
        status,
        head: head.to_string(),
        body: body.to_string(),
    }
}

async fn send(proxy: &Proxy, bytes: &[u8]) -> Resp {
    let mut stream = TcpStream::connect(proxy.addr).await.unwrap();
    exchange(&mut stream, bytes).await
}

async fn wait_for_metrics(log: &MetricsLog, count: usize) -> Vec<RequestMetrics> {
    for _ in 0..200 {
        let snapshot = log.snapshot();
        if snapshot.len() >= count {
            return snapshot;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("expected {count} metric records, got {:?}", log.snapshot());
}

// ---------------------------------------------------------------- tests

#[tokio::test]
async fn placeholder_key_passes_through_with_the_real_key() {
    let fake = fake_upstream(Reply::Json).await;
    let proxy = start_proxy(&fake.base()).await;
    let ph = proxy.placeholder.clone();
    let bearer = format!("Bearer {ph}");

    // The builder also sends an Authorization and a Proxy-Authorization header; both must go.
    let response = send(
        &proxy,
        &request(
            "POST",
            "/v1/messages?beta=true",
            &[
                ("x-api-key", &ph),
                ("authorization", &bearer),
                ("proxy-authorization", "Basic Zm9vOmJhcg=="),
                ("anthropic-version", "2023-06-01"),
                ("anthropic-beta", "tools-2024-04-04"),
                ("accept", "text/event-stream"),
                ("cookie", "session=builder"),
            ],
            REQUEST_BODY,
        ),
    )
    .await;

    assert_eq!(response.status, 200, "{}", response.head);
    assert_eq!(response.body, JSON_BODY);
    assert_eq!(fake.count(), 1);
    let seen = fake.first();
    assert_eq!(seen.request_line, "POST /v1/messages?beta=true HTTP/1.1");
    assert_eq!(seen.header("x-api-key"), Some(REAL_KEY));
    assert_eq!(seen.header("authorization"), None);
    assert_eq!(seen.header("proxy-authorization"), None);
    assert_eq!(seen.header("cookie"), None);
    assert_eq!(seen.header("anthropic-version"), Some("2023-06-01"));
    assert_eq!(seen.header("anthropic-beta"), Some("tools-2024-04-04"));
    assert_eq!(seen.header("content-type"), Some("application/json"));
    assert_eq!(seen.header("accept"), Some("text/event-stream"));
    assert_eq!(
        seen.header("host"),
        Some(fake.addr.to_string().as_str()),
        "host is set for the upstream"
    );
    assert_eq!(seen.body, REQUEST_BODY.as_bytes());
    for (name, value) in &seen.headers {
        assert!(!value.contains(&ph), "placeholder leaked in header {name}");
    }
    assert!(!response.head.contains(REAL_KEY) && !response.body.contains(REAL_KEY));
}

#[tokio::test]
async fn bearer_placeholder_and_count_tokens_pass_through() {
    let fake = fake_upstream(Reply::Json).await;
    let proxy = start_proxy(&fake.base()).await;
    let bearer = format!("Bearer {}", proxy.placeholder);
    let response = send(
        &proxy,
        &request(
            "POST",
            "/v1/messages/count_tokens",
            &[("authorization", &bearer)],
            REQUEST_BODY,
        ),
    )
    .await;
    assert_eq!(response.status, 200, "{}", response.head);
    let seen = fake.first();
    assert_eq!(seen.request_line, "POST /v1/messages/count_tokens HTTP/1.1");
    assert_eq!(seen.header("x-api-key"), Some(REAL_KEY));
    assert_eq!(seen.header("authorization"), None);
}

#[tokio::test]
async fn foreign_or_missing_credentials_are_refused_without_contacting_upstream() {
    let fake = fake_upstream(Reply::Json).await;
    let proxy = start_proxy(&fake.base()).await;
    let ph = proxy.placeholder.clone();
    let cases: Vec<(&str, Vec<(&str, String)>)> = vec![
        (
            "foreign x-api-key",
            vec![("x-api-key", "sk-ant-attacker".into())],
        ),
        (
            "foreign bearer",
            vec![("authorization", "Bearer sk-ant-attacker".into())],
        ),
        ("no credential", vec![]),
        (
            "placeholder beside a foreign key",
            vec![
                ("x-api-key", ph.clone()),
                ("authorization", "Bearer sk-ant-attacker".into()),
            ],
        ),
        (
            "only proxy-authorization",
            vec![("proxy-authorization", ph.clone())],
        ),
        (
            "placeholder as basic auth",
            vec![("authorization", format!("Basic {ph}"))],
        ),
    ];
    for (label, headers) in cases {
        let headers: Vec<(&str, &str)> = headers.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let response = send(
            &proxy,
            &request("POST", "/v1/messages", &headers, REQUEST_BODY),
        )
        .await;
        assert_eq!(response.status, 403, "{label}: {}", response.head);
        assert_eq!(fake.count(), 0, "{label}: upstream was contacted");
        assert!(!response.body.contains(REAL_KEY));
    }
}

#[tokio::test]
async fn other_paths_methods_connect_and_absolute_targets_are_refused() {
    let fake = fake_upstream(Reply::Json).await;
    let proxy = start_proxy(&fake.base()).await;
    let ph = proxy.placeholder.clone();
    let cred = [("x-api-key", ph.as_str())];

    let mut cases: Vec<(&str, Vec<u8>)> = vec![
        ("POST /v1/files", request("POST", "/v1/files", &cred, REQUEST_BODY)),
        ("GET /v1/messages", request("GET", "/v1/messages", &cred, "")),
        (
            "POST /v1/messages/batches",
            request("POST", "/v1/messages/batches", &cred, REQUEST_BODY),
        ),
        ("POST /v1/messages/", request("POST", "/v1/messages/", &cred, REQUEST_BODY)),
        ("POST //v1/messages", request("POST", "//v1/messages", &cred, REQUEST_BODY)),
        (
            "POST encoded path",
            request("POST", "/v1/%6dessages", &cred, REQUEST_BODY),
        ),
        ("PUT /v1/messages", request("PUT", "/v1/messages", &cred, REQUEST_BODY)),
        (
            "CONNECT",
            format!(
                "CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com:443\r\nConnection: close\r\nx-api-key: {ph}\r\n\r\n"
            )
            .into_bytes(),
        ),
    ];
    for target in [
        "http://evil.example/v1/messages",
        &format!("http://{}/v1/messages", fake.addr),
    ] {
        cases.push((
            "absolute-form target",
            request("POST", target, &cred, REQUEST_BODY),
        ));
    }
    for (label, bytes) in cases {
        let response = send(&proxy, &bytes).await;
        assert_eq!(response.status, 403, "{label}: {}", response.head);
        assert_eq!(fake.count(), 0, "{label}: upstream was contacted");
    }
}

#[tokio::test]
async fn responses_stream_instead_of_buffering() {
    let fake = fake_upstream(Reply::Sse).await;
    let proxy = start_proxy(&fake.base()).await;
    let mut stream = TcpStream::connect(proxy.addr).await.unwrap();
    let ph = proxy.placeholder.clone();
    stream
        .write_all(&request(
            "POST",
            "/v1/messages",
            &[("x-api-key", &ph), ("accept", "text/event-stream")],
            REQUEST_BODY,
        ))
        .await
        .unwrap();

    let mut received = Vec::new();
    let mut chunk = [0u8; 1024];
    let received_chunk1 = loop {
        let n = tokio::time::timeout(Duration::from_secs(10), stream.read(&mut chunk))
            .await
            .expect("no data")
            .unwrap();
        assert!(n > 0, "stream ended before the first event");
        received.extend_from_slice(&chunk[..n]);
        if String::from_utf8_lossy(&received).contains("data: one") {
            break Instant::now();
        }
    };
    // Read the rest so chunk 3 has been written and every event arrives in order.
    tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut received))
        .await
        .expect("stream did not finish")
        .unwrap();
    let text = String::from_utf8_lossy(&received);
    let (one, two, three) = (
        text.find("data: one").unwrap(),
        text.find("data: two").unwrap(),
        text.find("data: three").unwrap(),
    );
    assert!(one < two && two < three, "events out of order: {text}");

    let sent_chunk3 = fake
        .chunk3_sent
        .lock()
        .unwrap()
        .expect("chunk 3 was written");
    assert!(
        received_chunk1 < sent_chunk3,
        "the first event arrived {:?} after the upstream wrote the third: the proxy buffered",
        received_chunk1.duration_since(sent_chunk3)
    );
    assert!(
        sent_chunk3.duration_since(received_chunk1) > Duration::from_millis(200),
        "first event arrived too close to the third to show streaming"
    );
}

#[test]
fn debug_output_lacks_the_real_key() {
    let config = ProxyConfig::new(REAL_KEY, "http://127.0.0.1:1").unwrap();
    let shown = format!("{config:?}");
    assert!(!shown.contains(REAL_KEY), "{shown}");
    assert!(!shown.contains("real-upstream-key-SECRET"), "{shown}");
    assert!(shown.contains("<redacted>"));
}

#[tokio::test]
async fn upstream_connection_error_is_502_without_the_real_key() {
    // Bind and drop a listener to get a port nothing listens on.
    let dead = {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap()
    };
    let proxy = start_proxy(&format!("http://{dead}")).await;
    let ph = proxy.placeholder.clone();
    let response = send(
        &proxy,
        &request("POST", "/v1/messages", &[("x-api-key", &ph)], REQUEST_BODY),
    )
    .await;
    assert_eq!(response.status, 502, "{}", response.head);
    assert!(!response.head.contains(REAL_KEY));
    assert!(!response.body.contains(REAL_KEY));
    assert!(
        !response.body.contains(&dead.to_string()),
        "{}",
        response.body
    );
    let records = wait_for_metrics(&proxy.metrics, 1).await;
    assert_eq!(records[0].status, 502);
}

#[tokio::test]
async fn placeholder_passes_through_the_unix_socket() {
    let fake = fake_upstream(Reply::Json).await;
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("p.sock");
    let config = ProxyConfig::new(REAL_KEY, fake.base()).unwrap();
    let placeholder = config.placeholder_key().to_string();
    let server = ProxyServer::new(config);
    let path = socket.clone();
    tokio::spawn(server.listen_unix(path));
    for _ in 0..200 {
        if socket.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let mut stream = UnixStream::connect(&socket).await.unwrap();
    let response = exchange(
        &mut stream,
        &request(
            "POST",
            "/v1/messages",
            &[("authorization", &format!("Bearer {placeholder}"))],
            REQUEST_BODY,
        ),
    )
    .await;
    assert_eq!(response.status, 200, "{}", response.head);
    assert_eq!(response.body, JSON_BODY);
    assert_eq!(fake.count(), 1);
    assert_eq!(fake.first().header("x-api-key"), Some(REAL_KEY));
    assert_eq!(fake.first().header("authorization"), None);

    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "socket must not be reachable by other users");

    // A foreign key on the socket is refused as well.
    let mut stream = UnixStream::connect(&socket).await.unwrap();
    let refused = exchange(
        &mut stream,
        &request(
            "POST",
            "/v1/messages",
            &[("x-api-key", "other")],
            REQUEST_BODY,
        ),
    )
    .await;
    assert_eq!(refused.status, 403);
    assert_eq!(fake.count(), 1);
}

#[tokio::test]
async fn metrics_record_path_status_bytes_and_usage() {
    let fake = fake_upstream(Reply::Json).await;
    let proxy = start_proxy(&fake.base()).await;
    let ph = proxy.placeholder.clone();

    let allowed = send(
        &proxy,
        &request(
            "POST",
            "/v1/messages?beta=true",
            &[("x-api-key", &ph)],
            REQUEST_BODY,
        ),
    )
    .await;
    assert_eq!(allowed.status, 200);
    let rejected = send(
        &proxy,
        &request("POST", "/v1/files", &[("x-api-key", &ph)], REQUEST_BODY),
    )
    .await;
    assert_eq!(rejected.status, 403);

    let records = wait_for_metrics(&proxy.metrics, 2).await;
    let ok = records
        .iter()
        .find(|m| m.status == 200)
        .expect("allowed record");
    assert_eq!(ok.path, "/v1/messages", "the query string is not recorded");
    assert_eq!(ok.bytes_in, REQUEST_BODY.len() as u64);
    assert_eq!(ok.bytes_out, JSON_BODY.len() as u64);
    assert_eq!(ok.input_tokens, Some(11));
    assert_eq!(ok.output_tokens, Some(22));
    let no = records
        .iter()
        .find(|m| m.status == 403)
        .expect("rejected record");
    assert_eq!(no.path, "/v1/files");
    assert_eq!((no.bytes_in, no.bytes_out), (0, 0));
}

#[tokio::test]
async fn idle_timeout_upstream_stalls_after_first_chunk() {
    // Fake upstream that sends first chunk, then stalls for 3s
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let Some((head, _)) = read_until_head_end(&mut stream).await else {
                    return;
                };
                let mut lines = head.split("\r\n");
                let _request_line = lines.next().unwrap_or_default().to_string();
                let headers: Vec<(String, String)> = lines
                    .filter(|l| !l.is_empty())
                    .filter_map(|l| l.split_once(':'))
                    .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
                    .collect();
                let _body = read_request_body(&mut stream, &headers).await;

                // Send first chunk immediately
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n",
                    )
                    .await;
                let data = "data: first\n\n";
                let chunk = format!("{:x}\r\n{data}\r\n", data.len());
                let _ = stream.write_all(chunk.as_bytes()).await;
                let _ = stream.flush().await;

                // Stall for 3 seconds while the connection stays open
                tokio::time::sleep(Duration::from_secs(3)).await;
            });
        }
    });

    let config = ProxyConfig::new(REAL_KEY, format!("http://{}", upstream_addr))
        .unwrap()
        .with_idle_timeout(Duration::from_millis(300));
    let placeholder = config.placeholder_key().to_string();

    let server = ProxyServer::new(config);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    tokio::spawn(server.serve_tcp(listener));

    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
    stream
        .write_all(&request(
            "POST",
            "/v1/messages",
            &[("x-api-key", &placeholder)],
            REQUEST_BODY,
        ))
        .await
        .unwrap();

    let mut received = Vec::new();
    let mut chunk = [0u8; 1024];
    let first_chunk_time = loop {
        let n = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut chunk))
            .await
            .expect("no data within 2s")
            .unwrap();
        if n == 0 {
            break Instant::now();
        }
        received.extend_from_slice(&chunk[..n]);
        if String::from_utf8_lossy(&received).contains("data: first") {
            break Instant::now();
        }
    };

    let text = String::from_utf8_lossy(&received);
    assert!(
        text.contains("data: first"),
        "client received the first chunk"
    );

    // Continue reading until EOF or error
    let stream_end = loop {
        let n = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut chunk))
            .await
            .expect("stream read timed out")
            .unwrap();
        if n == 0 {
            break Instant::now();
        }
        received.extend_from_slice(&chunk[..n]);
    };

    // Stream should end between 250ms and 900ms after first chunk (300ms timeout with margin)
    let elapsed = stream_end.duration_since(first_chunk_time);
    assert!(
        elapsed >= Duration::from_millis(250) && elapsed < Duration::from_millis(900),
        "stream ended after idle timeout; elapsed: {:?}",
        elapsed
    );
}

#[tokio::test]
async fn idle_timeout_not_an_overall_limit() {
    // Fake upstream that sends 10 chunks 100ms apart (1s total, longer than 300ms idle limit)
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let seen_task = Arc::clone(&seen);
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let seen = Arc::clone(&seen_task);
            tokio::spawn(async move {
                let Some((head, _)) = read_until_head_end(&mut stream).await else {
                    return;
                };
                let mut lines = head.split("\r\n");
                let request_line = lines.next().unwrap_or_default().to_string();
                let headers: Vec<(String, String)> = lines
                    .filter(|l| !l.is_empty())
                    .filter_map(|l| l.split_once(':'))
                    .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
                    .collect();
                let _body = read_request_body(&mut stream, &headers).await;
                seen.lock().unwrap().push(Seen {
                    request_line,
                    headers,
                    body: Vec::new(),
                });

                // Send 10 chunks 100ms apart
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n"
                ).await;
                for i in 0..10 {
                    if i > 0 {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                    let data = format!("data: chunk{}\n\n", i);
                    let chunk = format!("{:x}\r\n{data}\r\n", data.len());
                    if stream.write_all(chunk.as_bytes()).await.is_err() {
                        return;
                    }
                    let _ = stream.flush().await;
                }
                let _ = stream.write_all(b"0\r\n\r\n").await;
            });
        }
    });

    let config = ProxyConfig::new(REAL_KEY, format!("http://{}", upstream_addr))
        .unwrap()
        .with_idle_timeout(Duration::from_millis(300));
    let placeholder = config.placeholder_key().to_string();

    let server = ProxyServer::new(config);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    tokio::spawn(server.serve_tcp(listener));

    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
    stream
        .write_all(&request(
            "POST",
            "/v1/messages",
            &[("x-api-key", &placeholder)],
            REQUEST_BODY,
        ))
        .await
        .unwrap();

    let mut received = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut received))
        .await
        .expect("response timed out")
        .expect("read failed");

    let text = String::from_utf8_lossy(&received);
    // Should receive all 10 chunks even though they arrive over 1 second
    for i in 0..10 {
        assert!(
            text.contains(&format!("data: chunk{}", i)),
            "missing chunk{}: {}",
            i,
            text
        );
    }
}

#[tokio::test]
async fn idle_timeout_client_stalls_mid_upload() {
    // Fake upstream that waits to read the full request body
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = listener.local_addr().unwrap();
    let upstream_error = Arc::new(Mutex::new(String::new()));
    let error_task = Arc::clone(&upstream_error);

    tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let error = Arc::clone(&error_task);
            tokio::spawn(async move {
                let Some((head, _)) = read_until_head_end(&mut stream).await else {
                    return;
                };
                let mut lines = head.split("\r\n");
                let _request_line = lines.next().unwrap_or_default();
                let headers: Vec<(String, String)> = lines
                    .filter(|l| !l.is_empty())
                    .filter_map(|l| l.split_once(':'))
                    .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
                    .collect();

                // Try to read the full request body; client will stall
                match read_request_body(&mut stream, &headers).await {
                    body if !body.is_empty() => {
                        // Got some body
                    }
                    _ => {
                        *error.lock().unwrap() = "body read error or incomplete".to_string();
                    }
                }
            });
        }
    });

    let config = ProxyConfig::new(REAL_KEY, format!("http://{}", upstream_addr))
        .unwrap()
        .with_idle_timeout(Duration::from_millis(300));
    let placeholder = config.placeholder_key().to_string();

    let server = ProxyServer::new(config);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    tokio::spawn(server.serve_tcp(listener));

    // Client sends headers with Content-Length but only partial body, then stalls
    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
    let request_text = format!(
        "POST /v1/messages HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: 1000\r\nx-api-key: {}\r\n\r\n",
        placeholder
    );
    stream.write_all(request_text.as_bytes()).await.unwrap();
    stream
        .write_all(b"incomplete_body_only_10bytes_")
        .await
        .unwrap();
    stream.flush().await.unwrap();

    // Wait for proxy to close the connection due to idle timeout
    let mut buf = [0u8; 1024];
    let start = Instant::now();
    let _n = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf))
        .await
        .expect("read timed out")
        .unwrap_or(0);

    let elapsed = Instant::now().duration_since(start);

    // Connection should be closed or return error within ~600ms (300ms timeout + margin)
    // The proxy may send an error response before closing
    assert!(
        elapsed < Duration::from_millis(600),
        "proxy should detect idle timeout within 600ms; elapsed: {:?}",
        elapsed
    );
}
