//! Behavior tests for the egress proxy (D4). Everything runs on loopback: a fake upstream that
//! counts requests and records headers, the proxy, and a raw-socket client. No internet.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use cowproof_run::proxy::{
    CallUsage, MetricsLog, Provider, ProxyConfig, ProxyServer, RequestMetrics,
};
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
    /// 200 event-stream of an OpenAI Responses call: a delta, then `response.completed` with
    /// usage, the completed event cut in two chunks in the middle of its JSON.
    Responses,
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
                    Reply::Responses => {
                        stream
                            .write_all(b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n")
                            .await
                            .unwrap();
                        let completed = r#"event: response.completed
data: {"type":"response.completed","response":{"id":"resp_1","usage":{"input_tokens":120,"input_tokens_details":{"cached_tokens":20},"output_tokens":30}}}

"#;
                        let (head, tail) = completed.split_at(completed.len() / 2);
                        for data in [
                            "event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\"}\n\n",
                            head,
                            tail,
                        ] {
                            let chunk = format!("{:x}\r\n{data}\r\n", data.len());
                            if stream.write_all(chunk.as_bytes()).await.is_err() {
                                return;
                            }
                            let _ = stream.flush().await;
                            tokio::time::sleep(Duration::from_millis(50)).await;
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
    const CHUNKS: usize = 21;
    // Fake upstream that sends 21 chunks 100ms apart: 2s in all, twice the 1s idle limit, while
    // each gap stays a tenth of it, so a slow runner cannot stretch a gap past the limit.
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

                // Send 21 chunks 100ms apart
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n"
                ).await;
                for i in 0..CHUNKS {
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
        .with_idle_timeout(Duration::from_secs(1));
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
    tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut received))
        .await
        .expect("response timed out")
        .expect("read failed");

    let text = String::from_utf8_lossy(&received);
    // Should receive every chunk although the stream outlasts the idle limit
    for i in 0..CHUNKS {
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

// ---------------------------------------------------------------- OpenRouter (D28 step 2)

const OR_KEY: &str = "real-openrouter-key-SECRET-9876543210";
const CHAT_PATH: &str = "/api/v1/chat/completions";

async fn start_openrouter_proxy(upstream_base: &str) -> Proxy {
    let config = ProxyConfig::for_provider(Provider::Openrouter, OR_KEY, upstream_base).unwrap();
    serve(config).await
}

async fn serve(config: ProxyConfig) -> Proxy {
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

#[tokio::test]
async fn openrouter_bearer_placeholder_is_swapped_for_the_real_bearer() {
    let fake = fake_upstream(Reply::Json).await;
    let proxy = start_openrouter_proxy(&fake.base()).await;
    let bearer = format!("Bearer {}", proxy.placeholder);
    // OpenCode's request: a Bearer, a user agent, its own session headers. The credential is
    // swapped; headers the allowlist does not name are dropped.
    let response = send(
        &proxy,
        &request(
            "POST",
            CHAT_PATH,
            &[
                ("authorization", &bearer),
                ("user-agent", "opencode/1.18.33"),
                ("x-session-id", "ses_x"),
                ("x-api-key", &proxy.placeholder),
                ("accept", "*/*"),
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
    assert_eq!(seen.request_line, format!("POST {CHAT_PATH} HTTP/1.1"));
    let want = format!("Bearer {OR_KEY}");
    assert_eq!(seen.header("authorization"), Some(want.as_str()));
    assert_eq!(
        seen.header("x-api-key"),
        None,
        "OpenRouter takes a Bearer only"
    );
    assert_eq!(seen.header("cookie"), None);
    assert_eq!(seen.header("x-session-id"), None);
    assert_eq!(seen.header("user-agent"), Some("opencode/1.18.33"));
    assert_eq!(seen.header("content-type"), Some("application/json"));
    assert_eq!(seen.header("host"), Some(fake.addr.to_string().as_str()));
    assert_eq!(seen.body, REQUEST_BODY.as_bytes());
    for (name, value) in &seen.headers {
        assert!(!value.contains(&proxy.placeholder), "placeholder in {name}");
    }
    assert!(!response.head.contains(OR_KEY) && !response.body.contains(OR_KEY));
}

#[tokio::test]
async fn an_openrouter_proxy_forwards_only_the_chat_completions_post() {
    let fake = fake_upstream(Reply::Json).await;
    let proxy = start_openrouter_proxy(&fake.base()).await;
    let bearer = format!("Bearer {}", proxy.placeholder);
    let auth: &[(&str, &str)] = &[("authorization", &bearer)];
    let cases = [
        (
            "anthropic path",
            request("POST", "/v1/messages", auth, REQUEST_BODY),
        ),
        ("models list", request("GET", "/api/v1/models", auth, "")),
        ("chat by GET", request("GET", CHAT_PATH, auth, "")),
        ("chat by PUT", request("PUT", CHAT_PATH, auth, REQUEST_BODY)),
        (
            "other path",
            request("POST", "/api/v1/credits", auth, REQUEST_BODY),
        ),
        (
            "path prefix trick",
            request(
                "POST",
                "/api/v1/chat/completions/../keys",
                auth,
                REQUEST_BODY,
            ),
        ),
        (
            "absolute-form target",
            request(
                "POST",
                &format!("http://evil.example{CHAT_PATH}"),
                auth,
                REQUEST_BODY,
            ),
        ),
        (
            "foreign bearer",
            request(
                "POST",
                CHAT_PATH,
                &[("authorization", "Bearer attacker-openrouter-key")],
                REQUEST_BODY,
            ),
        ),
        (
            "no credential",
            request("POST", CHAT_PATH, &[], REQUEST_BODY),
        ),
    ];
    for (name, bytes) in cases {
        let response = send(&proxy, &bytes).await;
        assert_eq!(response.status, 403, "{name}: {}", response.head);
    }
    assert_eq!(fake.count(), 0, "nothing reached the upstream");
}

#[tokio::test]
async fn an_anthropic_proxy_refuses_the_openrouter_path_and_the_reverse() {
    let fake = fake_upstream(Reply::Json).await;
    let proxy = start_proxy(&fake.base()).await;
    let bearer = format!("Bearer {}", proxy.placeholder);
    let response = send(
        &proxy,
        &request(
            "POST",
            CHAT_PATH,
            &[("authorization", &bearer)],
            REQUEST_BODY,
        ),
    )
    .await;
    assert_eq!(response.status, 403);
    assert_eq!(fake.count(), 0);

    let proxy = start_openrouter_proxy(&fake.base()).await;
    let response = send(
        &proxy,
        &request(
            "POST",
            "/v1/messages",
            &[("x-api-key", &proxy.placeholder)],
            REQUEST_BODY,
        ),
    )
    .await;
    assert_eq!(response.status, 403);
    assert_eq!(fake.count(), 0);
}

#[tokio::test]
async fn one_proxy_serves_both_providers_each_with_its_own_key_and_upstream() {
    let anthropic = fake_upstream(Reply::Json).await;
    let openrouter = fake_upstream(Reply::Json).await;
    let config = ProxyConfig::new(REAL_KEY, anthropic.base())
        .unwrap()
        .with_provider(Provider::Openrouter, OR_KEY, openrouter.base())
        .unwrap();
    let proxy = serve(config).await;
    let ph = proxy.placeholder.clone();
    let bearer = format!("Bearer {ph}");

    let one = send(
        &proxy,
        &request("POST", "/v1/messages", &[("x-api-key", &ph)], REQUEST_BODY),
    )
    .await;
    let two = send(
        &proxy,
        &request(
            "POST",
            CHAT_PATH,
            &[("authorization", &bearer)],
            REQUEST_BODY,
        ),
    )
    .await;
    assert_eq!((one.status, two.status), (200, 200));

    assert_eq!((anthropic.count(), openrouter.count()), (1, 1));
    let a = anthropic.first();
    assert_eq!(a.header("x-api-key"), Some(REAL_KEY));
    assert_eq!(a.header("authorization"), None);
    let o = openrouter.first();
    let want = format!("Bearer {OR_KEY}");
    assert_eq!(o.header("authorization"), Some(want.as_str()));
    assert_eq!(o.header("x-api-key"), None);
    // Neither upstream ever saw the other's key.
    for (seen, other) in [(&a, OR_KEY), (&o, REAL_KEY)] {
        for (name, value) in &seen.headers {
            assert!(!value.contains(other), "{name}");
        }
    }
    let metrics = wait_for_metrics(&proxy.metrics, 2).await;
    let paths: Vec<&str> = metrics.iter().map(|m| m.path.as_str()).collect();
    assert!(
        paths.contains(&"/v1/messages") && paths.contains(&CHAT_PATH),
        "{paths:?}"
    );
}

#[tokio::test]
async fn an_openrouter_stream_is_relayed_as_it_arrives() {
    let fake = fake_upstream(Reply::Sse).await;
    let proxy = start_openrouter_proxy(&fake.base()).await;
    let bearer = format!("Bearer {}", proxy.placeholder);
    let mut stream = TcpStream::connect(proxy.addr).await.unwrap();
    stream
        .write_all(&request(
            "POST",
            CHAT_PATH,
            &[("authorization", &bearer), ("accept", "text/event-stream")],
            REQUEST_BODY,
        ))
        .await
        .unwrap();
    let start = Instant::now();
    let mut raw = Vec::new();
    let mut first_event_at = None;
    let mut buf = [0u8; 1024];
    while first_event_at.is_none() || !raw.ends_with(b"0\r\n\r\n") {
        let n = tokio::time::timeout(Duration::from_secs(10), stream.read(&mut buf))
            .await
            .expect("stream timed out")
            .unwrap();
        if n == 0 {
            break;
        }
        raw.extend_from_slice(&buf[..n]);
        if first_event_at.is_none() && String::from_utf8_lossy(&raw).contains("data: one") {
            first_event_at = Some(start.elapsed());
        }
    }
    let first = first_event_at.expect("the first event arrived");
    assert!(
        first < Duration::from_millis(250),
        "the first event waited for the rest: {first:?}"
    );
    assert!(String::from_utf8_lossy(&raw).contains("data: three"));
}

// ---------------------------------------------------------------- OpenAI (D28 step 3)

const OA_KEY: &str = "real-openai-key-SECRET-5555555555";
const RESPONSES_PATH: &str = "/v1/responses";

#[tokio::test]
async fn openai_bearer_placeholder_is_swapped_for_the_real_bearer() {
    let fake = fake_upstream(Reply::Json).await;
    let proxy =
        serve(ProxyConfig::for_provider(Provider::Openai, OA_KEY, fake.base()).unwrap()).await;
    let bearer = format!("Bearer {}", proxy.placeholder);
    // Codex's request: a Bearer, the identifiers it adds to every call, a user agent.
    let response = send(
        &proxy,
        &request(
            "POST",
            RESPONSES_PATH,
            &[
                ("authorization", &bearer),
                ("user-agent", "codex_exec/0.157.0"),
                ("session-id", "01a12d9c-b587-7d70-b3bc-ec3bd1cb4130"),
                ("x-codex-turn-metadata", "{\"installation_id\":\"i\"}"),
                ("originator", "codex_exec"),
                ("accept", "text/event-stream"),
            ],
            REQUEST_BODY,
        ),
    )
    .await;
    assert_eq!(response.status, 200, "{}", response.head);
    assert_eq!(fake.count(), 1);
    let seen = fake.first();
    assert_eq!(seen.request_line, format!("POST {RESPONSES_PATH} HTTP/1.1"));
    let want = format!("Bearer {OA_KEY}");
    assert_eq!(seen.header("authorization"), Some(want.as_str()));
    // The identifiers Codex adds are not the API's business: they stay in the lane.
    for dropped in [
        "session-id",
        "x-codex-turn-metadata",
        "originator",
        "x-api-key",
    ] {
        assert_eq!(seen.header(dropped), None, "{dropped}");
    }
    assert_eq!(seen.header("user-agent"), Some("codex_exec/0.157.0"));
    assert_eq!(seen.header("host"), Some(fake.addr.to_string().as_str()));
    assert_eq!(seen.body, REQUEST_BODY.as_bytes());
    for (name, value) in &seen.headers {
        assert!(!value.contains(&proxy.placeholder), "placeholder in {name}");
    }
    assert!(!response.head.contains(OA_KEY) && !response.body.contains(OA_KEY));
}

#[tokio::test]
async fn an_openai_proxy_forwards_only_the_responses_post() {
    let fake = fake_upstream(Reply::Json).await;
    let proxy =
        serve(ProxyConfig::for_provider(Provider::Openai, OA_KEY, fake.base()).unwrap()).await;
    let bearer = format!("Bearer {}", proxy.placeholder);
    let auth: &[(&str, &str)] = &[("authorization", &bearer)];
    let cases = [
        (
            "anthropic path",
            request("POST", "/v1/messages", auth, REQUEST_BODY),
        ),
        (
            "openrouter path",
            request("POST", CHAT_PATH, auth, REQUEST_BODY),
        ),
        (
            "chat completions",
            request("POST", "/v1/chat/completions", auth, REQUEST_BODY),
        ),
        ("model list", request("GET", "/v1/models", auth, "")),
        (
            "compact",
            request("POST", "/v1/responses/compact", auth, REQUEST_BODY),
        ),
        ("responses by GET", request("GET", RESPONSES_PATH, auth, "")),
        (
            "responses by PUT",
            request("PUT", RESPONSES_PATH, auth, REQUEST_BODY),
        ),
        (
            "chatgpt backend",
            request("POST", "/backend-api/codex/responses", auth, REQUEST_BODY),
        ),
        (
            "path prefix trick",
            request("POST", "/v1/responses/../files", auth, REQUEST_BODY),
        ),
        (
            "absolute-form target",
            request(
                "POST",
                &format!("http://evil.example{RESPONSES_PATH}"),
                auth,
                REQUEST_BODY,
            ),
        ),
        (
            "foreign bearer",
            request(
                "POST",
                RESPONSES_PATH,
                &[("authorization", "Bearer attacker-openai-key")],
                REQUEST_BODY,
            ),
        ),
        (
            "no credential",
            request("POST", RESPONSES_PATH, &[], REQUEST_BODY),
        ),
    ];
    for (name, bytes) in cases {
        let response = send(&proxy, &bytes).await;
        assert_eq!(response.status, 403, "{name}: {}", response.head);
    }
    assert_eq!(fake.count(), 0, "nothing reached the upstream");
    // And the other providers' proxies do not serve the Responses path.
    let anthropic = start_proxy(&fake.base()).await;
    let bearer = format!("Bearer {}", anthropic.placeholder);
    let response = send(
        &anthropic,
        &request(
            "POST",
            RESPONSES_PATH,
            &[("authorization", &bearer)],
            REQUEST_BODY,
        ),
    )
    .await;
    assert_eq!(response.status, 403, "{}", response.head);
    assert_eq!(fake.count(), 0);
}

#[tokio::test]
async fn a_responses_stream_reports_each_calls_usage_to_the_log_as_it_passes() {
    let fake = fake_upstream(Reply::Responses).await;
    let proxy =
        serve(ProxyConfig::for_provider(Provider::Openai, OA_KEY, fake.base()).unwrap()).await;
    let bearer = format!("Bearer {}", proxy.placeholder);
    let call = || {
        request(
            "POST",
            RESPONSES_PATH,
            &[("authorization", &bearer)],
            REQUEST_BODY,
        )
    };
    assert_eq!(proxy.metrics.usage_recorded(), 0);
    let response = send(&proxy, &call()).await;
    assert_eq!(response.status, 200, "{}", response.head);
    assert!(
        response.body.contains("response.completed"),
        "the stream is relayed whole"
    );
    let first = CallUsage {
        input: 120,
        cached_input: 20,
        output: 30,
    };
    assert_eq!(proxy.metrics.usage_since(0), [first]);
    // The request's own record carries the same figures.
    let records = wait_for_metrics(&proxy.metrics, 1).await;
    assert_eq!(records[0].path, RESPONSES_PATH);
    assert_eq!(
        (
            records[0].input_tokens,
            records[0].cached_input_tokens,
            records[0].output_tokens
        ),
        (Some(120), Some(20), Some(30))
    );
    // A second call is a second entry, and a launch that began after the first sees only it.
    let _ = send(&proxy, &call()).await;
    assert_eq!(proxy.metrics.usage_recorded(), 2);
    assert_eq!(proxy.metrics.usage_since(1), [first]);
    assert_eq!(proxy.metrics.usage_since(2), []);
}

#[tokio::test]
async fn only_the_openai_route_reads_usage_from_a_stream() {
    // The same event-stream through an OpenRouter proxy is relayed and nothing is read from it.
    let fake = fake_upstream(Reply::Responses).await;
    let proxy = start_openrouter_proxy(&fake.base()).await;
    let bearer = format!("Bearer {}", proxy.placeholder);
    let response = send(
        &proxy,
        &request(
            "POST",
            CHAT_PATH,
            &[("authorization", &bearer)],
            REQUEST_BODY,
        ),
    )
    .await;
    assert_eq!(response.status, 200);
    assert_eq!(proxy.metrics.usage_recorded(), 0);
}

#[tokio::test]
async fn an_openai_proxy_with_a_model_limit_forwards_only_requests_for_those_models() {
    let fake = fake_upstream(Reply::Json).await;
    let config = ProxyConfig::for_provider(Provider::Openai, OA_KEY, fake.base())
        .unwrap()
        .with_models(Provider::Openai, ["gpt-6-luna".to_string()])
        .unwrap();
    let proxy = serve(config).await;
    let bearer = format!("Bearer {}", proxy.placeholder);
    let call = |body: &str| request("POST", RESPONSES_PATH, &[("authorization", &bearer)], body);

    // The lane's model passes, and the body arrives whole and unchanged.
    let body = r#"{"model":"gpt-6-luna","input":[{"role":"user","content":"hi"}],"stream":true}"#;
    let response = send(&proxy, &call(body)).await;
    assert_eq!(response.status, 200, "{}", response.head);
    assert_eq!(fake.count(), 1);
    let seen = fake.first();
    assert_eq!(seen.body, body.as_bytes());
    assert_eq!(
        seen.header("content-length"),
        Some(body.len().to_string().as_str())
    );
    let records = wait_for_metrics(&proxy.metrics, 1).await;
    assert_eq!(records[0].bytes_in, body.len() as u64);

    // Another model (a sub-agent Codex started on a dearer one), a body with two models, one
    // with none, and bytes that are not JSON are all refused before the upstream is touched.
    for (name, refused) in [
        ("another model", r#"{"model":"gpt-6-astra","input":[]}"#),
        (
            "two models",
            r#"{"model":"gpt-6-luna","input":[],"model":"gpt-6-astra"}"#,
        ),
        ("no model", r#"{"input":[]}"#),
        ("a model that is not a string", r#"{"model":7}"#),
        ("not JSON", "model=gpt-6-luna"),
        ("an empty body", ""),
    ] {
        let response = send(&proxy, &call(refused)).await;
        assert_eq!(response.status, 403, "{name}: {}", response.head);
    }
    assert_eq!(fake.count(), 1, "nothing else reached the upstream");
    let records = wait_for_metrics(&proxy.metrics, 7).await;
    assert_eq!(records.iter().filter(|r| r.status == 403).count(), 6);
}

#[tokio::test]
async fn a_model_limit_does_not_touch_the_other_providers() {
    let fake = fake_upstream(Reply::Json).await;
    let config = ProxyConfig::new(REAL_KEY, fake.base())
        .unwrap()
        .with_provider(Provider::Openai, OA_KEY, fake.base())
        .unwrap()
        .with_models(Provider::Openai, ["gpt-6-luna".to_string()])
        .unwrap();
    let proxy = serve(config).await;
    // Claude's request names a model the OpenAI limit would refuse; it is not subject to it.
    let response = send(
        &proxy,
        &request(
            "POST",
            "/v1/messages",
            &[("x-api-key", &proxy.placeholder)],
            r#"{"model":"claude-haiku","messages":[]}"#,
        ),
    )
    .await;
    assert_eq!(response.status, 200, "{}", response.head);
    assert_eq!(fake.count(), 1);
}

// ---------------------------------------------------------------- subscription route (D2)

/// A lettered synthetic OAuth token, built at run time so the source holds no key-shaped string.
fn real_token() -> String {
    format!("sk-ant-oat01-{}", "abcdefghij".repeat(4))
}

async fn start_subscription_proxy(upstream_base: &str) -> Proxy {
    let config = ProxyConfig::for_subscription(real_token(), upstream_base).unwrap();
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

#[tokio::test]
async fn the_subscription_route_swaps_the_bearer_and_forwards_the_oauth_beta_flag() {
    let fake = fake_upstream(Reply::Json).await;
    let proxy = start_subscription_proxy(&fake.base()).await;
    let real = real_token();
    let bearer = format!("Bearer {}", proxy.placeholder);
    // What Claude Code 2.1.296 sends with CLAUDE_CODE_OAUTH_TOKEN (measured): a bearer, the
    // OAuth beta flag among the betas, and the usual Anthropic headers.
    let response = send(
        &proxy,
        &request(
            "POST",
            "/v1/messages?beta=true",
            &[
                ("authorization", &bearer),
                ("anthropic-version", "2023-06-01"),
                (
                    "anthropic-beta",
                    "claude-code-20250219,oauth-2025-04-20,interleaved-thinking-2025-05-14",
                ),
                ("x-app", "cli"),
                ("proxy-authorization", "Basic Zm9vOmJhcg=="),
            ],
            REQUEST_BODY,
        ),
    )
    .await;
    assert_eq!(response.status, 200, "{}", response.head);
    assert_eq!(fake.count(), 1);
    let seen = fake.first();
    assert_eq!(seen.request_line, "POST /v1/messages?beta=true HTTP/1.1");
    // The real token is the bearer; the placeholder never leaves; no API-key header exists.
    let want = format!("Bearer {real}");
    assert_eq!(seen.header("authorization"), Some(want.as_str()));
    assert_eq!(seen.header("x-api-key"), None);
    assert_eq!(seen.header("proxy-authorization"), None);
    assert_eq!(
        seen.header("anthropic-beta"),
        Some("claude-code-20250219,oauth-2025-04-20,interleaved-thinking-2025-05-14")
    );
    assert_eq!(seen.header("x-app"), Some("cli"));
    for (name, value) in &seen.headers {
        assert!(
            !value.contains(&proxy.placeholder),
            "placeholder leaked in header {name}"
        );
    }
    assert!(!response.head.contains(&real) && !response.body.contains(&real));
    // The response relays untouched, and the usage is read as for an API-key route.
    assert_eq!(response.body, JSON_BODY);
}

#[tokio::test]
async fn the_subscription_route_refuses_any_x_api_key_and_any_foreign_bearer() {
    let fake = fake_upstream(Reply::Json).await;
    let proxy = start_subscription_proxy(&fake.base()).await;
    let ph = proxy.placeholder.clone();
    let bearer = format!("Bearer {ph}");
    let cases: Vec<(&str, Vec<(&str, String)>)> = vec![
        // Claude Code prefers an API key to the token, so a lane that held one would bill it:
        // the proxy refuses the request even when the key is the placeholder.
        ("placeholder in x-api-key", vec![("x-api-key", ph.clone())]),
        (
            "x-api-key beside the bearer",
            vec![("x-api-key", ph.clone()), ("authorization", bearer.clone())],
        ),
        (
            "foreign bearer",
            vec![("authorization", "Bearer sk-ant-attacker".into())],
        ),
        ("no credential", vec![]),
    ];
    for (name, headers) in cases {
        let pairs: Vec<(&str, &str)> = headers.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let response = send(
            &proxy,
            &request("POST", "/v1/messages", &pairs, REQUEST_BODY),
        )
        .await;
        assert_eq!(response.status, 403, "{name}: {}", response.head);
        assert!(!response.body.contains(&real_token()));
    }
    assert_eq!(fake.count(), 0, "the upstream must not be contacted");
}

#[test]
fn the_subscription_config_redacts_the_token_and_refuses_an_empty_one() {
    let config = ProxyConfig::for_subscription(real_token(), "http://127.0.0.1:9").unwrap();
    let shown = format!("{config:?}");
    assert!(!shown.contains(&real_token()), "{shown}");
    let err = ProxyConfig::for_subscription("", "http://127.0.0.1:9").unwrap_err();
    assert!(!format!("{err:#}").contains(&real_token()));
    let err = ProxyConfig::for_subscription("bad\nvalue", "http://127.0.0.1:9").unwrap_err();
    assert!(!format!("{err:#}").contains("bad"), "{err:#}");
}
