//! Egress proxy for sandboxed builders (D4): an HTTP/1.1 reverse proxy that holds the real API
//! credential outside the sandbox.
//!
//! The runner starts this proxy outside the sandbox. The sandbox policy
//! (`NetworkMode::Proxy`) lets the builder reach only the proxy's loopback port or Unix socket.
//! The builder sets `ANTHROPIC_BASE_URL` to the proxy and uses the per-lane placeholder key.
//!
//! What the proxy enforces (design.md, "Trust boundaries": Network and Credentials):
//! - It forwards only `POST /v1/messages` and `POST /v1/messages/count_tokens` (a query string is
//!   allowed). Every other path, method, `CONNECT` and absolute-form request target gets 403 and
//!   the upstream is never contacted.
//! - Every credential on the request (`x-api-key`, `Authorization: Bearer`) must be the lane's
//!   placeholder, and there must be at least one. Otherwise 403.
//! - Incoming `x-api-key`, `authorization` and `proxy-authorization` are never forwarded; the proxy
//!   sets `x-api-key` to the real key. Headers are forwarded by allowlist (see [`forward_header`]),
//!   so a builder cannot add arbitrary headers to the upstream request.
//! - The upstream host comes only from [`ProxyConfig`]; nothing in a request can change it.
//! - Request and response bodies stream in both directions. The response body is never collected
//!   before it is sent, so server-sent events reach the builder as they are produced.
//! - The real key is held as a sensitive header value, redacted in `Debug`, and appears in no
//!   error text, log line or response body.
//!
//! Limits and gaps, stated so nobody assumes more than is there: there is no overall timeout on a
//! response (a long stream is legitimate), only on connecting and on reading request headers; the
//! `https` upstream path (webpki roots) is built but has no test, because the tests have no
//! internet and no trusted local CA.

use std::collections::VecDeque;
use std::convert::Infallible;
use std::fmt;
use std::io::ErrorKind;
use std::path::Path;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail};
use bytes::Bytes;
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::{Body, Frame, Incoming, SizeHint};
use hyper::header::{self, HeaderMap, HeaderName, HeaderValue};
use hyper::http::uri::{Authority, Scheme};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, Uri, Version};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, UnixListener};
use tokio::sync::Semaphore;

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type ProxyBody = UnsyncBoxBody<Bytes, BoxError>;
type UpstreamClient = Client<HttpsConnector<HttpConnector>, ProxyBody>;

/// The only paths that are forwarded, always with `POST`.
const ALLOWED_PATHS: [&str; 2] = ["/v1/messages", "/v1/messages/count_tokens"];
/// Largest request body the proxy streams to the upstream.
const MAX_REQUEST_BYTES: u64 = 64 * 1024 * 1024;
/// Most response bytes copied aside to read `usage` from a non-streaming JSON response.
const MAX_USAGE_CAPTURE_BYTES: usize = 1024 * 1024;
/// Most metric records kept; the oldest are dropped first.
const MAX_METRICS: usize = 10_000;
/// Longest path stored in a metric record.
const MAX_METRIC_PATH: usize = 200;
/// Most connections served at once.
const MAX_CONNECTIONS: usize = 256;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(120);

/// Configuration for the proxy.
pub struct ProxyConfig {
    /// The real API key, as a sensitive header value. Never sent to the builder.
    real_api_key: HeaderValue,
    /// The upstream base URL as given (for display only).
    upstream_base: String,
    upstream: Upstream,
    /// Per-lane placeholder the builder must present.
    placeholder_key: String,
    /// Longest gap allowed between chunks while streaming a body in either direction.
    idle_timeout: Duration,
}

impl ProxyConfig {
    /// Create a configuration with a freshly generated placeholder key.
    ///
    /// `upstream_base` is an `http` or `https` URL such as `https://api.anthropic.com`. It may
    /// carry a path prefix but no user info, query or fragment. Errors never contain the key.
    pub fn new(real_api_key: impl Into<String>, upstream_base: impl Into<String>) -> Result<Self> {
        let real_api_key = real_api_key.into();
        let upstream_base = upstream_base.into();
        if real_api_key.is_empty() {
            bail!("the real API key is empty");
        }
        let mut real_api_key = HeaderValue::from_str(&real_api_key)
            .map_err(|_| anyhow::anyhow!("the real API key is not a valid header value"))?;
        real_api_key.set_sensitive(true);
        let upstream = Upstream::parse(&upstream_base)?;
        Ok(Self {
            real_api_key,
            upstream_base,
            upstream,
            placeholder_key: format!("placeholder-{}", uuid::Uuid::new_v4()),
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
        })
    }

    /// Set the idle timeout (longest gap between chunks while streaming).
    pub fn with_idle_timeout(mut self, timeout: Duration) -> Self {
        self.idle_timeout = timeout;
        self
    }

    /// The placeholder key (safe to give to the builder).
    pub fn placeholder_key(&self) -> &str {
        &self.placeholder_key
    }

    /// The upstream base URL.
    pub fn upstream_base(&self) -> &str {
        &self.upstream_base
    }

    /// The idle timeout.
    fn idle_timeout(&self) -> Duration {
        self.idle_timeout
    }
}

impl fmt::Debug for ProxyConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxyConfig")
            .field("real_api_key", &"<redacted>")
            .field("upstream_base", &self.upstream_base)
            .field("placeholder_key", &self.placeholder_key)
            .field("idle_timeout", &self.idle_timeout)
            .finish()
    }
}

/// The parsed upstream base. Request targets are built from this and the request's path only.
struct Upstream {
    scheme: Scheme,
    authority: Authority,
    prefix: String,
    host: HeaderValue,
}

impl Upstream {
    fn parse(base: &str) -> Result<Self> {
        let uri: Uri = base
            .parse()
            .map_err(|_| anyhow::anyhow!("upstream base URL is not a valid URL"))?;
        let scheme = uri
            .scheme()
            .cloned()
            .filter(|s| *s == Scheme::HTTP || *s == Scheme::HTTPS)
            .ok_or_else(|| anyhow::anyhow!("upstream base URL must be http or https"))?;
        let authority = uri
            .authority()
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("upstream base URL has no host"))?;
        if authority.as_str().contains('@') {
            bail!("upstream base URL must not carry user info");
        }
        if uri.query().is_some() || base.contains('#') {
            bail!("upstream base URL must not carry a query or fragment");
        }
        let prefix = uri.path().trim_end_matches('/').to_string();
        let host = HeaderValue::from_str(authority.as_str())
            .map_err(|_| anyhow::anyhow!("upstream host is not a valid header value"))?;
        Ok(Self {
            scheme,
            authority,
            prefix,
            host,
        })
    }

    fn target(&self, path_and_query: &str) -> Result<Uri> {
        Uri::builder()
            .scheme(self.scheme.clone())
            .authority(self.authority.clone())
            .path_and_query(format!("{}{}", self.prefix, path_and_query))
            .build()
            .map_err(|_| anyhow::anyhow!("could not build the upstream request target"))
    }
}

/// What the proxy recorded for one request.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RequestMetrics {
    /// Request path, without the query string, truncated.
    pub path: String,
    /// Status returned to the builder.
    pub status: u16,
    /// Request body bytes streamed to the upstream.
    pub bytes_in: u64,
    /// Response body bytes streamed to the builder.
    pub bytes_out: u64,
    /// `input_tokens` from a non-streaming JSON response, when present.
    pub input_tokens: Option<u64>,
    /// `output_tokens` from a non-streaming JSON response, when present.
    pub output_tokens: Option<u64>,
}

/// Shared, bounded, in-memory metrics. Cloning shares the same log.
#[derive(Clone, Default)]
pub struct MetricsLog(Arc<Mutex<VecDeque<RequestMetrics>>>);

impl MetricsLog {
    /// A copy of the records so far, oldest first.
    pub fn snapshot(&self) -> Vec<RequestMetrics> {
        self.lock().iter().cloned().collect()
    }

    fn record(&self, metrics: RequestMetrics) {
        let mut log = self.lock();
        if log.len() >= MAX_METRICS {
            log.pop_front();
        }
        log.push_back(metrics);
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, VecDeque<RequestMetrics>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

struct State {
    config: ProxyConfig,
    client: UpstreamClient,
    metrics: MetricsLog,
}

/// The proxy server.
pub struct ProxyServer {
    state: Arc<State>,
}

impl ProxyServer {
    /// Create a proxy server from a configuration.
    pub fn new(config: ProxyConfig) -> Self {
        let mut http = HttpConnector::new();
        http.enforce_http(false);
        http.set_connect_timeout(Some(CONNECT_TIMEOUT));
        http.set_nodelay(true);
        let https = HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_or_http()
            .enable_http1()
            .wrap_connector(http);
        let client = Client::builder(TokioExecutor::new())
            .pool_idle_timeout(Duration::from_secs(30))
            .build(https);
        Self {
            state: Arc::new(State {
                config,
                client,
                metrics: MetricsLog::default(),
            }),
        }
    }

    /// A handle on the metrics log; it stays valid after the server is moved into a task.
    pub fn metrics(&self) -> MetricsLog {
        self.state.metrics.clone()
    }

    /// Bind `127.0.0.1:port` and serve until the task is dropped or accepting fails fatally.
    pub async fn listen_tcp(self, port: u16) -> Result<()> {
        let listener = TcpListener::bind(("127.0.0.1", port))
            .await
            .context("failed to bind TCP listener")?;
        self.serve_tcp(listener).await
    }

    /// Serve on an already bound TCP listener (tests bind port 0 to learn the port).
    pub async fn serve_tcp(self, listener: TcpListener) -> Result<()> {
        let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
        loop {
            let permit = permits
                .clone()
                .acquire_owned()
                .await
                .context("connection limiter closed")?;
            let (socket, _) = match listener.accept().await {
                Ok(accepted) => accepted,
                Err(e) if transient_accept_error(&e) => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
                Err(e) => return Err(e).context("accept failed"),
            };
            let state = Arc::clone(&self.state);
            tokio::spawn(async move {
                serve_connection(socket, state).await;
                drop(permit);
            });
        }
    }

    /// Bind a Unix socket at `socket_path` (mode 0600) and serve on it.
    ///
    /// A stale socket at the path is replaced; any other kind of file there is an error.
    pub async fn listen_unix(self, socket_path: impl AsRef<Path>) -> Result<()> {
        let socket_path = socket_path.as_ref();
        match std::fs::symlink_metadata(socket_path) {
            Ok(meta) => {
                use std::os::unix::fs::FileTypeExt;
                if !meta.file_type().is_socket() {
                    bail!("{} exists and is not a socket", socket_path.display());
                }
                std::fs::remove_file(socket_path).context("failed to remove stale socket")?;
            }
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(e) => return Err(e).context("failed to inspect socket path"),
        }
        let listener = UnixListener::bind(socket_path).context("failed to bind Unix socket")?;
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))
                .context("failed to restrict socket permissions")?;
        }
        self.serve_unix(listener).await
    }

    /// Serve on an already bound Unix listener.
    pub async fn serve_unix(self, listener: UnixListener) -> Result<()> {
        let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
        loop {
            let permit = permits
                .clone()
                .acquire_owned()
                .await
                .context("connection limiter closed")?;
            let (socket, _) = match listener.accept().await {
                Ok(accepted) => accepted,
                Err(e) if transient_accept_error(&e) => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
                Err(e) => return Err(e).context("accept failed"),
            };
            let state = Arc::clone(&self.state);
            tokio::spawn(async move {
                serve_connection(socket, state).await;
                drop(permit);
            });
        }
    }
}

/// Accept failures that a retry can outlast (a peer that vanished, or descriptor pressure).
fn transient_accept_error(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        ErrorKind::ConnectionAborted
            | ErrorKind::ConnectionReset
            | ErrorKind::Interrupted
            | ErrorKind::WouldBlock
            | ErrorKind::OutOfMemory
    ) || matches!(e.raw_os_error(), Some(23 | 24 | 105))
}

async fn serve_connection<Io>(io: Io, state: Arc<State>)
where
    Io: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let service = service_fn(move |req: Request<Incoming>| {
        let state = Arc::clone(&state);
        async move { Ok::<_, Infallible>(handle(req, state).await) }
    });
    // Per-connection errors (client hang-ups, malformed requests) are expected and carry
    // nothing the operator needs; they are not logged.
    let _ = http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(HEADER_READ_TIMEOUT)
        .serve_connection(TokioIo::new(io), service)
        .await;
}

fn simple_response(status: StatusCode, text: &'static str) -> Response<ProxyBody> {
    let body = Full::new(Bytes::from_static(text.as_bytes()))
        .map_err(|never| match never {})
        .boxed_unsync();
    let mut response = Response::new(body);
    *response.status_mut() = status;
    response
}

/// Constant-time equality for the placeholder check.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// True when the request carries at least one credential and every credential is the placeholder.
///
/// Checking all of them, not the first, means a request that smuggles a foreign key beside the
/// placeholder is refused.
fn credential_ok(headers: &HeaderMap, placeholder: &str) -> bool {
    let mut seen = false;
    for value in headers.get_all("x-api-key") {
        seen = true;
        if !ct_eq(value.as_bytes(), placeholder.as_bytes()) {
            return false;
        }
    }
    for value in headers.get_all(header::AUTHORIZATION) {
        seen = true;
        let Ok(text) = value.to_str() else {
            return false;
        };
        let Some((scheme, token)) = text.split_once(' ') else {
            return false;
        };
        if !scheme.eq_ignore_ascii_case("bearer")
            || !ct_eq(token.trim_start().as_bytes(), placeholder.as_bytes())
        {
            return false;
        }
    }
    seen
}

/// Request headers that may reach the upstream. Everything else, including every credential
/// header, is dropped. Framing (`content-length`, `transfer-encoding`) is not copied: the body
/// is streamed and the client derives framing from it.
fn forward_header(name: &HeaderName) -> bool {
    let name = name.as_str();
    matches!(
        name,
        "anthropic-version" | "anthropic-beta" | "content-type" | "accept" | "user-agent" | "x-app"
    ) || name.starts_with("x-stainless-")
}

/// Response headers that must not be relayed (hop-by-hop, RFC 9110 section 7.6.1).
fn hop_by_hop(name: &HeaderName, listed_in_connection: &[String]) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    ) || listed_in_connection.iter().any(|l| l == name.as_str())
}

fn metric_path(uri: &Uri) -> String {
    let mut path = if uri.path().is_empty() {
        uri.authority()
            .map(Authority::to_string)
            .unwrap_or_default()
    } else {
        uri.path().to_string()
    };
    if path.len() > MAX_METRIC_PATH {
        let mut end = MAX_METRIC_PATH;
        while !path.is_char_boundary(end) {
            end -= 1;
        }
        path.truncate(end);
    }
    path
}

fn reject(
    state: &State,
    path: String,
    status: StatusCode,
    text: &'static str,
) -> Response<ProxyBody> {
    state.metrics.record(RequestMetrics {
        path,
        status: status.as_u16(),
        ..RequestMetrics::default()
    });
    simple_response(status, text)
}

/// Handle one request. Every refusal happens before the upstream client is touched.
async fn handle(req: Request<Incoming>, state: Arc<State>) -> Response<ProxyBody> {
    let path = metric_path(req.uri());
    let forbidden =
        |state: &State, path: String| reject(state, path, StatusCode::FORBIDDEN, "forbidden\n");

    if req.method() != Method::POST {
        return forbidden(&state, path);
    }
    // Origin-form only: an absolute-form or authority-form target names a host of the
    // builder's choosing, and the proxy has no business reading it.
    if req.uri().scheme().is_some() || req.uri().authority().is_some() {
        return forbidden(&state, path);
    }
    if !ALLOWED_PATHS.contains(&req.uri().path()) {
        return forbidden(&state, path);
    }
    if !credential_ok(req.headers(), state.config.placeholder_key()) {
        return forbidden(&state, path);
    }

    let (parts, body) = req.into_parts();
    if body.size_hint().lower() > MAX_REQUEST_BYTES {
        return reject(
            &state,
            path,
            StatusCode::PAYLOAD_TOO_LARGE,
            "request too large\n",
        );
    }
    let path_and_query = parts
        .uri
        .path_and_query()
        .map_or(parts.uri.path(), |pq| pq.as_str());
    let Ok(target) = state.config.upstream.target(path_and_query) else {
        return reject(&state, path, StatusCode::BAD_GATEWAY, "bad gateway\n");
    };

    let request_id = format!("req-{}", uuid::Uuid::new_v4());
    let bytes_in = Arc::new(AtomicU64::new(0));
    let request_body = RequestTap {
        inner: body,
        seen: Arc::clone(&bytes_in),
        idle_timeout: state.config.idle_timeout(),
        request_id: request_id.clone(),
        last_activity: Instant::now(),
    }
    .boxed_unsync();
    let mut upstream_request = Request::new(request_body);
    *upstream_request.method_mut() = Method::POST;
    *upstream_request.uri_mut() = target;
    *upstream_request.version_mut() = Version::HTTP_11;
    let headers = upstream_request.headers_mut();
    for (name, value) in &parts.headers {
        if forward_header(name) {
            headers.append(name.clone(), value.clone());
        }
    }
    headers.insert(header::HOST, state.config.upstream.host.clone());
    headers.insert("x-api-key", state.config.real_api_key.clone());

    let upstream_response = match state.client.request(upstream_request).await {
        Ok(response) => response,
        Err(_) => {
            // The error text is dropped on purpose: the builder gets a fixed body.
            state.metrics.record(RequestMetrics {
                path,
                status: StatusCode::BAD_GATEWAY.as_u16(),
                bytes_in: bytes_in.load(Ordering::Relaxed),
                ..RequestMetrics::default()
            });
            return simple_response(StatusCode::BAD_GATEWAY, "bad gateway\n");
        }
    };

    let (response_parts, response_body) = upstream_response.into_parts();
    let listed: Vec<String> = response_parts
        .headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|token| token.trim().to_ascii_lowercase())
        .collect();
    let mut headers = HeaderMap::new();
    for (name, value) in &response_parts.headers {
        if !hop_by_hop(name, &listed) {
            headers.append(name.clone(), value.clone());
        }
    }
    let capture_usage = is_plain_json(&response_parts.headers);
    let tap = ResponseTap {
        inner: response_body,
        report: Some(Report {
            metrics: state.metrics.clone(),
            path,
            status: response_parts.status.as_u16(),
            bytes_in,
        }),
        bytes_out: 0,
        captured: capture_usage.then(Vec::new),
        idle_timeout: state.config.idle_timeout(),
        request_id,
        last_activity: Instant::now(),
    };
    let mut response = Response::new(tap.boxed_unsync());
    *response.status_mut() = response_parts.status;
    *response.headers_mut() = headers;
    response
}

/// A JSON response that is not compressed, so `usage` can be read from the bytes as they pass.
fn is_plain_json(headers: &HeaderMap) -> bool {
    let json = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            v.trim_start()
                .to_ascii_lowercase()
                .starts_with("application/json")
        });
    let identity = headers
        .get(header::CONTENT_ENCODING)
        .is_none_or(|v| v.as_bytes().eq_ignore_ascii_case(b"identity"));
    json && identity
}

/// Read `input_tokens` and `output_tokens` from a message or count_tokens response.
fn parse_usage(body: &[u8]) -> (Option<u64>, Option<u64>) {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return (None, None);
    };
    let usage = value.get("usage").unwrap_or(&value);
    (
        usage
            .get("input_tokens")
            .and_then(serde_json::Value::as_u64),
        usage
            .get("output_tokens")
            .and_then(serde_json::Value::as_u64),
    )
}

/// Counts request bytes as they stream to the upstream and refuses a body over the limit.
/// Also enforces an idle timeout: if no data arrives within the configured idle timeout,
/// the stream is closed with an error.
struct RequestTap {
    inner: Incoming,
    seen: Arc<AtomicU64>,
    idle_timeout: Duration,
    request_id: String,
    last_activity: Instant,
}

impl Body for RequestTap {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        // Check for idle timeout before polling
        if Instant::now().duration_since(self.last_activity) > self.idle_timeout {
            eprintln!(
                "proxy idle timeout: request_id={} direction=request",
                self.request_id
            );
            return Poll::Ready(Some(Err("idle timeout".into())));
        }

        match Pin::new(&mut self.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    let total = self.seen.fetch_add(data.len() as u64, Ordering::Relaxed)
                        + data.len() as u64;
                    if total > MAX_REQUEST_BYTES {
                        return Poll::Ready(Some(Err("request body too large".into())));
                    }
                }
                // Reset idle timeout on successful frame
                self.last_activity = Instant::now();
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(Box::new(e)))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// What a finished response adds to the metrics log.
struct Report {
    metrics: MetricsLog,
    path: String,
    status: u16,
    bytes_in: Arc<AtomicU64>,
}

/// Relays the upstream body frame by frame. Nothing is held back: a frame goes to the builder
/// as soon as it arrives. The metric is written when the body ends, fails or is dropped.
/// Also enforces an idle timeout: if no data arrives within the configured idle timeout,
/// the stream is closed with an error.
struct ResponseTap {
    inner: Incoming,
    report: Option<Report>,
    bytes_out: u64,
    /// Copy of the body for `usage`, kept only for plain JSON and only up to a cap.
    captured: Option<Vec<u8>>,
    idle_timeout: Duration,
    request_id: String,
    last_activity: Instant,
}

impl ResponseTap {
    fn finish(&mut self) {
        let Some(report) = self.report.take() else {
            return;
        };
        let (input_tokens, output_tokens) = match &self.captured {
            Some(bytes) if (200..300).contains(&report.status) => parse_usage(bytes),
            _ => (None, None),
        };
        report.metrics.record(RequestMetrics {
            path: report.path,
            status: report.status,
            bytes_in: report.bytes_in.load(Ordering::Relaxed),
            bytes_out: self.bytes_out,
            input_tokens,
            output_tokens,
        });
    }
}

impl Drop for ResponseTap {
    fn drop(&mut self) {
        self.finish();
    }
}

impl Body for ResponseTap {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let this = &mut *self;

        // Check for idle timeout before polling
        if Instant::now().duration_since(this.last_activity) > this.idle_timeout {
            this.finish();
            eprintln!(
                "proxy idle timeout: request_id={} direction=response",
                this.request_id
            );
            return Poll::Ready(Some(Err("idle timeout".into())));
        }

        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    this.bytes_out += data.len() as u64;
                    if let Some(buffer) = &mut this.captured {
                        if buffer.len() + data.len() > MAX_USAGE_CAPTURE_BYTES {
                            this.captured = None;
                        } else {
                            buffer.extend_from_slice(data);
                        }
                    }
                }
                // Reset idle timeout on successful frame
                this.last_activity = Instant::now();
                // A body framed by Content-Length may never be polled again after its last
                // frame, so the metric is written here as well as at the end of the stream.
                if this.inner.is_end_stream() {
                    this.finish();
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(e))) => {
                this.finish();
                Poll::Ready(Some(Err(Box::new(e))))
            }
            Poll::Ready(None) => {
                this.finish();
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_key_is_generated_and_distinct() {
        let a = ProxyConfig::new("real-key", "https://api.test.com").unwrap();
        let b = ProxyConfig::new("real-key", "https://api.test.com").unwrap();
        assert!(a.placeholder_key().starts_with("placeholder-"));
        assert_ne!(a.placeholder_key(), b.placeholder_key());
    }

    #[test]
    fn config_rejects_bad_inputs_without_echoing_the_key() {
        assert!(ProxyConfig::new("", "https://api.test.com").is_err());
        let err = ProxyConfig::new("bad\nkey-SECRET", "https://api.test.com").unwrap_err();
        assert!(!format!("{err:#}").contains("SECRET"));
        for bad in [
            "api.test.com",
            "ftp://api.test.com",
            "https://user:pw@api.test.com",
            "https://api.test.com/?x=1",
            "https://api.test.com/#frag",
        ] {
            assert!(
                ProxyConfig::new("k", bad).is_err(),
                "{bad} should be refused"
            );
        }
    }

    #[test]
    fn upstream_target_uses_config_host_and_prefix() {
        let up = Upstream::parse("http://127.0.0.1:9999/gw/").unwrap();
        assert_eq!(
            up.target("/v1/messages?beta=true").unwrap().to_string(),
            "http://127.0.0.1:9999/gw/v1/messages?beta=true"
        );
        let up = Upstream::parse("https://api.anthropic.com").unwrap();
        assert_eq!(
            up.target("/v1/messages").unwrap().to_string(),
            "https://api.anthropic.com/v1/messages"
        );
    }

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (k, v) in pairs {
            map.append(
                HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        map
    }

    #[test]
    fn credential_requires_placeholder_everywhere() {
        let p = "placeholder-1";
        assert!(credential_ok(&headers(&[("x-api-key", p)]), p));
        assert!(credential_ok(
            &headers(&[("authorization", "Bearer placeholder-1")]),
            p
        ));
        assert!(credential_ok(
            &headers(&[("authorization", "bearer placeholder-1")]),
            p
        ));
        assert!(credential_ok(
            &headers(&[("x-api-key", p), ("authorization", "Bearer placeholder-1")]),
            p
        ));
        assert!(!credential_ok(&headers(&[]), p));
        assert!(!credential_ok(&headers(&[("x-api-key", "other")]), p));
        assert!(!credential_ok(
            &headers(&[("authorization", "Basic placeholder-1")]),
            p
        ));
        assert!(!credential_ok(
            &headers(&[("authorization", "placeholder-1")]),
            p
        ));
        // A foreign credential beside the placeholder is refused, in either header.
        assert!(!credential_ok(
            &headers(&[("x-api-key", p), ("authorization", "Bearer other")]),
            p
        ));
        assert!(!credential_ok(
            &headers(&[("x-api-key", p), ("x-api-key", "other")]),
            p
        ));
        // proxy-authorization is stripped, never a credential.
        assert!(!credential_ok(&headers(&[("proxy-authorization", p)]), p));
    }

    #[test]
    fn header_allowlist_drops_credentials_and_framing() {
        for dropped in [
            "x-api-key",
            "authorization",
            "proxy-authorization",
            "cookie",
            "content-length",
            "transfer-encoding",
            "connection",
            "host",
            "accept-encoding",
        ] {
            assert!(
                !forward_header(&HeaderName::from_static(dropped)),
                "{dropped}"
            );
        }
        for kept in [
            "anthropic-version",
            "anthropic-beta",
            "content-type",
            "accept",
            "x-stainless-os",
        ] {
            assert!(forward_header(&HeaderName::from_static(kept)), "{kept}");
        }
    }

    #[test]
    fn usage_is_read_from_messages_and_count_tokens_bodies() {
        assert_eq!(
            parse_usage(br#"{"id":"m","usage":{"input_tokens":12,"output_tokens":34}}"#),
            (Some(12), Some(34))
        );
        assert_eq!(parse_usage(br#"{"input_tokens":7}"#), (Some(7), None));
        assert_eq!(parse_usage(b"data: not json"), (None, None));
    }

    #[test]
    fn metrics_log_is_bounded() {
        let log = MetricsLog::default();
        for i in 0..(MAX_METRICS + 5) {
            log.record(RequestMetrics {
                status: (i % 600) as u16,
                ..RequestMetrics::default()
            });
        }
        assert_eq!(log.snapshot().len(), MAX_METRICS);
    }

    #[test]
    fn debug_redacts_real_key() {
        let config = ProxyConfig::new("secret-key-12345", "https://api.test.com").unwrap();
        let shown = format!("{config:?}");
        assert!(!shown.contains("secret-key-12345"));
        assert!(shown.contains("<redacted>"));
    }
}
