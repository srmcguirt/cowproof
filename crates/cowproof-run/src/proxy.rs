//! Egress proxy for sandboxed builders (D4): an HTTP/1.1 reverse proxy that holds the real API
//! credential outside the sandbox.
//!
//! The runner starts this proxy outside the sandbox. The sandbox policy
//! (`NetworkMode::Proxy`) lets the builder reach only the proxy's loopback port or Unix socket.
//! The builder sets `ANTHROPIC_BASE_URL` to the proxy and uses the per-lane placeholder key.
//!
//! A proxy serves one or more providers (D28): each [`Provider`] has its own upstream, its own
//! real key, its own auth scheme and its own path allowlist. A request is routed by its path, so
//! a lane that climbs from one runtime to another keeps one proxy and one placeholder.
//!
//! What the proxy enforces (design.md, "Trust boundaries": Network and Credentials):
//! - It forwards only the allowlisted `POST` paths of a configured provider: for Anthropic
//!   `/v1/messages` and `/v1/messages/count_tokens`, for OpenRouter `/api/v1/chat/completions`,
//!   for OpenAI (Codex, D28 step 3) `/v1/responses` (a query string is allowed). Every other path, method, `CONNECT` and absolute-form request
//!   target, and every path of a provider that is not configured, gets 403 and the upstream is
//!   never contacted.
//! - Every credential on the request (`x-api-key`, `Authorization: Bearer`) must be the lane's
//!   placeholder, and there must be at least one. Otherwise 403.
//! - Incoming `x-api-key`, `authorization` and `proxy-authorization` are never forwarded; the proxy
//!   sets the provider's own credential header to the real key (Anthropic: `x-api-key`;
//!   OpenRouter and OpenAI: `Authorization: Bearer`). Headers are forwarded by allowlist (see
//!   [`forward_header`]), so a builder cannot add arbitrary headers to the upstream request.
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

use std::collections::{BTreeSet, VecDeque};
use std::convert::Infallible;
use std::fmt;
use std::io::ErrorKind;
use std::path::Path;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};
use std::time::Duration;

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
use tokio::time::Sleep;

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type ProxyBody = UnsyncBoxBody<Bytes, BoxError>;
type UpstreamClient = Client<HttpsConnector<HttpConnector>, ProxyBody>;

/// The paths of Anthropic that are forwarded, always with `POST`.
const ANTHROPIC_PATHS: [&str; 2] = ["/v1/messages", "/v1/messages/count_tokens"];
/// The only path OpenCode uses on OpenRouter (observed against its 1.18.33 binary, D28 step 2),
/// always with `POST`.
const OPENROUTER_PATHS: [&str; 1] = ["/api/v1/chat/completions"];
/// The only path Codex uses on OpenAI (observed against its 0.157.0 binary, D28 step 3), always
/// with `POST`: the Responses API. Compaction of a long thread is one more request to this same
/// path, not a separate endpoint.
const OPENAI_PATHS: [&str; 1] = ["/v1/responses"];
/// Largest request body the proxy streams to the upstream.
const MAX_REQUEST_BYTES: u64 = 64 * 1024 * 1024;
/// Most response bytes copied aside to read `usage` from a non-streaming JSON response.
const MAX_USAGE_CAPTURE_BYTES: usize = 1024 * 1024;
/// Longest server-sent-events line the proxy keeps while it looks for `response.completed`. The
/// event carries the whole response object, so it can be large; a longer line is skipped (that
/// call's usage is then unseen, and the runtime's own totals stand in).
const MAX_SSE_LINE_BYTES: usize = 8 * 1024 * 1024;
/// Most metric records kept; the oldest are dropped first.
const MAX_METRICS: usize = 10_000;
/// Longest path stored in a metric record.
const MAX_METRIC_PATH: usize = 200;
/// Most connections served at once.
const MAX_CONNECTIONS: usize = 256;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(120);

/// A provider the proxy can forward to. The closed set of API shapes a runtime speaks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Provider {
    /// The Anthropic Messages API (Claude Code). The real key goes in `x-api-key`.
    Anthropic,
    /// OpenRouter's OpenAI-style chat completions (OpenCode). The real key goes in
    /// `Authorization: Bearer`.
    Openrouter,
    /// OpenAI's Responses API (Codex). The real key goes in `Authorization: Bearer`.
    Openai,
}

impl Provider {
    pub fn name(self) -> &'static str {
        match self {
            Self::Anthropic => "anthropic",
            Self::Openrouter => "openrouter",
            Self::Openai => "openai",
        }
    }

    /// The `POST` paths forwarded for this provider.
    pub fn allowed_paths(self) -> &'static [&'static str] {
        match self {
            Self::Anthropic => &ANTHROPIC_PATHS,
            Self::Openrouter => &OPENROUTER_PATHS,
            Self::Openai => &OPENAI_PATHS,
        }
    }
}

/// One provider's upstream and real credential.
struct Route {
    provider: Provider,
    /// The real credential as the header value the upstream wants (`Bearer <key>` for
    /// OpenRouter, the bare key for Anthropic). Sensitive; never sent to the builder.
    credential: HeaderValue,
    /// The header that carries it.
    credential_header: HeaderName,
    /// The upstream base URL as given (for display only).
    upstream_base: String,
    upstream: Upstream,
    /// When set, a request is forwarded only if its JSON body names one of these models.
    models: Option<BTreeSet<String>>,
}

/// Configuration for the proxy.
pub struct ProxyConfig {
    /// The providers served, in the order they were added. Never empty.
    routes: Vec<Route>,
    /// Per-lane placeholder the builder must present.
    placeholder_key: String,
    /// Longest gap allowed between chunks while streaming a body in either direction.
    idle_timeout: Duration,
}

impl ProxyConfig {
    /// Create a configuration for Anthropic with a freshly generated placeholder key.
    ///
    /// `upstream_base` is an `http` or `https` URL such as `https://api.anthropic.com`. It may
    /// carry a path prefix but no user info, query or fragment. Errors never contain the key.
    pub fn new(real_api_key: impl Into<String>, upstream_base: impl Into<String>) -> Result<Self> {
        Self::for_provider(Provider::Anthropic, real_api_key, upstream_base)
    }

    /// A configuration that serves `provider` alone, with a freshly generated placeholder key.
    pub fn for_provider(
        provider: Provider,
        real_api_key: impl Into<String>,
        upstream_base: impl Into<String>,
    ) -> Result<Self> {
        let route = Route::new(provider, real_api_key.into(), upstream_base.into())?;
        Ok(Self {
            routes: vec![route],
            placeholder_key: format!("placeholder-{}", uuid::Uuid::new_v4()),
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
        })
    }

    /// Also serve `provider` (with the same placeholder). A provider is added once.
    pub fn with_provider(
        mut self,
        provider: Provider,
        real_api_key: impl Into<String>,
        upstream_base: impl Into<String>,
    ) -> Result<Self> {
        if self.routes.iter().any(|r| r.provider == provider) {
            bail!("the {} provider is already configured", provider.name());
        }
        self.routes.push(Route::new(
            provider,
            real_api_key.into(),
            upstream_base.into(),
        )?);
        Ok(self)
    }

    /// Forward a `provider` request only if its JSON body names one of `models` (`"model"`,
    /// exactly once, as a string). Any other request gets 403 and the upstream is never
    /// contacted. The body is read whole first (the proxy otherwise streams it), which the
    /// runtimes' requests, a few hundred kilobytes at most, can bear. A runtime that can start
    /// another agent on a model of its choosing (Codex's `spawn_agent` takes a `model`) would
    /// otherwise spend at a price nobody configured.
    pub fn with_models(
        mut self,
        provider: Provider,
        models: impl IntoIterator<Item = String>,
    ) -> Result<Self> {
        let models: BTreeSet<String> = models.into_iter().collect();
        if models.is_empty() {
            bail!(
                "the {} provider is limited to no model at all",
                provider.name()
            );
        }
        match self.routes.iter_mut().find(|r| r.provider == provider) {
            Some(route) => route.models = Some(models),
            None => bail!("the {} provider is not configured", provider.name()),
        }
        Ok(self)
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

    /// The first provider's upstream base URL.
    pub fn upstream_base(&self) -> &str {
        &self.routes[0].upstream_base
    }

    /// The upstream base URL of `provider`, when it is served.
    pub fn upstream_of(&self, provider: Provider) -> Option<&str> {
        self.routes
            .iter()
            .find(|r| r.provider == provider)
            .map(|r| r.upstream_base.as_str())
    }

    /// The idle timeout.
    fn idle_timeout(&self) -> Duration {
        self.idle_timeout
    }

    /// The route whose allowlist holds `path`.
    fn route_for(&self, path: &str) -> Option<&Route> {
        self.routes
            .iter()
            .find(|r| r.provider.allowed_paths().contains(&path))
    }
}

impl Route {
    fn new(provider: Provider, real_api_key: String, upstream_base: String) -> Result<Self> {
        if real_api_key.is_empty() {
            bail!("the real API key is empty");
        }
        let (credential_header, text) = match provider {
            Provider::Anthropic => (HeaderName::from_static("x-api-key"), real_api_key),
            Provider::Openrouter | Provider::Openai => {
                (header::AUTHORIZATION, format!("Bearer {real_api_key}"))
            }
        };
        let mut credential = HeaderValue::from_str(&text)
            .map_err(|_| anyhow::anyhow!("the real API key is not a valid header value"))?;
        credential.set_sensitive(true);
        let upstream = Upstream::parse(&upstream_base)?;
        Ok(Self {
            provider,
            credential,
            credential_header,
            upstream_base,
            upstream,
            models: None,
        })
    }
}

impl fmt::Debug for ProxyConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let routes: Vec<String> = self
            .routes
            .iter()
            .map(|r| format!("{}={}", r.provider.name(), r.upstream_base))
            .collect();
        f.debug_struct("ProxyConfig")
            .field("real_api_key", &"<redacted>")
            .field("upstreams", &routes)
            .field("placeholder_key", &self.placeholder_key)
            .field("idle_timeout", &self.idle_timeout)
            .finish()
    }
}

/// The parsed upstream base. Request targets are built from this and the request's path only.
pub(crate) struct Upstream {
    scheme: Scheme,
    authority: Authority,
    prefix: String,
    host: HeaderValue,
}

impl Upstream {
    pub(crate) fn parse(base: &str) -> Result<Self> {
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

    pub(crate) fn target(&self, path_and_query: &str) -> Result<Uri> {
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
    /// `input_tokens_details.cached_tokens` of an OpenAI Responses stream's `response.completed`
    /// event (a part of `input_tokens`), when present.
    pub cached_input_tokens: Option<u64>,
}

/// The tokens one model call used, as OpenAI's Responses API reports them in the
/// `response.completed` event that ends the call's stream. `input` includes `cached_input`
/// and `output` includes the reasoning tokens (OpenAI's own definitions).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CallUsage {
    pub input: u64,
    pub cached_input: u64,
    pub output: u64,
}

/// Shared, bounded, in-memory metrics. Cloning shares the same log.
#[derive(Clone, Default)]
pub struct MetricsLog(Arc<Mutex<LogInner>>);

#[derive(Default)]
struct LogInner {
    records: VecDeque<RequestMetrics>,
    /// Model calls whose usage a Responses stream reported, oldest first. Written the moment
    /// the `response.completed` event passes, not when the stream ends, so a running lane can
    /// be metered live.
    usage: VecDeque<CallUsage>,
    /// How many usage entries were ever pushed (the queue drops the oldest at its bound).
    usage_total: u64,
}

impl MetricsLog {
    /// A copy of the records so far, oldest first.
    pub fn snapshot(&self) -> Vec<RequestMetrics> {
        self.lock().records.iter().cloned().collect()
    }

    /// How many model calls with reported usage have passed so far. A launch reads this before
    /// it starts and hands it to [`MetricsLog::usage_since`].
    pub fn usage_recorded(&self) -> u64 {
        self.lock().usage_total
    }

    /// The model calls with reported usage after the first `before` of them, oldest first.
    pub fn usage_since(&self, before: u64) -> Vec<CallUsage> {
        let log = self.lock();
        let first_held = log.usage_total - log.usage.len() as u64;
        let skip = before.saturating_sub(first_held) as usize;
        log.usage.iter().skip(skip).copied().collect()
    }

    fn record(&self, metrics: RequestMetrics) {
        let mut log = self.lock();
        if log.records.len() >= MAX_METRICS {
            log.records.pop_front();
        }
        log.records.push_back(metrics);
    }

    pub(crate) fn push_usage(&self, usage: CallUsage) {
        let mut log = self.lock();
        if log.usage.len() >= MAX_METRICS {
            log.usage.pop_front();
        }
        log.usage.push_back(usage);
        log.usage_total += 1;
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, LogInner> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

struct State {
    config: ProxyConfig,
    client: UpstreamClient,
    metrics: MetricsLog,
}

/// The HTTPS client for the providers: webpki roots, a connect timeout, HTTP/1. The proxy
/// forwards the builder's requests with it, and the director's own model-list request
/// ([`crate::models`]) uses the same one, so there is one client to audit.
pub(crate) fn https_client<B>() -> Client<HttpsConnector<HttpConnector>, B>
where
    B: Body + Send + 'static,
    B::Data: Send,
{
    let mut http = HttpConnector::new();
    http.enforce_http(false);
    http.set_connect_timeout(Some(CONNECT_TIMEOUT));
    http.set_nodelay(true);
    let https = HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .wrap_connector(http);
    Client::builder(TokioExecutor::new())
        .pool_idle_timeout(Duration::from_secs(30))
        .build(https)
}

/// The proxy server.
pub struct ProxyServer {
    state: Arc<State>,
}

impl ProxyServer {
    /// Create a proxy server from a configuration.
    pub fn new(config: ProxyConfig) -> Self {
        let client = https_client();
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

/// Request headers that may reach the upstream of `provider`. Everything else, including every
/// credential header, is dropped. Framing (`content-length`, `transfer-encoding`) is not copied:
/// the body is streamed and the client derives framing from it.
fn forward_header(provider: Provider, name: &HeaderName) -> bool {
    let name = name.as_str();
    if matches!(name, "content-type" | "accept" | "user-agent") {
        return true;
    }
    match provider {
        Provider::Anthropic => {
            matches!(name, "anthropic-version" | "anthropic-beta" | "x-app")
                || name.starts_with("x-stainless-")
        }
        // OpenCode sends nothing else OpenRouter needs, and Codex nothing else OpenAI needs
        // (it adds installation, window and turn identifiers that the API does not use): the
        // credential is the proxy's.
        Provider::Openrouter | Provider::Openai => false,
    }
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
    // The path picks the provider; a path no configured provider allows is refused here.
    let Some(route) = state.config.route_for(req.uri().path()) else {
        return forbidden(&state, path);
    };
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
    let Ok(target) = route.upstream.target(path_and_query) else {
        return reject(&state, path, StatusCode::BAD_GATEWAY, "bad gateway\n");
    };

    let request_id = format!("req-{}", uuid::Uuid::new_v4());
    let bytes_in = Arc::new(AtomicU64::new(0));
    let idle_timeout = state.config.idle_timeout();
    let tap = RequestTap {
        inner: body,
        seen: Arc::clone(&bytes_in),
        idle_timeout,
        request_id: request_id.clone(),
        idle_sleep: Box::pin(tokio::time::sleep(idle_timeout)),
    };
    let request_body: ProxyBody = match &route.models {
        None => tap.boxed_unsync(),
        Some(models) => {
            let Ok(collected) = tap.collect().await else {
                return reject(&state, path, StatusCode::BAD_REQUEST, "bad request\n");
            };
            let bytes = collected.to_bytes();
            if !requested_model(&bytes).is_some_and(|model| models.contains(&model)) {
                return reject(&state, path, StatusCode::FORBIDDEN, "forbidden\n");
            }
            Full::new(bytes)
                .map_err(|never| match never {})
                .boxed_unsync()
        }
    };
    let mut upstream_request = Request::new(request_body);
    *upstream_request.method_mut() = Method::POST;
    *upstream_request.uri_mut() = target;
    *upstream_request.version_mut() = Version::HTTP_11;
    let headers = upstream_request.headers_mut();
    for (name, value) in &parts.headers {
        if forward_header(route.provider, name) {
            headers.append(name.clone(), value.clone());
        }
    }
    headers.insert(header::HOST, route.upstream.host.clone());
    headers.insert(route.credential_header.clone(), route.credential.clone());

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
    // The Responses API reports a call's usage in the last event of its server-sent stream.
    let scan_usage = route.provider == Provider::Openai
        && is_event_stream(&response_parts.headers)
        && response_parts.status.is_success();
    let idle_timeout = state.config.idle_timeout();
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
        sse: scan_usage.then(|| SseScan::new(state.metrics.clone())),
        idle_timeout,
        request_id,
        idle_sleep: Box::pin(tokio::time::sleep(idle_timeout)),
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

/// The `"model"` a JSON request body names: the one string value of the body's top-level
/// `model` key. `None` when the body is not a JSON object, has no such key, has it twice (two
/// parsers may disagree about which one wins, so neither is trusted) or its value is not a
/// string.
fn requested_model(body: &[u8]) -> Option<String> {
    use serde::de::{Deserializer, IgnoredAny, MapAccess, Visitor};

    struct Top(Option<String>);

    impl<'de> serde::Deserialize<'de> for Top {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            struct V;
            impl<'de> Visitor<'de> for V {
                type Value = Top;
                fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    f.write_str("a JSON object")
                }
                fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Top, A::Error> {
                    let mut model: Option<Option<String>> = None;
                    while let Some(key) = map.next_key::<std::borrow::Cow<'de, str>>()? {
                        if key == "model" {
                            if model.is_some() {
                                return Ok(Top(None));
                            }
                            // A value that is not a string is no model.
                            model = Some(
                                map.next_value::<serde_json::Value>()?
                                    .as_str()
                                    .map(str::to_string),
                            );
                        } else {
                            map.next_value::<IgnoredAny>()?;
                        }
                    }
                    Ok(Top(model.flatten()))
                }
            }
            deserializer.deserialize_map(V)
        }
    }

    serde_json::from_slice::<Top>(body).ok().and_then(|t| t.0)
}

/// A server-sent-events response that is not compressed, so its events can be read as they pass.
fn is_event_stream(headers: &HeaderMap) -> bool {
    let sse = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            v.trim_start()
                .to_ascii_lowercase()
                .starts_with("text/event-stream")
        });
    let identity = headers
        .get(header::CONTENT_ENCODING)
        .is_none_or(|v| v.as_bytes().eq_ignore_ascii_case(b"identity"));
    sse && identity
}

/// Reads the `response.completed` (or `response.incomplete`) events of an OpenAI Responses
/// stream as they pass and reports each one's usage to the log at once. It copies nothing but
/// the line it is in the middle of, and that only up to [`MAX_SSE_LINE_BYTES`].
struct SseScan {
    log: MetricsLog,
    line: Vec<u8>,
    /// The current line outgrew the limit: skip it to its end.
    skipping: bool,
    /// The last usage seen, for the request's metric record.
    last: Option<(u64, u64, u64)>,
}

impl SseScan {
    fn new(log: MetricsLog) -> Self {
        Self {
            log,
            line: Vec::new(),
            skipping: false,
            last: None,
        }
    }

    fn feed(&mut self, data: &[u8]) {
        for chunk in data.split_inclusive(|b| *b == b'\n') {
            let ends_line = chunk.last() == Some(&b'\n');
            if self.skipping {
                self.skipping = !ends_line;
                continue;
            }
            if self.line.len() + chunk.len() > MAX_SSE_LINE_BYTES {
                self.line.clear();
                self.skipping = !ends_line;
                continue;
            }
            self.line.extend_from_slice(chunk);
            if ends_line {
                let line = std::mem::take(&mut self.line);
                self.read_line(&line);
            }
        }
    }

    fn read_line(&mut self, line: &[u8]) {
        let Some(rest) = line.strip_prefix(b"data:") else {
            return;
        };
        // Cheap test first: only the two terminal events carry usage.
        let text = String::from_utf8_lossy(rest);
        if !(text.contains("response.completed") || text.contains("response.incomplete")) {
            return;
        }
        let Ok(event) = serde_json::from_str::<serde_json::Value>(text.trim()) else {
            return;
        };
        if !matches!(
            event.get("type").and_then(serde_json::Value::as_str),
            Some("response.completed" | "response.incomplete")
        ) {
            return;
        }
        let Some(usage) = event.get("response").and_then(|r| r.get("usage")) else {
            return;
        };
        let count = |value: Option<&serde_json::Value>| {
            value.and_then(serde_json::Value::as_u64).unwrap_or(0)
        };
        let input = count(usage.get("input_tokens"));
        let output = count(usage.get("output_tokens"));
        let cached = count(
            usage
                .get("input_tokens_details")
                .and_then(|d| d.get("cached_tokens")),
        )
        .min(input);
        self.log.push_usage(CallUsage {
            input,
            cached_input: cached,
            output,
        });
        self.last = Some((input, cached, output));
    }
}

/// Read `input_tokens` and `output_tokens` from a message or count_tokens response, or
/// `prompt_tokens` and `completion_tokens` from an OpenAI-style chat completion.
fn parse_usage(body: &[u8]) -> (Option<u64>, Option<u64>) {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return (None, None);
    };
    let usage = value.get("usage").unwrap_or(&value);
    let count = |names: [&str; 2]| {
        names
            .iter()
            .find_map(|n| usage.get(*n).and_then(serde_json::Value::as_u64))
    };
    (
        count(["input_tokens", "prompt_tokens"]),
        count(["output_tokens", "completion_tokens"]),
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
    idle_sleep: Pin<Box<Sleep>>,
}

impl Body for RequestTap {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        match Pin::new(&mut self.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    let total = self.seen.fetch_add(data.len() as u64, Ordering::Relaxed)
                        + data.len() as u64;
                    if total > MAX_REQUEST_BYTES {
                        return Poll::Ready(Some(Err("request body too large".into())));
                    }
                }
                // A frame resets the idle timer.
                let deadline = tokio::time::Instant::now() + self.idle_timeout;
                self.idle_sleep.as_mut().reset(deadline);
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(Box::new(e)))),
            Poll::Ready(None) => Poll::Ready(None),
            // Only a body with nothing ready can be idle: polling the timer here
            // registers the wakeup, and a frame that is ready always goes through.
            Poll::Pending => {
                if self.idle_sleep.as_mut().poll(cx).is_ready() {
                    eprintln!(
                        "proxy idle timeout: request_id={} direction=request",
                        self.request_id
                    );
                    return Poll::Ready(Some(Err("idle timeout".into())));
                }
                Poll::Pending
            }
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
    /// The usage reader of an OpenAI Responses stream.
    sse: Option<SseScan>,
    idle_timeout: Duration,
    request_id: String,
    idle_sleep: Pin<Box<Sleep>>,
}

impl ResponseTap {
    fn finish(&mut self) {
        let Some(report) = self.report.take() else {
            return;
        };
        let (mut input_tokens, mut output_tokens) = match &self.captured {
            Some(bytes) if (200..300).contains(&report.status) => parse_usage(bytes),
            _ => (None, None),
        };
        let mut cached_input_tokens = None;
        if let Some((input, cached, output)) = self.sse.as_ref().and_then(|scan| scan.last) {
            input_tokens = Some(input);
            output_tokens = Some(output);
            cached_input_tokens = Some(cached);
        }
        report.metrics.record(RequestMetrics {
            path: report.path,
            status: report.status,
            bytes_in: report.bytes_in.load(Ordering::Relaxed),
            bytes_out: self.bytes_out,
            input_tokens,
            output_tokens,
            cached_input_tokens,
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

        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    this.bytes_out += data.len() as u64;
                    if let Some(scan) = &mut this.sse {
                        scan.feed(data);
                    }
                    if let Some(buffer) = &mut this.captured {
                        if buffer.len() + data.len() > MAX_USAGE_CAPTURE_BYTES {
                            this.captured = None;
                        } else {
                            buffer.extend_from_slice(data);
                        }
                    }
                }
                // A frame resets the idle timer.
                let deadline = tokio::time::Instant::now() + this.idle_timeout;
                this.idle_sleep.as_mut().reset(deadline);
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
            // See RequestTap: the timer is checked only when nothing is ready.
            Poll::Pending => {
                if this.idle_sleep.as_mut().poll(cx).is_ready() {
                    this.finish();
                    eprintln!(
                        "proxy idle timeout: request_id={} direction=response",
                        this.request_id
                    );
                    return Poll::Ready(Some(Err("idle timeout".into())));
                }
                Poll::Pending
            }
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
                !forward_header(Provider::Anthropic, &HeaderName::from_static(dropped)),
                "{dropped}"
            );
            assert!(
                !forward_header(Provider::Openrouter, &HeaderName::from_static(dropped)),
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
            assert!(
                forward_header(Provider::Anthropic, &HeaderName::from_static(kept)),
                "{kept}"
            );
        }
        // OpenRouter gets the three generic headers and nothing Anthropic-specific.
        for kept in ["content-type", "accept", "user-agent"] {
            assert!(
                forward_header(Provider::Openrouter, &HeaderName::from_static(kept)),
                "{kept}"
            );
        }
        for dropped in [
            "anthropic-version",
            "anthropic-beta",
            "x-stainless-os",
            "x-app",
        ] {
            assert!(
                !forward_header(Provider::Openrouter, &HeaderName::from_static(dropped)),
                "{dropped}"
            );
        }
    }

    #[test]
    fn usage_is_read_from_messages_and_count_tokens_bodies() {
        assert_eq!(
            parse_usage(br#"{"id":"m","usage":{"input_tokens":12,"output_tokens":34}}"#),
            (Some(12), Some(34))
        );
        assert_eq!(parse_usage(br#"{"input_tokens":7}"#), (Some(7), None));
        assert_eq!(
            parse_usage(br#"{"usage":{"prompt_tokens":9,"completion_tokens":3}}"#),
            (Some(9), Some(3))
        );
        assert_eq!(parse_usage(b"data: not json"), (None, None));
    }

    #[test]
    fn no_two_providers_allow_the_same_path() {
        let providers = [Provider::Anthropic, Provider::Openrouter, Provider::Openai];
        let mut seen = std::collections::BTreeSet::new();
        for provider in providers {
            for path in provider.allowed_paths() {
                assert!(seen.insert(*path), "{path} is allowed by two providers");
            }
        }
        assert_eq!(Provider::Openai.allowed_paths(), ["/v1/responses"]);
        let config = ProxyConfig::new("a-key", "https://api.test.com")
            .unwrap()
            .with_provider(Provider::Openrouter, "or-key", "https://or.test.com")
            .unwrap()
            .with_provider(Provider::Openai, "oa-key", "https://oa.test.com")
            .unwrap();
        let route = |path| config.route_for(path).map(|r| r.provider);
        assert_eq!(route("/v1/responses"), Some(Provider::Openai));
        assert_eq!(route("/v1/messages"), Some(Provider::Anthropic));
        assert_eq!(
            route("/api/v1/chat/completions"),
            Some(Provider::Openrouter)
        );
        // OpenAI's other endpoints are not forwarded: Codex needs none of them.
        for other in [
            "/v1/models",
            "/v1/responses/compact",
            "/v1/chat/completions",
        ] {
            assert_eq!(route(other), None, "{other}");
        }
    }

    const COMPLETED: &str = r#"data: {"type":"response.completed","response":{"id":"resp_1","output":[],"usage":{"input_tokens":120,"input_tokens_details":{"cached_tokens":20},"output_tokens":30,"output_tokens_details":{"reasoning_tokens":5},"total_tokens":150}}}"#;

    fn scan() -> (SseScan, MetricsLog) {
        let log = MetricsLog::default();
        (SseScan::new(log.clone()), log)
    }

    #[test]
    fn the_sse_scan_reads_usage_from_the_completed_event_however_the_bytes_are_cut() {
        let stream = format!(
            "event: response.created\ndata: {{\"type\":\"response.created\"}}\n\nevent: response.completed\n{COMPLETED}\n\n"
        );
        // Whole, then one byte at a time (a line split anywhere), then CRLF line ends.
        for pieces in [
            vec![stream.as_bytes().to_vec()],
            stream.bytes().map(|b| vec![b]).collect(),
            vec![stream.replace('\n', "\r\n").into_bytes()],
        ] {
            let (mut scan, log) = scan();
            for piece in pieces {
                scan.feed(&piece);
            }
            assert_eq!(
                log.usage_since(0),
                [CallUsage {
                    input: 120,
                    cached_input: 20,
                    output: 30
                }]
            );
            assert_eq!(scan.last, Some((120, 20, 30)));
        }
    }

    #[test]
    fn the_sse_scan_counts_each_call_and_ignores_what_is_not_usage() {
        let (mut scan, log) = scan();
        scan.feed(
            b"data: {\"type\":\"response.output_text.delta\",\"delta\":\"response.completed\"}\n\n",
        );
        scan.feed(b"data: not json response.completed\n\n");
        scan.feed(b": a comment line response.completed\n\n");
        scan.feed(b"data: {\"type\":\"response.completed\",\"response\":{\"id\":\"x\"}}\n\n");
        assert_eq!(log.usage_recorded(), 0, "no usage in any of those");
        scan.feed(format!("{COMPLETED}\n\n").as_bytes());
        scan.feed(
            b"data: {\"type\":\"response.incomplete\",\"response\":{\"usage\":{\"input_tokens\":7,\"output_tokens\":1}}}\n\n",
        );
        assert_eq!(log.usage_recorded(), 2);
        // `since` skips what a launch had already seen.
        assert_eq!(
            log.usage_since(1),
            [CallUsage {
                input: 7,
                cached_input: 0,
                output: 1
            }]
        );
        assert_eq!(log.usage_since(2), []);
        // A cached count above the input is clamped to it.
        scan.feed(
            b"data: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":3,\"input_tokens_details\":{\"cached_tokens\":9},\"output_tokens\":1}}}\n",
        );
        assert_eq!(log.usage_since(2)[0].cached_input, 3);
    }

    #[test]
    fn the_sse_scan_skips_a_line_over_the_limit_and_reads_the_next() {
        let (mut scan, log) = scan();
        let mut long = b"data: ".to_vec();
        long.resize(MAX_SSE_LINE_BYTES + 10, b'x');
        // Fed in pieces, with the end of the line in the last one.
        for piece in long.chunks(1024 * 1024) {
            scan.feed(piece);
        }
        scan.feed(b"\n\n");
        assert!(scan.line.is_empty() && !scan.skipping);
        scan.feed(format!("{COMPLETED}\n\n").as_bytes());
        assert_eq!(log.usage_recorded(), 1);
    }

    #[test]
    fn usage_since_survives_the_bound() {
        let log = MetricsLog::default();
        for i in 0..(MAX_METRICS as u64 + 5) {
            log.push_usage(CallUsage {
                input: i,
                cached_input: 0,
                output: 0,
            });
        }
        assert_eq!(log.usage_recorded(), MAX_METRICS as u64 + 5);
        // The first five were dropped; asking from before them returns all that are held, and
        // asking from after returns the rest.
        assert_eq!(log.usage_since(0).len(), MAX_METRICS);
        assert_eq!(log.usage_since(MAX_METRICS as u64).len(), 5);
    }

    #[test]
    fn the_requested_model_is_the_one_string_value_of_the_top_level_key() {
        let model = |body: &str| requested_model(body.as_bytes());
        assert_eq!(
            model(r#"{"model":"gpt-6-luna","input":[]}"#).as_deref(),
            Some("gpt-6-luna")
        );
        // Wherever the key sits, and whatever surrounds it.
        assert_eq!(
            model(r#" {"input":[{"model":"nested"}],"x":{"model":"deep"},"model":"gpt-6-luna","stream":true} "#).as_deref(),
            Some("gpt-6-luna")
        );
        // Escapes are decoded, as the upstream's parser will decode them.
        assert_eq!(
            model(r#"{"mod\u0065l":"a\u002fb"}"#).as_deref(),
            Some("a/b")
        );
        // Not trusted: no key, two keys (parsers disagree about which wins), a value that is not
        // a string, a body that is not an object, and bytes that are not JSON.
        for bad in [
            r#"{"input":[]}"#,
            r#"{"model":"gpt-6-luna","model":"gpt-6-astra"}"#,
            r#"{"model":"gpt-6-astra","input":[],"model":"gpt-6-luna"}"#,
            r#"{"model":["gpt-6-luna"]}"#,
            r#"{"model":null}"#,
            r#"["model"]"#,
            r#"{"model":"gpt-6-luna""#,
            "not json",
            "",
        ] {
            assert_eq!(model(bad), None, "{bad:?}");
        }
        assert_eq!(requested_model(&[0xff, 0xfe]), None);
    }

    #[test]
    fn a_model_limit_needs_a_configured_provider_and_a_model() {
        let config = ProxyConfig::new("a-key", "https://api.test.com").unwrap();
        assert!(
            ProxyConfig::new("a-key", "https://api.test.com")
                .unwrap()
                .with_models(Provider::Openai, ["m".to_string()])
                .is_err()
        );
        assert!(
            config
                .with_models(Provider::Anthropic, Vec::<String>::new())
                .is_err()
        );
        let limited = ProxyConfig::for_provider(Provider::Openai, "k", "https://oa.test.com")
            .unwrap()
            .with_models(Provider::Openai, ["gpt-6-luna".to_string()])
            .unwrap();
        assert!(limited.route_for("/v1/responses").unwrap().models.is_some());
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

    #[test]
    fn a_config_serves_each_provider_once_and_routes_by_path() {
        let config = ProxyConfig::new("anthropic-key", "https://api.test.com")
            .unwrap()
            .with_provider(Provider::Openrouter, "or-key", "https://or.test.com/gw")
            .unwrap();
        assert_eq!(config.upstream_base(), "https://api.test.com");
        assert_eq!(
            config.upstream_of(Provider::Openrouter),
            Some("https://or.test.com/gw")
        );
        let route = |path| config.route_for(path).map(|r| r.provider);
        assert_eq!(route("/v1/messages"), Some(Provider::Anthropic));
        assert_eq!(
            route("/v1/messages/count_tokens"),
            Some(Provider::Anthropic)
        );
        assert_eq!(
            route("/api/v1/chat/completions"),
            Some(Provider::Openrouter)
        );
        for other in [
            "/",
            "/v1",
            "/api/v1/models",
            "/api/v1/chat/completions/",
            "/v1/messages/x",
        ] {
            assert_eq!(route(other), None, "{other}");
        }
        // A provider twice is a mistake, and the message never echoes a key.
        let err = config
            .with_provider(Provider::Openrouter, "or-key-SECRET", "https://x.test.com")
            .expect_err("a second openrouter route is refused");
        assert!(!format!("{err:#}").contains("SECRET"));
    }

    #[test]
    fn an_openrouter_only_config_has_no_anthropic_route() {
        let config =
            ProxyConfig::for_provider(Provider::Openrouter, "or-key", "https://or.test.com")
                .unwrap();
        assert_eq!(config.upstream_of(Provider::Anthropic), None);
        assert!(config.route_for("/v1/messages").is_none());
        assert_eq!(config.upstream_base(), "https://or.test.com");
    }

    #[test]
    fn the_credential_is_the_providers_own_header_and_redacted_in_debug() {
        let anthropic = Route::new(
            Provider::Anthropic,
            "k1".into(),
            "https://a.test.com".into(),
        )
        .unwrap();
        assert_eq!(anthropic.credential_header, "x-api-key");
        assert_eq!(anthropic.credential.to_str().unwrap(), "k1");
        let openrouter = Route::new(
            Provider::Openrouter,
            "k2".into(),
            "https://o.test.com".into(),
        )
        .unwrap();
        assert_eq!(openrouter.credential_header, header::AUTHORIZATION);
        assert_eq!(openrouter.credential.to_str().unwrap(), "Bearer k2");
        assert!(openrouter.credential.is_sensitive());
        let config = ProxyConfig::new("secret-anthropic-1", "https://a.test.com")
            .unwrap()
            .with_provider(
                Provider::Openrouter,
                "secret-openrouter-2",
                "https://o.test.com",
            )
            .unwrap();
        let shown = format!("{config:?}");
        assert!(!shown.contains("secret-anthropic-1") && !shown.contains("secret-openrouter-2"));
        assert!(shown.contains("openrouter=https://o.test.com"), "{shown}");
    }
}
