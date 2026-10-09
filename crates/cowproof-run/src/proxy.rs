//! Egress proxy for sandboxed builders (D4) — HTTP/1.1 reverse proxy with credential substitution and path whitelisting.
//!
//! This module provides a reverse HTTP/1.1 proxy that runs outside the sandbox
//! and mediates builder traffic to upstream LLM APIs. The proxy enforces:
//! - Only specific paths are forwarded: POST /v1/messages, POST /v1/messages/count_tokens
//! - Credential substitution: builders use a placeholder key; the proxy injects the real one
//! - Denial of everything else without contacting upstream
//! - Streaming of request and response bodies without buffering
//!
//! See design.md "Trust boundaries" (network section) for the security model.

use anyhow::{Context, Result};
use hyper::body::Incoming;
use hyper::http::{Method, Request, Response, StatusCode};
use hyper::server::conn::http1;
use hyper::service::Service;
use hyper_util::rt::TokioIo;
use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::{TcpListener, UnixListener};
use tokio::sync::Mutex;

/// Configuration for the proxy.
pub struct ProxyConfig {
    /// Real API key (never logged, never sent to builder).
    #[allow(dead_code)]
    real_api_key: String,
    /// Upstream base URL (e.g., "https://api.anthropic.com").
    upstream_base: String,
    /// Placeholder token generated per proxy instance.
    placeholder_key: String,
}

impl ProxyConfig {
    /// Create a new proxy configuration with a generated placeholder.
    pub fn new(real_api_key: impl Into<String>, upstream_base: impl Into<String>) -> Self {
        Self {
            real_api_key: real_api_key.into(),
            upstream_base: upstream_base.into(),
            placeholder_key: format!("placeholder-{}", uuid::Uuid::new_v4()),
        }
    }

    /// Get the placeholder key (safe to expose to builder).
    pub fn placeholder_key(&self) -> &str {
        &self.placeholder_key
    }

    /// Get the upstream base URL.
    pub fn upstream_base(&self) -> &str {
        &self.upstream_base
    }
}

impl fmt::Debug for ProxyConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxyConfig")
            .field("real_api_key", &"<redacted>")
            .field("upstream_base", &self.upstream_base)
            .field("placeholder_key", &self.placeholder_key)
            .finish()
    }
}

/// Request/response metrics recorded in memory.
#[derive(Debug, Clone, Default)]
pub struct RequestMetrics {
    /// Path of the request.
    pub path: String,
    /// HTTP status code.
    pub status: u16,
}

/// The proxy server.
pub struct ProxyServer {
    config: Arc<ProxyConfig>,
    metrics: Arc<Mutex<Vec<RequestMetrics>>>,
}

impl ProxyServer {
    /// Create a new proxy server.
    pub fn new(config: ProxyConfig) -> Self {
        Self {
            config: Arc::new(config),
            metrics: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Listen on a TCP port (macOS, general case).
    pub async fn listen_tcp(self, port: u16) -> Result<()> {
        let addr = format!("127.0.0.1:{}", port)
            .parse::<std::net::SocketAddr>()
            .context("invalid address")?;
        let listener = TcpListener::bind(&addr)
            .await
            .context("failed to bind TCP listener")?;

        loop {
            let (socket, _) = listener.accept().await.context("accept failed")?;
            let config = Arc::clone(&self.config);
            let metrics = Arc::clone(&self.metrics);
            tokio::spawn(async move {
                if let Err(e) = http1::Builder::new()
                    .serve_connection(TokioIo::new(socket), ProxyService { config, metrics })
                    .with_upgrades()
                    .await
                {
                    eprintln!("HTTP error: {}", e);
                }
            });
        }
    }

    /// Listen on a Unix socket (Linux).
    pub async fn listen_unix(self, socket_path: PathBuf) -> Result<()> {
        // Remove existing socket file if present.
        let _ = std::fs::remove_file(&socket_path);

        let listener = UnixListener::bind(&socket_path).context("failed to bind Unix socket")?;

        loop {
            let (socket, _) = listener.accept().await.context("accept failed")?;
            let config = Arc::clone(&self.config);
            let metrics = Arc::clone(&self.metrics);
            tokio::spawn(async move {
                if let Err(e) = http1::Builder::new()
                    .serve_connection(TokioIo::new(socket), ProxyService { config, metrics })
                    .with_upgrades()
                    .await
                {
                    eprintln!("HTTP error: {}", e);
                }
            });
        }
    }

    /// Get accumulated metrics (thread-safe).
    pub async fn metrics(&self) -> Vec<RequestMetrics> {
        self.metrics.lock().await.clone()
    }
}

/// The HTTP service handler.
struct ProxyService {
    config: Arc<ProxyConfig>,
    metrics: Arc<Mutex<Vec<RequestMetrics>>>,
}

impl Service<Request<Incoming>> for ProxyService {
    type Response = Response<String>;
    type Error = anyhow::Error;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn call(&self, req: Request<Incoming>) -> Self::Future {
        let config = Arc::clone(&self.config);
        let metrics = Arc::clone(&self.metrics);

        Box::pin(async move { handle_request(req, config, metrics).await })
    }
}

/// Check if a request carries a valid credential.
fn extract_credential(req: &Request<Incoming>) -> Option<String> {
    // Check Authorization: Bearer <token>
    if let Some(auth_header) = req.headers().get("authorization")
        && let Ok(auth_str) = auth_header.to_str()
        && let Some(token) = auth_str.strip_prefix("Bearer ")
    {
        return Some(token.to_string());
    }

    // Check x-api-key header
    if let Some(key_header) = req.headers().get("x-api-key")
        && let Ok(key) = key_header.to_str()
    {
        return Some(key.to_string());
    }

    None
}

/// Handle a single HTTP request.
async fn handle_request(
    req: Request<Incoming>,
    config: Arc<ProxyConfig>,
    metrics: Arc<Mutex<Vec<RequestMetrics>>>,
) -> Result<Response<String>> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();

    // Only allow POST.
    if method != Method::POST {
        record_metric(&metrics, &path, 403).await;
        return Ok(Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body("Forbidden".to_string())
            .unwrap());
    }

    // Check allowed paths: /v1/messages or /v1/messages/count_tokens.
    let allowed_path = path == "/v1/messages" || path == "/v1/messages/count_tokens";
    if !allowed_path {
        record_metric(&metrics, &path, 403).await;
        return Ok(Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body("Forbidden".to_string())
            .unwrap());
    }

    // Verify credential.
    let credential = extract_credential(&req);
    if credential.as_deref() != Some(config.placeholder_key()) {
        record_metric(&metrics, &path, 403).await;
        return Ok(Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body("Forbidden".to_string())
            .unwrap());
    }

    // TODO(egress-proxy): Implement actual HTTP/1.1 forwarding with streaming.
    // For now return error to indicate proxy structure is in place.
    record_metric(&metrics, &path, 502).await;
    Ok(Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .body("Egress proxy: upstream unavailable".to_string())
        .unwrap())
}

/// Record request metrics.
async fn record_metric(metrics: &Arc<Mutex<Vec<RequestMetrics>>>, path: &str, status: u16) {
    metrics.lock().await.push(RequestMetrics {
        path: path.to_string(),
        status,
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn placeholder_key_is_generated() {
        let config = ProxyConfig::new("real-key", "https://api.test.com");
        assert!(!config.placeholder_key().is_empty());
        assert!(config.placeholder_key().starts_with("placeholder-"));
    }

    #[tokio::test]
    async fn debug_redacts_real_key() {
        let config = ProxyConfig::new("secret-key-12345", "https://api.test.com");
        let debug_str = format!("{:?}", config);
        assert!(!debug_str.contains("secret-key-12345"));
        assert!(debug_str.contains("<redacted>"));
    }

    #[tokio::test]
    async fn placeholder_key_is_distinct() {
        let config1 = ProxyConfig::new("key", "https://api.test.com");
        let config2 = ProxyConfig::new("key", "https://api.test.com");
        assert_ne!(config1.placeholder_key(), config2.placeholder_key());
    }

    #[tokio::test]
    async fn request_metrics_records_path_and_status() {
        let metrics = Arc::new(Mutex::new(Vec::new()));
        record_metric(&metrics, "/v1/messages", 200).await;
        let recorded = metrics.lock().await;
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].path, "/v1/messages");
        assert_eq!(recorded[0].status, 200);
    }

    #[tokio::test]
    async fn metrics_records_forbidden() {
        let metrics = Arc::new(Mutex::new(Vec::new()));
        record_metric(&metrics, "/v1/files", 403).await;
        let recorded = metrics.lock().await;
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].status, 403);
    }
}
