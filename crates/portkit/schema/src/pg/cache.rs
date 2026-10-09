//! Caching layer for introspection results.
//!
//! Uses [moka](https://docs.rs/moka) for a thread-safe, async-compatible cache with
//! configurable TTL. Supports explicit invalidation via Postgres NOTIFY on the
//! `postgraphile_schema_reload` channel for zero-downtime schema reloads.

use std::sync::Arc;
use std::time::Duration;

use moka::future::Cache;
use sqlx::PgPool;
use tokio::sync::broadcast;
use tracing::{info, warn};

use crate::pg::introspect::introspect;
use crate::pg::types::IntrospectionResult;

/// The Postgres NOTIFY channel used to signal schema reloads.
pub const RELOAD_CHANNEL: &str = "postgraphile_schema_reload";

/// Async cache for [`IntrospectionResult`] keyed by a schema-set string.
///
/// The cache has two invalidation mechanisms:
/// 1. **TTL** — entries expire after the configured duration.
/// 2. **NOTIFY** — listening on `postgraphile_schema_reload` evicts entries immediately.
pub struct IntrospectionCache {
    inner: Cache<String, Arc<IntrospectionResult>>,
    /// Broadcast channel used to propagate reload signals internally.
    reload_channel: broadcast::Sender<String>,
}

impl IntrospectionCache {
    /// Create a new cache with the given TTL in seconds.
    ///
    /// `max_capacity` is capped at 32 — one entry per distinct schema-set is typical.
    pub fn new(ttl_secs: u64) -> Self {
        let inner = Cache::builder()
            .time_to_live(Duration::from_secs(ttl_secs))
            .max_capacity(32)
            .build();
        let (tx, _) = broadcast::channel(16);
        Self {
            inner,
            reload_channel: tx,
        }
    }

    /// Get a cached introspection result, or run introspection and cache it.
    ///
    /// The cache key is the sorted, comma-joined list of schema names.
    pub async fn get_or_introspect(
        &self,
        pool: &PgPool,
        schemas: &[&str],
    ) -> Result<Arc<IntrospectionResult>, sqlx::Error> {
        let key = cache_key(schemas);

        if let Some(cached) = self.inner.get(&key).await {
            tracing::debug!(key = %key, "introspection cache hit");
            return Ok(cached);
        }

        tracing::debug!(key = %key, "introspection cache miss — running queries");
        let result = introspect(pool, schemas).await?;
        let arc = Arc::new(result);
        self.inner.insert(key, arc.clone()).await;
        Ok(arc)
    }

    /// Force-evict a schema from the cache. Called when a NOTIFY is received.
    pub async fn invalidate(&self, schema: &str) {
        self.inner.invalidate(schema).await;
        info!(schema = %schema, "introspection cache invalidated");
    }

    /// Evict all entries from the cache.
    pub async fn invalidate_all(&self) {
        self.inner.invalidate_all();
        info!("introspection cache fully invalidated");
    }

    /// Subscribe to reload notifications. Returns a broadcast receiver
    /// that yields the schema name (or "*" for all) on each reload signal.
    pub fn subscribe_reload(&self) -> broadcast::Receiver<String> {
        self.reload_channel.subscribe()
    }

    /// Start a background task that listens for `NOTIFY postgraphile_schema_reload`
    /// on the given pool and invalidates the cache when a notification arrives.
    ///
    /// The task runs until the pool is closed or the returned `JoinHandle` is aborted.
    pub fn spawn_listener(self: &Arc<Self>, pool: PgPool) -> tokio::task::JoinHandle<()> {
        let cache = Arc::clone(self);
        tokio::spawn(async move {
            if let Err(e) = listen_loop(&cache, &pool).await {
                warn!(error = %e, "NOTIFY listener exited with error");
            }
        })
    }
}

/// Build a deterministic cache key from schema names.
fn cache_key(schemas: &[&str]) -> String {
    let mut sorted: Vec<&str> = schemas.to_vec();
    sorted.sort_unstable();
    sorted.join(",")
}

/// Internal listen loop — acquires a raw connection and listens for NOTIFY.
async fn listen_loop(cache: &IntrospectionCache, pool: &PgPool) -> Result<(), sqlx::Error> {
    let mut listener = sqlx::postgres::PgListener::connect_with(pool).await?;
    listener.listen(RELOAD_CHANNEL).await?;
    info!(
        channel = RELOAD_CHANNEL,
        "listening for schema reload notifications"
    );

    loop {
        let notification = listener.recv().await?;
        let payload = notification.payload();

        // The payload may be a specific schema name, or empty for "all schemas".
        let target = if payload.is_empty() {
            "*".to_string()
        } else {
            payload.to_string()
        };

        info!(target = %target, "received schema reload notification");

        if target == "*" {
            cache.invalidate_all().await;
        } else {
            cache.invalidate(&target).await;
        }

        // Best-effort broadcast to any internal subscribers.
        let _ = cache.reload_channel.send(target);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_key_is_sorted_and_deterministic() {
        assert_eq!(cache_key(&["public", "auth"]), "auth,public");
        assert_eq!(cache_key(&["auth", "public"]), "auth,public");
        assert_eq!(cache_key(&["public"]), "public");
        assert_eq!(cache_key(&[]), "");
    }

    #[tokio::test]
    async fn cache_ttl_expiry() {
        // Create a cache with a very short TTL for testing.
        let cache: Cache<String, Arc<String>> = Cache::builder()
            .time_to_live(Duration::from_millis(50))
            .build();

        cache
            .insert("key".to_string(), Arc::new("value".to_string()))
            .await;

        // Should be present immediately.
        assert!(cache.get(&"key".to_string()).await.is_some());

        // Wait for TTL to expire.
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Should be evicted now.
        assert!(cache.get(&"key".to_string()).await.is_none());
    }

    #[tokio::test]
    async fn cache_explicit_invalidation() {
        let ic = IntrospectionCache::new(3600);

        // Manually insert a dummy entry.
        let dummy = Arc::new(IntrospectionResult {
            namespaces: vec![],
            classes: vec![],
            attributes: vec![],
            constraints: vec![],
            procs: vec![],
            types: vec![],
            enums: vec![],
            indexes: vec![],
            descriptions: vec![],
        });

        ic.inner.insert("public".to_string(), dummy).await;
        assert!(ic.inner.get(&"public".to_string()).await.is_some());

        ic.invalidate("public").await;
        assert!(ic.inner.get(&"public".to_string()).await.is_none());
    }

    #[tokio::test]
    async fn cache_invalidate_all() {
        let ic = IntrospectionCache::new(3600);

        let dummy = Arc::new(IntrospectionResult {
            namespaces: vec![],
            classes: vec![],
            attributes: vec![],
            constraints: vec![],
            procs: vec![],
            types: vec![],
            enums: vec![],
            indexes: vec![],
            descriptions: vec![],
        });

        ic.inner.insert("public".to_string(), dummy.clone()).await;
        ic.inner.insert("auth".to_string(), dummy).await;

        ic.invalidate_all().await;

        // moka invalidate_all is lazy — run_pending_tasks forces eviction.
        ic.inner.run_pending_tasks().await;

        assert!(ic.inner.get(&"public".to_string()).await.is_none());
        assert!(ic.inner.get(&"auth".to_string()).await.is_none());
    }

    #[test]
    fn reload_channel_subscribe() {
        let ic = IntrospectionCache::new(60);
        let mut rx = ic.subscribe_reload();

        // Send a signal and verify the subscriber receives it.
        ic.reload_channel.send("public".to_string()).unwrap();
        let msg = rx.try_recv().unwrap();
        assert_eq!(msg, "public");
    }
}
