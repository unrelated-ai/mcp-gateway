use crate::ttl_cache::{DEFAULT_CAPACITY, TtlCache};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use unrelated_http_tools::config::AuthConfig;

#[derive(Debug, Clone)]
struct Entry {
    endpoints: Arc<HashMap<String, UpstreamEndpoint>>,
}

#[derive(Debug, Clone)]
pub struct UpstreamEndpoint {
    pub url: String,
    pub auth: Option<AuthConfig>,
}

#[derive(Clone)]
pub struct UpstreamEndpointCache {
    inner: Arc<TtlCache<Entry>>,
}

impl UpstreamEndpointCache {
    #[must_use]
    pub fn new(ttl: Duration) -> Self {
        Self {
            inner: Arc::new(TtlCache::new(ttl, DEFAULT_CAPACITY)),
        }
    }

    #[must_use]
    pub fn get(&self, upstream_id: &str, endpoint_id: &str) -> Option<UpstreamEndpoint> {
        self.inner
            .get(upstream_id)?
            .endpoints
            .get(endpoint_id)
            .cloned()
    }

    pub fn put(&self, upstream_id: String, endpoints: HashMap<String, UpstreamEndpoint>) {
        self.inner.put(
            upstream_id,
            Entry {
                endpoints: Arc::new(endpoints),
            },
        );
    }

    /// Best-effort cache invalidation for HA deployments.
    pub fn invalidate_upstream(&self, upstream_id: &str) {
        self.inner.remove(upstream_id);
    }

    pub fn prune_expired(&self) -> usize {
        self.inner.prune_expired()
    }
}
