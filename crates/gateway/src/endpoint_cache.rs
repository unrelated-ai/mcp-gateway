use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use unrelated_http_tools::config::AuthConfig;

#[derive(Debug, Clone)]
struct Entry {
    expires_at: Instant,
    endpoints: Arc<HashMap<String, UpstreamEndpoint>>,
}

#[derive(Debug, Clone)]
pub struct UpstreamEndpoint {
    pub url: String,
    pub auth: Option<AuthConfig>,
    pub network_class: crate::store::UpstreamNetworkClass,
}

#[derive(Clone)]
pub struct UpstreamEndpointCache {
    ttl: Duration,
    inner: Arc<RwLock<HashMap<String, Entry>>>,
}

impl UpstreamEndpointCache {
    #[must_use]
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            inner: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    #[must_use]
    pub fn get(&self, upstream_id: &str, endpoint_id: &str) -> Option<UpstreamEndpoint> {
        let now = Instant::now();
        let mut map = self.inner.write();
        let entry = map.get(upstream_id)?;
        if entry.expires_at <= now {
            map.remove(upstream_id);
            return None;
        }
        entry.endpoints.get(endpoint_id).cloned()
    }

    pub fn put(&self, upstream_id: String, endpoints: HashMap<String, UpstreamEndpoint>) {
        let expires_at = Instant::now() + self.ttl;
        self.inner.write().insert(
            upstream_id,
            Entry {
                expires_at,
                endpoints: Arc::new(endpoints),
            },
        );
    }

    /// Best-effort cache invalidation for HA deployments.
    pub fn invalidate_upstream(&self, upstream_id: &str) {
        self.inner.write().remove(upstream_id);
    }
}
