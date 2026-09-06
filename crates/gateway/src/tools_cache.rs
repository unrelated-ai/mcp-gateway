use crate::store::Profile;
use crate::ttl_cache::{DEFAULT_CAPACITY, TtlCache};
use rmcp::model::Tool;
use serde_json::json;
use sha2::Digest as _;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolRouteKind {
    Upstream,
    SharedLocal,
    TenantLocal,
}

#[derive(Debug, Clone)]
pub struct ToolRoute {
    pub kind: ToolRouteKind,
    pub source_id: String,
    pub original_name: String,
}

#[derive(Debug, Clone)]
pub struct CachedToolsSurface {
    pub tools: Arc<Vec<Tool>>,
    pub routes: Arc<HashMap<String, ToolRoute>>,
    /// Tool names (post-transform) that were ambiguous and therefore require prefixing.
    pub ambiguous_names: Arc<HashSet<String>>,
}

#[derive(Debug, Clone)]
struct CacheEntry {
    profile_id: String,
    profile_fingerprint: String,
    surface: CachedToolsSurface,
}

#[derive(Clone)]
pub struct ToolSurfaceCache {
    inner: Arc<TtlCache<CacheEntry>>,
}

impl ToolSurfaceCache {
    #[must_use]
    pub fn new(ttl: Duration) -> Self {
        Self {
            inner: Arc::new(TtlCache::new(ttl, DEFAULT_CAPACITY)),
        }
    }

    #[must_use]
    pub fn get(
        &self,
        session_token: &str,
        profile_fingerprint: &str,
    ) -> Option<CachedToolsSurface> {
        let entry = self.inner.get(session_token)?;
        (entry.profile_fingerprint == profile_fingerprint).then_some(entry.surface)
    }

    pub fn put(
        &self,
        profile_id: &str,
        session_token: String,
        profile_fingerprint: String,
        surface: CachedToolsSurface,
    ) {
        self.inner.put(
            session_token,
            CacheEntry {
                profile_id: profile_id.to_owned(),
                profile_fingerprint,
                surface,
            },
        );
    }

    pub fn invalidate(&self, session_token: &str) {
        self.inner.remove(session_token);
    }

    /// Best-effort cache invalidation for HA deployments.
    pub fn invalidate_profile(&self, profile_id: &str) {
        self.inner.retain(|entry| entry.profile_id != profile_id);
    }

    pub fn prune_expired(&self) -> usize {
        self.inner.prune_expired()
    }
}

#[must_use]
pub fn profile_fingerprint(profile: &Profile) -> String {
    // We only include fields that influence the exposed tool surface and routing behavior.
    let v = json!({
        "profileId": profile.id,
        "tenantId": profile.tenant_id,
        "allowPartialUpstreams": profile.allow_partial_upstreams,
        "sourceIds": profile.source_ids,
        "enabledTools": profile.enabled_tools,
        "transforms": profile.transforms,
    });
    let s = serde_json::to_string(&v).expect("profile fingerprint json serializes");
    hex::encode(sha2::Sha256::digest(s.as_bytes()))
}
