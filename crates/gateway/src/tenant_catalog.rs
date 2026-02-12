use crate::store::{Store, ToolSourceKind, ToolSourceSpec};
use anyhow::Context as _;
use parking_lot::RwLock;
use rmcp::model::{CallToolResult, Tool};
use serde_json::Value;
use sha2::Digest as _;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use unrelated_http_tools::config::AuthConfig;
use unrelated_http_tools::runtime::HttpToolSource;
use unrelated_http_tools::safety::OutboundHttpSafety;
use unrelated_openapi_tools::runtime::OpenApiToolSource;

#[derive(Clone)]
pub struct TenantCatalog {
    inner: Arc<TenantCatalogInner>,
}

struct TenantCatalogInner {
    cache: RwLock<HashMap<(String, String), CachedSource>>,
    safety: OutboundHttpSafety,
    default_timeout: Duration,
    startup_timeout: Duration,
    openapi_probe_enabled: bool,
    openapi_probe_timeout: Duration,
}

#[derive(Clone)]
enum CachedSource {
    Http {
        spec_hash: String,
        source: HttpToolSource,
    },
    Openapi {
        spec_hash: String,
        source: Box<OpenApiToolSource>,
    },
}

impl TenantCatalog {
    #[must_use]
    pub fn new() -> Self {
        Self::new_with_safety(crate::outbound_safety::gateway_outbound_http_safety())
    }

    #[must_use]
    pub fn new_with_safety(safety: OutboundHttpSafety) -> Self {
        Self {
            inner: Arc::new(TenantCatalogInner {
                cache: RwLock::new(HashMap::new()),
                safety,
                default_timeout: Duration::from_secs(30),
                startup_timeout: Duration::from_secs(30),
                openapi_probe_enabled: true,
                openapi_probe_timeout: Duration::from_secs(5),
            }),
        }
    }

    /// Check whether a tenant-owned local source exists and is enabled.
    ///
    /// # Errors
    ///
    /// Returns an error if the store access fails or a stored spec is invalid.
    pub async fn has_tool_source(
        &self,
        store: &dyn Store,
        tenant_id: &str,
        source_id: &str,
    ) -> anyhow::Result<bool> {
        Ok(store
            .get_tenant_tool_source(tenant_id, source_id)
            .await?
            .is_some_and(|s| s.enabled))
    }

    /// List tools for a tenant-owned local source.
    pub async fn list_tools(
        &self,
        store: &dyn Store,
        tenant_id: &str,
        source_id: &str,
    ) -> anyhow::Result<Option<Vec<Tool>>> {
        let Some(source) = Box::pin(self.ensure_source(store, tenant_id, source_id))
            .await
            .with_context(|| format!("ensure tenant source '{source_id}'"))?
        else {
            return Ok(None);
        };

        Ok(Some(match source {
            CachedSource::Http { source, .. } => source.list_tools(),
            CachedSource::Openapi { source, .. } => source.list_tools(),
        }))
    }

    /// Execute a tool call for a tenant-owned local source.
    pub async fn call_tool(
        &self,
        store: &dyn Store,
        tenant_id: &str,
        source_id: &str,
        tool_name: &str,
        arguments: Value,
    ) -> anyhow::Result<CallToolResult> {
        let Some(source) = Box::pin(self.ensure_source(store, tenant_id, source_id))
            .await
            .with_context(|| format!("ensure tenant source '{source_id}'"))?
        else {
            anyhow::bail!("unknown tenant tool source '{source_id}'");
        };

        match source {
            CachedSource::Http { source, .. } => Ok(source
                .call_tool(tool_name, arguments)
                .await
                .map_err(|e| anyhow::anyhow!(e.to_string()))?),
            CachedSource::Openapi { source, .. } => Ok(source
                .call_tool(tool_name, arguments)
                .await
                .map_err(|e| anyhow::anyhow!(e.to_string()))?),
        }
    }

    async fn ensure_source(
        &self,
        store: &dyn Store,
        tenant_id: &str,
        source_id: &str,
    ) -> anyhow::Result<Option<CachedSource>> {
        let Some(spec) = store.get_tenant_tool_source(tenant_id, source_id).await? else {
            return Ok(None);
        };
        if !spec.enabled {
            return Ok(None);
        }

        let key = (tenant_id.to_string(), source_id.to_string());

        match (spec.kind, spec.spec) {
            (ToolSourceKind::Http, ToolSourceSpec::Http(mut cfg)) => {
                resolve_auth_secrets(store, tenant_id, cfg.auth.as_mut()).await?;
                let spec_hash = hash_json(&cfg)?;

                // Fast path: if cached and hash matches, reuse (avoid rebuilding).
                if let Some(existing) = self.inner.cache.read().get(&key).cloned()
                    && matches!(&existing, CachedSource::Http { spec_hash: h, .. } if h == &spec_hash)
                {
                    return Ok(Some(existing));
                }

                let built = HttpToolSource::new_with_safety(
                    source_id.to_string(),
                    cfg,
                    self.inner.default_timeout,
                    self.inner.safety.clone(),
                )
                .map_err(|e| anyhow::anyhow!(e.to_string()))?;

                let stored = CachedSource::Http {
                    spec_hash,
                    source: built,
                };
                self.inner.cache.write().insert(key, stored.clone());
                Ok(Some(stored))
            }
            (ToolSourceKind::Openapi, ToolSourceSpec::Openapi(mut cfg)) => {
                resolve_auth_secrets(store, tenant_id, cfg.auth.as_mut()).await?;
                let spec_hash = hash_json(&cfg)?;

                // Fast path: if cached and hash matches, reuse (avoid rebuilding).
                if let Some(existing) = self.inner.cache.read().get(&key).cloned()
                    && matches!(&existing, CachedSource::Openapi { spec_hash: h, .. } if h == &spec_hash)
                {
                    return Ok(Some(existing));
                }

                let built = OpenApiToolSource::build_with_safety(
                    source_id.to_string(),
                    cfg,
                    self.inner.default_timeout,
                    self.inner.startup_timeout,
                    self.inner.openapi_probe_enabled,
                    self.inner.openapi_probe_timeout,
                    self.inner.safety.clone(),
                )
                .await
                .map_err(|e| anyhow::anyhow!(e.to_string()))?;

                let stored = CachedSource::Openapi {
                    spec_hash,
                    source: Box::new(built),
                };
                self.inner.cache.write().insert(key, stored.clone());
                Ok(Some(stored))
            }
            (kind, _) => {
                anyhow::bail!("tool source kind/spec mismatch for '{source_id}': {kind:?}")
            }
        }
    }

    /// Best-effort cache invalidation for HA deployments.
    ///
    /// Removes any cached tool runtimes for the given tenant.
    pub fn invalidate_tenant(&self, tenant_id: &str) {
        let mut cache = self.inner.cache.write();
        cache.retain(|(t, _), _| t != tenant_id);
    }

    /// Best-effort cache invalidation for HA deployments.
    ///
    /// Removes a single cached tool runtime for a tenant-owned source.
    pub fn invalidate_source(&self, tenant_id: &str, source_id: &str) {
        self.inner
            .cache
            .write()
            .remove(&(tenant_id.to_string(), source_id.to_string()));
    }
}

async fn resolve_auth_secrets(
    store: &dyn Store,
    tenant_id: &str,
    auth: Option<&mut AuthConfig>,
) -> anyhow::Result<()> {
    let Some(auth) = auth else {
        return Ok(());
    };

    match auth {
        AuthConfig::None => Ok(()),
        AuthConfig::Bearer { token } => resolve_secret_ref(store, tenant_id, token).await,
        AuthConfig::Header { value, .. } | AuthConfig::Query { value, .. } => {
            resolve_secret_ref(store, tenant_id, value).await
        }
        AuthConfig::Basic { password, .. } => resolve_secret_ref(store, tenant_id, password).await,
    }
}

fn parse_secret_ref(s: &str) -> Option<&str> {
    s.strip_prefix("${secret:")?.strip_suffix('}')
}

async fn resolve_secret_ref(
    store: &dyn Store,
    tenant_id: &str,
    s: &mut String,
) -> anyhow::Result<()> {
    let Some(name) = parse_secret_ref(s.as_str()) else {
        return Ok(());
    };
    let secret = store
        .get_tenant_secret_value(tenant_id, name)
        .await?
        .ok_or_else(|| anyhow::anyhow!("missing secret '{name}'"))?;
    *s = secret;
    Ok(())
}

fn hash_json<T: serde::Serialize>(v: &T) -> anyhow::Result<String> {
    let bytes = serde_json::to_vec(v)?;
    Ok(hex::encode(sha2::Sha256::digest(bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use parking_lot::Mutex;
    use std::sync::Arc;
    use unrelated_http_tools::config as http_tools;

    #[derive(Clone, Default)]
    struct FakeStore {
        // mutable store for tests; not async-safe but sufficient here
        source: Arc<Mutex<Option<crate::store::TenantToolSource>>>,
        secrets: Arc<Mutex<std::collections::HashMap<String, String>>>,
    }

    impl FakeStore {
        fn set_source(&self, s: crate::store::TenantToolSource) {
            *self.source.lock() = Some(s);
        }

        fn clear_source(&self) {
            *self.source.lock() = None;
        }

        fn put_secret(&self, name: &str, value: &str) {
            self.secrets
                .lock()
                .insert(name.to_string(), value.to_string());
        }
    }

    #[async_trait]
    impl Store for FakeStore {
        async fn get_profile(
            &self,
            _profile_id: &str,
        ) -> anyhow::Result<Option<crate::store::Profile>> {
            Ok(None)
        }

        async fn get_upstream(
            &self,
            _upstream_id: &str,
        ) -> anyhow::Result<Option<crate::store::Upstream>> {
            Ok(None)
        }

        async fn get_tenant_tool_source(
            &self,
            _tenant_id: &str,
            _source_id: &str,
        ) -> anyhow::Result<Option<crate::store::TenantToolSource>> {
            Ok(self.source.lock().clone())
        }

        async fn get_tenant_secret_value(
            &self,
            _tenant_id: &str,
            name: &str,
        ) -> anyhow::Result<Option<String>> {
            Ok(self.secrets.lock().get(name).cloned())
        }

        async fn get_tenant_transport_limits(
            &self,
            _tenant_id: &str,
        ) -> anyhow::Result<Option<crate::store::TransportLimitsSettings>> {
            Ok(None)
        }

        async fn authenticate_api_key(
            &self,
            _tenant_id: &str,
            _profile_id: &str,
            _secret: &str,
        ) -> anyhow::Result<Option<crate::store::ApiKeyAuth>> {
            Ok(None)
        }

        async fn is_api_key_active(
            &self,
            _tenant_id: &str,
            _api_key_id: &str,
        ) -> anyhow::Result<bool> {
            Ok(false)
        }

        async fn touch_api_key(&self, _tenant_id: &str, _api_key_id: &str) -> anyhow::Result<()> {
            Ok(())
        }

        async fn record_tool_call_attempt(
            &self,
            _tenant_id: &str,
            _api_key_id: &str,
        ) -> anyhow::Result<()> {
            Ok(())
        }

        async fn check_and_apply_tool_call_limits(
            &self,
            _tenant_id: &str,
            _profile_id: &str,
            _api_key_id: &str,
            _rate_limit_tool_calls_per_minute: Option<i64>,
            _quota_tool_calls: Option<i64>,
        ) -> anyhow::Result<Option<crate::store::ToolCallLimitRejection>> {
            Ok(None)
        }

        async fn is_oidc_principal_allowed(
            &self,
            _tenant_id: &str,
            _profile_id: &str,
            _issuer: &str,
            _subject: &str,
        ) -> anyhow::Result<bool> {
            Ok(false)
        }
    }

    #[test]
    fn parse_secret_ref_accepts_expected_format() {
        assert_eq!(parse_secret_ref("${secret:api_token}"), Some("api_token"));
        assert_eq!(parse_secret_ref("${secret:}"), Some(""));
    }

    #[test]
    fn parse_secret_ref_rejects_non_matching_strings() {
        assert_eq!(parse_secret_ref("secret:api_token"), None);
        assert_eq!(parse_secret_ref("${SECRET:api_token}"), None);
        assert_eq!(parse_secret_ref("${secret:api_token"), None);
        assert_eq!(parse_secret_ref("}"), None);
    }

    #[tokio::test]
    async fn tenant_http_source_missing_secret_causes_list_tools_error_then_succeeds()
    -> anyhow::Result<()> {
        let store = FakeStore::default();
        let catalog = TenantCatalog::new();

        let cfg = http_tools::HttpServerConfig {
            base_url: "https://example.com".to_string(),
            auth: Some(http_tools::AuthConfig::Bearer {
                token: "${secret:api_token}".to_string(),
            }),
            defaults: http_tools::EndpointDefaults::default(),
            response_transforms: vec![],
            tools: std::collections::HashMap::from([(
                "ping".to_string(),
                http_tools::HttpToolConfig {
                    method: "GET".to_string(),
                    path: "/ping".to_string(),
                    description: None,
                    params: std::collections::HashMap::new(),
                    response: http_tools::HttpResponseConfig::default(),
                },
            )]),
        };

        store.set_source(crate::store::TenantToolSource {
            id: "s1".to_string(),
            kind: crate::store::ToolSourceKind::Http,
            enabled: true,
            spec: crate::store::ToolSourceSpec::Http(cfg.clone()),
        });

        let err = catalog.list_tools(&store, "t1", "s1").await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("missing secret 'api_token'"), "err={msg}");

        store.put_secret("api_token", "secret-value");
        let tools = catalog
            .list_tools(&store, "t1", "s1")
            .await?
            .expect("tools");
        let names: Vec<String> = tools.into_iter().map(|t| t.name.into_owned()).collect();
        assert_eq!(names, vec!["ping".to_string()]);

        // Ensure we didn't mutate the original cfg in the store.
        if let Some(crate::store::TenantToolSource {
            spec: crate::store::ToolSourceSpec::Http(cfg2),
            ..
        }) = store.get_tenant_tool_source("t1", "s1").await?
        {
            let http_tools::AuthConfig::Bearer { token } = cfg2.auth.unwrap() else {
                panic!("expected bearer auth");
            };
            assert_eq!(token, "${secret:api_token}");
        } else {
            panic!("expected http source in store");
        }
        Ok(())
    }

    #[tokio::test]
    async fn tenant_http_source_rebuilds_when_spec_changes() -> anyhow::Result<()> {
        let store = FakeStore::default();
        let catalog = TenantCatalog::new();

        // v0: tool_a + tool_b
        store.set_source(crate::store::TenantToolSource {
            id: "s1".to_string(),
            kind: crate::store::ToolSourceKind::Http,
            enabled: true,
            spec: crate::store::ToolSourceSpec::Http(http_tools::HttpServerConfig {
                base_url: "https://example.com".to_string(),
                auth: None,
                defaults: http_tools::EndpointDefaults::default(),
                response_transforms: vec![],
                tools: std::collections::HashMap::from([
                    (
                        "tool_a".to_string(),
                        http_tools::HttpToolConfig {
                            method: "GET".to_string(),
                            path: "/a".to_string(),
                            description: None,
                            params: std::collections::HashMap::new(),
                            response: http_tools::HttpResponseConfig::default(),
                        },
                    ),
                    (
                        "tool_b".to_string(),
                        http_tools::HttpToolConfig {
                            method: "GET".to_string(),
                            path: "/b".to_string(),
                            description: None,
                            params: std::collections::HashMap::new(),
                            response: http_tools::HttpResponseConfig::default(),
                        },
                    ),
                ]),
            }),
        });

        let tools = catalog
            .list_tools(&store, "t1", "s1")
            .await?
            .expect("tools");
        let mut names: Vec<String> = tools.into_iter().map(|t| t.name.into_owned()).collect();
        names.sort();
        assert_eq!(names, vec!["tool_a".to_string(), "tool_b".to_string()]);

        // v1: drop tool_b
        store.set_source(crate::store::TenantToolSource {
            id: "s1".to_string(),
            kind: crate::store::ToolSourceKind::Http,
            enabled: true,
            spec: crate::store::ToolSourceSpec::Http(http_tools::HttpServerConfig {
                base_url: "https://example.com".to_string(),
                auth: None,
                defaults: http_tools::EndpointDefaults::default(),
                response_transforms: vec![],
                tools: std::collections::HashMap::from([(
                    "tool_a".to_string(),
                    http_tools::HttpToolConfig {
                        method: "GET".to_string(),
                        path: "/a".to_string(),
                        description: None,
                        params: std::collections::HashMap::new(),
                        response: http_tools::HttpResponseConfig::default(),
                    },
                )]),
            }),
        });

        let tools = catalog
            .list_tools(&store, "t1", "s1")
            .await?
            .expect("tools");
        let mut names: Vec<String> = tools.into_iter().map(|t| t.name.into_owned()).collect();
        names.sort();
        assert_eq!(names, vec!["tool_a".to_string()]);

        // disabling or removing the source yields None
        store.clear_source();
        let none = catalog.list_tools(&store, "t1", "s1").await?;
        assert!(none.is_none());

        Ok(())
    }
}
