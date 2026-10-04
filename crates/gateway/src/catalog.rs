use crate::config::{GatewayConfig, SharedSourceConfig};
use anyhow::Context as _;
use rmcp::model::{CallToolResult, Tool};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use unrelated_http_tools::runtime::HttpToolSource;
use unrelated_openapi_tools::runtime::OpenApiToolSource;

// Shared by config-file and tenant-owned native tool sources.
// Per-source configuration may override these defaults.
pub(crate) const DEFAULT_CALL_TIMEOUT: Duration = Duration::from_secs(30);
pub(crate) const DEFAULT_STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
pub(crate) const OPENAPI_PROBE_ENABLED: bool = true;
pub(crate) const OPENAPI_PROBE_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Default)]
pub struct SharedCatalog {
    inner: Arc<SharedCatalogInner>,
}

#[derive(Default)]
struct SharedCatalogInner {
    http_sources: HashMap<String, HttpToolSource>,
    openapi_sources: HashMap<String, OpenApiToolSource>,
}

impl SharedCatalog {
    /// Build a shared catalog from config-file sources.
    ///
    /// # Errors
    ///
    /// Returns an error if any enabled source configuration is invalid.
    pub async fn from_config(cfg: &GatewayConfig) -> anyhow::Result<Self> {
        let mut http_sources = HashMap::new();
        let mut openapi_sources = HashMap::new();

        // Gateway is multi-tenant: use a restrictive outbound HTTP safety policy by default,
        // with an opt-in escape hatch for local development/testing.
        let safety = crate::outbound_safety::gateway_outbound_http_safety();

        for (id, src) in &cfg.shared_sources {
            match src {
                SharedSourceConfig::Http {
                    enabled,
                    public: _public,
                    config,
                } => {
                    if !enabled {
                        continue;
                    }
                    let source = HttpToolSource::new_with_safety(
                        id.clone(),
                        config.clone(),
                        DEFAULT_CALL_TIMEOUT,
                        safety.clone(),
                    )
                    .with_context(|| format!("build http shared source '{id}'"))?;
                    http_sources.insert(id.clone(), source);
                }
                SharedSourceConfig::Openapi {
                    enabled,
                    public: _public,
                    config,
                } => {
                    if !enabled {
                        continue;
                    }
                    let source = OpenApiToolSource::build_with_safety(
                        id.clone(),
                        config.clone(),
                        DEFAULT_CALL_TIMEOUT,
                        DEFAULT_STARTUP_TIMEOUT,
                        OPENAPI_PROBE_ENABLED,
                        OPENAPI_PROBE_TIMEOUT,
                        safety.clone(),
                    )
                    .await
                    .with_context(|| format!("build openapi shared source '{id}'"))?;
                    openapi_sources.insert(id.clone(), source);
                }
            }
        }

        Ok(Self {
            inner: Arc::new(SharedCatalogInner {
                http_sources,
                openapi_sources,
            }),
        })
    }

    #[must_use]
    pub fn is_local_tool_source(&self, source_id: &str) -> bool {
        self.inner.http_sources.contains_key(source_id)
            || self.inner.openapi_sources.contains_key(source_id)
    }

    #[must_use]
    pub fn list_tools(&self, source_id: &str) -> Option<Vec<Tool>> {
        if let Some(src) = self.inner.http_sources.get(source_id) {
            return Some(src.list_tools());
        }
        self.inner
            .openapi_sources
            .get(source_id)
            .map(OpenApiToolSource::list_tools)
    }

    /// Execute a tool call against a local (gateway-native) source.
    ///
    /// # Errors
    ///
    /// Returns an error if the source or tool is unknown, or if the outbound HTTP call fails.
    pub async fn call_tool(
        &self,
        source_id: &str,
        tool_name: &str,
        arguments: Value,
    ) -> anyhow::Result<CallToolResult> {
        if let Some(src) = self.inner.http_sources.get(source_id) {
            return src
                .clone()
                .call_tool(tool_name, arguments)
                .await
                .with_context(|| format!("call local tool '{source_id}:{tool_name}'"));
        }

        if let Some(src) = self.inner.openapi_sources.get(source_id) {
            return src
                .clone()
                .call_tool(tool_name, arguments)
                .await
                .with_context(|| format!("call local tool '{source_id}:{tool_name}'"));
        }

        anyhow::bail!("unknown local tool source '{source_id}'");
    }
}
