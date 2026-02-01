use crate::config::{GatewayConfig, Mode1AuthMode, ProfileConfig, UpstreamConfig};
use crate::tool_policy::ToolPolicy;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;
use unrelated_http_tools::config::AuthConfig;
use unrelated_http_tools::config::HttpServerConfig;
use unrelated_openapi_tools::config::ApiServerConfig;
use unrelated_tool_transforms::TransformPipeline;

use sha2::Digest as _;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct McpProfileSettings {
    /// Control which MCP server capabilities the Gateway advertises (and enforces).
    #[serde(default)]
    pub capabilities: McpCapabilitiesPolicy,
    /// Server→client notification filtering (for the merged SSE stream).
    #[serde(default)]
    pub notifications: McpNotificationFilter,
    /// Namespacing / collision-handling policy for IDs in the merged SSE stream.
    #[serde(default)]
    pub namespacing: McpNamespacing,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct McpCapabilitiesPolicy {
    /// If non-empty, acts as an allowlist overriding defaults.
    #[serde(default)]
    pub allow: Vec<McpCapability>,
    /// Denylist applied after defaults / allowlist.
    #[serde(default)]
    pub deny: Vec<McpCapability>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum McpCapability {
    Logging,
    Completions,
    ResourcesSubscribe,
    ToolsListChanged,
    ResourcesListChanged,
    PromptsListChanged,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct EffectiveMcpCapabilities(u32);

impl EffectiveMcpCapabilities {
    const LOGGING: u32 = 1 << 0;
    const COMPLETIONS: u32 = 1 << 1;
    const RESOURCES_SUBSCRIBE: u32 = 1 << 2;
    const TOOLS_LIST_CHANGED: u32 = 1 << 3;
    const RESOURCES_LIST_CHANGED: u32 = 1 << 4;
    const PROMPTS_LIST_CHANGED: u32 = 1 << 5;

    fn set(&mut self, bit: u32, enabled: bool) {
        if enabled {
            self.0 |= bit;
        } else {
            self.0 &= !bit;
        }
    }

    pub fn logging(self) -> bool {
        (self.0 & Self::LOGGING) != 0
    }

    pub fn completions(self) -> bool {
        (self.0 & Self::COMPLETIONS) != 0
    }

    pub fn resources_subscribe(self) -> bool {
        (self.0 & Self::RESOURCES_SUBSCRIBE) != 0
    }

    pub fn tools_list_changed(self) -> bool {
        (self.0 & Self::TOOLS_LIST_CHANGED) != 0
    }

    pub fn resources_list_changed(self) -> bool {
        (self.0 & Self::RESOURCES_LIST_CHANGED) != 0
    }

    pub fn prompts_list_changed(self) -> bool {
        (self.0 & Self::PROMPTS_LIST_CHANGED) != 0
    }
}

impl McpCapabilitiesPolicy {
    pub fn effective(&self) -> EffectiveMcpCapabilities {
        // Defaults: match current Gateway behavior (advertise everything we proxy).
        let mut e = EffectiveMcpCapabilities::default();
        e.set(EffectiveMcpCapabilities::LOGGING, true);
        e.set(EffectiveMcpCapabilities::COMPLETIONS, true);
        e.set(EffectiveMcpCapabilities::RESOURCES_SUBSCRIBE, true);
        e.set(EffectiveMcpCapabilities::TOOLS_LIST_CHANGED, true);
        e.set(EffectiveMcpCapabilities::RESOURCES_LIST_CHANGED, true);
        e.set(EffectiveMcpCapabilities::PROMPTS_LIST_CHANGED, true);

        // Allowlist (if present) overrides defaults.
        if !self.allow.is_empty() {
            e = EffectiveMcpCapabilities::default();
            for c in &self.allow {
                match c {
                    McpCapability::Logging => e.set(EffectiveMcpCapabilities::LOGGING, true),
                    McpCapability::Completions => {
                        e.set(EffectiveMcpCapabilities::COMPLETIONS, true);
                    }
                    McpCapability::ResourcesSubscribe => {
                        e.set(EffectiveMcpCapabilities::RESOURCES_SUBSCRIBE, true);
                    }
                    McpCapability::ToolsListChanged => {
                        e.set(EffectiveMcpCapabilities::TOOLS_LIST_CHANGED, true);
                    }
                    McpCapability::ResourcesListChanged => {
                        e.set(EffectiveMcpCapabilities::RESOURCES_LIST_CHANGED, true);
                    }
                    McpCapability::PromptsListChanged => {
                        e.set(EffectiveMcpCapabilities::PROMPTS_LIST_CHANGED, true);
                    }
                }
            }
        }

        // Denylist.
        for c in &self.deny {
            match c {
                McpCapability::Logging => e.set(EffectiveMcpCapabilities::LOGGING, false),
                McpCapability::Completions => e.set(EffectiveMcpCapabilities::COMPLETIONS, false),
                McpCapability::ResourcesSubscribe => {
                    e.set(EffectiveMcpCapabilities::RESOURCES_SUBSCRIBE, false);
                }
                McpCapability::ToolsListChanged => {
                    e.set(EffectiveMcpCapabilities::TOOLS_LIST_CHANGED, false);
                }
                McpCapability::ResourcesListChanged => {
                    e.set(EffectiveMcpCapabilities::RESOURCES_LIST_CHANGED, false);
                }
                McpCapability::PromptsListChanged => {
                    e.set(EffectiveMcpCapabilities::PROMPTS_LIST_CHANGED, false);
                }
            }
        }

        e
    }
}

#[cfg(test)]
mod tests {
    use super::{McpCapabilitiesPolicy, McpCapability};

    #[test]
    fn mcp_caps_defaults_all_on() {
        let caps = McpCapabilitiesPolicy::default().effective();
        assert!(caps.logging());
        assert!(caps.completions());
        assert!(caps.resources_subscribe());
        assert!(caps.tools_list_changed());
        assert!(caps.resources_list_changed());
        assert!(caps.prompts_list_changed());
    }

    #[test]
    fn mcp_caps_allowlist_overrides_defaults() {
        let caps = McpCapabilitiesPolicy {
            allow: vec![McpCapability::Logging],
            deny: vec![],
        }
        .effective();
        assert!(caps.logging());
        assert!(!caps.completions());
        assert!(!caps.resources_subscribe());
        assert!(!caps.tools_list_changed());
        assert!(!caps.resources_list_changed());
        assert!(!caps.prompts_list_changed());
    }

    #[test]
    fn mcp_caps_deny_overrides_allow() {
        let caps = McpCapabilitiesPolicy {
            allow: vec![McpCapability::Logging],
            deny: vec![McpCapability::Logging],
        }
        .effective();
        assert!(!caps.logging());
    }

    #[tokio::test]
    async fn mode1_data_plane_auth_none_maps_to_disabled() -> anyhow::Result<()> {
        use super::Store as _;
        use crate::config::{GatewayConfig, Mode1AuthMode, ProfileConfig};

        let profile_id = uuid::Uuid::new_v4().to_string();
        let cfg = GatewayConfig {
            tenants: std::collections::HashMap::from([(
                "t1".to_string(),
                crate::config::TenantConfig { enabled: true },
            )]),
            profiles: std::collections::HashMap::from([(
                profile_id.clone(),
                ProfileConfig {
                    tenant_id: "t1".to_string(),
                    allow_partial_upstreams: true,
                    upstreams: vec![],
                    transforms: unrelated_tool_transforms::TransformPipeline::default(),
                    tools: None,
                    tool_call_timeout_secs: None,
                    tool_policies: vec![],
                    mcp: crate::store::McpProfileSettings::default(),
                },
            )]),
            upstreams: std::collections::HashMap::new(),
            data_plane_auth: crate::config::DataPlaneAuthConfig {
                mode: Mode1AuthMode::None,
                api_keys: vec![],
                accept_x_api_key: true,
                require_every_request: false,
            },
            shared_sources: std::collections::HashMap::new(),
        };

        let store = super::ConfigStore::new(cfg);
        let p = store.get_profile(&profile_id).await?.expect("profile");
        assert_eq!(
            p.data_plane_auth_mode,
            crate::store::DataPlaneAuthMode::Disabled
        );
        Ok(())
    }

    #[tokio::test]
    async fn mode1_static_api_keys_maps_require_every_request_and_accept_x_api_key()
    -> anyhow::Result<()> {
        use super::Store as _;
        use crate::config::{GatewayConfig, Mode1AuthMode, ProfileConfig};

        let profile_id = uuid::Uuid::new_v4().to_string();
        let cfg = GatewayConfig {
            tenants: std::collections::HashMap::from([(
                "t1".to_string(),
                crate::config::TenantConfig { enabled: true },
            )]),
            profiles: std::collections::HashMap::from([(
                profile_id.clone(),
                ProfileConfig {
                    tenant_id: "t1".to_string(),
                    allow_partial_upstreams: true,
                    upstreams: vec![],
                    transforms: unrelated_tool_transforms::TransformPipeline::default(),
                    tools: None,
                    tool_call_timeout_secs: None,
                    tool_policies: vec![],
                    mcp: crate::store::McpProfileSettings::default(),
                },
            )]),
            upstreams: std::collections::HashMap::new(),
            data_plane_auth: crate::config::DataPlaneAuthConfig {
                mode: Mode1AuthMode::StaticApiKeys,
                api_keys: vec!["k1".to_string()],
                accept_x_api_key: false,
                require_every_request: true,
            },
            shared_sources: std::collections::HashMap::new(),
        };

        let store = super::ConfigStore::new(cfg);
        let p = store.get_profile(&profile_id).await?.expect("profile");
        assert_eq!(
            p.data_plane_auth_mode,
            crate::store::DataPlaneAuthMode::ApiKeyEveryRequest
        );
        assert!(!p.accept_x_api_key);
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct McpNotificationFilter {
    /// If non-empty, only notifications with these methods are forwarded.
    ///
    /// Example values:
    /// - `notifications/message`
    /// - `notifications/progress`
    /// - `notifications/resources/updated`
    /// - `notifications/cancelled`
    /// - `notifications/tools/list_changed`
    #[serde(default)]
    pub allow: Vec<String>,
    /// Notifications with these methods are dropped.
    #[serde(default)]
    pub deny: Vec<String>,
}

impl McpNotificationFilter {
    pub fn allows(&self, method: &str) -> bool {
        if !self.allow.is_empty() {
            return self.allow.iter().any(|m| m == method);
        }
        !self.deny.iter().any(|m| m == method)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum RequestIdNamespacing {
    /// Current format: `unrelated.proxy.<b64(upstream_id)>.<b64(json(request_id))>`.
    #[serde(rename = "opaque")]
    #[default]
    Opaque,
    /// More readable upstream id, with the request id still encoded:
    /// `unrelated.proxy.r.<upstream_id>.<b64(json(request_id))>`.
    ///
    /// Note: upstream id is used as-is; avoid dots in upstream ids if you rely on parsing/debugging.
    #[serde(rename = "readable")]
    Readable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum SseEventIdNamespacing {
    /// Current format: `{upstream_id}/{upstream_event_id}`.
    #[serde(rename = "upstream-slash")]
    #[default]
    UpstreamSlash,
    /// Do not modify upstream event ids (may collide across upstreams).
    #[serde(rename = "none")]
    None,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct McpNamespacing {
    #[serde(default)]
    pub request_id: RequestIdNamespacing,
    #[serde(default)]
    pub sse_event_id: SseEventIdNamespacing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DataPlaneAuthMode {
    /// No auth required on the data plane for this profile.
    Disabled,
    /// API key required only for `initialize`. Subsequent requests rely on the session token.
    ApiKeyInitializeOnly,
    /// API key required on every data-plane request (in addition to the session token).
    ApiKeyEveryRequest,
    /// OIDC/JWT required on every data-plane request (POST/GET/DELETE).
    JwtEveryRequest,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone)]
pub struct Profile {
    pub id: String,
    pub tenant_id: String,
    pub allow_partial_upstreams: bool,
    /// A profile's configured "sources" list.
    ///
    /// This is a mixed list that can include:
    /// - remote upstream MCP servers (`upstreams`), and
    /// - gateway-local shared sources (`sharedSources`), and
    /// - tenant-owned sources (Mode 3).
    pub source_ids: Vec<String>,
    pub transforms: TransformPipeline,
    /// Per-profile tool allowlist (see `config::ProfileConfig.tools`).
    ///
    /// Semantics: empty list => no allowlist configured (allow all tools).
    pub enabled_tools: Vec<String>,
    /// Per-profile data-plane auth policy (Mode 3; optional in Mode 1).
    pub data_plane_auth_mode: DataPlaneAuthMode,
    /// If enabled, accept `x-api-key: <secret>` as an alias for `Authorization: Bearer <secret>`.
    pub accept_x_api_key: bool,
    /// Optional per-profile rate limit config (Mode 3). Disabled by default.
    pub rate_limit_enabled: bool,
    pub rate_limit_tool_calls_per_minute: Option<i64>,
    /// Optional per-profile quota config (Mode 3). Disabled by default.
    pub quota_enabled: bool,
    pub quota_tool_calls: Option<i64>,

    /// Optional per-profile default timeout override for `tools/call` (seconds).
    pub tool_call_timeout_secs: Option<u64>,
    /// Optional per-profile per-tool policy overrides (timeouts + retry policy).
    pub tool_policies: Vec<ToolPolicy>,

    /// MCP proxy behavior settings for this profile (capabilities, notifications, namespacing).
    pub mcp: McpProfileSettings,
}

#[derive(Debug, Clone)]
pub struct Upstream {
    pub endpoints: Vec<UpstreamEndpoint>,
}

#[derive(Debug, Clone)]
pub struct UpstreamEndpoint {
    pub id: String,
    pub url: String,
    pub auth: Option<AuthConfig>,
}

#[derive(Debug, Clone)]
pub struct AdminTenant {
    pub id: String,
    pub enabled: bool,
}

#[derive(Debug, Clone)]
pub struct AdminUpstreamEndpoint {
    pub id: String,
    pub url: String,
    pub enabled: bool,
    pub auth: Option<AuthConfig>,
}

#[derive(Debug, Clone)]
pub struct AdminUpstream {
    pub id: String,
    pub enabled: bool,
    pub endpoints: Vec<AdminUpstreamEndpoint>,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone)]
pub struct AdminProfile {
    pub id: String,
    /// Human-friendly profile name (unique per tenant, case-insensitive).
    pub name: String,
    /// Optional human-friendly description.
    pub description: Option<String>,
    pub tenant_id: String,
    pub enabled: bool,
    pub allow_partial_upstreams: bool,
    pub upstream_ids: Vec<String>,
    /// Local tool source ids attached to this profile (shared + tenant-owned).
    pub source_ids: Vec<String>,
    pub transforms: TransformPipeline,
    pub enabled_tools: Vec<String>,
    pub data_plane_auth_mode: DataPlaneAuthMode,
    pub accept_x_api_key: bool,
    pub rate_limit_enabled: bool,
    pub rate_limit_tool_calls_per_minute: Option<i64>,
    pub quota_enabled: bool,
    pub quota_tool_calls: Option<i64>,

    pub tool_call_timeout_secs: Option<u64>,
    pub tool_policies: Vec<ToolPolicy>,

    pub mcp: McpProfileSettings,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolSourceKind {
    Http,
    Openapi,
}

#[derive(Debug, Clone)]
pub enum ToolSourceSpec {
    Http(HttpServerConfig),
    Openapi(ApiServerConfig),
}

#[derive(Debug, Clone)]
pub struct TenantToolSource {
    pub id: String,
    pub kind: ToolSourceKind,
    pub enabled: bool,
    pub spec: ToolSourceSpec,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantSecretMetadata {
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OidcPrincipalBinding {
    pub issuer: String,
    pub subject: String,
    pub profile_id: Option<String>,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiKeyMetadata {
    pub id: String,
    pub name: String,
    pub prefix: String,
    pub profile_id: Option<String>,
    pub revoked_at_unix: Option<i64>,
    pub last_used_at_unix: Option<i64>,
    pub total_tool_calls_attempted: i64,
    pub total_requests_attempted: i64,
    pub created_at_unix: i64,
}

#[derive(Debug, Clone)]
pub struct ApiKeyAuth {
    pub api_key_id: String,
    pub tenant_id: String,
}

#[derive(Debug, Clone)]
pub enum ToolCallLimitRejection {
    RateLimited { retry_after_secs: Option<u64> },
    QuotaExceeded,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantAuditSettings {
    pub enabled: bool,
    pub retention_days: i32,
    pub default_level: String,
}

#[derive(Debug, Clone)]
pub struct AuditEventFilter {
    pub from_unix_secs: Option<i64>,
    pub to_unix_secs: Option<i64>,
    pub before_id: Option<i64>,
    pub profile_id: Option<String>,
    pub api_key_id: Option<String>,
    pub tool_ref: Option<String>,
    pub action: Option<String>,
    pub ok: Option<bool>,
    pub limit: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditEventRow {
    pub id: i64,
    pub ts_unix_secs: i64,
    pub tenant_id: String,
    pub profile_id: Option<String>,
    pub api_key_id: Option<String>,
    pub oidc_issuer: Option<String>,
    pub oidc_subject: Option<String>,
    pub action: String,
    pub http_method: Option<String>,
    pub http_route: Option<String>,
    pub status_code: Option<i32>,
    pub tool_ref: Option<String>,
    pub tool_name_at_time: Option<String>,
    pub ok: bool,
    pub duration_ms: Option<i64>,
    pub error_kind: Option<String>,
    pub error_message: Option<String>,
    pub meta: Value,
}

#[derive(Debug, Clone)]
pub struct AuditStatsFilter {
    pub from_unix_secs: Option<i64>,
    pub to_unix_secs: Option<i64>,
    pub profile_id: Option<String>,
    pub api_key_id: Option<String>,
    pub tool_ref: Option<String>,
    pub limit: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolCallStatsByTool {
    pub tool_ref: String,
    pub total: i64,
    pub ok: i64,
    pub err: i64,
    pub avg_duration_ms: Option<i64>,
    pub p95_duration_ms: Option<i64>,
    pub p99_duration_ms: Option<i64>,
    pub max_duration_ms: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolCallStatsByApiKey {
    pub api_key_id: String,
    pub total: i64,
    pub ok: i64,
    pub err: i64,
    pub avg_duration_ms: Option<i64>,
    pub p95_duration_ms: Option<i64>,
    pub p99_duration_ms: Option<i64>,
    pub max_duration_ms: Option<i64>,
}

#[async_trait]
pub trait Store: Send + Sync {
    async fn get_profile(&self, profile_id: &str) -> anyhow::Result<Option<Profile>>;
    async fn get_upstream(&self, upstream_id: &str) -> anyhow::Result<Option<Upstream>>;

    /// Load a tenant-owned tool source (Mode 3 overlay).
    async fn get_tenant_tool_source(
        &self,
        tenant_id: &str,
        source_id: &str,
    ) -> anyhow::Result<Option<TenantToolSource>>;

    /// Load a tenant secret value (never returned by control-plane GETs; internal use only).
    async fn get_tenant_secret_value(
        &self,
        tenant_id: &str,
        name: &str,
    ) -> anyhow::Result<Option<String>>;

    /// Validate a data-plane API key secret for a tenant/profile context.
    ///
    /// IMPORTANT: the caller's secret MUST NOT be forwarded to any upstream.
    async fn authenticate_api_key(
        &self,
        tenant_id: &str,
        profile_id: &str,
        secret: &str,
    ) -> anyhow::Result<Option<ApiKeyAuth>>;

    async fn is_api_key_active(&self, tenant_id: &str, api_key_id: &str) -> anyhow::Result<bool>;

    /// Update last-used timestamp and increment the per-key request counter (best-effort metering).
    async fn touch_api_key(&self, tenant_id: &str, api_key_id: &str) -> anyhow::Result<()>;

    /// Increment the per-key `tools/call` attempt counter (best-effort metering).
    async fn record_tool_call_attempt(
        &self,
        tenant_id: &str,
        api_key_id: &str,
    ) -> anyhow::Result<()>;

    /// Apply configured per-profile rate limits / quotas for a single `tools/call` attempt.
    ///
    /// - Returns `Ok(None)` when allowed.
    /// - Returns `Ok(Some(...))` when blocked by limits (rate limit or quota).
    async fn check_and_apply_tool_call_limits(
        &self,
        tenant_id: &str,
        profile_id: &str,
        api_key_id: &str,
        rate_limit_tool_calls_per_minute: Option<i64>,
        quota_tool_calls: Option<i64>,
    ) -> anyhow::Result<Option<ToolCallLimitRejection>>;

    /// Authorization check for OIDC principals (JWT mode).
    ///
    /// A principal can be bound either:
    /// - tenant-wide (`profile_id` NULL), or
    /// - profile-scoped (`profile_id` matches the requested profile).
    async fn is_oidc_principal_allowed(
        &self,
        tenant_id: &str,
        profile_id: &str,
        issuer: &str,
        subject: &str,
    ) -> anyhow::Result<bool>;
}

#[async_trait]
pub trait AdminStore: Send + Sync {
    async fn list_tenants(&self) -> anyhow::Result<Vec<AdminTenant>>;
    async fn get_tenant(&self, tenant_id: &str) -> anyhow::Result<Option<AdminTenant>>;
    async fn delete_tenant(&self, tenant_id: &str) -> anyhow::Result<bool>;
    async fn put_tenant(&self, tenant_id: &str, enabled: bool) -> anyhow::Result<()>;

    async fn list_upstreams(&self) -> anyhow::Result<Vec<AdminUpstream>>;
    async fn get_upstream(&self, upstream_id: &str) -> anyhow::Result<Option<AdminUpstream>>;
    async fn delete_upstream(&self, upstream_id: &str) -> anyhow::Result<bool>;
    async fn put_upstream(
        &self,
        upstream_id: &str,
        enabled: bool,
        endpoints: &[UpstreamEndpoint],
    ) -> anyhow::Result<()>;

    async fn list_profiles(&self) -> anyhow::Result<Vec<AdminProfile>>;
    async fn get_profile(&self, profile_id: &str) -> anyhow::Result<Option<AdminProfile>>;
    async fn delete_profile(&self, profile_id: &str) -> anyhow::Result<bool>;
    #[allow(clippy::too_many_arguments, clippy::fn_params_excessive_bools)]
    async fn put_profile(
        &self,
        profile_id: &str,
        tenant_id: &str,
        name: &str,
        description: Option<&str>,
        enabled: bool,
        allow_partial_upstreams: bool,
        upstream_ids: &[String],
        source_ids: &[String],
        transforms: &TransformPipeline,
        enabled_tools: &[String],
        data_plane_auth_mode: DataPlaneAuthMode,
        accept_x_api_key: bool,
        rate_limit_enabled: bool,
        rate_limit_tool_calls_per_minute: Option<i64>,
        quota_enabled: bool,
        quota_tool_calls: Option<i64>,
        tool_call_timeout_secs: Option<u64>,
        tool_policies: &[ToolPolicy],
        mcp: &McpProfileSettings,
    ) -> anyhow::Result<()>;

    // Mode 3 overlay: tenant-owned tool sources.
    async fn list_tool_sources(&self, tenant_id: &str) -> anyhow::Result<Vec<TenantToolSource>>;
    async fn get_tool_source(
        &self,
        tenant_id: &str,
        source_id: &str,
    ) -> anyhow::Result<Option<TenantToolSource>>;
    async fn put_tool_source(
        &self,
        tenant_id: &str,
        source_id: &str,
        enabled: bool,
        kind: ToolSourceKind,
        spec: Value,
    ) -> anyhow::Result<()>;
    async fn delete_tool_source(&self, tenant_id: &str, source_id: &str) -> anyhow::Result<bool>;

    // Mode 3 overlay: tenant secrets.
    async fn list_secrets(&self, tenant_id: &str) -> anyhow::Result<Vec<TenantSecretMetadata>>;
    async fn put_secret(&self, tenant_id: &str, name: &str, value: &str) -> anyhow::Result<()>;
    async fn delete_secret(&self, tenant_id: &str, name: &str) -> anyhow::Result<bool>;

    // Mode 3: tenant API keys for data-plane auth.
    async fn list_api_keys(&self, tenant_id: &str) -> anyhow::Result<Vec<ApiKeyMetadata>>;
    async fn put_api_key(
        &self,
        tenant_id: &str,
        api_key_id: &str,
        profile_id: Option<&str>,
        name: &str,
        prefix: &str,
        secret_hash: &str,
    ) -> anyhow::Result<()>;
    async fn revoke_api_key(&self, tenant_id: &str, api_key_id: &str) -> anyhow::Result<bool>;

    // OIDC principal bindings (issuer + subject) -> tenant/profile scope.
    async fn list_oidc_principals(
        &self,
        tenant_id: &str,
        issuer: &str,
    ) -> anyhow::Result<Vec<OidcPrincipalBinding>>;

    async fn put_oidc_principal(
        &self,
        tenant_id: &str,
        issuer: &str,
        subject: &str,
        profile_id: Option<&str>,
        enabled: bool,
    ) -> anyhow::Result<()>;

    async fn delete_oidc_principal(
        &self,
        tenant_id: &str,
        issuer: &str,
        subject: &str,
        profile_id: Option<&str>,
    ) -> anyhow::Result<u64>;

    // ---------------------------------------------------------------------
    // Audit settings + audit event querying (Mode 3 only)
    // ---------------------------------------------------------------------

    async fn get_tenant_audit_settings(
        &self,
        tenant_id: &str,
    ) -> anyhow::Result<Option<TenantAuditSettings>>;

    async fn put_tenant_audit_settings(
        &self,
        tenant_id: &str,
        settings: &TenantAuditSettings,
    ) -> anyhow::Result<()>;

    async fn get_profile_audit_settings(&self, profile_id: &str) -> anyhow::Result<Option<Value>>;

    async fn put_profile_audit_settings(
        &self,
        profile_id: &str,
        audit_settings: Value,
    ) -> anyhow::Result<()>;

    async fn list_audit_events(
        &self,
        tenant_id: &str,
        filter: AuditEventFilter,
    ) -> anyhow::Result<Vec<AuditEventRow>>;

    async fn tool_call_stats_by_tool(
        &self,
        tenant_id: &str,
        filter: AuditStatsFilter,
    ) -> anyhow::Result<Vec<ToolCallStatsByTool>>;

    async fn tool_call_stats_by_api_key(
        &self,
        tenant_id: &str,
        filter: AuditStatsFilter,
    ) -> anyhow::Result<Vec<ToolCallStatsByApiKey>>;

    /// Delete audit events older than the configured tenant retention window.
    ///
    /// Returns the number of rows deleted.
    async fn cleanup_audit_events_for_tenant(&self, tenant_id: &str) -> anyhow::Result<u64>;
}

/// In-memory store backed by a static config file (Mode 1).
#[derive(Clone)]
pub struct ConfigStore {
    config: Arc<GatewayConfig>,
}

impl ConfigStore {
    pub fn new(config: GatewayConfig) -> Self {
        Self {
            config: Arc::new(config),
        }
    }

    fn profile_from_config(profile_id: &str, cfg: &ProfileConfig) -> Profile {
        Profile {
            id: profile_id.to_string(),
            tenant_id: cfg.tenant_id.clone(),
            allow_partial_upstreams: cfg.allow_partial_upstreams,
            source_ids: cfg.upstreams.clone(),
            transforms: cfg.transforms.clone(),
            enabled_tools: cfg.tools.clone().unwrap_or_default(),
            // Mode 1 defaults: data plane is unauthenticated unless configured otherwise.
            data_plane_auth_mode: DataPlaneAuthMode::Disabled,
            accept_x_api_key: true,
            // Mode 1: limits are disabled by default (and currently not configurable via config).
            rate_limit_enabled: false,
            rate_limit_tool_calls_per_minute: None,
            quota_enabled: false,
            quota_tool_calls: None,
            tool_call_timeout_secs: cfg.tool_call_timeout_secs,
            tool_policies: cfg.tool_policies.clone(),
            mcp: cfg.mcp.clone(),
        }
    }

    fn upstream_from_config(_upstream_id: &str, cfg: &UpstreamConfig) -> Upstream {
        Upstream {
            endpoints: cfg
                .endpoints
                .iter()
                .map(|e| UpstreamEndpoint {
                    id: e.id.clone(),
                    url: e.url.clone(),
                    auth: None,
                })
                .collect(),
        }
    }
}

#[async_trait]
impl Store for ConfigStore {
    async fn get_profile(&self, profile_id: &str) -> anyhow::Result<Option<Profile>> {
        let Some(profile_cfg) = self.config.profiles.get(profile_id) else {
            return Ok(None);
        };

        // Tenant is optional in Mode 1; if present, it can disable all profiles for that tenant.
        let tenant_enabled = self
            .config
            .tenants
            .get(&profile_cfg.tenant_id)
            .map_or(true, |t| t.enabled);

        if !tenant_enabled {
            return Ok(None);
        }

        let mut p = Self::profile_from_config(profile_id, profile_cfg);
        match self.config.data_plane_auth.mode {
            Mode1AuthMode::None => {
                p.data_plane_auth_mode = DataPlaneAuthMode::Disabled;
            }
            Mode1AuthMode::StaticApiKeys => {
                p.data_plane_auth_mode = if self.config.data_plane_auth.require_every_request {
                    DataPlaneAuthMode::ApiKeyEveryRequest
                } else {
                    DataPlaneAuthMode::ApiKeyInitializeOnly
                };
                p.accept_x_api_key = self.config.data_plane_auth.accept_x_api_key;
            }
        }

        Ok(Some(p))
    }

    async fn get_upstream(&self, upstream_id: &str) -> anyhow::Result<Option<Upstream>> {
        Ok(self
            .config
            .upstreams
            .get(upstream_id)
            .map(|cfg| Self::upstream_from_config(upstream_id, cfg)))
    }

    async fn get_tenant_tool_source(
        &self,
        _tenant_id: &str,
        _source_id: &str,
    ) -> anyhow::Result<Option<TenantToolSource>> {
        Ok(None)
    }

    async fn get_tenant_secret_value(
        &self,
        _tenant_id: &str,
        _name: &str,
    ) -> anyhow::Result<Option<String>> {
        Ok(None)
    }

    async fn authenticate_api_key(
        &self,
        tenant_id: &str,
        _profile_id: &str,
        secret: &str,
    ) -> anyhow::Result<Option<ApiKeyAuth>> {
        if self.config.data_plane_auth.mode != Mode1AuthMode::StaticApiKeys {
            return Ok(None);
        }
        let secret = secret.trim();
        if secret.is_empty() {
            return Ok(None);
        }
        if !self
            .config
            .data_plane_auth
            .api_keys
            .iter()
            .any(|k| k == secret)
        {
            return Ok(None);
        }

        // Mode 1: compute a stable, non-secret identifier from the secret.
        let api_key_id = hex::encode(sha2::Sha256::digest(secret.as_bytes()));
        Ok(Some(ApiKeyAuth {
            api_key_id,
            tenant_id: tenant_id.to_string(),
        }))
    }

    async fn is_api_key_active(&self, _tenant_id: &str, _api_key_id: &str) -> anyhow::Result<bool> {
        Ok(self.config.data_plane_auth.mode == Mode1AuthMode::StaticApiKeys)
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
    ) -> anyhow::Result<Option<ToolCallLimitRejection>> {
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
