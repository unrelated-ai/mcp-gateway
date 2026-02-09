use serde::Deserialize;
use std::collections::HashMap;

use crate::serde_helpers::default_true;
use crate::store::McpProfileSettings;
use crate::tool_policy::ToolPolicy;
use unrelated_http_tools::config as http_tools;
use unrelated_openapi_tools::config as openapi_tools;
use unrelated_tool_transforms::TransformPipeline;

/// Mode 1 (config-file) gateway configuration.
///
/// This is intentionally minimal:
/// - profiles are the public entrypoints (`/{profile_id}/mcp`)
/// - profiles are owned by tenants (tenant id only)
/// - profiles reference one or more upstream adapter clusters
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct GatewayConfig {
    #[serde(default)]
    pub tenants: HashMap<String, TenantConfig>,
    #[serde(default)]
    pub profiles: HashMap<String, ProfileConfig>,
    #[serde(default)]
    pub upstreams: HashMap<String, UpstreamConfig>,
    /// Mode 1 data-plane auth configuration (config-file mode only).
    ///
    /// In Mode 3 (Postgres), data-plane auth is configured per-profile and keys are stored in DB.
    #[serde(default)]
    pub data_plane_auth: DataPlaneAuthConfig,
    /// Shared tool sources loaded from config file (catalog layer).
    ///
    /// These are "public by default" (available to any tenant), but do not imply exposure
    /// unless a profile references them.
    #[serde(default)]
    pub shared_sources: HashMap<String, SharedSourceConfig>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct DataPlaneAuthConfig {
    /// Mode 1 only. Defaults to `none`.
    #[serde(default)]
    pub mode: Mode1AuthMode,
    /// Static API key secrets (Mode 1 only).
    #[serde(default)]
    pub api_keys: Vec<String>,
    /// If true, accept `x-api-key: <secret>` as an alias for `Authorization: Bearer <secret>`.
    #[serde(default)]
    pub accept_x_api_key: bool,
    /// If true, require the API key on every request (POST/GET/DELETE) rather than only on
    /// `initialize`.
    #[serde(default)]
    pub require_every_request: bool,
}

#[derive(Debug, Clone, Copy, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Mode1AuthMode {
    #[default]
    None,
    StaticApiKeys,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TenantConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileConfig {
    pub tenant_id: String,
    #[serde(default = "default_true")]
    pub allow_partial_upstreams: bool,
    pub upstreams: Vec<String>,
    /// Per-profile tool transforms (renames/defaults).
    #[serde(default)]
    pub transforms: TransformPipeline,
    /// Optional per-profile tool allowlist.
    ///
    /// Semantics:
    /// - omitted / `null` / `[]` => no allowlist configured (allow all tools)
    /// - otherwise entries are stable tool refs in the form `"<source_id>:<original_tool_name>"`
    #[serde(default)]
    pub tools: Option<Vec<String>>,

    /// Optional per-profile default timeout override for `tools/call` (seconds).
    #[serde(default)]
    pub tool_call_timeout_secs: Option<u64>,
    /// Optional per-profile per-tool policy overrides (timeouts + retry policy).
    #[serde(default)]
    pub tool_policies: Vec<ToolPolicy>,

    /// MCP proxy behavior settings for this profile (capabilities, notifications, namespacing).
    #[serde(default)]
    pub mcp: McpProfileSettings,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpstreamConfig {
    pub endpoints: Vec<UpstreamEndpointConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpstreamEndpointConfig {
    pub id: String,
    /// Full Streamable HTTP MCP URL, e.g. `http://adapter:8080/mcp`.
    pub url: String,
}

/// Shared catalog entry (config-file defined tool source).
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum SharedSourceConfig {
    /// Gateway-native manual HTTP tool source.
    Http {
        #[serde(default = "default_true")]
        enabled: bool,
        #[serde(default = "default_true")]
        public: bool,
        #[serde(flatten)]
        config: http_tools::HttpServerConfig,
    },
    /// Gateway-native `OpenAPI` tool source.
    Openapi {
        #[serde(default = "default_true")]
        enabled: bool,
        #[serde(default = "default_true")]
        public: bool,
        #[serde(flatten)]
        config: openapi_tools::ApiServerConfig,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode1_profile_allow_partial_upstreams_defaults_true() {
        let cfg: GatewayConfig = serde_yaml::from_str(
            r"
tenants: {}
upstreams: {}
sharedSources: {}
profiles:
  p1:
    tenantId: t1
    upstreams: []
",
        )
        .expect("valid yaml");

        let p1 = cfg.profiles.get("p1").expect("p1");
        assert!(p1.allow_partial_upstreams);
    }

    #[test]
    fn mode1_data_plane_auth_accept_x_api_key_defaults_false_and_require_every_request_defaults_false()
     {
        let cfg: GatewayConfig = serde_yaml::from_str(
            r"
tenants: {}
profiles: {}
upstreams: {}
sharedSources: {}
dataPlaneAuth: {}
",
        )
        .expect("valid yaml");

        assert!(!cfg.data_plane_auth.accept_x_api_key);
        assert!(!cfg.data_plane_auth.require_every_request);
        assert_eq!(cfg.data_plane_auth.mode, Mode1AuthMode::None);
    }

    #[test]
    fn mode1_profile_tools_parsing_semantics() {
        let cfg_omitted: GatewayConfig = serde_yaml::from_str(
            r"
tenants: {}
upstreams: {}
sharedSources: {}
profiles:
  p1:
    tenantId: t1
    upstreams: []
",
        )
        .expect("valid yaml");
        assert_eq!(cfg_omitted.profiles["p1"].tools, None);

        let cfg_null: GatewayConfig = serde_yaml::from_str(
            r"
tenants: {}
upstreams: {}
sharedSources: {}
profiles:
  p1:
    tenantId: t1
    upstreams: []
    tools: null
",
        )
        .expect("valid yaml");
        assert_eq!(cfg_null.profiles["p1"].tools, None);

        let cfg_empty: GatewayConfig = serde_yaml::from_str(
            r"
tenants: {}
upstreams: {}
sharedSources: {}
profiles:
  p1:
    tenantId: t1
    upstreams: []
    tools: []
",
        )
        .expect("valid yaml");
        assert_eq!(cfg_empty.profiles["p1"].tools, Some(Vec::new()));
    }
}
