use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use unrelated_http_tools::config::{
    AuthConfig, EndpointDefaults, HttpToolConfig, ResponseTransform, ResponseTransformChainConfig,
};

/// Configuration for an OpenAPI-based tool source.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiServerConfig {
    /// `OpenAPI` spec location (URL or file path).
    pub spec: String,

    /// Optional spec hash for version detection.
    #[serde(default)]
    pub spec_hash: Option<String>,

    /// Hash policy: warn, fail, or ignore.
    #[serde(default)]
    pub spec_hash_policy: HashPolicy,

    /// Override base URL from spec.
    #[serde(default)]
    pub base_url: Option<String>,

    /// Authentication for API calls and the configured root `OpenAPI` spec URL.
    /// Credentials are not forwarded to external `$ref` documents or across origins on redirects.
    #[serde(default)]
    pub auth: Option<AuthConfig>,

    /// Auto-discovery configuration.
    #[serde(default)]
    pub auto_discover: AutoDiscoverConfig,

    /// Explicit endpoint mappings.
    #[serde(default)]
    pub endpoints: HashMap<String, HashMap<String, EndpointConfig>>,

    /// Default settings for all endpoints.
    #[serde(default)]
    pub defaults: EndpointDefaults,

    /// Global response shaping pipeline applied to all tools derived from this spec (including
    /// manual overrides unless they explicitly replace it).
    #[serde(default)]
    pub response_transforms: Vec<ResponseTransform>,

    /// Per-operation response shaping / output schema overrides.
    #[serde(default)]
    pub response_overrides: Vec<ResponseOverrideConfig>,

    /// Optional `OpenAPI` tool overrides (manual HTTP tool DSL).
    #[serde(default)]
    pub overrides: OpenApiOverridesConfig,
}

/// Hash verification policy.
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum HashPolicy {
    /// Log warning if hash doesn't match.
    #[default]
    Warn,
    /// Fail startup if hash doesn't match.
    Fail,
    /// Ignore hash verification.
    Ignore,
}

/// Auto-discovery configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum AutoDiscoverConfig {
    /// Simple boolean: true = discover all, false = explicit only.
    Enabled(bool),
    /// Detailed configuration with include/exclude.
    Detailed {
        #[serde(default)]
        include: Vec<String>,
        #[serde(default)]
        exclude: Vec<String>,
    },
}

impl Default for AutoDiscoverConfig {
    fn default() -> Self {
        AutoDiscoverConfig::Enabled(true)
    }
}

impl AutoDiscoverConfig {
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        match self {
            AutoDiscoverConfig::Enabled(b) => *b,
            AutoDiscoverConfig::Detailed { .. } => true,
        }
    }

    #[must_use]
    pub fn include_patterns(&self) -> &[String] {
        match self {
            AutoDiscoverConfig::Enabled(_) => &[],
            AutoDiscoverConfig::Detailed { include, .. } => include,
        }
    }

    #[must_use]
    pub fn exclude_patterns(&self) -> &[String] {
        match self {
            AutoDiscoverConfig::Enabled(_) => &[],
            AutoDiscoverConfig::Detailed { exclude, .. } => exclude,
        }
    }
}

/// Configuration for a specific `OpenAPI` endpoint override.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EndpointConfig {
    /// MCP tool name.
    pub tool: String,

    /// Override description.
    #[serde(default)]
    pub description: Option<String>,

    /// Parameter configurations.
    #[serde(default)]
    pub params: HashMap<String, ParamConfig>,
}

/// Configuration for a parameter.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct ParamConfig {
    /// Rename the parameter.
    #[serde(default)]
    pub rename: Option<String>,

    /// Override description.
    #[serde(default)]
    pub description: Option<String>,

    /// Default value if not provided.
    #[serde(default)]
    pub default: Option<serde_json::Value>,

    /// Override required status.
    #[serde(default)]
    pub required: Option<bool>,
}

// ============================================================================
// OpenAPI overrides (manual HTTP tool DSL)
// ============================================================================

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct OpenApiOverridesConfig {
    #[serde(default)]
    pub tools: HashMap<String, OpenApiOverrideToolConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenApiOverrideToolConfig {
    /// Which `OpenAPI` operation this override targets.
    #[serde(rename = "match")]
    pub matcher: OpenApiToolMatch,

    /// Manual tool definition used instead of spec-derived behavior.
    pub request: HttpToolConfig,

    /// Optional tool description override.
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct OpenApiToolMatch {
    #[serde(default)]
    pub operation_id: Option<String>,
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
}

// ============================================================================
// Response shaping overrides
// ============================================================================

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResponseOverrideConfig {
    /// Which `OpenAPI` operation this override targets.
    #[serde(rename = "match")]
    pub matcher: OpenApiToolMatch,

    /// Optional response transform chain for the matched operation.
    #[serde(default)]
    pub transforms: Option<ResponseTransformChainConfig>,

    /// Optional JSON Schema fragment describing the response body for the matched operation.
    ///
    /// This is interpreted as the schema for the tool output `body` field (before MCP wrapping).
    #[serde(default)]
    pub output_schema: Option<serde_json::Value>,
}
