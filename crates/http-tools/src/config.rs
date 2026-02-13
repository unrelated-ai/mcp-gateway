use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Authentication configuration for outbound HTTP calls.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum AuthConfig {
    /// No authentication.
    None,
    /// Bearer token authentication.
    Bearer { token: String },
    /// Custom header authentication.
    Header { name: String, value: String },
    /// Basic authentication.
    Basic { username: String, password: String },
    /// Query parameter authentication.
    Query { name: String, value: String },
}

/// Default settings for endpoints/tools.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct EndpointDefaults {
    /// Request timeout in seconds.
    #[serde(
        default,
        deserialize_with = "unrelated_env::serde_helpers::deserialize_option_u64_env"
    )]
    pub timeout: Option<u64>,

    /// Array serialization style (legacy/default fallback when per-parameter style is absent).
    #[serde(default)]
    pub array_style: Option<ArrayStyle>,

    /// Additional headers applied to every request.
    #[serde(default)]
    pub headers: HashMap<String, String>,
}

/// Array serialization style (query parameters).
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ArrayStyle {
    /// Comma-separated: `?tags=a,b,c`.
    #[default]
    Form,
    /// Space-separated: `?tags=a%20b%20c`.
    SpaceDelimited,
    /// Pipe-separated: `?tags=a|b|c`.
    PipeDelimited,
    /// Deep object: `?tags[0]=a&tags[1]=b`.
    DeepObject,
}

/// Manual HTTP tool backend configuration (tool DSL).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HttpServerConfig {
    pub base_url: String,
    #[serde(default)]
    pub auth: Option<AuthConfig>,
    #[serde(default)]
    pub defaults: EndpointDefaults,
    /// Global response shaping pipeline applied to all tools in this source.
    ///
    /// Notes:
    /// - Tool-level transforms (in `tools.<name>.response.transforms`) can override this pipeline.
    /// - These transforms apply to the HTTP response body (what becomes `structured_content.body`).
    #[serde(default)]
    pub response_transforms: Vec<ResponseTransform>,
    #[serde(default)]
    pub tools: HashMap<String, HttpToolConfig>,
}

/// Manual HTTP tool definition.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HttpToolConfig {
    pub method: String,
    pub path: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub params: HashMap<String, HttpParamConfig>,
    #[serde(default)]
    pub response: HttpResponseConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct HttpResponseConfig {
    #[serde(default)]
    pub mode: HttpResponseMode,
    /// Optional JSON Schema fragment describing the tool output (the HTTP response body).
    ///
    /// Notes:
    /// - This is interpreted as the schema for the `body` field of the tool's structured output.
    /// - The MCP `Tool.output_schema` requires the *root* schema to be an object, so we wrap this
    ///   into `{ "type": "object", "required": ["body"], "properties": { "body": <outputSchema> } }`.
    /// - When this is set, the runtime will also return `structured_content` as
    ///   `{ "body": <parsed_response> }` (while still returning `Content::text(...)` for client
    ///   interoperability, since some MCP clients only render `content`).
    #[serde(default)]
    pub output_schema: Option<serde_json::Value>,
    /// Optional response transform overrides for this tool.
    ///
    /// When present:
    /// - default behavior is `mode: replace` (tool pipeline replaces server pipeline)
    /// - `mode: append` can be used to apply the server pipeline first, then the tool pipeline
    #[serde(default)]
    pub transforms: Option<ResponseTransformChainConfig>,
}

// ============================================================================
// Response shaping
// ============================================================================

/// How a per-tool response transform pipeline composes with the server-level pipeline.
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TransformChainMode {
    /// Replace the server-level pipeline.
    #[default]
    Replace,
    /// Apply the server-level pipeline, then append this pipeline.
    Append,
}

/// A single response transform step.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum ResponseTransform {
    /// Drop object keys with `null` values (recursive).
    DropNulls,
    /// Keep only a whitelist of top-level JSON pointers (e.g. `"/id"`).
    PickPointers { pointers: Vec<String> },
    /// Redact values of matching keys (any depth).
    RedactKeys {
        keys: Vec<String>,
        /// Replacement value to use (default: `"***REDACTED***"`).
        #[serde(default)]
        replacement: Option<String>,
    },
    /// Truncate all strings to at most `maxChars` (recursive).
    TruncateStrings { max_chars: usize },
    /// Truncate all arrays to at most `maxItems` (recursive).
    LimitArrays { max_items: usize },
}

/// Tool-level response transform pipeline configuration.
///
/// Supported forms:
///
/// - Shorthand (defaults to `mode: replace`):
///   - `transforms: [ {type: ...}, ... ]`
/// - Detailed:
///   - `transforms: { mode: append|replace, pipeline: [ ... ] }`
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(untagged)]
pub enum ResponseTransformChainConfig {
    Pipeline(Vec<ResponseTransform>),
    Detailed {
        #[serde(default)]
        mode: TransformChainMode,
        #[serde(default)]
        pipeline: Vec<ResponseTransform>,
    },
}

impl ResponseTransformChainConfig {
    #[must_use]
    pub fn mode_and_pipeline(&self) -> (TransformChainMode, &[ResponseTransform]) {
        match self {
            Self::Pipeline(p) => (TransformChainMode::Replace, p.as_slice()),
            Self::Detailed { mode, pipeline } => (*mode, pipeline.as_slice()),
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum HttpResponseMode {
    #[default]
    Json,
    Text,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HttpParamConfig {
    #[serde(rename = "in")]
    pub location: HttpParamLocation,

    /// Override the actual HTTP parameter/property name (defaults to the map key).
    #[serde(default)]
    pub name: Option<String>,

    #[serde(default)]
    pub required: Option<bool>,

    #[serde(default)]
    pub default: Option<serde_json::Value>,

    /// JSON Schema fragment for the argument.
    #[serde(default)]
    pub schema: Option<serde_json::Value>,

    // Query serialization (only relevant when `in: query`)
    #[serde(default)]
    pub style: Option<QueryStyleConfig>,
    #[serde(default)]
    pub explode: Option<bool>,
    #[serde(default)]
    pub allow_reserved: Option<bool>,
    #[serde(default)]
    pub allow_empty_value: Option<bool>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum HttpParamLocation {
    Path,
    Query,
    Header,
    Body,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum QueryStyleConfig {
    Form,
    SpaceDelimited,
    PipeDelimited,
    DeepObject,
}

#[cfg(test)]
mod tests {
    use super::EndpointDefaults;
    use serde_json::json;

    #[test]
    fn timeout_supports_env_expansion() {
        const VAR: &str = "UNRELATED_HTTP_TOOLS_TEST_TIMEOUT";
        // SAFETY: This test uses a unique env var name and cleans it up. The value is only read
        // within this test process.
        unsafe {
            std::env::set_var(VAR, "42");
        }

        let defaults: EndpointDefaults = serde_json::from_value(json!({
            "timeout": format!("${{{VAR}}}"),
        }))
        .expect("EndpointDefaults must deserialize with env expansion");

        assert_eq!(defaults.timeout, Some(42));

        // SAFETY: Clean up the process environment after the test.
        unsafe {
            std::env::remove_var(VAR);
        }
    }
}
