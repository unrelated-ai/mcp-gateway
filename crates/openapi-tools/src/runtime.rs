//! `OpenAPI` tool source runtime.
//!
//! This module implements an `OpenAPI` → MCP tool source by converting `OpenAPI` operations into
//! MCP tools and executing outbound HTTP requests for `tools/call`.

use crate::config::{ApiServerConfig, HashPolicy, OpenApiOverrideToolConfig, ParamConfig};
use crate::error::{OpenApiToolsError, Result};
use crate::resolver::{DocId, OpenApiResolver};
use base64::Engine as _;
use mime::Mime;
use openapiv3::{
    OpenAPI, Operation, Parameter, ParameterSchemaOrContent, QueryStyle, ReferenceOr, RequestBody,
    Response, Schema, StatusCode,
};
use parking_lot::RwLock;
use regex::Regex;
use reqwest::{Client, Method};
use rmcp::model::{CallToolResult, ContentBlock, JsonObject, Tool};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use unrelated_http_tools::config::{
    ArrayStyle, AuthConfig, HttpParamLocation, HttpResponseMode, HttpToolConfig, QueryStyleConfig,
    ResponseTransform, ResponseTransformChainConfig,
};
use unrelated_http_tools::response_shaping::{
    CompiledResponsePipeline, apply_chain, compile_pipeline_from_transforms,
};
use unrelated_http_tools::safety::{
    OutboundHttpSafety, RedirectPolicy, redact_url, sanitize_reqwest_error,
};
use url::Url;

mod conversion;
mod execution;
mod loading;
mod schema;
mod spec_fetch;
use conversion::{
    build_input_schema, default_query_explode, encode_query_component, extract_schema,
    extract_schema_ref, generate_canonical_name, manual_override_to_tool, match_override,
    match_response_override, matches_pattern, merge_parameters, query_value_is_empty,
    reserve_unique_tool_name, resolve_http_method, schema_to_json, serialize_empty_query_value,
    serialize_query_array, serialize_query_object, serialize_query_scalar, value_to_string,
    wrap_body_output_schema,
};

/// `OpenAPI` tool source that exposes HTTP API endpoints as MCP tools.
#[derive(Clone)]
pub struct OpenApiToolSource {
    /// Source name / id (used for logs and error context).
    name: String,
    /// Configuration
    config: ApiServerConfig,
    /// Parsed `OpenAPI` spec
    spec: Arc<RwLock<Option<OpenAPI>>>,
    /// Generated tools
    tools: Arc<RwLock<Vec<GeneratedTool>>>,
    /// HTTP client
    client: std::result::Result<Client, String>,
    /// Base URL for API calls
    base_url: Arc<RwLock<Option<String>>>,
    /// Fallback call timeout (used when API config doesn't specify one)
    default_timeout: Duration,
    /// Startup timeout for spec loading and tool discovery
    startup_timeout: Duration,
    /// Probe `OpenAPI` base URL reachability on startup
    probe_enabled: bool,
    /// Probe timeout
    probe_timeout: Duration,
    /// Outbound HTTP safety policy (SSRF protections, limits, redirect policy).
    safety: OutboundHttpSafety,
}

/// A tool generated from an `OpenAPI` operation.
#[derive(Debug, Clone)]
struct GeneratedTool {
    /// Tool name (exposed)
    name: String,
    /// Original operation ID or generated name
    original_name: String,
    /// `OpenAPI` operationId (if present)
    operation_id: Option<String>,
    /// Description
    description: Option<String>,
    /// HTTP method
    method: Method,
    /// Path template (e.g., /pet/{petId})
    path: String,
    /// Parameters with their locations
    parameters: Vec<ToolParameter>,
    /// Input schema for MCP
    input_schema: Value,
    /// Response mode (json/text) for this tool
    response_mode: HttpResponseMode,
    /// Optional output schema for MCP `Tool.output_schema` (must be a JSON Schema object).
    output_schema: Option<Arc<JsonObject>>,
    /// Compiled response shaping pipeline (applied to the response body value).
    response_pipeline: Arc<CompiledResponsePipeline>,
}

#[derive(Debug, Clone)]
struct OperationInfo {
    method: String,
    path: String,
    operation_id: Option<String>,
}

struct MethodOp<'a> {
    method: &'static str,
    operation: &'a Operation,
    info: OperationInfo,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct OperationKey {
    method: String,
    path: String,
    operation_id: Option<String>,
}

impl OperationKey {
    #[must_use]
    fn from_info(info: &OperationInfo) -> Self {
        Self {
            method: info.method.clone(),
            path: info.path.clone(),
            operation_id: info.operation_id.clone(),
        }
    }
}

#[derive(Debug, Clone)]
struct ResolvedResponseOverride {
    transforms: Option<ResponseTransformChainConfig>,
    output_schema: Option<Value>,
}

struct ToolGenerationInput<'a> {
    current_doc: &'a DocId,
    path_item_params: &'a [ReferenceOr<Parameter>],
    path: &'a str,
    method: &'a str,
    operation: &'a Operation,
}

/// Parameter information for a tool.
#[derive(Debug, Clone)]
struct ToolParameter {
    /// Parameter name in the tool (may be renamed)
    tool_name: String,
    /// Original parameter name
    original_name: String,
    /// Where the parameter goes: path, query, header, body
    location: ParamLocation,
    /// Whether the parameter is required
    required: bool,
    /// Default value if any
    default: Option<Value>,
    /// JSON schema for the parameter
    schema: Value,
    /// Query serialization settings (style/explode), for query parameters only
    query: Option<QuerySerialization>,
}

#[derive(Debug, Clone)]
struct QuerySerialization {
    style: QueryStyle,
    explode: bool,
    allow_reserved: bool,
    allow_empty_value: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct QueryPair {
    key: String,
    value: String,
    allow_reserved: bool,
}

struct RequestParts {
    path: String,
    query_params: Vec<QueryPair>,
    headers: Vec<(String, String)>,
    body_fields: HashMap<String, Value>,
    body_payload: Option<Value>,
}

enum ToolResponse {
    Value(Value),
    Image { bytes: Vec<u8>, mime_type: String },
}

/// Parameter location.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParamLocation {
    Path,
    Query,
    Header,
    Body,
}

impl OpenApiToolSource {
    /// Create a new `OpenAPI` tool source.
    ///
    /// This constructor does not fetch/parse the spec; call [`Self::start`] (or [`Self::build`])
    /// before using [`Self::list_tools`] / [`Self::call_tool`].
    #[must_use]
    pub fn new(
        name: String,
        config: ApiServerConfig,
        default_timeout: Duration,
        startup_timeout: Duration,
        probe_enabled: bool,
        probe_timeout: Duration,
    ) -> Self {
        Self::new_with_safety(
            name,
            config,
            default_timeout,
            startup_timeout,
            probe_enabled,
            probe_timeout,
            OutboundHttpSafety::permissive(),
        )
    }

    /// Create a new `OpenAPI` tool source with an explicit outbound safety policy.
    #[must_use]
    pub fn new_with_safety(
        name: String,
        config: ApiServerConfig,
        default_timeout: Duration,
        startup_timeout: Duration,
        probe_enabled: bool,
        probe_timeout: Duration,
        safety: OutboundHttpSafety,
    ) -> Self {
        // Preserve the infallible constructor API, but surface build failures during use.
        // Never fall back to a client without outbound safety protections.
        let client = safety
            .client_builder()
            .build()
            .map_err(|e| sanitize_reqwest_error(&e));

        Self {
            name,
            config,
            spec: Arc::new(RwLock::new(None)),
            tools: Arc::new(RwLock::new(Vec::new())),
            client,
            base_url: Arc::new(RwLock::new(None)),
            default_timeout,
            startup_timeout,
            probe_enabled,
            probe_timeout,
            safety,
        }
    }

    /// Create and start a tool source in one step.
    ///
    /// # Errors
    ///
    /// Returns an error if spec loading, parsing, tool discovery, or probing fails.
    pub async fn build(
        name: String,
        config: ApiServerConfig,
        default_timeout: Duration,
        startup_timeout: Duration,
        probe_enabled: bool,
        probe_timeout: Duration,
    ) -> Result<Self> {
        let src = Self::new(
            name,
            config,
            default_timeout,
            startup_timeout,
            probe_enabled,
            probe_timeout,
        );
        src.start().await?;
        Ok(src)
    }

    /// Create and start a tool source in one step with an explicit outbound safety policy.
    ///
    /// # Errors
    ///
    /// Returns an error if spec loading, parsing, tool discovery, or probing fails.
    pub async fn build_with_safety(
        name: String,
        config: ApiServerConfig,
        default_timeout: Duration,
        startup_timeout: Duration,
        probe_enabled: bool,
        probe_timeout: Duration,
        safety: OutboundHttpSafety,
    ) -> Result<Self> {
        let src = Self::new_with_safety(
            name,
            config,
            default_timeout,
            startup_timeout,
            probe_enabled,
            probe_timeout,
            safety,
        );
        src.start().await?;
        Ok(src)
    }

    fn client(&self) -> Result<&Client> {
        self.client.as_ref().map_err(|error| {
            OpenApiToolsError::Startup(format!("Failed to build safe HTTP client: {error}"))
        })
    }
}

impl OpenApiToolSource {
    /// List the MCP `Tool`s exposed by this source.
    #[must_use]
    pub fn list_tools(&self) -> Vec<Tool> {
        let tools = self.tools.read();
        tools
            .iter()
            .map(|t| {
                let schema_obj = t
                    .input_schema
                    .as_object()
                    .cloned()
                    .unwrap_or_else(JsonObject::new);
                let mut tool = Tool::new(
                    t.name.clone(),
                    t.description.clone().unwrap_or_default(),
                    Arc::new(schema_obj),
                );
                tool.output_schema.clone_from(&t.output_schema);
                tool.annotations = Some(unrelated_http_tools::semantics::annotations_for_method(
                    &t.method,
                ));
                tool
            })
            .collect()
    }

    /// Execute a tool call.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the tool name is unknown
    /// - required parameters are missing
    /// - the outbound HTTP request fails (transport or non-2xx response)
    pub async fn call_tool(&self, name: &str, arguments: Value) -> Result<CallToolResult> {
        // Clone the tool inside the sync block to avoid holding lock across await.
        let tool = {
            let tools = self.tools.read();
            tools
                .iter()
                .find(|t| t.name == name || t.original_name == name)
                .cloned()
                .ok_or_else(|| OpenApiToolsError::Runtime(format!("Tool not found: {name}")))?
        };

        let resp = self.execute_request(&tool, &arguments).await?;
        match resp {
            ToolResponse::Image { bytes, mime_type } => {
                let b64 = base64::engine::general_purpose::STANDARD.encode(bytes);
                // Response shaping doesn't apply to binary.
                Ok(CallToolResult::success(vec![ContentBlock::image(
                    b64, mime_type,
                )]))
            }
            ToolResponse::Value(mut body) => {
                tool.response_pipeline.apply_to_value(&mut body);

                // Emit `structured_content` only when the tool advertises an output schema.
                if tool.output_schema.is_some() {
                    let structured = json!({ "body": body });
                    let text = serde_json::to_string(&structured)
                        .unwrap_or_else(|_| structured.to_string());
                    let mut result = CallToolResult::success(vec![ContentBlock::text(text)]);
                    result.structured_content = Some(structured);
                    Ok(result)
                } else {
                    let text = if let Some(s) = body.as_str() {
                        s.to_string()
                    } else {
                        serde_json::to_string(&body).unwrap_or_else(|_| body.to_string())
                    };
                    Ok(CallToolResult::success(vec![ContentBlock::text(text)]))
                }
            }
        }
    }

    /// Load the spec, discover tools, and make the source ready for use.
    ///
    /// # Errors
    ///
    /// Returns an error if spec loading/parsing, tool discovery, or reachability probing fails.
    pub async fn start(&self) -> Result<()> {
        self.client()?;
        let startup_timeout = self.startup_timeout;

        let startup = async {
            // Load and parse spec.
            let spec = self.load_spec().await?;

            // Determine base URL.
            let base_url = self
                .config
                .base_url
                .clone()
                .or_else(|| spec.servers.first().map(|s| s.url.clone()));

            let Some(base_url) = base_url else {
                return Err(OpenApiToolsError::OpenApi(
                    "No base URL configured and none found in spec".to_string(),
                ));
            };
            let base_url = self.resolve_base_url(&base_url)?;

            // Discover tools.
            let tools = self.discover_tools(&spec).await?;

            Ok::<_, OpenApiToolsError>((spec, base_url, tools))
        };

        let (spec, base_url, tools) = match tokio::time::timeout(startup_timeout, startup).await {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                return Err(OpenApiToolsError::Startup(format!(
                    "Startup timeout after {}s for OpenAPI tool source '{}'",
                    startup_timeout.as_secs(),
                    self.name
                )));
            }
        };

        // Optional reachability probe (baseUrl only).
        self.probe_base_url(&base_url).await?;

        *self.base_url.write() = Some(base_url);

        tracing::info!(
            "Discovered {} tools from OpenAPI spec '{}'",
            tools.len(),
            self.name
        );

        // Store spec and tools.
        *self.spec.write() = Some(spec);
        *self.tools.write() = tools;

        Ok(())
    }

    /// The base URL inferred during `start` (or `build*`).
    ///
    /// Returns `None` if the source has not been started yet.
    #[must_use]
    pub fn inferred_base_url(&self) -> Option<String> {
        self.base_url.read().clone()
    }

    /// The `info.title` from the parsed `OpenAPI` spec.
    ///
    /// Returns `None` if the source has not been started yet.
    #[must_use]
    pub fn spec_title(&self) -> Option<String> {
        self.spec.read().as_ref().map(|s| s.info.title.clone())
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;
    use unrelated_http_tools::config::EndpointDefaults;

    #[test]
    fn test_generate_canonical_name() {
        assert_eq!(
            generate_canonical_name("get", "/pet/{petId}"),
            "get_pet_petId"
        );
        assert_eq!(
            generate_canonical_name("post", "/store/order"),
            "post_store_order"
        );
        assert_eq!(
            generate_canonical_name("get", "/user/{username}/repos"),
            "get_user_username_repos"
        );
        assert_eq!(
            generate_canonical_name("delete", "/pet/{petId}"),
            "delete_pet_petId"
        );
    }

    #[test]
    fn test_matches_pattern() {
        assert!(matches_pattern("GET *", "GET /users"));
        assert!(matches_pattern("GET /users/*", "GET /users/123"));
        assert!(!matches_pattern("GET /users/*", "POST /users/123"));
        assert!(matches_pattern("DELETE *", "DELETE /users/123"));
        assert!(!matches_pattern("DELETE *", "GET /users"));
        // Braces are common in OpenAPI templated paths and should be treated literally.
        assert!(matches_pattern("GET /users/{id}", "GET /users/{id}"));
    }

    #[test]
    fn test_value_to_string() {
        assert_eq!(value_to_string(&json!("hello")), "hello");
        assert_eq!(value_to_string(&json!(123)), "123");
        assert_eq!(value_to_string(&json!(true)), "true");
        assert_eq!(value_to_string(&json!(null)), "");
    }

    #[test]
    fn test_resolve_base_url_relative_to_spec_url() {
        let cfg = ApiServerConfig {
            spec: "https://petstore3.swagger.io/api/v3/openapi.json".to_string(),
            spec_hash: None,
            spec_hash_policy: HashPolicy::Ignore,
            base_url: None,
            auth: None,
            auto_discover: crate::config::AutoDiscoverConfig::Enabled(true),
            endpoints: HashMap::new(),
            defaults: EndpointDefaults {
                timeout: None,
                array_style: None,
                headers: HashMap::new(),
            },
            response_transforms: Vec::new(),
            response_overrides: Vec::new(),
            overrides: crate::config::OpenApiOverridesConfig::default(),
        };

        let backend = OpenApiToolSource::new(
            "test".to_string(),
            cfg,
            Duration::from_secs(30),
            Duration::from_secs(30),
            false,
            Duration::from_secs(0),
        );

        assert_eq!(
            backend.resolve_base_url("/api/v3").unwrap(),
            "https://petstore3.swagger.io/api/v3"
        );
    }

    #[test]
    fn test_resolve_base_url_requires_absolute_when_spec_is_not_a_url() {
        let cfg = ApiServerConfig {
            spec: "inline".to_string(),
            spec_hash: None,
            spec_hash_policy: HashPolicy::Ignore,
            base_url: None,
            auth: None,
            auto_discover: crate::config::AutoDiscoverConfig::Enabled(true),
            endpoints: HashMap::new(),
            defaults: EndpointDefaults {
                timeout: None,
                array_style: None,
                headers: HashMap::new(),
            },
            response_transforms: Vec::new(),
            response_overrides: Vec::new(),
            overrides: crate::config::OpenApiOverridesConfig::default(),
        };

        let backend = OpenApiToolSource::new(
            "test".to_string(),
            cfg,
            Duration::from_secs(30),
            Duration::from_secs(30),
            false,
            Duration::from_secs(0),
        );

        assert!(backend.resolve_base_url("/api/v3").is_err());
    }

    fn test_backend() -> OpenApiToolSource {
        let cfg = ApiServerConfig {
            spec: "inline".to_string(),
            spec_hash: None,
            spec_hash_policy: HashPolicy::Ignore,
            base_url: Some("https://example.com".to_string()),
            auth: None,
            auto_discover: crate::config::AutoDiscoverConfig::Enabled(true),
            endpoints: HashMap::new(),
            defaults: EndpointDefaults {
                timeout: None,
                array_style: None,
                headers: HashMap::new(),
            },
            response_transforms: Vec::new(),
            response_overrides: Vec::new(),
            overrides: crate::config::OpenApiOverridesConfig::default(),
        };

        OpenApiToolSource::new(
            "test".to_string(),
            cfg,
            Duration::from_secs(30),
            Duration::from_secs(30),
            false,
            Duration::from_secs(0),
        )
    }

    #[tokio::test]
    async fn test_resolves_parameter_ref() {
        let spec_yaml = r#"
openapi: "3.0.0"
info:
  title: t
  version: "1"
components:
  parameters:
    QParam:
      name: q
      in: query
      required: true
      schema:
        type: string
paths:
  /users:
    get:
      operationId: listUsers
      parameters:
        - $ref: '#/components/parameters/QParam'
      responses:
        "200":
          description: ok
"#;
        let spec: OpenAPI = serde_saphyr::from_str(spec_yaml).unwrap();
        let backend = test_backend();

        let tools = backend.discover_tools(&spec).await.unwrap();
        let tool = tools.iter().find(|t| t.name == "listUsers").unwrap();
        assert!(tool.parameters.iter().any(|p| p.tool_name == "q"));
    }

    #[tokio::test]
    async fn test_merges_path_item_parameters_and_overrides() {
        let spec_yaml = r#"
openapi: "3.0.0"
info:
  title: t
  version: "1"
paths:
  /users:
    parameters:
      - name: q
        in: query
        required: false
        schema: { type: string }
    get:
      operationId: listUsers
      parameters:
        - name: q
          in: query
          required: true
          schema: { type: string }
      responses:
        "200":
          description: ok
"#;
        let spec: OpenAPI = serde_saphyr::from_str(spec_yaml).unwrap();
        let backend = test_backend();

        let tools = backend.discover_tools(&spec).await.unwrap();
        let tool = tools.iter().find(|t| t.name == "listUsers").unwrap();
        let q = tool
            .parameters
            .iter()
            .find(|p| p.original_name == "q" && matches!(p.location, ParamLocation::Query))
            .unwrap();
        assert!(q.required);
    }

    #[tokio::test]
    async fn test_generates_output_schema_for_json_2xx_response() {
        let spec_yaml = r#"
openapi: "3.0.0"
info:
  title: t
  version: "1"
paths:
  /users:
    get:
      operationId: listUsers
      responses:
        "200":
          description: ok
          content:
            application/json:
              schema:
                type: array
                items:
                  type: string
"#;
        let spec: OpenAPI = serde_saphyr::from_str(spec_yaml).unwrap();
        let backend = test_backend();

        let tools = backend.discover_tools(&spec).await.unwrap();
        let tool = tools.iter().find(|t| t.name == "listUsers").unwrap();
        let out = tool.output_schema.as_ref().expect("output_schema");

        assert_eq!(out.get("type").and_then(Value::as_str), Some("object"));
        let props = out
            .get("properties")
            .and_then(Value::as_object)
            .expect("properties");
        let body = props
            .get("body")
            .and_then(Value::as_object)
            .expect("body schema");
        assert_eq!(body.get("type").and_then(Value::as_str), Some("array"));
    }

    #[tokio::test]
    async fn test_resolves_request_body_ref_and_schema_ref_for_flattening() {
        let spec_yaml = r#"
openapi: "3.0.0"
info:
  title: t
  version: "1"
components:
  requestBodies:
    CreateUserBody:
      required: true
      content:
        application/json:
          schema:
            $ref: '#/components/schemas/CreateUser'
  schemas:
    CreateUser:
      type: object
      required: [name]
      properties:
        name: { type: string }
        age: { type: integer }
paths:
  /users:
    post:
      operationId: createUser
      requestBody:
        $ref: '#/components/requestBodies/CreateUserBody'
      responses:
        "200":
          description: ok
"#;
        let spec: OpenAPI = serde_saphyr::from_str(spec_yaml).unwrap();
        let backend = test_backend();

        let tools = backend.discover_tools(&spec).await.unwrap();
        let tool = tools.iter().find(|t| t.name == "createUser").unwrap();
        let name = tool
            .parameters
            .iter()
            .find(|p| p.tool_name == "name")
            .unwrap();
        let age = tool
            .parameters
            .iter()
            .find(|p| p.tool_name == "age")
            .unwrap();
        assert!(name.required);
        assert!(!age.required);
    }

    #[test]
    fn test_query_serialization_respects_explode() {
        let backend = test_backend();

        // form + explode=true => repeated keys
        let pairs = backend.serialize_query_param(
            "tags",
            &json!(["a", "b"]),
            false,
            Some(&QuerySerialization {
                style: QueryStyle::Form,
                explode: true,
                allow_reserved: false,
                allow_empty_value: false,
            }),
        );
        assert_eq!(
            pairs,
            vec![
                QueryPair {
                    key: "tags".to_string(),
                    value: "a".to_string(),
                    allow_reserved: false
                },
                QueryPair {
                    key: "tags".to_string(),
                    value: "b".to_string(),
                    allow_reserved: false
                }
            ]
        );

        // form + explode=false => single key with comma-separated value
        let pairs = backend.serialize_query_param(
            "tags",
            &json!(["a", "b"]),
            false,
            Some(&QuerySerialization {
                style: QueryStyle::Form,
                explode: false,
                allow_reserved: false,
                allow_empty_value: false,
            }),
        );
        assert_eq!(
            pairs,
            vec![QueryPair {
                key: "tags".to_string(),
                value: "a,b".to_string(),
                allow_reserved: false
            }]
        );
    }

    #[tokio::test]
    async fn test_resolves_external_file_ref_parameter() {
        let dir = tempdir().unwrap();
        let common_path = dir.path().join("common.yaml");
        let root_path = dir.path().join("root.yaml");

        fs::write(
            &common_path,
            r"
components:
  parameters:
    QParam:
      name: q
      in: query
      required: true
      schema:
        type: string
",
        )
        .unwrap();

        fs::write(
            &root_path,
            r#"
openapi: "3.0.0"
info:
  title: t
  version: "1"
paths:
  /users:
    get:
      operationId: listUsers
      parameters:
        - $ref: "./common.yaml#/components/parameters/QParam"
      responses:
        "200":
          description: ok
"#,
        )
        .unwrap();

        let cfg = ApiServerConfig {
            spec: root_path.display().to_string(),
            spec_hash: None,
            spec_hash_policy: HashPolicy::Ignore,
            base_url: Some("https://example.com".to_string()),
            auth: None,
            auto_discover: crate::config::AutoDiscoverConfig::Enabled(true),
            endpoints: HashMap::new(),
            defaults: EndpointDefaults {
                timeout: None,
                array_style: None,
                headers: HashMap::new(),
            },
            response_transforms: Vec::new(),
            response_overrides: Vec::new(),
            overrides: crate::config::OpenApiOverridesConfig::default(),
        };

        let backend = OpenApiToolSource::new(
            "test".to_string(),
            cfg,
            Duration::from_secs(30),
            Duration::from_secs(30),
            false,
            Duration::from_secs(0),
        );

        backend.start().await.unwrap();
        let tools = backend.tools.read();
        let tool = tools.iter().find(|t| t.name == "listUsers").unwrap();
        let schema = &tool.input_schema;
        assert!(schema.get("properties").and_then(|p| p.get("q")).is_some());
    }

    #[tokio::test]
    async fn test_resolves_nested_external_file_refs_for_request_body_flattening() {
        let dir = tempdir().unwrap();
        let schemas_path = dir.path().join("schemas.yaml");
        let bodies_path = dir.path().join("bodies.yaml");
        let root_path = dir.path().join("root.yaml");

        fs::write(
            &schemas_path,
            r"
components:
  schemas:
    CreateUser:
      type: object
      required: [name]
      properties:
        name: { type: string }
        age: { type: integer }
",
        )
        .unwrap();

        fs::write(
            &bodies_path,
            r#"
components:
  requestBodies:
    CreateUserBody:
      required: true
      content:
        application/json:
          schema:
            $ref: "./schemas.yaml#/components/schemas/CreateUser"
"#,
        )
        .unwrap();

        fs::write(
            &root_path,
            r#"
openapi: "3.0.0"
info:
  title: t
  version: "1"
paths:
  /users:
    post:
      operationId: createUser
      requestBody:
        $ref: "./bodies.yaml#/components/requestBodies/CreateUserBody"
      responses:
        "200":
          description: ok
"#,
        )
        .unwrap();

        let cfg = ApiServerConfig {
            spec: root_path.display().to_string(),
            spec_hash: None,
            spec_hash_policy: HashPolicy::Ignore,
            base_url: Some("https://example.com".to_string()),
            auth: None,
            auto_discover: crate::config::AutoDiscoverConfig::Enabled(true),
            endpoints: HashMap::new(),
            defaults: EndpointDefaults {
                timeout: None,
                array_style: None,
                headers: HashMap::new(),
            },
            response_transforms: Vec::new(),
            response_overrides: Vec::new(),
            overrides: crate::config::OpenApiOverridesConfig::default(),
        };

        let backend = OpenApiToolSource::new(
            "test".to_string(),
            cfg,
            Duration::from_secs(30),
            Duration::from_secs(30),
            false,
            Duration::from_secs(0),
        );

        backend.start().await.unwrap();
        let tools = backend.tools.read();
        let tool = tools.iter().find(|t| t.name == "createUser").unwrap();
        let schema = &tool.input_schema;

        // Flattened body properties should show up as tool args.
        let props = schema.get("properties").unwrap();
        assert!(props.get("name").is_some());
        assert!(props.get("age").is_some());
        assert!(
            schema
                .get("required")
                .and_then(|r| r.as_array())
                .is_some_and(|r| r.iter().any(|v| v == "name"))
        );
    }
}
