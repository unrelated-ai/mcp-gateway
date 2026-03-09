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
use rmcp::model::{CallToolResult, Content, JsonObject, Tool};
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
use unrelated_http_tools::safety::{OutboundHttpSafety, RedirectPolicy, sanitize_reqwest_error};
use url::Url;

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
    client: Client,
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
        let client = match safety.redirects {
            RedirectPolicy::None => reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap_or_else(|_| Client::new()),
            RedirectPolicy::Checked => Client::new(),
        };

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

    async fn probe_base_url(&self, base_url: &str) -> Result<()> {
        if !self.probe_enabled {
            return Ok(());
        }

        let url = Url::parse(base_url).map_err(|e| {
            OpenApiToolsError::OpenApi(format!("Invalid baseUrl '{base_url}': {e}"))
        })?;

        self.safety
            .check_url(&url)
            .await
            .map_err(|e| OpenApiToolsError::Http(format!("Base URL probe blocked: {e}")))?;

        // We consider *any* HTTP response as "reachable" (401/403/404 are fine).
        // Only transport errors / timeouts fail the probe.
        let res = self
            .client
            .head(url)
            .timeout(self.probe_timeout)
            .send()
            .await;

        match res {
            Ok(_resp) => Ok(()),
            Err(e) => Err(OpenApiToolsError::Startup(format!(
                "OpenAPI baseUrl probe failed for '{}': {}",
                self.name, e
            ))),
        }
    }

    /// Load and parse the `OpenAPI` spec.
    async fn load_spec(&self) -> Result<OpenAPI> {
        let spec_content = if self.config.spec.starts_with("http://")
            || self.config.spec.starts_with("https://")
        {
            // Fetch from URL
            tracing::info!("Fetching OpenAPI spec from {}", self.config.spec);
            let url = Url::parse(&self.config.spec).map_err(|e| {
                OpenApiToolsError::OpenApi(format!(
                    "Invalid OpenAPI spec URL '{}': {e}",
                    self.config.spec
                ))
            })?;
            self.safety
                .check_url(&url)
                .await
                .map_err(|e| OpenApiToolsError::Http(format!("OpenAPI spec fetch blocked: {e}")))?;

            let resp = self.client.get(url).send().await.map_err(|e| {
                OpenApiToolsError::OpenApiSpecFetch {
                    url: self.config.spec.clone(),
                    message: sanitize_reqwest_error(&e),
                }
            })?;

            Self::read_response_body_limited(resp, self.safety.max_response_bytes)
                .await
                .map_err(|e| OpenApiToolsError::OpenApiSpecReadBody {
                    url: self.config.spec.clone(),
                    message: e.to_string(),
                })?
        } else {
            // Read from file
            tracing::info!("Loading OpenAPI spec from {}", self.config.spec);
            std::fs::read_to_string(&self.config.spec).map_err(|e| {
                OpenApiToolsError::OpenApiSpecReadFile {
                    path: self.config.spec.clone(),
                    source: e,
                }
            })?
        };

        // Verify hash if configured
        if let Some(expected_hash) = &self.config.spec_hash {
            let actual_hash = format!("sha256:{}", hex::encode(Sha256::digest(&spec_content)));
            if actual_hash != *expected_hash {
                match self.config.spec_hash_policy {
                    HashPolicy::Fail => {
                        return Err(OpenApiToolsError::OpenApi(format!(
                            "Spec hash mismatch. Expected: {expected_hash}, Got: {actual_hash}",
                        )));
                    }
                    HashPolicy::Warn => {
                        tracing::warn!(
                            "Spec hash mismatch for '{}'. Expected: {}, Got: {}",
                            self.name,
                            expected_hash,
                            actual_hash
                        );
                    }
                    HashPolicy::Ignore => {}
                }
            }
        }

        // Parse spec (JSON is a valid subset of YAML, so serde_yaml alone is enough)
        let spec: OpenAPI = serde_yaml::from_str(&spec_content).map_err(|e| {
            OpenApiToolsError::OpenApiSpecParse {
                location: self.config.spec.clone(),
                source: e,
            }
        })?;

        Ok(spec)
    }

    /// Discover tools from the `OpenAPI` spec.
    async fn discover_tools(&self, spec: &OpenAPI) -> Result<Vec<GeneratedTool>> {
        let root_doc = DocId::parse(&self.config.spec)?;
        let resolver = OpenApiResolver::new(root_doc, spec, &self.client, &self.safety)?;
        let mut tools = Vec::new();
        let mut tool_names: HashSet<String> = HashSet::new();
        let mut ops: Vec<OperationInfo> = Vec::new();
        let mut response_override_match_counts: Vec<usize> =
            vec![0; self.config.response_overrides.len()];
        let mut response_overrides: HashMap<OperationKey, ResolvedResponseOverride> =
            HashMap::new();

        // Get explicit endpoint configs
        let explicit_endpoints = &self.config.endpoints;

        self.validate_response_override_configs()?;

        for (path, path_item) in &spec.paths.paths {
            let (path_doc, path_item) = match resolver
                .resolve_path_item(resolver.root_doc(), path_item)
                .await
            {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!("Skipping path '{}' in '{}': {}", path, self.name, e);
                    continue;
                }
            };

            // Process each HTTP method
            let methods = [
                ("get", &path_item.get),
                ("post", &path_item.post),
                ("put", &path_item.put),
                ("delete", &path_item.delete),
                ("patch", &path_item.patch),
            ];

            let method_ops: Vec<MethodOp<'_>> = methods
                .into_iter()
                .filter_map(|(method, operation)| {
                    operation.as_ref().map(|op| MethodOp {
                        method,
                        operation: op,
                        info: OperationInfo {
                            method: method.to_string(),
                            path: path.clone(),
                            operation_id: op.operation_id.clone(),
                        },
                    })
                })
                .collect();

            for MethodOp {
                method,
                operation: op,
                info,
            } in method_ops
            {
                // Track this operation (used for override matcher validation and tooling).
                let op_key = OperationKey::from_info(&info);
                ops.push(info);

                self.register_response_override_for_operation(
                    &op_key,
                    &mut response_override_match_counts,
                    &mut response_overrides,
                )?;

                // Check for explicit config
                let explicit_config = explicit_endpoints
                    .get(path)
                    .and_then(|methods| methods.get(method));

                // If explicit config exists, use it
                // If auto-discover is enabled and no explicit config, generate tool
                let should_generate = explicit_config.is_some()
                    || (self.config.auto_discover.is_enabled()
                        && self.should_auto_discover(method, path, op));

                if !should_generate {
                    continue;
                }

                let input = ToolGenerationInput {
                    current_doc: &path_doc,
                    path_item_params: &path_item.parameters,
                    path,
                    method,
                    operation: op,
                };

                match self
                    .generate_tool(&resolver, input, &mut tool_names, &response_overrides)
                    .await
                {
                    Ok(tool) => tools.push(tool),
                    Err(e) => {
                        tracing::warn!(
                            "Skipping {} {} in '{}': {}",
                            method.to_uppercase(),
                            path,
                            self.name,
                            e
                        );
                    }
                }
            }
        }

        self.apply_overrides(&ops, &mut tools, &response_overrides)?;

        self.warn_unmatched_response_overrides(&response_override_match_counts);

        Ok(tools)
    }

    fn validate_response_override_configs(&self) -> Result<()> {
        for (idx, ovr) in self.config.response_overrides.iter().enumerate() {
            if ovr.matcher.operation_id.is_none()
                && ovr.matcher.method.is_none()
                && ovr.matcher.path.is_none()
            {
                return Err(OpenApiToolsError::Config(format!(
                    "OpenAPI responseOverrides[{idx}] matcher in '{}' is empty (need operationId and/or method+path)",
                    self.name
                )));
            }
            if let Some(schema) = ovr.output_schema.as_ref()
                && !schema.is_object()
            {
                return Err(OpenApiToolsError::Config(format!(
                    "Invalid responseOverrides[{idx}].outputSchema in '{}': outputSchema must be a JSON object (JSON Schema)",
                    self.name
                )));
            }
        }
        Ok(())
    }

    fn register_response_override_for_operation(
        &self,
        op_key: &OperationKey,
        match_counts: &mut [usize],
        out: &mut HashMap<OperationKey, ResolvedResponseOverride>,
    ) -> Result<()> {
        let matched = match_response_override(
            op_key,
            &self.config.response_overrides,
            match_counts,
            &self.name,
        )?;
        let Some((idx, resolved)) = matched else {
            return Ok(());
        };

        if out.insert(op_key.clone(), resolved).is_some() {
            return Err(OpenApiToolsError::Config(format!(
                "OpenAPI responseOverrides[{idx}] in '{}' is ambiguous (matched the same operation more than once)",
                self.name
            )));
        }

        Ok(())
    }

    fn warn_unmatched_response_overrides(&self, match_counts: &[usize]) {
        for (idx, count) in match_counts.iter().enumerate() {
            if *count == 0 {
                tracing::warn!(
                    backend = %self.name,
                    override_idx = idx,
                    "OpenAPI responseOverrides entry did not match any operation"
                );
            }
        }
    }

    /// Check if an operation should be auto-discovered.
    fn should_auto_discover(&self, method: &str, path: &str, _op: &Operation) -> bool {
        let operation_str = format!("{} {}", method.to_uppercase(), path);

        let include_patterns = self.config.auto_discover.include_patterns();
        let exclude_patterns = self.config.auto_discover.exclude_patterns();

        // Exclude patterns win.
        if exclude_patterns
            .iter()
            .any(|p| matches_pattern(p, &operation_str))
        {
            return false;
        }

        // If include patterns are specified, must match at least one.
        if !include_patterns.is_empty() {
            return include_patterns
                .iter()
                .any(|p| matches_pattern(p, &operation_str));
        }

        true
    }

    fn apply_overrides(
        &self,
        ops: &[OperationInfo],
        tools: &mut Vec<GeneratedTool>,
        response_overrides: &HashMap<OperationKey, ResolvedResponseOverride>,
    ) -> Result<()> {
        for (override_tool_name, override_cfg) in &self.config.overrides.tools {
            let Some(matched) = match_override(ops, &override_cfg.matcher, &self.name)? else {
                tracing::warn!(
                    "OpenAPI override '{}' in '{}' did not match any operation",
                    override_tool_name,
                    self.name
                );
                continue;
            };

            // Remove existing tool(s) for the matched operation (override precedence).
            if let Some(op_id) = &matched.operation_id {
                tools.retain(|t| t.operation_id.as_ref() != Some(op_id));
            } else {
                tools.retain(|t| {
                    !(t.method.as_str().eq_ignore_ascii_case(&matched.method)
                        && t.path == matched.path)
                });
            }

            // Prevent name collisions: overrides must be explicit.
            if tools.iter().any(|t| t.name == *override_tool_name) {
                return Err(OpenApiToolsError::Config(format!(
                    "OpenAPI override tool name '{}' in '{}' conflicts with an existing tool name",
                    override_tool_name, self.name
                )));
            }

            let op_key = OperationKey::from_info(&matched);
            let response_override = response_overrides.get(&op_key);

            let generated = manual_override_to_tool(
                &self.name,
                override_tool_name,
                override_cfg,
                matched.operation_id.clone(),
                response_override,
                &self.config.response_transforms,
            )?;
            tools.push(generated);
        }

        Ok(())
    }

    fn base_tool_name(
        explicit_config: Option<&crate::config::EndpointConfig>,
        operation: &Operation,
        method: &str,
        path: &str,
    ) -> String {
        if let Some(config) = explicit_config {
            config.tool.clone()
        } else if let Some(op_id) = &operation.operation_id {
            op_id.clone()
        } else {
            generate_canonical_name(method, path)
        }
    }

    fn tool_description(
        explicit_config: Option<&crate::config::EndpointConfig>,
        operation: &Operation,
        method: &str,
        path: &str,
    ) -> Option<String> {
        explicit_config
            .and_then(|c| c.description.clone())
            .or_else(|| operation.summary.clone())
            .or_else(|| operation.description.clone())
            .or_else(|| Some(format!("Calls {} {}", method.to_uppercase(), path)))
    }

    async fn collect_tool_parameters(
        &self,
        resolver: &OpenApiResolver<'_>,
        input: ToolGenerationInput<'_>,
        param_configs: Option<&HashMap<String, ParamConfig>>,
    ) -> Result<Vec<ToolParameter>> {
        let current_doc = input.current_doc;
        let path_item_params = input.path_item_params;
        let operation = input.operation;
        let method = input.method;
        let path = input.path;

        let merged_params = merge_parameters(
            resolver,
            current_doc,
            path_item_params,
            &operation.parameters,
        )
        .await?;

        let mut parameters = Vec::new();
        let mut param_names: HashSet<String> = HashSet::new();

        for (param_doc, param) in &merged_params {
            let param_info = self
                .extract_parameter(resolver, param_doc, param, param_configs)
                .await?;

            // Check for collision
            if param_names.contains(&param_info.tool_name) {
                return Err(OpenApiToolsError::ParamCollision(format!(
                    "Parameter '{}' appears multiple times in {} {}. \
                     Use explicit config with 'rename' to resolve.",
                    param_info.tool_name,
                    method.to_uppercase(),
                    path
                )));
            }
            param_names.insert(param_info.tool_name.clone());
            parameters.push(param_info);
        }

        // Request body parameters (flatten object properties)
        if let Some(body_ref) = &operation.request_body {
            let (body_doc, body) = resolver.resolve_request_body(current_doc, body_ref).await?;
            if let Some(schema_ref) = body
                .content
                .get("application/json")
                .and_then(|c| c.schema.as_ref())
            {
                let body_params = self
                    .extract_body_params(
                        resolver,
                        &body_doc,
                        &body,
                        schema_ref,
                        param_configs,
                        &param_names,
                    )
                    .await?;

                // Check for collisions
                for bp in &body_params {
                    if param_names.contains(&bp.tool_name) {
                        return Err(OpenApiToolsError::ParamCollision(format!(
                            "Body parameter '{}' collides with path/query parameter in {} {}. \
                             Use explicit config with 'rename' to resolve.",
                            bp.tool_name,
                            method.to_uppercase(),
                            path
                        )));
                    }
                    param_names.insert(bp.tool_name.clone());
                }
                parameters.extend(body_params);
            }
        }

        Ok(parameters)
    }

    /// Generate a tool from an `OpenAPI` operation.
    async fn generate_tool(
        &self,
        resolver: &OpenApiResolver<'_>,
        input: ToolGenerationInput<'_>,
        tool_names: &mut HashSet<String>,
        response_overrides: &HashMap<OperationKey, ResolvedResponseOverride>,
    ) -> Result<GeneratedTool> {
        let current_doc = input.current_doc;
        let path = input.path;
        let method = input.method;
        let operation = input.operation;

        let explicit_config = self
            .config
            .endpoints
            .get(path)
            .and_then(|methods| methods.get(method));

        // Determine tool name
        let tool_name = Self::base_tool_name(explicit_config, operation, method, path);

        // Ensure unique name
        let final_name = reserve_unique_tool_name(tool_names, &tool_name);

        // Get description
        let description = Self::tool_description(explicit_config, operation, method, path);

        let param_configs = explicit_config.map(|c| &c.params);
        let parameters = self
            .collect_tool_parameters(resolver, input, param_configs)
            .await?;

        // Build input schema
        let input_schema = build_input_schema(&parameters);

        let op_key = OperationKey {
            method: method.to_string(),
            path: path.to_string(),
            operation_id: operation.operation_id.clone(),
        };
        let response_override = response_overrides.get(&op_key);

        // Compile response shaping pipeline for this tool.
        let response_pipeline =
            if let Some(chain) = response_override.and_then(|o| o.transforms.as_ref()) {
                let effective = apply_chain(&self.config.response_transforms, Some(chain));
                compile_pipeline_from_transforms(&effective).map_err(|e| {
                    OpenApiToolsError::Config(format!(
                        "Invalid response transforms for {} {} in '{}': {e}",
                        method.to_uppercase(),
                        path,
                        self.name
                    ))
                })?
            } else {
                compile_pipeline_from_transforms(&self.config.response_transforms).map_err(|e| {
                    OpenApiToolsError::Config(format!(
                        "Invalid response transforms for '{}' (global): {e}",
                        self.name
                    ))
                })?
            };

        // Determine body schema: responseOverrides.outputSchema wins, otherwise best-effort derive from spec.
        let body_schema =
            if let Some(schema) = response_override.and_then(|o| o.output_schema.as_ref()) {
                Some(schema.clone())
            } else {
                self.derive_body_schema(resolver, current_doc, operation)
                    .await?
            };

        let output_schema = if let Some(mut body_schema) = body_schema {
            let warnings = response_pipeline.apply_to_schema(&mut body_schema);
            for w in warnings {
                tracing::warn!(
                    backend = %self.name,
                    tool = %final_name,
                    warning = %w,
                    "response schema transform warning"
                );
            }
            Some(wrap_body_output_schema(&body_schema)?)
        } else {
            None
        };

        let http_method = resolve_http_method(method)?;

        Ok(GeneratedTool {
            name: final_name,
            original_name: tool_name,
            operation_id: operation.operation_id.clone(),
            description,
            method: http_method,
            path: path.to_string(),
            parameters,
            input_schema,
            response_mode: HttpResponseMode::Json,
            output_schema,
            response_pipeline,
        })
    }

    async fn derive_body_schema(
        &self,
        resolver: &OpenApiResolver<'_>,
        current_doc: &DocId,
        operation: &Operation,
    ) -> Result<Option<Value>> {
        // Prefer explicit 2xx codes (200..=299), otherwise fall back to 2XX range.
        let mut explicit_2xx: Vec<(u16, &ReferenceOr<Response>)> = Vec::new();
        let mut range_2xx: Option<&ReferenceOr<Response>> = None;

        for (code, resp) in &operation.responses.responses {
            match code {
                StatusCode::Code(n) if (200..300).contains(n) => explicit_2xx.push((*n, resp)),
                StatusCode::Range(n) if *n == 2 => range_2xx = Some(resp),
                _ => {}
            }
        }

        explicit_2xx.sort_by_key(|(n, _)| *n);

        let resp_ref = if let Some((_, r)) = explicit_2xx.first() {
            *r
        } else if let Some(r) = range_2xx {
            r
        } else {
            return Ok(None);
        };

        let (resp_doc, resp) = resolver.resolve_response(current_doc, resp_ref).await?;

        // Select a JSON-ish media type.
        let mt = if let Some(mt) = resp.content.get("application/json") {
            Some(mt)
        } else {
            resp.content.iter().find_map(|(k, v)| {
                let lower = k.to_ascii_lowercase();
                (lower.contains("json") || lower.ends_with("+json")).then_some(v)
            })
        };
        let Some(mt) = mt else {
            return Ok(None);
        };

        let Some(schema_ref) = mt.schema.as_ref() else {
            return Ok(None);
        };

        let body_schema = extract_schema_ref(resolver, &resp_doc, schema_ref).await?;
        Ok(Some(body_schema))
    }

    /// Extract parameter info from `OpenAPI` parameter.
    async fn extract_parameter(
        &self,
        resolver: &OpenApiResolver<'_>,
        current_doc: &DocId,
        param: &Parameter,
        param_configs: Option<&HashMap<String, ParamConfig>>,
    ) -> Result<ToolParameter> {
        let (name, location, required, schema, query_ser, openapi_description) = match param {
            Parameter::Path { parameter_data, .. } => {
                let schema = extract_schema(resolver, current_doc, &parameter_data.format).await?;
                (
                    parameter_data.name.clone(),
                    ParamLocation::Path,
                    true, // Path params are always required
                    schema,
                    None,
                    parameter_data.description.clone(),
                )
            }
            Parameter::Query {
                parameter_data,
                style,
                allow_reserved,
                allow_empty_value,
                ..
            } => {
                let schema = extract_schema(resolver, current_doc, &parameter_data.format).await?;
                let style = style.clone();
                let allow_reserved = *allow_reserved;
                let allow_empty_value = allow_empty_value.unwrap_or(false);
                let explode = parameter_data
                    .explode
                    .unwrap_or_else(|| default_query_explode(&style));
                (
                    parameter_data.name.clone(),
                    ParamLocation::Query,
                    parameter_data.required,
                    schema,
                    Some(QuerySerialization {
                        style,
                        explode,
                        allow_reserved,
                        allow_empty_value,
                    }),
                    parameter_data.description.clone(),
                )
            }
            Parameter::Header { parameter_data, .. } => {
                let schema = extract_schema(resolver, current_doc, &parameter_data.format).await?;
                (
                    parameter_data.name.clone(),
                    ParamLocation::Header,
                    parameter_data.required,
                    schema,
                    None,
                    parameter_data.description.clone(),
                )
            }
            Parameter::Cookie { .. } => {
                return Err(OpenApiToolsError::OpenApi(
                    "Cookie parameters not supported".to_string(),
                ));
            }
        };

        // Apply config overrides
        let config = param_configs.and_then(|c| c.get(&name));
        let tool_name = config
            .and_then(|c| c.rename.clone())
            .unwrap_or_else(|| name.clone());
        let required = config.and_then(|c| c.required).unwrap_or(required);
        let default = config.and_then(|c| c.default.clone());

        let mut schema = schema;
        let config_description = config.and_then(|c| c.description.clone());
        if let Some(obj) = schema.as_object_mut() {
            if let Some(desc) = config_description {
                obj.insert("description".to_string(), Value::String(desc));
            } else if !obj.contains_key("description")
                && let Some(desc) = openapi_description
            {
                obj.insert("description".to_string(), Value::String(desc));
            }
        }

        Ok(ToolParameter {
            tool_name,
            original_name: name,
            location,
            required,
            default,
            schema,
            query: query_ser,
        })
    }

    /// Extract body parameters from request body schema.
    async fn extract_body_params(
        &self,
        resolver: &OpenApiResolver<'_>,
        current_doc: &DocId,
        body: &RequestBody,
        schema_ref: &ReferenceOr<Schema>,
        param_configs: Option<&HashMap<String, ParamConfig>>,
        existing_names: &HashSet<String>,
    ) -> Result<Vec<ToolParameter>> {
        let mut params = Vec::new();

        // Resolve schema ref (internal components/schemas supported).
        let schema = match schema_ref {
            ReferenceOr::Item(s) => s.clone(),
            ReferenceOr::Reference { .. } => {
                resolver.resolve_schema(current_doc, schema_ref).await?.1
            }
        };

        // If the requestBody itself is not required, we avoid marking any of its
        // flattened params as required (we can't express conditional requiredness
        // cleanly at the tool-arg level).
        let body_required = body.required;

        // Flatten object properties. Otherwise, expose a single `body` argument.
        if let openapiv3::SchemaKind::Type(openapiv3::Type::Object(obj)) = &schema.schema_kind {
            for (prop_name, prop_schema) in &obj.properties {
                let required = body_required && obj.required.contains(prop_name);

                // Skip if name already exists (collision)
                if existing_names.contains(prop_name) {
                    continue; // Will be caught by collision check in caller
                }

                let mut prop_schema_value = match prop_schema {
                    ReferenceOr::Item(s) => schema_to_json(s),
                    ReferenceOr::Reference { reference } => {
                        // Keep $ref for nested schemas (still useful for clients/tools).
                        json!({"$ref": reference})
                    }
                };

                // Apply config overrides
                let config = param_configs.and_then(|c| c.get(prop_name));
                let tool_name = config
                    .and_then(|c| c.rename.clone())
                    .unwrap_or_else(|| prop_name.clone());
                let required = config.and_then(|c| c.required).unwrap_or(required);
                let default = config.and_then(|c| c.default.clone());
                if let Some(desc) = config.and_then(|c| c.description.clone())
                    && let Some(obj) = prop_schema_value.as_object_mut()
                {
                    obj.insert("description".to_string(), Value::String(desc));
                }

                params.push(ToolParameter {
                    tool_name,
                    original_name: prop_name.clone(),
                    location: ParamLocation::Body,
                    required,
                    default,
                    schema: prop_schema_value,
                    query: None,
                });
            }
        } else {
            // Fallback: represent the full body as one tool argument named "body"
            // (unless it would collide).
            if !existing_names.contains("body") {
                let required = body_required;
                params.push(ToolParameter {
                    tool_name: "body".to_string(),
                    original_name: "body".to_string(),
                    location: ParamLocation::Body,
                    required,
                    default: None,
                    schema: schema_to_json(&schema),
                    query: None,
                });
            }
        }

        Ok(params)
    }

    /// Execute an HTTP request for a tool call.
    async fn execute_request(
        &self,
        tool: &GeneratedTool,
        arguments: &Value,
    ) -> Result<ToolResponse> {
        let base_url = self
            .base_url
            .read()
            .clone()
            .ok_or_else(|| OpenApiToolsError::Runtime("Base URL not configured".to_string()))?;

        let mut parts = self.build_request_parts(tool, arguments)?;
        self.apply_query_auth(&mut parts.query_params);
        let url = Self::build_url(&base_url, &parts.path, &parts.query_params)?;

        // Outbound safety checks (SSRF + allowlists).
        self.safety
            .check_url(&url)
            .await
            .map_err(|e| OpenApiToolsError::Http(e.to_string()))?;

        // Build request
        let mut request = self.client.request(tool.method.clone(), url);
        request = self.apply_auth(request);
        request = self.apply_headers(request, parts.headers);
        request = Self::apply_body(request, parts.body_payload.as_ref(), &parts.body_fields);
        request = self.apply_timeout(request);

        // Execute request
        let response = request
            .send()
            .await
            .map_err(|e| OpenApiToolsError::Request(sanitize_reqwest_error(&e)))?;

        // Handle response
        let status = response.status();
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(std::string::ToString::to_string);
        let bytes =
            Self::read_response_body_limited_bytes(response, self.safety.max_response_bytes)
                .await?;

        if status.is_success() {
            if Self::is_image_content_type(content_type.as_deref()) {
                let mime_type = content_type.unwrap_or_else(|| "image/*".to_string());
                return Ok(ToolResponse::Image { bytes, mime_type });
            }

            let body = Self::bytes_to_text_or_base64_json(&bytes, content_type.as_deref());
            match tool.response_mode {
                HttpResponseMode::Text => Ok(ToolResponse::Value(body)),
                HttpResponseMode::Json => {
                    // Try to parse as JSON, fall back to text
                    let result: Value = match body {
                        Value::String(s) => serde_json::from_str(&s).unwrap_or_else(|_| json!(s)),
                        other => other,
                    };
                    Ok(ToolResponse::Value(result))
                }
            }
        } else {
            // Map HTTP error to MCP error
            let body = Self::bytes_to_text_or_base64_json(&bytes, content_type.as_deref());
            let error_body: Value = match body {
                Value::String(s) => serde_json::from_str(&s).unwrap_or_else(|_| json!(s)),
                other => other,
            };
            let status_code = status.as_u16();
            let reason = status.canonical_reason().unwrap_or("Unknown");
            Err(OpenApiToolsError::Http(format!(
                "API returned {status_code} {reason}: {error_body}",
            )))
        }
    }

    async fn read_response_body_limited_bytes(
        mut response: reqwest::Response,
        max_bytes: Option<usize>,
    ) -> Result<Vec<u8>> {
        let Some(max) = max_bytes else {
            let bytes = response
                .bytes()
                .await
                .map_err(|e| OpenApiToolsError::Request(sanitize_reqwest_error(&e)))?;
            return Ok(bytes.to_vec());
        };

        if let Some(len) = response.content_length()
            && len > max as u64
        {
            return Err(OpenApiToolsError::Http(format!(
                "Response too large: {len} bytes (limit {max})"
            )));
        }

        let mut out: Vec<u8> = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| OpenApiToolsError::Request(sanitize_reqwest_error(&e)))?
        {
            if out.len().saturating_add(chunk.len()) > max {
                return Err(OpenApiToolsError::Http(format!(
                    "Response too large: exceeded {max} bytes"
                )));
            }
            out.extend_from_slice(&chunk);
        }

        Ok(out)
    }

    async fn read_response_body_limited(
        mut response: reqwest::Response,
        max_bytes: Option<usize>,
    ) -> Result<String> {
        let Some(max) = max_bytes else {
            return response
                .text()
                .await
                .map_err(|e| OpenApiToolsError::Request(sanitize_reqwest_error(&e)));
        };

        if let Some(len) = response.content_length()
            && len > max as u64
        {
            return Err(OpenApiToolsError::Http(format!(
                "Response too large: {len} bytes (limit {max})"
            )));
        }

        let mut out: Vec<u8> = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| OpenApiToolsError::Request(sanitize_reqwest_error(&e)))?
        {
            if out.len().saturating_add(chunk.len()) > max {
                return Err(OpenApiToolsError::Http(format!(
                    "Response too large: exceeded {max} bytes"
                )));
            }
            out.extend_from_slice(&chunk);
        }

        String::from_utf8(out)
            .map_err(|_| OpenApiToolsError::Http("Response is not valid UTF-8".into()))
    }

    fn is_image_content_type(content_type: Option<&str>) -> bool {
        let Some(ct) = content_type else {
            return false;
        };
        let Ok(m) = ct.parse::<Mime>() else {
            return false;
        };
        m.type_() == mime::IMAGE
    }

    fn bytes_to_text_or_base64_json(bytes: &[u8], content_type: Option<&str>) -> Value {
        if let Ok(s) = std::str::from_utf8(bytes) {
            Value::String(s.to_string())
        } else {
            let b64 = base64::engine::general_purpose::STANDARD.encode(bytes);
            json!({
                "encoding": "base64",
                "mimeType": content_type,
                "data": b64
            })
        }
    }

    fn build_request_parts(&self, tool: &GeneratedTool, arguments: &Value) -> Result<RequestParts> {
        // Build URL with path parameters substituted
        let mut path = tool.path.clone();
        let mut query_params: Vec<QueryPair> = Vec::new();
        let mut headers: Vec<(String, String)> = Vec::new();
        let mut body_fields: HashMap<String, Value> = HashMap::new();
        let mut body_payload: Option<Value> = None;

        for param in &tool.parameters {
            // Get value from arguments or use default
            let value = arguments
                .get(&param.tool_name)
                .cloned()
                .or_else(|| param.default.clone());

            if param.required && value.is_none() {
                let param_name = &param.tool_name;
                return Err(OpenApiToolsError::Runtime(format!(
                    "Missing required parameter: {param_name}",
                )));
            }

            let value = match value {
                Some(Value::Null) => None,
                other => other,
            };

            if let Some(val) = value {
                match param.location {
                    ParamLocation::Path => {
                        let val_str = value_to_string(&val);
                        path = path.replace(&format!("{{{}}}", param.original_name), &val_str);
                    }
                    ParamLocation::Query => {
                        let pairs = self.serialize_query_param(
                            &param.original_name,
                            &val,
                            param.required,
                            param.query.as_ref(),
                        );
                        query_params.extend(pairs);
                    }
                    ParamLocation::Header => {
                        let val_str = value_to_string(&val);
                        headers.push((param.original_name.clone(), val_str));
                    }
                    ParamLocation::Body => {
                        if param.original_name == "body" && param.tool_name == "body" {
                            body_payload = Some(val);
                        } else {
                            body_fields.insert(param.original_name.clone(), val);
                        }
                    }
                }
            }
        }

        if !path.starts_with('/') {
            path = format!("/{path}");
        }

        Ok(RequestParts {
            path,
            query_params,
            headers,
            body_fields,
            body_payload,
        })
    }

    fn apply_query_auth(&self, query_params: &mut Vec<QueryPair>) {
        if let Some(AuthConfig::Query { name, value }) = &self.config.auth {
            query_params.push(QueryPair {
                key: name.clone(),
                value: value.clone(),
                allow_reserved: false,
            });
        }
    }

    fn build_url(base_url: &str, path: &str, query_params: &[QueryPair]) -> Result<Url> {
        let url = format!("{}{}", base_url.trim_end_matches('/'), path);
        let mut url = Url::parse(&url)
            .map_err(|e| OpenApiToolsError::Runtime(format!("Invalid URL: {e}")))?;

        if !query_params.is_empty() {
            let mut query = String::new();
            for (i, p) in query_params.iter().enumerate() {
                if i > 0 {
                    query.push('&');
                }
                query.push_str(&encode_query_component(&p.key, false));
                query.push('=');
                query.push_str(&encode_query_component(&p.value, p.allow_reserved));
            }
            url.set_query(Some(&query));
        }

        Ok(url)
    }

    fn apply_headers(
        &self,
        mut request: reqwest::RequestBuilder,
        headers: Vec<(String, String)>,
    ) -> reqwest::RequestBuilder {
        for (key, value) in &self.config.defaults.headers {
            request = request.header(key, value);
        }
        for (key, value) in headers {
            request = request.header(&key, &value);
        }
        request
    }

    fn apply_body(
        mut request: reqwest::RequestBuilder,
        body_payload: Option<&Value>,
        body_fields: &HashMap<String, Value>,
    ) -> reqwest::RequestBuilder {
        if let Some(payload) = body_payload {
            request = request.json(payload);
        } else if !body_fields.is_empty() {
            request = request.json(body_fields);
        }
        request
    }

    fn apply_timeout(&self, mut request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        let effective_timeout = match self.config.defaults.timeout {
            Some(0) => None, // explicit disable
            Some(secs) => Some(Duration::from_secs(secs)),
            None => Some(self.default_timeout),
        };

        if let Some(t) = effective_timeout {
            request = request.timeout(t);
        }

        request
    }

    /// Apply authentication to the HTTP request.
    fn apply_auth(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.config.auth {
            Some(AuthConfig::Bearer { token }) => request.bearer_auth(token),
            Some(AuthConfig::Header { name, value }) => request.header(name, value),
            Some(AuthConfig::Basic { username, password }) => {
                request.basic_auth(username, Some(password))
            }
            Some(AuthConfig::Query { .. } | AuthConfig::None) | None => request, // query auth is applied during URL building
        }
    }

    fn serialize_query_param(
        &self,
        name: &str,
        value: &Value,
        required: bool,
        ser: Option<&QuerySerialization>,
    ) -> Vec<QueryPair> {
        let (style, explode) = match ser {
            Some(s) => (s.style.clone(), s.explode),
            None => {
                // Fallback to legacy defaults if we somehow didn't capture param-level info.
                match self.config.defaults.array_style.unwrap_or_default() {
                    ArrayStyle::Form => (QueryStyle::Form, true),
                    ArrayStyle::SpaceDelimited => (QueryStyle::SpaceDelimited, false),
                    ArrayStyle::PipeDelimited => (QueryStyle::PipeDelimited, false),
                    ArrayStyle::DeepObject => (QueryStyle::DeepObject, true),
                }
            }
        };

        let allow_reserved = ser.is_some_and(|s| s.allow_reserved);
        let allow_empty_value = ser.is_some_and(|s| s.allow_empty_value);

        if query_value_is_empty(value) {
            return serialize_empty_query_value(name, required, allow_reserved, allow_empty_value);
        }

        match value {
            Value::Array(arr) => serialize_query_array(name, arr, &style, explode, allow_reserved),
            Value::Object(map) => {
                serialize_query_object(name, map, &style, explode, allow_reserved)
            }
            _ => serialize_query_scalar(name, value, allow_reserved),
        }
    }
}

fn query_value_is_empty(value: &Value) -> bool {
    match value {
        Value::String(s) => s.is_empty(),
        Value::Array(a) => a.is_empty(),
        Value::Object(o) => o.is_empty(),
        Value::Null => true,
        _ => false,
    }
}

fn serialize_empty_query_value(
    name: &str,
    required: bool,
    allow_reserved: bool,
    allow_empty_value: bool,
) -> Vec<QueryPair> {
    if allow_empty_value || required {
        return vec![QueryPair {
            key: name.to_string(),
            value: String::new(),
            allow_reserved,
        }];
    }

    Vec::new()
}

fn serialize_query_array(
    name: &str,
    arr: &[Value],
    style: &QueryStyle,
    explode: bool,
    allow_reserved: bool,
) -> Vec<QueryPair> {
    let items: Vec<String> = arr.iter().map(value_to_string).collect();
    match style {
        QueryStyle::Form => {
            if explode {
                items
                    .into_iter()
                    .map(|v| QueryPair {
                        key: name.to_string(),
                        value: v,
                        allow_reserved,
                    })
                    .collect()
            } else {
                vec![QueryPair {
                    key: name.to_string(),
                    value: items.join(","),
                    allow_reserved,
                }]
            }
        }
        QueryStyle::SpaceDelimited => vec![QueryPair {
            key: name.to_string(),
            value: items.join(" "),
            allow_reserved,
        }],
        QueryStyle::PipeDelimited => vec![QueryPair {
            key: name.to_string(),
            value: items.join("|"),
            allow_reserved,
        }],
        QueryStyle::DeepObject => vec![QueryPair {
            key: name.to_string(),
            value: items.join(","),
            allow_reserved,
        }],
    }
}

fn serialize_query_object(
    name: &str,
    map: &serde_json::Map<String, Value>,
    style: &QueryStyle,
    explode: bool,
    allow_reserved: bool,
) -> Vec<QueryPair> {
    match style {
        QueryStyle::DeepObject => map
            .iter()
            .map(|(k, v)| QueryPair {
                key: format!("{name}[{k}]"),
                value: value_to_string(v),
                allow_reserved,
            })
            .collect(),
        QueryStyle::Form => {
            if explode {
                map.iter()
                    .map(|(k, v)| QueryPair {
                        key: k.clone(),
                        value: value_to_string(v),
                        allow_reserved,
                    })
                    .collect()
            } else {
                let mut parts = Vec::with_capacity(map.len() * 2);
                for (k, v) in map {
                    parts.push(k.clone());
                    parts.push(value_to_string(v));
                }
                vec![QueryPair {
                    key: name.to_string(),
                    value: parts.join(","),
                    allow_reserved,
                }]
            }
        }
        QueryStyle::SpaceDelimited | QueryStyle::PipeDelimited => vec![QueryPair {
            key: name.to_string(),
            value: serde_json::to_string(map).unwrap_or_else(|_| "{}".to_string()),
            allow_reserved,
        }],
    }
}

fn serialize_query_scalar(name: &str, value: &Value, allow_reserved: bool) -> Vec<QueryPair> {
    vec![QueryPair {
        key: name.to_string(),
        value: value_to_string(value),
        allow_reserved,
    }]
}

fn match_override(
    ops: &[OperationInfo],
    matcher: &crate::config::OpenApiToolMatch,
    backend_name: &str,
) -> Result<Option<OperationInfo>> {
    let mut candidates: Vec<OperationInfo> = ops.to_vec();

    if let Some(op_id) = &matcher.operation_id {
        candidates.retain(|o| o.operation_id.as_deref() == Some(op_id.as_str()));
    }

    if let Some(method) = &matcher.method {
        let m = method.trim().to_lowercase();
        candidates.retain(|o| o.method == m);
    }

    if let Some(path) = &matcher.path {
        candidates.retain(|o| o.path == *path);
    }

    if matcher.operation_id.is_none() && matcher.method.is_none() && matcher.path.is_none() {
        return Err(OpenApiToolsError::Config(format!(
            "OpenAPI override matcher for '{backend_name}' is empty (need operationId and/or method+path)",
        )));
    }

    match candidates.len() {
        0 => Ok(None),
        1 => Ok(Some(candidates.remove(0))),
        _ => {
            let matched_count = candidates.len();
            Err(OpenApiToolsError::Config(format!(
                "OpenAPI override matcher in '{backend_name}' is ambiguous (matched {matched_count} operations)",
            )))
        }
    }
}

fn response_override_matches_operation(
    matcher: &crate::config::OpenApiToolMatch,
    op: &OperationKey,
) -> bool {
    if let Some(op_id) = &matcher.operation_id
        && op.operation_id.as_deref() != Some(op_id.as_str())
    {
        return false;
    }
    if let Some(method) = &matcher.method {
        let m = method.trim().to_lowercase();
        if m != op.method {
            return false;
        }
    }
    if let Some(path) = &matcher.path
        && *path != op.path
    {
        return false;
    }
    true
}

fn match_response_override(
    op: &OperationKey,
    overrides: &[crate::config::ResponseOverrideConfig],
    match_counts: &mut [usize],
    backend_name: &str,
) -> Result<Option<(usize, ResolvedResponseOverride)>> {
    let mut matched: Option<usize> = None;

    for (idx, ovr) in overrides.iter().enumerate() {
        if response_override_matches_operation(&ovr.matcher, op) {
            if matched.is_some() {
                return Err(OpenApiToolsError::Config(format!(
                    "OpenAPI responseOverrides in '{backend_name}' are ambiguous (multiple entries match {} {}{})",
                    op.method.to_uppercase(),
                    op.path,
                    op.operation_id
                        .as_deref()
                        .map(|id| format!(" (operationId: {id})"))
                        .unwrap_or_default(),
                )));
            }
            matched = Some(idx);
        }
    }

    let Some(idx) = matched else {
        return Ok(None);
    };

    if match_counts[idx] > 0 {
        return Err(OpenApiToolsError::Config(format!(
            "OpenAPI responseOverrides[{idx}] in '{backend_name}' is ambiguous (matched more than one operation); narrow the matcher",
        )));
    }
    match_counts[idx] = 1;

    let ovr = &overrides[idx];
    Ok(Some((
        idx,
        ResolvedResponseOverride {
            transforms: ovr.transforms.clone(),
            output_schema: ovr.output_schema.clone(),
        },
    )))
}

fn parse_manual_override_http_method(tool_name: &str, method: &str) -> Result<Method> {
    let method_str = method.trim();
    method_str.to_uppercase().parse().map_err(|_| {
        OpenApiToolsError::Config(format!(
            "Invalid HTTP method '{method_str}' in OpenAPI override tool '{tool_name}'",
        ))
    })
}

fn normalize_tool_path(path: &str) -> String {
    if path.starts_with('/') {
        return path.to_string();
    }
    format!("/{path}")
}

fn build_manual_override_parameters(
    tool_name: &str,
    params: &HashMap<String, unrelated_http_tools::config::HttpParamConfig>,
) -> Result<Vec<ToolParameter>> {
    let mut parameters: Vec<ToolParameter> = Vec::new();

    for (arg_name, p) in params {
        let (location, required_default) = match p.location {
            HttpParamLocation::Path => (ParamLocation::Path, true),
            HttpParamLocation::Query => (ParamLocation::Query, false),
            HttpParamLocation::Header => (ParamLocation::Header, false),
            HttpParamLocation::Body => (ParamLocation::Body, false),
        };

        let http_name = p.name.clone().unwrap_or_else(|| arg_name.clone());
        let required = p.required.unwrap_or(required_default);
        let schema = p
            .schema
            .clone()
            .unwrap_or_else(|| json!({"type": "string"}));

        let query = if location == ParamLocation::Query {
            let style = p.style.map_or(QueryStyle::Form, map_query_style_config);
            let explode = p.explode.unwrap_or_else(|| default_query_explode(&style));
            Some(QuerySerialization {
                style,
                explode,
                allow_reserved: p.allow_reserved.unwrap_or(false),
                allow_empty_value: p.allow_empty_value.unwrap_or(false),
            })
        } else {
            None
        };

        parameters.push(ToolParameter {
            tool_name: arg_name.clone(),
            original_name: http_name,
            location,
            required,
            default: p.default.clone(),
            schema,
            query,
        });
    }

    if parameters
        .iter()
        .map(|p| p.tool_name.as_str())
        .collect::<HashSet<_>>()
        .len()
        != parameters.len()
    {
        return Err(OpenApiToolsError::Config(format!(
            "Duplicate param name in OpenAPI override tool '{tool_name}'",
        )));
    }

    Ok(parameters)
}

fn compile_manual_override_response_pipeline(
    backend_name: &str,
    tool_name: &str,
    response_override: Option<&ResolvedResponseOverride>,
    global_response_transforms: &[ResponseTransform],
    tool_transforms: Option<&ResponseTransformChainConfig>,
) -> Result<Arc<CompiledResponsePipeline>> {
    let mut effective: Vec<ResponseTransform> = global_response_transforms.to_vec();
    if let Some(chain) = response_override.and_then(|o| o.transforms.as_ref()) {
        effective = apply_chain(&effective, Some(chain));
    }
    effective = apply_chain(&effective, tool_transforms);

    compile_pipeline_from_transforms(&effective).map_err(|e| {
        OpenApiToolsError::Config(format!(
            "Invalid response transforms for OpenAPI override tool '{tool_name}' in '{backend_name}': {e}",
        ))
    })
}

fn build_manual_override_output_schema(
    backend_name: &str,
    tool_name: &str,
    response_override: Option<&ResolvedResponseOverride>,
    response_cfg: &unrelated_http_tools::config::HttpResponseConfig,
    response_pipeline: &CompiledResponsePipeline,
) -> Result<Option<Arc<JsonObject>>> {
    // Output schema precedence:
    // 1) explicit per-tool outputSchema (manual override request)
    // 2) per-operation responseOverrides.outputSchema (if any)
    let body_schema = response_cfg.output_schema.clone().or_else(|| {
        response_override
            .and_then(|o| o.output_schema.as_ref())
            .cloned()
    });

    let Some(mut body_schema) = body_schema else {
        return Ok(None);
    };
    if !body_schema.is_object() {
        return Err(OpenApiToolsError::Config(format!(
            "Invalid outputSchema for OpenAPI override tool '{tool_name}' in '{backend_name}': outputSchema must be a JSON object (JSON Schema)",
        )));
    }

    let warnings = response_pipeline.apply_to_schema(&mut body_schema);
    for w in warnings {
        tracing::warn!(
            backend = %backend_name,
            tool = %tool_name,
            warning = %w,
            "response schema transform warning"
        );
    }

    Ok(Some(wrap_body_output_schema(&body_schema)?))
}

fn manual_override_to_tool(
    backend_name: &str,
    tool_name: &str,
    override_cfg: &OpenApiOverrideToolConfig,
    operation_id: Option<String>,
    response_override: Option<&ResolvedResponseOverride>,
    global_response_transforms: &[ResponseTransform],
) -> Result<GeneratedTool> {
    let HttpToolConfig {
        method,
        path,
        description,
        params,
        response,
    } = &override_cfg.request;

    let method = parse_manual_override_http_method(tool_name, method)?;
    let normalized_path = normalize_tool_path(path);
    let parameters = build_manual_override_parameters(tool_name, params)?;

    let input_schema = build_input_schema(&parameters);

    let final_description = override_cfg
        .description
        .clone()
        .or_else(|| description.clone())
        .or_else(|| {
            let method_name = method.as_str();
            Some(format!("Calls {method_name} {normalized_path}"))
        });

    let response_pipeline = compile_manual_override_response_pipeline(
        backend_name,
        tool_name,
        response_override,
        global_response_transforms,
        response.transforms.as_ref(),
    )?;

    let output_schema = build_manual_override_output_schema(
        backend_name,
        tool_name,
        response_override,
        response,
        &response_pipeline,
    )?;

    Ok(GeneratedTool {
        name: tool_name.to_string(),
        original_name: tool_name.to_string(),
        operation_id,
        description: final_description,
        method,
        path: normalized_path,
        parameters,
        input_schema,
        response_mode: response.mode,
        output_schema,
        response_pipeline,
    })
}

fn map_query_style_config(style: QueryStyleConfig) -> QueryStyle {
    match style {
        QueryStyleConfig::Form => QueryStyle::Form,
        QueryStyleConfig::SpaceDelimited => QueryStyle::SpaceDelimited,
        QueryStyleConfig::PipeDelimited => QueryStyle::PipeDelimited,
        QueryStyleConfig::DeepObject => QueryStyle::DeepObject,
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
                Ok(CallToolResult {
                    content: vec![Content::image(b64, mime_type)],
                    structured_content: None,
                    is_error: Some(false),
                    meta: None,
                })
            }
            ToolResponse::Value(mut body) => {
                tool.response_pipeline.apply_to_value(&mut body);

                // Emit `structured_content` only when the tool advertises an output schema.
                if tool.output_schema.is_some() {
                    let structured = json!({ "body": body });
                    let text = serde_json::to_string(&structured)
                        .unwrap_or_else(|_| structured.to_string());
                    Ok(CallToolResult {
                        content: vec![Content::text(text)],
                        structured_content: Some(structured),
                        is_error: Some(false),
                        meta: None,
                    })
                } else {
                    let text = if let Some(s) = body.as_str() {
                        s.to_string()
                    } else {
                        serde_json::to_string(&body).unwrap_or_else(|_| body.to_string())
                    };
                    Ok(CallToolResult::success(vec![Content::text(text)]))
                }
            }
        }
    }

    fn resolve_base_url(&self, base_url: &str) -> Result<String> {
        if base_url.starts_with("http://") || base_url.starts_with("https://") {
            return Ok(base_url.to_string());
        }

        // OpenAPI allows relative server URLs (e.g. "/api/v3"). When the spec itself was loaded
        // from a URL, resolve these against the spec URL so common specs "just work".
        if self.config.spec.starts_with("http://") || self.config.spec.starts_with("https://") {
            let mut spec_url = Url::parse(&self.config.spec).map_err(|e| {
                OpenApiToolsError::OpenApi(format!(
                    "Invalid OpenAPI spec URL '{}': {e}",
                    self.config.spec
                ))
            })?;
            spec_url.set_fragment(None);

            let resolved = spec_url.join(base_url).map_err(|e| {
                OpenApiToolsError::OpenApi(format!(
                    "Invalid baseUrl '{base_url}': {e} (set baseUrl explicitly)",
                ))
            })?;
            return Ok(resolved.to_string());
        }

        Err(OpenApiToolsError::OpenApi(format!(
            "Invalid baseUrl '{base_url}': must be an absolute http(s) URL (set baseUrl explicitly)",
        )))
    }

    /// Load the spec, discover tools, and make the source ready for use.
    ///
    /// # Errors
    ///
    /// Returns an error if spec loading/parsing, tool discovery, or reachability probing fails.
    pub async fn start(&self) -> Result<()> {
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

/// Generate a canonical tool name from method and path.
fn generate_canonical_name(method: &str, path: &str) -> String {
    let mut name = format!("{}_{}", method.to_lowercase(), path);

    // Remove leading slash
    if name.starts_with('/') {
        name = name[1..].to_string();
    }

    // Replace path params {param} with _param
    let re = Regex::new(r"\{([^}]+)\}").unwrap();
    name = re.replace_all(&name, "_$1").to_string();

    // Replace non-alphanumeric with underscore
    let re = Regex::new(r"[^a-zA-Z0-9]+").unwrap();
    name = re.replace_all(&name, "_").to_string();

    // Collapse repeated underscores
    let re = Regex::new(r"_+").unwrap();
    name = re.replace_all(&name, "_").to_string();

    // Trim underscores
    name = name.trim_matches('_').to_string();

    // Cap length
    if name.len() > 64 {
        name = name[..64].to_string();
    }

    name
}

/// Check if an operation matches a pattern.
fn matches_pattern(pattern: &str, operation: &str) -> bool {
    glob_match(pattern, operation)
}

fn reserve_unique_tool_name(tool_names: &mut HashSet<String>, base: &str) -> String {
    let base = base.to_string();
    if tool_names.insert(base.clone()) {
        return base;
    }

    let mut counter = 1;
    loop {
        let candidate = format!("{base}_{counter}");
        if tool_names.insert(candidate.clone()) {
            return candidate;
        }
        counter += 1;
    }
}

fn resolve_http_method(method: &str) -> Result<Method> {
    match method {
        "get" => Ok(Method::GET),
        "post" => Ok(Method::POST),
        "put" => Ok(Method::PUT),
        "delete" => Ok(Method::DELETE),
        "patch" => Ok(Method::PATCH),
        other => Err(OpenApiToolsError::Runtime(format!(
            "Unsupported HTTP method: {other}",
        ))),
    }
}

fn default_query_explode(style: &QueryStyle) -> bool {
    matches!(style, QueryStyle::Form | QueryStyle::DeepObject)
}

fn encode_query_component(s: &str, allow_reserved: bool) -> String {
    // Percent-encode everything except:
    // - unreserved: ALPHA / DIGIT / "-" / "." / "_" / "~"
    // - if allow_reserved: also keep common reserved characters (excluding separators)
    //   to avoid breaking our own `&`-joined query string.
    //
    // NOTE: We intentionally still encode '&' and '=' even when allowReserved=true,
    // because leaving them raw would corrupt multi-parameter query strings.
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        let keep = is_unreserved(b) || (allow_reserved && is_reserved_but_safe_in_pairs(b));
        if keep {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 0x0F) as usize] as char);
        }
    }
    out
}

fn is_unreserved(b: u8) -> bool {
    matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~')
}

fn is_reserved_but_safe_in_pairs(b: u8) -> bool {
    // RFC3986 reserved = gen-delims + sub-delims.
    // We exclude '&' and '=' because they are used as separators in our encoder,
    // and exclude '#' to avoid fragment confusion.
    matches!(
        b,
        b':' | b'/'
            | b'?'
            | b'['
            | b']'
            | b'@'
            | b'!'
            | b'$'
            | b'\''
            | b'('
            | b')'
            | b'*'
            | b'+'
            | b','
            | b';'
    )
}

fn glob_match(pattern: &str, text: &str) -> bool {
    // Simple glob matching on bytes:
    //   * => any sequence
    //   ? => any single character
    let pattern_bytes = pattern.as_bytes();
    let text_bytes = text.as_bytes();

    let mut pattern_index = 0usize;
    let mut text_index = 0usize;

    let mut star_index: Option<usize> = None;
    let mut star_text_index: usize = 0;

    while text_index < text_bytes.len() {
        match pattern_bytes.get(pattern_index) {
            Some(b'*') => {
                star_index = Some(pattern_index);
                pattern_index += 1;
                star_text_index = text_index;
            }
            Some(b'?') => {
                pattern_index += 1;
                text_index += 1;
            }
            Some(&b) if b == text_bytes[text_index] => {
                pattern_index += 1;
                text_index += 1;
            }
            _ => {
                let Some(si) = star_index else {
                    return false;
                };

                pattern_index = si + 1;
                star_text_index += 1;
                text_index = star_text_index;
            }
        }
    }

    while matches!(pattern_bytes.get(pattern_index), Some(b'*')) {
        pattern_index += 1;
    }

    pattern_index == pattern_bytes.len()
}

/// Extract JSON schema from parameter schema.
async fn extract_schema(
    resolver: &OpenApiResolver<'_>,
    current_doc: &DocId,
    format: &ParameterSchemaOrContent,
) -> Result<Value> {
    use ParameterSchemaOrContent::{Content, Schema};

    match format {
        Schema(ReferenceOr::Item(schema)) => Ok(schema_to_json(schema)),
        Schema(schema_ref @ ReferenceOr::Reference { reference }) => {
            // Try to inline internal schema refs for better tool schemas.
            match resolver.resolve_schema(current_doc, schema_ref).await {
                Ok((_doc, s)) => Ok(schema_to_json(&s)),
                Err(_) => Ok(json!({"$ref": reference})),
            }
        }
        Content(_) => Ok(json!({"type": "string"})), // Fallback
    }
}

async fn merge_parameters(
    resolver: &OpenApiResolver<'_>,
    current_doc: &DocId,
    path_item_params: &[ReferenceOr<Parameter>],
    operation_params: &[ReferenceOr<Parameter>],
) -> Result<Vec<(DocId, Parameter)>> {
    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    struct Key {
        loc: &'static str,
        name: String,
    }

    fn key_for(p: &Parameter) -> Key {
        match p {
            Parameter::Path { parameter_data, .. } => Key {
                loc: "path",
                name: parameter_data.name.clone(),
            },
            Parameter::Query { parameter_data, .. } => Key {
                loc: "query",
                name: parameter_data.name.clone(),
            },
            Parameter::Header { parameter_data, .. } => Key {
                loc: "header",
                name: parameter_data.name.clone(),
            },
            Parameter::Cookie { parameter_data, .. } => Key {
                loc: "cookie",
                name: parameter_data.name.clone(),
            },
        }
    }

    let mut merged: Vec<(DocId, Parameter)> = Vec::new();
    let mut index: HashMap<Key, usize> = HashMap::new();

    for p in path_item_params {
        let (doc, rp) = resolver.resolve_parameter(current_doc, p).await?;
        let k = key_for(&rp);
        index.insert(k, merged.len());
        merged.push((doc, rp));
    }

    for p in operation_params {
        let (doc, rp) = resolver.resolve_parameter(current_doc, p).await?;
        let k = key_for(&rp);
        if let Some(i) = index.get(&k).copied() {
            merged[i] = (doc, rp);
        } else {
            index.insert(k, merged.len());
            merged.push((doc, rp));
        }
    }

    Ok(merged)
}

/// Convert `OpenAPI` schema to JSON Schema value.
fn schema_to_json(schema: &Schema) -> Value {
    let mut result = json!({});

    if let Some(desc) = &schema.schema_data.description {
        result["description"] = json!(desc);
    }

    match &schema.schema_kind {
        openapiv3::SchemaKind::Type(t) => match t {
            openapiv3::Type::String(s) => {
                result["type"] = json!("string");
                if !s.enumeration.is_empty() {
                    let enum_values: Vec<_> = s
                        .enumeration
                        .iter()
                        .filter_map(std::clone::Clone::clone)
                        .collect();
                    result["enum"] = json!(enum_values);
                }
            }
            openapiv3::Type::Number(_) => {
                result["type"] = json!("number");
            }
            openapiv3::Type::Integer(_) => {
                result["type"] = json!("integer");
            }
            openapiv3::Type::Boolean(_) => {
                result["type"] = json!("boolean");
            }
            openapiv3::Type::Array(a) => {
                result["type"] = json!("array");
                if let Some(items) = &a.items {
                    match items {
                        ReferenceOr::Item(item_schema) => {
                            result["items"] = schema_to_json(item_schema);
                        }
                        ReferenceOr::Reference { reference } => {
                            result["items"] = json!({"$ref": reference});
                        }
                    }
                }
            }
            openapiv3::Type::Object(o) => {
                result["type"] = json!("object");
                let mut properties = json!({});
                for (name, prop) in &o.properties {
                    match prop {
                        ReferenceOr::Item(prop_schema) => {
                            properties[name] = schema_to_json(prop_schema);
                        }
                        ReferenceOr::Reference { reference } => {
                            properties[name] = json!({ "$ref": reference });
                        }
                    }
                }
                if !o.properties.is_empty() {
                    result["properties"] = properties;
                }
                if !o.required.is_empty() {
                    result["required"] = json!(o.required);
                }
            }
        },
        _ => {
            result["type"] = json!("object");
        }
    }

    result
}

/// Build input schema for a tool from its parameters.
fn build_input_schema(parameters: &[ToolParameter]) -> Value {
    let mut properties = json!({});
    let mut required: Vec<String> = Vec::new();

    for param in parameters {
        let mut prop_schema = param.schema.clone();

        // Add default if present
        if let Some(default) = &param.default {
            prop_schema["default"] = default.clone();
        }

        properties[&param.tool_name] = prop_schema;

        if param.required && param.default.is_none() {
            required.push(param.tool_name.clone());
        }
    }

    let mut schema = json!({
        "type": "object",
        "properties": properties,
    });

    if !required.is_empty() {
        schema["required"] = json!(required);
    }

    schema
}

fn wrap_body_output_schema(body_schema: &Value) -> Result<Arc<JsonObject>> {
    if !body_schema.is_object() {
        return Err(OpenApiToolsError::Config(
            "outputSchema must be a JSON object (JSON Schema)".to_string(),
        ));
    }

    // MCP requires the root output schema to be an object.
    let wrapped = json!({
        "type": "object",
        "required": ["body"],
        "properties": {
            "body": body_schema.clone()
        }
    });

    let obj = wrapped.as_object().cloned().unwrap_or_else(JsonObject::new);
    Ok(Arc::new(obj))
}

async fn extract_schema_ref(
    resolver: &OpenApiResolver<'_>,
    current_doc: &DocId,
    schema_ref: &ReferenceOr<Schema>,
) -> Result<Value> {
    match schema_ref {
        ReferenceOr::Item(schema) => Ok(schema_to_json(schema)),
        ReferenceOr::Reference { reference } => {
            match resolver.resolve_schema(current_doc, schema_ref).await {
                Ok((_doc, s)) => Ok(schema_to_json(&s)),
                Err(_) => Ok(json!({"$ref": reference})),
            }
        }
    }
}

/// Convert a JSON value to a string for URL/header parameters.
fn value_to_string(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => String::new(),
        _ => value.to_string(),
    }
}

// ============================================================================
// Tests
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
        let spec: OpenAPI = serde_yaml::from_str(spec_yaml).unwrap();
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
        let spec: OpenAPI = serde_yaml::from_str(spec_yaml).unwrap();
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
        let spec: OpenAPI = serde_yaml::from_str(spec_yaml).unwrap();
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
        let spec: OpenAPI = serde_yaml::from_str(spec_yaml).unwrap();
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
