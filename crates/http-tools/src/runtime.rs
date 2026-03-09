//! Runtime for executing manually-configured HTTP tools.
//!
//! This is the shared implementation of the "HTTP tool DSL" used by:
//! - the Adapter (standalone mode)
//! - the Gateway (gateway-native tool sources)

use crate::config::{
    AuthConfig, HttpParamLocation, HttpResponseMode, HttpServerConfig, QueryStyleConfig,
};
use crate::response_shaping::CompiledResponsePipeline;
use crate::safety::{OutboundHttpSafety, RedirectPolicy, sanitize_reqwest_error};
use base64::Engine as _;
use mime::Mime;
use openapiv3::QueryStyle;
use reqwest::{Client, Method};
use rmcp::model::{CallToolResult, Content, JsonObject, Tool};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tracing::warn;
use url::Url;

#[derive(Debug, Error)]
pub enum HttpToolsError {
    #[error("config error: {0}")]
    Config(String),
    #[error("runtime error: {0}")]
    Runtime(String),
    #[error("http error: {0}")]
    Http(String),
    #[error("http transport error: {0}")]
    Transport(String),
}

pub type Result<T> = std::result::Result<T, HttpToolsError>;

impl From<reqwest::Error> for HttpToolsError {
    fn from(value: reqwest::Error) -> Self {
        Self::Transport(sanitize_reqwest_error(&value))
    }
}

#[derive(Debug, Clone)]
struct GeneratedTool {
    name: String,
    original_name: String,
    description: Option<String>,
    method: Method,
    path: String,
    parameters: Vec<ToolParameter>,
    input_schema: Value,
    response_mode: HttpResponseMode,
    output_schema: Option<Arc<JsonObject>>,
    response_pipeline: Arc<CompiledResponsePipeline>,
}

#[derive(Debug, Clone)]
struct ToolParameter {
    tool_name: String,
    http_name: String,
    location: HttpParamLocation,
    required: bool,
    default: Option<Value>,
    schema: Value,
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

#[derive(Clone)]
pub struct HttpToolSource {
    inner: Arc<HttpToolSourceInner>,
}

struct HttpToolSourceInner {
    config: HttpServerConfig,
    tools: Vec<GeneratedTool>,
    client: Client,
    default_timeout: Duration,
    safety: OutboundHttpSafety,
}

impl HttpToolSource {
    /// Build a tool source from a static config.
    ///
    /// The resulting instance is immutable and safe to share across tasks.
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration is invalid (e.g. invalid base URL, invalid HTTP
    /// method, duplicate tool names, or duplicate parameter names).
    pub fn new(
        name: impl Into<String>,
        config: HttpServerConfig,
        default_timeout: Duration,
    ) -> Result<Self> {
        Self::new_with_safety(
            name,
            config,
            default_timeout,
            OutboundHttpSafety::permissive(),
        )
    }

    /// Build a tool source from a static config with an explicit outbound safety policy.
    ///
    /// This is primarily intended for multi-tenant gateway deployments where outbound HTTP must be
    /// constrained (SSRF protections, limits, redirect policy).
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration is invalid or if the HTTP client cannot be built for
    /// the requested safety policy.
    pub fn new_with_safety(
        name: impl Into<String>,
        config: HttpServerConfig,
        default_timeout: Duration,
        safety: OutboundHttpSafety,
    ) -> Result<Self> {
        // Basic validation of base URL.
        Url::parse(&config.base_url).map_err(|e| {
            HttpToolsError::Config(format!(
                "Invalid baseUrl '{}' for HTTP tool source: {e}",
                config.base_url
            ))
        })?;

        let name = name.into();
        let tools = generate_tools(&name, &config)?;

        let client = match safety.redirects {
            RedirectPolicy::None => reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .map_err(HttpToolsError::from)?,
            RedirectPolicy::Checked => Client::new(),
        };

        Ok(Self {
            inner: Arc::new(HttpToolSourceInner {
                config,
                tools,
                client,
                default_timeout,
                safety,
            }),
        })
    }

    /// List the MCP `Tool`s exposed by this source.
    #[must_use]
    pub fn list_tools(&self) -> Vec<Tool> {
        self.inner
            .tools
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
                tool.annotations = Some(crate::semantics::annotations_for_method(&t.method));
                tool
            })
            .collect()
    }

    /// Execute a tool call against this source.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the tool name is unknown
    /// - required parameters are missing
    /// - the HTTP request fails (transport or non-2xx response)
    pub async fn call_tool(&self, tool_name: &str, arguments: Value) -> Result<CallToolResult> {
        let tool = self
            .inner
            .tools
            .iter()
            .find(|t| t.name == tool_name || t.original_name == tool_name)
            .ok_or_else(|| HttpToolsError::Runtime(format!("Tool not found: {tool_name}")))?;

        let resp = execute_request(&self.inner, tool, &arguments).await?;
        match resp {
            ToolResponse::Image { bytes, mime_type } => {
                let b64 = base64::engine::general_purpose::STANDARD.encode(bytes);
                // Response shaping doesn't apply to binary.
                Ok(CallToolResult::success(vec![Content::image(
                    b64, mime_type,
                )]))
            }
            ToolResponse::Value(mut body) => {
                tool.response_pipeline.apply_to_value(&mut body);

                // Emit `structured_content` only when the tool advertises an output schema.
                if tool.output_schema.is_some() {
                    let structured = json!({ "body": body });
                    // Return both `structured_content` and `Content::text(...)` for interoperability:
                    // some MCP clients only render `content` and ignore `structured_content`.
                    let text = serde_json::to_string(&structured)
                        .unwrap_or_else(|_| structured.to_string());

                    let mut result = CallToolResult::success(vec![Content::text(text)]);
                    result.structured_content = Some(structured);
                    Ok(result)
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
}

enum ToolResponse {
    Value(Value),
    Image { bytes: Vec<u8>, mime_type: String },
}

fn generate_tools(source_name: &str, config: &HttpServerConfig) -> Result<Vec<GeneratedTool>> {
    let mut out = Vec::new();
    let mut names: HashSet<String> = HashSet::new();

    for (tool_name, tool_cfg) in &config.tools {
        if !names.insert(tool_name.clone()) {
            return Err(HttpToolsError::Config(format!(
                "Duplicate tool name '{tool_name}' in HTTP tool source '{source_name}'"
            )));
        }

        let method = parse_http_method(source_name, tool_name, &tool_cfg.method)?;

        let path = tool_cfg.path.clone();
        let response_mode = tool_cfg.response.mode;

        let response_pipeline = crate::response_shaping::compile_pipeline(
            &config.response_transforms,
            tool_cfg.response.transforms.as_ref(),
        )
        .map_err(|e| {
            HttpToolsError::Config(format!(
                "Invalid response transforms for tool '{tool_name}' in HTTP tool source '{source_name}': {e}",
            ))
        })?;

        let output_schema = build_wrapped_output_schema(
            source_name,
            tool_name,
            &tool_cfg.response,
            &response_pipeline,
        )?;

        let parameters = collect_tool_parameters(source_name, tool_name, tool_cfg)?;

        let input_schema = build_input_schema(&parameters);

        out.push(GeneratedTool {
            name: tool_name.clone(),
            original_name: tool_name.clone(),
            description: tool_cfg.description.clone(),
            method,
            path,
            parameters,
            input_schema,
            response_mode,
            output_schema,
            response_pipeline,
        });
    }

    Ok(out)
}

fn parse_http_method(source_name: &str, tool_name: &str, method: &str) -> Result<Method> {
    let method_str = method.trim();
    method_str.to_uppercase().parse().map_err(|_| {
        HttpToolsError::Config(format!(
            "Invalid HTTP method '{method_str}' in tool '{tool_name}' (source '{source_name}')"
        ))
    })
}

fn build_wrapped_output_schema(
    source_name: &str,
    tool_name: &str,
    response_cfg: &crate::config::HttpResponseConfig,
    response_pipeline: &CompiledResponsePipeline,
) -> Result<Option<Arc<JsonObject>>> {
    let Some(body_schema) = response_cfg.output_schema.as_ref() else {
        return Ok(None);
    };
    if !body_schema.is_object() {
        return Err(HttpToolsError::Config(format!(
            "Invalid outputSchema for tool '{tool_name}' in HTTP tool source '{source_name}': outputSchema must be a JSON object (JSON Schema)"
        )));
    }

    let mut body_schema = body_schema.clone();
    let warnings = response_pipeline.apply_to_schema(&mut body_schema);
    for w in warnings {
        warn!(
            source = %source_name,
            tool = %tool_name,
            warning = %w,
            "response schema transform warning"
        );
    }

    let wrapped = json!({
        "type": "object",
        "required": ["body"],
        "properties": {
            "body": body_schema
        }
    });
    let schema_obj = wrapped.as_object().cloned().unwrap_or_else(JsonObject::new);
    Ok(Some(Arc::new(schema_obj)))
}

fn collect_tool_parameters(
    source_name: &str,
    tool_name: &str,
    tool_cfg: &crate::config::HttpToolConfig,
) -> Result<Vec<ToolParameter>> {
    let mut parameters = Vec::new();
    let mut param_names: HashSet<String> = HashSet::new();

    for (arg_name, p) in &tool_cfg.params {
        if !param_names.insert(arg_name.clone()) {
            return Err(HttpToolsError::Config(format!(
                "Duplicate param '{arg_name}' in tool '{tool_name}' (source '{source_name}')"
            )));
        }

        let http_name = p.name.clone().unwrap_or_else(|| arg_name.clone());
        let required_default = matches!(p.location, HttpParamLocation::Path);
        let required = p.required.unwrap_or(required_default);

        let schema = p
            .schema
            .clone()
            .unwrap_or_else(|| json!({"type": "string"}));

        let query = if matches!(p.location, HttpParamLocation::Query) {
            let style = p.style.map_or(QueryStyle::Form, map_query_style);
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
            http_name,
            location: p.location,
            required,
            default: p.default.clone(),
            schema,
            query,
        });
    }

    Ok(parameters)
}

async fn execute_request(
    inner: &HttpToolSourceInner,
    tool: &GeneratedTool,
    arguments: &Value,
) -> Result<ToolResponse> {
    let base_url = &inner.config.base_url;
    let mut parts = build_request_parts(tool, arguments)?;
    apply_query_auth(inner.config.auth.as_ref(), &mut parts.query_params);
    let url = build_url(base_url, &parts.path, &parts.query_params)?;

    // Outbound safety checks (SSRF + allowlists).
    inner.safety.check_url(&url).await?;

    let mut request = inner.client.request(tool.method.clone(), url);
    request = apply_auth(inner.config.auth.as_ref(), request);
    request = apply_headers(&inner.config, request, parts.headers);
    request = apply_body(request, parts.body_payload.as_ref(), &parts.body_fields);
    request = apply_timeout(inner, request);

    let response = request.send().await?;
    let status = response.status();
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(std::string::ToString::to_string);
    let bytes = read_response_body_limited_bytes(response, inner.safety.max_response_bytes).await?;

    if status.is_success() {
        if is_image_content_type(content_type.as_deref()) {
            let mime_type = content_type.unwrap_or_else(|| "image/*".to_string());
            return Ok(ToolResponse::Image { bytes, mime_type });
        }

        let body = bytes_to_text_or_base64_json(&bytes, content_type.as_deref());
        match tool.response_mode {
            HttpResponseMode::Text => Ok(ToolResponse::Value(body)),
            HttpResponseMode::Json => {
                let v = match body {
                    Value::String(s) => serde_json::from_str(&s).unwrap_or_else(|_| json!(s)),
                    other => other,
                };
                Ok(ToolResponse::Value(v))
            }
        }
    } else {
        let body = bytes_to_text_or_base64_json(&bytes, content_type.as_deref());
        let error_body: Value = match body {
            Value::String(s) => serde_json::from_str(&s).unwrap_or_else(|_| json!(s)),
            other => other,
        };
        let status_code = status.as_u16();
        let reason = status.canonical_reason().unwrap_or("Unknown");
        Err(HttpToolsError::Http(format!(
            "API returned {status_code} {reason}: {error_body}",
        )))
    }
}

async fn read_response_body_limited_bytes(
    mut response: reqwest::Response,
    max_bytes: Option<usize>,
) -> Result<Vec<u8>> {
    let Some(max) = max_bytes else {
        let bytes = response.bytes().await.map_err(HttpToolsError::from)?;
        return Ok(bytes.to_vec());
    };

    if let Some(len) = response.content_length()
        && len > max as u64
    {
        return Err(HttpToolsError::Http(format!(
            "Response too large: {len} bytes (limit {max})"
        )));
    }

    let mut out: Vec<u8> = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(HttpToolsError::from)? {
        if out.len().saturating_add(chunk.len()) > max {
            return Err(HttpToolsError::Http(format!(
                "Response too large: exceeded {max} bytes"
            )));
        }
        out.extend_from_slice(&chunk);
    }

    Ok(out)
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

fn build_request_parts(tool: &GeneratedTool, arguments: &Value) -> Result<RequestParts> {
    let mut path = tool.path.clone();
    if !path.starts_with('/') {
        path = format!("/{path}");
    }

    let mut query_params: Vec<QueryPair> = Vec::new();
    let mut headers: Vec<(String, String)> = Vec::new();
    let mut body_fields: HashMap<String, Value> = HashMap::new();
    let mut body_payload: Option<Value> = None;

    for param in &tool.parameters {
        let value = arguments
            .get(&param.tool_name)
            .cloned()
            .or_else(|| param.default.clone());

        if param.required && value.is_none() {
            return Err(HttpToolsError::Runtime(format!(
                "Missing required parameter: {}",
                param.tool_name
            )));
        }

        let value = match value {
            Some(Value::Null) => None,
            other => other,
        };

        if let Some(val) = value {
            match param.location {
                HttpParamLocation::Path => {
                    let val_str = value_to_string(&val);
                    path = path.replace(&format!("{{{}}}", param.http_name), &val_str);
                }
                HttpParamLocation::Query => {
                    let pairs = serialize_query_param(
                        &param.http_name,
                        &val,
                        param.required,
                        param.query.as_ref(),
                    );
                    query_params.extend(pairs);
                }
                HttpParamLocation::Header => {
                    headers.push((param.http_name.clone(), value_to_string(&val)));
                }
                HttpParamLocation::Body => {
                    if param.tool_name == "body" && param.http_name == "body" {
                        body_payload = Some(val);
                    } else {
                        body_fields.insert(param.http_name.clone(), val);
                    }
                }
            }
        }
    }

    Ok(RequestParts {
        path,
        query_params,
        headers,
        body_fields,
        body_payload,
    })
}

fn apply_query_auth(auth: Option<&AuthConfig>, query_params: &mut Vec<QueryPair>) {
    if let Some(AuthConfig::Query { name, value }) = auth {
        query_params.push(QueryPair {
            key: name.clone(),
            value: value.clone(),
            allow_reserved: false,
        });
    }
}

fn build_url(base_url: &str, path: &str, query_params: &[QueryPair]) -> Result<Url> {
    let url = format!("{}{}", base_url.trim_end_matches('/'), path);
    let mut url =
        Url::parse(&url).map_err(|e| HttpToolsError::Runtime(format!("Invalid URL: {e}")))?;

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
    cfg: &HttpServerConfig,
    mut request: reqwest::RequestBuilder,
    headers: Vec<(String, String)>,
) -> reqwest::RequestBuilder {
    for (key, value) in &cfg.defaults.headers {
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

fn apply_timeout(
    inner: &HttpToolSourceInner,
    mut request: reqwest::RequestBuilder,
) -> reqwest::RequestBuilder {
    let effective_timeout = match inner.config.defaults.timeout {
        Some(0) => None,
        Some(secs) => Some(Duration::from_secs(secs)),
        None => Some(inner.default_timeout),
    };
    if let Some(t) = effective_timeout {
        request = request.timeout(t);
    }
    request
}

fn apply_auth(
    auth: Option<&AuthConfig>,
    request: reqwest::RequestBuilder,
) -> reqwest::RequestBuilder {
    match auth {
        Some(AuthConfig::Bearer { token }) => request.bearer_auth(token),
        Some(AuthConfig::Header { name, value }) => request.header(name, value),
        Some(AuthConfig::Basic { username, password }) => {
            request.basic_auth(username, Some(password))
        }
        Some(AuthConfig::Query { .. } | AuthConfig::None) | None => request,
    }
}

fn map_query_style(s: QueryStyleConfig) -> QueryStyle {
    match s {
        QueryStyleConfig::Form => QueryStyle::Form,
        QueryStyleConfig::SpaceDelimited => QueryStyle::SpaceDelimited,
        QueryStyleConfig::PipeDelimited => QueryStyle::PipeDelimited,
        QueryStyleConfig::DeepObject => QueryStyle::DeepObject,
    }
}

fn default_query_explode(style: &QueryStyle) -> bool {
    matches!(style, QueryStyle::Form | QueryStyle::DeepObject)
}

fn serialize_query_param(
    name: &str,
    value: &Value,
    required: bool,
    ser: Option<&QuerySerialization>,
) -> Vec<QueryPair> {
    let (style, explode, allow_reserved, allow_empty_value) = match ser {
        Some(s) => (
            s.style.clone(),
            s.explode,
            s.allow_reserved,
            s.allow_empty_value,
        ),
        None => (QueryStyle::Form, true, false, false),
    };

    if query_value_is_empty(value) {
        return serialize_empty_query_value(name, required, allow_reserved, allow_empty_value);
    }

    match value {
        Value::Array(arr) => serialize_query_array(name, arr, &style, explode, allow_reserved),
        Value::Object(map) => serialize_query_object(name, map, &style, explode, allow_reserved),
        _ => serialize_query_scalar(name, value, allow_reserved),
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

fn encode_query_component(s: &str, allow_reserved: bool) -> String {
    // NOTE: still encodes '&' and '=' to avoid breaking our own query-string joining.
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

fn value_to_string(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => String::new(),
        _ => value.to_string(),
    }
}

fn build_input_schema(parameters: &[ToolParameter]) -> Value {
    let mut properties = json!({});
    let mut required: Vec<String> = Vec::new();

    for param in parameters {
        let mut prop_schema = param.schema.clone();
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

#[cfg(test)]
mod tests {
    use super::HttpToolSource;
    use crate::config::{
        AuthConfig, EndpointDefaults, HttpParamConfig, HttpParamLocation, HttpResponseConfig,
        HttpResponseMode, HttpServerConfig, HttpToolConfig,
    };
    use axum::Router;
    use axum::body::Bytes;
    use axum::http::{HeaderMap, Method, Uri};
    use axum::routing::any;
    use serde_json::{Value, json};
    use std::collections::HashMap;
    use std::time::Duration;
    use tokio::net::TcpListener;

    #[test]
    fn list_tools_builds_required_and_defaults_in_schema() {
        let mut params: HashMap<String, HttpParamConfig> = HashMap::new();
        params.insert(
            "id".to_string(),
            HttpParamConfig {
                location: HttpParamLocation::Path,
                name: None,
                required: None,
                default: None,
                schema: Some(json!({"type": "string"})),
                style: None,
                explode: None,
                allow_reserved: None,
                allow_empty_value: None,
            },
        );
        params.insert(
            "q".to_string(),
            HttpParamConfig {
                location: HttpParamLocation::Query,
                name: None,
                required: Some(false),
                default: Some(json!("hello")),
                schema: Some(json!({"type": "string"})),
                style: None,
                explode: None,
                allow_reserved: None,
                allow_empty_value: None,
            },
        );

        let mut tools: HashMap<String, HttpToolConfig> = HashMap::new();
        tools.insert(
            "getUser".to_string(),
            HttpToolConfig {
                method: "GET".to_string(),
                path: "/users/{id}".to_string(),
                description: None,
                params,
                response: HttpResponseConfig {
                    mode: HttpResponseMode::Json,
                    output_schema: None,
                    transforms: None,
                },
            },
        );

        let cfg = HttpServerConfig {
            base_url: "http://127.0.0.1:1".to_string(),
            auth: None,
            defaults: EndpointDefaults::default(),
            response_transforms: Vec::new(),
            tools,
        };

        let source =
            HttpToolSource::new("test", cfg, Duration::from_secs(30)).expect("valid config");
        let tools = source.list_tools();
        assert_eq!(tools.len(), 1);

        let schema = &tools[0].input_schema;
        let required = schema
            .get("required")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        assert!(required.contains(&json!("id")));
        assert!(!required.contains(&json!("q")));

        let default_q = schema
            .get("properties")
            .and_then(Value::as_object)
            .and_then(|props| props.get("q"))
            .and_then(Value::as_object)
            .and_then(|o| o.get("default"))
            .cloned();
        assert_eq!(default_q, Some(json!("hello")));
    }

    #[allow(clippy::too_many_lines)]
    #[tokio::test]
    async fn call_tool_builds_path_query_headers_and_auth() {
        async fn echo_handler(
            method: Method,
            uri: Uri,
            headers: HeaderMap,
            body: Bytes,
        ) -> axum::Json<Value> {
            let x_default = headers
                .get("x-default")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);
            let x_trace = headers
                .get("x-trace")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);

            axum::Json(json!({
                "method": method.as_str(),
                "path": uri.path(),
                "query": uri.query().unwrap_or(""),
                "x_default": x_default,
                "x_trace": x_trace,
                "body": String::from_utf8_lossy(&body),
            }))
        }

        let app = Router::new().route("/{*path}", any(echo_handler));
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let base_url = format!("http://{addr}");

        let server = axum::serve(listener, app);
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let server = server.with_graceful_shutdown(async move {
            let _ = shutdown_rx.await;
        });
        let server_handle = tokio::spawn(async move { server.await });

        let mut defaults = EndpointDefaults::default();
        defaults
            .headers
            .insert("x-default".to_string(), "1".to_string());

        let mut params: HashMap<String, HttpParamConfig> = HashMap::new();
        params.insert(
            "id".to_string(),
            HttpParamConfig {
                location: HttpParamLocation::Path,
                name: None,
                required: None,
                default: None,
                schema: Some(json!({"type": "string"})),
                style: None,
                explode: None,
                allow_reserved: None,
                allow_empty_value: None,
            },
        );
        params.insert(
            "q".to_string(),
            HttpParamConfig {
                location: HttpParamLocation::Query,
                name: None,
                required: Some(false),
                default: None,
                schema: Some(json!({"type": "string"})),
                style: None,
                explode: None,
                allow_reserved: None,
                allow_empty_value: None,
            },
        );
        params.insert(
            "trace".to_string(),
            HttpParamConfig {
                location: HttpParamLocation::Header,
                name: Some("x-trace".to_string()),
                required: Some(false),
                default: None,
                schema: Some(json!({"type": "string"})),
                style: None,
                explode: None,
                allow_reserved: None,
                allow_empty_value: None,
            },
        );

        let mut tools: HashMap<String, HttpToolConfig> = HashMap::new();
        tools.insert(
            "getUser".to_string(),
            HttpToolConfig {
                method: "GET".to_string(),
                path: "/users/{id}".to_string(),
                description: None,
                params,
                response: HttpResponseConfig {
                    mode: HttpResponseMode::Json,
                    output_schema: None,
                    transforms: None,
                },
            },
        );

        let cfg = HttpServerConfig {
            base_url,
            auth: Some(AuthConfig::Query {
                name: "token".to_string(),
                value: "abc".to_string(),
            }),
            defaults,
            response_transforms: Vec::new(),
            tools,
        };

        let source =
            HttpToolSource::new("test", cfg, Duration::from_secs(30)).expect("valid config");
        let result = source
            .call_tool(
                "getUser",
                json!({
                    "id": "123",
                    "q": "hello",
                    "trace": "t-1",
                }),
            )
            .await
            .expect("call_tool");

        let result_json = serde_json::to_value(&result).expect("CallToolResult serializes");
        let text = result_json
            .get("content")
            .and_then(Value::as_array)
            .and_then(|c| c.first())
            .and_then(|c| c.get("text"))
            .and_then(Value::as_str)
            .expect("content[0].text");

        let echoed: Value = serde_json::from_str(text).expect("echo json");

        assert_eq!(echoed["method"], "GET");
        assert_eq!(echoed["path"], "/users/123");
        assert_eq!(echoed["x_default"], "1");
        assert_eq!(echoed["x_trace"], "t-1");

        let query = echoed["query"].as_str().unwrap_or_default();
        let mut qmap: HashMap<String, Vec<String>> = HashMap::new();
        for (k, v) in url::form_urlencoded::parse(query.as_bytes()).into_owned() {
            qmap.entry(k).or_default().push(v);
        }
        assert_eq!(
            qmap.get("q").and_then(|v| v.first()).map(String::as_str),
            Some("hello")
        );
        assert_eq!(
            qmap.get("token")
                .and_then(|v| v.first())
                .map(String::as_str),
            Some("abc")
        );

        let _ = shutdown_tx.send(());
        server_handle
            .await
            .expect("server task join")
            .expect("server result");
    }

    #[allow(clippy::too_many_lines)]
    #[tokio::test]
    async fn call_tool_emits_structured_content_when_output_schema_is_configured() {
        async fn echo_handler(
            method: Method,
            uri: Uri,
            headers: HeaderMap,
            body: Bytes,
        ) -> axum::Json<Value> {
            axum::Json(json!({
                "method": method.as_str(),
                "path": uri.path(),
                "query": uri.query().unwrap_or(""),
                "x_trace": headers.get("x-trace").and_then(|v| v.to_str().ok()),
                "body": String::from_utf8_lossy(&body),
            }))
        }

        let app = Router::new().route("/{*path}", any(echo_handler));
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let base_url = format!("http://{addr}");

        let server = axum::serve(listener, app);
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let server = server.with_graceful_shutdown(async move {
            let _ = shutdown_rx.await;
        });
        let server_handle = tokio::spawn(async move { server.await });

        let mut params: HashMap<String, HttpParamConfig> = HashMap::new();
        params.insert(
            "id".to_string(),
            HttpParamConfig {
                location: HttpParamLocation::Path,
                name: None,
                required: None,
                default: None,
                schema: Some(json!({"type": "string"})),
                style: None,
                explode: None,
                allow_reserved: None,
                allow_empty_value: None,
            },
        );
        params.insert(
            "trace".to_string(),
            HttpParamConfig {
                location: HttpParamLocation::Header,
                name: Some("x-trace".to_string()),
                required: Some(false),
                default: None,
                schema: Some(json!({"type": "string"})),
                style: None,
                explode: None,
                allow_reserved: None,
                allow_empty_value: None,
            },
        );

        let mut tools: HashMap<String, HttpToolConfig> = HashMap::new();
        tools.insert(
            "getUser".to_string(),
            HttpToolConfig {
                method: "GET".to_string(),
                path: "/users/{id}".to_string(),
                description: None,
                params,
                response: HttpResponseConfig {
                    mode: HttpResponseMode::Json,
                    output_schema: Some(json!({"type": "object"})),
                    transforms: None,
                },
            },
        );

        let cfg = HttpServerConfig {
            base_url,
            auth: None,
            defaults: EndpointDefaults::default(),
            response_transforms: Vec::new(),
            tools,
        };

        let source =
            HttpToolSource::new("test", cfg, Duration::from_secs(30)).expect("valid config");

        // Listing should include output schema (wrapped under { body: ... }).
        let listed = source.list_tools();
        assert_eq!(listed.len(), 1);
        let out_schema = listed[0].output_schema.as_ref().expect("output_schema");
        assert!(out_schema.get("properties").is_some());
        assert!(
            out_schema
                .get("properties")
                .and_then(Value::as_object)
                .is_some_and(|p| p.contains_key("body"))
        );

        let result = source
            .call_tool(
                "getUser",
                json!({
                    "id": "123",
                    "trace": "t-1",
                }),
            )
            .await
            .expect("call_tool");

        let v = serde_json::to_value(&result).expect("CallToolResult serializes");
        let structured = v
            .get("structuredContent")
            .and_then(Value::as_object)
            .expect("structuredContent present");
        let body = structured.get("body").expect("structuredContent.body");
        assert_eq!(body.get("path").and_then(Value::as_str), Some("/users/123"));

        let _ = shutdown_tx.send(());
        server_handle
            .await
            .expect("server task join")
            .expect("server result");
    }

    #[tokio::test]
    async fn call_tool_returns_image_content_for_image_response() {
        use base64::Engine as _;

        async fn image_handler() -> ([(axum::http::HeaderName, &'static str); 1], &'static [u8]) {
            (
                [(axum::http::header::CONTENT_TYPE, "image/png")],
                &[0x00, 0x01, 0x02, 0x03],
            )
        }

        let app = Router::new().route("/img", axum::routing::get(image_handler));
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let base_url = format!("http://{addr}");

        let server = axum::serve(listener, app);
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let server = server.with_graceful_shutdown(async move {
            let _ = shutdown_rx.await;
        });
        let server_handle = tokio::spawn(async move { server.await });

        let tools = HashMap::from([(
            "getImage".to_string(),
            HttpToolConfig {
                method: "GET".to_string(),
                path: "/img".to_string(),
                description: None,
                params: HashMap::new(),
                response: HttpResponseConfig {
                    mode: HttpResponseMode::Text,
                    output_schema: None,
                    transforms: None,
                },
            },
        )]);

        let cfg = HttpServerConfig {
            base_url,
            auth: None,
            defaults: EndpointDefaults::default(),
            response_transforms: Vec::new(),
            tools,
        };

        let source =
            HttpToolSource::new("test", cfg, Duration::from_secs(30)).expect("valid config");

        let result = source
            .call_tool("getImage", json!({}))
            .await
            .expect("call_tool");

        let v = serde_json::to_value(&result).expect("CallToolResult serializes");
        let first = v
            .get("content")
            .and_then(Value::as_array)
            .and_then(|a| a.first())
            .expect("content[0]");

        assert_eq!(first.get("type").and_then(Value::as_str), Some("image"));
        assert_eq!(
            first.get("mimeType").and_then(Value::as_str),
            Some("image/png")
        );

        let data_b64 = first
            .get("data")
            .and_then(Value::as_str)
            .expect("content[0].data");
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(data_b64)
            .expect("base64");
        assert_eq!(decoded, vec![0x00, 0x01, 0x02, 0x03]);

        let _ = shutdown_tx.send(());
        server_handle
            .await
            .expect("server task join")
            .expect("server result");
    }
}
