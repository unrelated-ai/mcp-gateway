//! `OpenAPI` execution.
use super::*;

impl OpenApiToolSource {
    /// Execute an HTTP request for a tool call.
    pub(super) async fn execute_request(
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
        let mut request = self.client()?.request(tool.method.clone(), url);
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

    pub(super) async fn read_response_body_limited_bytes(
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

    pub(super) async fn read_response_body_limited(
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

    pub(super) fn is_image_content_type(content_type: Option<&str>) -> bool {
        let Some(ct) = content_type else {
            return false;
        };
        let Ok(m) = ct.parse::<Mime>() else {
            return false;
        };
        m.type_() == mime::IMAGE
    }

    pub(super) fn bytes_to_text_or_base64_json(bytes: &[u8], content_type: Option<&str>) -> Value {
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

    pub(super) fn build_request_parts(
        &self,
        tool: &GeneratedTool,
        arguments: &Value,
    ) -> Result<RequestParts> {
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

    pub(super) fn apply_query_auth(&self, query_params: &mut Vec<QueryPair>) {
        if let Some(AuthConfig::Query { name, value }) = &self.config.auth {
            query_params.push(QueryPair {
                key: name.clone(),
                value: value.clone(),
                allow_reserved: false,
            });
        }
    }

    pub(super) fn build_url(base_url: &str, path: &str, query_params: &[QueryPair]) -> Result<Url> {
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

    pub(super) fn apply_headers(
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

    pub(super) fn apply_body(
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

    pub(super) fn apply_timeout(
        &self,
        mut request: reqwest::RequestBuilder,
    ) -> reqwest::RequestBuilder {
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
    pub(super) fn apply_auth(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.config.auth {
            Some(AuthConfig::Bearer { token }) => request.bearer_auth(token),
            Some(AuthConfig::Header { name, value }) => request.header(name, value),
            Some(AuthConfig::Basic { username, password }) => {
                request.basic_auth(username, Some(password))
            }
            Some(AuthConfig::Query { .. } | AuthConfig::None) | None => request, // query auth is applied during URL building
        }
    }

    pub(super) fn serialize_query_param(
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
