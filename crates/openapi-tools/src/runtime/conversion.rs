//! Pure `OpenAPI` schema, override, and request serialization helpers.
use super::{
    Arc, CompiledResponsePipeline, DocId, GeneratedTool, HashMap, HashSet, HttpParamLocation,
    HttpToolConfig, JsonObject, Method, OpenApiOverrideToolConfig, OpenApiResolver,
    OpenApiToolsError, OperationInfo, OperationKey, ParamLocation, Parameter,
    ParameterSchemaOrContent, QueryPair, QuerySerialization, QueryStyle, QueryStyleConfig,
    ReferenceOr, Regex, ResolvedResponseOverride, ResponseTransform, ResponseTransformChainConfig,
    Result, Schema, ToolParameter, Value, apply_chain, compile_pipeline_from_transforms, json,
};

pub(super) fn query_value_is_empty(value: &Value) -> bool {
    match value {
        Value::String(s) => s.is_empty(),
        Value::Array(a) => a.is_empty(),
        Value::Object(o) => o.is_empty(),
        Value::Null => true,
        _ => false,
    }
}

pub(super) fn serialize_empty_query_value(
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

pub(super) fn serialize_query_array(
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

pub(super) fn serialize_query_object(
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

pub(super) fn serialize_query_scalar(
    name: &str,
    value: &Value,
    allow_reserved: bool,
) -> Vec<QueryPair> {
    vec![QueryPair {
        key: name.to_string(),
        value: value_to_string(value),
        allow_reserved,
    }]
}

pub(super) fn match_override(
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

pub(super) fn response_override_matches_operation(
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

pub(super) fn match_response_override(
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

pub(super) fn parse_manual_override_http_method(tool_name: &str, method: &str) -> Result<Method> {
    let method_str = method.trim();
    method_str.to_uppercase().parse().map_err(|_| {
        OpenApiToolsError::Config(format!(
            "Invalid HTTP method '{method_str}' in OpenAPI override tool '{tool_name}'",
        ))
    })
}

pub(super) fn normalize_tool_path(path: &str) -> String {
    if path.starts_with('/') {
        return path.to_string();
    }
    format!("/{path}")
}

pub(super) fn build_manual_override_parameters(
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

pub(super) fn compile_manual_override_response_pipeline(
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

pub(super) fn build_manual_override_output_schema(
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

pub(super) fn manual_override_to_tool(
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

pub(super) fn map_query_style_config(style: QueryStyleConfig) -> QueryStyle {
    match style {
        QueryStyleConfig::Form => QueryStyle::Form,
        QueryStyleConfig::SpaceDelimited => QueryStyle::SpaceDelimited,
        QueryStyleConfig::PipeDelimited => QueryStyle::PipeDelimited,
        QueryStyleConfig::DeepObject => QueryStyle::DeepObject,
    }
}

pub(super) fn generate_canonical_name(method: &str, path: &str) -> String {
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

pub(super) fn matches_pattern(pattern: &str, operation: &str) -> bool {
    glob_match(pattern, operation)
}

pub(super) fn reserve_unique_tool_name(tool_names: &mut HashSet<String>, base: &str) -> String {
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

pub(super) fn resolve_http_method(method: &str) -> Result<Method> {
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

pub(super) fn default_query_explode(style: &QueryStyle) -> bool {
    matches!(style, QueryStyle::Form | QueryStyle::DeepObject)
}

pub(super) fn encode_query_component(s: &str, allow_reserved: bool) -> String {
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

pub(super) fn is_unreserved(b: u8) -> bool {
    matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~')
}

pub(super) fn is_reserved_but_safe_in_pairs(b: u8) -> bool {
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

pub(super) fn glob_match(pattern: &str, text: &str) -> bool {
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

pub(super) async fn extract_schema(
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

pub(super) async fn merge_parameters(
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

pub(super) fn schema_to_json(schema: &Schema) -> Value {
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

pub(super) fn build_input_schema(parameters: &[ToolParameter]) -> Value {
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

pub(super) fn wrap_body_output_schema(body_schema: &Value) -> Result<Arc<JsonObject>> {
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

pub(super) async fn extract_schema_ref(
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

pub(super) fn value_to_string(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => String::new(),
        _ => value.to_string(),
    }
}
