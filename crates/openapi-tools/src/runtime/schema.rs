//! `OpenAPI` schema.
use super::*;

impl OpenApiToolSource {
    pub(super) async fn collect_tool_parameters(
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
    pub(super) async fn generate_tool(
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

    pub(super) async fn derive_body_schema(
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
    pub(super) async fn extract_parameter(
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
    pub(super) async fn extract_body_params(
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
}
