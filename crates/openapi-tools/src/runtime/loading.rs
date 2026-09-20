//! `OpenAPI` loading.
use super::*;

impl OpenApiToolSource {
    pub(super) async fn probe_base_url(&self, base_url: &str) -> Result<()> {
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
            .client()?
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
    pub(super) async fn load_spec(&self) -> Result<OpenAPI> {
        let spec_content = if self.config.spec.starts_with("http://")
            || self.config.spec.starts_with("https://")
        {
            let url = Url::parse(&self.config.spec).map_err(|e| {
                OpenApiToolsError::OpenApi(format!("Invalid OpenAPI spec URL: {e}"))
            })?;
            let location = redact_url(&url);
            tracing::info!("Fetching OpenAPI spec from {location}");
            let resp = self.fetch_spec(url).await?;

            Self::read_response_body_limited(resp, self.safety.max_response_bytes)
                .await
                .map_err(|e| OpenApiToolsError::OpenApiSpecReadBody {
                    url: location,
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

        // Parse spec (JSON is a valid subset of YAML, so serde_saphyr alone is enough)
        let spec: OpenAPI = serde_saphyr::from_str(&spec_content).map_err(|e| {
            OpenApiToolsError::OpenApiSpecParse {
                location: Url::parse(&self.config.spec)
                    .map_or_else(|_| self.config.spec.clone(), |url| redact_url(&url)),
                source: Box::new(e),
            }
        })?;

        Ok(spec)
    }

    /// Discover tools from the `OpenAPI` spec.
    pub(super) async fn discover_tools(&self, spec: &OpenAPI) -> Result<Vec<GeneratedTool>> {
        let root_doc = DocId::parse(&self.config.spec)?;
        let resolver = OpenApiResolver::new(root_doc, spec, self.client()?, &self.safety)?;
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

    pub(super) fn validate_response_override_configs(&self) -> Result<()> {
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

    pub(super) fn register_response_override_for_operation(
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

    pub(super) fn warn_unmatched_response_overrides(&self, match_counts: &[usize]) {
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
    pub(super) fn should_auto_discover(&self, method: &str, path: &str, _op: &Operation) -> bool {
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

    pub(super) fn apply_overrides(
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

    pub(super) fn base_tool_name(
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

    pub(super) fn tool_description(
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

    pub(super) fn resolve_base_url(&self, base_url: &str) -> Result<String> {
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
}
