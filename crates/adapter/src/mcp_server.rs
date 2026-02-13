//! MCP Server implementation using rmcp.
//!
//! This module implements the MCP server using the official rmcp SDK,
//! providing dynamic tool routing to our backends (stdio and `OpenAPI`).

use crate::aggregator::Aggregator;
use crate::contracts::ContractNotifier;
use crate::supervisor::BackendManager;
use axum::http::request::Parts;
use parking_lot::RwLock;
use rmcp::{
    ErrorData as McpError, ServerHandler,
    model::{
        AnnotateAble, CallToolRequestParams, CallToolResult, CompleteRequestParams, CompleteResult,
        Content, GetPromptRequestParams, GetPromptResult, Implementation, ListPromptsResult,
        ListResourcesResult, ListToolsResult, PaginatedRequestParams, Prompt, ProtocolVersion,
        RawResource, ReadResourceRequestParams, ReadResourceResult, Reference, Resource,
        ServerCapabilities, ServerInfo, SetLevelRequestParams, SubscribeRequestParams, Tool,
        UnsubscribeRequestParams,
    },
    service::{RequestContext, RoleServer},
};
use serde_json::Value;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;
use unrelated_tool_transforms::TransformPipeline;

fn mcp_session_id_from_context(context: &RequestContext<RoleServer>) -> Option<&str> {
    context
        .extensions
        .get::<Parts>()
        .and_then(|parts| parts.headers.get("mcp-session-id"))
        .and_then(|h| h.to_str().ok())
}

fn timeout_budget_from_meta(meta: &rmcp::model::Meta) -> Option<Duration> {
    let unrelated = meta.get("unrelated").and_then(Value::as_object)?;
    let timeout_ms = unrelated.get("timeoutMs").and_then(Value::as_u64)?;
    if timeout_ms == 0 {
        return None;
    }
    let cap_ms = crate::timeouts::tool_call_timeout_cap_secs().saturating_mul(1000);
    let timeout_ms = timeout_ms.min(cap_ms);
    Some(Duration::from_millis(timeout_ms))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn timeout_budget_from_meta_parses_and_clamps() {
        let mut meta = rmcp::model::Meta::default();
        assert!(timeout_budget_from_meta(&meta).is_none());

        meta.insert("unrelated".to_string(), json!({ "timeoutMs": 0 }));
        assert!(timeout_budget_from_meta(&meta).is_none());

        meta.insert("unrelated".to_string(), json!({ "timeoutMs": 1234 }));
        assert_eq!(
            timeout_budget_from_meta(&meta),
            Some(Duration::from_millis(1234))
        );

        let cap_ms = crate::timeouts::tool_call_timeout_cap_secs().saturating_mul(1000);
        meta.insert(
            "unrelated".to_string(),
            json!({ "timeoutMs": cap_ms + 10_000 }),
        );
        assert_eq!(
            timeout_budget_from_meta(&meta),
            Some(Duration::from_millis(cap_ms))
        );
    }
}

/// MCP Server that routes requests to our backends.
#[derive(Clone)]
pub struct AdapterMcpServer {
    /// Aggregator for tool routing
    aggregator: Arc<Aggregator>,
    /// Backend manager for accessing backends
    backend_manager: Arc<BackendManager>,
    /// Tool transforms (single-tenant scope).
    transforms: Arc<TransformPipeline>,
    /// Best-effort contract hashing + `list_changed` notifications.
    contracts: Arc<ContractNotifier>,
    /// Client-requested logging level (per session)
    log_level: Arc<RwLock<rmcp::model::LoggingLevel>>,
}

impl AdapterMcpServer {
    /// Create a new MCP server with the given aggregator and backend manager.
    pub fn new(
        aggregator: Arc<Aggregator>,
        backend_manager: Arc<BackendManager>,
        transforms: Arc<TransformPipeline>,
        contracts: Arc<ContractNotifier>,
    ) -> Self {
        Self {
            aggregator,
            backend_manager,
            transforms,
            contracts,
            log_level: Arc::new(RwLock::new(rmcp::model::LoggingLevel::Info)),
        }
    }
}

impl ServerHandler for AdapterMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: ProtocolVersion::V_2024_11_05,
            capabilities: ServerCapabilities::builder()
                .enable_logging()
                .enable_completions()
                .enable_tools()
                .enable_tool_list_changed()
                .enable_resources()
                .enable_resources_list_changed()
                .enable_resources_subscribe()
                .enable_prompts()
                .enable_prompts_list_changed()
                .build(),
            server_info: Implementation::from_build_env(),
            instructions: Some(
                "MCP adapter that bridges stdio MCP servers and OpenAPI backends.".to_string(),
            ),
        }
    }

    async fn set_level(
        &self,
        request: SetLevelRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<(), McpError> {
        let session_id = mcp_session_id_from_context(&context);
        if let Some(id) = session_id {
            self.contracts.observe_peer(id, context.peer.clone());
        }
        tracing::debug!(
            mcp_session_id = session_id.unwrap_or("<none>"),
            request_id = %context.id,
            level = ?request.level,
            "logging/setLevel"
        );
        *self.log_level.write() = request.level;
        Ok(())
    }

    async fn complete(
        &self,
        mut request: CompleteRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CompleteResult, McpError> {
        let session_id = mcp_session_id_from_context(&context);
        if let Some(id) = session_id {
            self.contracts.observe_peer(id, context.peer.clone());
        }

        let start = Instant::now();
        let (server_name, rewritten_ref) = match &request.r#ref {
            Reference::Prompt(p) => {
                let Some((server, original)) = self.aggregator.route_prompt(&p.name) else {
                    return Err(McpError::invalid_params(
                        format!("Unknown prompt for completion: {}", p.name),
                        None,
                    ));
                };
                (server, Reference::for_prompt(original))
            }
            Reference::Resource(r) => {
                let Some((server, original_uri)) = self.aggregator.route_resource(&r.uri) else {
                    return Err(McpError::invalid_params(
                        format!("Unknown resource for completion: {}", r.uri),
                        None,
                    ));
                };
                (server, Reference::for_resource(original_uri))
            }
        };
        request.r#ref = rewritten_ref;

        let backend = self
            .backend_manager
            .get_backend(&server_name)
            .ok_or_else(|| {
                McpError::internal_error(
                    format!("Backend '{server_name}' not found for completion/complete"),
                    None,
                )
            })?;

        let result = backend.complete(session_id, request).await.map_err(|e| {
            McpError::internal_error(format!("completion/complete failed: {e}"), None)
        })?;

        tracing::debug!(
            mcp_session_id = session_id.unwrap_or("<none>"),
            request_id = %context.id,
            backend = %server_name,
            elapsed = ?start.elapsed(),
            "completion/complete"
        );

        Ok(result)
    }

    async fn subscribe(
        &self,
        request: SubscribeRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<(), McpError> {
        let session_id = mcp_session_id_from_context(&context);
        if let Some(id) = session_id {
            self.contracts.observe_peer(id, context.peer.clone());
        }

        let start = Instant::now();
        let uri = &request.uri;
        let Some((server_name, original_uri)) = self.aggregator.route_resource(uri) else {
            tracing::debug!(
                mcp_session_id = session_id.unwrap_or("<none>"),
                request_id = %context.id,
                uri = %uri,
                elapsed = ?start.elapsed(),
                "resources/subscribe: resource not found"
            );
            return Err(McpError::invalid_params(
                format!("Resource not found: {uri}"),
                None,
            ));
        };

        let backend = self
            .backend_manager
            .get_backend(&server_name)
            .ok_or_else(|| {
                McpError::internal_error(format!("Backend not found: {server_name}"), None)
            })?;

        let backend_type = backend.backend_type();
        backend
            .subscribe(session_id, &original_uri)
            .await
            .map_err(|e| {
                tracing::warn!(
                    mcp_session_id = session_id.unwrap_or("<none>"),
                    request_id = %context.id,
                    uri = %uri,
                    backend = %server_name,
                    backend_type = %backend_type,
                    error = %e,
                    elapsed = ?start.elapsed(),
                    "resources/subscribe failed"
                );
                McpError::internal_error(format!("resources/subscribe failed: {e}"), None)
            })?;

        Ok(())
    }

    async fn unsubscribe(
        &self,
        request: UnsubscribeRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<(), McpError> {
        let session_id = mcp_session_id_from_context(&context);
        if let Some(id) = session_id {
            self.contracts.observe_peer(id, context.peer.clone());
        }

        let start = Instant::now();
        let uri = &request.uri;
        let Some((server_name, original_uri)) = self.aggregator.route_resource(uri) else {
            tracing::debug!(
                mcp_session_id = session_id.unwrap_or("<none>"),
                request_id = %context.id,
                uri = %uri,
                elapsed = ?start.elapsed(),
                "resources/unsubscribe: resource not found"
            );
            return Err(McpError::invalid_params(
                format!("Resource not found: {uri}"),
                None,
            ));
        };

        let backend = self
            .backend_manager
            .get_backend(&server_name)
            .ok_or_else(|| {
                McpError::internal_error(format!("Backend not found: {server_name}"), None)
            })?;

        let backend_type = backend.backend_type();
        backend
            .unsubscribe(session_id, &original_uri)
            .await
            .map_err(|e| {
                tracing::warn!(
                    mcp_session_id = session_id.unwrap_or("<none>"),
                    request_id = %context.id,
                    uri = %uri,
                    backend = %server_name,
                    backend_type = %backend_type,
                    error = %e,
                    elapsed = ?start.elapsed(),
                    "resources/unsubscribe failed"
                );
                McpError::internal_error(format!("resources/unsubscribe failed: {e}"), None)
            })?;

        Ok(())
    }

    /// List all tools from all backends.
    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        let session_id = mcp_session_id_from_context(&context);
        if let Some(id) = session_id {
            self.contracts.observe_peer(id, context.peer.clone());
        }
        let start = Instant::now();
        let tools = self.aggregator.get_all_tools();

        let tool_list: Vec<Tool> = tools
            .values()
            .map(|mapping| {
                // Build input schema
                let input_schema = mapping
                    .input_schema
                    .clone()
                    .and_then(|v| v.as_object().cloned())
                    .map_or_else(|| Arc::new(serde_json::Map::new()), Arc::new);

                let output_schema = mapping
                    .output_schema
                    .clone()
                    .and_then(|v| v.as_object().cloned())
                    .map(Arc::new);

                let mut tool = Tool::new(
                    mapping.exposed_name.clone(),
                    mapping.description.clone().unwrap_or_default(),
                    input_schema,
                );
                tool.output_schema = output_schema;
                tool.annotations.clone_from(&mapping.annotations);
                tool
            })
            .collect();

        tracing::debug!(
            mcp_session_id = session_id.unwrap_or("<none>"),
            request_id = %context.id,
            tool_count = tool_list.len(),
            elapsed = ?start.elapsed(),
            "tools/list"
        );
        Ok(ListToolsResult {
            tools: tool_list,
            next_cursor: None,
            ..Default::default()
        })
    }

    /// Call a tool by routing to the appropriate backend.
    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let session_id = mcp_session_id_from_context(&context);
        if let Some(id) = session_id {
            self.contracts.observe_peer(id, context.peer.clone());
        }
        let start = Instant::now();
        let tool_name = &request.name;

        // Route the tool call
        let Some((server_name, original_tool_name)) = self.aggregator.route_tool(tool_name) else {
            tracing::debug!(
                mcp_session_id = session_id.unwrap_or("<none>"),
                request_id = %context.id,
                tool = %tool_name,
                elapsed = ?start.elapsed(),
                "tools/call: tool not found"
            );
            return Err(McpError::invalid_params(
                format!("Tool not found: {tool_name}"),
                None,
            ));
        };

        // Find the backend (O(1) lookup)
        let backend = self
            .backend_manager
            .get_backend(&server_name)
            .ok_or_else(|| {
                tracing::warn!(
                    mcp_session_id = session_id.unwrap_or("<none>"),
                    request_id = %context.id,
                    tool = %tool_name,
                    backend = %server_name,
                    elapsed = ?start.elapsed(),
                    "tools/call: backend not found"
                );
                McpError::internal_error(format!("Backend not found: {server_name}"), None)
            })?;

        // Get arguments
        let mut arguments = request.arguments.unwrap_or_default();
        self.transforms
            .apply_call_transforms(&original_tool_name, &mut arguments);
        let args_value = serde_json::Value::Object(arguments);

        let timeout_budget = timeout_budget_from_meta(&context.meta);

        // Call the tool
        let backend_type = backend.backend_type();
        match backend
            .call_tool(session_id, &original_tool_name, args_value, timeout_budget)
            .await
        {
            Ok(result) => {
                tracing::debug!(
                    mcp_session_id = session_id.unwrap_or("<none>"),
                    request_id = %context.id,
                    tool = %tool_name,
                    backend = %server_name,
                    backend_type = %backend_type,
                    elapsed = ?start.elapsed(),
                    "tools/call ok"
                );
                Ok(result)
            }
            Err(e) => {
                tracing::warn!(
                    mcp_session_id = session_id.unwrap_or("<none>"),
                    request_id = %context.id,
                    tool = %tool_name,
                    backend = %server_name,
                    backend_type = %backend_type,
                    error = %e,
                    elapsed = ?start.elapsed(),
                    "tools/call failed"
                );
                Ok(CallToolResult::error(vec![Content::text(format!(
                    "Error: {e}"
                ))]))
            }
        }
    }

    /// Read a resource by routing to the appropriate backend.
    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResult, McpError> {
        let session_id = mcp_session_id_from_context(&context);
        if let Some(id) = session_id {
            self.contracts.observe_peer(id, context.peer.clone());
        }
        let start = Instant::now();
        let uri = &request.uri;

        let Some((server_name, original_uri)) = self.aggregator.route_resource(uri) else {
            tracing::debug!(
                mcp_session_id = session_id.unwrap_or("<none>"),
                request_id = %context.id,
                uri = %uri,
                elapsed = ?start.elapsed(),
                "resources/read: resource not found"
            );
            return Err(McpError::invalid_params(
                format!("Resource not found: {uri}"),
                None,
            ));
        };

        let backend = self
            .backend_manager
            .get_backend(&server_name)
            .ok_or_else(|| {
                tracing::warn!(
                    mcp_session_id = session_id.unwrap_or("<none>"),
                    request_id = %context.id,
                    uri = %uri,
                    backend = %server_name,
                    elapsed = ?start.elapsed(),
                    "resources/read: backend not found"
                );
                McpError::internal_error(format!("Backend not found: {server_name}"), None)
            })?;

        let backend_type = backend.backend_type();
        let result = backend
            .read_resource(session_id, &original_uri)
            .await
            .map_err(|e| {
                tracing::warn!(
                    mcp_session_id = session_id.unwrap_or("<none>"),
                    request_id = %context.id,
                    uri = %uri,
                    backend = %server_name,
                    backend_type = %backend_type,
                    error = %e,
                    elapsed = ?start.elapsed(),
                    "resources/read failed"
                );
                McpError::internal_error(format!("Read resource failed: {e}"), None)
            })?;

        tracing::debug!(
            mcp_session_id = session_id.unwrap_or("<none>"),
            request_id = %context.id,
            uri = %uri,
            backend = %server_name,
            backend_type = %backend_type,
            elapsed = ?start.elapsed(),
            "resources/read ok"
        );
        Ok(result)
    }

    /// List resources from all backends.
    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, McpError> {
        let session_id = mcp_session_id_from_context(&context);
        if let Some(id) = session_id {
            self.contracts.observe_peer(id, context.peer.clone());
        }
        let start = Instant::now();
        let resources = self.aggregator.get_all_resources();

        let resource_list: Vec<Resource> = resources
            .iter()
            .map(|(exposed_uri, mapping)| {
                let mut raw = RawResource::new(exposed_uri.clone(), mapping.name.clone());
                raw.description.clone_from(&mapping.description);
                raw.mime_type.clone_from(&mapping.mime_type);
                raw.size = mapping.size;
                raw.no_annotation()
            })
            .collect();

        tracing::debug!(
            mcp_session_id = session_id.unwrap_or("<none>"),
            request_id = %context.id,
            resource_count = resource_list.len(),
            elapsed = ?start.elapsed(),
            "resources/list"
        );
        Ok(ListResourcesResult {
            resources: resource_list,
            next_cursor: None,
            ..Default::default()
        })
    }

    /// Get a prompt by routing to the appropriate backend.
    async fn get_prompt(
        &self,
        request: GetPromptRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<GetPromptResult, McpError> {
        let session_id = mcp_session_id_from_context(&context);
        if let Some(id) = session_id {
            self.contracts.observe_peer(id, context.peer.clone());
        }
        let start = Instant::now();
        let prompt_name = &request.name;

        let Some((server_name, original_prompt_name)) = self.aggregator.route_prompt(prompt_name)
        else {
            tracing::debug!(
                mcp_session_id = session_id.unwrap_or("<none>"),
                request_id = %context.id,
                prompt = %prompt_name,
                elapsed = ?start.elapsed(),
                "prompts/get: prompt not found"
            );
            return Err(McpError::invalid_params(
                format!("Prompt not found: {prompt_name}"),
                None,
            ));
        };

        let backend = self
            .backend_manager
            .get_backend(&server_name)
            .ok_or_else(|| {
                tracing::warn!(
                    mcp_session_id = session_id.unwrap_or("<none>"),
                    request_id = %context.id,
                    prompt = %prompt_name,
                    backend = %server_name,
                    elapsed = ?start.elapsed(),
                    "prompts/get: backend not found"
                );
                McpError::internal_error(format!("Backend not found: {server_name}"), None)
            })?;

        let backend_type = backend.backend_type();
        let result = backend
            .get_prompt(session_id, &original_prompt_name, request.arguments)
            .await
            .map_err(|e| {
                tracing::warn!(
                    mcp_session_id = session_id.unwrap_or("<none>"),
                    request_id = %context.id,
                    prompt = %prompt_name,
                    backend = %server_name,
                    backend_type = %backend_type,
                    error = %e,
                    elapsed = ?start.elapsed(),
                    "prompts/get failed"
                );
                McpError::internal_error(format!("Get prompt failed: {e}"), None)
            })?;

        tracing::debug!(
            mcp_session_id = session_id.unwrap_or("<none>"),
            request_id = %context.id,
            prompt = %prompt_name,
            backend = %server_name,
            backend_type = %backend_type,
            elapsed = ?start.elapsed(),
            "prompts/get ok"
        );
        Ok(result)
    }

    /// List prompts from all backends.
    async fn list_prompts(
        &self,
        _request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListPromptsResult, McpError> {
        let session_id = mcp_session_id_from_context(&context);
        if let Some(id) = session_id {
            self.contracts.observe_peer(id, context.peer.clone());
        }
        let start = Instant::now();
        let prompts = self.aggregator.get_all_prompts();

        let prompt_list: Vec<Prompt> = prompts
            .iter()
            .map(|(exposed_name, mapping)| Prompt {
                name: exposed_name.clone(),
                title: None,
                description: mapping.description.clone(),
                arguments: mapping.arguments.clone(),
                icons: None,
                meta: None,
            })
            .collect();

        tracing::debug!(
            mcp_session_id = session_id.unwrap_or("<none>"),
            request_id = %context.id,
            prompt_count = prompt_list.len(),
            elapsed = ?start.elapsed(),
            "prompts/list"
        );
        Ok(ListPromptsResult {
            prompts: prompt_list,
            next_cursor: None,
            ..Default::default()
        })
    }
}
