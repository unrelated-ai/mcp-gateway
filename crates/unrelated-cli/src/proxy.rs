use crate::{
    catalog::{CachedCatalog, Detail},
    client::{self, GatewayConnection},
    config::ContextConfig,
};
use rmcp::{
    ErrorData as McpError, ServerHandler, ServiceExt as _,
    model::{
        CallToolRequestParams, CallToolResponse, CallToolResult, Implementation, JsonObject,
        ListToolsResult, ProtocolVersion, ServerCapabilities, ServerConfig, Tool, ToolAnnotations,
    },
    service::{RequestContext, RoleServer},
    transport::stdio_pipes,
};
use serde_json::{Value, json};
use std::{sync::Arc, time::Duration};
use tokio::sync::RwLock;
use unrelated_mcp_support::native::{self, NativeFilter, NativeSubscription, SubscriptionIo};

#[derive(Clone)]
struct CompactProxy {
    remote: Arc<GatewayConnection>,
    catalog: Arc<RwLock<CachedCatalog>>,
    timeout: Duration,
}

impl CompactProxy {
    fn native(&self) -> bool {
        self.remote
            .peer_info()
            .is_some_and(|info| !info.protocol_version.has_initialize())
    }

    async fn refresh_if_changed(&self) -> Result<(), McpError> {
        if self.remote.service().take_tools_changed() {
            let catalog = client::fetch_catalog(&self.remote)
                .await
                .map_err(proxy_error)?;
            *self.catalog.write().await = catalog;
        }
        Ok(())
    }

    async fn find_tool(&self, reference: &str) -> Result<Tool, McpError> {
        self.refresh_if_changed().await?;
        if let Some(tool) = self.catalog.read().await.find(reference).cloned() {
            return Ok(tool);
        }
        let refreshed = client::fetch_catalog(&self.remote)
            .await
            .map_err(proxy_error)?;
        let tool = refreshed.find(reference).cloned();
        *self.catalog.write().await = refreshed;
        tool.ok_or_else(|| {
            McpError::invalid_params(format!("unknown tool reference '{reference}'"), None)
        })
    }
}

impl ServerHandler for CompactProxy {
    fn supported_protocol_versions(&self) -> std::borrow::Cow<'static, [ProtocolVersion]> {
        if self.native() {
            return std::borrow::Cow::Borrowed(ProtocolVersion::KNOWN_VERSIONS);
        }
        std::borrow::Cow::Borrowed(&[
            ProtocolVersion::V_2024_11_05,
            ProtocolVersion::V_2025_03_26,
            ProtocolVersion::V_2025_06_18,
            ProtocolVersion::V_2025_11_25,
        ])
    }

    fn get_info(&self) -> ServerConfig {
        let capabilities = ServerCapabilities::builder()
            .enable_tools()
            .enable_tool_list_changed();
        let capabilities = if self.native() {
            capabilities.enable_tasks().build()
        } else {
            capabilities.build()
        };
        ServerConfig::new(capabilities)
            .with_protocol_version(ProtocolVersion::LATEST_WITH_INITIALIZE)
            .with_server_info(Implementation::new("unrelated", env!("CARGO_PKG_VERSION")))
            .with_instructions(
                "Search the authorized Gateway catalog, then execute one stable tool reference.",
            )
    }

    fn list_tools(
        &self,
        _request: Option<rmcp::model::PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ListToolsResult, McpError>> {
        std::future::ready(Ok(ListToolsResult::with_all_items(vec![
            search_tool_definition(),
            execute_tool_definition(),
        ])))
    }

    async fn call_tool(
        &self,
        mut request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        let arguments = request.arguments.take().unwrap_or_default();
        match request.name.as_ref() {
            "search_tools" => {
                self.refresh_if_changed().await?;
                let query = required_string(&arguments, "query")?;
                let detail = match arguments
                    .get("detail")
                    .and_then(Value::as_str)
                    .unwrap_or("detailed")
                {
                    "brief" => Detail::Brief,
                    "detailed" => Detail::Detailed,
                    "full" => Detail::Full,
                    other => {
                        return Err(McpError::invalid_params(
                            format!("invalid detail '{other}'"),
                            None,
                        ));
                    }
                };
                let limit = arguments.get("limit").and_then(Value::as_u64).unwrap_or(10);
                if !(1..=50).contains(&limit) {
                    return Err(McpError::invalid_params(
                        "limit must be between 1 and 50",
                        None,
                    ));
                }
                let results = self
                    .catalog
                    .read()
                    .await
                    .search(
                        query,
                        detail,
                        usize::try_from(limit).map_err(proxy_invalid_params)?,
                    )
                    .map_err(proxy_invalid_params)?;
                let value = serde_json::to_value(results).map_err(proxy_error)?;
                Ok(CallToolResult::structured(json!({"tools": value})).into())
            }
            "execute_tool" => {
                let reference = required_string(&arguments, "toolRef")?;
                let tool = self.find_tool(reference).await?;
                let tool_arguments = match arguments.get("arguments") {
                    Some(Value::Object(arguments)) => arguments.clone(),
                    Some(_) => {
                        return Err(McpError::invalid_params(
                            "arguments must be an object",
                            None,
                        ));
                    }
                    None => JsonObject::new(),
                };
                if context
                    .protocol_version()
                    .is_some_and(|version| !version.has_initialize())
                {
                    client::validate_arguments(&tool, &tool_arguments)
                        .map_err(proxy_invalid_params)?;
                    request.name = tool.name;
                    request.arguments = Some(tool_arguments);
                    let response = native::request(
                        self.remote.peer(),
                        rmcp::model::ClientRequest::CallToolRequest(
                            rmcp::model::CallToolRequest::new(request),
                        ),
                        &context,
                        self.timeout,
                    )
                    .await?;
                    return match response {
                        rmcp::model::ServerResult::CallToolResult(result) => {
                            Ok(CallToolResponse::Complete(result))
                        }
                        rmcp::model::ServerResult::InputRequiredResult(result) => {
                            Ok(CallToolResponse::InputRequired(result))
                        }
                        rmcp::model::ServerResult::CreateTaskResult(result) => {
                            Ok(CallToolResponse::Task(result))
                        }
                        _ => Err(McpError::internal_error(
                            "invalid upstream tool response",
                            None,
                        )),
                    };
                }
                client::call_tool(&self.remote, &tool, tool_arguments, self.timeout)
                    .await
                    .map(Into::into)
                    .map_err(proxy_error)
            }
            _ => Err(McpError::invalid_params(
                "only search_tools and execute_tool are available",
                None,
            )),
        }
    }

    async fn get_task(
        &self,
        request: rmcp::model::GetTaskParams,
        context: RequestContext<RoleServer>,
    ) -> Result<rmcp::model::GetTaskResult, McpError> {
        match native::request(
            self.remote.peer(),
            rmcp::model::ClientRequest::GetTaskRequest(rmcp::model::GetTaskRequest::new(request)),
            &context,
            self.timeout,
        )
        .await?
        {
            rmcp::model::ServerResult::GetTaskResult(result) => Ok(result),
            _ => Err(McpError::internal_error(
                "invalid upstream task response",
                None,
            )),
        }
    }

    async fn update_task(
        &self,
        request: rmcp::model::UpdateTaskParams,
        context: RequestContext<RoleServer>,
    ) -> Result<(), McpError> {
        match native::request(
            self.remote.peer(),
            rmcp::model::ClientRequest::UpdateTaskRequest(rmcp::model::UpdateTaskRequest::new(
                request,
            )),
            &context,
            self.timeout,
        )
        .await?
        {
            rmcp::model::ServerResult::TaskAckResult(_)
            | rmcp::model::ServerResult::EmptyResult(_) => Ok(()),
            _ => Err(McpError::internal_error(
                "invalid upstream task response",
                None,
            )),
        }
    }

    async fn cancel_task(
        &self,
        request: rmcp::model::CancelTaskParams,
        context: RequestContext<RoleServer>,
    ) -> Result<(), McpError> {
        match native::request(
            self.remote.peer(),
            rmcp::model::ClientRequest::CancelTaskRequest(rmcp::model::CancelTaskRequest::new(
                request,
            )),
            &context,
            self.timeout,
        )
        .await?
        {
            rmcp::model::ServerResult::TaskAckResult(_)
            | rmcp::model::ServerResult::EmptyResult(_) => Ok(()),
            _ => Err(McpError::internal_error(
                "invalid upstream task response",
                None,
            )),
        }
    }

    async fn on_custom_request(
        &self,
        request: rmcp::model::CustomRequest,
        context: RequestContext<RoleServer>,
    ) -> Result<rmcp::model::CustomResult, McpError> {
        if request.method != native::LISTEN_METHOD
            || !self.native()
            || context
                .protocol_version()
                .is_none_or(|version| version.has_initialize())
        {
            return Err(McpError::new(
                rmcp::model::ErrorCode::METHOD_NOT_FOUND,
                "unsupported method",
                None,
            ));
        }
        let mut filter =
            NativeFilter::parse(request.params.unwrap_or_default()["notifications"].clone())?;
        filter.resource_subscriptions.clear();
        filter.resources_list_changed = None;
        filter.prompts_list_changed = None;
        if !filter.task_ids.is_empty()
            && context
                .client_capabilities()
                .is_none_or(|caps| !caps.supports_tasks())
        {
            return Err(McpError::missing_required_client_capability(
                rmcp::model::ClientCapabilities::builder()
                    .enable_tasks()
                    .build(),
            ));
        }
        let mut stream = tokio::select! {
            () = context.ct.cancelled() => return Err(McpError::internal_error("subscription cancelled", None)),
            stream = NativeSubscription::open(
                self.remote.peer(),
                &self.remote.service().notifications,
                filter,
                context.meta.clone(),
                self.timeout,
            ) => stream?,
        };
        native::send_notification(
            &context.peer,
            "notifications/subscriptions/acknowledged",
            json!({"notifications":stream.accepted}),
            &context.id,
        )
        .await?;
        loop {
            let next = tokio::select! {
                () = context.ct.cancelled() => break,
                next = stream.next() => next?,
            };
            let Some(message) = next else { break };
            if message["method"] == "notifications/tools/list_changed" {
                *self.catalog.write().await = client::fetch_catalog(&self.remote)
                    .await
                    .map_err(proxy_error)?;
            }
            native::send_notification(
                &context.peer,
                message["method"].as_str().unwrap_or_default(),
                message["params"].clone(),
                &context.id,
            )
            .await?;
        }
        Ok(rmcp::model::CustomResult(
            json!({"resultType":"complete","_meta":{"io.modelcontextprotocol/subscriptionId":context.id}}),
        ))
    }
}

pub async fn run(
    context_name: &str,
    context: &ContextConfig,
    timeout: Duration,
) -> anyhow::Result<()> {
    let remote = Arc::new(client::connect(context_name, context, timeout).await?);
    let catalog = client::fetch_catalog(&remote).await?;
    let proxy = CompactProxy {
        remote,
        catalog: Arc::new(RwLock::new(catalog)),
        timeout,
    };
    let (read, write) = stdio_pipes();
    let service = proxy.serve(SubscriptionIo::new(read, write)).await?;
    service.waiting().await?;
    Ok(())
}

fn search_tool_definition() -> Tool {
    let mut tool = Tool::new(
        "search_tools".to_string(),
        "Search the tools authorized for the selected Gateway profile. Use this before execution and request full detail only when necessary.".to_string(),
        Arc::new(object_schema(json!({
            "query": {"type": "string", "minLength": 1},
            "detail": {"type": "string", "enum": ["brief", "detailed", "full"], "default": "detailed"},
            "limit": {"type": "integer", "minimum": 1, "maximum": 50, "default": 10}
        }), &["query"])),
    );
    tool.annotations = Some(ToolAnnotations::from_raw(
        Some("Search Gateway tools".into()),
        Some(true),
        Some(false),
        Some(true),
        Some(false),
    ));
    tool
}

fn execute_tool_definition() -> Tool {
    let mut tool = Tool::new(
        "execute_tool".to_string(),
        "Execute exactly one authorized Gateway tool by the stable toolRef returned by search_tools.".to_string(),
        Arc::new(object_schema(json!({
            "toolRef": {"type": "string", "minLength": 1},
            "arguments": {"type": "object", "default": {}}
        }), &["toolRef"])),
    );
    tool.annotations = Some(ToolAnnotations::from_raw(
        Some("Execute a Gateway tool".into()),
        Some(false),
        Some(true),
        Some(false),
        Some(true),
    ));
    tool
}

fn object_schema(properties: Value, required: &[&str]) -> JsonObject {
    serde_json::Map::from_iter([
        ("type".to_string(), json!("object")),
        ("properties".to_string(), properties),
        ("required".to_string(), json!(required)),
        ("additionalProperties".to_string(), json!(false)),
    ])
}

fn required_string<'a>(arguments: &'a JsonObject, name: &str) -> Result<&'a str, McpError> {
    arguments
        .get(name)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| McpError::invalid_params(format!("{name} must be a non-empty string"), None))
}

fn proxy_error(error: impl std::fmt::Display) -> McpError {
    McpError::internal_error(error.to_string(), None)
}

fn proxy_invalid_params(error: impl std::fmt::Display) -> McpError {
    McpError::invalid_params(error.to_string(), None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_definitions_are_exactly_two_and_safely_annotated() {
        let tools = [search_tool_definition(), execute_tool_definition()];
        assert_eq!(
            tools
                .iter()
                .map(|tool| tool.name.as_ref())
                .collect::<Vec<_>>(),
            ["search_tools", "execute_tool"]
        );
        assert_eq!(
            tools[0].annotations.as_ref().unwrap().read_only_hint,
            Some(true)
        );
        assert_eq!(
            tools[1].annotations.as_ref().unwrap().destructive_hint,
            Some(true)
        );
        let execute_schema = serde_json::Value::Object(tools[1].input_schema.as_ref().clone());
        assert!(!execute_schema.to_string().contains("code"));
        assert!(!execute_schema.to_string().contains("command"));
    }
}
