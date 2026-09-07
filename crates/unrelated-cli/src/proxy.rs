use crate::{
    catalog::{CachedCatalog, Detail},
    client::{self, GatewayConnection},
    config::ContextConfig,
};
use rmcp::{
    ErrorData as McpError, ServerHandler, ServiceExt as _,
    model::{
        CallToolRequestParams, CallToolResult, Implementation, JsonObject, ListToolsResult,
        ServerCapabilities, ServerInfo, Tool, ToolAnnotations,
    },
    service::{RequestContext, RoleServer},
    transport::stdio,
};
use serde_json::{Value, json};
use std::{sync::Arc, time::Duration};
use tokio::sync::RwLock;

#[derive(Clone)]
struct CompactProxy {
    remote: Arc<GatewayConnection>,
    catalog: Arc<RwLock<CachedCatalog>>,
    timeout: Duration,
}

impl CompactProxy {
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
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
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
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let arguments = request.arguments.unwrap_or_default();
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
                Ok(CallToolResult::structured(json!({"tools": value})))
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
                client::call_tool(&self.remote, &tool, tool_arguments, self.timeout)
                    .await
                    .map_err(proxy_error)
            }
            _ => Err(McpError::invalid_params(
                "only search_tools and execute_tool are available",
                None,
            )),
        }
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
    let service = proxy.serve(stdio()).await?;
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
