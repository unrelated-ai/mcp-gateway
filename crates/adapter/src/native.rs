//! Native stdio routing and request lifetimes.
mod routes;
mod subscriptions;

use crate::{CatalogScope, aggregator::Aggregator, supervisor::BackendManager};
use parking_lot::Mutex;
use rmcp::{
    ErrorData, Peer, RoleClient, RoleServer, model::ClientRequest, service::RequestContext,
};
use std::{collections::HashMap, sync::Arc, time::Duration};
use unrelated_mcp_support::native::{self, NotificationHub};

pub struct Connection {
    pub peer: Peer<RoleClient>,
    pub notifications: NotificationHub,
    pub generation: u32,
    pub timeout: Duration,
}

pub struct NativeRouter {
    manager: Arc<BackendManager>,
    pub catalog: Aggregator,
    pub inventory: Arc<Aggregator>,
    refresh_lock: tokio::sync::Mutex<()>,
    routes: Mutex<HashMap<String, routes::Route>>,
    transforms: Arc<unrelated_tool_transforms::TransformPipeline>,
}

impl NativeRouter {
    pub fn new(
        manager: Arc<BackendManager>,
        transforms: Arc<unrelated_tool_transforms::TransformPipeline>,
    ) -> Self {
        Self {
            manager,
            catalog: Aggregator::new(),
            inventory: Arc::new(Aggregator::new()),
            refresh_lock: tokio::sync::Mutex::new(()),
            transforms,
            routes: Mutex::new(HashMap::new()),
        }
    }

    pub async fn refresh(&self, revalidate: bool) -> crate::error::Result<()> {
        let _guard = self.refresh_lock.lock().await;
        let snapshot = crate::build_catalog(
            &self.manager,
            &self.transforms,
            CatalogScope::Native,
            revalidate,
        )
        .await?;
        self.catalog.overwrite_from(&snapshot);
        // /map spans both protocols and keeps its last complete inventory if a
        // legacy backend is unavailable while updating the native catalog.
        match crate::build_catalog(
            &self.manager,
            &self.transforms,
            CatalogScope::Inventory,
            false,
        )
        .await
        {
            Ok(inventory) => self.inventory.overwrite_from(&inventory),
            Err(error) => tracing::warn!(%error, "Failed to refresh adapter inventory"),
        }
        Ok(())
    }

    async fn connection(&self, server: &str) -> Result<Connection, ErrorData> {
        self.manager
            .get_backend(server)
            .ok_or_else(|| ErrorData::invalid_params("unknown backend", None))?
            .native_connection()
            .await
    }

    pub async fn forward<T: serde::de::DeserializeOwned>(
        &self,
        server: &str,
        request: ClientRequest,
        context: &RequestContext<RoleServer>,
    ) -> Result<T, ErrorData> {
        let connection = self.connection(server).await?;
        let mut body = serde_json::to_value(request).map_err(invalid_response)?;
        let route = self.prepare(server, connection.generation, &mut body)?;
        let request = serde_json::from_value(body).map_err(invalid_response)?;
        let timeout = context
            .meta
            .get("unrelated")
            .and_then(|meta| meta.get("timeoutMs"))
            .and_then(serde_json::Value::as_u64)
            .filter(|ms| *ms > 0)
            .map(Duration::from_millis)
            .map_or(connection.timeout, |budget| budget.min(connection.timeout));
        let response = native::request(&connection.peer, request, context, timeout).await?;
        let mut value = serde_json::to_value(response).map_err(invalid_response)?;
        self.wrap(&route, &mut value)?;
        serde_json::from_value(value).map_err(invalid_response)
    }

    pub async fn read_resource(
        &self,
        mut request: rmcp::model::ReadResourceRequestParams,
        context: &RequestContext<RoleServer>,
    ) -> Result<rmcp::model::ReadResourceResponse, ErrorData> {
        use rmcp::model::{
            ReadResourceRequest, ReadResourceResponse, ResourceContents, ServerResult,
        };
        let (server, original) = self
            .catalog
            .route_resource(&request.uri)
            .ok_or_else(|| ErrorData::invalid_params("unknown target", None))?;
        let exposed = std::mem::replace(&mut request.uri, original.clone());
        let response = self
            .forward(
                &server,
                ClientRequest::ReadResourceRequest(ReadResourceRequest::new(request)),
                context,
            )
            .await?;
        match response {
            ServerResult::ReadResourceResult(mut result) => {
                for content in &mut result.contents {
                    match content {
                        ResourceContents::TextResourceContents { uri, .. }
                        | ResourceContents::BlobResourceContents { uri, .. }
                            if *uri == original =>
                        {
                            uri.clone_from(&exposed);
                        }
                        _ => {}
                    }
                }
                Ok(ReadResourceResponse::Complete(result))
            }
            ServerResult::InputRequiredResult(result) => {
                Ok(ReadResourceResponse::InputRequired(result))
            }
            _ => Err(invalid_response("resource response")),
        }
    }

    pub async fn task<T: serde::de::DeserializeOwned>(
        &self,
        request: ClientRequest,
        context: &RequestContext<RoleServer>,
    ) -> Result<T, ErrorData> {
        let body = serde_json::to_value(&request).map_err(invalid_response)?;
        let token = body["params"]["taskId"]
            .as_str()
            .ok_or_else(invalid_state)?;
        let route = self.lookup(token, true)?;
        self.forward(&route.server, request, context).await
    }
}

fn invalid_response(_: impl std::fmt::Display) -> ErrorData {
    ErrorData::internal_error("invalid native backend response", None)
}
fn invalid_state() -> ErrorData {
    ErrorData::invalid_params("invalid or expired routing state", None)
}

pub fn is_native(context: &RequestContext<RoleServer>) -> bool {
    context
        .protocol_version()
        .is_some_and(|version| !version.has_initialize())
}
