use super::{NativeRouter, invalid_response, invalid_state};
use futures::{StreamExt as _, stream::FuturesUnordered};
use rmcp::{
    ErrorData, RoleServer,
    model::{ClientCapabilities, CustomRequest, CustomResult, ErrorCode},
    service::RequestContext,
};
use serde_json::{Value, json};
use std::{collections::HashMap, time::Duration};
use unrelated_mcp_support::native::{self, NativeFilter, NativeSubscription};

struct Plan {
    filters: HashMap<String, NativeFilter>,
    resources: HashMap<String, HashMap<String, String>>,
    tasks: HashMap<String, HashMap<String, String>>,
}

struct Stream {
    server: String,
    subscription: NativeSubscription,
    resources: HashMap<String, String>,
    tasks: HashMap<String, String>,
}

impl Stream {
    async fn next(mut self) -> (Self, Result<Option<Value>, ErrorData>) {
        let result = self.subscription.next().await;
        (self, result)
    }
}

impl NativeRouter {
    async fn plan(&self, filter: &NativeFilter) -> Result<Plan, ErrorData> {
        let mut filters: HashMap<String, NativeFilter> = HashMap::new();
        let mut resources: HashMap<String, HashMap<String, String>> = HashMap::new();
        let mut tasks: HashMap<String, HashMap<String, String>> = HashMap::new();
        for backend in self
            .manager
            .get_all_backends()
            .into_iter()
            .filter(|backend| backend.is_native())
        {
            filters.insert(
                backend.name().into(),
                NativeFilter {
                    tools_list_changed: filter.tools_list_changed,
                    resources_list_changed: filter.resources_list_changed,
                    prompts_list_changed: filter.prompts_list_changed,
                    ..Default::default()
                },
            );
        }
        for uri in &filter.resource_subscriptions {
            let (server, upstream) = self.catalog.route_resource(uri).ok_or_else(invalid_state)?;
            filters
                .get_mut(&server)
                .ok_or_else(invalid_state)?
                .resource_subscriptions
                .push(upstream.clone());
            resources
                .entry(server)
                .or_default()
                .insert(upstream, uri.clone());
        }
        for token in &filter.task_ids {
            let route = self.lookup(token, true)?;
            let connection = self.connection(&route.server).await?;
            let (server, upstream) = self.task_route(token, connection.generation)?;
            filters
                .get_mut(&server)
                .ok_or_else(invalid_state)?
                .task_ids
                .push(upstream.clone());
            tasks
                .entry(server)
                .or_default()
                .insert(upstream, token.clone());
        }
        Ok(Plan {
            filters,
            resources,
            tasks,
        })
    }

    async fn rewrite_notification(
        &self,
        stream: &Stream,
        notification: &mut Value,
    ) -> Result<(), ErrorData> {
        match notification["method"].as_str() {
            Some("notifications/resources/updated") => {
                let uri = notification["params"]["uri"]
                    .as_str()
                    .and_then(|uri| stream.resources.get(uri))
                    .ok_or_else(invalid_state)?;
                notification["params"]["uri"] = json!(uri);
            }
            Some("notifications/tasks") => {
                let token = notification["params"]["taskId"]
                    .as_str()
                    .and_then(|id| stream.tasks.get(id))
                    .ok_or_else(invalid_state)?;
                let route = self.lookup(token, true)?;
                if route.server != stream.server {
                    return Err(invalid_state());
                }
                self.wrap(&route, &mut notification["params"])?;
            }
            Some(
                "notifications/tools/list_changed"
                | "notifications/resources/list_changed"
                | "notifications/prompts/list_changed",
            ) => {
                if let Some(backend) = self.manager.get_backend(&stream.server) {
                    backend.invalidate_catalog();
                }
                self.refresh(false).await.map_err(invalid_response)?;
            }
            _ => {}
        }
        Ok(())
    }

    pub async fn listen(
        &self,
        request: CustomRequest,
        context: RequestContext<RoleServer>,
    ) -> Result<CustomResult, ErrorData> {
        if request.method != native::LISTEN_METHOD || !super::is_native(&context) {
            return Err(ErrorData::new(
                ErrorCode::METHOD_NOT_FOUND,
                "unsupported method",
                None,
            ));
        }
        let filter =
            NativeFilter::parse(request.params.unwrap_or_default()["notifications"].clone())?;
        if !filter.task_ids.is_empty()
            && context
                .client_capabilities()
                .is_none_or(|caps| !caps.supports_tasks())
        {
            return Err(ErrorData::missing_required_client_capability(
                ClientCapabilities::builder().enable_tasks().build(),
            ));
        }
        let Plan {
            filters,
            mut resources,
            mut tasks,
        } = self.plan(&filter).await?;
        let mut accepted = NativeFilter::default();
        let mut streams = FuturesUnordered::new();
        for (server, mut filter) in filters {
            if filter == NativeFilter::default() {
                continue;
            }
            let connection = self.connection(&server).await?;
            let info = connection
                .peer
                .peer_info()
                .ok_or_else(|| invalid_response("missing discovery"))?;
            filter.restrict_to(&info.capabilities);
            if filter == NativeFilter::default() {
                continue;
            }
            let subscription = tokio::select! {
                () = context.ct.cancelled() => return Err(ErrorData::internal_error("subscription cancelled", None)),
                result = NativeSubscription::open(&connection.peer, &connection.notifications, filter, context.meta.clone(), Duration::from_secs(30)) => result?,
            };
            let resources = resources.remove(&server).unwrap_or_default();
            let tasks = tasks.remove(&server).unwrap_or_default();
            extend_accepted(&mut accepted, &subscription.accepted, &resources, &tasks);
            streams.push(
                Stream {
                    server,
                    subscription,
                    resources,
                    tasks,
                }
                .next(),
            );
        }
        native::send_notification(
            &context.peer,
            "notifications/subscriptions/acknowledged",
            json!({"notifications": accepted}),
            &context.id,
        )
        .await?;
        loop {
            let next = tokio::select! {
                () = context.ct.cancelled() => break,
                next = streams.next() => next,
            };
            let Some((stream, notification)) = next else {
                break;
            };
            if let Some(mut notification) = notification? {
                self.rewrite_notification(&stream, &mut notification)
                    .await?;
                native::send_notification(
                    &context.peer,
                    notification["method"]
                        .as_str()
                        .ok_or_else(|| invalid_response("method"))?,
                    notification["params"].clone(),
                    &context.id,
                )
                .await?;
                streams.push(stream.next());
            }
        }
        Ok(CustomResult(
            json!({"resultType":"complete","_meta":{"io.modelcontextprotocol/subscriptionId":context.id}}),
        ))
    }
}

fn extend_accepted(
    accepted: &mut NativeFilter,
    upstream: &NativeFilter,
    resources: &HashMap<String, String>,
    tasks: &HashMap<String, String>,
) {
    if upstream.tools_list_changed == Some(true) {
        accepted.tools_list_changed = Some(true);
    }
    if upstream.resources_list_changed == Some(true) {
        accepted.resources_list_changed = Some(true);
    }
    if upstream.prompts_list_changed == Some(true) {
        accepted.prompts_list_changed = Some(true);
    }
    accepted.resource_subscriptions.extend(
        upstream
            .resource_subscriptions
            .iter()
            .filter_map(|uri| resources.get(uri).cloned()),
    );
    accepted.task_ids.extend(
        upstream
            .task_ids
            .iter()
            .filter_map(|id| tasks.get(id).cloned()),
    );
}
