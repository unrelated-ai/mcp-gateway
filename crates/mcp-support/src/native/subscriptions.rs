use super::ACK_METHOD;
use rmcp::{
    ErrorData, Peer, RoleClient, RoleServer,
    model::{
        ClientRequest, CustomNotification, CustomRequest, RequestId, RequestMetaObject,
        ServerNotification,
    },
    service::{PeerRequestOptions, RequestHandle, ServiceError},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::time::Duration;
use tokio::sync::broadcast;

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeFilter {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tools_list_changed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources_list_changed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompts_list_changed: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resource_subscriptions: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub task_ids: Vec<String>,
}

impl NativeFilter {
    /// # Errors
    /// Rejects malformed or oversized filters.
    pub fn parse(value: Value) -> Result<Self, ErrorData> {
        let filter: Self = serde_json::from_value(value)
            .map_err(|_| ErrorData::invalid_params("invalid subscription filter", None))?;
        if filter.resource_subscriptions.len() + filter.task_ids.len() > 128
            || filter
                .resource_subscriptions
                .iter()
                .chain(&filter.task_ids)
                .any(|id| id.is_empty() || id.len() > 16384)
        {
            return Err(ErrorData::invalid_params(
                "subscription filter exceeds limits",
                None,
            ));
        }
        Ok(filter)
    }

    /// Keep only notifications the peer advertises in discovery.
    pub fn restrict_to(&mut self, caps: &rmcp::model::ServerCapabilities) {
        self.tools_list_changed = self
            .tools_list_changed
            .filter(|yes| *yes && caps.tools.as_ref().and_then(|c| c.list_changed) == Some(true));
        self.resources_list_changed = self.resources_list_changed.filter(|yes| {
            *yes && caps.resources.as_ref().and_then(|c| c.list_changed) == Some(true)
        });
        self.prompts_list_changed = self
            .prompts_list_changed
            .filter(|yes| *yes && caps.prompts.as_ref().and_then(|c| c.list_changed) == Some(true));
        if caps.resources.as_ref().and_then(|c| c.subscribe) != Some(true) {
            self.resource_subscriptions.clear();
        }
        if !caps.supports_tasks() {
            self.task_ids.clear();
        }
    }

    #[must_use]
    pub fn is_subset_of(&self, requested: &Self) -> bool {
        [
            (self.tools_list_changed, requested.tools_list_changed),
            (
                self.resources_list_changed,
                requested.resources_list_changed,
            ),
            (self.prompts_list_changed, requested.prompts_list_changed),
        ]
        .into_iter()
        .all(|(accepted, requested)| accepted != Some(true) || requested == Some(true))
            && self
                .resource_subscriptions
                .iter()
                .all(|uri| requested.resource_subscriptions.contains(uri))
            && self
                .task_ids
                .iter()
                .all(|id| requested.task_ids.contains(id))
    }

    #[must_use]
    pub fn accepts(&self, notification: &Value) -> bool {
        match notification["method"].as_str() {
            Some("notifications/tools/list_changed") => self.tools_list_changed == Some(true),
            Some("notifications/resources/list_changed") => {
                self.resources_list_changed == Some(true)
            }
            Some("notifications/prompts/list_changed") => self.prompts_list_changed == Some(true),
            Some("notifications/resources/updated") => notification["params"]["uri"]
                .as_str()
                .is_some_and(|uri| self.resource_subscriptions.iter().any(|item| item == uri)),
            Some("notifications/tasks") => notification["params"]["taskId"]
                .as_str()
                .is_some_and(|id| self.task_ids.iter().any(|item| item == id)),
            _ => false,
        }
    }
}

#[derive(Clone, Debug)]
pub struct NotificationHub(broadcast::Sender<Value>);

impl Default for NotificationHub {
    fn default() -> Self {
        Self(broadcast::channel(128).0)
    }
}

impl NotificationHub {
    pub(super) fn publish_message(&self, message: &Value) {
        if message.get("method").is_none() || message.get("id").is_some() {
            return;
        }
        let mut message = message.clone();
        if message["method"] == "notifications/cancelled" {
            message["params"]["_meta"]["io.modelcontextprotocol/subscriptionId"] =
                message["params"]["requestId"].clone();
        }
        if message["params"]["_meta"]["io.modelcontextprotocol/subscriptionId"].is_null() {
            return;
        }
        let _ = self.0.send(message);
    }
}

#[must_use]
pub fn service_error(error: ServiceError) -> ErrorData {
    match error {
        ServiceError::McpError(error) => error,
        ServiceError::Timeout { .. } => {
            ErrorData::internal_error("upstream request timed out", None)
        }
        _ => ErrorData::internal_error("upstream connection failed", None),
    }
}

/// # Errors
/// Returns a transport error if delivery fails.
pub async fn send_notification(
    peer: &Peer<RoleServer>,
    method: &str,
    mut params: Value,
    id: &RequestId,
) -> Result<(), ErrorData> {
    if !params.is_object() {
        params = json!({});
    }
    params["_meta"]["io.modelcontextprotocol/subscriptionId"] =
        serde_json::to_value(id).unwrap_or_default();
    peer.send_notification(ServerNotification::CustomNotification(
        CustomNotification::new(method.to_owned(), Some(params)),
    ))
    .await
    .map_err(service_error)
}

pub struct NativeSubscription {
    pub accepted: NativeFilter,
    request: Option<RequestHandle<RoleClient>>,
    notifications: broadcast::Receiver<Value>,
    id: Value,
}

impl NativeSubscription {
    /// # Errors
    /// Rejects missing or invalid acknowledgements and transport failures.
    pub async fn open(
        peer: &Peer<RoleClient>,
        hub: &NotificationHub,
        filter: NativeFilter,
        meta: RequestMetaObject,
        timeout: Duration,
    ) -> Result<Self, ErrorData> {
        let notifications = hub.0.subscribe();
        let request = peer
            .send_cancellable_request(
                ClientRequest::CustomRequest(CustomRequest::new(
                    "subscriptions/listen",
                    Some(json!({"notifications":filter})),
                )),
                PeerRequestOptions::no_options().with_meta(meta),
            )
            .await
            .map_err(service_error)?;
        let id = serde_json::to_value(&request.id).unwrap_or_default();
        let mut stream = Self {
            accepted: NativeFilter::default(),
            request: Some(request),
            notifications,
            id,
        };
        let acknowledgement = tokio::time::timeout(timeout, stream.next_message())
            .await
            .map_err(|_| {
                ErrorData::internal_error("subscription acknowledgement timed out", None)
            })??
            .ok_or_else(|| {
                ErrorData::internal_error("subscription closed before acknowledgement", None)
            })?;
        if acknowledgement["method"] != ACK_METHOD {
            return Err(ErrorData::internal_error(
                "subscription notification preceded acknowledgement",
                None,
            ));
        }
        stream.accepted = NativeFilter::parse(acknowledgement["params"]["notifications"].clone())?;
        if !stream.accepted.is_subset_of(&filter) {
            return Err(ErrorData::internal_error(
                "upstream acknowledged an unrequested subscription",
                None,
            ));
        }
        Ok(stream)
    }

    async fn next_message(&mut self) -> Result<Option<Value>, ErrorData> {
        loop {
            let Some(request) = self.request.as_mut() else {
                return Ok(None);
            };
            tokio::select! {
                biased;
                notification = self.notifications.recv() => {
                    let notification = notification.map_err(|_| ErrorData::internal_error("subscription notification buffer exhausted",None))?;
                    if notification["params"]["_meta"]["io.modelcontextprotocol/subscriptionId"] == self.id {
                        if notification["method"] == "notifications/cancelled" { return Ok(None); }
                        return Ok(Some(notification));
                    }
                }
                result = &mut request.rx => {
                    self.request = None;
                    let result = result.map_err(|_| ErrorData::internal_error("subscription disconnected",None))?
                        .map_err(service_error)?;
                    if let rmcp::model::ServerResult::SubscriptionsListenResult(result) = result
                        && serde_json::to_value(result.meta.subscription_id()).unwrap_or_default() == self.id {
                        return Ok(None);
                    }
                    return Err(ErrorData::internal_error("invalid subscription completion", None));
                }
            }
        }
    }

    /// # Errors
    /// Rejects unrequested notifications, buffer overflow, and transport failures.
    pub async fn next(&mut self) -> Result<Option<Value>, ErrorData> {
        let message = self.next_message().await?;
        if message
            .as_ref()
            .is_some_and(|message| !self.accepted.accepts(message))
        {
            return Err(ErrorData::internal_error(
                "notification outside acknowledged subscription",
                None,
            ));
        }
        if let Some(message) = &message
            && message["method"] == "notifications/tasks"
        {
            serde_json::from_value::<rmcp::model::TaskStatusNotificationParams>(
                message["params"].clone(),
            )
            .map_err(|_| ErrorData::internal_error("invalid task notification", None))?;
        }
        Ok(message)
    }
}

impl Drop for NativeSubscription {
    fn drop(&mut self) {
        if let Some(request) = self.request.take()
            && let Ok(runtime) = tokio::runtime::Handle::try_current()
        {
            runtime.spawn(async move {
                let _ = request.cancel(Some("subscription closed".into())).await;
            });
        }
    }
}
