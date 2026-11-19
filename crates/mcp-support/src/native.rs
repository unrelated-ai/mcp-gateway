//! Native protocol forwarding without narrowing subscription extension fields.

mod subscriptions;
mod transport;

pub use subscriptions::{
    NativeFilter, NativeSubscription, NotificationHub, send_notification, service_error,
};
pub use transport::{SubscriptionHttpClient, SubscriptionIo};

pub const LISTEN_METHOD: &str = "unrelated/subscriptions/listen";
pub const ACK_METHOD: &str = "unrelated/notifications/subscriptions/acknowledged";

/// Preserve extension filters until the proxy can validate and route them.
/// RMCP 3.8's typed subscription filter omits Tasks Extension identifiers.
pub fn preserve_subscription(message: &mut serde_json::Value) {
    let replacement = match message["method"].as_str() {
        Some("subscriptions/listen") => LISTEN_METHOD,
        Some("notifications/subscriptions/acknowledged") => ACK_METHOD,
        _ => return,
    };
    message["method"] = replacement.into();
}

/// Forward one request with the caller's metadata and cancellation lifetime.
/// # Errors
/// Returns upstream protocol errors, cancellation, or transport failures.
pub async fn request(
    peer: &rmcp::Peer<rmcp::RoleClient>,
    request: rmcp::model::ClientRequest,
    context: &rmcp::service::RequestContext<rmcp::RoleServer>,
    timeout: std::time::Duration,
) -> Result<rmcp::model::ServerResult, rmcp::ErrorData> {
    let task_ack = matches!(
        request,
        rmcp::model::ClientRequest::UpdateTaskRequest(_)
            | rmcp::model::ClientRequest::CancelTaskRequest(_)
    );
    let handle = peer
        .send_cancellable_request(
            request,
            rmcp::service::PeerRequestOptions::with_timeout(timeout)
                .with_meta(context.meta.clone()),
        )
        .await
        .map_err(service_error)?;
    let mut cancellation = CancelRequest {
        peer: peer.clone(),
        id: Some(handle.id.clone()),
    };
    let result = tokio::select! {
        () = context.ct.cancelled() => return Err(rmcp::ErrorData::internal_error("request cancelled", None)),
        result = handle.await_response() => result.map_err(service_error),
    };
    cancellation.id = None;
    result.map(|result| normalize_task_ack(result, task_ack))
}

fn normalize_task_ack(
    result: rmcp::model::ServerResult,
    task_ack: bool,
) -> rmcp::model::ServerResult {
    // RMCP 3.8 decodes metadata-only task acknowledgements as empty tool results.
    if task_ack
        && let rmcp::model::ServerResult::CallToolResult(ref tool) = result
        && tool.content.is_empty()
        && tool.structured_content.is_none()
        && tool.is_error.is_none()
        && tool
            .result_type
            .as_ref()
            .is_some_and(rmcp::model::ResultType::is_complete)
    {
        let mut ack = rmcp::model::TaskAckResult::new();
        ack.meta.clone_from(&tool.meta);
        return rmcp::model::ServerResult::TaskAckResult(ack);
    }
    result
}

struct CancelRequest {
    peer: rmcp::Peer<rmcp::RoleClient>,
    id: Option<rmcp::model::RequestId>,
}

impl Drop for CancelRequest {
    fn drop(&mut self) {
        if let Some(id) = self.id.take()
            && let Ok(runtime) = tokio::runtime::Handle::try_current()
        {
            let peer = self.peer.clone();
            runtime.spawn(async move {
                let _ = peer
                    .notify_cancelled(rmcp::model::CancelledNotificationParam::new(Some(id), None))
                    .await;
            });
        }
    }
}
