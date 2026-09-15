use super::*;
use rmcp::model::{CallToolResult, ContentBlock, ListToolsResult};
use serde_json::json;

#[tokio::test]
async fn legacy_results_keep_their_wire_shape() -> anyhow::Result<()> {
    for (result, expected) in [
        (
            ServerResult::ListToolsResult(ListToolsResult::with_all_items(vec![])),
            json!({"tools": []}),
        ),
        (
            ServerResult::CallToolResult(CallToolResult::success(vec![ContentBlock::text("ok")])),
            json!({"content": [{"type": "text", "text": "ok"}], "isError": false}),
        ),
    ] {
        let response = sse_single_message(ServerJsonRpcMessage::Response(JsonRpcResponse {
            jsonrpc: JsonRpcVersion2_0,
            id: RequestId::Number(1),
            result,
        }));
        let body = axum::body::to_bytes(response.into_body(), 4096).await?;
        let text = std::str::from_utf8(&body)?;
        let data = text
            .lines()
            .find_map(|line| line.strip_prefix("data: "))
            .ok_or_else(|| anyhow::anyhow!("missing SSE data"))?;
        let message: serde_json::Value = serde_json::from_str(data)?;
        assert_eq!(
            message,
            json!({"jsonrpc": "2.0", "id": 1, "result": expected})
        );
    }
    Ok(())
}

#[test]
fn modern_task_notifications_remain_blocked() {
    let notification = parse_server_notification(
        "notifications/tasks",
        Some(json!({
            "taskId": "task-1",
            "status": "working",
            "createdAt": "2026-09-07T00:00:00Z",
            "lastUpdatedAt": "2026-09-07T00:00:00Z",
            "ttlMs": null
        })),
    );
    assert!(matches!(
        notification,
        ServerNotification::TaskStatusNotification(_)
    ));
    let kind = classify_server_notification(&notification);
    assert_eq!(kind, NotificationKind::TaskStatusUpdate);
    assert_eq!(kind.method(), "notifications/tasks");
    assert!(!notification_allowed(
        default_effective_caps(),
        &crate::store::McpNotificationFilter::default(),
        &kind,
    ));
}
