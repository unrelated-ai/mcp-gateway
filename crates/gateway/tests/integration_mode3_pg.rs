mod common;

use anyhow::Context as _;
use axum::{
    Router,
    response::IntoResponse,
    routing::{get, post},
};
use common::mcp::McpSession;
use common::pg::{apply_dbmate_migrations, wait_pg_ready};
use common::{KillOnDrop, pick_unused_port, spawn_gateway, wait_http_ok};
use rmcp::model::{
    CallToolResult, ClientJsonRpcMessage, ClientRequest, Content, ErrorData, InitializeResult,
    JsonObject, JsonRpcError, JsonRpcRequest, JsonRpcResponse, JsonRpcVersion2_0, ListToolsResult,
    ServerCapabilities, ServerJsonRpcMessage, ServerResult, Tool,
};
use serde_json::json;
use std::{collections::HashSet, sync::Arc, time::Duration};
use tokio::sync::Mutex;

use testcontainers::GenericImage;
use testcontainers::ImageExt as _;
use testcontainers::core::IntoContainerPort;
use testcontainers::runners::AsyncRunner;

const ADMIN_TOKEN: &str = "test-admin-token";
const SESSION_SECRET: &str = "test-session-secret";

#[derive(Clone)]
struct MockUpstream {
    upstream_id: &'static str,
    sessions: Arc<Mutex<HashSet<String>>>,
}

impl MockUpstream {
    fn new(upstream_id: &'static str) -> Self {
        Self {
            upstream_id,
            sessions: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    fn router(self) -> Router {
        Router::new()
            .route("/health", get(|| async { "ok" }))
            .route("/mcp", post(Self::post_mcp).delete(Self::delete_mcp))
            .with_state(self)
    }

    async fn post_mcp(
        axum::extract::State(this): axum::extract::State<MockUpstream>,
        headers: axum::http::HeaderMap,
        body: axum::body::Bytes,
    ) -> axum::response::Response {
        let session = headers
            .get("Mcp-Session-Id")
            .and_then(|h| h.to_str().ok())
            .map(str::to_string);

        let message: ClientJsonRpcMessage = match serde_json::from_slice(&body) {
            Ok(m) => m,
            Err(e) => {
                return (
                    axum::http::StatusCode::UNSUPPORTED_MEDIA_TYPE,
                    format!("invalid json: {e}"),
                )
                    .into_response();
            }
        };

        match session {
            None => this.handle_initialize(message).await,
            Some(session_id) => this.handle_in_session(session_id, message).await,
        }
    }

    async fn delete_mcp(
        axum::extract::State(this): axum::extract::State<MockUpstream>,
        headers: axum::http::HeaderMap,
    ) -> axum::response::Response {
        let Some(session_id) = headers
            .get("Mcp-Session-Id")
            .and_then(|h| h.to_str().ok())
            .map(str::to_string)
        else {
            return (axum::http::StatusCode::UNAUTHORIZED, "missing session id").into_response();
        };
        this.sessions.lock().await.remove(&session_id);
        (axum::http::StatusCode::ACCEPTED, "").into_response()
    }

    async fn handle_initialize(&self, message: ClientJsonRpcMessage) -> axum::response::Response {
        let ClientJsonRpcMessage::Request(JsonRpcRequest {
            id: req_id,
            request: ClientRequest::InitializeRequest(init),
            ..
        }) = message
        else {
            return (
                axum::http::StatusCode::UNPROCESSABLE_ENTITY,
                "expected initialize request",
            )
                .into_response();
        };
        let init_params = init.params;

        let session_id = uuid::Uuid::new_v4().to_string();
        self.sessions.lock().await.insert(session_id.clone());

        let init_result = InitializeResult {
            protocol_version: init_params.protocol_version,
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            server_info: rmcp::model::Implementation {
                name: format!("mock-upstream-{}", self.upstream_id),
                title: None,
                version: "0".to_string(),
                icons: None,
                website_url: None,
            },
            instructions: None,
        };

        let msg = ServerJsonRpcMessage::Response(JsonRpcResponse {
            jsonrpc: JsonRpcVersion2_0,
            id: req_id,
            result: ServerResult::InitializeResult(init_result),
        });

        sse_single_message_with_session_id(&msg, &session_id)
    }

    async fn handle_in_session(
        &self,
        session_id: String,
        message: ClientJsonRpcMessage,
    ) -> axum::response::Response {
        if !self.sessions.lock().await.contains(&session_id) {
            return (axum::http::StatusCode::UNAUTHORIZED, "session not found").into_response();
        }

        match message {
            ClientJsonRpcMessage::Request(JsonRpcRequest { id, request, .. }) => match request {
                ClientRequest::ListToolsRequest(_) => {
                    let tool = Tool::new(
                        "echo_request",
                        "Echo request (mock)",
                        Arc::new(JsonObject::new()),
                    );
                    let result = ListToolsResult {
                        tools: vec![tool],
                        ..Default::default()
                    };
                    let msg = ServerJsonRpcMessage::Response(JsonRpcResponse {
                        jsonrpc: JsonRpcVersion2_0,
                        id,
                        result: ServerResult::ListToolsResult(result),
                    });
                    sse_single_message(&msg)
                }
                ClientRequest::CallToolRequest(call) => {
                    let name = call.params.name.to_string();
                    let text = format!("upstream={}, tool={name}", self.upstream_id);
                    let result = CallToolResult {
                        content: vec![Content::text(text)],
                        structured_content: None,
                        is_error: None,
                        meta: None,
                    };
                    let msg = ServerJsonRpcMessage::Response(JsonRpcResponse {
                        jsonrpc: JsonRpcVersion2_0,
                        id,
                        result: ServerResult::CallToolResult(result),
                    });
                    sse_single_message(&msg)
                }
                _ => {
                    let msg = ServerJsonRpcMessage::Error(JsonRpcError {
                        jsonrpc: JsonRpcVersion2_0,
                        id,
                        error: ErrorData::new(
                            rmcp::model::ErrorCode::METHOD_NOT_FOUND,
                            "method not found",
                            None,
                        ),
                    });
                    sse_single_message(&msg)
                }
            },
            _ => (axum::http::StatusCode::ACCEPTED, "").into_response(),
        }
    }
}

fn sse_single_message(msg: &ServerJsonRpcMessage) -> axum::response::Response {
    use axum::response::sse::Event;
    use std::convert::Infallible;

    let data = serde_json::to_string(msg).expect("valid json");
    let stream =
        futures::stream::once(async move { Ok::<_, Infallible>(Event::default().data(data)) });
    axum::response::Sse::new(stream).into_response()
}

fn sse_single_message_with_session_id(
    msg: &ServerJsonRpcMessage,
    session_id: &str,
) -> axum::response::Response {
    let mut resp = sse_single_message(msg);
    resp.headers_mut().insert(
        "Mcp-Session-Id",
        axum::http::HeaderValue::from_str(session_id).expect("valid header"),
    );
    resp
}

async fn admin_post(
    client: &reqwest::Client,
    base: &str,
    path: &str,
    body: serde_json::Value,
) -> anyhow::Result<serde_json::Value> {
    let resp = client
        .post(format!("{base}{path}"))
        .header("Authorization", format!("Bearer {ADMIN_TOKEN}"))
        .json(&body)
        .send()
        .await
        .context("admin POST")?
        .error_for_status()
        .context("admin POST status")?;
    resp.json().await.context("admin POST json")
}

async fn admin_issue_tenant_token(
    client: &reqwest::Client,
    admin_base: &str,
    tenant_id: &str,
) -> anyhow::Result<String> {
    let resp = admin_post(
        client,
        admin_base,
        "/admin/v1/tenant-tokens",
        json!({"tenantId": tenant_id, "ttlSeconds": 3600}),
    )
    .await?;
    resp.get("token")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
        .context("tenant token response missing token")
}

async fn tenant_create_api_key(
    client: &reqwest::Client,
    admin_base: &str,
    tenant_token: &str,
    profile_id: &str,
) -> anyhow::Result<String> {
    let resp = client
        .post(format!("{admin_base}/tenant/v1/api-keys"))
        .header("Authorization", format!("Bearer {tenant_token}"))
        .json(&json!({"name": "test", "profileId": profile_id}))
        .send()
        .await
        .context("tenant POST /api-keys")?
        .error_for_status()
        .context("tenant POST /api-keys status")?;
    let body: serde_json::Value = resp.json().await.context("tenant POST /api-keys json")?;
    body.get("secret")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
        .context("create api key response missing secret")
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
#[allow(clippy::too_many_lines)]
async fn mode3_pg_profile_aggregates_two_upstreams_and_prefixes_on_collision() -> anyhow::Result<()>
{
    // Postgres
    let pg = GenericImage::new("postgres", "16-alpine")
        .with_exposed_port(5432.tcp())
        .with_env_var("POSTGRES_PASSWORD", "postgres")
        .with_env_var("POSTGRES_USER", "postgres")
        .with_env_var("POSTGRES_DB", "gateway")
        .start()
        .await
        .context("start postgres container")?;
    let host = pg.get_host().await?.to_string();
    let port = pg.get_host_port_ipv4(5432).await?;
    let database_url =
        format!("postgres://postgres:postgres@{host}:{port}/gateway?sslmode=disable");
    wait_pg_ready(&database_url, Duration::from_secs(30)).await?;
    apply_dbmate_migrations(&database_url).await?;

    // Two upstream MCP servers with the same tool name -> collision.
    let u1_port = pick_unused_port()?;
    let u2_port = pick_unused_port()?;

    let u1 = MockUpstream::new("u1").router();
    let u2 = MockUpstream::new("u2").router();

    let u1_listener = tokio::net::TcpListener::bind(("127.0.0.1", u1_port)).await?;
    let u2_listener = tokio::net::TcpListener::bind(("127.0.0.1", u2_port)).await?;

    let u1_task = tokio::spawn(async move {
        let _ = axum::serve(u1_listener, u1).await;
    });
    let u2_task = tokio::spawn(async move {
        let _ = axum::serve(u2_listener, u2).await;
    });

    // Wait for upstream health.
    wait_http_ok(
        &format!("http://127.0.0.1:{u1_port}/health"),
        Duration::from_secs(10),
    )
    .await?;
    wait_http_ok(
        &format!("http://127.0.0.1:{u2_port}/health"),
        Duration::from_secs(10),
    )
    .await?;

    // Gateway (Mode 3).
    let gw = spawn_gateway(&database_url, Some(ADMIN_TOKEN), SESSION_SECRET)?;
    let data_base = gw.data_base.clone();
    let admin_base = gw.admin_base.clone();
    let _gateway_child = KillOnDrop(gw.child);
    wait_http_ok(&format!("{data_base}/health"), Duration::from_secs(20)).await?;
    wait_http_ok(&format!("{admin_base}/health"), Duration::from_secs(20)).await?;

    // Provision via admin API.
    let client = reqwest::Client::new();
    let _ = admin_post(
        &client,
        &admin_base,
        "/admin/v1/tenants",
        json!({ "id": "t1", "enabled": true }),
    )
    .await?;

    let _ = admin_post(
        &client,
        &admin_base,
        "/admin/v1/upstreams",
        json!({
            "id": "u1",
            "enabled": true,
            "endpoints": [{ "id": "e1", "url": format!("http://127.0.0.1:{u1_port}/mcp") }]
        }),
    )
    .await?;

    let _ = admin_post(
        &client,
        &admin_base,
        "/admin/v1/upstreams",
        json!({
            "id": "u2",
            "enabled": true,
            "endpoints": [{ "id": "e1", "url": format!("http://127.0.0.1:{u2_port}/mcp") }]
        }),
    )
    .await?;

    let profile_resp = admin_post(
        &client,
        &admin_base,
        "/admin/v1/profiles",
        json!({
            "tenantId": "t1",
            "name": "p1",
            "allowPartialUpstreams": true,
            "upstreams": ["u1", "u2"]
        }),
    )
    .await?;

    let profile_id = profile_resp
        .get("id")
        .and_then(serde_json::Value::as_str)
        .context("create profile response missing id")?
        .to_string();

    // Mode 3 data-plane requires an API key (profile default: ApiKeyInitializeOnly).
    let t1_token = admin_issue_tenant_token(&client, &admin_base, "t1").await?;
    let api_key = tenant_create_api_key(&client, &admin_base, &t1_token, &profile_id).await?;

    let session = McpSession::connect(
        format!("{data_base}/{profile_id}/mcp"),
        Some(api_key.clone()),
    )
    .await?;

    // No allowlist configured: tools/list should include all tools (collision => prefixed names).
    let tools_msg = session
        .request_value_no_auth(1, "tools/list", json!({}))
        .await?;
    let tools = tools_msg
        .get("result")
        .and_then(|r| r.get("tools"))
        .and_then(serde_json::Value::as_array)
        .context("tools/list missing result.tools")?;

    let names: Vec<String> = tools
        .iter()
        .filter_map(|t| {
            t.get("name")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string)
        })
        .collect();

    anyhow::ensure!(
        names.contains(&"u1:echo_request".to_string())
            && names.contains(&"u2:echo_request".to_string()),
        "expected both upstream tools (prefixed) to be present, got: {names:?}"
    );

    // Restrict allowlist to a single tool (update profile).
    let _ = admin_post(
        &client,
        &admin_base,
        "/admin/v1/profiles",
        json!({
            "id": profile_id,
            "tenantId": "t1",
            "allowPartialUpstreams": true,
            "upstreams": ["u1", "u2"],
            "tools": ["u1:echo_request"]
        }),
    )
    .await?;

    // With only one tool enabled, there is no collision, so tools/list should show the base name.
    let tools_msg = session
        .request_value_no_auth(2, "tools/list", json!({}))
        .await?;
    let tools = tools_msg
        .get("result")
        .and_then(|r| r.get("tools"))
        .and_then(serde_json::Value::as_array)
        .context("tools/list missing result.tools")?;

    let names: Vec<String> = tools
        .iter()
        .filter_map(|t| {
            t.get("name")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string)
        })
        .collect();

    assert_eq!(names, vec!["echo_request".to_string()]);

    // tools/call route to specific upstream.
    let call_msg = session
        .request_value_no_auth(
            3,
            "tools/call",
            json!({ "name": "u1:echo_request", "arguments": {} }),
        )
        .await?;
    let text = call_msg
        .get("result")
        .and_then(|r| r.get("content"))
        .and_then(serde_json::Value::as_array)
        .and_then(|c| c.first())
        .and_then(|c| c.get("text"))
        .and_then(serde_json::Value::as_str)
        .context("tools/call missing result.content[0].text")?;
    anyhow::ensure!(
        text.contains("upstream=u1"),
        "expected tools/call to hit upstream u1, got: {text}"
    );

    // Cleanup upstream servers.
    u1_task.abort();
    u2_task.abort();

    Ok(())
}
