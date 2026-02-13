mod common;

use anyhow::Context as _;
use axum::{
    Router,
    response::IntoResponse,
    routing::{get, post},
};
use common::pg::{apply_dbmate_migrations, wait_pg_ready};
use common::sse::read_first_event_stream_json_message;
use common::{KillOnDrop, pick_unused_port, spawn_gateway, wait_http_ok};
use futures::StreamExt as _;
use rmcp::model::{
    ClientJsonRpcMessage, ClientRequest, ErrorData, InitializeResult, JsonRpcError, JsonRpcRequest,
    JsonRpcResponse, JsonRpcVersion2_0, ListPromptsResult, ListResourcesResult, ListToolsResult,
    Prompt, RawResource, Resource, ServerCapabilities, ServerJsonRpcMessage, ServerResult, Tool,
};
use serde_json::json;
use std::collections::HashSet;
use std::convert::Infallible;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;
use testcontainers::GenericImage;
use testcontainers::ImageExt as _;
use testcontainers::core::IntoContainerPort;
use testcontainers::runners::AsyncRunner;
use tokio::io::AsyncBufReadExt as _;
use tokio::sync::Mutex;

const ADMIN_TOKEN: &str = "test-admin-token";
const SESSION_SECRET: &str = "test-session-secret";

#[derive(Clone)]
struct DynamicUpstream {
    upstream_id: &'static str,
    sessions: Arc<Mutex<HashSet<String>>>,
    version: Arc<AtomicUsize>,
}

impl DynamicUpstream {
    fn new(upstream_id: &'static str) -> Self {
        Self {
            upstream_id,
            sessions: Arc::new(Mutex::new(HashSet::new())),
            version: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn set_version(&self, v: usize) {
        self.version.store(v, Ordering::SeqCst);
    }

    fn router(self) -> Router {
        Router::new()
            .route("/health", get(|| async { "ok" }))
            .route(
                "/mcp",
                post(Self::post_mcp)
                    .get(Self::get_mcp)
                    .delete(Self::delete_mcp),
            )
            .with_state(self)
    }

    async fn get_mcp(
        axum::extract::State(this): axum::extract::State<DynamicUpstream>,
        headers: axum::http::HeaderMap,
    ) -> axum::response::Response {
        // Minimal streamable HTTP SSE endpoint: keep the stream open.
        let session_id = headers
            .get("Mcp-Session-Id")
            .and_then(|h| h.to_str().ok())
            .map(str::to_string);
        let Some(session_id) = session_id else {
            return (axum::http::StatusCode::UNAUTHORIZED, "missing session id").into_response();
        };

        if !this.sessions.lock().await.contains(&session_id) {
            return (axum::http::StatusCode::UNAUTHORIZED, "session not found").into_response();
        }

        let stream = futures::stream::pending::<Result<axum::response::sse::Event, Infallible>>();
        axum::response::Sse::new(stream).into_response()
    }

    async fn post_mcp(
        axum::extract::State(this): axum::extract::State<DynamicUpstream>,
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
        axum::extract::State(this): axum::extract::State<DynamicUpstream>,
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
            capabilities: ServerCapabilities::builder()
                .enable_tools()
                .enable_resources()
                .enable_prompts()
                .build(),
            server_info: rmcp::model::Implementation {
                name: format!("dynamic-upstream-{}", self.upstream_id),
                title: None,
                version: "0".to_string(),
                description: None,
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
                    let v = self.version.load(Ordering::SeqCst);
                    let mut tools = vec![Tool::new(
                        "tool_v1".to_string(),
                        "tool v1",
                        Arc::new(rmcp::model::JsonObject::new()),
                    )];
                    if v >= 1 {
                        tools.push(Tool::new(
                            "tool_v2".to_string(),
                            "tool v2",
                            Arc::new(rmcp::model::JsonObject::new()),
                        ));
                    }
                    let result = ListToolsResult {
                        tools,
                        ..Default::default()
                    };
                    let msg = ServerJsonRpcMessage::Response(JsonRpcResponse {
                        jsonrpc: JsonRpcVersion2_0,
                        id,
                        result: ServerResult::ListToolsResult(result),
                    });
                    sse_single_message(&msg)
                }
                ClientRequest::ListResourcesRequest(_) => {
                    let v = self.version.load(Ordering::SeqCst);
                    let mut resources: Vec<Resource> = vec![rmcp::model::Annotated::new(
                        RawResource::new("file:///r1".to_string(), "r1".to_string()),
                        None,
                    )];
                    if v >= 1 {
                        resources.push(rmcp::model::Annotated::new(
                            RawResource::new("file:///r2".to_string(), "r2".to_string()),
                            None,
                        ));
                    }
                    let result = ListResourcesResult {
                        resources,
                        ..Default::default()
                    };
                    let msg = ServerJsonRpcMessage::Response(JsonRpcResponse {
                        jsonrpc: JsonRpcVersion2_0,
                        id,
                        result: ServerResult::ListResourcesResult(result),
                    });
                    sse_single_message(&msg)
                }
                ClientRequest::ListPromptsRequest(_) => {
                    let v = self.version.load(Ordering::SeqCst);
                    let mut prompts = vec![Prompt::new("p1", Some("p1"), None)];
                    if v >= 1 {
                        prompts.push(Prompt::new("p2", Some("p2"), None));
                    }
                    let result = ListPromptsResult {
                        prompts,
                        ..Default::default()
                    };
                    let msg = ServerJsonRpcMessage::Response(JsonRpcResponse {
                        jsonrpc: JsonRpcVersion2_0,
                        id,
                        result: ServerResult::ListPromptsResult(result),
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

async fn wait_for_notification_method_with_sse_id(
    resp: reqwest::Response,
    method: &str,
    timeout: Duration,
) -> anyhow::Result<(String, serde_json::Value)> {
    use tokio_util::io::StreamReader;

    let mut byte_stream = resp.bytes_stream();
    let byte_stream = futures::stream::poll_fn(move |cx| byte_stream.poll_next_unpin(cx))
        .map(|r| r.map_err(std::io::Error::other));
    let reader = StreamReader::new(byte_stream);
    let mut lines = tokio::io::BufReader::new(reader).lines();

    let deadline = tokio::time::Instant::now() + timeout;

    let mut cur_id: Option<String> = None;
    let mut data_lines: Vec<String> = Vec::new();

    loop {
        let line_opt = tokio::time::timeout_at(deadline, lines.next_line())
            .await
            .context("timeout waiting for SSE line")??;
        let Some(line) = line_opt else {
            anyhow::bail!("SSE stream ended before receiving {method}");
        };
        let line = line.trim_end();

        if line.is_empty() {
            if data_lines.is_empty() {
                continue;
            }
            let data = data_lines.join("\n");
            data_lines.clear();

            let msg: serde_json::Value =
                serde_json::from_str(&data).context("parse SSE data JSON")?;
            if msg
                .get("method")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|m| m == method)
            {
                let id = cur_id
                    .take()
                    .context("expected SSE id for notification event")?;
                return Ok((id, msg));
            }

            cur_id = None;
            continue;
        }

        if let Some(v) = line.strip_prefix("id:") {
            cur_id = Some(v.trim().to_string());
            continue;
        }
        if let Some(v) = line.strip_prefix("data:") {
            data_lines.push(v.trim().to_string());
        }
    }
}

async fn post_mcp(
    client: &reqwest::Client,
    url: &str,
    session_id: Option<&str>,
    api_key_secret: Option<&str>,
    body: serde_json::Value,
) -> anyhow::Result<reqwest::Response> {
    let mut req = client
        .post(url)
        .header("Accept", "application/json, text/event-stream")
        .header("Content-Type", "application/json")
        .json(&body);

    if let Some(session_id) = session_id {
        req = req.header("Mcp-Session-Id", session_id);
    }
    if let Some(secret) = api_key_secret {
        req = req.header("Authorization", format!("Bearer {secret}"));
    }

    req.send()
        .await?
        .error_for_status()
        .context("POST mcp status")
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
async fn pg_fanout_broadcasts_list_changed_cross_node() -> anyhow::Result<()> {
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

    // Upstream (dynamic)
    let upstream_port = pick_unused_port()?;
    let upstream = DynamicUpstream::new("u1");
    let upstream_handle = upstream.clone();
    let upstream_router = upstream.router();
    let upstream_listener = tokio::net::TcpListener::bind(("127.0.0.1", upstream_port)).await?;
    let upstream_task = tokio::spawn(async move {
        let _ = axum::serve(upstream_listener, upstream_router).await;
    });
    wait_http_ok(
        &format!("http://127.0.0.1:{upstream_port}/health"),
        Duration::from_secs(10),
    )
    .await?;

    // Two gateway nodes (Mode 3).
    let gw_a = spawn_gateway(&database_url, Some(ADMIN_TOKEN), SESSION_SECRET)?;
    let gw_b = spawn_gateway(&database_url, Some(ADMIN_TOKEN), SESSION_SECRET)?;
    let data_base_a = gw_a.data_base.clone();
    let admin_base_a = gw_a.admin_base.clone();
    let data_base_b = gw_b.data_base.clone();
    let admin_base_b = gw_b.admin_base.clone();
    let _gw_a = KillOnDrop(gw_a.child);
    let _gw_b = KillOnDrop(gw_b.child);

    wait_http_ok(&format!("{data_base_a}/health"), Duration::from_secs(20)).await?;
    wait_http_ok(&format!("{admin_base_a}/health"), Duration::from_secs(20)).await?;
    wait_http_ok(&format!("{data_base_b}/health"), Duration::from_secs(20)).await?;
    wait_http_ok(&format!("{admin_base_b}/health"), Duration::from_secs(20)).await?;

    // Provision tenant/upstream/profile via admin API (node A).
    let client = reqwest::Client::new();
    let _ = admin_post(
        &client,
        &admin_base_a,
        "/admin/v1/tenants",
        json!({ "id": "t1", "enabled": true }),
    )
    .await?;
    let _ = admin_post(
        &client,
        &admin_base_a,
        "/admin/v1/upstreams",
        json!({
            "id": "u1",
            "enabled": true,
            "endpoints": [{ "id": "e1", "url": format!("http://127.0.0.1:{upstream_port}/mcp") }]
        }),
    )
    .await?;
    let profile_resp = admin_post(
        &client,
        &admin_base_a,
        "/admin/v1/profiles",
        json!({
            "tenantId": "t1",
            "name": "p1",
            "allowPartialUpstreams": true,
            "upstreams": ["u1"],
            "tools": []
        }),
    )
    .await?;
    let profile_id = profile_resp
        .get("id")
        .and_then(serde_json::Value::as_str)
        .context("create profile response missing id")?
        .to_string();

    // Mode 3 data-plane requires an API key (profile default: ApiKeyInitializeOnly).
    let t1_token = admin_issue_tenant_token(&client, &admin_base_a, "t1").await?;
    let api_key = tenant_create_api_key(&client, &admin_base_a, &t1_token, &profile_id).await?;

    // Initialize a session (node A).
    let init_resp = post_mcp(
        &client,
        &format!("{data_base_a}/{profile_id}/mcp"),
        None,
        Some(&api_key),
        json!({
            "jsonrpc": "2.0",
            "id": 0,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": { "name": "fanout-test", "version": "0" }
            }
        }),
    )
    .await?;
    let session_id = init_resp
        .headers()
        .get("Mcp-Session-Id")
        .and_then(|h| h.to_str().ok())
        .context("missing Mcp-Session-Id header")?
        .to_string();
    let _init_msg = read_first_event_stream_json_message(init_resp).await?;

    // Establish baseline on BOTH nodes by calling tools/resources/prompts list once.
    for base in [&data_base_a, &data_base_b] {
        let _ = read_first_event_stream_json_message(
            post_mcp(
                &client,
                &format!("{base}/{profile_id}/mcp"),
                Some(&session_id),
                None,
                json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}),
            )
            .await?,
        )
        .await?;

        let _ = read_first_event_stream_json_message(
            post_mcp(
                &client,
                &format!("{base}/{profile_id}/mcp"),
                Some(&session_id),
                None,
                json!({"jsonrpc": "2.0", "id": 2, "method": "resources/list", "params": {}}),
            )
            .await?,
        )
        .await?;

        let _ = read_first_event_stream_json_message(
            post_mcp(
                &client,
                &format!("{base}/{profile_id}/mcp"),
                Some(&session_id),
                None,
                json!({"jsonrpc": "2.0", "id": 3, "method": "prompts/list", "params": {}}),
            )
            .await?,
        )
        .await?;
    }

    // Open a GET stream on node A and wait for notifications.
    let stream_resp = client
        .get(format!("{data_base_a}/{profile_id}/mcp"))
        .header("Accept", "text/event-stream")
        .header("Mcp-Session-Id", &session_id)
        .send()
        .await?
        .error_for_status()
        .context("GET stream status")?;

    // Trigger a contract change by changing the upstream, then calling list methods on node B.
    upstream_handle.set_version(1);

    let _ = read_first_event_stream_json_message(
        post_mcp(
            &client,
            &format!("{data_base_b}/{profile_id}/mcp"),
            Some(&session_id),
            None,
            json!({"jsonrpc": "2.0", "id": 4, "method": "tools/list", "params": {}}),
        )
        .await?,
    )
    .await?;

    let _ = read_first_event_stream_json_message(
        post_mcp(
            &client,
            &format!("{data_base_b}/{profile_id}/mcp"),
            Some(&session_id),
            None,
            json!({"jsonrpc": "2.0", "id": 5, "method": "resources/list", "params": {}}),
        )
        .await?,
    )
    .await?;

    let _ = read_first_event_stream_json_message(
        post_mcp(
            &client,
            &format!("{data_base_b}/{profile_id}/mcp"),
            Some(&session_id),
            None,
            json!({"jsonrpc": "2.0", "id": 6, "method": "prompts/list", "params": {}}),
        )
        .await?,
    )
    .await?;

    // We expect all 3 surfaces to propagate via LISTEN/NOTIFY.
    let want: std::collections::HashSet<&str> = [
        "notifications/tools/list_changed",
        "notifications/resources/list_changed",
        "notifications/prompts/list_changed",
    ]
    .into_iter()
    .collect();

    // Parse SSE events until we see all expected notifications (or time out).
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);

    let mut byte_stream = stream_resp.bytes_stream();
    let byte_stream = futures::stream::poll_fn(move |cx| byte_stream.poll_next_unpin(cx))
        .map(|r| r.map_err(std::io::Error::other));
    let reader = tokio_util::io::StreamReader::new(byte_stream);
    let mut lines = tokio::io::BufReader::new(reader).lines();

    let mut found: std::collections::HashSet<String> = std::collections::HashSet::new();
    while found.len() < want.len() {
        let line_opt = tokio::time::timeout_at(deadline, lines.next_line())
            .await
            .context("timeout waiting for SSE line")??;
        let Some(line) = line_opt else {
            anyhow::bail!("SSE stream ended before receiving all notifications");
        };
        let line = line.trim_end();
        let Some(v) = line.strip_prefix("data:") else {
            continue;
        };

        // Collect all data lines for this SSE event.
        let mut data_lines = vec![v.trim().to_string()];
        loop {
            let next = tokio::time::timeout_at(deadline, lines.next_line())
                .await
                .context("timeout waiting for SSE line")??;
            let Some(next) = next else {
                anyhow::bail!("SSE stream ended before receiving all notifications");
            };
            let next = next.trim_end();
            if next.is_empty() {
                break;
            }
            if let Some(v) = next.strip_prefix("data:") {
                data_lines.push(v.trim().to_string());
            }
        }

        let data = data_lines.join("\n");
        let msg: serde_json::Value = match serde_json::from_str(&data) {
            Ok(v) => v,
            Err(_) => continue, // ignore non-JSON events
        };
        if let Some(method) = msg.get("method").and_then(serde_json::Value::as_str)
            && want.contains(method)
        {
            found.insert(method.to_string());
        }
    }
    anyhow::ensure!(
        found.len() == want.len(),
        "expected all notifications, found: {found:?}"
    );

    upstream_task.abort();
    Ok(())
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
#[allow(clippy::too_many_lines)]
async fn pg_replay_replays_missed_contract_notifications() -> anyhow::Result<()> {
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

    // Upstream (dynamic)
    let upstream_port = pick_unused_port()?;
    let upstream = DynamicUpstream::new("u1");
    let upstream_handle = upstream.clone();
    let upstream_router = upstream.router();
    let upstream_listener = tokio::net::TcpListener::bind(("127.0.0.1", upstream_port)).await?;
    let upstream_task = tokio::spawn(async move {
        let _ = axum::serve(upstream_listener, upstream_router).await;
    });
    wait_http_ok(
        &format!("http://127.0.0.1:{upstream_port}/health"),
        Duration::from_secs(10),
    )
    .await?;

    // Gateway (Mode 3).
    let gw = spawn_gateway(&database_url, Some(ADMIN_TOKEN), SESSION_SECRET)?;
    let data_base = gw.data_base.clone();
    let admin_base = gw.admin_base.clone();
    let _gw = KillOnDrop(gw.child);
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
            "endpoints": [{ "id": "e1", "url": format!("http://127.0.0.1:{upstream_port}/mcp") }]
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
            "upstreams": ["u1"],
            "tools": []
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

    // Initialize a session.
    let init_resp = post_mcp(
        &client,
        &format!("{data_base}/{profile_id}/mcp"),
        None,
        Some(&api_key),
        json!({
            "jsonrpc": "2.0",
            "id": 0,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": { "name": "replay-test", "version": "0" }
            }
        }),
    )
    .await?;
    let session_id = init_resp
        .headers()
        .get("Mcp-Session-Id")
        .and_then(|h| h.to_str().ok())
        .context("missing Mcp-Session-Id header")?
        .to_string();
    let _init_msg = read_first_event_stream_json_message(init_resp).await?;

    // Baseline: record the initial contract (no notify on first observation).
    let _ = read_first_event_stream_json_message(
        post_mcp(
            &client,
            &format!("{data_base}/{profile_id}/mcp"),
            Some(&session_id),
            None,
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}),
        )
        .await?,
    )
    .await?;

    // Open a GET stream and observe one notification.
    let stream_resp = client
        .get(format!("{data_base}/{profile_id}/mcp"))
        .header("Accept", "text/event-stream")
        .header("Mcp-Session-Id", &session_id)
        .send()
        .await?
        .error_for_status()
        .context("GET stream status")?;

    // Trigger first contract change (v=1 => adds tool_v2).
    upstream_handle.set_version(1);
    let _ = read_first_event_stream_json_message(
        post_mcp(
            &client,
            &format!("{data_base}/{profile_id}/mcp"),
            Some(&session_id),
            None,
            json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
        )
        .await?,
    )
    .await?;

    let (last_id, _msg) = wait_for_notification_method_with_sse_id(
        stream_resp,
        "notifications/tools/list_changed",
        Duration::from_secs(10),
    )
    .await?;

    // Disconnect, then trigger another contract change while disconnected (v=0 => removes tool_v2).
    upstream_handle.set_version(0);
    let _ = read_first_event_stream_json_message(
        post_mcp(
            &client,
            &format!("{data_base}/{profile_id}/mcp"),
            Some(&session_id),
            None,
            json!({"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {}}),
        )
        .await?,
    )
    .await?;

    // Reconnect with Last-Event-ID set to the last seen contract event id and expect replay.
    let replay_resp = client
        .get(format!("{data_base}/{profile_id}/mcp"))
        .header("Accept", "text/event-stream")
        .header("Mcp-Session-Id", &session_id)
        .header("Last-Event-ID", &last_id)
        .send()
        .await?
        .error_for_status()
        .context("GET stream status (replay)")?;

    let (_replayed_id, _msg) = wait_for_notification_method_with_sse_id(
        replay_resp,
        "notifications/tools/list_changed",
        Duration::from_secs(10),
    )
    .await?;

    upstream_task.abort();
    Ok(())
}
