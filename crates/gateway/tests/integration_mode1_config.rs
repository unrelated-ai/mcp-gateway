mod common;

use anyhow::Context as _;
use axum::{
    Router,
    extract::State,
    response::IntoResponse,
    routing::{get, post},
};
use common::mcp::McpSession;
use common::sse::read_first_event_stream_json_message;
use common::{KillOnDrop, pick_unused_port, spawn_gateway_mode1, wait_http_ok};
use rmcp::model::{
    CallToolResult, ClientJsonRpcMessage, ClientRequest, Content, InitializeResult, JsonObject,
    JsonRpcRequest, JsonRpcResponse, JsonRpcVersion2_0, ListToolsResult, ServerCapabilities,
    ServerJsonRpcMessage, ServerResult, Tool,
};
use serde_json::json;
use std::collections::HashSet;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;
use tokio::sync::Mutex;

const ADMIN_TOKEN: &str = "test-admin-token";
const SESSION_SECRET: &str = "test-session-secret";

async fn post_mcp(
    client: &reqwest::Client,
    url: &str,
    session_id: Option<&str>,
    authz_bearer: Option<&str>,
    x_api_key: Option<&str>,
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
    if let Some(secret) = authz_bearer {
        req = req.header("Authorization", format!("Bearer {secret}"));
    }
    if let Some(secret) = x_api_key {
        req = req.header("x-api-key", secret);
    }

    req.send().await.context("POST mcp")
}

fn write_mode1_config(
    dir: &tempfile::TempDir,
    profile_id: &str,
    backend_base: &str,
    require_every_request: bool,
    accept_x_api_key: bool,
    tools: Option<&str>,
) -> anyhow::Result<std::path::PathBuf> {
    let cfg_path = dir.path().join("gateway.yaml");

    let tools_yaml = tools.unwrap_or("");
    let config = format!(
        r#"
dataPlaneAuth:
  mode: static-api-keys
  apiKeys:
    - "k1"
  acceptXApiKey: {accept_x_api_key}
  requireEveryRequest: {require_every_request}

tenants:
  t1:
    enabled: true

sharedSources:
  s1:
    type: http
    enabled: true
    public: true
    baseUrl: "{backend_base}"
    tools:
      ping:
        method: GET
        path: /ping

profiles:
  {profile_id}:
    tenantId: t1
    allowPartialUpstreams: true
    upstreams: ["s1"]
{tools_yaml}
"#
    );

    std::fs::write(&cfg_path, config).context("write mode1 config")?;
    Ok(cfg_path)
}

async fn start_http_backend() -> anyhow::Result<(String, tokio::task::JoinHandle<()>)> {
    let app = Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/ping", get(|| async { axum::Json(json!({"ok": true})) }));

    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
    let addr = listener.local_addr()?;
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    let base = format!("http://{addr}");
    wait_http_ok(&format!("{base}/health"), Duration::from_secs(10)).await?;
    Ok((base, handle))
}

fn write_mode1_config_upstream_only(
    dir: &tempfile::TempDir,
    profile_id: &str,
    upstream_url: &str,
    require_every_request: bool,
    accept_x_api_key: bool,
) -> anyhow::Result<std::path::PathBuf> {
    let cfg_path = dir.path().join("gateway.yaml");
    let config = format!(
        r#"
dataPlaneAuth:
  mode: static-api-keys
  apiKeys:
    - "k1"
  acceptXApiKey: {accept_x_api_key}
  requireEveryRequest: {require_every_request}

tenants:
  t1:
    enabled: true

upstreams:
  u1:
    endpoints:
      - id: e1
        url: "{upstream_url}"

profiles:
  {profile_id}:
    tenantId: t1
    allowPartialUpstreams: true
    upstreams: ["u1"]
"#
    );
    std::fs::write(&cfg_path, config).context("write mode1 config (upstream)")?;
    Ok(cfg_path)
}

#[derive(Clone)]
struct MockUpstream {
    sessions: Arc<Mutex<HashSet<String>>>,
}

impl MockUpstream {
    fn new() -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    fn router(self) -> Router {
        Router::new()
            .route("/health", get(|| async { "ok" }))
            .route("/mcp", post(Self::post_mcp))
            .with_state(self)
    }

    fn reject_if_auth_headers_present(
        headers: &axum::http::HeaderMap,
    ) -> Option<axum::response::Response> {
        if headers.get("authorization").is_some() || headers.get("x-api-key").is_some() {
            return Some(
                (
                    axum::http::StatusCode::BAD_REQUEST,
                    "unexpected auth header forwarded to upstream",
                )
                    .into_response(),
            );
        }
        None
    }

    async fn post_mcp(
        State(this): State<MockUpstream>,
        headers: axum::http::HeaderMap,
        body: axum::body::Bytes,
    ) -> axum::response::Response {
        if let Some(resp) = Self::reject_if_auth_headers_present(&headers) {
            return resp;
        }

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
                name: "mock-upstream".to_string(),
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

        let ClientJsonRpcMessage::Request(JsonRpcRequest { id, request, .. }) = message else {
            return (axum::http::StatusCode::ACCEPTED, "").into_response();
        };

        match request {
            ClientRequest::ListToolsRequest(_) => {
                let tool = Tool::new(
                    "echo_request",
                    "Echo request (mock upstream)",
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
                let result = CallToolResult {
                    content: vec![Content::text(format!("ok:{name}"))],
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

fn write_mode1_config_with_tenant_enabled(
    dir: &tempfile::TempDir,
    profile_id: &str,
    tenant_enabled: bool,
    require_every_request: bool,
    accept_x_api_key: bool,
) -> anyhow::Result<std::path::PathBuf> {
    let cfg_path = dir.path().join("gateway.yaml");
    let config = format!(
        r#"
dataPlaneAuth:
  mode: static-api-keys
  apiKeys:
    - "k1"
  acceptXApiKey: {accept_x_api_key}
  requireEveryRequest: {require_every_request}

tenants:
  t1:
    enabled: {tenant_enabled}

profiles:
  {profile_id}:
    tenantId: t1
    allowPartialUpstreams: true
    upstreams: []
"#
    );
    std::fs::write(&cfg_path, config).context("write mode1 config (tenant enabled)")?;
    Ok(cfg_path)
}

fn write_mode1_config_two_upstreams(
    dir: &tempfile::TempDir,
    profile_id: &str,
    allow_partial_upstreams: bool,
    upstream_ok_url: &str,
    upstream_down_url: &str,
) -> anyhow::Result<std::path::PathBuf> {
    let cfg_path = dir.path().join("gateway.yaml");
    let config = format!(
        r#"
dataPlaneAuth:
  mode: static-api-keys
  apiKeys:
    - "k1"
  acceptXApiKey: true
  requireEveryRequest: false

tenants:
  t1:
    enabled: true

upstreams:
  u_ok:
    endpoints:
      - id: e1
        url: "{upstream_ok_url}"
  u_down:
    endpoints:
      - id: e1
        url: "{upstream_down_url}"

profiles:
  {profile_id}:
    tenantId: t1
    allowPartialUpstreams: {allow_partial_upstreams}
    upstreams: ["u_ok", "u_down"]
"#
    );
    std::fs::write(&cfg_path, config).context("write mode1 config (two upstreams)")?;
    Ok(cfg_path)
}

fn write_mode1_config_shared_source_and_down_upstream(
    dir: &tempfile::TempDir,
    profile_id: &str,
    backend_base: &str,
    upstream_down_url: &str,
    allow_partial_upstreams: bool,
) -> anyhow::Result<std::path::PathBuf> {
    let cfg_path = dir.path().join("gateway.yaml");
    let config = format!(
        r#"
dataPlaneAuth:
  mode: static-api-keys
  apiKeys:
    - "k1"
  acceptXApiKey: true
  requireEveryRequest: false

tenants:
  t1:
    enabled: true

sharedSources:
  s1:
    type: http
    enabled: true
    public: true
    baseUrl: "{backend_base}"
    tools:
      ping:
        method: GET
        path: /ping

upstreams:
  u_down:
    endpoints:
      - id: e1
        url: "{upstream_down_url}"

profiles:
  {profile_id}:
    tenantId: t1
    allowPartialUpstreams: {allow_partial_upstreams}
    upstreams: ["s1", "u_down"]
"#
    );
    std::fs::write(&cfg_path, config).context("write mode1 config (shared + down upstream)")?;
    Ok(cfg_path)
}

fn write_mode1_config_shared_source_and_upstream(
    dir: &tempfile::TempDir,
    profile_id: &str,
    backend_base: &str,
    upstream_ok_url: &str,
) -> anyhow::Result<std::path::PathBuf> {
    let cfg_path = dir.path().join("gateway.yaml");
    let config = format!(
        r#"
dataPlaneAuth:
  mode: static-api-keys
  apiKeys:
    - "k1"
  acceptXApiKey: true
  requireEveryRequest: false

tenants:
  t1:
    enabled: true

sharedSources:
  s1:
    type: http
    enabled: true
    public: true
    baseUrl: "{backend_base}"
    tools:
      ping:
        method: GET
        path: /ping

upstreams:
  u1:
    endpoints:
      - id: e1
        url: "{upstream_ok_url}"

profiles:
  {profile_id}:
    tenantId: t1
    allowPartialUpstreams: true
    upstreams: ["s1", "u1"]
"#
    );
    std::fs::write(&cfg_path, config).context("write mode1 config (shared + upstream)")?;
    Ok(cfg_path)
}

#[derive(Clone)]
struct MockUpstreamSingleTool {
    tool_name: &'static str,
    sessions: Arc<Mutex<HashSet<String>>>,
}

impl MockUpstreamSingleTool {
    fn new(tool_name: &'static str) -> Self {
        Self {
            tool_name,
            sessions: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    fn router(self) -> Router {
        Router::new()
            .route("/health", get(|| async { "ok" }))
            .route("/mcp", post(Self::post_mcp))
            .with_state(self)
    }

    async fn post_mcp(
        State(this): State<MockUpstreamSingleTool>,
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
            None => {
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
                let session_id = uuid::Uuid::new_v4().to_string();
                this.sessions.lock().await.insert(session_id.clone());
                let init_result = InitializeResult {
                    protocol_version: init.params.protocol_version,
                    capabilities: ServerCapabilities::builder().enable_tools().build(),
                    server_info: rmcp::model::Implementation {
                        name: "mock-upstream".to_string(),
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
            Some(session_id) => {
                if !this.sessions.lock().await.contains(&session_id) {
                    return (axum::http::StatusCode::UNAUTHORIZED, "session not found")
                        .into_response();
                }
                let ClientJsonRpcMessage::Request(JsonRpcRequest { id, request, .. }) = message
                else {
                    return (axum::http::StatusCode::ACCEPTED, "").into_response();
                };
                match request {
                    ClientRequest::ListToolsRequest(_) => {
                        let tool =
                            Tool::new(this.tool_name, "mock tool", Arc::new(JsonObject::new()));
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
                    _ => (axum::http::StatusCode::ACCEPTED, "").into_response(),
                }
            }
        }
    }
}

#[tokio::test]
async fn mode1_static_api_keys_initialize_only_allows_followups_without_key() -> anyhow::Result<()>
{
    let profile_id = uuid::Uuid::new_v4().to_string();
    let dir = tempdir().context("create temp dir")?;
    let (backend_base, backend_task) = start_http_backend().await?;

    let cfg_path = write_mode1_config(
        &dir,
        &profile_id,
        &backend_base,
        false, // requireEveryRequest
        true,  // acceptXApiKey
        None,
    )?;

    let gw = spawn_gateway_mode1(&cfg_path, Some(ADMIN_TOKEN), SESSION_SECRET)?;
    let data_base = gw.data_base.clone();
    let admin_base = gw.admin_base.clone();
    let _child = KillOnDrop(gw.child);

    wait_http_ok(&format!("{data_base}/health"), Duration::from_secs(20)).await?;
    wait_http_ok(&format!("{admin_base}/health"), Duration::from_secs(20)).await?;

    let client = reqwest::Client::new();

    // Missing key -> 401 on initialize.
    let resp = post_mcp(
        &client,
        &format!("{data_base}/{profile_id}/mcp"),
        None,
        None,
        None,
        json!({
            "jsonrpc": "2.0",
            "id": 0,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": { "name": "mode1-test", "version": "0" }
            }
        }),
    )
    .await?;
    anyhow::ensure!(resp.status() == reqwest::StatusCode::UNAUTHORIZED);

    // Provide key -> initialize success.
    let session = McpSession::connect(
        format!("{data_base}/{profile_id}/mcp"),
        Some("k1".to_string()),
    )
    .await?;

    // Follow-up tools/list should succeed with session only (no auth header).
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
        .filter_map(|t| t.get("name").and_then(serde_json::Value::as_str))
        .map(str::to_string)
        .collect();
    anyhow::ensure!(names.contains(&"ping".to_string()), "expected ping tool");

    backend_task.abort();
    Ok(())
}

#[tokio::test]
async fn mode1_static_api_keys_every_request_requires_key_each_time_and_x_api_key_alias_works()
-> anyhow::Result<()> {
    let profile_id = uuid::Uuid::new_v4().to_string();
    let dir = tempdir().context("create temp dir")?;
    let (backend_base, backend_task) = start_http_backend().await?;

    let cfg_path = write_mode1_config(
        &dir,
        &profile_id,
        &backend_base,
        true, // requireEveryRequest
        true, // acceptXApiKey
        None,
    )?;

    let gw = spawn_gateway_mode1(&cfg_path, Some(ADMIN_TOKEN), SESSION_SECRET)?;
    let data_base = gw.data_base.clone();
    let _child = KillOnDrop(gw.child);

    wait_http_ok(&format!("{data_base}/health"), Duration::from_secs(20)).await?;

    let client = reqwest::Client::new();

    // Initialize with API key (bearer).
    let session = McpSession::connect(
        format!("{data_base}/{profile_id}/mcp"),
        Some("k1".to_string()),
    )
    .await?;
    let session_id = session.session_id().to_string();

    // tools/list without key should be rejected.
    let resp = post_mcp(
        &client,
        &format!("{data_base}/{profile_id}/mcp"),
        Some(&session_id),
        None,
        None,
        json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}),
    )
    .await?;
    anyhow::ensure!(resp.status() == reqwest::StatusCode::UNAUTHORIZED);

    // tools/list with x-api-key alias should succeed.
    let tools_resp = post_mcp(
        &client,
        &format!("{data_base}/{profile_id}/mcp"),
        Some(&session_id),
        None,
        Some("k1"),
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
    )
    .await?
    .error_for_status()
    .context("tools/list status")?;
    let tools_msg = read_first_event_stream_json_message(tools_resp).await?;
    let tools = tools_msg
        .get("result")
        .and_then(|r| r.get("tools"))
        .and_then(serde_json::Value::as_array)
        .context("tools/list missing result.tools")?;
    anyhow::ensure!(
        tools.iter().any(|t| t.get("name") == Some(&json!("ping"))),
        "expected ping tool"
    );

    backend_task.abort();
    Ok(())
}

#[tokio::test]
async fn mode1_tool_allowlist_allows_all_when_omitted() -> anyhow::Result<()> {
    let profile_id = uuid::Uuid::new_v4().to_string();
    let dir = tempdir().context("create temp dir")?;
    let (backend_base, backend_task) = start_http_backend().await?;

    // Omit `tools:` entirely => no allowlist configured (allow all tools).
    let cfg_path = write_mode1_config(
        &dir,
        &profile_id,
        &backend_base,
        false, // requireEveryRequest
        true,  // acceptXApiKey
        None,
    )?;

    let gw = spawn_gateway_mode1(&cfg_path, Some(ADMIN_TOKEN), SESSION_SECRET)?;
    let data_base = gw.data_base.clone();
    let _child = KillOnDrop(gw.child);

    wait_http_ok(&format!("{data_base}/health"), Duration::from_secs(20)).await?;

    let session = McpSession::connect(
        format!("{data_base}/{profile_id}/mcp"),
        Some("k1".to_string()),
    )
    .await?;

    // tools/list should include the shared `ping` tool.
    let tools_msg = session.request_value(1, "tools/list", json!({})).await?;
    let tools = tools_msg
        .get("result")
        .and_then(|r| r.get("tools"))
        .and_then(serde_json::Value::as_array)
        .context("tools/list missing result.tools")?;
    anyhow::ensure!(
        tools.iter().any(|t| t.get("name") == Some(&json!("ping"))),
        "expected ping tool"
    );

    backend_task.abort();
    Ok(())
}

#[tokio::test]
async fn mode1_tool_allowlist_can_allow_single_tool_by_stable_ref() -> anyhow::Result<()> {
    let profile_id = uuid::Uuid::new_v4().to_string();
    let dir = tempdir().context("create temp dir")?;
    let (backend_base, backend_task) = start_http_backend().await?;

    // Allow only `s1:ping` (stable ref) but expect tool name to be `ping` in tools/list.
    let cfg_path = write_mode1_config(
        &dir,
        &profile_id,
        &backend_base,
        false, // requireEveryRequest
        true,  // acceptXApiKey
        Some("    tools: [\"s1:ping\"]"),
    )?;

    let gw = spawn_gateway_mode1(&cfg_path, Some(ADMIN_TOKEN), SESSION_SECRET)?;
    let data_base = gw.data_base.clone();
    let _child = KillOnDrop(gw.child);

    wait_http_ok(&format!("{data_base}/health"), Duration::from_secs(20)).await?;

    let session = McpSession::connect(
        format!("{data_base}/{profile_id}/mcp"),
        Some("k1".to_string()),
    )
    .await?;
    let tools_msg = session.request_value(1, "tools/list", json!({})).await?;
    let tools = tools_msg
        .get("result")
        .and_then(|r| r.get("tools"))
        .and_then(serde_json::Value::as_array)
        .context("tools/list missing result.tools")?;

    let names: Vec<String> = tools
        .iter()
        .filter_map(|t| t.get("name").and_then(serde_json::Value::as_str))
        .map(str::to_string)
        .collect();
    assert_eq!(names, vec!["ping".to_string()]);

    backend_task.abort();
    Ok(())
}

#[tokio::test]
async fn mode1_accept_x_api_key_false_rejects_x_api_key_header() -> anyhow::Result<()> {
    let profile_id = uuid::Uuid::new_v4().to_string();
    let dir = tempdir().context("create temp dir")?;
    let (backend_base, backend_task) = start_http_backend().await?;

    let cfg_path = write_mode1_config(
        &dir,
        &profile_id,
        &backend_base,
        false, // requireEveryRequest
        false, // acceptXApiKey
        None,
    )?;

    let gw = spawn_gateway_mode1(&cfg_path, Some(ADMIN_TOKEN), SESSION_SECRET)?;
    let data_base = gw.data_base.clone();
    let _child = KillOnDrop(gw.child);

    wait_http_ok(&format!("{data_base}/health"), Duration::from_secs(20)).await?;

    let client = reqwest::Client::new();

    // x-api-key should not be accepted for initialize when acceptXApiKey=false
    let resp = post_mcp(
        &client,
        &format!("{data_base}/{profile_id}/mcp"),
        None,
        None,
        Some("k1"),
        json!({
            "jsonrpc": "2.0",
            "id": 0,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": { "name": "mode1-test", "version": "0" }
            }
        }),
    )
    .await?;
    anyhow::ensure!(resp.status() == reqwest::StatusCode::UNAUTHORIZED);

    // Bearer should still work.
    let _session = McpSession::connect(
        format!("{data_base}/{profile_id}/mcp"),
        Some("k1".to_string()),
    )
    .await?;

    backend_task.abort();
    Ok(())
}

#[tokio::test]
async fn mode1_gateway_does_not_forward_caller_auth_to_upstream_mcp() -> anyhow::Result<()> {
    let profile_id = uuid::Uuid::new_v4().to_string();
    let dir = tempdir().context("create temp dir")?;

    // Start a local upstream MCP server that hard-fails if it sees auth headers.
    let upstream = MockUpstream::new().router();
    let upstream_listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
    let upstream_port = upstream_listener.local_addr()?.port();
    let upstream_task = tokio::spawn(async move {
        let _ = axum::serve(upstream_listener, upstream).await;
    });
    wait_http_ok(
        &format!("http://127.0.0.1:{upstream_port}/health"),
        Duration::from_secs(10),
    )
    .await?;

    let cfg_path = write_mode1_config_upstream_only(
        &dir,
        &profile_id,
        &format!("http://127.0.0.1:{upstream_port}/mcp"),
        true, // requireEveryRequest
        true, // acceptXApiKey
    )?;

    let gw = spawn_gateway_mode1(&cfg_path, Some(ADMIN_TOKEN), SESSION_SECRET)?;
    let data_base = gw.data_base.clone();
    let _child = KillOnDrop(gw.child);

    wait_http_ok(&format!("{data_base}/health"), Duration::from_secs(20)).await?;

    // Initialize with gateway auth header.
    let session = McpSession::connect(
        format!("{data_base}/{profile_id}/mcp"),
        Some("k1".to_string()),
    )
    .await?;

    // tools/list with Authorization required by gateway; upstream must not see it.
    let _ = session.request_value(1, "tools/list", json!({})).await?;

    // tools/call also must not forward auth.
    let _ = session
        .request_value(
            2,
            "tools/call",
            json!({ "name": "echo_request", "arguments": {} }),
        )
        .await?;

    upstream_task.abort();
    Ok(())
}

#[tokio::test]
async fn mode1_disabled_tenant_hides_profiles_as_404() -> anyhow::Result<()> {
    let profile_id = uuid::Uuid::new_v4().to_string();
    let dir = tempdir().context("create temp dir")?;

    let cfg_path = write_mode1_config_with_tenant_enabled(
        &dir,
        &profile_id,
        false, // tenant enabled
        false, // requireEveryRequest
        true,  // acceptXApiKey
    )?;

    let gw = spawn_gateway_mode1(&cfg_path, Some(ADMIN_TOKEN), SESSION_SECRET)?;
    let data_base = gw.data_base.clone();
    let _child = KillOnDrop(gw.child);

    wait_http_ok(&format!("{data_base}/health"), Duration::from_secs(20)).await?;

    let client = reqwest::Client::new();
    let resp = post_mcp(
        &client,
        &format!("{data_base}/{profile_id}/mcp"),
        None,
        Some("k1"),
        None,
        json!({
            "jsonrpc": "2.0",
            "id": 0,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": { "name": "mode1-test", "version": "0" }
            }
        }),
    )
    .await?;
    anyhow::ensure!(resp.status() == reqwest::StatusCode::NOT_FOUND);

    Ok(())
}

#[tokio::test]
async fn mode1_allow_partial_upstreams_allows_initialize_when_one_upstream_is_down()
-> anyhow::Result<()> {
    let profile_id = uuid::Uuid::new_v4().to_string();
    let dir = tempdir().context("create temp dir")?;

    // One healthy upstream.
    let upstream = MockUpstream::new().router();
    let upstream_listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
    let upstream_port = upstream_listener.local_addr()?.port();
    let upstream_task = tokio::spawn(async move {
        let _ = axum::serve(upstream_listener, upstream).await;
    });
    wait_http_ok(
        &format!("http://127.0.0.1:{upstream_port}/health"),
        Duration::from_secs(10),
    )
    .await?;

    // One dead upstream (connection refused).
    let dead_port = pick_unused_port()?;
    let cfg_path = write_mode1_config_two_upstreams(
        &dir,
        &profile_id,
        true, // allowPartialUpstreams
        &format!("http://127.0.0.1:{upstream_port}/mcp"),
        &format!("http://127.0.0.1:{dead_port}/mcp"),
    )?;

    let gw = spawn_gateway_mode1(&cfg_path, Some(ADMIN_TOKEN), SESSION_SECRET)?;
    let data_base = gw.data_base.clone();
    let _child = KillOnDrop(gw.child);

    wait_http_ok(&format!("{data_base}/health"), Duration::from_secs(20)).await?;

    // Initialize should succeed (partial upstreams allowed).
    let session = McpSession::connect(
        format!("{data_base}/{profile_id}/mcp"),
        Some("k1".to_string()),
    )
    .await?;

    // tools/list should still work and return at least the healthy upstream tool.
    let tools_msg = session.request_value(1, "tools/list", json!({})).await?;
    let tools = tools_msg
        .get("result")
        .and_then(|r| r.get("tools"))
        .and_then(serde_json::Value::as_array)
        .context("tools/list missing result.tools")?;
    anyhow::ensure!(
        tools
            .iter()
            .any(|t| t.get("name") == Some(&json!("echo_request"))),
        "expected echo_request from healthy upstream"
    );

    upstream_task.abort();
    Ok(())
}

#[tokio::test]
async fn mode1_disallow_partial_upstreams_fails_initialize_when_one_upstream_is_down()
-> anyhow::Result<()> {
    let profile_id = uuid::Uuid::new_v4().to_string();
    let dir = tempdir().context("create temp dir")?;

    // One healthy upstream.
    let upstream = MockUpstream::new().router();
    let upstream_listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
    let upstream_port = upstream_listener.local_addr()?.port();
    let upstream_task = tokio::spawn(async move {
        let _ = axum::serve(upstream_listener, upstream).await;
    });
    wait_http_ok(
        &format!("http://127.0.0.1:{upstream_port}/health"),
        Duration::from_secs(10),
    )
    .await?;

    // One dead upstream.
    let dead_port = pick_unused_port()?;
    let cfg_path = write_mode1_config_two_upstreams(
        &dir,
        &profile_id,
        false, // allowPartialUpstreams
        &format!("http://127.0.0.1:{upstream_port}/mcp"),
        &format!("http://127.0.0.1:{dead_port}/mcp"),
    )?;

    let gw = spawn_gateway_mode1(&cfg_path, Some(ADMIN_TOKEN), SESSION_SECRET)?;
    let data_base = gw.data_base.clone();
    let _child = KillOnDrop(gw.child);

    wait_http_ok(&format!("{data_base}/health"), Duration::from_secs(20)).await?;

    // Initialize should fail because partial upstreams are NOT allowed.
    let client = reqwest::Client::new();
    let resp = post_mcp(
        &client,
        &format!("{data_base}/{profile_id}/mcp"),
        None,
        Some("k1"),
        None,
        json!({
            "jsonrpc": "2.0",
            "id": 0,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": { "name": "mode1-test", "version": "0" }
            }
        }),
    )
    .await?;
    anyhow::ensure!(resp.status() == reqwest::StatusCode::BAD_GATEWAY);

    upstream_task.abort();
    Ok(())
}

#[tokio::test]
async fn mode1_allow_partial_upstreams_still_lists_shared_tools_when_upstream_is_down()
-> anyhow::Result<()> {
    let profile_id = uuid::Uuid::new_v4().to_string();
    let dir = tempdir().context("create temp dir")?;

    let (backend_base, backend_task) = start_http_backend().await?;
    let dead_port = pick_unused_port()?;

    let cfg_path = write_mode1_config_shared_source_and_down_upstream(
        &dir,
        &profile_id,
        &backend_base,
        &format!("http://127.0.0.1:{dead_port}/mcp"),
        true, // allowPartialUpstreams
    )?;

    let gw = spawn_gateway_mode1(&cfg_path, Some(ADMIN_TOKEN), SESSION_SECRET)?;
    let data_base = gw.data_base.clone();
    let admin_base = gw.admin_base.clone();
    let _child = KillOnDrop(gw.child);

    wait_http_ok(&format!("{data_base}/health"), Duration::from_secs(20)).await?;
    wait_http_ok(&format!("{admin_base}/health"), Duration::from_secs(20)).await?;

    let session = McpSession::connect(
        format!("{data_base}/{profile_id}/mcp"),
        Some("k1".to_string()),
    )
    .await?;

    // Even with the upstream down, shared tools should still be listed.
    let tools_msg = session.request_value(1, "tools/list", json!({})).await?;

    let tools = tools_msg
        .get("result")
        .and_then(|r| r.get("tools"))
        .and_then(serde_json::Value::as_array)
        .context("tools/list missing result.tools")?;
    anyhow::ensure!(
        tools.iter().any(|t| t.get("name") == Some(&json!("ping"))),
        "expected shared tool ping to be present"
    );

    backend_task.abort();
    Ok(())
}

#[tokio::test]
async fn mode1_collision_between_shared_and_upstream_tools_is_namespaced() -> anyhow::Result<()> {
    let profile_id = uuid::Uuid::new_v4().to_string();
    let dir = tempdir().context("create temp dir")?;
    let (backend_base, backend_task) = start_http_backend().await?;

    // Upstream exposes a tool called "ping" (collides with shared source ping).
    let upstream = MockUpstreamSingleTool::new("ping").router();
    let upstream_listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
    let upstream_addr = upstream_listener.local_addr()?;
    let upstream_task = tokio::spawn(async move {
        let _ = axum::serve(upstream_listener, upstream).await;
    });
    wait_http_ok(
        &format!("http://{upstream_addr}/health"),
        Duration::from_secs(10),
    )
    .await?;

    let cfg_path = write_mode1_config_shared_source_and_upstream(
        &dir,
        &profile_id,
        &backend_base,
        &format!("http://{upstream_addr}/mcp"),
    )?;

    let gw = spawn_gateway_mode1(&cfg_path, Some(ADMIN_TOKEN), SESSION_SECRET)?;
    let data_base = gw.data_base.clone();
    let _child = KillOnDrop(gw.child);

    wait_http_ok(&format!("{data_base}/health"), Duration::from_secs(20)).await?;

    let session = McpSession::connect(
        format!("{data_base}/{profile_id}/mcp"),
        Some("k1".to_string()),
    )
    .await?;

    let tools_msg = session.request_value(1, "tools/list", json!({})).await?;

    let tools = tools_msg
        .get("result")
        .and_then(|r| r.get("tools"))
        .and_then(serde_json::Value::as_array)
        .context("tools/list missing result.tools")?;
    let names: Vec<&str> = tools
        .iter()
        .filter_map(|t| t.get("name").and_then(serde_json::Value::as_str))
        .collect();

    anyhow::ensure!(
        names.contains(&"s1:ping"),
        "expected s1:ping after collision"
    );
    anyhow::ensure!(
        names.contains(&"u1:ping"),
        "expected u1:ping after collision"
    );
    anyhow::ensure!(
        !names.contains(&"ping"),
        "expected unprefixed ping to be removed"
    );

    upstream_task.abort();
    backend_task.abort();
    Ok(())
}
