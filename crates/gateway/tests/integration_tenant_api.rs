mod common;

use anyhow::Context as _;
use axum::{
    Router,
    response::IntoResponse,
    routing::{get, post},
};
use common::mcp::McpSession;
use common::pg::{apply_dbmate_migrations, wait_pg_ready};
use common::{KillOnDrop, pick_unused_port, spawn_gateway, spawn_gateway_with_env, wait_http_ok};
use rmcp::model::{
    ClientJsonRpcMessage, ClientRequest, ErrorData, InitializeResult, JsonObject, JsonRpcError,
    JsonRpcRequest, JsonRpcResponse, JsonRpcVersion2_0, ListToolsResult, ServerCapabilities,
    ServerJsonRpcMessage, ServerResult, Tool,
};
use serde_json::json;
use std::time::Duration;
use std::{collections::HashSet, sync::Arc};
use testcontainers::core::IntoContainerPort;
use testcontainers::runners::AsyncRunner;
use testcontainers::{GenericImage, ImageExt as _};
use tokio::sync::Mutex;

const ADMIN_TOKEN: &str = "test-admin-token";
const SESSION_SECRET: &str = "test-session-secret";

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

        let mut resp = axum::response::Response::new(axum::body::Body::from(
            serde_json::to_vec(&msg).unwrap_or_default(),
        ));
        *resp.status_mut() = axum::http::StatusCode::OK;
        resp.headers_mut().insert(
            "Content-Type",
            axum::http::HeaderValue::from_static("application/json"),
        );
        resp.headers_mut().insert(
            "Mcp-Session-Id",
            axum::http::HeaderValue::from_str(&session_id).unwrap(),
        );
        resp
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
            ClientJsonRpcMessage::Notification(n) => {
                if matches!(
                    n.notification,
                    rmcp::model::ClientNotification::InitializedNotification(_)
                ) {
                    return (axum::http::StatusCode::ACCEPTED, "").into_response();
                }
                (
                    axum::http::StatusCode::UNPROCESSABLE_ENTITY,
                    "unexpected notification",
                )
                    .into_response()
            }
            ClientJsonRpcMessage::Request(JsonRpcRequest { id, request, .. }) => {
                if let ClientRequest::ListToolsRequest(_) = request {
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
                    let body = serde_json::to_string(&msg).unwrap_or_default();
                    let mut resp = axum::response::Response::new(axum::body::Body::from(body));
                    *resp.status_mut() = axum::http::StatusCode::OK;
                    resp.headers_mut().insert(
                        "Content-Type",
                        axum::http::HeaderValue::from_static("application/json"),
                    );
                    resp
                } else {
                    let msg = ServerJsonRpcMessage::Error(JsonRpcError {
                        jsonrpc: JsonRpcVersion2_0,
                        id,
                        error: ErrorData::new(
                            rmcp::model::ErrorCode::METHOD_NOT_FOUND,
                            "method not found",
                            None,
                        ),
                    });
                    let body = serde_json::to_string(&msg).unwrap_or_default();
                    let mut resp = axum::response::Response::new(axum::body::Body::from(body));
                    *resp.status_mut() = axum::http::StatusCode::OK;
                    resp.headers_mut().insert(
                        "Content-Type",
                        axum::http::HeaderValue::from_static("application/json"),
                    );
                    resp
                }
            }
            _ => (
                axum::http::StatusCode::UNPROCESSABLE_ENTITY,
                "expected request",
            )
                .into_response(),
        }
    }
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

async fn admin_put(
    client: &reqwest::Client,
    base: &str,
    path: &str,
    body: serde_json::Value,
) -> anyhow::Result<serde_json::Value> {
    let resp = client
        .put(format!("{base}{path}"))
        .header("Authorization", format!("Bearer {ADMIN_TOKEN}"))
        .json(&body)
        .send()
        .await
        .context("admin PUT")?
        .error_for_status()
        .context("admin PUT status")?;
    resp.json().await.context("admin PUT json")
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

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
#[allow(clippy::too_many_lines)]
async fn tenant_profiles_are_scoped_and_cross_tenant_access_is_404() -> anyhow::Result<()> {
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

    // Gateway (Mode 3)
    let gw = spawn_gateway(&database_url, Some(ADMIN_TOKEN), SESSION_SECRET)?;
    let data_base = gw.data_base.clone();
    let admin_base = gw.admin_base.clone();
    let _gateway_child = KillOnDrop(gw.child);
    wait_http_ok(&format!("{data_base}/health"), Duration::from_secs(20)).await?;
    wait_http_ok(&format!("{admin_base}/health"), Duration::from_secs(20)).await?;

    let client = reqwest::Client::new();

    // Two tenants
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
        "/admin/v1/tenants",
        json!({ "id": "t2", "enabled": true }),
    )
    .await?;

    let t1_token = admin_issue_tenant_token(&client, &admin_base, "t1").await?;
    let t2_token = admin_issue_tenant_token(&client, &admin_base, "t2").await?;

    // Tenant creates a profile.
    let create_resp = client
        .post(format!("{admin_base}/tenant/v1/profiles"))
        .header("Authorization", format!("Bearer {t1_token}"))
        .json(&json!({
            "name": "My first profile",
            "enabled": true,
            "allowPartialUpstreams": true,
            "upstreams": [],
            "tools": []
        }))
        .send()
        .await
        .context("tenant POST /profiles")?
        .error_for_status()
        .context("tenant POST /profiles status")?;
    let created: serde_json::Value = create_resp
        .json()
        .await
        .context("tenant POST /profiles json")?;
    let profile_id = created
        .get("id")
        .and_then(serde_json::Value::as_str)
        .context("create profile response missing id")?
        .to_string();

    // Tenant can list its profiles.
    let list_resp = client
        .get(format!("{admin_base}/tenant/v1/profiles"))
        .header("Authorization", format!("Bearer {t1_token}"))
        .send()
        .await
        .context("tenant GET /profiles")?
        .error_for_status()
        .context("tenant GET /profiles status")?;
    let list: serde_json::Value = list_resp
        .json()
        .await
        .context("tenant GET /profiles json")?;
    let profiles = list
        .get("profiles")
        .and_then(serde_json::Value::as_array)
        .context("tenant profiles response missing profiles")?;
    anyhow::ensure!(
        profiles
            .iter()
            .any(|p| p.get("id") == Some(&json!(profile_id))),
        "expected created profile in tenant list"
    );

    // Cross-tenant access is 404 (not 403).
    let resp = client
        .get(format!("{admin_base}/tenant/v1/profiles/{profile_id}"))
        .header("Authorization", format!("Bearer {t2_token}"))
        .send()
        .await
        .context("tenant cross-tenant GET")?;
    anyhow::ensure!(resp.status() == reqwest::StatusCode::NOT_FOUND);

    // Invalid token is 401.
    let resp = client
        .get(format!("{admin_base}/tenant/v1/profiles/{profile_id}"))
        .header("Authorization", "Bearer not-a-token")
        .send()
        .await
        .context("tenant invalid token GET")?;
    anyhow::ensure!(resp.status() == reqwest::StatusCode::UNAUTHORIZED);

    Ok(())
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
#[allow(clippy::too_many_lines)]
async fn profile_name_is_unique_per_tenant_case_insensitive() -> anyhow::Result<()> {
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

    // Gateway (Mode 3)
    let gw = spawn_gateway(&database_url, Some(ADMIN_TOKEN), SESSION_SECRET)?;
    let data_base = gw.data_base.clone();
    let admin_base = gw.admin_base.clone();
    let _gateway_child = KillOnDrop(gw.child);
    wait_http_ok(&format!("{data_base}/health"), Duration::from_secs(20)).await?;
    wait_http_ok(&format!("{admin_base}/health"), Duration::from_secs(20)).await?;

    let client = reqwest::Client::new();

    // Tenant
    let _ = admin_post(
        &client,
        &admin_base,
        "/admin/v1/tenants",
        json!({ "id": "t1", "enabled": true }),
    )
    .await?;
    let t1_token = admin_issue_tenant_token(&client, &admin_base, "t1").await?;

    // Create a profile with name "Hello".
    let resp = client
        .post(format!("{admin_base}/tenant/v1/profiles"))
        .header("Authorization", format!("Bearer {t1_token}"))
        .json(&json!({
            "name": "Hello",
            "enabled": true,
            "allowPartialUpstreams": true,
            "upstreams": [],
            "tools": []
        }))
        .send()
        .await
        .context("tenant POST /profiles (1)")?;
    anyhow::ensure!(resp.status().is_success());

    // Creating another profile with "hello" should conflict (case-insensitive).
    let resp = client
        .post(format!("{admin_base}/tenant/v1/profiles"))
        .header("Authorization", format!("Bearer {t1_token}"))
        .json(&json!({
            "name": "hello",
            "enabled": true,
            "allowPartialUpstreams": true,
            "upstreams": [],
            "tools": []
        }))
        .send()
        .await
        .context("tenant POST /profiles (2)")?;
    anyhow::ensure!(resp.status() == reqwest::StatusCode::CONFLICT);

    Ok(())
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
#[allow(clippy::too_many_lines)]
async fn bootstrap_tenant_creates_first_tenant_and_returns_tenant_token() -> anyhow::Result<()> {
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

    // Gateway (Mode 3) with admin token unset (bootstrap enabled).
    let gw = spawn_gateway(&database_url, None, SESSION_SECRET)?;
    let data_base = gw.data_base.clone();
    let admin_base = gw.admin_base.clone();
    let _gateway_child = KillOnDrop(gw.child);
    wait_http_ok(&format!("{data_base}/health"), Duration::from_secs(20)).await?;
    wait_http_ok(&format!("{admin_base}/health"), Duration::from_secs(20)).await?;

    let client = reqwest::Client::new();

    // Bootstrap initial tenant + starter profile.
    let resp = client
        .post(format!("{admin_base}/bootstrap/v1/tenant"))
        .json(&json!({
            "tenantId": "owner",
            "ttlSeconds": 3600,
            "createProfile": true,
            "profileName": "Starter",
            "profileDescription": "Bootstrapped profile"
        }))
        .send()
        .await
        .context("POST /bootstrap/v1/tenant")?
        .error_for_status()
        .context("POST /bootstrap/v1/tenant status")?;
    let body: serde_json::Value = resp.json().await.context("bootstrap response json")?;

    let token = body
        .get("token")
        .and_then(serde_json::Value::as_str)
        .context("bootstrap response missing token")?
        .to_string();
    anyhow::ensure!(token.starts_with("tv1."), "expected tenant token format");

    // Tenant API is now usable with that token (starter profile should exist).
    let list_resp = client
        .get(format!("{admin_base}/tenant/v1/profiles"))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .context("tenant GET /profiles after bootstrap")?
        .error_for_status()
        .context("tenant GET /profiles after bootstrap status")?;
    let list: serde_json::Value = list_resp
        .json()
        .await
        .context("tenant GET /profiles after bootstrap json")?;
    let profiles = list
        .get("profiles")
        .and_then(serde_json::Value::as_array)
        .context("tenant profiles response missing profiles")?;
    anyhow::ensure!(
        profiles
            .iter()
            .any(|p| p.get("name") == Some(&json!("Starter"))),
        "expected starter profile in tenant list"
    );

    Ok(())
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
#[allow(clippy::too_many_lines)]
async fn tenant_can_create_upstream_and_attach_to_profile() -> anyhow::Result<()> {
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

    // Upstream MCP server
    let u1_port = pick_unused_port()?;
    let u1 = MockUpstream::new().router();
    let u1_listener = tokio::net::TcpListener::bind(("127.0.0.1", u1_port)).await?;
    let u1_task = tokio::spawn(async move {
        let _ = axum::serve(u1_listener, u1).await;
    });
    wait_http_ok(
        &format!("http://127.0.0.1:{u1_port}/health"),
        Duration::from_secs(10),
    )
    .await?;

    // Gateway (Mode 3)
    let gw = spawn_gateway(&database_url, Some(ADMIN_TOKEN), SESSION_SECRET)?;
    let data_base = gw.data_base.clone();
    let admin_base = gw.admin_base.clone();
    let _gateway_child = KillOnDrop(gw.child);
    wait_http_ok(&format!("{data_base}/health"), Duration::from_secs(20)).await?;
    wait_http_ok(&format!("{admin_base}/health"), Duration::from_secs(20)).await?;

    let client = reqwest::Client::new();
    let _ = admin_post(
        &client,
        &admin_base,
        "/admin/v1/tenants",
        json!({ "id": "t1", "enabled": true }),
    )
    .await?;
    let t1_token = admin_issue_tenant_token(&client, &admin_base, "t1").await?;

    // Tenant creates tenant-owned upstream "u1".
    let resp = client
        .put(format!("{admin_base}/tenant/v1/upstreams/u1"))
        .header("Authorization", format!("Bearer {t1_token}"))
        .json(&json!({
            "enabled": true,
            "endpoints": [{ "id": "e1", "url": format!("http://127.0.0.1:{u1_port}/mcp") }]
        }))
        .send()
        .await
        .context("tenant PUT /upstreams/u1")?;
    anyhow::ensure!(resp.status().is_success());

    // Tenant creates a profile referencing "u1" and allowing all tools.
    let create_resp = client
        .post(format!("{admin_base}/tenant/v1/profiles"))
        .header("Authorization", format!("Bearer {t1_token}"))
        .json(&json!({
            "name": "Uses tenant upstream",
            "enabled": true,
            "allowPartialUpstreams": true,
            "upstreams": ["u1"],
            "tools": []
        }))
        .send()
        .await
        .context("tenant POST /profiles")?
        .error_for_status()
        .context("tenant POST /profiles status")?;
    let created: serde_json::Value = create_resp
        .json()
        .await
        .context("tenant POST /profiles json")?;
    let profile_id = created
        .get("id")
        .and_then(serde_json::Value::as_str)
        .context("create profile response missing id")?
        .to_string();

    // Create API key for data-plane access.
    let create_key_resp = client
        .post(format!("{admin_base}/tenant/v1/api-keys"))
        .header("Authorization", format!("Bearer {t1_token}"))
        .json(&json!({ "name": "k1", "profileId": profile_id }))
        .send()
        .await
        .context("tenant POST /api-keys")?
        .error_for_status()
        .context("tenant POST /api-keys status")?;
    let key_body: serde_json::Value = create_key_resp
        .json()
        .await
        .context("tenant POST /api-keys json")?;
    let secret = key_body
        .get("secret")
        .and_then(serde_json::Value::as_str)
        .context("api key response missing secret")?
        .to_string();

    // Data-plane initialize + tools/list should succeed.
    let mcp = McpSession::connect(format!("{data_base}/{profile_id}/mcp"), Some(secret)).await?;
    let tools = mcp
        .request_value_no_auth(1, "tools/list", json!({}))
        .await?;
    let arr = tools
        .get("result")
        .and_then(|r| r.get("tools"))
        .and_then(serde_json::Value::as_array)
        .context("tools/list missing result.tools")?;
    anyhow::ensure!(!arr.is_empty(), "expected at least one tool");

    u1_task.abort();
    Ok(())
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
#[allow(clippy::too_many_lines)]
async fn tenant_tool_source_requires_secret_and_appears_in_tools_list_after_put_secret()
-> anyhow::Result<()> {
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

    // Gateway (Mode 3)
    let gw = spawn_gateway(&database_url, Some(ADMIN_TOKEN), SESSION_SECRET)?;
    let data_base = gw.data_base.clone();
    let admin_base = gw.admin_base.clone();
    let _gateway_child = KillOnDrop(gw.child);
    wait_http_ok(&format!("{data_base}/health"), Duration::from_secs(20)).await?;
    wait_http_ok(&format!("{admin_base}/health"), Duration::from_secs(20)).await?;

    let client = reqwest::Client::new();

    // Tenant
    let _ = admin_post(
        &client,
        &admin_base,
        "/admin/v1/tenants",
        json!({ "id": "t1", "enabled": true }),
    )
    .await?;
    let t1_token = admin_issue_tenant_token(&client, &admin_base, "t1").await?;

    // Create a tenant-owned HTTP tool source that references a missing secret.
    let resp = client
        .put(format!("{admin_base}/tenant/v1/tool-sources/s1"))
        .header("Authorization", format!("Bearer {t1_token}"))
        .json(&json!({
            "type": "http",
            "enabled": true,
            "baseUrl": "https://example.com",
            "auth": { "type": "bearer", "token": "${secret:api_token}" },
            "tools": {
                "ping": { "method": "GET", "path": "/ping" }
            }
        }))
        .send()
        .await
        .context("tenant PUT /tool-sources/s1")?;
    anyhow::ensure!(resp.status().is_success());

    // Create a profile that attaches this source and allowlists its tool.
    let create_profile_resp = client
        .post(format!("{admin_base}/tenant/v1/profiles"))
        .header("Authorization", format!("Bearer {t1_token}"))
        .json(&json!({
            "name": "Profile with tool source",
            "enabled": true,
            "allowPartialUpstreams": true,
            "upstreams": [],
            "sources": ["s1"],
            "tools": ["s1:ping"]
        }))
        .send()
        .await
        .context("tenant POST /profiles")?
        .error_for_status()
        .context("tenant POST /profiles status")?;
    let created: serde_json::Value = create_profile_resp
        .json()
        .await
        .context("tenant POST /profiles json")?;
    let profile_id = created
        .get("id")
        .and_then(serde_json::Value::as_str)
        .context("create profile response missing id")?
        .to_string();

    // Mode 3 data-plane requires an API key (profile default: ApiKeyInitializeOnly).
    let create_key_resp = client
        .post(format!("{admin_base}/tenant/v1/api-keys"))
        .header("Authorization", format!("Bearer {t1_token}"))
        .json(&json!({"name": "test", "profileId": profile_id.as_str()}))
        .send()
        .await
        .context("tenant POST /api-keys")?
        .error_for_status()
        .context("tenant POST /api-keys status")?;
    let created_key: serde_json::Value = create_key_resp
        .json()
        .await
        .context("tenant POST /api-keys json")?;
    let api_key = created_key
        .get("secret")
        .and_then(serde_json::Value::as_str)
        .context("create api key response missing secret")?
        .to_string();

    // Initialize over the data plane.
    let session = McpSession::connect(
        format!("{data_base}/{profile_id}/mcp"),
        Some(api_key.clone()),
    )
    .await?;

    // tools/list: should be empty because the required secret is missing (source cannot be built).
    // (ApiKeyInitializeOnly → follow-ups should work without auth.)
    let tools_msg = session
        .request_value_no_auth(1, "tools/list", json!({}))
        .await?;
    let tools = tools_msg
        .get("result")
        .and_then(|r| r.get("tools"))
        .and_then(serde_json::Value::as_array)
        .context("tools/list missing result.tools")?;
    anyhow::ensure!(tools.is_empty(), "expected no tools before secret exists");

    // Create the secret.
    let put_secret_resp = client
        .post(format!("{admin_base}/tenant/v1/secrets"))
        .header("Authorization", format!("Bearer {t1_token}"))
        .json(&json!({ "name": "api_token", "value": "secret-value" }))
        .send()
        .await
        .context("tenant POST /secrets")?;
    anyhow::ensure!(put_secret_resp.status().is_success());

    // tools/list: now the tool source can be built and the tool should appear.
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
    anyhow::ensure!(
        names.contains(&"ping".to_string()),
        "expected tool 'ping' after secret exists, got: {names:?}"
    );

    Ok(())
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn tenant_tool_source_get_returns_spec_for_round_trip() -> anyhow::Result<()> {
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

    // Gateway (Mode 3)
    let gw = spawn_gateway(&database_url, Some(ADMIN_TOKEN), SESSION_SECRET)?;
    let admin_base = gw.admin_base.clone();
    let _gateway_child = KillOnDrop(gw.child);
    wait_http_ok(&format!("{admin_base}/health"), Duration::from_secs(20)).await?;

    let client = reqwest::Client::new();

    // Tenant
    let _ = admin_post(
        &client,
        &admin_base,
        "/admin/v1/tenants",
        json!({ "id": "t1", "enabled": true }),
    )
    .await?;
    let t1_token = admin_issue_tenant_token(&client, &admin_base, "t1").await?;

    // Put tool source.
    let put = client
        .put(format!("{admin_base}/tenant/v1/tool-sources/s1"))
        .header("Authorization", format!("Bearer {t1_token}"))
        .json(&json!({
            "type": "http",
            "enabled": true,
            "baseUrl": "https://example.com",
            "tools": {
                "ping": { "method": "GET", "path": "/ping" }
            }
        }))
        .send()
        .await
        .context("tenant PUT /tool-sources/s1")?;
    anyhow::ensure!(put.status().is_success());

    // GET should include stored spec for round-trip.
    let get = client
        .get(format!("{admin_base}/tenant/v1/tool-sources/s1"))
        .header("Authorization", format!("Bearer {t1_token}"))
        .send()
        .await
        .context("tenant GET /tool-sources/s1")?
        .error_for_status()
        .context("tenant GET /tool-sources/s1 status")?;
    let got: serde_json::Value = get
        .json()
        .await
        .context("tenant GET /tool-sources/s1 json")?;
    anyhow::ensure!(
        got.get("type").and_then(serde_json::Value::as_str) == Some("http"),
        "expected type=http, got: {got}"
    );
    anyhow::ensure!(
        got.get("enabled").and_then(serde_json::Value::as_bool) == Some(true),
        "expected enabled=true, got: {got}"
    );
    let spec = got
        .get("spec")
        .and_then(serde_json::Value::as_object)
        .context("tool source GET missing spec object")?;
    anyhow::ensure!(
        spec.get("baseUrl").and_then(serde_json::Value::as_str) == Some("https://example.com"),
        "expected spec.baseUrl, got: {got}"
    );
    anyhow::ensure!(
        spec.get("tools")
            .and_then(serde_json::Value::as_object)
            .is_some(),
        "spec.tools missing"
    );

    Ok(())
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
#[allow(clippy::too_many_lines)]
async fn tenant_profile_surface_probe_returns_tools_and_source_status() -> anyhow::Result<()> {
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

    // Gateway (Mode 3)
    let gw = spawn_gateway(&database_url, Some(ADMIN_TOKEN), SESSION_SECRET)?;
    let admin_base = gw.admin_base.clone();
    let _gateway_child = KillOnDrop(gw.child);
    wait_http_ok(&format!("{admin_base}/health"), Duration::from_secs(20)).await?;

    let client = reqwest::Client::new();

    // Tenant
    let _ = admin_post(
        &client,
        &admin_base,
        "/admin/v1/tenants",
        json!({ "id": "t1", "enabled": true }),
    )
    .await?;
    let t1_token = admin_issue_tenant_token(&client, &admin_base, "t1").await?;

    // Tenant tool source
    let resp = client
        .put(format!("{admin_base}/tenant/v1/tool-sources/s1"))
        .header("Authorization", format!("Bearer {t1_token}"))
        .json(&json!({
            "type": "http",
            "enabled": true,
            "baseUrl": "https://example.com",
            "tools": { "ping": { "method": "GET", "path": "/ping" } }
        }))
        .send()
        .await
        .context("tenant PUT /tool-sources/s1")?;
    anyhow::ensure!(resp.status().is_success());

    // Create profile that attaches this source and allowlists everything.
    let create_profile_resp = client
        .post(format!("{admin_base}/tenant/v1/profiles"))
        .header("Authorization", format!("Bearer {t1_token}"))
        .json(&json!({
            "name": "Surface probe profile",
            "enabled": true,
            "allowPartialUpstreams": true,
            "upstreams": [],
            "sources": ["s1"],
            "tools": []
        }))
        .send()
        .await
        .context("tenant POST /profiles")?
        .error_for_status()
        .context("tenant POST /profiles status")?;
    let created: serde_json::Value = create_profile_resp
        .json()
        .await
        .context("tenant POST /profiles json")?;
    let profile_id = created
        .get("id")
        .and_then(serde_json::Value::as_str)
        .context("create profile response missing id")?
        .to_string();

    // Probe surface.
    let surface_resp = client
        .get(format!(
            "{admin_base}/tenant/v1/profiles/{profile_id}/surface"
        ))
        .header("Authorization", format!("Bearer {t1_token}"))
        .send()
        .await
        .context("tenant GET /profiles/{id}/surface")?
        .error_for_status()
        .context("tenant GET /profiles/{id}/surface status")?;
    let surface: serde_json::Value = surface_resp
        .json()
        .await
        .context("tenant GET /profiles/{id}/surface json")?;

    let tools = surface
        .get("tools")
        .and_then(serde_json::Value::as_array)
        .context("surface missing tools array")?;
    anyhow::ensure!(
        tools.iter().any(|t| t.get("name") == Some(&json!("ping"))),
        "expected discovered tool 'ping', got: {tools:?}"
    );

    let sources = surface
        .get("sources")
        .and_then(serde_json::Value::as_array)
        .context("surface missing sources array")?;
    anyhow::ensure!(
        sources
            .iter()
            .any(|s| s.get("sourceId") == Some(&json!("s1"))),
        "expected sourceId 's1' in sources, got: {sources:?}"
    );

    // Disable the profile and ensure probing still works.
    let disable = client
        .put(format!("{admin_base}/tenant/v1/profiles/{profile_id}"))
        .header("Authorization", format!("Bearer {t1_token}"))
        .json(&json!({
            "name": "Surface probe profile",
            "description": null,
            "enabled": false,
            "allowPartialUpstreams": true,
            "upstreams": [],
            "sources": ["s1"],
            "tools": []
        }))
        .send()
        .await
        .context("tenant PUT /profiles/{id} disable")?
        .error_for_status()
        .context("tenant PUT /profiles/{id} disable status")?;
    drop(disable);

    let surface_disabled_resp = client
        .get(format!(
            "{admin_base}/tenant/v1/profiles/{profile_id}/surface"
        ))
        .header("Authorization", format!("Bearer {t1_token}"))
        .send()
        .await
        .context("tenant GET /profiles/{id}/surface (disabled profile)")?
        .error_for_status()
        .context("tenant GET /profiles/{id}/surface (disabled) status")?;
    let surface2: serde_json::Value = surface_disabled_resp
        .json()
        .await
        .context("tenant GET /profiles/{id}/surface (disabled) json")?;

    let tools2 = surface2
        .get("tools")
        .and_then(serde_json::Value::as_array)
        .context("surface2 missing tools array")?;
    anyhow::ensure!(
        tools2.iter().any(|t| t.get("name") == Some(&json!("ping"))),
        "expected discovered tool 'ping' for disabled profile, got: {tools2:?}"
    );

    Ok(())
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
#[allow(clippy::too_many_lines)]
async fn tenant_can_patch_delete_and_inspect_upstream_endpoints() -> anyhow::Result<()> {
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

    // Gateway (Mode 3)
    let gw = spawn_gateway(&database_url, Some(ADMIN_TOKEN), SESSION_SECRET)?;
    let admin_base = gw.admin_base.clone();
    let _gateway_child = KillOnDrop(gw.child);
    wait_http_ok(&format!("{admin_base}/health"), Duration::from_secs(20)).await?;

    let client = reqwest::Client::new();

    // Tenant
    let _ = admin_post(
        &client,
        &admin_base,
        "/admin/v1/tenants",
        json!({ "id": "t1", "enabled": true }),
    )
    .await?;
    let t1_token = admin_issue_tenant_token(&client, &admin_base, "t1").await?;

    // Create tenant-owned upstream with two endpoints.
    let put_resp = client
        .put(format!("{admin_base}/tenant/v1/upstreams/u1"))
        .header("Authorization", format!("Bearer {t1_token}"))
        .json(&json!({
            "enabled": true,
            "endpoints": [
                { "id": "e1", "url": "https://example.com/mcp" },
                { "id": "e2", "url": "https://example.org/mcp" }
            ]
        }))
        .send()
        .await
        .context("tenant PUT /upstreams/u1")?;
    anyhow::ensure!(put_resp.status().is_success());

    // Empty PATCH payload is rejected.
    let empty_patch = client
        .patch(format!("{admin_base}/tenant/v1/upstreams/u1/endpoints/e1"))
        .header("Authorization", format!("Bearer {t1_token}"))
        .json(&json!({}))
        .send()
        .await
        .context("tenant PATCH empty endpoint payload")?;
    anyhow::ensure!(empty_patch.status() == reqwest::StatusCode::BAD_REQUEST);

    // Mark endpoint e1 draining.
    let patch_drain = client
        .patch(format!("{admin_base}/tenant/v1/upstreams/u1/endpoints/e1"))
        .header("Authorization", format!("Bearer {t1_token}"))
        .json(&json!({ "lifecycle": "draining" }))
        .send()
        .await
        .context("tenant PATCH endpoint draining")?;
    anyhow::ensure!(patch_drain.status().is_success());

    // Inspect upstream and verify endpoint state.
    let upstream_resp = client
        .get(format!("{admin_base}/tenant/v1/upstreams/u1"))
        .header("Authorization", format!("Bearer {t1_token}"))
        .send()
        .await
        .context("tenant GET /upstreams/u1")?
        .error_for_status()
        .context("tenant GET /upstreams/u1 status")?;
    let upstream: serde_json::Value = upstream_resp
        .json()
        .await
        .context("tenant GET /upstreams/u1 json")?;
    let endpoints = upstream
        .get("endpoints")
        .and_then(serde_json::Value::as_array)
        .context("tenant upstream response missing endpoints")?;
    let e1 = endpoints
        .iter()
        .find(|ep| ep.get("id") == Some(&json!("e1")))
        .context("endpoint e1 missing after patch")?;
    anyhow::ensure!(
        e1.get("lifecycle") == Some(&json!("draining")),
        "expected e1 lifecycle=draining, got: {e1}"
    );
    anyhow::ensure!(
        e1.get("enabled") == Some(&json!(true)),
        "expected e1 enabled=true, got: {e1}"
    );

    // Session-activity endpoint returns shape + honors ttlSecs request value.
    let activity_resp = client
        .get(format!(
            "{admin_base}/tenant/v1/upstreams/u1/session-activity?ttlSecs=123"
        ))
        .header("Authorization", format!("Bearer {t1_token}"))
        .send()
        .await
        .context("tenant GET upstream session activity")?
        .error_for_status()
        .context("tenant GET upstream session activity status")?;
    let activity: serde_json::Value = activity_resp
        .json()
        .await
        .context("tenant GET upstream session activity json")?;
    anyhow::ensure!(
        activity.get("upstreamId") == Some(&json!("u1")),
        "expected upstreamId=u1, got: {activity}"
    );
    anyhow::ensure!(
        activity.get("ttlSecs") == Some(&json!(123)),
        "expected ttlSecs=123, got: {activity}"
    );

    // Disable endpoint e1.
    let patch_disable = client
        .patch(format!("{admin_base}/tenant/v1/upstreams/u1/endpoints/e1"))
        .header("Authorization", format!("Bearer {t1_token}"))
        .json(&json!({ "enabled": false, "lifecycle": "disabled" }))
        .send()
        .await
        .context("tenant PATCH endpoint disable")?;
    anyhow::ensure!(patch_disable.status().is_success());

    // Delete endpoint e2.
    let delete_e2 = client
        .delete(format!("{admin_base}/tenant/v1/upstreams/u1/endpoints/e2"))
        .header("Authorization", format!("Bearer {t1_token}"))
        .send()
        .await
        .context("tenant DELETE endpoint e2")?;
    anyhow::ensure!(delete_e2.status().is_success());

    // Verify only e1 remains and it is disabled.
    let upstream_resp = client
        .get(format!("{admin_base}/tenant/v1/upstreams/u1"))
        .header("Authorization", format!("Bearer {t1_token}"))
        .send()
        .await
        .context("tenant GET /upstreams/u1 after delete")?
        .error_for_status()
        .context("tenant GET /upstreams/u1 after delete status")?;
    let upstream: serde_json::Value = upstream_resp
        .json()
        .await
        .context("tenant GET /upstreams/u1 after delete json")?;
    let endpoints = upstream
        .get("endpoints")
        .and_then(serde_json::Value::as_array)
        .context("tenant upstream response missing endpoints after delete")?;
    anyhow::ensure!(
        endpoints.len() == 1,
        "expected one endpoint, got: {endpoints:?}"
    );
    anyhow::ensure!(
        endpoints[0].get("id") == Some(&json!("e1")),
        "expected surviving endpoint to be e1, got: {endpoints:?}"
    );
    anyhow::ensure!(
        endpoints[0].get("enabled") == Some(&json!(false))
            && endpoints[0].get("lifecycle") == Some(&json!("disabled")),
        "expected surviving e1 endpoint disabled+disabled lifecycle, got: {endpoints:?}"
    );

    Ok(())
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
#[allow(clippy::too_many_lines)]
async fn tenant_managed_mcp_deployables_and_requests_are_scoped() -> anyhow::Result<()> {
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

    // Gateway (Mode 3) with managed backend enabled for request create/patch coverage.
    let gw = spawn_gateway_with_env(
        &database_url,
        Some(ADMIN_TOKEN),
        SESSION_SECRET,
        &[
            ("UNRELATED_MANAGED_MCP_BACKEND_MODE", "k8s"),
            ("UNRELATED_MANAGED_MCP_RECONCILER_HEARTBEAT_TTL_SECS", "900"),
        ],
    )?;
    let admin_base = gw.admin_base.clone();
    let _gateway_child = KillOnDrop(gw.child);
    wait_http_ok(&format!("{admin_base}/health"), Duration::from_secs(20)).await?;

    let client = reqwest::Client::new();

    // Publish an in-test heartbeat so managed write-guard is healthy.
    let _ = admin_post(
        &client,
        &admin_base,
        "/admin/v1/managed-mcp/reconciler-heartbeat",
        json!({ "mode": "k8s", "reconcilerId": "tenant-api-it" }),
    )
    .await?;

    // Two tenants.
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
        "/admin/v1/tenants",
        json!({ "id": "t2", "enabled": true }),
    )
    .await?;
    let t1_token = admin_issue_tenant_token(&client, &admin_base, "t1").await?;
    let t2_token = admin_issue_tenant_token(&client, &admin_base, "t2").await?;

    // Publish one enabled and one disabled deployable.
    let _ = admin_put(
        &client,
        &admin_base,
        "/admin/v1/managed-mcp/deployables",
        json!({
            "id": "demo-enabled",
            "displayName": "Demo enabled",
            "description": "visible to tenants",
            "image": "ghcr.io/acme/demo-enabled:latest",
            "defaultUpstreamUrl": "http://demo-enabled/mcp",
            "enabled": true
        }),
    )
    .await?;
    let _ = admin_put(
        &client,
        &admin_base,
        "/admin/v1/managed-mcp/deployables",
        json!({
            "id": "demo-disabled",
            "displayName": "Demo disabled",
            "description": "hidden from tenants",
            "image": "ghcr.io/acme/demo-disabled:latest",
            "defaultUpstreamUrl": "http://demo-disabled/mcp",
            "enabled": false
        }),
    )
    .await?;

    // Tenant sees only enabled deployables.
    let deployables_resp = client
        .get(format!("{admin_base}/tenant/v1/managed-mcp/deployables"))
        .header("Authorization", format!("Bearer {t1_token}"))
        .send()
        .await
        .context("tenant GET managed deployables")?
        .error_for_status()
        .context("tenant GET managed deployables status")?;
    let deployables_body: serde_json::Value = deployables_resp
        .json()
        .await
        .context("tenant GET managed deployables json")?;
    let deployables = deployables_body
        .get("deployables")
        .and_then(serde_json::Value::as_array)
        .context("managed deployables response missing deployables")?;
    anyhow::ensure!(
        deployables
            .iter()
            .any(|d| d.get("id") == Some(&json!("demo-enabled"))),
        "expected enabled deployable to be visible, got: {deployables:?}"
    );
    anyhow::ensure!(
        !deployables
            .iter()
            .any(|d| d.get("id") == Some(&json!("demo-disabled"))),
        "expected disabled deployable to be hidden, got: {deployables:?}"
    );

    // Empty deployableId is rejected.
    let empty_create = client
        .post(format!("{admin_base}/tenant/v1/managed-mcp/deployments"))
        .header("Authorization", format!("Bearer {t1_token}"))
        .json(&json!({ "deployableId": "" }))
        .send()
        .await
        .context("tenant POST deployment request with empty deployableId")?;
    anyhow::ensure!(empty_create.status() == reqwest::StatusCode::BAD_REQUEST);

    // Disabled deployable is rejected for create.
    let disabled_create = client
        .post(format!("{admin_base}/tenant/v1/managed-mcp/deployments"))
        .header("Authorization", format!("Bearer {t1_token}"))
        .json(&json!({ "deployableId": "demo-disabled" }))
        .send()
        .await
        .context("tenant POST deployment request for disabled deployable")?;
    anyhow::ensure!(disabled_create.status() == reqwest::StatusCode::BAD_REQUEST);

    // Valid request starts in pending state.
    let create_resp = client
        .post(format!("{admin_base}/tenant/v1/managed-mcp/deployments"))
        .header("Authorization", format!("Bearer {t1_token}"))
        .json(&json!({ "deployableId": "demo-enabled" }))
        .send()
        .await
        .context("tenant POST deployment request")?
        .error_for_status()
        .context("tenant POST deployment request status")?;
    let created: serde_json::Value = create_resp
        .json()
        .await
        .context("tenant POST deployment request json")?;
    let request = created
        .get("request")
        .and_then(serde_json::Value::as_object)
        .context("deployment create response missing request")?;
    let request_id = request
        .get("id")
        .and_then(serde_json::Value::as_str)
        .context("deployment create response missing request.id")?
        .to_string();
    anyhow::ensure!(
        request.get("tenantId") == Some(&json!("t1"))
            && request.get("deployableId") == Some(&json!("demo-enabled"))
            && request.get("desiredEnabled") == Some(&json!(true))
            && request.get("desiredReplicas") == Some(&json!(1))
            && request.get("status") == Some(&json!("pending")),
        "unexpected deployment request payload: {request:?}"
    );

    // Repeated create for the same tenant+deployable is idempotent.
    let create_resp_again = client
        .post(format!("{admin_base}/tenant/v1/managed-mcp/deployments"))
        .header("Authorization", format!("Bearer {t1_token}"))
        .json(&json!({ "deployableId": "demo-enabled" }))
        .send()
        .await
        .context("tenant POST deployment request again")?
        .error_for_status()
        .context("tenant POST deployment request again status")?;
    let created_again: serde_json::Value = create_resp_again
        .json()
        .await
        .context("tenant POST deployment request again json")?;
    let request_again_id = created_again
        .get("request")
        .and_then(|r| r.get("id"))
        .and_then(serde_json::Value::as_str)
        .context("deployment create-again response missing request.id")?;
    anyhow::ensure!(
        request_again_id == request_id,
        "expected idempotent request id, got first={request_id} second={request_again_id}"
    );

    // Another tenant still gets an independent request id.
    let t2_create_resp = client
        .post(format!("{admin_base}/tenant/v1/managed-mcp/deployments"))
        .header("Authorization", format!("Bearer {t2_token}"))
        .json(&json!({ "deployableId": "demo-enabled" }))
        .send()
        .await
        .context("t2 tenant POST deployment request")?
        .error_for_status()
        .context("t2 tenant POST deployment request status")?;
    let t2_created: serde_json::Value = t2_create_resp
        .json()
        .await
        .context("t2 tenant POST deployment request json")?;
    let t2_request_id = t2_created
        .get("request")
        .and_then(|r| r.get("id"))
        .and_then(serde_json::Value::as_str)
        .context("t2 deployment create response missing request.id")?
        .to_string();
    anyhow::ensure!(
        t2_request_id != request_id,
        "expected t2 request id to differ from t1 request id"
    );

    // List endpoint is tenant scoped.
    let t1_list_resp = client
        .get(format!("{admin_base}/tenant/v1/managed-mcp/deployments"))
        .header("Authorization", format!("Bearer {t1_token}"))
        .send()
        .await
        .context("tenant GET managed deployment requests list")?
        .error_for_status()
        .context("tenant GET managed deployment requests list status")?;
    let t1_list_body: serde_json::Value = t1_list_resp
        .json()
        .await
        .context("tenant GET managed deployment requests list json")?;
    let t1_requests = t1_list_body
        .get("requests")
        .and_then(serde_json::Value::as_array)
        .context("managed deployment requests list missing requests")?;
    anyhow::ensure!(
        t1_requests
            .iter()
            .any(|r| r.get("id") == Some(&json!(request_id))),
        "expected t1 request in t1 list, got: {t1_requests:?}"
    );
    anyhow::ensure!(
        !t1_requests
            .iter()
            .any(|r| r.get("id") == Some(&json!(t2_request_id))),
        "expected t2 request to be excluded from t1 list, got: {t1_requests:?}"
    );

    // Empty PATCH body is rejected.
    let empty_patch = client
        .patch(format!(
            "{admin_base}/tenant/v1/managed-mcp/deployments/{request_id}"
        ))
        .header("Authorization", format!("Bearer {t1_token}"))
        .json(&json!({}))
        .send()
        .await
        .context("tenant PATCH managed deployment request with empty body")?;
    anyhow::ensure!(empty_patch.status() == reqwest::StatusCode::BAD_REQUEST);

    // Cross-tenant PATCH is rejected as not found.
    let cross_tenant_patch = client
        .patch(format!(
            "{admin_base}/tenant/v1/managed-mcp/deployments/{request_id}"
        ))
        .header("Authorization", format!("Bearer {t2_token}"))
        .json(&json!({ "replicas": 2 }))
        .send()
        .await
        .context("cross-tenant PATCH managed deployment request")?;
    anyhow::ensure!(cross_tenant_patch.status() == reqwest::StatusCode::NOT_FOUND);

    // Tenant can update desired replicas; request transitions back to pending.
    let patch_resp = client
        .patch(format!(
            "{admin_base}/tenant/v1/managed-mcp/deployments/{request_id}"
        ))
        .header("Authorization", format!("Bearer {t1_token}"))
        .json(&json!({ "replicas": 3 }))
        .send()
        .await
        .context("tenant PATCH managed deployment request replicas")?
        .error_for_status()
        .context("tenant PATCH managed deployment request replicas status")?;
    let patch_body: serde_json::Value = patch_resp
        .json()
        .await
        .context("tenant PATCH managed deployment request replicas json")?;
    anyhow::ensure!(
        patch_body
            .get("request")
            .and_then(|r| r.get("desiredReplicas"))
            .and_then(serde_json::Value::as_i64)
            == Some(3),
        "expected desiredReplicas=3 after PATCH, got: {patch_body}"
    );
    anyhow::ensure!(
        patch_body
            .get("request")
            .and_then(|r| r.get("status"))
            .and_then(serde_json::Value::as_str)
            == Some("pending"),
        "expected status=pending after PATCH, got: {patch_body}"
    );

    // Disabling sets desiredEnabled false and allows replicas=0.
    let disable_resp = client
        .patch(format!(
            "{admin_base}/tenant/v1/managed-mcp/deployments/{request_id}"
        ))
        .header("Authorization", format!("Bearer {t1_token}"))
        .json(&json!({ "enabled": false, "replicas": 0 }))
        .send()
        .await
        .context("tenant PATCH managed deployment request disable")?
        .error_for_status()
        .context("tenant PATCH managed deployment request disable status")?;
    let disable_body: serde_json::Value = disable_resp
        .json()
        .await
        .context("tenant PATCH managed deployment request disable json")?;
    anyhow::ensure!(
        disable_body
            .get("request")
            .and_then(|r| r.get("desiredEnabled"))
            .and_then(serde_json::Value::as_bool)
            == Some(false),
        "expected desiredEnabled=false after disable PATCH, got: {disable_body}"
    );
    anyhow::ensure!(
        disable_body
            .get("request")
            .and_then(|r| r.get("desiredReplicas"))
            .and_then(serde_json::Value::as_i64)
            == Some(0),
        "expected desiredReplicas=0 after disable PATCH, got: {disable_body}"
    );

    // Enabling requires replicas >= 1.
    let invalid_enable = client
        .patch(format!(
            "{admin_base}/tenant/v1/managed-mcp/deployments/{request_id}"
        ))
        .header("Authorization", format!("Bearer {t1_token}"))
        .json(&json!({ "enabled": true, "replicas": 0 }))
        .send()
        .await
        .context("tenant PATCH managed deployment request invalid enable")?;
    anyhow::ensure!(invalid_enable.status() == reqwest::StatusCode::BAD_REQUEST);

    // Request is tenant scoped: other tenant gets 404.
    let cross_tenant_get = client
        .get(format!(
            "{admin_base}/tenant/v1/managed-mcp/deployments/{request_id}"
        ))
        .header("Authorization", format!("Bearer {t2_token}"))
        .send()
        .await
        .context("cross-tenant GET managed deployment request")?;
    anyhow::ensure!(cross_tenant_get.status() == reqwest::StatusCode::NOT_FOUND);

    // Owning tenant can read it back.
    let own_get = client
        .get(format!(
            "{admin_base}/tenant/v1/managed-mcp/deployments/{request_id}"
        ))
        .header("Authorization", format!("Bearer {t1_token}"))
        .send()
        .await
        .context("tenant GET managed deployment request")?
        .error_for_status()
        .context("tenant GET managed deployment request status")?;
    let own_body: serde_json::Value = own_get
        .json()
        .await
        .context("tenant GET managed deployment request json")?;
    anyhow::ensure!(
        own_body
            .get("request")
            .and_then(|r| r.get("id"))
            .and_then(serde_json::Value::as_str)
            == Some(request_id.as_str()),
        "expected same request id in GET response, got: {own_body}"
    );
    anyhow::ensure!(
        own_body
            .get("request")
            .and_then(|r| r.get("desiredEnabled"))
            .and_then(serde_json::Value::as_bool)
            == Some(false),
        "expected desiredEnabled=false in GET response, got: {own_body}"
    );
    anyhow::ensure!(
        own_body
            .get("request")
            .and_then(|r| r.get("desiredReplicas"))
            .and_then(serde_json::Value::as_i64)
            == Some(0),
        "expected desiredReplicas=0 in GET response, got: {own_body}"
    );

    Ok(())
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
#[allow(clippy::too_many_lines)]
async fn tenant_managed_upstream_created_via_admin_is_tenant_scoped() -> anyhow::Result<()> {
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

    // Gateway (Mode 3)
    let gw = spawn_gateway(&database_url, Some(ADMIN_TOKEN), SESSION_SECRET)?;
    let admin_base = gw.admin_base.clone();
    let _gateway_child = KillOnDrop(gw.child);
    wait_http_ok(&format!("{admin_base}/health"), Duration::from_secs(20)).await?;

    let client = reqwest::Client::new();

    // Two tenants.
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
        "/admin/v1/tenants",
        json!({ "id": "t2", "enabled": true }),
    )
    .await?;
    let t1_token = admin_issue_tenant_token(&client, &admin_base, "t1").await?;
    let t2_token = admin_issue_tenant_token(&client, &admin_base, "t2").await?;

    // Operator-style upsert: logical upstream id + tenantId.
    let managed_upstream_id = "managed_t1_scope_test";
    let _ = admin_post(
        &client,
        &admin_base,
        "/admin/v1/upstreams",
        json!({
            "id": managed_upstream_id,
            "tenantId": "t1",
            "enabled": true,
            "networkClass": "external",
            "endpoints": [
                {
                    "id": "e1",
                    "url": "http://127.0.0.1:9999/mcp",
                    "enabled": true,
                    "lifecycle": "active"
                }
            ]
        }),
    )
    .await?;

    // Owning tenant sees the upstream in list.
    let t1_list_resp = client
        .get(format!("{admin_base}/tenant/v1/upstreams"))
        .header("Authorization", format!("Bearer {t1_token}"))
        .send()
        .await
        .context("t1 GET /tenant/v1/upstreams")?
        .error_for_status()
        .context("t1 GET /tenant/v1/upstreams status")?;
    let t1_list_body: serde_json::Value = t1_list_resp
        .json()
        .await
        .context("t1 GET /tenant/v1/upstreams json")?;
    let t1_upstreams = t1_list_body
        .get("upstreams")
        .and_then(serde_json::Value::as_array)
        .context("t1 upstream list missing upstreams")?;
    anyhow::ensure!(
        t1_upstreams.iter().any(|u| {
            u.get("id") == Some(&json!(managed_upstream_id))
                && u.get("owner") == Some(&json!("tenant"))
        }),
        "expected tenant-owned managed upstream in t1 list, got: {t1_upstreams:?}"
    );

    // Other tenant does not see it in list.
    let t2_list_resp = client
        .get(format!("{admin_base}/tenant/v1/upstreams"))
        .header("Authorization", format!("Bearer {t2_token}"))
        .send()
        .await
        .context("t2 GET /tenant/v1/upstreams")?
        .error_for_status()
        .context("t2 GET /tenant/v1/upstreams status")?;
    let t2_list_body: serde_json::Value = t2_list_resp
        .json()
        .await
        .context("t2 GET /tenant/v1/upstreams json")?;
    let t2_upstreams = t2_list_body
        .get("upstreams")
        .and_then(serde_json::Value::as_array)
        .context("t2 upstream list missing upstreams")?;
    anyhow::ensure!(
        !t2_upstreams
            .iter()
            .any(|u| u.get("id") == Some(&json!(managed_upstream_id))),
        "expected managed upstream to be hidden from t2 list, got: {t2_upstreams:?}"
    );

    // Cross-tenant direct GET is hidden as not found.
    let t2_get = client
        .get(format!(
            "{admin_base}/tenant/v1/upstreams/{managed_upstream_id}"
        ))
        .header("Authorization", format!("Bearer {t2_token}"))
        .send()
        .await
        .context("t2 cross-tenant GET managed upstream")?;
    anyhow::ensure!(t2_get.status() == reqwest::StatusCode::NOT_FOUND);

    // Owning tenant can read it directly.
    let t1_get_resp = client
        .get(format!(
            "{admin_base}/tenant/v1/upstreams/{managed_upstream_id}"
        ))
        .header("Authorization", format!("Bearer {t1_token}"))
        .send()
        .await
        .context("t1 GET managed upstream")?
        .error_for_status()
        .context("t1 GET managed upstream status")?;
    let t1_get_body: serde_json::Value = t1_get_resp
        .json()
        .await
        .context("t1 GET managed upstream json")?;
    anyhow::ensure!(
        t1_get_body.get("id") == Some(&json!(managed_upstream_id))
            && t1_get_body.get("owner") == Some(&json!("tenant")),
        "expected tenant-owned managed upstream payload, got: {t1_get_body}"
    );

    Ok(())
}
