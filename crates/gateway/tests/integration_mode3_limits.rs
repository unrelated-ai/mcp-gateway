mod common;

use anyhow::Context as _;
use axum::{
    Router,
    response::IntoResponse,
    routing::{get, post},
};
use common::pg::{
    apply_dbmate_migration_file, apply_dbmate_migrations, apply_dbmate_migrations_before,
    wait_pg_ready,
};
use common::sse::read_first_event_stream_json_message;
use common::{KillOnDrop, pick_unused_port, spawn_gateway, wait_http_ok};
use rmcp::model::{
    CallToolResult, ClientJsonRpcMessage, ClientRequest, ContentBlock, InitializeResult,
    JsonObject, JsonRpcRequest, JsonRpcResponse, JsonRpcVersion2_0, ListToolsResult,
    ServerCapabilities, ServerJsonRpcMessage, ServerResult, Tool,
};
use serde_json::json;
use std::{collections::HashSet, convert::Infallible, process::Command, sync::Arc, time::Duration};
use testcontainers::core::IntoContainerPort;
use testcontainers::runners::AsyncRunner;
use testcontainers::{GenericImage, ImageExt as _};
use tokio::sync::Mutex;

const ADMIN_TOKEN: &str = "test-admin-token";
const SESSION_SECRET: &str = "test-session-secret";
const TEST_OAUTH_ISSUER: &str = "https://issuer.example";
const TEST_PUBLIC_DATA_BASE_URL: &str = "https://mcp.example.com";
const OAUTH_MIGRATION: &str = "20260712000000_oauth_resource_server.sql";

struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct Pg {
    _container: testcontainers::ContainerAsync<GenericImage>,
    database_url: String,
}

async fn start_postgres() -> anyhow::Result<Pg> {
    let pg = GenericImage::new("postgres", "16.14-alpine3.24")
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

    Ok(Pg {
        _container: pg,
        database_url,
    })
}

async fn start_postgres_before_oauth_migration() -> anyhow::Result<Pg> {
    let pg = GenericImage::new("postgres", "16.14-alpine3.24")
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
    apply_dbmate_migrations_before(&database_url, OAUTH_MIGRATION).await?;
    Ok(Pg {
        _container: pg,
        database_url,
    })
}

struct Upstream {
    port: u16,
    _task: AbortOnDrop,
}

async fn start_mock_upstream() -> anyhow::Result<Upstream> {
    let port = pick_unused_port()?;
    let upstream = MockUpstream::new().router();
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, upstream).await;
    });
    wait_http_ok(
        &format!("http://127.0.0.1:{port}/health"),
        Duration::from_secs(10),
    )
    .await?;
    Ok(Upstream {
        port,
        _task: AbortOnDrop(task),
    })
}

struct Gateway {
    data_base: String,
    admin_base: String,
    _proc: KillOnDrop,
}

async fn start_gateway_mode3(database_url: &str) -> anyhow::Result<Gateway> {
    let gw = spawn_gateway(database_url, Some(ADMIN_TOKEN), SESSION_SECRET)?;
    let data_base = gw.data_base.clone();
    let admin_base = gw.admin_base.clone();
    let gw = KillOnDrop(gw.child);
    wait_http_ok(&format!("{data_base}/health"), Duration::from_secs(20)).await?;
    wait_http_ok(&format!("{admin_base}/health"), Duration::from_secs(20)).await?;

    Ok(Gateway {
        data_base,
        admin_base,
        _proc: gw,
    })
}

async fn start_gateway_mode3_with_oauth(
    database_url: &str,
    jwks_uri: &str,
) -> anyhow::Result<Gateway> {
    let gw = spawn_gateway_with_oauth(database_url, jwks_uri)?;
    let data_base = gw.data_base.clone();
    let admin_base = gw.admin_base.clone();
    let gw = KillOnDrop(gw.child);
    wait_http_ok(&format!("{data_base}/health"), Duration::from_secs(20)).await?;
    wait_http_ok(&format!("{admin_base}/health"), Duration::from_secs(20)).await?;

    Ok(Gateway {
        data_base,
        admin_base,
        _proc: gw,
    })
}

async fn admin_create_tenant(
    client: &reqwest::Client,
    admin_base: &str,
    tenant_id: &str,
) -> anyhow::Result<()> {
    let _ = admin_post(
        client,
        admin_base,
        "/admin/v1/tenants",
        json!({ "id": tenant_id, "enabled": true }),
    )
    .await?;
    Ok(())
}

async fn admin_create_upstream(
    client: &reqwest::Client,
    admin_base: &str,
    upstream_id: &str,
    upstream_url: &str,
) -> anyhow::Result<()> {
    let _ = admin_post(
        client,
        admin_base,
        "/admin/v1/upstreams",
        json!({
            "id": upstream_id,
            "enabled": true,
            "endpoints": [{ "id": "e1", "url": upstream_url }]
        }),
    )
    .await?;
    Ok(())
}

async fn admin_create_profile(
    client: &reqwest::Client,
    admin_base: &str,
    body: serde_json::Value,
) -> anyhow::Result<String> {
    let resp = admin_post(client, admin_base, "/admin/v1/profiles", body).await?;
    resp.get("id")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
        .context("create profile response missing id")
}

fn profile_mcp_url(data_base: &str, profile_id: &str) -> String {
    format!("{}/{}/mcp", data_base.trim_end_matches('/'), profile_id)
}

async fn mcp_initialize_with_api_key(
    client: &reqwest::Client,
    data_base: &str,
    profile_id: &str,
    api_key: &str,
) -> anyhow::Result<String> {
    let init_resp = post_mcp(
        client,
        &profile_mcp_url(data_base, profile_id),
        None,
        Some(api_key),
        json!({
            "jsonrpc": "2.0",
            "id": 0,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": { "name": "mode3-test", "version": "0" }
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
    let _ = read_first_event_stream_json_message(init_resp).await?;
    Ok(session_id)
}

struct JwksServer {
    jwks_uri: String,
    _task: AbortOnDrop,
}

async fn start_jwks_server(jwks_json: serde_json::Value) -> anyhow::Result<JwksServer> {
    let port = pick_unused_port()?;
    let router = Router::new().route(
        "/jwks",
        get({
            let jwks_json = jwks_json.clone();
            move || async move { axum::Json(jwks_json) }
        }),
    );
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    wait_http_ok(
        &format!("http://127.0.0.1:{port}/jwks"),
        Duration::from_secs(10),
    )
    .await?;
    Ok(JwksServer {
        jwks_uri: format!("http://127.0.0.1:{port}/jwks"),
        _task: AbortOnDrop(task),
    })
}

fn generate_test_keypair_and_jwks(kid: &str) -> anyhow::Result<(String, serde_json::Value)> {
    use base64::Engine as _;
    use rsa::pkcs8::{EncodePrivateKey as _, LineEnding};
    use rsa::rand_core::OsRng;
    use rsa::traits::PublicKeyParts as _;

    let mut rng = OsRng;
    let key = rsa::RsaPrivateKey::new(&mut rng, 2048).context("generate rsa key")?;
    let pem = key
        .to_pkcs8_pem(LineEnding::LF)
        .context("encode private key to pkcs8 pem")?
        .to_string();
    let public = key.to_public_key();
    let b64u = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let n = b64u.encode(public.n().to_bytes_be());
    let e = b64u.encode(public.e().to_bytes_be());

    Ok((
        pem,
        json!({
            "keys": [{
                "kty": "RSA",
                "kid": kid,
                "use": "sig",
                "n": n,
                "e": e
            }]
        }),
    ))
}

#[allow(clippy::needless_pass_by_value)]
fn sign_rs256_jwt(
    pem: &str,
    kid: &str,
    subject: &str,
    issuer: &str,
    audience: serde_json::Value,
    scopes: serde_json::Value,
    now: u64,
) -> anyhow::Result<String> {
    use jsonwebtoken::{Algorithm, EncodingKey, Header};

    let claims = json!({
        "iss": issuer,
        "aud": audience,
        "scope": scopes,
        "sub": subject,
        "iat": now,
        "nbf": now.saturating_sub(1),
        "exp": now + 3600,
    });
    let header = Header {
        alg: Algorithm::RS256,
        kid: Some(kid.to_string()),
        ..Header::default()
    };
    jsonwebtoken::encode(
        &header,
        &claims,
        &EncodingKey::from_rsa_pem(pem.as_bytes()).context("build encoding key")?,
    )
    .context("encode jwt")
}

async fn mcp_initialize_with_jwt_allow_error(
    client: &reqwest::Client,
    data_base: &str,
    profile_id: &str,
    jwt: &str,
    id: u64,
) -> anyhow::Result<reqwest::Response> {
    post_mcp_allow_error(
        client,
        &profile_mcp_url(data_base, profile_id),
        None,
        Some(jwt),
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": { "name": "mode3-oauth-test", "version": "0" }
            }
        }),
    )
    .await
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

async fn tenant_create_api_key(
    client: &reqwest::Client,
    admin_base: &str,
    tenant_token: &str,
    profile_id: &str,
) -> anyhow::Result<(String, String)> {
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
    let secret = body
        .get("secret")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
        .context("create api key response missing secret")?;
    let id = body
        .get("id")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
        .context("create api key response missing id")?;
    Ok((secret, id))
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
        .await
        .context("POST mcp")?
        .error_for_status()
        .context("POST mcp status")
}

async fn post_mcp_allow_error(
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

    req.send().await.context("POST mcp")
}

fn spawn_gateway_with_oauth(
    database_url: &str,
    jwks_uri: &str,
) -> anyhow::Result<common::SpawnedGateway> {
    let bin = env!("CARGO_BIN_EXE_unrelated-mcp-gateway");
    let child = Command::new(bin)
        .arg("--bind")
        .arg("127.0.0.1:0")
        .arg("--admin-bind")
        .arg("127.0.0.1:0")
        .arg("--database-url")
        .arg(database_url)
        .arg("--log-level")
        .arg("info")
        .env("UNRELATED_GATEWAY_ADMIN_TOKEN", ADMIN_TOKEN)
        .env("UNRELATED_GATEWAY_SESSION_SECRET", SESSION_SECRET)
        // Integration tests run mock upstreams on loopback.
        .env("UNRELATED_GATEWAY_OUTBOUND_ALLOW_PRIVATE_NETWORKS", "1")
        // Integration tests run mock upstreams over plain HTTP on loopback.
        .env("UNRELATED_GATEWAY_UPSTREAM_ALLOW_HTTP", "1")
        // Mode 3 requires tenant secret encryption keys.
        .env(
            "UNRELATED_GATEWAY_SECRET_KEYS",
            "unrelated-mcp-gateway-test-secret-keys-v1",
        )
        .env(
            "UNRELATED_GATEWAY_PUBLIC_DATA_BASE_URL",
            TEST_PUBLIC_DATA_BASE_URL,
        )
        .env("UNRELATED_GATEWAY_OAUTH_ISSUER", TEST_OAUTH_ISSUER)
        .env("UNRELATED_GATEWAY_OAUTH_JWKS_URI", jwks_uri)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context("spawn gateway with oauth")?;
    common::wait_for_gateway_ports(child, Duration::from_secs(10))
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

    async fn post_mcp(
        axum::extract::State(this): axum::extract::State<MockUpstream>,
        headers: axum::http::HeaderMap,
        body: axum::body::Bytes,
    ) -> axum::response::Response {
        // Caller auth must never be forwarded by the gateway.
        if headers.get("authorization").is_some() || headers.get("x-api-key").is_some() {
            return (
                axum::http::StatusCode::BAD_REQUEST,
                "unexpected auth header forwarded to upstream",
            )
                .into_response();
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

        let init_result =
            InitializeResult::new(ServerCapabilities::builder().enable_tools().build())
                .with_protocol_version(init_params.protocol_version)
                .with_server_info(rmcp::model::Implementation::new("mock-upstream", "0"));
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
                let mut result =
                    CallToolResult::success(vec![ContentBlock::text(format!("ok:{name}"))]);
                result.is_error = None;
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

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn mode3_quota_blocks_second_tools_call() -> anyhow::Result<()> {
    let pg = start_postgres().await?;
    let upstream = start_mock_upstream().await?;
    let gw = start_gateway_mode3(&pg.database_url).await?;
    let client = reqwest::Client::new();

    admin_create_tenant(&client, &gw.admin_base, "t1").await?;
    admin_create_upstream(
        &client,
        &gw.admin_base,
        "u1",
        &format!("http://127.0.0.1:{}/mcp", upstream.port),
    )
    .await?;
    let profile_id = admin_create_profile(
        &client,
        &gw.admin_base,
        json!({
            "tenantId": "t1",
            "name": "p1",
            "enabled": true,
            "allowPartialUpstreams": true,
            "upstreams": ["u1"],
            "tools": [],
            "dataPlaneLimits": { "quotaEnabled": true, "quotaToolCalls": 1 }
        }),
    )
    .await?;
    let t1_token = admin_issue_tenant_token(&client, &gw.admin_base, "t1").await?;
    let (api_key, _) =
        tenant_create_api_key(&client, &gw.admin_base, &t1_token, &profile_id).await?;
    let session_id =
        mcp_initialize_with_api_key(&client, &gw.data_base, &profile_id, &api_key).await?;

    // First tools/call should succeed.
    let call1 = read_first_event_stream_json_message(
        post_mcp(
            &client,
            &profile_mcp_url(&gw.data_base, &profile_id),
            Some(&session_id),
            Some(&api_key),
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": { "name": "echo_request", "arguments": {} }
            }),
        )
        .await?,
    )
    .await?;
    anyhow::ensure!(call1.get("result").is_some(), "expected result");

    // Second tools/call should be quota-exceeded.
    let call2 = read_first_event_stream_json_message(
        post_mcp(
            &client,
            &profile_mcp_url(&gw.data_base, &profile_id),
            Some(&session_id),
            Some(&api_key),
            json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": { "name": "echo_request", "arguments": {} }
            }),
        )
        .await?,
    )
    .await?;
    let err = call2.get("error").context("expected error")?;
    assert_eq!(err.get("code"), Some(&json!(-32030)));
    assert_eq!(err.get("message"), Some(&json!("quota exceeded")));
    Ok(())
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn mode3_rate_limit_blocks_subsequent_tools_call_and_sets_retry_after() -> anyhow::Result<()>
{
    let pg = start_postgres().await?;
    let upstream = start_mock_upstream().await?;
    let gw = start_gateway_mode3(&pg.database_url).await?;
    let client = reqwest::Client::new();

    admin_create_tenant(&client, &gw.admin_base, "t1").await?;
    admin_create_upstream(
        &client,
        &gw.admin_base,
        "u1",
        &format!("http://127.0.0.1:{}/mcp", upstream.port),
    )
    .await?;
    let profile_id = admin_create_profile(
        &client,
        &gw.admin_base,
        json!({
            "tenantId": "t1",
            "name": "p1",
            "enabled": true,
            "allowPartialUpstreams": true,
            "upstreams": ["u1"],
            "tools": [],
            "dataPlaneLimits": { "rateLimitEnabled": true, "rateLimitToolCallsPerMinute": 1 }
        }),
    )
    .await?;
    let t1_token = admin_issue_tenant_token(&client, &gw.admin_base, "t1").await?;
    let (api_key, _) =
        tenant_create_api_key(&client, &gw.admin_base, &t1_token, &profile_id).await?;
    let session_id =
        mcp_initialize_with_api_key(&client, &gw.data_base, &profile_id, &api_key).await?;

    // First tools/call should succeed, then we should be rate-limited within the same minute.
    let call1 = read_first_event_stream_json_message(
        post_mcp(
            &client,
            &profile_mcp_url(&gw.data_base, &profile_id),
            Some(&session_id),
            Some(&api_key),
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": { "name": "echo_request", "arguments": {} }
            }),
        )
        .await?,
    )
    .await?;
    anyhow::ensure!(call1.get("result").is_some(), "expected result for call1");

    // Second and/or third should be rate limited (handle minute-boundary edge).
    let mut saw_rate_limited = false;
    for (id, attempt) in [(2, "call2"), (3, "call3")] {
        let msg = read_first_event_stream_json_message(
            post_mcp(
                &client,
                &profile_mcp_url(&gw.data_base, &profile_id),
                Some(&session_id),
                Some(&api_key),
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "method": "tools/call",
                    "params": { "name": "echo_request", "arguments": {} }
                }),
            )
            .await?,
        )
        .await?;

        if let Some(err) = msg.get("error") {
            assert_eq!(err.get("code"), Some(&json!(-32029)));
            assert_eq!(err.get("message"), Some(&json!("rate limit exceeded")));
            let retry = err
                .get("data")
                .and_then(|d| d.get("retryAfterSecs"))
                .and_then(serde_json::Value::as_u64)
                .context("expected error.data.retryAfterSecs")?;
            anyhow::ensure!(retry <= 60, "unexpected retryAfterSecs={retry}");
            saw_rate_limited = true;
            break;
        }

        anyhow::ensure!(
            msg.get("result").is_some(),
            "expected {attempt} to have result or be rate limited"
        );
    }
    anyhow::ensure!(saw_rate_limited, "expected to observe rate limiting");
    Ok(())
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn mode3_revoked_api_key_breaks_authenticated_session() -> anyhow::Result<()> {
    let pg = start_postgres().await?;
    let upstream = start_mock_upstream().await?;
    let gw = start_gateway_mode3(&pg.database_url).await?;
    let client = reqwest::Client::new();

    // Provision tenant + upstream + profile (default data-plane auth mode is API key).
    admin_create_tenant(&client, &gw.admin_base, "t1").await?;
    admin_create_upstream(
        &client,
        &gw.admin_base,
        "u1",
        &format!("http://127.0.0.1:{}/mcp", upstream.port),
    )
    .await?;
    let profile_id = admin_create_profile(
        &client,
        &gw.admin_base,
        json!({
            "tenantId": "t1",
            "name": "p1",
            "enabled": true,
            "allowPartialUpstreams": true,
            "upstreams": ["u1"],
            "tools": []
        }),
    )
    .await?;

    let t1_token = admin_issue_tenant_token(&client, &gw.admin_base, "t1").await?;
    let (api_key, api_key_id) =
        tenant_create_api_key(&client, &gw.admin_base, &t1_token, &profile_id).await?;

    let session_id = mcp_initialize_with_api_key(&client, &gw.data_base, &profile_id, &api_key)
        .await
        .context("initialize")?;

    // Confirm session works before revocation.
    let ok = post_mcp_allow_error(
        &client,
        &profile_mcp_url(&gw.data_base, &profile_id),
        Some(&session_id),
        Some(&api_key),
        json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}),
    )
    .await?;
    anyhow::ensure!(ok.status().is_success());

    // Revoke the key via tenant control plane.
    let revoke_resp = client
        .delete(format!("{}/tenant/v1/api-keys/{api_key_id}", gw.admin_base))
        .header("Authorization", format!("Bearer {t1_token}"))
        .send()
        .await
        .context("tenant DELETE /api-keys/{id}")?;
    anyhow::ensure!(
        revoke_resp.status().is_success(),
        "expected revoke to succeed, got {}",
        revoke_resp.status()
    );

    // The revoked key is rejected on subsequent requests.
    let after = post_mcp_allow_error(
        &client,
        &profile_mcp_url(&gw.data_base, &profile_id),
        Some(&session_id),
        Some(&api_key),
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
    )
    .await?;
    anyhow::ensure!(
        after.status() == reqwest::StatusCode::UNAUTHORIZED,
        "expected 401 after revocation, got {}",
        after.status()
    );

    // And re-initialize with the revoked key should fail.
    let reinit = post_mcp_allow_error(
        &client,
        &profile_mcp_url(&gw.data_base, &profile_id),
        None,
        Some(&api_key),
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": { "name": "mode3-revoke-test", "version": "0" }
            }
        }),
    )
    .await?;
    anyhow::ensure!(
        reinit.status() == reqwest::StatusCode::UNAUTHORIZED,
        "expected 401 on initialize with revoked key, got {}",
        reinit.status()
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn oauth_migration_converts_legacy_modes_and_preserves_x_api_key_values() -> anyhow::Result<()>
{
    use sqlx::Row as _;

    let pg = start_postgres_before_oauth_migration().await?;
    let pool = sqlx::PgPool::connect(&pg.database_url).await?;
    sqlx::query("insert into tenants (id) values ('t1')")
        .execute(&pool)
        .await?;
    for (name, mode, accept_x_api_key) in [
        ("legacy-api-init", "api_key_initialize_only", false),
        ("legacy-api-every", "api_key_every_request", true),
        ("legacy-jwt", "jwt_every_request", true),
        ("disabled", "disabled", false),
    ] {
        sqlx::query(
            "insert into profiles (id, tenant_id, name, data_plane_auth_mode, accept_x_api_key) \
             values (gen_random_uuid(), 't1', $1, $2, $3)",
        )
        .bind(name)
        .bind(mode)
        .bind(accept_x_api_key)
        .execute(&pool)
        .await?;
    }

    apply_dbmate_migration_file(&pg.database_url, OAUTH_MIGRATION).await?;
    let rows = sqlx::query(
        "select name, data_plane_auth_mode, accept_x_api_key, oauth_required_scopes \
         from profiles order by name",
    )
    .fetch_all(&pool)
    .await?;
    let actual: Vec<(String, String, bool, Vec<String>)> = rows
        .iter()
        .map(|row| {
            Ok((
                row.try_get("name")?,
                row.try_get("data_plane_auth_mode")?,
                row.try_get("accept_x_api_key")?,
                row.try_get("oauth_required_scopes")?,
            ))
        })
        .collect::<Result<_, sqlx::Error>>()?;
    assert_eq!(
        actual,
        vec![
            (
                "disabled".to_string(),
                "disabled".to_string(),
                false,
                vec![]
            ),
            (
                "legacy-api-every".to_string(),
                "api_key".to_string(),
                true,
                vec![]
            ),
            (
                "legacy-api-init".to_string(),
                "api_key".to_string(),
                false,
                vec![]
            ),
            (
                "legacy-jwt".to_string(),
                "oauth".to_string(),
                true,
                vec!["mcp:access".to_string()]
            ),
        ]
    );

    sqlx::query("insert into profiles (id, tenant_id, name) values (gen_random_uuid(), 't1', 'new-default')")
        .execute(&pool)
        .await?;
    let default = sqlx::query(
        "select data_plane_auth_mode, accept_x_api_key, oauth_required_scopes \
         from profiles where name = 'new-default'",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(
        default.try_get::<String, _>("data_plane_auth_mode")?,
        "api_key"
    );
    assert!(!default.try_get::<bool, _>("accept_x_api_key")?);
    assert!(
        default
            .try_get::<Vec<String>, _>("oauth_required_scopes")?
            .is_empty()
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn mode3_rejects_oauth_profiles_and_partial_runtime_configuration() -> anyhow::Result<()> {
    let pg = start_postgres().await?;
    let gw = start_gateway_mode3(&pg.database_url).await?;
    let client = reqwest::Client::new();
    admin_create_tenant(&client, &gw.admin_base, "t1").await?;

    let response = client
        .post(format!("{}/admin/v1/profiles", gw.admin_base))
        .header("Authorization", format!("Bearer {ADMIN_TOKEN}"))
        .json(&json!({
            "tenantId": "t1",
            "name": "oauth-without-runtime",
            "enabled": true,
            "allowPartialUpstreams": true,
            "upstreams": [],
            "dataPlaneAuth": { "mode": "oauth", "requiredScopes": ["mcp:access"] }
        }))
        .send()
        .await?;
    anyhow::ensure!(response.status() == reqwest::StatusCode::BAD_REQUEST);
    drop(gw);

    let error = match common::spawn_gateway_with_env(
        &pg.database_url,
        Some(ADMIN_TOKEN),
        SESSION_SECRET,
        &[(
            "UNRELATED_GATEWAY_PUBLIC_DATA_BASE_URL",
            TEST_PUBLIC_DATA_BASE_URL,
        )],
    ) {
        Ok(spawned) => {
            drop(KillOnDrop(spawned.child));
            anyhow::bail!("gateway started with partial OAuth configuration");
        }
        Err(error) => error,
    };
    anyhow::ensure!(
        format!("{error:#}").contains("partial OAuth configuration"),
        "unexpected startup error: {error:#}"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
#[allow(clippy::too_many_lines)]
async fn mode3_oauth_enforces_profile_scoped_and_tenant_wide_principal_bindings()
-> anyhow::Result<()> {
    let kid = "test-kid";
    let (pem, jwks_json) = generate_test_keypair_and_jwks(kid)?;
    let jwks = start_jwks_server(jwks_json).await?;
    let pg = start_postgres().await?;
    let upstream = start_mock_upstream().await?;
    let gw = start_gateway_mode3_with_oauth(&pg.database_url, &jwks.jwks_uri).await?;

    let client = reqwest::Client::new();
    admin_create_tenant(&client, &gw.admin_base, "t1").await?;
    admin_create_upstream(
        &client,
        &gw.admin_base,
        "u1",
        &format!("http://127.0.0.1:{}/mcp", upstream.port),
    )
    .await?;

    let profile_body = json!({
        "tenantId": "t1",
        "name": "p1",
        "enabled": true,
        "allowPartialUpstreams": true,
        "upstreams": ["u1"],
        "tools": [],
        "dataPlaneAuth": { "mode": "oauth", "requiredScopes": ["mcp:access"] }
    });
    let mut profile_body_2 = profile_body.clone();
    profile_body_2["name"] = json!("p2");
    let p1_id = admin_create_profile(&client, &gw.admin_base, profile_body).await?;
    let p2_id = admin_create_profile(&client, &gw.admin_base, profile_body_2.clone()).await?;

    let mut api_key_profile = profile_body_2.clone();
    api_key_profile["name"] = json!("api-key-profile");
    api_key_profile["dataPlaneAuth"] = json!({ "mode": "apiKey", "acceptXApiKey": false });
    let api_key_profile_id = admin_create_profile(&client, &gw.admin_base, api_key_profile).await?;

    let mut disabled_auth_profile = profile_body_2.clone();
    disabled_auth_profile["name"] = json!("disabled-auth-profile");
    disabled_auth_profile["dataPlaneAuth"] = json!({ "mode": "disabled" });
    let disabled_auth_profile_id =
        admin_create_profile(&client, &gw.admin_base, disabled_auth_profile).await?;

    let mut disabled_profile = profile_body_2.clone();
    disabled_profile["name"] = json!("disabled-profile");
    disabled_profile["enabled"] = json!(false);
    let disabled_profile_id =
        admin_create_profile(&client, &gw.admin_base, disabled_profile).await?;

    let metadata = client
        .get(format!(
            "{}/.well-known/oauth-protected-resource/{p1_id}/mcp",
            gw.data_base
        ))
        .send()
        .await?;
    anyhow::ensure!(metadata.status().is_success());
    anyhow::ensure!(
        metadata
            .headers()
            .get("cache-control")
            .and_then(|v| v.to_str().ok())
            == Some("no-store")
    );
    let metadata: serde_json::Value = metadata.json().await?;
    anyhow::ensure!(
        metadata["resource"] == json!(format!("{TEST_PUBLIC_DATA_BASE_URL}/{p1_id}/mcp"))
    );
    for metadata_path in [
        format!("/.well-known/oauth-protected-resource/{api_key_profile_id}/mcp"),
        format!("/.well-known/oauth-protected-resource/{disabled_auth_profile_id}/mcp"),
        format!("/.well-known/oauth-protected-resource/{disabled_profile_id}/mcp"),
        format!(
            "/.well-known/oauth-protected-resource/{}/mcp",
            uuid::Uuid::new_v4()
        ),
        "/.well-known/oauth-protected-resource/not-a-uuid/mcp".to_string(),
    ] {
        let response = client
            .get(format!("{}{}", gw.data_base, metadata_path))
            .send()
            .await?;
        anyhow::ensure!(response.status() == reqwest::StatusCode::NOT_FOUND);
    }

    let x_api_key_only = client
        .post(profile_mcp_url(&gw.data_base, &p1_id))
        .header("Accept", "application/json, text/event-stream")
        .header("Content-Type", "application/json")
        .header("X-API-Key", "must-be-ignored")
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 9,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": { "name": "mode3-oauth-test", "version": "0" }
            }
        }))
        .send()
        .await?;
    anyhow::ensure!(x_api_key_only.status() == reqwest::StatusCode::UNAUTHORIZED);
    let challenge = x_api_key_only
        .headers()
        .get("www-authenticate")
        .and_then(|value| value.to_str().ok())
        .context("missing OAuth challenge")?;
    anyhow::ensure!(challenge.contains("resource_metadata="));
    anyhow::ensure!(!challenge.contains("error="));

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("time")?
        .as_secs();
    let p1_resource = format!("{TEST_PUBLIC_DATA_BASE_URL}/{p1_id}/mcp");
    let p2_resource = format!("{TEST_PUBLIC_DATA_BASE_URL}/{p2_id}/mcp");
    let jwt_p1 = sign_rs256_jwt(
        &pem,
        kid,
        "user1",
        TEST_OAUTH_ISSUER,
        json!(&p1_resource),
        json!("mcp:access"),
        now,
    )?;

    let wrong_issuer = sign_rs256_jwt(
        &pem,
        kid,
        "user1",
        "https://wrong-issuer.example",
        json!(&p1_resource),
        json!(["mcp:access"]),
        now,
    )?;
    let invalid =
        mcp_initialize_with_jwt_allow_error(&client, &gw.data_base, &p1_id, &wrong_issuer, 10)
            .await?;
    anyhow::ensure!(invalid.status() == reqwest::StatusCode::UNAUTHORIZED);
    anyhow::ensure!(
        invalid
            .headers()
            .get("www-authenticate")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.contains("error=\"invalid_token\""))
    );

    let wrong_audience = sign_rs256_jwt(
        &pem,
        kid,
        "user1",
        TEST_OAUTH_ISSUER,
        json!("https://mcp.example.com/wrong/mcp"),
        json!("mcp:access"),
        now,
    )?;
    let invalid =
        mcp_initialize_with_jwt_allow_error(&client, &gw.data_base, &p1_id, &wrong_audience, 11)
            .await?;
    anyhow::ensure!(invalid.status() == reqwest::StatusCode::UNAUTHORIZED);

    let missing_scope = sign_rs256_jwt(
        &pem,
        kid,
        "user1",
        TEST_OAUTH_ISSUER,
        json!(&p1_resource),
        json!(["tools:read"]),
        now,
    )?;
    let insufficient =
        mcp_initialize_with_jwt_allow_error(&client, &gw.data_base, &p1_id, &missing_scope, 12)
            .await?;
    anyhow::ensure!(insufficient.status() == reqwest::StatusCode::FORBIDDEN);
    anyhow::ensure!(
        insufficient
            .headers()
            .get("www-authenticate")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.contains("error=\"insufficient_scope\""))
    );

    let denied =
        mcp_initialize_with_jwt_allow_error(&client, &gw.data_base, &p1_id, &jwt_p1, 0).await?;
    anyhow::ensure!(denied.status() == reqwest::StatusCode::FORBIDDEN);

    let _ = admin_put(
        &client,
        &gw.admin_base,
        "/admin/v1/tenants/t1/oidc-principals",
        json!({"subject": "user1", "profileId": p1_id, "enabled": true}),
    )
    .await?;

    let init_p1 =
        mcp_initialize_with_jwt_allow_error(&client, &gw.data_base, &p1_id, &jwt_p1, 1).await?;
    anyhow::ensure!(init_p1.status().is_success());
    let session_id = init_p1
        .headers()
        .get("Mcp-Session-Id")
        .and_then(|h| h.to_str().ok())
        .context("missing Mcp-Session-Id header")?
        .to_string();
    let _ = read_first_event_stream_json_message(init_p1).await?;

    let list_ok = post_mcp_allow_error(
        &client,
        &profile_mcp_url(&gw.data_base, &p1_id),
        Some(&session_id),
        Some(&jwt_p1),
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
    )
    .await?;
    anyhow::ensure!(list_ok.status().is_success());

    let jwt_both = sign_rs256_jwt(
        &pem,
        kid,
        "user1",
        TEST_OAUTH_ISSUER,
        json!([p1_resource, p2_resource]),
        json!(["mcp:access"]),
        now,
    )?;
    let denied_p2 =
        mcp_initialize_with_jwt_allow_error(&client, &gw.data_base, &p2_id, &jwt_both, 3).await?;
    anyhow::ensure!(denied_p2.status() == reqwest::StatusCode::FORBIDDEN);

    let _ = admin_put(
        &client,
        &gw.admin_base,
        "/admin/v1/tenants/t1/oidc-principals",
        json!({"subject": "user1", "enabled": true}),
    )
    .await?;

    let allowed_p2 =
        mcp_initialize_with_jwt_allow_error(&client, &gw.data_base, &p2_id, &jwt_both, 4).await?;
    anyhow::ensure!(allowed_p2.status().is_success());

    drop(gw);
    match spawn_gateway(&pg.database_url, Some(ADMIN_TOKEN), SESSION_SECRET) {
        Ok(spawned) => {
            drop(KillOnDrop(spawned.child));
            anyhow::bail!("gateway started without OAuth despite persisted OAuth profiles");
        }
        Err(error) => {
            let detail = format!("{error:#}");
            anyhow::ensure!(
                detail.contains("persisted OAuth profiles exist"),
                "unexpected startup error: {error:#}"
            );
        }
    }
    Ok(())
}
