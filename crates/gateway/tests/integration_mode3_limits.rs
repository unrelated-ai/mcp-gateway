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
use rmcp::model::{
    CallToolResult, ClientJsonRpcMessage, ClientRequest, Content, InitializeResult, JsonObject,
    JsonRpcRequest, JsonRpcResponse, JsonRpcVersion2_0, ListToolsResult, ServerCapabilities,
    ServerJsonRpcMessage, ServerResult, Tool,
};
use serde_json::json;
use std::{collections::HashSet, convert::Infallible, process::Command, sync::Arc, time::Duration};
use testcontainers::core::IntoContainerPort;
use testcontainers::runners::AsyncRunner;
use testcontainers::{GenericImage, ImageExt as _};
use tokio::sync::Mutex;

const ADMIN_TOKEN: &str = "test-admin-token";
const SESSION_SECRET: &str = "test-session-secret";
const TEST_OIDC_ISSUER: &str = "https://issuer.example";

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

async fn start_gateway_mode3_with_oidc(
    database_url: &str,
    jwks_uri: &str,
) -> anyhow::Result<Gateway> {
    let gw = spawn_gateway_with_oidc(database_url, jwks_uri)?;
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

fn sign_rs256_jwt(pem: &str, kid: &str, subject: &str, now: u64) -> anyhow::Result<String> {
    use jsonwebtoken::{Algorithm, EncodingKey, Header};

    let claims = json!({
        "iss": TEST_OIDC_ISSUER,
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
                "clientInfo": { "name": "mode3-oidc-test", "version": "0" }
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

fn spawn_gateway_with_oidc(
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
        .env("UNRELATED_GATEWAY_OIDC_ISSUER", TEST_OIDC_ISSUER)
        .env("UNRELATED_GATEWAY_OIDC_JWKS_URI", jwks_uri)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context("spawn gateway with oidc")?;
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
            None,
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
            None,
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
            None,
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
                None,
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
async fn mode3_revoked_api_key_breaks_session_for_initialize_only_mode() -> anyhow::Result<()> {
    let pg = start_postgres().await?;
    let upstream = start_mock_upstream().await?;
    let gw = start_gateway_mode3(&pg.database_url).await?;
    let client = reqwest::Client::new();

    // Provision tenant + upstream + profile (default data-plane auth mode is ApiKeyInitializeOnly).
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
        None,
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

    // Now, in ApiKeyInitializeOnly mode, the gateway should reject follow-ups because it checks
    // the key is still active on every request.
    let after = post_mcp_allow_error(
        &client,
        &profile_mcp_url(&gw.data_base, &profile_id),
        Some(&session_id),
        None,
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
async fn mode3_jwt_every_request_enforces_profile_scoped_and_tenant_wide_oidc_bindings()
-> anyhow::Result<()> {
    let kid = "test-kid";
    let (pem, jwks_json) = generate_test_keypair_and_jwks(kid)?;
    let jwks = start_jwks_server(jwks_json).await?;
    let pg = start_postgres().await?;
    let upstream = start_mock_upstream().await?;
    let gw = start_gateway_mode3_with_oidc(&pg.database_url, &jwks.jwks_uri).await?;

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
        "dataPlaneAuth": { "mode": "jwtEveryRequest" }
    });
    let mut profile_body_2 = profile_body.clone();
    profile_body_2["name"] = json!("p2");
    let p1_id = admin_create_profile(&client, &gw.admin_base, profile_body).await?;
    let p2_id = admin_create_profile(&client, &gw.admin_base, profile_body_2).await?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("time")?
        .as_secs();
    let jwt = sign_rs256_jwt(&pem, kid, "user1", now)?;

    let denied =
        mcp_initialize_with_jwt_allow_error(&client, &gw.data_base, &p1_id, &jwt, 0).await?;
    anyhow::ensure!(denied.status() == reqwest::StatusCode::UNAUTHORIZED);

    let _ = admin_put(
        &client,
        &gw.admin_base,
        "/admin/v1/tenants/t1/oidc-principals",
        json!({"subject": "user1", "profileId": p1_id, "enabled": true}),
    )
    .await?;

    let init_p1 =
        mcp_initialize_with_jwt_allow_error(&client, &gw.data_base, &p1_id, &jwt, 1).await?;
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
        Some(&jwt),
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
    )
    .await?;
    anyhow::ensure!(list_ok.status().is_success());

    let denied_p2 =
        mcp_initialize_with_jwt_allow_error(&client, &gw.data_base, &p2_id, &jwt, 3).await?;
    anyhow::ensure!(denied_p2.status() == reqwest::StatusCode::UNAUTHORIZED);

    let _ = admin_put(
        &client,
        &gw.admin_base,
        "/admin/v1/tenants/t1/oidc-principals",
        json!({"subject": "user1", "enabled": true}),
    )
    .await?;

    let allowed_p2 =
        mcp_initialize_with_jwt_allow_error(&client, &gw.data_base, &p2_id, &jwt, 4).await?;
    anyhow::ensure!(allowed_p2.status().is_success());
    Ok(())
}
