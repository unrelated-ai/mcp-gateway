use crate::{
    catalog::{self, CachedCatalog},
    config::{AuthMode, ContextConfig},
    credentials::{self, KeychainCredentialStore},
};
use anyhow::{Context as _, bail};
use rmcp::{
    ClientHandler, RoleClient, ServiceExt as _,
    model::{
        CallToolRequestParams, CallToolResult, ClientCapabilities, ClientInfo, Implementation,
        JsonObject, Tool,
    },
    service::{NotificationContext, RunningService},
    transport::{
        AuthClient, AuthorizationManager, AuthorizationRequest, AuthorizationSession,
        CredentialStore as _, StoredCredentials, StreamableHttpClientTransport,
        auth::OAuthClientConfig, streamable_http_client::StreamableHttpClientTransportConfig,
    },
};
use std::{
    borrow::Cow,
    io::Write as _,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpListener,
};
use url::Url;

#[derive(Clone, Default)]
pub struct GatewayClientHandler {
    tools_changed: Arc<AtomicBool>,
}

impl GatewayClientHandler {
    #[must_use]
    pub fn take_tools_changed(&self) -> bool {
        self.tools_changed.swap(false, Ordering::AcqRel)
    }
}

impl ClientHandler for GatewayClientHandler {
    fn get_info(&self) -> ClientInfo {
        ClientInfo::new(
            ClientCapabilities::default(),
            Implementation::new("unrelated", env!("CARGO_PKG_VERSION")),
        )
    }

    async fn on_tool_list_changed(&self, _context: NotificationContext<RoleClient>) {
        self.tools_changed.store(true, Ordering::Release);
    }
}

pub type GatewayConnection = RunningService<RoleClient, GatewayClientHandler>;

pub async fn connect(
    context_name: &str,
    context: &ContextConfig,
    timeout: Duration,
) -> anyhow::Result<GatewayConnection> {
    let connection = connect_with_auth(context_name, context, timeout).await?;
    // The CLI catalog owns freshness; upstream errors must still reach callers.
    connection
        .set_response_cache_config(rmcp::service::ClientCacheConfig::disabled())
        .await;
    Ok(connection)
}

#[allow(clippy::too_many_lines)]
async fn connect_with_auth(
    context_name: &str,
    context: &ContextConfig,
    timeout: Duration,
) -> anyhow::Result<GatewayConnection> {
    let handler = GatewayClientHandler::default();
    let http = reqwest::Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("failed to build HTTP client")?;
    let config = StreamableHttpClientTransportConfig::with_uri(context.mcp_url.clone())
        .reinit_on_expired_session(true);

    if let Ok(token) = std::env::var("UNRELATED_TOKEN") {
        if token.trim().is_empty() {
            bail!("UNRELATED_TOKEN is set but empty");
        }
        let transport = StreamableHttpClientTransport::with_client(http, config.auth_header(token));
        return tokio::time::timeout(timeout, handler.serve(transport))
            .await
            .context("MCP connection timed out")?
            .context("failed to initialize MCP connection");
    }

    match context.auth {
        AuthMode::Oauth => {
            let mut manager = AuthorizationManager::new(context.mcp_url.clone())
                .await
                .context("failed to initialize OAuth discovery")?;
            manager.set_credential_store(KeychainCredentialStore::new(context_name));
            if !manager
                .initialize_from_store()
                .await
                .context("failed to load OAuth credentials")?
            {
                bail!("OAuth login required; run `unrelated auth login`");
            }
            let transport =
                StreamableHttpClientTransport::with_client(AuthClient::new(http, manager), config);
            tokio::time::timeout(timeout, handler.serve(transport))
                .await
                .context("MCP connection timed out")?
                .context("failed to initialize authenticated MCP connection")
        }
        AuthMode::Auto => {
            let mut manager = AuthorizationManager::new(context.mcp_url.clone())
                .await
                .context("failed to initialize OAuth discovery")?;
            manager.set_credential_store(KeychainCredentialStore::new(context_name));
            if manager
                .initialize_from_store()
                .await
                .context("failed to load OAuth credentials")?
            {
                let transport = StreamableHttpClientTransport::with_client(
                    AuthClient::new(http, manager),
                    config,
                );
                tokio::time::timeout(timeout, handler.serve(transport))
                    .await
                    .context("MCP connection timed out")?
                    .context("failed to initialize authenticated MCP connection")
            } else if let Some(token) = credentials::load_api_key(context_name).await? {
                let transport =
                    StreamableHttpClientTransport::with_client(http, config.auth_header(token));
                tokio::time::timeout(timeout, handler.serve(transport))
                    .await
                    .context("MCP connection timed out")?
                    .context("failed to initialize API-key MCP connection")
            } else {
                match detect_auth_mode(context).await? {
                    AuthMode::None => {
                        let transport = StreamableHttpClientTransport::with_client(http, config);
                        tokio::time::timeout(timeout, handler.serve(transport))
                            .await
                            .context("MCP connection timed out")?
                            .context("failed to initialize MCP connection")
                    }
                    AuthMode::Oauth => {
                        bail!("OAuth login required; run `unrelated auth login`")
                    }
                    AuthMode::ApiKey => {
                        bail!("API key login required; run `unrelated auth login`")
                    }
                    AuthMode::Auto => unreachable!("authentication probes never return auto"),
                }
            }
        }
        AuthMode::ApiKey => {
            let token = credentials::load_api_key(context_name)
                .await?
                .context("API key login required; run `unrelated auth login`")?;
            let transport =
                StreamableHttpClientTransport::with_client(http, config.auth_header(token));
            tokio::time::timeout(timeout, handler.serve(transport))
                .await
                .context("MCP connection timed out")?
                .context("failed to initialize API-key MCP connection")
        }
        AuthMode::None => {
            let transport = StreamableHttpClientTransport::with_client(http, config);
            tokio::time::timeout(timeout, handler.serve(transport))
                .await
                .context("MCP connection timed out")?
                .context("failed to initialize MCP connection")
        }
    }
}

pub async fn detect_auth_mode(context: &ContextConfig) -> anyhow::Result<AuthMode> {
    let response = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()?
        .post(&context.mcp_url)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header(
            reqwest::header::ACCEPT,
            "application/json, text/event-stream",
        )
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "unrelated-auth-probe", "version": env!("CARGO_PKG_VERSION")}
            }
        }))
        .send()
        .await
        .context("authentication probe failed")?;
    if response.status().is_success() {
        return Ok(AuthMode::None);
    }
    let oauth_challenge = response
        .headers()
        .get(reqwest::header::WWW_AUTHENTICATE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.to_ascii_lowercase().contains("resource_metadata"));
    Ok(if oauth_challenge {
        AuthMode::Oauth
    } else {
        AuthMode::ApiKey
    })
}

pub async fn fetch_catalog(connection: &GatewayConnection) -> anyhow::Result<CachedCatalog> {
    let tools = connection
        .peer()
        .list_all_tools()
        .await
        .context("tools/list failed")?;
    Ok(CachedCatalog::fresh(tools))
}

pub async fn call_tool(
    connection: &GatewayConnection,
    tool: &Tool,
    arguments: JsonObject,
    timeout: Duration,
) -> anyhow::Result<CallToolResult> {
    validate_arguments(tool, &arguments)?;
    let params =
        CallToolRequestParams::new(Cow::Owned(tool.name.to_string())).with_arguments(arguments);
    tokio::time::timeout(timeout, connection.peer().call_tool(params))
        .await
        .context("tool call timed out")?
        .context("tools/call failed")
}

pub fn validate_arguments(tool: &Tool, arguments: &JsonObject) -> anyhow::Result<()> {
    let schema = serde_json::Value::Object(tool.input_schema.as_ref().clone());
    let validator = jsonschema::options()
        .with_retriever(NoExternalSchemas)
        .build(&schema)
        .context("tool has an invalid input schema")?;
    let value = serde_json::Value::Object(arguments.clone());
    let errors: Vec<String> = validator
        .iter_errors(&value)
        .map(|error| error.to_string())
        .collect();
    if !errors.is_empty() {
        bail!(
            "input does not match the tool schema: {}",
            errors.join("; ")
        );
    }
    Ok(())
}

struct NoExternalSchemas;

impl jsonschema::Retrieve for NoExternalSchemas {
    fn retrieve(
        &self,
        uri: &jsonschema::Uri<String>,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error + Send + Sync>> {
        Err(format!("external schema retrieval is disabled: {uri}").into())
    }
}

pub async fn oauth_login(
    context_name: &str,
    context: &ContextConfig,
    no_browser: bool,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .context("failed to bind OAuth loopback callback")?;
    let address = listener.local_addr()?;
    let redirect_uri = format!("http://127.0.0.1:{}/callback", address.port());

    let prepared = prepare_oauth_login(
        context,
        &redirect_uri,
        KeychainCredentialStore::new(context_name),
    )
    .await?;
    let callback_url = complete_browser_flow(
        &listener,
        &redirect_uri,
        prepared.authorization_url(),
        no_browser,
    )
    .await?;
    prepared.complete(&callback_url).await
}

enum PreparedOAuthLogin {
    Preconfigured {
        manager: AuthorizationManager,
        authorization_url: String,
    },
    Dynamic(AuthorizationSession),
}

impl PreparedOAuthLogin {
    fn authorization_url(&self) -> &str {
        match self {
            Self::Preconfigured {
                authorization_url, ..
            } => authorization_url,
            Self::Dynamic(session) => session.get_authorization_url(),
        }
    }

    async fn complete(self, callback_url: &str) -> anyhow::Result<()> {
        match self {
            Self::Preconfigured { manager, .. } => {
                let callback = Url::parse(callback_url).context("invalid OAuth callback URL")?;
                let parameters: std::collections::HashMap<_, _> =
                    callback.query_pairs().into_owned().collect();
                let code = parameters
                    .get("code")
                    .context("OAuth callback is missing code")?;
                let state = parameters
                    .get("state")
                    .context("OAuth callback is missing state")?;
                manager
                    .exchange_code_for_token_with_issuer(
                        code,
                        state,
                        parameters.get("iss").map(String::as_str),
                    )
                    .await
                    .context("OAuth token exchange failed")?;
            }
            Self::Dynamic(session) => {
                session
                    .handle_callback_url(callback_url)
                    .await
                    .context("OAuth token exchange failed")?;
            }
        }
        Ok(())
    }
}

async fn prepare_oauth_login<S>(
    context: &ContextConfig,
    redirect_uri: &str,
    credential_store: S,
) -> anyhow::Result<PreparedOAuthLogin>
where
    S: rmcp::transport::CredentialStore + 'static,
{
    let mut manager = AuthorizationManager::new(context.mcp_url.clone())
        .await
        .context("failed to initialize OAuth")?;
    manager.set_credential_store(credential_store);
    let metadata = manager
        .resolve_metadata()
        .await
        .context("OAuth metadata discovery failed")?;
    manager.set_metadata(metadata.metadata);
    let scopes = manager.select_scopes(None, &["mcp:access"]);
    let scope_refs: Vec<&str> = scopes.iter().map(String::as_str).collect();

    if let Some(client_id) = context.oauth_client_id.as_deref() {
        manager.configure_client(
            OAuthClientConfig::new(client_id, redirect_uri).with_scopes(scopes.clone()),
        )?;
        let authorization_url = manager.get_authorization_url(&scope_refs).await?;
        Ok(PreparedOAuthLogin::Preconfigured {
            manager,
            authorization_url,
        })
    } else {
        let session = AuthorizationSession::new(
            manager,
            AuthorizationRequest::new(redirect_uri)
                .with_scopes(scopes)
                .with_client_name("Unrelated CLI"),
        )
        .await
        .map_err(|(_, error)| error)
        .context("OAuth client registration failed")?;
        Ok(PreparedOAuthLogin::Dynamic(session))
    }
}

async fn complete_browser_flow(
    listener: &TcpListener,
    redirect_uri: &str,
    authorization_url: &str,
    no_browser: bool,
) -> anyhow::Result<String> {
    eprintln!("Open this URL to authorize Unrelated CLI:\n{authorization_url}");
    if no_browser {
        return tokio::task::spawn_blocking(|| {
            eprint!("Paste the final callback URL: ");
            std::io::stderr().flush()?;
            let mut line = String::new();
            std::io::stdin().read_line(&mut line)?;
            Ok::<_, std::io::Error>(line.trim().to_string())
        })
        .await
        .context("callback input task failed")?
        .context("failed to read callback URL");
    }

    webbrowser::open(authorization_url).context("failed to open a browser")?;
    accept_loopback_callback(listener, redirect_uri).await
}

async fn accept_loopback_callback(
    listener: &TcpListener,
    redirect_uri: &str,
) -> anyhow::Result<String> {
    let (mut socket, _) = tokio::time::timeout(Duration::from_secs(300), listener.accept())
        .await
        .context("OAuth callback timed out")??;
    let mut buffer = vec![0_u8; 16 * 1024];
    let length = tokio::time::timeout(Duration::from_secs(10), socket.read(&mut buffer))
        .await
        .context("OAuth callback read timed out")??;
    let request = std::str::from_utf8(&buffer[..length]).context("OAuth callback was not UTF-8")?;
    let target = request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .context("invalid OAuth callback request")?;
    let base = Url::parse(redirect_uri)?;
    let callback = base.join(target)?.to_string();
    let body = "Authorization complete. You can close this window.";
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    socket.write_all(response.as_bytes()).await?;
    Ok(callback)
}

pub async fn oauth_status(context_name: &str, context: &ContextConfig) -> anyhow::Result<bool> {
    let mut manager = AuthorizationManager::new(context.mcp_url.clone()).await?;
    manager.set_credential_store(KeychainCredentialStore::new(context_name));
    manager.initialize_from_store().await.map_err(Into::into)
}

pub async fn logout(context_name: &str, context: &ContextConfig) -> anyhow::Result<()> {
    if matches!(context.auth, AuthMode::Oauth | AuthMode::Auto) {
        let store = KeychainCredentialStore::new(context_name);
        if let Some(stored) = store.load().await?
            && let Err(error) = try_revoke(context, &stored).await
        {
            eprintln!("warning: token revocation failed: {error}");
        }
        store.clear().await?;
    }
    if matches!(context.auth, AuthMode::ApiKey | AuthMode::Auto) {
        credentials::clear_api_key(context_name).await?;
    }
    Ok(())
}

async fn try_revoke(context: &ContextConfig, stored: &StoredCredentials) -> anyhow::Result<()> {
    let manager = AuthorizationManager::new(context.mcp_url.clone()).await?;
    let metadata = manager.resolve_metadata().await?.metadata;
    let endpoint = metadata
        .additional_fields
        .get("revocation_endpoint")
        .and_then(serde_json::Value::as_str)
        .context("authorization server does not advertise token revocation")?;
    let token = stored
        .token_response
        .as_ref()
        .and_then(|token| serde_json::to_value(token).ok())
        .and_then(|token| {
            token
                .get("refresh_token")
                .or_else(|| token.get("access_token"))
                .and_then(serde_json::Value::as_str)
                .map(str::to_string)
        })
        .context("stored OAuth credential contains no revocable token")?;
    let response = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()?
        .post(endpoint)
        .form(&[
            ("token", token.as_str()),
            ("client_id", stored.client_id.as_str()),
        ])
        .send()
        .await?;
    if !response.status().is_success() {
        bail!("revocation endpoint returned HTTP {}", response.status());
    }
    Ok(())
}

pub fn load_or_fetch_catalog<'a>(
    cache_base: &'a std::path::Path,
    context_name: &'a str,
    force_refresh: bool,
) -> anyhow::Result<Option<CachedCatalog>> {
    if force_refresh {
        return Ok(None);
    }
    Ok(catalog::load_cache(cache_base, context_name)?.filter(CachedCatalog::is_fresh))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Json, Router,
        extract::{Query, State},
        http::{StatusCode, header},
        response::{IntoResponse as _, Response},
        routing::{get, post},
    };
    use rmcp::transport::InMemoryCredentialStore;
    use std::collections::HashMap;
    use std::sync::Arc;

    #[test]
    fn validates_arguments_against_tool_schema() {
        let tool = Tool::new(
            "get".to_string(),
            String::new(),
            Arc::new(serde_json::Map::from_iter([
                ("type".into(), serde_json::json!("object")),
                (
                    "properties".into(),
                    serde_json::json!({"id": {"type": "integer"}}),
                ),
                ("required".into(), serde_json::json!(["id"])),
                ("additionalProperties".into(), serde_json::json!(false)),
            ])),
        );
        assert!(
            validate_arguments(
                &tool,
                &serde_json::Map::from_iter([("id".into(), serde_json::json!(1))])
            )
            .is_ok()
        );
        assert!(validate_arguments(&tool, &serde_json::Map::new()).is_err());

        let external = Tool::new(
            "external".to_string(),
            String::new(),
            Arc::new(serde_json::Map::from_iter([(
                "$ref".into(),
                serde_json::json!("http://127.0.0.1/schema.json"),
            )])),
        );
        assert!(validate_arguments(&external, &serde_json::Map::new()).is_err());
    }

    #[tokio::test]
    async fn oauth_pkce_supports_configured_and_dynamic_clients() -> anyhow::Result<()> {
        let (base, server) = start_oauth_server().await?;
        run_oauth_flow(&base, Some("configured-client".to_string())).await?;
        run_oauth_flow(&base, None).await?;
        server.abort();
        Ok(())
    }

    #[tokio::test]
    async fn oauth_rejects_callback_issuer_mismatch() -> anyhow::Result<()> {
        let (base, server) = start_oauth_server().await?;
        let store = InMemoryCredentialStore::new();
        let context = oauth_context(&base, Some("configured-client".to_string()));
        let callback_listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
        let redirect_uri = format!(
            "http://127.0.0.1:{}/callback",
            callback_listener.local_addr()?.port()
        );
        let prepared = prepare_oauth_login(&context, &redirect_uri, store).await?;
        let authorization_url = Url::parse(prepared.authorization_url())?;
        let state = authorization_url
            .query_pairs()
            .find_map(|(key, value)| (key == "state").then(|| value.into_owned()))
            .context("authorization URL missing state")?;
        let callback =
            format!("{redirect_uri}?code=test-code&state={state}&iss=https%3A%2F%2Fevil.example");
        let error = prepared.complete(&callback).await.unwrap_err();
        assert!(format!("{error:#}").contains("issuer"));
        server.abort();
        Ok(())
    }

    async fn run_oauth_flow(base: &str, client_id: Option<String>) -> anyhow::Result<()> {
        let store = InMemoryCredentialStore::new();
        let context = oauth_context(base, client_id);
        let callback_listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
        let redirect_uri = format!(
            "http://127.0.0.1:{}/callback",
            callback_listener.local_addr()?.port()
        );
        let prepared = prepare_oauth_login(&context, &redirect_uri, store.clone()).await?;
        let authorization_url = prepared.authorization_url().to_string();
        let opener = tokio::spawn(async move { reqwest::get(authorization_url).await });
        let callback = accept_loopback_callback(&callback_listener, &redirect_uri).await?;
        let response = opener.await??;
        assert!(response.status().is_success());
        prepared.complete(&callback).await?;
        let stored = store.load().await?.context("credentials were not stored")?;
        assert!(stored.token_response.is_some());
        assert!(
            stored
                .granted_scopes
                .iter()
                .any(|scope| scope == "mcp:access")
        );
        Ok(())
    }

    fn oauth_context(base: &str, client_id: Option<String>) -> ContextConfig {
        ContextConfig {
            mcp_url: format!("{base}/profile/mcp"),
            auth: AuthMode::Oauth,
            oauth_client_id: client_id,
        }
    }

    async fn start_oauth_server() -> anyhow::Result<(String, tokio::task::JoinHandle<()>)> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let base = format!("http://{}", listener.local_addr()?);
        let app = Router::new()
            .route("/profile/mcp", get(|| async { StatusCode::NOT_FOUND }))
            .route(
                "/.well-known/oauth-protected-resource/profile/mcp",
                get(resource_metadata),
            )
            .route(
                "/.well-known/oauth-authorization-server",
                get(authorization_metadata),
            )
            .route("/register", post(register_client))
            .route("/authorize", get(authorize))
            .route("/token", post(exchange_token))
            .with_state(base.clone());
        let server = tokio::spawn(async move {
            if let Err(error) = axum::serve(listener, app).await {
                panic!("OAuth test server failed: {error}");
            }
        });
        Ok((base, server))
    }

    async fn resource_metadata(State(base): State<String>) -> Json<serde_json::Value> {
        Json(serde_json::json!({
            "resource": format!("{base}/profile/mcp"),
            "authorization_servers": [base],
            "scopes_supported": ["mcp:access"]
        }))
    }

    async fn authorization_metadata(State(base): State<String>) -> Json<serde_json::Value> {
        Json(serde_json::json!({
            "issuer": base,
            "authorization_endpoint": format!("{base}/authorize"),
            "token_endpoint": format!("{base}/token"),
            "registration_endpoint": format!("{base}/register"),
            "scopes_supported": ["mcp:access", "offline_access"],
            "response_types_supported": ["code"],
            "code_challenge_methods_supported": ["S256"],
            "authorization_response_iss_parameter_supported": true
        }))
    }

    async fn register_client(Json(body): Json<serde_json::Value>) -> Json<serde_json::Value> {
        Json(serde_json::json!({
            "client_id": "dynamic-client",
            "client_name": "Unrelated CLI",
            "redirect_uris": body["redirect_uris"]
        }))
    }

    async fn authorize(
        State(base): State<String>,
        Query(parameters): Query<HashMap<String, String>>,
    ) -> Response {
        let valid = parameters.get("code_challenge_method").map(String::as_str) == Some("S256")
            && parameters.contains_key("code_challenge")
            && parameters.get("resource").map(String::as_str)
                == Some(format!("{base}/profile/mcp").as_str());
        if !valid {
            return StatusCode::BAD_REQUEST.into_response();
        }
        let Some(redirect_uri) = parameters.get("redirect_uri") else {
            return StatusCode::BAD_REQUEST.into_response();
        };
        let Some(state) = parameters.get("state") else {
            return StatusCode::BAD_REQUEST.into_response();
        };
        let separator = if redirect_uri.contains('?') { '&' } else { '?' };
        let location = format!(
            "{redirect_uri}{separator}code=test-code&state={state}&iss={}",
            url::form_urlencoded::byte_serialize(base.as_bytes()).collect::<String>()
        );
        (StatusCode::FOUND, [(header::LOCATION, location)]).into_response()
    }

    async fn exchange_token(
        axum::Form(parameters): axum::Form<HashMap<String, String>>,
    ) -> Response {
        if parameters.get("code").map(String::as_str) != Some("test-code")
            || !parameters.contains_key("code_verifier")
        {
            return StatusCode::BAD_REQUEST.into_response();
        }
        Json(serde_json::json!({
            "access_token": "test-access-token",
            "refresh_token": "test-refresh-token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": "mcp:access offline_access"
        }))
        .into_response()
    }
}
