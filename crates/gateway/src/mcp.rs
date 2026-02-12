use crate::audit::AuditSink;
use crate::catalog::SharedCatalog;
use crate::contracts::ContractTracker;
use crate::oidc::OidcValidator;
use crate::session_token::{
    SessionSigner, SessionTokenVerifyError, SessionTokenVerifyErrorKind, TokenAuthV1, TokenOidcV1,
    TokenPayloadV1, UpstreamSessionBinding,
};
use crate::store::{
    DataPlaneAuthMode, EffectiveMcpCapabilities, RequestIdNamespacing, SseEventIdNamespacing,
    Store, ToolCallLimitRejection,
};
use crate::tenant_catalog::TenantCatalog;
use crate::{
    contracts::ContractEvent, contracts::list_changed_notification_json,
    pg_fanout::PgContractFanout,
};
use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response, Sse},
};
use base64::Engine as _;
use futures::{Stream, StreamExt};
use rmcp::{
    model::{
        CallToolRequestParam, ClientJsonRpcMessage, ClientNotification, ClientRequest, ErrorCode,
        ErrorData, GetPromptRequestParam, InitializeResult, JsonRpcError, JsonRpcNotification,
        JsonRpcRequest, JsonRpcResponse, JsonRpcVersion2_0, ReadResourceRequestParam, Reference,
        RequestId, ServerCapabilities, ServerJsonRpcMessage, ServerNotification, ServerResult,
        SubscribeRequestParam, UnsubscribeRequestParam,
    },
    transport::common::http_header::{
        EVENT_STREAM_MIME_TYPE, HEADER_LAST_EVENT_ID, HEADER_SESSION_ID, JSON_MIME_TYPE,
    },
};
use serde::Serialize;
use std::{collections::HashMap, convert::Infallible, sync::Arc};
use tokio_util::sync::CancellationToken;
use tracing::Instrument as _;
use uuid::{Uuid, Version};

mod auth;
mod ids;
mod probe;
mod streamable_http;
mod surface;
mod tool_call;
mod upstream;
use auth::{
    authenticate_api_key_on_initialize, authorize_jwt_request, enforce_data_plane_auth,
    unauthorized,
};
use ids::{make_proxied_request_id, parse_proxied_request_id, resource_collision_urn};
use surface::{
    aggregate_list_prompts, aggregate_list_resources, aggregate_list_tools, count_resource_uris,
    resolve_prompt_owner, resolve_resource_owner,
};
use tool_call::route_and_proxy_tools_call;
use upstream::{proxy_to_single_upstream, upstream_initialize};

pub(crate) use probe::probe_profile_surface;

// Custom Gateway JSON-RPC server error codes (-32000..-32099 range).
const ERROR_CODE_RATE_LIMIT_EXCEEDED: ErrorCode = ErrorCode(-32029);
const ERROR_CODE_QUOTA_EXCEEDED: ErrorCode = ErrorCode(-32030);

const PROXY_KEY_BYTES: usize = 32;
const CONTRACT_REPLAY_LIMIT: i64 = 1000;
const SSE_PRIMING_RETRY_MS: u64 = 3_000;

fn truncate_string_to_bytes(mut s: String, max_bytes: usize) -> (String, bool) {
    if s.len() <= max_bytes {
        return (s, false);
    }
    let mut cut = max_bytes;
    while cut > 0 && !s.is_char_boundary(cut) {
        cut -= 1;
    }
    s.truncate(cut);
    (s, true)
}

fn truncate_bytes_lossy(bytes: &[u8], max_bytes: usize) -> (String, bool) {
    let truncated = bytes.len() > max_bytes;
    let slice = if truncated {
        &bytes[..max_bytes]
    } else {
        bytes
    };
    (String::from_utf8_lossy(slice).to_string(), truncated)
}

#[derive(Debug)]
struct PayloadLimitExceededAudit<'a> {
    tenant_id: &'a str,
    profile_id: &'a str,
    http_method: &'static str,
    http_route: &'static str,
    status_code: Option<i32>,
    direction: &'static str,
    action_taken: &'static str,
    reason: &'static str,
    metric: &'static str,
    observed: u64,
    limit: u64,
    upstream_id: Option<&'a str>,
    sample: Option<(String, bool)>,
}

async fn record_payload_limit_exceeded(audit: &dyn AuditSink, a: PayloadLimitExceededAudit<'_>) {
    let include_sample = matches!(
        audit.tenant_default_level(a.tenant_id).await,
        crate::audit::AuditLevel::Payload
    );

    let profile_uuid = Uuid::parse_str(a.profile_id).ok();
    let mut meta = serde_json::Map::new();
    meta.insert("direction".to_string(), serde_json::json!(a.direction));
    meta.insert("metric".to_string(), serde_json::json!(a.metric));
    meta.insert("observed".to_string(), serde_json::json!(a.observed));
    meta.insert("limit".to_string(), serde_json::json!(a.limit));
    meta.insert("actionTaken".to_string(), serde_json::json!(a.action_taken));
    meta.insert("reason".to_string(), serde_json::json!(a.reason));
    meta.insert("profileId".to_string(), serde_json::json!(a.profile_id));
    if let Some(upstream_id) = a.upstream_id {
        meta.insert("upstreamId".to_string(), serde_json::json!(upstream_id));
    }

    if include_sample && let Some((s, truncated)) = a.sample {
        meta.insert("sample".to_string(), serde_json::json!(s));
        meta.insert("sampleTruncated".to_string(), serde_json::json!(truncated));
    }

    // Convenience keys for byte-based limits (most common).
    if a.metric == "bytes" {
        meta.insert("bytesObserved".to_string(), serde_json::json!(a.observed));
        meta.insert("limitBytes".to_string(), serde_json::json!(a.limit));
    }

    audit
        .record(crate::audit::AuditEvent {
            tenant_id: a.tenant_id.to_string(),
            profile_id: profile_uuid,
            api_key_id: None,
            oidc_issuer: None,
            oidc_subject: None,
            action: "mcp.payload_limit_exceeded".to_string(),
            http_method: Some(a.http_method.to_string()),
            http_route: Some(a.http_route.to_string()),
            status_code: a.status_code,
            tool_ref: None,
            tool_name_at_time: None,
            ok: false,
            duration_ms: None,
            error_kind: Some("payload_limit_exceeded".to_string()),
            error_message: None,
            meta: serde_json::Value::Object(meta),
        })
        .await;
}

#[derive(Clone)]
pub struct McpState {
    pub store: Arc<dyn Store>,
    pub signer: SessionSigner,
    pub http: reqwest::Client,
    pub oidc: Option<OidcValidator>,
    pub shutdown: CancellationToken,
    pub audit: Arc<dyn AuditSink>,
    pub catalog: Arc<SharedCatalog>,
    pub tenant_catalog: Arc<TenantCatalog>,
    pub contracts: Arc<ContractTracker>,
    pub contract_fanout: Option<Arc<PgContractFanout>>,
    pub tools_cache: Arc<crate::tools_cache::ToolSurfaceCache>,
    pub endpoint_cache: Arc<crate::endpoint_cache::UpstreamEndpointCache>,
}

pub fn router(state: Arc<McpState>) -> axum::Router {
    axum::Router::new()
        .route(
            "/{profile_id}/mcp",
            axum::routing::post(post_mcp)
                .get(get_mcp)
                .delete(delete_mcp),
        )
        // Hard cap to protect the process from unbounded request bodies.
        .layer(DefaultBodyLimit::max(
            usize::try_from(crate::transport_limits::HARD_MAX_POST_BODY_BYTES)
                .unwrap_or(usize::MAX),
        ))
        .with_state(state)
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileSurfaceSource {
    /// `upstream | sharedLocal | tenantLocal`
    pub kind: String,
    pub source_id: String,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub tools_count: usize,
    pub resources_count: usize,
    pub prompts_count: usize,
}

async fn post_mcp(
    Path(profile_id): Path<String>,
    State(state): State<Arc<McpState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    if Uuid::parse_str(&profile_id)
        .ok()
        .and_then(|u| (u.get_version() == Some(Version::Random)).then_some(u))
        .is_none()
    {
        return Err((StatusCode::NOT_FOUND, "profile not found").into_response());
    }

    ensure_accepts_post(&headers).map_err(|(s, m)| (s, m).into_response())?;
    ensure_json_content_type(&headers).map_err(|(s, m)| (s, m).into_response())?;

    let (profile, limits) =
        load_profile_and_effective_transport_limits(state.as_ref(), &profile_id).await?;
    let message =
        parse_post_body_message_with_limits(state.as_ref(), &profile_id, &profile, limits, &body)
            .await?;

    let session_header = headers
        .get(HEADER_SESSION_ID)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    let span = tracing::info_span!(
        "gateway.mcp.post",
        profile_id = %profile_id,
        has_session = session_header.is_some()
    );

    Box::pin(
        async move {
            match session_header {
                None => handle_initialize(&state, &profile_id, &headers, message).await,
                Some(token) => {
                    Box::pin(handle_post_in_session(
                        &state,
                        &profile_id,
                        &headers,
                        token,
                        message,
                    ))
                    .await
                }
            }
        }
        .instrument(span),
    )
    .await
}

async fn load_profile_and_effective_transport_limits(
    state: &McpState,
    profile_id: &str,
) -> Result<
    (
        crate::store::Profile,
        crate::transport_limits::EffectiveTransportLimits,
    ),
    Response,
> {
    // Load profile early so we can apply per-profile / per-tenant transport limits before parsing.
    let profile = state
        .store
        .get_profile(profile_id)
        .await
        .map_err(internal_error_response("load profile"))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "profile not found").into_response())?;

    let tenant_limits = match state
        .store
        .get_tenant_transport_limits(&profile.tenant_id)
        .await
    {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(
                error = %e,
                tenant_id = %profile.tenant_id,
                "load tenant transport limits failed; using defaults"
            );
            None
        }
    };
    let limits = crate::transport_limits::EffectiveTransportLimits::from_profile_and_tenant(
        &profile.mcp.security.transport_limits,
        tenant_limits.as_ref(),
    );

    Ok((profile, limits))
}

async fn parse_post_body_message_with_limits(
    state: &McpState,
    profile_id: &str,
    profile: &crate::store::Profile,
    limits: crate::transport_limits::EffectiveTransportLimits,
    body: &Bytes,
) -> Result<ClientJsonRpcMessage, Response> {
    let ctx = PostBodyLimitsCtx {
        state,
        profile_id,
        profile,
        limits,
    };

    enforce_post_body_bytes_limit(&ctx, body).await?;

    let value: serde_json::Value = serde_json::from_slice(body).map_err(|e| {
        (
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            format!("invalid json: {e}"),
        )
            .into_response()
    })?;

    if limits.has_json_complexity_limits() {
        enforce_post_json_complexity_limit(&ctx, &value, body).await?;
    }

    parse_client_jsonrpc_message(value)
}

struct PostBodyLimitsCtx<'a> {
    state: &'a McpState,
    profile_id: &'a str,
    profile: &'a crate::store::Profile,
    limits: crate::transport_limits::EffectiveTransportLimits,
}

async fn enforce_post_body_bytes_limit(
    ctx: &PostBodyLimitsCtx<'_>,
    body: &Bytes,
) -> Result<(), Response> {
    let observed_bytes = body.len() as u64;
    if observed_bytes <= ctx.limits.max_post_body_bytes {
        return Ok(());
    }

    record_payload_limit_exceeded(
        ctx.state.audit.as_ref(),
        PayloadLimitExceededAudit {
            tenant_id: &ctx.profile.tenant_id,
            profile_id: ctx.profile_id,
            http_method: "POST",
            http_route: "/{profile_id}/mcp",
            status_code: Some(i32::from(StatusCode::PAYLOAD_TOO_LARGE.as_u16())),
            direction: "downstream_request",
            action_taken: "rejected",
            reason: "maxPostBodyBytes",
            metric: "bytes",
            observed: observed_bytes,
            limit: ctx.limits.max_post_body_bytes,
            upstream_id: None,
            sample: Some(truncate_bytes_lossy(body.as_ref(), 4096)),
        },
    )
    .await;

    Err((
        StatusCode::PAYLOAD_TOO_LARGE,
        format!(
            "payload too large (bytes={}, limit={})",
            observed_bytes, ctx.limits.max_post_body_bytes
        ),
    )
        .into_response())
}

async fn enforce_post_json_complexity_limit(
    ctx: &PostBodyLimitsCtx<'_>,
    value: &serde_json::Value,
    body: &Bytes,
) -> Result<(), Response> {
    let Some(vio) = crate::transport_limits::check_json_complexity(value, ctx.limits) else {
        return Ok(());
    };

    record_payload_limit_exceeded(
        ctx.state.audit.as_ref(),
        PayloadLimitExceededAudit {
            tenant_id: &ctx.profile.tenant_id,
            profile_id: ctx.profile_id,
            http_method: "POST",
            http_route: "/{profile_id}/mcp",
            status_code: Some(i32::from(StatusCode::BAD_REQUEST.as_u16())),
            direction: "downstream_request",
            action_taken: "rejected",
            reason: vio.kind,
            metric: "complexity",
            observed: vio.observed,
            limit: vio.limit,
            upstream_id: None,
            sample: Some(truncate_bytes_lossy(body.as_ref(), 4096)),
        },
    )
    .await;

    // Best-effort: if the message has a JSON-RPC `id`, return a JSON-RPC error.
    let req_id = value
        .get("id")
        .cloned()
        .and_then(|v| serde_json::from_value::<RequestId>(v).ok());
    Err(match req_id {
        Some(id) => jsonrpc_error_response_with_data(
            id,
            ErrorCode::INVALID_REQUEST,
            "payload too complex".to_string(),
            Some(serde_json::json!({
                "type": "payload-too-complex",
                "metric": vio.kind,
                "observed": vio.observed,
                "limit": vio.limit,
            })),
        ),
        None => (
            StatusCode::BAD_REQUEST,
            format!(
                "payload too complex ({metric}: observed={observed}, limit={limit})",
                metric = vio.kind,
                observed = vio.observed,
                limit = vio.limit
            ),
        )
            .into_response(),
    })
}

#[allow(clippy::result_large_err)] // Response is intentionally the shared error type for handlers.
fn parse_client_jsonrpc_message(
    value: serde_json::Value,
) -> Result<ClientJsonRpcMessage, Response> {
    // Best-effort: if the message has a JSON-RPC `id`, return a JSON-RPC error instead of an
    // HTTP 415 "invalid json" (the JSON *is* valid; the shape is not).
    let req_id = value
        .get("id")
        .cloned()
        .and_then(|v| serde_json::from_value::<RequestId>(v).ok());
    serde_json::from_value(value).map_err(|e| match req_id {
        Some(id) => jsonrpc_error_response_with_data(
            id,
            ErrorCode::INVALID_REQUEST,
            "Invalid request".to_string(),
            Some(serde_json::json!({
                "type": "invalid-mcp-shape",
                "details": e.to_string(),
            })),
        ),
        None => (
            StatusCode::BAD_REQUEST,
            format!("invalid MCP JSON-RPC message shape: {e}"),
        )
            .into_response(),
    })
}

async fn get_mcp(
    Path(profile_id): Path<String>,
    State(state): State<Arc<McpState>>,
    headers: HeaderMap,
) -> Result<Response, Response> {
    if Uuid::parse_str(&profile_id)
        .ok()
        .and_then(|u| (u.get_version() == Some(Version::Random)).then_some(u))
        .is_none()
    {
        return Err((StatusCode::NOT_FOUND, "profile not found").into_response());
    }

    ensure_accepts_get(&headers).map_err(|(s, m)| (s, m).into_response())?;

    let token = headers
        .get(HEADER_SESSION_ID)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                "Unauthorized: Session ID is required",
            )
                .into_response()
        })?
        .to_string();

    let last_event_id = headers
        .get(HEADER_LAST_EVENT_ID)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    let span = tracing::info_span!("gateway.mcp.get", profile_id = %profile_id);
    async move { handle_get_stream(&state, &profile_id, &headers, token, last_event_id).await }
        .instrument(span)
        .await
}

async fn delete_mcp(
    Path(profile_id): Path<String>,
    State(state): State<Arc<McpState>>,
    headers: HeaderMap,
) -> Result<Response, Response> {
    if Uuid::parse_str(&profile_id)
        .ok()
        .and_then(|u| (u.get_version() == Some(Version::Random)).then_some(u))
        .is_none()
    {
        return Err((StatusCode::NOT_FOUND, "profile not found").into_response());
    }

    let token = headers
        .get(HEADER_SESSION_ID)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                "Unauthorized: Session ID is required",
            )
                .into_response()
        })?
        .to_string();

    let span = tracing::info_span!("gateway.mcp.delete", profile_id = %profile_id);
    async move { handle_delete(&state, &profile_id, &headers, token).await }
        .instrument(span)
        .await
}

async fn handle_initialize(
    state: &McpState,
    profile_id: &str,
    headers: &HeaderMap,
    message: ClientJsonRpcMessage,
) -> Result<Response, Response> {
    let (req_id, protocol_version) =
        parse_initialize_request(&message).map_err(|(s, m)| (s, m).into_response())?;

    let profile = state
        .store
        .get_profile(profile_id)
        .await
        .map_err(internal_error_response("load profile"))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "profile not found").into_response())?;

    // Data-plane authn/z (per-profile).
    let (auth, oidc): (Option<TokenAuthV1>, Option<TokenOidcV1>) =
        match profile.data_plane_auth_mode {
            DataPlaneAuthMode::Disabled => (None, None),
            DataPlaneAuthMode::ApiKeyInitializeOnly | DataPlaneAuthMode::ApiKeyEveryRequest => (
                Some(authenticate_api_key_on_initialize(state, &profile, headers).await?),
                None,
            ),
            DataPlaneAuthMode::JwtEveryRequest => (
                None,
                Some(authorize_jwt_request(state, &profile, headers).await?),
            ),
        };

    tracing::info!(
        profile_id = %profile.id,
        tenant_id = %profile.tenant_id,
        "initialize profile session"
    );

    let (bindings, warnings) =
        initialize_profile_sources(state, &profile, &message, parse_hop(headers)).await?;

    let mut local_sources: usize = 0;
    for id in &profile.source_ids {
        if state.catalog.is_local_tool_source(id) {
            local_sources += 1;
            continue;
        }
        if state
            .tenant_catalog
            .has_tool_source(state.store.as_ref(), &profile.tenant_id, id)
            .await
            .map_err(internal_error_response("check tenant tool source"))?
        {
            local_sources += 1;
        }
    }
    if bindings.is_empty() && local_sources == 0 {
        return Err((
            StatusCode::BAD_GATEWAY,
            "All upstreams failed to initialize",
        )
            .into_response());
    }

    if !warnings.is_empty() && !profile.allow_partial_upstreams {
        return Err((
            StatusCode::BAD_GATEWAY,
            format!(
                "Profile disallows partial upstreams; initialize warnings: {}",
                warnings.join("; ")
            ),
        )
            .into_response());
    }

    for warning in &warnings {
        tracing::warn!(profile_id = %profile.id, warning = %warning, "profile initialize warning");
    }

    let init_result = gateway_initialize_result(&profile, protocol_version, &warnings);
    let response_message = ServerJsonRpcMessage::Response(JsonRpcResponse {
        jsonrpc: JsonRpcVersion2_0,
        id: req_id,
        result: ServerResult::InitializeResult(init_result),
    });

    let proxy_key = if profile.mcp.security.signed_proxied_request_ids {
        Some(mint_proxy_key_b64().map_err(internal_error_response("mint proxy key"))?)
    } else {
        None
    };

    let token_payload = TokenPayloadV1 {
        profile_id: profile.id,
        bindings,
        auth,
        oidc,
        iat: None,
        exp: None,
        proxy_key,
    };
    let token = state
        .signer
        .sign(token_payload)
        .map_err(internal_error_response("sign session token"))?;

    Ok(sse_single_message_with_session_id(
        &response_message,
        &token,
    ))
}

fn parse_initialize_request(
    message: &ClientJsonRpcMessage,
) -> Result<(rmcp::model::RequestId, rmcp::model::ProtocolVersion), (StatusCode, &'static str)> {
    match message {
        ClientJsonRpcMessage::Request(JsonRpcRequest {
            id,
            request: ClientRequest::InitializeRequest(init),
            ..
        }) => Ok((id.clone(), init.params.protocol_version.clone())),
        _ => Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            "Unexpected message, expect initialize request",
        )),
    }
}

fn mint_proxy_key_b64() -> anyhow::Result<String> {
    use rand_core::TryRngCore as _;
    let mut bytes = [0u8; PROXY_KEY_BYTES];
    rand_core::OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|e| anyhow::anyhow!("OS RNG failure: {e}"))?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

fn decode_proxy_key(payload: &TokenPayloadV1) -> Option<Vec<u8>> {
    let b64 = payload.proxy_key.as_ref()?;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(b64.as_bytes())
        .ok()
}

async fn initialize_profile_sources(
    state: &McpState,
    profile: &crate::store::Profile,
    init_message: &ClientJsonRpcMessage,
    hop: u32,
) -> Result<(Vec<UpstreamSessionBinding>, Vec<String>), Response> {
    let mut bindings = Vec::<UpstreamSessionBinding>::new();
    let mut warnings = Vec::<String>::new();

    for upstream_id in &profile.source_ids {
        // Gateway-native tool sources do not require upstream MCP session initialization.
        if state.catalog.is_local_tool_source(upstream_id) {
            continue;
        }
        // Tenant-owned local tool sources do not require upstream MCP session initialization.
        if state
            .tenant_catalog
            .has_tool_source(state.store.as_ref(), &profile.tenant_id, upstream_id)
            .await
            .map_err(internal_error_response("check tenant tool source"))?
        {
            continue;
        }

        let upstream = state
            .store
            .get_upstream(upstream_id)
            .await
            .map_err(internal_error_response("load upstream"))?
            .ok_or_else(|| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("profile references unknown upstream '{upstream_id}'"),
                )
                    .into_response()
            })?;

        if upstream.endpoints.is_empty() {
            warnings.push(format!("Upstream '{upstream_id}' has no endpoints"));
            continue;
        }

        let upstream_policy = profile.mcp.security.effective_upstream_policy(upstream_id);
        let upstream_init_message =
            upstream::rewrite_upstream_initialize_message(init_message, &upstream_policy);

        // Pick a starting endpoint index randomly and then try all endpoints (failover on init).
        let start = upstream::random_start_index(upstream.endpoints.len());

        let mut last_err: Option<anyhow::Error> = None;
        let mut initialized: Option<(String, String)> = None; // (endpoint_id, session_id)
        for i in 0..upstream.endpoints.len() {
            let ep = &upstream.endpoints[(start + i) % upstream.endpoints.len()];
            let headers = upstream::build_upstream_headers(ep.auth.as_ref(), hop + 1);
            let endpoint_url = upstream::apply_query_auth(&ep.url, ep.auth.as_ref());
            match upstream_initialize(&state.http, &endpoint_url, &upstream_init_message, &headers)
                .await
            {
                Ok(session_id) => {
                    initialized = Some((ep.id.clone(), session_id));
                    break;
                }
                Err(e) => last_err = Some(e),
            }
        }

        if let Some((endpoint_id, upstream_session_id)) = initialized {
            bindings.push(UpstreamSessionBinding {
                upstream: upstream_id.clone(),
                endpoint: endpoint_id,
                session: upstream_session_id,
            });
        } else if let Some(e) = last_err {
            warnings.push(format!("Upstream '{upstream_id}' initialize failed: {e}"));
        } else {
            warnings.push(format!("Upstream '{upstream_id}' initialize failed"));
        }
    }

    Ok((bindings, warnings))
}

fn effective_caps(profile: &crate::store::Profile) -> EffectiveMcpCapabilities {
    profile.mcp.capabilities.effective()
}

fn gateway_initialize_result(
    profile: &crate::store::Profile,
    protocol_version: rmcp::model::ProtocolVersion,
    warnings: &[String],
) -> InitializeResult {
    let caps = effective_caps(profile);
    // Build a "maximal" capability set, then clear fields based on profile policy.
    // This avoids the type-state complexity in the rmcp builder generics.
    let mut server_caps = ServerCapabilities::builder()
        .enable_logging()
        .enable_completions()
        .enable_tools()
        .enable_tool_list_changed()
        .enable_resources()
        .enable_resources_list_changed()
        .enable_resources_subscribe()
        .enable_prompts()
        .enable_prompts_list_changed()
        .build();

    if !caps.logging() {
        server_caps.logging = None;
    }
    if !caps.completions() {
        server_caps.completions = None;
    }
    if let Some(t) = server_caps.tools.as_mut()
        && !caps.tools_list_changed()
    {
        t.list_changed = None;
    }
    if let Some(r) = server_caps.resources.as_mut() {
        if !caps.resources_list_changed() {
            r.list_changed = None;
        }
        if !caps.resources_subscribe() {
            r.subscribe = None;
        }
    }
    if let Some(p) = server_caps.prompts.as_mut()
        && !caps.prompts_list_changed()
    {
        p.list_changed = None;
    }

    let mut init_result = InitializeResult {
        protocol_version,
        capabilities: server_caps,
        server_info: rmcp::model::Implementation {
            name: "unrelated-mcp-gateway".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            ..Default::default()
        },
        instructions: None,
    };

    if !warnings.is_empty() {
        init_result.instructions = Some(format!(
            "Gateway warnings (partial upstream availability):\n- {}",
            warnings.join("\n- ")
        ));
    }

    init_result
}

fn verify_session_token(
    signer: &SessionSigner,
    token: &str,
    profile_id: &str,
) -> Result<TokenPayloadV1, (StatusCode, &'static str)> {
    let payload = signer.verify(token).map_err(|e| {
        let expired = matches!(
            e.downcast_ref::<SessionTokenVerifyError>().map(|e| e.kind),
            Some(SessionTokenVerifyErrorKind::Expired)
        );
        if expired {
            (
                StatusCode::UNAUTHORIZED,
                "Unauthorized: session expired; re-initialize required",
            )
        } else {
            (
                StatusCode::UNAUTHORIZED,
                "Unauthorized: invalid session token",
            )
        }
    })?;

    if payload.profile_id != profile_id {
        return Err((
            StatusCode::UNAUTHORIZED,
            "Unauthorized: session token does not match profile",
        ));
    }

    Ok(payload)
}

async fn load_profile_or_404(
    state: &McpState,
    profile_id: &str,
) -> Result<crate::store::Profile, Response> {
    state
        .store
        .get_profile(profile_id)
        .await
        .map_err(internal_error_response("load profile"))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "profile not found").into_response())
}

fn parse_hop(headers: &HeaderMap) -> u32 {
    headers
        .get(upstream::HOP_HEADER)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(0)
}

async fn forward_proxied_response_if_any(
    state: &McpState,
    profile_id: &str,
    payload: &TokenPayloadV1,
    message: &mut ClientJsonRpcMessage,
    hop: u32,
) -> Result<Option<Response>, Response> {
    match message {
        ClientJsonRpcMessage::Response(JsonRpcResponse { id, .. })
        | ClientJsonRpcMessage::Error(JsonRpcError { id, .. }) => {
            let proxy_key = decode_proxy_key(payload);
            let Some((upstream_id, original_id)) =
                parse_proxied_request_id(id, proxy_key.as_deref())
            else {
                return Ok(None);
            };
            *id = original_id;
            let Some(binding) = payload
                .bindings
                .iter()
                .find(|b| b.upstream.as_str() == upstream_id.as_str())
            else {
                return Err((
                    StatusCode::BAD_REQUEST,
                    "Unknown upstream for proxied response id",
                )
                    .into_response());
            };
            let Some(endpoint) = upstream::resolve_endpoint(state, profile_id, binding).await?
            else {
                return Err((
                    StatusCode::BAD_GATEWAY,
                    "Upstream endpoint not available for proxied response",
                )
                    .into_response());
            };
            if hop >= upstream::MAX_HOPS {
                return Err((
                    StatusCode::BAD_GATEWAY,
                    "proxy loop detected (max hops exceeded)",
                )
                    .into_response());
            }
            let endpoint_url = upstream::apply_query_auth(&endpoint.url, endpoint.auth.as_ref());
            let headers = upstream::build_upstream_headers(endpoint.auth.as_ref(), hop + 1);
            let _ = streamable_http::post_message(
                &state.http,
                endpoint_url.into(),
                message.clone(),
                Some(binding.session.clone().into()),
                &headers,
            )
            .await;
            Ok(Some(StatusCode::ACCEPTED.into_response()))
        }
        _ => Ok(None),
    }
}

async fn broadcast_notification_best_effort(
    state: &McpState,
    profile_id: &str,
    bindings: &[UpstreamSessionBinding],
    msg: ClientJsonRpcMessage,
    hop: u32,
) -> Result<(), Response> {
    if hop >= upstream::MAX_HOPS {
        return Ok(());
    }
    for binding in bindings {
        if let Some(endpoint) = upstream::resolve_endpoint(state, profile_id, binding).await? {
            let endpoint_url = upstream::apply_query_auth(&endpoint.url, endpoint.auth.as_ref());
            let headers = upstream::build_upstream_headers(endpoint.auth.as_ref(), hop + 1);
            let _ = streamable_http::post_message(
                &state.http,
                endpoint_url.into(),
                msg.clone(),
                Some(binding.session.clone().into()),
                &headers,
            )
            .await;
        }
    }
    Ok(())
}

async fn forward_notification_if_any(
    state: &McpState,
    profile_id: &str,
    payload: &TokenPayloadV1,
    message: &mut ClientJsonRpcMessage,
    hop: u32,
) -> Result<Option<Response>, Response> {
    // Special-case `notifications/cancelled` for proxied ids: route to the owning upstream
    // (server→client request cancellation), otherwise keep the existing best-effort fanout.
    let proxy_key = decode_proxy_key(payload);
    let proxied_cancel = if let ClientJsonRpcMessage::Notification(JsonRpcNotification {
        notification: ClientNotification::CancelledNotification(cancelled),
        ..
    }) = &*message
    {
        parse_proxied_request_id(&cancelled.params.request_id, proxy_key.as_deref())
    } else {
        None
    };

    if let Some((upstream_id, original_id)) = proxied_cancel {
        if let ClientJsonRpcMessage::Notification(JsonRpcNotification {
            notification: ClientNotification::CancelledNotification(cancelled),
            ..
        }) = message
        {
            cancelled.params.request_id = original_id;
        }
        let Some(binding) = payload
            .bindings
            .iter()
            .find(|b| b.upstream.as_str() == upstream_id.as_str())
        else {
            return Err((
                StatusCode::BAD_REQUEST,
                "Unknown upstream for proxied cancellation id",
            )
                .into_response());
        };
        if let Some(endpoint) = upstream::resolve_endpoint(state, profile_id, binding).await? {
            if hop >= upstream::MAX_HOPS {
                return Ok(Some(StatusCode::ACCEPTED.into_response()));
            }
            let endpoint_url = upstream::apply_query_auth(&endpoint.url, endpoint.auth.as_ref());
            let headers = upstream::build_upstream_headers(endpoint.auth.as_ref(), hop + 1);
            let _ = streamable_http::post_message(
                &state.http,
                endpoint_url.into(),
                message.clone(),
                Some(binding.session.clone().into()),
                &headers,
            )
            .await;
        }
        return Ok(Some(StatusCode::ACCEPTED.into_response()));
    }

    if matches!(message, ClientJsonRpcMessage::Notification(_)) {
        broadcast_notification_best_effort(
            state,
            profile_id,
            &payload.bindings,
            message.clone(),
            hop,
        )
        .await?;
        return Ok(Some(StatusCode::ACCEPTED.into_response()));
    }

    Ok(None)
}

#[derive(Clone, Copy)]
struct InSessionRequestCtx<'a> {
    state: &'a McpState,
    profile_id: &'a str,
    profile: &'a crate::store::Profile,
    payload: &'a TokenPayloadV1,
    hop: u32,
}

async fn handle_tools_call_in_session(
    ctx: InSessionRequestCtx<'_>,
    token: String,
    message: &mut ClientJsonRpcMessage,
    req_id: &RequestId,
) -> Result<Response, Response> {
    if let Some(auth) = ctx.payload.auth.as_ref() {
        ctx.state
            .store
            .record_tool_call_attempt(&auth.tenant_id, &auth.api_key_id)
            .await
            .map_err(internal_error_response("record tool call attempt"))?;

        let rate_limit = if ctx.profile.rate_limit_enabled {
            ctx.profile.rate_limit_tool_calls_per_minute
        } else {
            None
        };
        let quota = if ctx.profile.quota_enabled {
            ctx.profile.quota_tool_calls
        } else {
            None
        };

        if (ctx.profile.rate_limit_enabled && rate_limit.is_none())
            || (ctx.profile.quota_enabled && quota.is_none())
        {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "profile limits misconfigured",
            )
                .into_response());
        }

        if let Some(rejection) = ctx
            .state
            .store
            .check_and_apply_tool_call_limits(
                &auth.tenant_id,
                &ctx.profile.id,
                &auth.api_key_id,
                rate_limit,
                quota,
            )
            .await
            .map_err(internal_error_response("apply tool call limits"))?
        {
            match rejection {
                ToolCallLimitRejection::RateLimited { retry_after_secs } => {
                    let data = retry_after_secs.map(|s| serde_json::json!({ "retryAfterSecs": s }));
                    return Err(jsonrpc_error_response_with_data(
                        req_id.clone(),
                        ERROR_CODE_RATE_LIMIT_EXCEEDED,
                        "rate limit exceeded".to_string(),
                        data,
                    ));
                }
                ToolCallLimitRejection::QuotaExceeded => {
                    return Err(jsonrpc_error_response_with_data(
                        req_id.clone(),
                        ERROR_CODE_QUOTA_EXCEEDED,
                        "quota exceeded".to_string(),
                        None,
                    ));
                }
            }
        }
    } else if ctx.profile.rate_limit_enabled || ctx.profile.quota_enabled {
        return Err(unauthorized(
            "Unauthorized: profile limits require API key authentication",
        ));
    }

    Box::pin(route_and_proxy_tools_call(
        ctx.state,
        ctx.profile_id,
        ctx.profile,
        ctx.payload,
        token,
        message,
        ctx.hop,
    ))
    .await
}

async fn handle_logging_set_level_in_session(
    state: &McpState,
    profile_id: &str,
    profile: &crate::store::Profile,
    payload: &TokenPayloadV1,
    message: &ClientJsonRpcMessage,
    req_id: RequestId,
    hop: u32,
) -> Result<Response, Response> {
    if !effective_caps(profile).logging() {
        return Err(jsonrpc_error_response(
            req_id,
            ErrorCode::METHOD_NOT_FOUND,
            "logging is disabled by profile MCP capability policy".to_string(),
        ));
    }

    // Best-effort: forward to all upstreams so they can adjust verbosity.
    for binding in &payload.bindings {
        if let Some(endpoint) = upstream::resolve_endpoint(state, profile_id, binding).await? {
            if hop >= upstream::MAX_HOPS {
                continue;
            }
            let endpoint_url = upstream::apply_query_auth(&endpoint.url, endpoint.auth.as_ref());
            let headers = upstream::build_upstream_headers(endpoint.auth.as_ref(), hop + 1);
            let _ = streamable_http::post_message(
                &state.http,
                endpoint_url.into(),
                message.clone(),
                Some(binding.session.clone().into()),
                &headers,
            )
            .await;
        }
    }

    let msg = ServerJsonRpcMessage::Response(JsonRpcResponse {
        jsonrpc: JsonRpcVersion2_0,
        id: req_id,
        result: ServerResult::EmptyResult(rmcp::model::EmptyResult {}),
    });
    Ok(sse_single_message(&msg))
}

#[derive(Debug, Clone, Copy)]
enum ResourceSubscriptionOp {
    Subscribe,
    Unsubscribe,
}

impl ResourceSubscriptionOp {
    const fn method(self) -> &'static str {
        match self {
            Self::Subscribe => "resources/subscribe",
            Self::Unsubscribe => "resources/unsubscribe",
        }
    }
}

async fn handle_resource_subscription_in_session(
    ctx: InSessionRequestCtx<'_>,
    op: ResourceSubscriptionOp,
    token: String,
    message: &mut ClientJsonRpcMessage,
    req_id: RequestId,
) -> Result<Response, Response> {
    if !effective_caps(ctx.profile).resources_subscribe() {
        return Err(jsonrpc_error_response(
            req_id,
            ErrorCode::METHOD_NOT_FOUND,
            format!(
                "{} is disabled by profile MCP capability policy",
                op.method()
            ),
        ));
    }
    match op {
        ResourceSubscriptionOp::Subscribe => {
            route_and_proxy_resource_subscribe(
                ctx.state,
                ctx.profile_id,
                ctx.payload,
                token,
                message,
                ctx.hop,
            )
            .await
        }
        ResourceSubscriptionOp::Unsubscribe => {
            route_and_proxy_resource_unsubscribe(
                ctx.state,
                ctx.profile_id,
                ctx.payload,
                token,
                message,
                ctx.hop,
            )
            .await
        }
    }
}

async fn handle_post_in_session_request(
    state: &McpState,
    profile_id: &str,
    profile: &crate::store::Profile,
    payload: &TokenPayloadV1,
    token: String,
    message: &mut ClientJsonRpcMessage,
    hop: u32,
) -> Result<Response, Response> {
    let (req_id, method) = match as_request_ref(&*message) {
        Some(JsonRpcRequest { id, request, .. }) => (id.clone(), request.method().to_string()),
        None => return Ok(StatusCode::ACCEPTED.into_response()),
    };

    let ctx = InSessionRequestCtx {
        state,
        profile_id,
        profile,
        payload,
        hop,
    };

    match method.as_str() {
        "logging/setLevel" => {
            handle_logging_set_level_in_session(
                state,
                profile_id,
                profile,
                payload,
                &message.clone(),
                req_id,
                hop,
            )
            .await
        }
        "tools/list" => {
            Box::pin(aggregate_list_tools(
                state, profile_id, profile, payload, &token, req_id, hop,
            ))
            .await
        }
        "resources/list" => aggregate_list_resources(state, profile_id, payload, req_id, hop).await,
        "resources/subscribe" => {
            handle_resource_subscription_in_session(
                ctx,
                ResourceSubscriptionOp::Subscribe,
                token,
                message,
                req_id,
            )
            .await
        }
        "resources/unsubscribe" => {
            handle_resource_subscription_in_session(
                ctx,
                ResourceSubscriptionOp::Unsubscribe,
                token,
                message,
                req_id,
            )
            .await
        }
        "prompts/list" => aggregate_list_prompts(state, profile_id, payload, req_id, hop).await,
        "completion/complete" => {
            if !effective_caps(profile).completions() {
                return Err(jsonrpc_error_response(
                    req_id,
                    ErrorCode::METHOD_NOT_FOUND,
                    "completions are disabled by profile MCP capability policy".to_string(),
                ));
            }
            route_and_proxy_completion_complete(state, profile_id, payload, token, message, hop)
                .await
        }
        "tools/call" => handle_tools_call_in_session(ctx, token, message, &req_id).await,
        "resources/read" => {
            route_and_proxy_resource_read(state, profile_id, payload, token, message, hop).await
        }
        "prompts/get" => {
            route_and_proxy_prompt_get(state, profile_id, payload, token, message, hop).await
        }
        "ping" => {
            let msg = ServerJsonRpcMessage::Response(JsonRpcResponse {
                jsonrpc: JsonRpcVersion2_0,
                id: req_id,
                result: ServerResult::EmptyResult(rmcp::model::EmptyResult {}),
            });
            Ok(sse_single_message(&msg))
        }
        other => Err(jsonrpc_error_response(
            req_id,
            ErrorCode::METHOD_NOT_FOUND,
            format!("Unsupported method: {other}"),
        )),
    }
}

async fn handle_post_in_session(
    state: &McpState,
    profile_id: &str,
    headers: &HeaderMap,
    token: String,
    mut message: ClientJsonRpcMessage,
) -> Result<Response, Response> {
    let hop = parse_hop(headers);
    let payload = verify_session_token(&state.signer, &token, profile_id)
        .map_err(|(s, m)| (s, m).into_response())?;
    let profile = load_profile_or_404(state, profile_id).await?;
    enforce_data_plane_auth(
        state,
        &profile,
        headers,
        payload.auth.as_ref(),
        payload.oidc.as_ref(),
    )
    .await?;

    if let Some(resp) =
        forward_proxied_response_if_any(state, profile_id, &payload, &mut message, hop).await?
    {
        return Ok(resp);
    }

    if let Some(resp) =
        forward_notification_if_any(state, profile_id, &payload, &mut message, hop).await?
    {
        return Ok(resp);
    }

    handle_post_in_session_request(
        state,
        profile_id,
        &profile,
        &payload,
        token,
        &mut message,
        hop,
    )
    .await
}

async fn handle_get_stream(
    state: &McpState,
    profile_id: &str,
    headers: &HeaderMap,
    token: String,
    last_event_id: Option<String>,
) -> Result<Response, Response> {
    let send_priming = last_event_id.is_none();
    let payload = verify_session_token(&state.signer, &token, profile_id)
        .map_err(|(s, m)| (s, m).into_response())?;

    let profile = state
        .store
        .get_profile(profile_id)
        .await
        .map_err(internal_error_response("load profile"))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "profile not found").into_response())?;

    enforce_data_plane_auth(
        state,
        &profile,
        headers,
        payload.auth.as_ref(),
        payload.oidc.as_ref(),
    )
    .await?;

    let tenant_limits = match state
        .store
        .get_tenant_transport_limits(&profile.tenant_id)
        .await
    {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, tenant_id = %profile.tenant_id, "load tenant transport limits failed; using defaults");
            None
        }
    };
    let limits = crate::transport_limits::EffectiveTransportLimits::from_profile_and_tenant(
        &profile.mcp.security.transport_limits,
        tenant_limits.as_ref(),
    );
    let limits_shutdown = CancellationToken::new();

    // Parse Last-Event-ID:
    // - If it looks like an upstream-prefixed id (`<upstream>/<id...>`), resume only that upstream.
    // - If it is numeric, treat it as the durable contract event cursor and do not forward to upstreams.
    let last = parse_last_event_id(
        profile.mcp.namespacing.sse_event_id,
        last_event_id.as_deref(),
    );

    // Stored behind an `RwLock` so we can refresh collision counts later without rewiring the
    // upstream SSE stream closures (counts can change when resources are added/removed upstream).
    let collision_counts = Arc::new(parking_lot::RwLock::new(
        match compute_resource_collision_counts(state, profile_id, &payload, parse_hop(headers))
            .await
        {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!(error = ?e, "failed to compute resource collision counts");
                HashMap::new()
            }
        },
    ));

    let mut streams: Vec<
        futures::stream::BoxStream<'static, Result<axum::response::sse::Event, Infallible>>,
    > = Vec::new();
    if send_priming {
        streams.push(priming_stream());
    }

    let proxy_key = decode_proxy_key(&payload).map(|v| Arc::from(v.into_boxed_slice()));
    streams.extend(
        open_upstream_streams(OpenUpstreamStreamsInputs {
            state,
            profile: &profile,
            bindings: &payload.bindings,
            last: &last,
            resource_collision_counts: collision_counts,
            proxy_key,
            hop: parse_hop(headers),
            limits,
            limits_shutdown: limits_shutdown.clone(),
        })
        .await?,
    );

    if let Some(replay) =
        contract_replay_stream(state, &profile, profile_id, last.contract_after_id).await
    {
        streams.push(replay);
    }

    streams.push(contract_notifications_stream(
        &profile,
        state.contracts.subscribe(profile_id),
    ));

    let merged = futures::stream::select_all(streams);
    // Ensure long-lived streams don't prevent shutdown (e.g. docker stop / SIGTERM),
    // and close the SSE stream on transport limit violations.
    let shutdown = state.shutdown.clone();
    let merged = merged.take_until(async move {
        tokio::select! {
            () = shutdown.cancelled() => {},
            () = limits_shutdown.cancelled() => {},
        }
    });
    let mut resp = Sse::new(merged).into_response();
    resp.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static(EVENT_STREAM_MIME_TYPE),
    );
    Ok(resp)
}

#[derive(Debug, Clone, Default)]
struct ParsedLastEventId {
    resume_upstream: Option<String>,
    resume_upstream_event_id: Option<String>,
    contract_after_id: Option<u64>,
}

fn parse_last_event_id(
    ns: SseEventIdNamespacing,
    last_event_id: Option<&str>,
) -> ParsedLastEventId {
    let Some(id) = last_event_id else {
        return ParsedLastEventId::default();
    };
    if matches!(ns, SseEventIdNamespacing::UpstreamSlash)
        && let Some((upstream, rest)) = id.split_once('/')
        && !upstream.is_empty()
        && !rest.is_empty()
    {
        return ParsedLastEventId {
            resume_upstream: Some(upstream.to_string()),
            resume_upstream_event_id: Some(rest.to_string()),
            contract_after_id: None,
        };
    }
    ParsedLastEventId {
        contract_after_id: id.parse::<u64>().ok(),
        ..Default::default()
    }
}

fn namespace_sse_event_id(ns: SseEventIdNamespacing, upstream_id: &str, id: String) -> String {
    match ns {
        SseEventIdNamespacing::UpstreamSlash => format!("{upstream_id}/{id}"),
        SseEventIdNamespacing::None => id,
    }
}

fn server_notification_method(notification: &ServerNotification) -> &str {
    match notification {
        ServerNotification::CancelledNotification(_) => "notifications/cancelled",
        ServerNotification::ProgressNotification(_) => "notifications/progress",
        ServerNotification::LoggingMessageNotification(_) => "notifications/message",
        ServerNotification::ResourceUpdatedNotification(_) => "notifications/resources/updated",
        ServerNotification::ResourceListChangedNotification(_) => {
            "notifications/resources/list_changed"
        }
        ServerNotification::ToolListChangedNotification(_) => "notifications/tools/list_changed",
        ServerNotification::PromptListChangedNotification(_) => {
            "notifications/prompts/list_changed"
        }
        ServerNotification::CustomNotification(n) => n.method.as_str(),
    }
}

fn allowed_by_caps_for_notification(caps: EffectiveMcpCapabilities, method: &str) -> bool {
    match method {
        "notifications/message" => caps.logging(),
        "notifications/tools/list_changed" => caps.tools_list_changed(),
        "notifications/resources/list_changed" => caps.resources_list_changed(),
        "notifications/prompts/list_changed" => caps.prompts_list_changed(),
        _ => true,
    }
}

enum RewriteOutcome {
    Drop,
    Unchanged,
    Changed(String),
}

fn rewrite_upstream_sse_data(
    caps: EffectiveMcpCapabilities,
    notification_filter: &crate::store::McpNotificationFilter,
    ns_req: RequestIdNamespacing,
    upstream_id: &str,
    counts: &parking_lot::RwLock<HashMap<String, usize>>,
    proxy_key: Option<&[u8]>,
    data: &str,
) -> RewriteOutcome {
    let Ok(mut msg) = serde_json::from_str::<ServerJsonRpcMessage>(data) else {
        return RewriteOutcome::Unchanged;
    };

    if let ServerJsonRpcMessage::Notification(JsonRpcNotification { notification, .. }) = &msg {
        let method = server_notification_method(notification);
        if !allowed_by_caps_for_notification(caps, method) || !notification_filter.allows(method) {
            return RewriteOutcome::Drop;
        }
    }

    let mut changed = false;
    match &mut msg {
        ServerJsonRpcMessage::Request(JsonRpcRequest { id, .. }) => {
            *id = make_proxied_request_id(ns_req, upstream_id, id, proxy_key);
            changed = true;
        }
        ServerJsonRpcMessage::Notification(JsonRpcNotification { notification, .. }) => {
            if let ServerNotification::CancelledNotification(cancelled) = notification {
                cancelled.params.request_id = make_proxied_request_id(
                    ns_req,
                    upstream_id,
                    &cancelled.params.request_id,
                    proxy_key,
                );
                changed = true;
            }
            if let ServerNotification::ResourceUpdatedNotification(updated) = notification {
                let original_uri = updated.params.uri.clone();
                let collision = counts.read().get(&original_uri).copied().unwrap_or(0) > 1;
                if collision {
                    updated.params.uri = resource_collision_urn(upstream_id, &original_uri);
                    changed = true;
                }
            }
        }
        _ => {}
    }

    if !changed {
        return RewriteOutcome::Unchanged;
    }
    match serde_json::to_string(&msg) {
        Ok(s) => RewriteOutcome::Changed(s),
        Err(_) => RewriteOutcome::Unchanged,
    }
}

struct UpstreamSseMapCtx {
    tenant_id: Arc<str>,
    profile_id: Arc<str>,
    upstream_id: Arc<str>,
    upstream_session_id: Arc<str>,
    endpoint_url: Arc<str>,
    headers_for_post: HeaderMap,
    server_requests_filter: crate::store::McpServerRequestFilter,
    caps: EffectiveMcpCapabilities,
    notification_filter: crate::store::McpNotificationFilter,
    ns_req: RequestIdNamespacing,
    ns_evt: SseEventIdNamespacing,
    counts: Arc<parking_lot::RwLock<HashMap<String, usize>>>,
    proxy_key: Option<Arc<[u8]>>,
    http: reqwest::Client,
    limits: crate::transport_limits::EffectiveTransportLimits,
    limits_shutdown: CancellationToken,
    audit: Arc<dyn AuditSink>,
}

async fn maybe_block_upstream_server_request(ctx: &UpstreamSseMapCtx, data: &str) -> bool {
    // Policy: optionally block upstream server→client requests before they reach the downstream
    // client.
    //
    // We detect request messages by the presence of both `method` and `id`. (Responses have `id`
    // but no `method`.)
    let Ok(v) = serde_json::from_str::<serde_json::Value>(data) else {
        return false;
    };
    let Some(method) = v.get("method").and_then(serde_json::Value::as_str) else {
        return false;
    };
    if v.get("id").is_none() {
        return false;
    }
    if ctx.server_requests_filter.allows(method) {
        return false;
    }

    if let Some(id_value) = v.get("id").cloned()
        && let Ok(id) = serde_json::from_value::<RequestId>(id_value)
    {
        let err = ClientJsonRpcMessage::Error(JsonRpcError {
            jsonrpc: JsonRpcVersion2_0,
            id,
            error: ErrorData::new(
                ErrorCode::METHOD_NOT_FOUND,
                format!("blocked by gateway upstream request policy: {method}"),
                None,
            ),
        });
        let _ = streamable_http::post_message(
            &ctx.http,
            ctx.endpoint_url.clone(),
            err,
            Some(ctx.upstream_session_id.clone()),
            &ctx.headers_for_post,
        )
        .await;
    }

    true
}

async fn enforce_sse_data_limits_or_close(
    ctx: &UpstreamSseMapCtx,
    direction: &'static str,
    data: &str,
    check_complexity: bool,
) -> bool {
    let observed = data.len() as u64;
    if observed > ctx.limits.max_sse_event_bytes {
        record_payload_limit_exceeded(
            ctx.audit.as_ref(),
            PayloadLimitExceededAudit {
                tenant_id: ctx.tenant_id.as_ref(),
                profile_id: ctx.profile_id.as_ref(),
                http_method: "GET",
                http_route: "/{profile_id}/mcp",
                status_code: None,
                direction,
                action_taken: "closed_stream",
                reason: "maxSseEventBytes",
                metric: "bytes",
                observed,
                limit: ctx.limits.max_sse_event_bytes,
                upstream_id: Some(ctx.upstream_id.as_ref()),
                sample: Some(truncate_string_to_bytes(data.to_string(), 4096)),
            },
        )
        .await;
        ctx.limits_shutdown.cancel();
        return false;
    }

    if check_complexity
        && ctx.limits.has_json_complexity_limits()
        && let Ok(v) = serde_json::from_str::<serde_json::Value>(data)
        && let Some(vio) = crate::transport_limits::check_json_complexity(&v, ctx.limits)
    {
        record_payload_limit_exceeded(
            ctx.audit.as_ref(),
            PayloadLimitExceededAudit {
                tenant_id: ctx.tenant_id.as_ref(),
                profile_id: ctx.profile_id.as_ref(),
                http_method: "GET",
                http_route: "/{profile_id}/mcp",
                status_code: None,
                direction,
                action_taken: "closed_stream",
                reason: vio.kind,
                metric: "complexity",
                observed: vio.observed,
                limit: vio.limit,
                upstream_id: Some(ctx.upstream_id.as_ref()),
                sample: Some(truncate_string_to_bytes(data.to_string(), 4096)),
            },
        )
        .await;
        ctx.limits_shutdown.cancel();
        return false;
    }

    true
}

async fn map_upstream_sse_event(
    ctx: &UpstreamSseMapCtx,
    evt: Result<sse_stream::Sse, sse_stream::Error>,
) -> Option<Result<axum::response::sse::Event, Infallible>> {
    match evt {
        Ok(mut sse) => {
            if let Some(id) = sse.id.take() {
                sse.id = Some(namespace_sse_event_id(ctx.ns_evt, &ctx.upstream_id, id));
            }

            if let Some(data) = sse.data.clone()
                && !data.trim().is_empty()
            {
                if !enforce_sse_data_limits_or_close(ctx, "upstream_sse", &data, true).await {
                    return None;
                }

                if maybe_block_upstream_server_request(ctx, &data).await {
                    return None;
                }

                match rewrite_upstream_sse_data(
                    ctx.caps,
                    &ctx.notification_filter,
                    ctx.ns_req,
                    &ctx.upstream_id,
                    &ctx.counts,
                    ctx.proxy_key.as_deref(),
                    &data,
                ) {
                    RewriteOutcome::Drop => return None,
                    RewriteOutcome::Unchanged => {}
                    RewriteOutcome::Changed(new_data) => {
                        if !enforce_sse_data_limits_or_close(
                            ctx,
                            "downstream_sse",
                            &new_data,
                            false,
                        )
                        .await
                        {
                            return None;
                        }
                        sse.data = Some(new_data);
                    }
                }
            }

            let mut ev = axum::response::sse::Event::default();
            if let Some(id) = sse.id {
                ev = ev.id(id);
            }
            if let Some(data) = sse.data {
                ev = ev.data(data);
            }
            Some(Ok::<_, Infallible>(ev))
        }
        Err(e) => {
            tracing::warn!(error = %e, "upstream sse error");
            Some(Ok::<_, Infallible>(
                axum::response::sse::Event::default().comment("upstream error"),
            ))
        }
    }
}

struct OpenUpstreamStreamsInputs<'a> {
    state: &'a McpState,
    profile: &'a crate::store::Profile,
    bindings: &'a [UpstreamSessionBinding],
    last: &'a ParsedLastEventId,
    resource_collision_counts: Arc<parking_lot::RwLock<HashMap<String, usize>>>,
    proxy_key: Option<Arc<[u8]>>,
    hop: u32,
    limits: crate::transport_limits::EffectiveTransportLimits,
    limits_shutdown: CancellationToken,
}

async fn open_upstream_streams(
    inputs: OpenUpstreamStreamsInputs<'_>,
) -> Result<
    Vec<futures::stream::BoxStream<'static, Result<axum::response::sse::Event, Infallible>>>,
    Response,
> {
    let OpenUpstreamStreamsInputs {
        state,
        profile,
        bindings,
        last,
        resource_collision_counts,
        proxy_key,
        hop,
        limits,
        limits_shutdown,
    } = inputs;
    let mut streams: Vec<
        futures::stream::BoxStream<'static, Result<axum::response::sse::Event, Infallible>>,
    > = Vec::new();

    for binding in bindings {
        let Some(endpoint) =
            upstream::resolve_endpoint(state, profile.id.as_str(), binding).await?
        else {
            continue;
        };
        if hop >= upstream::MAX_HOPS {
            continue;
        }
        let endpoint_url: Arc<str> = Arc::<str>::from(upstream::apply_query_auth(
            &endpoint.url,
            endpoint.auth.as_ref(),
        ));
        let headers = upstream::build_upstream_headers(endpoint.auth.as_ref(), hop + 1);

        let upstream_policy = profile
            .mcp
            .security
            .effective_upstream_policy(binding.upstream.as_str());
        let server_requests_filter = upstream_policy.server_requests.clone();

        let upstream_last = if last.resume_upstream.as_deref() == Some(binding.upstream.as_str()) {
            last.resume_upstream_event_id.clone()
        } else {
            None
        };

        let upstream = streamable_http::get_stream(
            &state.http,
            endpoint_url.clone(),
            binding.session.clone().into(),
            upstream_last,
            &headers,
        )
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                format!("failed to open upstream stream: {e}"),
            )
                .into_response()
        })?;

        let ctx = Arc::new(UpstreamSseMapCtx {
            tenant_id: Arc::<str>::from(profile.tenant_id.clone()),
            profile_id: Arc::<str>::from(profile.id.clone()),
            upstream_id: Arc::<str>::from(binding.upstream.clone()),
            upstream_session_id: Arc::<str>::from(binding.session.clone()),
            endpoint_url: endpoint_url.clone(),
            headers_for_post: headers.clone(),
            server_requests_filter,
            caps: effective_caps(profile),
            notification_filter: profile.mcp.notifications.clone(),
            ns_req: profile.mcp.namespacing.request_id,
            ns_evt: profile.mcp.namespacing.sse_event_id,
            counts: resource_collision_counts.clone(),
            proxy_key: proxy_key.clone(),
            http: state.http.clone(),
            limits,
            limits_shutdown: limits_shutdown.clone(),
            audit: state.audit.clone(),
        });

        let mapped = upstream.filter_map(move |evt| {
            let ctx = ctx.clone();
            async move { map_upstream_sse_event(ctx.as_ref(), evt).await }
        });
        streams.push(mapped.boxed());
    }

    Ok(streams)
}

async fn compute_resource_collision_counts(
    state: &McpState,
    profile_id: &str,
    payload: &TokenPayloadV1,
    hop: u32,
) -> Result<HashMap<String, usize>, Response> {
    let per_upstream =
        upstream::list_resources_all_upstreams(state, profile_id, payload, hop).await?;
    Ok(count_resource_uris(&per_upstream))
}

async fn contract_replay_stream(
    state: &McpState,
    profile: &crate::store::Profile,
    profile_id: &str,
    after: Option<u64>,
) -> Option<futures::stream::BoxStream<'static, Result<axum::response::sse::Event, Infallible>>> {
    let (fanout, after) = (state.contract_fanout.as_ref()?, after?);
    let caps = effective_caps(profile);
    let filter = profile.mcp.notifications.clone();

    match fanout
        .replay(profile_id, after, CONTRACT_REPLAY_LIMIT)
        .await
    {
        Ok(events) => {
            let replay = futures::stream::iter(events.into_iter().filter_map(move |evt| {
                let method = evt.kind.list_changed_method();
                let allowed_by_caps = match evt.kind {
                    crate::contracts::ContractKind::Tools => caps.tools_list_changed(),
                    crate::contracts::ContractKind::Resources => caps.resources_list_changed(),
                    crate::contracts::ContractKind::Prompts => caps.prompts_list_changed(),
                };
                if !allowed_by_caps || !filter.allows(method) {
                    return None;
                }
                let json = list_changed_notification_json(&evt);
                Some(Ok::<_, Infallible>(
                    axum::response::sse::Event::default()
                        .id(evt.event_id.to_string())
                        .data(json),
                ))
            }));
            Some(replay.boxed())
        }
        Err(e) => {
            tracing::warn!(error = %e, "failed to replay contract events");
            None
        }
    }
}

fn contract_notifications_stream(
    profile: &crate::store::Profile,
    rx: tokio::sync::broadcast::Receiver<ContractEvent>,
) -> futures::stream::BoxStream<'static, Result<axum::response::sse::Event, Infallible>> {
    let caps = effective_caps(profile);
    let filter = profile.mcp.notifications.clone();
    let notifications = futures::stream::unfold(rx, move |mut rx| {
        let caps = caps;
        let filter = filter.clone();
        async move {
            loop {
                match rx.recv().await {
                    Ok(evt) => {
                        let method = evt.kind.list_changed_method();
                        let allowed_by_caps = match evt.kind {
                            crate::contracts::ContractKind::Tools => caps.tools_list_changed(),
                            crate::contracts::ContractKind::Resources => {
                                caps.resources_list_changed()
                            }
                            crate::contracts::ContractKind::Prompts => caps.prompts_list_changed(),
                        };
                        if !allowed_by_caps || !filter.allows(method) {
                            continue;
                        }
                        let json = list_changed_notification_json(&evt);
                        return Some((
                            Ok::<_, Infallible>(
                                axum::response::sse::Event::default()
                                    .id(evt.event_id.to_string())
                                    .data(json),
                            ),
                            rx,
                        ));
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return None,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        return Some((
                            Ok::<_, Infallible>(
                                axum::response::sse::Event::default()
                                    .comment("gateway notification lagged"),
                            ),
                            rx,
                        ));
                    }
                }
            }
        }
    });
    notifications.boxed()
}

fn priming_stream()
-> futures::stream::BoxStream<'static, Result<axum::response::sse::Event, Infallible>> {
    // SSE priming event (SEP-1699): send a first event with an id and empty data ("data:\n").
    // RMCP also sets `retry: 3000`; axum supports `retry()` so we mirror that when possible.
    let ev = axum::response::sse::Event::default()
        .id("0")
        .retry(std::time::Duration::from_millis(SSE_PRIMING_RETRY_MS))
        .data("");
    futures::stream::once(async move { Ok::<_, Infallible>(ev) }).boxed()
}

async fn handle_delete(
    state: &McpState,
    profile_id: &str,
    headers: &HeaderMap,
    token: String,
) -> Result<Response, Response> {
    let hop = parse_hop(headers);
    let payload = verify_session_token(&state.signer, &token, profile_id)
        .map_err(|(s, m)| (s, m).into_response())?;

    let profile = state
        .store
        .get_profile(profile_id)
        .await
        .map_err(internal_error_response("load profile"))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "profile not found").into_response())?;

    enforce_data_plane_auth(
        state,
        &profile,
        headers,
        payload.auth.as_ref(),
        payload.oidc.as_ref(),
    )
    .await?;

    // Best-effort: invalidate local caches for this session token.
    state.tools_cache.invalidate(&token);

    for binding in &payload.bindings {
        if let Some(endpoint) = upstream::resolve_endpoint(state, profile_id, binding).await? {
            if hop >= upstream::MAX_HOPS {
                continue;
            }
            let endpoint_url = upstream::apply_query_auth(&endpoint.url, endpoint.auth.as_ref());
            let headers = upstream::build_upstream_headers(endpoint.auth.as_ref(), hop + 1);
            let _ = streamable_http::delete_session(
                &state.http,
                endpoint_url.into(),
                binding.session.clone().into(),
                &headers,
            )
            .await;
        }
    }
    Ok(StatusCode::ACCEPTED.into_response())
}

async fn route_and_proxy_resource_read(
    state: &McpState,
    profile_id: &str,
    payload: &TokenPayloadV1,
    _token: String,
    message: &mut ClientJsonRpcMessage,
    hop: u32,
) -> Result<Response, Response> {
    let Some((uri, req_id)) = extract_read_resource(message) else {
        return Err((StatusCode::BAD_REQUEST, "invalid resources/read request").into_response());
    };

    let (upstream_id, original_uri) = resolve_resource_owner(state, profile_id, payload, &uri, hop)
        .await
        .map_err(|e| jsonrpc_error_response(req_id, ErrorCode::INVALID_PARAMS, e.to_string()))?;

    if let Some(param) = as_read_resource_mut(message) {
        param.uri = original_uri;
    }

    proxy_to_single_upstream(
        state,
        profile_id,
        payload,
        &upstream_id,
        message.clone(),
        hop,
    )
    .await
}

async fn route_and_proxy_resource_subscribe(
    state: &McpState,
    profile_id: &str,
    payload: &TokenPayloadV1,
    _token: String,
    message: &mut ClientJsonRpcMessage,
    hop: u32,
) -> Result<Response, Response> {
    let Some((uri, req_id)) = extract_subscribe(message) else {
        return Err((
            StatusCode::BAD_REQUEST,
            "invalid resources/subscribe request",
        )
            .into_response());
    };

    let (upstream_id, original_uri) = resolve_resource_owner(state, profile_id, payload, &uri, hop)
        .await
        .map_err(|e| jsonrpc_error_response(req_id, ErrorCode::INVALID_PARAMS, e.to_string()))?;

    if let Some(param) = as_subscribe_mut(message) {
        param.uri = original_uri;
    }

    proxy_to_single_upstream(
        state,
        profile_id,
        payload,
        &upstream_id,
        message.clone(),
        hop,
    )
    .await
}

async fn route_and_proxy_resource_unsubscribe(
    state: &McpState,
    profile_id: &str,
    payload: &TokenPayloadV1,
    _token: String,
    message: &mut ClientJsonRpcMessage,
    hop: u32,
) -> Result<Response, Response> {
    let Some((uri, req_id)) = extract_unsubscribe(message) else {
        return Err((
            StatusCode::BAD_REQUEST,
            "invalid resources/unsubscribe request",
        )
            .into_response());
    };

    let (upstream_id, original_uri) = resolve_resource_owner(state, profile_id, payload, &uri, hop)
        .await
        .map_err(|e| jsonrpc_error_response(req_id, ErrorCode::INVALID_PARAMS, e.to_string()))?;

    if let Some(param) = as_unsubscribe_mut(message) {
        param.uri = original_uri;
    }

    proxy_to_single_upstream(
        state,
        profile_id,
        payload,
        &upstream_id,
        message.clone(),
        hop,
    )
    .await
}

async fn route_and_proxy_prompt_get(
    state: &McpState,
    profile_id: &str,
    payload: &TokenPayloadV1,
    _token: String,
    message: &mut ClientJsonRpcMessage,
    hop: u32,
) -> Result<Response, Response> {
    let Some((name, req_id)) = extract_get_prompt(message) else {
        return Err((StatusCode::BAD_REQUEST, "invalid prompts/get request").into_response());
    };

    let (upstream_id, original_name) = resolve_prompt_owner(state, profile_id, payload, &name, hop)
        .await
        .map_err(|e| jsonrpc_error_response(req_id, ErrorCode::INVALID_PARAMS, e.to_string()))?;

    if let Some(param) = as_get_prompt_mut(message) {
        param.name = original_name;
    }

    proxy_to_single_upstream(
        state,
        profile_id,
        payload,
        &upstream_id,
        message.clone(),
        hop,
    )
    .await
}

async fn route_and_proxy_completion_complete(
    state: &McpState,
    profile_id: &str,
    payload: &TokenPayloadV1,
    _token: String,
    message: &mut ClientJsonRpcMessage,
    hop: u32,
) -> Result<Response, Response> {
    let Some((reference, req_id)) = extract_complete(message) else {
        return Err((
            StatusCode::BAD_REQUEST,
            "invalid completion/complete request",
        )
            .into_response());
    };

    let (upstream_id, rewritten_ref) = match reference {
        Reference::Prompt(p) => {
            let (upstream_id, original_name) =
                resolve_prompt_owner(state, profile_id, payload, &p.name, hop)
                    .await
                    .map_err(|e| {
                        jsonrpc_error_response(req_id, ErrorCode::INVALID_PARAMS, e.to_string())
                    })?;
            (upstream_id, Reference::for_prompt(original_name))
        }
        Reference::Resource(r) => {
            let (upstream_id, original_uri) =
                resolve_resource_owner(state, profile_id, payload, &r.uri, hop)
                    .await
                    .map_err(|e| {
                        jsonrpc_error_response(req_id, ErrorCode::INVALID_PARAMS, e.to_string())
                    })?;
            (upstream_id, Reference::for_resource(original_uri))
        }
    };

    if let Some(param) = as_complete_mut(message) {
        param.r#ref = rewritten_ref;
    }

    proxy_to_single_upstream(
        state,
        profile_id,
        payload,
        &upstream_id,
        message.clone(),
        hop,
    )
    .await
}

fn extract_call_tool(
    message: &ClientJsonRpcMessage,
) -> Option<(String, rmcp::model::RequestId, serde_json::Value)> {
    let ClientJsonRpcMessage::Request(JsonRpcRequest { id, request, .. }) = message else {
        return None;
    };
    let ClientRequest::CallToolRequest(call) = request else {
        return None;
    };
    let args = call.params.arguments.clone().unwrap_or_default();
    Some((
        call.params.name.to_string(),
        id.clone(),
        serde_json::Value::Object(args),
    ))
}

fn as_call_tool_mut(message: &mut ClientJsonRpcMessage) -> Option<&mut CallToolRequestParam> {
    let ClientJsonRpcMessage::Request(JsonRpcRequest { request, .. }) = message else {
        return None;
    };
    let ClientRequest::CallToolRequest(call) = request else {
        return None;
    };
    Some(&mut call.params)
}

fn extract_read_resource(
    message: &ClientJsonRpcMessage,
) -> Option<(String, rmcp::model::RequestId)> {
    let ClientJsonRpcMessage::Request(JsonRpcRequest { id, request, .. }) = message else {
        return None;
    };
    let ClientRequest::ReadResourceRequest(req) = request else {
        return None;
    };
    Some((req.params.uri.clone(), id.clone()))
}

fn extract_subscribe(message: &ClientJsonRpcMessage) -> Option<(String, rmcp::model::RequestId)> {
    let ClientJsonRpcMessage::Request(JsonRpcRequest { id, request, .. }) = message else {
        return None;
    };
    let ClientRequest::SubscribeRequest(req) = request else {
        return None;
    };
    Some((req.params.uri.clone(), id.clone()))
}

fn as_subscribe_mut(message: &mut ClientJsonRpcMessage) -> Option<&mut SubscribeRequestParam> {
    let ClientJsonRpcMessage::Request(JsonRpcRequest { request, .. }) = message else {
        return None;
    };
    let ClientRequest::SubscribeRequest(req) = request else {
        return None;
    };
    Some(&mut req.params)
}

fn extract_unsubscribe(message: &ClientJsonRpcMessage) -> Option<(String, rmcp::model::RequestId)> {
    let ClientJsonRpcMessage::Request(JsonRpcRequest { id, request, .. }) = message else {
        return None;
    };
    let ClientRequest::UnsubscribeRequest(req) = request else {
        return None;
    };
    Some((req.params.uri.clone(), id.clone()))
}

fn as_unsubscribe_mut(message: &mut ClientJsonRpcMessage) -> Option<&mut UnsubscribeRequestParam> {
    let ClientJsonRpcMessage::Request(JsonRpcRequest { request, .. }) = message else {
        return None;
    };
    let ClientRequest::UnsubscribeRequest(req) = request else {
        return None;
    };
    Some(&mut req.params)
}

fn as_read_resource_mut(
    message: &mut ClientJsonRpcMessage,
) -> Option<&mut ReadResourceRequestParam> {
    let ClientJsonRpcMessage::Request(JsonRpcRequest { request, .. }) = message else {
        return None;
    };
    let ClientRequest::ReadResourceRequest(req) = request else {
        return None;
    };
    Some(&mut req.params)
}

fn extract_get_prompt(message: &ClientJsonRpcMessage) -> Option<(String, rmcp::model::RequestId)> {
    let ClientJsonRpcMessage::Request(JsonRpcRequest { id, request, .. }) = message else {
        return None;
    };
    let ClientRequest::GetPromptRequest(req) = request else {
        return None;
    };
    Some((req.params.name.clone(), id.clone()))
}

fn as_get_prompt_mut(message: &mut ClientJsonRpcMessage) -> Option<&mut GetPromptRequestParam> {
    let ClientJsonRpcMessage::Request(JsonRpcRequest { request, .. }) = message else {
        return None;
    };
    let ClientRequest::GetPromptRequest(req) = request else {
        return None;
    };
    Some(&mut req.params)
}

fn extract_complete(message: &ClientJsonRpcMessage) -> Option<(Reference, rmcp::model::RequestId)> {
    let ClientJsonRpcMessage::Request(JsonRpcRequest { id, request, .. }) = message else {
        return None;
    };
    let ClientRequest::CompleteRequest(req) = request else {
        return None;
    };
    Some((req.params.r#ref.clone(), id.clone()))
}

fn as_complete_mut(
    message: &mut ClientJsonRpcMessage,
) -> Option<&mut rmcp::model::CompleteRequestParam> {
    let ClientJsonRpcMessage::Request(JsonRpcRequest { request, .. }) = message else {
        return None;
    };
    let ClientRequest::CompleteRequest(req) = request else {
        return None;
    };
    Some(&mut req.params)
}

fn as_request_ref(message: &ClientJsonRpcMessage) -> Option<&JsonRpcRequest<ClientRequest>> {
    let ClientJsonRpcMessage::Request(req) = message else {
        return None;
    };
    Some(req)
}

fn sse_single_message(msg: &ServerJsonRpcMessage) -> Response {
    let data = serde_json::to_string(&msg).expect("valid json");
    let stream = futures::stream::once(async move {
        Ok::<_, Infallible>(axum::response::sse::Event::default().data(data))
    });
    let mut resp = Sse::new(stream).into_response();
    resp.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static(EVENT_STREAM_MIME_TYPE),
    );
    resp
}

fn sse_single_message_with_session_id(msg: &ServerJsonRpcMessage, session_id: &str) -> Response {
    let mut resp = sse_single_message(msg);
    resp.headers_mut().insert(
        HEADER_SESSION_ID,
        HeaderValue::from_str(session_id).expect("valid header"),
    );
    resp
}

fn sse_from_upstream_stream<S>(stream: S) -> Response
where
    S: Stream<Item = Result<sse_stream::Sse, sse_stream::Error>> + Send + 'static,
{
    let mapped = stream.map(|evt| match evt {
        Ok(sse) => {
            let mut ev = axum::response::sse::Event::default();
            if let Some(id) = sse.id {
                ev = ev.id(id);
            }
            if let Some(data) = sse.data {
                ev = ev.data(data);
            }
            Ok::<_, Infallible>(ev)
        }
        Err(e) => {
            tracing::warn!(error = %e, "upstream sse error");
            Ok::<_, Infallible>(axum::response::sse::Event::default().comment("upstream error"))
        }
    });
    let mut resp = Sse::new(mapped).into_response();
    resp.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static(EVENT_STREAM_MIME_TYPE),
    );
    resp
}

fn sse_from_upstream_stream_with_timeout<S>(stream: S, timeout: std::time::Duration) -> Response
where
    S: Stream<Item = Result<sse_stream::Sse, sse_stream::Error>> + Send + 'static,
{
    // Best-effort: cap a single request's SSE response lifetime to avoid hanging forever.
    let mapped = stream.map(|evt| match evt {
        Ok(sse) => {
            let mut ev = axum::response::sse::Event::default();
            if let Some(id) = sse.id {
                ev = ev.id(id);
            }
            if let Some(data) = sse.data {
                ev = ev.data(data);
            }
            Ok::<_, Infallible>(ev)
        }
        Err(e) => {
            tracing::warn!(error = %e, "upstream sse error");
            Ok::<_, Infallible>(axum::response::sse::Event::default().comment("upstream error"))
        }
    });

    let deadline = tokio::time::sleep(timeout);
    let mapped = mapped.take_until(deadline);

    let mut resp = Sse::new(mapped).into_response();
    resp.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static(EVENT_STREAM_MIME_TYPE),
    );
    resp
}

fn ensure_accepts_post(headers: &HeaderMap) -> Result<(), (StatusCode, &'static str)> {
    let accept = headers
        .get(axum::http::header::ACCEPT)
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default();
    if accept.contains(JSON_MIME_TYPE) && accept.contains(EVENT_STREAM_MIME_TYPE) {
        Ok(())
    } else {
        Err((
            StatusCode::NOT_ACCEPTABLE,
            "Not Acceptable: Client must accept both application/json and text/event-stream",
        ))
    }
}

fn ensure_accepts_get(headers: &HeaderMap) -> Result<(), (StatusCode, &'static str)> {
    let accept = headers
        .get(axum::http::header::ACCEPT)
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default();
    if accept.contains(EVENT_STREAM_MIME_TYPE) {
        Ok(())
    } else {
        Err((
            StatusCode::NOT_ACCEPTABLE,
            "Not Acceptable: Client must accept text/event-stream",
        ))
    }
}

fn ensure_json_content_type(headers: &HeaderMap) -> Result<(), (StatusCode, &'static str)> {
    let ct = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default();
    if ct.starts_with(JSON_MIME_TYPE) {
        Ok(())
    } else {
        Err((
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Unsupported Media Type: Content-Type must be application/json",
        ))
    }
}

fn internal_error_response(context: &'static str) -> impl FnOnce(anyhow::Error) -> Response {
    move |e| {
        tracing::error!(error = %e, "internal error when {context}");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Internal error when {context}: {e}"),
        )
            .into_response()
    }
}

fn jsonrpc_error_response(
    id: rmcp::model::RequestId,
    code: ErrorCode,
    message: String,
) -> Response {
    jsonrpc_error_response_with_data(id, code, message, None)
}

fn jsonrpc_error_response_with_data(
    id: rmcp::model::RequestId,
    code: ErrorCode,
    message: String,
    data: Option<serde_json::Value>,
) -> Response {
    let error = ServerJsonRpcMessage::Error(JsonRpcError {
        jsonrpc: JsonRpcVersion2_0,
        id,
        error: ErrorData::new(code, message, data),
    });
    sse_single_message(&error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::GatewayConfig;
    use crate::tool_policy::{RetryPolicy, ToolPolicy};
    use crate::tools_cache::{CachedToolsSurface, ToolRoute, ToolRouteKind, profile_fingerprint};
    use async_trait::async_trait;
    use axum::{
        Router,
        routing::{get, post},
    };
    use rmcp::model::{
        ClientCapabilities, Implementation, InitializeRequest, InitializeRequestParam,
    };
    use std::borrow::Cow;
    use std::collections::{HashMap, HashSet};
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    };
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use tokio::net::TcpListener;

    #[test]
    fn tools_call_args_validation_reports_unknown_param_with_suggestion() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "petId": { "type": "integer" }
            },
            "required": ["petId"]
        });
        let schema_obj = schema.as_object().unwrap().clone();
        let tool = rmcp::model::Tool::new(
            "getPetById".to_string(),
            String::new(),
            Arc::new(schema_obj),
        );

        let (msg, data) =
            super::tool_call::validate_tool_arguments(&tool, &serde_json::json!({ "petID": 1 }))
                .unwrap_err();
        assert!(msg.contains("did you mean 'petId'"), "message: {msg}");
        assert_eq!(
            data.get("type").and_then(serde_json::Value::as_str),
            Some("validation-errors")
        );
        assert!(
            data.get("violations")
                .and_then(serde_json::Value::as_array)
                .is_some(),
            "expected violations array"
        );
    }

    #[test]
    fn upstream_initialize_rewrite_strip_allowlist_and_clientinfo() {
        let caps: ClientCapabilities = serde_json::from_value(serde_json::json!({
            "roots": { "listChanged": true },
            "sampling": {},
            "elicitation": { "form": {}, "url": {} }
        }))
        .expect("valid client capabilities");

        let init = InitializeRequest::new(InitializeRequestParam {
            protocol_version: rmcp::model::ProtocolVersion::default(),
            capabilities: caps,
            client_info: Implementation {
                name: "DownstreamClient".to_string(),
                version: "0.1.0".to_string(),
                ..Default::default()
            },
        });
        let msg = ClientJsonRpcMessage::Request(JsonRpcRequest {
            jsonrpc: JsonRpcVersion2_0,
            id: rmcp::model::RequestId::Number(1),
            request: ClientRequest::InitializeRequest(init),
        });

        // Strip capabilities.
        let strip_policy = crate::store::UpstreamSecurityPolicy {
            client_capabilities_mode: crate::store::UpstreamClientCapabilitiesMode::Strip,
            ..Default::default()
        };
        let rewritten = upstream::rewrite_upstream_initialize_message(&msg, &strip_policy);
        let stripped_caps = match &rewritten {
            ClientJsonRpcMessage::Request(JsonRpcRequest {
                request: ClientRequest::InitializeRequest(init),
                ..
            }) => serde_json::to_value(&init.params.capabilities).expect("serialize caps"),
            other => panic!("expected initialize request, got {other:?}"),
        };
        assert!(
            stripped_caps
                .as_object()
                .is_some_and(serde_json::Map::is_empty),
            "expected empty capabilities, got {stripped_caps:?}"
        );

        // Allowlist only roots.
        let allow_policy = crate::store::UpstreamSecurityPolicy {
            client_capabilities_mode: crate::store::UpstreamClientCapabilitiesMode::Allowlist,
            client_capabilities_allow: vec!["roots".to_string()],
            ..Default::default()
        };
        let rewritten = upstream::rewrite_upstream_initialize_message(&msg, &allow_policy);
        let allow_caps = match &rewritten {
            ClientJsonRpcMessage::Request(JsonRpcRequest {
                request: ClientRequest::InitializeRequest(init),
                ..
            }) => serde_json::to_value(&init.params.capabilities).expect("serialize caps"),
            other => panic!("expected initialize request, got {other:?}"),
        };
        assert!(
            allow_caps.get("roots").is_some(),
            "expected roots capability present, got {allow_caps:?}"
        );
        assert!(
            allow_caps.get("sampling").is_none(),
            "expected sampling stripped, got {allow_caps:?}"
        );
        assert!(
            allow_caps.get("elicitation").is_none(),
            "expected elicitation stripped, got {allow_caps:?}"
        );

        // Rewrite clientInfo (privacy).
        let ci_policy = crate::store::UpstreamSecurityPolicy {
            rewrite_client_info: true,
            ..Default::default()
        };
        let rewritten = upstream::rewrite_upstream_initialize_message(&msg, &ci_policy);
        let client_info = match &rewritten {
            ClientJsonRpcMessage::Request(JsonRpcRequest {
                request: ClientRequest::InitializeRequest(init),
                ..
            }) => init.params.client_info.clone(),
            other => panic!("expected initialize request, got {other:?}"),
        };
        assert_eq!(client_info.name, "unrelated-mcp-gateway");
    }

    #[derive(Clone)]
    struct TestStore {
        profiles: HashMap<String, crate::store::Profile>,
        upstreams: HashMap<String, crate::store::Upstream>,
    }

    #[async_trait]
    impl crate::store::Store for TestStore {
        async fn get_profile(
            &self,
            profile_id: &str,
        ) -> anyhow::Result<Option<crate::store::Profile>> {
            Ok(self.profiles.get(profile_id).cloned())
        }
        async fn get_upstream(
            &self,
            upstream_id: &str,
        ) -> anyhow::Result<Option<crate::store::Upstream>> {
            Ok(self.upstreams.get(upstream_id).cloned())
        }
        async fn get_tenant_tool_source(
            &self,
            _tenant_id: &str,
            _source_id: &str,
        ) -> anyhow::Result<Option<crate::store::TenantToolSource>> {
            Ok(None)
        }
        async fn get_tenant_secret_value(
            &self,
            _tenant_id: &str,
            _name: &str,
        ) -> anyhow::Result<Option<String>> {
            Ok(None)
        }
        async fn get_tenant_transport_limits(
            &self,
            _tenant_id: &str,
        ) -> anyhow::Result<Option<crate::store::TransportLimitsSettings>> {
            Ok(None)
        }
        async fn authenticate_api_key(
            &self,
            _tenant_id: &str,
            _profile_id: &str,
            _secret: &str,
        ) -> anyhow::Result<Option<crate::store::ApiKeyAuth>> {
            Ok(None)
        }
        async fn is_api_key_active(
            &self,
            _tenant_id: &str,
            _api_key_id: &str,
        ) -> anyhow::Result<bool> {
            Ok(false)
        }
        async fn touch_api_key(&self, _tenant_id: &str, _api_key_id: &str) -> anyhow::Result<()> {
            Ok(())
        }
        async fn record_tool_call_attempt(
            &self,
            _tenant_id: &str,
            _api_key_id: &str,
        ) -> anyhow::Result<()> {
            Ok(())
        }
        async fn check_and_apply_tool_call_limits(
            &self,
            _tenant_id: &str,
            _profile_id: &str,
            _api_key_id: &str,
            _rate_limit_tool_calls_per_minute: Option<i64>,
            _quota_tool_calls: Option<i64>,
        ) -> anyhow::Result<Option<crate::store::ToolCallLimitRejection>> {
            Ok(None)
        }
        async fn is_oidc_principal_allowed(
            &self,
            _tenant_id: &str,
            _profile_id: &str,
            _issuer: &str,
            _subject: &str,
        ) -> anyhow::Result<bool> {
            Ok(false)
        }
    }

    async fn start_server(app: Router) -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve");
        });
        (format!("http://{addr}"), handle)
    }

    #[test]
    fn retry_delay_matches_temporal_style_backoff() {
        let policy = RetryPolicy {
            maximum_attempts: 5,
            initial_interval_ms: 100,
            backoff_coefficient: 2.0,
            maximum_interval_ms: Some(1_000),
            non_retryable_error_types: vec![],
        };
        assert_eq!(
            super::tool_call::retry_delay(&policy, 1),
            Duration::from_millis(100)
        );
        assert_eq!(
            super::tool_call::retry_delay(&policy, 2),
            Duration::from_millis(200)
        );
        assert_eq!(
            super::tool_call::retry_delay(&policy, 3),
            Duration::from_millis(400)
        );
        assert_eq!(
            super::tool_call::retry_delay(&policy, 4),
            Duration::from_millis(800)
        );
        assert_eq!(
            super::tool_call::retry_delay(&policy, 5),
            Duration::from_millis(1_000)
        ); // capped
    }

    #[test]
    fn proxied_request_id_roundtrips_opaque_and_readable() {
        let original = RequestId::Number(42);

        // Opaque: base64 encodes upstream id so dots/utf8 are safe.
        let upstream_opaque = "u.one.two/✓";
        let proxied = make_proxied_request_id(
            RequestIdNamespacing::Opaque,
            upstream_opaque,
            &original,
            None,
        );
        let Some((got_upstream, got_original)) = parse_proxied_request_id(&proxied, None) else {
            panic!("failed to parse opaque proxied request id: {proxied:?}");
        };
        assert_eq!(got_upstream, upstream_opaque);
        assert_eq!(got_original, original);

        // Readable: upstream id is used as-is; parsing splits at last '.'.
        let upstream_readable = "u.one.two";
        let proxied = make_proxied_request_id(
            RequestIdNamespacing::Readable,
            upstream_readable,
            &original,
            None,
        );
        let Some((got_upstream, got_original)) = parse_proxied_request_id(&proxied, None) else {
            panic!("failed to parse readable proxied request id: {proxied:?}");
        };
        assert_eq!(got_upstream, upstream_readable);
        assert_eq!(got_original, original);

        // Signed v2: requires a key to parse/route (mitigates forged responses).
        let key = b"0123456789abcdef0123456789abcdef"; // 32 bytes
        let proxied = make_proxied_request_id(
            RequestIdNamespacing::Opaque,
            upstream_opaque,
            &original,
            Some(key),
        );
        let Some((got_upstream, got_original)) = parse_proxied_request_id(&proxied, Some(key))
        else {
            panic!("failed to parse signed proxied request id: {proxied:?}");
        };
        assert_eq!(got_upstream, upstream_opaque);
        assert_eq!(got_original, original);
        assert!(
            parse_proxied_request_id(&proxied, None).is_none(),
            "signed proxied id should not parse without key"
        );

        // Forge: flip one character in the signature (must fail verification).
        let RequestId::String(s) = proxied.clone() else {
            panic!("expected string request id");
        };
        let mut parts: Vec<String> = s.split('.').map(std::string::ToString::to_string).collect();
        let sig = parts.last_mut().expect("sig part");
        if sig.starts_with('A') {
            sig.replace_range(0..1, "B");
        } else {
            sig.replace_range(0..1, "A");
        }
        let forged = RequestId::String(parts.join(".").into());
        assert!(parse_proxied_request_id(&forged, Some(key)).is_none());
    }

    #[test]
    fn resource_collision_urn_is_deterministic_and_parsable() {
        let original = "https://example.com/a?b=c";
        let urn1 = resource_collision_urn("u1", original);
        let urn2 = resource_collision_urn("u1", original);
        assert_eq!(urn1, urn2);
        assert!(urn1.starts_with(super::ids::RESOURCE_URN_PREFIX));

        let (upstream_id, hash) =
            super::ids::parse_resource_collision_urn(&urn1).expect("parse urn");
        assert_eq!(upstream_id, "u1");
        assert!(!hash.is_empty());

        // Upstream id is part of the URN.
        let urn_other = resource_collision_urn("u2", original);
        assert_ne!(urn_other, urn1);
    }

    #[test]
    fn session_token_expiry_maps_to_unauthorized_expired_message() {
        let signer =
            SessionSigner::new(vec![b"secret".to_vec()], Duration::from_secs(0)).expect("signer");
        let payload = TokenPayloadV1 {
            profile_id: "p".to_string(),
            bindings: vec![],
            auth: None,
            oidc: None,
            iat: None,
            exp: None,
            proxy_key: None,
        };
        let token = signer.sign(payload).expect("token");

        // Ensure we're at least 1 unix-second after sign() so `now_secs > exp`.
        let start = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        while SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            == start
        {
            std::thread::yield_now();
        }

        let err = verify_session_token(&signer, &token, "p").unwrap_err();
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
        assert_eq!(
            err.1,
            "Unauthorized: session expired; re-initialize required"
        );
    }

    #[tokio::test]
    async fn post_returns_jsonrpc_invalid_request_for_valid_json_invalid_shape_when_id_present() {
        let profile_id = uuid::Uuid::new_v4().to_string();
        let profile = crate::store::Profile {
            id: profile_id.clone(),
            tenant_id: "t".to_string(),
            allow_partial_upstreams: true,
            source_ids: vec![],
            transforms: unrelated_tool_transforms::TransformPipeline::default(),
            enabled_tools: Vec::new(),
            data_plane_auth_mode: DataPlaneAuthMode::Disabled,
            accept_x_api_key: false,
            rate_limit_enabled: false,
            rate_limit_tool_calls_per_minute: None,
            quota_enabled: false,
            quota_tool_calls: None,
            tool_call_timeout_secs: None,
            tool_policies: vec![],
            mcp: crate::store::McpProfileSettings::default(),
        };

        let store = Arc::new(TestStore {
            profiles: HashMap::from([(profile_id.clone(), profile)]),
            upstreams: HashMap::new(),
        });
        let state = Arc::new(McpState {
            store,
            signer: SessionSigner::new(vec![vec![0u8; 32]], Duration::from_secs(60))
                .expect("signer"),
            http: reqwest::Client::default(),
            oidc: None,
            shutdown: CancellationToken::new(),
            audit: Arc::new(crate::audit::NoopAuditSink),
            catalog: Arc::new(SharedCatalog::default()),
            tenant_catalog: Arc::new(TenantCatalog::new()),
            contracts: Arc::new(ContractTracker::new()),
            contract_fanout: None,
            tools_cache: Arc::new(crate::tools_cache::ToolSurfaceCache::new(
                Duration::from_secs(60),
            )),
            endpoint_cache: Arc::new(crate::endpoint_cache::UpstreamEndpointCache::new(
                Duration::from_secs(60),
            )),
        });

        let app = super::router(state);
        let (base, handle) = start_server(app).await;

        // Valid JSON, but invalid JSON-RPC/MCP shape (`method` must be a string).
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": 123,
            "params": {}
        });

        let resp = reqwest::Client::new()
            .post(format!("{base}/{profile_id}/mcp"))
            .header(
                reqwest::header::ACCEPT,
                format!("{JSON_MIME_TYPE}, {EVENT_STREAM_MIME_TYPE}"),
            )
            .header(reqwest::header::CONTENT_TYPE, JSON_MIME_TYPE)
            .body(body.to_string())
            .send()
            .await
            .expect("post");

        assert_eq!(resp.status(), reqwest::StatusCode::OK);
        assert!(
            resp.headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .starts_with(EVENT_STREAM_MIME_TYPE),
            "expected SSE content-type"
        );

        let text = resp.text().await.expect("body text");
        assert!(
            text.contains(&format!("\"code\":{}", ErrorCode::INVALID_REQUEST.0)),
            "body: {text}"
        );
        assert!(text.contains("invalid-mcp-shape"), "body: {text}");

        handle.abort();
    }

    #[tokio::test]
    async fn post_rejects_when_post_body_limit_exceeded() {
        let profile_id = uuid::Uuid::new_v4().to_string();
        let mut mcp = crate::store::McpProfileSettings::default();
        mcp.security.transport_limits.max_post_body_bytes = Some(128);
        let profile = crate::store::Profile {
            id: profile_id.clone(),
            tenant_id: "t".to_string(),
            allow_partial_upstreams: true,
            source_ids: vec![],
            transforms: unrelated_tool_transforms::TransformPipeline::default(),
            enabled_tools: Vec::new(),
            data_plane_auth_mode: DataPlaneAuthMode::Disabled,
            accept_x_api_key: false,
            rate_limit_enabled: false,
            rate_limit_tool_calls_per_minute: None,
            quota_enabled: false,
            quota_tool_calls: None,
            tool_call_timeout_secs: None,
            tool_policies: vec![],
            mcp,
        };

        let store = Arc::new(TestStore {
            profiles: HashMap::from([(profile_id.clone(), profile)]),
            upstreams: HashMap::new(),
        });
        let state = Arc::new(McpState {
            store,
            signer: SessionSigner::new(vec![vec![0u8; 32]], Duration::from_secs(60))
                .expect("signer"),
            http: reqwest::Client::default(),
            oidc: None,
            shutdown: CancellationToken::new(),
            audit: Arc::new(crate::audit::NoopAuditSink),
            catalog: Arc::new(SharedCatalog::default()),
            tenant_catalog: Arc::new(TenantCatalog::new()),
            contracts: Arc::new(ContractTracker::new()),
            contract_fanout: None,
            tools_cache: Arc::new(crate::tools_cache::ToolSurfaceCache::new(
                Duration::from_secs(60),
            )),
            endpoint_cache: Arc::new(crate::endpoint_cache::UpstreamEndpointCache::new(
                Duration::from_secs(60),
            )),
        });

        let app = super::router(state);
        let (base, handle) = start_server(app).await;

        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": { "pad": "x".repeat(2_048) }
        });

        let resp = reqwest::Client::new()
            .post(format!("{base}/{profile_id}/mcp"))
            .header(
                reqwest::header::ACCEPT,
                format!("{JSON_MIME_TYPE}, {EVENT_STREAM_MIME_TYPE}"),
            )
            .header(reqwest::header::CONTENT_TYPE, JSON_MIME_TYPE)
            .body(body.to_string())
            .send()
            .await
            .expect("post");

        assert_eq!(resp.status(), reqwest::StatusCode::PAYLOAD_TOO_LARGE);
        let text = resp.text().await.expect("body text");
        assert!(text.contains("payload too large"), "body: {text}");

        handle.abort();
    }

    #[tokio::test]
    async fn post_returns_jsonrpc_error_when_json_complexity_limit_exceeded() {
        let profile_id = uuid::Uuid::new_v4().to_string();
        let mut mcp = crate::store::McpProfileSettings::default();
        mcp.security.transport_limits.max_json_depth = Some(2);
        let profile = crate::store::Profile {
            id: profile_id.clone(),
            tenant_id: "t".to_string(),
            allow_partial_upstreams: true,
            source_ids: vec![],
            transforms: unrelated_tool_transforms::TransformPipeline::default(),
            enabled_tools: Vec::new(),
            data_plane_auth_mode: DataPlaneAuthMode::Disabled,
            accept_x_api_key: false,
            rate_limit_enabled: false,
            rate_limit_tool_calls_per_minute: None,
            quota_enabled: false,
            quota_tool_calls: None,
            tool_call_timeout_secs: None,
            tool_policies: vec![],
            mcp,
        };

        let store = Arc::new(TestStore {
            profiles: HashMap::from([(profile_id.clone(), profile)]),
            upstreams: HashMap::new(),
        });
        let state = Arc::new(McpState {
            store,
            signer: SessionSigner::new(vec![vec![0u8; 32]], Duration::from_secs(60))
                .expect("signer"),
            http: reqwest::Client::default(),
            oidc: None,
            shutdown: CancellationToken::new(),
            audit: Arc::new(crate::audit::NoopAuditSink),
            catalog: Arc::new(SharedCatalog::default()),
            tenant_catalog: Arc::new(TenantCatalog::new()),
            contracts: Arc::new(ContractTracker::new()),
            contract_fanout: None,
            tools_cache: Arc::new(crate::tools_cache::ToolSurfaceCache::new(
                Duration::from_secs(60),
            )),
            endpoint_cache: Arc::new(crate::endpoint_cache::UpstreamEndpointCache::new(
                Duration::from_secs(60),
            )),
        });

        let app = super::router(state);
        let (base, handle) = start_server(app).await;

        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/list",
            "params": {
                "nested": {
                    "v": {
                        "x": 1
                    }
                }
            }
        });

        let resp = reqwest::Client::new()
            .post(format!("{base}/{profile_id}/mcp"))
            .header(
                reqwest::header::ACCEPT,
                format!("{JSON_MIME_TYPE}, {EVENT_STREAM_MIME_TYPE}"),
            )
            .header(reqwest::header::CONTENT_TYPE, JSON_MIME_TYPE)
            .body(body.to_string())
            .send()
            .await
            .expect("post");

        assert_eq!(resp.status(), reqwest::StatusCode::OK);
        let text = resp.text().await.expect("body text");
        assert!(
            text.contains(&format!("\"code\":{}", ErrorCode::INVALID_REQUEST.0)),
            "body: {text}"
        );
        assert!(text.contains("payload-too-complex"), "body: {text}");
        assert!(text.contains("maxJsonDepth"), "body: {text}");

        handle.abort();
    }

    #[allow(clippy::too_many_lines)]
    #[tokio::test]
    async fn initialize_profile_sources_fails_over_endpoints() {
        let bad = Router::new().route(
            "/mcp",
            post(|| async { (StatusCode::INTERNAL_SERVER_ERROR, "nope") }),
        );
        let (bad_base, bad_handle) = start_server(bad).await;
        let bad_url = format!("{bad_base}/mcp");

        let good = Router::new().route(
            "/mcp",
            post(|axum::Json(v): axum::Json<serde_json::Value>| async move {
                // Simulate a minimal MCP server over streamable HTTP:
                // - `initialize` returns a session id and a JSON response
                // - `notifications/initialized` returns 202 Accepted
                if v.get("method") == Some(&serde_json::json!("notifications/initialized")) {
                    return (axum::http::StatusCode::ACCEPTED, "").into_response();
                }

                let id = v.get("id").cloned().unwrap_or_else(|| serde_json::json!(1));
                let resp = serde_json::json!({
                  "jsonrpc": "2.0",
                  "id": id,
                  "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "serverInfo": { "name": "test", "version": "0" }
                  }
                });
                let mut headers = HeaderMap::new();
                headers.insert(HEADER_SESSION_ID, HeaderValue::from_static("up-session"));
                (headers, axum::Json(resp)).into_response()
            }),
        );
        let (good_base, good_handle) = start_server(good).await;
        let good_url = format!("{good_base}/mcp");

        let store = Arc::new(TestStore {
            profiles: HashMap::new(),
            upstreams: HashMap::from([(
                "u1".to_string(),
                crate::store::Upstream {
                    endpoints: vec![
                        crate::store::UpstreamEndpoint {
                            id: "a".to_string(),
                            url: bad_url,
                            auth: None,
                        },
                        crate::store::UpstreamEndpoint {
                            id: "b".to_string(),
                            url: good_url,
                            auth: None,
                        },
                    ],
                },
            )]),
        });

        let state = McpState {
            store,
            signer: SessionSigner::new(vec![vec![0u8; 32]], Duration::from_secs(60))
                .expect("signer"),
            http: reqwest::Client::default(),
            oidc: None,
            shutdown: CancellationToken::new(),
            audit: Arc::new(crate::audit::NoopAuditSink),
            catalog: Arc::new(SharedCatalog::default()),
            tenant_catalog: Arc::new(TenantCatalog::new()),
            contracts: Arc::new(ContractTracker::new()),
            contract_fanout: None,
            tools_cache: Arc::new(crate::tools_cache::ToolSurfaceCache::new(
                Duration::from_secs(60),
            )),
            endpoint_cache: Arc::new(crate::endpoint_cache::UpstreamEndpointCache::new(
                Duration::from_secs(60),
            )),
        };

        let profile = crate::store::Profile {
            id: "p".to_string(),
            tenant_id: "t".to_string(),
            allow_partial_upstreams: false,
            source_ids: vec!["u1".to_string()],
            transforms: unrelated_tool_transforms::TransformPipeline::default(),
            enabled_tools: Vec::new(),
            data_plane_auth_mode: DataPlaneAuthMode::Disabled,
            accept_x_api_key: false,
            rate_limit_enabled: false,
            rate_limit_tool_calls_per_minute: None,
            quota_enabled: false,
            quota_tool_calls: None,
            tool_call_timeout_secs: None,
            tool_policies: vec![],
            mcp: crate::store::McpProfileSettings::default(),
        };

        let init = InitializeRequest::new(InitializeRequestParam {
            protocol_version: rmcp::model::ProtocolVersion::default(),
            capabilities: ClientCapabilities::default(),
            client_info: Implementation::from_build_env(),
        });
        let init_msg = ClientJsonRpcMessage::Request(JsonRpcRequest {
            jsonrpc: JsonRpcVersion2_0,
            id: rmcp::model::RequestId::Number(1),
            request: ClientRequest::InitializeRequest(init),
        });

        let (bindings, warnings) = initialize_profile_sources(&state, &profile, &init_msg, 0)
            .await
            .expect("init ok");
        assert!(warnings.is_empty(), "no upstream should be fully down");
        assert_eq!(bindings.len(), 1);
        assert_eq!(bindings[0].upstream, "u1");
        assert_eq!(bindings[0].endpoint, "b");
        assert_eq!(bindings[0].session, "up-session");

        bad_handle.abort();
        good_handle.abort();
    }

    #[allow(clippy::too_many_lines)] // Test includes full upstream mock + gateway wiring.
    #[tokio::test]
    async fn upstream_server_to_client_request_blocking_drops_event_and_errors_upstream() {
        use axum::response::sse::{Event, Sse};
        use futures::StreamExt as _;

        let posted: Arc<Mutex<Vec<serde_json::Value>>> = Arc::new(Mutex::new(Vec::new()));
        let posted_for_post = posted.clone();

        let upstream = Router::new().route(
            "/mcp",
            get(|| async {
                // Server→client request (interactive).
                let data = serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "roots/list",
                    "params": {}
                })
                .to_string();

                let stream =
                    futures::stream::iter(vec![Ok::<_, Infallible>(Event::default().data(data))]);
                Sse::new(stream)
            })
            .post(
                move |axum::Json(v): axum::Json<serde_json::Value>| async move {
                    posted_for_post.lock().expect("lock").push(v);
                    StatusCode::ACCEPTED
                },
            ),
        );
        let (up_base, up_handle) = start_server(upstream).await;
        let up_url = format!("{up_base}/mcp");

        let store = Arc::new(TestStore {
            profiles: HashMap::new(),
            upstreams: HashMap::from([(
                "u1".to_string(),
                crate::store::Upstream {
                    endpoints: vec![crate::store::UpstreamEndpoint {
                        id: "e1".to_string(),
                        url: up_url,
                        auth: None,
                    }],
                },
            )]),
        });

        let state = McpState {
            store,
            signer: SessionSigner::new(vec![vec![0u8; 32]], Duration::from_secs(60))
                .expect("signer"),
            http: reqwest::Client::default(),
            oidc: None,
            shutdown: CancellationToken::new(),
            audit: Arc::new(crate::audit::NoopAuditSink),
            catalog: Arc::new(SharedCatalog::default()),
            tenant_catalog: Arc::new(TenantCatalog::new()),
            contracts: Arc::new(ContractTracker::new()),
            contract_fanout: None,
            tools_cache: Arc::new(crate::tools_cache::ToolSurfaceCache::new(
                Duration::from_secs(60),
            )),
            endpoint_cache: Arc::new(crate::endpoint_cache::UpstreamEndpointCache::new(
                Duration::from_secs(60),
            )),
        };

        let mut mcp = crate::store::McpProfileSettings::default();
        mcp.security.upstream_overrides.insert(
            "u1".to_string(),
            crate::store::UpstreamSecurityPolicy {
                server_requests: crate::store::McpServerRequestFilter {
                    default_action: crate::store::McpPolicyAction::Deny,
                    allow: vec![],
                    deny: vec![],
                },
                ..Default::default()
            },
        );
        let profile = crate::store::Profile {
            id: "p".to_string(),
            tenant_id: "t".to_string(),
            allow_partial_upstreams: true,
            source_ids: vec!["u1".to_string()],
            transforms: unrelated_tool_transforms::TransformPipeline::default(),
            enabled_tools: Vec::new(),
            data_plane_auth_mode: DataPlaneAuthMode::Disabled,
            accept_x_api_key: false,
            rate_limit_enabled: false,
            rate_limit_tool_calls_per_minute: None,
            quota_enabled: false,
            quota_tool_calls: None,
            tool_call_timeout_secs: None,
            tool_policies: vec![],
            mcp,
        };

        let bindings = vec![UpstreamSessionBinding {
            upstream: "u1".to_string(),
            endpoint: "e1".to_string(),
            session: "up-session".to_string(),
        }];

        let collision_counts = Arc::new(parking_lot::RwLock::new(HashMap::new()));
        let limits = crate::transport_limits::EffectiveTransportLimits::from_profile_and_tenant(
            &profile.mcp.security.transport_limits,
            None,
        );
        let last = ParsedLastEventId::default();
        let streams = open_upstream_streams(OpenUpstreamStreamsInputs {
            state: &state,
            profile: &profile,
            bindings: &bindings,
            last: &last,
            resource_collision_counts: collision_counts,
            proxy_key: None,
            hop: 0,
            limits,
            limits_shutdown: CancellationToken::new(),
        })
        .await
        .expect("open streams");
        assert_eq!(streams.len(), 1);

        let mut s = streams.into_iter().next().expect("stream");
        let next = tokio::time::timeout(Duration::from_secs(1), s.next())
            .await
            .expect("timeout");
        assert!(
            next.is_none(),
            "expected blocked upstream request to be dropped"
        );

        let posts = posted.lock().expect("lock").clone();
        assert_eq!(posts.len(), 1, "expected one error response to upstream");
        let err = &posts[0];
        assert_eq!(err.get("jsonrpc"), Some(&serde_json::json!("2.0")));
        assert_eq!(err.get("id"), Some(&serde_json::json!(1)));
        assert_eq!(
            err.get("error")
                .and_then(|e| e.get("code"))
                .and_then(serde_json::Value::as_i64),
            Some(i64::from(ErrorCode::METHOD_NOT_FOUND.0))
        );

        up_handle.abort();
    }

    #[derive(Clone)]
    struct CountingStore {
        upstreams: HashMap<String, crate::store::Upstream>,
        tenant_sources: HashSet<String>,
        get_upstream_calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl crate::store::Store for CountingStore {
        async fn get_profile(
            &self,
            _profile_id: &str,
        ) -> anyhow::Result<Option<crate::store::Profile>> {
            Ok(None)
        }

        async fn get_upstream(
            &self,
            upstream_id: &str,
        ) -> anyhow::Result<Option<crate::store::Upstream>> {
            self.get_upstream_calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.upstreams.get(upstream_id).cloned())
        }

        async fn get_tenant_tool_source(
            &self,
            _tenant_id: &str,
            source_id: &str,
        ) -> anyhow::Result<Option<crate::store::TenantToolSource>> {
            if self.tenant_sources.contains(source_id) {
                // We don't need a usable spec for this test: we only need TenantCatalog::has_tool_source
                // to return true, which is based on presence.
                return Ok(Some(crate::store::TenantToolSource {
                    id: source_id.to_string(),
                    kind: crate::store::ToolSourceKind::Http,
                    enabled: true,
                    spec: crate::store::ToolSourceSpec::Http(
                        unrelated_http_tools::config::HttpServerConfig {
                            base_url: "https://example.com".to_string(),
                            auth: None,
                            defaults: unrelated_http_tools::config::EndpointDefaults::default(),
                            response_transforms: vec![],
                            tools: HashMap::new(),
                        },
                    ),
                }));
            }
            Ok(None)
        }

        async fn get_tenant_secret_value(
            &self,
            _tenant_id: &str,
            _name: &str,
        ) -> anyhow::Result<Option<String>> {
            Ok(None)
        }

        async fn get_tenant_transport_limits(
            &self,
            _tenant_id: &str,
        ) -> anyhow::Result<Option<crate::store::TransportLimitsSettings>> {
            Ok(None)
        }

        async fn authenticate_api_key(
            &self,
            _tenant_id: &str,
            _profile_id: &str,
            _secret: &str,
        ) -> anyhow::Result<Option<crate::store::ApiKeyAuth>> {
            Ok(None)
        }

        async fn is_api_key_active(
            &self,
            _tenant_id: &str,
            _api_key_id: &str,
        ) -> anyhow::Result<bool> {
            Ok(false)
        }

        async fn touch_api_key(&self, _tenant_id: &str, _api_key_id: &str) -> anyhow::Result<()> {
            Ok(())
        }

        async fn record_tool_call_attempt(
            &self,
            _tenant_id: &str,
            _api_key_id: &str,
        ) -> anyhow::Result<()> {
            Ok(())
        }

        async fn check_and_apply_tool_call_limits(
            &self,
            _tenant_id: &str,
            _profile_id: &str,
            _api_key_id: &str,
            _rate_limit_tool_calls_per_minute: Option<i64>,
            _quota_tool_calls: Option<i64>,
        ) -> anyhow::Result<Option<crate::store::ToolCallLimitRejection>> {
            Ok(None)
        }

        async fn is_oidc_principal_allowed(
            &self,
            _tenant_id: &str,
            _profile_id: &str,
            _issuer: &str,
            _subject: &str,
        ) -> anyhow::Result<bool> {
            Ok(false)
        }
    }

    #[tokio::test]
    async fn initialize_profile_sources_skips_shared_and_tenant_local_sources() -> anyhow::Result<()>
    {
        let cfg: GatewayConfig = serde_yaml::from_str(
            r"
tenants: {}
profiles: {}
upstreams: {}
sharedSources:
  s_local:
    type: http
    enabled: true
    public: true
    baseUrl: https://example.com
    tools:
      local_ping:
        method: GET
        path: /ping
",
        )
        .expect("valid yaml");
        let shared = SharedCatalog::from_config(&cfg).await?;

        let calls = Arc::new(AtomicUsize::new(0));
        let store = Arc::new(CountingStore {
            upstreams: HashMap::from([(
                "u1".to_string(),
                crate::store::Upstream {
                    endpoints: vec![crate::store::UpstreamEndpoint {
                        id: "e1".to_string(),
                        url: "http://127.0.0.1:1/mcp".to_string(),
                        auth: None,
                    }],
                },
            )]),
            tenant_sources: HashSet::from(["t_local".to_string()]),
            get_upstream_calls: calls.clone(),
        });

        let state = McpState {
            store,
            signer: SessionSigner::new(vec![vec![0u8; 32]], Duration::from_secs(60))
                .expect("signer"),
            http: reqwest::Client::default(),
            oidc: None,
            shutdown: CancellationToken::new(),
            audit: Arc::new(crate::audit::NoopAuditSink),
            catalog: Arc::new(shared),
            tenant_catalog: Arc::new(TenantCatalog::new()),
            contracts: Arc::new(ContractTracker::new()),
            contract_fanout: None,
            tools_cache: Arc::new(crate::tools_cache::ToolSurfaceCache::new(
                Duration::from_secs(60),
            )),
            endpoint_cache: Arc::new(crate::endpoint_cache::UpstreamEndpointCache::new(
                Duration::from_secs(60),
            )),
        };

        let profile = crate::store::Profile {
            id: "p".to_string(),
            tenant_id: "t".to_string(),
            allow_partial_upstreams: true,
            source_ids: vec![
                "s_local".to_string(),
                "t_local".to_string(),
                "u1".to_string(),
            ],
            transforms: unrelated_tool_transforms::TransformPipeline::default(),
            enabled_tools: Vec::new(),
            data_plane_auth_mode: DataPlaneAuthMode::Disabled,
            accept_x_api_key: false,
            rate_limit_enabled: false,
            rate_limit_tool_calls_per_minute: None,
            quota_enabled: false,
            quota_tool_calls: None,
            tool_call_timeout_secs: None,
            tool_policies: vec![],
            mcp: crate::store::McpProfileSettings::default(),
        };

        let init = InitializeRequest::new(InitializeRequestParam {
            protocol_version: rmcp::model::ProtocolVersion::default(),
            capabilities: ClientCapabilities::default(),
            client_info: Implementation::from_build_env(),
        });
        let init_msg = ClientJsonRpcMessage::Request(JsonRpcRequest {
            jsonrpc: JsonRpcVersion2_0,
            id: rmcp::model::RequestId::Number(1),
            request: ClientRequest::InitializeRequest(init),
        });

        // We expect this to try resolving exactly one upstream id ("u1"), skipping local sources.
        // It will fail to initialize because endpoint is unreachable, but allow_partial_upstreams
        // should make it return a warning instead of an error.
        let (_bindings, warnings) = initialize_profile_sources(&state, &profile, &init_msg, 0)
            .await
            .expect("init ok");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(warnings.len(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn tools_surface_prefixes_on_collision_across_shared_sources() -> anyhow::Result<()> {
        let cfg: GatewayConfig = serde_yaml::from_str(
            r"
tenants: {}
profiles: {}
upstreams: {}
sharedSources:
  s1:
    type: http
    enabled: true
    public: true
    baseUrl: https://example.com
    tools:
      ping:
        method: GET
        path: /ping
  s2:
    type: http
    enabled: true
    public: true
    baseUrl: https://example.com
    tools:
      ping:
        method: GET
        path: /ping
",
        )
        .expect("valid yaml");
        let shared = SharedCatalog::from_config(&cfg).await?;

        let store = Arc::new(TestStore {
            profiles: HashMap::new(),
            upstreams: HashMap::new(),
        });
        let state = McpState {
            store,
            signer: SessionSigner::new(vec![vec![0u8; 32]], Duration::from_secs(60))
                .expect("signer"),
            http: reqwest::Client::default(),
            oidc: None,
            shutdown: CancellationToken::new(),
            audit: Arc::new(crate::audit::NoopAuditSink),
            catalog: Arc::new(shared),
            tenant_catalog: Arc::new(TenantCatalog::new()),
            contracts: Arc::new(ContractTracker::new()),
            contract_fanout: None,
            tools_cache: Arc::new(crate::tools_cache::ToolSurfaceCache::new(
                Duration::from_secs(60),
            )),
            endpoint_cache: Arc::new(crate::endpoint_cache::UpstreamEndpointCache::new(
                Duration::from_secs(60),
            )),
        };

        let profile = crate::store::Profile {
            id: "p".to_string(),
            tenant_id: "t".to_string(),
            allow_partial_upstreams: true,
            source_ids: vec!["s1".to_string(), "s2".to_string()],
            transforms: unrelated_tool_transforms::TransformPipeline::default(),
            enabled_tools: Vec::new(),
            data_plane_auth_mode: DataPlaneAuthMode::Disabled,
            accept_x_api_key: false,
            rate_limit_enabled: false,
            rate_limit_tool_calls_per_minute: None,
            quota_enabled: false,
            quota_tool_calls: None,
            tool_call_timeout_secs: None,
            tool_policies: vec![],
            mcp: crate::store::McpProfileSettings::default(),
        };
        let payload = TokenPayloadV1 {
            profile_id: profile.id.clone(),
            bindings: vec![],
            auth: None,
            oidc: None,
            iat: None,
            exp: None,
            proxy_key: None,
        };

        let surface =
            super::surface::build_tools_surface(&state, &profile.id, &profile, &payload, 0)
                .await
                .expect("build tools surface");
        assert!(surface.ambiguous_names.contains("ping"));
        assert!(!surface.routes.contains_key("ping"));
        assert!(surface.routes.contains_key("s1:ping"));
        assert!(surface.routes.contains_key("s2:ping"));

        let r1 = surface.routes.get("s1:ping").expect("s1 route");
        assert_eq!(r1.kind, ToolRouteKind::SharedLocal);
        assert_eq!(r1.source_id, "s1");
        assert_eq!(r1.original_name, "ping");

        Ok(())
    }

    #[tokio::test]
    async fn tools_surface_allows_optional_prefix_when_not_ambiguous() -> anyhow::Result<()> {
        let cfg: GatewayConfig = serde_yaml::from_str(
            r"
tenants: {}
profiles: {}
upstreams: {}
sharedSources:
  s1:
    type: http
    enabled: true
    public: true
    baseUrl: https://example.com
    tools:
      ping:
        method: GET
        path: /ping
",
        )
        .expect("valid yaml");
        let shared = SharedCatalog::from_config(&cfg).await?;

        let store = Arc::new(TestStore {
            profiles: HashMap::new(),
            upstreams: HashMap::new(),
        });
        let state = McpState {
            store,
            signer: SessionSigner::new(vec![vec![0u8; 32]], Duration::from_secs(60))
                .expect("signer"),
            http: reqwest::Client::default(),
            oidc: None,
            shutdown: CancellationToken::new(),
            audit: Arc::new(crate::audit::NoopAuditSink),
            catalog: Arc::new(shared),
            tenant_catalog: Arc::new(TenantCatalog::new()),
            contracts: Arc::new(ContractTracker::new()),
            contract_fanout: None,
            tools_cache: Arc::new(crate::tools_cache::ToolSurfaceCache::new(
                Duration::from_secs(60),
            )),
            endpoint_cache: Arc::new(crate::endpoint_cache::UpstreamEndpointCache::new(
                Duration::from_secs(60),
            )),
        };

        let profile = crate::store::Profile {
            id: "p".to_string(),
            tenant_id: "t".to_string(),
            allow_partial_upstreams: true,
            source_ids: vec!["s1".to_string()],
            transforms: unrelated_tool_transforms::TransformPipeline::default(),
            enabled_tools: Vec::new(),
            data_plane_auth_mode: DataPlaneAuthMode::Disabled,
            accept_x_api_key: false,
            rate_limit_enabled: false,
            rate_limit_tool_calls_per_minute: None,
            quota_enabled: false,
            quota_tool_calls: None,
            tool_call_timeout_secs: None,
            tool_policies: vec![],
            mcp: crate::store::McpProfileSettings::default(),
        };
        let payload = TokenPayloadV1 {
            profile_id: profile.id.clone(),
            bindings: vec![],
            auth: None,
            oidc: None,
            iat: None,
            exp: None,
            proxy_key: None,
        };

        let surface =
            super::surface::build_tools_surface(&state, &profile.id, &profile, &payload, 0)
                .await
                .expect("build tools surface");
        assert!(!surface.ambiguous_names.contains("ping"));
        assert!(surface.routes.contains_key("ping"));
        assert!(surface.routes.contains_key("s1:ping"));

        let base = surface.routes.get("ping").expect("base route");
        let pref = surface.routes.get("s1:ping").expect("pref route");
        assert_eq!(base.kind, ToolRouteKind::SharedLocal);
        assert_eq!(pref.kind, ToolRouteKind::SharedLocal);
        assert_eq!(base.source_id, "s1");
        assert_eq!(pref.source_id, "s1");
        assert_eq!(base.original_name, "ping");
        assert_eq!(pref.original_name, "ping");
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    #[tokio::test]
    async fn tool_call_propagates_timeout_budget_meta_and_retries_when_configured() {
        let seen_timeout_ms = Arc::new(Mutex::new(None::<u64>));
        let calls = Arc::new(AtomicUsize::new(0));
        let app = Router::new().route(
            "/mcp",
            post({
                let seen_timeout_ms = seen_timeout_ms.clone();
                let calls = calls.clone();
                move |axum::Json(v): axum::Json<serde_json::Value>| async move {
                    let n = calls.fetch_add(1, Ordering::SeqCst);
                    let timeout_ms = v
                        .get("params")
                        .and_then(|p| p.get("_meta"))
                        .and_then(|m| m.get("unrelated"))
                        .and_then(|m| m.get("timeoutMs"))
                        .and_then(serde_json::Value::as_u64);
                    *seen_timeout_ms.lock().expect("lock") = timeout_ms;

                    // Fail the first attempt to force a retry.
                    if n == 0 {
                        return (StatusCode::INTERNAL_SERVER_ERROR, "try again").into_response();
                    }

                    let id = v.get("id").cloned().unwrap_or_else(|| serde_json::json!(1));
                    let resp = serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": {
                            "content": [{ "type": "text", "text": "ok" }],
                            "isError": false
                        }
                    });
                    axum::Json(resp).into_response()
                }
            }),
        );
        let (base, handle) = start_server(app).await;
        let url = format!("{base}/mcp");

        let store = Arc::new(TestStore {
            profiles: HashMap::new(),
            upstreams: HashMap::from([(
                "u1".to_string(),
                crate::store::Upstream {
                    endpoints: vec![crate::store::UpstreamEndpoint {
                        id: "e1".to_string(),
                        url,
                        auth: None,
                    }],
                },
            )]),
        });

        let state = McpState {
            store,
            signer: SessionSigner::new(vec![vec![0u8; 32]], Duration::from_secs(60))
                .expect("signer"),
            http: reqwest::Client::default(),
            oidc: None,
            shutdown: CancellationToken::new(),
            audit: Arc::new(crate::audit::NoopAuditSink),
            catalog: Arc::new(SharedCatalog::default()),
            tenant_catalog: Arc::new(TenantCatalog::new()),
            contracts: Arc::new(ContractTracker::new()),
            contract_fanout: None,
            tools_cache: Arc::new(crate::tools_cache::ToolSurfaceCache::new(
                Duration::from_secs(60),
            )),
            endpoint_cache: Arc::new(crate::endpoint_cache::UpstreamEndpointCache::new(
                Duration::from_secs(60),
            )),
        };

        let profile = crate::store::Profile {
            id: "p".to_string(),
            tenant_id: "t".to_string(),
            allow_partial_upstreams: false,
            source_ids: vec!["u1".to_string()],
            transforms: unrelated_tool_transforms::TransformPipeline::default(),
            enabled_tools: Vec::new(),
            data_plane_auth_mode: DataPlaneAuthMode::Disabled,
            accept_x_api_key: false,
            rate_limit_enabled: false,
            rate_limit_tool_calls_per_minute: None,
            quota_enabled: false,
            quota_tool_calls: None,
            tool_call_timeout_secs: None,
            tool_policies: vec![ToolPolicy {
                tool: "u1:foo".to_string(),
                timeout_secs: Some(2),
                retry: Some(RetryPolicy {
                    maximum_attempts: 2,
                    initial_interval_ms: 0,
                    backoff_coefficient: 1.0,
                    maximum_interval_ms: None,
                    non_retryable_error_types: vec![],
                }),
            }],
            mcp: crate::store::McpProfileSettings::default(),
        };

        let payload = TokenPayloadV1 {
            profile_id: profile.id.clone(),
            bindings: vec![UpstreamSessionBinding {
                upstream: "u1".to_string(),
                endpoint: "e1".to_string(),
                session: "s".to_string(),
            }],
            auth: None,
            oidc: None,
            iat: None,
            exp: None,
            proxy_key: None,
        };

        // Seed tool routing cache so we don't have to build the full tools surface.
        let fp = profile_fingerprint(&profile);
        let routes = Arc::new(HashMap::from([(
            "foo".to_string(),
            ToolRoute {
                kind: ToolRouteKind::Upstream,
                source_id: "u1".to_string(),
                original_name: "foo".to_string(),
            },
        )]));
        let surface = CachedToolsSurface {
            tools: Arc::new(Vec::new()),
            routes,
            ambiguous_names: Arc::new(HashSet::new()),
        };
        state.tools_cache.put("p", "tok".to_string(), fp, surface);

        let mut msg = ClientJsonRpcMessage::Request(JsonRpcRequest {
            jsonrpc: JsonRpcVersion2_0,
            id: rmcp::model::RequestId::Number(1),
            request: ClientRequest::CallToolRequest(rmcp::model::CallToolRequest::new(
                CallToolRequestParam {
                    name: Cow::Owned("foo".to_string()),
                    arguments: None,
                },
            )),
        });

        let resp = route_and_proxy_tools_call(
            &state,
            "p",
            &profile,
            &payload,
            "tok".to_string(),
            &mut msg,
            0,
        )
        .await
        .expect("tool call ok");

        assert_eq!(calls.load(Ordering::SeqCst), 2, "should retry once");
        let timeout_ms = seen_timeout_ms.lock().expect("lock").expect("timeout meta");
        assert!(timeout_ms > 0);
        assert!(
            timeout_ms <= 2_000,
            "should respect per-tool timeout override"
        );
        assert_eq!(resp.status(), StatusCode::OK);

        handle.abort();
    }
}
