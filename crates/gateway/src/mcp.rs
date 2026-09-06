#![allow(
    clippy::wildcard_imports,
    reason = "the protocol helper module intentionally supplies the MCP response vocabulary"
)]

use crate::audit::AuditSink;
use crate::catalog::SharedCatalog;
use crate::contracts::ContractTracker;
use crate::oauth::OAuthRuntime;
use crate::session_token::{
    SessionSigner, SessionTokenVerifyError, SessionTokenVerifyErrorKind, TokenPayloadV1,
    UpstreamSessionBinding,
};
use crate::store::{
    EffectiveMcpCapabilities, RequestIdNamespacing, SessionActivityBinding, SseEventIdNamespacing,
    Store, ToolCallLimitRejection,
};
use crate::tenant_catalog::TenantCatalog;
use crate::{
    contracts::ContractEvent, contracts::list_changed_notification_json,
    pg_fanout::PgContractFanout,
};
use axum::{
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response, Sse},
};
use base64::Engine as _;
use futures::{Stream, StreamExt};
use rmcp::{
    model::{
        CallToolRequestParams, ClientJsonRpcMessage, ClientNotification, ClientRequest, ErrorCode,
        ErrorData, GetPromptRequestParams, JsonRpcError, JsonRpcNotification, JsonRpcRequest,
        JsonRpcResponse, JsonRpcVersion2_0, ReadResourceRequestParams, Reference, RequestId,
        ServerJsonRpcMessage, ServerNotification, ServerResult, SubscribeRequestParams,
        UnsubscribeRequestParams,
    },
    transport::common::http_header::{EVENT_STREAM_MIME_TYPE, HEADER_SESSION_ID, JSON_MIME_TYPE},
};
use serde::Serialize;
use sha2::Digest as _;
use std::{collections::HashMap, convert::Infallible, sync::Arc};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

mod auth;
mod ids;
mod initialize;
mod probe;
mod protocol;
mod request_context;
use request_context::RequestContext;
mod stream;
mod streamable_http;
mod surface;
mod tool_call;
mod transport;
mod upstream;
use auth::{enforce_data_plane_auth, unauthorized};
use ids::{make_proxied_request_id, parse_proxied_request_id, resource_collision_urn};
use protocol::*;
#[cfg(test)]
use stream::{NotificationKind, classify_server_notification, notification_allowed};
#[cfg(test)]
use stream::{
    OpenUpstreamStreamsInputs, ParsedLastEventId, allowed_by_caps_for_notification_kind,
    open_upstream_streams,
};
use surface::{
    aggregate_list_prompts, aggregate_list_resources, aggregate_list_tools, count_resource_uris,
    resolve_prompt_owner, resolve_resource_owner,
};
use tool_call::route_and_proxy_tools_call;
use upstream::proxy_to_single_upstream;

#[cfg(test)]
use initialize::initialize_profile_sources;
pub(crate) use probe::probe_profile_surface;
pub use transport::router;

// Custom Gateway JSON-RPC server error codes (-32000..-32099 range).
const ERROR_CODE_RATE_LIMIT_EXCEEDED: ErrorCode = ErrorCode(-32029);
const ERROR_CODE_QUOTA_EXCEEDED: ErrorCode = ErrorCode(-32030);

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
    pub oauth: Option<OAuthRuntime>,
    pub shutdown: CancellationToken,
    pub audit: Arc<dyn AuditSink>,
    pub catalog: Arc<SharedCatalog>,
    pub tenant_catalog: Arc<TenantCatalog>,
    pub contracts: Arc<ContractTracker>,
    pub contract_fanout: Option<Arc<PgContractFanout>>,
    pub tools_cache: Arc<crate::tools_cache::ToolSurfaceCache>,
    pub endpoint_cache: Arc<crate::endpoint_cache::UpstreamEndpointCache>,
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

fn decode_proxy_key(payload: &TokenPayloadV1) -> Option<Vec<u8>> {
    let b64 = payload.proxy_key.as_ref()?;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(b64.as_bytes())
        .ok()
}

fn effective_caps(profile: &crate::store::Profile) -> EffectiveMcpCapabilities {
    profile.mcp.capabilities.effective()
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

fn parse_hop(headers: &HeaderMap) -> u32 {
    headers
        .get(upstream::HOP_HEADER)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(0)
}

async fn record_upstream_bindings_activity_best_effort(
    state: &McpState,
    profile: &crate::store::Profile,
    session_token: &str,
    bindings: &[UpstreamSessionBinding],
    reason: &'static str,
) {
    if bindings.is_empty() {
        return;
    }
    let session_hash = hex::encode(sha2::Sha256::digest(session_token.as_bytes()));
    let rows: Vec<SessionActivityBinding> = bindings
        .iter()
        .map(|binding| SessionActivityBinding {
            upstream_id: binding.upstream.clone(),
            endpoint_id: binding.endpoint.clone(),
        })
        .collect();
    if let Err(e) = state
        .store
        .record_session_activity(&profile.tenant_id, &profile.id, &session_hash, &rows)
        .await
    {
        tracing::debug!(
            error = %e,
            tenant_id = %profile.tenant_id,
            profile_id = %profile.id,
            reason,
            "failed to record upstream session activity"
        );
    }
}

async fn forward_proxied_response_if_any(
    state: &McpState,
    profile_id: &str,
    payload: &TokenPayloadV1,
    message: &mut ClientJsonRpcMessage,
    hop: u32,
) -> Result<Option<Response>, Response> {
    let id = match message {
        ClientJsonRpcMessage::Response(JsonRpcResponse { id, .. }) => id,
        ClientJsonRpcMessage::Error(JsonRpcError { id, .. }) => {
            let Some(id) = id.as_mut() else {
                return Ok(None);
            };
            id
        }
        _ => return Ok(None),
    };

    let proxy_key = decode_proxy_key(payload);
    let Some((upstream_id, original_id)) = parse_proxied_request_id(id, proxy_key.as_deref())
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
    let Some(endpoint) = upstream::resolve_endpoint(state, profile_id, binding).await? else {
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
        cancelled
            .params
            .request_id
            .as_ref()
            .and_then(|id| parse_proxied_request_id(id, proxy_key.as_deref()))
    } else {
        None
    };

    if let Some((upstream_id, original_id)) = proxied_cancel {
        if let ClientJsonRpcMessage::Notification(JsonRpcNotification {
            notification: ClientNotification::CancelledNotification(cancelled),
            ..
        }) = message
        {
            cancelled.params.request_id = Some(original_id);
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
    request: &'a RequestContext,
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
        ctx.request,
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
    request: &RequestContext,
    payload: &TokenPayloadV1,
    token: String,
    message: &mut ClientJsonRpcMessage,
    hop: u32,
) -> Result<Response, Response> {
    let profile = &request.profile;
    let profile_id = profile.id.as_str();
    let (req_id, method) = match as_request_ref(&*message) {
        Some(JsonRpcRequest { id, request, .. }) => (id.clone(), request.method().to_string()),
        None => return Ok(StatusCode::ACCEPTED.into_response()),
    };

    let ctx = InSessionRequestCtx {
        state,
        profile_id,
        profile,
        request,
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
    request: &RequestContext,
    headers: &HeaderMap,
    token: String,
    mut message: ClientJsonRpcMessage,
) -> Result<Response, Response> {
    let profile = &request.profile;
    let profile_id = profile.id.as_str();
    let hop = parse_hop(headers);
    let payload = verify_session_token(&state.signer, &token, profile_id)
        .map_err(|(s, m)| (s, m).into_response())?;
    enforce_data_plane_auth(
        state,
        profile,
        headers,
        payload.auth.as_ref(),
        payload.oidc.as_ref(),
    )
    .await?;

    // Any in-session request extends liveness for bound upstream sessions.
    record_upstream_bindings_activity_best_effort(
        state,
        profile,
        &token,
        &payload.bindings,
        "post_in_session",
    )
    .await;

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

    handle_post_in_session_request(state, request, &payload, token, &mut message, hop).await
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
        _ => {
            return Err(jsonrpc_error_response(
                req_id,
                ErrorCode::INVALID_PARAMS,
                "Unsupported completion reference type".to_string(),
            ));
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

#[cfg(test)]
mod tests;
