//! HTTP routes, request decoding, and transport limits for the MCP endpoint.
use super::{
    McpState, PayloadLimitExceededAudit, handle_delete, handle_post_in_session,
    initialize::handle_initialize, protocol::*, record_payload_limit_exceeded,
    stream::handle_get_stream, truncate_bytes_lossy,
};
use crate::store::DataPlaneAuthMode;
use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use rmcp::{
    model::{ClientJsonRpcMessage, ErrorCode, RequestId},
    transport::common::http_header::{HEADER_LAST_EVENT_ID, HEADER_SESSION_ID},
};
use std::sync::Arc;
use tracing::Instrument as _;
use uuid::{Uuid, Version};

pub fn router(state: Arc<McpState>) -> axum::Router {
    axum::Router::new()
        .route(
            "/{profile_id}/mcp",
            axum::routing::post(post_mcp)
                .get(get_mcp)
                .delete(delete_mcp),
        )
        .route(
            "/.well-known/oauth-protected-resource/{profile_id}/mcp",
            axum::routing::get(protected_resource_metadata),
        )
        // Hard cap to protect the process from unbounded request bodies.
        .layer(DefaultBodyLimit::max(
            usize::try_from(crate::transport_limits::HARD_MAX_POST_BODY_BYTES)
                .unwrap_or(usize::MAX),
        ))
        .with_state(state)
}

async fn protected_resource_metadata(
    Path(profile_id): Path<String>,
    State(state): State<Arc<McpState>>,
) -> Response {
    if Uuid::parse_str(&profile_id)
        .ok()
        .and_then(|id| (id.get_version() == Some(Version::Random)).then_some(id))
        .is_none()
    {
        return (StatusCode::NOT_FOUND, "profile not found").into_response();
    }
    let Ok(Some(profile)) = state.store.get_profile(&profile_id).await else {
        return (StatusCode::NOT_FOUND, "profile not found").into_response();
    };
    if profile.data_plane_auth_mode != DataPlaneAuthMode::OAuth {
        return (StatusCode::NOT_FOUND, "profile not found").into_response();
    }
    let Some(oauth) = state.oauth.as_ref() else {
        return (StatusCode::NOT_FOUND, "profile not found").into_response();
    };
    (
        [(axum::http::header::CACHE_CONTROL, "no-store")],
        axum::Json(oauth.metadata(&profile.id, &profile.oauth_required_scopes)),
    )
        .into_response()
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

    let request = super::request_context::RequestContext::load(state.store.as_ref(), &profile_id)
        .await
        .map_err(internal_error_response("load profile"))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "profile not found").into_response())?;
    let message = parse_post_body_message_with_limits(
        state.as_ref(),
        &profile_id,
        &request.profile,
        request.limits,
        &body,
    )
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
                None => handle_initialize(&state, &request.profile, &headers, message).await,
                Some(token) => {
                    Box::pin(handle_post_in_session(
                        &state, &request, &headers, token, message,
                    ))
                    .await
                }
            }
        }
        .instrument(span),
    )
    .await
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
