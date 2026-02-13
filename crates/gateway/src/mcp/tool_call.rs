use super::McpState;
use super::streamable_http;
use crate::audit::{AuditActor, AuditError, McpToolsCallAuditEvent};
use crate::session_token::TokenPayloadV1;
use crate::tool_policy::RetryPolicy;
use crate::tools_cache::{CachedToolsSurface, ToolRoute, ToolRouteKind, profile_fingerprint};
use axum::{Json, http::StatusCode, response::IntoResponse as _, response::Response};
use futures::{Stream, StreamExt as _};
use rmcp::model::GetMeta as _;
use rmcp::{
    model::{ClientJsonRpcMessage, ErrorCode, JsonRpcRequest, JsonRpcVersion2_0, RequestId},
    transport::streamable_http_client::StreamableHttpPostResponse,
};
use std::borrow::Cow;
use std::time::Instant;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

pub(super) async fn route_and_proxy_tools_call(
    state: &McpState,
    profile_id: &str,
    profile: &crate::store::Profile,
    payload: &TokenPayloadV1,
    token: String,
    message: &mut ClientJsonRpcMessage,
    hop: u32,
) -> Result<Response, Response> {
    let started = Instant::now();
    let audit_ctx = ToolsCallAuditCtx {
        state,
        profile,
        payload,
        profile_id,
    };
    let ctx = ToolsCallCtx {
        audit_ctx,
        started: &started,
        token: &token,
        hop,
    };
    let (tool_name, req_id, args_value) = tools_call_extract_or_reject(ctx, message).await?;
    let (mut surface, built_now) = tools_call_get_surface_or_reject(&tool_name, ctx).await?;
    tools_call_refresh_surface_on_miss_or_reject(&tool_name, ctx, &mut surface, built_now).await?;
    let route = tools_call_resolve_route_or_reject(&tool_name, &req_id, ctx, &surface).await?;
    tools_call_validate_args_or_reject(&tool_name, &req_id, ctx, &surface, &route, &args_value)
        .await?;

    let args = build_transformed_call_args(profile, &route.original_name, args_value);
    let tool_ref = stable_tool_ref(&route.source_id, &route.original_name);
    let timeout_secs = tool_call_timeout_secs_for(profile, &tool_ref);
    let timeout = std::time::Duration::from_secs(timeout_secs);

    if let Some(resp) = tools_call_try_local_or_reject(
        ctx,
        ToolsCallLocalInputs {
            tool_ref: &tool_ref,
            tool_name: &tool_name,
            req_id: &req_id,
            route: &route,
            args: &args,
            timeout,
            timeout_secs,
        },
    )
    .await?
    {
        return Ok(resp);
    }

    // Rewrite name before proxying.
    if let Some(call) = super::as_call_tool_mut(message) {
        call.name = Cow::Owned(route.original_name.clone());
        call.arguments = Some(args);
    }

    let result = proxy_upstream_tool_call_with_retry(UpstreamToolCall {
        state,
        profile_id,
        profile,
        payload,
        route: &route,
        req_id: &req_id,
        message: message.clone(),
        timeout,
        timeout_secs,
        hop,
    })
    .await;

    record_tools_call_audit(
        ctx.audit_ctx,
        ToolsCallAuditEvent {
            tool_ref: Some(&tool_ref),
            tool_name_at_time: Some(&tool_name),
            ok: result.is_ok(),
            elapsed: started.elapsed(),
            error: if result.is_ok() {
                None
            } else {
                Some(AuditError::new(
                    "upstream_tool_call_failed",
                    "upstream tool call failed",
                ))
            },
            meta: serde_json::json!({}),
        },
    )
    .await;

    result
}

#[derive(Clone, Copy)]
struct ToolsCallCtx<'a> {
    audit_ctx: ToolsCallAuditCtx<'a>,
    started: &'a Instant,
    token: &'a str,
    hop: u32,
}

async fn tools_call_extract_or_reject(
    ctx: ToolsCallCtx<'_>,
    message: &mut ClientJsonRpcMessage,
) -> Result<(String, RequestId, serde_json::Value), Response> {
    let Some((tool_name, req_id, args_value)) = super::extract_call_tool(message) else {
        record_tools_call_audit(
            ctx.audit_ctx,
            ToolsCallAuditEvent {
                tool_ref: None,
                tool_name_at_time: None,
                ok: false,
                elapsed: ctx.started.elapsed(),
                error: Some(AuditError::new("bad_request", "invalid tools/call request")),
                meta: serde_json::json!({}),
            },
        )
        .await;
        return Err((StatusCode::BAD_REQUEST, "invalid tools/call request").into_response());
    };
    Ok((tool_name, req_id, args_value))
}

async fn tools_call_get_surface_or_reject(
    tool_name: &str,
    ctx: ToolsCallCtx<'_>,
) -> Result<(CachedToolsSurface, bool), Response> {
    match get_or_build_tools_surface_for_call(
        ctx.audit_ctx.state,
        ctx.audit_ctx.profile_id,
        ctx.audit_ctx.profile,
        ctx.audit_ctx.payload,
        ctx.token,
        ctx.hop,
    )
    .await
    {
        Ok(v) => Ok(v),
        Err(resp) => {
            record_tools_call_audit(
                ctx.audit_ctx,
                ToolsCallAuditEvent {
                    tool_ref: None,
                    tool_name_at_time: Some(tool_name),
                    ok: false,
                    elapsed: ctx.started.elapsed(),
                    error: Some(AuditError::new(
                        "surface_build_failed",
                        "failed to build tools surface",
                    )),
                    meta: serde_json::json!({}),
                },
            )
            .await;
            Err(resp)
        }
    }
}

async fn tools_call_refresh_surface_on_miss_or_reject(
    tool_name: &str,
    ctx: ToolsCallCtx<'_>,
    surface: &mut CachedToolsSurface,
    built_now: bool,
) -> Result<(), Response> {
    let missing = surface.routes.get(tool_name).is_none();
    if !missing || built_now {
        return Ok(());
    }

    // JIT refresh on miss: invalidate and rebuild once.
    ctx.audit_ctx.state.tools_cache.invalidate(ctx.token);
    *surface = match Box::pin(super::surface::build_tools_surface(
        ctx.audit_ctx.state,
        ctx.audit_ctx.profile_id,
        ctx.audit_ctx.profile,
        ctx.audit_ctx.payload,
        ctx.hop,
    ))
    .await
    {
        Ok(s) => s,
        Err(resp) => {
            record_tools_call_audit(
                ctx.audit_ctx,
                ToolsCallAuditEvent {
                    tool_ref: None,
                    tool_name_at_time: Some(tool_name),
                    ok: false,
                    elapsed: ctx.started.elapsed(),
                    error: Some(AuditError::new(
                        "surface_build_failed",
                        "failed to rebuild tools surface",
                    )),
                    meta: serde_json::json!({}),
                },
            )
            .await;
            return Err(resp);
        }
    };
    ctx.audit_ctx.state.tools_cache.put(
        ctx.audit_ctx.profile_id,
        ctx.token.to_string(),
        profile_fingerprint(ctx.audit_ctx.profile),
        surface.clone(),
    );

    Ok(())
}

async fn tools_call_resolve_route_or_reject(
    tool_name: &str,
    req_id: &RequestId,
    ctx: ToolsCallCtx<'_>,
    surface: &CachedToolsSurface,
) -> Result<ToolRoute, Response> {
    match resolve_tool_route(surface, tool_name) {
        Ok(r) => Ok(r),
        Err(ToolRouteLookupError::Ambiguous) => {
            record_tools_call_audit(
                ctx.audit_ctx,
                ToolsCallAuditEvent {
                    tool_ref: None,
                    tool_name_at_time: Some(tool_name),
                    ok: false,
                    elapsed: ctx.started.elapsed(),
                    error: Some(AuditError::new("ambiguous_tool", "ambiguous tool name")),
                    meta: serde_json::json!({ "tool_name": tool_name.to_string() }),
                },
            )
            .await;
            Err(super::jsonrpc_error_response(
                req_id.clone(),
                ErrorCode::INVALID_PARAMS,
                format!("ambiguous tool name '{tool_name}'; use '<source_id>:{tool_name}'"),
            ))
        }
        Err(ToolRouteLookupError::Unknown) => {
            record_tools_call_audit(
                ctx.audit_ctx,
                ToolsCallAuditEvent {
                    tool_ref: None,
                    tool_name_at_time: Some(tool_name),
                    ok: false,
                    elapsed: ctx.started.elapsed(),
                    error: Some(AuditError::new("unknown_tool", "unknown tool")),
                    meta: serde_json::json!({ "tool_name": tool_name.to_string() }),
                },
            )
            .await;
            Err(super::jsonrpc_error_response(
                req_id.clone(),
                ErrorCode::INVALID_PARAMS,
                format!("unknown tool: {tool_name}"),
            ))
        }
    }
}

async fn tools_call_validate_args_or_reject(
    tool_name: &str,
    req_id: &RequestId,
    ctx: ToolsCallCtx<'_>,
    surface: &CachedToolsSurface,
    route: &ToolRoute,
    args_value: &serde_json::Value,
) -> Result<(), Response> {
    // Validate incoming args against the *advertised* (post-transform) tool schema.
    if let Some(tool_def) = surface.tools.iter().find(|t| t.name == tool_name)
        && let Err((msg, data)) = validate_tool_arguments(tool_def, args_value)
    {
        let tool_ref = stable_tool_ref(&route.source_id, &route.original_name);
        record_tools_call_audit(
            ctx.audit_ctx,
            ToolsCallAuditEvent {
                tool_ref: Some(&tool_ref),
                tool_name_at_time: Some(tool_name),
                ok: false,
                elapsed: ctx.started.elapsed(),
                error: Some(AuditError::new("invalid_params", msg.clone())),
                meta: serde_json::json!({ "validation": data }),
            },
        )
        .await;
        return Err(super::jsonrpc_error_response_with_data(
            req_id.clone(),
            ErrorCode::INVALID_PARAMS,
            msg,
            Some(data),
        ));
    }
    Ok(())
}

struct ToolsCallLocalInputs<'a> {
    tool_ref: &'a str,
    tool_name: &'a str,
    req_id: &'a RequestId,
    route: &'a ToolRoute,
    args: &'a serde_json::Map<String, serde_json::Value>,
    timeout: std::time::Duration,
    timeout_secs: u64,
}

async fn tools_call_try_local_or_reject(
    ctx: ToolsCallCtx<'_>,
    input: ToolsCallLocalInputs<'_>,
) -> Result<Option<Response>, Response> {
    match execute_local_tool_call(
        ctx.audit_ctx.state,
        ctx.audit_ctx.profile,
        input.route,
        input.args,
        input.req_id.clone(),
        input.timeout,
        input.timeout_secs,
    )
    .await
    {
        Ok(Some(resp)) => {
            record_tools_call_audit(
                ctx.audit_ctx,
                ToolsCallAuditEvent {
                    tool_ref: Some(input.tool_ref),
                    tool_name_at_time: Some(input.tool_name),
                    ok: true,
                    elapsed: ctx.started.elapsed(),
                    error: None,
                    meta: serde_json::json!({}),
                },
            )
            .await;
            Ok(Some(resp))
        }
        Ok(None) => Ok(None),
        Err(resp) => {
            record_tools_call_audit(
                ctx.audit_ctx,
                ToolsCallAuditEvent {
                    tool_ref: Some(input.tool_ref),
                    tool_name_at_time: Some(input.tool_name),
                    ok: false,
                    elapsed: ctx.started.elapsed(),
                    error: Some(AuditError::new(
                        "local_tool_call_failed",
                        "local tool call failed",
                    )),
                    meta: serde_json::json!({}),
                },
            )
            .await;
            Err(resp)
        }
    }
}

#[derive(Clone, Copy)]
struct ToolsCallAuditCtx<'a> {
    state: &'a McpState,
    profile: &'a crate::store::Profile,
    payload: &'a TokenPayloadV1,
    profile_id: &'a str,
}

struct ToolsCallAuditEvent<'a> {
    tool_ref: Option<&'a str>,
    tool_name_at_time: Option<&'a str>,
    ok: bool,
    elapsed: std::time::Duration,
    error: Option<AuditError>,
    meta: serde_json::Value,
}

async fn record_tools_call_audit(ctx: ToolsCallAuditCtx<'_>, ev: ToolsCallAuditEvent<'_>) {
    // Per-tenant gating is enforced inside the sink (DB-backed, cached).
    let tenant_id = ctx.profile.tenant_id.clone();
    let profile_uuid = Uuid::parse_str(ctx.profile_id).ok();

    let api_key_id = ctx
        .payload
        .auth
        .as_ref()
        .and_then(|a| Uuid::parse_str(&a.api_key_id).ok());
    let oidc_issuer = ctx.payload.oidc.as_ref().map(|o| o.issuer.clone());
    let oidc_subject = ctx.payload.oidc.as_ref().map(|o| o.subject.clone());

    ctx.state
        .audit
        .record(crate::audit::mcp_tools_call_event(McpToolsCallAuditEvent {
            tenant_id,
            actor: AuditActor {
                profile_id: profile_uuid,
                api_key_id,
                oidc_issuer,
                oidc_subject,
            },
            tool_ref: ev.tool_ref.map(str::to_string),
            tool_name_at_time: ev.tool_name_at_time.map(str::to_string),
            ok: ev.ok,
            elapsed: ev.elapsed,
            meta: ev.meta,
            error: ev.error,
        }))
        .await;
}

async fn get_or_build_tools_surface_for_call(
    state: &McpState,
    profile_id: &str,
    profile: &crate::store::Profile,
    payload: &TokenPayloadV1,
    token: &str,
    hop: u32,
) -> Result<(CachedToolsSurface, bool), Response> {
    let fp = profile_fingerprint(profile);
    let mut surface = state.tools_cache.get(token, &fp);
    let mut built_now = false;
    if surface.is_none() {
        surface = Some(
            Box::pin(super::surface::build_tools_surface(
                state, profile_id, profile, payload, hop,
            ))
            .await?,
        );
        state.tools_cache.put(
            profile_id,
            token.to_string(),
            fp,
            surface.clone().expect("surface"),
        );
        built_now = true;
    }
    Ok((surface.expect("surface"), built_now))
}

#[derive(Debug, Clone, Copy)]
enum ToolRouteLookupError {
    Ambiguous,
    Unknown,
}

fn resolve_tool_route(
    surface: &CachedToolsSurface,
    tool_name: &str,
) -> Result<ToolRoute, ToolRouteLookupError> {
    surface.routes.get(tool_name).cloned().ok_or_else(|| {
        if surface.ambiguous_names.contains(tool_name) {
            ToolRouteLookupError::Ambiguous
        } else {
            ToolRouteLookupError::Unknown
        }
    })
}

fn build_transformed_call_args(
    profile: &crate::store::Profile,
    original_tool_name: &str,
    args_value: serde_json::Value,
) -> serde_json::Map<String, serde_json::Value> {
    let mut args = match args_value {
        serde_json::Value::Object(m) => m,
        _ => serde_json::Map::new(),
    };
    profile
        .transforms
        .apply_call_transforms(original_tool_name, &mut args);
    args
}

async fn execute_local_tool_call(
    state: &McpState,
    profile: &crate::store::Profile,
    route: &ToolRoute,
    args: &serde_json::Map<String, serde_json::Value>,
    req_id: RequestId,
    timeout: std::time::Duration,
    timeout_secs: u64,
) -> Result<Option<Response>, Response> {
    if route.kind == ToolRouteKind::SharedLocal {
        let fut = state.catalog.call_tool(
            &route.source_id,
            &route.original_name,
            serde_json::Value::Object(args.clone()),
        );
        let result = match tokio::time::timeout(timeout, fut).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => {
                return Err(super::jsonrpc_error_response(
                    req_id,
                    ErrorCode::INTERNAL_ERROR,
                    e.to_string(),
                ));
            }
            Err(_) => {
                return Err(super::jsonrpc_error_response(
                    req_id,
                    ErrorCode::INTERNAL_ERROR,
                    format!("tool call timed out after {timeout_secs}s"),
                ));
            }
        };
        let msg = rmcp::model::ServerJsonRpcMessage::Response(rmcp::model::JsonRpcResponse {
            jsonrpc: JsonRpcVersion2_0,
            id: req_id,
            result: rmcp::model::ServerResult::CallToolResult(result),
        });
        return Ok(Some(super::sse_single_message(&msg)));
    }

    if route.kind == ToolRouteKind::TenantLocal {
        let fut = Box::pin(state.tenant_catalog.call_tool(
            state.store.as_ref(),
            &profile.tenant_id,
            &route.source_id,
            &route.original_name,
            serde_json::Value::Object(args.clone()),
        ));
        let result = match tokio::time::timeout(timeout, fut).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => {
                return Err(super::jsonrpc_error_response(
                    req_id,
                    ErrorCode::INTERNAL_ERROR,
                    e.to_string(),
                ));
            }
            Err(_) => {
                return Err(super::jsonrpc_error_response(
                    req_id,
                    ErrorCode::INTERNAL_ERROR,
                    format!("tool call timed out after {timeout_secs}s"),
                ));
            }
        };
        let msg = rmcp::model::ServerJsonRpcMessage::Response(rmcp::model::JsonRpcResponse {
            jsonrpc: JsonRpcVersion2_0,
            id: req_id,
            result: rmcp::model::ServerResult::CallToolResult(result),
        });
        return Ok(Some(super::sse_single_message(&msg)));
    }

    Ok(None)
}

fn inject_timeout_budget_meta(msg: &mut ClientJsonRpcMessage, remaining: std::time::Duration) {
    if let ClientJsonRpcMessage::Request(JsonRpcRequest { request, .. }) = msg {
        let ms: u64 = remaining.as_millis().try_into().unwrap_or(u64::MAX);
        let meta = request.get_meta_mut();
        meta.insert(
            "unrelated".to_string(),
            serde_json::json!({ "timeoutMs": ms }),
        );
    }
}

#[derive(Clone)]
struct ToolCallSseLimitCtx {
    tenant_id: String,
    profile_id: String,
    upstream_id: String,
    limits: crate::transport_limits::EffectiveTransportLimits,
    audit: std::sync::Arc<dyn crate::audit::AuditSink>,
    stop: CancellationToken,
}

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

async fn effective_transport_limits_for_profile(
    state: &McpState,
    profile: &crate::store::Profile,
) -> crate::transport_limits::EffectiveTransportLimits {
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

    crate::transport_limits::EffectiveTransportLimits::from_profile_and_tenant(
        &profile.mcp.security.transport_limits,
        tenant_limits.as_ref(),
    )
}

async fn enforce_tool_call_sse_limits_or_close(ctx: &ToolCallSseLimitCtx, data: &str) -> bool {
    let observed = data.len() as u64;
    if observed > ctx.limits.max_sse_event_bytes {
        super::record_payload_limit_exceeded(
            ctx.audit.as_ref(),
            super::PayloadLimitExceededAudit {
                tenant_id: &ctx.tenant_id,
                profile_id: &ctx.profile_id,
                http_method: "POST",
                http_route: "/{profile_id}/mcp",
                status_code: None,
                direction: "upstream_sse",
                action_taken: "closed_stream",
                reason: "maxSseEventBytes",
                metric: "bytes",
                observed,
                limit: ctx.limits.max_sse_event_bytes,
                upstream_id: Some(&ctx.upstream_id),
                sample: Some(truncate_string_to_bytes(data.to_string(), 4096)),
            },
        )
        .await;
        ctx.stop.cancel();
        return false;
    }

    if ctx.limits.has_json_complexity_limits()
        && let Ok(v) = serde_json::from_str::<serde_json::Value>(data)
        && let Some(vio) = crate::transport_limits::check_json_complexity(&v, ctx.limits)
    {
        super::record_payload_limit_exceeded(
            ctx.audit.as_ref(),
            super::PayloadLimitExceededAudit {
                tenant_id: &ctx.tenant_id,
                profile_id: &ctx.profile_id,
                http_method: "POST",
                http_route: "/{profile_id}/mcp",
                status_code: None,
                direction: "upstream_sse",
                action_taken: "closed_stream",
                reason: vio.kind,
                metric: "complexity",
                observed: vio.observed,
                limit: vio.limit,
                upstream_id: Some(&ctx.upstream_id),
                sample: Some(truncate_string_to_bytes(data.to_string(), 4096)),
            },
        )
        .await;
        ctx.stop.cancel();
        return false;
    }

    true
}

fn sse_from_upstream_stream_with_timeout_and_limits<S>(
    stream: S,
    timeout: std::time::Duration,
    limit_ctx: ToolCallSseLimitCtx,
) -> Response
where
    S: Stream<Item = Result<sse_stream::Sse, sse_stream::Error>> + Send + 'static,
{
    let deadline = tokio::time::sleep(timeout);
    let mapped = stream
        .take_until(deadline)
        .take_until(limit_ctx.stop.clone().cancelled_owned())
        .then(move |evt| {
            let limit_ctx = limit_ctx.clone();
            async move {
                match evt {
                    Ok(sse) => {
                        if let Some(data) = sse.data.as_deref()
                            && !data.trim().is_empty()
                            && !enforce_tool_call_sse_limits_or_close(&limit_ctx, data).await
                        {
                            return None;
                        }

                        let mut ev = axum::response::sse::Event::default();
                        if let Some(id) = sse.id {
                            ev = ev.id(id);
                        }
                        if let Some(data) = sse.data {
                            ev = ev.data(data);
                        }
                        Some(Ok::<_, std::convert::Infallible>(ev))
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "upstream sse error");
                        Some(Ok::<_, std::convert::Infallible>(
                            axum::response::sse::Event::default().comment("upstream error"),
                        ))
                    }
                }
            }
        })
        .filter_map(futures::future::ready);

    let mut resp = axum::response::Sse::new(mapped).into_response();
    resp.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static(
            rmcp::transport::common::http_header::EVENT_STREAM_MIME_TYPE,
        ),
    );
    resp
}

struct UpstreamToolCall<'a> {
    state: &'a McpState,
    profile_id: &'a str,
    profile: &'a crate::store::Profile,
    payload: &'a TokenPayloadV1,
    route: &'a ToolRoute,
    req_id: &'a RequestId,
    message: ClientJsonRpcMessage,
    timeout: std::time::Duration,
    timeout_secs: u64,
    hop: u32,
}

fn upstream_request_timed_out_error(id: RequestId, timeout_secs: u64) -> Response {
    super::jsonrpc_error_response(
        id,
        ErrorCode::INTERNAL_ERROR,
        format!("upstream request timed out after {timeout_secs}s"),
    )
}

fn find_upstream_binding<'a>(
    call: &'a UpstreamToolCall<'_>,
) -> Option<&'a crate::session_token::UpstreamSessionBinding> {
    call.payload
        .bindings
        .iter()
        .find(|b| b.upstream == call.route.source_id)
}

async fn resolve_upstream_endpoint_url(
    call: &UpstreamToolCall<'_>,
    binding: &crate::session_token::UpstreamSessionBinding,
) -> Result<crate::endpoint_cache::UpstreamEndpoint, Response> {
    super::upstream::resolve_endpoint(call.state, call.profile_id, binding)
        .await?
        .ok_or_else(|| {
            super::jsonrpc_error_response(
                call.req_id.clone(),
                ErrorCode::INTERNAL_ERROR,
                "upstream endpoint not found".to_string(),
            )
        })
}

async fn post_upstream_with_retry(
    call: &UpstreamToolCall<'_>,
    binding: &crate::session_token::UpstreamSessionBinding,
    endpoint_url: &str,
    headers: &reqwest::header::HeaderMap,
    retry: Option<&RetryPolicy>,
    max_attempts: u32,
    deadline: std::time::Instant,
) -> Result<StreamableHttpPostResponse, Response> {
    let mut attempt: u32 = 1;
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return Err(upstream_request_timed_out_error(
                call.req_id.clone(),
                call.timeout_secs,
            ));
        }

        let mut msg = call.message.clone();
        inject_timeout_budget_meta(&mut msg, remaining);

        let fut = streamable_http::post_message(
            &call.state.http,
            endpoint_url.to_owned().into(),
            msg,
            Some(binding.session.clone().into()),
            headers,
        );

        match tokio::time::timeout(remaining, fut).await {
            Ok(Ok(r)) => return Ok(r),
            Ok(Err(e)) => {
                let retryable = should_retry_upstream_error(retry, &e);
                let msg = format!("upstream request failed: {e}");
                if !retryable || attempt >= max_attempts {
                    return Err(super::jsonrpc_error_response(
                        call.req_id.clone(),
                        ErrorCode::INTERNAL_ERROR,
                        msg,
                    ));
                }
            }
            Err(_) => {
                let msg = format!("upstream request timed out after {}s", call.timeout_secs);
                let timeout_retryable =
                    retry.is_some_and(|p| !retry_policy_disallows(p, "timeout"));
                if attempt >= max_attempts || !timeout_retryable {
                    return Err(super::jsonrpc_error_response(
                        call.req_id.clone(),
                        ErrorCode::INTERNAL_ERROR,
                        msg,
                    ));
                }
            }
        }

        if let Some(policy) = retry {
            let delay = retry_delay(policy, attempt);
            if !delay.is_zero() {
                let remaining = deadline.saturating_duration_since(std::time::Instant::now());
                if remaining.is_zero() {
                    return Err(upstream_request_timed_out_error(
                        call.req_id.clone(),
                        call.timeout_secs,
                    ));
                }
                if delay >= remaining {
                    return Err(upstream_request_timed_out_error(
                        call.req_id.clone(),
                        call.timeout_secs,
                    ));
                }
                tokio::time::sleep(delay).await;
            }
        }
        attempt = attempt.saturating_add(1);
    }
}

async fn proxy_upstream_tool_call_with_retry(
    call: UpstreamToolCall<'_>,
) -> Result<Response, Response> {
    let tool_ref = stable_tool_ref(&call.route.source_id, &call.route.original_name);
    let retry = tool_retry_policy_for(call.profile, &tool_ref);
    let max_attempts: u32 = retry.as_ref().map_or(1, |r| r.maximum_attempts.max(1));

    let binding = find_upstream_binding(&call).ok_or_else(|| {
        super::jsonrpc_error_response(
            call.req_id.clone(),
            ErrorCode::INTERNAL_ERROR,
            "upstream session not available".to_string(),
        )
    })?;
    let endpoint = resolve_upstream_endpoint_url(&call, binding).await?;
    if call.hop >= super::upstream::MAX_HOPS {
        return Err(super::jsonrpc_error_response(
            call.req_id.clone(),
            ErrorCode::INTERNAL_ERROR,
            "proxy loop detected (max hops exceeded)".to_string(),
        ));
    }
    let endpoint_url = super::upstream::apply_query_auth(&endpoint.url, endpoint.auth.as_ref());
    let headers = super::upstream::build_upstream_headers(endpoint.auth.as_ref(), call.hop + 1);

    let deadline = std::time::Instant::now() + call.timeout;
    let resp = post_upstream_with_retry(
        &call,
        binding,
        &endpoint_url,
        &headers,
        retry.as_ref(),
        max_attempts,
        deadline,
    )
    .await?;

    match resp {
        StreamableHttpPostResponse::Accepted => Ok(StatusCode::ACCEPTED.into_response()),
        StreamableHttpPostResponse::Json(msg, ..) => Ok(Json(msg).into_response()),
        StreamableHttpPostResponse::Sse(stream, ..) => {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return Err(upstream_request_timed_out_error(
                    call.req_id.clone(),
                    call.timeout_secs,
                ));
            }
            let limit_ctx = ToolCallSseLimitCtx {
                tenant_id: call.profile.tenant_id.clone(),
                profile_id: call.profile_id.to_string(),
                upstream_id: call.route.source_id.clone(),
                limits: effective_transport_limits_for_profile(call.state, call.profile).await,
                audit: call.state.audit.clone(),
                stop: CancellationToken::new(),
            };
            Ok(sse_from_upstream_stream_with_timeout_and_limits(
                stream, remaining, limit_ctx,
            ))
        }
    }
}

fn stable_tool_ref(source_id: &str, original_tool_name: &str) -> String {
    format!("{source_id}:{original_tool_name}")
}

fn tool_call_timeout_secs_for(profile: &crate::store::Profile, tool_ref: &str) -> u64 {
    let max = crate::timeouts::tool_call_timeout_max_secs();
    let mut secs = crate::timeouts::tool_call_timeout_default_secs();
    if let Some(v) = profile.tool_call_timeout_secs
        && v > 0
    {
        secs = v.min(max);
    }
    if let Some(p) = profile.tool_policies.iter().find(|p| p.tool == tool_ref)
        && let Some(v) = p.timeout_secs
        && v > 0
    {
        secs = v.min(max);
    }
    secs.max(1)
}

fn tool_retry_policy_for(profile: &crate::store::Profile, tool_ref: &str) -> Option<RetryPolicy> {
    profile
        .tool_policies
        .iter()
        .find(|p| p.tool == tool_ref)
        .and_then(|p| p.retry.clone())
}

fn retry_policy_disallows(policy: &RetryPolicy, category: &str) -> bool {
    policy
        .non_retryable_error_types
        .iter()
        .any(|t| t == category)
}

pub(super) fn retry_delay(policy: &RetryPolicy, attempt: u32) -> std::time::Duration {
    // attempt starts at 1 for the initial try; delay after attempt 1 is `initial_interval`.
    if attempt == 0 {
        return std::time::Duration::from_millis(0);
    }
    let exp = attempt.saturating_sub(1).min(30);
    let coeff = policy.backoff_coefficient;
    if !coeff.is_finite() || coeff <= 0.0 {
        return std::time::Duration::from_millis(0);
    }
    let mult = coeff.powi(i32::try_from(exp).unwrap_or(30));
    if !mult.is_finite() || mult <= 0.0 {
        return std::time::Duration::from_millis(0);
    }

    let mut d = std::time::Duration::from_millis(policy.initial_interval_ms).mul_f64(mult);
    if let Some(max_ms) = policy.maximum_interval_ms {
        d = d.min(std::time::Duration::from_millis(max_ms));
    }
    d
}

fn upstream_error_category(
    e: &rmcp::transport::streamable_http_client::StreamableHttpError<reqwest::Error>,
) -> Option<&'static str> {
    use rmcp::transport::streamable_http_client::StreamableHttpError;
    match e {
        StreamableHttpError::Client(err) => {
            if err.status().is_some_and(|s| s.is_server_error()) {
                return Some("upstream_5xx");
            }
            if err.is_timeout() || err.is_connect() {
                return Some("transport");
            }
            None
        }
        StreamableHttpError::UnexpectedServerResponse(msg) => {
            let s = msg.as_ref();
            if s.contains("http 5") {
                return Some("upstream_5xx");
            }
            None
        }
        // Likely transient / transport-ish.
        StreamableHttpError::Io(_)
        | StreamableHttpError::Sse(_)
        | StreamableHttpError::UnexpectedEndOfStream
        | StreamableHttpError::TokioJoinError(_)
        | StreamableHttpError::TransportChannelClosed => Some("transport"),
        // Might be transient, but often indicates a server bug; still allow retry if configured.
        StreamableHttpError::Deserialize(_) => Some("deserialize"),

        // Default: not retryable.
        _ => None,
    }
}

fn should_retry_upstream_error(
    policy: Option<&RetryPolicy>,
    e: &rmcp::transport::streamable_http_client::StreamableHttpError<reqwest::Error>,
) -> bool {
    let Some(category) = upstream_error_category(e) else {
        return false;
    };
    if policy.is_some_and(|p| retry_policy_disallows(p, category)) {
        return false;
    }
    true
}

pub(super) fn validate_tool_arguments(
    tool: &rmcp::model::Tool,
    args: &serde_json::Value,
) -> Result<(), (String, serde_json::Value)> {
    let schema = serde_json::Value::Object((*tool.input_schema).clone());
    let props = schema
        .get("properties")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();
    let required: Vec<String> = schema
        .get("required")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect();

    let args_obj = args.as_object().cloned().unwrap_or_default();
    let valid_params: Vec<String> = props.keys().cloned().collect();
    let valid_param_refs: Vec<&str> = valid_params.iter().map(String::as_str).collect();

    let mut violations: Vec<serde_json::Value> = Vec::new();

    // Unknown parameters (suggestions).
    for k in args_obj.keys() {
        if props.contains_key(k) {
            continue;
        }
        let suggestions = find_similar_strings(k, &valid_param_refs);
        violations.push(serde_json::json!({
            "type": "invalid-parameter",
            "parameter": k,
            "suggestions": suggestions,
            "validParameters": valid_params,
        }));
    }

    // Missing required parameters.
    for r in &required {
        if !args_obj.contains_key(r) {
            violations.push(serde_json::json!({
                "type": "missing-required-parameter",
                "parameter": r,
            }));
        }
    }

    // JSON Schema validation (types/constraints).
    if let Ok(compiled) = jsonschema::validator_for(&schema) {
        for e in compiled.iter_errors(args) {
            // Filter out "required" errors; we already report them with a nicer shape.
            if matches!(
                e.kind(),
                jsonschema::error::ValidationErrorKind::Required { .. }
            ) {
                continue;
            }
            let instance_path = e.instance_path().to_string();
            violations.push(serde_json::json!({
                "type": "constraint-violation",
                "message": e.to_string(),
                "instancePath": instance_path,
            }));
        }
    }

    if violations.is_empty() {
        return Ok(());
    }

    // Message: optimize for unknown-parameter typos (even if there are other violations too).
    let msg = if let Some(v) = violations
        .iter()
        .find(|v| v.get("type").and_then(|t| t.as_str()) == Some("invalid-parameter"))
    {
        let p = v.get("parameter").and_then(|v| v.as_str()).unwrap_or("?");
        let suggestion = v
            .get("suggestions")
            .and_then(|v| v.as_array())
            .and_then(|arr| arr.first())
            .and_then(|v| v.as_str());
        if let Some(s) = suggestion {
            format!("Invalid params: unknown parameter '{p}' (did you mean '{s}'?)")
        } else {
            format!("Invalid params: unknown parameter '{p}'")
        }
    } else {
        format!(
            "Invalid params: validation failed with {} error(s)",
            violations.len()
        )
    };

    Err((
        msg,
        serde_json::json!({
            "type": "validation-errors",
            "violations": violations,
        }),
    ))
}

fn find_similar_strings(unknown: &str, known: &[&str]) -> Vec<String> {
    let mut candidates: Vec<(f64, String)> = Vec::new();
    for k in known {
        let score = strsim::jaro(unknown, k);
        if score > 0.7 {
            candidates.push((score, (*k).to_string()));
        }
    }
    candidates.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
    candidates.into_iter().map(|(_, s)| s).collect()
}
