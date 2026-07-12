use super::*;

pub(super) async fn handle_get_stream(
    state: &McpState,
    profile_id: &str,
    headers: &HeaderMap,
    token: String,
    last_event_id: Option<String>,
) -> Result<Response, Response> {
    let send_priming = last_event_id.is_none();
    let payload = verify_session_token(&state.signer, &token, profile_id)
        .map_err(|(s, m)| (s, m).into_response())?;
    let profile = load_stream_profile(state, profile_id).await?;

    enforce_data_plane_auth(
        state,
        &profile,
        headers,
        payload.auth.as_ref(),
        payload.oidc.as_ref(),
    )
    .await?;

    // Opening/refreshing the downstream stream marks all upstream bindings as active.
    record_upstream_bindings_activity_best_effort(
        state,
        &profile,
        &token,
        &payload.bindings,
        "get_stream",
    )
    .await;

    let (limits, limits_shutdown) = resolve_stream_limits(state, &profile).await;

    // Parse Last-Event-ID:
    // - If it looks like an upstream-prefixed id (`<upstream>/<id...>`), resume only that upstream.
    // - If it is numeric, treat it as the durable contract event cursor and do not forward to upstreams.
    let last = parse_last_event_id(
        profile.mcp.namespacing.sse_event_id,
        last_event_id.as_deref(),
    );

    let collision_counts =
        load_collision_counts_for_stream(state, profile_id, &payload, parse_hop(headers)).await;

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

async fn load_stream_profile(
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

async fn resolve_stream_limits(
    state: &McpState,
    profile: &crate::store::Profile,
) -> (
    crate::transport_limits::EffectiveTransportLimits,
    CancellationToken,
) {
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
    (limits, CancellationToken::new())
}

async fn load_collision_counts_for_stream(
    state: &McpState,
    profile_id: &str,
    payload: &TokenPayloadV1,
    hop: u32,
) -> Arc<parking_lot::RwLock<HashMap<String, usize>>> {
    // Stored behind an `RwLock` so we can refresh collision counts later without rewiring the
    // upstream SSE stream closures (counts can change when resources are added/removed upstream).
    let counts = match compute_resource_collision_counts(state, profile_id, payload, hop).await {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!(error = ?e, "failed to compute resource collision counts");
            HashMap::new()
        }
    };
    Arc::new(parking_lot::RwLock::new(counts))
}

#[derive(Debug, Clone, Default)]
pub(super) struct ParsedLastEventId {
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum NotificationKind {
    Cancelled,
    Progress,
    LoggingMessage,
    ResourceUpdated,
    ResourceListChanged,
    ToolListChanged,
    PromptListChanged,
    ElicitationCompletion,
    TaskStatus,
    Custom(String),
}

impl NotificationKind {
    pub(super) fn method(&self) -> &str {
        match self {
            NotificationKind::Cancelled => "notifications/cancelled",
            NotificationKind::Progress => "notifications/progress",
            NotificationKind::LoggingMessage => "notifications/message",
            NotificationKind::ResourceUpdated => "notifications/resources/updated",
            NotificationKind::ResourceListChanged => "notifications/resources/list_changed",
            NotificationKind::ToolListChanged => "notifications/tools/list_changed",
            NotificationKind::PromptListChanged => "notifications/prompts/list_changed",
            NotificationKind::ElicitationCompletion => "notifications/elicitation/complete",
            NotificationKind::TaskStatus => "notifications/tasks/status",
            NotificationKind::Custom(method) => method,
        }
    }
}

pub(super) fn classify_server_notification(notification: &ServerNotification) -> NotificationKind {
    match notification {
        ServerNotification::CancelledNotification(_) => NotificationKind::Cancelled,
        ServerNotification::ProgressNotification(_) => NotificationKind::Progress,
        ServerNotification::LoggingMessageNotification(_) => NotificationKind::LoggingMessage,
        ServerNotification::ResourceUpdatedNotification(_) => NotificationKind::ResourceUpdated,
        ServerNotification::ResourceListChangedNotification(_) => {
            NotificationKind::ResourceListChanged
        }
        ServerNotification::ToolListChangedNotification(_) => NotificationKind::ToolListChanged,
        ServerNotification::PromptListChangedNotification(_) => NotificationKind::PromptListChanged,
        ServerNotification::ElicitationCompleteNotification(_) => {
            NotificationKind::ElicitationCompletion
        }
        ServerNotification::TaskStatusNotification(_) => NotificationKind::TaskStatus,
        ServerNotification::CustomNotification(n) => NotificationKind::Custom(n.method.clone()),
    }
}

pub(super) fn allowed_by_caps_for_notification_kind(
    caps: EffectiveMcpCapabilities,
    kind: &NotificationKind,
) -> bool {
    match kind {
        NotificationKind::LoggingMessage => caps.logging(),
        NotificationKind::ToolListChanged => caps.tools_list_changed(),
        NotificationKind::ResourceListChanged => caps.resources_list_changed(),
        NotificationKind::PromptListChanged => caps.prompts_list_changed(),
        // Tasks are not advertised or routed end-to-end yet. Do not leak unrouteable task ids to
        // downstream clients if a non-conforming upstream sends a status notification anyway.
        NotificationKind::TaskStatus => false,
        _ => true,
    }
}

pub(super) fn notification_allowed(
    caps: EffectiveMcpCapabilities,
    notification_filter: &crate::store::McpNotificationFilter,
    kind: &NotificationKind,
) -> bool {
    allowed_by_caps_for_notification_kind(caps, kind) && notification_filter.allows(kind.method())
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
        let kind = classify_server_notification(notification);
        if !notification_allowed(caps, notification_filter, &kind) {
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
            if let ServerNotification::CancelledNotification(cancelled) = notification
                && let Some(request_id) = cancelled.params.request_id.as_ref()
            {
                cancelled.params.request_id = Some(make_proxied_request_id(
                    ns_req,
                    upstream_id,
                    request_id,
                    proxy_key,
                ));
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
            id: Some(id),
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

pub(super) struct OpenUpstreamStreamsInputs<'a> {
    pub(super) state: &'a McpState,
    pub(super) profile: &'a crate::store::Profile,
    pub(super) bindings: &'a [UpstreamSessionBinding],
    pub(super) last: &'a ParsedLastEventId,
    pub(super) resource_collision_counts: Arc<parking_lot::RwLock<HashMap<String, usize>>>,
    pub(super) proxy_key: Option<Arc<[u8]>>,
    pub(super) hop: u32,
    pub(super) limits: crate::transport_limits::EffectiveTransportLimits,
    pub(super) limits_shutdown: CancellationToken,
}

pub(super) async fn open_upstream_streams(
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
