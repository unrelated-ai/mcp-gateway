use super::*;
use unrelated_gateway_api::error::{ApiError, Resource, StoreKind};
use unrelated_gateway_api::routes;

pub(super) async fn get_tenant_audit_settings(
    Extension(state): Extension<Arc<AdminState>>,
    headers: HeaderMap,
    Path(tenant_id): Path<String>,
) -> impl IntoResponse {
    if let Err(resp) = authz(&headers, state.admin_token.as_deref()) {
        return resp.into_response();
    }
    let Some(store) = &state.store else {
        return ApiError::store_unavailable(StoreKind::Admin).into_response();
    };

    match store.get_tenant_audit_settings(&tenant_id).await {
        Ok(Some(s)) => Json(TenantAuditSettingsResponse {
            enabled: s.enabled,
            retention_days: s.retention_days,
            default_level: s.default_level,
        })
        .into_response(),
        Ok(None) => ApiError::not_found(Resource::Tenant).into_response(),
        Err(e) => ApiError::internal(e).into_response(),
    }
}

pub(super) async fn put_tenant_audit_settings(
    Extension(state): Extension<Arc<AdminState>>,
    headers: HeaderMap,
    Path(tenant_id): Path<String>,
    Json(req): Json<PutTenantAuditSettingsRequest>,
) -> impl IntoResponse {
    if let Err(resp) = authz(&headers, state.admin_token.as_deref()) {
        return resp.into_response();
    }
    let Some(store) = &state.store else {
        return ApiError::store_unavailable(StoreKind::Admin).into_response();
    };
    let started = Instant::now();

    if req.retention_days < 0 {
        return (StatusCode::BAD_REQUEST, "retentionDays must be >= 0").into_response();
    }
    if let Err(msg) = req
        .default_level
        .trim()
        .parse::<unrelated_gateway_api::audit::AuditLevel>()
    {
        return (StatusCode::BAD_REQUEST, msg).into_response();
    }

    let settings = crate::store::TenantAuditSettings {
        enabled: req.enabled,
        retention_days: req.retention_days,
        default_level: req.default_level.trim().to_string(),
    };

    let (status, ok, error, resp) =
        match store.put_tenant_audit_settings(&tenant_id, &settings).await {
            Ok(()) => {
                state.invalidation.apply_local(
                    &crate::pg_invalidation::InvalidationEvent::TenantAuditSettings {
                        tenant_id: tenant_id.clone(),
                    },
                );
                (
                    StatusCode::OK,
                    true,
                    None,
                    Json(OkResponse { ok: true }).into_response(),
                )
            }
            Err(e) => {
                let msg = e.to_string();
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    false,
                    Some(AuditError::new("internal_error", msg.clone())),
                    ApiError::internal(msg).into_response(),
                )
            }
        };

    state
        .audit
        .record(crate::audit::http_event(HttpAuditEvent {
            tenant_id: tenant_id.clone(),
            actor: AuditActor::default(),
            action: "admin.audit_settings_put",
            http_method: "PUT",
            http_route: routes::admin::AUDIT_SETTINGS.template(),
            status_code: i32::from(status.as_u16()),
            ok,
            elapsed: started.elapsed(),
            meta: serde_json::json!({
                "tenant_id": tenant_id,
                "enabled": settings.enabled,
                "retention_days": settings.retention_days,
                "default_level": settings.default_level,
            }),
            error,
        }))
        .await;

    resp
}

pub(super) async fn list_tenant_audit_events(
    Extension(state): Extension<Arc<AdminState>>,
    headers: HeaderMap,
    Path(tenant_id): Path<String>,
    Query(q): Query<AuditEventsQuery>,
) -> impl IntoResponse {
    if let Err(resp) = authz(&headers, state.admin_token.as_deref()) {
        return resp.into_response();
    }
    let Some(store) = &state.store else {
        return ApiError::store_unavailable(StoreKind::Admin).into_response();
    };

    // Ensure tenant exists.
    match store.get_tenant(&tenant_id).await {
        Ok(Some(_)) => {}
        Ok(None) => return ApiError::not_found(Resource::Tenant).into_response(),
        Err(e) => return ApiError::internal(e).into_response(),
    }

    let filter = crate::store::AuditEventFilter {
        from_unix_secs: q.from_unix_secs,
        to_unix_secs: q.to_unix_secs,
        before_id: q.before_id,
        profile_id: q.profile_id,
        api_key_id: q.api_key_id,
        tool_ref: q.tool_ref,
        action: q.action,
        ok: q.ok,
        limit: q.limit.unwrap_or(200).clamp(1, 1000),
    };

    match store.list_audit_events(&tenant_id, filter).await {
        Ok(events) => Json(AuditEventsResponse { events }).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

pub(super) async fn tool_call_stats_by_tool(
    Extension(state): Extension<Arc<AdminState>>,
    headers: HeaderMap,
    Path(tenant_id): Path<String>,
    Query(q): Query<AuditStatsQuery>,
) -> impl IntoResponse {
    if let Err(resp) = authz(&headers, state.admin_token.as_deref()) {
        return resp.into_response();
    }
    let Some(store) = &state.store else {
        return ApiError::store_unavailable(StoreKind::Admin).into_response();
    };

    // Ensure tenant exists.
    match store.get_tenant(&tenant_id).await {
        Ok(Some(_)) => {}
        Ok(None) => return ApiError::not_found(Resource::Tenant).into_response(),
        Err(e) => return ApiError::internal(e).into_response(),
    }

    let filter = crate::store::AuditStatsFilter {
        from_unix_secs: q.from_unix_secs,
        to_unix_secs: q.to_unix_secs,
        profile_id: q.profile_id,
        api_key_id: q.api_key_id,
        tool_ref: q.tool_ref,
        limit: q.limit.unwrap_or(100).clamp(1, 1000),
        offset: q.offset.unwrap_or(0).max(0),
    };

    match store.tool_call_stats_by_tool(&tenant_id, filter).await {
        Ok(items) => Json(ToolCallStatsByToolResponse { items }).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

pub(super) async fn tool_call_stats_by_api_key(
    Extension(state): Extension<Arc<AdminState>>,
    headers: HeaderMap,
    Path(tenant_id): Path<String>,
    Query(q): Query<AuditStatsQuery>,
) -> impl IntoResponse {
    if let Err(resp) = authz(&headers, state.admin_token.as_deref()) {
        return resp.into_response();
    }
    let Some(store) = &state.store else {
        return ApiError::store_unavailable(StoreKind::Admin).into_response();
    };

    // Ensure tenant exists.
    match store.get_tenant(&tenant_id).await {
        Ok(Some(_)) => {}
        Ok(None) => return ApiError::not_found(Resource::Tenant).into_response(),
        Err(e) => return ApiError::internal(e).into_response(),
    }

    let filter = crate::store::AuditStatsFilter {
        from_unix_secs: q.from_unix_secs,
        to_unix_secs: q.to_unix_secs,
        profile_id: q.profile_id,
        api_key_id: q.api_key_id,
        tool_ref: q.tool_ref,
        limit: q.limit.unwrap_or(100).clamp(1, 1000),
        offset: q.offset.unwrap_or(0).max(0),
    };

    match store.tool_call_stats_by_api_key(&tenant_id, filter).await {
        Ok(items) => Json(ToolCallStatsByApiKeyResponse { items }).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

pub(super) async fn cleanup_tenant_audit_events(
    Extension(state): Extension<Arc<AdminState>>,
    headers: HeaderMap,
    Path(tenant_id): Path<String>,
) -> impl IntoResponse {
    if let Err(resp) = authz(&headers, state.admin_token.as_deref()) {
        return resp.into_response();
    }
    let Some(store) = &state.store else {
        return ApiError::store_unavailable(StoreKind::Admin).into_response();
    };
    let started = Instant::now();

    // Ensure tenant exists.
    match store.get_tenant(&tenant_id).await {
        Ok(Some(_)) => {}
        Ok(None) => return ApiError::not_found(Resource::Tenant).into_response(),
        Err(e) => return ApiError::internal(e).into_response(),
    }

    let (status, ok, error, resp, deleted) =
        match store.cleanup_audit_events_for_tenant(&tenant_id).await {
            Ok(deleted) => (
                StatusCode::OK,
                true,
                None,
                Json(AuditCleanupResponse { ok: true, deleted }).into_response(),
                deleted,
            ),
            Err(e) => {
                let msg = e.to_string();
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    false,
                    Some(AuditError::new("internal_error", msg.clone())),
                    ApiError::internal(msg).into_response(),
                    0,
                )
            }
        };

    state
        .audit
        .record(crate::audit::http_event(HttpAuditEvent {
            tenant_id: tenant_id.clone(),
            actor: AuditActor::default(),
            action: "admin.audit_cleanup",
            http_method: "POST",
            http_route: routes::admin::AUDIT_CLEANUP.template(),
            status_code: i32::from(status.as_u16()),
            ok,
            elapsed: started.elapsed(),
            meta: serde_json::json!({
                "tenant_id": tenant_id,
                "deleted": deleted,
            }),
            error,
        }))
        .await;

    resp
}

pub(super) async fn get_profile_audit_settings(
    Extension(state): Extension<Arc<AdminState>>,
    headers: HeaderMap,
    Path(profile_id): Path<String>,
) -> impl IntoResponse {
    if let Err(resp) = authz(&headers, state.admin_token.as_deref()) {
        return resp.into_response();
    }
    let Some(store) = &state.store else {
        return ApiError::store_unavailable(StoreKind::Admin).into_response();
    };

    // Avoid leaking details / DB errors on obviously-invalid ids.
    if Uuid::parse_str(&profile_id)
        .ok()
        .and_then(|u| (u.get_version() == Some(Version::Random)).then_some(u))
        .is_none()
    {
        return ApiError::not_found(Resource::Profile).into_response();
    }

    let tenant_id = match store.get_profile(&profile_id).await {
        Ok(Some(profile)) => profile.tenant_id,
        Ok(None) => return ApiError::not_found(Resource::Profile).into_response(),
        Err(error) => return ApiError::internal(error).into_response(),
    };
    match store
        .get_profile_audit_settings(&tenant_id, &profile_id)
        .await
    {
        Ok(Some(v)) => Json(v).into_response(),
        Ok(None) => ApiError::not_found(Resource::Profile).into_response(),
        Err(e) => ApiError::internal(e).into_response(),
    }
}

pub(super) async fn put_profile_audit_settings(
    Extension(state): Extension<Arc<AdminState>>,
    headers: HeaderMap,
    Path(profile_id): Path<String>,
    Json(req): Json<PutProfileAuditSettingsRequest>,
) -> impl IntoResponse {
    if let Err(resp) = authz(&headers, state.admin_token.as_deref()) {
        return resp.into_response();
    }
    let Some(store) = &state.store else {
        return ApiError::store_unavailable(StoreKind::Admin).into_response();
    };
    let started = Instant::now();

    // Avoid leaking details / DB errors on obviously-invalid ids.
    let profile_uuid = match Uuid::parse_str(&profile_id) {
        Ok(u) if u.get_version() == Some(Version::Random) => u,
        _ => return ApiError::not_found(Resource::Profile).into_response(),
    };

    let audit_settings = match serde_json::from_value::<
        unrelated_gateway_api::audit::ProfileAuditSettings,
    >(req.audit_settings.clone())
    {
        Ok(settings) => settings,
        Err(error) => return (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    };

    let tenant_id_for_audit = match store.get_profile(&profile_id).await {
        Ok(Some(p)) => p.tenant_id,
        Ok(None) => return ApiError::not_found(Resource::Profile).into_response(),
        Err(e) => return ApiError::internal(e).into_response(),
    };

    let (status, ok, error, resp) = match store
        .put_profile_audit_settings(
            &tenant_id_for_audit,
            &profile_id,
            audit_settings,
            req.expected_revision,
        )
        .await
    {
        Ok(()) => {
            state
                .invalidation
                .apply_local(&crate::pg_invalidation::InvalidationEvent::Profile {
                    profile_id: profile_id.clone(),
                });
            (
                StatusCode::OK,
                true,
                None,
                Json(OkResponse { ok: true }).into_response(),
            )
        }
        Err(e) if e.is::<crate::store::ProfileRevisionConflict>() => (
            StatusCode::CONFLICT,
            false,
            Some(AuditError::new("revision_conflict", e.to_string())),
            (StatusCode::CONFLICT, e.to_string()).into_response(),
        ),
        Err(e) => {
            let msg = e.to_string();
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                false,
                Some(AuditError::new("internal_error", msg.clone())),
                ApiError::internal(msg).into_response(),
            )
        }
    };

    state
        .audit
        .record(crate::audit::http_event(HttpAuditEvent {
            tenant_id: tenant_id_for_audit.clone(),
            actor: AuditActor {
                profile_id: Some(profile_uuid),
                ..AuditActor::default()
            },
            action: "admin.profile_audit_settings_put",
            http_method: "PUT",
            http_route: routes::admin::PROFILE_AUDIT.template(),
            status_code: i32::from(status.as_u16()),
            ok,
            elapsed: started.elapsed(),
            meta: serde_json::json!({
                "tenant_id": tenant_id_for_audit,
                "profile_id": profile_id,
                "audit_settings": req.audit_settings,
            }),
            error,
        }))
        .await;

    resp
}
