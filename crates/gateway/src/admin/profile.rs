use super::*;

fn parse_or_generate_profile_uuid(id: Option<&str>) -> Result<Uuid, &'static str> {
    let Some(id) = id else {
        return Ok(Uuid::new_v4());
    };
    match Uuid::parse_str(id) {
        Ok(u) if u.get_version() == Some(Version::Random) => Ok(u),
        _ => Err("profile id must be a UUIDv4 (random)"),
    }
}

fn resolve_data_plane_auth_settings(
    req: Option<DataPlaneAuthSettings>,
    existing: Option<&AdminProfile>,
    is_update: bool,
) -> DataPlaneAuthSettings {
    match req {
        Some(v) => v,
        None => {
            if is_update {
                existing.map_or_else(DataPlaneAuthSettings::default, |p| {
                    DataPlaneAuthSettings::from_parts(
                        p.data_plane_auth_mode,
                        p.accept_x_api_key,
                        p.oauth_required_scopes.clone(),
                    )
                })
            } else {
                DataPlaneAuthSettings::default()
            }
        }
    }
}

fn resolve_data_plane_limits_settings(
    req: Option<DataPlaneLimitsSettings>,
    existing: Option<&AdminProfile>,
    is_update: bool,
) -> Result<DataPlaneLimitsSettings, &'static str> {
    let limits = match req {
        Some(v) => v,
        None => {
            if is_update {
                existing.map_or(
                    DataPlaneLimitsSettings {
                        rate_limit_enabled: false,
                        rate_limit_tool_calls_per_minute: None,
                        quota_enabled: false,
                        quota_tool_calls: None,
                    },
                    |p| DataPlaneLimitsSettings {
                        rate_limit_enabled: p.rate_limit_enabled,
                        rate_limit_tool_calls_per_minute: p.rate_limit_tool_calls_per_minute,
                        quota_enabled: p.quota_enabled,
                        quota_tool_calls: p.quota_tool_calls,
                    },
                )
            } else {
                DataPlaneLimitsSettings {
                    rate_limit_enabled: false,
                    rate_limit_tool_calls_per_minute: None,
                    quota_enabled: false,
                    quota_tool_calls: None,
                }
            }
        }
    };
    limits.validate()?;
    Ok(limits)
}

fn resolve_tool_call_timeout_secs(
    req: Option<NullableU64>,
    existing: Option<&AdminProfile>,
) -> Option<u64> {
    resolve_nullable_u64(req, existing.and_then(|p| p.tool_call_timeout_secs))
}

fn resolve_tool_policies(
    req: Option<Vec<ToolPolicy>>,
    existing: Option<&AdminProfile>,
) -> Vec<ToolPolicy> {
    req.or_else(|| existing.map(|p| p.tool_policies.clone()))
        .unwrap_or_default()
}

fn resolve_mcp_settings(
    req: Option<McpProfileSettings>,
    existing: Option<&AdminProfile>,
) -> McpProfileSettings {
    req.or_else(|| existing.map(|p| p.mcp.clone()))
        .unwrap_or_default()
}

async fn load_existing_profile_for_update(
    store: &dyn AdminStore,
    profile_id: &str,
    is_update: bool,
) -> Result<Option<AdminProfile>, BoxResponse> {
    if !is_update {
        return Ok(None);
    }
    store
        .get_profile(profile_id)
        .await
        .map_err(|e| Box::new((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()))
}

fn resolve_profile_name(
    req_name: Option<String>,
    existing: Option<&AdminProfile>,
) -> Result<String, BoxResponse> {
    let name = match (req_name, existing) {
        (Some(n), _) => n,
        (None, Some(p)) => p.name.clone(),
        (None, None) => {
            return Err(Box::new(
                (StatusCode::BAD_REQUEST, "name is required").into_response(),
            ));
        }
    };
    if name.trim().is_empty() {
        return Err(Box::new(
            (StatusCode::BAD_REQUEST, "name is required").into_response(),
        ));
    }
    Ok(name)
}

fn resolve_profile_description(
    req_description: Option<&NullableString>,
    existing: Option<&AdminProfile>,
) -> Option<String> {
    match req_description {
        None => existing.and_then(|p| p.description.clone()),
        Some(NullableString::Null) => None,
        Some(NullableString::Value(v)) => Some(v.clone()),
    }
}

pub(super) fn validate_oauth_configured_if_needed(
    oidc_issuer: Option<&str>,
    mode: DataPlaneAuthMode,
) -> Result<(), BoxResponse> {
    if mode == DataPlaneAuthMode::OAuth && oidc_issuer.is_none() {
        return Err(Box::new(
            (StatusCode::BAD_REQUEST, OAUTH_NOT_CONFIGURED_MSG).into_response(),
        ));
    }
    Ok(())
}

struct PutProfileStoreInputs<'a> {
    profile_id: &'a str,
    name: &'a str,
    description: Option<&'a str>,
    enabled_tools: &'a [String],
    data_plane_auth: DataPlaneAuthSettings,
    data_plane_limits: DataPlaneLimitsSettings,
    tool_call_timeout_secs: Option<u64>,
    tool_policies: &'a [ToolPolicy],
    mcp: &'a McpProfileSettings,
}

async fn put_profile_in_store(
    store: &dyn AdminStore,
    req: &PutProfileRequest,
    upstream_ids: &[String],
    input: PutProfileStoreInputs<'_>,
) -> Result<(), BoxResponse> {
    store
        .put_profile(PutProfileInput {
            profile_id: input.profile_id,
            tenant_id: &req.tenant_id,
            name: input.name,
            description: input.description,
            flags: PutProfileFlags {
                enabled: req.enabled,
                allow_partial_upstreams: req.allow_partial_upstreams,
            },
            upstream_ids,
            source_ids: &req.sources,
            transforms: &req.transforms,
            enabled_tools: input.enabled_tools,
            data_plane_auth: PutProfileDataPlaneAuth {
                mode: input.data_plane_auth.mode(),
                accept_x_api_key: input.data_plane_auth.accept_x_api_key(),
                oauth_required_scopes: input.data_plane_auth.required_scopes().to_vec(),
            },
            limits: PutProfileLimits {
                rate_limit_enabled: input.data_plane_limits.rate_limit_enabled,
                rate_limit_tool_calls_per_minute: input
                    .data_plane_limits
                    .rate_limit_tool_calls_per_minute,
                quota_enabled: input.data_plane_limits.quota_enabled,
                quota_tool_calls: input.data_plane_limits.quota_tool_calls,
            },
            tool_call_timeout_secs: input.tool_call_timeout_secs,
            tool_policies: input.tool_policies,
            mcp: input.mcp,
        })
        .await
        .map_err(|e| {
            if e.to_string().contains("profiles_tenant_name_ci_uq") {
                Box::new(
                    (
                        StatusCode::CONFLICT,
                        "profile name already exists for this tenant (case-insensitive)",
                    )
                        .into_response(),
                )
            } else {
                Box::new((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response())
            }
        })?;
    Ok(())
}

pub(super) async fn put_profile(
    Extension(state): Extension<Arc<AdminState>>,
    headers: HeaderMap,
    Json(req): Json<PutProfileRequest>,
) -> impl IntoResponse {
    if let Err(resp) = authz(&headers, state.admin_token.as_deref()) {
        return resp.into_response();
    }
    let Some(store) = &state.store else {
        return (StatusCode::SERVICE_UNAVAILABLE, "Admin store unavailable").into_response();
    };
    let started = Instant::now();
    let tenant_id = req.tenant_id.clone();
    let (resp, profile_uuid, profile_id_for_meta, name_for_meta, error) =
        admin_put_profile_inner(store.as_ref(), state.oidc_issuer.as_deref(), req).await;
    let status = resp.status();
    state
        .audit
        .record(crate::audit::http_event(HttpAuditEvent {
            tenant_id: tenant_id.clone(),
            actor: AuditActor {
                profile_id: profile_uuid,
                ..AuditActor::default()
            },
            action: "admin.profile_put",
            http_method: "POST",
            http_route: "/admin/v1/profiles",
            status_code: i32::from(status.as_u16()),
            ok: status.is_success(),
            elapsed: started.elapsed(),
            meta: serde_json::json!({
                "tenant_id": tenant_id,
                "profile_id": profile_id_for_meta,
                "name": name_for_meta,
            }),
            error,
        }))
        .await;
    resp
}

async fn admin_put_profile_inner(
    store: &dyn AdminStore,
    oidc_issuer: Option<&str>,
    req: PutProfileRequest,
) -> (
    Response,
    Option<Uuid>,
    Option<String>,
    Option<String>,
    Option<AuditError>,
) {
    match admin_put_profile_inner_impl(store, oidc_issuer, req).await {
        Ok((resp, profile_uuid, profile_id, name)) => {
            (resp, Some(profile_uuid), Some(profile_id), Some(name), None)
        }
        Err(e) => (e.resp, e.profile_uuid, e.profile_id, e.name, Some(e.error)),
    }
}

type AdminPutProfileInnerResult<T> = Result<T, Box<AdminPutProfileInnerError>>;

struct AdminPutProfileInnerError {
    resp: Response,
    profile_uuid: Option<Uuid>,
    profile_id: Option<String>,
    name: Option<String>,
    error: AuditError,
}

#[allow(clippy::too_many_lines)]
async fn admin_put_profile_inner_impl(
    store: &dyn AdminStore,
    oidc_issuer: Option<&str>,
    req: PutProfileRequest,
) -> AdminPutProfileInnerResult<(Response, Uuid, String, String)> {
    let (profile_uuid, profile_id, is_update) = admin_put_profile_parse_uuid(&req)?;
    let existing =
        admin_put_profile_load_existing(store, profile_uuid, &profile_id, is_update).await?;
    let name = admin_put_profile_resolve_name(
        profile_uuid,
        profile_id.clone(),
        req.name.clone(),
        existing.as_ref(),
    )?;

    let description = resolve_profile_description(req.description.as_ref(), existing.as_ref());
    let enabled_tools = req.tools.as_deref().unwrap_or(&[]);
    let mut data_plane_auth =
        resolve_data_plane_auth_settings(req.data_plane_auth.clone(), existing.as_ref(), is_update);
    if let Err(message) = data_plane_auth.validate() {
        return Err(Box::new(AdminPutProfileInnerError {
            resp: (StatusCode::BAD_REQUEST, message.clone()).into_response(),
            profile_uuid: Some(profile_uuid),
            profile_id: Some(profile_id),
            name: Some(name),
            error: AuditError::new("bad_request", message),
        }));
    }
    admin_put_profile_validate_oidc(
        profile_uuid,
        profile_id.clone(),
        name.clone(),
        oidc_issuer,
        data_plane_auth.mode(),
    )?;

    let data_plane_limits = admin_put_profile_resolve_data_plane_limits(
        profile_uuid,
        profile_id.clone(),
        name.clone(),
        req.data_plane_limits.clone(),
        existing.as_ref(),
        is_update,
    )?;

    let tool_call_timeout_secs =
        resolve_tool_call_timeout_secs(req.tool_call_timeout_secs, existing.as_ref());
    let tool_policies = resolve_tool_policies(req.tool_policies.clone(), existing.as_ref());
    let mcp = resolve_mcp_settings(req.mcp.clone(), existing.as_ref());

    admin_put_profile_validate_tools(
        profile_uuid,
        profile_id.clone(),
        name.clone(),
        enabled_tools,
        tool_call_timeout_secs,
        &tool_policies,
    )?;

    let resolved_upstreams = admin_put_profile_resolve_upstreams(
        store,
        profile_uuid,
        profile_id.clone(),
        name.clone(),
        &req.tenant_id,
        &req.upstreams,
    )
    .await?;

    admin_put_profile_validate_no_self_upstream_loop(
        store,
        profile_uuid,
        profile_id.clone(),
        name.clone(),
        &resolved_upstreams,
    )
    .await?;

    admin_put_profile_write_store(
        store,
        profile_uuid,
        profile_id.clone(),
        name.clone(),
        &req,
        &resolved_upstreams,
        PutProfileStoreInputs {
            profile_id: &profile_id,
            name: &name,
            description: description.as_deref(),
            enabled_tools,
            data_plane_auth,
            data_plane_limits,
            tool_call_timeout_secs,
            tool_policies: &tool_policies,
            mcp: &mcp,
        },
    )
    .await?;

    Ok((
        (
            StatusCode::CREATED,
            Json(CreateProfileResponse {
                ok: true,
                data_plane_path: format!("/{profile_id}/mcp"),
                id: profile_id.clone(),
            }),
        )
            .into_response(),
        profile_uuid,
        profile_id,
        name,
    ))
}

fn admin_put_profile_parse_uuid(
    req: &PutProfileRequest,
) -> AdminPutProfileInnerResult<(Uuid, String, bool)> {
    let is_update = req.id.is_some();
    match parse_or_generate_profile_uuid(req.id.as_deref()) {
        Ok(profile_uuid) => Ok((profile_uuid, profile_uuid.to_string(), is_update)),
        Err(msg) => Err(Box::new(AdminPutProfileInnerError {
            resp: (StatusCode::BAD_REQUEST, msg).into_response(),
            profile_uuid: None,
            profile_id: None,
            name: None,
            error: AuditError::new("bad_request", msg.to_string()),
        })),
    }
}

async fn admin_put_profile_load_existing(
    store: &dyn AdminStore,
    profile_uuid: Uuid,
    profile_id: &str,
    is_update: bool,
) -> AdminPutProfileInnerResult<Option<AdminProfile>> {
    match load_existing_profile_for_update(store, profile_id, is_update).await {
        Ok(p) => Ok(p),
        Err(resp) => {
            let status = resp.status();
            Err(Box::new(AdminPutProfileInnerError {
                resp: *resp,
                profile_uuid: Some(profile_uuid),
                profile_id: Some(profile_id.to_string()),
                name: None,
                error: AuditError::new("request_failed", status.to_string()),
            }))
        }
    }
}

fn admin_put_profile_resolve_name(
    profile_uuid: Uuid,
    profile_id: String,
    req_name: Option<String>,
    existing: Option<&AdminProfile>,
) -> AdminPutProfileInnerResult<String> {
    match resolve_profile_name(req_name, existing) {
        Ok(n) => Ok(n),
        Err(resp) => {
            let status = resp.status();
            Err(Box::new(AdminPutProfileInnerError {
                resp: *resp,
                profile_uuid: Some(profile_uuid),
                profile_id: Some(profile_id),
                name: None,
                error: AuditError::new("bad_request", status.to_string()),
            }))
        }
    }
}

fn admin_put_profile_validate_oidc(
    profile_uuid: Uuid,
    profile_id: String,
    name: String,
    oidc_issuer: Option<&str>,
    mode: DataPlaneAuthMode,
) -> AdminPutProfileInnerResult<()> {
    if let Err(resp) = validate_oauth_configured_if_needed(oidc_issuer, mode) {
        let status = resp.status();
        return Err(Box::new(AdminPutProfileInnerError {
            resp: *resp,
            profile_uuid: Some(profile_uuid),
            profile_id: Some(profile_id),
            name: Some(name),
            error: AuditError::new("bad_request", status.to_string()),
        }));
    }
    Ok(())
}

fn admin_put_profile_resolve_data_plane_limits(
    profile_uuid: Uuid,
    profile_id: String,
    name: String,
    req: Option<DataPlaneLimitsSettings>,
    existing: Option<&AdminProfile>,
    is_update: bool,
) -> AdminPutProfileInnerResult<DataPlaneLimitsSettings> {
    match resolve_data_plane_limits_settings(req, existing, is_update) {
        Ok(v) => Ok(v),
        Err(msg) => Err(Box::new(AdminPutProfileInnerError {
            resp: (StatusCode::BAD_REQUEST, msg).into_response(),
            profile_uuid: Some(profile_uuid),
            profile_id: Some(profile_id),
            name: Some(name),
            error: AuditError::new("bad_request", msg.to_string()),
        })),
    }
}

fn admin_put_profile_validate_tools(
    profile_uuid: Uuid,
    profile_id: String,
    name: String,
    enabled_tools: &[String],
    tool_call_timeout_secs: Option<u64>,
    tool_policies: &[ToolPolicy],
) -> AdminPutProfileInnerResult<()> {
    if let Err(msg) = validate_tool_timeout_and_policies(tool_call_timeout_secs, tool_policies) {
        return Err(Box::new(AdminPutProfileInnerError {
            resp: (StatusCode::BAD_REQUEST, msg.clone()).into_response(),
            profile_uuid: Some(profile_uuid),
            profile_id: Some(profile_id),
            name: Some(name),
            error: AuditError::new("bad_request", msg),
        }));
    }
    if let Err(msg) = validate_tool_allowlist(enabled_tools) {
        return Err(Box::new(AdminPutProfileInnerError {
            resp: (StatusCode::BAD_REQUEST, msg.clone()).into_response(),
            profile_uuid: Some(profile_uuid),
            profile_id: Some(profile_id),
            name: Some(name),
            error: AuditError::new("bad_request", msg),
        }));
    }
    Ok(())
}

async fn resolve_admin_profile_upstream_ids(
    store: &dyn AdminStore,
    tenant_id: &str,
    upstream_ids: &[String],
) -> Result<Vec<String>, Response> {
    let mut resolved = Vec::with_capacity(upstream_ids.len());
    for upstream_id in upstream_ids {
        // Admin profile writes keep previous behavior for unknown IDs, but when a
        // tenant-owned managed upstream exists we must bind to its internal ID.
        let internal_id = tenant_upstream_internal_id(tenant_id, upstream_id);
        let has_tenant_owned = store
            .get_upstream(&internal_id)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response())?
            .is_some();
        if has_tenant_owned {
            resolved.push(internal_id);
        } else {
            resolved.push(upstream_id.clone());
        }
    }
    Ok(resolved)
}

async fn admin_put_profile_resolve_upstreams(
    store: &dyn AdminStore,
    profile_uuid: Uuid,
    profile_id: String,
    name: String,
    tenant_id: &str,
    upstream_ids: &[String],
) -> AdminPutProfileInnerResult<Vec<String>> {
    match resolve_admin_profile_upstream_ids(store, tenant_id, upstream_ids).await {
        Ok(v) => Ok(v),
        Err(resp) => {
            let status = resp.status();
            Err(Box::new(AdminPutProfileInnerError {
                resp,
                profile_uuid: Some(profile_uuid),
                profile_id: Some(profile_id),
                name: Some(name),
                error: AuditError::new("request_failed", status.to_string()),
            }))
        }
    }
}

async fn admin_put_profile_validate_no_self_upstream_loop(
    store: &dyn AdminStore,
    profile_uuid: Uuid,
    profile_id: String,
    name: String,
    upstreams: &[String],
) -> AdminPutProfileInnerResult<()> {
    if let Err(resp) = validate_no_self_upstream_loop(store, &profile_id, upstreams).await {
        let status = resp.status();
        return Err(Box::new(AdminPutProfileInnerError {
            resp,
            profile_uuid: Some(profile_uuid),
            profile_id: Some(profile_id),
            name: Some(name),
            error: AuditError::new("bad_request", status.to_string()),
        }));
    }
    Ok(())
}

async fn admin_put_profile_write_store(
    store: &dyn AdminStore,
    profile_uuid: Uuid,
    profile_id: String,
    name: String,
    req: &PutProfileRequest,
    resolved_upstreams: &[String],
    store_input: PutProfileStoreInputs<'_>,
) -> AdminPutProfileInnerResult<()> {
    if let Err(resp) = put_profile_in_store(store, req, resolved_upstreams, store_input).await {
        let status = resp.status();
        return Err(Box::new(AdminPutProfileInnerError {
            resp: *resp,
            profile_uuid: Some(profile_uuid),
            profile_id: Some(profile_id),
            name: Some(name),
            error: AuditError::new("request_failed", status.to_string()),
        }));
    }
    Ok(())
}

pub(super) async fn list_profiles(
    Extension(state): Extension<Arc<AdminState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(resp) = authz(&headers, state.admin_token.as_deref()) {
        return resp.into_response();
    }

    let Some(store) = &state.store else {
        return (StatusCode::SERVICE_UNAVAILABLE, "Admin store unavailable").into_response();
    };

    match store.list_profiles().await {
        Ok(profiles) => Json(ProfilesResponse {
            profiles: profiles
                .into_iter()
                .map(profile_to_admin_response)
                .collect(),
        })
        .into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

pub(super) async fn get_profile(
    Extension(state): Extension<Arc<AdminState>>,
    headers: HeaderMap,
    Path(profile_id): Path<String>,
) -> impl IntoResponse {
    if let Err(resp) = authz(&headers, state.admin_token.as_deref()) {
        return resp.into_response();
    }

    let Some(store) = &state.store else {
        return (StatusCode::SERVICE_UNAVAILABLE, "Admin store unavailable").into_response();
    };

    // Avoid leaking details / DB errors on obviously-invalid ids.
    if Uuid::parse_str(&profile_id)
        .ok()
        .and_then(|u| (u.get_version() == Some(Version::Random)).then_some(u))
        .is_none()
    {
        return (StatusCode::NOT_FOUND, "profile not found").into_response();
    }

    match store.get_profile(&profile_id).await {
        Ok(Some(profile)) => Json(profile_to_admin_response(profile)).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "profile not found").into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

pub(super) async fn delete_profile(
    Extension(state): Extension<Arc<AdminState>>,
    headers: HeaderMap,
    Path(profile_id): Path<String>,
) -> impl IntoResponse {
    if let Err(resp) = authz(&headers, state.admin_token.as_deref()) {
        return resp.into_response();
    }
    let Some(store) = &state.store else {
        return (StatusCode::SERVICE_UNAVAILABLE, "Admin store unavailable").into_response();
    };
    let started = Instant::now();

    if Uuid::parse_str(&profile_id)
        .ok()
        .and_then(|u| (u.get_version() == Some(Version::Random)).then_some(u))
        .is_none()
    {
        return (StatusCode::NOT_FOUND, "profile not found").into_response();
    }
    let profile_uuid = Uuid::parse_str(&profile_id).ok();

    let tenant_id_for_audit = match store.get_profile(&profile_id).await {
        Ok(Some(p)) => Some(p.tenant_id),
        _ => None,
    };

    let (status, ok, error, resp) = match store.delete_profile(&profile_id).await {
        Ok(true) => (
            StatusCode::OK,
            true,
            None,
            Json(OkResponse { ok: true }).into_response(),
        ),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            false,
            Some(AuditError::new("not_found", "profile not found")),
            (StatusCode::NOT_FOUND, "profile not found").into_response(),
        ),
        Err(e) => {
            let msg = e.to_string();
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                false,
                Some(AuditError::new("internal_error", msg.clone())),
                (StatusCode::INTERNAL_SERVER_ERROR, msg).into_response(),
            )
        }
    };

    if let Some(tenant_id) = tenant_id_for_audit {
        state
            .audit
            .record(crate::audit::http_event(HttpAuditEvent {
                tenant_id,
                actor: AuditActor {
                    profile_id: profile_uuid,
                    ..AuditActor::default()
                },
                action: "admin.profile_delete",
                http_method: "DELETE",
                http_route: "/admin/v1/profiles/{profile_id}",
                status_code: i32::from(status.as_u16()),
                ok,
                elapsed: started.elapsed(),
                meta: serde_json::json!({
                    "profile_id": profile_id,
                }),
                error,
            }))
            .await;
    }

    resp
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ProfileResponse {
    id: String,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    tenant_id: String,
    enabled: bool,
    allow_partial_upstreams: bool,
    upstreams: Vec<String>,
    sources: Vec<String>,
    transforms: TransformPipeline,
    tools: Vec<String>,
    data_plane_auth: DataPlaneAuthSettings,
    data_plane_limits: DataPlaneLimitsSettings,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_call_timeout_secs: Option<u64>,
    tool_policies: Vec<ToolPolicy>,
    mcp: McpProfileSettings,
}

pub(super) fn tenant_to_response(t: AdminTenant) -> TenantResponse {
    TenantResponse {
        id: t.id,
        enabled: t.enabled,
    }
}

pub(super) fn upstream_to_response(u: AdminUpstream) -> UpstreamResponse {
    UpstreamResponse {
        id: u.id,
        enabled: u.enabled,
        network_class: u.network_class,
        endpoints: u
            .endpoints
            .into_iter()
            .map(|e| UpstreamEndpointResponse {
                id: e.id,
                url: e.url,
                enabled: e.enabled,
                lifecycle: e.lifecycle,
                auth: e.auth,
            })
            .collect(),
    }
}

fn profile_to_admin_response(profile: AdminProfile) -> ProfileResponse {
    ProfileResponse {
        id: profile.id,
        name: profile.name,
        description: profile.description,
        tenant_id: profile.tenant_id,
        enabled: profile.enabled,
        allow_partial_upstreams: profile.allow_partial_upstreams,
        upstreams: profile.upstream_ids,
        sources: profile.source_ids,
        transforms: profile.transforms,
        tools: profile.enabled_tools,
        data_plane_auth: DataPlaneAuthSettings::from_parts(
            profile.data_plane_auth_mode,
            profile.accept_x_api_key,
            profile.oauth_required_scopes,
        ),
        data_plane_limits: DataPlaneLimitsSettings {
            rate_limit_enabled: profile.rate_limit_enabled,
            rate_limit_tool_calls_per_minute: profile.rate_limit_tool_calls_per_minute,
            quota_enabled: profile.quota_enabled,
            quota_tool_calls: profile.quota_tool_calls,
        },
        tool_call_timeout_secs: profile.tool_call_timeout_secs,
        tool_policies: profile.tool_policies,
        mcp: profile.mcp,
    }
}
