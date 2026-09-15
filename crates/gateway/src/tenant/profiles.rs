mod validation;

use super::{
    OkResponse, TenantState, authn, parse_tenant_upstream_internal_id, tenant_upstream_internal_id,
};
use crate::audit::{AuditActor, AuditError, HttpAuditEvent};
use crate::profile_http::{
    DataPlaneAuthSettings, DataPlaneLimitsSettings, NullableString, NullableU64,
};
use crate::serde_helpers::default_true;
use crate::store::{
    AdminProfile, AdminStore, McpProfileSettings, PutProfileDataPlaneAuth, PutProfileFlags,
    PutProfileInput, PutProfileLimits,
};
use crate::tool_policy::ToolPolicy;
use axum::extract::Path;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Instant;
use unrelated_tool_transforms::TransformPipeline;
use uuid::{Uuid, Version};

pub(super) fn router() -> Router {
    Router::new()
        .route(
            "/tenant/v1/profiles",
            get(list_profiles).post(create_profile),
        )
        .route(
            "/tenant/v1/profiles/{profile_id}",
            get(get_profile).put(put_profile).delete(delete_profile),
        )
}

fn is_profile_mcp_endpoint_url(profile_id: &str, url: &str) -> bool {
    let Ok(u) = reqwest::Url::parse(url) else {
        return false;
    };
    let want = format!("/{profile_id}/mcp");
    u.path() == want || u.path() == format!("{want}/")
}

async fn validate_no_self_upstream_loop(
    store: &dyn AdminStore,
    profile_id: &str,
    upstream_ids: &[String],
) -> Result<(), axum::response::Response> {
    for upstream_id in upstream_ids {
        let Some(upstream) = store
            .get_upstream(upstream_id)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response())?
        else {
            continue;
        };
        for ep in upstream.endpoints {
            if is_profile_mcp_endpoint_url(profile_id, &ep.url) {
                return Err((
                    StatusCode::BAD_REQUEST,
                    format!(
                        "upstream endpoint '{}' points to this profile's MCP endpoint (self-loop)",
                        ep.url
                    ),
                )
                    .into_response());
            }
        }
    }
    Ok(())
}

async fn resolve_upstream_ids_for_tenant(
    store: &dyn AdminStore,
    tenant_id: &str,
    upstream_ids: &[String],
) -> Result<Vec<String>, axum::response::Response> {
    let mut out = Vec::with_capacity(upstream_ids.len());
    for id in upstream_ids {
        let internal = tenant_upstream_internal_id(tenant_id, id);
        let tenant_owned = store
            .get_upstream(&internal)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response())?
            .is_some();
        if tenant_owned {
            out.push(internal);
            continue;
        }

        let global = store
            .get_upstream(id)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response())?
            .is_some();
        if global {
            out.push(id.clone());
            continue;
        }

        return Err((StatusCode::BAD_REQUEST, format!("unknown upstream '{id}'")).into_response());
    }
    Ok(out)
}

async fn resolve_upstreams_for_create_profile(
    store: &dyn AdminStore,
    tenant_id: &str,
    profile_id: &str,
    upstream_ids: &[String],
) -> Result<Vec<String>, axum::response::Response> {
    let resolved = resolve_upstream_ids_for_tenant(store, tenant_id, upstream_ids).await?;
    validate_no_self_upstream_loop(store, profile_id, &resolved).await?;
    Ok(resolved)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateProfileRequest {
    /// Human-friendly profile name (unique per tenant, case-insensitive).
    name: String,
    /// Optional human-friendly description.
    #[serde(default)]
    description: Option<String>,
    #[serde(default = "default_true")]
    enabled: bool,
    #[serde(default = "default_true")]
    allow_partial_upstreams: bool,
    upstreams: Vec<String>,
    /// Local tool sources attached to this profile (shared + tenant-owned).
    #[serde(default)]
    sources: Vec<String>,
    /// Per-profile tool transforms (renames/defaults).
    #[serde(default)]
    transforms: TransformPipeline,
    #[serde(default)]
    tools: Option<Vec<String>>,
    /// Optional per-profile data-plane auth settings.
    #[serde(default)]
    data_plane_auth: Option<DataPlaneAuthSettings>,
    /// Optional per-profile data-plane limits (rate limits and quotas).
    #[serde(default)]
    data_plane_limits: Option<DataPlaneLimitsSettings>,

    /// Optional per-profile default timeout override for `tools/call` (seconds).
    #[serde(default)]
    tool_call_timeout_secs: Option<u64>,
    /// Optional per-profile per-tool policies (timeouts + retry policy).
    #[serde(default)]
    tool_policies: Vec<ToolPolicy>,

    /// Optional per-profile MCP proxy behavior settings (capabilities allow/deny, notification filters, namespacing).
    #[serde(default)]
    mcp: McpProfileSettings,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PutProfileRequest {
    /// Human-friendly profile name (unique per tenant, case-insensitive).
    ///
    /// If omitted, defaults to the existing profile name (PUT semantics).
    #[serde(default)]
    name: Option<String>,
    /// Optional human-friendly description (PUT semantics).
    ///
    /// - omitted => keep existing description
    /// - null => clear description
    /// - string => set description
    #[serde(
        default,
        deserialize_with = "crate::profile_http::deserialize_present_nullable"
    )]
    description: Option<NullableString>,
    #[serde(default = "default_true")]
    enabled: bool,
    #[serde(default = "default_true")]
    allow_partial_upstreams: bool,
    upstreams: Vec<String>,
    /// Local tool sources attached to this profile (shared + tenant-owned).
    #[serde(default)]
    sources: Vec<String>,
    /// Per-profile tool transforms (renames/defaults).
    #[serde(default)]
    transforms: TransformPipeline,
    #[serde(default)]
    tools: Option<Vec<String>>,
    /// Optional per-profile data-plane auth settings.
    #[serde(default)]
    data_plane_auth: Option<DataPlaneAuthSettings>,
    /// Optional per-profile data-plane limits (rate limits and quotas).
    #[serde(default)]
    data_plane_limits: Option<DataPlaneLimitsSettings>,

    /// Optional per-profile default timeout override for `tools/call` (seconds).
    #[serde(
        default,
        deserialize_with = "crate::profile_http::deserialize_present_nullable"
    )]
    tool_call_timeout_secs: Option<NullableU64>,
    /// Optional per-profile per-tool policies (timeouts + retry policy).
    #[serde(default)]
    tool_policies: Option<Vec<ToolPolicy>>,

    /// Optional per-profile MCP proxy behavior settings (capabilities allow/deny, notification filters, namespacing).
    #[serde(default)]
    mcp: Option<McpProfileSettings>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProfileResponse {
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
    data_plane_path: String,
    data_plane_auth: DataPlaneAuthSettings,
    data_plane_limits: DataPlaneLimitsSettings,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_call_timeout_secs: Option<u64>,
    tool_policies: Vec<ToolPolicy>,
    mcp: McpProfileSettings,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProfilesResponse {
    profiles: Vec<ProfileResponse>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateProfileResponse {
    ok: bool,
    id: String,
    data_plane_path: String,
}

fn profile_to_response(p: AdminProfile) -> ProfileResponse {
    let id = p.id;
    let upstreams = p
        .upstream_ids
        .into_iter()
        .map(|uid| {
            if let Some((t, u)) = parse_tenant_upstream_internal_id(&uid)
                && t == p.tenant_id
            {
                u
            } else {
                uid
            }
        })
        .collect();
    ProfileResponse {
        name: p.name,
        description: p.description,
        tenant_id: p.tenant_id,
        enabled: p.enabled,
        allow_partial_upstreams: p.allow_partial_upstreams,
        upstreams,
        sources: p.source_ids,
        transforms: p.transforms,
        tools: p.enabled_tools,
        data_plane_path: format!("/{id}/mcp"),
        data_plane_auth: DataPlaneAuthSettings::from_parts(
            p.data_plane_auth_mode,
            p.accept_x_api_key,
            p.oauth_required_scopes,
        ),
        data_plane_limits: DataPlaneLimitsSettings {
            rate_limit_enabled: p.rate_limit_enabled,
            rate_limit_tool_calls_per_minute: p.rate_limit_tool_calls_per_minute,
            quota_enabled: p.quota_enabled,
            quota_tool_calls: p.quota_tool_calls,
        },
        tool_call_timeout_secs: p.tool_call_timeout_secs,
        tool_policies: p.tool_policies,
        mcp: p.mcp,
        id,
    }
}

async fn list_profiles(
    axum::Extension(state): axum::Extension<Arc<TenantState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let tenant_id = match authn(&headers, &state.signer) {
        Ok(t) => t,
        Err(resp) => return resp.into_response(),
    };
    let Some(store) = &state.store else {
        return (StatusCode::SERVICE_UNAVAILABLE, "Tenant store unavailable").into_response();
    };

    match store.list_profiles().await {
        Ok(profiles) => {
            let profiles = profiles
                .into_iter()
                .filter(|p| p.tenant_id == tenant_id)
                .map(profile_to_response)
                .collect();
            Json(ProfilesResponse { profiles }).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn get_profile(
    axum::Extension(state): axum::Extension<Arc<TenantState>>,
    headers: HeaderMap,
    Path(profile_id): Path<String>,
) -> impl IntoResponse {
    let tenant_id = match authn(&headers, &state.signer) {
        Ok(t) => t,
        Err(resp) => return resp.into_response(),
    };
    let Some(store) = &state.store else {
        return (StatusCode::SERVICE_UNAVAILABLE, "Tenant store unavailable").into_response();
    };

    // UUIDv4 only, otherwise 404 (avoid enumeration patterns).
    if Uuid::parse_str(&profile_id)
        .ok()
        .and_then(|u| (u.get_version() == Some(Version::Random)).then_some(u))
        .is_none()
    {
        return (StatusCode::NOT_FOUND, "profile not found").into_response();
    }

    match store.get_profile(&profile_id).await {
        Ok(Some(profile)) if profile.tenant_id == tenant_id => {
            Json(profile_to_response(profile)).into_response()
        }
        Ok(_) => (StatusCode::NOT_FOUND, "profile not found").into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn put_profile_handle_name_conflict(
    store: &dyn AdminStore,
    input: PutProfileInput<'_>,
) -> Result<(), Response> {
    store.put_profile(input).await.map_err(|e| {
        if e.to_string().contains("profiles_tenant_name_ci_uq") {
            (
                StatusCode::CONFLICT,
                "profile name already exists for this tenant (case-insensitive)",
            )
                .into_response()
        } else {
            (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
        }
    })
}

async fn create_profile(
    axum::Extension(state): axum::Extension<Arc<TenantState>>,
    headers: HeaderMap,
    Json(req): Json<CreateProfileRequest>,
) -> impl IntoResponse {
    let tenant_id = match authn(&headers, &state.signer) {
        Ok(t) => t,
        Err(resp) => return resp.into_response(),
    };
    let Some(store) = &state.store else {
        return (StatusCode::SERVICE_UNAVAILABLE, "Tenant store unavailable").into_response();
    };
    // Ensure tenant exists + enabled.
    match store.get_tenant(&tenant_id).await {
        Ok(Some(t)) if t.enabled => {}
        Ok(_) => return (StatusCode::UNAUTHORIZED, "invalid tenant").into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }

    let profile_id = Uuid::new_v4().to_string();
    let validated = match validation::validate_create(&req, state.mcp_state.oauth.is_some()) {
        Ok(v) => v,
        Err(error) => {
            return (StatusCode::BAD_REQUEST, error.message().to_string()).into_response();
        }
    };
    let resolved_upstreams = match resolve_upstreams_for_create_profile(
        store.as_ref(),
        &tenant_id,
        &profile_id,
        &req.upstreams,
    )
    .await
    {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    if let Err(resp) = put_profile_handle_name_conflict(
        store.as_ref(),
        PutProfileInput {
            profile_id: &profile_id,
            tenant_id: &tenant_id,
            name: &req.name,
            description: req.description.as_deref(),
            flags: PutProfileFlags {
                enabled: req.enabled,
                allow_partial_upstreams: req.allow_partial_upstreams,
            },
            upstream_ids: &resolved_upstreams,
            source_ids: &req.sources,
            transforms: &req.transforms,
            enabled_tools: &validated.enabled_tools,
            data_plane_auth: PutProfileDataPlaneAuth {
                mode: validated.data_plane_auth.mode(),
                accept_x_api_key: validated.data_plane_auth.accept_x_api_key(),
                oauth_required_scopes: validated.data_plane_auth.required_scopes().to_vec(),
            },
            limits: PutProfileLimits {
                rate_limit_enabled: validated.data_plane_limits.rate_limit_enabled,
                rate_limit_tool_calls_per_minute: validated
                    .data_plane_limits
                    .rate_limit_tool_calls_per_minute,
                quota_enabled: validated.data_plane_limits.quota_enabled,
                quota_tool_calls: validated.data_plane_limits.quota_tool_calls,
            },
            tool_call_timeout_secs: validated.tool_call_timeout_secs,
            tool_policies: &validated.tool_policies,
            mcp: &validated.mcp,
        },
    )
    .await
    {
        return resp;
    }

    (
        StatusCode::CREATED,
        Json(CreateProfileResponse {
            ok: true,
            data_plane_path: format!("/{profile_id}/mcp"),
            id: profile_id,
        }),
    )
        .into_response()
}

async fn put_profile(
    axum::Extension(state): axum::Extension<Arc<TenantState>>,
    headers: HeaderMap,
    Path(profile_id): Path<String>,
    Json(req): Json<PutProfileRequest>,
) -> impl IntoResponse {
    let tenant_id = match authn(&headers, &state.signer) {
        Ok(t) => t,
        Err(resp) => return resp.into_response(),
    };
    let Some(store) = &state.store else {
        return (StatusCode::SERVICE_UNAVAILABLE, "Tenant store unavailable").into_response();
    };
    let started = Instant::now();

    let outcome =
        tenant_put_profile_inner(state.as_ref(), store.as_ref(), &tenant_id, profile_id, req).await;
    state
        .audit
        .record(crate::audit::http_event(HttpAuditEvent {
            tenant_id: tenant_id.clone(),
            actor: AuditActor {
                profile_id: outcome.profile_uuid,
                ..AuditActor::default()
            },
            action: "tenant.profile_put",
            http_method: "PUT",
            http_route: "/tenant/v1/profiles/{profile_id}",
            status_code: i32::from(outcome.status.as_u16()),
            ok: outcome.status.is_success(),
            elapsed: started.elapsed(),
            meta: serde_json::json!({
                "profile_id": outcome.profile_id_for_meta,
                "name": outcome.name_for_meta,
                "enabled": outcome.enabled_for_meta,
            }),
            error: outcome.error,
        }))
        .await;
    outcome.resp
}

struct TenantPutProfileOutcome {
    resp: axum::response::Response,
    status: StatusCode,
    error: Option<AuditError>,
    profile_uuid: Option<Uuid>,
    profile_id_for_meta: String,
    name_for_meta: Option<String>,
    enabled_for_meta: bool,
}

impl TenantPutProfileOutcome {
    fn fail(
        profile_id_for_meta: String,
        enabled_for_meta: bool,
        profile_uuid: Option<Uuid>,
        status: StatusCode,
        message: impl Into<String>,
        error: AuditError,
        name_for_meta: Option<String>,
    ) -> Self {
        let msg = message.into();
        Self {
            resp: (status, msg.clone()).into_response(),
            status,
            error: Some(error),
            profile_uuid,
            profile_id_for_meta,
            name_for_meta,
            enabled_for_meta,
        }
    }

    fn ok(
        profile_id_for_meta: String,
        enabled_for_meta: bool,
        profile_uuid: Uuid,
        name: String,
    ) -> Self {
        Self {
            resp: Json(CreateProfileResponse {
                ok: true,
                data_plane_path: format!("/{profile_id_for_meta}/mcp"),
                id: profile_id_for_meta.clone(),
            })
            .into_response(),
            status: StatusCode::OK,
            error: None,
            profile_uuid: Some(profile_uuid),
            profile_id_for_meta,
            name_for_meta: Some(name),
            enabled_for_meta,
        }
    }
}

async fn tenant_put_profile_inner(
    state: &TenantState,
    store: &dyn crate::store::AdminStore,
    tenant_id: &str,
    profile_id: String,
    req: PutProfileRequest,
) -> TenantPutProfileOutcome {
    match tenant_put_profile_inner_impl(state, store, tenant_id, profile_id, req).await {
        Ok(out) => out,
        Err(out) => *out,
    }
}

type TenantPutProfileStep<T> = Result<T, Box<TenantPutProfileOutcome>>;

async fn tenant_put_profile_inner_impl(
    state: &TenantState,
    store: &dyn crate::store::AdminStore,
    tenant_id: &str,
    profile_id: String,
    req: PutProfileRequest,
) -> TenantPutProfileStep<TenantPutProfileOutcome> {
    let enabled_for_meta = req.enabled;
    let profile_uuid = tenant_put_profile_parse_uuid(&profile_id, enabled_for_meta)?;
    let existing = tenant_put_profile_load_existing(
        store,
        tenant_id,
        &profile_id,
        enabled_for_meta,
        profile_uuid,
    )
    .await?;
    let update = validation::plan_update(&req, &existing, state.mcp_state.oauth.is_some())
        .map_err(|error| {
            let name_for_meta = match error {
                validation::ValidationError::NameRequired => None,
                validation::ValidationError::Settings { .. } => {
                    Some(req.name.clone().unwrap_or_else(|| existing.name.clone()))
                }
            };
            Box::new(TenantPutProfileOutcome::fail(
                profile_id.clone(),
                enabled_for_meta,
                Some(profile_uuid),
                StatusCode::BAD_REQUEST,
                error.message(),
                AuditError::new("bad_request", error.detail()),
                name_for_meta,
            ))
        })?;
    let resolved_upstreams = tenant_put_profile_resolve_upstreams(
        store,
        tenant_id,
        &profile_id,
        enabled_for_meta,
        profile_uuid,
        &update.name,
        &req.upstreams,
    )
    .await?;
    let settings = &update.settings;

    tenant_put_profile_store_put(
        store,
        TenantPutProfileStorePutInput {
            tenant_id,
            profile_id: &profile_id,
            enabled_for_meta,
            profile_uuid,
            name_for_meta: &update.name,
            description: update.description.as_deref(),
            enabled: req.enabled,
            allow_partial_upstreams: req.allow_partial_upstreams,
            resolved_upstreams: &resolved_upstreams,
            sources: &req.sources,
            transforms: &req.transforms,
            enabled_tools: &settings.enabled_tools,
            data_plane_auth: &settings.data_plane_auth,
            data_plane_limits: &settings.data_plane_limits,
            tool_call_timeout_secs: settings.tool_call_timeout_secs,
            tool_policies: &settings.tool_policies,
            mcp: &settings.mcp,
        },
    )
    .await?;

    Ok(TenantPutProfileOutcome::ok(
        profile_id,
        enabled_for_meta,
        profile_uuid,
        update.name,
    ))
}

fn tenant_put_profile_parse_uuid(
    profile_id: &str,
    enabled_for_meta: bool,
) -> TenantPutProfileStep<Uuid> {
    let Some(profile_uuid) = Uuid::parse_str(profile_id)
        .ok()
        .and_then(|u| (u.get_version() == Some(Version::Random)).then_some(u))
    else {
        return Err(Box::new(TenantPutProfileOutcome::fail(
            profile_id.to_string(),
            enabled_for_meta,
            None,
            StatusCode::NOT_FOUND,
            "profile not found",
            AuditError::new("not_found", "profile not found"),
            None,
        )));
    };
    Ok(profile_uuid)
}

async fn tenant_put_profile_load_existing(
    store: &dyn crate::store::AdminStore,
    tenant_id: &str,
    profile_id: &str,
    enabled_for_meta: bool,
    profile_uuid: Uuid,
) -> TenantPutProfileStep<crate::store::AdminProfile> {
    match store.get_profile(profile_id).await {
        Ok(Some(p)) if p.tenant_id == tenant_id => Ok(p),
        Ok(_) => Err(Box::new(TenantPutProfileOutcome::fail(
            profile_id.to_string(),
            enabled_for_meta,
            Some(profile_uuid),
            StatusCode::NOT_FOUND,
            "profile not found",
            AuditError::new("not_found", "profile not found"),
            None,
        ))),
        Err(e) => {
            let msg = e.to_string();
            Err(Box::new(TenantPutProfileOutcome::fail(
                profile_id.to_string(),
                enabled_for_meta,
                Some(profile_uuid),
                StatusCode::INTERNAL_SERVER_ERROR,
                msg.clone(),
                AuditError::new("internal_error", msg),
                None,
            )))
        }
    }
}

async fn tenant_put_profile_resolve_upstreams(
    store: &dyn crate::store::AdminStore,
    tenant_id: &str,
    profile_id: &str,
    enabled_for_meta: bool,
    profile_uuid: Uuid,
    name_for_meta: &str,
    upstreams: &[String],
) -> TenantPutProfileStep<Vec<String>> {
    let resolved = match resolve_upstream_ids_for_tenant(store, tenant_id, upstreams).await {
        Ok(v) => v,
        Err(resp) => {
            let status = resp.status();
            return Err(Box::new(TenantPutProfileOutcome {
                resp,
                status,
                error: Some(AuditError::new("request_failed", status.to_string())),
                profile_uuid: Some(profile_uuid),
                profile_id_for_meta: profile_id.to_string(),
                name_for_meta: Some(name_for_meta.to_string()),
                enabled_for_meta,
            }));
        }
    };
    if let Err(resp) = validate_no_self_upstream_loop(store, profile_id, &resolved).await {
        let status = resp.status();
        return Err(Box::new(TenantPutProfileOutcome {
            resp,
            status,
            error: Some(AuditError::new("bad_request", status.to_string())),
            profile_uuid: Some(profile_uuid),
            profile_id_for_meta: profile_id.to_string(),
            name_for_meta: Some(name_for_meta.to_string()),
            enabled_for_meta,
        }));
    }
    Ok(resolved)
}

struct TenantPutProfileStorePutInput<'a> {
    tenant_id: &'a str,
    profile_id: &'a str,
    enabled_for_meta: bool,
    profile_uuid: Uuid,
    name_for_meta: &'a str,
    description: Option<&'a str>,
    enabled: bool,
    allow_partial_upstreams: bool,
    resolved_upstreams: &'a [String],
    sources: &'a [String],
    transforms: &'a TransformPipeline,
    enabled_tools: &'a [String],
    data_plane_auth: &'a DataPlaneAuthSettings,
    data_plane_limits: &'a DataPlaneLimitsSettings,
    tool_call_timeout_secs: Option<u64>,
    tool_policies: &'a [ToolPolicy],
    mcp: &'a McpProfileSettings,
}

async fn tenant_put_profile_store_put(
    store: &dyn crate::store::AdminStore,
    input: TenantPutProfileStorePutInput<'_>,
) -> TenantPutProfileStep<()> {
    if let Err(e) = store
        .put_profile(PutProfileInput {
            profile_id: input.profile_id,
            tenant_id: input.tenant_id,
            name: input.name_for_meta,
            description: input.description,
            flags: PutProfileFlags {
                enabled: input.enabled,
                allow_partial_upstreams: input.allow_partial_upstreams,
            },
            upstream_ids: input.resolved_upstreams,
            source_ids: input.sources,
            transforms: input.transforms,
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
    {
        if e.to_string().contains("profiles_tenant_name_ci_uq") {
            return Err(Box::new(TenantPutProfileOutcome::fail(
                input.profile_id.to_string(),
                input.enabled_for_meta,
                Some(input.profile_uuid),
                StatusCode::CONFLICT,
                "profile name already exists for this tenant (case-insensitive)",
                AuditError::new(
                    "conflict",
                    "profile name already exists for this tenant (case-insensitive)",
                ),
                Some(input.name_for_meta.to_string()),
            )));
        }
        let msg = e.to_string();
        return Err(Box::new(TenantPutProfileOutcome::fail(
            input.profile_id.to_string(),
            input.enabled_for_meta,
            Some(input.profile_uuid),
            StatusCode::INTERNAL_SERVER_ERROR,
            msg.clone(),
            AuditError::new("internal_error", msg),
            Some(input.name_for_meta.to_string()),
        )));
    }
    Ok(())
}

async fn delete_profile(
    axum::Extension(state): axum::Extension<Arc<TenantState>>,
    headers: HeaderMap,
    Path(profile_id): Path<String>,
) -> impl IntoResponse {
    let tenant_id = match authn(&headers, &state.signer) {
        Ok(t) => t,
        Err(resp) => return resp.into_response(),
    };
    let Some(store) = &state.store else {
        return (StatusCode::SERVICE_UNAVAILABLE, "Tenant store unavailable").into_response();
    };
    let started = Instant::now();
    let http_action = "tenant.profile_delete";
    let http_method = "DELETE";
    let http_route = "/tenant/v1/profiles/{profile_id}";

    let tenant_id_for_audit = tenant_id.clone();
    let profile_id_for_meta = profile_id.clone();

    let mut status = StatusCode::OK;
    let mut ok = false;
    let mut error: Option<AuditError> = None;
    let mut profile_uuid: Option<Uuid> = None;

    let resp = 'resp: {
        // UUIDv4 only, otherwise 404 (avoid enumeration patterns).
        let pu = match Uuid::parse_str(&profile_id) {
            Ok(u) if u.get_version() == Some(Version::Random) => u,
            _ => {
                status = StatusCode::NOT_FOUND;
                error = Some(AuditError::new("not_found", "profile not found"));
                break 'resp (status, "profile not found").into_response();
            }
        };
        profile_uuid = Some(pu);

        // Cross-tenant guard (404 on mismatch).
        match store.get_profile(&profile_id).await {
            Ok(Some(p)) if p.tenant_id == tenant_id => {}
            Ok(_) => {
                status = StatusCode::NOT_FOUND;
                error = Some(AuditError::new("not_found", "profile not found"));
                break 'resp (status, "profile not found").into_response();
            }
            Err(e) => {
                status = StatusCode::INTERNAL_SERVER_ERROR;
                let msg = e.to_string();
                error = Some(AuditError::new("internal_error", msg.clone()));
                break 'resp (status, msg).into_response();
            }
        }

        match store.delete_profile(&profile_id).await {
            Ok(true) => {
                ok = true;
                break 'resp Json(OkResponse { ok: true }).into_response();
            }
            Ok(false) => {
                status = StatusCode::NOT_FOUND;
                error = Some(AuditError::new("not_found", "profile not found"));
                break 'resp (status, "profile not found").into_response();
            }
            Err(e) => {
                status = StatusCode::INTERNAL_SERVER_ERROR;
                let msg = e.to_string();
                error = Some(AuditError::new("internal_error", msg.clone()));
                break 'resp (status, msg).into_response();
            }
        }
    };

    state
        .audit
        .record(crate::audit::http_event(HttpAuditEvent {
            tenant_id: tenant_id_for_audit,
            actor: AuditActor {
                profile_id: profile_uuid,
                ..AuditActor::default()
            },
            action: http_action,
            http_method,
            http_route,
            status_code: i32::from(status.as_u16()),
            ok,
            elapsed: started.elapsed(),
            meta: serde_json::json!({
                "profile_id": profile_id_for_meta,
            }),
            error,
        }))
        .await;

    resp
}
