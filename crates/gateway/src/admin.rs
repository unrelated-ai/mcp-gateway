use crate::audit::{AuditActor, AuditError, HttpAuditEvent};
use crate::profile_http::{
    DataPlaneAuthSettings, DataPlaneLimitsSettings, NullableString, NullableU64,
    default_data_plane_auth_mode, resolve_nullable_u64, validate_tool_allowlist,
    validate_tool_timeout_and_policies,
};
use crate::serde_helpers::default_true;
use crate::store::{
    AdminProfile, AdminStore, AdminTenant, AdminUpstream, DataPlaneAuthMode, McpProfileSettings,
    OidcPrincipalBinding, PutProfileDataPlaneAuth, PutProfileFlags, PutProfileInput,
    PutProfileLimits, TenantSecretMetadata, ToolSourceKind, UpstreamEndpoint,
};
use crate::tenant::{IssueTenantTokenRequest, IssueTenantTokenResponse, now_unix_secs};
use crate::tenant_token::{TenantSigner, TenantTokenPayloadV1};
use crate::tool_policy::ToolPolicy;
use axum::{
    Extension, Json, Router,
    extract::{Path, Query},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Instant;
use unrelated_http_tools::config::AuthConfig;
use unrelated_http_tools::config::HttpServerConfig;
use unrelated_openapi_tools::config::ApiServerConfig;
use unrelated_tool_transforms::TransformPipeline;
use uuid::{Uuid, Version};

const OIDC_NOT_CONFIGURED_MSG: &str = "JWT/OIDC is unavailable because OIDC is not configured on the Gateway (missing UNRELATED_GATEWAY_OIDC_ISSUER). Configure OIDC or choose a different mode.";
type BoxResponse = Box<axum::response::Response>;

#[derive(Clone)]
pub struct AdminState {
    pub store: Option<Arc<dyn AdminStore>>,
    pub admin_token: Option<String>,
    /// Enable the fresh-install bootstrap endpoint.
    ///
    /// When false, `/bootstrap/v1/tenant` is disabled.
    pub bootstrap_enabled: bool,
    pub tenant_signer: TenantSigner,
    pub shared_source_ids: Arc<std::collections::HashSet<String>>,
    pub oidc_issuer: Option<String>,
    pub audit: Arc<dyn crate::audit::AuditSink>,
}

pub fn router() -> Router {
    Router::new()
        // Bootstrap (fresh install)
        .route("/bootstrap/v1/tenant/status", get(bootstrap_tenant_status))
        .route("/bootstrap/v1/tenant", post(bootstrap_tenant))
        .route("/admin/v1/tenants", post(put_tenant).get(list_tenants))
        .route(
            "/admin/v1/tenants/{tenant_id}",
            get(get_tenant).delete(delete_tenant),
        )
        .route(
            "/admin/v1/tenants/{tenant_id}/tool-sources",
            get(list_tool_sources),
        )
        .route(
            "/admin/v1/tenants/{tenant_id}/tool-sources/{source_id}",
            get(get_tool_source)
                .put(put_tool_source)
                .delete(delete_tool_source),
        )
        .route("/admin/v1/tenants/{tenant_id}/secrets", get(list_secrets))
        .route(
            "/admin/v1/tenants/{tenant_id}/secrets/{name}",
            put(put_secret).delete(delete_secret),
        )
        .route(
            "/admin/v1/tenants/{tenant_id}/oidc-principals",
            get(list_oidc_principals).put(put_oidc_principal),
        )
        .route(
            "/admin/v1/tenants/{tenant_id}/oidc-principals/{subject}",
            delete(delete_oidc_principal),
        )
        .route(
            "/admin/v1/tenants/{tenant_id}/audit/settings",
            get(get_tenant_audit_settings).put(put_tenant_audit_settings),
        )
        .route(
            "/admin/v1/tenants/{tenant_id}/audit/events",
            get(list_tenant_audit_events),
        )
        .route(
            "/admin/v1/tenants/{tenant_id}/audit/analytics/tool-calls/by-tool",
            get(tool_call_stats_by_tool),
        )
        .route(
            "/admin/v1/tenants/{tenant_id}/audit/analytics/tool-calls/by-api-key",
            get(tool_call_stats_by_api_key),
        )
        .route(
            "/admin/v1/tenants/{tenant_id}/audit/cleanup",
            post(cleanup_tenant_audit_events),
        )
        .route(
            "/admin/v1/upstreams",
            post(put_upstream).get(list_upstreams),
        )
        .route(
            "/admin/v1/upstreams/{upstream_id}",
            get(get_upstream).delete(delete_upstream),
        )
        .route("/admin/v1/profiles", post(put_profile).get(list_profiles))
        .route(
            "/admin/v1/profiles/{profile_id}",
            get(get_profile).delete(delete_profile),
        )
        .route(
            "/admin/v1/profiles/{profile_id}/audit/settings",
            get(get_profile_audit_settings).put(put_profile_audit_settings),
        )
        .route("/admin/v1/tenant-tokens", post(issue_tenant_token))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BootstrapTenantRequest {
    /// First tenant id to create as the initial tenant.
    tenant_id: String,
    /// Optional tenant token TTL (seconds). Defaults to 365 days.
    #[serde(default)]
    ttl_seconds: Option<u64>,
    /// If true (default), create a starter profile for the new tenant.
    #[serde(default = "default_true")]
    create_profile: bool,
    /// Starter profile name when `createProfile` is true.
    #[serde(default)]
    profile_name: Option<String>,
    /// Starter profile description when `createProfile` is true.
    #[serde(default)]
    profile_description: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct BootstrapTenantResponse {
    ok: bool,
    tenant_id: String,
    token: String,
    exp_unix_secs: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    profile_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    data_plane_path: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct BootstrapTenantStatusResponse {
    bootstrap_enabled: bool,
    can_bootstrap: bool,
    tenant_count: usize,
}

async fn bootstrap_tenant_status(
    Extension(state): Extension<Arc<AdminState>>,
) -> impl IntoResponse {
    // Mirror the bootstrap endpoint behavior: hidden unless explicitly enabled.
    if !state.bootstrap_enabled {
        return (StatusCode::NOT_FOUND, "Not found").into_response();
    }
    let Some(store) = &state.store else {
        return (StatusCode::SERVICE_UNAVAILABLE, "Admin store unavailable").into_response();
    };

    let tenants = match store.list_tenants().await {
        Ok(t) => t,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    Json(BootstrapTenantStatusResponse {
        bootstrap_enabled: true,
        can_bootstrap: tenants.is_empty(),
        tenant_count: tenants.len(),
    })
    .into_response()
}

#[allow(clippy::too_many_lines)] // TODO: refactor this to be more readable.
async fn bootstrap_tenant(
    Extension(state): Extension<Arc<AdminState>>,
    Json(req): Json<BootstrapTenantRequest>,
) -> impl IntoResponse {
    // Safety: only enabled explicitly.
    if !state.bootstrap_enabled {
        return (StatusCode::NOT_FOUND, "Not found").into_response();
    }
    let Some(store) = &state.store else {
        return (StatusCode::SERVICE_UNAVAILABLE, "Admin store unavailable").into_response();
    };

    let tenant_id = req.tenant_id.trim();
    if tenant_id.is_empty() {
        return (StatusCode::BAD_REQUEST, "tenantId is required").into_response();
    }

    // Only allow bootstrapping on an empty DB.
    let existing = match store.list_tenants().await {
        Ok(t) => t,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    if !existing.is_empty() {
        return (StatusCode::CONFLICT, "already bootstrapped").into_response();
    }

    if let Err(e) = store.put_tenant(tenant_id, true).await {
        return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
    }

    let mut profile_id: Option<String> = None;
    let mut data_plane_path: Option<String> = None;
    if req.create_profile {
        let pid = Uuid::new_v4().to_string();
        let name = req
            .profile_name
            .as_deref()
            .unwrap_or("Starter profile")
            .trim();
        if name.is_empty() {
            return (StatusCode::BAD_REQUEST, "profileName must be non-empty").into_response();
        }
        let description = req.profile_description.as_deref();

        // Create an empty (no upstreams/sources) profile; UI can attach sources later.
        let (transforms, mcp) = (TransformPipeline::default(), McpProfileSettings::default());
        if let Err(e) = store
            .put_profile(PutProfileInput {
                profile_id: &pid,
                tenant_id,
                name,
                description,
                flags: PutProfileFlags {
                    enabled: true,
                    allow_partial_upstreams: true,
                },
                upstream_ids: &[],
                source_ids: &[],
                transforms: &transforms,
                enabled_tools: &[],
                data_plane_auth: PutProfileDataPlaneAuth {
                    // Security posture: strict mode by default for newly created starter profiles.
                    mode: DataPlaneAuthMode::ApiKeyEveryRequest,
                    accept_x_api_key: false,
                },
                limits: PutProfileLimits {
                    rate_limit_enabled: false,
                    rate_limit_tool_calls_per_minute: None,
                    quota_enabled: false,
                    quota_tool_calls: None,
                },
                tool_call_timeout_secs: None,
                tool_policies: &[],
                mcp: &mcp,
            })
            .await
        {
            if e.to_string().contains("profiles_tenant_name_ci_uq") {
                return (
                    StatusCode::CONFLICT,
                    "profile name already exists for this tenant (case-insensitive)",
                )
                    .into_response();
            }
            return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
        }

        data_plane_path = Some(format!("/{pid}/mcp"));
        profile_id = Some(pid);
    }

    let ttl = req.ttl_seconds.unwrap_or(31_536_000);
    let now = match now_unix_secs() {
        Ok(n) => n,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let exp = now.saturating_add(ttl).max(now + 1);

    let payload = TenantTokenPayloadV1 {
        tenant_id: tenant_id.to_string(),
        exp_unix_secs: exp,
    };
    let token = match state.tenant_signer.sign_v1(&payload) {
        Ok(t) => t,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    Json(BootstrapTenantResponse {
        ok: true,
        tenant_id: tenant_id.to_string(),
        token,
        exp_unix_secs: exp,
        profile_id,
        data_plane_path,
    })
    .into_response()
}

fn authz(headers: &HeaderMap, expected: Option<&str>) -> Result<(), impl IntoResponse> {
    let Some(expected) = expected else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "Admin API disabled (UNRELATED_GATEWAY_ADMIN_TOKEN not set)",
        ));
    };
    let got = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default();
    let want = format!("Bearer {expected}");
    if got == want {
        Ok(())
    } else {
        Err((StatusCode::UNAUTHORIZED, "Unauthorized"))
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PutTenantRequest {
    id: String,
    #[serde(default = "default_true")]
    enabled: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PutUpstreamRequest {
    id: String,
    #[serde(default = "default_true")]
    enabled: bool,
    endpoints: Vec<PutEndpoint>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PutEndpoint {
    id: String,
    url: String,
    #[serde(default)]
    auth: Option<AuthConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PutProfileRequest {
    #[serde(default)]
    id: Option<String>,
    tenant_id: String,
    /// Human-friendly profile name (unique per tenant, case-insensitive).
    ///
    /// If omitted, defaults to the existing profile name when updating.
    #[serde(default)]
    name: Option<String>,
    /// Optional human-friendly description (PUT semantics).
    ///
    /// - omitted => keep existing description
    /// - null => clear description
    /// - string => set description
    #[serde(default)]
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
    /// Per-profile tool allowlist.
    ///
    /// Semantics:
    /// - omitted / `null` / `[]` => no allowlist configured (allow all tools)
    /// - otherwise entries should be `"<source_id>:<original_tool_name>"`.
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
struct OkResponse {
    ok: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct TenantAuditSettingsResponse {
    enabled: bool,
    retention_days: i32,
    default_level: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PutTenantAuditSettingsRequest {
    enabled: bool,
    retention_days: i32,
    default_level: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuditEventsQuery {
    #[serde(default)]
    from_unix_secs: Option<i64>,
    #[serde(default)]
    to_unix_secs: Option<i64>,
    #[serde(default)]
    before_id: Option<i64>,
    #[serde(default)]
    profile_id: Option<String>,
    #[serde(default)]
    api_key_id: Option<String>,
    #[serde(default)]
    tool_ref: Option<String>,
    #[serde(default)]
    action: Option<String>,
    #[serde(default)]
    ok: Option<bool>,
    #[serde(default)]
    limit: Option<i64>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AuditEventsResponse {
    events: Vec<crate::store::AuditEventRow>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuditStatsQuery {
    #[serde(default)]
    from_unix_secs: Option<i64>,
    #[serde(default)]
    to_unix_secs: Option<i64>,
    #[serde(default)]
    profile_id: Option<String>,
    #[serde(default)]
    api_key_id: Option<String>,
    #[serde(default)]
    tool_ref: Option<String>,
    #[serde(default)]
    limit: Option<i64>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ToolCallStatsByToolResponse {
    items: Vec<crate::store::ToolCallStatsByTool>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ToolCallStatsByApiKeyResponse {
    items: Vec<crate::store::ToolCallStatsByApiKey>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AuditCleanupResponse {
    ok: bool,
    deleted: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProfileAuditSettingsResponse {
    audit_settings: serde_json::Value,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PutProfileAuditSettingsRequest {
    audit_settings: serde_json::Value,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateProfileResponse {
    ok: bool,
    id: String,
    data_plane_path: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct TenantsResponse {
    tenants: Vec<TenantResponse>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct TenantResponse {
    id: String,
    enabled: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct UpstreamsResponse {
    upstreams: Vec<UpstreamResponse>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct UpstreamResponse {
    id: String,
    enabled: bool,
    endpoints: Vec<UpstreamEndpointResponse>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct UpstreamEndpointResponse {
    id: String,
    url: String,
    enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    auth: Option<AuthConfig>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProfilesResponse {
    profiles: Vec<ProfileResponse>,
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

async fn put_tenant(
    Extension(state): Extension<Arc<AdminState>>,
    headers: HeaderMap,
    Json(req): Json<PutTenantRequest>,
) -> impl IntoResponse {
    if let Err(resp) = authz(&headers, state.admin_token.as_deref()) {
        return resp.into_response();
    }
    let Some(store) = &state.store else {
        return (StatusCode::SERVICE_UNAVAILABLE, "Admin store unavailable").into_response();
    };
    let started = Instant::now();

    let tenant_id = req.id.clone();
    let enabled = req.enabled;
    let (status, ok, error, resp) = match store.put_tenant(&tenant_id, enabled).await {
        Ok(()) => (
            StatusCode::CREATED,
            true,
            None,
            (StatusCode::CREATED, Json(OkResponse { ok: true })).into_response(),
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

    let tenant_id_for_meta = tenant_id.clone();
    state
        .audit
        .record(crate::audit::http_event(HttpAuditEvent {
            tenant_id,
            actor: AuditActor::default(),
            action: "admin.tenant_put",
            http_method: "POST",
            http_route: "/admin/v1/tenants",
            status_code: i32::from(status.as_u16()),
            ok,
            elapsed: started.elapsed(),
            meta: serde_json::json!({
                "tenant_id": tenant_id_for_meta,
                "enabled": enabled,
            }),
            error,
        }))
        .await;

    resp
}

async fn list_tenants(
    Extension(state): Extension<Arc<AdminState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(resp) = authz(&headers, state.admin_token.as_deref()) {
        return resp.into_response();
    }
    let Some(store) = &state.store else {
        return (StatusCode::SERVICE_UNAVAILABLE, "Admin store unavailable").into_response();
    };

    match store.list_tenants().await {
        Ok(tenants) => Json(TenantsResponse {
            tenants: tenants.into_iter().map(tenant_to_response).collect(),
        })
        .into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn get_tenant(
    Extension(state): Extension<Arc<AdminState>>,
    headers: HeaderMap,
    Path(tenant_id): Path<String>,
) -> impl IntoResponse {
    if let Err(resp) = authz(&headers, state.admin_token.as_deref()) {
        return resp.into_response();
    }
    let Some(store) = &state.store else {
        return (StatusCode::SERVICE_UNAVAILABLE, "Admin store unavailable").into_response();
    };

    match store.get_tenant(&tenant_id).await {
        Ok(Some(t)) => Json(tenant_to_response(t)).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "tenant not found").into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn delete_tenant(
    Extension(state): Extension<Arc<AdminState>>,
    headers: HeaderMap,
    Path(tenant_id): Path<String>,
) -> impl IntoResponse {
    if let Err(resp) = authz(&headers, state.admin_token.as_deref()) {
        return resp.into_response();
    }
    let Some(store) = &state.store else {
        return (StatusCode::SERVICE_UNAVAILABLE, "Admin store unavailable").into_response();
    };
    let started = Instant::now();

    let tenant_id_for_audit = tenant_id.clone();
    let (status, ok, error, resp) = match store.delete_tenant(&tenant_id).await {
        Ok(true) => (
            StatusCode::OK,
            true,
            None,
            Json(OkResponse { ok: true }).into_response(),
        ),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            false,
            Some(AuditError::new("not_found", "tenant not found")),
            (StatusCode::NOT_FOUND, "tenant not found").into_response(),
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

    state
        .audit
        .record(crate::audit::http_event(HttpAuditEvent {
            tenant_id: tenant_id_for_audit.clone(),
            actor: AuditActor::default(),
            action: "admin.tenant_delete",
            http_method: "DELETE",
            http_route: "/admin/v1/tenants/{tenant_id}",
            status_code: i32::from(status.as_u16()),
            ok,
            elapsed: started.elapsed(),
            meta: serde_json::json!({
                "tenant_id": tenant_id_for_audit,
            }),
            error,
        }))
        .await;

    resp
}

async fn put_upstream(
    Extension(state): Extension<Arc<AdminState>>,
    headers: HeaderMap,
    Json(req): Json<PutUpstreamRequest>,
) -> impl IntoResponse {
    if let Err(resp) = authz(&headers, state.admin_token.as_deref()) {
        return resp.into_response();
    }
    let Some(store) = &state.store else {
        return (StatusCode::SERVICE_UNAVAILABLE, "Admin store unavailable").into_response();
    };

    let endpoints: Vec<UpstreamEndpoint> = req
        .endpoints
        .into_iter()
        .map(|e| UpstreamEndpoint {
            id: e.id,
            url: e.url,
            auth: e.auth,
        })
        .collect();

    // Outbound safety (SSRF hardening): validate upstream endpoints before storing them.
    let safety = crate::outbound_safety::gateway_outbound_http_safety();
    for ep in &endpoints {
        // Upstream endpoint scheme policy: prefer HTTPS by default (dev override supported).
        if let Err(e) = crate::outbound_safety::check_upstream_https_policy(&ep.url) {
            return (
                StatusCode::BAD_REQUEST,
                format!(
                    "upstream endpoint '{}' rejected by HTTPS policy: {e}",
                    ep.id
                ),
            )
                .into_response();
        }
        if let Err(e) = crate::outbound_safety::check_url_allowed(&safety, &ep.url).await {
            return (
                StatusCode::BAD_REQUEST,
                format!(
                    "upstream endpoint '{}' blocked by outbound safety: {e}",
                    ep.id
                ),
            )
                .into_response();
        }
    }

    if let Err(e) = store.put_upstream(&req.id, req.enabled, &endpoints).await {
        return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
    }
    (StatusCode::CREATED, Json(OkResponse { ok: true })).into_response()
}

async fn list_upstreams(
    Extension(state): Extension<Arc<AdminState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(resp) = authz(&headers, state.admin_token.as_deref()) {
        return resp.into_response();
    }
    let Some(store) = &state.store else {
        return (StatusCode::SERVICE_UNAVAILABLE, "Admin store unavailable").into_response();
    };

    match store.list_upstreams().await {
        Ok(upstreams) => Json(UpstreamsResponse {
            upstreams: upstreams.into_iter().map(upstream_to_response).collect(),
        })
        .into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn get_upstream(
    Extension(state): Extension<Arc<AdminState>>,
    headers: HeaderMap,
    Path(upstream_id): Path<String>,
) -> impl IntoResponse {
    if let Err(resp) = authz(&headers, state.admin_token.as_deref()) {
        return resp.into_response();
    }
    let Some(store) = &state.store else {
        return (StatusCode::SERVICE_UNAVAILABLE, "Admin store unavailable").into_response();
    };

    match store.get_upstream(&upstream_id).await {
        Ok(Some(u)) => Json(upstream_to_response(u)).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "upstream not found").into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn delete_upstream(
    Extension(state): Extension<Arc<AdminState>>,
    headers: HeaderMap,
    Path(upstream_id): Path<String>,
) -> impl IntoResponse {
    if let Err(resp) = authz(&headers, state.admin_token.as_deref()) {
        return resp.into_response();
    }
    let Some(store) = &state.store else {
        return (StatusCode::SERVICE_UNAVAILABLE, "Admin store unavailable").into_response();
    };

    match store.delete_upstream(&upstream_id).await {
        Ok(true) => Json(OkResponse { ok: true }).into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, "upstream not found").into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

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
                existing.map_or(
                    DataPlaneAuthSettings {
                        mode: default_data_plane_auth_mode(),
                        accept_x_api_key: false,
                    },
                    |p| DataPlaneAuthSettings {
                        mode: p.data_plane_auth_mode,
                        accept_x_api_key: p.accept_x_api_key,
                    },
                )
            } else {
                DataPlaneAuthSettings {
                    mode: default_data_plane_auth_mode(),
                    accept_x_api_key: false,
                }
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

fn validate_oidc_configured_if_needed(
    oidc_issuer: Option<&str>,
    mode: DataPlaneAuthMode,
) -> Result<(), BoxResponse> {
    if mode == DataPlaneAuthMode::JwtEveryRequest && oidc_issuer.is_none() {
        return Err(Box::new(
            (StatusCode::BAD_REQUEST, OIDC_NOT_CONFIGURED_MSG).into_response(),
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
            upstream_ids: &req.upstreams,
            source_ids: &req.sources,
            transforms: &req.transforms,
            enabled_tools: input.enabled_tools,
            data_plane_auth: PutProfileDataPlaneAuth {
                mode: input.data_plane_auth.mode,
                accept_x_api_key: input.data_plane_auth.accept_x_api_key,
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

async fn put_profile(
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
    let data_plane_auth =
        resolve_data_plane_auth_settings(req.data_plane_auth.clone(), existing.as_ref(), is_update);
    admin_put_profile_validate_oidc(
        profile_uuid,
        profile_id.clone(),
        name.clone(),
        oidc_issuer,
        data_plane_auth.mode,
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

    admin_put_profile_validate_no_self_upstream_loop(
        store,
        profile_uuid,
        profile_id.clone(),
        name.clone(),
        &req.upstreams,
    )
    .await?;

    admin_put_profile_write_store(
        store,
        profile_uuid,
        profile_id.clone(),
        name.clone(),
        &req,
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
    if let Err(resp) = validate_oidc_configured_if_needed(oidc_issuer, mode) {
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
    store_input: PutProfileStoreInputs<'_>,
) -> AdminPutProfileInnerResult<()> {
    if let Err(resp) = put_profile_in_store(store, req, store_input).await {
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

async fn list_profiles(
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

async fn get_profile(
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

async fn delete_profile(
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
    data_plane_auth: DataPlaneAuthSettings,
    data_plane_limits: DataPlaneLimitsSettings,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_call_timeout_secs: Option<u64>,
    tool_policies: Vec<ToolPolicy>,
    mcp: McpProfileSettings,
}

fn tenant_to_response(t: AdminTenant) -> TenantResponse {
    TenantResponse {
        id: t.id,
        enabled: t.enabled,
    }
}

fn upstream_to_response(u: AdminUpstream) -> UpstreamResponse {
    UpstreamResponse {
        id: u.id,
        enabled: u.enabled,
        endpoints: u
            .endpoints
            .into_iter()
            .map(|e| UpstreamEndpointResponse {
                id: e.id,
                url: e.url,
                enabled: e.enabled,
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
        data_plane_auth: DataPlaneAuthSettings {
            mode: profile.data_plane_auth_mode,
            accept_x_api_key: profile.accept_x_api_key,
        },
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

async fn issue_tenant_token(
    Extension(state): Extension<Arc<AdminState>>,
    headers: HeaderMap,
    Json(req): Json<IssueTenantTokenRequest>,
) -> impl IntoResponse {
    if let Err(resp) = authz(&headers, state.admin_token.as_deref()) {
        return resp.into_response();
    }
    let Some(store) = &state.store else {
        return (StatusCode::SERVICE_UNAVAILABLE, "Admin store unavailable").into_response();
    };

    match store.get_tenant(&req.tenant_id).await {
        Ok(Some(t)) if t.enabled => {}
        Ok(Some(_)) => return (StatusCode::BAD_REQUEST, "tenant is disabled").into_response(),
        Ok(None) => return (StatusCode::NOT_FOUND, "tenant not found").into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }

    let ttl = req.ttl_seconds.unwrap_or(31_536_000);
    let now = match now_unix_secs() {
        Ok(n) => n,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let exp = now.saturating_add(ttl).max(now + 1);

    let payload = TenantTokenPayloadV1 {
        tenant_id: req.tenant_id.clone(),
        exp_unix_secs: exp,
    };
    let token = match state.tenant_signer.sign_v1(&payload) {
        Ok(t) => t,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    Json(IssueTenantTokenResponse {
        ok: true,
        tenant_id: req.tenant_id,
        token,
        exp_unix_secs: exp,
    })
    .into_response()
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
enum PutToolSourceBody {
    Http {
        #[serde(default = "default_true")]
        enabled: bool,
        #[serde(flatten)]
        config: HttpServerConfig,
    },
    Openapi {
        #[serde(default = "default_true")]
        enabled: bool,
        #[serde(flatten)]
        config: ApiServerConfig,
    },
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ToolSourceResponse {
    id: String,
    #[serde(rename = "type")]
    tool_type: String,
    enabled: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ToolSourcesResponse {
    sources: Vec<ToolSourceResponse>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PutSecretBody {
    value: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SecretsResponse {
    secrets: Vec<TenantSecretMetadata>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PutOidcPrincipalRequest {
    subject: String,
    /// If set, the principal is scoped to this profile. If omitted, principal is tenant-wide.
    #[serde(default)]
    profile_id: Option<String>,
    #[serde(default = "default_true")]
    enabled: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeleteOidcPrincipalQuery {
    #[serde(default)]
    profile_id: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct OidcPrincipalsResponse {
    principals: Vec<OidcPrincipalBinding>,
}

fn is_valid_source_id(id: &str) -> bool {
    !id.is_empty()
        && !id.contains(':')
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

fn tool_source_kind_str(k: ToolSourceKind) -> &'static str {
    match k {
        ToolSourceKind::Http => "http",
        ToolSourceKind::Openapi => "openapi",
    }
}

async fn list_tool_sources(
    Extension(state): Extension<Arc<AdminState>>,
    headers: HeaderMap,
    Path(tenant_id): Path<String>,
) -> impl IntoResponse {
    if let Err(resp) = authz(&headers, state.admin_token.as_deref()) {
        return resp.into_response();
    }
    let Some(store) = &state.store else {
        return (StatusCode::SERVICE_UNAVAILABLE, "Admin store unavailable").into_response();
    };

    match store.list_tool_sources(&tenant_id).await {
        Ok(list) => {
            let sources = list
                .into_iter()
                .map(|s| ToolSourceResponse {
                    id: s.id,
                    tool_type: tool_source_kind_str(s.kind).to_string(),
                    enabled: s.enabled,
                })
                .collect();
            Json(ToolSourcesResponse { sources }).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn get_tool_source(
    Extension(state): Extension<Arc<AdminState>>,
    headers: HeaderMap,
    Path((tenant_id, source_id)): Path<(String, String)>,
) -> impl IntoResponse {
    if let Err(resp) = authz(&headers, state.admin_token.as_deref()) {
        return resp.into_response();
    }
    let Some(store) = &state.store else {
        return (StatusCode::SERVICE_UNAVAILABLE, "Admin store unavailable").into_response();
    };

    match store.get_tool_source(&tenant_id, &source_id).await {
        Ok(Some(s)) => Json(ToolSourceResponse {
            id: s.id,
            tool_type: tool_source_kind_str(s.kind).to_string(),
            enabled: s.enabled,
        })
        .into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "tool source not found").into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn put_tool_source(
    Extension(state): Extension<Arc<AdminState>>,
    headers: HeaderMap,
    Path((tenant_id, source_id)): Path<(String, String)>,
    Json(body): Json<PutToolSourceBody>,
) -> impl IntoResponse {
    if let Err(resp) = authz(&headers, state.admin_token.as_deref()) {
        return resp.into_response();
    }
    let Some(store) = &state.store else {
        return (StatusCode::SERVICE_UNAVAILABLE, "Admin store unavailable").into_response();
    };
    let started = Instant::now();

    let outcome =
        admin_put_tool_source_inner(state.as_ref(), store.as_ref(), &tenant_id, &source_id, body)
            .await;

    state
        .audit
        .record(crate::audit::http_event(HttpAuditEvent {
            tenant_id: tenant_id.clone(),
            actor: AuditActor::default(),
            action: "admin.tool_source_put",
            http_method: "PUT",
            http_route: "/admin/v1/tenants/{tenant_id}/tool-sources/{source_id}",
            status_code: i32::from(outcome.status.as_u16()),
            ok: outcome.ok,
            elapsed: started.elapsed(),
            meta: serde_json::json!({
                "tenant_id": tenant_id,
                "source_id": source_id,
                "kind": outcome.kind_for_meta,
                "enabled": outcome.enabled_for_meta,
            }),
            error: outcome.error,
        }))
        .await;

    outcome.resp
}

struct AdminPutToolSourceOutcome {
    resp: Response,
    status: StatusCode,
    ok: bool,
    error: Option<AuditError>,
    kind_for_meta: Option<String>,
    enabled_for_meta: Option<bool>,
}

impl AdminPutToolSourceOutcome {
    fn fail(status: StatusCode, message: impl Into<String>, error: AuditError) -> Self {
        let msg = message.into();
        Self {
            resp: (status, msg.clone()).into_response(),
            status,
            ok: false,
            error: Some(error),
            kind_for_meta: None,
            enabled_for_meta: None,
        }
    }

    fn fail_with_meta(
        status: StatusCode,
        message: impl Into<String>,
        error: AuditError,
        kind_for_meta: Option<String>,
        enabled_for_meta: Option<bool>,
    ) -> Self {
        let msg = message.into();
        Self {
            resp: (status, msg.clone()).into_response(),
            status,
            ok: false,
            error: Some(error),
            kind_for_meta,
            enabled_for_meta,
        }
    }

    fn ok(kind_for_meta: Option<String>, enabled_for_meta: Option<bool>) -> Self {
        Self {
            resp: Json(OkResponse { ok: true }).into_response(),
            status: StatusCode::OK,
            ok: true,
            error: None,
            kind_for_meta,
            enabled_for_meta,
        }
    }
}

async fn admin_put_tool_source_inner(
    state: &AdminState,
    store: &dyn AdminStore,
    tenant_id: &str,
    source_id: &str,
    body: PutToolSourceBody,
) -> AdminPutToolSourceOutcome {
    if let Err(outcome) =
        admin_put_tool_source_validate_request(state, store, tenant_id, source_id).await
    {
        return outcome;
    }

    let (enabled, kind, spec_res) = match body {
        PutToolSourceBody::Http { enabled, config } => (
            enabled,
            ToolSourceKind::Http,
            serde_json::to_value(&config).map_err(|e| e.to_string()),
        ),
        PutToolSourceBody::Openapi { enabled, config } => (
            enabled,
            ToolSourceKind::Openapi,
            serde_json::to_value(&config).map_err(|e| e.to_string()),
        ),
    };
    let kind_for_meta = Some(tool_source_kind_str(kind).to_string());
    let enabled_for_meta = Some(enabled);

    let spec = match spec_res {
        Ok(v) => v,
        Err(e) => {
            return AdminPutToolSourceOutcome::fail_with_meta(
                StatusCode::INTERNAL_SERVER_ERROR,
                e.clone(),
                AuditError::new("internal_error", e),
                kind_for_meta,
                enabled_for_meta,
            );
        }
    };

    match store
        .put_tool_source(tenant_id, source_id, enabled, kind, spec)
        .await
    {
        Ok(()) => AdminPutToolSourceOutcome::ok(kind_for_meta, enabled_for_meta),
        Err(e) => {
            let msg = e.to_string();
            AdminPutToolSourceOutcome::fail_with_meta(
                StatusCode::INTERNAL_SERVER_ERROR,
                msg.clone(),
                AuditError::new("internal_error", msg),
                kind_for_meta,
                enabled_for_meta,
            )
        }
    }
}

async fn admin_put_tool_source_validate_request(
    state: &AdminState,
    store: &dyn AdminStore,
    tenant_id: &str,
    source_id: &str,
) -> Result<(), AdminPutToolSourceOutcome> {
    if !is_valid_source_id(source_id) {
        return Err(AdminPutToolSourceOutcome::fail(
            StatusCode::BAD_REQUEST,
            "invalid source id (allowed: [a-zA-Z0-9_-], must not contain ':')",
            AuditError::new("bad_request", "invalid source id"),
        ));
    }
    if state.shared_source_ids.contains(source_id) {
        return Err(AdminPutToolSourceOutcome::fail(
            StatusCode::BAD_REQUEST,
            "source id collides with a shared catalog source id",
            AuditError::new(
                "bad_request",
                "source id collides with a shared catalog source id",
            ),
        ));
    }
    if store.get_upstream(source_id).await.ok().flatten().is_some() {
        return Err(AdminPutToolSourceOutcome::fail(
            StatusCode::BAD_REQUEST,
            "source id collides with an upstream id",
            AuditError::new("bad_request", "source id collides with an upstream id"),
        ));
    }

    match store.get_tenant(tenant_id).await {
        Ok(Some(_)) => Ok(()),
        Ok(None) => Err(AdminPutToolSourceOutcome::fail(
            StatusCode::NOT_FOUND,
            "tenant not found",
            AuditError::new("not_found", "tenant not found"),
        )),
        Err(e) => {
            let msg = e.to_string();
            Err(AdminPutToolSourceOutcome::fail(
                StatusCode::INTERNAL_SERVER_ERROR,
                msg.clone(),
                AuditError::new("internal_error", msg),
            ))
        }
    }
}

async fn delete_tool_source(
    Extension(state): Extension<Arc<AdminState>>,
    headers: HeaderMap,
    Path((tenant_id, source_id)): Path<(String, String)>,
) -> impl IntoResponse {
    if let Err(resp) = authz(&headers, state.admin_token.as_deref()) {
        return resp.into_response();
    }
    let Some(store) = &state.store else {
        return (StatusCode::SERVICE_UNAVAILABLE, "Admin store unavailable").into_response();
    };
    let started = Instant::now();

    let tenant_id_for_audit = tenant_id.clone();
    let source_id_for_meta = source_id.clone();
    let (status, ok, error, resp) = match store.delete_tool_source(&tenant_id, &source_id).await {
        Ok(true) => (
            StatusCode::OK,
            true,
            None,
            Json(OkResponse { ok: true }).into_response(),
        ),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            false,
            Some(AuditError::new("not_found", "tool source not found")),
            (StatusCode::NOT_FOUND, "tool source not found").into_response(),
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

    state
        .audit
        .record(crate::audit::http_event(HttpAuditEvent {
            tenant_id: tenant_id_for_audit,
            actor: AuditActor::default(),
            action: "admin.tool_source_delete",
            http_method: "DELETE",
            http_route: "/admin/v1/tenants/{tenant_id}/tool-sources/{source_id}",
            status_code: i32::from(status.as_u16()),
            ok,
            elapsed: started.elapsed(),
            meta: serde_json::json!({
                "tenant_id": tenant_id,
                "source_id": source_id_for_meta,
            }),
            error,
        }))
        .await;

    resp
}

async fn list_secrets(
    Extension(state): Extension<Arc<AdminState>>,
    headers: HeaderMap,
    Path(tenant_id): Path<String>,
) -> impl IntoResponse {
    if let Err(resp) = authz(&headers, state.admin_token.as_deref()) {
        return resp.into_response();
    }
    let Some(store) = &state.store else {
        return (StatusCode::SERVICE_UNAVAILABLE, "Admin store unavailable").into_response();
    };

    match store.list_secrets(&tenant_id).await {
        Ok(secrets) => Json(SecretsResponse { secrets }).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn put_secret(
    Extension(state): Extension<Arc<AdminState>>,
    headers: HeaderMap,
    Path((tenant_id, name)): Path<(String, String)>,
    Json(req): Json<PutSecretBody>,
) -> impl IntoResponse {
    if let Err(resp) = authz(&headers, state.admin_token.as_deref()) {
        return resp.into_response();
    }
    let Some(store) = &state.store else {
        return (StatusCode::SERVICE_UNAVAILABLE, "Admin store unavailable").into_response();
    };
    let started = Instant::now();
    let tenant_id_for_audit = tenant_id.clone();
    let name_for_meta = name.clone();
    let value_len = req.value.len();

    if name.trim().is_empty() {
        let status = StatusCode::BAD_REQUEST;
        let resp = (status, "secret name is required").into_response();
        state
            .audit
            .record(crate::audit::http_event(HttpAuditEvent {
                tenant_id: tenant_id_for_audit,
                actor: AuditActor::default(),
                action: "admin.secret_put",
                http_method: "PUT",
                http_route: "/admin/v1/tenants/{tenant_id}/secrets/{name}",
                status_code: i32::from(status.as_u16()),
                ok: false,
                elapsed: started.elapsed(),
                meta: serde_json::json!({
                    "tenant_id": tenant_id,
                    "name": name,
                    "value_len": value_len,
                }),
                error: Some(AuditError::new("bad_request", "secret name is required")),
            }))
            .await;
        return resp;
    }
    if req.value.is_empty() {
        let status = StatusCode::BAD_REQUEST;
        let resp = (status, "secret value is required").into_response();
        state
            .audit
            .record(crate::audit::http_event(HttpAuditEvent {
                tenant_id: tenant_id_for_audit,
                actor: AuditActor::default(),
                action: "admin.secret_put",
                http_method: "PUT",
                http_route: "/admin/v1/tenants/{tenant_id}/secrets/{name}",
                status_code: i32::from(status.as_u16()),
                ok: false,
                elapsed: started.elapsed(),
                meta: serde_json::json!({
                    "tenant_id": tenant_id,
                    "name": name,
                    "value_len": value_len,
                }),
                error: Some(AuditError::new("bad_request", "secret value is required")),
            }))
            .await;
        return resp;
    }

    let (status, ok, error, resp) = match store.put_secret(&tenant_id, &name, &req.value).await {
        Ok(()) => (
            StatusCode::OK,
            true,
            None,
            Json(OkResponse { ok: true }).into_response(),
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

    state
        .audit
        .record(crate::audit::http_event(HttpAuditEvent {
            tenant_id: tenant_id_for_audit,
            actor: AuditActor::default(),
            action: "admin.secret_put",
            http_method: "PUT",
            http_route: "/admin/v1/tenants/{tenant_id}/secrets/{name}",
            status_code: i32::from(status.as_u16()),
            ok,
            elapsed: started.elapsed(),
            meta: serde_json::json!({
                "tenant_id": tenant_id,
                "name": name_for_meta,
                "value_len": value_len,
            }),
            error,
        }))
        .await;

    resp
}

async fn delete_secret(
    Extension(state): Extension<Arc<AdminState>>,
    headers: HeaderMap,
    Path((tenant_id, name)): Path<(String, String)>,
) -> impl IntoResponse {
    if let Err(resp) = authz(&headers, state.admin_token.as_deref()) {
        return resp.into_response();
    }
    let Some(store) = &state.store else {
        return (StatusCode::SERVICE_UNAVAILABLE, "Admin store unavailable").into_response();
    };
    let started = Instant::now();

    let tenant_id_for_audit = tenant_id.clone();
    let name_for_meta = name.clone();
    let (status, ok, error, resp) = match store.delete_secret(&tenant_id, &name).await {
        Ok(true) => (
            StatusCode::OK,
            true,
            None,
            Json(OkResponse { ok: true }).into_response(),
        ),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            false,
            Some(AuditError::new("not_found", "secret not found")),
            (StatusCode::NOT_FOUND, "secret not found").into_response(),
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

    state
        .audit
        .record(crate::audit::http_event(HttpAuditEvent {
            tenant_id: tenant_id_for_audit,
            actor: AuditActor::default(),
            action: "admin.secret_delete",
            http_method: "DELETE",
            http_route: "/admin/v1/tenants/{tenant_id}/secrets/{name}",
            status_code: i32::from(status.as_u16()),
            ok,
            elapsed: started.elapsed(),
            meta: serde_json::json!({
                "tenant_id": tenant_id,
                "name": name_for_meta,
            }),
            error,
        }))
        .await;

    resp
}

fn is_valid_oidc_subject(subject: &str) -> bool {
    // For simplicity and to avoid path confusion, disallow '/'.
    // Cognito/Entra commonly use UUID-like subjects, so this is fine for the current scope.
    let s = subject.trim();
    !s.is_empty() && !s.contains('/')
}

async fn list_oidc_principals(
    Extension(state): Extension<Arc<AdminState>>,
    headers: HeaderMap,
    Path(tenant_id): Path<String>,
) -> impl IntoResponse {
    if let Err(resp) = authz(&headers, state.admin_token.as_deref()) {
        return resp.into_response();
    }
    let Some(store) = &state.store else {
        return (StatusCode::SERVICE_UNAVAILABLE, "Admin store unavailable").into_response();
    };
    let Some(issuer) = state.oidc_issuer.as_deref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "OIDC not configured (set UNRELATED_GATEWAY_OIDC_ISSUER)",
        )
            .into_response();
    };

    // Ensure tenant exists.
    match store.get_tenant(&tenant_id).await {
        Ok(Some(_)) => {}
        Ok(None) => return (StatusCode::NOT_FOUND, "tenant not found").into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }

    match store.list_oidc_principals(&tenant_id, issuer).await {
        Ok(principals) => Json(OidcPrincipalsResponse { principals }).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn put_oidc_principal(
    Extension(state): Extension<Arc<AdminState>>,
    headers: HeaderMap,
    Path(tenant_id): Path<String>,
    Json(req): Json<PutOidcPrincipalRequest>,
) -> impl IntoResponse {
    if let Err(resp) = authz(&headers, state.admin_token.as_deref()) {
        return resp.into_response();
    }
    let Some(store) = &state.store else {
        return (StatusCode::SERVICE_UNAVAILABLE, "Admin store unavailable").into_response();
    };
    let Some(issuer) = state.oidc_issuer.as_deref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "OIDC not configured (set UNRELATED_GATEWAY_OIDC_ISSUER)",
        )
            .into_response();
    };

    let subject = req.subject.trim().to_string();
    if !is_valid_oidc_subject(&subject) {
        return (StatusCode::BAD_REQUEST, "invalid OIDC subject").into_response();
    }

    // Ensure tenant exists.
    match store.get_tenant(&tenant_id).await {
        Ok(Some(_)) => {}
        Ok(None) => return (StatusCode::NOT_FOUND, "tenant not found").into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }

    if let Some(profile_id) = req.profile_id.as_deref() {
        // Validate UUID and cross-tenant correctness.
        if Uuid::parse_str(profile_id)
            .ok()
            .and_then(|u| (u.get_version() == Some(Version::Random)).then_some(u))
            .is_none()
        {
            return (StatusCode::NOT_FOUND, "profile not found").into_response();
        }
        match store.get_profile(profile_id).await {
            Ok(Some(p)) if p.tenant_id == tenant_id => {}
            Ok(_) => return (StatusCode::NOT_FOUND, "profile not found").into_response(),
            Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        }
    }

    if let Err(e) = store
        .put_oidc_principal(
            &tenant_id,
            issuer,
            &subject,
            req.profile_id.as_deref(),
            req.enabled,
        )
        .await
    {
        return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
    }

    Json(OkResponse { ok: true }).into_response()
}

async fn delete_oidc_principal(
    Extension(state): Extension<Arc<AdminState>>,
    headers: HeaderMap,
    Path((tenant_id, subject)): Path<(String, String)>,
    Query(q): Query<DeleteOidcPrincipalQuery>,
) -> impl IntoResponse {
    if let Err(resp) = authz(&headers, state.admin_token.as_deref()) {
        return resp.into_response();
    }
    let Some(store) = &state.store else {
        return (StatusCode::SERVICE_UNAVAILABLE, "Admin store unavailable").into_response();
    };
    let Some(issuer) = state.oidc_issuer.as_deref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "OIDC not configured (set UNRELATED_GATEWAY_OIDC_ISSUER)",
        )
            .into_response();
    };

    let subject = subject.trim().to_string();
    if !is_valid_oidc_subject(&subject) {
        return (StatusCode::BAD_REQUEST, "invalid OIDC subject").into_response();
    }

    // Ensure tenant exists.
    match store.get_tenant(&tenant_id).await {
        Ok(Some(_)) => {}
        Ok(None) => return (StatusCode::NOT_FOUND, "tenant not found").into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }

    match store
        .delete_oidc_principal(&tenant_id, issuer, &subject, q.profile_id.as_deref())
        .await
    {
        Ok(0) => (StatusCode::NOT_FOUND, "oidc principal not found").into_response(),
        Ok(_) => Json(OkResponse { ok: true }).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

fn validate_audit_default_level(level: &str) -> Result<(), &'static str> {
    match level {
        "off" | "summary" | "metadata" | "payload" => Ok(()),
        _ => Err("invalid defaultLevel (allowed: off|summary|metadata|payload)"),
    }
}

async fn get_tenant_audit_settings(
    Extension(state): Extension<Arc<AdminState>>,
    headers: HeaderMap,
    Path(tenant_id): Path<String>,
) -> impl IntoResponse {
    if let Err(resp) = authz(&headers, state.admin_token.as_deref()) {
        return resp.into_response();
    }
    let Some(store) = &state.store else {
        return (StatusCode::SERVICE_UNAVAILABLE, "Admin store unavailable").into_response();
    };

    match store.get_tenant_audit_settings(&tenant_id).await {
        Ok(Some(s)) => Json(TenantAuditSettingsResponse {
            enabled: s.enabled,
            retention_days: s.retention_days,
            default_level: s.default_level,
        })
        .into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "tenant not found").into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn put_tenant_audit_settings(
    Extension(state): Extension<Arc<AdminState>>,
    headers: HeaderMap,
    Path(tenant_id): Path<String>,
    Json(req): Json<PutTenantAuditSettingsRequest>,
) -> impl IntoResponse {
    if let Err(resp) = authz(&headers, state.admin_token.as_deref()) {
        return resp.into_response();
    }
    let Some(store) = &state.store else {
        return (StatusCode::SERVICE_UNAVAILABLE, "Admin store unavailable").into_response();
    };
    let started = Instant::now();

    if req.retention_days < 0 {
        return (StatusCode::BAD_REQUEST, "retentionDays must be >= 0").into_response();
    }
    if let Err(msg) = validate_audit_default_level(req.default_level.trim()) {
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
                state.audit.invalidate_tenant_settings_cache(&tenant_id);
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
                    (StatusCode::INTERNAL_SERVER_ERROR, msg).into_response(),
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
            http_route: "/admin/v1/tenants/{tenant_id}/audit/settings",
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

async fn list_tenant_audit_events(
    Extension(state): Extension<Arc<AdminState>>,
    headers: HeaderMap,
    Path(tenant_id): Path<String>,
    Query(q): Query<AuditEventsQuery>,
) -> impl IntoResponse {
    if let Err(resp) = authz(&headers, state.admin_token.as_deref()) {
        return resp.into_response();
    }
    let Some(store) = &state.store else {
        return (StatusCode::SERVICE_UNAVAILABLE, "Admin store unavailable").into_response();
    };

    // Ensure tenant exists.
    match store.get_tenant(&tenant_id).await {
        Ok(Some(_)) => {}
        Ok(None) => return (StatusCode::NOT_FOUND, "tenant not found").into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
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

async fn tool_call_stats_by_tool(
    Extension(state): Extension<Arc<AdminState>>,
    headers: HeaderMap,
    Path(tenant_id): Path<String>,
    Query(q): Query<AuditStatsQuery>,
) -> impl IntoResponse {
    if let Err(resp) = authz(&headers, state.admin_token.as_deref()) {
        return resp.into_response();
    }
    let Some(store) = &state.store else {
        return (StatusCode::SERVICE_UNAVAILABLE, "Admin store unavailable").into_response();
    };

    // Ensure tenant exists.
    match store.get_tenant(&tenant_id).await {
        Ok(Some(_)) => {}
        Ok(None) => return (StatusCode::NOT_FOUND, "tenant not found").into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }

    let filter = crate::store::AuditStatsFilter {
        from_unix_secs: q.from_unix_secs,
        to_unix_secs: q.to_unix_secs,
        profile_id: q.profile_id,
        api_key_id: q.api_key_id,
        tool_ref: q.tool_ref,
        limit: q.limit.unwrap_or(100).clamp(1, 1000),
    };

    match store.tool_call_stats_by_tool(&tenant_id, filter).await {
        Ok(items) => Json(ToolCallStatsByToolResponse { items }).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

async fn tool_call_stats_by_api_key(
    Extension(state): Extension<Arc<AdminState>>,
    headers: HeaderMap,
    Path(tenant_id): Path<String>,
    Query(q): Query<AuditStatsQuery>,
) -> impl IntoResponse {
    if let Err(resp) = authz(&headers, state.admin_token.as_deref()) {
        return resp.into_response();
    }
    let Some(store) = &state.store else {
        return (StatusCode::SERVICE_UNAVAILABLE, "Admin store unavailable").into_response();
    };

    // Ensure tenant exists.
    match store.get_tenant(&tenant_id).await {
        Ok(Some(_)) => {}
        Ok(None) => return (StatusCode::NOT_FOUND, "tenant not found").into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }

    let filter = crate::store::AuditStatsFilter {
        from_unix_secs: q.from_unix_secs,
        to_unix_secs: q.to_unix_secs,
        profile_id: q.profile_id,
        api_key_id: q.api_key_id,
        tool_ref: q.tool_ref,
        limit: q.limit.unwrap_or(100).clamp(1, 1000),
    };

    match store.tool_call_stats_by_api_key(&tenant_id, filter).await {
        Ok(items) => Json(ToolCallStatsByApiKeyResponse { items }).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

async fn cleanup_tenant_audit_events(
    Extension(state): Extension<Arc<AdminState>>,
    headers: HeaderMap,
    Path(tenant_id): Path<String>,
) -> impl IntoResponse {
    if let Err(resp) = authz(&headers, state.admin_token.as_deref()) {
        return resp.into_response();
    }
    let Some(store) = &state.store else {
        return (StatusCode::SERVICE_UNAVAILABLE, "Admin store unavailable").into_response();
    };
    let started = Instant::now();

    // Ensure tenant exists.
    match store.get_tenant(&tenant_id).await {
        Ok(Some(_)) => {}
        Ok(None) => return (StatusCode::NOT_FOUND, "tenant not found").into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
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
                    (StatusCode::INTERNAL_SERVER_ERROR, msg).into_response(),
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
            http_route: "/admin/v1/tenants/{tenant_id}/audit/cleanup",
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

async fn get_profile_audit_settings(
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

    match store.get_profile_audit_settings(&profile_id).await {
        Ok(Some(v)) => Json(ProfileAuditSettingsResponse { audit_settings: v }).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "profile not found").into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn put_profile_audit_settings(
    Extension(state): Extension<Arc<AdminState>>,
    headers: HeaderMap,
    Path(profile_id): Path<String>,
    Json(req): Json<PutProfileAuditSettingsRequest>,
) -> impl IntoResponse {
    if let Err(resp) = authz(&headers, state.admin_token.as_deref()) {
        return resp.into_response();
    }
    let Some(store) = &state.store else {
        return (StatusCode::SERVICE_UNAVAILABLE, "Admin store unavailable").into_response();
    };
    let started = Instant::now();

    // Avoid leaking details / DB errors on obviously-invalid ids.
    let profile_uuid = match Uuid::parse_str(&profile_id) {
        Ok(u) if u.get_version() == Some(Version::Random) => u,
        _ => return (StatusCode::NOT_FOUND, "profile not found").into_response(),
    };

    if !req.audit_settings.is_object() {
        return (
            StatusCode::BAD_REQUEST,
            "auditSettings must be a JSON object",
        )
            .into_response();
    }

    let tenant_id_for_audit = match store.get_profile(&profile_id).await {
        Ok(Some(p)) => p.tenant_id,
        Ok(None) => return (StatusCode::NOT_FOUND, "profile not found").into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    let (status, ok, error, resp) = match store
        .put_profile_audit_settings(&profile_id, req.audit_settings.clone())
        .await
    {
        Ok(()) => (
            StatusCode::OK,
            true,
            None,
            Json(OkResponse { ok: true }).into_response(),
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
            http_route: "/admin/v1/profiles/{profile_id}/audit/settings",
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
