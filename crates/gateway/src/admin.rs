#![allow(
    clippy::wildcard_imports,
    reason = "split admin route modules share the parent module's private HTTP types"
)]

use crate::audit::{AuditActor, AuditError, AuditEvent, HttpAuditEvent, duration_ms};
use crate::profile_http::{
    DataPlaneAuthSettings, DataPlaneLimitsSettings, NullableString, NullableU64,
    resolve_nullable_u64, validate_tool_allowlist, validate_tool_timeout_and_policies,
};
use crate::serde_helpers::default_true;
use crate::store::{
    AdminProfile, AdminStore, AdminTenant, AdminUpstream, DataPlaneAuthMode, ManagedMcpBackendMode,
    ManagedMcpDeployable, ManagedMcpDeploymentRequest, ManagedMcpDeploymentStatus,
    McpProfileSettings, OidcPrincipalBinding, PutProfileDataPlaneAuth, PutProfileFlags,
    PutProfileInput, PutProfileLimits, TenantSecretMetadata, ToolSourceKind, UpstreamEndpoint,
    UpstreamEndpointActivity, UpstreamEndpointLifecycle, UpstreamNetworkClass,
};
use crate::tenant::{
    IssueTenantTokenRequest, IssueTenantTokenResponse, now_unix_secs, tenant_upstream_internal_id,
};
use crate::tenant_token::{TenantSigner, TenantTokenPayloadV1};
use crate::tool_policy::ToolPolicy;
use axum::{
    Extension, Json, Router,
    extract::{Path, Query},
    http::{HeaderMap, Method, StatusCode},
    middleware::{Next, from_fn},
    response::{IntoResponse, Response},
    routing::{delete, get, patch, post, put},
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;
use unrelated_http_tools::config::AuthConfig;
use unrelated_http_tools::config::HttpServerConfig;
use unrelated_openapi_tools::config::ApiServerConfig;
use unrelated_tool_transforms::TransformPipeline;
use uuid::{Uuid, Version};

mod audit_http;
mod auth;
mod bootstrap;
mod profile;
mod tenant_resources;
use audit_http::*;
use auth::{authz, control_plane_auth_middleware};
use bootstrap::{bootstrap_tenant, bootstrap_tenant_status};
use profile::*;
use tenant_resources::*;

const OAUTH_NOT_CONFIGURED_MSG: &str = "OAuth is unavailable because data-plane OAuth is not configured on the Gateway. Configure UNRELATED_GATEWAY_PUBLIC_DATA_BASE_URL and UNRELATED_GATEWAY_OAUTH_ISSUER, or choose a different mode.";
type BoxResponse = Box<axum::response::Response>;

#[derive(Debug, Clone, Default)]
struct ControlPlanePrincipal {
    auth_kind: &'static str,
    issuer: Option<String>,
    subject: Option<String>,
    scopes: Vec<String>,
}

#[derive(Clone)]
pub struct AdminState {
    pub store: Option<Arc<dyn AdminStore>>,
    pub admin_token: Option<String>,
    pub control_plane_oidc: Option<crate::oidc::OidcValidator>,
    pub control_plane_scope_read: String,
    pub control_plane_scope_write: String,
    /// Enable the fresh-install bootstrap endpoint.
    ///
    /// When false, `/bootstrap/v1/tenant` is disabled.
    pub bootstrap_enabled: bool,
    pub tenant_signer: TenantSigner,
    pub shared_source_ids: Arc<std::collections::HashSet<String>>,
    pub oidc_issuer: Option<String>,
    pub audit: Arc<dyn crate::audit::AuditSink>,
    pub invalidation: Arc<crate::pg_invalidation::InvalidationDispatcher>,
}

pub fn router() -> Router {
    let admin_v1 = Router::new()
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
        .route(
            "/admin/v1/upstreams/{upstream_id}/session-activity",
            get(get_upstream_session_activity),
        )
        .route(
            "/admin/v1/upstreams/{upstream_id}/endpoints/{endpoint_id}",
            patch(patch_upstream_endpoint).delete(delete_upstream_endpoint),
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
        .route(
            "/admin/v1/managed-mcp/deployables",
            get(list_managed_mcp_deployables).put(put_managed_mcp_deployable),
        )
        .route(
            "/admin/v1/managed-mcp/reconciler-heartbeat",
            post(put_managed_mcp_reconciler_heartbeat),
        )
        .route(
            "/admin/v1/managed-mcp/deployments",
            get(list_managed_mcp_deployment_requests),
        )
        .route(
            "/admin/v1/managed-mcp/deployments/{request_id}",
            get(get_managed_mcp_deployment_request).patch(patch_managed_mcp_deployment_request),
        )
        .route_layer(from_fn(control_plane_auth_middleware));

    Router::new()
        .route("/bootstrap/v1/tenant/status", get(bootstrap_tenant_status))
        .route("/bootstrap/v1/tenant", post(bootstrap_tenant))
        .merge(admin_v1)
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
    #[serde(default)]
    tenant_id: Option<String>,
    #[serde(default = "default_true")]
    enabled: bool,
    #[serde(default = "default_upstream_network_class")]
    network_class: UpstreamNetworkClass,
    endpoints: Vec<PutEndpoint>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PutEndpoint {
    id: String,
    url: String,
    #[serde(default = "default_true")]
    enabled: bool,
    #[serde(default = "default_upstream_endpoint_lifecycle")]
    lifecycle: UpstreamEndpointLifecycle,
    #[serde(default)]
    auth: Option<AuthConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PatchUpstreamEndpointRequest {
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    lifecycle: Option<UpstreamEndpointLifecycle>,
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

const fn default_upstream_network_class() -> UpstreamNetworkClass {
    UpstreamNetworkClass::External
}

const fn default_upstream_endpoint_lifecycle() -> UpstreamEndpointLifecycle {
    UpstreamEndpointLifecycle::Active
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

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpstreamSessionActivityQuery {
    #[serde(default)]
    ttl_secs: Option<u64>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct UpstreamSessionActivityResponse {
    upstream_id: String,
    ttl_secs: u64,
    generated_at_unix: i64,
    endpoints: Vec<UpstreamEndpointActivity>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ManagedMcpDeployablesResponse {
    deployables: Vec<ManagedMcpDeployable>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PutManagedMcpDeployableRequest {
    id: String,
    display_name: String,
    #[serde(default)]
    description: Option<String>,
    image: String,
    default_upstream_url: String,
    #[serde(default = "default_true")]
    enabled: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ManagedMcpDeploymentResponse {
    request: ManagedMcpDeploymentRequest,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ManagedMcpDeploymentsResponse {
    requests: Vec<ManagedMcpDeploymentRequest>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PatchManagedMcpDeploymentRequest {
    status: ManagedMcpDeploymentStatus,
    #[serde(default)]
    upstream_id: Option<String>,
    #[serde(default)]
    message: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PutManagedMcpReconcilerHeartbeatRequest {
    mode: ManagedMcpBackendMode,
    reconciler_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListManagedMcpDeploymentsQuery {
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    limit: Option<u32>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct UpstreamResponse {
    id: String,
    enabled: bool,
    network_class: UpstreamNetworkClass,
    endpoints: Vec<UpstreamEndpointResponse>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct UpstreamEndpointResponse {
    id: String,
    url: String,
    enabled: bool,
    lifecycle: UpstreamEndpointLifecycle,
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
    principal: Option<Extension<ControlPlanePrincipal>>,
    Json(req): Json<PutUpstreamRequest>,
) -> impl IntoResponse {
    if let Err(resp) = authz(&headers, state.admin_token.as_deref()) {
        return resp.into_response();
    }
    let Some(store) = &state.store else {
        return (StatusCode::SERVICE_UNAVAILABLE, "Admin store unavailable").into_response();
    };
    if matches!(
        req.network_class,
        UpstreamNetworkClass::ClusterInternalManaged
    ) && !matches!(
        principal.as_ref().map(|p| p.0.auth_kind),
        Some("oidc" | "static-token")
    ) {
        return (
            StatusCode::FORBIDDEN,
            "cluster-internal-managed classification requires control-plane authentication",
        )
            .into_response();
    }
    let upstream_id = if let Some(tenant_id_raw) = req.tenant_id.as_deref() {
        let tenant_id = tenant_id_raw.trim();
        if tenant_id.is_empty() {
            return (StatusCode::BAD_REQUEST, "tenantId must be non-empty").into_response();
        }
        match store.get_tenant(tenant_id).await {
            Ok(Some(_)) => {}
            Ok(None) => {
                return (StatusCode::BAD_REQUEST, "tenantId does not exist").into_response();
            }
            Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        }
        tenant_upstream_internal_id(tenant_id, &req.id)
    } else {
        req.id.clone()
    };

    let endpoints: Vec<UpstreamEndpoint> = req
        .endpoints
        .into_iter()
        .map(|e| UpstreamEndpoint {
            id: e.id,
            url: e.url,
            enabled: e.enabled,
            lifecycle: e.lifecycle,
            auth: e.auth,
        })
        .collect();

    if let Err(e) =
        crate::upstream_validation::validate_upstream_endpoints(req.network_class, &endpoints).await
    {
        return (StatusCode::BAD_REQUEST, e).into_response();
    }

    if let Err(e) = store
        .put_upstream(&upstream_id, req.enabled, req.network_class, &endpoints)
        .await
    {
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

async fn get_upstream_session_activity(
    Extension(state): Extension<Arc<AdminState>>,
    headers: HeaderMap,
    Path(upstream_id): Path<String>,
    Query(q): Query<UpstreamSessionActivityQuery>,
) -> impl IntoResponse {
    if let Err(resp) = authz(&headers, state.admin_token.as_deref()) {
        return resp.into_response();
    }
    let Some(store) = &state.store else {
        return (StatusCode::SERVICE_UNAVAILABLE, "Admin store unavailable").into_response();
    };
    let ttl_secs = crate::pg_store::resolve_upstream_session_activity_ttl_secs(q.ttl_secs);
    match store
        .list_upstream_endpoint_activity(&upstream_id, ttl_secs)
        .await
    {
        Ok(endpoints) => {
            let generated_at_unix = now_unix_secs().map_or(0, |v| i64::try_from(v).unwrap_or(0));
            Json(UpstreamSessionActivityResponse {
                upstream_id,
                ttl_secs,
                generated_at_unix,
                endpoints,
            })
            .into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn list_managed_mcp_deployables(
    Extension(state): Extension<Arc<AdminState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(resp) = authz(&headers, state.admin_token.as_deref()) {
        return resp.into_response();
    }
    let Some(store) = &state.store else {
        return (StatusCode::SERVICE_UNAVAILABLE, "Admin store unavailable").into_response();
    };
    match store.list_managed_mcp_deployables().await {
        Ok(deployables) => Json(ManagedMcpDeployablesResponse { deployables }).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn put_managed_mcp_reconciler_heartbeat(
    Extension(state): Extension<Arc<AdminState>>,
    headers: HeaderMap,
    Json(req): Json<PutManagedMcpReconcilerHeartbeatRequest>,
) -> impl IntoResponse {
    if let Err(resp) = authz(&headers, state.admin_token.as_deref()) {
        return resp.into_response();
    }
    let Some(store) = &state.store else {
        return (StatusCode::SERVICE_UNAVAILABLE, "Admin store unavailable").into_response();
    };
    if let Err(message) = validate_managed_mcp_reconciler_heartbeat_request(&req) {
        return (StatusCode::BAD_REQUEST, message).into_response();
    }
    match store
        .upsert_managed_mcp_reconciler_heartbeat(req.mode, &req.reconciler_id)
        .await
    {
        Ok(()) => (StatusCode::CREATED, Json(OkResponse { ok: true })).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

fn validate_managed_mcp_reconciler_heartbeat_request(
    req: &PutManagedMcpReconcilerHeartbeatRequest,
) -> Result<(), &'static str> {
    if matches!(req.mode, ManagedMcpBackendMode::None) {
        return Err("mode must be k8s or docker");
    }
    if req.reconciler_id.trim().is_empty() {
        return Err("reconcilerId is required");
    }
    Ok(())
}

fn parse_managed_mcp_deployment_status_filter(
    raw: Option<&str>,
) -> Result<Vec<ManagedMcpDeploymentStatus>, String> {
    let Some(raw) = raw.map(str::trim).filter(|v| !v.is_empty()) else {
        return Ok(vec![
            ManagedMcpDeploymentStatus::Pending,
            ManagedMcpDeploymentStatus::Reconciling,
        ]);
    };
    let mut out = Vec::new();
    for part in raw.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        let status = ManagedMcpDeploymentStatus::parse(part)
            .ok_or_else(|| format!("unsupported status '{part}'"))?;
        if !out.contains(&status) {
            out.push(status);
        }
    }
    Ok(out)
}

async fn list_managed_mcp_deployment_requests(
    Extension(state): Extension<Arc<AdminState>>,
    headers: HeaderMap,
    Query(query): Query<ListManagedMcpDeploymentsQuery>,
) -> impl IntoResponse {
    if let Err(resp) = authz(&headers, state.admin_token.as_deref()) {
        return resp.into_response();
    }
    let Some(store) = &state.store else {
        return (StatusCode::SERVICE_UNAVAILABLE, "Admin store unavailable").into_response();
    };
    let statuses = match parse_managed_mcp_deployment_status_filter(query.status.as_deref()) {
        Ok(v) => v,
        Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
    };
    let limit = query.limit.unwrap_or(100).clamp(1, 500);
    match store
        .list_managed_mcp_deployment_requests(&statuses, limit)
        .await
    {
        Ok(requests) => Json(ManagedMcpDeploymentsResponse { requests }).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn put_managed_mcp_deployable(
    Extension(state): Extension<Arc<AdminState>>,
    headers: HeaderMap,
    Json(req): Json<PutManagedMcpDeployableRequest>,
) -> impl IntoResponse {
    if let Err(resp) = authz(&headers, state.admin_token.as_deref()) {
        return resp.into_response();
    }
    let Some(store) = &state.store else {
        return (StatusCode::SERVICE_UNAVAILABLE, "Admin store unavailable").into_response();
    };
    if req.id.trim().is_empty()
        || req.display_name.trim().is_empty()
        || req.image.trim().is_empty()
        || req.default_upstream_url.trim().is_empty()
    {
        return (
            StatusCode::BAD_REQUEST,
            "id, displayName, image, and defaultUpstreamUrl are required",
        )
            .into_response();
    }
    let deployable = ManagedMcpDeployable {
        id: req.id,
        display_name: req.display_name,
        description: req.description,
        image: req.image,
        default_upstream_url: req.default_upstream_url,
        enabled: req.enabled,
    };
    match store.upsert_managed_mcp_deployable(&deployable).await {
        Ok(()) => (StatusCode::CREATED, Json(OkResponse { ok: true })).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn get_managed_mcp_deployment_request(
    Extension(state): Extension<Arc<AdminState>>,
    headers: HeaderMap,
    Path(request_id): Path<String>,
) -> impl IntoResponse {
    if let Err(resp) = authz(&headers, state.admin_token.as_deref()) {
        return resp.into_response();
    }
    let Some(store) = &state.store else {
        return (StatusCode::SERVICE_UNAVAILABLE, "Admin store unavailable").into_response();
    };
    match store.get_managed_mcp_deployment_request(&request_id).await {
        Ok(Some(request)) => Json(ManagedMcpDeploymentResponse { request }).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "deployment request not found").into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn patch_managed_mcp_deployment_request(
    Extension(state): Extension<Arc<AdminState>>,
    headers: HeaderMap,
    Path(request_id): Path<String>,
    Json(req): Json<PatchManagedMcpDeploymentRequest>,
) -> impl IntoResponse {
    if let Err(resp) = authz(&headers, state.admin_token.as_deref()) {
        return resp.into_response();
    }
    let Some(store) = &state.store else {
        return (StatusCode::SERVICE_UNAVAILABLE, "Admin store unavailable").into_response();
    };
    if let Err(message) = validate_managed_mcp_status_patch_request(&req) {
        return (StatusCode::BAD_REQUEST, message).into_response();
    }
    match store
        .mark_managed_mcp_deployment_status(
            &request_id,
            req.status,
            req.upstream_id.as_deref(),
            req.message.as_deref(),
        )
        .await
    {
        Ok(true) => Json(OkResponse { ok: true }).into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, "deployment request not found").into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

fn validate_managed_mcp_status_patch_request(
    req: &PatchManagedMcpDeploymentRequest,
) -> Result<(), &'static str> {
    if matches!(req.status, ManagedMcpDeploymentStatus::Ready)
        && req
            .upstream_id
            .as_deref()
            .map(str::trim)
            .is_none_or(str::is_empty)
    {
        return Err("upstreamId is required when status is ready");
    }
    Ok(())
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

async fn patch_upstream_endpoint(
    Extension(state): Extension<Arc<AdminState>>,
    headers: HeaderMap,
    Path((upstream_id, endpoint_id)): Path<(String, String)>,
    Json(req): Json<PatchUpstreamEndpointRequest>,
) -> impl IntoResponse {
    if let Err(resp) = authz(&headers, state.admin_token.as_deref()) {
        return resp.into_response();
    }
    let Some(store) = &state.store else {
        return (StatusCode::SERVICE_UNAVAILABLE, "Admin store unavailable").into_response();
    };
    if req.enabled.is_none() && req.lifecycle.is_none() {
        return (
            StatusCode::BAD_REQUEST,
            "at least one of enabled or lifecycle must be set",
        )
            .into_response();
    }
    match store
        .patch_upstream_endpoint(&upstream_id, &endpoint_id, req.enabled, req.lifecycle)
        .await
    {
        Ok(true) => Json(OkResponse { ok: true }).into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, "upstream endpoint not found").into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn delete_upstream_endpoint(
    Extension(state): Extension<Arc<AdminState>>,
    headers: HeaderMap,
    Path((upstream_id, endpoint_id)): Path<(String, String)>,
) -> impl IntoResponse {
    if let Err(resp) = authz(&headers, state.admin_token.as_deref()) {
        return resp.into_response();
    }
    let Some(store) = &state.store else {
        return (StatusCode::SERVICE_UNAVAILABLE, "Admin store unavailable").into_response();
    };
    match store
        .delete_upstream_endpoint(&upstream_id, &endpoint_id)
        .await
    {
        Ok(true) => Json(OkResponse { ok: true }).into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, "upstream endpoint not found").into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
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

#[cfg(test)]
mod tests;
