mod managed_deployments;
mod profiles;

use crate::audit::{AuditActor, AuditError, HttpAuditEvent};
use crate::managed_mcp::ManagedMcpRuntimeConfig;
use crate::serde_helpers::default_true;
use crate::store::{
    AdminStore, AdminUpstream, ApiKeyMetadata, DataPlaneAuthMode, McpProfileSettings,
    TenantSecretMetadata, ToolSourceKind, TransportLimitsSettings, UpstreamEndpoint,
    UpstreamEndpointActivity, UpstreamEndpointLifecycle, UpstreamNetworkClass,
};
use crate::tenant_token::TenantSigner;
use axum::extract::{Path, Query};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, patch, post};
use axum::{Json, Router};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rmcp::model::Tool;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Digest as _;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use unrelated_gateway_api::error::{ApiError, Resource, StoreKind};
use unrelated_gateway_api::routes;
use unrelated_http_tools::config::AuthConfig;
use unrelated_http_tools::config::HttpServerConfig;
use unrelated_openapi_tools::config::{
    ApiServerConfig, AutoDiscoverConfig, HashPolicy, OpenApiOverridesConfig,
};
use unrelated_openapi_tools::runtime::OpenApiToolSource;
use unrelated_tool_transforms::TransformPipeline;
use uuid::{Uuid, Version};

#[derive(Clone)]
pub struct TenantState {
    pub store: Option<Arc<dyn AdminStore>>,
    pub managed_mcp: ManagedMcpRuntimeConfig,
    pub signer: TenantSigner,
    pub shared_source_ids: Arc<std::collections::HashSet<String>>,
    /// Shared MCP data-plane state (used for profile surface probing).
    pub mcp_state: Arc<crate::mcp::McpState>,
    pub audit: Arc<dyn crate::audit::AuditSink>,
    pub invalidation: Arc<crate::pg_invalidation::InvalidationDispatcher>,
}

pub fn router(state: Arc<TenantState>) -> Router {
    Router::new()
        .route(routes::tenant::UPSTREAMS.template(), get(list_upstreams))
        .route(
            routes::tenant::UPSTREAM.template(),
            get(get_upstream).put(put_upstream).delete(delete_upstream),
        )
        .route(
            routes::tenant::ENDPOINT.template(),
            patch(patch_upstream_endpoint).delete(delete_upstream_endpoint),
        )
        .route(
            routes::tenant::UPSTREAM_SURFACE.template(),
            get(get_upstream_surface),
        )
        .route(
            routes::tenant::UPSTREAM_ACTIVITY.template(),
            get(get_upstream_session_activity),
        )
        .merge(managed_deployments::router())
        .merge(profiles::router())
        .route(
            routes::tenant::PROFILE_AUDIT.template(),
            get(get_profile_audit_settings).put(put_profile_audit_settings),
        )
        .route(
            routes::tenant::PROFILE_SURFACE.template(),
            get(get_profile_surface),
        )
        .route(
            routes::tenant::PROFILE_CONNECTIONS.template(),
            post(check_profile_connections),
        )
        .route(
            routes::tenant::TOOL_SOURCES.template(),
            get(list_tool_sources),
        )
        .route(
            routes::tenant::TOOL_SOURCE_TOOLS.template(),
            get(get_tool_source_tools),
        )
        .route(
            routes::tenant::TOOL_SOURCE.template(),
            get(get_tool_source)
                .put(put_tool_source)
                .delete(delete_tool_source),
        )
        .route(
            routes::tenant::OPENAPI_INSPECT.template(),
            axum::routing::post(openapi_inspect),
        )
        .route(
            routes::tenant::VALIDATE_SOURCE_ID.template(),
            axum::routing::post(validate_source_id),
        )
        .route(
            routes::tenant::SECRETS.template(),
            get(list_secrets).post(put_secret),
        )
        .route(routes::tenant::SECRET.template(), delete(delete_secret))
        .route(
            routes::tenant::API_KEYS.template(),
            get(list_api_keys).post(create_api_key),
        )
        .route(routes::tenant::API_KEY.template(), delete(revoke_api_key))
        .route(
            routes::tenant::AUDIT_SETTINGS.template(),
            get(get_audit_settings).put(put_audit_settings),
        )
        .route(
            routes::tenant::TRANSPORT_LIMITS.template(),
            get(get_transport_limits).put(put_transport_limits),
        )
        .route(
            routes::tenant::AUDIT_EVENTS.template(),
            get(list_audit_events),
        )
        .route(
            routes::tenant::AUDIT_BY_TOOL.template(),
            get(tool_call_stats_by_tool),
        )
        .route(
            routes::tenant::AUDIT_BY_API_KEY.template(),
            get(tool_call_stats_by_api_key),
        )
        .layer(axum::Extension(state))
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ToolSourceToolsResponse {
    tools: Vec<Tool>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OpenApiInspectRequest {
    spec_url: String,
    #[serde(default)]
    auth: Option<AuthConfig>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct OpenApiInspectResponse {
    title: Option<String>,
    inferred_base_url: String,
    suggested_id: String,
    tools: Vec<Tool>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ValidateSourceIdRequest {
    id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ValidateSourceIdResponse {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

const TENANT_UPSTREAM_ID_PREFIX: &str = "tu1.";

pub(crate) fn tenant_upstream_internal_id(tenant_id: &str, upstream_id: &str) -> String {
    unrelated_mcp_support::tenant_upstream_id(tenant_id, upstream_id)
}

fn parse_tenant_upstream_internal_id(id: &str) -> Option<(String, String)> {
    let rest = id.strip_prefix(TENANT_UPSTREAM_ID_PREFIX)?;
    let (t, u) = rest.split_once('.')?;
    let t = URL_SAFE_NO_PAD.decode(t).ok()?;
    let u = URL_SAFE_NO_PAD.decode(u).ok()?;
    let tenant_id = String::from_utf8(t).ok()?;
    let upstream_id = String::from_utf8(u).ok()?;
    Some((tenant_id, upstream_id))
}

fn authn(headers: &HeaderMap, signer: &TenantSigner) -> Result<String, impl IntoResponse> {
    let Some(authz) = headers.get("Authorization").and_then(|h| h.to_str().ok()) else {
        return Err((StatusCode::UNAUTHORIZED, "missing Authorization header"));
    };
    let Some(token) = authz.strip_prefix("Bearer ").map(str::trim) else {
        return Err((StatusCode::UNAUTHORIZED, "invalid Authorization header"));
    };
    let payload = signer
        .verify(token)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "invalid tenant token"))?;
    Ok(payload.tenant_id)
}

async fn ensure_enabled_tenant(
    store: &Arc<dyn AdminStore>,
    tenant_id: &str,
) -> Result<(), Response> {
    match store.get_tenant(tenant_id).await {
        Ok(Some(t)) if t.enabled => Ok(()),
        Ok(_) => Err(ApiError::invalid_tenant().into_response()),
        Err(e) => Err(ApiError::internal(e).into_response()),
    }
}

fn upstream_to_response(tenant_id: &str, u: AdminUpstream) -> Option<UpstreamResponse> {
    // Tenant-owned upstreams are stored in the shared upstream table with a stable encoded id.
    if let Some((t, local_id)) = parse_tenant_upstream_internal_id(&u.id) {
        if t != tenant_id {
            return None;
        }
        return Some(UpstreamResponse {
            id: local_id,
            owner: "tenant".to_string(),
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
        });
    }

    // Global upstreams: visible to tenants for attachment (but only editable by admin API).
    Some(UpstreamResponse {
        id: u.id,
        owner: "global".to_string(),
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
    })
}

async fn list_upstreams(
    axum::Extension(state): axum::Extension<Arc<TenantState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let tenant_id = match authn(&headers, &state.signer) {
        Ok(t) => t,
        Err(resp) => return resp.into_response(),
    };
    let Some(store) = &state.store else {
        return ApiError::store_unavailable(StoreKind::Tenant).into_response();
    };
    // Ensure tenant exists + enabled.
    match store.get_tenant(&tenant_id).await {
        Ok(Some(t)) if t.enabled => {}
        Ok(_) => return ApiError::invalid_tenant().into_response(),
        Err(e) => return ApiError::internal(e).into_response(),
    }

    match store.list_upstreams().await {
        Ok(upstreams) => {
            let upstreams = upstreams
                .into_iter()
                .filter_map(|u| upstream_to_response(&tenant_id, u))
                .collect();
            Json(UpstreamsResponse { upstreams }).into_response()
        }
        Err(e) => ApiError::internal(e).into_response(),
    }
}

async fn get_upstream(
    axum::Extension(state): axum::Extension<Arc<TenantState>>,
    headers: HeaderMap,
    Path(upstream_id): Path<String>,
) -> impl IntoResponse {
    let tenant_id = match authn(&headers, &state.signer) {
        Ok(t) => t,
        Err(resp) => return resp.into_response(),
    };
    let Some(store) = &state.store else {
        return ApiError::store_unavailable(StoreKind::Tenant).into_response();
    };

    // Prefer tenant-owned upstream if present; otherwise fall back to global.
    let internal_id = tenant_upstream_internal_id(&tenant_id, &upstream_id);
    let u = match store.get_upstream(&internal_id).await {
        Ok(Some(u)) => Some(u),
        Ok(None) => match store.get_upstream(&upstream_id).await {
            Ok(Some(u)) => Some(u),
            Ok(None) => None,
            Err(e) => return ApiError::internal(e).into_response(),
        },
        Err(e) => return ApiError::internal(e).into_response(),
    };
    let Some(u) = u else {
        return ApiError::not_found(Resource::Upstream).into_response();
    };

    let Some(resp) = upstream_to_response(&tenant_id, u) else {
        return ApiError::not_found(Resource::Upstream).into_response();
    };
    Json(resp).into_response()
}

async fn get_upstream_session_activity(
    axum::Extension(state): axum::Extension<Arc<TenantState>>,
    headers: HeaderMap,
    Path(upstream_id): Path<String>,
    Query(q): Query<UpstreamSessionActivityQuery>,
) -> impl IntoResponse {
    let tenant_id = match authn(&headers, &state.signer) {
        Ok(t) => t,
        Err(resp) => return resp.into_response(),
    };
    let Some(store) = &state.store else {
        return ApiError::store_unavailable(StoreKind::Tenant).into_response();
    };

    // Resolve tenant-owned upstream first, then global visible upstream.
    let internal_id = tenant_upstream_internal_id(&tenant_id, &upstream_id);
    let canonical_upstream_id = match store.get_upstream(&internal_id).await {
        Ok(Some(_)) => internal_id,
        Ok(None) => match store.get_upstream(&upstream_id).await {
            Ok(Some(u)) => {
                if upstream_to_response(&tenant_id, u).is_some() {
                    upstream_id.clone()
                } else {
                    return ApiError::not_found(Resource::Upstream).into_response();
                }
            }
            Ok(None) => return ApiError::not_found(Resource::Upstream).into_response(),
            Err(e) => return ApiError::internal(e).into_response(),
        },
        Err(e) => return ApiError::internal(e).into_response(),
    };

    let ttl_secs = crate::pg_store::resolve_upstream_session_activity_ttl_secs(q.ttl_secs);
    match store
        .list_upstream_endpoint_activity(&canonical_upstream_id, ttl_secs)
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
        Err(e) => ApiError::internal(e).into_response(),
    }
}

async fn put_upstream(
    axum::Extension(state): axum::Extension<Arc<TenantState>>,
    headers: HeaderMap,
    Path(upstream_id): Path<String>,
    Json(req): Json<PutUpstreamRequest>,
) -> impl IntoResponse {
    let tenant_id = match authn(&headers, &state.signer) {
        Ok(t) => t,
        Err(resp) => return resp.into_response(),
    };
    let Some(store) = &state.store else {
        return ApiError::store_unavailable(StoreKind::Tenant).into_response();
    };
    // Ensure tenant exists + enabled.
    match store.get_tenant(&tenant_id).await {
        Ok(Some(t)) if t.enabled => {}
        Ok(_) => return ApiError::invalid_tenant().into_response(),
        Err(e) => return ApiError::internal(e).into_response(),
    }

    if upstream_id.trim().is_empty() {
        return (StatusCode::BAD_REQUEST, "upstream id is required").into_response();
    }
    if req.endpoints.is_empty() {
        return (StatusCode::BAD_REQUEST, "endpoints is required").into_response();
    }

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

    if let Err(e) = crate::upstream_validation::validate_upstream_endpoints(
        UpstreamNetworkClass::External,
        &endpoints,
    )
    .await
    {
        return (StatusCode::BAD_REQUEST, e).into_response();
    }

    let internal_id = tenant_upstream_internal_id(&tenant_id, &upstream_id);
    if let Err(e) = store
        .put_upstream(
            &internal_id,
            req.enabled,
            UpstreamNetworkClass::External,
            &endpoints,
        )
        .await
    {
        return ApiError::internal(e).into_response();
    }
    (StatusCode::CREATED, Json(OkResponse { ok: true })).into_response()
}

async fn delete_upstream(
    axum::Extension(state): axum::Extension<Arc<TenantState>>,
    headers: HeaderMap,
    Path(upstream_id): Path<String>,
) -> impl IntoResponse {
    let tenant_id = match authn(&headers, &state.signer) {
        Ok(t) => t,
        Err(resp) => return resp.into_response(),
    };
    let Some(store) = &state.store else {
        return ApiError::store_unavailable(StoreKind::Tenant).into_response();
    };

    let internal_id = tenant_upstream_internal_id(&tenant_id, &upstream_id);
    match store.delete_upstream(&internal_id).await {
        Ok(true) => Json(OkResponse { ok: true }).into_response(),
        Ok(false) => ApiError::not_found(Resource::Upstream).into_response(),
        Err(e) => ApiError::internal(e).into_response(),
    }
}

async fn patch_upstream_endpoint(
    axum::Extension(state): axum::Extension<Arc<TenantState>>,
    headers: HeaderMap,
    Path((upstream_id, endpoint_id)): Path<(String, String)>,
    Json(req): Json<PatchUpstreamEndpointRequest>,
) -> impl IntoResponse {
    let tenant_id = match authn(&headers, &state.signer) {
        Ok(t) => t,
        Err(resp) => return resp.into_response(),
    };
    let Some(store) = &state.store else {
        return ApiError::store_unavailable(StoreKind::Tenant).into_response();
    };
    if req.enabled.is_none() && req.lifecycle.is_none() {
        return (
            StatusCode::BAD_REQUEST,
            "at least one of enabled or lifecycle must be set",
        )
            .into_response();
    }
    let internal_id = tenant_upstream_internal_id(&tenant_id, &upstream_id);
    match store
        .patch_upstream_endpoint(&internal_id, &endpoint_id, req.enabled, req.lifecycle)
        .await
    {
        Ok(true) => Json(OkResponse { ok: true }).into_response(),
        Ok(false) => ApiError::not_found(Resource::Endpoint).into_response(),
        Err(e) => ApiError::internal(e).into_response(),
    }
}

async fn delete_upstream_endpoint(
    axum::Extension(state): axum::Extension<Arc<TenantState>>,
    headers: HeaderMap,
    Path((upstream_id, endpoint_id)): Path<(String, String)>,
) -> impl IntoResponse {
    let tenant_id = match authn(&headers, &state.signer) {
        Ok(t) => t,
        Err(resp) => return resp.into_response(),
    };
    let Some(store) = &state.store else {
        return ApiError::store_unavailable(StoreKind::Tenant).into_response();
    };
    let internal_id = tenant_upstream_internal_id(&tenant_id, &upstream_id);
    match store
        .delete_upstream_endpoint(&internal_id, &endpoint_id)
        .await
    {
        Ok(true) => Json(OkResponse { ok: true }).into_response(),
        Ok(false) => ApiError::not_found(Resource::Endpoint).into_response(),
        Err(e) => ApiError::internal(e).into_response(),
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PutUpstreamRequest {
    #[serde(default = "default_true")]
    enabled: bool,
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

const fn default_upstream_endpoint_lifecycle() -> UpstreamEndpointLifecycle {
    UpstreamEndpointLifecycle::Active
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
struct UpstreamResponse {
    id: String,
    /// "tenant" for tenant-owned upstreams, "global" for admin-provisioned upstreams.
    owner: String,
    enabled: bool,
    network_class: UpstreamNetworkClass,
    endpoints: Vec<UpstreamEndpointResponse>,
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
struct ProfileSurfaceTool {
    source_id: String,
    name: String,
    base_name: String,
    original_name: String,
    enabled: bool,
    #[serde(default)]
    original_params: Vec<String>,
    #[serde(default)]
    original_description: Option<String>,
    #[serde(default)]
    description: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProfileSurfaceResponse {
    all_resources: Vec<crate::mcp::catalog_transforms::CatalogEntry<rmcp::model::Resource>>,
    all_resource_templates:
        Vec<crate::mcp::catalog_transforms::CatalogEntry<rmcp::model::ResourceTemplate>>,
    all_prompts: Vec<crate::mcp::catalog_transforms::CatalogEntry<rmcp::model::Prompt>>,
    resource_templates: Vec<rmcp::model::ResourceTemplate>,
    profile_id: String,
    generated_at_unix: u64,
    sources: Vec<crate::mcp::ProfileSurfaceSource>,
    #[serde(default)]
    tools: Vec<rmcp::model::Tool>,
    #[serde(default)]
    all_tools: Vec<ProfileSurfaceTool>,
    #[serde(default)]
    resources: Vec<rmcp::model::Resource>,
    #[serde(default)]
    prompts: Vec<rmcp::model::Prompt>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct UpstreamSurfaceResponse {
    resource_templates: Vec<rmcp::model::ResourceTemplate>,
    upstream_id: String,
    generated_at_unix: u64,
    sources: Vec<crate::mcp::ProfileSurfaceSource>,
    #[serde(default)]
    tools: Vec<rmcp::model::Tool>,
    #[serde(default)]
    resources: Vec<rmcp::model::Resource>,
    #[serde(default)]
    prompts: Vec<rmcp::model::Prompt>,
}

async fn get_upstream_surface(
    axum::Extension(state): axum::Extension<Arc<TenantState>>,
    headers: HeaderMap,
    Path(upstream_id): Path<String>,
) -> impl IntoResponse {
    let tenant_id = match authn(&headers, &state.signer) {
        Ok(t) => t,
        Err(resp) => return resp.into_response(),
    };
    let Some(admin_store) = &state.store else {
        return ApiError::store_unavailable(StoreKind::Tenant).into_response();
    };

    // Ensure tenant exists + enabled.
    match admin_store.get_tenant(&tenant_id).await {
        Ok(Some(t)) if t.enabled => {}
        Ok(_) => return ApiError::invalid_tenant().into_response(),
        Err(e) => return ApiError::internal(e).into_response(),
    }

    // Resolve upstream id: prefer tenant-owned, else global.
    let internal_id = tenant_upstream_internal_id(&tenant_id, &upstream_id);
    let resolved = match admin_store.get_upstream(&internal_id).await {
        Ok(Some(_)) => internal_id,
        Ok(None) => match admin_store.get_upstream(&upstream_id).await {
            Ok(Some(_)) => upstream_id.clone(),
            Ok(None) => return ApiError::not_found(Resource::Upstream).into_response(),
            Err(e) => return ApiError::internal(e).into_response(),
        },
        Err(e) => return ApiError::internal(e).into_response(),
    };

    let profile = crate::store::Profile {
        id: format!("probe-upstream:{upstream_id}"),
        tenant_id: tenant_id.clone(),
        allow_partial_upstreams: true,
        source_ids: vec![resolved],
        transforms: TransformPipeline::default(),
        enabled_tools: vec![],
        data_plane_auth_mode: DataPlaneAuthMode::Disabled,
        accept_x_api_key: false,
        oauth_required_scopes: Vec::new(),
        rate_limit_enabled: false,
        rate_limit_tool_calls_per_minute: None,
        quota_enabled: false,
        quota_tool_calls: None,
        tool_call_timeout_secs: None,
        tool_policies: vec![],
        mcp: McpProfileSettings::default(),
    };

    let crate::mcp::ProbedProfileSurface {
        sources,
        tools,
        resources,
        resource_templates,
        prompts,
        ..
    } = match crate::mcp::probe_upstream_surface(&state.mcp_state, &profile).await {
        Ok(r) => r,
        Err(e) => return (StatusCode::BAD_GATEWAY, e).into_response(),
    };

    let generated_at_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    Json(UpstreamSurfaceResponse {
        resource_templates,
        upstream_id,
        generated_at_unix,
        sources,
        tools,
        resources,
        prompts,
    })
    .into_response()
}

async fn load_profile_for_probe(
    state: &TenantState,
    headers: &HeaderMap,
    profile_id: &str,
) -> Result<crate::store::Profile, Response> {
    let tenant_id = authn(headers, &state.signer).map_err(IntoResponse::into_response)?;
    if !Uuid::parse_str(profile_id).is_ok_and(|id| id.get_version() == Some(Version::Random)) {
        return Err(ApiError::not_found(Resource::Profile).into_response());
    }
    let admin_store = state
        .store
        .as_ref()
        .ok_or_else(|| ApiError::store_unavailable(StoreKind::Tenant).into_response())?;
    match admin_store.get_tenant(&tenant_id).await {
        Ok(Some(tenant)) if tenant.enabled => {}
        Ok(_) => return Err(ApiError::invalid_tenant().into_response()),
        Err(error) => return Err(ApiError::internal(error).into_response()),
    }
    // Tenant ownership is required; disabled profiles remain inspectable.
    let admin_profile = match admin_store.get_profile(profile_id).await {
        Ok(Some(profile)) if profile.tenant_id == tenant_id => profile,
        Ok(_) => return Err(ApiError::not_found(Resource::Profile).into_response()),
        Err(error) => return Err(ApiError::internal(error).into_response()),
    };
    let mut source_ids = admin_profile.upstream_ids.clone();
    source_ids.extend(admin_profile.source_ids.clone());
    let mut seen = std::collections::HashSet::new();
    source_ids.retain(|source| seen.insert(source.clone()));
    Ok(crate::store::Profile {
        id: admin_profile.id,
        tenant_id: admin_profile.tenant_id,
        allow_partial_upstreams: admin_profile.allow_partial_upstreams,
        source_ids,
        transforms: admin_profile.transforms,
        enabled_tools: admin_profile.enabled_tools,
        data_plane_auth_mode: admin_profile.data_plane_auth_mode,
        accept_x_api_key: admin_profile.accept_x_api_key,
        oauth_required_scopes: admin_profile.oauth_required_scopes,
        rate_limit_enabled: admin_profile.rate_limit_enabled,
        rate_limit_tool_calls_per_minute: admin_profile.rate_limit_tool_calls_per_minute,
        quota_enabled: admin_profile.quota_enabled,
        quota_tool_calls: admin_profile.quota_tool_calls,
        tool_call_timeout_secs: admin_profile.tool_call_timeout_secs,
        tool_policies: admin_profile.tool_policies,
        mcp: admin_profile.mcp,
    })
}

async fn check_profile_connections(
    axum::Extension(state): axum::Extension<Arc<TenantState>>,
    headers: HeaderMap,
    Path(profile_id): Path<String>,
) -> Response {
    let profile = match load_profile_for_probe(&state, &headers, &profile_id).await {
        Ok(profile) => profile,
        Err(response) => return response,
    };
    let mut checks = crate::mcp::check_profile_connections(&state.mcp_state, &profile).await;
    for check in &mut checks {
        if let Some((tenant, local_id)) = parse_tenant_upstream_internal_id(&check.source_id)
            && tenant == profile.tenant_id
        {
            check.source_id = local_id;
        }
    }
    Json(serde_json::json!({"checks":checks})).into_response()
}

async fn get_profile_surface(
    axum::Extension(state): axum::Extension<Arc<TenantState>>,
    headers: HeaderMap,
    Path(profile_id): Path<String>,
) -> impl IntoResponse {
    let profile = match load_profile_for_probe(&state, &headers, &profile_id).await {
        Ok(profile) => profile,
        Err(response) => return response,
    };

    let crate::mcp::ProbedProfileSurface {
        all_resources,
        all_resource_templates,
        all_prompts,
        sources,
        tools,
        all_tools,
        resources,
        resource_templates,
        prompts,
    } = match crate::mcp::probe_profile_surface(&state.mcp_state, &profile).await {
        Ok(r) => r,
        Err(e) => return (StatusCode::BAD_GATEWAY, e).into_response(),
    };

    let generated_at_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    Json(ProfileSurfaceResponse {
        all_resources,
        all_resource_templates,
        all_prompts,
        resource_templates,
        profile_id,
        generated_at_unix,
        sources,
        tools,
        all_tools: all_tools
            .into_iter()
            .map(|t| ProfileSurfaceTool {
                source_id: t.source_id,
                name: t.name,
                base_name: t.base_name,
                original_name: t.original_name,
                enabled: t.enabled,
                original_params: t.original_params,
                original_description: t.original_description,
                description: t.description,
            })
            .collect(),
        resources,
        prompts,
    })
    .into_response()
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
enum PutToolSourceBody {
    Http {
        #[serde(default, rename = "expectedRevision")]
        expected_revision: Option<i64>,
        #[serde(default = "default_true")]
        enabled: bool,
        #[serde(flatten)]
        config: HttpServerConfig,
    },
    Openapi {
        #[serde(default, rename = "expectedRevision")]
        expected_revision: Option<i64>,
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
struct ToolSourceDetailResponse {
    revision: i64,
    id: String,
    #[serde(rename = "type")]
    tool_type: String,
    enabled: bool,
    /// Stored tool source config (does not include `type` / `enabled`).
    spec: Value,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ToolSourcesResponse {
    sources: Vec<ToolSourceResponse>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PutSecretRequest {
    name: String,
    value: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SecretsResponse {
    secrets: Vec<TenantSecretMetadata>,
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
    #[serde(default)]
    offset: Option<i64>,
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

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PutProfileAuditSettingsRequest {
    audit_settings: Value,
    #[serde(default)]
    expected_revision: Option<i64>,
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

fn suggest_source_id_from_title(title: Option<&str>, spec_url: &str) -> String {
    let mut base = title.unwrap_or("").trim().to_string();
    if base.is_empty() {
        // Fallback: use URL host/path as a best-effort hint.
        if let Ok(u) = reqwest::Url::parse(spec_url)
            && let Some(host) = u.host_str()
        {
            base = host.to_string();
        }
    }

    if base.is_empty() {
        base = "openapi".to_string();
    }

    // Normalize to [A-Za-z0-9_-] (prefer lower for consistency).
    let mut out = String::with_capacity(base.len());
    let mut prev_us = false;
    for ch in base.chars() {
        let c = if ch.is_ascii_alphanumeric() {
            ch.to_ascii_lowercase()
        } else {
            '_'
        };
        if c == '_' {
            if prev_us {
                continue;
            }
            prev_us = true;
            out.push('_');
        } else {
            prev_us = false;
            out.push(c);
        }
    }
    let out = out.trim_matches('_').to_string();
    if out.is_empty() {
        "openapi".to_string()
    } else {
        out
    }
}

fn openapi_default_config(spec_url: &str) -> ApiServerConfig {
    ApiServerConfig {
        spec: spec_url.to_string(),
        spec_hash: None,
        spec_hash_policy: HashPolicy::Warn,
        base_url: None,
        auth: None,
        auto_discover: AutoDiscoverConfig::Enabled(true),
        endpoints: std::collections::HashMap::new(),
        defaults: unrelated_http_tools::config::EndpointDefaults::default(),
        response_transforms: vec![],
        response_overrides: vec![],
        overrides: OpenApiOverridesConfig::default(),
    }
}

async fn openapi_inspect(
    axum::Extension(state): axum::Extension<Arc<TenantState>>,
    headers: HeaderMap,
    Json(req): Json<OpenApiInspectRequest>,
) -> impl IntoResponse {
    let tenant_id = match authn(&headers, &state.signer) {
        Ok(t) => t,
        Err(resp) => return resp.into_response(),
    };
    let Some(store) = &state.store else {
        return ApiError::store_unavailable(StoreKind::Tenant).into_response();
    };

    // Ensure tenant exists + enabled.
    match store.get_tenant(&tenant_id).await {
        Ok(Some(t)) if t.enabled => {}
        Ok(_) => return ApiError::invalid_tenant().into_response(),
        Err(e) => return ApiError::internal(e).into_response(),
    }

    let spec_url = req.spec_url.trim();
    if !(spec_url.starts_with("http://") || spec_url.starts_with("https://")) {
        return (StatusCode::BAD_REQUEST, "specUrl must be an http(s) URL").into_response();
    }

    let mut cfg = openapi_default_config(spec_url);
    cfg.auth = req.auth;
    if let Err(error) = crate::tenant_catalog::resolve_auth_secrets(
        state.mcp_state.store.as_ref(),
        &tenant_id,
        cfg.auth.as_mut(),
    )
    .await
    {
        return (StatusCode::BAD_REQUEST, format!("{error:#}")).into_response();
    }
    let safety = crate::outbound_safety::gateway_outbound_http_safety();
    let built = OpenApiToolSource::build_with_safety(
        "openapi-inspect".to_string(),
        cfg,
        std::time::Duration::from_secs(30),
        std::time::Duration::from_secs(30),
        true,
        std::time::Duration::from_secs(5),
        safety,
    )
    .await;

    match built {
        Ok(src) => {
            let tools = src.list_tools();
            let title = src.spec_title();
            let Some(base_url) = src.inferred_base_url() else {
                return (
                    StatusCode::BAD_GATEWAY,
                    "could not infer baseUrl from spec (missing servers[0]?)",
                )
                    .into_response();
            };
            let suggested_id = suggest_source_id_from_title(title.as_deref(), spec_url);
            Json(OpenApiInspectResponse {
                title,
                inferred_base_url: base_url,
                suggested_id,
                tools,
            })
            .into_response()
        }
        Err(e) => {
            // Keep this human-readable for the wizard UX.
            let msg = e.to_string();
            (StatusCode::BAD_GATEWAY, msg).into_response()
        }
    }
}

async fn validate_source_id(
    axum::Extension(state): axum::Extension<Arc<TenantState>>,
    headers: HeaderMap,
    Json(req): Json<ValidateSourceIdRequest>,
) -> impl IntoResponse {
    let tenant_id = match authn(&headers, &state.signer) {
        Ok(t) => t,
        Err(resp) => return resp.into_response(),
    };
    let Some(store) = &state.store else {
        return ApiError::store_unavailable(StoreKind::Tenant).into_response();
    };

    // Ensure tenant exists + enabled.
    match store.get_tenant(&tenant_id).await {
        Ok(Some(t)) if t.enabled => {}
        Ok(_) => return ApiError::invalid_tenant().into_response(),
        Err(e) => return ApiError::internal(e).into_response(),
    }

    let id = req.id.trim();
    if !is_valid_source_id(id) {
        return Json(ValidateSourceIdResponse {
            ok: false,
            error: Some(
                "invalid source id (allowed: [a-zA-Z0-9_-], must not contain ':')".to_string(),
            ),
        })
        .into_response();
    }
    if state.shared_source_ids.contains(id) {
        return Json(ValidateSourceIdResponse {
            ok: false,
            error: Some("source id collides with a shared catalog source id".to_string()),
        })
        .into_response();
    }
    if store.get_upstream(id).await.ok().flatten().is_some() {
        return Json(ValidateSourceIdResponse {
            ok: false,
            error: Some("source id collides with an upstream id".to_string()),
        })
        .into_response();
    }
    match store.get_tool_source(&tenant_id, id).await {
        Ok(Some(_)) => {
            return Json(ValidateSourceIdResponse {
                ok: false,
                error: Some("a tool source with this id already exists".to_string()),
            })
            .into_response();
        }
        Ok(None) => {}
        Err(e) => return ApiError::internal(e).into_response(),
    }

    Json(ValidateSourceIdResponse {
        ok: true,
        error: None,
    })
    .into_response()
}

async fn list_tool_sources(
    axum::Extension(state): axum::Extension<Arc<TenantState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let tenant_id = match authn(&headers, &state.signer) {
        Ok(t) => t,
        Err(resp) => return resp.into_response(),
    };
    let Some(store) = &state.store else {
        return ApiError::store_unavailable(StoreKind::Tenant).into_response();
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
        Err(e) => ApiError::internal(e).into_response(),
    }
}

async fn get_tool_source(
    axum::Extension(state): axum::Extension<Arc<TenantState>>,
    headers: HeaderMap,
    Path(source_id): Path<String>,
) -> impl IntoResponse {
    let tenant_id = match authn(&headers, &state.signer) {
        Ok(t) => t,
        Err(resp) => return resp.into_response(),
    };
    let Some(store) = &state.store else {
        return ApiError::store_unavailable(StoreKind::Tenant).into_response();
    };

    match store.get_tool_source(&tenant_id, &source_id).await {
        Ok(Some(s)) => {
            let spec = match &s.spec {
                crate::store::ToolSourceSpec::Http(cfg) => serde_json::to_value(cfg),
                crate::store::ToolSourceSpec::Openapi(cfg) => serde_json::to_value(cfg),
            };
            let spec = match spec {
                Ok(v) => v,
                Err(e) => {
                    return ApiError::internal(e).into_response();
                }
            };

            Json(ToolSourceDetailResponse {
                revision: s.revision,
                id: s.id,
                tool_type: tool_source_kind_str(s.kind).to_string(),
                enabled: s.enabled,
                spec,
            })
            .into_response()
        }
        Ok(None) => ApiError::not_found(Resource::ToolSource).into_response(),
        Err(e) => ApiError::internal(e).into_response(),
    }
}

async fn get_tool_source_tools(
    axum::Extension(state): axum::Extension<Arc<TenantState>>,
    headers: HeaderMap,
    Path(source_id): Path<String>,
) -> impl IntoResponse {
    let tenant_id = match authn(&headers, &state.signer) {
        Ok(t) => t,
        Err(resp) => return resp.into_response(),
    };
    let Some(store) = &state.store else {
        return ApiError::store_unavailable(StoreKind::Tenant).into_response();
    };

    // Ensure tenant exists + enabled.
    match store.get_tenant(&tenant_id).await {
        Ok(Some(t)) if t.enabled => {}
        Ok(_) => return ApiError::invalid_tenant().into_response(),
        Err(e) => return ApiError::internal(e).into_response(),
    }

    match state
        .mcp_state
        .tenant_catalog
        .list_tools(state.mcp_state.store.as_ref(), &tenant_id, &source_id)
        .await
    {
        Ok(Some(tools)) => Json(ToolSourceToolsResponse { tools }).into_response(),
        Ok(None) => ApiError::not_found(Resource::ToolSource).into_response(),
        Err(e) => (StatusCode::BAD_GATEWAY, format!("{e:#}")).into_response(),
    }
}

async fn put_tool_source(
    axum::Extension(state): axum::Extension<Arc<TenantState>>,
    headers: HeaderMap,
    Path(source_id): Path<String>,
    Json(body): Json<PutToolSourceBody>,
) -> impl IntoResponse {
    let tenant_id = match authn(&headers, &state.signer) {
        Ok(t) => t,
        Err(resp) => return resp.into_response(),
    };
    let Some(store) = &state.store else {
        return ApiError::store_unavailable(StoreKind::Tenant).into_response();
    };
    let started = Instant::now();
    let outcome =
        tenant_put_tool_source_inner(state.as_ref(), store.as_ref(), &tenant_id, &source_id, body)
            .await;

    state
        .audit
        .record(crate::audit::http_event(HttpAuditEvent {
            tenant_id: tenant_id.clone(),
            actor: AuditActor::default(),
            action: "tenant.tool_source_put",
            http_method: "PUT",
            http_route: routes::tenant::TOOL_SOURCE.template(),
            status_code: i32::from(outcome.status.as_u16()),
            ok: outcome.status.is_success(),
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

struct TenantPutToolSourceOutcome {
    resp: axum::response::Response,
    status: StatusCode,
    error: Option<AuditError>,
    kind_for_meta: Option<String>,
    enabled_for_meta: Option<bool>,
}

impl TenantPutToolSourceOutcome {
    fn fail(status: StatusCode, message: impl Into<String>, error: AuditError) -> Self {
        let msg = message.into();
        Self {
            resp: (status, msg.clone()).into_response(),
            status,
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
            error: Some(error),
            kind_for_meta,
            enabled_for_meta,
        }
    }

    fn ok(kind_for_meta: Option<String>, enabled_for_meta: Option<bool>) -> Self {
        Self {
            resp: Json(OkResponse { ok: true }).into_response(),
            status: StatusCode::OK,
            error: None,
            kind_for_meta,
            enabled_for_meta,
        }
    }
}

async fn tenant_put_tool_source_validate_request(
    state: &TenantState,
    store: &dyn crate::store::AdminStore,
    tenant_id: &str,
    source_id: &str,
) -> Result<(), TenantPutToolSourceOutcome> {
    if !is_valid_source_id(source_id) {
        return Err(TenantPutToolSourceOutcome::fail(
            StatusCode::BAD_REQUEST,
            "invalid source id (allowed: [a-zA-Z0-9_-], must not contain ':')",
            AuditError::new("bad_request", "invalid source id"),
        ));
    }
    if state.shared_source_ids.contains(source_id) {
        return Err(TenantPutToolSourceOutcome::fail(
            StatusCode::BAD_REQUEST,
            "source id collides with a shared catalog source id",
            AuditError::new(
                "bad_request",
                "source id collides with a shared catalog source id",
            ),
        ));
    }
    if store.get_upstream(source_id).await.ok().flatten().is_some() {
        return Err(TenantPutToolSourceOutcome::fail(
            StatusCode::BAD_REQUEST,
            "source id collides with an upstream id",
            AuditError::new("bad_request", "source id collides with an upstream id"),
        ));
    }
    match store.get_tenant(tenant_id).await {
        Ok(Some(t)) if t.enabled => Ok(()),
        Ok(_) => Err(TenantPutToolSourceOutcome::fail(
            StatusCode::UNAUTHORIZED,
            "invalid tenant",
            AuditError::new("unauthorized", "invalid tenant"),
        )),
        Err(e) => {
            let msg = e.to_string();
            Err(TenantPutToolSourceOutcome::fail(
                StatusCode::INTERNAL_SERVER_ERROR,
                msg.clone(),
                AuditError::new("internal_error", msg),
            ))
        }
    }
}

async fn tenant_put_tool_source_inner(
    state: &TenantState,
    store: &dyn crate::store::AdminStore,
    tenant_id: &str,
    source_id: &str,
    body: PutToolSourceBody,
) -> TenantPutToolSourceOutcome {
    if let Err(outcome) =
        tenant_put_tool_source_validate_request(state, store, tenant_id, source_id).await
    {
        return outcome;
    }

    let (enabled, kind, spec_res, expected_revision) = match body {
        PutToolSourceBody::Http {
            enabled,
            config,
            expected_revision,
        } => (
            enabled,
            ToolSourceKind::Http,
            serde_json::to_value(&config),
            expected_revision,
        ),
        PutToolSourceBody::Openapi {
            enabled,
            config,
            expected_revision,
        } => (
            enabled,
            ToolSourceKind::Openapi,
            serde_json::to_value(&config),
            expected_revision,
        ),
    };
    let kind_for_meta = Some(format!("{kind:?}"));
    let enabled_for_meta = Some(enabled);

    let spec = match spec_res {
        Ok(v) => v,
        Err(e) => {
            let msg = e.to_string();
            return TenantPutToolSourceOutcome::fail_with_meta(
                StatusCode::INTERNAL_SERVER_ERROR,
                msg.clone(),
                AuditError::new("internal_error", msg),
                kind_for_meta,
                enabled_for_meta,
            );
        }
    };

    match store
        .put_tool_source(tenant_id, source_id, enabled, kind, spec, expected_revision)
        .await
    {
        Ok(()) => TenantPutToolSourceOutcome::ok(kind_for_meta, enabled_for_meta),
        Err(e)
            if e.is::<crate::store::ToolSourceRevisionConflict>()
                || e.is::<crate::store::ToolSourceAlreadyExists>() =>
        {
            TenantPutToolSourceOutcome::fail_with_meta(
                StatusCode::CONFLICT,
                e.to_string(),
                AuditError::new("revision_conflict", e.to_string()),
                kind_for_meta,
                enabled_for_meta,
            )
        }
        Err(e) => {
            let msg = e.to_string();
            TenantPutToolSourceOutcome::fail_with_meta(
                StatusCode::INTERNAL_SERVER_ERROR,
                msg.clone(),
                AuditError::new("internal_error", msg),
                kind_for_meta,
                enabled_for_meta,
            )
        }
    }
}

async fn delete_tool_source(
    axum::Extension(state): axum::Extension<Arc<TenantState>>,
    headers: HeaderMap,
    Path(source_id): Path<String>,
) -> impl IntoResponse {
    let tenant_id = match authn(&headers, &state.signer) {
        Ok(t) => t,
        Err(resp) => return resp.into_response(),
    };
    let Some(store) = &state.store else {
        return ApiError::store_unavailable(StoreKind::Tenant).into_response();
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
            ApiError::not_found(Resource::ToolSource).into_response(),
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
            tenant_id: tenant_id_for_audit,
            actor: AuditActor::default(),
            action: "tenant.tool_source_delete",
            http_method: "DELETE",
            http_route: routes::tenant::TOOL_SOURCE.template(),
            status_code: i32::from(status.as_u16()),
            ok,
            elapsed: started.elapsed(),
            meta: serde_json::json!({
                "source_id": source_id_for_meta,
            }),
            error,
        }))
        .await;

    resp
}

async fn list_secrets(
    axum::Extension(state): axum::Extension<Arc<TenantState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let tenant_id = match authn(&headers, &state.signer) {
        Ok(t) => t,
        Err(resp) => return resp.into_response(),
    };
    let Some(store) = &state.store else {
        return ApiError::store_unavailable(StoreKind::Tenant).into_response();
    };

    match store.list_secrets(&tenant_id).await {
        Ok(secrets) => Json(SecretsResponse { secrets }).into_response(),
        Err(e) => ApiError::internal(e).into_response(),
    }
}

async fn put_secret(
    axum::Extension(state): axum::Extension<Arc<TenantState>>,
    headers: HeaderMap,
    Json(req): Json<PutSecretRequest>,
) -> impl IntoResponse {
    let tenant_id = match authn(&headers, &state.signer) {
        Ok(t) => t,
        Err(resp) => return resp.into_response(),
    };
    let Some(store) = &state.store else {
        return ApiError::store_unavailable(StoreKind::Tenant).into_response();
    };
    let started = Instant::now();
    let tenant_id_for_audit = tenant_id.clone();
    let name_for_meta = req.name.clone();
    let value_len = req.value.len();

    if req.name.trim().is_empty() {
        let status = StatusCode::BAD_REQUEST;
        let resp = (status, "secret name is required").into_response();
        state
            .audit
            .record(crate::audit::http_event(HttpAuditEvent {
                tenant_id: tenant_id_for_audit,
                actor: AuditActor::default(),
                action: "tenant.secret_put",
                http_method: "PUT",
                http_route: routes::tenant::SECRETS.template(),
                status_code: i32::from(status.as_u16()),
                ok: false,
                elapsed: started.elapsed(),
                meta: serde_json::json!({
                    "name": req.name,
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
                action: "tenant.secret_put",
                http_method: "PUT",
                http_route: routes::tenant::SECRETS.template(),
                status_code: i32::from(status.as_u16()),
                ok: false,
                elapsed: started.elapsed(),
                meta: serde_json::json!({
                    "name": req.name,
                    "value_len": value_len,
                }),
                error: Some(AuditError::new("bad_request", "secret value is required")),
            }))
            .await;
        return resp;
    }

    let (status, ok, error, resp) = match store.put_secret(&tenant_id, &req.name, &req.value).await
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
                ApiError::internal(msg).into_response(),
            )
        }
    };

    state
        .audit
        .record(crate::audit::http_event(HttpAuditEvent {
            tenant_id: tenant_id_for_audit,
            actor: AuditActor::default(),
            action: "tenant.secret_put",
            http_method: "PUT",
            http_route: routes::tenant::SECRETS.template(),
            status_code: i32::from(status.as_u16()),
            ok,
            elapsed: started.elapsed(),
            meta: serde_json::json!({
                "name": name_for_meta,
                "value_len": value_len,
            }),
            error,
        }))
        .await;

    resp
}

async fn delete_secret(
    axum::Extension(state): axum::Extension<Arc<TenantState>>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> impl IntoResponse {
    let tenant_id = match authn(&headers, &state.signer) {
        Ok(t) => t,
        Err(resp) => return resp.into_response(),
    };
    let Some(store) = &state.store else {
        return ApiError::store_unavailable(StoreKind::Tenant).into_response();
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
            ApiError::not_found(Resource::Secret).into_response(),
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
            tenant_id: tenant_id_for_audit,
            actor: AuditActor::default(),
            action: "tenant.secret_delete",
            http_method: "DELETE",
            http_route: routes::tenant::SECRET.template(),
            status_code: i32::from(status.as_u16()),
            ok,
            elapsed: started.elapsed(),
            meta: serde_json::json!({
                "name": name_for_meta,
            }),
            error,
        }))
        .await;

    resp
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ApiKeysResponse {
    api_keys: Vec<ApiKeyMetadata>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateApiKeyRequest {
    /// Display name/label for the key (not secret).
    #[serde(default)]
    name: Option<String>,
    /// If set, key is scoped to the specific profile. If omitted, key is tenant-wide.
    #[serde(default)]
    profile_id: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateApiKeyResponse {
    ok: bool,
    id: String,
    /// Returned only once. We do NOT store or return it again.
    secret: String,
    prefix: String,
    profile_id: Option<String>,
}

async fn list_api_keys(
    axum::Extension(state): axum::Extension<Arc<TenantState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let tenant_id = match authn(&headers, &state.signer) {
        Ok(t) => t,
        Err(resp) => return resp.into_response(),
    };
    let Some(store) = &state.store else {
        return ApiError::store_unavailable(StoreKind::Tenant).into_response();
    };
    if let Err(resp) = ensure_enabled_tenant(store, &tenant_id).await {
        return resp;
    }

    match store.list_api_keys(&tenant_id).await {
        Ok(api_keys) => Json(ApiKeysResponse { api_keys }).into_response(),
        Err(e) => ApiError::internal(e).into_response(),
    }
}

async fn create_api_key(
    axum::Extension(state): axum::Extension<Arc<TenantState>>,
    headers: HeaderMap,
    Json(req): Json<CreateApiKeyRequest>,
) -> impl IntoResponse {
    let tenant_id = match authn(&headers, &state.signer) {
        Ok(t) => t,
        Err(resp) => return resp.into_response(),
    };
    let Some(store) = &state.store else {
        return ApiError::store_unavailable(StoreKind::Tenant).into_response();
    };
    if let Err(resp) = ensure_enabled_tenant(store, &tenant_id).await {
        return resp;
    }
    let started = Instant::now();
    let outcome = tenant_create_api_key_inner(store.as_ref(), &tenant_id, req).await;

    state
        .audit
        .record(crate::audit::http_event(HttpAuditEvent {
            tenant_id: tenant_id.clone(),
            actor: AuditActor {
                profile_id: outcome.profile_uuid,
                api_key_id: outcome.api_key_uuid,
                ..AuditActor::default()
            },
            action: "tenant.api_key_create",
            http_method: "POST",
            http_route: routes::tenant::API_KEYS.template(),
            status_code: i32::from(outcome.status.as_u16()),
            ok: outcome.status.is_success(),
            elapsed: started.elapsed(),
            meta: serde_json::json!({
                "api_key_id": outcome.api_key_id_for_meta,
                "name": outcome.name_for_meta,
                "prefix": outcome.prefix_for_meta,
                "profile_id": outcome.profile_id_for_meta,
            }),
            error: outcome.error,
        }))
        .await;

    outcome.resp
}

struct TenantCreateApiKeyOutcome {
    resp: axum::response::Response,
    status: StatusCode,
    error: Option<AuditError>,
    profile_uuid: Option<Uuid>,
    api_key_uuid: Option<Uuid>,
    api_key_id_for_meta: Option<String>,
    name_for_meta: Option<String>,
    prefix_for_meta: Option<String>,
    profile_id_for_meta: Option<String>,
}

impl TenantCreateApiKeyOutcome {
    fn fail(
        status: StatusCode,
        message: impl Into<String>,
        error: AuditError,
        profile_id_for_meta: Option<String>,
        profile_uuid: Option<Uuid>,
    ) -> Self {
        let msg = message.into();
        Self {
            resp: (status, msg.clone()).into_response(),
            status,
            error: Some(error),
            profile_uuid,
            api_key_uuid: None,
            api_key_id_for_meta: None,
            name_for_meta: None,
            prefix_for_meta: None,
            profile_id_for_meta,
        }
    }
}

async fn tenant_create_api_key_inner(
    store: &dyn crate::store::AdminStore,
    tenant_id: &str,
    req: CreateApiKeyRequest,
) -> TenantCreateApiKeyOutcome {
    let profile_uuid = req
        .profile_id
        .as_deref()
        .and_then(|p| Uuid::parse_str(p).ok());
    let profile_id_for_meta = req.profile_id.clone();

    let name = req.name.as_deref().unwrap_or("default").trim().to_string();
    if name.is_empty() {
        return TenantCreateApiKeyOutcome::fail(
            StatusCode::BAD_REQUEST,
            "name is required",
            AuditError::new("bad_request", "name is required"),
            profile_id_for_meta,
            profile_uuid,
        );
    }

    if let Some(profile_id) = req.profile_id.as_deref()
        && let Err(outcome) =
            tenant_validate_profile_for_api_key(store, tenant_id, profile_id, profile_uuid).await
    {
        return outcome;
    }

    let api_key_id = Uuid::new_v4().to_string();
    let api_key_uuid = Uuid::parse_str(&api_key_id).ok();
    let secret = generate_api_key_secret();
    let prefix = api_key_prefix(&secret);
    let secret_hash = hex::encode(sha2::Sha256::digest(secret.as_bytes()));

    if let Err(e) = store
        .put_api_key(
            tenant_id,
            &api_key_id,
            req.profile_id.as_deref(),
            &name,
            &prefix,
            &secret_hash,
        )
        .await
    {
        let msg = e.to_string();
        return TenantCreateApiKeyOutcome {
            resp: (StatusCode::INTERNAL_SERVER_ERROR, msg.clone()).into_response(),
            status: StatusCode::INTERNAL_SERVER_ERROR,
            error: Some(AuditError::new("internal_error", msg)),
            profile_uuid,
            api_key_uuid,
            api_key_id_for_meta: Some(api_key_id),
            name_for_meta: Some(name),
            prefix_for_meta: Some(prefix),
            profile_id_for_meta,
        };
    }

    TenantCreateApiKeyOutcome {
        resp: Json(CreateApiKeyResponse {
            ok: true,
            id: api_key_id.clone(),
            secret,
            prefix: prefix.clone(),
            profile_id: req.profile_id,
        })
        .into_response(),
        status: StatusCode::OK,
        error: None,
        profile_uuid,
        api_key_uuid,
        api_key_id_for_meta: Some(api_key_id),
        name_for_meta: Some(name),
        prefix_for_meta: Some(prefix),
        profile_id_for_meta,
    }
}

async fn tenant_validate_profile_for_api_key(
    store: &dyn crate::store::AdminStore,
    tenant_id: &str,
    profile_id: &str,
    profile_uuid: Option<Uuid>,
) -> Result<(), TenantCreateApiKeyOutcome> {
    // UUIDv4 only, otherwise 404 (avoid enumeration patterns).
    if Uuid::parse_str(profile_id)
        .ok()
        .and_then(|u| (u.get_version() == Some(Version::Random)).then_some(u))
        .is_none()
    {
        return Err(TenantCreateApiKeyOutcome::fail(
            StatusCode::NOT_FOUND,
            "profile not found",
            AuditError::new("not_found", "profile not found"),
            Some(profile_id.to_string()),
            profile_uuid,
        ));
    }

    match store.get_profile(profile_id).await {
        Ok(Some(p)) if p.tenant_id == tenant_id && p.enabled => Ok(()),
        Ok(_) => Err(TenantCreateApiKeyOutcome::fail(
            StatusCode::NOT_FOUND,
            "profile not found",
            AuditError::new("not_found", "profile not found"),
            Some(profile_id.to_string()),
            profile_uuid,
        )),
        Err(e) => {
            let msg = e.to_string();
            Err(TenantCreateApiKeyOutcome::fail(
                StatusCode::INTERNAL_SERVER_ERROR,
                msg.clone(),
                AuditError::new("internal_error", msg),
                Some(profile_id.to_string()),
                profile_uuid,
            ))
        }
    }
}

async fn revoke_api_key(
    axum::Extension(state): axum::Extension<Arc<TenantState>>,
    headers: HeaderMap,
    Path(api_key_id): Path<String>,
) -> impl IntoResponse {
    let tenant_id = match authn(&headers, &state.signer) {
        Ok(t) => t,
        Err(resp) => return resp.into_response(),
    };
    let Some(store) = &state.store else {
        return ApiError::store_unavailable(StoreKind::Tenant).into_response();
    };
    if let Err(resp) = ensure_enabled_tenant(store, &tenant_id).await {
        return resp;
    }
    let started = Instant::now();

    let tenant_id_for_audit = tenant_id.clone();
    let api_key_uuid = Uuid::parse_str(&api_key_id).ok();
    let api_key_id_for_meta = api_key_id.clone();
    let (status, ok, error, resp) = match store.revoke_api_key(&tenant_id, &api_key_id).await {
        Ok(true) => (
            StatusCode::OK,
            true,
            None,
            Json(OkResponse { ok: true }).into_response(),
        ),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            false,
            Some(AuditError::new("not_found", "api key not found")),
            (StatusCode::NOT_FOUND, "api key not found").into_response(),
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
            tenant_id: tenant_id_for_audit,
            actor: AuditActor {
                api_key_id: api_key_uuid,
                ..AuditActor::default()
            },
            action: "tenant.api_key_revoke",
            http_method: "DELETE",
            http_route: routes::tenant::API_KEY.template(),
            status_code: i32::from(status.as_u16()),
            ok,
            elapsed: started.elapsed(),
            meta: serde_json::json!({
                "api_key_id": api_key_id_for_meta,
            }),
            error,
        }))
        .await;

    resp
}

async fn get_audit_settings(
    axum::Extension(state): axum::Extension<Arc<TenantState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let tenant_id = match authn(&headers, &state.signer) {
        Ok(t) => t,
        Err(resp) => return resp.into_response(),
    };
    let Some(store) = &state.store else {
        return ApiError::store_unavailable(StoreKind::Tenant).into_response();
    };

    // Ensure tenant exists + enabled.
    match store.get_tenant(&tenant_id).await {
        Ok(Some(t)) if t.enabled => {}
        Ok(_) => return ApiError::invalid_tenant().into_response(),
        Err(e) => return ApiError::internal(e).into_response(),
    }

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

async fn put_audit_settings(
    axum::Extension(state): axum::Extension<Arc<TenantState>>,
    headers: HeaderMap,
    Json(req): Json<PutTenantAuditSettingsRequest>,
) -> impl IntoResponse {
    let tenant_id = match authn(&headers, &state.signer) {
        Ok(t) => t,
        Err(resp) => return resp.into_response(),
    };
    let Some(store) = &state.store else {
        return ApiError::store_unavailable(StoreKind::Tenant).into_response();
    };

    // Ensure tenant exists + enabled.
    match store.get_tenant(&tenant_id).await {
        Ok(Some(t)) if t.enabled => {}
        Ok(_) => return ApiError::invalid_tenant().into_response(),
        Err(e) => return ApiError::internal(e).into_response(),
    }

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

    match store.put_tenant_audit_settings(&tenant_id, &settings).await {
        Ok(()) => {
            // Keep per-tenant audit level cache coherent on this node.
            state.invalidation.apply_local(
                &crate::pg_invalidation::InvalidationEvent::TenantAuditSettings {
                    tenant_id: tenant_id.clone(),
                },
            );
            Json(OkResponse { ok: true }).into_response()
        }
        Err(e) => {
            let msg = e.to_string();
            ApiError::internal(msg).into_response()
        }
    }
}

async fn get_transport_limits(
    axum::Extension(state): axum::Extension<Arc<TenantState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let tenant_id = match authn(&headers, &state.signer) {
        Ok(t) => t,
        Err(resp) => return resp.into_response(),
    };
    let Some(store) = &state.store else {
        return ApiError::store_unavailable(StoreKind::Tenant).into_response();
    };

    // Ensure tenant exists + enabled.
    match store.get_tenant(&tenant_id).await {
        Ok(Some(t)) if t.enabled => {}
        Ok(_) => return ApiError::invalid_tenant().into_response(),
        Err(e) => return ApiError::internal(e).into_response(),
    }

    match store.get_tenant_transport_limits(&tenant_id).await {
        Ok(Some(limits)) => Json(limits).into_response(),
        Ok(None) => ApiError::not_found(Resource::Tenant).into_response(),
        Err(e) => ApiError::internal(e).into_response(),
    }
}

async fn put_transport_limits(
    axum::Extension(state): axum::Extension<Arc<TenantState>>,
    headers: HeaderMap,
    Json(req): Json<TransportLimitsSettings>,
) -> impl IntoResponse {
    let tenant_id = match authn(&headers, &state.signer) {
        Ok(t) => t,
        Err(resp) => return resp.into_response(),
    };
    let Some(store) = &state.store else {
        return ApiError::store_unavailable(StoreKind::Tenant).into_response();
    };

    // Ensure tenant exists + enabled.
    match store.get_tenant(&tenant_id).await {
        Ok(Some(t)) if t.enabled => {}
        Ok(_) => return ApiError::invalid_tenant().into_response(),
        Err(e) => return ApiError::internal(e).into_response(),
    }

    if let Err(msg) = crate::transport_limits::validate_transport_limits_settings(&req) {
        return (StatusCode::BAD_REQUEST, msg).into_response();
    }

    match store.put_tenant_transport_limits(&tenant_id, &req).await {
        Ok(()) => Json(OkResponse { ok: true }).into_response(),
        Err(e) => {
            let msg = e.to_string();
            ApiError::internal(msg).into_response()
        }
    }
}

async fn list_audit_events(
    axum::Extension(state): axum::Extension<Arc<TenantState>>,
    headers: HeaderMap,
    axum::extract::Query(q): axum::extract::Query<AuditEventsQuery>,
) -> impl IntoResponse {
    let tenant_id = match authn(&headers, &state.signer) {
        Ok(t) => t,
        Err(resp) => return resp.into_response(),
    };
    let Some(store) = &state.store else {
        return ApiError::store_unavailable(StoreKind::Tenant).into_response();
    };

    // Ensure tenant exists + enabled.
    match store.get_tenant(&tenant_id).await {
        Ok(Some(t)) if t.enabled => {}
        Ok(_) => return ApiError::invalid_tenant().into_response(),
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

async fn tool_call_stats_by_tool(
    axum::Extension(state): axum::Extension<Arc<TenantState>>,
    headers: HeaderMap,
    axum::extract::Query(q): axum::extract::Query<AuditStatsQuery>,
) -> impl IntoResponse {
    let tenant_id = match authn(&headers, &state.signer) {
        Ok(t) => t,
        Err(resp) => return resp.into_response(),
    };
    let Some(store) = &state.store else {
        return ApiError::store_unavailable(StoreKind::Tenant).into_response();
    };

    match store.get_tenant(&tenant_id).await {
        Ok(Some(t)) if t.enabled => {}
        Ok(_) => return ApiError::invalid_tenant().into_response(),
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

async fn tool_call_stats_by_api_key(
    axum::Extension(state): axum::Extension<Arc<TenantState>>,
    headers: HeaderMap,
    axum::extract::Query(q): axum::extract::Query<AuditStatsQuery>,
) -> impl IntoResponse {
    let tenant_id = match authn(&headers, &state.signer) {
        Ok(t) => t,
        Err(resp) => return resp.into_response(),
    };
    let Some(store) = &state.store else {
        return ApiError::store_unavailable(StoreKind::Tenant).into_response();
    };

    match store.get_tenant(&tenant_id).await {
        Ok(Some(t)) if t.enabled => {}
        Ok(_) => return ApiError::invalid_tenant().into_response(),
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

async fn get_profile_audit_settings(
    axum::Extension(state): axum::Extension<Arc<TenantState>>,
    headers: HeaderMap,
    Path(profile_id): Path<String>,
) -> impl IntoResponse {
    let tenant_id = match authn(&headers, &state.signer) {
        Ok(t) => t,
        Err(resp) => return resp.into_response(),
    };
    let Some(store) = &state.store else {
        return ApiError::store_unavailable(StoreKind::Tenant).into_response();
    };

    match store.get_tenant(&tenant_id).await {
        Ok(Some(tenant)) if tenant.enabled => {}
        Ok(_) => return ApiError::invalid_tenant().into_response(),
        Err(error) => return ApiError::internal(error).into_response(),
    }

    // UUIDv4 only, otherwise 404 (avoid enumeration patterns).
    if Uuid::parse_str(&profile_id)
        .ok()
        .and_then(|u| (u.get_version() == Some(Version::Random)).then_some(u))
        .is_none()
    {
        return ApiError::not_found(Resource::Profile).into_response();
    }

    // Cross-tenant guard (404 on mismatch).
    match store.get_profile(&profile_id).await {
        Ok(Some(p)) if p.tenant_id == tenant_id => {}
        Ok(_) => return ApiError::not_found(Resource::Profile).into_response(),
        Err(e) => return ApiError::internal(e).into_response(),
    }

    match store
        .get_profile_audit_settings(&tenant_id, &profile_id)
        .await
    {
        Ok(Some(v)) => Json(v).into_response(),
        Ok(None) => ApiError::not_found(Resource::Profile).into_response(),
        Err(e) => ApiError::internal(e).into_response(),
    }
}

async fn put_profile_audit_settings(
    axum::Extension(state): axum::Extension<Arc<TenantState>>,
    headers: HeaderMap,
    Path(profile_id): Path<String>,
    Json(req): Json<PutProfileAuditSettingsRequest>,
) -> impl IntoResponse {
    let tenant_id = match authn(&headers, &state.signer) {
        Ok(t) => t,
        Err(resp) => return resp.into_response(),
    };
    let Some(store) = &state.store else {
        return ApiError::store_unavailable(StoreKind::Tenant).into_response();
    };
    let started = Instant::now();

    match store.get_tenant(&tenant_id).await {
        Ok(Some(tenant)) if tenant.enabled => {}
        Ok(_) => return ApiError::invalid_tenant().into_response(),
        Err(error) => return ApiError::internal(error).into_response(),
    }

    // UUIDv4 only, otherwise 404 (avoid enumeration patterns).
    let profile_uuid = match Uuid::parse_str(&profile_id) {
        Ok(u) if u.get_version() == Some(Version::Random) => u,
        _ => return ApiError::not_found(Resource::Profile).into_response(),
    };

    // Cross-tenant guard (404 on mismatch).
    match store.get_profile(&profile_id).await {
        Ok(Some(p)) if p.tenant_id == tenant_id => {}
        Ok(_) => return ApiError::not_found(Resource::Profile).into_response(),
        Err(e) => return ApiError::internal(e).into_response(),
    }

    let audit_settings = match serde_json::from_value::<
        unrelated_gateway_api::audit::ProfileAuditSettings,
    >(req.audit_settings.clone())
    {
        Ok(settings) => settings,
        Err(error) => return (StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    };

    let (status, ok, error, resp) = match store
        .put_profile_audit_settings(
            &tenant_id,
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
            tenant_id: tenant_id.clone(),
            actor: AuditActor {
                profile_id: Some(profile_uuid),
                ..AuditActor::default()
            },
            action: "tenant.profile_audit_settings_put",
            http_method: "PUT",
            http_route: routes::tenant::PROFILE_AUDIT.template(),
            status_code: i32::from(status.as_u16()),
            ok,
            elapsed: started.elapsed(),
            meta: serde_json::json!({
                "profile_id": profile_id,
                "audit_settings": req.audit_settings,
            }),
            error,
        }))
        .await;

    resp
}

fn generate_api_key_secret() -> String {
    // 32 bytes of randomness using UUIDv4 (backed by `getrandom`).
    let mut bytes = Vec::with_capacity(32);
    bytes.extend_from_slice(Uuid::new_v4().as_bytes());
    bytes.extend_from_slice(Uuid::new_v4().as_bytes());
    let b64 = URL_SAFE_NO_PAD.encode(bytes);
    format!("ugw_sk_{b64}")
}

fn api_key_prefix(secret: &str) -> String {
    // Prefix is for UX/debugging only (not sensitive). Keep it short and stable.
    secret.chars().take(12).collect()
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IssueTenantTokenRequest {
    pub tenant_id: String,
    /// TTL in seconds. Defaults to 365 days.
    #[serde(default)]
    pub ttl_seconds: Option<u64>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IssueTenantTokenResponse {
    pub ok: bool,
    pub tenant_id: String,
    pub token: String,
    pub exp_unix_secs: u64,
}

pub fn now_unix_secs() -> anyhow::Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| anyhow::anyhow!("system clock is before UNIX_EPOCH"))?
        .as_secs())
}

#[cfg(test)]
mod tests {

    #[test]
    fn upstream_activity_ttl_uses_request_override_and_clamps_to_minimum() {
        assert_eq!(
            crate::pg_store::resolve_upstream_session_activity_ttl_secs(Some(300)),
            300
        );
        assert_eq!(
            crate::pg_store::resolve_upstream_session_activity_ttl_secs(Some(0)),
            1
        );
    }
}
