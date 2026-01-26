use crate::profile_http::{
    DataPlaneAuthSettings, DataPlaneLimitsSettings, NullableString, NullableU64,
    default_data_plane_auth_mode, default_true, resolve_nullable_u64, validate_tool_allowlist,
    validate_tool_timeout_and_policies,
};
use crate::store::{
    AdminProfile, AdminStore, AdminUpstream, ApiKeyMetadata, DataPlaneAuthMode, McpProfileSettings,
    TenantSecretMetadata, ToolSourceKind, UpstreamEndpoint,
};
use crate::tenant_token::TenantSigner;
use crate::tool_policy::ToolPolicy;
use axum::extract::Path;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{delete, get};
use axum::{Json, Router};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rmcp::model::Tool;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Digest as _;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
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
    pub signer: TenantSigner,
    pub shared_source_ids: Arc<std::collections::HashSet<String>>,
    /// Shared MCP data-plane state (used for profile surface probing).
    pub mcp_state: Arc<crate::mcp::McpState>,
}

pub fn router(state: Arc<TenantState>) -> Router {
    Router::new()
        .route("/tenant/v1/upstreams", get(list_upstreams))
        .route(
            "/tenant/v1/upstreams/{upstream_id}",
            get(get_upstream).put(put_upstream).delete(delete_upstream),
        )
        .route(
            "/tenant/v1/upstreams/{upstream_id}/surface",
            get(get_upstream_surface),
        )
        .route(
            "/tenant/v1/profiles",
            get(list_profiles).post(create_profile),
        )
        .route(
            "/tenant/v1/profiles/{profile_id}",
            get(get_profile).put(put_profile).delete(delete_profile),
        )
        .route(
            "/tenant/v1/profiles/{profile_id}/surface",
            get(get_profile_surface),
        )
        .route("/tenant/v1/tool-sources", get(list_tool_sources))
        .route(
            "/tenant/v1/tool-sources/{source_id}/tools",
            get(get_tool_source_tools),
        )
        .route(
            "/tenant/v1/tool-sources/{source_id}",
            get(get_tool_source)
                .put(put_tool_source)
                .delete(delete_tool_source),
        )
        .route(
            "/tenant/v1/tool-sources/openapi/inspect",
            axum::routing::post(openapi_inspect),
        )
        .route(
            "/tenant/v1/tool-sources/validate-id",
            axum::routing::post(validate_source_id),
        )
        .route("/tenant/v1/secrets", get(list_secrets).post(put_secret))
        .route("/tenant/v1/secrets/{name}", delete(delete_secret))
        .route(
            "/tenant/v1/api-keys",
            get(list_api_keys).post(create_api_key),
        )
        .route("/tenant/v1/api-keys/{api_key_id}", delete(revoke_api_key))
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

fn tenant_upstream_internal_id(tenant_id: &str, upstream_id: &str) -> String {
    let t = URL_SAFE_NO_PAD.encode(tenant_id);
    let u = URL_SAFE_NO_PAD.encode(upstream_id);
    format!("{TENANT_UPSTREAM_ID_PREFIX}{t}.{u}")
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
        });
    }

    // Global upstreams: visible to tenants for attachment (but only editable by admin API).
    Some(UpstreamResponse {
        id: u.id,
        owner: "global".to_string(),
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
        return (StatusCode::SERVICE_UNAVAILABLE, "Tenant store unavailable").into_response();
    };

    // Ensure tenant exists + enabled.
    match store.get_tenant(&tenant_id).await {
        Ok(Some(t)) if t.enabled => {}
        Ok(_) => return (StatusCode::UNAUTHORIZED, "invalid tenant").into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }

    match store.list_upstreams().await {
        Ok(upstreams) => {
            let upstreams = upstreams
                .into_iter()
                .filter_map(|u| upstream_to_response(&tenant_id, u))
                .collect();
            Json(UpstreamsResponse { upstreams }).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
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
        return (StatusCode::SERVICE_UNAVAILABLE, "Tenant store unavailable").into_response();
    };

    // Prefer tenant-owned upstream if present; otherwise fall back to global.
    let internal_id = tenant_upstream_internal_id(&tenant_id, &upstream_id);
    let u = match store.get_upstream(&internal_id).await {
        Ok(Some(u)) => Some(u),
        Ok(None) => match store.get_upstream(&upstream_id).await {
            Ok(Some(u)) => Some(u),
            Ok(None) => None,
            Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        },
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let Some(u) = u else {
        return (StatusCode::NOT_FOUND, "upstream not found").into_response();
    };

    let Some(resp) = upstream_to_response(&tenant_id, u) else {
        return (StatusCode::NOT_FOUND, "upstream not found").into_response();
    };
    Json(resp).into_response()
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
        return (StatusCode::SERVICE_UNAVAILABLE, "Tenant store unavailable").into_response();
    };

    // Ensure tenant exists + enabled.
    match store.get_tenant(&tenant_id).await {
        Ok(Some(t)) if t.enabled => {}
        Ok(_) => return (StatusCode::UNAUTHORIZED, "invalid tenant").into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
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
            auth: e.auth,
        })
        .collect();

    let internal_id = tenant_upstream_internal_id(&tenant_id, &upstream_id);
    if let Err(e) = store
        .put_upstream(&internal_id, req.enabled, &endpoints)
        .await
    {
        return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
    }
    (StatusCode::CREATED, Json(serde_json::json!({"ok": true}))).into_response()
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
        return (StatusCode::SERVICE_UNAVAILABLE, "Tenant store unavailable").into_response();
    };

    let internal_id = tenant_upstream_internal_id(&tenant_id, &upstream_id);
    match store.delete_upstream(&internal_id).await {
        Ok(true) => Json(serde_json::json!({"ok": true})).into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, "upstream not found").into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
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
    #[serde(default)]
    auth: Option<AuthConfig>,
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
struct UpstreamResponse {
    id: String,
    /// "tenant" for tenant-owned upstreams, "global" for admin-provisioned upstreams.
    owner: String,
    enabled: bool,
    endpoints: Vec<UpstreamEndpointResponse>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct UpstreamsResponse {
    upstreams: Vec<UpstreamResponse>,
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
        data_plane_auth: DataPlaneAuthSettings {
            mode: p.data_plane_auth_mode,
            accept_x_api_key: p.accept_x_api_key,
        },
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

async fn create_profile(
    axum::Extension(state): axum::Extension<Arc<TenantState>>,
    headers: HeaderMap,
    Json(req): Json<CreateProfileRequest>,
) -> impl IntoResponse {
    const OIDC_NOT_CONFIGURED_MSG: &str = "JWT/OIDC is unavailable because OIDC is not configured on the Gateway (missing UNRELATED_GATEWAY_OIDC_ISSUER). Configure OIDC or choose a different mode.";

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
    if req.name.trim().is_empty() {
        return (StatusCode::BAD_REQUEST, "name is required").into_response();
    }
    let resolved_upstreams =
        match resolve_upstream_ids_for_tenant(store.as_ref(), &tenant_id, &req.upstreams).await {
            Ok(v) => v,
            Err(resp) => return resp,
        };
    if let Err(resp) =
        validate_no_self_upstream_loop(store.as_ref(), &profile_id, &resolved_upstreams).await
    {
        return resp;
    }
    let enabled_tools = req.tools.unwrap_or_default();
    let data_plane_auth = req.data_plane_auth.unwrap_or(DataPlaneAuthSettings {
        mode: default_data_plane_auth_mode(),
        accept_x_api_key: default_true(),
    });
    if data_plane_auth.mode == DataPlaneAuthMode::JwtEveryRequest && state.mcp_state.oidc.is_none()
    {
        return (StatusCode::BAD_REQUEST, OIDC_NOT_CONFIGURED_MSG).into_response();
    }
    let data_plane_limits = req.data_plane_limits.unwrap_or(DataPlaneLimitsSettings {
        rate_limit_enabled: false,
        rate_limit_tool_calls_per_minute: None,
        quota_enabled: false,
        quota_tool_calls: None,
    });
    if let Err(msg) = data_plane_limits.validate() {
        return (StatusCode::BAD_REQUEST, msg).into_response();
    }

    // Tool call timeouts + per-tool policies (timeouts + retry policy).
    let tool_call_timeout_secs = req.tool_call_timeout_secs;
    let tool_policies = req.tool_policies.clone();
    let mcp = req.mcp.clone();
    if let Err(msg) = validate_tool_timeout_and_policies(tool_call_timeout_secs, &tool_policies) {
        return (StatusCode::BAD_REQUEST, msg).into_response();
    }
    if let Err(msg) = validate_tool_allowlist(&enabled_tools) {
        return (StatusCode::BAD_REQUEST, msg).into_response();
    }

    if let Err(e) = store
        .put_profile(
            &profile_id,
            &tenant_id,
            &req.name,
            req.description.as_deref(),
            req.enabled,
            req.allow_partial_upstreams,
            &resolved_upstreams,
            &req.sources,
            &req.transforms,
            &enabled_tools,
            data_plane_auth.mode,
            data_plane_auth.accept_x_api_key,
            data_plane_limits.rate_limit_enabled,
            data_plane_limits.rate_limit_tool_calls_per_minute,
            data_plane_limits.quota_enabled,
            data_plane_limits.quota_tool_calls,
            tool_call_timeout_secs,
            &tool_policies,
            &mcp,
        )
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

#[allow(clippy::too_many_lines)]
async fn put_profile(
    axum::Extension(state): axum::Extension<Arc<TenantState>>,
    headers: HeaderMap,
    Path(profile_id): Path<String>,
    Json(req): Json<PutProfileRequest>,
) -> impl IntoResponse {
    const OIDC_NOT_CONFIGURED_MSG: &str = "JWT/OIDC is unavailable because OIDC is not configured on the Gateway (missing UNRELATED_GATEWAY_OIDC_ISSUER). Configure OIDC or choose a different mode.";

    let tenant_id = match authn(&headers, &state.signer) {
        Ok(t) => t,
        Err(resp) => return resp.into_response(),
    };
    let Some(store) = &state.store else {
        return (StatusCode::SERVICE_UNAVAILABLE, "Tenant store unavailable").into_response();
    };

    let profile_uuid = match Uuid::parse_str(&profile_id) {
        Ok(u) if u.get_version() == Some(Version::Random) => u,
        _ => return (StatusCode::NOT_FOUND, "profile not found").into_response(),
    };

    // Cross-tenant guard (404 on mismatch).
    let existing = match store.get_profile(&profile_id).await {
        Ok(Some(p)) if p.tenant_id == tenant_id => p,
        Ok(_) => return (StatusCode::NOT_FOUND, "profile not found").into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    let name = req.name.unwrap_or_else(|| existing.name.clone());
    if name.trim().is_empty() {
        return (StatusCode::BAD_REQUEST, "name is required").into_response();
    }
    let description: Option<String> = match req.description {
        None => existing.description.clone(),
        Some(NullableString::Null) => None,
        Some(NullableString::Value(v)) => Some(v),
    };
    let resolved_upstreams =
        match resolve_upstream_ids_for_tenant(store.as_ref(), &tenant_id, &req.upstreams).await {
            Ok(v) => v,
            Err(resp) => return resp,
        };
    if let Err(resp) =
        validate_no_self_upstream_loop(store.as_ref(), &profile_id, &resolved_upstreams).await
    {
        return resp;
    }
    let enabled_tools = req.tools.unwrap_or_default();
    let data_plane_auth = req.data_plane_auth.unwrap_or(DataPlaneAuthSettings {
        mode: existing.data_plane_auth_mode,
        accept_x_api_key: existing.accept_x_api_key,
    });
    if data_plane_auth.mode == DataPlaneAuthMode::JwtEveryRequest && state.mcp_state.oidc.is_none()
    {
        return (StatusCode::BAD_REQUEST, OIDC_NOT_CONFIGURED_MSG).into_response();
    }
    let data_plane_limits = req.data_plane_limits.unwrap_or(DataPlaneLimitsSettings {
        rate_limit_enabled: existing.rate_limit_enabled,
        rate_limit_tool_calls_per_minute: existing.rate_limit_tool_calls_per_minute,
        quota_enabled: existing.quota_enabled,
        quota_tool_calls: existing.quota_tool_calls,
    });
    if let Err(msg) = data_plane_limits.validate() {
        return (StatusCode::BAD_REQUEST, msg).into_response();
    }

    let tool_call_timeout_secs =
        resolve_nullable_u64(req.tool_call_timeout_secs, existing.tool_call_timeout_secs);
    let tool_policies = req
        .tool_policies
        .clone()
        .unwrap_or_else(|| existing.tool_policies.clone());

    let mcp = req.mcp.clone().unwrap_or_else(|| existing.mcp.clone());
    if let Err(msg) = validate_tool_timeout_and_policies(tool_call_timeout_secs, &tool_policies) {
        return (StatusCode::BAD_REQUEST, msg).into_response();
    }
    if let Err(msg) = validate_tool_allowlist(&enabled_tools) {
        return (StatusCode::BAD_REQUEST, msg).into_response();
    }

    if let Err(e) = store
        .put_profile(
            &profile_uuid.to_string(),
            &tenant_id,
            &name,
            description.as_deref(),
            req.enabled,
            req.allow_partial_upstreams,
            &resolved_upstreams,
            &req.sources,
            &req.transforms,
            &enabled_tools,
            data_plane_auth.mode,
            data_plane_auth.accept_x_api_key,
            data_plane_limits.rate_limit_enabled,
            data_plane_limits.rate_limit_tool_calls_per_minute,
            data_plane_limits.quota_enabled,
            data_plane_limits.quota_tool_calls,
            tool_call_timeout_secs,
            &tool_policies,
            &mcp,
        )
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

    Json(CreateProfileResponse {
        ok: true,
        data_plane_path: format!("/{profile_id}/mcp"),
        id: profile_id,
    })
    .into_response()
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

    // UUIDv4 only, otherwise 404 (avoid enumeration patterns).
    if Uuid::parse_str(&profile_id)
        .ok()
        .and_then(|u| (u.get_version() == Some(Version::Random)).then_some(u))
        .is_none()
    {
        return (StatusCode::NOT_FOUND, "profile not found").into_response();
    }

    // Cross-tenant guard (404 on mismatch).
    match store.get_profile(&profile_id).await {
        Ok(Some(p)) if p.tenant_id == tenant_id => {}
        Ok(_) => return (StatusCode::NOT_FOUND, "profile not found").into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }

    match store.delete_profile(&profile_id).await {
        Ok(true) => Json(OkResponse { ok: true }).into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, "profile not found").into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
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
        return (StatusCode::SERVICE_UNAVAILABLE, "Tenant store unavailable").into_response();
    };

    // Ensure tenant exists + enabled.
    match admin_store.get_tenant(&tenant_id).await {
        Ok(Some(t)) if t.enabled => {}
        Ok(_) => return (StatusCode::UNAUTHORIZED, "invalid tenant").into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }

    // Resolve upstream id: prefer tenant-owned, else global.
    let internal_id = tenant_upstream_internal_id(&tenant_id, &upstream_id);
    let resolved = match admin_store.get_upstream(&internal_id).await {
        Ok(Some(_)) => internal_id,
        Ok(None) => match admin_store.get_upstream(&upstream_id).await {
            Ok(Some(_)) => upstream_id.clone(),
            Ok(None) => return (StatusCode::NOT_FOUND, "upstream not found").into_response(),
            Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        },
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    let profile = crate::store::Profile {
        id: format!("probe-upstream:{upstream_id}"),
        tenant_id: tenant_id.clone(),
        allow_partial_upstreams: true,
        source_ids: vec![resolved],
        transforms: TransformPipeline::default(),
        enabled_tools: vec![],
        data_plane_auth_mode: DataPlaneAuthMode::Disabled,
        accept_x_api_key: true,
        rate_limit_enabled: false,
        rate_limit_tool_calls_per_minute: None,
        quota_enabled: false,
        quota_tool_calls: None,
        tool_call_timeout_secs: None,
        tool_policies: vec![],
        mcp: McpProfileSettings::default(),
    };

    let (sources, tools, _all_tools, resources, prompts) =
        match crate::mcp::probe_profile_surface(&state.mcp_state, &profile).await {
            Ok(r) => r,
            Err(e) => return (StatusCode::BAD_GATEWAY, e).into_response(),
        };

    let generated_at_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    Json(UpstreamSurfaceResponse {
        upstream_id,
        generated_at_unix,
        sources,
        tools,
        resources,
        prompts,
    })
    .into_response()
}

async fn get_profile_surface(
    axum::Extension(state): axum::Extension<Arc<TenantState>>,
    headers: HeaderMap,
    Path(profile_id): Path<String>,
) -> impl IntoResponse {
    let tenant_id = match authn(&headers, &state.signer) {
        Ok(t) => t,
        Err(resp) => return resp.into_response(),
    };

    // UUIDv4 only, otherwise 404 (avoid enumeration patterns).
    if Uuid::parse_str(&profile_id)
        .ok()
        .and_then(|u| (u.get_version() == Some(Version::Random)).then_some(u))
        .is_none()
    {
        return (StatusCode::NOT_FOUND, "profile not found").into_response();
    }

    // Ensure tenant exists + enabled (consistent with other tenant endpoints).
    let Some(admin_store) = &state.store else {
        return (StatusCode::SERVICE_UNAVAILABLE, "Tenant store unavailable").into_response();
    };
    match admin_store.get_tenant(&tenant_id).await {
        Ok(Some(t)) if t.enabled => {}
        Ok(_) => return (StatusCode::UNAUTHORIZED, "invalid tenant").into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }

    // IMPORTANT: allow probing surfaces for disabled profiles.
    // Disabled profiles are hidden from the data-plane store (and from /{profile_id}/mcp),
    // but operators still need to inspect their surface to configure/fix them.
    let admin_profile = match admin_store.get_profile(&profile_id).await {
        Ok(Some(p)) if p.tenant_id == tenant_id => p,
        Ok(_) => return (StatusCode::NOT_FOUND, "profile not found").into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    let mut source_ids = admin_profile.upstream_ids.clone();
    source_ids.extend(admin_profile.source_ids.clone());

    let profile = crate::store::Profile {
        id: admin_profile.id,
        tenant_id: admin_profile.tenant_id,
        allow_partial_upstreams: admin_profile.allow_partial_upstreams,
        source_ids,
        transforms: admin_profile.transforms,
        enabled_tools: admin_profile.enabled_tools,
        data_plane_auth_mode: admin_profile.data_plane_auth_mode,
        accept_x_api_key: admin_profile.accept_x_api_key,
        rate_limit_enabled: admin_profile.rate_limit_enabled,
        rate_limit_tool_calls_per_minute: admin_profile.rate_limit_tool_calls_per_minute,
        quota_enabled: admin_profile.quota_enabled,
        quota_tool_calls: admin_profile.quota_tool_calls,
        tool_call_timeout_secs: admin_profile.tool_call_timeout_secs,
        tool_policies: admin_profile.tool_policies,
        mcp: admin_profile.mcp,
    };

    let (sources, tools, all_tools, resources, prompts) =
        match crate::mcp::probe_profile_surface(&state.mcp_state, &profile).await {
            Ok(r) => r,
            Err(e) => return (StatusCode::BAD_GATEWAY, e).into_response(),
        };

    let generated_at_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    Json(ProfileSurfaceResponse {
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
struct ToolSourceDetailResponse {
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
        return (StatusCode::SERVICE_UNAVAILABLE, "Tenant store unavailable").into_response();
    };

    // Ensure tenant exists + enabled.
    match store.get_tenant(&tenant_id).await {
        Ok(Some(t)) if t.enabled => {}
        Ok(_) => return (StatusCode::UNAUTHORIZED, "invalid tenant").into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }

    let spec_url = req.spec_url.trim();
    if !(spec_url.starts_with("http://") || spec_url.starts_with("https://")) {
        return (StatusCode::BAD_REQUEST, "specUrl must be an http(s) URL").into_response();
    }

    let cfg = openapi_default_config(spec_url);
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
        return (StatusCode::SERVICE_UNAVAILABLE, "Tenant store unavailable").into_response();
    };

    // Ensure tenant exists + enabled.
    match store.get_tenant(&tenant_id).await {
        Ok(Some(t)) if t.enabled => {}
        Ok(_) => return (StatusCode::UNAUTHORIZED, "invalid tenant").into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
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
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
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
        return (StatusCode::SERVICE_UNAVAILABLE, "Tenant store unavailable").into_response();
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
    axum::Extension(state): axum::Extension<Arc<TenantState>>,
    headers: HeaderMap,
    Path(source_id): Path<String>,
) -> impl IntoResponse {
    let tenant_id = match authn(&headers, &state.signer) {
        Ok(t) => t,
        Err(resp) => return resp.into_response(),
    };
    let Some(store) = &state.store else {
        return (StatusCode::SERVICE_UNAVAILABLE, "Tenant store unavailable").into_response();
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
                    return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
                }
            };

            Json(ToolSourceDetailResponse {
                id: s.id,
                tool_type: tool_source_kind_str(s.kind).to_string(),
                enabled: s.enabled,
                spec,
            })
            .into_response()
        }
        Ok(None) => (StatusCode::NOT_FOUND, "tool source not found").into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
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
        return (StatusCode::SERVICE_UNAVAILABLE, "Tenant store unavailable").into_response();
    };

    // Ensure tenant exists + enabled.
    match store.get_tenant(&tenant_id).await {
        Ok(Some(t)) if t.enabled => {}
        Ok(_) => return (StatusCode::UNAUTHORIZED, "invalid tenant").into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }

    match state
        .mcp_state
        .tenant_catalog
        .list_tools(state.mcp_state.store.as_ref(), &tenant_id, &source_id)
        .await
    {
        Ok(Some(tools)) => Json(ToolSourceToolsResponse { tools }).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "tool source not found").into_response(),
        Err(e) => (StatusCode::BAD_GATEWAY, e.to_string()).into_response(),
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
        return (StatusCode::SERVICE_UNAVAILABLE, "Tenant store unavailable").into_response();
    };

    if !is_valid_source_id(&source_id) {
        return (
            StatusCode::BAD_REQUEST,
            "invalid source id (allowed: [a-zA-Z0-9_-], must not contain ':')",
        )
            .into_response();
    }
    if state.shared_source_ids.contains(&source_id) {
        return (
            StatusCode::BAD_REQUEST,
            "source id collides with a shared catalog source id",
        )
            .into_response();
    }
    if store
        .get_upstream(&source_id)
        .await
        .ok()
        .flatten()
        .is_some()
    {
        return (
            StatusCode::BAD_REQUEST,
            "source id collides with an upstream id",
        )
            .into_response();
    }

    // Ensure tenant exists + enabled.
    match store.get_tenant(&tenant_id).await {
        Ok(Some(t)) if t.enabled => {}
        Ok(_) => return (StatusCode::UNAUTHORIZED, "invalid tenant").into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }

    let (enabled, kind, spec) = match body {
        PutToolSourceBody::Http { enabled, config } => (
            enabled,
            ToolSourceKind::Http,
            match serde_json::to_value(&config) {
                Ok(v) => v,
                Err(e) => {
                    return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
                }
            },
        ),
        PutToolSourceBody::Openapi { enabled, config } => (
            enabled,
            ToolSourceKind::Openapi,
            match serde_json::to_value(&config) {
                Ok(v) => v,
                Err(e) => {
                    return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
                }
            },
        ),
    };

    if let Err(e) = store
        .put_tool_source(&tenant_id, &source_id, enabled, kind, spec)
        .await
    {
        return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
    }

    Json(OkResponse { ok: true }).into_response()
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
        return (StatusCode::SERVICE_UNAVAILABLE, "Tenant store unavailable").into_response();
    };

    match store.delete_tool_source(&tenant_id, &source_id).await {
        Ok(true) => Json(OkResponse { ok: true }).into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, "tool source not found").into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
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
        return (StatusCode::SERVICE_UNAVAILABLE, "Tenant store unavailable").into_response();
    };

    match store.list_secrets(&tenant_id).await {
        Ok(secrets) => Json(SecretsResponse { secrets }).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
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
        return (StatusCode::SERVICE_UNAVAILABLE, "Tenant store unavailable").into_response();
    };

    if req.name.trim().is_empty() {
        return (StatusCode::BAD_REQUEST, "secret name is required").into_response();
    }
    if req.value.is_empty() {
        return (StatusCode::BAD_REQUEST, "secret value is required").into_response();
    }

    if let Err(e) = store.put_secret(&tenant_id, &req.name, &req.value).await {
        return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
    }
    Json(OkResponse { ok: true }).into_response()
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
        return (StatusCode::SERVICE_UNAVAILABLE, "Tenant store unavailable").into_response();
    };

    match store.delete_secret(&tenant_id, &name).await {
        Ok(true) => Json(OkResponse { ok: true }).into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, "secret not found").into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
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
        return (StatusCode::SERVICE_UNAVAILABLE, "Tenant store unavailable").into_response();
    };

    match store.list_api_keys(&tenant_id).await {
        Ok(api_keys) => Json(ApiKeysResponse { api_keys }).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
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
        return (StatusCode::SERVICE_UNAVAILABLE, "Tenant store unavailable").into_response();
    };

    let name = req.name.as_deref().unwrap_or("default").trim().to_string();
    if name.is_empty() {
        return (StatusCode::BAD_REQUEST, "name is required").into_response();
    }

    if let Some(profile_id) = req.profile_id.as_deref() {
        // UUIDv4 only, otherwise 404 (avoid enumeration patterns).
        if Uuid::parse_str(profile_id)
            .ok()
            .and_then(|u| (u.get_version() == Some(Version::Random)).then_some(u))
            .is_none()
        {
            return (StatusCode::NOT_FOUND, "profile not found").into_response();
        }

        match store.get_profile(profile_id).await {
            Ok(Some(p)) if p.tenant_id == tenant_id && p.enabled => {}
            Ok(_) => return (StatusCode::NOT_FOUND, "profile not found").into_response(),
            Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        }
    }

    let api_key_id = Uuid::new_v4().to_string();
    let secret = generate_api_key_secret();
    let prefix = api_key_prefix(&secret);
    let secret_hash = hex::encode(sha2::Sha256::digest(secret.as_bytes()));

    if let Err(e) = store
        .put_api_key(
            &tenant_id,
            &api_key_id,
            req.profile_id.as_deref(),
            &name,
            &prefix,
            &secret_hash,
        )
        .await
    {
        return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
    }

    Json(CreateApiKeyResponse {
        ok: true,
        id: api_key_id,
        secret,
        prefix,
        profile_id: req.profile_id,
    })
    .into_response()
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
        return (StatusCode::SERVICE_UNAVAILABLE, "Tenant store unavailable").into_response();
    };

    match store.revoke_api_key(&tenant_id, &api_key_id).await {
        Ok(true) => Json(OkResponse { ok: true }).into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, "api key not found").into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
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
