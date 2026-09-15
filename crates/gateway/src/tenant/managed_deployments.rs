//! Tenant-scoped managed deployment routes and request validation.
use super::{TenantState, authn, ensure_enabled_tenant};
use crate::managed_mcp::{ManagedMcpWriteGuard, managed_mcp_write_guard};
use crate::store::{ManagedMcpDeployable, ManagedMcpDeploymentRequest};
use axum::{
    Json, Router,
    extract::Path,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::get,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

const DEFAULT_TENANT_MANAGED_MCP_DEPLOYMENT_LIST_LIMIT: u32 = 200;
const MIN_MANAGED_MCP_REPLICAS: i32 = 0;
const MAX_MANAGED_MCP_REPLICAS: i32 = 50;

pub(super) fn router() -> Router {
    Router::new()
        .route(
            "/tenant/v1/managed-mcp/deployables",
            get(list_managed_mcp_deployables),
        )
        .route(
            "/tenant/v1/managed-mcp/deployments",
            get(list_managed_mcp_deployment_requests).post(create_managed_mcp_deployment_request),
        )
        .route(
            "/tenant/v1/managed-mcp/deployments/{request_id}",
            get(get_managed_mcp_deployment_request).patch(patch_managed_mcp_deployment_request),
        )
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ManagedMcpDeployablesResponse {
    deployables: Vec<ManagedMcpDeployable>,
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
struct CreateManagedMcpDeploymentRequestBody {
    deployable_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PatchManagedMcpDeploymentRequestBody {
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    replicas: Option<i32>,
}

async fn list_managed_mcp_deployables(
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
    if let Err(resp) = ensure_enabled_tenant(store, &tenant_id).await {
        return resp;
    }
    match store.list_managed_mcp_deployables().await {
        Ok(mut deployables) => {
            deployables.retain(|d| d.enabled);
            Json(ManagedMcpDeployablesResponse { deployables }).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn create_managed_mcp_deployment_request(
    axum::Extension(state): axum::Extension<Arc<TenantState>>,
    headers: HeaderMap,
    Json(req): Json<CreateManagedMcpDeploymentRequestBody>,
) -> impl IntoResponse {
    let tenant_id = match authn(&headers, &state.signer) {
        Ok(t) => t,
        Err(resp) => return resp.into_response(),
    };
    let Some(store) = &state.store else {
        return (StatusCode::SERVICE_UNAVAILABLE, "Tenant store unavailable").into_response();
    };
    if let Err(resp) = ensure_enabled_tenant(store, &tenant_id).await {
        return resp;
    }
    if req.deployable_id.trim().is_empty() {
        return (StatusCode::BAD_REQUEST, "deployableId is required").into_response();
    }
    match managed_mcp_write_guard(state.store.clone(), &state.managed_mcp).await {
        ManagedMcpWriteGuard::Allow => {}
        ManagedMcpWriteGuard::Reject { status, message } => {
            return (status, message).into_response();
        }
    }
    match store
        .create_managed_mcp_deployment_request(&tenant_id, &req.deployable_id)
        .await
    {
        Ok(request) => (
            StatusCode::CREATED,
            Json(ManagedMcpDeploymentResponse { request }),
        )
            .into_response(),
        Err(e) => {
            let message = e.to_string();
            (managed_mcp_create_error_status(&message), message).into_response()
        }
    }
}

async fn list_managed_mcp_deployment_requests(
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
    if let Err(resp) = ensure_enabled_tenant(store, &tenant_id).await {
        return resp;
    }
    match store
        .list_managed_mcp_deployment_requests_for_tenant(
            &tenant_id,
            DEFAULT_TENANT_MANAGED_MCP_DEPLOYMENT_LIST_LIMIT,
        )
        .await
    {
        Ok(requests) => Json(ManagedMcpDeploymentsResponse { requests }).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn get_managed_mcp_deployment_request(
    axum::Extension(state): axum::Extension<Arc<TenantState>>,
    headers: HeaderMap,
    Path(request_id): Path<String>,
) -> impl IntoResponse {
    let tenant_id = match authn(&headers, &state.signer) {
        Ok(t) => t,
        Err(resp) => return resp.into_response(),
    };
    let Some(store) = &state.store else {
        return (StatusCode::SERVICE_UNAVAILABLE, "Tenant store unavailable").into_response();
    };
    match store
        .get_managed_mcp_deployment_request_for_tenant(&tenant_id, &request_id)
        .await
    {
        Ok(Some(request)) => Json(ManagedMcpDeploymentResponse { request }).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "deployment request not found").into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn patch_managed_mcp_deployment_request(
    axum::Extension(state): axum::Extension<Arc<TenantState>>,
    headers: HeaderMap,
    Path(request_id): Path<String>,
    Json(req): Json<PatchManagedMcpDeploymentRequestBody>,
) -> impl IntoResponse {
    let tenant_id = match authn(&headers, &state.signer) {
        Ok(t) => t,
        Err(resp) => return resp.into_response(),
    };
    let Some(store) = &state.store else {
        return (StatusCode::SERVICE_UNAVAILABLE, "Tenant store unavailable").into_response();
    };
    if let Err(resp) = ensure_enabled_tenant(store, &tenant_id).await {
        return resp;
    }
    if req.enabled.is_none() && req.replicas.is_none() {
        return (
            StatusCode::BAD_REQUEST,
            "at least one of enabled or replicas is required",
        )
            .into_response();
    }
    match managed_mcp_write_guard(state.store.clone(), &state.managed_mcp).await {
        ManagedMcpWriteGuard::Allow => {}
        ManagedMcpWriteGuard::Reject { status, message } => {
            return (status, message).into_response();
        }
    }

    let Some(existing) = (match store
        .get_managed_mcp_deployment_request_for_tenant(&tenant_id, &request_id)
        .await
    {
        Ok(v) => v,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }) else {
        return (StatusCode::NOT_FOUND, "deployment request not found").into_response();
    };

    let (desired_enabled, desired_replicas) = match resolve_managed_mcp_patch(&existing, &req) {
        Ok(v) => v,
        Err(message) => return (StatusCode::BAD_REQUEST, message).into_response(),
    };

    match store
        .update_managed_mcp_deployment_request_for_tenant(
            &tenant_id,
            &request_id,
            desired_enabled,
            desired_replicas,
        )
        .await
    {
        Ok(Some(request)) => Json(ManagedMcpDeploymentResponse { request }).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "deployment request not found").into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

fn managed_mcp_create_error_status(message: &str) -> StatusCode {
    if message.contains("not found") || message.contains("disabled") {
        return StatusCode::BAD_REQUEST;
    }
    StatusCode::INTERNAL_SERVER_ERROR
}

fn resolve_managed_mcp_patch(
    existing: &ManagedMcpDeploymentRequest,
    req: &PatchManagedMcpDeploymentRequestBody,
) -> Result<(bool, i32), String> {
    let desired_enabled = req.enabled.unwrap_or(existing.desired_enabled);
    let desired_replicas = req.replicas.unwrap_or(existing.desired_replicas);
    if !(MIN_MANAGED_MCP_REPLICAS..=MAX_MANAGED_MCP_REPLICAS).contains(&desired_replicas) {
        return Err(format!(
            "replicas must be between {MIN_MANAGED_MCP_REPLICAS} and {MAX_MANAGED_MCP_REPLICAS}"
        ));
    }
    if desired_enabled && desired_replicas < 1 {
        return Err("replicas must be at least 1 when enabled".to_string());
    }
    Ok((desired_enabled, desired_replicas))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn managed_mcp_create_error_status_maps_known_messages_to_bad_request() {
        assert_eq!(
            managed_mcp_create_error_status("deployable not found or disabled"),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            managed_mcp_create_error_status("unexpected db error"),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[test]
    fn resolve_managed_mcp_patch_validates_enabled_replica_rules() {
        let existing = ManagedMcpDeploymentRequest {
            id: "req-1".to_string(),
            tenant_id: "t1".to_string(),
            deployable_id: "d1".to_string(),
            desired_enabled: true,
            desired_replicas: 1,
            status: crate::store::ManagedMcpDeploymentStatus::Pending,
            upstream_id: None,
            message: None,
            created_at_unix: 0,
            updated_at_unix: 0,
        };
        let patch = PatchManagedMcpDeploymentRequestBody {
            enabled: Some(true),
            replicas: Some(0),
        };
        let err = resolve_managed_mcp_patch(&existing, &patch).expect_err("should reject");
        assert!(err.contains("at least 1"));
    }

    #[test]
    fn resolve_managed_mcp_patch_applies_defaults_and_accepts_disable_to_zero() {
        let existing = ManagedMcpDeploymentRequest {
            id: "req-1".to_string(),
            tenant_id: "t1".to_string(),
            deployable_id: "d1".to_string(),
            desired_enabled: true,
            desired_replicas: 3,
            status: crate::store::ManagedMcpDeploymentStatus::Ready,
            upstream_id: Some("managed_t1_req_1".to_string()),
            message: None,
            created_at_unix: 0,
            updated_at_unix: 0,
        };
        let patch = PatchManagedMcpDeploymentRequestBody {
            enabled: Some(false),
            replicas: Some(0),
        };
        let (enabled, replicas) = resolve_managed_mcp_patch(&existing, &patch).expect("valid");
        assert!(!enabled);
        assert_eq!(replicas, 0);
    }
}
