//! HTTP server and endpoints.

use crate::aggregator::Aggregator;
use crate::backend::BackendState;
use crate::supervisor::BackendManager;
use axum::{Json, Router, extract::State, http::StatusCode, response::IntoResponse, routing::get};
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::collections::HashMap;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::time::Instant;

/// Shared application state.
pub struct AppState {
    pub backend_manager: Arc<BackendManager>,
    pub aggregator: Arc<Aggregator>,
    pub start_time: Instant,
    pub version: &'static str,
    /// Optional static bearer token required for non-health HTTP endpoints (including `/mcp`).
    pub mcp_bearer_token: Option<String>,
    pub total_requests: AtomicU64,
    pub failed_requests: AtomicU64,
}

/// Create the HTTP router with all endpoints.
pub fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        // Health endpoints
        .route("/health", get(health))
        .route("/health/any", get(health_any))
        .route("/health/all", get(health_all))
        // Readiness
        .route("/ready", get(ready))
        // Status and map
        .route("/status", get(status))
        .route("/map", get(map))
        // State
        .with_state(state)
}

/// Attach request counting middleware (total + failed).
pub fn with_request_counting(router: Router, state: Arc<AppState>) -> Router {
    use axum::{
        body::Body,
        http::Request,
        middleware::{Next, from_fn_with_state},
        response::Response,
    };

    async fn count_requests(
        State(state): State<Arc<AppState>>,
        request: Request<Body>,
        next: Next,
    ) -> Response {
        let path = request.uri().path();
        let should_count = !path.starts_with("/health") && path != "/ready";

        if should_count {
            state.total_requests.fetch_add(1, Ordering::Relaxed);
        }
        let response = next.run(request).await;
        if should_count && !response.status().is_success() {
            state.failed_requests.fetch_add(1, Ordering::Relaxed);
        }
        response
    }

    router.layer(from_fn_with_state(state, count_requests))
}

/// Optional bearer-token auth for HTTP endpoints.
///
/// If `state.mcp_bearer_token` is set, all requests except `/health*` and `/ready` must include:
/// `Authorization: Bearer <token>`.
pub fn with_optional_bearer_auth(router: Router, state: Arc<AppState>) -> Router {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        middleware::{Next, from_fn_with_state},
        response::{IntoResponse as _, Response},
    };

    async fn require_bearer(
        State(state): State<Arc<AppState>>,
        request: Request<Body>,
        next: Next,
    ) -> Response {
        let path = request.uri().path();
        if path.starts_with("/health") || path == "/ready" {
            return next.run(request).await;
        }

        let expected = state.mcp_bearer_token.as_deref().unwrap_or_default().trim();
        if expected.is_empty() {
            return next.run(request).await;
        }

        let got = request
            .headers()
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer ").map(str::trim));

        if got == Some(expected) {
            return next.run(request).await;
        }

        (StatusCode::UNAUTHORIZED, "Unauthorized").into_response()
    }

    if state
        .mcp_bearer_token
        .as_deref()
        .is_none_or(|t| t.trim().is_empty())
    {
        return router;
    }

    router.layer(from_fn_with_state(state, require_bearer))
}

// ============================================================================
// Health Endpoints
// ============================================================================

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
}

/// GET /health - Always returns 200 if adapter is running.
async fn health() -> Json<HealthResponse> {
    Json(HealthResponse { status: "healthy" })
}

#[derive(Serialize)]
struct HealthAnyResponse {
    status: &'static str,
    alive_servers: Vec<String>,
    dead_servers: Vec<String>,
}

/// GET /health/any - Returns 200 if any server is alive, 503 if all dead.
async fn health_any(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let statuses = state.backend_manager.get_all_status();

    let alive: Vec<String> = statuses
        .iter()
        .filter(|(_, s)| s.state == BackendState::Running)
        .map(|(name, _)| name.clone())
        .collect();

    let dead: Vec<String> = statuses
        .iter()
        .filter(|(_, s)| s.state != BackendState::Running)
        .map(|(name, _)| name.clone())
        .collect();

    // If no backends configured, consider it healthy
    let any_alive = !alive.is_empty() || statuses.is_empty();

    let response = HealthAnyResponse {
        status: if any_alive { "healthy" } else { "unhealthy" },
        alive_servers: alive,
        dead_servers: dead,
    };

    if any_alive {
        (StatusCode::OK, Json(response))
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, Json(response))
    }
}

#[derive(Serialize)]
struct HealthAllResponse {
    status: &'static str,
    servers: HashMap<String, String>,
}

/// GET /health/all - Returns 200 if all servers are alive, 503 if any dead.
async fn health_all(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let statuses = state.backend_manager.get_all_status();

    let servers: HashMap<String, String> = statuses
        .iter()
        .map(|(name, s)| (name.clone(), s.state.to_string()))
        .collect();

    // If no backends configured, consider it healthy
    let all_alive =
        statuses.values().all(|s| s.state == BackendState::Running) || statuses.is_empty();

    let response = HealthAllResponse {
        status: if all_alive { "healthy" } else { "unhealthy" },
        servers,
    };

    if all_alive {
        (StatusCode::OK, Json(response))
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, Json(response))
    }
}

// ============================================================================
// Readiness Endpoint
// ============================================================================

#[derive(Serialize)]
struct ReadyResponse {
    status: &'static str,
    servers: HashMap<String, String>,
}

/// GET /ready - Returns 200 if all servers are running.
async fn ready(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let statuses = state.backend_manager.get_all_status();

    let servers: HashMap<String, String> = statuses
        .iter()
        .map(|(name, s)| (name.clone(), s.state.to_string()))
        .collect();

    // If no backends configured, consider it ready
    let all_running =
        statuses.values().all(|s| s.state == BackendState::Running) || statuses.is_empty();

    let response = ReadyResponse {
        status: if all_running { "ready" } else { "not_ready" },
        servers,
    };

    if all_running {
        (StatusCode::OK, Json(response))
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, Json(response))
    }
}

// ============================================================================
// Status Endpoint
// ============================================================================

#[derive(Serialize)]
struct StatusResponse {
    version: &'static str,
    uptime_seconds: u64,
    servers: HashMap<String, ServerStatusInfo>,
    stats: StatsInfo,
}

#[derive(Serialize)]
struct ServerStatusInfo {
    #[serde(rename = "type")]
    backend_type: String,
    state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    spec_url: Option<String>,
    tool_count: usize,
    restarts: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_restart: Option<DateTime<Utc>>,
}

#[derive(Serialize)]
struct StatsInfo {
    total_requests: u64,
    failed_requests: u64,
}

/// GET /status - Detailed status information.
async fn status(State(state): State<Arc<AppState>>) -> Json<StatusResponse> {
    let statuses = state.backend_manager.get_all_status();

    let servers: HashMap<String, ServerStatusInfo> = statuses
        .into_iter()
        .map(|(name, s)| {
            (
                name,
                ServerStatusInfo {
                    backend_type: s.backend_type.to_string(),
                    state: s.state.to_string(),
                    spec_url: s.spec_url,
                    tool_count: s.tool_count,
                    restarts: s.restart_count,
                    last_restart: s.last_restart,
                },
            )
        })
        .collect();

    Json(StatusResponse {
        version: state.version,
        uptime_seconds: state.start_time.elapsed().as_secs(),
        servers,
        stats: StatsInfo {
            total_requests: state.total_requests.load(Ordering::Relaxed),
            failed_requests: state.failed_requests.load(Ordering::Relaxed),
        },
    })
}

// ============================================================================
// Map Endpoint
// ============================================================================

#[derive(Serialize)]
struct MapResponse {
    tools: HashMap<String, ToolMapEntry>,
    resources: HashMap<String, ResourceMapEntry>,
    prompts: HashMap<String, PromptMapEntry>,
    servers: HashMap<String, ServerMapEntry>,
}

#[derive(Serialize)]
struct ToolMapEntry {
    server: String,
    original_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    input_schema: Option<serde_json::Value>,
}

#[derive(Serialize)]
struct ResourceMapEntry {
    server: String,
    original_uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mime_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    size: Option<u32>,
}

#[derive(Serialize)]
struct PromptMapEntry {
    server: String,
    original_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    arguments: Option<Vec<rmcp::model::PromptArgument>>,
}

#[derive(Serialize)]
struct ServerMapEntry {
    #[serde(rename = "type")]
    backend_type: String,
    state: String,
    tool_count: usize,
    resource_count: usize,
    prompt_count: usize,
}

/// GET /map - Tool/resource/prompt metadata for Gateway integration.
async fn map(State(state): State<Arc<AppState>>) -> Json<MapResponse> {
    let all_tools = state.aggregator.get_all_tools();
    let all_resources = state.aggregator.get_all_resources();
    let all_prompts = state.aggregator.get_all_prompts();
    let statuses = state.backend_manager.get_all_status();

    // Convert to response format
    let tools: HashMap<String, ToolMapEntry> = all_tools
        .iter()
        .map(|(key, m)| {
            (
                key.clone(),
                ToolMapEntry {
                    server: m.server.clone(),
                    original_name: m.original_name.clone(),
                    description: m.description.clone(),
                    input_schema: m.input_schema.clone(),
                },
            )
        })
        .collect();

    let resources: HashMap<String, ResourceMapEntry> = all_resources
        .iter()
        .map(|(key, m)| {
            (
                key.clone(),
                ResourceMapEntry {
                    server: m.server.clone(),
                    original_uri: m.original_uri.clone(),
                    name: Some(m.name.clone()),
                    description: m.description.clone(),
                    mime_type: m.mime_type.clone(),
                    size: m.size,
                },
            )
        })
        .collect();

    let prompts: HashMap<String, PromptMapEntry> = all_prompts
        .iter()
        .map(|(key, m)| {
            (
                key.clone(),
                PromptMapEntry {
                    server: m.server.clone(),
                    original_name: m.original_name.clone(),
                    description: m.description.clone(),
                    arguments: m.arguments.clone(),
                },
            )
        })
        .collect();

    // Build server entries with counts
    let servers: HashMap<String, ServerMapEntry> = statuses
        .into_iter()
        .map(|(name, status)| {
            let tool_count = tools.values().filter(|t| t.server == name).count();
            let resource_count = resources.values().filter(|r| r.server == name).count();
            let prompt_count = prompts.values().filter(|p| p.server == name).count();

            (
                name,
                ServerMapEntry {
                    backend_type: status.backend_type.to_string(),
                    state: status.state.to_string(),
                    tool_count,
                    resource_count,
                    prompt_count,
                },
            )
        })
        .collect();

    Json(MapResponse {
        tools,
        resources,
        prompts,
        servers,
    })
}
