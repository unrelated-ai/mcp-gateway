use crate::store::{AdminStore, ManagedMcpBackendMode, ManagedMcpDeploymentStatus};
use axum::http::StatusCode;
use serde::Serialize;
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

pub const MANAGED_MCP_BACKEND_MODE_ENV: &str = "UNRELATED_MANAGED_MCP_BACKEND_MODE";
pub const MANAGED_MCP_HEARTBEAT_TTL_SECS_ENV: &str =
    "UNRELATED_MANAGED_MCP_RECONCILER_HEARTBEAT_TTL_SECS";
pub const MANAGED_MCP_STALE_TIMEOUT_SECS_ENV: &str =
    "UNRELATED_MANAGED_MCP_STALE_REQUEST_TIMEOUT_SECS";
pub const MANAGED_MCP_STALE_SWEEP_INTERVAL_SECS_ENV: &str =
    "UNRELATED_MANAGED_MCP_STALE_REQUEST_SWEEP_INTERVAL_SECS";

const DEFAULT_MANAGED_MCP_BACKEND_MODE: ManagedMcpBackendMode = ManagedMcpBackendMode::None;
const DEFAULT_MANAGED_MCP_HEARTBEAT_TTL_SECS: u64 = 30;
const DEFAULT_MANAGED_MCP_STALE_TIMEOUT_SECS: u64 = 300;
const DEFAULT_MANAGED_MCP_STALE_SWEEP_INTERVAL_SECS: u64 = 30;

#[derive(Debug, Clone)]
pub struct ManagedMcpRuntimeConfig {
    pub backend_mode: ManagedMcpBackendMode,
    pub heartbeat_ttl_secs: u64,
    pub stale_timeout_secs: u64,
    pub stale_sweep_interval_secs: u64,
}

impl ManagedMcpRuntimeConfig {
    pub fn from_env() -> Self {
        let backend_mode_raw = std::env::var(MANAGED_MCP_BACKEND_MODE_ENV)
            .ok()
            .unwrap_or_else(|| DEFAULT_MANAGED_MCP_BACKEND_MODE.as_str().to_string());
        let backend_mode = ManagedMcpBackendMode::parse(&backend_mode_raw).unwrap_or_else(|| {
            tracing::warn!(
                mode = %backend_mode_raw,
                "invalid managed MCP backend mode; falling back to 'none'"
            );
            DEFAULT_MANAGED_MCP_BACKEND_MODE
        });

        Self {
            backend_mode,
            heartbeat_ttl_secs: parse_u64_env(
                MANAGED_MCP_HEARTBEAT_TTL_SECS_ENV,
                DEFAULT_MANAGED_MCP_HEARTBEAT_TTL_SECS,
            ),
            stale_timeout_secs: parse_u64_env(
                MANAGED_MCP_STALE_TIMEOUT_SECS_ENV,
                DEFAULT_MANAGED_MCP_STALE_TIMEOUT_SECS,
            ),
            stale_sweep_interval_secs: parse_u64_env(
                MANAGED_MCP_STALE_SWEEP_INTERVAL_SECS_ENV,
                DEFAULT_MANAGED_MCP_STALE_SWEEP_INTERVAL_SECS,
            ),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ManagedMcpBackendStatus {
    pub backend_mode: ManagedMcpBackendMode,
    pub enabled: bool,
    pub reconciler_healthy: bool,
    pub accepting_requests: bool,
    pub heartbeat_ttl_secs: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_heartbeat_unix: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

pub enum ManagedMcpWriteGuard {
    Allow,
    Reject { status: StatusCode, message: String },
}

pub async fn managed_mcp_backend_status(
    store: Option<Arc<dyn AdminStore>>,
    cfg: &ManagedMcpRuntimeConfig,
) -> ManagedMcpBackendStatus {
    if !cfg.backend_mode.is_enabled() {
        return ManagedMcpBackendStatus {
            backend_mode: cfg.backend_mode,
            enabled: false,
            reconciler_healthy: false,
            accepting_requests: false,
            heartbeat_ttl_secs: cfg.heartbeat_ttl_secs,
            last_heartbeat_unix: None,
            message: Some(format!(
                "managed deployments are disabled ({MANAGED_MCP_BACKEND_MODE_ENV}=none)"
            )),
        };
    }

    let Some(store) = store else {
        return ManagedMcpBackendStatus {
            backend_mode: cfg.backend_mode,
            enabled: true,
            reconciler_healthy: false,
            accepting_requests: false,
            heartbeat_ttl_secs: cfg.heartbeat_ttl_secs,
            last_heartbeat_unix: None,
            message: Some("managed deployment store unavailable".to_string()),
        };
    };

    let last_heartbeat_unix = match store
        .latest_managed_mcp_reconciler_heartbeat_unix(cfg.backend_mode)
        .await
    {
        Ok(v) => v,
        Err(err) => {
            tracing::warn!(error = %err, "failed to read managed MCP reconciler heartbeat");
            return ManagedMcpBackendStatus {
                backend_mode: cfg.backend_mode,
                enabled: true,
                reconciler_healthy: false,
                accepting_requests: false,
                heartbeat_ttl_secs: cfg.heartbeat_ttl_secs,
                last_heartbeat_unix: None,
                message: Some("failed to read reconciler heartbeat".to_string()),
            };
        }
    };

    let now_unix = now_unix_secs_i64();
    let reconciler_healthy = last_heartbeat_unix.is_some_and(|last| {
        now_unix.saturating_sub(last) <= i64::try_from(cfg.heartbeat_ttl_secs).unwrap_or(i64::MAX)
    });
    let message = if reconciler_healthy {
        None
    } else if last_heartbeat_unix.is_none() {
        Some(format!(
            "no {} reconciler heartbeat observed",
            cfg.backend_mode.as_str()
        ))
    } else {
        Some(format!(
            "{} reconciler heartbeat is older than {}s",
            cfg.backend_mode.as_str(),
            cfg.heartbeat_ttl_secs
        ))
    };

    ManagedMcpBackendStatus {
        backend_mode: cfg.backend_mode,
        enabled: true,
        reconciler_healthy,
        accepting_requests: reconciler_healthy,
        heartbeat_ttl_secs: cfg.heartbeat_ttl_secs,
        last_heartbeat_unix,
        message,
    }
}

pub async fn managed_mcp_write_guard(
    store: Option<Arc<dyn AdminStore>>,
    cfg: &ManagedMcpRuntimeConfig,
) -> ManagedMcpWriteGuard {
    let status = managed_mcp_backend_status(store, cfg).await;
    if !status.enabled {
        return ManagedMcpWriteGuard::Reject {
            status: StatusCode::CONFLICT,
            message: status
                .message
                .unwrap_or_else(|| "managed deployments are disabled".to_string()),
        };
    }
    if !status.accepting_requests {
        return ManagedMcpWriteGuard::Reject {
            status: StatusCode::SERVICE_UNAVAILABLE,
            message: status.message.unwrap_or_else(|| {
                "managed deployment backend is unavailable; no healthy reconciler".to_string()
            }),
        };
    }
    ManagedMcpWriteGuard::Allow
}

pub fn spawn_stale_request_sweeper_task(
    store: Option<Arc<dyn AdminStore>>,
    cfg: ManagedMcpRuntimeConfig,
    shutdown: CancellationToken,
) {
    let Some(store) = store else {
        return;
    };
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(cfg.stale_sweep_interval_secs));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                () = shutdown.cancelled() => break,
                _ = tick.tick() => {
                    let status = managed_mcp_backend_status(Some(store.clone()), &cfg).await;
                    if status.accepting_requests {
                        continue;
                    }
                    let message = status.message.unwrap_or_else(|| {
                        "managed deployment backend unavailable".to_string()
                    });
                    match store
                        .fail_stale_managed_mcp_deployment_requests(
                            &[
                                ManagedMcpDeploymentStatus::Pending,
                                ManagedMcpDeploymentStatus::Reconciling,
                            ],
                            cfg.stale_timeout_secs,
                            &message,
                        )
                        .await
                    {
                        Ok(0) => {}
                        Ok(updated) => {
                            tracing::info!(
                                updated,
                                stale_timeout_secs = cfg.stale_timeout_secs,
                                "marked stale managed MCP deployment requests as failed"
                            );
                        }
                        Err(err) => {
                            tracing::warn!(
                                error = %err,
                                "managed MCP stale-request sweep failed"
                            );
                        }
                    }
                }
            }
        }
    });
}

fn parse_u64_env(name: &str, default: u64) -> u64 {
    match std::env::var(name) {
        Ok(raw) => match raw.trim().parse::<u64>() {
            Ok(v) => v.max(1),
            Err(_) => {
                tracing::warn!(name, value = %raw, "invalid u64 env value; falling back to default");
                default
            }
        },
        Err(_) => default,
    }
}

fn now_unix_secs_i64() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |v| i64::try_from(v.as_secs()).unwrap_or(i64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_backend_mode_supports_expected_values() {
        assert_eq!(
            ManagedMcpBackendMode::parse("none"),
            Some(ManagedMcpBackendMode::None)
        );
        assert_eq!(
            ManagedMcpBackendMode::parse("k8s"),
            Some(ManagedMcpBackendMode::K8s)
        );
        assert_eq!(
            ManagedMcpBackendMode::parse("docker"),
            Some(ManagedMcpBackendMode::Docker)
        );
        assert_eq!(ManagedMcpBackendMode::parse("nope"), None);
    }
}
