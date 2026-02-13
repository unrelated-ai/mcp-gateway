use crate::audit::AuditSink;
use crate::endpoint_cache::UpstreamEndpointCache;
use crate::tenant_catalog::TenantCatalog;
use crate::tools_cache::ToolSurfaceCache;
use anyhow::Context as _;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use sqlx::postgres::PgListener;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

const INVALIDATION_CHANNEL: &str = "unrelated_gateway_invalidation_v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum InvalidationEvent {
    TenantSecret {
        tenant_id: String,
        name: Option<String>,
    },
    TenantAuditSettings {
        tenant_id: String,
    },
    TenantToolSource {
        tenant_id: String,
        source_id: String,
    },
    Profile {
        profile_id: String,
    },
    Upstream {
        upstream_id: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum LocalInvalidationAction {
    Tenant {
        tenant_id: String,
    },
    TenantAuditSettings {
        tenant_id: String,
    },
    TenantToolSource {
        tenant_id: String,
        source_id: String,
    },
    Profile {
        profile_id: String,
    },
    Upstream {
        upstream_id: String,
    },
}

fn local_action_for_event(event: &InvalidationEvent) -> LocalInvalidationAction {
    match event {
        InvalidationEvent::TenantSecret { tenant_id, .. } => LocalInvalidationAction::Tenant {
            tenant_id: tenant_id.clone(),
        },
        InvalidationEvent::TenantAuditSettings { tenant_id } => {
            LocalInvalidationAction::TenantAuditSettings {
                tenant_id: tenant_id.clone(),
            }
        }
        InvalidationEvent::TenantToolSource {
            tenant_id,
            source_id,
        } => LocalInvalidationAction::TenantToolSource {
            tenant_id: tenant_id.clone(),
            source_id: source_id.clone(),
        },
        InvalidationEvent::Profile { profile_id } => LocalInvalidationAction::Profile {
            profile_id: profile_id.clone(),
        },
        InvalidationEvent::Upstream { upstream_id } => LocalInvalidationAction::Upstream {
            upstream_id: upstream_id.clone(),
        },
    }
}

#[derive(Clone)]
pub struct InvalidationDispatcher {
    pool: Option<PgPool>,
    tenant_catalog: Arc<TenantCatalog>,
    tools_cache: Arc<ToolSurfaceCache>,
    endpoint_cache: Arc<UpstreamEndpointCache>,
    audit: Arc<dyn AuditSink>,
}

impl InvalidationDispatcher {
    pub fn new(
        pool: Option<PgPool>,
        tenant_catalog: Arc<TenantCatalog>,
        tools_cache: Arc<ToolSurfaceCache>,
        endpoint_cache: Arc<UpstreamEndpointCache>,
        audit: Arc<dyn AuditSink>,
    ) -> Self {
        Self {
            pool,
            tenant_catalog,
            tools_cache,
            endpoint_cache,
            audit,
        }
    }

    pub fn pool(&self) -> Option<PgPool> {
        self.pool.clone()
    }

    pub fn apply_local(&self, event: &InvalidationEvent) {
        match local_action_for_event(event) {
            LocalInvalidationAction::Tenant { tenant_id } => {
                self.tenant_catalog.invalidate_tenant(&tenant_id);
            }
            LocalInvalidationAction::TenantAuditSettings { tenant_id } => {
                self.audit.invalidate_tenant_settings_cache(&tenant_id);
            }
            LocalInvalidationAction::TenantToolSource {
                tenant_id,
                source_id,
            } => {
                self.tenant_catalog
                    .invalidate_source(&tenant_id, &source_id);
            }
            LocalInvalidationAction::Profile { profile_id } => {
                self.tools_cache.invalidate_profile(&profile_id);
            }
            LocalInvalidationAction::Upstream { upstream_id } => {
                self.endpoint_cache.invalidate_upstream(&upstream_id);
            }
        }
    }

    #[allow(dead_code)] // reserved for follow-up write-path event emission centralization
    pub async fn publish_best_effort(&self, event: &InvalidationEvent) {
        if let Some(pool) = &self.pool {
            let _ = publish(pool, event).await;
        }
    }
}

pub async fn publish(pool: &PgPool, event: &InvalidationEvent) -> anyhow::Result<()> {
    let payload = serde_json::to_string(event).expect("valid json");
    sqlx::query("select pg_notify($1, $2)")
        .bind(INVALIDATION_CHANNEL)
        .bind(payload)
        .execute(pool)
        .await
        .context("pg_notify invalidation")?;
    Ok(())
}

pub async fn start_listener(
    pool: PgPool,
    shutdown: CancellationToken,
    on_event: std::sync::Arc<dyn Fn(InvalidationEvent) + Send + Sync>,
) -> anyhow::Result<()> {
    let mut listener = PgListener::connect_with(&pool)
        .await
        .context("connect PgListener")?;
    listener
        .listen(INVALIDATION_CHANNEL)
        .await
        .with_context(|| format!("LISTEN {INVALIDATION_CHANNEL}"))?;

    tokio::spawn(async move {
        loop {
            tokio::select! {
                () = shutdown.cancelled() => {
                    tracing::info!("pg invalidation listener shutting down");
                    break;
                }
                res = listener.recv() => {
                    let notification = match res {
                        Ok(n) => n,
                        Err(e) => {
                            tracing::warn!(error = %e, "pg invalidation recv error");
                            break;
                        }
                    };

                    let payload = notification.payload();
                    let evt: InvalidationEvent = match serde_json::from_str(payload) {
                        Ok(v) => v,
                        Err(e) => {
                            tracing::warn!(error = %e, payload = %payload, "invalid pg invalidation payload");
                            continue;
                        }
                    };
                    (on_event)(evt);
                }
            }
        }
    });

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalidation_event_serializes_expected_tag_names() {
        let event = InvalidationEvent::TenantAuditSettings {
            tenant_id: "t1".to_string(),
        };
        let value = serde_json::to_value(event).expect("serialize");
        assert_eq!(
            value.get("type"),
            Some(&serde_json::json!("tenant_audit_settings"))
        );
        assert_eq!(value.get("tenant_id"), Some(&serde_json::json!("t1")));
    }

    #[test]
    fn local_action_mapping_covers_all_event_variants() {
        assert_eq!(
            local_action_for_event(&InvalidationEvent::TenantSecret {
                tenant_id: "t1".to_string(),
                name: None,
            }),
            LocalInvalidationAction::Tenant {
                tenant_id: "t1".to_string()
            }
        );

        assert_eq!(
            local_action_for_event(&InvalidationEvent::TenantAuditSettings {
                tenant_id: "t2".to_string(),
            }),
            LocalInvalidationAction::TenantAuditSettings {
                tenant_id: "t2".to_string()
            }
        );

        assert_eq!(
            local_action_for_event(&InvalidationEvent::TenantToolSource {
                tenant_id: "t3".to_string(),
                source_id: "s1".to_string(),
            }),
            LocalInvalidationAction::TenantToolSource {
                tenant_id: "t3".to_string(),
                source_id: "s1".to_string(),
            }
        );

        assert_eq!(
            local_action_for_event(&InvalidationEvent::Profile {
                profile_id: "p1".to_string(),
            }),
            LocalInvalidationAction::Profile {
                profile_id: "p1".to_string()
            }
        );

        assert_eq!(
            local_action_for_event(&InvalidationEvent::Upstream {
                upstream_id: "u1".to_string(),
            }),
            LocalInvalidationAction::Upstream {
                upstream_id: "u1".to_string()
            }
        );
    }
}
