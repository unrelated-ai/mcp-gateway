use anyhow::Context as _;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use sqlx::postgres::PgListener;
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
