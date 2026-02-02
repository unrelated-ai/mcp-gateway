use sqlx::{PgConnection, PgPool, Row as _};
use std::time::Duration;
use tokio_util::sync::CancellationToken;

/// Background audit retention cleanup interval.
const AUDIT_RETENTION_INTERVAL: Duration = Duration::from_secs(10 * 60);

/// Use a global advisory lock so only one HA replica performs cleanup per tick.
///
/// This is a Postgres session-level lock; it is held for the lifetime of the connection
/// that acquired it (until explicitly unlocked or the connection is dropped).
const AUDIT_RETENTION_ADVISORY_LOCK_KEY: i64 = 8_704_193_017_661_123_407i64;

pub fn spawn_audit_retention_task(pg_pool: Option<PgPool>, shutdown: CancellationToken) {
    let Some(pool) = pg_pool else {
        // Mode 1: no DB => nothing to clean up.
        return;
    };

    tokio::spawn(async move {
        let mut tick = tokio::time::interval(AUDIT_RETENTION_INTERVAL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                () = shutdown.cancelled() => break,
                _ = tick.tick() => {
                    if let Err(e) = cleanup_all_tenants_once(&pool).await {
                        tracing::warn!(error = %e, "audit retention cleanup tick failed");
                    }
                }
            }
        }
    });
}

async fn cleanup_all_tenants_once(pool: &PgPool) -> anyhow::Result<()> {
    let mut conn = pool.acquire().await?;
    let conn: &mut PgConnection = conn.as_mut();

    let locked: bool = sqlx::query_scalar(
        r"
select pg_try_advisory_lock($1)
",
    )
    .bind(AUDIT_RETENTION_ADVISORY_LOCK_KEY)
    .fetch_one(&mut *conn)
    .await?;

    if !locked {
        // Another replica is doing cleanup on this tick; skip to avoid duplicated load.
        return Ok(());
    }

    let res = cleanup_all_tenants_once_with_conn(conn).await;

    // Always attempt to unlock (best-effort).
    let _unlocked: Result<bool, sqlx::Error> = sqlx::query_scalar(
        r"
select pg_advisory_unlock($1)
",
    )
    .bind(AUDIT_RETENTION_ADVISORY_LOCK_KEY)
    .fetch_one(&mut *conn)
    .await;

    res
}

async fn cleanup_all_tenants_once_with_conn(conn: &mut PgConnection) -> anyhow::Result<()> {
    let rows = sqlx::query(
        r"
select id, audit_retention_days
from tenants
where audit_retention_days >= 0
order by id asc
",
    )
    .fetch_all(&mut *conn)
    .await?;

    let mut total_deleted: u64 = 0;
    for r in rows {
        let tenant_id: String = r.try_get("id")?;
        let retention_days: i32 = r.try_get("audit_retention_days")?;

        // Delete rows older than now - retention_days.
        let res = sqlx::query(
            r"
delete from audit_events
where tenant_id = $1
  and ts < now() - ($2::int * interval '1 day')
",
        )
        .bind(&tenant_id)
        .bind(retention_days)
        .execute(&mut *conn)
        .await;

        match res {
            Ok(res) => {
                let deleted = res.rows_affected();
                total_deleted = total_deleted.saturating_add(deleted);
                if deleted > 0 {
                    tracing::info!(
                        tenant_id = %tenant_id,
                        retention_days,
                        deleted,
                        "audit retention cleanup deleted rows"
                    );
                }
            }
            Err(e) => {
                tracing::warn!(
                    tenant_id = %tenant_id,
                    retention_days,
                    error = %e,
                    "audit retention cleanup failed for tenant"
                );
            }
        }
    }

    if total_deleted > 0 {
        tracing::info!(deleted = total_deleted, "audit retention cleanup completed");
    }

    Ok(())
}
