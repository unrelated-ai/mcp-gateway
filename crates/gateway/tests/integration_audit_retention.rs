mod common;

use anyhow::Context as _;
use common::pg::{apply_dbmate_migrations, wait_pg_ready};
use common::{KillOnDrop, spawn_gateway, wait_http_ok};
use serde_json::json;
use sqlx::Row as _;
use std::time::Duration;
use testcontainers::core::IntoContainerPort;
use testcontainers::runners::AsyncRunner;
use testcontainers::{GenericImage, ImageExt as _};

const ADMIN_TOKEN: &str = "test-admin-token";
const SESSION_SECRET: &str = "test-session-secret";

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn audit_retention_cleanup_endpoint_deletes_old_rows() -> anyhow::Result<()> {
    // Postgres
    let pg = GenericImage::new("postgres", "16-alpine")
        .with_exposed_port(5432.tcp())
        .with_env_var("POSTGRES_PASSWORD", "postgres")
        .with_env_var("POSTGRES_USER", "postgres")
        .with_env_var("POSTGRES_DB", "gateway")
        .start()
        .await
        .context("start postgres container")?;
    let host = pg.get_host().await?.to_string();
    let port = pg.get_host_port_ipv4(5432).await?;
    let database_url =
        format!("postgres://postgres:postgres@{host}:{port}/gateway?sslmode=disable");
    wait_pg_ready(&database_url, Duration::from_secs(30)).await?;
    apply_dbmate_migrations(&database_url).await?;

    let pool = sqlx::PgPool::connect(&database_url)
        .await
        .context("connect pg")?;

    // Create tenant with immediate retention (0 days).
    sqlx::query(
        r"
insert into tenants (id, enabled, audit_enabled, audit_retention_days, audit_default_level)
values ($1, true, true, 0, 'metadata')
on conflict (id) do update
set enabled = excluded.enabled,
    audit_enabled = excluded.audit_enabled,
    audit_retention_days = excluded.audit_retention_days,
    audit_default_level = excluded.audit_default_level
",
    )
    .bind("t1")
    .execute(&pool)
    .await
    .context("insert tenant")?;

    // Insert an old audit event (should be deleted).
    sqlx::query(
        r"
insert into audit_events (ts, tenant_id, action, ok, meta)
values ('2000-01-01T00:00:00Z', $1, 'mcp.tools_call', true, '{}'::jsonb)
",
    )
    .bind("t1")
    .execute(&pool)
    .await
    .context("insert old audit event")?;

    // Gateway (Mode 3).
    let gw = spawn_gateway(&database_url, Some(ADMIN_TOKEN), SESSION_SECRET)?;
    let admin_base = gw.admin_base.clone();
    let _gateway_child = KillOnDrop(gw.child);
    wait_http_ok(&format!("{admin_base}/health"), Duration::from_secs(20)).await?;

    // Run cleanup.
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{admin_base}/admin/v1/tenants/t1/audit/cleanup"))
        .header("Authorization", format!("Bearer {ADMIN_TOKEN}"))
        .send()
        .await
        .context("POST cleanup")?;
    anyhow::ensure!(
        resp.status() == reqwest::StatusCode::OK,
        "expected 200 OK, got {}",
        resp.status()
    );
    let body: serde_json::Value = resp.json().await.context("decode cleanup response")?;
    anyhow::ensure!(body["ok"] == json!(true), "expected ok=true, got {body}");

    // Confirm old row is gone.
    let cnt: i64 = sqlx::query(
        r"
select count(*)::bigint as cnt
from audit_events
where tenant_id = $1 and action = 'mcp.tools_call'
",
    )
    .bind("t1")
    .fetch_one(&pool)
    .await
    .context("count audit events")?
    .try_get("cnt")?;
    assert_eq!(cnt, 0);

    Ok(())
}
