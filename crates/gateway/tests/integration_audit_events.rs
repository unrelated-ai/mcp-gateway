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
async fn audit_events_are_written_when_enabled() -> anyhow::Result<()> {
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

    // Insert tenant with audit enabled *before* starting gateway (avoid cache TTL issues).
    let pool = sqlx::PgPool::connect(&database_url)
        .await
        .context("connect pg")?;
    sqlx::query(
        r"
insert into tenants (id, enabled, audit_enabled, audit_default_level)
values ($1, true, true, 'metadata')
on conflict (id) do update
set enabled = excluded.enabled,
    audit_enabled = excluded.audit_enabled,
    audit_default_level = excluded.audit_default_level
",
    )
    .bind("t1")
    .execute(&pool)
    .await
    .context("insert tenant")?;

    // Gateway (Mode 3).
    let gw = spawn_gateway(&database_url, Some(ADMIN_TOKEN), SESSION_SECRET)?;
    let admin_base = gw.admin_base.clone();
    let _gateway_child = KillOnDrop(gw.child);
    wait_http_ok(&format!("{admin_base}/health"), Duration::from_secs(20)).await?;

    // Trigger one audited action (admin secret put).
    let client = reqwest::Client::new();
    let resp = client
        .put(format!(
            "{admin_base}/admin/v1/tenants/t1/secrets/test_secret"
        ))
        .header("Authorization", format!("Bearer {ADMIN_TOKEN}"))
        .json(&json!({ "value": "hello" }))
        .send()
        .await
        .context("PUT secret request")?;
    anyhow::ensure!(
        resp.status() == reqwest::StatusCode::OK,
        "expected 200 OK, got {}",
        resp.status()
    );

    // Assert audit row exists (audit sink is buffered + async).
    let mut row = None;
    let started_wait = std::time::Instant::now();
    while started_wait.elapsed() < Duration::from_secs(5) {
        row = sqlx::query(
            r"
select action, http_method, http_route, status_code, ok, error_kind
from audit_events
where tenant_id = $1 and action = 'admin.secret_put'
order by ts desc
limit 1
",
        )
        .bind("t1")
        .fetch_optional(&pool)
        .await
        .context("select audit event")?;

        if row.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let Some(row) = row else {
        anyhow::bail!("expected audit_events row for admin.secret_put, found none");
    };

    let action: String = row.try_get("action")?;
    let http_method: Option<String> = row.try_get("http_method")?;
    let http_route: Option<String> = row.try_get("http_route")?;
    let status_code: Option<i32> = row.try_get("status_code")?;
    let ok: bool = row.try_get("ok")?;
    let error_kind: Option<String> = row.try_get("error_kind")?;

    assert_eq!(action, "admin.secret_put");
    assert_eq!(http_method.as_deref(), Some("PUT"));
    assert_eq!(
        http_route.as_deref(),
        Some("/admin/v1/tenants/{tenant_id}/secrets/{name}")
    );
    assert_eq!(status_code, Some(200));
    assert!(ok);
    assert_eq!(error_kind, None);

    Ok(())
}
