use anyhow::Context as _;
use std::time::{Duration, Instant};

/// All PostgreSQL integration fixtures use the shared infrastructure pin.
pub fn image() -> testcontainers::GenericImage {
    testcontainers::GenericImage::new(
        unrelated_test_support::images::POSTGRES.name,
        unrelated_test_support::images::POSTGRES.tag,
    )
}

pub async fn wait_pg_ready(database_url: &str, timeout: Duration) -> anyhow::Result<()> {
    let start = Instant::now();
    loop {
        if start.elapsed() > timeout {
            anyhow::bail!("timed out waiting for Postgres");
        }

        if sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(database_url)
            .await
            .is_ok()
        {
            return Ok(());
        }

        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

pub fn extract_dbmate_up(sql: &str) -> anyhow::Result<String> {
    let (_, rest) = sql
        .split_once("-- migrate:up")
        .context("missing dbmate marker: -- migrate:up")?;
    let (up, _) = rest
        .split_once("-- migrate:down")
        .context("missing dbmate marker: -- migrate:down")?;
    Ok(up.trim().to_string())
}

pub async fn apply_dbmate_migrations(database_url: &str) -> anyhow::Result<()> {
    apply_dbmate_migrations_filtered(database_url, |_| true).await
}

pub async fn apply_dbmate_migrations_before(
    database_url: &str,
    filename: &str,
) -> anyhow::Result<()> {
    apply_dbmate_migrations_filtered(database_url, |path| {
        path.file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name < filename)
    })
    .await
}

pub async fn apply_dbmate_migrations_from(
    database_url: &str,
    filename: &str,
) -> anyhow::Result<()> {
    apply_dbmate_migrations_filtered(database_url, |path| {
        path.file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name >= filename)
    })
    .await
}

pub async fn apply_dbmate_migration_file(database_url: &str, filename: &str) -> anyhow::Result<()> {
    apply_dbmate_migrations_filtered(database_url, |path| {
        path.file_name().and_then(|name| name.to_str()) == Some(filename)
    })
    .await
}

async fn apply_dbmate_migrations_filtered(
    database_url: &str,
    include: impl Fn(&std::path::Path) -> bool,
) -> anyhow::Result<()> {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(database_url)
        .await
        .context("connect to Postgres for migrations")?;

    // Ensure required extensions exist (UUIDs are used as primary keys).
    sqlx::query("create extension if not exists pgcrypto")
        .execute(&pool)
        .await
        .context("create extension pgcrypto")?;

    // In gateway tests, CARGO_MANIFEST_DIR points at `crates/gateway`.
    let migrations_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
    let mut paths: Vec<std::path::PathBuf> = std::fs::read_dir(&migrations_dir)
        .with_context(|| format!("read migrations dir {}", migrations_dir.display()))?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|ext| ext == "sql"))
        .filter(|p| include(p))
        .collect();
    paths.sort();

    for path in paths {
        let sql = std::fs::read_to_string(&path)
            .with_context(|| format!("read migration {}", path.display()))?;
        let up = extract_dbmate_up(&sql)?;
        // Execute each migration inside a transaction for better failure isolation.
        let mut tx = pool.begin().await.context("begin migration tx")?;
        // PostgreSQL parses dollar-quoted function bodies and statement boundaries.
        // Input is exclusively checked-in migration SQL, never request data.
        sqlx::raw_sql(sqlx::AssertSqlSafe(up.as_str()))
            .execute(&mut *tx)
            .await
            .with_context(|| format!("execute migration {}", path.display()))?;
        tx.commit().await.context("commit migration tx")?;
    }

    Ok(())
}
