use anyhow::Context as _;
use std::time::{Duration, Instant};

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

fn strip_sql_line_comments(sql: &str) -> String {
    // NOTE: This is a deliberately small helper for our migrations:
    // - It removes `-- ...` comments so semicolons in comments don't break statement splitting.
    // - It does not attempt to understand string literals; our migrations avoid `--` inside strings.
    let mut out = String::with_capacity(sql.len());
    for line in sql.lines() {
        let code = line.split_once("--").map_or(line, |(code, _)| code);
        out.push_str(code);
        out.push('\n');
    }
    out
}

pub async fn apply_dbmate_migrations(database_url: &str) -> anyhow::Result<()> {
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
        .collect();
    paths.sort();

    for path in paths {
        let sql = std::fs::read_to_string(&path)
            .with_context(|| format!("read migration {}", path.display()))?;
        let up = extract_dbmate_up(&sql)?;
        let up = strip_sql_line_comments(&up);
        // Execute each migration inside a transaction for better failure isolation.
        let mut tx = pool.begin().await.context("begin migration tx")?;
        for stmt in up.split(';') {
            let stmt = stmt.trim();
            if stmt.is_empty() {
                continue;
            }
            sqlx::query(stmt).execute(&mut *tx).await.with_context(|| {
                format!(
                    "execute migration statement from {}:\n{}",
                    path.display(),
                    stmt
                )
            })?;
        }
        tx.commit().await.context("commit migration tx")?;
    }

    Ok(())
}
