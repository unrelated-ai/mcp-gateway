//! Opt-in repeatable Mode 3 benchmark. No external services or existing databases are touched.
#[allow(unused_imports)]
mod common;
#[path = "common/journey.rs"]
#[allow(dead_code)]
mod journey;
#[path = "common/journey_pg.rs"]
mod journey_pg;

use anyhow::Context as _;
use common::mcp::McpSession;
use journey::{Gateway, GatewayOptions, PROFILE_ID, RemoteServer};
use serde::Serialize;
use serde_json::json;
use sqlx::{PgPool, Row as _};
use std::{path::Path, sync::atomic::Ordering, time::Instant};

#[derive(Serialize)]
struct Sample {
    upstreams: usize,
    concurrency: usize,
    iteration: usize,
    phase: &'static str,
    elapsed_ms: f64,
    database_statements: i64,
    gateway_rss_kib: u64,
}

async fn statement_count(pool: &PgPool) -> anyhow::Result<i64> {
    // The observer uses postgres, while the Gateway has its own role. Observer
    // queries and migrations therefore cannot contaminate Gateway statement counts.
    Ok(sqlx::query("select coalesce(sum(calls), 0)::bigint as calls from pg_stat_statements where userid = (select oid from pg_roles where rolname = 'gateway_bench')")
        .fetch_one(pool).await?.try_get("calls")?)
}

fn rss_kib(pid: u32) -> anyhow::Result<u64> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status"))?;
    status
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:"))
        .context("VmRSS")?
        .split_whitespace()
        .next()
        .context("RSS value")?
        .parse()
        .context("RSS integer")
}

struct Measurement<'a> {
    pool: &'a PgPool,
    gateway: &'a Gateway,
    upstreams: usize,
    concurrency: usize,
    iteration: usize,
}

impl Measurement<'_> {
    async fn record<T>(
        &self,
        samples: &mut Vec<Sample>,
        phase: &'static str,
        operation: impl Future<Output = anyhow::Result<T>>,
    ) -> anyhow::Result<T> {
        let before = statement_count(self.pool).await?;
        let started = Instant::now();
        let result = operation.await?;
        let elapsed_ms = started.elapsed().as_secs_f64() * 1000.0;
        samples.push(Sample {
            upstreams: self.upstreams,
            concurrency: self.concurrency,
            iteration: self.iteration,
            phase,
            elapsed_ms,
            database_statements: statement_count(self.pool).await? - before,
            gateway_rss_kib: rss_kib(self.gateway.process.child.id())?,
        });
        Ok(result)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "Linux, Docker and release build; make bench-v1"]
#[allow(clippy::too_many_lines)]
async fn benchmark_upstream_scaling() -> anyhow::Result<()> {
    anyhow::ensure!(
        !cfg!(debug_assertions),
        "Use --release for benchmark results"
    );
    let output = std::env::var("MCP_V1_BENCH_OUTPUT")
        .context("set MCP_V1_BENCH_OUTPUT to an output JSON path")?;
    let iterations = std::env::var("MCP_V1_BENCH_SAMPLES")
        .ok()
        .map(|s| s.parse::<usize>())
        .transpose()?
        .unwrap_or(10);
    anyhow::ensure!(iterations > 0, "samples must be positive");
    let dir = tempfile::tempdir()?;
    let (_pg, database_url) = journey_pg::start(true).await?;
    common::pg::apply_dbmate_migrations(&database_url).await?;
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&database_url)
        .await?;
    sqlx::raw_sql("CREATE EXTENSION pg_stat_statements; CREATE ROLE gateway_bench LOGIN PASSWORD 'bench'; GRANT USAGE ON SCHEMA public TO gateway_bench; GRANT ALL ON ALL TABLES IN SCHEMA public TO gateway_bench; GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO gateway_bench;").execute(&pool).await?;
    let gateway_url = database_url.replacen("postgres:postgres@", "gateway_bench:bench@", 1);
    let seed = Gateway::start(
        dir.path(),
        "seed",
        GatewayOptions {
            database_url: Some(&database_url),
            ..GatewayOptions::default()
        },
    )
    .await?;
    journey_pg::seed_tenant(&seed.admin_base).await?;
    let mut servers = Vec::new();
    let ids: Vec<String> = (0..50).map(|i| format!("u{i:02}")).collect();
    for id in &ids {
        let server = RemoteServer::start(None, "benchmark").await?;
        server
            .control
            .initialize_delay_ms
            .store(20, Ordering::SeqCst);
        server.control.list_delay_ms.store(20, Ordering::SeqCst);
        journey_pg::seed_upstream(&seed.admin_base, id, &server.url()).await?;
        servers.push(server);
    }
    let mut samples = Vec::new();
    for upstreams in [1, 10, 50] {
        journey_pg::seed_profile(
            &seed.admin_base,
            &ids[..upstreams],
            json!({"mode":"disabled"}),
        )
        .await?;
        for concurrency in [1, 8, 16] {
            for iteration in 0..iterations {
                let gateway = Gateway::start(
                    dir.path(),
                    "measured",
                    GatewayOptions {
                        database_url: Some(&gateway_url),
                        concurrency,
                        ..GatewayOptions::default()
                    },
                )
                .await?;
                let measure = Measurement {
                    pool: &pool,
                    gateway: &gateway,
                    upstreams,
                    concurrency,
                    iteration,
                };
                let url = format!("{}/{PROFILE_ID}/mcp", gateway.data_base);
                let session = measure
                    .record(
                        &mut samples,
                        "cold_initialize",
                        McpSession::connect(url.clone(), None),
                    )
                    .await?;
                let catalog = measure
                    .record(
                        &mut samples,
                        "cold_discovery",
                        session.request_value(1, "tools/list", json!({})),
                    )
                    .await?;
                anyhow::ensure!(
                    catalog["result"]["tools"]
                        .as_array()
                        .context("tools")?
                        .len()
                        == upstreams,
                    "incomplete catalog: {catalog}"
                );
                let refreshed = measure
                    .record(
                        &mut samples,
                        "warm_discovery",
                        session.request_value(2, "tools/list", json!({})),
                    )
                    .await?;
                anyhow::ensure!(
                    refreshed["result"]["tools"]
                        .as_array()
                        .context("tools")?
                        .len()
                        == upstreams
                );
                let tool = catalog["result"]["tools"][0]["name"]
                    .as_str()
                    .context("tool name")?;
                let called = measure
                    .record(
                        &mut samples,
                        "warm_call",
                        session.request_value(3, "tools/call", json!({"name":tool,"arguments":{}})),
                    )
                    .await?;
                anyhow::ensure!(
                    called.get("error").is_none() && called["result"]["isError"] != true,
                    "{called}"
                );
                measure
                    .record(
                        &mut samples,
                        "warm_initialize",
                        McpSession::connect(url, None),
                    )
                    .await?;
            }
            eprintln!(
                "benchmark completed: {upstreams} upstreams, concurrency {concurrency}, {iterations} samples per phase"
            );
        }
    }
    let revision = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()?;
    let cpu = std::fs::read_to_string("/proc/cpuinfo")?
        .lines()
        .find(|line| line.starts_with("model name"))
        .unwrap_or("unknown")
        .to_string();
    let report = json!({"revision":String::from_utf8(revision.stdout)?.trim(), "iterations":iterations,
        "upstream_delay_ms":20, "upstream_implementation":"rmcp 2.2.0, sessionless, JSON responses, 50 independent loopback listeners in one fixture process",
        "client":"rmcp StreamableHttpClient plumbing (McpSession); initialize includes notifications/initialized; no background client GET stream",
        "database":"disposable PostgreSQL 16 with pg_stat_statements; separate Gateway role; counts include all statements executed by that role during each operation",
        "memory":"Gateway process VmRSS after each operation; excludes database and fixture", "cpu":cpu,
        "available_parallelism":std::thread::available_parallelism()?.get(), "samples":samples});
    if let Some(parent) = Path::new(&output).parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&output, serde_json::to_vec_pretty(&report)?)?;
    for server in servers {
        server.stop().await;
    }
    eprintln!("benchmark report: {output}");
    Ok(())
}
