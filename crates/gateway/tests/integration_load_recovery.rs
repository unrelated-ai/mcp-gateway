//! Private, bounded load and recovery acceptance test, using disposable PostgreSQL.
#[allow(unused_imports)]
mod common;
#[path = "common/journey.rs"]
#[allow(dead_code)]
mod journey;
#[path = "common/journey_pg.rs"]
#[allow(dead_code)]
mod journey_pg;
use common::mcp::McpSession;
use futures::{StreamExt as _, TryStreamExt as _};
use journey::{Gateway, GatewayOptions, RemoteServer};
use serde_json::json;
use std::{
    sync::atomic::Ordering,
    time::{Duration, Instant},
};

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "Docker and real Gateway process; private load/recovery rehearsal"]
#[allow(clippy::too_many_lines)] // Keep the workload and recovery sequence together.
async fn concurrent_tenants_large_catalogs_churn_and_restart() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let (_pg, database) = journey_pg::start(false).await?;
    common::pg::apply_dbmate_migrations(&database).await?;
    let mut gateway = Gateway::start(
        dir.path(),
        "load",
        GatewayOptions {
            database_url: Some(&database),
            operation_timeout_secs: 1,
            ..GatewayOptions::default()
        },
    )
    .await?;
    let mut servers = Vec::new();
    let mut profiles = Vec::new();
    for tenant in ["load0", "load1", "load2", "load3"] {
        let remote = RemoteServer::start(None, tenant).await?;
        remote.control.tool_count.store(2000, Ordering::SeqCst);
        journey_pg::admin(
            &gateway.admin_base,
            "/admin/v1/tenants",
            json!({"id":tenant,"enabled":true}),
        )
        .await?;
        journey_pg::seed_upstream(&gateway.admin_base, tenant, &remote.url()).await?;
        let id = uuid::Uuid::new_v4().to_string();
        journey_pg::admin(&gateway.admin_base, "/admin/v1/profiles", json!({"id":id,"tenantId":tenant,"name":tenant,"enabled":true,"upstreams":[tenant],"dataPlaneAuth":{"mode":"disabled"}})).await?;
        profiles.push((id, tenant));
        servers.push(remote);
    }
    let started = Instant::now();
    let latencies: Vec<f64> = futures::stream::iter((0..160).map(|index| {
        let (id, tenant) = profiles[index % profiles.len()].clone();
        let url = format!("{}/{id}/mcp", gateway.data_base);
        async move {
            let started = Instant::now();
            let session = McpSession::connect(url.clone(), None).await?;
            let list = session.request_value(1, "tools/list", json!({})).await?;
            assert_eq!(list["result"]["tools"].as_array().unwrap().len(), 2000);
            let call = session
                .request_value(2, "tools/call", json!({"name":"echo","arguments":{}}))
                .await?;
            assert_eq!(call["result"]["content"][0]["text"], tenant);
            reqwest::Client::new()
                .delete(url)
                .header("Mcp-Session-Id", session.session_id())
                .send()
                .await?
                .error_for_status()?;
            Ok::<_, anyhow::Error>(started.elapsed().as_secs_f64() * 1000.0)
        }
    }))
    .buffer_unordered(16)
    .try_collect()
    .await?;
    let mut sorted = latencies;
    sorted.sort_by(f64::total_cmp);
    eprintln!(
        "load: 4 tenants, 2000 tools each, 16 clients, 160 initialize/list/call/delete cycles; elapsed={:.2}s, cycle p50={:.1}ms p95={:.1}ms",
        started.elapsed().as_secs_f64(),
        sorted[80],
        sorted[152]
    );
    // A slow tenant's source must time out without holding another tenant's catalog.
    servers[0]
        .control
        .list_delay_ms
        .store(3000, Ordering::SeqCst);
    let slow =
        McpSession::connect(format!("{}/{}/mcp", gateway.data_base, profiles[0].0), None).await?;
    let fast =
        McpSession::connect(format!("{}/{}/mcp", gateway.data_base, profiles[1].0), None).await?;
    let started = Instant::now();
    let (slow_result, fast_result) = tokio::join!(
        slow.request_value(3, "tools/list", json!({})),
        fast.request_value(3, "tools/list", json!({}))
    );
    // The default profile permits partial catalogs while the unavailable source times out.
    assert_eq!(slow_result?["result"]["tools"], json!([]));
    assert_eq!(
        fast_result?["result"]["tools"].as_array().unwrap().len(),
        2000
    );
    assert!(started.elapsed() < Duration::from_secs(3));
    servers[0].control.list_delay_ms.store(0, Ordering::SeqCst);
    let retry = slow.request_value(4, "tools/list", json!({})).await?;
    assert_eq!(retry["result"]["tools"].as_array().unwrap().len(), 2000);
    gateway.process.stop()?;
    let recovered = Gateway::start(
        dir.path(),
        "recovered",
        GatewayOptions {
            database_url: Some(&database),
            ..GatewayOptions::default()
        },
    )
    .await?;
    let response = reqwest::Client::new()
        .post(format!("{}/{}/mcp", recovered.data_base, profiles[1].0))
        .header("Mcp-Session-Id", fast.session_id())
        .header("accept", "application/json, text/event-stream")
        .json(&json!({"jsonrpc":"2.0","id":4,"method":"tools/list","params":{}}))
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;
    assert!(response.contains("tool_1999"));
    for server in servers {
        server.stop().await;
    }
    Ok(())
}
