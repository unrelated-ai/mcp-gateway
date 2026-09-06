#[allow(unused_imports)]
mod common;
#[path = "common/journey.rs"]
#[allow(dead_code)]
mod journey;

use anyhow::Context as _;
use journey::{Gateway, GatewayOptions, PROFILE_ID, RemoteServer};
use std::{
    sync::atomic::Ordering,
    time::{Duration, Instant},
};
use unrelated_cli::{catalog::stable_ref, client};

async fn call(
    connection: &client::GatewayConnection,
    tool: &rmcp::model::Tool,
) -> anyhow::Result<serde_json::Value> {
    let result = client::call_tool(
        connection,
        tool,
        serde_json::Map::new(),
        Duration::from_secs(5),
    )
    .await?;
    anyhow::ensure!(result.is_error != Some(true), "tool failed: {result:?}");
    Ok(serde_json::to_value(result)?)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires sibling Adapter, stdio fixture and unrelated binaries; make test-v1-journey"]
#[allow(clippy::too_many_lines)]
async fn real_clients_keep_session_across_replicas_and_restarts() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let remote = RemoteServer::start(None, "generation-one").await?;
    let (_adapter, adapter_url) = journey::start_adapter(dir.path()).await?;
    let config = journey::mode1_config(
        dir.path(),
        &[("remote", remote.url()), ("adapter", adapter_url)],
        true,
    )?;
    let mut first = Gateway::start(
        dir.path(),
        "gateway-one",
        GatewayOptions {
            config: Some(&config),
            ..GatewayOptions::default()
        },
    )
    .await?;
    let second = Gateway::start(
        dir.path(),
        "gateway-two",
        GatewayOptions {
            config: Some(&config),
            ..GatewayOptions::default()
        },
    )
    .await?;
    let (proxy_url, proxy, proxy_task) = journey::start_proxy(&first.data_base).await?;
    let url = format!("{proxy_url}/{PROFILE_ID}/mcp");
    let connection = journey::connect(&url).await?;
    let catalog = client::fetch_catalog(&connection).await?;
    assert_eq!(catalog.tools.len(), 2);
    let echo = catalog.find("remote:echo").context("remote echo")?;
    let whoami = catalog
        .find("adapter:whoami")
        .context("Adapter stdio whoami")?;
    assert_eq!(
        call(&connection, echo).await?["content"][0]["text"],
        "generation-one"
    );
    let identity = call(&connection, whoami).await?;
    let identity: serde_json::Value = serde_json::from_str(
        identity["content"][0]["text"]
            .as_str()
            .context("stdio result")?,
    )?;
    let original_session = proxy.sessions.lock().unwrap()[0].clone();

    // Reusing the connection also reuses the downstream token and Adapter session.
    *proxy.backend.write().await = second.data_base.clone();
    assert_eq!(client::fetch_catalog(&connection).await?.tools.len(), 2);
    assert_eq!(
        call(&connection, echo).await?["content"][0]["text"],
        "generation-one"
    );
    let second_identity = call(&connection, whoami).await?;
    let second_identity: serde_json::Value =
        serde_json::from_str(second_identity["content"][0]["text"].as_str().unwrap())?;
    assert_eq!(second_identity["instanceId"], identity["instanceId"]);

    first.process.stop()?;
    let restarted = Gateway::start(
        dir.path(),
        "gateway-restarted",
        GatewayOptions {
            config: Some(&config),
            ..GatewayOptions::default()
        },
    )
    .await?;
    *proxy.backend.write().await = restarted.data_base.clone();
    assert_eq!(
        call(&connection, echo).await?["content"][0]["text"],
        "generation-one"
    );
    assert!(call(&connection, whoami).await?["content"][0]["text"].is_string());

    // Sessionless upstream replacement at the bound URL needs no new initialize.
    let address = remote.address;
    remote.stop().await;
    let replacement = RemoteServer::start(Some(address), "generation-two").await?;
    assert_eq!(
        call(&connection, echo).await?["content"][0]["text"],
        "generation-two"
    );
    assert_eq!(
        replacement.control.initializations.load(Ordering::SeqCst),
        0
    );
    assert!(
        proxy
            .sessions
            .lock()
            .unwrap()
            .iter()
            .all(|session| session == &original_session)
    );

    journey::cli(
        dir.path(),
        &["context", "add", "journey", "--url", &url, "--auth", "none"],
    )
    .await?;
    let searched = journey::cli(dir.path(), &["--json", "tools", "search", "sessionless"]).await?;
    assert_eq!(searched[0]["toolRef"], "remote:echo");
    let described =
        journey::cli(dir.path(), &["--json", "tools", "describe", "remote:echo"]).await?;
    assert_eq!(described["name"], echo.name.as_ref());
    let called = journey::cli(
        dir.path(),
        &[
            "--json",
            "tools",
            "call",
            "remote:echo",
            "--input",
            "{}",
            "--yes",
        ],
    )
    .await?;
    assert_eq!(called["content"][0]["text"], "generation-two");
    journey::exercise_compact_proxy(dir.path()).await?;
    connection.cancel().await?;
    replacement.stop().await;
    proxy_task.abort();
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real Gateway process; make test-v1-journey"]
async fn slow_upstream_obeys_deadline_for_initialize_and_discovery() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let healthy = RemoteServer::start(None, "healthy").await?;
    let slow = RemoteServer::start(None, "slow").await?;
    slow.control
        .initialize_delay_ms
        .store(3000, Ordering::SeqCst);
    let config = journey::mode1_config(
        dir.path(),
        &[("healthy", healthy.url()), ("slow", slow.url())],
        true,
    )?;
    let gateway = Gateway::start(
        dir.path(),
        "gateway-partial",
        GatewayOptions {
            config: Some(&config),
            operation_timeout_secs: 1,
            ..GatewayOptions::default()
        },
    )
    .await?;
    let started = Instant::now();
    let connection = journey::connect(&format!("{}/{PROFILE_ID}/mcp", gateway.data_base)).await?;
    assert!(started.elapsed() < Duration::from_millis(2500));
    let catalog = client::fetch_catalog(&connection).await?;
    assert_eq!(
        catalog.tools.iter().map(stable_ref).collect::<Vec<_>>(),
        ["healthy:echo"]
    );
    assert_eq!(
        call(&connection, &catalog.tools[0]).await?["content"][0]["text"],
        "healthy"
    );
    connection.cancel().await?;

    slow.control.initialize_delay_ms.store(0, Ordering::SeqCst);
    slow.control.list_delay_ms.store(3000, Ordering::SeqCst);
    let connection = journey::connect(&format!("{}/{PROFILE_ID}/mcp", gateway.data_base)).await?;
    let started = Instant::now();
    let catalog = client::fetch_catalog(&connection).await?;
    assert!(started.elapsed() < Duration::from_millis(2500));
    assert_eq!(
        catalog.tools.iter().map(stable_ref).collect::<Vec<_>>(),
        ["healthy:echo"]
    );
    connection.cancel().await?;

    let strict_config = journey::mode1_config(
        dir.path(),
        &[("healthy", healthy.url()), ("slow", slow.url())],
        false,
    )?;
    slow.control
        .initialize_delay_ms
        .store(3000, Ordering::SeqCst);
    let strict = Gateway::start(
        dir.path(),
        "gateway-strict",
        GatewayOptions {
            config: Some(&strict_config),
            operation_timeout_secs: 1,
            ..GatewayOptions::default()
        },
    )
    .await?;
    let started = Instant::now();
    assert!(
        journey::connect(&format!("{}/{PROFILE_ID}/mcp", strict.data_base))
            .await
            .is_err()
    );
    assert!(started.elapsed() < Duration::from_millis(2500));
    healthy.stop().await;
    slow.stop().await;
    Ok(())
}
