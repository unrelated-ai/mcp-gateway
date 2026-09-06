//! Disposable real services for the standalone UI browser suite.
#[allow(unused_imports)]
mod common;
#[path = "common/journey.rs"]
#[allow(dead_code)]
mod journey;
#[path = "common/journey_pg.rs"]
#[allow(dead_code)]
mod journey_pg;

use anyhow::Context as _;
use journey::{Gateway, GatewayOptions, RemoteServer};
use serde_json::json;
use std::{path::PathBuf, time::Duration};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "UI browser fixture; run make test-ui-e2e"]
async fn standalone_ui_fixture() -> anyhow::Result<()> {
    let state =
        PathBuf::from(std::env::var("MCP_UI_FIXTURE_STATE").context("run make test-ui-e2e")?);
    let done = state.with_extension("done");
    anyhow::ensure!(state.is_absolute() && !state.exists() && !done.exists());
    let dir = tempfile::tempdir()?;
    let (_pg, database_url) = journey_pg::start(false).await?;
    common::pg::apply_dbmate_migrations(&database_url).await?;
    let (_adapter, adapter_url) = journey::start_adapter(dir.path()).await?;
    let remote = RemoteServer::start(None, "ui-e2e").await?;
    let gateway = Gateway::start(
        dir.path(),
        "ui-gateway",
        GatewayOptions {
            database_url: Some(&database_url),
            bootstrap_enabled: true,
            ..GatewayOptions::default()
        },
    )
    .await?;
    std::fs::write(
        &state,
        serde_json::to_vec(&json!({
            "adminBase": gateway.admin_base,
            "dataBase": gateway.data_base,
            "remoteUrl": remote.url(),
            "adapterUrl": adapter_url,
            "cli": journey::sibling_binary("unrelated")?,
        }))?,
    )?;
    let finished = tokio::time::timeout(Duration::from_secs(900), async {
        while !done.exists() {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await;
    remote.stop().await;
    std::fs::remove_file(&state)?;
    if done.exists() {
        std::fs::remove_file(done)?;
    }
    finished.context("browser suite did not finish within 15 minutes")?;
    Ok(())
}
