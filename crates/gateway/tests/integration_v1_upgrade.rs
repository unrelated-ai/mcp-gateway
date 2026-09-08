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
use serde_json::{Value, json};
use sqlx::Row as _;
use std::{
    path::Path,
    time::{Duration, Instant},
};

const MIGRATION: &str = "20260712000000_oauth_resource_server.sql";

async fn profile(
    client: &reqwest::Client,
    gateway: &Gateway,
    token: &str,
) -> anyhow::Result<Value> {
    Ok(client
        .get(format!(
            "{}/tenant/v1/profiles/{PROFILE_ID}",
            gateway.admin_base
        ))
        .bearer_auth(token)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "Docker, sibling binaries and MCP_GATEWAY_0131_BIN; see V1_UPGRADE.md"]
#[allow(clippy::too_many_lines)]
async fn public_0131_database_upgrades_with_existing_profiles_keys_and_sessions()
-> anyhow::Result<()> {
    let old_binary = std::env::var("MCP_GATEWAY_0131_BIN")
        .context("set MCP_GATEWAY_0131_BIN to the public 0.13.1 executable")?;
    let version = std::process::Command::new(&old_binary)
        .arg("--version")
        .output()?;
    anyhow::ensure!(
        version.status.success()
            && String::from_utf8_lossy(&version.stdout).trim() == "unrelated-mcp-gateway 0.13.1",
        "expected public 0.13.1 binary"
    );
    let dir = tempfile::tempdir()?;
    let (_pg, database_url) = journey_pg::start(false).await?;
    common::pg::apply_dbmate_migrations_before(&database_url, MIGRATION).await?;
    let (_adapter, adapter_url) = journey::start_adapter(dir.path()).await?;
    let mut old = Gateway::start(
        dir.path(),
        "public-0131",
        GatewayOptions {
            binary: Path::new(&old_binary),
            database_url: Some(&database_url),
            ..GatewayOptions::default()
        },
    )
    .await?;
    let token = journey_pg::seed_tenant(&old.admin_base).await?;
    journey_pg::seed_upstream(&old.admin_base, "adapter", &adapter_url).await?;
    journey_pg::seed_profile(
        &old.admin_base,
        &["adapter".to_string()],
        json!({"mode":"apiKeyInitializeOnly", "acceptXApiKey":true}),
    )
    .await?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()?;
    let key: Value = client
        .post(format!("{}/tenant/v1/api-keys", old.admin_base))
        .bearer_auth(&token)
        .json(&json!({"name":"created-on-0131", "profileId":PROFILE_ID}))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let secret = key["secret"].as_str().context("API-key secret")?;
    let before = profile(&client, &old, &token).await?;
    let session = McpSession::connect(
        format!("{}/{PROFILE_ID}/mcp", old.data_base),
        Some(secret.to_string()),
    )
    .await?;
    let catalog = session
        .request_value_no_auth(1, "tools/list", json!({}))
        .await?;
    assert_eq!(catalog["result"]["tools"].as_array().unwrap().len(), 1);
    let tool = catalog["result"]["tools"][0]["name"]
        .as_str()
        .context("Adapter tool")?;
    let called = session
        .request_value(2, "tools/call", json!({"name":tool,"arguments":{}}))
        .await?;
    assert!(called.get("error").is_none(), "{called}");
    let old_session = session.session_id().to_string();
    old.process.stop()?;

    // This is a maintenance-window migration: no old Gateway remains running.
    common::pg::apply_dbmate_migration_file(&database_url, MIGRATION).await?;
    let candidate = Gateway::start(
        dir.path(),
        "v1",
        GatewayOptions {
            database_url: Some(&database_url),
            ..GatewayOptions::default()
        },
    )
    .await?;
    let after = profile(&client, &candidate, &token).await?;
    for field in [
        "id",
        "name",
        "description",
        "upstreams",
        "toolCallTimeoutSecs",
    ] {
        assert_eq!(after[field], before[field], "{field}");
    }
    assert_eq!(after["dataPlaneAuth"]["mode"], "apiKey");
    assert_eq!(after["dataPlaneAuth"]["acceptXApiKey"], true);

    let url = format!("{}/{PROFILE_ID}/mcp", candidate.data_base);
    let request =
        json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":tool,"arguments":{}}});
    let response = client
        .post(&url)
        .header("accept", "application/json, text/event-stream")
        .header("mcp-session-id", &old_session)
        .bearer_auth(secret)
        .json(&request)
        .send()
        .await?;
    assert!(
        response.status().is_success(),
        "old signed routing token must remain usable: {}",
        response.status()
    );
    let result: Value = if response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("text/event-stream"))
    {
        common::sse::read_first_event_stream_json_message(response).await?
    } else {
        response.json().await?
    };
    assert!(result.get("error").is_none(), "{result}");
    assert!(
        result["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("instanceId")
    );
    let without_key = client
        .post(&url)
        .header("accept", "application/json, text/event-stream")
        .header("mcp-session-id", &old_session)
        .json(&request)
        .send()
        .await?;
    assert_eq!(without_key.status(), reqwest::StatusCode::UNAUTHORIZED);

    // Introduce a sessionless upstream after the migration and exercise the real CLI.
    let remote = RemoteServer::start(None, "after-upgrade").await?;
    journey_pg::seed_upstream(&candidate.admin_base, "remote", &remote.url()).await?;
    let response = client
        .put(format!(
            "{}/tenant/v1/profiles/{PROFILE_ID}",
            candidate.admin_base
        ))
        .bearer_auth(&token)
        .json(&json!({"upstreams":["adapter","remote"]}))
        .send()
        .await?;
    assert!(response.status().is_success(), "{}", response.text().await?);
    journey::cli(
        dir.path(),
        &[
            "context", "add", "journey", "--url", &url, "--auth", "api-key",
        ],
    )
    .await?;
    let searched = journey::cli_with_token(
        dir.path(),
        &["--json", "tools", "search", "sessionless"],
        Some(secret),
    )
    .await?;
    assert_eq!(searched[0]["toolRef"], "remote:echo");
    let result = journey::cli_with_token(
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
        Some(secret),
    )
    .await?;
    assert_eq!(result["content"][0]["text"], "after-upgrade");
    let result = journey::cli_with_token(
        dir.path(),
        &[
            "--json",
            "tools",
            "call",
            "adapter:whoami",
            "--input",
            "{}",
            "--yes",
        ],
        Some(secret),
    )
    .await?;
    assert!(
        result["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("instanceId")
    );
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&database_url)
        .await?;
    let row =
        sqlx::query("select data_plane_auth_mode, accept_x_api_key from profiles where id = $1")
            .bind(uuid::Uuid::parse_str(PROFILE_ID)?)
            .fetch_one(&pool)
            .await?;
    assert_eq!(row.try_get::<String, _>("data_plane_auth_mode")?, "api_key");
    assert!(row.try_get::<bool, _>("accept_x_api_key")?);

    // Optional local handoff to a browser. Nothing is exported by default.
    if let Ok(path) = std::env::var("MCP_V1_UPGRADE_UI_STATE") {
        let path = Path::new(&path);
        let done = path.with_extension("done");
        anyhow::ensure!(
            !path.exists() && !done.exists(),
            "use a fresh UI state path"
        );
        std::fs::write(
            path,
            serde_json::to_vec_pretty(
                &json!({"adminBase":candidate.admin_base, "dataBase":candidate.data_base, "tenantToken":token, "profileId":PROFILE_ID}),
            )?,
        )?;
        eprintln!(
            "upgrade passed; UI fixture ready at {}; create {} to finish",
            path.display(),
            done.display()
        );
        let started = Instant::now();
        while !done.exists() && started.elapsed() < Duration::from_mins(30) {
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        let finished = done.exists();
        std::fs::remove_file(path)?;
        if finished {
            std::fs::remove_file(done)?;
        }
        anyhow::ensure!(finished, "UI rehearsal handoff timed out");
    }
    remote.stop().await;
    Ok(())
}
