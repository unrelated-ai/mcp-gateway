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
    let http_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let http_base = format!("http://{}", http_listener.local_addr()?);
    let http_api = tokio::spawn(async move {
        axum::serve(
            http_listener,
            axum::Router::new()
                .route("/items/{id}", axum::routing::post(http_echo))
                .route("/mcp", axum::routing::post(catalog_fixture)),
        )
        .await
        .unwrap();
    });
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
            "httpBase": http_base,
            "adapterUrl": adapter_url,
            "cli": journey::sibling_binary("unrelated")?,
        }))?,
    )?;
    let finished = tokio::time::timeout(Duration::from_mins(15), async {
        while !done.exists() {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await;
    remote.stop().await;
    http_api.abort();
    std::fs::remove_file(&state)?;
    if done.exists() {
        std::fs::remove_file(done)?;
    }
    finished.context("browser suite did not finish within 15 minutes")?;
    Ok(())
}

async fn http_echo(
    axum::extract::Path(id): axum::extract::Path<String>,
    axum::extract::Query(query): axum::extract::Query<std::collections::HashMap<String, String>>,
    headers: axum::http::HeaderMap,
    axum::Json(body): axum::Json<serde_json::Value>,
) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
    if headers.get("authorization").and_then(|v| v.to_str().ok()) != Some("Bearer local-http-token")
    {
        return (
            axum::http::StatusCode::UNAUTHORIZED,
            axum::Json(json!({"error":"missing fixture token"})),
        );
    }
    (
        axum::http::StatusCode::OK,
        axum::Json(
            json!({"id":id,"query":query,"caller":headers.get("x-client").and_then(|v|v.to_str().ok()),"body":body}),
        ),
    )
}

async fn catalog_fixture(
    axum::Json(body): axum::Json<serde_json::Value>,
) -> axum::response::Response {
    use axum::response::IntoResponse as _;
    let result = match body["method"].as_str().unwrap_or("") {
        "server/discover" => serde_json::to_value(rmcp::model::DiscoverResult::new(
            vec![rmcp::model::ProtocolVersion::V_2026_07_28],
            rmcp::model::ServerCapabilities::builder().enable_tools().enable_resources().enable_prompts().build(),
        )).unwrap(),
        "initialize" => json!({"protocolVersion":"2025-11-25","capabilities":{"tools":{},"resources":{},"prompts":{}},"serverInfo":{"name":"catalog-demo","version":"1"}}),
        "notifications/initialized" => return axum::http::StatusCode::ACCEPTED.into_response(),
        "tools/list" => json!({"tools":[{"name":"lookup","description":"Look up an item","inputSchema":{"type":"object"}}]}),
        "resources/list" => json!({"resources":[{"uri":"docs:///guide","name":"Guide","description":"Upstream guide"}]}),
        "resources/templates/list" => json!({"resourceTemplates":[{"uriTemplate":"docs:///orders/{id}","name":"Orders","description":"Order documents"}]}),
        "prompts/list" => json!({"prompts":[{"name":"review","description":"Review changes","arguments":[{"name":"topic","required":true},{"name":"audience"}]}]}),
        _ => return axum::Json(json!({"jsonrpc":"2.0","id":body["id"],"error":{"code":-32601,"message":"Method not found"}})).into_response(),
    };
    axum::Json(json!({"jsonrpc":"2.0","id":body["id"],"result":result})).into_response()
}
