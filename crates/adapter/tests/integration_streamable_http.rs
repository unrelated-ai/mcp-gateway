use unrelated_test_support::images;
mod common;
mod common_mcp;

use anyhow::Context as _;
use serde_json::json;
use std::time::Duration;
use tempfile::tempdir;
use testcontainers::GenericImage;
use testcontainers::core::IntoContainerPort;
use testcontainers::runners::AsyncRunner;

use common::{KillOnDrop, pick_unused_port, spawn_adapter, wait_http_ok};
use common_mcp::{McpStreamableHttpSession, tool_call_body_json};

async fn start_httpbin() -> anyhow::Result<(testcontainers::ContainerAsync<GenericImage>, String)> {
    let httpbin = GenericImage::new(images::HTTPBIN.name, images::HTTPBIN.tag)
        .with_exposed_port(80.tcp())
        .start()
        .await
        .context("start httpbin container")?;

    let httpbin_host = httpbin.get_host().await?.to_string();
    let httpbin_port = httpbin.get_host_port_ipv4(80).await?;
    let httpbin_base = format!("http://{httpbin_host}:{httpbin_port}");

    wait_http_ok(&format!("{httpbin_base}/get"), Duration::from_secs(20)).await?;
    Ok((httpbin, httpbin_base))
}

fn write_httpbin_echo_config(
    dir: &tempfile::TempDir,
    httpbin_base: &str,
) -> anyhow::Result<std::path::PathBuf> {
    let cfg_path = dir.path().join("config.yaml");
    std::fs::write(
        &cfg_path,
        format!(
            r"imports: []
servers:
  httpbin:
    type: http
    baseUrl: {httpbin_base}
    tools:
      echo_request:
        method: POST
        path: /anything/{{id}}
        params:
          id: {{ in: path, required: true, schema: {{ type: string }} }}
          q: {{ in: query, schema: {{ type: string }} }}
          body: {{ in: body, schema: {{ type: object }} }}
#",
        ),
    )
    .context("write config")?;

    Ok(cfg_path)
}

async fn start_adapter_with_config(
    cfg_path: &std::path::Path,
) -> anyhow::Result<(String, KillOnDrop)> {
    let port = pick_unused_port()?;
    let child = spawn_adapter(cfg_path, port)?;
    let child = KillOnDrop(child);

    let base_url = format!("http://127.0.0.1:{port}");
    wait_http_ok(&format!("{base_url}/health"), Duration::from_secs(20)).await?;

    Ok((base_url, child))
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn streamable_http_tools_echo_request_roundtrip() -> anyhow::Result<()> {
    let (_httpbin, httpbin_base) = start_httpbin().await?;
    let dir = tempdir().context("create temp dir")?;
    let cfg_path = write_httpbin_echo_config(&dir, &httpbin_base)?;
    let (base_url, _adapter) = start_adapter_with_config(&cfg_path).await?;

    let session = McpStreamableHttpSession::connect(&base_url).await?;

    let tools_msg = session
        .request(1, "tools/list", json!({}), Duration::from_secs(10))
        .await?;
    let tools = tools_msg
        .get("result")
        .and_then(|r| r.get("tools"))
        .and_then(serde_json::Value::as_array)
        .context("tools/list missing result.tools")?;
    anyhow::ensure!(
        tools
            .iter()
            .any(|t| t.get("name") == Some(&json!("echo_request"))),
        "expected echo_request in tools/list"
    );

    let call_msg = session
        .request(
            2,
            "tools/call",
            json!({
                "name": "echo_request",
                "arguments": {
                    "id": "test-123",
                    "q": "hello",
                    "body": { "msg": "hello from streamable http integration test" }
                }
            }),
            Duration::from_secs(20),
        )
        .await?;
    let echoed = tool_call_body_json(&call_msg)?;
    anyhow::ensure!(echoed.get("method") == Some(&json!("POST")));
    anyhow::ensure!(
        echoed
            .get("json")
            .and_then(|j| j.get("msg"))
            .and_then(serde_json::Value::as_str)
            == Some("hello from streamable http integration test")
    );

    Ok(())
}
