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

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
#[allow(clippy::too_many_lines)]
async fn mixed_sources_tool_collision_is_prefixed_and_routed() -> anyhow::Result<()> {
    let httpbin = GenericImage::new(images::HTTPBIN.name, images::HTTPBIN.tag)
        .with_exposed_port(80.tcp())
        .start()
        .await
        .context("start httpbin container")?;

    let httpbin_host = httpbin.get_host().await?.to_string();
    let httpbin_port = httpbin.get_host_port_ipv4(80).await?;
    let httpbin_base = format!("http://{httpbin_host}:{httpbin_port}");
    wait_http_ok(&format!("{httpbin_base}/get"), Duration::from_secs(20)).await?;

    let petstore = GenericImage::new(images::PETSTORE.name, images::PETSTORE.tag)
        .with_exposed_port(8080.tcp())
        .start()
        .await
        .context("start petstore container")?;

    let pet_host = petstore.get_host().await?.to_string();
    let pet_port = petstore.get_host_port_ipv4(8080).await?;
    let pet_base = format!("http://{pet_host}:{pet_port}");

    wait_http_ok(
        &format!("{pet_base}/api/v3/openapi.json"),
        Duration::from_secs(60),
    )
    .await?;

    let dir = tempdir().context("create temp dir")?;
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
      addPet:
        method: GET
        path: /anything/addPet
  petstore:
    type: openapi
    spec: {pet_base}/api/v3/openapi.json
    baseUrl: {pet_base}/api/v3
    autoDiscover: true
#",
        ),
    )
    .context("write config")?;

    let port = pick_unused_port()?;
    let child = spawn_adapter(&cfg_path, port)?;
    let _child = KillOnDrop(child);

    let adapter_base = format!("http://127.0.0.1:{port}");
    wait_http_ok(&format!("{adapter_base}/health"), Duration::from_secs(30)).await?;

    let mcp = McpStreamableHttpSession::connect(&adapter_base).await?;

    let tools_list = mcp
        .request(1, "tools/list", json!({}), Duration::from_secs(10))
        .await?;

    let tools = tools_list
        .get("result")
        .and_then(|r| r.get("tools"))
        .and_then(serde_json::Value::as_array)
        .context("tools/list missing result.tools")?;

    let tool_names: Vec<&str> = tools
        .iter()
        .filter_map(|t| t.get("name").and_then(serde_json::Value::as_str))
        .collect();

    assert!(
        tool_names.contains(&"httpbin:addPet"),
        "expected httpbin:addPet in tools/list"
    );
    assert!(
        tool_names.contains(&"petstore:addPet"),
        "expected petstore:addPet in tools/list"
    );
    assert!(
        !tool_names.contains(&"addPet"),
        "expected unprefixed addPet to be removed on collision"
    );

    // Call httpbin tool via prefixed name.
    let httpbin_call = mcp
        .request(
            2,
            "tools/call",
            json!({ "name": "httpbin:addPet", "arguments": {} }),
            Duration::from_secs(10),
        )
        .await?;

    let httpbin_body = tool_call_body_json(&httpbin_call).context("httpbin:addPet body JSON")?;
    let url = httpbin_body
        .get("url")
        .and_then(serde_json::Value::as_str)
        .context("httpbin:addPet missing url")?;
    assert!(
        url.contains("/anything/addPet"),
        "expected httpbin url to contain /anything/addPet, got: {url}"
    );

    // Call petstore tool via prefixed name.
    let pet_id = 424_245_u64;
    let add_pet = mcp
        .request(
            3,
            "tools/call",
            json!({
                "name": "petstore:addPet",
                "arguments": {
                    "id": pet_id,
                    "name": "mcp-integration-test-mixed-pet",
                    "photoUrls": ["https://example.com/mixed.png"]
                }
            }),
            Duration::from_secs(20),
        )
        .await?;

    let added = tool_call_body_json(&add_pet).context("petstore:addPet body JSON")?;
    assert_eq!(added.get("id"), Some(&json!(pet_id)));
    assert_eq!(
        added.get("name"),
        Some(&json!("mcp-integration-test-mixed-pet"))
    );

    Ok(())
}
