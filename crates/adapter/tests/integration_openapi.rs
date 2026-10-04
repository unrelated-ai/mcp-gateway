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
async fn openapi_roundtrip_add_pet_and_get_pet() -> anyhow::Result<()> {
    let petstore = GenericImage::new(images::PETSTORE.name, images::PETSTORE.tag)
        .with_exposed_port(8080.tcp())
        .start()
        .await
        .context("start petstore container")?;

    let host = petstore.get_host().await?.to_string();
    let port = petstore.get_host_port_ipv4(8080).await?;
    let base = format!("http://{host}:{port}");

    wait_http_ok(
        &format!("{base}/api/v3/openapi.json"),
        Duration::from_secs(60),
    )
    .await?;

    let dir = tempdir().context("create temp dir")?;

    // ---------------------------------------------------------------------
    // Case 1: Baseline auto-discovery (existing roundtrip)
    // ---------------------------------------------------------------------
    {
        let cfg_path = dir.path().join("case1-auto.yaml");
        std::fs::write(
            &cfg_path,
            format!(
                r"imports: []
servers:
  petstore:
    type: openapi
    spec: {base}/api/v3/openapi.json
    baseUrl: {base}/api/v3
    autoDiscover: true
#",
            ),
        )
        .context("write case1 config")?;

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

        assert!(
            tools
                .iter()
                .any(|t| t.get("name") == Some(&json!("addPet"))),
            "expected addPet in tools/list"
        );
        assert!(
            tools
                .iter()
                .any(|t| t.get("name") == Some(&json!("getPetById"))),
            "expected getPetById in tools/list"
        );

        let pet_id = 424_242_u64;
        let add_pet = mcp
            .request(
                2,
                "tools/call",
                json!({
                    "name": "addPet",
                    "arguments": {
                        "id": pet_id,
                        "name": "mcp-integration-test-pet",
                        "photoUrls": ["https://example.com/pet.png"]
                    }
                }),
                Duration::from_secs(20),
            )
            .await?;
        let added = tool_call_body_json(&add_pet).context("addPet body JSON")?;
        assert_eq!(added.get("id"), Some(&json!(pet_id)));
        assert_eq!(added.get("name"), Some(&json!("mcp-integration-test-pet")));

        let get_pet = mcp
            .request(
                3,
                "tools/call",
                json!({
                    "name": "getPetById",
                    "arguments": {
                        "petId": pet_id
                    }
                }),
                Duration::from_secs(20),
            )
            .await?;
        let fetched = tool_call_body_json(&get_pet).context("getPetById body JSON")?;
        assert_eq!(fetched.get("id"), Some(&json!(pet_id)));
        assert_eq!(
            fetched.get("name"),
            Some(&json!("mcp-integration-test-pet"))
        );
    }

    // ---------------------------------------------------------------------
    // Case 2: autoDiscover include/exclude filters
    // ---------------------------------------------------------------------
    {
        let cfg_path = dir.path().join("case2-filters.yaml");
        std::fs::write(
            &cfg_path,
            format!(
                r"imports: []
servers:
  petstore:
    type: openapi
    spec: {base}/api/v3/openapi.json
    baseUrl: {base}/api/v3
    autoDiscover:
      include:
        - 'POST /pet'
        - 'GET /pet/{{petId}}'
      exclude:
        - 'POST /pet'
#",
            ),
        )
        .context("write case2 config")?;

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

        assert!(
            tools
                .iter()
                .any(|t| t.get("name") == Some(&json!("getPetById"))),
            "expected getPetById in tools/list for filtered config"
        );
        assert!(
            tools
                .iter()
                .all(|t| t.get("name") != Some(&json!("addPet"))),
            "expected addPet to be excluded by filters"
        );
    }

    // ---------------------------------------------------------------------
    // Case 3: explicit endpoints with autoDiscover disabled
    // ---------------------------------------------------------------------
    {
        let cfg_path = dir.path().join("case3-explicit.yaml");
        std::fs::write(
            &cfg_path,
            format!(
                r"imports: []
servers:
  petstore:
    type: openapi
    spec: {base}/api/v3/openapi.json
    baseUrl: {base}/api/v3
    autoDiscover: false
    endpoints:
      /pet:
        post:
          tool: create_pet
          description: 'Explicit endpoint mapping for POST /pet'
#",
            ),
        )
        .context("write case3 config")?;

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

        assert!(
            tools
                .iter()
                .any(|t| t.get("name") == Some(&json!("create_pet"))),
            "expected create_pet in tools/list"
        );

        let pet_id = 424_243_u64;
        let add_pet = mcp
            .request(
                2,
                "tools/call",
                json!({
                    "name": "create_pet",
                    "arguments": {
                        "id": pet_id,
                        "name": "mcp-integration-test-explicit-pet",
                        "photoUrls": ["https://example.com/explicit.png"]
                    }
                }),
                Duration::from_secs(20),
            )
            .await?;
        let added = tool_call_body_json(&add_pet).context("create_pet body JSON")?;
        assert_eq!(added.get("id"), Some(&json!(pet_id)));
        assert_eq!(
            added.get("name"),
            Some(&json!("mcp-integration-test-explicit-pet"))
        );
    }

    // ---------------------------------------------------------------------
    // Case 4: overrides replace generated behavior
    // ---------------------------------------------------------------------
    {
        let cfg_path = dir.path().join("case4-overrides.yaml");
        std::fs::write(
            &cfg_path,
            format!(
                r"imports: []
servers:
  petstore:
    type: openapi
    spec: {base}/api/v3/openapi.json
    baseUrl: {base}/api/v3
    autoDiscover: true
    overrides:
      tools:
        add_pet_override:
          match:
            operationId: addPet
          request:
            method: POST
            path: /pet
            params:
              body:
                in: body
                required: true
                schema:
                  type: object
#",
            ),
        )
        .context("write case4 config")?;

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

        assert!(
            tools
                .iter()
                .any(|t| t.get("name") == Some(&json!("add_pet_override"))),
            "expected add_pet_override in tools/list"
        );
        assert!(
            tools
                .iter()
                .all(|t| t.get("name") != Some(&json!("addPet"))),
            "expected addPet to be removed by override"
        );

        let pet_id = 424_244_u64;
        let add_pet = mcp
            .request(
                2,
                "tools/call",
                json!({
                    "name": "add_pet_override",
                    "arguments": {
                        "body": {
                            "id": pet_id,
                            "name": "mcp-integration-test-override-pet",
                            "photoUrls": ["https://example.com/override.png"]
                        }
                    }
                }),
                Duration::from_secs(20),
            )
            .await?;
        let added = tool_call_body_json(&add_pet).context("add_pet_override body JSON")?;
        assert_eq!(added.get("id"), Some(&json!(pet_id)));
        assert_eq!(
            added.get("name"),
            Some(&json!("mcp-integration-test-override-pet"))
        );
    }

    // ---------------------------------------------------------------------
    // Case 5: spec hash mismatch fails when policy=fail
    // ---------------------------------------------------------------------
    {
        let cfg_path = dir.path().join("case5-hash-fail.yaml");
        std::fs::write(
            &cfg_path,
            format!(
                r"imports: []
servers:
  petstore:
    type: openapi
    spec: {base}/api/v3/openapi.json
    specHash: sha256:0000
    specHashPolicy: fail
    baseUrl: {base}/api/v3
    autoDiscover: true
#",
            ),
        )
        .context("write case5 config")?;

        let port = pick_unused_port()?;
        let mut child = spawn_adapter(&cfg_path, port)?;

        let start = std::time::Instant::now();
        loop {
            if start.elapsed() > Duration::from_secs(15) {
                anyhow::bail!("expected adapter to exit on spec hash mismatch (policy=fail)");
            }

            if let Some(status) = child.try_wait().context("try_wait adapter")? {
                anyhow::ensure!(
                    !status.success(),
                    "expected non-zero exit status on spec hash mismatch, got: {status}"
                );
                break;
            }

            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    Ok(())
}
