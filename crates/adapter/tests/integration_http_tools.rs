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

fn find_header<'a>(headers: &'a serde_json::Value, name: &str) -> Option<&'a str> {
    let obj = headers.as_object()?;
    let needle = name.to_ascii_lowercase();
    obj.iter()
        .find(|(k, _)| k.to_ascii_lowercase() == needle)
        .and_then(|(_, v)| v.as_str())
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
#[allow(clippy::too_many_lines)]
async fn http_tools_echo_request_roundtrip() -> anyhow::Result<()> {
    let httpbin = GenericImage::new(images::HTTPBIN.name, images::HTTPBIN.tag)
        .with_exposed_port(80.tcp())
        .start()
        .await
        .context("start httpbin container")?;

    let httpbin_host = httpbin.get_host().await?.to_string();
    let httpbin_port = httpbin.get_host_port_ipv4(80).await?;
    let httpbin_base = format!("http://{httpbin_host}:{httpbin_port}");

    wait_http_ok(&format!("{httpbin_base}/get"), Duration::from_secs(20)).await?;

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
    defaults:
      headers:
        X-Default: default-1
    tools:
      echo_request:
        method: POST
        path: /anything/{{id}}
        description: Echo a test request and return JSON describing what the server received (path, query, headers, and JSON body).
        params:
          id:
            in: path
            required: true
            schema:
              type: string
          q:
            in: query
            schema:
              type: string
          body:
            in: body
            schema:
              type: object
      echo_headers:
        method: GET
        path: /anything/headers
      echo_query:
        method: GET
        path: /anything/query
        params:
          tags:
            in: query
            schema:
              type: array
              items:
                type: string
            style: form
            explode: false
          filter:
            in: query
            schema:
              type: object
            style: deepObject
          emptyOpt:
            in: query
            required: false
            allowEmptyValue: false
            schema:
              type: string
          emptyRequired:
            in: query
            required: true
            allowEmptyValue: false
            schema:
              type: string
    auth:
      type: header
      name: X-Api-Key
      value: secret-header
  httpbin_bearer_auth:
    type: http
    baseUrl: {httpbin_base}
    auth:
      type: bearer
      token: secret-bearer
    tools:
      echo_bearer:
        method: GET
        path: /anything/bearer
  httpbin_query_auth:
    type: http
    baseUrl: {httpbin_base}
    auth:
      type: query
      name: api_key
      value: secret-query
    tools:
      echo_query_auth:
        method: GET
        path: /anything/query-auth
        params:
          tags:
            in: query
            schema:
              type: array
              items:
                type: string
            style: form
            explode: false
#",
        ),
    )
    .context("write config")?;

    let port = pick_unused_port()?;
    let child = spawn_adapter(&cfg_path, port)?;
    let _child = KillOnDrop(child);

    let base_url = format!("http://127.0.0.1:{port}");
    wait_http_ok(&format!("{base_url}/health"), Duration::from_secs(20)).await?;

    let mcp = McpStreamableHttpSession::connect(&base_url).await?;

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
            .any(|t| t.get("name") == Some(&json!("echo_request"))),
        "expected echo_request in tools/list"
    );

    let tool_call = mcp
        .request(
            2,
            "tools/call",
            json!({
                "name": "echo_request",
                "arguments": {
                    "id": "test-123",
                    "q": "hello",
                    "body": { "msg": "hello from integration test" }
                }
            }),
            Duration::from_secs(10),
        )
        .await?;

    let echoed = tool_call_body_json(&tool_call).context("echo_request body JSON")?;

    assert_eq!(echoed.get("method"), Some(&json!("POST")));
    assert_eq!(
        echoed
            .get("args")
            .and_then(|a| a.get("q"))
            .and_then(serde_json::Value::as_str),
        Some("hello")
    );
    assert_eq!(
        echoed
            .get("json")
            .and_then(|j| j.get("msg"))
            .and_then(serde_json::Value::as_str),
        Some("hello from integration test")
    );

    // Verify header auth + defaults headers are applied.
    let headers_call = mcp
        .request(
            3,
            "tools/call",
            json!({"name": "echo_headers"}),
            Duration::from_secs(10),
        )
        .await?;
    let headers_body = tool_call_body_json(&headers_call).context("echo_headers body JSON")?;
    let headers = headers_body
        .get("headers")
        .context("echo_headers missing headers")?;
    assert_eq!(find_header(headers, "X-Api-Key"), Some("secret-header"));
    assert_eq!(find_header(headers, "X-Default"), Some("default-1"));

    // Verify bearer auth is applied.
    let bearer_call = mcp
        .request(
            5,
            "tools/call",
            json!({"name": "echo_bearer"}),
            Duration::from_secs(10),
        )
        .await?;
    let bearer_body = tool_call_body_json(&bearer_call).context("echo_bearer body JSON")?;
    let headers = bearer_body
        .get("headers")
        .context("echo_bearer missing headers")?;
    assert_eq!(
        find_header(headers, "Authorization"),
        Some("Bearer secret-bearer")
    );

    // Verify query serialization and empty handling.
    let query_call = mcp
        .request(
            6,
            "tools/call",
            json!({
                "name": "echo_query",
                "arguments": {
                    "tags": ["a", "b"],
                    "filter": { "a": 1, "b": 2 },
                    "emptyOpt": "",
                    "emptyRequired": ""
                }
            }),
            Duration::from_secs(10),
        )
        .await?;
    let query_body = tool_call_body_json(&query_call).context("echo_query body JSON")?;
    let args = query_body
        .get("args")
        .and_then(serde_json::Value::as_object)
        .context("echo_query missing args object")?;

    assert_eq!(
        args.get("tags").and_then(serde_json::Value::as_str),
        Some("a,b"),
        "expected tags form+noexplode to use comma-join in args"
    );
    assert_eq!(
        args.get("filter[a]").and_then(serde_json::Value::as_str),
        Some("1"),
        "expected deepObject key filter[a] in args"
    );
    assert_eq!(
        args.get("filter[b]").and_then(serde_json::Value::as_str),
        Some("2"),
        "expected deepObject key filter[b] in args"
    );
    assert_eq!(
        args.get("emptyRequired")
            .and_then(serde_json::Value::as_str),
        Some(""),
        "expected required empty value to be present in args"
    );
    assert!(
        !args.contains_key("emptyOpt"),
        "expected optional empty value to be omitted from args"
    );

    // Verify query auth is appended.
    let mcp2 = McpStreamableHttpSession::connect(&base_url).await?;
    let query_auth_call = mcp2
        .request(
            10,
            "tools/call",
            json!({
                "name": "echo_query_auth",
                "arguments": { "tags": ["x", "y"] }
            }),
            Duration::from_secs(10),
        )
        .await?;
    let query_auth_body =
        tool_call_body_json(&query_auth_call).context("echo_query_auth body JSON")?;
    let args = query_auth_body
        .get("args")
        .and_then(serde_json::Value::as_object)
        .context("echo_query_auth missing args object")?;
    assert_eq!(
        args.get("api_key").and_then(serde_json::Value::as_str),
        Some("secret-query"),
        "expected query auth param in args"
    );

    Ok(())
}
