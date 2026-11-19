mod common;
#[allow(dead_code)]
mod common_mcp;

use anyhow::Context as _;
use common::{KillOnDrop, pick_unused_port, spawn_adapter, wait_http_ok};
use futures::StreamExt as _;
use serde_json::{Value, json};
use std::time::Duration;
use tokio::io::AsyncBufReadExt as _;

fn request(method: &str, mut params: Value) -> Value {
    params["_meta"] = json!({
        "io.modelcontextprotocol/protocolVersion":"2026-07-28",
        "io.modelcontextprotocol/clientInfo":{"name":"native-test","version":"1"},
        "io.modelcontextprotocol/clientCapabilities":{"roots":{},"extensions":{"io.modelcontextprotocol/tasks":{}}}
    });
    json!({"jsonrpc":"2.0","id":1,"method":method,"params":params})
}

async fn post(
    client: &reqwest::Client,
    url: &str,
    body: &Value,
) -> anyhow::Result<reqwest::Response> {
    Ok(client
        .post(url)
        .bearer_auth("native-test-token")
        .headers(
            unrelated_mcp_support::headers::request_headers(body, Some(&json!({"type":"object","properties":{"mode":{"type":"string","x-mcp-header":"mode"}}})))
                .map_err(anyhow::Error::msg)?,
        )
        .header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", "2026-07-28")
        .json(body)
        .send()
        .await?)
}

async fn call(client: &reqwest::Client, url: &str, body: &Value) -> anyhow::Result<Value> {
    let response = post(client, url, body).await?;
    if response
        .headers()
        .get("content-type")
        .is_some_and(|value| value.as_bytes().starts_with(b"application/json"))
    {
        return Ok(response.json().await?);
    }
    assert!(response.status().is_success(), "{}", response.text().await?);
    assert!(response.headers().get("mcp-session-id").is_none());
    common_mcp::read_first_event_stream_json_message(response).await
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn native_stdio_continuations_tasks_and_subscriptions() -> anyhow::Result<()> {
    let temp = tempfile::tempdir()?;
    let fixture =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/native_stdio.py");
    let config = temp.path().join("adapter.yaml");
    let log_a = temp.path().join("a.log");
    let log_b = temp.path().join("b.log");
    std::fs::write(
        &config,
        format!(
            "adapter:\n  modernProtocol: true\n  mcpBearerToken: native-test-token\nservers:\n  a:\n    type: stdio\n    modernProtocol: true\n    command: python3\n    args: [{fixture:?}, a, {log_a:?}]\n  b:\n    type: stdio\n    modernProtocol: true\n    command: python3\n    args: [{fixture:?}, b, {log_b:?}]\n"
        ),
    )?;
    let port = pick_unused_port()?;
    let _adapter = KillOnDrop(spawn_adapter(&config, port)?);
    let base = format!("http://127.0.0.1:{port}");
    wait_http_ok(&format!("{base}/ready"), Duration::from_secs(15)).await?;
    let url = format!("{base}/mcp");
    let client = reqwest::Client::new();
    let discovery = call(&client, &url, &request("server/discover", json!({}))).await?;
    assert!(
        discovery["result"]["supportedVersions"]
            .as_array()
            .context("versions")?
            .contains(&json!("2026-07-28"))
    );
    let catalog = call(&client, &url, &request("tools/list", json!({}))).await?;
    assert_eq!(
        catalog["result"]["tools"]
            .as_array()
            .context("tools")?
            .len(),
        2
    );
    let mut continuation = request(
        "tools/call",
        json!({"name":"a:echo","arguments":{"mode":"mrtr"}}),
    );
    let first = call(&client, &url, &continuation).await?;
    let state = first["result"]["requestState"]
        .as_str()
        .context("continuation state")?;
    assert_ne!(state, "same-state");
    continuation["params"]["requestState"] = json!(state);
    continuation["params"]["inputResponses"] = json!({"roots":{"roots":[]}});
    let resumed = call(&client, &url, &continuation).await?;
    assert_eq!(resumed["result"]["content"][0]["text"], "a", "{resumed}");
    continuation["params"]["name"] = json!("b:echo");
    assert_eq!(
        call(&client, &url, &continuation).await?["error"]["code"],
        -32602
    );
    let mut tokens = Vec::new();
    for server in ["a", "b"] {
        let task = call(
            &client,
            &url,
            &request(
                "tools/call",
                json!({"name":format!("{server}:echo"),"arguments":{"mode":"task"}}),
            ),
        )
        .await?;
        let token = task["result"]["taskId"]
            .as_str()
            .context("task token")?
            .to_owned();
        let result = call(
            &client,
            &url,
            &request("tasks/get", json!({"taskId":token})),
        )
        .await?;
        assert_eq!(
            result["result"]["result"]["content"][0]["text"], server,
            "{result}"
        );
        assert_eq!(result["result"]["taskId"], token);
        assert_eq!(result["result"]["ttlMs"], 120_000);
        for method in ["tasks/update", "tasks/cancel"] {
            let result = call(
                &client,
                &url,
                &request(method, json!({"taskId":token,"inputResponses":{}})),
            )
            .await?;
            assert!(result.get("error").is_none(), "{result}");
        }
        tokens.push(token);
    }
    assert_ne!(tokens[0], tokens[1]);
    let resources = call(&client, &url, &request("resources/list", json!({}))).await?;
    let uris: Vec<Value> = resources["result"]["resources"]
        .as_array()
        .context("resources")?
        .iter()
        .map(|v| v["uri"].clone())
        .collect();
    for (method, params, payload) in [
        ("resources/read", json!({"uri":uris[0]}), "contents"),
        (
            "prompts/get",
            json!({"name":"a:prompt","arguments":{"mode":"mrtr"}}),
            "messages",
        ),
    ] {
        let mut continuation = request(method, params);
        let first = call(&client, &url, &continuation).await?;
        assert_eq!(first["result"]["resultType"], "input_required", "{first}");
        continuation["params"]["requestState"] = first["result"]["requestState"].clone();
        continuation["params"]["inputResponses"] = json!({"roots":{"roots":[]}});
        let resumed = call(&client, &url, &continuation).await?;
        if method == "resources/read" {
            assert_eq!(resumed["result"]["contents"][0]["uri"], uris[0]);
        }
        assert!(
            resumed["result"][payload]
                .as_array()
                .is_some_and(|items| !items.is_empty()),
            "{resumed}"
        );
    }
    let templates = call(
        &client,
        &url,
        &request("resources/templates/list", json!({})),
    )
    .await?;
    assert_eq!(
        templates["result"]["resourceTemplates"]
            .as_array()
            .context("templates")?
            .len(),
        2
    );
    let completed = call(&client, &url, &request("completion/complete", json!({"ref":{"type":"ref/prompt","name":"a:prompt"},"argument":{"name":"mode","value":""}}))).await?;
    assert_eq!(
        completed["result"]["completion"]["values"],
        json!(["a"]),
        "{completed}"
    );
    let subscription = request(
        "subscriptions/listen",
        json!({"notifications":{"taskIds":tokens,"resourceSubscriptions":uris}}),
    );
    let response = post(&client, &url, &subscription).await?;
    assert!(response.status().is_success());
    let stream = response
        .bytes_stream()
        .map(|item| item.map_err(std::io::Error::other));
    let mut reader = tokio::io::BufReader::new(tokio_util::io::StreamReader::new(stream)).lines();
    let mut events = Vec::new();
    while events.len() < 5 {
        let line = tokio::time::timeout(Duration::from_secs(5), reader.next_line())
            .await??
            .context("SSE closed")?;
        if let Some(data) = line.strip_prefix("data: ") {
            events.push(serde_json::from_str::<Value>(data)?);
        }
    }
    assert_eq!(
        events[0]["method"],
        "notifications/subscriptions/acknowledged"
    );
    assert_eq!(
        events[0]["params"]["notifications"]["taskIds"]
            .as_array()
            .context("accepted tasks")?
            .len(),
        2
    );
    for event in &events[1..] {
        assert_eq!(
            event["params"]["_meta"]["io.modelcontextprotocol/subscriptionId"],
            1
        );
        if event["method"] == "notifications/tasks" {
            assert_eq!(event["params"]["ttlMs"], 90_000);
            assert!(
                tokens
                    .iter()
                    .any(|token| event["params"]["taskId"] == *token)
            );
        }
    }
    drop(reader);
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let cancelled = [&log_a, &log_b].iter().all(|log| {
                std::fs::read_to_string(log)
                    .unwrap_or_default()
                    .contains("notifications/cancelled")
            });
            if cancelled {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .context("upstream subscriptions were not cancelled")?;
    let graceful = request(
        "subscriptions/listen",
        json!({"notifications":{"toolsListChanged":true}}),
    );
    let response = post(&client, &format!("{url}/"), &graceful).await?;
    let text = tokio::time::timeout(Duration::from_secs(5), response.text()).await??;
    let events: Vec<Value> = text
        .lines()
        .filter_map(|line| line.strip_prefix("data: "))
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()?;
    assert_eq!(
        events.last().context("completion")?["result"]["_meta"]["io.modelcontextprotocol/subscriptionId"],
        1,
        "{text}"
    );
    let refreshed = call(&client, &url, &request("tools/list", json!({}))).await?;
    assert_eq!(
        refreshed["result"]["tools"]
            .as_array()
            .context("refreshed catalog")?
            .len(),
        4
    );
    let mut no_capability = request(
        "subscriptions/listen",
        json!({"notifications":{"taskIds":[tokens[0]]}}),
    );
    no_capability["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"] = json!({});
    assert!(
        call(&client, &url, &no_capability)
            .await?
            .get("error")
            .is_some()
    );
    let invalid_header = client
        .post(&url)
        .bearer_auth("native-test-token")
        .header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/list")
        .json(&subscription)
        .send()
        .await?;
    assert_eq!(invalid_header.status(), 400);
    assert_eq!(
        invalid_header.json::<Value>().await?["error"]["code"],
        -32020
    );
    let crashed = call(
        &client,
        &url,
        &request(
            "tools/call",
            json!({"name":"a:echo","arguments":{"mode":"crash"}}),
        ),
    )
    .await?;
    assert!(crashed.get("error").is_some());
    let old_task = call(
        &client,
        &url,
        &request("tasks/get", json!({"taskId":tokens[0]})),
    )
    .await?;
    assert_eq!(old_task["error"]["code"], -32602, "{old_task}");
    let restarted = call(
        &client,
        &url,
        &request("tools/call", json!({"name":"a:echo","arguments":{}})),
    )
    .await?;
    assert_eq!(
        restarted["result"]["content"][0]["text"], "a",
        "{restarted}"
    );
    let unauthorized = client
        .post(&url)
        .json(&request("server/discover", json!({})))
        .send()
        .await?;
    assert_eq!(unauthorized.status(), 401);
    Ok(())
}

#[tokio::test]
async fn native_catalog_uses_declared_capabilities_and_keeps_legacy_backends_separate()
-> anyhow::Result<()> {
    let temp = tempfile::tempdir()?;
    let config = temp.path().join("adapter.json");
    let fixture =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/native_stdio.py");
    std::fs::write(
        &config,
        serde_json::to_vec(&json!({
            "adapter":{"modernProtocol":true},
            "servers":{
                "native":{"type":"stdio","modernProtocol":true,"command":"python3","args":[fixture,"tools-only",temp.path().join("stdio.log")]},
                "legacy":{"type":"stdio","command":env!("CARGO_BIN_EXE_unrelated-mcp-stdio-test-server")}
            }
        }))?,
    )?;
    let port = pick_unused_port()?;
    let _adapter = KillOnDrop(spawn_adapter(&config, port)?);
    let base = format!("http://127.0.0.1:{port}");
    wait_http_ok(&format!("{base}/ready"), Duration::from_secs(15)).await?;
    let client = reqwest::Client::new();
    let url = format!("{base}/mcp");
    let tools = call(&client, &url, &request("tools/list", json!({}))).await?;
    assert_eq!(
        tools["result"]["tools"].as_array().context("tools")?.len(),
        1
    );
    assert_eq!(tools["result"]["tools"][0]["name"], "echo");
    for (method, key) in [
        ("resources/list", "resources"),
        ("resources/templates/list", "resourceTemplates"),
        ("prompts/list", "prompts"),
    ] {
        assert_eq!(
            call(&client, &url, &request(method, json!({}))).await?["result"][key]
                .as_array()
                .context("catalog")?
                .as_slice(),
            &[] as &[Value]
        );
    }
    let legacy = common_mcp::McpStreamableHttpSession::connect(&base).await?;
    let tools = legacy
        .request(1, "tools/list", json!({}), Duration::from_secs(5))
        .await?;
    assert!(
        tools["result"]["tools"]
            .as_array()
            .context("legacy tools")?
            .iter()
            .all(|tool| tool["name"] != "echo")
    );
    let result = legacy
        .request(
            2,
            "tools/call",
            json!({"name":"whoami","arguments":{}}),
            Duration::from_secs(5),
        )
        .await?;
    assert!(result.get("error").is_none(), "{result}");
    let denied = call(
        &client,
        &url,
        &request("tools/call", json!({"name":"whoami","arguments":{}})),
    )
    .await?;
    assert_eq!(denied["error"]["code"], -32602);
    Ok(())
}

#[tokio::test]
async fn mixed_catalogs_preserve_names_refresh_on_read_and_filter_subscriptions()
-> anyhow::Result<()> {
    let temp = tempfile::tempdir()?;
    let config = temp.path().join("adapter.json");
    let fixture =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/native_stdio.py");
    let static_log = temp.path().join("static.log");
    std::fs::write(
        &config,
        serde_json::to_vec(&json!({
            "adapter":{"modernProtocol":true},
            "servers":{
                "dynamic":{"type":"stdio","modernProtocol":true,"command":"python3","args":[fixture,"mixed",temp.path().join("dynamic.log")]},
                "static":{"type":"stdio","modernProtocol":true,"command":"python3","args":[fixture,"tools-only",static_log]},
                "old":{"type":"stdio","command":env!("CARGO_BIN_EXE_unrelated-mcp-stdio-test-server")}
            }
        }))?,
    )?;
    let port = pick_unused_port()?;
    let _adapter = KillOnDrop(spawn_adapter(&config, port)?);
    let base = format!("http://127.0.0.1:{port}");
    wait_http_ok(&format!("{base}/ready"), Duration::from_secs(15)).await?;
    let legacy = common_mcp::McpStreamableHttpSession::connect(&base).await?;
    let old = legacy
        .request(
            1,
            "tools/call",
            json!({"name":"whoami","arguments":{}}),
            Duration::from_secs(5),
        )
        .await?;
    assert!(old["result"]["content"].is_array(), "{old}");
    let client = reqwest::Client::new();
    let url = format!("{base}/mcp");
    let enabled = call(
        &client,
        &url,
        &request(
            "tools/call",
            json!({"name":"whoami","arguments":{"mode":"add-tool"}}),
        ),
    )
    .await?;
    assert_eq!(
        enabled["result"]["content"][0]["text"], "mixed",
        "{enabled}"
    );
    let catalog = call(&client, &url, &request("tools/list", json!({}))).await?;
    let mut names: Vec<_> = catalog["result"]["tools"]
        .as_array()
        .context("tools")?
        .iter()
        .filter_map(|tool| tool["name"].as_str())
        .collect();
    names.sort_unstable();
    assert_eq!(names, ["echo", "fresh", "whoami"]);
    let inventory: Value = client
        .get(format!("{base}/map"))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(inventory["tools"]["old:whoami"]["server"], "old");
    assert_eq!(inventory["tools"]["dynamic:whoami"]["server"], "dynamic");
    assert_eq!(inventory["tools"]["fresh"]["server"], "dynamic");
    let fresh = call(
        &client,
        &url,
        &request("tools/call", json!({"name":"fresh","arguments":{}})),
    )
    .await?;
    assert_eq!(fresh["result"]["content"][0]["text"], "mixed");
    let ack = call(
        &client,
        &url,
        &request(
            "subscriptions/listen",
            json!({"notifications":{"toolsListChanged":true}}),
        ),
    )
    .await?;
    assert_eq!(
        ack["params"]["notifications"]["toolsListChanged"], true,
        "{ack}"
    );
    assert!(!std::fs::read_to_string(static_log)?.contains("subscriptions/listen"));
    Ok(())
}
