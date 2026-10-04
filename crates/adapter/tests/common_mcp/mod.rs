use anyhow::Context as _;
use futures::StreamExt as _;
use serde_json::json;
use std::time::Duration;
use tokio::io::AsyncBufReadExt as _;
use tokio_util::io::StreamReader;

/// Minimal MCP client for the adapter's rmcp-native streamable HTTP endpoint (`/mcp`).
///
/// This intentionally avoids re-implementing any MCP logic in production code; it exists only
/// for integration tests.
pub struct McpStreamableHttpSession {
    client: reqwest::Client,
    base_url: String,
    session_id: String,
}

impl McpStreamableHttpSession {
    pub async fn connect(base_url: &str) -> anyhow::Result<Self> {
        let client = reqwest::Client::new();
        let base_url = base_url.trim_end_matches('/').to_string();

        // initialize → creates session id header and returns first response over event-stream
        let init_resp = post_mcp(&client, &base_url, None, json!({
            "jsonrpc": "2.0",
            "id": 0,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": { "name": "unrelated-mcp-adapter-integration-tests", "version": "0" }
            }
        }))
        .await?;

        let session_id = init_resp
            .headers()
            .get("Mcp-Session-Id")
            .and_then(|h| h.to_str().ok())
            .context("missing Mcp-Session-Id header")?
            .to_string();

        let init_msg = read_first_event_stream_json_message(init_resp).await?;
        anyhow::ensure!(init_msg.get("id") == Some(&json!(0)), "unexpected init id");
        anyhow::ensure!(
            init_msg["result"]["protocolVersion"] == "2024-11-05",
            "legacy protocol negotiation changed"
        );

        // notifications/initialized
        let initialized_resp = post_mcp(
            &client,
            &base_url,
            Some(&session_id),
            json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        )
        .await?;

        anyhow::ensure!(
            initialized_resp.status().as_u16() == 202,
            "POST /mcp notifications/initialized returned {}",
            initialized_resp.status()
        );

        Ok(Self {
            client,
            base_url,
            session_id,
        })
    }

    pub async fn request(
        &self,
        id: u64,
        method: &str,
        params: serde_json::Value,
        timeout_dur: Duration,
    ) -> anyhow::Result<serde_json::Value> {
        let resp = post_mcp(
            &self.client,
            &self.base_url,
            Some(&self.session_id),
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": method,
                "params": params,
            }),
        )
        .await?;

        let msg = tokio::time::timeout(timeout_dur, read_first_event_stream_json_message(resp))
            .await
            .context("timeout waiting for event-stream response")??;

        Ok(msg)
    }

    #[allow(dead_code)]
    pub async fn notify(&self, method: &str) -> anyhow::Result<()> {
        let response = post_mcp(
            &self.client,
            &self.base_url,
            Some(&self.session_id),
            json!({"jsonrpc":"2.0","method":method}),
        )
        .await?;
        anyhow::ensure!(response.status().as_u16() == 202, "notification rejected");
        Ok(())
    }
}

/// Extract the tool call response body as JSON.
///
/// This helper is resilient to tools that return `structuredContent`:
/// - If `result.structuredContent.body` is present, it is returned.
/// - Otherwise, `result.content[0].text` is parsed as JSON. If the parsed value is of the form
///   `{ "body": ... }`, the inner `body` is returned.
///
/// # Errors
///
/// Returns an error if the message is missing a tool call result, or if the body cannot be
/// extracted/parsed as JSON.
#[allow(dead_code)]
pub fn tool_call_body_json(msg: &serde_json::Value) -> anyhow::Result<serde_json::Value> {
    let result = msg.get("result").context("tools/call missing result")?;

    if let Some(sc) = result.get("structuredContent") {
        let body = sc
            .get("body")
            .cloned()
            .context("tools/call missing result.structuredContent.body")?;
        return Ok(body);
    }

    let text = result
        .get("content")
        .and_then(serde_json::Value::as_array)
        .and_then(|c| c.first())
        .and_then(|c| c.get("text"))
        .and_then(serde_json::Value::as_str)
        .context("tools/call missing result.content[0].text")?;

    let v: serde_json::Value = serde_json::from_str(text).context("tools/call text is not JSON")?;

    // If the tool serialized structured output into a text block, unwrap the standard envelope.
    if let Some(body) = v.get("body") {
        return Ok(body.clone());
    }

    Ok(v)
}

async fn post_mcp(
    client: &reqwest::Client,
    base_url: &str,
    session_id: Option<&str>,
    body: serde_json::Value,
) -> anyhow::Result<reqwest::Response> {
    let mut req = client
        .post(format!("{}/mcp", base_url.trim_end_matches('/')))
        .header("Accept", "application/json, text/event-stream")
        .header("Content-Type", "application/json")
        .json(&body);

    if let Some(session_id) = session_id {
        req = req.header("Mcp-Session-Id", session_id);
    }

    req.send()
        .await
        .context("POST /mcp")?
        .error_for_status()
        .context("POST /mcp status")
}

async fn read_first_event_stream_json_message(
    resp: reqwest::Response,
) -> anyhow::Result<serde_json::Value> {
    let mut stream = resp.bytes_stream();
    let byte_stream = futures::stream::poll_fn(move |cx| stream.poll_next_unpin(cx))
        .map(|r| r.map_err(std::io::Error::other));
    let reader = StreamReader::new(byte_stream);
    let mut lines = tokio::io::BufReader::new(reader).lines();

    let mut data_lines: Vec<String> = Vec::new();
    while let Ok(Some(line)) = lines.next_line().await {
        let line = line.trim_end().to_string();

        if line.is_empty() {
            if data_lines.is_empty() {
                continue;
            }
            let data = data_lines.join("\n");
            return serde_json::from_str(&data).context("parse event-stream data as JSON");
        }

        if let Some(v) = line.strip_prefix("data:") {
            data_lines.push(v.trim().to_string());
        }
    }

    anyhow::bail!("event-stream ended without a JSON message")
}
