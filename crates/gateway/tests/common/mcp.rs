use anyhow::Context as _;
use reqwest13 as reqwest;
use rmcp::model::ClientJsonRpcMessage;
use rmcp::transport::streamable_http_client::{
    StreamableHttpClient as _, StreamableHttpPostResponse,
};
use std::collections::HashMap;
use std::sync::Arc;

/// Minimal MCP client for gateway integration tests.
///
/// Uses rmcp's streamable HTTP client plumbing (SSE parsing + session header handling).
pub struct McpSession {
    client: reqwest::Client,
    uri: Arc<str>,
    session_id: Arc<str>,
    default_auth_header: Option<String>,
}

impl McpSession {
    pub async fn connect(
        uri: impl Into<Arc<str>>,
        auth_header: Option<String>,
    ) -> anyhow::Result<Self> {
        let client = reqwest::Client::new();
        let uri: Arc<str> = uri.into();

        // initialize (establishes session id)
        let init: ClientJsonRpcMessage = serde_json::from_value(serde_json::json!({
            "jsonrpc": "2.0",
            "id": 0,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": { "name": "unrelated-mcp-gateway-integration-tests", "version": "0" }
            }
        }))
        .expect("initialize json must deserialize");

        let resp = client
            .post_message(uri.clone(), init, None, auth_header.clone(), HashMap::new())
            .await
            .context("POST initialize")?;
        let (_msg, session_id) = resp
            .expect_initialized::<reqwest::Error>()
            .await
            .context("expect initialize response")?;
        let session_id = session_id.context("missing Mcp-Session-Id header")?.into();

        let session = Self {
            client,
            uri,
            session_id,
            default_auth_header: auth_header,
        };

        // notifications/initialized
        session
            .notify_initialized()
            .await
            .context("notifications/initialized")?;

        Ok(session)
    }

    pub fn session_id(&self) -> &str {
        self.session_id.as_ref()
    }

    pub async fn notify_initialized(&self) -> anyhow::Result<()> {
        let msg: ClientJsonRpcMessage = serde_json::from_value(serde_json::json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }))
        .expect("notification json must deserialize");

        let resp = self
            .client
            .post_message(
                self.uri.clone(),
                msg,
                Some(self.session_id.clone()),
                self.default_auth_header.clone(),
                HashMap::new(),
            )
            .await
            .context("POST notifications/initialized")?;

        resp.expect_accepted_or_json::<reqwest::Error>()
            .context("expected 202 Accepted or JSON response")?;

        Ok(())
    }

    pub async fn request_value(
        &self,
        id: u64,
        method: &str,
        params: serde_json::Value,
    ) -> anyhow::Result<serde_json::Value> {
        self.request_value_with_explicit_auth(id, method, params, self.default_auth_header.clone())
            .await
    }

    pub async fn request_value_no_auth(
        &self,
        id: u64,
        method: &str,
        params: serde_json::Value,
    ) -> anyhow::Result<serde_json::Value> {
        self.request_value_with_explicit_auth(id, method, params, None)
            .await
    }

    pub async fn request_value_with_explicit_auth(
        &self,
        id: u64,
        method: &str,
        params: serde_json::Value,
        auth_header: Option<String>,
    ) -> anyhow::Result<serde_json::Value> {
        let msg: ClientJsonRpcMessage = serde_json::from_value(serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        }))
        .expect("request json must deserialize");

        let resp = self
            .client
            .post_message(
                self.uri.clone(),
                msg,
                Some(self.session_id.clone()),
                auth_header,
                HashMap::new(),
            )
            .await
            .with_context(|| format!("POST {method}"))?;

        let server_msg = read_first_server_message(resp).await?;
        serde_json::to_value(server_msg).context("serialize server message to json")
    }
}

async fn read_first_server_message(
    resp: StreamableHttpPostResponse,
) -> anyhow::Result<rmcp::model::ServerJsonRpcMessage> {
    use anyhow::bail;
    use futures::StreamExt as _;

    match resp {
        StreamableHttpPostResponse::Json(msg, ..) => Ok(msg),
        StreamableHttpPostResponse::Sse(mut stream, ..) => {
            while let Some(evt) = stream.next().await {
                let evt = evt.context("read SSE event")?;
                let payload = evt.data.unwrap_or_default();
                if payload.trim().is_empty() {
                    continue;
                }
                let msg: rmcp::model::ServerJsonRpcMessage =
                    serde_json::from_str(&payload).context("parse SSE data as JSON-RPC")?;
                return Ok(msg);
            }
            bail!("unexpected end of SSE stream")
        }
        StreamableHttpPostResponse::Accepted => bail!("unexpected 202 Accepted response"),
        _ => bail!("unsupported streamable HTTP response type"),
    }
}
