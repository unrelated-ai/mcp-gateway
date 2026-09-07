use axum::{Router, http::StatusCode, response::IntoResponse as _, routing::post};
use rmcp::{
    ErrorData as McpError, ServerHandler,
    model::{
        CallToolRequestParams, CallToolResult, ContentBlock, Implementation, ListToolsResult,
        ServerCapabilities, ServerInfo, Tool,
    },
    service::{RequestContext, RoleServer},
    transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
    },
};
use serde_json::{Value, json};
use std::{process::Stdio, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader},
    process::Command,
};
use tokio_util::sync::CancellationToken;
use unrelated_cli::{
    TOOL_REF_META_KEY, client,
    config::{AuthMode, ContextConfig},
};

#[derive(Clone)]
struct RemoteTools;

impl ServerHandler for RemoteTools {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("proxy-test-remote", "1"))
    }

    fn list_tools(
        &self,
        _request: Option<rmcp::model::PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ListToolsResult, McpError>> {
        let mut tool = Tool::new(
            "exposed_get_messages".to_string(),
            "Find unread Telegram messages".to_string(),
            Arc::new(serde_json::Map::from_iter([
                ("type".into(), json!("object")),
                ("properties".into(), json!({"unread": {"type": "boolean"}})),
            ])),
        );
        tool.meta = Some(rmcp::model::Meta(serde_json::Map::from_iter([(
            TOOL_REF_META_KEY.to_string(),
            json!("telegram:get_messages"),
        )])));
        std::future::ready(Ok(ListToolsResult::with_all_items(vec![tool])))
    }

    fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<CallToolResult, McpError>> {
        if request.name != "exposed_get_messages" {
            return std::future::ready(Err(McpError::invalid_params("unknown tool", None)));
        }
        std::future::ready(Ok(CallToolResult::success(vec![ContentBlock::text(
            "Hi Mom — 2 unread messages",
        )])))
    }
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn proxy_advertises_two_tools_and_executes_by_stable_ref() -> anyhow::Result<()> {
    let cancellation = CancellationToken::new();
    let service: StreamableHttpService<RemoteTools, LocalSessionManager> =
        StreamableHttpService::new(
            || Ok(RemoteTools),
            Arc::default(),
            StreamableHttpServerConfig::default()
                .with_sse_keep_alive(None)
                .with_cancellation_token(cancellation.child_token()),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().nest_service("/profile/mcp", service),
        )
        .await
    });

    let temp = tempfile::tempdir()?;
    let config_home = temp.path().join("config");
    let cache_home = temp.path().join("cache");
    let binary = env!("CARGO_BIN_EXE_unrelated");
    let status = Command::new(binary)
        .env("XDG_CONFIG_HOME", &config_home)
        .env("XDG_CACHE_HOME", &cache_home)
        .args([
            "context",
            "add",
            "test",
            "--url",
            &format!("http://{address}/profile/mcp"),
            "--auth",
            "none",
        ])
        .stdout(Stdio::null())
        .status()
        .await?;
    assert!(status.success());

    let searched = cli_output(
        binary,
        &config_home,
        &cache_home,
        &[
            "--json",
            "tools",
            "search",
            "unread telegram",
            "--detail",
            "detailed",
        ],
    )
    .await?;
    assert_eq!(searched[0]["toolRef"], "telegram:get_messages");
    let described = cli_output(
        binary,
        &config_home,
        &cache_home,
        &["--json", "tools", "describe", "telegram:get_messages"],
    )
    .await?;
    assert_eq!(described["name"], "exposed_get_messages");
    let called = cli_output(
        binary,
        &config_home,
        &cache_home,
        &[
            "--json",
            "tools",
            "call",
            "telegram:get_messages",
            "--input",
            r#"{"unread":true}"#,
            "--yes",
        ],
    )
    .await?;
    assert_eq!(called["content"][0]["text"], "Hi Mom — 2 unread messages");

    let mut child = Command::new(binary)
        .env("XDG_CONFIG_HOME", &config_home)
        .env("XDG_CACHE_HOME", &cache_home)
        .args(["proxy", "--context", "test"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut stdin = child.stdin.take().expect("proxy stdin");
    let mut stdout = BufReader::new(child.stdout.take().expect("proxy stdout"));

    send(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "proxy-test", "version": "1"}
            }
        }),
    )
    .await?;
    assert_eq!(receive(&mut stdout).await?["id"], 1);
    send(
        &mut stdin,
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    )
    .await?;

    send(
        &mut stdin,
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
    )
    .await?;
    let listed = receive(&mut stdout).await?;
    let names: Vec<_> = listed["result"]["tools"]
        .as_array()
        .expect("tool array")
        .iter()
        .filter_map(|tool| tool["name"].as_str())
        .collect();
    assert_eq!(names, ["search_tools", "execute_tool"]);

    send(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "search_tools", "arguments": {"query": "unread telegram"}}
        }),
    )
    .await?;
    let searched = receive(&mut stdout).await?;
    assert_eq!(
        searched["result"]["structuredContent"]["tools"][0]["toolRef"],
        "telegram:get_messages"
    );

    send(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "execute_tool",
                "arguments": {"toolRef": "telegram:get_messages", "arguments": {"unread": true}}
            }
        }),
    )
    .await?;
    let executed = receive(&mut stdout).await?;
    assert_eq!(
        executed["result"]["content"][0]["text"],
        "Hi Mom — 2 unread messages"
    );

    child.kill().await?;
    cancellation.cancel();
    server.abort();
    Ok(())
}

#[tokio::test]
async fn auto_auth_probe_distinguishes_oauth_api_key_and_disabled() -> anyhow::Result<()> {
    let app = Router::new()
        .route(
            "/oauth/mcp",
            post(|| async {
                (
                    StatusCode::UNAUTHORIZED,
                    [(
                        "www-authenticate",
                        "Bearer resource_metadata=\"http://127.0.0.1/metadata\", scope=\"mcp:access\"",
                    )],
                )
                    .into_response()
            }),
        )
        .route(
            "/api/mcp",
            post(|| async { StatusCode::UNAUTHORIZED }),
        )
        .route("/none/mcp", post(|| async { StatusCode::OK }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let server = tokio::spawn(async move { axum::serve(listener, app).await });

    for (path, expected) in [
        ("oauth", AuthMode::Oauth),
        ("api", AuthMode::ApiKey),
        ("none", AuthMode::None),
    ] {
        let context = ContextConfig {
            mcp_url: format!("http://{address}/{path}/mcp"),
            auth: AuthMode::Auto,
            oauth_client_id: None,
        };
        assert_eq!(client::detect_auth_mode(&context).await?, expected);
    }
    server.abort();
    Ok(())
}

async fn send(stdin: &mut tokio::process::ChildStdin, value: Value) -> anyhow::Result<()> {
    stdin
        .write_all(serde_json::to_string(&value)?.as_bytes())
        .await?;
    stdin.write_all(b"\n").await?;
    stdin.flush().await?;
    Ok(())
}

async fn receive(stdout: &mut BufReader<tokio::process::ChildStdout>) -> anyhow::Result<Value> {
    let mut line = String::new();
    tokio::time::timeout(Duration::from_secs(10), stdout.read_line(&mut line)).await??;
    anyhow::ensure!(!line.is_empty(), "proxy closed stdout unexpectedly");
    Ok(serde_json::from_str(&line)?)
}

async fn cli_output(
    binary: &str,
    config_home: &std::path::Path,
    cache_home: &std::path::Path,
    arguments: &[&str],
) -> anyhow::Result<Value> {
    let output = Command::new(binary)
        .env("XDG_CONFIG_HOME", config_home)
        .env("XDG_CACHE_HOME", cache_home)
        .args(arguments)
        .output()
        .await?;
    anyhow::ensure!(
        output.status.success(),
        "CLI failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(serde_json::from_slice(&output.stdout)?)
}
