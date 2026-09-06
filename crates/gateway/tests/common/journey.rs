//! Real-process fixtures shared by v1 acceptance tests and the opt-in benchmark.
use anyhow::Context as _;
use axum::{Router, body::Body, extract::State, http::Request, response::Response};
use rmcp::{
    ErrorData, ServerHandler,
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
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    process::{Child, Command},
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{sync::RwLock, task::JoinHandle};
use tokio_util::sync::CancellationToken;
use unrelated_cli::{
    client,
    config::{AuthMode, ContextConfig},
};

pub const PROFILE_ID: &str = "25d7e0bc-00ca-428c-b66c-d8b6cce049f7";
pub const ADMIN_TOKEN: &str = "v1-journey-local-admin";

pub fn sibling_binary(name: &str) -> anyhow::Result<PathBuf> {
    let path = Path::new(env!("CARGO_BIN_EXE_unrelated-mcp-gateway"))
        .parent()
        .context("binary directory")?
        .join(name);
    anyhow::ensure!(
        path.is_file(),
        "Missing {}. Run make test-v1-journey (or build the Adapter and CLI binaries in the same Cargo profile).",
        path.display()
    );
    Ok(path)
}

pub struct Process {
    pub child: Child,
    pub log: PathBuf,
}

impl Process {
    pub fn spawn(
        binary: &Path,
        args: &[&str],
        env: &[(&str, &str)],
        log: PathBuf,
    ) -> anyhow::Result<Self> {
        let output = std::fs::File::create(&log)?;
        let child = Command::new(binary)
            .args(args)
            .envs(env.iter().copied())
            .env_remove("UNRELATED_TOKEN")
            .stdout(output.try_clone()?)
            .stderr(output)
            .spawn()
            .with_context(|| format!("start {}", binary.display()))?;
        Ok(Self { child, log })
    }

    pub fn stop(&mut self) -> anyhow::Result<()> {
        if self.child.try_wait()?.is_none() {
            self.child.kill()?;
        }
        self.child.wait()?;
        Ok(())
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

pub struct Gateway {
    pub process: Process,
    pub data_base: String,
    pub admin_base: String,
}

pub struct GatewayOptions<'a> {
    pub binary: &'a Path,
    pub config: Option<&'a Path>,
    pub database_url: Option<&'a str>,
    pub operation_timeout_secs: u64,
    pub concurrency: usize,
}

impl Default for GatewayOptions<'_> {
    fn default() -> Self {
        Self {
            binary: Path::new(env!("CARGO_BIN_EXE_unrelated-mcp-gateway")),
            config: None,
            database_url: None,
            operation_timeout_secs: 10,
            concurrency: 8,
        }
    }
}

impl Gateway {
    pub async fn start(
        dir: &Path,
        name: &str,
        options: GatewayOptions<'_>,
    ) -> anyhow::Result<Self> {
        let data = format!("127.0.0.1:{}", crate::common::pick_unused_port()?);
        let admin = format!("127.0.0.1:{}", crate::common::pick_unused_port()?);
        let mut args = vec![
            "--bind",
            &data,
            "--admin-bind",
            &admin,
            "--log-level",
            "warn",
        ];
        if let Some(config) = options.config {
            args.extend(["--config", config.to_str().context("config path")?]);
        }
        if let Some(database_url) = options.database_url {
            args.extend(["--database-url", database_url]);
        }
        let mut process = Process::spawn(
            options.binary,
            &args,
            &[
                (
                    "UNRELATED_GATEWAY_SESSION_SECRET",
                    "v1-journey-shared-session-key",
                ),
                (
                    "UNRELATED_GATEWAY_SECRET_KEYS",
                    "v1-journey-shared-encryption-key",
                ),
                ("UNRELATED_GATEWAY_ADMIN_TOKEN", ADMIN_TOKEN),
                ("UNRELATED_GATEWAY_OUTBOUND_ALLOW_PRIVATE_NETWORKS", "1"),
                ("UNRELATED_GATEWAY_UPSTREAM_ALLOW_HTTP", "1"),
                (
                    "UNRELATED_GATEWAY_UPSTREAM_OPERATION_TIMEOUT_SECS",
                    &options.operation_timeout_secs.to_string(),
                ),
                (
                    "UNRELATED_GATEWAY_UPSTREAM_CONCURRENCY",
                    &options.concurrency.to_string(),
                ),
            ],
            dir.join(format!("{name}.log")),
        )?;
        let data_base = format!("http://{data}");
        let admin_base = format!("http://{admin}");
        if let Err(error) =
            crate::common::wait_http_ok(&format!("{data_base}/health"), Duration::from_secs(15))
                .await
        {
            let _ = process.stop();
            anyhow::bail!(
                "{error}; gateway log: {}",
                std::fs::read_to_string(&process.log)?
            );
        }
        Ok(Self {
            process,
            data_base,
            admin_base,
        })
    }
}

pub async fn start_adapter(dir: &Path) -> anyhow::Result<(Process, String)> {
    let config = dir.join("adapter.json");
    std::fs::write(
        &config,
        serde_json::to_vec(&json!({"servers": {"stdio": {
            "type": "stdio", "command": sibling_binary("unrelated-mcp-stdio-test-server")?, "args": []
        }}}))?,
    )?;
    let address = format!("127.0.0.1:{}", crate::common::pick_unused_port()?);
    let process = Process::spawn(
        &sibling_binary("unrelated-mcp-adapter")?,
        &[
            "--config",
            config.to_str().context("adapter path")?,
            "--bind",
            &address,
            "--log-level",
            "warn",
        ],
        &[],
        dir.join("adapter.log"),
    )?;
    let base = format!("http://{address}");
    crate::common::wait_http_ok(&format!("{base}/health"), Duration::from_secs(15)).await?;
    Ok((process, format!("{base}/mcp")))
}

#[derive(Clone, Default)]
pub struct RemoteControl {
    pub list_delay_ms: Arc<AtomicU64>,
    pub initialize_delay_ms: Arc<AtomicU64>,
    pub initializations: Arc<AtomicUsize>,
    pub lists: Arc<AtomicUsize>,
}

#[derive(Clone)]
struct Remote {
    control: RemoteControl,
    generation: &'static str,
}

impl ServerHandler for Remote {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("v1-rmcp-fixture", self.generation))
    }
    async fn list_tools(
        &self,
        _: Option<rmcp::model::PaginatedRequestParams>,
        _: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        self.control.lists.fetch_add(1, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(
            self.control.list_delay_ms.load(Ordering::SeqCst),
        ))
        .await;
        Ok(ListToolsResult::with_all_items(vec![Tool::new(
            "echo",
            "Echo from the sessionless rmcp upstream",
            Arc::new(
                json!({"type":"object", "properties":{}})
                    .as_object()
                    .unwrap()
                    .clone(),
            ),
        )]))
    }
    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        if request.name != "echo" {
            return Err(ErrorData::invalid_params("unknown tool", None));
        }
        Ok(CallToolResult::success(vec![ContentBlock::text(
            self.generation,
        )]))
    }
}

async fn observe_initialize(
    State(control): State<RemoteControl>,
    request: Request<Body>,
    next: axum::middleware::Next,
) -> Response {
    let (parts, body) = request.into_parts();
    let body = axum::body::to_bytes(body, 1024 * 1024)
        .await
        .expect("fixture request body");
    if serde_json::from_slice::<Value>(&body)
        .ok()
        .and_then(|v| v["method"].as_str().map(str::to_string))
        .as_deref()
        == Some("initialize")
    {
        control.initializations.fetch_add(1, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(
            control.initialize_delay_ms.load(Ordering::SeqCst),
        ))
        .await;
    }
    next.run(Request::from_parts(parts, Body::from(body))).await
}

pub struct RemoteServer {
    pub address: SocketAddr,
    pub control: RemoteControl,
    cancellation: CancellationToken,
    task: JoinHandle<()>,
}

impl RemoteServer {
    pub async fn start(
        address: Option<SocketAddr>,
        generation: &'static str,
    ) -> anyhow::Result<Self> {
        let listener = tokio::net::TcpListener::bind(
            address.unwrap_or_else(|| "127.0.0.1:0".parse().unwrap()),
        )
        .await?;
        let address = listener.local_addr()?;
        let cancellation = CancellationToken::new();
        let control = RemoteControl::default();
        let remote = Remote {
            control: control.clone(),
            generation,
        };
        let service: StreamableHttpService<Remote, LocalSessionManager> =
            StreamableHttpService::new(
                move || Ok(remote.clone()),
                Arc::default(),
                StreamableHttpServerConfig::default()
                    .with_stateful_mode(false)
                    .with_json_response(true)
                    .with_cancellation_token(cancellation.child_token()),
            );
        let app = Router::new().nest_service("/mcp", service).layer(
            axum::middleware::from_fn_with_state(control.clone(), observe_initialize),
        );
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("rmcp server");
        });
        Ok(Self {
            address,
            control,
            cancellation,
            task,
        })
    }
    pub fn url(&self) -> String {
        format!("http://{}/mcp", self.address)
    }
    pub async fn stop(self) {
        self.cancellation.cancel();
        self.task.abort();
        let _ = self.task.await;
    }
}

// The client keeps one URL and session while the proxy switches replicas.
#[derive(Clone)]
pub struct ProxyState {
    pub backend: Arc<RwLock<String>>,
    pub sessions: Arc<std::sync::Mutex<Vec<String>>>,
    client: reqwest::Client,
}

async fn forward(State(state): State<ProxyState>, request: Request<Body>) -> Response {
    let (parts, body) = request.into_parts();
    if parts.method == axum::http::Method::POST
        && let Some(session) = parts.headers.get("mcp-session-id")
    {
        state
            .sessions
            .lock()
            .unwrap()
            .push(session.to_str().unwrap().to_string());
    }
    let body = axum::body::to_bytes(body, 1024 * 1024).await.unwrap();
    let target = format!("{}{}", state.backend.read().await, parts.uri);
    let mut headers = parts.headers;
    headers.remove("host");
    match state
        .client
        .request(parts.method, target)
        .headers(headers)
        .body(body)
        .send()
        .await
    {
        Ok(response) => {
            let mut output = Response::builder().status(response.status());
            *output.headers_mut().unwrap() = response.headers().clone();
            output
                .body(Body::from_stream(response.bytes_stream()))
                .unwrap()
        }
        Err(error) => Response::builder()
            .status(502)
            .body(Body::from(error.to_string()))
            .unwrap(),
    }
}

pub async fn start_proxy(backend: &str) -> anyhow::Result<(String, ProxyState, JoinHandle<()>)> {
    let state = ProxyState {
        backend: Arc::new(RwLock::new(backend.to_string())),
        sessions: Arc::default(),
        client: reqwest::Client::new(),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("http://{}", listener.local_addr()?);
    let app = Router::new().fallback(forward).with_state(state.clone());
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    Ok((url, state, task))
}

pub async fn connect(url: &str) -> anyhow::Result<client::GatewayConnection> {
    client::connect(
        "v1-journey",
        &ContextConfig {
            mcp_url: url.to_string(),
            auth: AuthMode::None,
            oauth_client_id: None,
        },
        Duration::from_secs(15),
    )
    .await
}

pub async fn cli(dir: &Path, args: &[&str]) -> anyhow::Result<Value> {
    cli_with_token(dir, args, None).await
}

pub async fn cli_with_token(
    dir: &Path,
    args: &[&str],
    token: Option<&str>,
) -> anyhow::Result<Value> {
    let mut command = tokio::process::Command::new(sibling_binary("unrelated")?);
    command
        .env_remove("UNRELATED_TOKEN")
        .env("XDG_CONFIG_HOME", dir.join("config"))
        .env("XDG_CACHE_HOME", dir.join("cache"))
        .args(args);
    if let Some(token) = token {
        command.env("UNRELATED_TOKEN", token);
    }
    let output = command.output().await?;
    anyhow::ensure!(
        output.status.success(),
        "unrelated {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    if output.stdout.is_empty() {
        return Ok(Value::Null);
    }
    Ok(serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|_| json!(String::from_utf8_lossy(&output.stdout))))
}

pub fn mode1_config(
    dir: &Path,
    upstreams: &[(&str, String)],
    partial: bool,
) -> anyhow::Result<PathBuf> {
    let path = dir.join("gateway.json");
    let entries: serde_json::Map<String, Value> = upstreams
        .iter()
        .map(|(id, url)| {
            (
                id.to_string(),
                json!({"endpoints": [{"id":"one", "url":url}]}),
            )
        })
        .collect();
    std::fs::write(
        &path,
        serde_json::to_vec_pretty(&json!({
            "tenants": {"journey": {}}, "upstreams": entries,
            "profiles": {PROFILE_ID: {"tenantId": "journey", "upstreams": upstreams.iter().map(|(id, _)| id).collect::<Vec<_>>(), "allowPartialUpstreams": partial}}
        }))?,
    )?;
    Ok(path)
}

pub async fn exercise_compact_proxy(dir: &Path) -> anyhow::Result<()> {
    use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
    let mut child = tokio::process::Command::new(sibling_binary("unrelated")?)
        .env_remove("UNRELATED_TOKEN")
        .env("XDG_CONFIG_HOME", dir.join("config"))
        .env("XDG_CACHE_HOME", dir.join("cache"))
        .args(["proxy", "--context", "journey"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::fs::File::create(dir.join("compact-proxy.log"))?)
        .kill_on_drop(true)
        .spawn()?;
    let mut input = child.stdin.take().context("proxy stdin")?;
    let mut output = BufReader::new(child.stdout.take().context("proxy stdout")?);
    let messages = [
        json!({"jsonrpc":"2.0", "id":1, "method":"initialize", "params": {"protocolVersion":"2025-11-25", "capabilities":{}, "clientInfo":{"name":"journey", "version":"1"}}}),
        json!({"jsonrpc":"2.0", "method":"notifications/initialized"}),
        json!({"jsonrpc":"2.0", "id":2, "method":"tools/list", "params":{}}),
        json!({"jsonrpc":"2.0", "id":3, "method":"tools/call", "params":{"name":"search_tools", "arguments":{"query":"sessionless"}}}),
        json!({"jsonrpc":"2.0", "id":4, "method":"tools/call", "params":{"name":"execute_tool", "arguments":{"toolRef":"remote:echo", "arguments":{}}}}),
    ];
    for message in messages {
        input.write_all(format!("{message}\n").as_bytes()).await?;
        input.flush().await?;
        let Some(id) = message.get("id") else {
            continue;
        };
        let mut line = String::new();
        tokio::time::timeout(Duration::from_secs(10), output.read_line(&mut line)).await??;
        let response: Value = serde_json::from_str(&line)?;
        assert_eq!(&response["id"], id);
        assert!(response.get("error").is_none(), "{response}");
        match id.as_u64().unwrap() {
            2 => assert_eq!(
                response["result"]["tools"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|tool| tool["name"].as_str().unwrap())
                    .collect::<Vec<_>>(),
                ["search_tools", "execute_tool"]
            ),
            3 => assert_eq!(
                response["result"]["structuredContent"]["tools"][0]["toolRef"],
                "remote:echo"
            ),
            4 => assert_eq!(response["result"]["content"][0]["text"], "generation-two"),
            _ => {}
        }
    }
    child.kill().await?;
    Ok(())
}
