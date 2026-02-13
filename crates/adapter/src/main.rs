//! Unrelated MCP Adapter
//!
//! Expose stdio-based MCP servers and HTTP APIs over MCP.

mod aggregator;
mod backend;
mod config;
mod contracts;
mod error;
mod http;
mod http_backend;
mod mcp_server;
mod openapi;
mod session_manager;
mod supervisor;
mod timeouts;

use crate::aggregator::Aggregator;
use crate::config::{AdapterConfig, CliArgs, ServerConfig};
use crate::http::{AppState, create_router, with_optional_bearer_auth, with_request_counting};
use crate::mcp_server::AdapterMcpServer;
use crate::openapi::OpenApiBackend;
use crate::session_manager::AdapterSessionManager;
use crate::supervisor::BackendManager;
use crate::supervisor::StdioBackend;
use crate::supervisor::StdioBackendSettings;
use clap::Parser;
use rmcp::model::AnnotateAble;
use rmcp::transport::{StreamableHttpServerConfig, StreamableHttpService};
use std::io::{IsTerminal as _, stdout};
use std::net::SocketAddr;
use std::sync::{Arc, atomic::AtomicU64};
use std::time::{Duration, Instant};
use tokio::signal;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::prelude::*;
use unrelated_tool_transforms::TransformPipeline;

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Parse CLI arguments
    let cli = CliArgs::parse();

    // Load configuration
    let config = AdapterConfig::load(cli)?;

    if config.cli.print_effective_config {
        let yaml = serde_yaml::to_string(&config.effective())?;
        print!("{yaml}");
        return Ok(());
    }

    // Initialize logging (effective config already includes CLI/ENV/config precedence).
    init_logging(&config.adapter.log_level);

    tracing::info!("Starting Unrelated MCP Adapter v{}", VERSION);

    let total_servers = config.servers.len();
    tracing::info!("Loaded {} server(s) from config", total_servers);

    if total_servers == 0 {
        tracing::warn!("No servers configured. Adapter will start but have no tools.");
    }

    // Create backend manager
    let backend_manager = Arc::new(BackendManager::new());

    // Create aggregator (tool/resource/prompt registry)
    let aggregator = Arc::new(Aggregator::new());

    let transforms = Arc::new(config.transforms.clone());

    let contract_notifier = Arc::new(contracts::ContractNotifier::default());

    // Registry refresh channel (used by stdio backends to trigger a rebuild after restart).
    let (refresh_tx, refresh_rx) = mpsc::unbounded_channel::<String>();
    spawn_registry_refresh_loop(
        backend_manager.clone(),
        aggregator.clone(),
        transforms.clone(),
        contract_notifier.clone(),
        refresh_rx,
    );

    // Create backends from unified `servers` map
    let servers = config.servers;
    register_backends_from_config(
        backend_manager.as_ref(),
        &config.adapter,
        servers,
        &refresh_tx,
        &contract_notifier,
        &aggregator,
    );

    // Start all backends
    if !backend_manager.is_empty() {
        tracing::info!("Starting all backends...");
        backend_manager.start_all().await?;
        tracing::info!("All backends started successfully");

        // Build the initial registry snapshot.
        refresh_aggregator(
            &aggregator,
            &backend_manager,
            transforms.as_ref(),
            contract_notifier.as_ref(),
        )
        .await?;
    }

    // Create app state for HTTP endpoints
    let state = Arc::new(AppState {
        backend_manager: backend_manager.clone(),
        aggregator: aggregator.clone(),
        start_time: Instant::now(),
        version: VERSION,
        mcp_bearer_token: config.adapter.mcp_bearer_token.clone(),
        total_requests: AtomicU64::new(0),
        failed_requests: AtomicU64::new(0),
    });

    // Parse bind address
    let addr: SocketAddr =
        config.adapter.bind.parse().map_err(|e| {
            anyhow::anyhow!("Invalid bind address '{}': {}", config.adapter.bind, e)
        })?;

    // Create cancellation token for graceful shutdown
    let ct = CancellationToken::new();

    // Also expose rmcp's streamable HTTP transport (session header + GET/POST/DELETE).
    // This is rmcp-native and avoids us re-implementing session management for clients
    // that support streamable HTTP.
    let streamable_http_service = build_streamable_http_service(
        aggregator.clone(),
        backend_manager.clone(),
        transforms.clone(),
        contract_notifier.clone(),
        &ct,
    );

    // Build combined router: auxiliary endpoints + MCP endpoint.
    let http_router = create_router(state.clone());
    let app = with_request_counting(
        with_optional_bearer_auth(
            http_router.nest_service("/mcp", streamable_http_service),
            state.clone(),
        ),
        state.clone(),
    );

    tracing::info!("Starting HTTP server (MCP + aux) on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let ct_clone = ct.clone();

    tokio::spawn(async move {
        let server = axum::serve(listener, app).with_graceful_shutdown(async move {
            ct_clone.cancelled().await;
        });

        if let Err(e) = server.await {
            tracing::error!(error = %e, "http server stopped with error");
        }
    });

    // Wait for shutdown signal
    shutdown_signal(backend_manager, ct).await;

    tracing::info!("Adapter shut down gracefully");
    Ok(())
}

fn build_streamable_http_service(
    aggregator: Arc<Aggregator>,
    backend_manager: Arc<BackendManager>,
    transforms: Arc<TransformPipeline>,
    contract_notifier: Arc<contracts::ContractNotifier>,
    ct: &CancellationToken,
) -> StreamableHttpService<AdapterMcpServer, AdapterSessionManager> {
    let session_manager = Arc::new(AdapterSessionManager::new(
        backend_manager.clone(),
        contract_notifier.clone(),
    ));

    StreamableHttpService::new(
        move || {
            Ok(AdapterMcpServer::new(
                aggregator.clone(),
                backend_manager.clone(),
                transforms.clone(),
                contract_notifier.clone(),
            ))
        },
        session_manager,
        StreamableHttpServerConfig {
            stateful_mode: true,
            sse_keep_alive: Some(Duration::from_secs(15)),
            // Keep retry unset to preserve existing client/test behavior expectations
            // (first stream event is JSON data, not an SSE retry hint frame).
            sse_retry: None,
            cancellation_token: ct.child_token(),
        },
    )
}

fn spawn_registry_refresh_loop(
    backend_manager: Arc<BackendManager>,
    aggregator: Arc<Aggregator>,
    transforms: Arc<TransformPipeline>,
    contract_notifier: Arc<contracts::ContractNotifier>,
    mut refresh_rx: mpsc::UnboundedReceiver<String>,
) {
    // Background registry refresh loop (best-effort).
    tokio::spawn(async move {
        while let Some(first) = refresh_rx.recv().await {
            // Coalesce multiple restarts into one refresh.
            let mut restarted = vec![first];
            while let Ok(name) = refresh_rx.try_recv() {
                restarted.push(name);
            }

            tracing::info!(
                "Registry refresh requested ({:?}); refreshing aggregated registry",
                restarted
            );

            if let Err(e) = refresh_aggregator(
                &aggregator,
                &backend_manager,
                transforms.as_ref(),
                contract_notifier.as_ref(),
            )
            .await
            {
                tracing::warn!("Failed to refresh registry after restart: {}", e);
            }
        }
    });
}

fn register_backends_from_config(
    backend_manager: &BackendManager,
    adapter: &crate::config::AdapterSettings,
    servers: std::collections::HashMap<String, ServerConfig>,
    refresh_tx: &mpsc::UnboundedSender<String>,
    contract_notifier: &Arc<contracts::ContractNotifier>,
    aggregator: &Arc<Aggregator>,
) {
    for (name, server) in servers {
        match server {
            ServerConfig::Stdio { config: stdio_cfg } => {
                tracing::info!("Creating stdio backend: {}", name);
                let backend = Arc::new(StdioBackend::new(
                    name.clone(),
                    stdio_cfg,
                    StdioBackendSettings {
                        startup_timeout: adapter.startup_timeout_duration(),
                        call_timeout: adapter.call_timeout_duration(),
                        restart_policy: adapter.restart_policy,
                        stdio_lifecycle: adapter.stdio_lifecycle,
                        restart_backoff_min: adapter.restart_backoff_min_duration(),
                        restart_backoff_max: adapter.restart_backoff_max_duration(),
                        refresh_tx: Some(refresh_tx.clone()),
                        session_peers: Arc::clone(contract_notifier),
                        aggregator: Arc::clone(aggregator),
                    },
                ));
                backend_manager.add_backend(backend);
            }
            ServerConfig::OpenApi { config: api_cfg } => {
                tracing::info!("Creating OpenAPI backend: {}", name);
                let backend = Arc::new(OpenApiBackend::new(
                    name.clone(),
                    api_cfg,
                    adapter.call_timeout_duration(),
                    adapter.startup_timeout_duration(),
                    adapter.openapi_probe,
                    adapter.openapi_probe_timeout_duration(),
                ));
                backend_manager.add_backend(backend);
            }
            ServerConfig::Http { config: http_cfg } => {
                tracing::info!("Creating HTTP backend: {}", name);
                let backend = Arc::new(crate::http_backend::HttpBackend::new(
                    name.clone(),
                    http_cfg,
                    adapter.call_timeout_duration(),
                ));
                backend_manager.add_backend(backend);
            }
        }
    }
}

/// Refresh the aggregator registry from the current backend set.
///
/// This is used on startup and after stdio backends restart, so `/map` and
/// `tools/list` reflect the current tool surface.
async fn refresh_aggregator(
    aggregator: &Aggregator,
    backend_manager: &BackendManager,
    transforms: &TransformPipeline,
    contract_notifier: &contracts::ContractNotifier,
) -> crate::error::Result<()> {
    let snapshot = Aggregator::new();

    for backend in backend_manager.get_all_backends() {
        let tools = backend.list_tools().await?;
        tracing::debug!(
            "Refreshing registry: backend '{}' ({}) has {} tool(s)",
            backend.name(),
            backend.backend_type(),
            tools.len()
        );
        let tool_infos: Vec<crate::aggregator::ToolInfo> = tools
            .into_iter()
            .map(|t| {
                let mut schema = t.input_schema;
                transforms.apply_schema_transforms(&t.original_name, &mut schema);

                crate::aggregator::ToolInfo {
                    name: t.original_name,
                    description: t.description,
                    input_schema: Some(schema),
                    output_schema: t.output_schema,
                    annotations: t.annotations,
                }
            })
            .collect();
        snapshot.register_tools(backend.name(), tool_infos, transforms);

        let resources = backend.list_resources().await?;
        snapshot.register_resources(backend.name(), resources);

        let prompts = backend.list_prompts().await?;
        snapshot.register_prompts(backend.name(), prompts);
    }

    // Best-effort: compute exposed surfaces from the new snapshot and notify if they changed.
    // This keeps Adapter sessions in sync when the registry refreshes after backend restarts.
    let tools_for_hash: Vec<rmcp::model::Tool> = snapshot
        .get_all_tools()
        .values()
        .map(|mapping| {
            let input_schema = mapping
                .input_schema
                .clone()
                .and_then(|v| v.as_object().cloned())
                .map_or_else(|| Arc::new(serde_json::Map::new()), Arc::new);
            let output_schema = mapping
                .output_schema
                .clone()
                .and_then(|v| v.as_object().cloned())
                .map(Arc::new);
            let mut tool = rmcp::model::Tool::new(
                mapping.exposed_name.clone(),
                mapping.description.clone().unwrap_or_default(),
                input_schema,
            );
            tool.output_schema = output_schema;
            tool.annotations.clone_from(&mapping.annotations);
            tool
        })
        .collect();

    let resources_for_hash: Vec<rmcp::model::Resource> = snapshot
        .get_all_resources()
        .iter()
        .map(|(exposed_uri, mapping)| {
            let mut raw = rmcp::model::RawResource::new(exposed_uri.clone(), mapping.name.clone());
            raw.description.clone_from(&mapping.description);
            raw.mime_type.clone_from(&mapping.mime_type);
            raw.size = mapping.size;
            raw.no_annotation()
        })
        .collect();

    let prompts_for_hash: Vec<rmcp::model::Prompt> = snapshot
        .get_all_prompts()
        .iter()
        .map(|(exposed_name, mapping)| rmcp::model::Prompt {
            name: exposed_name.clone(),
            title: None,
            description: mapping.description.clone(),
            arguments: mapping.arguments.clone(),
            icons: None,
            meta: None,
        })
        .collect();

    contract_notifier
        .update_and_notify(&tools_for_hash, &resources_for_hash, &prompts_for_hash)
        .await;

    aggregator.overwrite_from(&snapshot);
    Ok(())
}

/// Initialize logging based on the log level string.
fn init_logging(log_level: &str) {
    let env_filter = EnvFilter::try_new(log_level).unwrap_or_else(|_| EnvFilter::new("info"));

    // Check if stdout is a TTY for format selection
    let is_tty = stdout().is_terminal();

    if is_tty {
        // Human-readable format for development
        tracing_subscriber::registry()
            .with(env_filter)
            .with(tracing_subscriber::fmt::layer().with_target(true))
            .init();
    } else {
        // JSON format for production
        tracing_subscriber::registry()
            .with(env_filter)
            .with(tracing_subscriber::fmt::layer().json())
            .init();
    }
}

/// Wait for shutdown signal (SIGTERM or SIGINT).
async fn shutdown_signal(backend_manager: Arc<BackendManager>, ct: CancellationToken) {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {
            tracing::info!("Received Ctrl+C, initiating shutdown...");
        }
        () = terminate => {
            tracing::info!("Received SIGTERM, initiating shutdown...");
        }
    }

    // Cancel the HTTP server
    ct.cancel();

    // Shutdown all backends
    backend_manager.shutdown_all().await;
}
