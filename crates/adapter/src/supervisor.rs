//! Backend supervision and lifecycle management.
//!
//! This module manages both stdio MCP server processes and `OpenAPI` backends.

use crate::aggregator::Aggregator;
use crate::backend::{
    Backend, BackendState, BackendStatus, BackendType, PromptInfo, ResourceInfo, ToolInfo,
};
use crate::config::{McpServerConfig, RestartPolicy, StdioLifecycle};
use crate::contracts::ContractNotifier;
use crate::contracts::compute_contract_hashes;
use crate::error::{AdapterError, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use rmcp::{
    ClientHandler, RoleClient, ServiceExt,
    model::{
        CallToolRequestParams, CallToolResult, ClientInfo, CompleteRequestParams, CompleteResult,
        CreateElicitationRequestParams, CreateElicitationResult, CreateMessageRequestMethod,
        CreateMessageRequestParams, CreateMessageResult, ErrorData as McpError,
        GetPromptRequestParams, GetPromptResult, ListRootsResult, LoggingMessageNotificationParam,
        ProgressNotificationParam, Prompt, ReadResourceRequestParams, ReadResourceResult, Resource,
        ResourceUpdatedNotificationParam, Tool,
    },
    service::{Peer, RequestContext, RoleServer, RunningService, ServiceError},
    transport::TokioChildProcess,
};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tokio::process::Command;
use tokio::sync::Mutex;
use tokio::sync::mpsc::UnboundedSender;
use tokio::time::timeout;

async fn refresh_lists_from_peer(
    peer: &Peer<RoleClient>,
    backend_name: &str,
) -> Result<(Vec<Tool>, Vec<Resource>, Vec<Prompt>)> {
    let tools = peer.list_all_tools().await.map_err(|e| {
        AdapterError::Runtime(format!(
            "Failed to refresh tools from '{backend_name}': {e}"
        ))
    })?;
    let resources = peer.list_all_resources().await.map_err(|e| {
        AdapterError::Runtime(format!(
            "Failed to refresh resources from '{backend_name}': {e}",
        ))
    })?;
    let prompts = peer.list_all_prompts().await.map_err(|e| {
        AdapterError::Runtime(format!(
            "Failed to refresh prompts from '{backend_name}': {e}"
        ))
    })?;
    Ok((tools, resources, prompts))
}

// ============================================================================
// Stdio Backend (MCP Server Process via rmcp)
// ============================================================================

/// Internal information about a managed stdio MCP server.
#[derive(Debug, Clone)]
struct StdioServerInfo {
    /// Current state
    pub state: BackendState,
    /// Number of times this server has been restarted
    pub restart_count: u32,
    /// Timestamp of last restart (if any)
    pub last_restart: Option<DateTime<Utc>>,
    /// Number of tools discovered
    pub tool_count: usize,
}

/// Type alias for the rmcp running client service
type McpClient = RunningService<RoleClient, ProxyClientHandler>;

#[derive(Clone)]
struct ProxyClientHandler {
    backend_name: String,
    aggregator: Arc<Aggregator>,
    downstream_peer: Option<Peer<RoleServer>>,
    downstream_client_info: ClientInfo,
    // Best-effort: when the upstream signals list_changed, trigger a registry refresh in the
    // adapter main loop (only wired for persistent stdio backends).
    refresh_tx: Option<UnboundedSender<String>>,
    registry_dirty: Option<Arc<AtomicBool>>,
}

impl ProxyClientHandler {
    fn discovery(backend_name: String, aggregator: Arc<Aggregator>) -> Self {
        Self {
            backend_name,
            aggregator,
            downstream_peer: None,
            downstream_client_info: ClientInfo::default(),
            refresh_tx: None,
            registry_dirty: None,
        }
    }

    fn discovery_with_refresh(
        backend_name: String,
        aggregator: Arc<Aggregator>,
        refresh_tx: Option<UnboundedSender<String>>,
        registry_dirty: Arc<AtomicBool>,
    ) -> Self {
        Self {
            backend_name,
            aggregator,
            downstream_peer: None,
            downstream_client_info: ClientInfo::default(),
            refresh_tx,
            registry_dirty: Some(registry_dirty),
        }
    }

    fn for_session(
        backend_name: String,
        aggregator: Arc<Aggregator>,
        session_id: &str,
        peers: &ContractNotifier,
    ) -> Self {
        let downstream_peer = peers.get_peer(session_id);
        let downstream_client_info = downstream_peer
            .as_ref()
            .and_then(|p| p.peer_info().cloned())
            .unwrap_or_default();
        Self {
            backend_name,
            aggregator,
            downstream_peer,
            downstream_client_info,
            refresh_tx: None,
            registry_dirty: None,
        }
    }

    fn proxy_error(context: &'static str, err: &ServiceError) -> McpError {
        McpError::internal_error(format!("proxy {context} failed: {err}"), None)
    }

    fn mark_dirty_and_request_refresh(&self) -> impl std::future::Future<Output = ()> + Send + '_ {
        let backend_name = self.backend_name.clone();
        let refresh_tx = self.refresh_tx.clone();
        let dirty = self.registry_dirty.clone();
        async move {
            let already_dirty = dirty
                .as_ref()
                .is_some_and(|d| d.swap(true, Ordering::AcqRel));
            if already_dirty {
                return;
            }
            if let Some(tx) = refresh_tx {
                let _ = tx.send(backend_name);
            }
        }
    }
}

impl std::fmt::Debug for ProxyClientHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyClientHandler")
            .field("backend_name", &self.backend_name)
            .field("has_downstream_peer", &self.downstream_peer.is_some())
            .finish_non_exhaustive()
    }
}

impl ClientHandler for ProxyClientHandler {
    fn get_info(&self) -> ClientInfo {
        self.downstream_client_info.clone()
    }

    fn create_message(
        &self,
        params: CreateMessageRequestParams,
        _context: RequestContext<RoleClient>,
    ) -> impl std::future::Future<Output = std::result::Result<CreateMessageResult, McpError>> + Send + '_
    {
        let peer = self.downstream_peer.clone();
        async move {
            let Some(peer) = peer else {
                return Err(McpError::method_not_found::<CreateMessageRequestMethod>());
            };
            peer.create_message(params)
                .await
                .map_err(|e| Self::proxy_error("sampling/createMessage", &e))
        }
    }

    fn list_roots(
        &self,
        _context: RequestContext<RoleClient>,
    ) -> impl std::future::Future<Output = std::result::Result<ListRootsResult, McpError>> + Send + '_
    {
        let peer = self.downstream_peer.clone();
        async move {
            let Some(peer) = peer else {
                return Ok(ListRootsResult::default());
            };
            peer.list_roots()
                .await
                .map_err(|e| Self::proxy_error("roots/list", &e))
        }
    }

    fn create_elicitation(
        &self,
        request: CreateElicitationRequestParams,
        _context: RequestContext<RoleClient>,
    ) -> impl std::future::Future<Output = std::result::Result<CreateElicitationResult, McpError>>
    + Send
    + '_ {
        let peer = self.downstream_peer.clone();
        async move {
            let Some(peer) = peer else {
                return Ok(CreateElicitationResult {
                    action: rmcp::model::ElicitationAction::Decline,
                    content: None,
                });
            };
            peer.create_elicitation(request)
                .await
                .map_err(|e| Self::proxy_error("elicitation/create", &e))
        }
    }

    fn on_cancelled(
        &self,
        params: rmcp::model::CancelledNotificationParam,
        _context: rmcp::service::NotificationContext<RoleClient>,
    ) -> impl std::future::Future<Output = ()> + Send + '_ {
        let peer = self.downstream_peer.clone();
        async move {
            if let Some(peer) = peer {
                let _ = peer.notify_cancelled(params).await;
            }
        }
    }

    fn on_progress(
        &self,
        params: ProgressNotificationParam,
        _context: rmcp::service::NotificationContext<RoleClient>,
    ) -> impl std::future::Future<Output = ()> + Send + '_ {
        let peer = self.downstream_peer.clone();
        async move {
            if let Some(peer) = peer {
                let _ = peer.notify_progress(params).await;
            }
        }
    }

    fn on_logging_message(
        &self,
        params: LoggingMessageNotificationParam,
        _context: rmcp::service::NotificationContext<RoleClient>,
    ) -> impl std::future::Future<Output = ()> + Send + '_ {
        let peer = self.downstream_peer.clone();
        async move {
            if let Some(peer) = peer {
                let _ = peer.notify_logging_message(params).await;
            }
        }
    }

    fn on_resource_updated(
        &self,
        mut params: ResourceUpdatedNotificationParam,
        _context: rmcp::service::NotificationContext<RoleClient>,
    ) -> impl std::future::Future<Output = ()> + Send + '_ {
        let peer = self.downstream_peer.clone();
        let aggregator = self.aggregator.clone();
        let backend_name = self.backend_name.clone();
        async move {
            // Rewrite original backend URI -> Adapter exposed URI (URN when collisions exist).
            if let Some(exposed) = aggregator.exposed_resource_uri_for(&backend_name, &params.uri) {
                params.uri = exposed;
            }
            if let Some(peer) = peer {
                let _ = peer.notify_resource_updated(params).await;
            }
        }
    }

    fn on_resource_list_changed(
        &self,
        _context: rmcp::service::NotificationContext<RoleClient>,
    ) -> impl std::future::Future<Output = ()> + Send + '_ {
        self.mark_dirty_and_request_refresh()
    }

    fn on_tool_list_changed(
        &self,
        _context: rmcp::service::NotificationContext<RoleClient>,
    ) -> impl std::future::Future<Output = ()> + Send + '_ {
        self.mark_dirty_and_request_refresh()
    }

    fn on_prompt_list_changed(
        &self,
        _context: rmcp::service::NotificationContext<RoleClient>,
    ) -> impl std::future::Future<Output = ()> + Send + '_ {
        self.mark_dirty_and_request_refresh()
    }
}

/// Stdio backend that spawns MCP server as a child process and communicates via rmcp.
#[derive(Clone)]
pub struct StdioBackend {
    /// Server name
    name: String,
    /// Server configuration
    config: McpServerConfig,
    /// Stdio lifecycle (process reuse strategy)
    lifecycle: StdioLifecycle,
    /// Server info (state, restarts, etc.)
    info: Arc<RwLock<StdioServerInfo>>,
    /// rmcp client for communicating with the MCP server
    client: Arc<Mutex<Option<McpClient>>>,
    /// Cached tools discovered from the server
    tools: Arc<RwLock<Vec<Tool>>>,
    /// Cached resources discovered from the server
    resources: Arc<RwLock<Vec<Resource>>>,
    /// Cached prompts discovered from the server
    prompts: Arc<RwLock<Vec<Prompt>>>,
    /// Startup timeout
    startup_timeout: Duration,
    /// Call timeout for individual requests
    call_timeout: Duration,
    /// Restart policy for stdio backend
    restart_policy: RestartPolicy,
    /// Minimum restart backoff
    restart_backoff_min: Duration,
    /// Maximum restart backoff
    restart_backoff_max: Duration,
    /// Serialize restart attempts
    restart_lock: Arc<Mutex<()>>,
    /// Restart state (backoff tracking, background loop guard)
    restart_state: Arc<Mutex<RestartState>>,
    /// Notify the main loop to refresh the aggregated registry after a successful restart.
    refresh_tx: Option<UnboundedSender<String>>,
    /// Mark that the upstream tool/resource/prompt lists are stale (best-effort; persistent only).
    registry_dirty: Arc<AtomicBool>,
    /// Serialize discovery refresh operations (best-effort; persistent only).
    registry_refresh_lock: Arc<Mutex<()>>,
    /// Per-session process slots (only used when `lifecycle=per_session`).
    session_processes: Arc<RwLock<HashMap<String, Arc<SessionProcess>>>>,
    /// Session → downstream peer mapping (used to proxy server→client requests).
    session_peers: Arc<ContractNotifier>,
    /// Aggregator for rewriting resource URIs inside forwarded notifications.
    aggregator: Arc<Aggregator>,
}

/// Settings for `StdioBackend` construction.
///
/// Grouped to avoid an overly-wide constructor signature.
pub struct StdioBackendSettings {
    pub startup_timeout: Duration,
    pub call_timeout: Duration,
    pub restart_policy: RestartPolicy,
    pub stdio_lifecycle: StdioLifecycle,
    pub restart_backoff_min: Duration,
    pub restart_backoff_max: Duration,
    pub refresh_tx: Option<UnboundedSender<String>>,
    pub session_peers: Arc<ContractNotifier>,
    pub aggregator: Arc<Aggregator>,
}

#[derive(Debug)]
struct RestartState {
    consecutive_failures: u32,
    next_allowed_restart: Instant,
    background_running: bool,
}

#[derive(Debug)]
struct SessionProcess {
    client: Mutex<Option<McpClient>>,
    restart_lock: Mutex<()>,
    restart_state: Mutex<RestartState>,
}

impl StdioBackend {
    /// Create a new stdio backend.
    pub fn new(name: String, config: McpServerConfig, settings: StdioBackendSettings) -> Self {
        let lifecycle = config.lifecycle.unwrap_or(settings.stdio_lifecycle);
        let info = StdioServerInfo {
            state: BackendState::Dead,
            restart_count: 0,
            last_restart: None,
            tool_count: 0,
        };

        Self {
            name,
            config,
            lifecycle,
            info: Arc::new(RwLock::new(info)),
            client: Arc::new(Mutex::new(None)),
            tools: Arc::new(RwLock::new(Vec::new())),
            resources: Arc::new(RwLock::new(Vec::new())),
            prompts: Arc::new(RwLock::new(Vec::new())),
            startup_timeout: settings.startup_timeout,
            call_timeout: settings.call_timeout,
            restart_policy: settings.restart_policy,
            restart_backoff_min: settings.restart_backoff_min,
            restart_backoff_max: settings.restart_backoff_max,
            restart_lock: Arc::new(Mutex::new(())),
            restart_state: Arc::new(Mutex::new(RestartState {
                consecutive_failures: 0,
                next_allowed_restart: Instant::now(),
                background_running: false,
            })),
            refresh_tx: settings.refresh_tx,
            registry_dirty: Arc::new(AtomicBool::new(false)),
            registry_refresh_lock: Arc::new(Mutex::new(())),
            session_processes: Arc::new(RwLock::new(HashMap::new())),
            session_peers: settings.session_peers,
            aggregator: settings.aggregator,
        }
    }

    /// Start the server process and establish MCP connection.
    ///
    /// When `store_client` is `false`, this will still perform discovery to populate the cached
    /// tool/resource/prompt surfaces, but it will not keep the child process alive.
    async fn start_server(&self, store_client: bool) -> Result<()> {
        tracing::info!("Starting MCP server: {}", self.name);

        // Capture the previous tool/resource/prompt surfaces so we can avoid refreshing the
        // aggregated registry if a restart didn't actually change anything.
        let old_hashes = {
            let tools = self.tools.read();
            let resources = self.resources.read();
            let prompts = self.prompts.read();
            compute_contract_hashes(tools.as_slice(), resources.as_slice(), prompts.as_slice())
        };

        // Update state to Starting
        self.info.write().state = BackendState::Starting;

        let startup_timeout = self.startup_timeout;
        let (client, discovered_tools, discovered_resources, discovered_prompts) =
            match timeout(startup_timeout, self.connect_and_discover()).await {
                Ok(Ok(v)) => v,
                Ok(Err(e)) => {
                    // Mark as dead on startup failure
                    self.info.write().state = BackendState::Dead;
                    return Err(e);
                }
                Err(_) => {
                    self.info.write().state = BackendState::Dead;
                    return Err(AdapterError::Startup(format!(
                        "Startup timeout after {}s for '{}'",
                        startup_timeout.as_secs(),
                        self.name
                    )));
                }
            };

        let new_hashes = compute_contract_hashes(
            &discovered_tools,
            &discovered_resources,
            &discovered_prompts,
        );
        let surfaces_changed = old_hashes != new_hashes;

        let tool_count = discovered_tools.len();
        tracing::info!(
            "Discovered {} tools, {} resources, {} prompts from MCP server '{}'",
            tool_count,
            discovered_resources.len(),
            discovered_prompts.len(),
            self.name
        );

        // Store discoveries
        *self.tools.write() = discovered_tools;
        *self.resources.write() = discovered_resources;
        *self.prompts.write() = discovered_prompts;

        if store_client {
            // Store the client (persistent lifecycle)
            let mut client_guard = self.client.lock().await;
            *client_guard = Some(client);
        } else {
            // Discover-only: shut down the process now; calls will spawn their own instances.
            if let Err(e) = client.cancel().await {
                tracing::debug!("Failed to stop discovery client for '{}': {}", self.name, e);
            }
            let mut client_guard = self.client.lock().await;
            *client_guard = None;
        }

        // Update state to Running
        let is_restart = {
            let info = self.info.read();
            info.last_restart.is_some()
        };
        {
            let mut info = self.info.write();
            info.state = BackendState::Running;
            info.tool_count = tool_count;
            info.last_restart = Some(Utc::now());
            if is_restart {
                info.restart_count = info.restart_count.saturating_add(1);
            }
        }

        if is_restart
            && surfaces_changed
            && let Some(tx) = &self.refresh_tx
        {
            let _ = tx.send(self.name.clone());
        }

        Ok(())
    }

    async fn connect_and_discover(
        &self,
    ) -> Result<(McpClient, Vec<Tool>, Vec<Resource>, Vec<Prompt>)> {
        let name = self.name.clone();

        let handler = if self.lifecycle == StdioLifecycle::Persistent {
            ProxyClientHandler::discovery_with_refresh(
                self.name.clone(),
                self.aggregator.clone(),
                self.refresh_tx.clone(),
                self.registry_dirty.clone(),
            )
        } else {
            ProxyClientHandler::discovery(self.name.clone(), self.aggregator.clone())
        };

        let client = self.connect_client(handler).await?;

        // Get server info (best-effort)
        if let Some(server_info) = client.peer_info() {
            tracing::info!(
                "MCP server '{}' connected: name={}, version={}",
                name,
                server_info.server_info.name,
                server_info.server_info.version,
            );
        } else {
            tracing::info!("MCP server '{}' connected (peer_info unavailable)", name);
        }

        // Discover tools/resources/prompts from the server
        let tools = client.list_all_tools().await.map_err(|e| {
            AdapterError::Startup(format!("Failed to list tools from '{name}': {e}"))
        })?;
        let resources = client.list_all_resources().await.map_err(|e| {
            AdapterError::Startup(format!("Failed to list resources from '{name}': {e}"))
        })?;
        let prompts = client.list_all_prompts().await.map_err(|e| {
            AdapterError::Startup(format!("Failed to list prompts from '{name}': {e}"))
        })?;

        Ok((client, tools, resources, prompts))
    }

    fn compute_backoff_delay(&self, consecutive_failures: u32) -> Duration {
        if consecutive_failures == 0 {
            return Duration::from_millis(0);
        }

        let min_ms_u128 = self
            .restart_backoff_min
            .as_millis()
            .min(u128::from(u64::MAX));
        let max_ms_u128 = self
            .restart_backoff_max
            .as_millis()
            .min(u128::from(u64::MAX));
        let min_ms = u64::try_from(min_ms_u128).unwrap_or(u64::MAX);
        let max_ms = u64::try_from(max_ms_u128).unwrap_or(u64::MAX);

        // Exponential backoff: min * 2^(failures-1), capped at max.
        let exp = (consecutive_failures - 1).min(30);
        let candidate = min_ms.saturating_mul(1u64 << exp);
        Duration::from_millis(candidate.min(max_ms))
    }

    async fn connect_client(&self, handler: ProxyClientHandler) -> Result<McpClient> {
        // Build the command
        let config = self.config.clone();
        let name = self.name.clone();

        let mut cmd = Command::new(&config.command);
        cmd.args(&config.args);
        for (key, value) in &config.env {
            cmd.env(key, value);
        }

        let transport = TokioChildProcess::new(cmd)
            .map_err(|e| AdapterError::Startup(format!("Failed to spawn '{name}': {e}")))?;

        handler
            .serve(transport)
            .await
            .map_err(|e| AdapterError::Startup(format!("Failed to connect to '{name}': {e}")))
    }

    fn get_or_create_session_process(&self, session_id: &str) -> Arc<SessionProcess> {
        if let Some(p) = self.session_processes.read().get(session_id) {
            return p.clone();
        }

        let mut map = self.session_processes.write();
        map.entry(session_id.to_string())
            .or_insert_with(|| {
                Arc::new(SessionProcess {
                    client: Mutex::new(None),
                    restart_lock: Mutex::new(()),
                    restart_state: Mutex::new(RestartState {
                        consecutive_failures: 0,
                        next_allowed_restart: Instant::now(),
                        background_running: false,
                    }),
                })
            })
            .clone()
    }

    async fn get_peer_for_session(&self, session_id: &str) -> Result<Peer<RoleClient>> {
        let proc = self.get_or_create_session_process(session_id);

        // Fast path: already connected.
        if let Some(client) = proc.client.lock().await.as_ref() {
            return Ok(client.peer().clone());
        }

        // Backoff gate.
        {
            let rs = proc.restart_state.lock().await;
            let now = Instant::now();
            if now < rs.next_allowed_restart {
                let remaining = rs
                    .next_allowed_restart
                    .checked_duration_since(now)
                    .unwrap_or_else(|| Duration::from_millis(0));
                return Err(AdapterError::Runtime(format!(
                    "MCP server '{}' per-session restart backoff (retry in {}ms)",
                    self.name,
                    remaining.as_millis()
                )));
            }
        }

        // Serialize connects/restarts per session.
        let _guard = proc.restart_lock.lock().await;

        // Re-check after acquiring the lock.
        if let Some(client) = proc.client.lock().await.as_ref() {
            return Ok(client.peer().clone());
        }

        // Connect with startup timeout.
        let startup_timeout = self.startup_timeout;
        let handler = ProxyClientHandler::for_session(
            self.name.clone(),
            self.aggregator.clone(),
            session_id,
            self.session_peers.as_ref(),
        );
        let connect = self.connect_client(handler);
        let client = match timeout(startup_timeout, connect).await {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => {
                let mut rs = proc.restart_state.lock().await;
                rs.consecutive_failures = rs.consecutive_failures.saturating_add(1);
                let delay = self.compute_backoff_delay(rs.consecutive_failures);
                rs.next_allowed_restart = Instant::now() + delay;
                return Err(e);
            }
            Err(_) => {
                let mut rs = proc.restart_state.lock().await;
                rs.consecutive_failures = rs.consecutive_failures.saturating_add(1);
                let delay = self.compute_backoff_delay(rs.consecutive_failures);
                rs.next_allowed_restart = Instant::now() + delay;
                return Err(AdapterError::Startup(format!(
                    "Startup timeout after {}s for '{}' (per-session)",
                    startup_timeout.as_secs(),
                    self.name
                )));
            }
        };

        {
            let mut guard = proc.client.lock().await;
            *guard = Some(client);
        }

        {
            let mut rs = proc.restart_state.lock().await;
            rs.consecutive_failures = 0;
            rs.next_allowed_restart = Instant::now();
        }

        let proc_guard = proc.client.lock().await;
        let client = proc_guard.as_ref().expect("client just set");
        Ok(client.peer().clone())
    }

    async fn handle_session_service_error(&self, session_id: &str, err: &ServiceError) {
        match err {
            ServiceError::TransportSend(_) | ServiceError::TransportClosed => {}
            _ => return,
        }

        let proc = self.session_processes.read().get(session_id).cloned();
        let Some(proc) = proc else { return };

        {
            let mut client_guard = proc.client.lock().await;
            *client_guard = None;
        }

        let mut rs = proc.restart_state.lock().await;
        rs.consecutive_failures = rs.consecutive_failures.saturating_add(1);
        let delay = self.compute_backoff_delay(rs.consecutive_failures);
        rs.next_allowed_restart = Instant::now() + delay;
    }

    fn per_call_handler(&self, session_id: Option<&str>) -> ProxyClientHandler {
        if let Some(sid) = session_id {
            ProxyClientHandler::for_session(
                self.name.clone(),
                self.aggregator.clone(),
                sid,
                self.session_peers.as_ref(),
            )
        } else {
            ProxyClientHandler::discovery(self.name.clone(), self.aggregator.clone())
        }
    }

    async fn call_tool_per_call(
        &self,
        session_id: Option<&str>,
        name: &str,
        arguments: Value,
        effective_timeout: Duration,
    ) -> Result<CallToolResult> {
        let startup_timeout = self.startup_timeout;
        let handler = self.per_call_handler(session_id);
        let connect = self.connect_client(handler);
        let client = match timeout(startup_timeout, connect).await {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                return Err(AdapterError::Startup(format!(
                    "Startup timeout after {}s for '{}' (per_call)",
                    startup_timeout.as_secs(),
                    self.name
                )));
            }
        };

        let peer = client.peer().clone();
        let args = arguments.as_object().cloned();
        let request = rmcp::model::ClientRequest::CallToolRequest(rmcp::model::CallToolRequest {
            method: rmcp::model::CallToolRequestMethod,
            params: CallToolRequestParams {
                name: name.to_string().into(),
                arguments: args,
                meta: None,
                task: None,
            },
            extensions: rmcp::model::Extensions::default(),
        });

        let handle = peer
            .send_cancellable_request(
                request,
                rmcp::service::PeerRequestOptions {
                    timeout: Some(effective_timeout),
                    meta: None,
                },
            )
            .await;

        let result = match handle {
            Ok(h) => match h.await_response().await {
                Ok(v) => match v {
                    rmcp::model::ServerResult::CallToolResult(r) => Ok(r),
                    other => Err(AdapterError::Runtime(format!(
                        "Unexpected response type for tools/call: {other:?}",
                    ))),
                },
                Err(ServiceError::Timeout { .. }) => Err(AdapterError::Runtime(format!(
                    "Tool call timed out after {}ms",
                    effective_timeout.as_millis()
                ))),
                Err(ServiceError::TransportClosed) => Err(AdapterError::Runtime(
                    "Tool call failed: disconnected".to_string(),
                )),
                Err(other) => Err(AdapterError::Runtime(format!("Tool call failed: {other}"))),
            },
            Err(e) => Err(AdapterError::Runtime(format!(
                "Tool call failed to send: {e}",
            ))),
        };

        // Best-effort cleanup.
        if let Err(e) = client.cancel().await {
            tracing::debug!("Failed to stop per-call client for '{}': {}", self.name, e);
        }

        result
    }

    async fn read_resource_per_call(
        &self,
        session_id: Option<&str>,
        uri: &str,
    ) -> Result<ReadResourceResult> {
        let startup_timeout = self.startup_timeout;
        let handler = self.per_call_handler(session_id);
        let connect = self.connect_client(handler);
        let client = match timeout(startup_timeout, connect).await {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                return Err(AdapterError::Startup(format!(
                    "Startup timeout after {}s for '{}' (per_call)",
                    startup_timeout.as_secs(),
                    self.name
                )));
            }
        };

        let peer = client.peer().clone();
        let request =
            rmcp::model::ClientRequest::ReadResourceRequest(rmcp::model::ReadResourceRequest {
                method: rmcp::model::ReadResourceRequestMethod,
                params: ReadResourceRequestParams {
                    uri: uri.to_string(),
                    meta: None,
                },
                extensions: rmcp::model::Extensions::default(),
            });

        let handle = peer
            .send_cancellable_request(
                request,
                rmcp::service::PeerRequestOptions {
                    timeout: Some(self.call_timeout),
                    meta: None,
                },
            )
            .await;

        let result = match handle {
            Ok(h) => match h.await_response().await {
                Ok(v) => match v {
                    rmcp::model::ServerResult::ReadResourceResult(r) => Ok(r),
                    other => Err(AdapterError::Runtime(format!(
                        "Unexpected response type for resources/read: {other:?}",
                    ))),
                },
                Err(ServiceError::Timeout { .. }) => Err(AdapterError::Runtime(format!(
                    "Read resource timed out after {}s",
                    self.call_timeout.as_secs()
                ))),
                Err(ServiceError::TransportClosed) => Err(AdapterError::Runtime(
                    "Read resource failed: disconnected".to_string(),
                )),
                Err(other) => Err(AdapterError::Runtime(format!(
                    "Read resource failed: {other}"
                ))),
            },
            Err(e) => Err(AdapterError::Runtime(format!(
                "Read resource failed to send: {e}",
            ))),
        };

        if let Err(e) = client.cancel().await {
            tracing::debug!("Failed to stop per-call client for '{}': {}", self.name, e);
        }

        result
    }

    async fn get_prompt_per_call(
        &self,
        session_id: Option<&str>,
        name: &str,
        arguments: Option<serde_json::Map<String, Value>>,
    ) -> Result<GetPromptResult> {
        let startup_timeout = self.startup_timeout;
        let handler = self.per_call_handler(session_id);
        let connect = self.connect_client(handler);
        let client = match timeout(startup_timeout, connect).await {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                return Err(AdapterError::Startup(format!(
                    "Startup timeout after {}s for '{}' (per_call)",
                    startup_timeout.as_secs(),
                    self.name
                )));
            }
        };

        let peer = client.peer().clone();
        let request = rmcp::model::ClientRequest::GetPromptRequest(rmcp::model::GetPromptRequest {
            method: rmcp::model::GetPromptRequestMethod,
            params: GetPromptRequestParams {
                name: name.to_string(),
                arguments,
                meta: None,
            },
            extensions: rmcp::model::Extensions::default(),
        });

        let handle = peer
            .send_cancellable_request(
                request,
                rmcp::service::PeerRequestOptions {
                    timeout: Some(self.call_timeout),
                    meta: None,
                },
            )
            .await;

        let result = match handle {
            Ok(h) => match h.await_response().await {
                Ok(v) => match v {
                    rmcp::model::ServerResult::GetPromptResult(r) => Ok(r),
                    other => Err(AdapterError::Runtime(format!(
                        "Unexpected response type for prompts/get: {other:?}",
                    ))),
                },
                Err(ServiceError::Timeout { .. }) => Err(AdapterError::Runtime(format!(
                    "Get prompt timed out after {}s",
                    self.call_timeout.as_secs()
                ))),
                Err(ServiceError::TransportClosed) => Err(AdapterError::Runtime(
                    "Get prompt failed: disconnected".to_string(),
                )),
                Err(other) => Err(AdapterError::Runtime(format!("Get prompt failed: {other}"))),
            },
            Err(e) => Err(AdapterError::Runtime(format!(
                "Get prompt failed to send: {e}",
            ))),
        };

        if let Err(e) = client.cancel().await {
            tracing::debug!("Failed to stop per-call client for '{}': {}", self.name, e);
        }

        result
    }

    async fn complete_per_call(
        &self,
        session_id: Option<&str>,
        request: CompleteRequestParams,
    ) -> Result<CompleteResult> {
        let startup_timeout = self.startup_timeout;
        let handler = self.per_call_handler(session_id);
        let connect = self.connect_client(handler);
        let client = match timeout(startup_timeout, connect).await {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                return Err(AdapterError::Startup(format!(
                    "Startup timeout after {}s for '{}' (per_call)",
                    startup_timeout.as_secs(),
                    self.name
                )));
            }
        };

        let peer = client.peer().clone();
        let request = rmcp::model::ClientRequest::CompleteRequest(rmcp::model::CompleteRequest {
            method: rmcp::model::CompleteRequestMethod,
            params: request,
            extensions: rmcp::model::Extensions::default(),
        });

        let handle = peer
            .send_cancellable_request(
                request,
                rmcp::service::PeerRequestOptions {
                    timeout: Some(self.call_timeout),
                    meta: None,
                },
            )
            .await;

        let result = match handle {
            Ok(h) => match h.await_response().await {
                Ok(v) => match v {
                    rmcp::model::ServerResult::CompleteResult(r) => Ok(r),
                    other => Err(AdapterError::Runtime(format!(
                        "Unexpected response type for completion/complete: {other:?}",
                    ))),
                },
                Err(ServiceError::Timeout { .. }) => Err(AdapterError::Runtime(format!(
                    "completion/complete timed out after {}s",
                    self.call_timeout.as_secs()
                ))),
                Err(ServiceError::TransportClosed) => Err(AdapterError::Runtime(
                    "completion/complete failed: disconnected".to_string(),
                )),
                Err(other) => Err(AdapterError::Runtime(format!(
                    "completion/complete failed: {other}"
                ))),
            },
            Err(e) => Err(AdapterError::Runtime(format!(
                "completion/complete failed to send: {e}",
            ))),
        };

        if let Err(e) = client.cancel().await {
            tracing::debug!("Failed to stop per-call client for '{}': {}", self.name, e);
        }

        result
    }

    async fn handle_service_error(&self, err: &ServiceError) {
        match err {
            ServiceError::TransportSend(_) | ServiceError::TransportClosed => {
                self.mark_dead(&err.to_string()).await;
                self.maybe_spawn_background_restart().await;
            }
            _ => {}
        }
    }

    async fn mark_dead(&self, reason: &str) {
        tracing::warn!("Marking MCP server '{}' as dead: {}", self.name, reason);

        {
            let mut info = self.info.write();
            info.state = BackendState::Dead;
        }

        // Drop the client (TokioChildProcess is kill_on_drop).
        let mut client_guard = self.client.lock().await;
        *client_guard = None;
    }

    async fn ensure_running(&self) -> Result<()> {
        // Fast path: running + connected.
        if self.info.read().state == BackendState::Running && self.client.lock().await.is_some() {
            return Ok(());
        }

        if self.restart_policy == RestartPolicy::Never {
            return Err(AdapterError::Runtime(format!(
                "MCP server '{}' is not running (restartPolicy=never)",
                self.name
            )));
        }

        // Backoff gate
        {
            let rs = self.restart_state.lock().await;
            let now = Instant::now();
            if now < rs.next_allowed_restart {
                let remaining = rs
                    .next_allowed_restart
                    .checked_duration_since(now)
                    .unwrap_or_else(|| Duration::from_millis(0));
                return Err(AdapterError::Runtime(format!(
                    "MCP server '{}' restart backoff (retry in {}ms)",
                    self.name,
                    remaining.as_millis()
                )));
            }
        }

        // Serialize restarts.
        let _guard = self.restart_lock.lock().await;

        // Re-check after acquiring the lock.
        if self.info.read().state == BackendState::Running && self.client.lock().await.is_some() {
            return Ok(());
        }

        match self.start_server(true).await {
            Ok(()) => {
                let mut rs = self.restart_state.lock().await;
                rs.consecutive_failures = 0;
                rs.next_allowed_restart = Instant::now();
                Ok(())
            }
            Err(e) => {
                let mut rs = self.restart_state.lock().await;
                rs.consecutive_failures = rs.consecutive_failures.saturating_add(1);
                let delay = self.compute_backoff_delay(rs.consecutive_failures);
                rs.next_allowed_restart = Instant::now() + delay;
                Err(e)
            }
        }
    }

    async fn get_peer(&self) -> Result<Peer<RoleClient>> {
        self.ensure_running().await?;
        let client_guard = self.client.lock().await;
        let client = client_guard.as_ref().ok_or_else(|| {
            AdapterError::Runtime(format!("MCP server '{}' not connected", self.name))
        })?;
        Ok(client.peer().clone())
    }

    async fn refresh_discovery_if_dirty(&self) -> Result<()> {
        if self.lifecycle != StdioLifecycle::Persistent {
            return Ok(());
        }
        if !self.registry_dirty.load(Ordering::Acquire) {
            return Ok(());
        }

        // Coalesce concurrent refresh attempts.
        let _guard = self.registry_refresh_lock.lock().await;

        // Re-check after acquiring the lock.
        if !self.registry_dirty.load(Ordering::Acquire) {
            return Ok(());
        }

        let peer = self.get_peer().await?;

        let (tools, resources, prompts) = refresh_lists_from_peer(&peer, &self.name).await?;

        *self.tools.write() = tools;
        *self.resources.write() = resources;
        *self.prompts.write() = prompts;
        self.registry_dirty.store(false, Ordering::Release);
        Ok(())
    }

    async fn maybe_spawn_background_restart(&self) {
        if self.restart_policy != RestartPolicy::Always {
            return;
        }

        {
            let mut rs = self.restart_state.lock().await;
            if rs.background_running {
                return;
            }
            rs.background_running = true;
        }

        let backend = self.clone();
        tokio::spawn(async move {
            backend.background_restart_loop().await;
        });
    }

    async fn background_restart_loop(self) {
        loop {
            // Try to bring it up.
            if self.ensure_running().await.is_ok() {
                break;
            }

            // Sleep until the next allowed restart time.
            let delay = {
                let rs = self.restart_state.lock().await;
                rs.next_allowed_restart
                    .checked_duration_since(Instant::now())
                    .unwrap_or_else(|| Duration::from_millis(50))
            };
            tokio::time::sleep(delay).await;
        }

        let mut rs = self.restart_state.lock().await;
        rs.background_running = false;
    }

    // NOTE: if you need additional runtime metrics for `/status`, add them to `BackendStatus`
    // so all backends expose a consistent status surface.
}

#[async_trait]
impl Backend for StdioBackend {
    fn name(&self) -> &str {
        &self.name
    }

    fn backend_type(&self) -> BackendType {
        BackendType::Stdio
    }

    fn state(&self) -> BackendState {
        self.info.read().state
    }

    fn status(&self) -> BackendStatus {
        let info = self.info.read();
        BackendStatus {
            name: self.name.clone(),
            backend_type: BackendType::Stdio,
            state: info.state,
            tool_count: info.tool_count,
            spec_url: None,
            restart_count: info.restart_count,
            last_restart: info.last_restart,
        }
    }

    async fn list_tools(&self) -> Result<Vec<ToolInfo>> {
        self.refresh_discovery_if_dirty().await?;
        let tools = self.tools.read();
        Ok(tools
            .iter()
            .map(|t| {
                let name = t.name.to_string();
                ToolInfo {
                    name: name.clone(),
                    original_name: name,
                    description: t.description.clone().map(|d| d.to_string()),
                    input_schema: serde_json::to_value(&*t.input_schema).unwrap_or_default(),
                    output_schema: t
                        .output_schema
                        .as_ref()
                        .map(|s| serde_json::to_value(&**s).unwrap_or_default()),
                    annotations: t.annotations.clone(),
                }
            })
            .collect())
    }

    async fn call_tool(
        &self,
        session_id: Option<&str>,
        name: &str,
        arguments: Value,
        timeout: Option<Duration>,
    ) -> Result<CallToolResult> {
        let effective_timeout = timeout
            .filter(|t| *t > Duration::from_millis(0))
            .map_or(self.call_timeout, |t| t.min(self.call_timeout));

        let peer = match self.lifecycle {
            StdioLifecycle::Persistent => self.get_peer().await?,
            StdioLifecycle::PerSession => {
                let sid = session_id.ok_or_else(|| {
                    AdapterError::Runtime(format!(
                        "MCP server '{}' requires an MCP session id (stdio.lifecycle=per_session)",
                        self.name
                    ))
                })?;
                self.get_peer_for_session(sid).await?
            }
            StdioLifecycle::PerCall => {
                return self
                    .call_tool_per_call(session_id, name, arguments, effective_timeout)
                    .await;
            }
        };

        // Convert arguments to JsonObject
        let args = arguments.as_object().cloned();

        let request = rmcp::model::ClientRequest::CallToolRequest(rmcp::model::CallToolRequest {
            method: rmcp::model::CallToolRequestMethod,
            params: CallToolRequestParams {
                name: name.to_string().into(),
                arguments: args,
                meta: None,
                task: None,
            },
            extensions: rmcp::model::Extensions::default(),
        });

        let handle = match peer
            .send_cancellable_request(
                request,
                rmcp::service::PeerRequestOptions {
                    timeout: Some(effective_timeout),
                    meta: None,
                },
            )
            .await
        {
            Ok(h) => h,
            Err(e) => {
                match self.lifecycle {
                    StdioLifecycle::Persistent => self.handle_service_error(&e).await,
                    StdioLifecycle::PerSession => {
                        if let Some(sid) = session_id {
                            self.handle_session_service_error(sid, &e).await;
                        }
                    }
                    StdioLifecycle::PerCall => {}
                }
                return Err(AdapterError::Runtime(format!(
                    "Tool call failed to send: {e}",
                )));
            }
        };

        let server_result = match handle.await_response().await {
            Ok(v) => v,
            Err(e) => match e {
                ServiceError::Timeout { .. } => {
                    return Err(AdapterError::Runtime(format!(
                        "Tool call timed out after {}ms",
                        effective_timeout.as_millis()
                    )));
                }
                ServiceError::TransportClosed => {
                    match self.lifecycle {
                        StdioLifecycle::Persistent => self.handle_service_error(&e).await,
                        StdioLifecycle::PerSession => {
                            if let Some(sid) = session_id {
                                self.handle_session_service_error(sid, &e).await;
                            }
                        }
                        StdioLifecycle::PerCall => {}
                    }
                    return Err(AdapterError::Runtime(
                        "Tool call failed: disconnected".to_string(),
                    ));
                }
                other => {
                    match self.lifecycle {
                        StdioLifecycle::Persistent => self.handle_service_error(&other).await,
                        StdioLifecycle::PerSession => {
                            if let Some(sid) = session_id {
                                self.handle_session_service_error(sid, &other).await;
                            }
                        }
                        StdioLifecycle::PerCall => {}
                    }
                    return Err(AdapterError::Runtime(format!("Tool call failed: {other}")));
                }
            },
        };

        match server_result {
            rmcp::model::ServerResult::CallToolResult(r) => Ok(r),
            other => Err(AdapterError::Runtime(format!(
                "Unexpected response type for tools/call: {other:?}",
            ))),
        }
    }

    async fn list_resources(&self) -> Result<Vec<ResourceInfo>> {
        self.refresh_discovery_if_dirty().await?;
        let resources = self.resources.read();
        Ok(resources
            .iter()
            .map(|r| ResourceInfo {
                uri: r.uri.clone(),
                name: r.name.clone(),
                description: r.description.clone(),
                mime_type: r.mime_type.clone(),
                size: r.size,
            })
            .collect())
    }

    async fn read_resource(
        &self,
        session_id: Option<&str>,
        uri: &str,
    ) -> Result<ReadResourceResult> {
        let peer = match self.lifecycle {
            StdioLifecycle::Persistent => self.get_peer().await?,
            StdioLifecycle::PerSession => {
                let sid = session_id.ok_or_else(|| {
                    AdapterError::Runtime(format!(
                        "MCP server '{}' requires an MCP session id (stdio.lifecycle=per_session)",
                        self.name
                    ))
                })?;
                self.get_peer_for_session(sid).await?
            }
            StdioLifecycle::PerCall => {
                return self.read_resource_per_call(session_id, uri).await;
            }
        };

        let request =
            rmcp::model::ClientRequest::ReadResourceRequest(rmcp::model::ReadResourceRequest {
                method: rmcp::model::ReadResourceRequestMethod,
                params: ReadResourceRequestParams {
                    uri: uri.to_string(),
                    meta: None,
                },
                extensions: rmcp::model::Extensions::default(),
            });

        let handle = match peer
            .send_cancellable_request(
                request,
                rmcp::service::PeerRequestOptions {
                    timeout: Some(self.call_timeout),
                    meta: None,
                },
            )
            .await
        {
            Ok(h) => h,
            Err(e) => {
                match self.lifecycle {
                    StdioLifecycle::Persistent => self.handle_service_error(&e).await,
                    StdioLifecycle::PerSession => {
                        if let Some(sid) = session_id {
                            self.handle_session_service_error(sid, &e).await;
                        }
                    }
                    StdioLifecycle::PerCall => {}
                }
                return Err(AdapterError::Runtime(format!(
                    "Read resource failed to send: {e}",
                )));
            }
        };

        let server_result = match handle.await_response().await {
            Ok(v) => v,
            Err(e) => match e {
                ServiceError::Timeout { .. } => {
                    return Err(AdapterError::Runtime(format!(
                        "Read resource timed out after {}s",
                        self.call_timeout.as_secs()
                    )));
                }
                ServiceError::TransportClosed => {
                    match self.lifecycle {
                        StdioLifecycle::Persistent => self.handle_service_error(&e).await,
                        StdioLifecycle::PerSession => {
                            if let Some(sid) = session_id {
                                self.handle_session_service_error(sid, &e).await;
                            }
                        }
                        StdioLifecycle::PerCall => {}
                    }
                    return Err(AdapterError::Runtime(
                        "Read resource failed: disconnected".to_string(),
                    ));
                }
                other => {
                    match self.lifecycle {
                        StdioLifecycle::Persistent => self.handle_service_error(&other).await,
                        StdioLifecycle::PerSession => {
                            if let Some(sid) = session_id {
                                self.handle_session_service_error(sid, &other).await;
                            }
                        }
                        StdioLifecycle::PerCall => {}
                    }
                    return Err(AdapterError::Runtime(format!(
                        "Read resource failed: {other}"
                    )));
                }
            },
        };

        match server_result {
            rmcp::model::ServerResult::ReadResourceResult(r) => Ok(r),
            other => Err(AdapterError::Runtime(format!(
                "Unexpected response type for resources/read: {other:?}",
            ))),
        }
    }

    async fn list_prompts(&self) -> Result<Vec<PromptInfo>> {
        self.refresh_discovery_if_dirty().await?;
        let prompts = self.prompts.read();
        Ok(prompts
            .iter()
            .map(|p| PromptInfo {
                name: p.name.clone(),
                description: p.description.clone(),
                arguments: p.arguments.clone(),
            })
            .collect())
    }

    async fn get_prompt(
        &self,
        session_id: Option<&str>,
        name: &str,
        arguments: Option<serde_json::Map<String, Value>>,
    ) -> Result<GetPromptResult> {
        let peer = match self.lifecycle {
            StdioLifecycle::Persistent => self.get_peer().await?,
            StdioLifecycle::PerSession => {
                let sid = session_id.ok_or_else(|| {
                    AdapterError::Runtime(format!(
                        "MCP server '{}' requires an MCP session id (stdio.lifecycle=per_session)",
                        self.name
                    ))
                })?;
                self.get_peer_for_session(sid).await?
            }
            StdioLifecycle::PerCall => {
                return self.get_prompt_per_call(session_id, name, arguments).await;
            }
        };

        let request = rmcp::model::ClientRequest::GetPromptRequest(rmcp::model::GetPromptRequest {
            method: rmcp::model::GetPromptRequestMethod,
            params: GetPromptRequestParams {
                name: name.to_string(),
                arguments,
                meta: None,
            },
            extensions: rmcp::model::Extensions::default(),
        });

        let handle = match peer
            .send_cancellable_request(
                request,
                rmcp::service::PeerRequestOptions {
                    timeout: Some(self.call_timeout),
                    meta: None,
                },
            )
            .await
        {
            Ok(h) => h,
            Err(e) => {
                match self.lifecycle {
                    StdioLifecycle::Persistent => self.handle_service_error(&e).await,
                    StdioLifecycle::PerSession => {
                        if let Some(sid) = session_id {
                            self.handle_session_service_error(sid, &e).await;
                        }
                    }
                    StdioLifecycle::PerCall => {}
                }
                return Err(AdapterError::Runtime(format!(
                    "Get prompt failed to send: {e}",
                )));
            }
        };

        let server_result = match handle.await_response().await {
            Ok(v) => v,
            Err(e) => match e {
                ServiceError::Timeout { .. } => {
                    return Err(AdapterError::Runtime(format!(
                        "Get prompt timed out after {}s",
                        self.call_timeout.as_secs()
                    )));
                }
                ServiceError::TransportClosed => {
                    match self.lifecycle {
                        StdioLifecycle::Persistent => self.handle_service_error(&e).await,
                        StdioLifecycle::PerSession => {
                            if let Some(sid) = session_id {
                                self.handle_session_service_error(sid, &e).await;
                            }
                        }
                        StdioLifecycle::PerCall => {}
                    }
                    return Err(AdapterError::Runtime(
                        "Get prompt failed: disconnected".to_string(),
                    ));
                }
                other => {
                    match self.lifecycle {
                        StdioLifecycle::Persistent => self.handle_service_error(&other).await,
                        StdioLifecycle::PerSession => {
                            if let Some(sid) = session_id {
                                self.handle_session_service_error(sid, &other).await;
                            }
                        }
                        StdioLifecycle::PerCall => {}
                    }
                    return Err(AdapterError::Runtime(format!("Get prompt failed: {other}")));
                }
            },
        };

        match server_result {
            rmcp::model::ServerResult::GetPromptResult(r) => Ok(r),
            other => Err(AdapterError::Runtime(format!(
                "Unexpected response type for prompts/get: {other:?}",
            ))),
        }
    }

    async fn complete(
        &self,
        session_id: Option<&str>,
        request: CompleteRequestParams,
    ) -> Result<CompleteResult> {
        let peer = match self.lifecycle {
            StdioLifecycle::Persistent => self.get_peer().await?,
            StdioLifecycle::PerSession => {
                let sid = session_id.ok_or_else(|| {
                    AdapterError::Runtime(format!(
                        "MCP server '{}' requires an MCP session id (stdio.lifecycle=per_session)",
                        self.name
                    ))
                })?;
                self.get_peer_for_session(sid).await?
            }
            StdioLifecycle::PerCall => {
                return self.complete_per_call(session_id, request).await;
            }
        };

        let request = rmcp::model::ClientRequest::CompleteRequest(rmcp::model::CompleteRequest {
            method: rmcp::model::CompleteRequestMethod,
            params: request,
            extensions: rmcp::model::Extensions::default(),
        });

        let handle = match peer
            .send_cancellable_request(
                request,
                rmcp::service::PeerRequestOptions {
                    timeout: Some(self.call_timeout),
                    meta: None,
                },
            )
            .await
        {
            Ok(h) => h,
            Err(e) => {
                match self.lifecycle {
                    StdioLifecycle::Persistent => self.handle_service_error(&e).await,
                    StdioLifecycle::PerSession => {
                        if let Some(sid) = session_id {
                            self.handle_session_service_error(sid, &e).await;
                        }
                    }
                    StdioLifecycle::PerCall => {}
                }
                return Err(AdapterError::Runtime(format!(
                    "completion/complete failed to send: {e}",
                )));
            }
        };

        let server_result = match handle.await_response().await {
            Ok(v) => v,
            Err(e) => match e {
                ServiceError::Timeout { .. } => {
                    return Err(AdapterError::Runtime(format!(
                        "completion/complete timed out after {}s",
                        self.call_timeout.as_secs()
                    )));
                }
                ServiceError::TransportClosed => {
                    match self.lifecycle {
                        StdioLifecycle::Persistent => self.handle_service_error(&e).await,
                        StdioLifecycle::PerSession => {
                            if let Some(sid) = session_id {
                                self.handle_session_service_error(sid, &e).await;
                            }
                        }
                        StdioLifecycle::PerCall => {}
                    }
                    return Err(AdapterError::Runtime(
                        "completion/complete failed: disconnected".to_string(),
                    ));
                }
                other => {
                    match self.lifecycle {
                        StdioLifecycle::Persistent => self.handle_service_error(&other).await,
                        StdioLifecycle::PerSession => {
                            if let Some(sid) = session_id {
                                self.handle_session_service_error(sid, &other).await;
                            }
                        }
                        StdioLifecycle::PerCall => {}
                    }
                    return Err(AdapterError::Runtime(format!(
                        "completion/complete failed: {other}"
                    )));
                }
            },
        };

        match server_result {
            rmcp::model::ServerResult::CompleteResult(r) => Ok(r),
            other => Err(AdapterError::Runtime(format!(
                "Unexpected response type for completion/complete: {other:?}",
            ))),
        }
    }

    async fn subscribe(&self, session_id: Option<&str>, uri: &str) -> Result<()> {
        if self.lifecycle != StdioLifecycle::PerSession {
            return Err(AdapterError::Runtime(format!(
                "resources/subscribe is only supported when stdio.lifecycle=per_session for '{}' (to avoid cross-session notification leakage)",
                self.name,
            )));
        }

        let peer = match self.lifecycle {
            StdioLifecycle::PerSession => {
                let sid = session_id.ok_or_else(|| {
                    AdapterError::Runtime(format!(
                        "MCP server '{}' requires an MCP session id (stdio.lifecycle=per_session)",
                        self.name
                    ))
                })?;
                self.get_peer_for_session(sid).await?
            }
            _ => unreachable!("handled above"),
        };

        let request = rmcp::model::ClientRequest::SubscribeRequest(rmcp::model::SubscribeRequest {
            method: rmcp::model::SubscribeRequestMethod,
            params: rmcp::model::SubscribeRequestParams {
                uri: uri.to_string(),
                meta: None,
            },
            extensions: rmcp::model::Extensions::default(),
        });

        let handle = match peer
            .send_cancellable_request(
                request,
                rmcp::service::PeerRequestOptions {
                    timeout: Some(self.call_timeout),
                    meta: None,
                },
            )
            .await
        {
            Ok(h) => h,
            Err(e) => {
                match self.lifecycle {
                    StdioLifecycle::Persistent => self.handle_service_error(&e).await,
                    StdioLifecycle::PerSession => {
                        if let Some(sid) = session_id {
                            self.handle_session_service_error(sid, &e).await;
                        }
                    }
                    StdioLifecycle::PerCall => {}
                }
                return Err(AdapterError::Runtime(format!(
                    "resources/subscribe failed to send: {e}",
                )));
            }
        };

        let server_result = match handle.await_response().await {
            Ok(v) => v,
            Err(e) => match e {
                ServiceError::Timeout { .. } => {
                    return Err(AdapterError::Runtime(format!(
                        "resources/subscribe timed out after {}s",
                        self.call_timeout.as_secs()
                    )));
                }
                ServiceError::TransportClosed => {
                    match self.lifecycle {
                        StdioLifecycle::Persistent => self.handle_service_error(&e).await,
                        StdioLifecycle::PerSession => {
                            if let Some(sid) = session_id {
                                self.handle_session_service_error(sid, &e).await;
                            }
                        }
                        StdioLifecycle::PerCall => {}
                    }
                    return Err(AdapterError::Runtime(
                        "resources/subscribe failed: disconnected".to_string(),
                    ));
                }
                other => {
                    match self.lifecycle {
                        StdioLifecycle::Persistent => self.handle_service_error(&other).await,
                        StdioLifecycle::PerSession => {
                            if let Some(sid) = session_id {
                                self.handle_session_service_error(sid, &other).await;
                            }
                        }
                        StdioLifecycle::PerCall => {}
                    }
                    return Err(AdapterError::Runtime(format!(
                        "resources/subscribe failed: {other}"
                    )));
                }
            },
        };

        match server_result {
            rmcp::model::ServerResult::EmptyResult(_) => Ok(()),
            other => Err(AdapterError::Runtime(format!(
                "Unexpected response type for resources/subscribe: {other:?}",
            ))),
        }
    }

    async fn unsubscribe(&self, session_id: Option<&str>, uri: &str) -> Result<()> {
        if self.lifecycle != StdioLifecycle::PerSession {
            return Err(AdapterError::Runtime(format!(
                "resources/unsubscribe is only supported when stdio.lifecycle=per_session for '{}' (to avoid cross-session notification leakage)",
                self.name,
            )));
        }

        let peer = match self.lifecycle {
            StdioLifecycle::PerSession => {
                let sid = session_id.ok_or_else(|| {
                    AdapterError::Runtime(format!(
                        "MCP server '{}' requires an MCP session id (stdio.lifecycle=per_session)",
                        self.name
                    ))
                })?;
                self.get_peer_for_session(sid).await?
            }
            _ => unreachable!("handled above"),
        };

        let request =
            rmcp::model::ClientRequest::UnsubscribeRequest(rmcp::model::UnsubscribeRequest {
                method: rmcp::model::UnsubscribeRequestMethod,
                params: rmcp::model::UnsubscribeRequestParams {
                    uri: uri.to_string(),
                    meta: None,
                },
                extensions: rmcp::model::Extensions::default(),
            });

        let handle = match peer
            .send_cancellable_request(
                request,
                rmcp::service::PeerRequestOptions {
                    timeout: Some(self.call_timeout),
                    meta: None,
                },
            )
            .await
        {
            Ok(h) => h,
            Err(e) => {
                match self.lifecycle {
                    StdioLifecycle::Persistent => self.handle_service_error(&e).await,
                    StdioLifecycle::PerSession => {
                        if let Some(sid) = session_id {
                            self.handle_session_service_error(sid, &e).await;
                        }
                    }
                    StdioLifecycle::PerCall => {}
                }
                return Err(AdapterError::Runtime(format!(
                    "resources/unsubscribe failed to send: {e}",
                )));
            }
        };

        let server_result = match handle.await_response().await {
            Ok(v) => v,
            Err(e) => match e {
                ServiceError::Timeout { .. } => {
                    return Err(AdapterError::Runtime(format!(
                        "resources/unsubscribe timed out after {}s",
                        self.call_timeout.as_secs()
                    )));
                }
                ServiceError::TransportClosed => {
                    match self.lifecycle {
                        StdioLifecycle::Persistent => self.handle_service_error(&e).await,
                        StdioLifecycle::PerSession => {
                            if let Some(sid) = session_id {
                                self.handle_session_service_error(sid, &e).await;
                            }
                        }
                        StdioLifecycle::PerCall => {}
                    }
                    return Err(AdapterError::Runtime(
                        "resources/unsubscribe failed: disconnected".to_string(),
                    ));
                }
                other => {
                    match self.lifecycle {
                        StdioLifecycle::Persistent => self.handle_service_error(&other).await,
                        StdioLifecycle::PerSession => {
                            if let Some(sid) = session_id {
                                self.handle_session_service_error(sid, &other).await;
                            }
                        }
                        StdioLifecycle::PerCall => {}
                    }
                    return Err(AdapterError::Runtime(format!(
                        "resources/unsubscribe failed: {other}"
                    )));
                }
            },
        };

        match server_result {
            rmcp::model::ServerResult::EmptyResult(_) => Ok(()),
            other => Err(AdapterError::Runtime(format!(
                "Unexpected response type for resources/unsubscribe: {other:?}",
            ))),
        }
    }

    async fn start(&self) -> Result<()> {
        self.start_server(self.lifecycle == StdioLifecycle::Persistent)
            .await
    }

    async fn shutdown(&self) {
        tracing::info!("Stopping MCP server: {}", self.name);

        // Cancel the client
        let client = {
            let mut client_guard = self.client.lock().await;
            client_guard.take()
        };
        if let Some(client) = client
            && let Err(e) = client.cancel().await
        {
            tracing::warn!("Failed to gracefully stop '{}': {}", self.name, e);
        }

        // Cancel any per-session processes (best-effort)
        let sessions: Vec<(String, Arc<SessionProcess>)> =
            self.session_processes.write().drain().collect();
        for (sid, proc) in sessions {
            let client = {
                let mut guard = proc.client.lock().await;
                guard.take()
            };
            if let Some(client) = client
                && let Err(e) = client.cancel().await
            {
                tracing::debug!(
                    mcp_session_id = %sid,
                    error = %e,
                    "Failed to stop per-session stdio backend '{}'",
                    self.name
                );
            }
        }

        // Mark as dead
        let mut info = self.info.write();
        info.state = BackendState::Dead;
        info.tool_count = 0;
        info.last_restart = None;
    }

    async fn shutdown_session(&self, session_id: &str) {
        if self.lifecycle != StdioLifecycle::PerSession {
            return;
        }

        let proc = self.session_processes.write().remove(session_id);
        let Some(proc) = proc else { return };

        let client = {
            let mut guard = proc.client.lock().await;
            guard.take()
        };
        if let Some(client) = client
            && let Err(e) = client.cancel().await
        {
            tracing::debug!(
                mcp_session_id = %session_id,
                error = %e,
                "Failed to stop per-session stdio backend '{}'",
                self.name
            );
        }
    }
}

// ============================================================================
// Backend Manager
// ============================================================================

/// Manages all backends (both stdio and `OpenAPI`).
pub struct BackendManager {
    /// All backends by name
    backends: Arc<RwLock<HashMap<String, Arc<dyn Backend>>>>,
}

impl BackendManager {
    /// Create a new backend manager.
    pub fn new() -> Self {
        Self {
            backends: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Add a backend.
    pub fn add_backend(&self, backend: Arc<dyn Backend>) {
        let mut backends = self.backends.write();
        backends.insert(backend.name().to_string(), backend);
    }

    /// Get a backend by name.
    pub fn get_backend(&self, name: &str) -> Option<Arc<dyn Backend>> {
        let backends = self.backends.read();
        backends.get(name).cloned()
    }

    /// Get all backends.
    pub fn get_all_backends(&self) -> Vec<Arc<dyn Backend>> {
        let backends = self.backends.read();
        backends.values().cloned().collect()
    }

    /// Get status for all backends.
    pub fn get_all_status(&self) -> HashMap<String, BackendStatus> {
        let backends = self.backends.read();
        backends
            .iter()
            .map(|(name, backend)| (name.clone(), backend.status()))
            .collect()
    }

    /// Start all backends.
    pub async fn start_all(&self) -> Result<()> {
        let backends: Vec<_> = {
            let backends = self.backends.read();
            backends.values().cloned().collect()
        };

        for backend in backends {
            backend.start().await?;
        }

        Ok(())
    }

    /// Shutdown all backends.
    pub async fn shutdown_all(&self) {
        tracing::info!("Shutting down all backends");

        let backends: Vec<_> = {
            let backends = self.backends.read();
            backends.values().cloned().collect()
        };

        for backend in backends {
            backend.shutdown().await;
        }
    }

    /// Check if there are no backends.
    pub fn is_empty(&self) -> bool {
        let backends = self.backends.read();
        backends.is_empty()
    }
}

impl Default for BackendManager {
    fn default() -> Self {
        Self::new()
    }
}
