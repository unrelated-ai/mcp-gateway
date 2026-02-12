//! Configuration parsing and validation.
//!
//! Supports both:
//! - Legacy JSON format (mcpServers only)
//! - Unified config format (adapter/imports/servers)

use crate::error::{AdapterError, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;
use unrelated_env::serde_helpers::{deserialize_option_bool_env, deserialize_option_u64_env};
use unrelated_tool_transforms::TransformPipeline;

// Re-export shared HTTP/OpenAPI config types so the Adapter keeps its current config schema,
// while allowing the Gateway to reuse the same shapes without copy/pasting.
pub use unrelated_http_tools::config::{
    AuthConfig, EndpointDefaults, HttpServerConfig, HttpToolConfig,
};
pub use unrelated_openapi_tools::config::{
    ApiServerConfig, AutoDiscoverConfig, HashPolicy, OpenApiOverrideToolConfig,
    OpenApiOverridesConfig,
};

// NOTE: env-backed deserializers live in `unrelated-env` so they can be shared across crates.

// ============================================================================
// CLI Arguments
// ============================================================================

/// CLI arguments for the adapter.
#[derive(Parser, Debug, Clone)]
#[command(name = "unrelated-mcp-adapter")]
#[command(
    version,
    about = "Expose stdio-based MCP servers and HTTP APIs over MCP"
)]
pub struct CliArgs {
    /// Path to unified YAML config file.
    #[arg(short = 'c', long = "config", env = "UNRELATED_CONFIG")]
    pub config: Option<PathBuf>,

    /// Path(s) to MCP servers JSON config (mcpServers format).
    /// Can be specified multiple times. Legacy option.
    #[arg(
        short = 'm',
        long = "mcp-config",
        env = "UNRELATED_MCP_CONFIG",
        value_delimiter = ':'
    )]
    pub mcp_config: Vec<PathBuf>,

    /// Convenience mode: single `OpenAPI` spec URL (no config file needed).
    #[arg(long = "api-spec", env = "UNRELATED_API_SPEC")]
    pub api_spec: Option<String>,

    /// Print the fully resolved configuration (after imports + env expansion + overrides) and exit.
    #[arg(long = "print-effective-config")]
    pub print_effective_config: bool,

    /// HTTP bind address (ip:port)
    #[arg(short = 'b', long, env = "UNRELATED_BIND")]
    pub bind: Option<String>,

    /// Optional static bearer token required for all non-health HTTP endpoints (including `/mcp`).
    ///
    /// If set, requests must include: `Authorization: Bearer <token>`.
    #[arg(long = "mcp-bearer-token", env = "UNRELATED_MCP_BEARER_TOKEN")]
    pub mcp_bearer_token: Option<String>,

    /// Log level. Supports tracing filter syntax.
    #[arg(short = 'l', long = "log-level", env = "UNRELATED_LOG")]
    pub log_level: Option<String>,

    /// Timeout for individual tool calls (seconds)
    #[arg(long, env = "UNRELATED_CALL_TIMEOUT")]
    pub call_timeout: Option<u64>,

    /// Max time to wait for servers to initialize on startup (seconds)
    #[arg(long, env = "UNRELATED_STARTUP_TIMEOUT")]
    pub startup_timeout: Option<u64>,

    /// Probe `OpenAPI` base URLs for reachability on startup.
    #[arg(
        long = "openapi-probe",
        env = "UNRELATED_OPENAPI_PROBE",
        action = clap::ArgAction::Set
    )]
    pub openapi_probe: Option<bool>,

    /// Timeout for the `OpenAPI` base URL probe (seconds).
    #[arg(
        long = "openapi-probe-timeout",
        env = "UNRELATED_OPENAPI_PROBE_TIMEOUT"
    )]
    pub openapi_probe_timeout: Option<u64>,

    /// Restart policy for stdio MCP backends.
    #[arg(long, env = "UNRELATED_RESTART_POLICY")]
    pub restart_policy: Option<RestartPolicy>,

    /// Stdio backend lifecycle (process reuse strategy).
    #[arg(long, env = "UNRELATED_STDIO_LIFECYCLE")]
    pub stdio_lifecycle: Option<StdioLifecycle>,

    /// Minimum restart backoff in milliseconds (stdio backends).
    #[arg(long, env = "UNRELATED_RESTART_BACKOFF_MIN_MS")]
    pub restart_backoff_min_ms: Option<u64>,

    /// Maximum restart backoff in milliseconds (stdio backends).
    #[arg(long, env = "UNRELATED_RESTART_BACKOFF_MAX_MS")]
    pub restart_backoff_max_ms: Option<u64>,
}

// ============================================================================
// Restart Policy (Stdio Backends)
// ============================================================================

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum RestartPolicy {
    #[value(name = "never")]
    Never,
    #[value(name = "on_demand")]
    OnDemand,
    #[value(name = "always")]
    Always,
}

// ============================================================================
// Stdio Lifecycle (Stdio Backends)
// ============================================================================

/// Controls how stdio MCP server processes are reused.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum StdioLifecycle {
    /// One shared process for this backend (fast, but can leak state across sessions).
    #[value(name = "persistent")]
    Persistent,
    /// One process per MCP session (good isolation, moderate overhead).
    #[value(name = "per_session")]
    PerSession,
    /// One process per tool/resource/prompt call (maximum isolation, highest overhead).
    #[value(name = "per_call")]
    PerCall,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct RestartBackoffConfig {
    /// Minimum backoff in milliseconds
    #[serde(default, deserialize_with = "deserialize_option_u64_env")]
    pub min_ms: Option<u64>,
    /// Maximum backoff in milliseconds
    #[serde(default, deserialize_with = "deserialize_option_u64_env")]
    pub max_ms: Option<u64>,
}

// ============================================================================
// Unified Config File (adapter/imports/servers)
// ============================================================================

const DEFAULT_BIND: &str = "127.0.0.1:3000";
const DEFAULT_LOG_LEVEL: &str = "info";
const DEFAULT_STARTUP_TIMEOUT_SECS: u64 = 30;
const DEFAULT_OPENAPI_PROBE: bool = true;
const DEFAULT_OPENAPI_PROBE_TIMEOUT_SECS: u64 = 5;
const DEFAULT_RESTART_POLICY: RestartPolicy = RestartPolicy::OnDemand;
const DEFAULT_STDIO_LIFECYCLE: StdioLifecycle = StdioLifecycle::PerSession;
const DEFAULT_RESTART_BACKOFF_MIN_MS: u64 = 250;
const DEFAULT_RESTART_BACKOFF_MAX_MS: u64 = 30000;

/// Effective adapter settings (after merging defaults + config + env + CLI).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdapterSettings {
    pub bind: String,
    /// Optional static bearer token required for all non-health HTTP endpoints (including `/mcp`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mcp_bearer_token: Option<String>,
    pub log_level: String,
    pub call_timeout: u64,
    pub startup_timeout: u64,
    pub openapi_probe: bool,
    pub openapi_probe_timeout: u64,
    pub restart_policy: RestartPolicy,
    pub stdio_lifecycle: StdioLifecycle,
    pub restart_backoff: RestartBackoff,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RestartBackoff {
    pub min_ms: u64,
    pub max_ms: u64,
}

impl Default for AdapterSettings {
    fn default() -> Self {
        Self {
            bind: DEFAULT_BIND.to_string(),
            mcp_bearer_token: None,
            log_level: DEFAULT_LOG_LEVEL.to_string(),
            call_timeout: crate::timeouts::tool_call_timeout_default_secs(),
            startup_timeout: DEFAULT_STARTUP_TIMEOUT_SECS,
            openapi_probe: DEFAULT_OPENAPI_PROBE,
            openapi_probe_timeout: DEFAULT_OPENAPI_PROBE_TIMEOUT_SECS,
            restart_policy: DEFAULT_RESTART_POLICY,
            stdio_lifecycle: DEFAULT_STDIO_LIFECYCLE,
            restart_backoff: RestartBackoff {
                min_ms: DEFAULT_RESTART_BACKOFF_MIN_MS,
                max_ms: DEFAULT_RESTART_BACKOFF_MAX_MS,
            },
        }
    }
}

impl AdapterSettings {
    pub fn call_timeout_duration(&self) -> Duration {
        Duration::from_secs(self.call_timeout)
    }

    pub fn startup_timeout_duration(&self) -> Duration {
        Duration::from_secs(self.startup_timeout)
    }

    pub fn openapi_probe_timeout_duration(&self) -> Duration {
        Duration::from_secs(self.openapi_probe_timeout)
    }

    pub fn restart_backoff_min_duration(&self) -> Duration {
        Duration::from_millis(self.restart_backoff.min_ms)
    }

    pub fn restart_backoff_max_duration(&self) -> Duration {
        Duration::from_millis(self.restart_backoff.max_ms)
    }
}

/// Adapter settings as provided by the config file (partial; all fields optional).
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct AdapterSection {
    #[serde(default)]
    pub bind: Option<String>,
    /// Optional static bearer token required for all non-health HTTP endpoints (including `/mcp`).
    #[serde(default)]
    pub mcp_bearer_token: Option<String>,
    #[serde(default)]
    pub log_level: Option<String>,
    #[serde(default, deserialize_with = "deserialize_option_u64_env")]
    pub call_timeout: Option<u64>,
    #[serde(default, deserialize_with = "deserialize_option_u64_env")]
    pub startup_timeout: Option<u64>,
    #[serde(default, deserialize_with = "deserialize_option_bool_env")]
    pub openapi_probe: Option<bool>,
    #[serde(default, deserialize_with = "deserialize_option_u64_env")]
    pub openapi_probe_timeout: Option<u64>,
    #[serde(default)]
    pub restart_policy: Option<RestartPolicy>,
    #[serde(default)]
    pub stdio_lifecycle: Option<StdioLifecycle>,
    #[serde(default)]
    pub restart_backoff: RestartBackoffConfig,
    /// Tool transforms applied to `tools/list` and `tools/call` (single-tenant scope).
    #[serde(default)]
    pub transforms: TransformPipeline,
}

/// Import-time includes (load-time macros).
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum ImportConfig {
    #[serde(rename = "mcp-json")]
    McpJson(McpJsonImportConfig),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpJsonImportConfig {
    pub path: String,
    #[serde(default)]
    pub prefix: Option<String>,
    #[serde(default)]
    pub conflict: ImportConflictPolicy,
}

#[derive(Debug, Clone, Copy, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ImportConflictPolicy {
    #[default]
    Error,
    Skip,
    Overwrite,
}

/// Unified config file format.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ConfigFile {
    #[serde(default)]
    pub adapter: AdapterSection,
    #[serde(default)]
    pub imports: Vec<ImportConfig>,
    #[serde(default)]
    pub servers: HashMap<String, ServerConfig>,
}

// ============================================================================
// MCP Server Config (Stdio)
// ============================================================================

/// Legacy MCP JSON configuration format.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpConfigFile {
    /// Map of server name to server configuration.
    #[serde(default)]
    pub mcp_servers: HashMap<String, McpServerConfig>,
}

/// Configuration for a single stdio MCP server.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct McpServerConfig {
    /// Command to execute
    pub command: String,

    /// Arguments to pass to the command
    #[serde(default)]
    pub args: Vec<String>,

    /// Environment variables for the process
    #[serde(default)]
    pub env: HashMap<String, String>,

    /// Optional per-server override for stdio lifecycle (defaults to `adapter.stdioLifecycle`).
    #[serde(default)]
    pub lifecycle: Option<StdioLifecycle>,
}

// ============================================================================
// Servers (runtime backends)
// ============================================================================

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ServerConfig {
    #[serde(rename = "stdio")]
    Stdio {
        #[serde(flatten)]
        config: McpServerConfig,
    },
    #[serde(rename = "openapi")]
    OpenApi {
        #[serde(flatten)]
        config: ApiServerConfig,
    },
    #[serde(rename = "http")]
    Http {
        #[serde(flatten)]
        config: HttpServerConfig,
    },
}

// ============================================================================
// Effective Configuration
// ============================================================================

/// Merged configuration from all sources.
#[derive(Debug, Clone)]
pub struct AdapterConfig {
    pub cli: CliArgs,
    pub adapter: AdapterSettings,
    pub transforms: TransformPipeline,
    pub servers: HashMap<String, ServerConfig>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EffectiveConfig {
    pub adapter: AdapterSettings,
    pub transforms: TransformPipeline,
    pub servers: HashMap<String, ServerConfig>,
}

impl AdapterConfig {
    pub fn effective(&self) -> EffectiveConfig {
        EffectiveConfig {
            adapter: self.adapter.clone(),
            transforms: self.transforms.clone(),
            servers: self.servers.clone(),
        }
    }

    /// Load and merge configuration from CLI args, env, and config files.
    pub fn load(cli: CliArgs) -> Result<Self> {
        let mut adapter = AdapterSettings::default();
        let mut transforms = TransformPipeline::default();
        let mut servers: HashMap<String, ServerConfig> = HashMap::new();

        // 1) Load config file (if provided).
        if let Some(config_path) = &cli.config {
            let file = load_config_file(config_path)?;

            // Apply adapter section from file.
            transforms = file.adapter.transforms.clone();
            apply_adapter_section(&mut adapter, file.adapter)?;

            // Seed servers from file.
            for (name, server) in file.servers {
                let expanded = expand_server_env_vars(server)?;
                servers.insert(name, expanded);
            }

            // Apply imports from file.
            for import in file.imports {
                apply_import(&mut servers, import)?;
            }
        }

        // 2) Apply CLI/ENV overrides for adapter settings (CLI > ENV is handled by clap).
        apply_cli_overrides(&mut adapter, &cli)?;

        // 3) Apply legacy `--mcp-config` as implicit mcp-json imports.
        apply_legacy_mcp_configs(&mut servers, &cli.mcp_config)?;

        // 4) Apply quick `--api-spec` as implicit OpenAPI server.
        if let Some(spec_url) = &cli.api_spec {
            let expanded = expand_env_string(spec_url)?;
            let cfg = ApiServerConfig {
                spec: expanded,
                spec_hash: None,
                spec_hash_policy: HashPolicy::Ignore,
                base_url: None,
                auth: None,
                auto_discover: AutoDiscoverConfig::Enabled(true),
                endpoints: HashMap::new(),
                defaults: EndpointDefaults::default(),
                response_transforms: Vec::new(),
                response_overrides: Vec::new(),
                overrides: OpenApiOverridesConfig::default(),
            };
            servers.insert("default".to_string(), ServerConfig::OpenApi { config: cfg });
        }

        // 5) Validate: must have at least one config source (unless a config file was explicitly provided).
        if cli.config.is_none()
            && cli.mcp_config.is_empty()
            && cli.api_spec.is_none()
            && servers.is_empty()
        {
            return Err(AdapterError::Config(
                "No configuration provided. Use --config, --mcp-config, or --api-spec".to_string(),
            ));
        }

        // 6) Validate restart backoff bounds.
        if adapter.restart_backoff.min_ms > adapter.restart_backoff.max_ms {
            return Err(AdapterError::Config(format!(
                "Invalid restart backoff: minMs ({}) must be <= maxMs ({})",
                adapter.restart_backoff.min_ms, adapter.restart_backoff.max_ms
            )));
        }

        // 7) Clamp tool call timeout to the shared cap (Gateway ↔ Adapter coordination).
        let cap = crate::timeouts::tool_call_timeout_cap_secs();
        if adapter.call_timeout == 0 {
            return Err(AdapterError::Config("callTimeout must be > 0".to_string()));
        }
        if adapter.call_timeout > cap {
            tracing::warn!(
                call_timeout = adapter.call_timeout,
                cap,
                "adapter callTimeout exceeds UNRELATED_TOOL_CALL_TIMEOUT_MAX_SECS cap; clamping"
            );
            adapter.call_timeout = cap;
        }

        Ok(Self {
            cli,
            adapter,
            transforms,
            servers,
        })
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

fn load_config_file(path: &std::path::Path) -> Result<ConfigFile> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| AdapterError::Config(format!("Failed to read {}: {}", path.display(), e)))?;

    // YAML by default; JSON when extension is .json
    if path.extension().is_some_and(|ext| ext == "json") {
        serde_json::from_str(&content)
            .map_err(|e| AdapterError::Config(format!("Failed to parse {}: {}", path.display(), e)))
    } else {
        serde_yaml::from_str(&content)
            .map_err(|e| AdapterError::Config(format!("Failed to parse {}: {}", path.display(), e)))
    }
}

fn apply_adapter_section(adapter: &mut AdapterSettings, section: AdapterSection) -> Result<()> {
    if let Some(bind) = section.bind {
        adapter.bind = expand_env_string(&bind)?;
    }
    if let Some(v) = section.mcp_bearer_token {
        let t = expand_env_string(&v)?;
        let t = t.trim().to_string();
        adapter.mcp_bearer_token = (!t.is_empty()).then_some(t);
    }
    if let Some(level) = section.log_level {
        adapter.log_level = expand_env_string(&level)?;
    }
    if let Some(v) = section.call_timeout {
        adapter.call_timeout = v;
    }
    if let Some(v) = section.startup_timeout {
        adapter.startup_timeout = v;
    }
    if let Some(v) = section.openapi_probe {
        adapter.openapi_probe = v;
    }
    if let Some(v) = section.openapi_probe_timeout {
        adapter.openapi_probe_timeout = v;
    }
    if let Some(v) = section.restart_policy {
        adapter.restart_policy = v;
    }
    if let Some(v) = section.stdio_lifecycle {
        adapter.stdio_lifecycle = v;
    }
    if let Some(v) = section.restart_backoff.min_ms {
        adapter.restart_backoff.min_ms = v;
    }
    if let Some(v) = section.restart_backoff.max_ms {
        adapter.restart_backoff.max_ms = v;
    }
    Ok(())
}

fn apply_cli_overrides(adapter: &mut AdapterSettings, cli: &CliArgs) -> Result<()> {
    if let Some(bind) = &cli.bind {
        adapter.bind = expand_env_string(bind)?;
    }
    if let Some(v) = &cli.mcp_bearer_token {
        let t = expand_env_string(v)?;
        let t = t.trim().to_string();
        adapter.mcp_bearer_token = (!t.is_empty()).then_some(t);
    }

    // Precedence for log level:
    // CLI flag (--log-level) / UNRELATED_LOG env (via clap) > RUST_LOG env > config file > defaults
    if let Some(level) = &cli.log_level {
        adapter.log_level.clone_from(level);
    } else if let Ok(level) = std::env::var("RUST_LOG") {
        adapter.log_level = level;
    }

    if let Some(v) = cli.call_timeout {
        adapter.call_timeout = v;
    }
    if let Some(v) = cli.startup_timeout {
        adapter.startup_timeout = v;
    }
    if let Some(v) = cli.openapi_probe {
        adapter.openapi_probe = v;
    }
    if let Some(v) = cli.openapi_probe_timeout {
        adapter.openapi_probe_timeout = v;
    }
    if let Some(v) = cli.restart_policy {
        adapter.restart_policy = v;
    }
    if let Some(v) = cli.stdio_lifecycle {
        adapter.stdio_lifecycle = v;
    }
    if let Some(v) = cli.restart_backoff_min_ms {
        adapter.restart_backoff.min_ms = v;
    }
    if let Some(v) = cli.restart_backoff_max_ms {
        adapter.restart_backoff.max_ms = v;
    }
    Ok(())
}

fn apply_import(servers: &mut HashMap<String, ServerConfig>, import: ImportConfig) -> Result<()> {
    match import {
        ImportConfig::McpJson(cfg) => {
            let path_str = expand_env_string(&cfg.path)?;
            let prefix = cfg.prefix.map(|p| expand_env_string(&p)).transpose()?;
            let content = std::fs::read_to_string(&path_str).map_err(|e| {
                AdapterError::Config(format!("Failed to read import {path_str}: {e}"))
            })?;
            let file: McpConfigFile = serde_json::from_str(&content).map_err(|e| {
                AdapterError::Config(format!("Failed to parse import {path_str}: {e}"))
            })?;

            for (name, server_config) in file.mcp_servers {
                let expanded = expand_mcp_env_vars(server_config)?;
                let final_name = match &prefix {
                    Some(p) => format!("{p}:{name}"),
                    None => name,
                };
                merge_server(
                    servers,
                    final_name,
                    ServerConfig::Stdio { config: expanded },
                    cfg.conflict,
                    Some(&path_str),
                )?;
            }
            Ok(())
        }
    }
}

fn apply_legacy_mcp_configs(
    servers: &mut HashMap<String, ServerConfig>,
    paths: &[PathBuf],
) -> Result<()> {
    let mut seen_paths: Vec<PathBuf> = Vec::new();
    for path in paths {
        let canonical = path.canonicalize().unwrap_or_else(|_| path.clone());
        if seen_paths.contains(&canonical) {
            continue;
        }
        seen_paths.push(canonical);

        let content = std::fs::read_to_string(path).map_err(|e| {
            AdapterError::Config(format!("Failed to read {}: {}", path.display(), e))
        })?;

        let file: McpConfigFile = serde_json::from_str(&content).map_err(|e| {
            AdapterError::Config(format!("Failed to parse {}: {}", path.display(), e))
        })?;

        for (name, server_config) in file.mcp_servers {
            let expanded = expand_mcp_env_vars(server_config)?;
            merge_server(
                servers,
                name,
                ServerConfig::Stdio { config: expanded },
                ImportConflictPolicy::Error,
                Some(&path.display().to_string()),
            )?;
        }
    }
    Ok(())
}

fn merge_server(
    servers: &mut HashMap<String, ServerConfig>,
    name: String,
    new_server: ServerConfig,
    policy: ImportConflictPolicy,
    source: Option<&str>,
) -> Result<()> {
    match servers.get(&name) {
        None => {
            servers.insert(name, new_server);
            Ok(())
        }
        Some(existing) => match policy {
            ImportConflictPolicy::Skip => Ok(()),
            ImportConflictPolicy::Overwrite => {
                servers.insert(name, new_server);
                Ok(())
            }
            ImportConflictPolicy::Error => {
                // Allow dedupe for identical stdio configs.
                if let (ServerConfig::Stdio { config: a }, ServerConfig::Stdio { config: b }) =
                    (existing, &new_server)
                    && a == b
                {
                    return Ok(());
                }

                let src = source.unwrap_or("<import>");
                Err(AdapterError::Config(format!(
                    "Conflicting configurations for server '{name}' from {src}"
                )))
            }
        },
    }
}

fn expand_server_env_vars(server: ServerConfig) -> Result<ServerConfig> {
    match server {
        ServerConfig::Stdio { config } => Ok(ServerConfig::Stdio {
            config: expand_mcp_env_vars(config)?,
        }),
        ServerConfig::OpenApi { config } => Ok(ServerConfig::OpenApi {
            config: expand_api_env_vars(config)?,
        }),
        ServerConfig::Http { config } => Ok(ServerConfig::Http {
            config: expand_http_env_vars(config)?,
        }),
    }
}

/// Expand ${VAR} patterns in MCP server config.
fn expand_mcp_env_vars(mut config: McpServerConfig) -> Result<McpServerConfig> {
    config.command = expand_env_string(&config.command)?;
    config.args = config
        .args
        .into_iter()
        .map(|arg| expand_env_string(&arg))
        .collect::<Result<Vec<_>>>()?;
    config.env = config
        .env
        .into_iter()
        .map(|(k, v)| Ok((k, expand_env_string(&v)?)))
        .collect::<Result<HashMap<_, _>>>()?;
    Ok(config)
}

/// Expand ${VAR} patterns in API server config.
fn expand_api_env_vars(mut config: ApiServerConfig) -> Result<ApiServerConfig> {
    config.spec = expand_env_string(&config.spec)?;
    if let Some(hash) = config.spec_hash {
        config.spec_hash = Some(expand_env_string(&hash)?);
    }
    if let Some(url) = config.base_url {
        config.base_url = Some(expand_env_string(&url)?);
    }
    if let Some(auth) = config.auth {
        config.auth = Some(expand_auth_env_vars(auth)?);
    }
    // Expand headers in defaults
    config.defaults.headers = config
        .defaults
        .headers
        .into_iter()
        .map(|(k, v)| Ok((k, expand_env_string(&v)?)))
        .collect::<Result<HashMap<_, _>>>()?;

    // Expand overrides
    config.overrides = expand_openapi_overrides_env_vars(config.overrides)?;
    Ok(config)
}

fn expand_openapi_overrides_env_vars(
    mut overrides: OpenApiOverridesConfig,
) -> Result<OpenApiOverridesConfig> {
    overrides.tools = overrides
        .tools
        .into_iter()
        .map(|(name, tool)| Ok((name, expand_openapi_override_tool_env_vars(tool)?)))
        .collect::<Result<HashMap<_, _>>>()?;
    Ok(overrides)
}

fn expand_openapi_override_tool_env_vars(
    mut tool: OpenApiOverrideToolConfig,
) -> Result<OpenApiOverrideToolConfig> {
    if let Some(desc) = tool.description.take() {
        tool.description = Some(expand_env_string(&desc)?);
    }

    if let Some(op) = tool.matcher.operation_id.take() {
        tool.matcher.operation_id = Some(expand_env_string(&op)?);
    }
    if let Some(m) = tool.matcher.method.take() {
        tool.matcher.method = Some(expand_env_string(&m)?);
    }
    if let Some(p) = tool.matcher.path.take() {
        tool.matcher.path = Some(expand_env_string(&p)?);
    }

    tool.request = expand_http_tool_env_vars(tool.request)?;
    Ok(tool)
}

fn expand_http_env_vars(mut config: HttpServerConfig) -> Result<HttpServerConfig> {
    config.base_url = expand_env_string(&config.base_url)?;
    if let Some(auth) = config.auth.take() {
        config.auth = Some(expand_auth_env_vars(auth)?);
    }
    config.defaults.headers = config
        .defaults
        .headers
        .into_iter()
        .map(|(k, v)| Ok((k, expand_env_string(&v)?)))
        .collect::<Result<HashMap<_, _>>>()?;
    config.tools = config
        .tools
        .into_iter()
        .map(|(name, tool)| Ok((name, expand_http_tool_env_vars(tool)?)))
        .collect::<Result<HashMap<_, _>>>()?;
    Ok(config)
}

fn expand_http_tool_env_vars(mut tool: HttpToolConfig) -> Result<HttpToolConfig> {
    tool.method = expand_env_string(&tool.method)?;
    tool.path = expand_env_string(&tool.path)?;
    if let Some(desc) = tool.description.take() {
        tool.description = Some(expand_env_string(&desc)?);
    }
    tool.params = tool
        .params
        .into_iter()
        .map(|(k, mut p)| {
            if let Some(name) = p.name.take() {
                p.name = Some(expand_env_string(&name)?);
            }
            Ok((k, p))
        })
        .collect::<Result<HashMap<_, _>>>()?;
    Ok(tool)
}

/// Expand ${VAR} patterns in auth config.
fn expand_auth_env_vars(auth: AuthConfig) -> Result<AuthConfig> {
    Ok(match auth {
        AuthConfig::None => AuthConfig::None,
        AuthConfig::Bearer { token } => AuthConfig::Bearer {
            token: expand_env_string(&token)?,
        },
        AuthConfig::Header { name, value } => AuthConfig::Header {
            name,
            value: expand_env_string(&value)?,
        },
        AuthConfig::Basic { username, password } => AuthConfig::Basic {
            username: expand_env_string(&username)?,
            password: expand_env_string(&password)?,
        },
        AuthConfig::Query { name, value } => AuthConfig::Query {
            name,
            value: expand_env_string(&value)?,
        },
    })
}

/// Expand ${VAR} patterns in a string.
pub fn expand_env_string(s: &str) -> Result<String> {
    unrelated_env::expand_env_string(s).map_err(AdapterError::Config)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_expand_env_string() {
        unsafe { std::env::set_var("TEST_VAR", "hello") };
        assert_eq!(expand_env_string("${TEST_VAR}").unwrap(), "hello");
        assert_eq!(
            expand_env_string("prefix_${TEST_VAR}_suffix").unwrap(),
            "prefix_hello_suffix"
        );
        assert_eq!(expand_env_string("no_vars_here").unwrap(), "no_vars_here");
        unsafe { std::env::remove_var("TEST_VAR") };
    }

    #[test]
    fn test_expand_env_missing_var() {
        let result = expand_env_string("${DEFINITELY_NOT_SET_12345}");
        assert!(result.is_err());
    }

    #[test]
    fn test_auto_discover_config_default() {
        let config = AutoDiscoverConfig::default();
        assert!(config.is_enabled());
        assert!(config.include_patterns().is_empty());
        assert!(config.exclude_patterns().is_empty());
    }

    #[test]
    fn test_auto_discover_config_disabled() {
        let config = AutoDiscoverConfig::Enabled(false);
        assert!(!config.is_enabled());
    }

    #[test]
    fn test_auto_discover_config_detailed() {
        let config = AutoDiscoverConfig::Detailed {
            include: vec!["GET *".to_string()],
            exclude: vec!["DELETE *".to_string()],
        };
        assert!(config.is_enabled());
        assert_eq!(config.include_patterns(), &["GET *"]);
        assert_eq!(config.exclude_patterns(), &["DELETE *"]);
    }

    #[test]
    fn mcp_json_import_conflict_error_rejects_different_stdio_configs() {
        let dir = tempdir().expect("tempdir");
        let mcp1 = dir.path().join("mcp1.json");
        let mcp2 = dir.path().join("mcp2.json");
        std::fs::write(
            &mcp1,
            r#"{"mcpServers":{"s1":{"command":"cmd-a","args":[],"env":{}}}}"#,
        )
        .expect("write mcp1");
        std::fs::write(
            &mcp2,
            r#"{"mcpServers":{"s1":{"command":"cmd-b","args":[],"env":{}}}}"#,
        )
        .expect("write mcp2");

        let cfg = dir.path().join("cfg.yaml");
        std::fs::write(
            &cfg,
            format!(
                r#"imports:
  - type: mcp-json
    path: "{}"
    conflict: error
  - type: mcp-json
    path: "{}"
    conflict: error
"#,
                mcp1.display(),
                mcp2.display()
            ),
        )
        .expect("write cfg");

        let cli = CliArgs {
            config: Some(cfg),
            mcp_config: vec![],
            api_spec: None,
            print_effective_config: false,
            bind: None,
            mcp_bearer_token: None,
            log_level: None,
            call_timeout: None,
            startup_timeout: None,
            openapi_probe: None,
            openapi_probe_timeout: None,
            restart_policy: None,
            stdio_lifecycle: None,
            restart_backoff_min_ms: None,
            restart_backoff_max_ms: None,
        };

        let err = AdapterConfig::load(cli).unwrap_err().to_string();
        assert!(
            err.contains("Conflicting configurations for server 's1'"),
            "err={err}"
        );
    }

    #[test]
    fn mcp_json_import_conflict_error_allows_identical_stdio_configs() {
        let dir = tempdir().expect("tempdir");
        let mcp1 = dir.path().join("mcp1.json");
        let mcp2 = dir.path().join("mcp2.json");
        std::fs::write(
            &mcp1,
            r#"{"mcpServers":{"s1":{"command":"same","args":["--x"],"env":{"A":"1"}}}}"#,
        )
        .expect("write mcp1");
        std::fs::write(
            &mcp2,
            r#"{"mcpServers":{"s1":{"command":"same","args":["--x"],"env":{"A":"1"}}}}"#,
        )
        .expect("write mcp2");

        let cfg = dir.path().join("cfg.yaml");
        std::fs::write(
            &cfg,
            format!(
                r#"imports:
  - type: mcp-json
    path: "{}"
    conflict: error
  - type: mcp-json
    path: "{}"
    conflict: error
"#,
                mcp1.display(),
                mcp2.display()
            ),
        )
        .expect("write cfg");

        let cli = CliArgs {
            config: Some(cfg),
            mcp_config: vec![],
            api_spec: None,
            print_effective_config: false,
            bind: None,
            mcp_bearer_token: None,
            log_level: None,
            call_timeout: None,
            startup_timeout: None,
            openapi_probe: None,
            openapi_probe_timeout: None,
            restart_policy: None,
            stdio_lifecycle: None,
            restart_backoff_min_ms: None,
            restart_backoff_max_ms: None,
        };

        let loaded = AdapterConfig::load(cli).expect("load");
        assert!(matches!(
            loaded.servers.get("s1"),
            Some(ServerConfig::Stdio { .. })
        ));
    }

    #[test]
    fn mcp_json_import_conflict_skip_keeps_first() {
        let dir = tempdir().expect("tempdir");
        let mcp1 = dir.path().join("mcp1.json");
        let mcp2 = dir.path().join("mcp2.json");
        std::fs::write(
            &mcp1,
            r#"{"mcpServers":{"s1":{"command":"cmd-a","args":[],"env":{}}}}"#,
        )
        .expect("write mcp1");
        std::fs::write(
            &mcp2,
            r#"{"mcpServers":{"s1":{"command":"cmd-b","args":[],"env":{}}}}"#,
        )
        .expect("write mcp2");

        let cfg = dir.path().join("cfg.yaml");
        std::fs::write(
            &cfg,
            format!(
                r#"imports:
  - type: mcp-json
    path: "{}"
    conflict: error
  - type: mcp-json
    path: "{}"
    conflict: skip
"#,
                mcp1.display(),
                mcp2.display()
            ),
        )
        .expect("write cfg");

        let cli = CliArgs {
            config: Some(cfg),
            mcp_config: vec![],
            api_spec: None,
            print_effective_config: false,
            bind: None,
            mcp_bearer_token: None,
            log_level: None,
            call_timeout: None,
            startup_timeout: None,
            openapi_probe: None,
            openapi_probe_timeout: None,
            restart_policy: None,
            stdio_lifecycle: None,
            restart_backoff_min_ms: None,
            restart_backoff_max_ms: None,
        };

        let loaded = AdapterConfig::load(cli).expect("load");
        let ServerConfig::Stdio { config } = loaded.servers.get("s1").unwrap() else {
            panic!("expected stdio config");
        };
        assert_eq!(config.command, "cmd-a");
    }

    #[test]
    fn mcp_json_import_conflict_overwrite_replaces() {
        let dir = tempdir().expect("tempdir");
        let mcp1 = dir.path().join("mcp1.json");
        let mcp2 = dir.path().join("mcp2.json");
        std::fs::write(
            &mcp1,
            r#"{"mcpServers":{"s1":{"command":"cmd-a","args":[],"env":{}}}}"#,
        )
        .expect("write mcp1");
        std::fs::write(
            &mcp2,
            r#"{"mcpServers":{"s1":{"command":"cmd-b","args":[],"env":{}}}}"#,
        )
        .expect("write mcp2");

        let cfg = dir.path().join("cfg.yaml");
        std::fs::write(
            &cfg,
            format!(
                r#"imports:
  - type: mcp-json
    path: "{}"
    conflict: error
  - type: mcp-json
    path: "{}"
    conflict: overwrite
"#,
                mcp1.display(),
                mcp2.display()
            ),
        )
        .expect("write cfg");

        let cli = CliArgs {
            config: Some(cfg),
            mcp_config: vec![],
            api_spec: None,
            print_effective_config: false,
            bind: None,
            mcp_bearer_token: None,
            log_level: None,
            call_timeout: None,
            startup_timeout: None,
            openapi_probe: None,
            openapi_probe_timeout: None,
            restart_policy: None,
            stdio_lifecycle: None,
            restart_backoff_min_ms: None,
            restart_backoff_max_ms: None,
        };

        let loaded = AdapterConfig::load(cli).expect("load");
        let ServerConfig::Stdio { config } = loaded.servers.get("s1").unwrap() else {
            panic!("expected stdio config");
        };
        assert_eq!(config.command, "cmd-b");
    }
}
