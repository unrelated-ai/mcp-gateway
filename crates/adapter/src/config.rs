//! Configuration parsing and validation.
//!
//! Unified config format:
//! - `adapter` process settings
//! - `servers` runtime backends

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

    /// Convenience mode: single `OpenAPI` spec URL (no config file needed).
    #[arg(long = "api-spec", env = "UNRELATED_API_SPEC")]
    pub api_spec: Option<String>,

    /// Print the fully resolved configuration (after env expansion + overrides) and exit.
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
// Unified Config File (adapter/servers)
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

/// Legacy import stubs kept only to produce migration-focused errors.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum LegacyImportConfig {
    #[serde(rename = "mcp-json")]
    McpJson(LegacyMcpJsonImportConfig),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LegacyMcpJsonImportConfig {
    pub path: String,
    #[serde(default)]
    pub prefix: Option<String>,
}

/// Unified config file format.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ConfigFile {
    #[serde(default)]
    pub adapter: AdapterSection,
    #[serde(default)]
    pub imports: Vec<LegacyImportConfig>,
    #[serde(default)]
    pub servers: HashMap<String, ServerConfig>,
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

const REDACTED_SECRET: &str = "***REDACTED***";

impl AdapterConfig {
    pub fn effective(&self) -> EffectiveConfig {
        EffectiveConfig {
            adapter: self.adapter.clone(),
            transforms: self.transforms.clone(),
            servers: self.servers.clone(),
        }
    }

    /// Like `effective()`, but with sensitive credentials redacted for safe printing.
    #[must_use]
    pub fn effective_redacted(&self) -> EffectiveConfig {
        let mut cfg = self.effective();
        if cfg.adapter.mcp_bearer_token.is_some() {
            cfg.adapter.mcp_bearer_token = Some(REDACTED_SECRET.to_string());
        }
        for server in cfg.servers.values_mut() {
            match server {
                ServerConfig::Stdio { .. } => {}
                ServerConfig::OpenApi { config } => redact_auth(config.auth.as_mut()),
                ServerConfig::Http { config } => redact_auth(config.auth.as_mut()),
            }
        }
        cfg
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

            // Legacy import support was removed; fail fast with a migration-focused error.
            if !file.imports.is_empty() {
                return Err(unsupported_legacy_imports_error(&file.imports));
            }
        }

        // 2) Apply CLI/ENV overrides for adapter settings (CLI > ENV is handled by clap).
        apply_cli_overrides(&mut adapter, &cli)?;

        // 3) Apply quick `--api-spec` as implicit OpenAPI server.
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

        // 4) Validate: must have at least one config source (unless a config file was explicitly provided).
        if cli.config.is_none() && cli.api_spec.is_none() && servers.is_empty() {
            return Err(AdapterError::Config(
                "No configuration provided. Use --config or --api-spec".to_string(),
            ));
        }

        // 5) Validate restart backoff bounds.
        if adapter.restart_backoff.min_ms > adapter.restart_backoff.max_ms {
            return Err(AdapterError::Config(format!(
                "Invalid restart backoff: minMs ({}) must be <= maxMs ({})",
                adapter.restart_backoff.min_ms, adapter.restart_backoff.max_ms
            )));
        }

        // 6) Clamp tool call timeout to the shared cap (Gateway ↔ Adapter coordination).
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

fn redact_auth(auth: Option<&mut AuthConfig>) {
    let Some(auth) = auth else {
        return;
    };
    match auth {
        AuthConfig::None => {}
        AuthConfig::Bearer { token } => *token = REDACTED_SECRET.to_string(),
        AuthConfig::Header { value, .. } | AuthConfig::Query { value, .. } => {
            *value = REDACTED_SECRET.to_string();
        }
        AuthConfig::Basic { password, .. } => *password = REDACTED_SECRET.to_string(),
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

fn unsupported_legacy_imports_error(imports: &[LegacyImportConfig]) -> AdapterError {
    let mut details = Vec::new();
    for import in imports {
        match import {
            LegacyImportConfig::McpJson(cfg) => {
                let entry = if let Some(prefix) = &cfg.prefix {
                    format!("{} (prefix: {})", cfg.path, prefix)
                } else {
                    cfg.path.clone()
                };
                details.push(entry);
            }
        }
    }
    let joined = if details.is_empty() {
        "<unknown>".to_string()
    } else {
        details.join(", ")
    };
    AdapterError::Config(format!(
        "The `imports` section is no longer supported. Found legacy `mcp-json` imports: {joined}. \
Please move each imported server into `servers:` using `type: stdio` and remove `imports`."
    ))
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
    use std::path::PathBuf;
    use tempfile::tempdir;

    fn cli_args_with_config(config: PathBuf) -> CliArgs {
        CliArgs {
            config: Some(config),
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
        }
    }

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
    fn effective_redacted_masks_sensitive_values() {
        let dir = tempdir().expect("tempdir");
        let cfg = dir.path().join("cfg.yaml");
        std::fs::write(
            &cfg,
            r"adapter:
  mcpBearerToken: MCP_BEARER_SUPER_SECRET
servers:
  http_bearer:
    type: http
    baseUrl: https://example.com
    auth:
      type: bearer
      token: HTTP_BEARER_SECRET
  http_header:
    type: http
    baseUrl: https://example.com
    auth:
      type: header
      name: X-Api-Key
      value: HTTP_HEADER_SECRET
  http_query:
    type: http
    baseUrl: https://example.com
    auth:
      type: query
      name: api_key
      value: HTTP_QUERY_SECRET
  openapi_basic:
    type: openapi
    spec: https://example.com/openapi.json
    auth:
      type: basic
      username: test-user
      password: OPENAPI_BASIC_PASSWORD_SECRET
",
        )
        .expect("write cfg");

        let loaded = AdapterConfig::load(cli_args_with_config(cfg)).expect("load config");

        let rendered =
            serde_yaml::to_string(&loaded.effective_redacted()).expect("serialize redacted config");

        for secret in [
            "MCP_BEARER_SUPER_SECRET",
            "HTTP_BEARER_SECRET",
            "HTTP_HEADER_SECRET",
            "HTTP_QUERY_SECRET",
            "OPENAPI_BASIC_PASSWORD_SECRET",
        ] {
            assert!(
                !rendered.contains(secret),
                "redacted output leaked secret '{secret}'",
            );
        }
        assert_eq!(rendered.matches(REDACTED_SECRET).count(), 5);
    }

    #[test]
    fn legacy_imports_are_rejected_with_migration_message() {
        let dir = tempdir().expect("tempdir");
        let cfg = dir.path().join("cfg.yaml");
        std::fs::write(
            &cfg,
            r"imports:
  - type: mcp-json
    path: ./legacy.json
servers: {}
",
        )
        .expect("write cfg");

        let err = AdapterConfig::load(cli_args_with_config(cfg))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("`imports` section is no longer supported"),
            "err={err}"
        );
        assert!(err.contains("mcp-json"), "err={err}");
    }

    #[test]
    fn empty_imports_list_is_allowed() {
        let dir = tempdir().expect("tempdir");
        let cfg = dir.path().join("cfg.yaml");
        std::fs::write(
            &cfg,
            r"imports: []
servers:
  local:
    type: stdio
    command: /bin/echo
",
        )
        .expect("write cfg");

        let loaded = AdapterConfig::load(cli_args_with_config(cfg)).expect("load");
        assert!(matches!(
            loaded.servers.get("local"),
            Some(ServerConfig::Stdio { .. })
        ));
    }
}
