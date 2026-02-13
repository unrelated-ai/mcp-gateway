mod api;
mod config;

use anyhow::Context as _;
use clap::{ArgAction, Args, Parser, Subcommand, ValueEnum};
use owo_colors::OwoColorize as _;
use std::path::PathBuf;
use std::process::ExitCode;
use unrelated_tool_transforms::TransformPipeline;
use url::Url;

const DEFAULT_ADMIN_BASE: &str = "http://127.0.0.1:27101";
const DEFAULT_DATA_BASE: &str = "http://127.0.0.1:27100";

#[derive(Parser, Debug)]
#[command(name = "unrelated-gateway-admin")]
#[command(about = "Manage Unrelated MCP Gateway (admin/control plane)")]
struct Cli {
    /// Path to CLI config file (JSON). Defaults to XDG config dir.
    #[arg(long)]
    config: Option<PathBuf>,

    /// Gateway admin base URL (e.g. <http://127.0.0.1:27101>).
    #[arg(long, env = "UNRELATED_GATEWAY_ADMIN_BASE")]
    admin_base: Option<String>,

    /// Gateway data plane base URL (e.g. <http://127.0.0.1:27100>).
    /// Used only for printing connection strings / mcp.json.
    #[arg(long, env = "UNRELATED_GATEWAY_DATA_BASE")]
    data_base: Option<String>,

    /// Admin API token.
    #[arg(long, env = "UNRELATED_GATEWAY_ADMIN_TOKEN", conflicts_with_all = ["token_file", "token_stdin"])]
    token: Option<String>,

    /// Read admin API token from file.
    #[arg(long, env = "UNRELATED_GATEWAY_ADMIN_TOKEN_FILE", conflicts_with_all = ["token", "token_stdin"])]
    token_file: Option<PathBuf>,

    /// Read admin API token from stdin (trimmed).
    #[arg(long, conflicts_with_all = ["token", "token_file"])]
    token_stdin: bool,

    /// Output JSON instead of human-readable text (where supported).
    #[arg(long)]
    json: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    Tenants {
        #[command(subcommand)]
        command: TenantsCommand,
    },
    Upstreams {
        #[command(subcommand)]
        command: UpstreamsCommand,
    },
    Profiles {
        #[command(subcommand)]
        command: Box<ProfilesCommand>,
    },
    McpJson {
        #[command(subcommand)]
        command: McpJsonCommand,
    },
}

#[derive(Subcommand, Debug)]
enum ConfigCommand {
    /// Print the resolved config (flags/env/config file + defaults).
    Show,
    /// Persist defaults (admin base, token, etc.) into the config file.
    Set(ConfigSetArgs),
}

#[derive(Args, Debug)]
struct ConfigSetArgs {
    #[arg(long)]
    admin_base: Option<String>,
    #[arg(long)]
    data_base: Option<String>,

    #[arg(long, conflicts_with_all = ["token_file", "token_stdin"])]
    token: Option<String>,
    #[arg(long, conflicts_with_all = ["token", "token_stdin"])]
    token_file: Option<PathBuf>,
    #[arg(long, conflicts_with_all = ["token", "token_file"])]
    token_stdin: bool,
}

#[derive(Subcommand, Debug)]
enum TenantsCommand {
    List,
    Get {
        id: String,
    },
    Put {
        id: String,
        #[arg(long, default_value_t = true, action = ArgAction::Set)]
        enabled: bool,
    },
    Delete {
        id: String,
    },
    /// Issue a tenant token (for tenant control-plane APIs).
    IssueToken {
        id: String,
        /// TTL in seconds (default: server default).
        #[arg(long)]
        ttl_seconds: Option<u64>,
    },
    ToolSources {
        tenant_id: String,
        #[command(subcommand)]
        command: TenantToolSourcesCommand,
    },
    Secrets {
        tenant_id: String,
        #[command(subcommand)]
        command: TenantSecretsCommand,
    },
    ApiKeys {
        tenant_id: String,
        /// TTL used when issuing an ephemeral tenant token for this operation.
        #[arg(long)]
        ttl_seconds: Option<u64>,
        #[command(subcommand)]
        command: TenantApiKeysCommand,
    },
    OidcPrincipals {
        tenant_id: String,
        #[command(subcommand)]
        command: TenantOidcPrincipalsCommand,
    },
}

#[derive(Subcommand, Debug)]
enum TenantToolSourcesCommand {
    List,
    Get { source_id: String },
    Put(TenantToolSourcePutArgs),
    Delete { source_id: String },
}

#[derive(Args, Debug)]
struct TenantToolSourcePutArgs {
    source_id: String,
    /// JSON payload for the tool source (must include `type: http|openapi` and the config fields).
    #[arg(long, conflicts_with = "body_file")]
    body_json: Option<String>,
    /// Path to a JSON file containing the tool source payload.
    #[arg(long, conflicts_with = "body_json")]
    body_file: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
enum TenantSecretsCommand {
    List,
    Put(TenantSecretPutArgs),
    Delete { name: String },
}

#[derive(Args, Debug)]
struct TenantSecretPutArgs {
    name: String,
    /// Secret value (be careful: shell history).
    #[arg(long, conflicts_with_all = ["value_file", "value_stdin"])]
    value: Option<String>,
    /// Read secret value from file.
    #[arg(long, conflicts_with_all = ["value", "value_stdin"])]
    value_file: Option<PathBuf>,
    /// Read secret value from stdin (trimmed).
    #[arg(long, conflicts_with_all = ["value", "value_file"])]
    value_stdin: bool,
}

#[derive(Subcommand, Debug)]
enum TenantApiKeysCommand {
    List,
    Create(TenantApiKeyCreateArgs),
    Revoke { api_key_id: String },
}

#[derive(Args, Debug)]
struct TenantApiKeyCreateArgs {
    /// Display name/label (not secret).
    #[arg(long)]
    name: Option<String>,
    /// If set, key is scoped to this profile id (`UUIDv4`). If omitted, key is tenant-wide.
    #[arg(long)]
    profile_id: Option<String>,
}

#[derive(Subcommand, Debug)]
enum TenantOidcPrincipalsCommand {
    List,
    Put(TenantOidcPrincipalPutArgs),
    Delete(TenantOidcPrincipalDeleteArgs),
}

#[derive(Args, Debug)]
struct TenantOidcPrincipalPutArgs {
    subject: String,
    /// If set, principal is scoped to this profile id (`UUIDv4`). If omitted, principal is tenant-wide.
    #[arg(long)]
    profile_id: Option<String>,
    #[arg(long, default_value_t = true, action = ArgAction::Set)]
    enabled: bool,
}

#[derive(Args, Debug)]
struct TenantOidcPrincipalDeleteArgs {
    subject: String,
    /// If set, delete only the profile-scoped binding. If omitted, deletes all bindings for the subject.
    #[arg(long)]
    profile_id: Option<String>,
}

#[derive(Subcommand, Debug)]
enum UpstreamsCommand {
    List,
    Get { id: String },
    Put(UpstreamPutArgs),
    Delete { id: String },
}

#[derive(Args, Debug)]
struct UpstreamPutArgs {
    id: String,
    #[arg(long, default_value_t = true, action = ArgAction::Set)]
    enabled: bool,
    /// Upstream endpoint in the form "<id>=<url>" (repeatable).
    #[arg(long = "endpoint")]
    endpoints: Vec<String>,
}

#[derive(Subcommand, Debug)]
enum ProfilesCommand {
    List,
    Get {
        id: String,
    },
    Create(ProfileCreateArgs),
    Put(ProfilePutArgs),
    Delete {
        id: String,
    },
    /// Print the data-plane MCP URL for a profile id.
    Url {
        id: String,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum DataPlaneAuthModeArg {
    Disabled,
    ApiKeyInitializeOnly,
    ApiKeyEveryRequest,
    JwtEveryRequest,
}

impl From<DataPlaneAuthModeArg> for api::DataPlaneAuthMode {
    fn from(v: DataPlaneAuthModeArg) -> Self {
        match v {
            DataPlaneAuthModeArg::Disabled => api::DataPlaneAuthMode::Disabled,
            DataPlaneAuthModeArg::ApiKeyInitializeOnly => {
                api::DataPlaneAuthMode::ApiKeyInitializeOnly
            }
            DataPlaneAuthModeArg::ApiKeyEveryRequest => api::DataPlaneAuthMode::ApiKeyEveryRequest,
            DataPlaneAuthModeArg::JwtEveryRequest => api::DataPlaneAuthMode::JwtEveryRequest,
        }
    }
}

#[derive(Args, Debug, Clone)]
struct ProfileAuthArgs {
    /// Per-profile data-plane auth mode (Mode 3).
    #[arg(long)]
    data_plane_auth_mode: Option<DataPlaneAuthModeArg>,
    /// Whether to accept `x-api-key` as an alias for `Authorization: Bearer ...` (Mode 3).
    #[arg(long)]
    accept_x_api_key: Option<bool>,
}

#[derive(Args, Debug, Clone)]
struct ProfileLimitsArgs {
    /// Enable per-API-key fixed-window rate limits for `tools/call` (Mode 3).
    #[arg(long)]
    rate_limit_enabled: Option<bool>,
    /// Tool calls per minute when rate limiting is enabled.
    #[arg(long)]
    rate_limit_tool_calls_per_minute: Option<i64>,
    /// Enable per-API-key quota for `tools/call` (Mode 3).
    #[arg(long)]
    quota_enabled: Option<bool>,
    /// Total allowed tool calls (quota) when quota is enabled.
    #[arg(long)]
    quota_tool_calls: Option<i64>,
}

#[derive(Args, Debug)]
struct ProfileCreateArgs {
    #[arg(long)]
    tenant_id: String,
    /// Human-friendly profile name (unique per tenant, case-insensitive).
    #[arg(long)]
    name: String,
    /// Optional profile description.
    #[arg(long)]
    description: Option<String>,
    #[arg(long, default_value_t = true, action = ArgAction::Set)]
    enabled: bool,
    #[arg(long, default_value_t = true, action = ArgAction::Set)]
    allow_partial_upstreams: bool,
    #[arg(long = "upstream")]
    upstreams: Vec<String>,
    /// Local tool sources attached to this profile (repeatable).
    #[arg(long = "source")]
    sources: Vec<String>,
    /// Tool allowlist entry (repeatable).
    ///
    /// If omitted, no allowlist is configured and all tools are allowed.
    #[arg(long = "tool")]
    tools: Vec<String>,

    #[command(flatten)]
    data_plane_auth: ProfileAuthArgs,

    #[command(flatten)]
    data_plane_limits: ProfileLimitsArgs,

    /// Tool transforms JSON (matches `TransformPipeline` / `camelCase` keys).
    #[arg(long, conflicts_with = "transforms_file")]
    transforms_json: Option<String>,
    /// Tool transforms JSON file path.
    #[arg(long, conflicts_with = "transforms_json")]
    transforms_file: Option<PathBuf>,

    /// Optional per-profile default timeout override for `tools/call` (seconds).
    #[arg(long)]
    tool_call_timeout_secs: Option<u64>,

    /// Tool policies JSON (array of `{ tool, timeoutSecs?, retry? }` in camelCase).
    #[arg(long, conflicts_with = "tool_policies_file")]
    tool_policies_json: Option<String>,
    /// Tool policies JSON file path.
    #[arg(long, conflicts_with = "tool_policies_json")]
    tool_policies_file: Option<PathBuf>,

    /// MCP profile settings JSON (capabilities/notifications/namespacing). See `docs/gateway/MCP_SETTINGS.md`.
    #[arg(long, conflicts_with = "mcp_file")]
    mcp_json: Option<String>,
    /// Path to a JSON file containing MCP profile settings.
    #[arg(long, conflicts_with = "mcp_json")]
    mcp_file: Option<PathBuf>,
}

#[derive(Args, Debug)]
struct ProfilePutArgs {
    #[arg(long)]
    id: String,
    #[arg(long)]
    tenant_id: String,
    /// Human-friendly profile name (unique per tenant, case-insensitive).
    #[arg(long)]
    name: String,
    /// Optional profile description.
    #[arg(long)]
    description: Option<String>,
    #[arg(long, default_value_t = true, action = ArgAction::Set)]
    enabled: bool,
    #[arg(long, default_value_t = true, action = ArgAction::Set)]
    allow_partial_upstreams: bool,
    #[arg(long = "upstream")]
    upstreams: Vec<String>,
    /// Local tool sources attached to this profile (repeatable).
    #[arg(long = "source")]
    sources: Vec<String>,
    /// Tool allowlist entry (repeatable).
    ///
    /// If omitted, no allowlist is configured and all tools are allowed.
    #[arg(long = "tool")]
    tools: Vec<String>,

    #[command(flatten)]
    data_plane_auth: ProfileAuthArgs,

    #[command(flatten)]
    data_plane_limits: ProfileLimitsArgs,

    /// Tool transforms JSON (matches `TransformPipeline` / `camelCase` keys).
    #[arg(long, conflicts_with = "transforms_file")]
    transforms_json: Option<String>,
    /// Tool transforms JSON file path.
    #[arg(long, conflicts_with = "transforms_json")]
    transforms_file: Option<PathBuf>,

    /// Optional per-profile default timeout override for `tools/call` (seconds).
    #[arg(long)]
    tool_call_timeout_secs: Option<u64>,

    /// Tool policies JSON (array of `{ tool, timeoutSecs?, retry? }` in camelCase).
    #[arg(long, conflicts_with = "tool_policies_file")]
    tool_policies_json: Option<String>,
    /// Tool policies JSON file path.
    #[arg(long, conflicts_with = "tool_policies_json")]
    tool_policies_file: Option<PathBuf>,

    /// MCP profile settings JSON (capabilities/notifications/namespacing). See `docs/gateway/MCP_SETTINGS.md`.
    #[arg(long, conflicts_with = "mcp_file")]
    mcp_json: Option<String>,
    /// Path to a JSON file containing MCP profile settings.
    #[arg(long, conflicts_with = "mcp_json")]
    mcp_file: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
enum McpJsonCommand {
    /// Print a full `mcp.json` (mcpServers) file for a Gateway profile.
    ServersFile(McpJsonServersFileArgs),
    /// Print only a single server entry object (for adding under `mcpServers.<name>`).
    ServerEntry(McpJsonServerEntryArgs),
}

#[derive(Args, Debug)]
struct McpJsonServersFileArgs {
    #[arg(long)]
    profile_id: String,
    /// `mcpServers` key. Defaults to `unrelated-gateway-<profile_id>`.
    #[arg(long)]
    name: Option<String>,
}

#[derive(Args, Debug)]
struct McpJsonServerEntryArgs {
    #[arg(long)]
    profile_id: String,
}

#[tokio::main]
async fn main() -> ExitCode {
    match run(Cli::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            print_user_friendly_error(&err);
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> anyhow::Result<()> {
    let Cli {
        config,
        admin_base: admin_base_flag,
        data_base: data_base_flag,
        token,
        token_file,
        token_stdin,
        json,
        command,
    } = cli;

    let config_path = match config {
        Some(p) => p,
        None => config::default_config_path()?,
    };
    let mut cfg = config::load_config(&config_path)?;

    // Resolve admin_base / data_base (flags > env > config file > default).
    let admin_base = admin_base_flag
        .or_else(|| cfg.admin_base.clone())
        .unwrap_or_else(|| DEFAULT_ADMIN_BASE.to_string());
    let data_base = data_base_flag
        .or_else(|| cfg.data_base.clone())
        .unwrap_or_else(|| DEFAULT_DATA_BASE.to_string());

    match command {
        Command::Config { command } => handle_config_command(
            command,
            json,
            &config_path,
            &mut cfg,
            &admin_base,
            &data_base,
            token_stdin,
        ),
        Command::Tenants { command } => {
            let token =
                resolve_token_parts(token.as_ref(), token_file.as_ref(), token_stdin, &cfg)?;
            let api = api_client(&admin_base, token)?;
            handle_tenants(command, api, json).await
        }
        Command::Upstreams { command } => {
            let token =
                resolve_token_parts(token.as_ref(), token_file.as_ref(), token_stdin, &cfg)?;
            let api = api_client(&admin_base, token)?;
            handle_upstreams(command, api, json).await
        }
        Command::Profiles { command } => {
            let token =
                resolve_token_parts(token.as_ref(), token_file.as_ref(), token_stdin, &cfg)?;
            let api = api_client(&admin_base, token)?;
            handle_profiles(*command, api, json, &data_base).await
        }
        Command::McpJson { command } => handle_mcp_json(command, &data_base),
    }
}

fn handle_config_command(
    command: ConfigCommand,
    json: bool,
    config_path: &std::path::Path,
    cfg: &mut config::CliConfig,
    admin_base: &str,
    data_base: &str,
    token_stdin: bool,
) -> anyhow::Result<()> {
    match command {
        ConfigCommand::Show => {
            let effective = config::CliConfig {
                admin_base: Some(admin_base.to_string()),
                data_base: Some(data_base.to_string()),
                admin_token: cfg.admin_token.clone(),
            };

            if json {
                println!("{}", serde_json::to_string_pretty(&effective)?);
            } else {
                println!("{}", "unrelated-gateway-admin config".bold());
                println!("  adminBase: {}", effective.admin_base.unwrap_or_default());
                println!("  dataBase:  {}", effective.data_base.unwrap_or_default());
                println!(
                    "  token:     {}",
                    match effective.admin_token {
                        None => "(not set)".dimmed().to_string(),
                        Some(t) => redact_token(&t),
                    }
                );
                println!();
                println!("Config file: {}", config_path.display());
            }
        }
        ConfigCommand::Set(args) => {
            if let Some(v) = args.admin_base {
                cfg.admin_base = Some(v);
            }
            if let Some(v) = args.data_base {
                cfg.data_base = Some(v);
            }
            if let Some(t) = args.token {
                cfg.admin_token = Some(t);
            }
            if let Some(p) = args.token_file {
                let t = std::fs::read_to_string(&p)
                    .with_context(|| format!("read token file {}", p.display()))?;
                cfg.admin_token = Some(t.trim().to_string());
            }
            if args.token_stdin || token_stdin {
                let t = read_stdin_trimmed()?;
                cfg.admin_token = Some(t);
            }

            config::save_config(config_path, cfg)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&cfg)?);
            } else {
                println!("{}", "Saved.".green());
                println!("Config file: {}", config_path.display());
            }
        }
    }

    Ok(())
}

fn api_client(admin_base: &str, token: String) -> anyhow::Result<api::ApiClient> {
    let admin_base =
        Url::parse(admin_base).with_context(|| format!("invalid admin base URL '{admin_base}'"))?;
    Ok(api::ApiClient::new(admin_base, token))
}

fn print_user_friendly_error(err: &anyhow::Error) {
    // Default headline is the top context (what we were doing).
    eprintln!("{} {}", "error:".red().bold(), err.to_string().bold());

    // If this looks like an HTTP failure, add actionable hints (common CLI UX).
    if let Some(re) = find_reqwest_error(err) {
        if re.is_connect() {
            if let Some(url) = re.url() {
                eprintln!();
                eprintln!("{} {}", "target:".dimmed(), url);
            }
            eprintln!();
            eprintln!("{}", "Hints:".bold());
            eprintln!(
                "  - Make sure the Gateway is running and reachable from this machine/network."
            );
            eprintln!(
                "  - Verify the admin base URL (use `--admin-base` or `UNRELATED_GATEWAY_ADMIN_BASE`)."
            );
            eprintln!(
                "  - Confirm the host/port is correct and reachable (firewall, routing, port-forward, ingress, etc.)."
            );
            eprintln!("  - Try a basic health check, e.g.: `curl -sf <admin_base>/health`.");
            eprintln!(
                "  - If the Gateway is running but still unreachable, check the Gateway service logs."
            );
            return;
        }

        if re.is_timeout() {
            if let Some(url) = re.url() {
                eprintln!();
                eprintln!("{} {}", "target:".dimmed(), url);
            }
            eprintln!();
            eprintln!("{}", "Hints:".bold());
            eprintln!("  - The Gateway might be slow to start; wait a few seconds and retry.");
            eprintln!(
                "  - Verify the admin base URL (use `--admin-base` or `UNRELATED_GATEWAY_ADMIN_BASE`)."
            );
            eprintln!(
                "  - Check for network timeouts (proxy, VPN, firewall) between you and the Gateway."
            );
            eprintln!("  - Check the Gateway service logs for slow startup or errors.");
            return;
        }

        if let Some(status) = re.status() {
            use reqwest::StatusCode;
            match status {
                StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
                    eprintln!();
                    eprintln!("{}", "Hints:".bold());
                    eprintln!(
                        "  - Your admin token is missing/invalid (use `--token`, `--token-file`, or `config set`)."
                    );
                    eprintln!(
                        "  - Ensure the token matches the Gateway's configured admin token (or auth provider)."
                    );
                    return;
                }
                StatusCode::NOT_FOUND => {
                    eprintln!();
                    eprintln!("{}", "Hints:".bold());
                    eprintln!(
                        "  - This Gateway might not expose the admin API at this URL. Double-check `--admin-base`."
                    );
                    eprintln!(
                        "  - If you meant to talk to the data plane, use {DEFAULT_DATA_BASE} (not {DEFAULT_ADMIN_BASE})."
                    );
                    return;
                }
                _ if status.is_server_error() => {
                    eprintln!();
                    eprintln!("{}", "Hints:".bold());
                    eprintln!(
                        "  - The Gateway returned {status}. Check the Gateway service logs for details."
                    );
                    return;
                }
                _ => {}
            }
        }
    }

    // Fallback: print the cause chain (still short, but gives enough context).
    let mut chain = err.chain();
    let _ = chain.next(); // skip headline (already printed)
    if chain.next().is_some() {
        eprintln!();
        eprintln!("{}", "Details:".dimmed().bold());
        for (i, cause) in err.chain().enumerate() {
            eprintln!("  {i}: {cause}");
        }
    }
}

fn find_reqwest_error(err: &anyhow::Error) -> Option<&reqwest::Error> {
    err.chain().find_map(|e| e.downcast_ref::<reqwest::Error>())
}

fn resolve_token_parts(
    token: Option<&String>,
    token_file: Option<&PathBuf>,
    token_stdin: bool,
    cfg: &config::CliConfig,
) -> anyhow::Result<String> {
    if let Some(t) = token {
        return Ok(t.clone());
    }
    if let Some(p) = token_file {
        let t = std::fs::read_to_string(p)
            .with_context(|| format!("read token file {}", p.display()))?;
        return Ok(t.trim().to_string());
    }
    if token_stdin {
        return read_stdin_trimmed();
    }
    if let Some(t) = &cfg.admin_token {
        return Ok(t.clone());
    }
    anyhow::bail!(
        "admin token not configured (use --token/--token-file/--token-stdin or `config set`)"
    )
}

fn resolve_value_parts(
    value: Option<&String>,
    value_file: Option<&PathBuf>,
    value_stdin: bool,
) -> anyhow::Result<String> {
    if let Some(v) = value {
        return Ok(v.clone());
    }
    if let Some(p) = value_file {
        let v = std::fs::read_to_string(p)
            .with_context(|| format!("read value file {}", p.display()))?;
        let v = v.trim().to_string();
        if v.is_empty() {
            anyhow::bail!("value from file is empty");
        }
        return Ok(v);
    }
    if value_stdin {
        return read_stdin_trimmed();
    }
    anyhow::bail!("value not provided (use --value/--value-file/--value-stdin)")
}

fn read_stdin_trimmed() -> anyhow::Result<String> {
    use std::io::Read as _;
    let mut buf = String::new();
    std::io::stdin()
        .read_to_string(&mut buf)
        .context("read value from stdin")?;
    let t = buf.trim().to_string();
    if t.is_empty() {
        anyhow::bail!("value from stdin is empty");
    }
    Ok(t)
}

fn redact_token(t: &str) -> String {
    if t.len() <= 8 {
        return "***".to_string();
    }
    let start = &t[..4];
    let end = &t[t.len() - 4..];
    format!("{start}…{end}")
}

async fn handle_tenants(
    cmd: TenantsCommand,
    api: api::ApiClient,
    json: bool,
) -> anyhow::Result<()> {
    match cmd {
        TenantsCommand::List => handle_tenants_list(&api, json).await,
        TenantsCommand::Get { id } => handle_tenants_get(&api, json, &id).await,
        TenantsCommand::Put { id, enabled } => handle_tenants_put(&api, json, &id, enabled).await,
        TenantsCommand::Delete { id } => handle_tenants_delete(&api, json, &id).await,
        TenantsCommand::IssueToken { id, ttl_seconds } => {
            handle_tenants_issue_token(&api, json, &id, ttl_seconds).await
        }
        TenantsCommand::ToolSources { tenant_id, command } => {
            handle_tenants_tool_sources(&api, json, &tenant_id, command).await
        }
        TenantsCommand::Secrets { tenant_id, command } => {
            handle_tenants_secrets(&api, json, &tenant_id, command).await
        }
        TenantsCommand::ApiKeys {
            tenant_id,
            ttl_seconds,
            command,
        } => handle_tenants_api_keys(&api, json, &tenant_id, ttl_seconds, command).await,
        TenantsCommand::OidcPrincipals { tenant_id, command } => {
            handle_tenants_oidc_principals(&api, json, &tenant_id, command).await
        }
    }
}

async fn handle_tenants_oidc_principals(
    api: &api::ApiClient,
    json: bool,
    tenant_id: &str,
    command: TenantOidcPrincipalsCommand,
) -> anyhow::Result<()> {
    match command {
        TenantOidcPrincipalsCommand::List => {
            let principals = api.list_oidc_principals(tenant_id).await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&principals)?);
                return Ok(());
            }
            if principals.is_empty() {
                println!("{}", "(no oidc principals)".dimmed());
                return Ok(());
            }
            println!("{}", "oidc principals".bold());
            for p in principals {
                let scope = p.profile_id.as_deref().unwrap_or("(tenant-wide)");
                let status = if p.enabled {
                    "enabled".green().to_string()
                } else {
                    "disabled".red().to_string()
                };
                println!("  {}  {}  {}", p.subject, scope.dimmed(), status);
            }
        }
        TenantOidcPrincipalsCommand::Put(args) => {
            api.put_oidc_principal(
                tenant_id,
                &args.subject,
                args.profile_id.as_deref(),
                args.enabled,
            )
            .await?;
            if json {
                println!("{}", serde_json::json!({"ok": true}));
            } else {
                println!("{}", "ok".green());
            }
        }
        TenantOidcPrincipalsCommand::Delete(args) => {
            api.delete_oidc_principal(tenant_id, &args.subject, args.profile_id.as_deref())
                .await?;
            if json {
                println!("{}", serde_json::json!({"ok": true}));
            } else {
                println!("{}", "ok".green());
            }
        }
    }
    Ok(())
}

async fn handle_tenants_list(api: &api::ApiClient, json: bool) -> anyhow::Result<()> {
    let tenants = api.list_tenants().await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&tenants)?);
        return Ok(());
    }
    if tenants.is_empty() {
        println!("{}", "(no tenants)".dimmed());
        return Ok(());
    }
    println!("{}", "tenants".bold());
    for t in tenants {
        let status = if t.enabled {
            "enabled".green().to_string()
        } else {
            "disabled".red().to_string()
        };
        println!("  {}  {}", t.id, status);
    }
    Ok(())
}

async fn handle_tenants_get(api: &api::ApiClient, json: bool, id: &str) -> anyhow::Result<()> {
    let t = api.get_tenant(id).await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&t)?);
        return Ok(());
    }
    println!("{}", "tenant".bold());
    println!("  id: {}", t.id);
    println!("  enabled: {}", t.enabled);
    Ok(())
}

async fn handle_tenants_put(
    api: &api::ApiClient,
    json: bool,
    id: &str,
    enabled: bool,
) -> anyhow::Result<()> {
    api.put_tenant(id, enabled).await?;
    if json {
        println!("{}", serde_json::json!({"ok": true}));
    } else {
        println!("{}", "ok".green());
    }
    Ok(())
}

async fn handle_tenants_delete(api: &api::ApiClient, json: bool, id: &str) -> anyhow::Result<()> {
    api.delete_tenant(id).await?;
    if json {
        println!("{}", serde_json::json!({"ok": true}));
    } else {
        println!("{}", "ok".green());
    }
    Ok(())
}

async fn handle_tenants_issue_token(
    api: &api::ApiClient,
    json: bool,
    id: &str,
    ttl_seconds: Option<u64>,
) -> anyhow::Result<()> {
    let resp = api.issue_tenant_token(id, ttl_seconds).await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&resp)?);
        return Ok(());
    }
    println!("{}", "tenant token".bold());
    println!("  tenantId: {}", resp.tenant_id);
    println!("  expUnixSecs: {}", resp.exp_unix_secs);
    println!("  token: {}", resp.token);
    Ok(())
}

async fn handle_tenants_tool_sources(
    api: &api::ApiClient,
    json: bool,
    tenant_id: &str,
    command: TenantToolSourcesCommand,
) -> anyhow::Result<()> {
    match command {
        TenantToolSourcesCommand::List => {
            let sources = api.list_tool_sources(tenant_id).await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&sources)?);
                return Ok(());
            }
            if sources.is_empty() {
                println!("{}", "(no tool sources)".dimmed());
                return Ok(());
            }
            println!("{}", "tool sources".bold());
            for s in sources {
                let status = if s.enabled {
                    "enabled".green().to_string()
                } else {
                    "disabled".red().to_string()
                };
                println!("  {}  {}  {}", s.id, s.tool_type.dimmed(), status);
            }
        }
        TenantToolSourcesCommand::Get { source_id } => {
            let s = api.get_tool_source(tenant_id, &source_id).await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&s)?);
            } else {
                println!("{}", "tool source".bold());
                println!("  id: {}", s.id);
                println!("  type: {}", s.tool_type);
                println!("  enabled: {}", s.enabled);
            }
        }
        TenantToolSourcesCommand::Put(args) => {
            let body = read_json_body(args.body_json.as_deref(), args.body_file.as_ref())
                .context("read tool source body json")?;
            api.put_tool_source(tenant_id, &args.source_id, body)
                .await?;
            if json {
                println!("{}", serde_json::json!({"ok": true}));
            } else {
                println!("{}", "ok".green());
            }
        }
        TenantToolSourcesCommand::Delete { source_id } => {
            api.delete_tool_source(tenant_id, &source_id).await?;
            if json {
                println!("{}", serde_json::json!({"ok": true}));
            } else {
                println!("{}", "ok".green());
            }
        }
    }
    Ok(())
}

async fn handle_tenants_secrets(
    api: &api::ApiClient,
    json: bool,
    tenant_id: &str,
    command: TenantSecretsCommand,
) -> anyhow::Result<()> {
    match command {
        TenantSecretsCommand::List => {
            let secrets = api.list_secrets(tenant_id).await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&secrets)?);
                return Ok(());
            }
            if secrets.is_empty() {
                println!("{}", "(no secrets)".dimmed());
                return Ok(());
            }
            println!("{}", "secrets".bold());
            for s in secrets {
                println!("  {}", s.name);
            }
        }
        TenantSecretsCommand::Put(args) => {
            let value = resolve_value_parts(
                args.value.as_ref(),
                args.value_file.as_ref(),
                args.value_stdin,
            )?;
            api.put_secret(tenant_id, &args.name, &value).await?;
            if json {
                println!("{}", serde_json::json!({"ok": true}));
            } else {
                println!("{}", "ok".green());
            }
        }
        TenantSecretsCommand::Delete { name } => {
            api.delete_secret(tenant_id, &name).await?;
            if json {
                println!("{}", serde_json::json!({"ok": true}));
            } else {
                println!("{}", "ok".green());
            }
        }
    }
    Ok(())
}

async fn handle_tenants_api_keys(
    api: &api::ApiClient,
    json: bool,
    tenant_id: &str,
    ttl_seconds: Option<u64>,
    command: TenantApiKeysCommand,
) -> anyhow::Result<()> {
    let token = api.issue_tenant_token(tenant_id, ttl_seconds).await?.token;
    let tenant_api = api.clone_with_token(token);

    match command {
        TenantApiKeysCommand::List => {
            let keys = tenant_api.list_api_keys().await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&keys)?);
                return Ok(());
            }
            if keys.is_empty() {
                println!("{}", "(no api keys)".dimmed());
                return Ok(());
            }
            println!("{}", "api keys".bold());
            for k in keys {
                let scope = k.profile_id.as_deref().unwrap_or("(tenant-wide)");
                let revoked = if k.revoked_at_unix.is_some() {
                    "revoked".red().to_string()
                } else {
                    "active".green().to_string()
                };
                println!("  {}  {}  {}", k.id, scope.dimmed(), revoked);
                println!("    name: {}", k.name.dimmed());
                println!("    prefix: {}", k.prefix.dimmed());
                println!(
                    "    toolCallsAttempted: {}",
                    k.total_tool_calls_attempted.to_string().dimmed()
                );
            }
        }
        TenantApiKeysCommand::Create(args) => {
            let resp = tenant_api
                .create_api_key(args.name.as_deref(), args.profile_id.as_deref())
                .await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&resp)?);
                return Ok(());
            }
            println!("{}", "api key created".green());
            println!("  id: {}", resp.id);
            println!("  prefix: {}", resp.prefix);
            println!(
                "  profileId: {}",
                resp.profile_id.as_deref().unwrap_or("(tenant-wide)")
            );
            println!();
            println!("{}", "Secret (displayed once):".bold());
            println!("{}", resp.secret);
        }
        TenantApiKeysCommand::Revoke { api_key_id } => {
            tenant_api.revoke_api_key(&api_key_id).await?;
            if json {
                println!("{}", serde_json::json!({"ok": true}));
            } else {
                println!("{}", "ok".green());
            }
        }
    }
    Ok(())
}

async fn handle_upstreams(
    cmd: UpstreamsCommand,
    api: api::ApiClient,
    json: bool,
) -> anyhow::Result<()> {
    match cmd {
        UpstreamsCommand::List => {
            let upstreams = api.list_upstreams().await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&upstreams)?);
            } else if upstreams.is_empty() {
                println!("{}", "(no upstreams)".dimmed());
            } else {
                println!("{}", "upstreams".bold());
                for u in upstreams {
                    let status = if u.enabled {
                        "enabled".green().to_string()
                    } else {
                        "disabled".red().to_string()
                    };
                    println!("  {}  {}", u.id, status);
                    for ep in u.endpoints {
                        let ep_status = if ep.enabled {
                            "enabled".green().to_string()
                        } else {
                            "disabled".red().to_string()
                        };
                        println!("    - {}  {}  {}", ep.id, ep.url.dimmed(), ep_status);
                    }
                }
            }
        }
        UpstreamsCommand::Get { id } => {
            let u = api.get_upstream(&id).await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&u)?);
            } else {
                println!("{}", "upstream".bold());
                println!("  id: {}", u.id);
                println!("  enabled: {}", u.enabled);
                println!("  endpoints:");
                for ep in u.endpoints {
                    println!("    - id: {}", ep.id);
                    println!("      url: {}", ep.url);
                    println!("      enabled: {}", ep.enabled);
                }
            }
        }
        UpstreamsCommand::Put(args) => {
            let endpoints = args
                .endpoints
                .into_iter()
                .map(|s| parse_endpoint_kv(&s))
                .collect::<anyhow::Result<Vec<_>>>()?;
            api.put_upstream(&args.id, args.enabled, endpoints).await?;
            if json {
                println!("{}", serde_json::json!({"ok": true}));
            } else {
                println!("{}", "ok".green());
            }
        }
        UpstreamsCommand::Delete { id } => {
            api.delete_upstream(&id).await?;
            if json {
                println!("{}", serde_json::json!({"ok": true}));
            } else {
                println!("{}", "ok".green());
            }
        }
    }
    Ok(())
}

async fn handle_profiles(
    cmd: ProfilesCommand,
    api: api::ApiClient,
    json: bool,
    data_base: &str,
) -> anyhow::Result<()> {
    match cmd {
        ProfilesCommand::List => handle_profiles_list(api, json).await,
        ProfilesCommand::Get { id } => handle_profiles_get(api, json, data_base, &id).await,
        ProfilesCommand::Create(args) => handle_profiles_create(api, json, data_base, args).await,
        ProfilesCommand::Put(args) => handle_profiles_put(api, json, data_base, args).await,
        ProfilesCommand::Delete { id } => handle_profiles_delete(api, json, &id).await,
        ProfilesCommand::Url { id } => {
            let url = profile_url(data_base, &id)?;
            println!("{url}");
            Ok(())
        }
    }
}

async fn handle_profiles_list(api: api::ApiClient, json: bool) -> anyhow::Result<()> {
    let profiles = api.list_profiles().await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&profiles)?);
        return Ok(());
    }
    if profiles.is_empty() {
        println!("{}", "(no profiles)".dimmed());
        return Ok(());
    }

    println!("{}", "profiles".bold());
    for p in profiles {
        let status = if p.enabled {
            "enabled".green().to_string()
        } else {
            "disabled".red().to_string()
        };
        println!("  {}  {}", p.id, status);
        println!("    tenant: {}", p.tenant_id.dimmed());
        println!("    upstreams: {}", p.upstreams.join(", ").dimmed());
        println!("    sources: {}", p.sources.join(", ").dimmed());
        println!(
            "    transforms: {}",
            if transforms_is_set(&p.transforms) {
                "set".dimmed().to_string()
            } else {
                "none".dimmed().to_string()
            }
        );
        println!(
            "    mcp: {}",
            if mcp_is_default(&p.mcp) {
                "default".dimmed().to_string()
            } else {
                "custom".dimmed().to_string()
            }
        );
        println!("    tools: {}", p.tools.join(", ").dimmed());
        println!(
            "    dataPlaneAuth: {:?}  acceptXApiKey={}",
            p.data_plane_auth.mode, p.data_plane_auth.accept_x_api_key
        );
        println!(
            "    dataPlaneLimits: rateLimit={} quota={}",
            if p.data_plane_limits.rate_limit_enabled {
                p.data_plane_limits
                    .rate_limit_tool_calls_per_minute
                    .map_or_else(|| "on(?)".to_string(), |v| format!("on({v}/min)"))
            } else {
                "off".to_string()
            },
            if p.data_plane_limits.quota_enabled {
                p.data_plane_limits
                    .quota_tool_calls
                    .map_or_else(|| "on(?)".to_string(), |v| format!("on({v})"))
            } else {
                "off".to_string()
            }
        );
    }
    Ok(())
}

async fn handle_profiles_get(
    api: api::ApiClient,
    json: bool,
    data_base: &str,
    id: &str,
) -> anyhow::Result<()> {
    let p = api.get_profile(id).await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&p)?);
        return Ok(());
    }

    println!("{}", "profile".bold());
    println!("  id: {}", p.id);
    println!("  tenantId: {}", p.tenant_id);
    println!("  enabled: {}", p.enabled);
    println!("  allowPartialUpstreams: {}", p.allow_partial_upstreams);
    println!("  upstreams: {}", p.upstreams.join(", "));
    println!("  sources: {}", p.sources.join(", "));
    println!(
        "  transforms: {}",
        if transforms_is_set(&p.transforms) {
            "set"
        } else {
            "none"
        }
    );
    println!(
        "  mcp: {}",
        if mcp_is_default(&p.mcp) {
            "default"
        } else {
            "custom"
        }
    );
    println!("  tools: {}", p.tools.join(", "));
    println!(
        "  dataPlaneAuth: {:?}  acceptXApiKey={}",
        p.data_plane_auth.mode, p.data_plane_auth.accept_x_api_key
    );
    println!(
        "  dataPlaneLimits: rateLimitEnabled={} rateLimitToolCallsPerMinute={:?} quotaEnabled={} quotaToolCalls={:?}",
        p.data_plane_limits.rate_limit_enabled,
        p.data_plane_limits.rate_limit_tool_calls_per_minute,
        p.data_plane_limits.quota_enabled,
        p.data_plane_limits.quota_tool_calls
    );
    println!("  url: {}", profile_url(data_base, &p.id)?);
    Ok(())
}

async fn handle_profiles_create(
    api: api::ApiClient,
    json: bool,
    data_base: &str,
    args: ProfileCreateArgs,
) -> anyhow::Result<()> {
    let tools = args.tools;
    let transforms = parse_transforms(
        args.transforms_json.as_deref(),
        args.transforms_file.as_ref(),
    )
    .context("parse transforms")?;
    let tool_policies = parse_tool_policies(
        args.tool_policies_json.as_deref(),
        args.tool_policies_file.as_ref(),
    )
    .context("parse tool policies")?;
    let mcp = parse_mcp_settings(args.mcp_json.as_deref(), args.mcp_file.as_ref())
        .context("parse mcp settings")?;

    let data_plane_auth = build_data_plane_auth_for_create(&args.data_plane_auth);
    let data_plane_limits = build_data_plane_limits_for_create(&args.data_plane_limits)?;

    let resp = api
        .create_profile(api::ProfileUpsert {
            tenant_id: args.tenant_id,
            name: args.name,
            description: args.description,
            enabled: args.enabled,
            allow_partial_upstreams: args.allow_partial_upstreams,
            upstreams: args.upstreams,
            sources: args.sources,
            transforms,
            tools,
            data_plane_auth,
            data_plane_limits,
            tool_call_timeout_secs: args.tool_call_timeout_secs,
            tool_policies,
            mcp,
        })
        .await?;

    if json {
        println!("{}", serde_json::to_string_pretty(&resp)?);
        return Ok(());
    }

    println!("{}", "profile created".green());
    println!("  id: {}", resp.id);
    println!("  url: {}", profile_url(data_base, &resp.id)?);
    Ok(())
}

async fn handle_profiles_put(
    api: api::ApiClient,
    json: bool,
    data_base: &str,
    args: ProfilePutArgs,
) -> anyhow::Result<()> {
    let settings_overridden = profile_settings_are_overridden(&args);
    let tools = args.tools;
    let transforms = parse_transforms(
        args.transforms_json.as_deref(),
        args.transforms_file.as_ref(),
    )
    .context("parse transforms")?;
    let tool_policies = parse_tool_policies(
        args.tool_policies_json.as_deref(),
        args.tool_policies_file.as_ref(),
    )
    .context("parse tool policies")?;
    let mcp = parse_mcp_settings(args.mcp_json.as_deref(), args.mcp_file.as_ref())
        .context("parse mcp settings")?;

    let existing = if settings_overridden {
        Some(api.get_profile(&args.id).await?)
    } else {
        None
    };
    let data_plane_auth = build_data_plane_auth_for_put(existing.as_ref(), &args.data_plane_auth)?;
    let data_plane_limits =
        build_data_plane_limits_for_put(existing.as_ref(), &args.data_plane_limits)?;

    let resp = api
        .put_profile(
            &args.id,
            api::ProfileUpsert {
                tenant_id: args.tenant_id,
                name: args.name,
                description: args.description,
                enabled: args.enabled,
                allow_partial_upstreams: args.allow_partial_upstreams,
                upstreams: args.upstreams,
                sources: args.sources,
                transforms,
                tools,
                data_plane_auth,
                data_plane_limits,
                tool_call_timeout_secs: args.tool_call_timeout_secs,
                tool_policies,
                mcp,
            },
        )
        .await?;

    if json {
        println!("{}", serde_json::to_string_pretty(&resp)?);
        return Ok(());
    }

    println!("{}", "profile saved".green());
    println!("  id: {}", resp.id);
    println!("  url: {}", profile_url(data_base, &resp.id)?);
    Ok(())
}

async fn handle_profiles_delete(api: api::ApiClient, json: bool, id: &str) -> anyhow::Result<()> {
    api.delete_profile(id).await?;
    if json {
        println!("{}", serde_json::json!({"ok": true}));
    } else {
        println!("{}", "ok".green());
    }
    Ok(())
}

fn transforms_is_set(t: &TransformPipeline) -> bool {
    !t.tool_overrides.is_empty()
}

fn mcp_is_default(m: &api::McpProfileSettings) -> bool {
    // Compare JSON values to avoid needing Eq for all nested types.
    let a = serde_json::to_value(m).ok();
    let b = serde_json::to_value(api::McpProfileSettings::default()).ok();
    a == b
}

fn parse_tool_policies(
    json: Option<&str>,
    file: Option<&PathBuf>,
) -> anyhow::Result<Option<Vec<api::ToolPolicy>>> {
    if let Some(s) = json {
        let v: Vec<api::ToolPolicy> = serde_json::from_str(s).context("parse toolPolicies JSON")?;
        return Ok(Some(v));
    }
    if let Some(path) = file {
        let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
        let v: Vec<api::ToolPolicy> =
            serde_json::from_slice(&bytes).context("parse toolPolicies JSON file")?;
        return Ok(Some(v));
    }
    Ok(None)
}

fn parse_mcp_settings(
    json: Option<&str>,
    file: Option<&PathBuf>,
) -> anyhow::Result<Option<api::McpProfileSettings>> {
    if let Some(s) = json {
        let v: api::McpProfileSettings = serde_json::from_str(s).context("parse mcp JSON")?;
        return Ok(Some(v));
    }
    if let Some(path) = file {
        let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
        let v: api::McpProfileSettings =
            serde_json::from_slice(&bytes).context("parse mcp JSON file")?;
        return Ok(Some(v));
    }
    Ok(None)
}

fn handle_mcp_json(cmd: McpJsonCommand, data_base: &str) -> anyhow::Result<()> {
    match cmd {
        McpJsonCommand::ServersFile(args) => {
            let name = args
                .name
                .unwrap_or_else(|| format!("unrelated-gateway-{}", args.profile_id));
            let url = profile_url(data_base, &args.profile_id)?;

            let payload = serde_json::json!({
                "mcpServers": {
                    name: {
                        "type": "streamable-http",
                        "url": url,
                        "note": "Unrelated MCP Gateway profile (streamable HTTP)"
                    }
                }
            });
            println!("{}", serde_json::to_string_pretty(&payload)?);
        }
        McpJsonCommand::ServerEntry(args) => {
            let url = profile_url(data_base, &args.profile_id)?;
            let payload = serde_json::json!({
                "type": "streamable-http",
                "url": url,
                "note": "Unrelated MCP Gateway profile (streamable HTTP)"
            });
            println!("{}", serde_json::to_string_pretty(&payload)?);
        }
    }
    Ok(())
}

fn profile_url(data_base: &str, profile_id: &str) -> anyhow::Result<String> {
    let base = Url::parse(data_base).context("parse data base url")?;
    let url = base
        .join(&format!("/{profile_id}/mcp"))
        .context("build profile url")?;
    Ok(url.to_string())
}

fn parse_endpoint_kv(s: &str) -> anyhow::Result<api::PutEndpoint> {
    let (id, url) = s
        .split_once('=')
        .ok_or_else(|| anyhow::anyhow!("invalid endpoint '{s}': expected '<id>=<url>'"))?;
    Ok(api::PutEndpoint {
        id: id.to_string(),
        url: url.to_string(),
    })
}

fn parse_transforms(
    transforms_json: Option<&str>,
    transforms_file: Option<&PathBuf>,
) -> anyhow::Result<TransformPipeline> {
    if let Some(s) = transforms_json {
        let t: TransformPipeline = serde_json::from_str(s).context("parse transforms json")?;
        return Ok(t);
    }
    if let Some(p) = transforms_file {
        let content = std::fs::read_to_string(p)
            .with_context(|| format!("read transforms file {}", p.display()))?;
        let t: TransformPipeline =
            serde_json::from_str(&content).context("parse transforms file json")?;
        return Ok(t);
    }
    Ok(TransformPipeline::default())
}

fn read_json_body(
    body_json: Option<&str>,
    body_file: Option<&PathBuf>,
) -> anyhow::Result<serde_json::Value> {
    if let Some(s) = body_json {
        let v: serde_json::Value = serde_json::from_str(s).context("parse body json")?;
        return Ok(v);
    }
    if let Some(p) = body_file {
        let content = std::fs::read_to_string(p)
            .with_context(|| format!("read json file {}", p.display()))?;
        let v: serde_json::Value =
            serde_json::from_str(&content).context("parse body json file")?;
        return Ok(v);
    }
    anyhow::bail!("missing body (use --body-json or --body-file)")
}

fn profile_settings_are_overridden(args: &ProfilePutArgs) -> bool {
    args.data_plane_auth.data_plane_auth_mode.is_some()
        || args.data_plane_auth.accept_x_api_key.is_some()
        || args.data_plane_limits.rate_limit_enabled.is_some()
        || args
            .data_plane_limits
            .rate_limit_tool_calls_per_minute
            .is_some()
        || args.data_plane_limits.quota_enabled.is_some()
        || args.data_plane_limits.quota_tool_calls.is_some()
}

fn build_data_plane_auth_for_create(args: &ProfileAuthArgs) -> Option<api::DataPlaneAuthSettings> {
    if args.data_plane_auth_mode.is_none() && args.accept_x_api_key.is_none() {
        return None;
    }
    Some(api::DataPlaneAuthSettings {
        mode: args
            .data_plane_auth_mode
            .unwrap_or(DataPlaneAuthModeArg::ApiKeyInitializeOnly)
            .into(),
        accept_x_api_key: args.accept_x_api_key.unwrap_or(false),
    })
}

fn build_data_plane_auth_for_put(
    existing: Option<&api::Profile>,
    args: &ProfileAuthArgs,
) -> anyhow::Result<Option<api::DataPlaneAuthSettings>> {
    if args.data_plane_auth_mode.is_none() && args.accept_x_api_key.is_none() {
        return Ok(None);
    }
    let existing =
        existing.ok_or_else(|| anyhow::anyhow!("load profile before overriding auth"))?;
    Ok(Some(api::DataPlaneAuthSettings {
        mode: args
            .data_plane_auth_mode
            .map_or(existing.data_plane_auth.mode, Into::into),
        accept_x_api_key: args
            .accept_x_api_key
            .unwrap_or(existing.data_plane_auth.accept_x_api_key),
    }))
}

fn validate_limits(l: &api::DataPlaneLimitsSettings) -> anyhow::Result<()> {
    if let Some(v) = l.rate_limit_tool_calls_per_minute
        && v <= 0
    {
        anyhow::bail!("rateLimitToolCallsPerMinute must be > 0");
    }
    if let Some(v) = l.quota_tool_calls
        && v <= 0
    {
        anyhow::bail!("quotaToolCalls must be > 0");
    }
    if l.rate_limit_enabled && l.rate_limit_tool_calls_per_minute.is_none() {
        anyhow::bail!("rateLimitToolCallsPerMinute is required when rateLimitEnabled is true");
    }
    if l.quota_enabled && l.quota_tool_calls.is_none() {
        anyhow::bail!("quotaToolCalls is required when quotaEnabled is true");
    }
    Ok(())
}

fn build_data_plane_limits_for_create(
    args: &ProfileLimitsArgs,
) -> anyhow::Result<Option<api::DataPlaneLimitsSettings>> {
    if args.rate_limit_enabled.is_none()
        && args.rate_limit_tool_calls_per_minute.is_none()
        && args.quota_enabled.is_none()
        && args.quota_tool_calls.is_none()
    {
        return Ok(None);
    }
    let l = api::DataPlaneLimitsSettings {
        rate_limit_enabled: args.rate_limit_enabled.unwrap_or(false),
        rate_limit_tool_calls_per_minute: args.rate_limit_tool_calls_per_minute,
        quota_enabled: args.quota_enabled.unwrap_or(false),
        quota_tool_calls: args.quota_tool_calls,
    };
    validate_limits(&l)?;
    Ok(Some(l))
}

fn build_data_plane_limits_for_put(
    existing: Option<&api::Profile>,
    args: &ProfileLimitsArgs,
) -> anyhow::Result<Option<api::DataPlaneLimitsSettings>> {
    if args.rate_limit_enabled.is_none()
        && args.rate_limit_tool_calls_per_minute.is_none()
        && args.quota_enabled.is_none()
        && args.quota_tool_calls.is_none()
    {
        return Ok(None);
    }
    let existing =
        existing.ok_or_else(|| anyhow::anyhow!("load profile before overriding limits"))?;
    let l = api::DataPlaneLimitsSettings {
        rate_limit_enabled: args
            .rate_limit_enabled
            .unwrap_or(existing.data_plane_limits.rate_limit_enabled),
        rate_limit_tool_calls_per_minute: if args.rate_limit_tool_calls_per_minute.is_some() {
            args.rate_limit_tool_calls_per_minute
        } else {
            existing.data_plane_limits.rate_limit_tool_calls_per_minute
        },
        quota_enabled: args
            .quota_enabled
            .unwrap_or(existing.data_plane_limits.quota_enabled),
        quota_tool_calls: if args.quota_tool_calls.is_some() {
            args.quota_tool_calls
        } else {
            existing.data_plane_limits.quota_tool_calls
        },
    };
    validate_limits(&l)?;
    Ok(Some(l))
}
