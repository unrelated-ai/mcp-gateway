use anyhow::Context as _;
use axum::{Json, Router, extract::State, routing::get};
use clap::Parser;
use serde::Serialize;
use std::time::Duration;
use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Instant};
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::prelude::*;

mod admin;
mod audit;
mod audit_retention;
mod catalog;
mod config;
mod contracts;
mod endpoint_cache;
mod mcp;
mod oidc;
mod outbound_safety;
mod pg_fanout;
mod pg_invalidation;
mod pg_store;
mod profile_http;
mod secrets_crypto;
mod serde_helpers;
mod session_token;
mod store;
mod tenant;
mod tenant_catalog;
mod tenant_token;
mod timeouts;
mod tool_policy;
mod tools_cache;
mod transport_limits;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const LICENSE: &str = env!("CARGO_PKG_LICENSE");

/// CLI arguments for the gateway.
#[derive(Parser, Debug, Clone)]
#[command(name = "unrelated-mcp-gateway")]
#[command(
    version,
    about = "MCP Gateway (beta): MCP proxy + upstream aggregation + admin API"
)]
struct CliArgs {
    /// Path to a gateway config file (YAML).
    #[arg(short = 'c', long = "config", env = "UNRELATED_GATEWAY_CONFIG")]
    config: Option<PathBuf>,

    /// Postgres connection string to enable Mode 3 (HA) storage.
    #[arg(long = "database-url", env = "UNRELATED_GATEWAY_DATABASE_URL")]
    database_url: Option<String>,

    /// Data plane HTTP bind address (ip:port).
    #[arg(
        short = 'b',
        long,
        env = "UNRELATED_GATEWAY_BIND",
        default_value = "127.0.0.1:4000"
    )]
    bind: String,

    /// Admin/control plane HTTP bind address (ip:port).
    #[arg(
        long = "admin-bind",
        env = "UNRELATED_GATEWAY_ADMIN_BIND",
        default_value = "127.0.0.1:4001"
    )]
    admin_bind: String,

    /// Log level. Supports tracing filter syntax.
    #[arg(
        short = 'l',
        long = "log-level",
        env = "UNRELATED_GATEWAY_LOG",
        default_value = "info"
    )]
    log_level: String,
}

#[derive(Clone)]
struct AppState {
    start_time: Instant,
    version: &'static str,
    config_loaded: bool,
    profile_count: usize,
    oidc_issuer: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StatusResponse {
    version: &'static str,
    license: &'static str,
    uptime_secs: u64,
    config_loaded: bool,
    profile_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    oidc_issuer: Option<String>,
    oidc_configured: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = CliArgs::parse();
    init_logging(&args.log_level);

    tracing::info!("Starting Unrelated MCP Gateway v{VERSION}");
    Box::pin(run(args)).await
}

async fn run(args: CliArgs) -> anyhow::Result<()> {
    let (config, config_loaded) = load_config(&args).await?;
    validate_config_guardrails(&args, &config)?;
    let profile_count = config.profiles.len();
    let session_secrets = load_session_secrets();
    let session_ttl = load_session_ttl();

    let shared_source_ids: Arc<std::collections::HashSet<String>> =
        Arc::new(config.shared_sources.keys().cloned().collect());

    let catalog = Arc::new(catalog::SharedCatalog::from_config(&config).await?);

    let (store, admin_store, pg_pool) = build_store(&args, config).await?;

    // Graceful shutdown coordination for all long-lived tasks (servers + streams).
    let ct = CancellationToken::new();
    let audit = build_audit_sink(pg_pool.clone(), &ct);

    let contracts = Arc::new(contracts::ContractTracker::new());
    let contract_fanout =
        build_contract_fanout(pg_pool.clone(), contracts.clone(), ct.clone()).await?;

    audit_retention::spawn_audit_retention_task(pg_pool.clone(), ct.clone());

    let http = build_no_redirect_http_client("upstream HTTP client")?;
    let oidc_http = build_no_redirect_http_client("OIDC HTTP client")?;
    let oidc = oidc::OidcValidator::from_env(oidc_http).await?;
    let oidc_issuer = oidc.as_ref().map(|o| o.issuer().to_string());

    let mcp_state = Arc::new(mcp::McpState {
        store: store.clone(),
        signer: session_token::SessionSigner::new(session_secrets.clone(), session_ttl)
            .context("init session token signer")?,
        http,
        oidc,
        shutdown: ct.clone(),
        audit: audit.clone(),
        catalog,
        tenant_catalog: Arc::new(tenant_catalog::TenantCatalog::new()),
        contracts,
        contract_fanout,
        tools_cache: Arc::new(tools_cache::ToolSurfaceCache::new(Duration::from_secs(30))),
        endpoint_cache: Arc::new(endpoint_cache::UpstreamEndpointCache::new(
            Duration::from_secs(30),
        )),
    });

    start_mode3_ha_tasks(pg_pool.clone(), mcp_state.clone(), ct.clone()).await?;
    start_tool_contract_invalidator(&mcp_state, ct.clone());

    let admin_state = Arc::new(admin::AdminState {
        store: admin_store,
        admin_token: std::env::var("UNRELATED_GATEWAY_ADMIN_TOKEN").ok(),
        bootstrap_enabled: env_truthy("UNRELATED_GATEWAY_BOOTSTRAP_ENABLED"),
        tenant_signer: tenant_token::TenantSigner::new(session_secrets[0].clone()),
        shared_source_ids: shared_source_ids.clone(),
        oidc_issuer: oidc_issuer.clone(),
        audit: audit.clone(),
    });

    let tenant_state = Arc::new(tenant::TenantState {
        store: admin_state.store.clone(),
        signer: tenant_token::TenantSigner::new(session_secrets[0].clone()),
        shared_source_ids,
        mcp_state: mcp_state.clone(),
        audit,
    });

    let data_bind = parse_socket_addr(&args.bind, "bind")?;
    let admin_bind = parse_socket_addr(&args.admin_bind, "admin-bind")?;

    let state = Arc::new(AppState {
        start_time: Instant::now(),
        version: VERSION,
        config_loaded,
        profile_count,
        oidc_issuer,
    });

    let data_app = mcp::router(mcp_state).route("/health", get(health));

    // Make the admin routes compatible with the admin app's state type for `merge`.
    // Admin routes don't need `AppState`, but `merge` requires both routers to be missing
    // the same state type.
    let admin_routes = admin::router()
        .layer(axum::Extension(admin_state))
        .with_state::<Arc<AppState>>(());
    let tenant_routes = tenant::router(tenant_state).with_state::<Arc<AppState>>(());

    let admin_app = Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/status", get(status))
        .merge(admin_routes)
        .merge(tenant_routes)
        .with_state(state);

    let (data_listener, _data_addr) = bind_and_log(data_bind, "data", "bind").await?;
    let (admin_listener, _admin_addr) =
        bind_and_log(admin_bind, "admin/control", "admin-bind").await?;

    spawn_shutdown_watcher(ct.clone());

    serve_servers(
        ct.clone(),
        data_listener,
        data_app,
        admin_listener,
        admin_app,
    )
    .await?;

    tracing::info!("Gateway shut down gracefully");
    Ok(())
}

fn build_no_redirect_http_client(label: &'static str) -> anyhow::Result<reqwest::Client> {
    // Redirects are disabled (SSRF hardening). Upstream endpoints should be configured with their
    // final URL.
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .with_context(|| format!("build {label}"))
}

fn env_truthy(name: &str) -> bool {
    let Ok(v) = std::env::var(name) else {
        return false;
    };
    let s = v.trim();
    s == "1"
        || s.eq_ignore_ascii_case("true")
        || s.eq_ignore_ascii_case("yes")
        || s.eq_ignore_ascii_case("on")
}

fn build_audit_sink(
    pg_pool: Option<sqlx::PgPool>,
    ct: &CancellationToken,
) -> Arc<dyn audit::AuditSink> {
    match pg_pool {
        Some(pool) => audit::PostgresAuditSink::new(pool, ct.clone()),
        None => Arc::new(audit::NoopAuditSink),
    }
}

async fn start_mode3_ha_tasks(
    pg_pool: Option<sqlx::PgPool>,
    mcp_state: Arc<mcp::McpState>,
    ct: CancellationToken,
) -> anyhow::Result<()> {
    // Mode 3 HA: best-effort cross-node cache invalidation signals.
    let Some(pool) = pg_pool else {
        return Ok(());
    };

    let tools_cache = mcp_state.tools_cache.clone();
    let endpoint_cache = mcp_state.endpoint_cache.clone();
    let tenant_catalog = mcp_state.tenant_catalog.clone();
    let on_event: std::sync::Arc<dyn Fn(pg_invalidation::InvalidationEvent) + Send + Sync> =
        std::sync::Arc::new(move |evt| match evt {
            pg_invalidation::InvalidationEvent::TenantSecret { tenant_id, .. } => {
                tenant_catalog.invalidate_tenant(&tenant_id);
            }
            pg_invalidation::InvalidationEvent::TenantToolSource {
                tenant_id,
                source_id,
            } => {
                tenant_catalog.invalidate_source(&tenant_id, &source_id);
            }
            pg_invalidation::InvalidationEvent::Profile { profile_id } => {
                tools_cache.invalidate_profile(&profile_id);
            }
            pg_invalidation::InvalidationEvent::Upstream { upstream_id } => {
                endpoint_cache.invalidate_upstream(&upstream_id);
            }
        });

    pg_invalidation::start_listener(pool, ct, on_event)
        .await
        .with_context(|| "start Postgres LISTEN/NOTIFY invalidation listener")?;
    Ok(())
}

fn start_tool_contract_invalidator(mcp_state: &Arc<mcp::McpState>, ct: CancellationToken) {
    // HA: invalidate per-session tool routing caches when tools contracts change (including remote
    // changes delivered via Postgres fanout).
    let mut rx = mcp_state.contracts.subscribe_all();
    let tools_cache = mcp_state.tools_cache.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                () = ct.cancelled() => break,
                res = rx.recv() => {
                    let evt = match res {
                        Ok(e) => e,
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    };
                    if evt.kind == contracts::ContractKind::Tools {
                        tools_cache.invalidate_profile(&evt.profile_id);
                    }
                }
            }
        }
    });
}

fn validate_config_guardrails(
    args: &CliArgs,
    config: &config::GatewayConfig,
) -> anyhow::Result<()> {
    // Mode 1 vs Mode 3 auth config guardrails.
    match (&args.database_url, config.data_plane_auth.mode) {
        (Some(_), config::Mode1AuthMode::None) => {}
        (Some(_), _) => {
            anyhow::bail!(
                "Mode 3 is enabled (--database-url), but config file contains Mode 1 dataPlaneAuth settings. \
                 Remove `dataPlaneAuth` from config when running in Mode 3."
            );
        }
        (None, config::Mode1AuthMode::None) => {
            tracing::warn!(
                "Mode 1: data plane is UNAUTHENTICATED. Do not expose the data-plane bind address publicly."
            );
        }
        (None, config::Mode1AuthMode::StaticApiKeys) => {
            if config.data_plane_auth.api_keys.is_empty() {
                anyhow::bail!(
                    "Mode 1 dataPlaneAuth.mode=static-api-keys requires dataPlaneAuth.apiKeys to be non-empty"
                );
            }
        }
    }
    Ok(())
}

async fn bind_and_log(
    addr: SocketAddr,
    label: &'static str,
    name: &'static str,
) -> anyhow::Result<(tokio::net::TcpListener, SocketAddr)> {
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind {name} address '{addr}'"))?;
    let bound = listener
        .local_addr()
        .with_context(|| format!("get {name} bind address"))?;
    tracing::info!("Starting {label} plane HTTP server on {bound}");
    Ok((listener, bound))
}

fn spawn_shutdown_watcher(ct: CancellationToken) {
    // Placeholder for later: graceful shutdown on SIGINT/SIGTERM.
    tokio::spawn(async move {
        #[cfg(unix)]
        let terminate = async {
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("Failed to install SIGTERM handler")
                .recv()
                .await;
        };

        #[cfg(not(unix))]
        let terminate = std::future::pending::<()>();

        tokio::select! {
            res = tokio::signal::ctrl_c() => {
                if let Err(e) = res {
                    tracing::warn!(error = %e, "failed to listen for Ctrl+C");
                }
                tracing::info!("Received Ctrl+C, initiating shutdown...");
            }
            () = terminate => {
                tracing::info!("Received SIGTERM, initiating shutdown...");
            }
        }

        ct.cancel();
    });
}

async fn serve_servers(
    ct: CancellationToken,
    data_listener: tokio::net::TcpListener,
    data_app: Router,
    admin_listener: tokio::net::TcpListener,
    admin_app: Router,
) -> anyhow::Result<()> {
    let data_ct = ct.clone();
    let data_server = axum::serve(data_listener, data_app).with_graceful_shutdown(async move {
        data_ct.cancelled().await;
    });

    let admin_ct = ct.clone();
    let admin_server = axum::serve(admin_listener, admin_app).with_graceful_shutdown(async move {
        admin_ct.cancelled().await;
    });

    tokio::try_join!(data_server, admin_server)?;
    Ok(())
}

async fn build_contract_fanout(
    pg_pool: Option<sqlx::PgPool>,
    contracts: Arc<contracts::ContractTracker>,
    shutdown: CancellationToken,
) -> anyhow::Result<Option<Arc<pg_fanout::PgContractFanout>>> {
    let Some(pool) = pg_pool else {
        return Ok(None);
    };

    let node_id = std::env::var("UNRELATED_GATEWAY_NODE_ID")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let fanout = Arc::new(pg_fanout::PgContractFanout::new(pool, node_id));
    fanout
        .start_listener(contracts, shutdown)
        .await
        .with_context(|| "start Postgres LISTEN/NOTIFY contract fanout")?;
    Ok(Some(fanout))
}

async fn load_config(args: &CliArgs) -> anyhow::Result<(config::GatewayConfig, bool)> {
    if let Some(path) = &args.config {
        let bytes = tokio::fs::read(path)
            .await
            .with_context(|| format!("read config: {}", path.display()))?;
        let cfg: config::GatewayConfig = serde_yaml::from_slice(&bytes)
            .with_context(|| format!("parse YAML config: {}", path.display()))?;
        validate_config(&cfg).with_context(|| format!("validate config: {}", path.display()))?;
        Ok((cfg, true))
    } else {
        Ok((config::GatewayConfig::default(), false))
    }
}

fn validate_config(cfg: &config::GatewayConfig) -> anyhow::Result<()> {
    for (profile_id, p) in &cfg.profiles {
        if let Some(tools) = &p.tools {
            validate_tool_allowlist(profile_id, tools)?;
        }
    }
    Ok(())
}

fn validate_tool_allowlist(profile_id: &str, tools: &[String]) -> anyhow::Result<()> {
    use anyhow::bail;
    use std::collections::HashSet;

    if tools.is_empty() {
        // No allowlist configured (allow all tools).
        return Ok(());
    }

    let mut seen: HashSet<String> = HashSet::new();
    for raw in tools {
        let entry = raw.trim();
        if entry.is_empty() {
            bail!("profiles.{profile_id}.tools entries must be non-empty");
        }
        if entry == "*" {
            bail!(
                "profiles.{profile_id}.tools: wildcard '*' is no longer supported; use explicit '<source_id>:<original_tool_name>' entries"
            );
        }
        let Some((src, name)) = entry.split_once(':') else {
            bail!("profiles.{profile_id}.tools entries must be '<source_id>:<original_tool_name>'");
        };
        if src.trim().is_empty() || name.trim().is_empty() {
            bail!("profiles.{profile_id}.tools entries must be '<source_id>:<original_tool_name>'");
        }
        if !seen.insert(entry.to_string()) {
            bail!("profiles.{profile_id}.tools contains duplicate entries");
        }
    }

    Ok(())
}

fn load_session_secret() -> Vec<u8> {
    match std::env::var("UNRELATED_GATEWAY_SESSION_SECRET") {
        Ok(v) if !v.is_empty() => v.into_bytes(),
        _ => {
            tracing::warn!(
                "UNRELATED_GATEWAY_SESSION_SECRET is not set; generating an ephemeral secret (not HA-safe)"
            );
            uuid::Uuid::new_v4().as_bytes().to_vec()
        }
    }
}

fn load_session_secrets() -> Vec<Vec<u8>> {
    // Rotation-friendly: comma-separated secrets; first is active for minting.
    if let Ok(v) = std::env::var("UNRELATED_GATEWAY_SESSION_SECRETS")
        && !v.trim().is_empty()
    {
        let secrets: Vec<Vec<u8>> = v
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| s.as_bytes().to_vec())
            .collect();
        if !secrets.is_empty() {
            return secrets;
        }
    }
    vec![load_session_secret()]
}

fn load_session_ttl() -> Duration {
    // Default aligns with `rusty_paseto`'s default builder exp (1h), and is a good baseline.
    // Clients can re-initialize when expired.
    let default_secs: u64 = 3600;
    let secs = std::env::var("UNRELATED_GATEWAY_SESSION_TTL_SECS")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(default_secs);
    Duration::from_secs(secs.max(1))
}

async fn build_store(
    args: &CliArgs,
    config: config::GatewayConfig,
) -> anyhow::Result<(
    Arc<dyn store::Store>,
    Option<Arc<dyn store::AdminStore>>,
    Option<sqlx::PgPool>,
)> {
    if let Some(database_url) = &args.database_url {
        tracing::info!(
            "Mode 3 enabled (Postgres). Ensure migrations have been applied (e.g. via dbmate)."
        );
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(10)
            .connect(database_url)
            .await
            .with_context(|| "connect to Postgres")?;
        // Mode 3 requires tenant secret encryption keys. Migrations are managed externally (dbmate).
        let secrets_cipher =
            std::sync::Arc::new(crate::secrets_crypto::SecretsCipher::new_from_env()?);
        ensure_mode3_secret_schema(&pool).await?;

        let pg = pg_store::PostgresStore::new(pool.clone(), secrets_cipher);
        let pg = Arc::new(pg);
        Ok((
            pg.clone() as Arc<dyn store::Store>,
            Some(pg as Arc<dyn store::AdminStore>),
            Some(pool),
        ))
    } else {
        Ok((
            Arc::new(store::ConfigStore::new(config)) as Arc<dyn store::Store>,
            None,
            None,
        ))
    }
}

async fn ensure_mode3_secret_schema(pool: &sqlx::PgPool) -> anyhow::Result<()> {
    use sqlx::Row as _;

    // If this fails, dbmate migrations for `crates/gateway/migrations/` were not applied.
    let row = sqlx::query(
        r"
select count(*)::int as n
from information_schema.columns
where table_name = 'secrets'
  and column_name in ('kid', 'nonce', 'ciphertext', 'algo')
",
    )
    .fetch_one(pool)
    .await
    .with_context(|| "check Mode 3 secrets schema")?;

    let n: i32 = row.try_get("n")?;
    if n < 4 {
        anyhow::bail!(
            "Mode 3 Postgres schema is missing secret-encryption columns; run dbmate migrations for crates/gateway/migrations"
        );
    }
    Ok(())
}

fn parse_socket_addr(value: &str, name: &str) -> anyhow::Result<SocketAddr> {
    value
        .parse()
        .with_context(|| format!("invalid {name} address '{value}'"))
}

async fn health() -> &'static str {
    "ok"
}

async fn ready() -> &'static str {
    "ready"
}

async fn status(State(state): State<Arc<AppState>>) -> Json<StatusResponse> {
    Json(StatusResponse {
        version: state.version,
        license: LICENSE,
        uptime_secs: state.start_time.elapsed().as_secs(),
        config_loaded: state.config_loaded,
        profile_count: state.profile_count,
        oidc_issuer: state.oidc_issuer.clone(),
        oidc_configured: state.oidc_issuer.is_some(),
    })
}

/// Initialize logging based on the log level string.
fn init_logging(log_level: &str) {
    let env_filter = EnvFilter::try_new(log_level).unwrap_or_else(|_| EnvFilter::new("info"));

    // Check if stdout is a TTY for format selection.
    let is_tty = atty::is(atty::Stream::Stdout);

    if is_tty {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(tracing_subscriber::fmt::layer().with_target(true))
            .init();
    } else {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(tracing_subscriber::fmt::layer().json())
            .init();
    }
}
