use anyhow::{Context as _, bail};
use clap::{Args, Parser, Subcommand};
use rmcp::model::{CallToolResult, JsonObject, Tool};
use serde::Serialize;
use serde_json::Value;
use std::{
    fs,
    io::{IsTerminal as _, Read as _, Write as _},
    path::PathBuf,
    process::ExitCode,
    time::Duration,
};
use unrelated_cli::{
    catalog::{self, CachedCatalog, Detail},
    client,
    config::{self, AuthMode, Config, ContextConfig},
    credentials, proxy, skills,
};

#[derive(Debug, Parser)]
#[command(
    name = "unrelated",
    version,
    about = "Compact client for Unrelated MCP Gateway"
)]
struct Cli {
    /// Named Gateway profile context to use.
    #[arg(long, global = true, env = "UNRELATED_CONTEXT")]
    context: Option<String>,
    /// Emit one machine-readable JSON value on stdout.
    #[arg(long, global = true)]
    json: bool,
    /// Network and tool-call timeout in seconds.
    #[arg(long, global = true, default_value_t = 60)]
    timeout: u64,
    /// Disable terminal colors (reserved for stable scripting behavior).
    #[arg(long, global = true)]
    no_color: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Manage named profile-URL contexts.
    Context(ContextArgs),
    /// Manage credentials for the selected context.
    Auth(AuthArgs),
    /// Search, inspect, and call authorized tools.
    Tools(ToolsArgs),
    /// Run a local stdio MCP server exposing only `search_tools` and `execute_tool`.
    Proxy(ProxyArgs),
    /// Install bundled agent skills.
    Skills(SkillsArgs),
}

#[derive(Debug, Args)]
struct ContextArgs {
    #[command(subcommand)]
    command: ContextCommand,
}

#[derive(Debug, Subcommand)]
enum ContextCommand {
    Add {
        name: String,
        #[arg(long)]
        url: String,
        #[arg(long, value_enum, default_value_t = AuthMode::Auto)]
        auth: AuthMode,
        #[arg(long)]
        client_id: Option<String>,
    },
    List,
    Show {
        name: Option<String>,
    },
    Use {
        name: String,
    },
    Remove {
        name: String,
    },
}

#[derive(Debug, Args)]
struct AuthArgs {
    #[command(subcommand)]
    command: AuthCommand,
}

#[derive(Debug, Subcommand)]
enum AuthCommand {
    Login {
        /// Print the authorization URL and read the final callback URL instead of opening a browser.
        #[arg(long)]
        no_browser: bool,
    },
    Status,
    Logout,
}

#[derive(Debug, Args)]
struct ToolsArgs {
    #[command(subcommand)]
    command: ToolsCommand,
}

#[derive(Debug, Subcommand)]
enum ToolsCommand {
    Search {
        query: String,
        #[arg(long, value_enum, default_value_t = Detail::Detailed)]
        detail: Detail,
        #[arg(long, default_value_t = 10, value_parser = parse_limit)]
        limit: usize,
        #[arg(long)]
        refresh: bool,
    },
    Describe {
        tool_ref: String,
    },
    Call {
        tool_ref: String,
        #[arg(long, conflicts_with = "input_file")]
        input: Option<String>,
        #[arg(long, value_name = "PATH|-", conflicts_with = "input")]
        input_file: Option<PathBuf>,
        /// Confirm a potentially side-effecting call without an interactive prompt.
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Debug, Args)]
struct ProxyArgs {
    /// Override the global context for this proxy process.
    #[arg(long)]
    context: Option<String>,
}

#[derive(Debug, Args)]
struct SkillsArgs {
    #[command(subcommand)]
    command: SkillsCommand,
}

#[derive(Debug, Subcommand)]
enum SkillsCommand {
    Install {
        #[arg(value_enum)]
        host: skills::SkillHost,
        #[arg(long)]
        force: bool,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let json = cli.json;
    match run(cli).await {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            if json {
                let payload = serde_json::json!({"error": format!("{error:#}")});
                println!("{}", serde_json::to_string(&payload).unwrap_or_default());
            } else {
                eprintln!("error: {error:#}");
            }
            ExitCode::from(classify_error(&error))
        }
    }
}

async fn run(cli: Cli) -> anyhow::Result<u8> {
    let timeout = Duration::from_secs(cli.timeout.max(1));
    let path = config::config_path()?;
    let mut config = Config::load(&path)?;

    match cli.command {
        Command::Context(args) => {
            handle_context(args.command, &path, &mut config, cli.json).await?;
        }
        Command::Auth(args) => {
            let (name, context) = config.resolve_context(cli.context.as_deref())?;
            handle_auth(args.command, &name, context, cli.json).await?;
        }
        Command::Tools(args) => {
            let (name, context) = config.resolve_context(cli.context.as_deref())?;
            return handle_tools(args.command, &name, context, cli.json, timeout).await;
        }
        Command::Proxy(args) => {
            let selected = args.context.as_deref().or(cli.context.as_deref());
            let (name, context) = config.resolve_context(selected)?;
            proxy::run(&name, context, timeout).await?;
        }
        Command::Skills(args) => match args.command {
            SkillsCommand::Install { host, force } => {
                let target = skills::install(host, force)?;
                print_value(cli.json, &serde_json::json!({"installed": target}), || {
                    format!("Installed unrelated-tools at {}", target.display())
                })?;
            }
        },
    }
    Ok(0)
}

#[allow(clippy::too_many_lines)]
async fn handle_context(
    command: ContextCommand,
    path: &std::path::Path,
    config: &mut Config,
    json: bool,
) -> anyhow::Result<()> {
    match command {
        ContextCommand::Add {
            name,
            url,
            auth,
            client_id,
        } => {
            config::validate_context_name(&name)?;
            if client_id.as_ref().is_some_and(|id| id.trim().is_empty()) {
                bail!("OAuth client ID must not be empty");
            }
            if client_id.is_some() && !matches!(auth, AuthMode::Oauth | AuthMode::Auto) {
                bail!("--client-id is valid only with --auth oauth or auto");
            }
            let context = ContextConfig {
                mcp_url: config::validate_mcp_url(&url)?,
                auth,
                oauth_client_id: client_id,
            };
            if let Some(previous) = config.contexts.get(&name)
                && previous != &context
            {
                client::logout(&name, previous).await?;
                catalog::remove_cache(&config::cache_dir()?, &name)?;
            }
            let replaced = config.contexts.insert(name.clone(), context).is_some();
            if config.current_context.is_none() {
                config.current_context = Some(name.clone());
            }
            config.save(path)?;
            print_value(
                json,
                &serde_json::json!({"name": name, "replaced": replaced}),
                || {
                    if replaced {
                        "Updated context".into()
                    } else {
                        "Added context".into()
                    }
                },
            )?;
        }
        ContextCommand::List => {
            #[derive(Serialize)]
            struct Item<'a> {
                name: &'a str,
                current: bool,
                #[serde(flatten)]
                context: &'a ContextConfig,
            }
            let items: Vec<_> = config
                .contexts
                .iter()
                .map(|(name, context)| Item {
                    name,
                    current: config.current_context.as_deref() == Some(name),
                    context,
                })
                .collect();
            print_value(json, &items, || {
                items
                    .iter()
                    .map(|item| {
                        format!(
                            "{}{}\t{}\t{}",
                            if item.current { "* " } else { "  " },
                            item.name,
                            item.context.auth,
                            item.context.mcp_url
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            })?;
        }
        ContextCommand::Show { name } => {
            let (name, context) = config.resolve_context(name.as_deref())?;
            print_value(
                json,
                &serde_json::json!({"name": name, "context": context}),
                || {
                    format!(
                        "{name}\n  URL: {}\n  Auth: {}",
                        context.mcp_url, context.auth
                    )
                },
            )?;
        }
        ContextCommand::Use { name } => {
            if !config.contexts.contains_key(&name) {
                bail!("unknown context '{name}'");
            }
            config.current_context = Some(name.clone());
            config.save(path)?;
            print_value(json, &serde_json::json!({"currentContext": name}), || {
                format!("Using context {name}")
            })?;
        }
        ContextCommand::Remove { name } => {
            let context = config
                .contexts
                .remove(&name)
                .with_context(|| format!("unknown context '{name}'"))?;
            client::logout(&name, &context).await?;
            catalog::remove_cache(&config::cache_dir()?, &name)?;
            if config.current_context.as_deref() == Some(&name) {
                config.current_context = config.contexts.keys().next().cloned();
            }
            config.save(path)?;
            print_value(json, &serde_json::json!({"removed": name}), || {
                format!("Removed context {name}")
            })?;
        }
    }
    Ok(())
}

async fn handle_auth(
    command: AuthCommand,
    name: &str,
    context: &ContextConfig,
    json: bool,
) -> anyhow::Result<()> {
    match command {
        AuthCommand::Login { no_browser } => match context.auth {
            AuthMode::Oauth => {
                client::oauth_login(name, context, no_browser).await?;
                print_value(
                    json,
                    &serde_json::json!({"authenticated": true, "mode": "oauth"}),
                    || "OAuth login complete".into(),
                )?;
            }
            AuthMode::Auto => match client::detect_auth_mode(context).await? {
                AuthMode::Oauth => {
                    client::oauth_login(name, context, no_browser).await?;
                    print_value(
                        json,
                        &serde_json::json!({"authenticated": true, "mode": "oauth"}),
                        || "OAuth login complete".into(),
                    )?;
                }
                AuthMode::ApiKey => {
                    let key = read_api_key()?;
                    credentials::save_api_key(name, &key).await?;
                    print_value(
                        json,
                        &serde_json::json!({"authenticated": true, "mode": "api-key"}),
                        || "API key saved in the native keychain".into(),
                    )?;
                }
                AuthMode::None | AuthMode::Auto => {
                    bail!("the Gateway profile does not require login")
                }
            },
            AuthMode::ApiKey => {
                let key = read_api_key()?;
                credentials::save_api_key(name, &key).await?;
                print_value(
                    json,
                    &serde_json::json!({"authenticated": true, "mode": "api-key"}),
                    || "API key saved in the native keychain".into(),
                )?;
            }
            AuthMode::None => bail!("this context has authentication disabled"),
        },
        AuthCommand::Status => {
            let authenticated = if std::env::var("UNRELATED_TOKEN").is_ok() {
                true
            } else {
                match context.auth {
                    AuthMode::Oauth => client::oauth_status(name, context).await?,
                    AuthMode::Auto => {
                        let has_credentials = client::oauth_status(name, context).await?
                            || credentials::load_api_key(name).await?.is_some();
                        has_credentials
                            || client::detect_auth_mode(context).await? == AuthMode::None
                    }
                    AuthMode::ApiKey => credentials::load_api_key(name).await?.is_some(),
                    AuthMode::None => true,
                }
            };
            print_value(
                json,
                &serde_json::json!({"authenticated": authenticated, "mode": context.auth.to_string()}),
                || {
                    format!(
                        "{} ({})",
                        if authenticated {
                            "authenticated"
                        } else {
                            "not authenticated"
                        },
                        context.auth
                    )
                },
            )?;
        }
        AuthCommand::Logout => {
            client::logout(name, context).await?;
            print_value(json, &serde_json::json!({"authenticated": false}), || {
                "Logged out".into()
            })?;
        }
    }
    Ok(())
}

async fn handle_tools(
    command: ToolsCommand,
    name: &str,
    context: &ContextConfig,
    json: bool,
    timeout: Duration,
) -> anyhow::Result<u8> {
    let cache_base = config::cache_dir()?;
    match command {
        ToolsCommand::Search {
            query,
            detail,
            limit,
            refresh,
        } => {
            let catalog = get_catalog(name, context, &cache_base, refresh, timeout).await?;
            let results = catalog.search(&query, detail, limit)?;
            print_value(json, &results, || {
                results
                    .iter()
                    .map(|result| {
                        let mut line = format!(
                            "{}\t{}",
                            result.tool_ref,
                            result.description.as_deref().unwrap_or_default()
                        );
                        if let Some(parameters) = &result.parameters {
                            let params = parameters
                                .iter()
                                .map(|p| {
                                    format!(
                                        "{}:{}{}",
                                        p.name,
                                        p.kind,
                                        if p.required { "*" } else { "" }
                                    )
                                })
                                .collect::<Vec<_>>()
                                .join(", ");
                            if !params.is_empty() {
                                line.push_str("\n  ");
                                line.push_str(&params);
                            }
                        }
                        line
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            })?;
            Ok(0)
        }
        ToolsCommand::Describe { tool_ref } => {
            let mut catalog = get_catalog(name, context, &cache_base, false, timeout).await?;
            if catalog.find(&tool_ref).is_none() {
                catalog = get_catalog(name, context, &cache_base, true, timeout).await?;
            }
            let tool = catalog
                .find(&tool_ref)
                .with_context(|| format!("unknown tool reference '{tool_ref}'"))?;
            print_value(json, tool, || {
                serde_json::to_string_pretty(tool).unwrap_or_default()
            })?;
            Ok(0)
        }
        ToolsCommand::Call {
            tool_ref,
            input,
            input_file,
            yes,
        } => {
            let arguments = read_input(input, input_file)?;
            // Resolve against a fresh catalog on the connection used for the call. This avoids
            // retrying an ambiguous tool execution when a cached exposed name has gone stale.
            let connection = client::connect(name, context, timeout).await?;
            let catalog = client::fetch_catalog(&connection).await?;
            catalog::save_cache(&cache_base, name, &catalog)?;
            let tool = catalog
                .find(&tool_ref)
                .cloned()
                .with_context(|| format!("unknown tool reference '{tool_ref}'"))?;
            confirm_if_needed(&tool, yes)?;
            let result = client::call_tool(&connection, &tool, arguments, timeout).await?;
            render_tool_result(&result, json)?;
            Ok(if result.is_error == Some(true) { 5 } else { 0 })
        }
    }
}

async fn get_catalog(
    name: &str,
    context: &ContextConfig,
    cache_base: &std::path::Path,
    refresh: bool,
    timeout: Duration,
) -> anyhow::Result<CachedCatalog> {
    if let Some(catalog) = client::load_or_fetch_catalog(cache_base, name, refresh)? {
        return Ok(catalog);
    }
    let connection = client::connect(name, context, timeout).await?;
    let catalog = client::fetch_catalog(&connection).await?;
    catalog::save_cache(cache_base, name, &catalog)?;
    Ok(catalog)
}

fn read_input(input: Option<String>, input_file: Option<PathBuf>) -> anyhow::Result<JsonObject> {
    let raw = match (input, input_file) {
        (Some(raw), None) => raw,
        (None, Some(path)) if path.as_os_str() == "-" => {
            let mut raw = String::new();
            std::io::stdin().read_to_string(&mut raw)?;
            raw
        }
        (None, Some(path)) => fs::read_to_string(&path)
            .with_context(|| format!("failed to read input from {}", path.display()))?,
        (None, None) => "{}".to_string(),
        (Some(_), Some(_)) => unreachable!("clap enforces conflicts"),
    };
    let value: Value = serde_json::from_str(&raw).context("input must be valid JSON")?;
    value
        .as_object()
        .cloned()
        .context("input must be a JSON object")
}

fn read_api_key() -> anyhow::Result<String> {
    let value = if std::io::stdin().is_terminal() {
        rpassword::prompt_password("API key: ")?
    } else {
        let mut value = String::new();
        std::io::stdin().read_to_string(&mut value)?;
        value
    };
    let value = value.trim().to_string();
    if value.is_empty() {
        bail!("API key must not be empty");
    }
    Ok(value)
}

fn confirm_if_needed(tool: &Tool, yes: bool) -> anyhow::Result<()> {
    if tool.annotations.as_ref().and_then(|a| a.read_only_hint) == Some(true) || yes {
        return Ok(());
    }
    if !std::io::stdin().is_terminal() {
        bail!("tool may have external side effects; pass --yes to confirm in non-interactive mode");
    }
    eprint!(
        "Tool '{}' may have external side effects. Continue? [y/N] ",
        catalog::stable_ref(tool)
    );
    std::io::stderr().flush()?;
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    if !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
        bail!("tool call cancelled");
    }
    Ok(())
}

fn render_tool_result(result: &CallToolResult, json: bool) -> anyhow::Result<()> {
    if json {
        println!("{}", serde_json::to_string(result)?);
        return Ok(());
    }
    for block in &result.content {
        let value = serde_json::to_value(block)?;
        match value.get("type").and_then(Value::as_str) {
            Some("text") => println!(
                "{}",
                value
                    .get("text")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
            ),
            Some("resource_link" | "resourceLink") => println!(
                "{}",
                value
                    .get("uri")
                    .and_then(Value::as_str)
                    .unwrap_or_else(|| value.as_str().unwrap_or_default())
            ),
            Some("image" | "audio") => {
                let kind = value
                    .get("type")
                    .and_then(Value::as_str)
                    .unwrap_or("binary");
                let mime = value
                    .get("mimeType")
                    .and_then(Value::as_str)
                    .unwrap_or("application/octet-stream");
                println!("[{kind} content: {mime}]");
            }
            _ => println!("{}", serde_json::to_string_pretty(&value)?),
        }
    }
    if let Some(structured) = &result.structured_content {
        println!("{}", serde_json::to_string_pretty(structured)?);
    }
    Ok(())
}

fn print_value<T: Serialize>(
    json: bool,
    value: &T,
    human: impl FnOnce() -> String,
) -> anyhow::Result<()> {
    if json {
        println!("{}", serde_json::to_string(value)?);
    } else {
        let output = human();
        if !output.is_empty() {
            println!("{output}");
        }
    }
    Ok(())
}

fn classify_error(error: &anyhow::Error) -> u8 {
    let message = format!("{error:#}").to_ascii_lowercase();
    if message.contains("oauth")
        || message.contains("api key")
        || message.contains("authenticated")
        || message.contains("unauthorized")
        || message.contains("credential")
        || message.contains("keychain")
    {
        3
    } else if message.contains("context")
        || message.contains("configuration")
        || message.contains("input")
        || message.contains("unknown tool reference")
        || message.contains("cancelled")
    {
        2
    } else {
        4
    }
}

fn parse_limit(value: &str) -> Result<usize, String> {
    let limit = value
        .parse::<usize>()
        .map_err(|_| "limit must be an integer between 1 and 50".to_string())?;
    if !(1..=50).contains(&limit) {
        return Err("limit must be between 1 and 50".to_string());
    }
    Ok(limit)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn input_must_be_an_object() {
        assert!(read_input(Some("{}".into()), None).is_ok());
        assert!(read_input(Some("[]".into()), None).is_err());
    }

    #[test]
    fn read_only_calls_do_not_require_confirmation() {
        let mut tool = Tool::new(
            "read".to_string(),
            String::new(),
            Arc::new(JsonObject::new()),
        );
        tool.annotations = Some(rmcp::model::ToolAnnotations::from_raw(
            None,
            Some(true),
            None,
            None,
            None,
        ));
        assert!(confirm_if_needed(&tool, false).is_ok());
    }
}
