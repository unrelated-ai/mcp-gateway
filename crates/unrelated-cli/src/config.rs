use anyhow::{Context as _, bail};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    path::{Path, PathBuf},
};
use url::Url;

pub const CONFIG_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum AuthMode {
    #[default]
    Auto,
    Oauth,
    ApiKey,
    None,
}

impl std::fmt::Display for AuthMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Auto => "auto",
            Self::Oauth => "oauth",
            Self::ApiKey => "api-key",
            Self::None => "none",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ContextConfig {
    pub mcp_url: String,
    #[serde(default)]
    pub auth: AuthMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth_client_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_context: Option<String>,
    #[serde(default)]
    pub contexts: BTreeMap<String, ContextConfig>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            version: CONFIG_VERSION,
            current_context: None,
            contexts: BTreeMap::new(),
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read configuration at {}", path.display()))?;
        let config: Self = toml::from_str(&raw)
            .with_context(|| format!("invalid configuration at {}", path.display()))?;
        if config.version != CONFIG_VERSION {
            bail!(
                "unsupported configuration version {}; expected {}",
                config.version,
                CONFIG_VERSION
            );
        }
        Ok(config)
    }

    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        let parent = path.parent().context("configuration path has no parent")?;
        create_private_dir(parent)?;
        let tmp = parent.join("config.toml.tmp");
        let raw = toml::to_string_pretty(self).context("failed to serialize configuration")?;
        write_private_file(&tmp, raw.as_bytes())?;
        fs::rename(&tmp, path).with_context(|| {
            format!(
                "failed to replace configuration {} with {}",
                path.display(),
                tmp.display()
            )
        })?;
        Ok(())
    }

    pub fn resolve_context(
        &self,
        requested: Option<&str>,
    ) -> anyhow::Result<(String, &ContextConfig)> {
        let name = requested
            .or(self.current_context.as_deref())
            .context("no context selected; run `unrelated context add` or pass --context")?;
        let context = self
            .contexts
            .get(name)
            .with_context(|| format!("unknown context '{name}'"))?;
        Ok((name.to_string(), context))
    }
}

pub fn config_path() -> anyhow::Result<PathBuf> {
    let base =
        dirs::config_dir().context("could not determine the user configuration directory")?;
    Ok(base.join("unrelated/config.toml"))
}

pub fn cache_dir() -> anyhow::Result<PathBuf> {
    let base = dirs::cache_dir().context("could not determine the user cache directory")?;
    Ok(base.join("unrelated/catalogs"))
}

pub fn validate_context_name(name: &str) -> anyhow::Result<()> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    {
        bail!("context names must be 1-64 ASCII letters, digits, '-' or '_'");
    }
    Ok(())
}

pub fn validate_mcp_url(value: &str) -> anyhow::Result<String> {
    let mut url = Url::parse(value).context("MCP URL must be absolute")?;
    if url.username() != "" || url.password().is_some() {
        bail!("MCP URL must not contain credentials");
    }
    if url.query().is_some() || url.fragment().is_some() {
        bail!("MCP URL must not contain a query or fragment");
    }
    let host = url.host_str().context("MCP URL must contain a host")?;
    let loopback = host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
        bail!("MCP URL must use HTTPS (HTTP is allowed only for loopback development)");
    }
    if !url.path().ends_with("/mcp") {
        bail!("MCP URL must identify a profile endpoint ending in /mcp");
    }
    if url.path().contains("//") {
        bail!("MCP URL path must not contain empty segments");
    }
    url.set_fragment(None);
    Ok(url.to_string())
}

pub(crate) fn create_private_dir(path: &Path) -> anyhow::Result<()> {
    fs::create_dir_all(path)
        .with_context(|| format!("failed to create directory {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

pub(crate) fn write_private_file(path: &Path, data: &[u8]) -> anyhow::Result<()> {
    let mut options = fs::OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("failed to write {}", path.display()))?;
    file.write_all(data)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_public_and_loopback_profile_urls() {
        assert!(validate_mcp_url("https://mcp.example.com/p/mcp").is_ok());
        assert!(validate_mcp_url("http://127.0.0.1:8080/p/mcp").is_ok());
        assert!(validate_mcp_url("http://example.com/p/mcp").is_err());
        assert!(validate_mcp_url("https://u:p@example.com/p/mcp").is_err());
        assert!(validate_mcp_url("https://example.com/p/mcp?q=1").is_err());
        assert!(validate_mcp_url("https://example.com/not-profile").is_err());
    }

    #[test]
    fn explicit_context_wins_over_current() {
        let mut config = Config {
            current_context: Some("one".into()),
            ..Default::default()
        };
        for name in ["one", "two"] {
            config.contexts.insert(
                name.into(),
                ContextConfig {
                    mcp_url: format!("https://example.com/{name}/mcp"),
                    auth: AuthMode::None,
                    oauth_client_id: None,
                },
            );
        }
        assert_eq!(config.resolve_context(Some("two")).unwrap().0, "two");
    }
}
