use crate::oidc::{OidcConfig, OidcValidator};
use anyhow::Context as _;
use reqwest::Url;
use serde::Serialize;

const PUBLIC_BASE_URL_ENV: &str = "UNRELATED_GATEWAY_PUBLIC_DATA_BASE_URL";
const OAUTH_PREFIX: &str = "UNRELATED_GATEWAY_OAUTH";

#[derive(Clone)]
pub struct OAuthRuntime {
    public_data_base_url: Url,
    validator: OidcValidator,
}

#[derive(Debug, Serialize)]
pub struct ProtectedResourceMetadata {
    pub resource: String,
    pub authorization_servers: Vec<String>,
    pub scopes_supported: Vec<String>,
    pub bearer_methods_supported: Vec<&'static str>,
    pub resource_name: &'static str,
}

impl OAuthRuntime {
    pub async fn from_env(http: reqwest::Client) -> anyhow::Result<Option<Self>> {
        let public_base = non_empty_env(PUBLIC_BASE_URL_ENV);
        let issuer = non_empty_env(&format!("{OAUTH_PREFIX}_ISSUER"));
        let jwks_uri = non_empty_env(&format!("{OAUTH_PREFIX}_JWKS_URI"));
        let leeway = non_empty_env(&format!("{OAUTH_PREFIX}_LEEWAY_SECS"));
        let refresh = non_empty_env(&format!("{OAUTH_PREFIX}_JWKS_REFRESH_SECS"));

        let any_configured = public_base.is_some()
            || issuer.is_some()
            || jwks_uri.is_some()
            || leeway.is_some()
            || refresh.is_some();
        if !any_configured {
            return Ok(None);
        }
        let public_base = public_base.ok_or_else(|| {
            anyhow::anyhow!("partial OAuth configuration: {PUBLIC_BASE_URL_ENV} is required")
        })?;
        let issuer = issuer.ok_or_else(|| {
            anyhow::anyhow!("partial OAuth configuration: {OAUTH_PREFIX}_ISSUER is required")
        })?;

        let public_data_base_url = normalize_public_data_base_url(&public_base)?;
        let issuer = normalize_issuer(&issuer)?;
        let leeway_secs = parse_u64_env(leeway.as_deref(), 60, "OAUTH_LEEWAY_SECS")?;
        let jwks_refresh_secs = parse_u64_env(refresh.as_deref(), 600, "OAUTH_JWKS_REFRESH_SECS")?;
        let jwks_uri = match jwks_uri {
            Some(uri) => {
                validate_secure_url(&uri, "OAuth JWKS URI")?;
                uri
            }
            None => crate::oidc::discover_oauth_jwks_uri(&http, &issuer).await?,
        };

        Ok(Some(Self {
            public_data_base_url,
            validator: OidcValidator::new(
                http,
                OidcConfig {
                    issuer,
                    audiences: Vec::new(),
                    jwks_uri,
                    leeway_secs,
                    jwks_refresh_secs,
                },
            ),
        }))
    }

    pub fn issuer(&self) -> &str {
        self.validator.issuer()
    }

    pub fn public_data_base_url(&self) -> &str {
        self.public_data_base_url.as_str().trim_end_matches('/')
    }

    pub fn resource_url(&self, profile_id: &str) -> String {
        format!("{}/{profile_id}/mcp", self.public_data_base_url())
    }

    pub fn metadata_url(&self, profile_id: &str) -> String {
        format!(
            "{}/.well-known/oauth-protected-resource/{profile_id}/mcp",
            self.public_data_base_url()
        )
    }

    pub fn metadata(
        &self,
        profile_id: &str,
        required_scopes: &[String],
    ) -> ProtectedResourceMetadata {
        ProtectedResourceMetadata {
            resource: self.resource_url(profile_id),
            authorization_servers: vec![self.issuer().to_string()],
            scopes_supported: required_scopes.to_vec(),
            bearer_methods_supported: vec!["header"],
            resource_name: "Unrelated MCP Gateway",
        }
    }

    pub async fn validate(&self, jwt: &str, profile_id: &str) -> anyhow::Result<serde_json::Value> {
        self.validator
            .validate_for_audience(jwt, &self.resource_url(profile_id))
            .await
    }
}

fn non_empty_env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn parse_u64_env(value: Option<&str>, default: u64, name: &str) -> anyhow::Result<u64> {
    value.map_or(Ok(default), |value| {
        value
            .parse::<u64>()
            .with_context(|| format!("invalid {name}: expected an unsigned integer"))
    })
}

pub(crate) fn normalize_public_data_base_url(value: &str) -> anyhow::Result<Url> {
    let mut url = Url::parse(value).context("parse public data-plane base URL")?;
    validate_http_url(&url, "public data-plane base URL")?;
    if !url.username().is_empty() || url.password().is_some() {
        anyhow::bail!("public data-plane base URL must not contain credentials");
    }
    if url.query().is_some() || url.fragment().is_some() {
        anyhow::bail!("public data-plane base URL must not contain a query or fragment");
    }
    let normalized_path = url.path().trim_end_matches('/').to_string();
    url.set_path(if normalized_path.is_empty() {
        "/"
    } else {
        &normalized_path
    });
    Ok(url)
}

fn normalize_issuer(value: &str) -> anyhow::Result<String> {
    let url = Url::parse(value).context("parse OAuth issuer")?;
    validate_http_url(&url, "OAuth issuer")?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        anyhow::bail!("OAuth issuer must not contain credentials, query, or fragment");
    }
    Ok(value.to_string())
}

fn validate_secure_url(value: &str, label: &str) -> anyhow::Result<()> {
    let url = Url::parse(value).with_context(|| format!("parse {label}"))?;
    validate_http_url(&url, label)
}

fn validate_http_url(url: &Url, label: &str) -> anyhow::Result<()> {
    let loopback = url.host_str().is_some_and(|host| {
        host.eq_ignore_ascii_case("localhost")
            || host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    });
    if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
        anyhow::bail!("{label} must use HTTPS (HTTP is allowed only for loopback development)");
    }
    if url.host_str().is_none() {
        anyhow::bail!("{label} must be an absolute URL");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_public_base_url_and_preserves_prefix() {
        let url = normalize_public_data_base_url("https://mcp.example.com/proxy/").unwrap();
        assert_eq!(url.as_str(), "https://mcp.example.com/proxy");
    }

    #[test]
    fn permits_loopback_http_only() {
        assert!(normalize_public_data_base_url("http://127.0.0.1:4000").is_ok());
        assert!(normalize_public_data_base_url("http://example.com").is_err());
    }

    #[test]
    fn rejects_ambiguous_public_urls() {
        assert!(normalize_public_data_base_url("https://user@example.com").is_err());
        assert!(normalize_public_data_base_url("https://example.com?q=1").is_err());
        assert!(normalize_public_data_base_url("https://example.com/#x").is_err());
    }

    #[test]
    fn constructs_profile_urls_and_metadata_from_trusted_config() {
        let runtime = OAuthRuntime {
            public_data_base_url: normalize_public_data_base_url("https://mcp.example.com/prefix/")
                .unwrap(),
            validator: OidcValidator::new(
                reqwest::Client::new(),
                OidcConfig {
                    issuer: "https://login.example.com".to_string(),
                    audiences: Vec::new(),
                    jwks_uri: "https://login.example.com/jwks".to_string(),
                    leeway_secs: 60,
                    jwks_refresh_secs: 600,
                },
            ),
        };
        let id = "00000000-0000-4000-8000-000000000000";
        assert_eq!(
            runtime.resource_url(id),
            "https://mcp.example.com/prefix/00000000-0000-4000-8000-000000000000/mcp"
        );
        let metadata = runtime.metadata(id, &["mcp:access".to_string()]);
        assert_eq!(
            metadata.authorization_servers,
            ["https://login.example.com"]
        );
        assert_eq!(metadata.scopes_supported, ["mcp:access"]);
        assert_eq!(metadata.bearer_methods_supported, ["header"]);
    }
}
