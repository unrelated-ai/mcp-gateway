use anyhow::Context as _;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::RwLock;

const MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(5);

/// OIDC/JWT validator for protecting the Gateway data plane.
///
/// This is intentionally **generic** and configuration-driven, so Cognito/Entra/Okta/Auth0 are
/// "just config".
#[derive(Clone)]
pub struct OidcValidator {
    inner: Arc<Inner>,
}

struct Inner {
    issuer: String,
    audiences: Vec<String>,
    jwks_uri: String,
    leeway_secs: u64,
    refresh_after: Duration,
    http: reqwest::Client,
    jwks: RwLock<JwksCache>,
}

#[derive(Clone, Default)]
struct JwksCache {
    fetched_at: Option<Instant>,
    next_refresh_after: Option<Instant>,
    last_refresh_attempt: Option<Instant>,
    keys_by_kid: HashMap<String, DecodingKey>,
}

#[derive(Debug, Clone)]
pub struct OidcConfig {
    pub issuer: String,
    pub audiences: Vec<String>,
    pub jwks_uri: String,
    pub leeway_secs: u64,
    pub jwks_refresh_secs: u64,
}

impl OidcValidator {
    /// Load OIDC config from env vars.
    ///
    /// Enabled when `UNRELATED_GATEWAY_OIDC_ISSUER` is set (non-empty).
    ///
    /// Required:
    /// - `UNRELATED_GATEWAY_OIDC_ISSUER`
    ///
    /// Optional:
    /// - `UNRELATED_GATEWAY_OIDC_AUDIENCE` (comma-separated)
    /// - `UNRELATED_GATEWAY_OIDC_JWKS_URI` (overrides discovery)
    /// - `UNRELATED_GATEWAY_OIDC_LEEWAY_SECS` (default: 60)
    /// - `UNRELATED_GATEWAY_OIDC_JWKS_REFRESH_SECS` (default: 600)
    pub async fn from_env(http: reqwest::Client) -> anyhow::Result<Option<Self>> {
        Self::from_env_prefixed(http, "UNRELATED_GATEWAY_OIDC").await
    }

    /// Load OIDC config from env vars using a custom prefix.
    ///
    /// Example: prefix `UNRELATED_GATEWAY_CONTROL_PLANE_OIDC` expects:
    /// - `UNRELATED_GATEWAY_CONTROL_PLANE_OIDC_ISSUER`
    /// - `UNRELATED_GATEWAY_CONTROL_PLANE_OIDC_AUDIENCE`
    /// - `UNRELATED_GATEWAY_CONTROL_PLANE_OIDC_JWKS_URI`
    /// - `UNRELATED_GATEWAY_CONTROL_PLANE_OIDC_LEEWAY_SECS`
    /// - `UNRELATED_GATEWAY_CONTROL_PLANE_OIDC_JWKS_REFRESH_SECS`
    pub async fn from_env_prefixed(
        http: reqwest::Client,
        prefix: &str,
    ) -> anyhow::Result<Option<Self>> {
        let key = |suffix: &str| format!("{prefix}_{suffix}");

        let issuer = std::env::var(key("ISSUER"))
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        let Some(issuer) = issuer else {
            return Ok(None);
        };

        let audiences = std::env::var(key("AUDIENCE")).ok().unwrap_or_default();
        let audiences: Vec<String> = audiences
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();

        let leeway_secs = std::env::var(key("LEEWAY_SECS"))
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(60);
        let jwks_refresh_secs = std::env::var(key("JWKS_REFRESH_SECS"))
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(600);

        let jwks_uri_override = std::env::var(key("JWKS_URI"))
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        let jwks_uri = match jwks_uri_override {
            Some(v) => {
                // Allow non-HTTPS only when explicitly overridden (useful for local dev),
                // but warn loudly since this weakens transport security.
                if !v.starts_with("https://") {
                    tracing::warn!(
                        jwks_uri = %v,
                        "UNRELATED_GATEWAY_OIDC_JWKS_URI is not https; this should only be used for local development"
                    );
                }
                v
            }
            None => discover_jwks_uri(&http, &issuer).await?,
        };

        Ok(Some(Self::new(
            http,
            OidcConfig {
                issuer,
                audiences,
                jwks_uri,
                leeway_secs,
                jwks_refresh_secs,
            },
        )))
    }

    #[must_use]
    pub fn new(http: reqwest::Client, cfg: OidcConfig) -> Self {
        Self {
            inner: Arc::new(Inner {
                issuer: cfg.issuer,
                audiences: cfg.audiences,
                jwks_uri: cfg.jwks_uri,
                leeway_secs: cfg.leeway_secs,
                refresh_after: Duration::from_secs(cfg.jwks_refresh_secs.max(5)),
                http,
                jwks: RwLock::new(JwksCache::default()),
            }),
        }
    }

    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.inner.issuer
    }

    /// Validate a JWT and return its claims as JSON.
    ///
    /// Mode A: must be validated on every data-plane request.
    pub async fn validate(&self, jwt: &str) -> anyhow::Result<serde_json::Value> {
        let header = jsonwebtoken::decode_header(jwt).context("decode jwt header")?;
        // `crit` indicates critical JOSE extensions that must be understood by the verifier.
        // `jsonwebtoken::Header` doesn't expose `crit`, so we decode the raw JOSE header.
        if jwt_has_crit_header(jwt)? {
            anyhow::bail!("unsupported jwt crit header");
        }
        let kid = header
            .kid
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("missing jwt kid"))?;
        if header.alg != Algorithm::RS256 {
            anyhow::bail!("unsupported jwt alg (expected RS256)");
        }

        // Fast path: if we have the key, try decode without refreshing.
        if let Some(key) = self.get_key_if_present(kid).await
            && let Ok(claims) = self.decode_with_key(jwt, &key)
        {
            return Ok(claims);
        }

        // Refresh on missing kid (or stale cache), then try once more.
        self.refresh_jwks_if_needed(Some(kid)).await?;

        let key = self
            .get_key_if_present(kid)
            .await
            .ok_or_else(|| anyhow::anyhow!("unknown jwt kid"))?;

        self.decode_with_key(jwt, &key)
    }

    fn decode_with_key(&self, jwt: &str, key: &DecodingKey) -> anyhow::Result<serde_json::Value> {
        let mut validation = Validation::new(Algorithm::RS256);
        validation.leeway = self.inner.leeway_secs;
        validation.validate_exp = true;
        validation.validate_nbf = true;

        // `jsonwebtoken` expects issuer/audience as string sets; the helpers take `&[&str]`.
        validation.set_issuer(&[self.inner.issuer.as_str()]);
        if !self.inner.audiences.is_empty() {
            let aud: Vec<&str> = self.inner.audiences.iter().map(String::as_str).collect();
            validation.set_audience(&aud);
        }

        let data = jsonwebtoken::decode::<serde_json::Value>(jwt, key, &validation)
            .context("decode jwt")?;
        Ok(data.claims)
    }

    async fn get_key_if_present(&self, kid: &str) -> Option<DecodingKey> {
        let cache = self.inner.jwks.read().await;
        cache.keys_by_kid.get(kid).cloned()
    }

    async fn refresh_jwks_if_needed(&self, maybe_kid: Option<&str>) -> anyhow::Result<()> {
        let now = Instant::now();

        {
            let cache = self.inner.jwks.read().await;
            let stale = cache.next_refresh_after.is_none_or(|t| now >= t);
            let missing = maybe_kid
                .and_then(|kid| (!cache.keys_by_kid.contains_key(kid)).then_some(()))
                .is_some();
            if !stale && !missing {
                return Ok(());
            }
        }

        let mut cache = self.inner.jwks.write().await;
        let stale = cache.next_refresh_after.is_none_or(|t| now >= t);
        let missing = maybe_kid
            .and_then(|kid| (!cache.keys_by_kid.contains_key(kid)).then_some(()))
            .is_some();

        if !stale && !missing {
            return Ok(());
        }

        // Avoid tight refresh loops (e.g. attacker sends random kids).
        if let Some(last) = cache.last_refresh_attempt
            && now.duration_since(last) < MIN_REFRESH_INTERVAL
        {
            return Ok(());
        }
        cache.last_refresh_attempt = Some(now);

        let (keys_by_kid, cache_ttl) = fetch_jwks(&self.inner.http, &self.inner.jwks_uri).await?;
        cache.keys_by_kid = keys_by_kid;
        cache.fetched_at = Some(now);
        cache.next_refresh_after = Some(now + cache_ttl.unwrap_or(self.inner.refresh_after));

        Ok(())
    }
}

#[derive(Debug, Deserialize)]
struct OidcDiscovery {
    jwks_uri: String,
}

async fn discover_jwks_uri(http: &reqwest::Client, issuer: &str) -> anyhow::Result<String> {
    let issuer = issuer.trim_end_matches('/');
    let url = format!("{issuer}/.well-known/openid-configuration");
    let resp = http
        .get(&url)
        .send()
        .await
        .with_context(|| format!("GET discovery {url}"))?
        .error_for_status()
        .with_context(|| format!("discovery status {url}"))?;
    let doc: OidcDiscovery = resp.json().await.context("parse discovery json")?;
    if doc.jwks_uri.trim().is_empty() {
        anyhow::bail!("discovery returned empty jwks_uri");
    }
    // Require HTTPS for discovered endpoints. If you really need HTTP (e.g., local dev),
    // set `UNRELATED_GATEWAY_OIDC_JWKS_URI` explicitly to override discovery.
    let parsed = reqwest::Url::parse(&doc.jwks_uri).context("parse discovered jwks_uri")?;
    if parsed.scheme() != "https" {
        anyhow::bail!(
            "discovery returned non-https jwks_uri; set UNRELATED_GATEWAY_OIDC_JWKS_URI to override"
        );
    }
    Ok(doc.jwks_uri)
}

#[derive(Debug, Deserialize)]
struct JwksResponse {
    keys: Vec<Jwk>,
}

#[derive(Debug, Deserialize)]
struct Jwk {
    kty: String,
    #[serde(default)]
    kid: Option<String>,
    #[serde(rename = "use", default)]
    use_: Option<String>,
    // RSA public key params (base64url-encoded).
    #[serde(default)]
    n: Option<String>,
    #[serde(default)]
    e: Option<String>,
}

async fn fetch_jwks(
    http: &reqwest::Client,
    jwks_uri: &str,
) -> anyhow::Result<(HashMap<String, DecodingKey>, Option<Duration>)> {
    let resp = http
        .get(jwks_uri)
        .send()
        .await
        .with_context(|| format!("GET jwks {jwks_uri}"))?
        .error_for_status()
        .with_context(|| format!("jwks status {jwks_uri}"))?;

    let cache_ttl = parse_cache_control_max_age(resp.headers());
    let jwks: JwksResponse = resp.json().await.context("parse jwks json")?;

    let mut out: HashMap<String, DecodingKey> = HashMap::new();
    for k in jwks.keys {
        if k.kty != "RSA" {
            continue;
        }
        if let Some(use_) = &k.use_
            && use_ != "sig"
        {
            continue;
        }
        let Some(kid) = k.kid else { continue };
        let Some(n) = k.n else { continue };
        let Some(e) = k.e else { continue };

        // `jsonwebtoken` expects the JWK base64url-encoded components.
        let key = DecodingKey::from_rsa_components(&n, &e).context("build rsa decoding key")?;
        out.insert(kid, key);
    }

    if out.is_empty() {
        anyhow::bail!("jwks contains no usable RSA keys");
    }

    Ok((out, cache_ttl))
}

fn parse_cache_control_max_age(headers: &reqwest::header::HeaderMap) -> Option<Duration> {
    let v = headers.get(reqwest::header::CACHE_CONTROL)?.to_str().ok()?;
    for part in v.split(',').map(str::trim) {
        let Some(rest) = part.strip_prefix("max-age=") else {
            continue;
        };
        if let Ok(secs) = rest.parse::<u64>() {
            return Some(Duration::from_secs(secs));
        }
    }
    None
}

fn jwt_has_crit_header(jwt: &str) -> anyhow::Result<bool> {
    let mut parts = jwt.split('.');
    let header_b64 = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("invalid jwt (missing header part)"))?;
    if parts.next().is_none() {
        anyhow::bail!("invalid jwt (missing payload part)");
    }
    if parts.next().is_none() {
        anyhow::bail!("invalid jwt (missing signature part)");
    }
    if parts.next().is_some() {
        anyhow::bail!("invalid jwt (unexpected extra parts)");
    }

    let header_json = URL_SAFE_NO_PAD
        .decode(header_b64)
        .context("base64url decode jwt header")?;
    let header: serde_json::Value =
        serde_json::from_slice(&header_json).context("parse jwt header json")?;

    let header = header
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("invalid jwt header (expected JSON object)"))?;
    Ok(header.contains_key("crit"))
}
