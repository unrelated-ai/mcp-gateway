use unrelated_http_tools::safety::OutboundHttpSafety;

/// Outbound HTTP safety policy for the Gateway.
///
/// Default is restrictive (SSRF hardening). For local development/testing you can opt into
/// allowing private networks.
///
/// Env:
/// - `UNRELATED_GATEWAY_OUTBOUND_ALLOW_PRIVATE_NETWORKS=1` to allow RFC1918/loopback/link-local.
/// - `UNRELATED_GATEWAY_OUTBOUND_ALLOWED_HOSTS=host1,host2` to restrict hosts (case-insensitive).
#[must_use]
pub fn gateway_outbound_http_safety() -> OutboundHttpSafety {
    let mut safety = OutboundHttpSafety::gateway_default();

    // Unit tests commonly spin up mock services on loopback. Allow private networks in tests so
    // outbound safety hardening does not break local test servers.
    #[cfg(test)]
    {
        safety.allow_private_networks = true;
    }

    if unrelated_env::flag("UNRELATED_GATEWAY_OUTBOUND_ALLOW_PRIVATE_NETWORKS") {
        safety.allow_private_networks = true;
    }

    if let Some(set) = unrelated_env::csv_set_lower("UNRELATED_GATEWAY_OUTBOUND_ALLOWED_HOSTS") {
        safety.allowed_hosts = Some(set);
    }

    safety
}

/// Validate a URL against the provided outbound safety policy.
///
/// This is a small helper wrapper around `OutboundHttpSafety::check_url` so call sites can share
/// consistent parsing + error strings.
pub async fn check_url_allowed(safety: &OutboundHttpSafety, url: &str) -> Result<(), String> {
    let u = reqwest::Url::parse(url).map_err(|e| format!("invalid URL: {e}"))?;
    safety.check_url(&u).await.map_err(|e| e.to_string())?;
    Ok(())
}

/// Process-level policy for upstream MCP endpoint URL schemes.
///
/// Default posture: require `https://` for upstream endpoints.
///
/// Dev override:
/// - set `UNRELATED_GATEWAY_UPSTREAM_ALLOW_HTTP=1` to allow `http://` upstream endpoints
#[must_use]
pub fn upstream_allows_http() -> bool {
    unrelated_env::flag("UNRELATED_GATEWAY_UPSTREAM_ALLOW_HTTP")
}

/// Enforce the upstream HTTPS policy for a candidate endpoint URL.
pub fn check_upstream_https_policy(url: &str) -> Result<(), String> {
    let u = reqwest::Url::parse(url).map_err(|e| format!("invalid URL: {e}"))?;
    match u.scheme() {
        "https" => Ok(()),
        "http" => {
            // Unit tests commonly spin up mock upstreams on loopback via plain HTTP. Allow that in
            // tests without requiring process-global env mutation (which is unsafe to do in
            // multi-threaded test runners).
            #[cfg(test)]
            {
                if let Some(host) = u.host_str() {
                    if host.eq_ignore_ascii_case("localhost") {
                        return Ok(());
                    }
                    if let Ok(ip) = host.parse::<std::net::IpAddr>()
                        && ip.is_loopback()
                    {
                        return Ok(());
                    }
                }
            }

            if upstream_allows_http() {
                Ok(())
            } else {
                Err("upstream endpoint must use https (dev override: UNRELATED_GATEWAY_UPSTREAM_ALLOW_HTTP=1)".to_string())
            }
        }
        other => Err(format!(
            "unsupported upstream URL scheme '{other}' (expected https)"
        )),
    }
}
