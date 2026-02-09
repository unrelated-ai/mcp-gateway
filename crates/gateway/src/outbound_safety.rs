use std::collections::HashSet;
use unrelated_http_tools::safety::OutboundHttpSafety;

fn env_flag(name: &str) -> bool {
    matches!(
        std::env::var(name)
            .unwrap_or_default()
            .to_ascii_lowercase()
            .as_str(),
        "1" | "true" | "yes" | "on"
    )
}

fn env_csv_set(name: &str) -> Option<HashSet<String>> {
    let raw = std::env::var(name).ok()?;
    let set: HashSet<String> = raw
        .split(',')
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect();
    (!set.is_empty()).then_some(set)
}

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

    if env_flag("UNRELATED_GATEWAY_OUTBOUND_ALLOW_PRIVATE_NETWORKS") {
        safety.allow_private_networks = true;
    }

    if let Some(set) = env_csv_set("UNRELATED_GATEWAY_OUTBOUND_ALLOWED_HOSTS") {
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
