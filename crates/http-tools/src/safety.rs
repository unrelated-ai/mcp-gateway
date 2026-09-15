//! Outbound HTTP safety controls (SSRF protection, limits, redaction).
//!
//! Consumers choose a policy and build their HTTP client with `client_builder`:
//! - Adapter (standalone): typically permissive
//! - Gateway (multi-tenant): typically restrictive

use crate::runtime::HttpToolsError;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::lookup_host;
use url::Url;

#[derive(Debug, Clone)]
pub enum RedirectPolicy {
    /// Do not follow redirects.
    None,
    /// Follow redirects, but re-check the destination URL on each hop.
    Checked,
}

#[derive(Debug, Clone)]
pub struct OutboundHttpSafety {
    /// If set, only these hosts are allowed (case-insensitive).
    pub allowed_hosts: Option<HashSet<String>>,
    /// If true, allow private/loopback/link-local/reserved destination IPs.
    pub allow_private_networks: bool,
    /// Maximum response body size (bytes). `None` = unlimited.
    pub max_response_bytes: Option<usize>,
    /// Redirect behavior.
    pub redirects: RedirectPolicy,
}

impl OutboundHttpSafety {
    /// Build a client that validates the DNS addresses actually used by its connector.
    ///
    /// Call `check_url` before the initial request to also enforce scheme, host allowlist,
    /// and IP-literal restrictions. DNS checks at configuration time alone cannot prevent
    /// rebinding. Keep the original URL so Host, TLS SNI, and certificate checks are preserved.
    /// System proxies are disabled when destinations are restricted: a proxy could resolve
    /// the destination independently. Fully permissive Adapter policies retain proxy support.
    pub fn client_builder(&self) -> reqwest::ClientBuilder {
        let safety = self.clone();
        let redirects = match self.redirects {
            RedirectPolicy::None => reqwest::redirect::Policy::none(),
            RedirectPolicy::Checked => reqwest::redirect::Policy::custom(move |attempt| {
                if attempt.previous().len() >= 10 {
                    return attempt.error("too many redirects");
                }
                // DNS names are checked by the connector. IP literals bypass DNS, so they
                // must also be validated here before following a redirect.
                match safety.check_url_host(attempt.url()) {
                    Ok(()) => attempt.follow(),
                    Err(error) => attempt.error(error),
                }
            }),
        };
        let builder = reqwest::Client::builder()
            .dns_resolver(Arc::new(SafetyResolver {
                safety: self.clone(),
            }))
            .redirect(redirects);
        if !self.allow_private_networks || self.allowed_hosts.is_some() {
            builder.no_proxy()
        } else {
            builder
        }
    }

    /// Most permissive policy (intended for the Adapter).
    #[must_use]
    pub fn permissive() -> Self {
        Self {
            allowed_hosts: None,
            allow_private_networks: true,
            max_response_bytes: None,
            redirects: RedirectPolicy::Checked,
        }
    }

    /// Safer default policy for multi-tenant environments (intended for the Gateway).
    #[must_use]
    pub fn gateway_default() -> Self {
        Self {
            allowed_hosts: None,
            allow_private_networks: false,
            max_response_bytes: Some(1024 * 1024), // 1 MiB
            redirects: RedirectPolicy::None,
        }
    }

    /// Validate a URL before making an outbound request with a policy-aware client.
    ///
    /// This rejects non-`http(s)` schemes and applies host/IP restrictions. This preflight
    /// check is not sufficient on its own: requests must use `client_builder` so a later
    /// DNS answer is validated at connection time, including reconnects and redirects.
    ///
    /// # Errors
    ///
    /// Returns an error if the URL is disallowed by the policy (unsupported scheme, host not in
    /// allowlist, or hostname resolves to a disallowed IP range).
    pub async fn check_url(&self, url: &Url) -> Result<(), HttpToolsError> {
        self.check_url_host(url)?;
        if self.allow_private_networks {
            return Ok(());
        }
        if let Some(url::Host::Domain(host)) = url.host() {
            let port = url.port_or_known_default().unwrap_or(443);
            let addrs: Vec<_> = lookup_host((host, port))
                .await
                .map_err(|e| {
                    HttpToolsError::Http(format!("DNS lookup failed for host '{host}': {e}"))
                })?
                .collect();
            self.check_addresses(host, &addrs)?;
        }
        Ok(())
    }

    fn check_url_host(&self, url: &Url) -> Result<(), HttpToolsError> {
        let scheme = url.scheme();
        if scheme != "http" && scheme != "https" {
            return Err(HttpToolsError::Http(format!(
                "Outbound HTTP blocked: unsupported URL scheme '{scheme}'"
            )));
        }

        let Some(host) = url.host_str() else {
            return Err(HttpToolsError::Http(
                "Outbound HTTP blocked: missing URL host".to_string(),
            ));
        };

        if let Some(allowed) = &self.allowed_hosts
            && !allowed.contains(&host.to_ascii_lowercase())
        {
            return Err(HttpToolsError::Http(format!(
                "Outbound HTTP blocked: host '{host}' not in allowlist"
            )));
        }

        if self.allow_private_networks {
            return Ok(());
        }

        let ip = match url.host() {
            Some(url::Host::Ipv4(ip)) => Some(IpAddr::V4(ip)),
            Some(url::Host::Ipv6(ip)) => Some(IpAddr::V6(ip)),
            _ => None,
        };
        if let Some(ip) = ip
            && is_denied_ip(ip)
        {
            return Err(HttpToolsError::Http(format!(
                "Outbound HTTP blocked: destination IP '{ip}' is not allowed"
            )));
        }
        Ok(())
    }

    fn check_addresses(&self, host: &str, addrs: &[SocketAddr]) -> Result<(), HttpToolsError> {
        for addr in addrs {
            if !self.allow_private_networks && is_denied_ip(addr.ip()) {
                return Err(HttpToolsError::Http(format!(
                    "Outbound HTTP blocked: host '{host}' resolved to disallowed IP '{}'",
                    addr.ip()
                )));
            }
        }

        if addrs.is_empty() {
            return Err(HttpToolsError::Http(format!(
                "DNS lookup returned no addresses for host '{host}'"
            )));
        }

        Ok(())
    }
}

struct SafetyResolver {
    safety: OutboundHttpSafety,
}

impl Resolve for SafetyResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let safety = self.safety.clone();
        Box::pin(async move {
            let addrs: Vec<_> = lookup_host((name.as_str(), 0)).await?.collect();
            // Validate the entire set before returning any addresses. These exact socket
            // addresses go to reqwest's connector; there is no second unchecked lookup.
            safety.check_addresses(name.as_str(), &addrs)?;
            Ok(Box::new(addrs.into_iter()) as Addrs)
        })
    }
}

#[must_use]
pub fn redact_url(url: &Url) -> String {
    let mut u = url.clone();
    // Best-effort: drop credentials + query + fragment.
    let _ = u.set_username("");
    let _ = u.set_password(None);
    u.set_query(None);
    u.set_fragment(None);
    u.to_string()
}

#[must_use]
pub fn sanitize_reqwest_error(e: &reqwest::Error) -> String {
    let mut msg = e.to_string();
    if let Some(u) = e.url() {
        msg = msg.replace(u.as_str(), &redact_url(u));
    }
    msg
}

fn is_denied_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_denied_ipv4(v4),
        IpAddr::V6(v6) => is_denied_ipv6(v6),
    }
}

fn is_denied_ipv4(ip: Ipv4Addr) -> bool {
    // Disallow:
    // - loopback
    // - private
    // - link-local (incl. metadata IPs like 169.254.169.254)
    // - unspecified/broadcast
    // - multicast
    // - CGNAT (100.64.0.0/10)
    // - reserved (240.0.0.0/4)
    if ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_multicast()
    {
        return true;
    }

    // Carrier-grade NAT range.
    let oct = ip.octets();
    if oct[0] == 100 && (64..=127).contains(&oct[1]) {
        return true;
    }

    // Reserved / future use.
    if oct[0] >= 240 {
        return true;
    }

    false
}

fn is_denied_ipv6(ip: Ipv6Addr) -> bool {
    if let Some(ipv4) = ip.to_ipv4_mapped() {
        return is_denied_ipv4(ipv4);
    }
    ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || ip.is_unique_local()
        || ip.is_unicast_link_local()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn restrictive_policy_blocks_loopback() {
        let safety = OutboundHttpSafety::gateway_default();
        let url = Url::parse("http://127.0.0.1:1234/").expect("url");
        let err = safety.check_url(&url).await.unwrap_err();
        assert!(err.to_string().contains("blocked"));
    }

    #[tokio::test]
    async fn permissive_policy_allows_loopback() {
        let safety = OutboundHttpSafety::permissive();
        let url = Url::parse("http://127.0.0.1:1234/").expect("url");
        safety.check_url(&url).await.expect("allowed");
    }

    #[tokio::test]
    async fn restrictive_policy_blocks_ipv6_and_mapped_private_literals() {
        for host in [
            "[::1]",
            "[::]",
            "[fc00::1]",
            "[fe80::1]",
            "[::ffff:127.0.0.1]",
            "[::ffff:169.254.169.254]",
            "[::ffff:10.0.0.1]",
        ] {
            let url = Url::parse(&format!("http://{host}:8081/")).unwrap();
            assert!(
                OutboundHttpSafety::gateway_default()
                    .check_url(&url)
                    .await
                    .is_err(),
                "{host}"
            );
            OutboundHttpSafety::permissive()
                .check_url(&url)
                .await
                .unwrap();
        }
    }

    #[test]
    fn dns_answers_fail_closed_on_empty_or_any_disallowed_address() {
        let safety = OutboundHttpSafety::gateway_default();
        let public: SocketAddr = "203.0.113.10:0".parse().unwrap();
        assert!(safety.check_addresses("test", &[]).is_err());
        safety.check_addresses("test", &[public]).unwrap();
        for ip in [
            "127.0.0.1:0",
            "10.0.0.1:0",
            "169.254.169.254:0",
            "[::1]:0",
            "[::ffff:127.0.0.1]:0",
        ] {
            let private = ip.parse().unwrap();
            assert!(safety.check_addresses("test", &[public, private]).is_err());
            assert!(safety.check_addresses("test", &[private, public]).is_err());
            OutboundHttpSafety::permissive()
                .check_addresses("test", &[public, private])
                .unwrap();
        }
    }

    #[tokio::test]
    async fn checked_redirects_validate_literal_ips_and_host_allowlists() {
        use axum::{Router, response::Redirect, routing::get};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new().route(
            "/",
            get(|| async { Redirect::temporary("http://127.0.0.1:8081/secret") }),
        );
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let mut safety = OutboundHttpSafety::gateway_default();
        safety.redirects = RedirectPolicy::Checked;
        for allow_private in [false, true] {
            safety.allow_private_networks = allow_private;
            safety.allowed_hosts = Some(HashSet::from(["redirect.test".to_string()]));
            // A test-only DNS override supplies the initial local redirect server. The
            // redirect target must still be rejected before opening a connection.
            let client = safety
                .client_builder()
                .resolve("redirect.test", addr)
                .build()
                .unwrap();
            let error = client
                .get(format!("http://redirect.test:{}/", addr.port()))
                .send()
                .await
                .unwrap_err();
            assert!(error.is_redirect());
        }
        // Also check IP restrictions independently of the host allowlist.
        safety.allowed_hosts = None;
        safety.allow_private_networks = false;
        let client = safety
            .client_builder()
            .resolve("redirect.test", addr)
            .build()
            .unwrap();
        assert!(
            client
                .get(format!("http://redirect.test:{}/", addr.port()))
                .send()
                .await
                .unwrap_err()
                .is_redirect()
        );
        task.abort();
    }
}
