use crate::store::{UpstreamEndpoint, UpstreamNetworkClass};

pub async fn validate_upstream_endpoints(
    network_class: UpstreamNetworkClass,
    endpoints: &[UpstreamEndpoint],
) -> Result<(), String> {
    let safety = crate::outbound_safety::gateway_outbound_http_safety_for_class(network_class);
    for ep in endpoints {
        crate::outbound_safety::check_upstream_scheme_policy_for_class(network_class, &ep.url)
            .map_err(|e| {
                format!(
                    "upstream endpoint '{}' rejected by scheme policy: {e}",
                    ep.id
                )
            })?;
        crate::outbound_safety::check_url_allowed(&safety, &ep.url)
            .await
            .map_err(|e| {
                format!(
                    "upstream endpoint '{}' blocked by outbound safety: {e}",
                    ep.id
                )
            })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::UpstreamEndpointLifecycle;

    fn endpoint(id: &str, url: &str) -> UpstreamEndpoint {
        UpstreamEndpoint {
            id: id.to_string(),
            url: url.to_string(),
            enabled: true,
            lifecycle: UpstreamEndpointLifecycle::Active,
            auth: None,
        }
    }

    #[tokio::test]
    async fn external_endpoints_reject_http_scheme() {
        let endpoints = vec![endpoint("e1", "http://example.com/mcp")];
        let err = validate_upstream_endpoints(UpstreamNetworkClass::External, &endpoints)
            .await
            .expect_err("external should reject http by default");
        assert!(err.contains("scheme policy"));
    }

    #[tokio::test]
    async fn cluster_internal_managed_endpoints_allow_http_scheme() {
        let endpoints = vec![endpoint("e1", "http://localhost:8080/mcp")];
        validate_upstream_endpoints(UpstreamNetworkClass::ClusterInternalManaged, &endpoints)
            .await
            .expect("cluster-internal-managed should allow http");
    }
}
