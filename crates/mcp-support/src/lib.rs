//! Shared wire helpers for the Gateway and Adapter.
use base64::Engine as _;

pub mod headers;
pub mod timeouts;

const TEMPLATE_PREFIX: &str = "urn:unrelated:template:";

/// Namespace a template without encoding its RFC 6570 expressions. The same
/// route can be decoded after the client expands the template into a resource URI.
#[must_use]
pub fn resource_template_uri(source: &str, uri: &str) -> String {
    let source = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(source);
    format!("{TEMPLATE_PREFIX}{source}:{uri}")
}

/// Decode only the source; preserve the expanded URI byte for byte.
#[must_use]
pub fn parse_resource_template_uri(uri: &str) -> Option<(String, String)> {
    let (source, original) = uri.strip_prefix(TEMPLATE_PREFIX)?.split_once(':')?;
    if original.is_empty() {
        return None;
    }
    let source = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(source)
        .ok()?;
    let source = String::from_utf8(source).ok()?;
    if source.is_empty() {
        return None;
    }
    Some((source, original.to_owned()))
}

/// Stable storage identity for a tenant-owned Gateway upstream.
#[must_use]
pub fn tenant_upstream_id(tenant: &str, upstream: &str) -> String {
    use base64::Engine as _;
    let base64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    format!("tu1.{}.{}", base64.encode(tenant), base64.encode(upstream))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tenant_identity_is_unambiguous_and_matches_existing_storage() {
        assert_eq!(
            tenant_upstream_id("tenant", "source"),
            "tu1.dGVuYW50.c291cmNl"
        );
        assert_ne!(
            tenant_upstream_id("a.b", "c"),
            tenant_upstream_id("a", "b.c")
        );
    }

    #[test]
    fn routing_survives_expansion_and_gateway_chaining() {
        let template = resource_template_uri("tenant:source", "file:///notes/{id}{?format}");
        assert!(template.ends_with("{id}{?format}"));
        let expanded = template.replace("{id}{?format}", "a%2Fb?format=text");
        let chained = resource_template_uri("adapter", &expanded);
        let (source, inner) = parse_resource_template_uri(&chained).unwrap();
        assert_eq!(source, "adapter");
        assert_eq!(
            parse_resource_template_uri(&inner),
            Some((
                "tenant:source".into(),
                "file:///notes/a%2Fb?format=text".into()
            ))
        );
        assert!(parse_resource_template_uri("urn:unrelated:template:!!!:x").is_none());
    }
}
