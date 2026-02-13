use base64::Engine as _;
use hmac::Mac as _;
use rmcp::model::RequestId;
use sha2::Digest as _;

pub(super) const PROXIED_REQUEST_ID_PREFIX: &str = "unrelated.proxy";
pub(super) const PROXIED_REQUEST_ID_PREFIX_READABLE: &str = "unrelated.proxy.r";
pub(super) const PROXIED_REQUEST_ID_PREFIX_V2: &str = "unrelated.proxy2";
pub(super) const PROXIED_REQUEST_ID_PREFIX_V2_READABLE: &str = "unrelated.proxy2.r";
pub(super) const RESOURCE_URN_PREFIX: &str = "urn:unrelated-mcp-gateway:resource:";

type HmacSha256 = hmac::Hmac<sha2::Sha256>;
const PROXIED_REQUEST_ID_SIG_SEPARATOR: [u8; 1] = [0u8];

pub(super) fn make_proxied_request_id(
    ns: crate::store::RequestIdNamespacing,
    upstream_id: &str,
    original: &RequestId,
    proxy_key: Option<&[u8]>,
) -> RequestId {
    // Encode both parts so parsing is unambiguous even if upstream ids or original ids contain
    // arbitrary characters.
    let original_json = original.clone().into_json_value();
    let original_json_bytes = serde_json::to_vec(&original_json).unwrap_or_default();
    let original_b64 =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&original_json_bytes);

    if let Some(key) = proxy_key {
        let sig: Vec<u8> = if let Ok(mut mac) = HmacSha256::new_from_slice(key) {
            mac.update(upstream_id.as_bytes());
            mac.update(&PROXIED_REQUEST_ID_SIG_SEPARATOR);
            mac.update(&original_json_bytes);
            mac.finalize().into_bytes().to_vec()
        } else {
            Vec::new()
        };
        let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig);

        match ns {
            crate::store::RequestIdNamespacing::Opaque => {
                let upstream_b64 =
                    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(upstream_id);
                RequestId::String(
                    format!(
                        "{PROXIED_REQUEST_ID_PREFIX_V2}.{upstream_b64}.{original_b64}.{sig_b64}"
                    )
                    .into(),
                )
            }
            crate::store::RequestIdNamespacing::Readable => RequestId::String(
                format!(
                    "{PROXIED_REQUEST_ID_PREFIX_V2_READABLE}.{upstream_id}.{original_b64}.{sig_b64}"
                )
                .into(),
            ),
        }
    } else {
        // Legacy (unsigned) format.
        match ns {
            crate::store::RequestIdNamespacing::Opaque => {
                let upstream_b64 =
                    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(upstream_id);
                RequestId::String(
                    format!("{PROXIED_REQUEST_ID_PREFIX}.{upstream_b64}.{original_b64}").into(),
                )
            }
            crate::store::RequestIdNamespacing::Readable => RequestId::String(
                format!("{PROXIED_REQUEST_ID_PREFIX_READABLE}.{upstream_id}.{original_b64}").into(),
            ),
        }
    }
}

pub(super) fn parse_proxied_request_id(
    id: &RequestId,
    proxy_key: Option<&[u8]>,
) -> Option<(String, RequestId)> {
    let RequestId::String(s) = id else {
        return None;
    };
    let s = s.as_ref();

    if let Some(key) = proxy_key {
        // Signed v2 format (required when proxy_key is present).
        let (upstream_id, original_b64, sig_b64) = if let Some(rest) =
            s.strip_prefix(&format!("{PROXIED_REQUEST_ID_PREFIX_V2_READABLE}."))
        {
            // Readable v2: unrelated.proxy2.r.<upstream_id>.<b64(original)>.<b64(sig)>
            let (rest, sig_b64) = rest.rsplit_once('.')?;
            let (upstream_id, original_b64) = rest.rsplit_once('.')?;
            (upstream_id.to_string(), original_b64, sig_b64)
        } else if let Some(rest) = s.strip_prefix(&format!("{PROXIED_REQUEST_ID_PREFIX_V2}.")) {
            // Opaque v2: unrelated.proxy2.<b64(upstream)>.<b64(original)>.<b64(sig)>
            let (upstream_b64, rest) = rest.split_once('.')?;
            let (original_b64, sig_b64) = rest.split_once('.')?;
            let upstream_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(upstream_b64.as_bytes())
                .ok()?;
            let upstream_id = String::from_utf8(upstream_bytes).ok()?;
            (upstream_id, original_b64, sig_b64)
        } else {
            return None;
        };

        let sig_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(sig_b64.as_bytes())
            .ok()?;
        let original_json_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(original_b64.as_bytes())
            .ok()?;

        let mut mac = HmacSha256::new_from_slice(key).ok()?;
        mac.update(upstream_id.as_bytes());
        mac.update(&PROXIED_REQUEST_ID_SIG_SEPARATOR);
        mac.update(&original_json_bytes);
        mac.verify_slice(&sig_bytes).ok()?;

        let original_json: serde_json::Value = serde_json::from_slice(&original_json_bytes).ok()?;
        let original: RequestId = serde_json::from_value(original_json).ok()?;
        return Some((upstream_id, original));
    }

    // Legacy v1 (unsigned) format (only accepted when proxy_key is not present).
    //
    // IMPORTANT: check readable first, since its prefix is a strict extension of the opaque prefix.
    // If we check opaque first, "unrelated.proxy.r.*" would incorrectly match the opaque branch.
    let (upstream_id, original_b64) =
        if let Some(rest) = s.strip_prefix(&format!("{PROXIED_REQUEST_ID_PREFIX_READABLE}.")) {
            // Readable: unrelated.proxy.r.<upstream_id>.<b64(original)>
            let (upstream_id, original_b64) = rest.rsplit_once('.')?;
            (upstream_id.to_string(), original_b64)
        } else if let Some(rest) = s.strip_prefix(&format!("{PROXIED_REQUEST_ID_PREFIX}.")) {
            // Opaque: unrelated.proxy.<b64(upstream)>.<b64(original)>
            let (upstream_b64, original_b64) = rest.split_once('.')?;
            let upstream_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(upstream_b64.as_bytes())
                .ok()?;
            let upstream_id = String::from_utf8(upstream_bytes).ok()?;
            (upstream_id, original_b64)
        } else {
            return None;
        };

    let original_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(original_b64.as_bytes())
        .ok()?;
    let original_json: serde_json::Value = serde_json::from_slice(&original_bytes).ok()?;
    let original: RequestId = serde_json::from_value(original_json).ok()?;
    Some((upstream_id, original))
}

pub(super) fn parse_resource_collision_urn(uri: &str) -> Option<(&str, &str)> {
    uri.strip_prefix(RESOURCE_URN_PREFIX)
        .and_then(|rest| rest.split_once(':'))
}

pub(super) fn resource_collision_urn(upstream_id: &str, original_uri: &str) -> String {
    let hash = hex::encode(sha2::Sha256::digest(original_uri.as_bytes()));
    format!("{RESOURCE_URN_PREFIX}{upstream_id}:{hash}")
}
