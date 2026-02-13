use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use rusty_paseto::prelude::{
    CustomClaim, ExpirationClaim, Footer, IssuedAtClaim, Key, Local, NotBeforeClaim, PasetoBuilder,
    PasetoParser, PasetoSymmetricKey, V4,
};

type HmacSha256 = hmac::Hmac<Sha256>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionTokenVerifyErrorKind {
    Expired,
    Invalid,
}

#[derive(Debug, Clone)]
pub struct SessionTokenVerifyError {
    pub kind: SessionTokenVerifyErrorKind,
}

impl std::fmt::Display for SessionTokenVerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.kind {
            SessionTokenVerifyErrorKind::Expired => write!(f, "session token expired"),
            SessionTokenVerifyErrorKind::Invalid => write!(f, "invalid session token"),
        }
    }
}

impl std::error::Error for SessionTokenVerifyError {}

fn session_token_err(kind: SessionTokenVerifyErrorKind) -> anyhow::Error {
    anyhow::Error::new(SessionTokenVerifyError { kind })
}

/// PASETO-based codec for Gateway session tokens (`Mcp-Session-Id`).
///
/// This replaces the legacy sign-only HMAC token with a standard, audited token format:
/// - **v4.local** (symmetric, encrypted+authenticated)
/// - optional **footer** carrying a `kid` for key rotation (authenticated but not encrypted)
///
/// Note: this token is **not** a user auth token. It's a routing token that encodes upstream
/// session bindings so any Gateway node can route requests in HA deployments.
#[derive(Clone)]
pub struct SessionSigner {
    keys: Vec<KeyEntry>,
    ttl: Duration,
}

impl SessionSigner {
    /// Create a signer with one or more secrets and a token TTL.
    ///
    /// - The **first** secret is used for minting new tokens.
    /// - All secrets are accepted for verification (rotation support).
    ///
    /// Secrets can be any bytes; they are deterministically expanded to 32-byte v4.local keys
    /// via SHA-256.
    pub fn new(secrets: Vec<Vec<u8>>, ttl: Duration) -> anyhow::Result<Self> {
        if secrets.is_empty() {
            anyhow::bail!("session token secrets must be non-empty");
        }
        let keys = secrets
            .into_iter()
            .map(|s| KeyEntry::from_secret_bytes(&s))
            .collect::<Vec<_>>();
        Ok(Self { keys, ttl })
    }

    /// Mint a new session token.
    ///
    /// This updates `iat`/`exp` based on `ttl`.
    pub fn sign(&self, mut payload: TokenPayloadV1) -> anyhow::Result<String> {
        let now = SystemTime::now();
        let now_secs = unix_epoch_secs(now)?;
        payload.iat = Some(now_secs);
        payload.exp = Some(now_secs.saturating_add(self.ttl.as_secs()));

        let key = &self.keys[0];
        let json = serde_json::to_value(&payload)?;

        // Align standard PASETO time claims with our unix-second fields.
        let iat_ts: i64 = i64::try_from(now_secs).map_err(|_| anyhow::anyhow!("invalid iat"))?;
        let exp_secs_u64 = payload.exp.unwrap_or(now_secs);
        let exp_ts: i64 =
            i64::try_from(exp_secs_u64).map_err(|_| anyhow::anyhow!("invalid exp"))?;
        let iat = OffsetDateTime::from_unix_timestamp(iat_ts)
            .map_err(|_| anyhow::anyhow!("invalid iat"))?;
        let exp = OffsetDateTime::from_unix_timestamp(exp_ts)
            .map_err(|_| anyhow::anyhow!("invalid exp"))?;
        let iat = iat
            .format(&Rfc3339)
            .map_err(|_| anyhow::anyhow!("format iat"))?;
        let exp = exp
            .format(&Rfc3339)
            .map_err(|_| anyhow::anyhow!("format exp"))?;

        let token = PasetoBuilder::<V4, Local>::default()
            .set_claim(CustomClaim::try_from(("payload", json))?)
            .set_claim(IssuedAtClaim::try_from(iat.as_str())?)
            .set_claim(NotBeforeClaim::try_from(iat.as_str())?)
            .set_claim(ExpirationClaim::try_from(exp.as_str())?)
            .set_footer(Footer::from(key.kid.as_str()))
            .build(key.key.as_ref())?;

        Ok(token)
    }

    pub fn verify(&self, token: &str) -> anyhow::Result<TokenPayloadV1> {
        // 1) Try v4.local PASETO tokens first (new format).
        if token.starts_with("v4.local.") {
            return self.verify_paseto_v4_local(token);
        }

        // 2) Legacy format support (sign-only HMAC token) for smoother rollouts.
        self.verify_legacy_v1(token)
    }

    fn verify_paseto_v4_local(&self, token: &str) -> anyhow::Result<TokenPayloadV1> {
        // Extract footer (kid) if present: v4.local.<payload>[.<footer>]
        let kid = extract_paseto_footer_kid(token);

        // Candidate keys: if kid provided, try that first; otherwise try all.
        let candidates: Vec<&KeyEntry> = if let Some(ref k) = kid {
            let mut out: Vec<&KeyEntry> = self.keys.iter().filter(|e| e.kid == *k).collect();
            if out.is_empty() {
                // Unknown kid: still try all keys (helps during rotation/config mistakes).
                out = self.keys.iter().collect();
            }
            out
        } else {
            self.keys.iter().collect()
        };
        for key in candidates {
            // `default()` validates exp/nbf and would fail parsing for expired tokens, which makes it
            // hard to provide a precise error to callers. We parse first and enforce expiry using
            // our own unix-second `payload.exp` field.
            let mut parser = PasetoParser::<V4, Local>::new();
            if let Some(ref k) = kid {
                parser.set_footer(Footer::from(k.as_str()));
            }
            if let Ok(claims) = parser.parse(token, key.key.as_ref()) {
                let payload_value = claims
                    .get("payload")
                    .cloned()
                    .ok_or_else(|| anyhow::anyhow!("missing payload claim"))?;
                let payload: TokenPayloadV1 = serde_json::from_value(payload_value)?;
                Self::enforce_exp(&payload)?;
                return Ok(payload);
            }
        }

        Err(session_token_err(SessionTokenVerifyErrorKind::Invalid))
    }

    fn enforce_exp(payload: &TokenPayloadV1) -> anyhow::Result<()> {
        let now_secs = unix_epoch_secs(SystemTime::now())?;
        let exp = payload.exp.ok_or_else(|| anyhow::anyhow!("missing exp"))?;
        if now_secs > exp {
            return Err(session_token_err(SessionTokenVerifyErrorKind::Expired));
        }
        Ok(())
    }

    fn verify_legacy_v1(&self, token: &str) -> anyhow::Result<TokenPayloadV1> {
        // Legacy format: v1.<base64url(payload_json)>.<base64url(hmac_sha256(payload_b64))>
        // We keep it for a migration window. It does NOT have exp/iat.
        use hmac::Mac as _;
        let (version, rest) = token
            .split_once('.')
            .ok_or_else(|| anyhow::anyhow!("invalid token format"))?;
        if version != "v1" {
            return Err(anyhow::anyhow!("unsupported token version: {version}"));
        }
        let (payload_b64, sig_b64) = rest
            .split_once('.')
            .ok_or_else(|| anyhow::anyhow!("invalid token format"))?;
        let got = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(sig_b64)
            .map_err(|_| anyhow::anyhow!("invalid token signature encoding"))?;

        let mut mac = HmacSha256::new_from_slice(self.keys[0].raw_secret.as_slice())
            .map_err(|_| anyhow::anyhow!("invalid HMAC key"))?;
        mac.update(payload_b64.as_bytes());
        mac.verify_slice(&got)
            .map_err(|_| anyhow::anyhow!("invalid token signature"))?;

        let payload_json = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload_b64)
            .map_err(|_| anyhow::anyhow!("invalid token payload encoding"))?;
        let payload: TokenPayloadV1 = serde_json::from_slice(&payload_json)?;
        Ok(payload)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenPayloadV1 {
    pub profile_id: String,
    pub bindings: Vec<UpstreamSessionBinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<TokenAuthV1>,
    /// Optional OIDC principal binding for `jwtEveryRequest` data-plane auth.
    ///
    /// When present, the Gateway will reject requests whose bearer JWT principal does not match.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oidc: Option<TokenOidcV1>,
    /// Issued-at (unix seconds). Present for PASETO tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iat: Option<u64>,
    /// Expiry (unix seconds). Present for PASETO tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exp: Option<u64>,
    /// Per-session proxy signing key (base64url, no padding).
    ///
    /// When present, the Gateway uses it to sign proxied upstream server→client request IDs and to
    /// validate downstream responses/cancellations for those IDs (mitigates forged responses from
    /// malicious downstream clients).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenAuthV1 {
    pub tenant_id: String,
    pub api_key_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenOidcV1 {
    pub issuer: String,
    pub subject: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpstreamSessionBinding {
    pub upstream: String,
    pub endpoint: String,
    pub session: String,
}

struct KeyEntry {
    kid: String,
    key: Arc<
        rusty_paseto::prelude::PasetoSymmetricKey<
            rusty_paseto::prelude::V4,
            rusty_paseto::prelude::Local,
        >,
    >,
    // Keep raw secret bytes so we can derive a legacy HMAC key for migration only.
    raw_secret: Vec<u8>,
}

impl KeyEntry {
    fn from_secret_bytes(secret: &[u8]) -> Self {
        // v4.local requires 32 bytes.
        let derived = Sha256::digest(secret);
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&derived);

        let kid = {
            // Short, stable identifier used in footer for rotation.
            let kid_hash = Sha256::digest(key_bytes);
            hex::encode(&kid_hash[..8])
        };

        Self {
            kid,
            key: Arc::new(PasetoSymmetricKey::<V4, Local>::from(Key::<32>::from(
                key_bytes,
            ))),
            raw_secret: secret.to_vec(),
        }
    }
}

impl Clone for KeyEntry {
    fn clone(&self) -> Self {
        Self {
            kid: self.kid.clone(),
            key: self.key.clone(),
            raw_secret: self.raw_secret.clone(),
        }
    }
}

fn unix_epoch_secs(t: SystemTime) -> anyhow::Result<u64> {
    t.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| anyhow::anyhow!("system time before unix epoch"))
}

fn extract_paseto_footer_kid(token: &str) -> Option<String> {
    // PASETO tokens are dot-separated. With footer: v4.local.<payload>.<footer>
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    // Footer is base64url-encoded bytes.
    let footer_b64 = parts[3];
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(footer_b64.as_bytes())
        .ok()?;
    String::from_utf8(bytes).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hmac::Mac as _;

    #[test]
    fn token_roundtrip() {
        let signer =
            SessionSigner::new(vec![b"secret".to_vec()], Duration::from_secs(60)).expect("signer");
        let payload = TokenPayloadV1 {
            profile_id: "p1".to_string(),
            bindings: vec![UpstreamSessionBinding {
                upstream: "u1".to_string(),
                endpoint: "e1".to_string(),
                session: "s1".to_string(),
            }],
            auth: Some(TokenAuthV1 {
                tenant_id: "t1".to_string(),
                api_key_id: "k1".to_string(),
            }),
            oidc: None,
            iat: None,
            exp: None,
            proxy_key: None,
        };

        let token = signer.sign(payload).expect("token");
        let decoded = signer.verify(&token).expect("verify");
        assert_eq!(decoded.profile_id, "p1");
        assert_eq!(decoded.bindings.len(), 1);
        assert_eq!(decoded.bindings[0].upstream, "u1");
        assert_eq!(decoded.auth.unwrap().tenant_id, "t1");
    }

    #[test]
    fn verify_rejects_unknown_version() {
        let signer =
            SessionSigner::new(vec![b"secret".to_vec()], Duration::from_secs(60)).expect("signer");
        let err = signer.verify("v2.payload.sig").unwrap_err().to_string();
        assert!(err.contains("unsupported token version"));
    }

    #[test]
    fn verify_rejects_invalid_format() {
        let signer =
            SessionSigner::new(vec![b"secret".to_vec()], Duration::from_secs(60)).expect("signer");
        let err = signer.verify("not-a-token").unwrap_err().to_string();
        // It's not a PASETO token and not a legacy token either.
        assert!(err.contains("invalid token format") || err.contains("invalid session token"));
    }

    #[test]
    fn verify_rejects_bad_signature_encoding() {
        let signer =
            SessionSigner::new(vec![b"secret".to_vec()], Duration::from_secs(60)).expect("signer");
        let payload = TokenPayloadV1 {
            profile_id: "p1".to_string(),
            bindings: vec![],
            auth: None,
            oidc: None,
            iat: None,
            exp: None,
            proxy_key: None,
        };
        let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&payload).unwrap());
        let token = format!("v1.{payload_b64}.@@@"); // invalid base64
        let err = signer.verify(&token).unwrap_err().to_string();
        assert!(err.contains("signature encoding"));
    }

    #[test]
    fn verify_rejects_bad_payload_encoding() {
        let signer =
            SessionSigner::new(vec![b"secret".to_vec()], Duration::from_secs(60)).expect("signer");

        // Sign the "payload" bytes, but payload is not valid base64 for JSON.
        let payload_b64 = "!!!notbase64!!!";
        let mut mac = HmacSha256::new_from_slice(b"secret").unwrap();
        mac.update(payload_b64.as_bytes());
        let sig = mac.finalize().into_bytes();
        let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig);
        let token = format!("v1.{payload_b64}.{sig_b64}");

        let err = signer.verify(&token).unwrap_err().to_string();
        assert!(err.contains("payload encoding"));
    }

    #[test]
    fn verify_rejects_tampered_payload() {
        let signer =
            SessionSigner::new(vec![b"secret".to_vec()], Duration::from_secs(60)).expect("signer");
        let payload = TokenPayloadV1 {
            profile_id: "p1".to_string(),
            bindings: vec![UpstreamSessionBinding {
                upstream: "u1".to_string(),
                endpoint: "e1".to_string(),
                session: "s1".to_string(),
            }],
            auth: None,
            oidc: None,
            iat: None,
            exp: None,
            proxy_key: None,
        };
        // Create a legacy token and then tamper it.
        let legacy = {
            // Legacy signer: raw secret bytes as HMAC key.
            let payload_json = serde_json::to_vec(&payload).unwrap();
            let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload_json);
            let mut mac = HmacSha256::new_from_slice(b"secret").unwrap();
            mac.update(payload_b64.as_bytes());
            let sig = mac.finalize().into_bytes();
            let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig);
            format!("v1.{payload_b64}.{sig_b64}")
        };

        // Tamper by changing one char in the payload section; signature should fail.
        let mut parts: Vec<&str> = legacy.split('.').collect();
        assert_eq!(parts.len(), 3);
        let mut payload_b64 = parts[1].as_bytes().to_vec();
        // Flip one byte (keep it URL-safe-ish; this is enough to invalidate signature).
        payload_b64[0] = if payload_b64[0] == b'A' { b'B' } else { b'A' };
        parts[1] = std::str::from_utf8(&payload_b64).unwrap();
        let tampered = parts.join(".");

        let err = signer.verify(&tampered).unwrap_err().to_string();
        assert!(err.contains("invalid token signature"));
    }
}
