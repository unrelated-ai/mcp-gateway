use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, KeyInit as _, Mac as _};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

/// Secret used to sign tenant-scoped control-plane tokens.
#[derive(Clone)]
pub struct TenantSigner {
    secret: Vec<u8>,
}

impl TenantSigner {
    #[must_use]
    pub fn new(secret: Vec<u8>) -> Self {
        Self { secret }
    }

    /// Sign a tenant token (v1).
    ///
    /// The token is a compact, URL-safe string:
    /// `tv1.<payload_b64>.<sig_b64>`
    pub fn sign_v1(&self, payload: &TenantTokenPayloadV1) -> anyhow::Result<String> {
        let payload_json = serde_json::to_vec(payload)?;
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json);

        let mut mac = HmacSha256::new_from_slice(&self.secret)
            .map_err(|_| anyhow::anyhow!("invalid HMAC key"))?;
        mac.update(payload_b64.as_bytes());
        let sig = mac.finalize().into_bytes();
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig);

        Ok(format!("tv1.{payload_b64}.{sig_b64}"))
    }

    /// Verify a tenant token and enforce expiry.
    pub fn verify(&self, token: &str) -> anyhow::Result<TenantTokenPayloadV1> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| anyhow::anyhow!("system clock is before UNIX_EPOCH"))?
            .as_secs();
        self.verify_at(token, now)
    }

    fn verify_at(&self, token: &str, now_unix_secs: u64) -> anyhow::Result<TenantTokenPayloadV1> {
        let (version, rest) = token
            .split_once('.')
            .ok_or_else(|| anyhow::anyhow!("invalid token format"))?;
        if version != "tv1" {
            return Err(anyhow::anyhow!("unsupported token version: {version}"));
        }
        let (payload_b64, sig_b64) = rest
            .split_once('.')
            .ok_or_else(|| anyhow::anyhow!("invalid token format"))?;

        let got = URL_SAFE_NO_PAD
            .decode(sig_b64)
            .map_err(|_| anyhow::anyhow!("invalid token signature encoding"))?;

        let mut mac = HmacSha256::new_from_slice(&self.secret)
            .map_err(|_| anyhow::anyhow!("invalid HMAC key"))?;
        mac.update(payload_b64.as_bytes());
        mac.verify_slice(&got)
            .map_err(|_| anyhow::anyhow!("invalid token signature"))?;

        let payload_json = URL_SAFE_NO_PAD
            .decode(payload_b64)
            .map_err(|_| anyhow::anyhow!("invalid token payload encoding"))?;
        let payload: TenantTokenPayloadV1 = serde_json::from_slice(&payload_json)?;

        if payload.exp_unix_secs <= now_unix_secs {
            return Err(anyhow::anyhow!("token expired"));
        }
        Ok(payload)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantTokenPayloadV1 {
    pub tenant_id: String,
    pub exp_unix_secs: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tenant_token_roundtrip_and_expiry() {
        let signer = TenantSigner::new(b"secret".to_vec());

        let payload = TenantTokenPayloadV1 {
            tenant_id: "t1".to_string(),
            exp_unix_secs: 200,
        };
        let token = signer.sign_v1(&payload).expect("sign");

        let decoded = signer.verify_at(&token, 199).expect("verify");
        assert_eq!(decoded.tenant_id, "t1");

        let err = signer.verify_at(&token, 200).unwrap_err();
        assert!(err.to_string().contains("expired"));
    }
}
