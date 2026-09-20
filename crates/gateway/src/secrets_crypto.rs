use anyhow::Context as _;
use base64::Engine as _;
use chacha20poly1305::aead::{Aead as _, Payload};
use chacha20poly1305::{KeyInit as _, XChaCha20Poly1305, XNonce};
use sha2::Digest as _;
use zeroize::Zeroize as _;

/// App-layer encryption for Mode 3 tenant secrets.
///
/// Threat model goal:
/// - DB snapshots / accidental reads of `secrets` table should not reveal secret plaintext.
/// - Gateway nodes decrypt at runtime using a local keyring (env / KMS integration later).
///
/// Crypto:
/// - AEAD: XChaCha20-Poly1305 (24-byte nonce, 32-byte key).
/// - AAD binds ciphertext to `{tenant_id, secret_name}` to prevent cross-tenant copy/paste.
///
/// Key management:
/// - Rotation-friendly: multiple keys accepted for decryption; first key used for encryption.
/// - We store a short `kid` alongside ciphertext to select the right key quickly.
#[derive(Clone)]
pub struct SecretsCipher {
    keys: Vec<KeyEntry>,
}

#[derive(Clone)]
struct KeyEntry {
    kid: String,
    aead: XChaCha20Poly1305,
}

impl SecretsCipher {
    pub fn new_from_env() -> anyhow::Result<Self> {
        let v = std::env::var("UNRELATED_GATEWAY_SECRET_KEYS")
            .context("UNRELATED_GATEWAY_SECRET_KEYS is required in Mode 3")?;
        let v = v.trim();
        if v.is_empty() {
            anyhow::bail!("UNRELATED_GATEWAY_SECRET_KEYS is required in Mode 3");
        }

        let secrets = v
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(decode_key_material)
            .collect::<Vec<Vec<u8>>>();

        Self::new_from_secrets(secrets)
    }

    pub fn new_from_secrets(secrets: Vec<Vec<u8>>) -> anyhow::Result<Self> {
        let mut keys = Vec::new();
        for secret in secrets {
            let mut bytes = secret;
            let derived = sha2::Sha256::digest(&bytes);
            bytes.zeroize();

            let mut key_bytes = [0u8; 32];
            key_bytes.copy_from_slice(&derived);
            let kid = {
                let kid_hash = sha2::Sha256::digest(key_bytes);
                hex::encode(&kid_hash[..8])
            };
            let aead = XChaCha20Poly1305::new((&key_bytes).into());
            key_bytes.zeroize();

            keys.push(KeyEntry { kid, aead });
        }
        if keys.is_empty() {
            anyhow::bail!("no secret encryption keys provided");
        }
        Ok(Self { keys })
    }

    #[must_use]
    pub fn active_kid(&self) -> &str {
        &self.keys[0].kid
    }

    pub fn encrypt(
        &self,
        tenant_id: &str,
        secret_name: &str,
        plaintext: &str,
        nonce: [u8; 24],
    ) -> anyhow::Result<Vec<u8>> {
        let aad = aad(tenant_id, secret_name);
        let payload = Payload {
            msg: plaintext.as_bytes(),
            aad: aad.as_bytes(),
        };
        self.keys[0]
            .aead
            .encrypt(&XNonce::from(nonce), payload)
            .map_err(|e| {
                // `aead::Error` doesn't implement `std::error::Error`, so wrap manually.
                anyhow::anyhow!("encrypt secret failed: {e:?}")
            })
    }

    pub fn decrypt(
        &self,
        tenant_id: &str,
        secret_name: &str,
        kid: Option<&str>,
        nonce: &[u8],
        ciphertext: &[u8],
    ) -> anyhow::Result<String> {
        let aad = aad(tenant_id, secret_name);

        if nonce.len() != 24 {
            anyhow::bail!("invalid nonce length (expected 24)");
        }
        let nonce = <&XNonce>::try_from(nonce).context("invalid nonce length (expected 24)")?;

        // Try keyed first if provided, then fall back to all keys (rotation/config mistakes).
        let candidates: Vec<&KeyEntry> = if let Some(k) = kid {
            let mut out: Vec<&KeyEntry> = self.keys.iter().filter(|e| e.kid == k).collect();
            if out.is_empty() {
                out = self.keys.iter().collect();
            }
            out
        } else {
            self.keys.iter().collect()
        };

        let mut last_err: Option<anyhow::Error> = None;
        for key in candidates {
            let payload = Payload {
                msg: ciphertext,
                aad: aad.as_bytes(),
            };
            match key.aead.decrypt(nonce, payload) {
                Ok(pt) => {
                    return String::from_utf8(pt).context("decrypt secret (utf-8)");
                }
                Err(e) => last_err = Some(anyhow::anyhow!("decrypt secret failed: {e:?}")),
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("decrypt secret failed")))
    }
}

fn aad(tenant_id: &str, secret_name: &str) -> String {
    format!("unrelated-mcp-gateway:tenant:{tenant_id}:secret:{secret_name}")
}

fn decode_key_material(s: &str) -> Vec<u8> {
    // Try URL-safe no pad, then standard, then raw bytes.
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s.as_bytes())
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(s.as_bytes()));
    if let Ok(bytes) = b64
        && !bytes.is_empty()
    {
        return bytes;
    }
    s.as_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decrypts_pre_upgrade_ciphertext() -> anyhow::Result<()> {
        // Produced with chacha20poly1305 0.10.1 and sha2 0.10.9, before the
        // dependency migration. Persisted secrets must survive the upgrade.
        let cipher = SecretsCipher::new_from_secrets(vec![b"legacy-fixture-key".to_vec()])?;
        let ciphertext = hex::decode("0328ff65a2e49fcb51b2cba4808b67ff4e5bc9bc63ce59ed3f2a76a2b9")?;
        assert_eq!(
            cipher.decrypt("t1", "s1", Some(cipher.active_kid()), &[7; 24], &ciphertext)?,
            "legacy-secret"
        );
        assert!(
            cipher
                .decrypt("t2", "s1", None, &[7; 24], &ciphertext)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn encrypt_decrypt_roundtrip_and_rotation() -> anyhow::Result<()> {
        let c1 = SecretsCipher::new_from_secrets(vec![b"k1".to_vec(), b"k2".to_vec()])?;

        let nonce = [7u8; 24];
        let ct = c1.encrypt("t1", "s1", "hello", nonce)?;
        let pt = c1.decrypt("t1", "s1", Some(c1.active_kid()), &nonce, &ct)?;
        assert_eq!(pt, "hello");

        // Rotation: new key first, old key still accepted for decrypt.
        let c2 = SecretsCipher::new_from_secrets(vec![b"k2".to_vec(), b"k1".to_vec()])?;
        let pt2 = c2.decrypt("t1", "s1", Some(c1.active_kid()), &nonce, &ct)?;
        assert_eq!(pt2, "hello");
        Ok(())
    }

    #[test]
    fn aad_binds_to_tenant_and_name() -> anyhow::Result<()> {
        let c = SecretsCipher::new_from_secrets(vec![b"k1".to_vec()])?;
        let nonce = [1u8; 24];
        let ct = c.encrypt("t1", "s1", "hello", nonce)?;

        assert!(
            c.decrypt("t2", "s1", Some(c.active_kid()), &nonce, &ct)
                .is_err()
        );
        assert!(
            c.decrypt("t1", "s2", Some(c.active_kid()), &nonce, &ct)
                .is_err()
        );
        Ok(())
    }
}
