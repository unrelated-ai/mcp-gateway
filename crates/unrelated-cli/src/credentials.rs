use anyhow::Context as _;
use async_trait::async_trait;
use rmcp::transport::{AuthError, CredentialStore, StoredCredentials};

const OAUTH_SERVICE: &str = "ai.unrelated.cli.oauth";
const API_KEY_SERVICE: &str = "ai.unrelated.cli.api-key";

#[derive(Debug, Clone)]
pub struct KeychainCredentialStore {
    context: String,
}

impl KeychainCredentialStore {
    pub fn new(context: impl Into<String>) -> Self {
        Self {
            context: context.into(),
        }
    }
}

#[async_trait]
impl CredentialStore for KeychainCredentialStore {
    async fn load(&self) -> Result<Option<StoredCredentials>, AuthError> {
        let context = self.context.clone();
        tokio::task::spawn_blocking(move || {
            let entry = keyring::Entry::new(OAUTH_SERVICE, &context)
                .map_err(|error| keychain_auth_error("open OAuth credentials", &error))?;
            match entry.get_password() {
                Ok(raw) => serde_json::from_str(&raw).map(Some).map_err(|error| {
                    AuthError::InternalError(format!("invalid keychain credential: {error}"))
                }),
                Err(keyring::Error::NoEntry) => Ok(None),
                Err(error) => Err(keychain_auth_error("read OAuth credentials", &error)),
            }
        })
        .await
        .map_err(|error| keychain_task_error(&error))?
    }

    async fn save(&self, credentials: StoredCredentials) -> Result<(), AuthError> {
        let raw = serde_json::to_string(&credentials).map_err(|error| {
            AuthError::InternalError(format!("serialize OAuth credentials: {error}"))
        })?;
        let context = self.context.clone();
        tokio::task::spawn_blocking(move || {
            let entry = keyring::Entry::new(OAUTH_SERVICE, &context)
                .map_err(|error| keychain_auth_error("open OAuth credentials", &error))?;
            entry
                .set_password(&raw)
                .map_err(|error| keychain_auth_error("save OAuth credentials", &error))
        })
        .await
        .map_err(|error| keychain_task_error(&error))?
    }

    async fn clear(&self) -> Result<(), AuthError> {
        let context = self.context.clone();
        tokio::task::spawn_blocking(move || {
            let entry = keyring::Entry::new(OAUTH_SERVICE, &context)
                .map_err(|error| keychain_auth_error("open OAuth credentials", &error))?;
            match entry.delete_credential() {
                Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
                Err(error) => Err(keychain_auth_error("delete OAuth credentials", &error)),
            }
        })
        .await
        .map_err(|error| keychain_task_error(&error))?
    }
}

fn keychain_auth_error(action: &str, error: &keyring::Error) -> AuthError {
    AuthError::InternalError(format!(
        "failed to {action} in the native keychain: {error}"
    ))
}

fn keychain_task_error(error: &tokio::task::JoinError) -> AuthError {
    AuthError::InternalError(format!("native keychain task failed: {error}"))
}

pub async fn load_api_key(context: &str) -> anyhow::Result<Option<String>> {
    let context = context.to_string();
    tokio::task::spawn_blocking(move || {
        let entry = keyring::Entry::new(API_KEY_SERVICE, &context)
            .map_err(|error| anyhow::anyhow!("failed to open native keychain: {error}"))?;
        match entry.get_password() {
            Ok(value) => Ok(Some(value)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(error) => Err(anyhow::anyhow!(
                "failed to read API key from native keychain: {error}"
            )),
        }
    })
    .await
    .context("native keychain task failed")?
}

pub async fn save_api_key(context: &str, value: &str) -> anyhow::Result<()> {
    let context = context.to_string();
    let value = value.to_string();
    tokio::task::spawn_blocking(move || {
        keyring::Entry::new(API_KEY_SERVICE, &context)
            .map_err(|error| anyhow::anyhow!("failed to open native keychain: {error}"))?
            .set_password(&value)
            .map_err(|error| anyhow::anyhow!("failed to save API key in native keychain: {error}"))
    })
    .await
    .context("native keychain task failed")?
}

pub async fn clear_api_key(context: &str) -> anyhow::Result<()> {
    let context = context.to_string();
    tokio::task::spawn_blocking(move || {
        let entry = keyring::Entry::new(API_KEY_SERVICE, &context)
            .map_err(|error| anyhow::anyhow!("failed to open native keychain: {error}"))?;
        match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(error) => Err(anyhow::anyhow!(
                "failed to delete API key from native keychain: {error}"
            )),
        }
    })
    .await
    .context("native keychain task failed")?
}

#[must_use]
pub fn redact_error(message: &str, secrets: &[&str]) -> String {
    secrets
        .iter()
        .filter(|value| !value.is_empty())
        .fold(message.to_string(), |redacted, secret| {
            redacted.replace(secret, "[REDACTED]")
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_every_secret() {
        assert_eq!(
            redact_error("token=abc key=xyz", &["abc", "xyz"]),
            "token=[REDACTED] key=[REDACTED]"
        );
    }
}
