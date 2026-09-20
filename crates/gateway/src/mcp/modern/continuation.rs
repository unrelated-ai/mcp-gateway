//! Encrypted continuation/task routes shared by every Gateway replica.
use crate::session_token::{SessionSigner, TokenPayloadV1, UpstreamSessionBinding};
use crate::store::Profile;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::Digest as _;
use std::time::{SystemTime, UNIX_EPOCH};

const CONTINUATION_TTL_SECS: u64 = 15 * 60;
const MAX_TASK_TTL_SECS: u64 = 24 * 60 * 60;
const MAX_CONTINUATION_ROUNDS: u8 = 10;
const MAX_STATE_TOKEN_BYTES: usize = 16 * 1024;
const TASK_STATE_PURPOSE: &str = "mcp-task-v1";
const CONTINUATION_STATE_PURPOSE: &str = "mcp-mrtr-v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct RouteState {
    pub scope: String,
    pub binding: UpstreamSessionBinding,
    pub method: String,
    pub request_hash: String,
    pub policy_hash: String,
    pub upstream_state: Option<String>,
    pub task_id: Option<String>,
    pub input_ids: Vec<String>,
    pub round: u8,
    pub expires_at: u64,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn hash(value: &Value) -> String {
    hex::encode(sha2::Sha256::digest(
        crate::contracts::canonicalize_json(value)
            .to_string()
            .as_bytes(),
    ))
}

pub(super) fn scope(profile: &Profile, payload: &TokenPayloadV1) -> String {
    hash(
        &json!({"profile":profile.id,"tenant":profile.tenant_id,"auth":payload.auth,"oidc":payload.oidc,"mode":format!("{:?}", profile.data_plane_auth_mode)}),
    )
}

pub(super) fn request_hash(request: &Value) -> String {
    let mut params = request["params"].clone();
    if let Some(params) = params.as_object_mut() {
        for key in ["_meta", "inputResponses", "requestState"] {
            params.remove(key);
        }
    }
    hash(&json!({"method":request["method"],"params":params}))
}

fn policy_hash(profile: &Profile) -> String {
    hash(&json!({"surface":crate::tools_cache::profile_fingerprint(profile),"mcp":profile.mcp}))
}

impl RouteState {
    pub fn new(
        profile: &Profile,
        payload: &TokenPayloadV1,
        binding: UpstreamSessionBinding,
        request: &Value,
    ) -> Self {
        Self {
            scope: scope(profile, payload),
            binding,
            method: request["method"].as_str().unwrap_or("").into(),
            request_hash: request_hash(request),
            policy_hash: policy_hash(profile),
            upstream_state: None,
            task_id: None,
            input_ids: Vec::new(),
            round: 0,
            expires_at: now().saturating_add(CONTINUATION_TTL_SECS),
        }
    }

    pub fn seal(&self, signer: &SessionSigner) -> anyhow::Result<String> {
        let purpose = if self.task_id.is_some() {
            TASK_STATE_PURPOSE
        } else {
            CONTINUATION_STATE_PURPOSE
        };
        let token = signer.seal_state_until(purpose, self, self.expires_at)?;
        anyhow::ensure!(
            token.len() <= MAX_STATE_TOKEN_BYTES,
            "upstream continuation state exceeds limit"
        );
        Ok(token)
    }

    pub fn open(
        signer: &SessionSigner,
        token: &str,
        task: bool,
        profile: &Profile,
        payload: &TokenPayloadV1,
        request: &Value,
    ) -> anyhow::Result<Self> {
        let purpose = if task {
            TASK_STATE_PURPOSE
        } else {
            CONTINUATION_STATE_PURPOSE
        };
        let state: Self = signer.open_state(purpose, token)?;
        anyhow::ensure!(
            state.scope == scope(profile, payload),
            "state belongs to another principal or profile"
        );
        anyhow::ensure!(state.expires_at >= now(), "state has expired");
        anyhow::ensure!(
            profile.source_ids.contains(&state.binding.upstream),
            "state source is no longer attached"
        );
        if !task {
            anyhow::ensure!(
                state.round <= MAX_CONTINUATION_ROUNDS,
                "continuation round limit reached"
            );
            anyhow::ensure!(
                state.policy_hash == policy_hash(profile),
                "profile policy changed during continuation"
            );
            anyhow::ensure!(
                state.request_hash == request_hash(request),
                "continuation request changed"
            );
            if let Some(responses) = request["params"]["inputResponses"].as_object() {
                anyhow::ensure!(
                    responses.keys().all(|key| state.input_ids.contains(key)),
                    "unexpected input response identifier"
                );
            }
        }
        Ok(state)
    }

    pub fn wrap_result(
        &self,
        signer: &SessionSigner,
        profile: &Profile,
        result: &mut Value,
        task_token: Option<&str>,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(self.expires_at > now(), "state has expired");
        if let Some(inputs) = result["inputRequests"].as_object() {
            let policy = profile
                .mcp
                .security
                .effective_upstream_policy(&self.binding.upstream);
            anyhow::ensure!(
                inputs.values().all(|input| input["method"]
                    .as_str()
                    .is_some_and(|method| policy.server_requests.allows(method))),
                "upstream input request blocked by profile policy"
            );
        }
        if result["resultType"] == "input_required" {
            let mut state = self.clone();
            state.round = state.round.saturating_add(1);
            anyhow::ensure!(
                state.round <= MAX_CONTINUATION_ROUNDS,
                "continuation round limit reached"
            );
            state.upstream_state = result["requestState"].as_str().map(str::to_owned);
            state.input_ids = result["inputRequests"]
                .as_object()
                .map(|inputs| inputs.keys().cloned().collect())
                .unwrap_or_default();
            result["requestState"] = json!(state.seal(signer)?);
        }
        if let Some(task_id) = result["taskId"].as_str().map(str::to_owned) {
            let mut state = self.clone();
            if state.task_id.is_none() {
                let created = result["createdAt"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("task lacks createdAt"))?;
                let created = time::OffsetDateTime::parse(
                    created,
                    &time::format_description::well_known::Rfc3339,
                )?
                .unix_timestamp();
                let created = u64::try_from(created)?;
                state.expires_at = result["ttlMs"].as_u64().map_or_else(
                    || now().saturating_add(MAX_TASK_TTL_SECS),
                    |ttl| {
                        created
                            .saturating_add(ttl / 1000)
                            .min(now().saturating_add(MAX_TASK_TTL_SECS))
                    },
                );
                anyhow::ensure!(state.expires_at > now(), "upstream task has expired");
            }
            // Report the actual routing lifetime, including our 24 hour upper bound.
            let created = result["createdAt"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("task lacks createdAt"))?;
            let created = u64::try_from(
                time::OffsetDateTime::parse(
                    created,
                    &time::format_description::well_known::Rfc3339,
                )?
                .unix_timestamp(),
            )?;
            result["ttlMs"] = json!(
                state
                    .expires_at
                    .saturating_sub(created)
                    .saturating_mul(1000)
            );
            state.task_id = Some(task_id.clone());
            if let Some(token) = task_token {
                anyhow::ensure!(
                    self.task_id.as_deref() == Some(task_id.as_str()),
                    "upstream task identifier changed"
                );
                result["taskId"] = json!(token);
            } else {
                result["taskId"] = json!(state.seal(signer)?);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypted_state_is_rotatable_and_rejects_tampering_and_purpose_confusion() {
        let signer = SessionSigner::new(
            vec![b"old key".to_vec()],
            std::time::Duration::from_secs(60),
        )
        .unwrap();
        let token = signer
            .seal_state("mcp-mrtr-v1", &json!({"secret":"upstream state"}))
            .unwrap();
        assert!(!token.contains("upstream"));
        let rotated = SessionSigner::new(
            vec![b"new key".to_vec(), b"old key".to_vec()],
            std::time::Duration::from_secs(60),
        )
        .unwrap();
        assert_eq!(
            rotated.open_state::<Value>("mcp-mrtr-v1", &token).unwrap()["secret"],
            "upstream state"
        );
        assert!(rotated.open_state::<Value>("mcp-task-v1", &token).is_err());
        let mut bytes = token.into_bytes();
        bytes[20] = if bytes[20] == b'a' { b'b' } else { b'a' };
        assert!(
            rotated
                .open_state::<Value>("mcp-mrtr-v1", std::str::from_utf8(&bytes).unwrap())
                .is_err()
        );
    }
    #[tokio::test]
    async fn state_enforces_identity_policy_rounds_expiry_and_restart() -> anyhow::Result<()> {
        use crate::store::Store as _;
        let config =
            serde_json::from_value(json!({"profiles":{"p":{"tenantId":"t","upstreams":["u"]}}}))?;
        let store = crate::store::ConfigStore::new(config);
        let profile = store.get_profile("p").await?.unwrap();
        let payload: TokenPayloadV1 = serde_json::from_value(
            json!({"profileId":"p","bindings":[],"auth":{"tenantId":"t","apiKeyId":"key1"}}),
        )?;
        let request = json!({"method":"tools/call","params":{"name":"echo","arguments":{"x":1}}});
        let binding = UpstreamSessionBinding {
            upstream: "u".into(),
            endpoint: "e".into(),
            session: None,
            protocol_version: Some("2026-07-28".into()),
        };
        let mut state = RouteState::new(&profile, &payload, binding, &request);
        state.input_ids = vec!["roots".into()];
        let signer = SessionSigner::new(
            vec![b"test key".to_vec()],
            std::time::Duration::from_secs(60),
        )?;
        let token = state.seal(&signer)?;
        let restarted = SessionSigner::new(
            vec![b"test key".to_vec()],
            std::time::Duration::from_secs(60),
        )?;
        RouteState::open(&restarted, &token, false, &profile, &payload, &request)?;
        let mut other = payload.clone();
        other.auth.as_mut().unwrap().api_key_id = "key2".into();
        assert!(RouteState::open(&signer, &token, false, &profile, &other, &request).is_err());
        let mut changed = profile.clone();
        changed.mcp.modern_protocol = !changed.mcp.modern_protocol;
        assert!(RouteState::open(&signer, &token, false, &changed, &payload, &request).is_err());
        let mut bad_input = request.clone();
        bad_input["params"]["inputResponses"] = json!({"unrequested":{}});
        assert!(RouteState::open(&signer, &token, false, &profile, &payload, &bad_input).is_err());
        state.round = 10;
        assert!(
            state
                .wrap_result(
                    &signer,
                    &profile,
                    &mut json!({"resultType":"input_required","inputRequests":{}}),
                    None
                )
                .is_err()
        );
        state.expires_at = now() - 1;
        let expired = state.seal(&signer)?;
        assert!(RouteState::open(&signer, &expired, false, &profile, &payload, &request).is_err());
        assert!(RouteState::open(&signer, &token, true, &profile, &payload, &request).is_err());
        Ok(())
    }
}
