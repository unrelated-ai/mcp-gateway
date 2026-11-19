//! Operator leader election.
use super::*;

pub(super) fn load_leader_election_config() -> LeaderElectionConfig {
    let enabled = std::env::var("OPERATOR_LEADER_ELECTION_ENABLED")
        .ok()
        .is_none_or(|v| matches!(v.trim(), "1" | "true" | "TRUE" | "yes" | "YES"));
    let lease_name = std::env::var("OPERATOR_LEADER_ELECTION_LEASE_NAME")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_LEADER_ELECTION_LEASE_NAME.to_string());
    let lease_namespace = std::env::var("OPERATOR_LEADER_ELECTION_LEASE_NAMESPACE")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            std::env::var("OPERATOR_NAMESPACE")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        })
        .unwrap_or_else(|| DEFAULT_LEADER_ELECTION_LEASE_NAMESPACE.to_string());
    let holder_identity = format!(
        "{}-{}",
        hostname::get()
            .ok()
            .and_then(|h| h.into_string().ok())
            .unwrap_or_else(|| "unknown-host".to_string()),
        std::process::id()
    );
    let lease_duration_secs = std::env::var("OPERATOR_LEADER_ELECTION_LEASE_DURATION_SECS")
        .ok()
        .and_then(|v| v.parse::<i32>().ok())
        .unwrap_or(DEFAULT_LEADER_ELECTION_LEASE_DURATION_SECS)
        .max(MIN_LEADER_ELECTION_LEASE_DURATION_SECS);
    let renew_interval_secs = std::env::var("OPERATOR_LEADER_ELECTION_RENEW_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(DEFAULT_LEADER_ELECTION_RENEW_INTERVAL_SECS)
        .max(MIN_LEADER_ELECTION_RENEW_INTERVAL_SECS);
    let retry_interval_secs = std::env::var("OPERATOR_LEADER_ELECTION_RETRY_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(DEFAULT_LEADER_ELECTION_RETRY_INTERVAL_SECS)
        .max(MIN_LEADER_ELECTION_RETRY_INTERVAL_SECS);
    LeaderElectionConfig {
        enabled,
        lease_name,
        lease_namespace,
        holder_identity,
        lease_duration_secs,
        renew_interval_secs,
        retry_interval_secs,
    }
}

pub(super) async fn try_acquire_or_renew_lease(
    client: Client,
    cfg: &LeaderElectionConfig,
) -> anyhow::Result<bool> {
    let leases: Api<Lease> = Api::namespaced(client, &cfg.lease_namespace);
    let now = Timestamp::now();
    let mut allow_takeover = true;
    if let Some(existing) = leases.get_opt(&cfg.lease_name).await?
        && let Some(spec) = existing.spec.as_ref()
    {
        let holder = spec.holder_identity.as_deref().unwrap_or_default();
        if !holder.is_empty() && holder != cfg.holder_identity && !lease_expired(spec, now) {
            allow_takeover = false;
        }
    }
    if !allow_takeover {
        return Ok(false);
    }

    let patch = Patch::Apply(json!({
        "apiVersion": "coordination.k8s.io/v1",
        "kind": "Lease",
        "metadata": {
            "name": cfg.lease_name,
            "namespace": cfg.lease_namespace,
        },
        "spec": {
            "holderIdentity": cfg.holder_identity,
            "leaseDurationSeconds": cfg.lease_duration_secs,
            "renewTime": k8s_openapi::apimachinery::pkg::apis::meta::v1::MicroTime(now),
        }
    }));
    leases
        .patch(
            &cfg.lease_name,
            &PatchParams::apply(FIELD_MANAGER).force(),
            &patch,
        )
        .await?;
    Ok(true)
}

pub(super) fn lease_expired(spec: &LeaseSpec, now: Timestamp) -> bool {
    let Some(renew_time) = spec.renew_time.as_ref() else {
        return true;
    };
    let duration = i64::from(spec.lease_duration_seconds.unwrap_or(0));
    if duration <= 0 {
        return true;
    }
    now.duration_since(renew_time.0) > k8s_openapi::jiff::SignedDuration::from_secs(duration)
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::{apimachinery::pkg::apis::meta::v1::MicroTime, jiff::SignedDuration};

    #[test]
    fn lease_expires_only_after_its_full_duration() {
        let renewed: Timestamp = "2026-10-01T23:59:59.123456Z".parse().unwrap();
        let spec = LeaseSpec {
            renew_time: Some(MicroTime(renewed)),
            lease_duration_seconds: Some(1),
            ..LeaseSpec::default()
        };
        let deadline = renewed + SignedDuration::from_secs(1);
        assert!(!lease_expired(&spec, deadline));
        assert!(lease_expired(
            &spec,
            deadline + SignedDuration::from_micros(1)
        ));
    }
}
