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
    let now = Utc::now();
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
            "renewTime": now.to_rfc3339_opts(SecondsFormat::Micros, false),
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

pub(super) fn lease_expired(spec: &LeaseSpec, now: DateTime<Utc>) -> bool {
    let Some(renew_time) = spec.renew_time.as_ref() else {
        return true;
    };
    let duration = i64::from(spec.lease_duration_seconds.unwrap_or(0));
    if duration <= 0 {
        return true;
    }
    let Ok(renew_at) = DateTime::parse_from_rfc3339(&renew_time.0.to_string()) else {
        return true;
    };
    now > renew_at.with_timezone(&Utc) + ChronoDuration::seconds(duration)
}
