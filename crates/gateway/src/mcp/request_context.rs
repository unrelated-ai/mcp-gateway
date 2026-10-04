//! Configuration loaded once for an MCP POST and reused through execution.
use crate::store::{Profile, Store};
use crate::transport_limits::EffectiveTransportLimits;

pub(super) struct RequestContext {
    pub profile: Profile,
    pub limits: EffectiveTransportLimits,
}

impl RequestContext {
    pub async fn load(store: &dyn Store, profile_id: &str) -> anyhow::Result<Option<Self>> {
        let Some(profile) = store.get_profile(profile_id).await? else {
            return Ok(None);
        };
        let tenant_limits = match store.get_tenant_transport_limits(&profile.tenant_id).await {
            Ok(limits) => limits,
            Err(error) => {
                tracing::warn!(%error, tenant_id = %profile.tenant_id,
                    "load tenant transport limits failed; using defaults");
                None
            }
        };
        let limits = EffectiveTransportLimits::from_profile_and_tenant(
            &profile.mcp.security.transport_limits,
            tenant_limits.as_ref(),
        );
        Ok(Some(Self { profile, limits }))
    }
}
