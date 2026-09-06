//! Maintenance lifetime is tied to the Gateway process shutdown token.
use crate::{endpoint_cache::UpstreamEndpointCache, tools_cache::ToolSurfaceCache};
use std::{sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;

pub(crate) fn spawn(
    tools: Arc<ToolSurfaceCache>,
    endpoints: Arc<UpstreamEndpointCache>,
    shutdown: CancellationToken,
) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                () = shutdown.cancelled() => break,
                _ = interval.tick() => {
                    let tools_removed = tools.prune_expired();
                    let endpoints_removed = endpoints.prune_expired();
                    if tools_removed + endpoints_removed > 0 {
                        tracing::debug!(tools_removed, endpoints_removed, "expired routing cache entries reclaimed");
                    }
                }
            }
        }
    });
}
