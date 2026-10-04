//! On-demand MCP handshakes using saved endpoint credentials and outbound policy.
use super::{
    McpState, aggregation::AggregationPolicy, initialize::LEGACY_VERSIONS, probe, streamable_http,
    upstream,
};
use crate::store::{Profile, UpstreamEndpoint, UpstreamEndpointLifecycle, UpstreamNetworkClass};
use futures::FutureExt as _;
use rmcp::transport::common::http_header::HEADER_MCP_PROTOCOL_VERSION;
use serde::Serialize;
use std::time::Duration;
use unrelated_mcp_support::headers::VERSION;

// Leave time for the UI proxy's 15-second deadline, including metadata lookup.
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(2);
const CHECK_TIMEOUT: Duration = Duration::from_secs(8);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(1);
const CHECK_CONCURRENCY: usize = 8;

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum CheckStatus {
    Passed,
    Failed,
    NotChecked,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ConnectionCheck {
    pub source_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    endpoint_id: Option<String>,
    status: CheckStatus,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    protocol_version: Option<String>,
}

impl ConnectionCheck {
    fn configuration_error(source_id: &str) -> Self {
        Self::new(
            source_id,
            CheckStatus::Failed,
            "Source configuration could not be loaded. Try again.",
        )
    }

    fn new(source_id: &str, status: CheckStatus, message: &str) -> Self {
        Self {
            source_id: source_id.into(),
            endpoint_id: None,
            status,
            message: message.into(),
            protocol_version: None,
        }
    }
}

struct Target {
    source_id: String,
    endpoint: UpstreamEndpoint,
    network_class: UpstreamNetworkClass,
}

enum Prepared {
    Result(ConnectionCheck),
    Targets(Vec<Target>),
}

async fn prepare(state: &McpState, source: &str, tenant_local: bool) -> anyhow::Result<Prepared> {
    if state.catalog.is_local_tool_source(source) || tenant_local {
        return Ok(Prepared::Result(ConnectionCheck::new(
            source,
            CheckStatus::NotChecked,
            "HTTP/OpenAPI source: API reachability and credentials are checked when a tool runs.",
        )));
    }
    let Some(upstream) = state.store.get_upstream(source).await? else {
        return Ok(Prepared::Result(ConnectionCheck::new(
            source,
            CheckStatus::Failed,
            "Source is missing or disabled.",
        )));
    };
    let targets: Vec<_> = upstream
        .endpoints
        .into_iter()
        .filter(|ep| ep.enabled && ep.lifecycle == UpstreamEndpointLifecycle::Active)
        .map(|endpoint| Target {
            source_id: source.into(),
            endpoint,
            network_class: upstream.network_class,
        })
        .collect();
    if targets.is_empty() {
        return Ok(Prepared::Result(ConnectionCheck::new(
            source,
            CheckStatus::Failed,
            "No active endpoints are configured.",
        )));
    }
    Ok(Prepared::Targets(targets))
}

pub(crate) async fn check_profile_connections(
    state: &McpState,
    profile: &Profile,
) -> Vec<ConnectionCheck> {
    let Ok(Ok(local_ids)) = tokio::time::timeout(
        LOOKUP_TIMEOUT,
        state
            .store
            .tenant_tool_source_ids(&profile.tenant_id, &profile.source_ids),
    )
    .await
    else {
        return profile
            .source_ids
            .iter()
            .map(|source| ConnectionCheck::configuration_error(source))
            .collect();
    };
    let prepared = AggregationPolicy {
        concurrency: CHECK_CONCURRENCY,
        timeout: LOOKUP_TIMEOUT,
    }
    .collect(
        profile
            .source_ids
            .iter()
            .map(|source| prepare(state, source, local_ids.contains(source)).boxed())
            .collect(),
    )
    .await;
    let mut checks = Vec::new();
    let mut targets = Vec::new();
    for (source, result) in profile.source_ids.iter().zip(prepared) {
        match result {
            Ok(Ok(Prepared::Result(check))) => checks.push(check),
            Ok(Ok(Prepared::Targets(values))) => targets.extend(values),
            _ => checks.push(ConnectionCheck::configuration_error(source)),
        }
    }
    let results = AggregationPolicy {
        concurrency: CHECK_CONCURRENCY,
        timeout: CHECK_TIMEOUT,
    }
    .collect(
        targets
            .iter()
            .map(|target| check_endpoint(state, target, profile.mcp.modern_protocol).boxed())
            .collect(),
    )
    .await;
    for (target, result) in targets.into_iter().zip(results) {
        let mut check = ConnectionCheck::new(
            &target.source_id,
            CheckStatus::Failed,
            "Connection check timed out. Try again or check the upstream service.",
        );
        check.endpoint_id = Some(target.endpoint.id);
        match result {
            Ok(Ok(version)) => {
                check.status = CheckStatus::Passed;
                check.message = "MCP handshake succeeded with the configured credentials.".into();
                check.protocol_version = Some(version);
            }
            Ok(Err(message)) => check.message = message,
            Err(_) => {}
        }
        checks.push(check);
    }
    checks
}

async fn check_endpoint(state: &McpState, target: &Target, modern: bool) -> Result<String, String> {
    let class = target.network_class;
    let url = upstream::apply_query_auth(&target.endpoint.url, target.endpoint.auth.as_ref());
    crate::outbound_safety::check_upstream_scheme_policy_for_class(class, &url)
        .map_err(|_| "Endpoint scheme is blocked by the outbound policy.".to_owned())?;
    let safety = crate::outbound_safety::gateway_outbound_http_safety_for_class(class);
    crate::outbound_safety::check_url_allowed(&safety, &url)
        .await
        .map_err(|_| {
            "Endpoint address is blocked by the outbound policy or could not be resolved."
                .to_owned()
        })?;
    let mut headers = upstream::build_upstream_headers(target.endpoint.auth.as_ref(), 1);
    if modern {
        return upstream::discover_server(&state.http, &url, &headers, class).await
            .map(|_| VERSION.to_owned())
            .map_err(|error| if error.is::<upstream::NativeProtocolMismatch>() {
                format!("This profile requires native MCP {VERSION}; the upstream did not confirm support.")
            } else { connection_error(&error) });
    }
    let handshake = upstream::upstream_initialize(
        &state.http,
        &url,
        &probe::minimal_initialize_message(),
        &headers,
        class,
    )
    .await
    .map_err(|error| connection_error(&error))?;
    if let Some(session) = handshake.session_id {
        if let Ok(version) = reqwest::header::HeaderValue::from_str(&handshake.protocol_version) {
            headers.insert(HEADER_MCP_PROTOCOL_VERSION, version);
        }
        let _ = tokio::time::timeout(
            CLEANUP_TIMEOUT,
            streamable_http::delete_session(
                state.http.for_class(class),
                url.into(),
                session.into(),
                &headers,
            ),
        )
        .await;
    }
    if !LEGACY_VERSIONS
        .iter()
        .any(|v| v.as_str() == handshake.protocol_version)
    {
        return Err("The upstream negotiated an unsupported MCP version.".into());
    }
    Ok(handshake.protocol_version)
}

// Avoid returning remote response text or request URLs containing credentials.
pub(super) fn connection_error(error: &anyhow::Error) -> String {
    use rmcp::transport::streamable_http_client::StreamableHttpError;
    if let Some(StreamableHttpError::<reqwest::Error>::UnexpectedServerResponse(message)) =
        error.downcast_ref()
        && (message.starts_with("upstream http 401") || message.starts_with("upstream http 403"))
    {
        return "Upstream rejected the configured credentials or access permissions (HTTP 401/403).".into();
    }
    "MCP handshake failed. Check the upstream URL, credentials, and protocol support.".into()
}
