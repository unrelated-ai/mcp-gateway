//! Profile source initialization and downstream session creation.
use super::auth::{authenticate_api_key_on_initialize, authorize_oauth_request};
use super::{
    McpState, effective_caps, parse_hop, protocol::*,
    record_upstream_bindings_activity_best_effort, upstream,
};
use crate::session_token::{TokenAuthV1, TokenOidcV1, TokenPayloadV1, UpstreamSessionBinding};
use crate::store::DataPlaneAuthMode;
use axum::{
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use base64::Engine as _;
use rmcp::model::{
    ClientJsonRpcMessage, ClientRequest, InitializeResult, JsonRpcRequest, JsonRpcResponse,
    JsonRpcVersion2_0, ServerCapabilities, ServerJsonRpcMessage, ServerResult,
};

const PROXY_KEY_BYTES: usize = 32;

pub(super) async fn handle_initialize(
    state: &McpState,
    profile: &crate::store::Profile,
    headers: &HeaderMap,
    message: ClientJsonRpcMessage,
) -> Result<Response, Response> {
    let (req_id, protocol_version) =
        parse_initialize_request(&message).map_err(|(s, m)| (s, m).into_response())?;

    // Data-plane authn/z (per-profile).
    let (auth, oidc): (Option<TokenAuthV1>, Option<TokenOidcV1>) =
        match profile.data_plane_auth_mode {
            DataPlaneAuthMode::Disabled => (None, None),
            DataPlaneAuthMode::ApiKey => (
                Some(authenticate_api_key_on_initialize(state, profile, headers).await?),
                None,
            ),
            DataPlaneAuthMode::OAuth => (
                None,
                Some(authorize_oauth_request(state, profile, headers).await?),
            ),
        };

    tracing::info!(
        profile_id = %profile.id,
        tenant_id = %profile.tenant_id,
        "initialize profile session"
    );

    let (bindings, warnings) =
        initialize_profile_sources(state, profile, &message, parse_hop(headers)).await?;

    let mut local_sources: usize = 0;
    for id in &profile.source_ids {
        if state.catalog.is_local_tool_source(id) {
            local_sources += 1;
            continue;
        }
        if state
            .tenant_catalog
            .has_tool_source(state.store.as_ref(), &profile.tenant_id, id)
            .await
            .map_err(internal_error_response("check tenant tool source"))?
        {
            local_sources += 1;
        }
    }
    if bindings.is_empty() && local_sources == 0 {
        return Err((
            StatusCode::BAD_GATEWAY,
            "All upstreams failed to initialize",
        )
            .into_response());
    }

    if !warnings.is_empty() && !profile.allow_partial_upstreams {
        return Err((
            StatusCode::BAD_GATEWAY,
            format!(
                "Profile disallows partial upstreams; initialize warnings: {}",
                warnings.join("; ")
            ),
        )
            .into_response());
    }

    for warning in &warnings {
        tracing::warn!(profile_id = %profile.id, warning = %warning, "profile initialize warning");
    }

    let init_result = gateway_initialize_result(profile, protocol_version, &warnings);
    let response_message = ServerJsonRpcMessage::Response(JsonRpcResponse {
        jsonrpc: JsonRpcVersion2_0,
        id: req_id,
        result: ServerResult::InitializeResult(init_result),
    });

    let proxy_key = if profile.mcp.security.signed_proxied_request_ids {
        Some(mint_proxy_key_b64().map_err(internal_error_response("mint proxy key"))?)
    } else {
        None
    };

    let token_payload = TokenPayloadV1 {
        profile_id: profile.id.clone(),
        bindings: bindings.clone(),
        auth,
        oidc,
        iat: None,
        exp: None,
        proxy_key,
    };
    let token = state
        .signer
        .sign(token_payload)
        .map_err(internal_error_response("sign session token"))?;

    // Mark freshly initialized upstream bindings as active.
    record_upstream_bindings_activity_best_effort(state, profile, &token, &bindings, "initialize")
        .await;

    Ok(sse_single_message_with_session_id(
        &response_message,
        &token,
    ))
}

fn parse_initialize_request(
    message: &ClientJsonRpcMessage,
) -> Result<(rmcp::model::RequestId, rmcp::model::ProtocolVersion), (StatusCode, &'static str)> {
    match message {
        ClientJsonRpcMessage::Request(JsonRpcRequest {
            id,
            request: ClientRequest::InitializeRequest(init),
            ..
        }) => Ok((id.clone(), init.params.protocol_version.clone())),
        _ => Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            "Unexpected message, expect initialize request",
        )),
    }
}

fn mint_proxy_key_b64() -> anyhow::Result<String> {
    let mut bytes = [0u8; PROXY_KEY_BYTES];
    getrandom::fill(&mut bytes).map_err(|e| anyhow::anyhow!("OS RNG failure: {e}"))?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

pub(super) async fn initialize_profile_sources(
    state: &McpState,
    profile: &crate::store::Profile,
    init_message: &ClientJsonRpcMessage,
    hop: u32,
) -> Result<(Vec<UpstreamSessionBinding>, Vec<String>), Response> {
    let mut bindings = Vec::<UpstreamSessionBinding>::new();
    let mut warnings = Vec::<String>::new();

    for upstream_id in &profile.source_ids {
        // Gateway-native tool sources do not require upstream MCP session initialization.
        if state.catalog.is_local_tool_source(upstream_id) {
            continue;
        }
        // Tenant-owned local tool sources do not require upstream MCP session initialization.
        if state
            .tenant_catalog
            .has_tool_source(state.store.as_ref(), &profile.tenant_id, upstream_id)
            .await
            .map_err(internal_error_response("check tenant tool source"))?
        {
            continue;
        }

        let upstream = state
            .store
            .get_upstream(upstream_id)
            .await
            .map_err(internal_error_response("load upstream"))?
            .ok_or_else(|| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("profile references unknown upstream '{upstream_id}'"),
                )
                    .into_response()
            })?;

        if upstream.endpoints.is_empty() {
            warnings.push(format!("Upstream '{upstream_id}' has no endpoints"));
            continue;
        }

        let active_endpoints: Vec<&crate::store::UpstreamEndpoint> = upstream
            .endpoints
            .iter()
            .filter(|ep| {
                ep.enabled
                    && matches!(
                        ep.lifecycle,
                        crate::store::UpstreamEndpointLifecycle::Active
                    )
            })
            .collect();
        if active_endpoints.is_empty() {
            warnings.push(format!(
                "Upstream '{upstream_id}' has no active endpoints (all are draining/disabled)"
            ));
            continue;
        }

        let upstream_policy = profile.mcp.security.effective_upstream_policy(upstream_id);
        let upstream_init_message =
            upstream::rewrite_upstream_initialize_message(init_message, &upstream_policy);

        // Pick a starting endpoint index randomly and then try all endpoints (failover on init).
        let start = upstream::random_start_index(active_endpoints.len());

        let mut last_err: Option<anyhow::Error> = None;
        let mut initialized: Option<(String, upstream::UpstreamHandshake)> = None;
        for i in 0..active_endpoints.len() {
            let ep = active_endpoints[(start + i) % active_endpoints.len()];
            let headers = upstream::build_upstream_headers(ep.auth.as_ref(), hop + 1);
            let endpoint_url = upstream::apply_query_auth(&ep.url, ep.auth.as_ref());
            match upstream::upstream_initialize(
                &state.http,
                &endpoint_url,
                &upstream_init_message,
                &headers,
                upstream.network_class,
            )
            .await
            {
                Ok(handshake) => {
                    initialized = Some((ep.id.clone(), handshake));
                    break;
                }
                Err(e) => last_err = Some(e),
            }
        }

        if let Some((endpoint_id, handshake)) = initialized {
            bindings.push(UpstreamSessionBinding {
                upstream: upstream_id.clone(),
                endpoint: endpoint_id,
                session: handshake.session_id,
                protocol_version: Some(handshake.protocol_version),
            });
        } else if let Some(e) = last_err {
            warnings.push(format!("Upstream '{upstream_id}' initialize failed: {e}"));
        } else {
            warnings.push(format!("Upstream '{upstream_id}' initialize failed"));
        }
    }

    Ok((bindings, warnings))
}

// SEP-2577 keeps logging wire-compatible during its deprecation window. Continue advertising it
// when profile policy allows it so an SDK-only upgrade does not change the gateway contract.
#[allow(deprecated)]
fn gateway_initialize_result(
    profile: &crate::store::Profile,
    protocol_version: rmcp::model::ProtocolVersion,
    warnings: &[String],
) -> InitializeResult {
    let caps = effective_caps(profile);
    // Build a "maximal" capability set, then clear fields based on profile policy.
    // This avoids the type-state complexity in the rmcp builder generics.
    let mut server_caps = ServerCapabilities::builder()
        .enable_logging()
        .enable_completions()
        .enable_tools()
        .enable_tool_list_changed()
        .enable_resources()
        .enable_resources_list_changed()
        .enable_resources_subscribe()
        .enable_prompts()
        .enable_prompts_list_changed()
        .build();

    if !caps.logging() {
        server_caps.logging = None;
    }
    if !caps.completions() {
        server_caps.completions = None;
    }
    if let Some(t) = server_caps.tools.as_mut()
        && !caps.tools_list_changed()
    {
        t.list_changed = None;
    }
    if let Some(r) = server_caps.resources.as_mut() {
        if !caps.resources_list_changed() {
            r.list_changed = None;
        }
        if !caps.resources_subscribe() {
            r.subscribe = None;
        }
    }
    if let Some(p) = server_caps.prompts.as_mut()
        && !caps.prompts_list_changed()
    {
        p.list_changed = None;
    }

    let mut init_result = InitializeResult::new(server_caps)
        .with_protocol_version(protocol_version)
        .with_server_info(rmcp::model::Implementation::new(
            "unrelated-mcp-gateway",
            env!("CARGO_PKG_VERSION"),
        ));

    if !warnings.is_empty() {
        init_result.instructions = Some(format!(
            "Gateway warnings (partial upstream availability):\n- {}",
            warnings.join("\n- ")
        ));
    }

    init_result
}
