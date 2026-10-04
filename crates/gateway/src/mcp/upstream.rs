use super::McpState;
use super::streamable_http;
use crate::session_token::{TokenPayloadV1, UpstreamSessionBinding};
use crate::store::{UpstreamClientCapabilitiesMode, UpstreamSecurityPolicy};
use axum::{Json, http::StatusCode, response::IntoResponse as _, response::Response};
use base64::Engine as _;
use futures::{FutureExt as _, StreamExt as _};
use reqwest::header::HeaderValue;
use rmcp::model::{JsonRpcResponse, ServerJsonRpcMessage};
use rmcp::transport::common::http_header::HEADER_MCP_PROTOCOL_VERSION;
use rmcp::{
    model::{ClientJsonRpcMessage, ClientRequest, JsonRpcRequest, JsonRpcVersion2_0, ServerResult},
    transport::streamable_http_client::StreamableHttpPostResponse,
};
use std::collections::{HashMap, HashSet};
use unrelated_http_tools::config::AuthConfig;
use unrelated_mcp_support::headers::{CLIENT_CAPABILITIES_META, CLIENT_INFO_META};
use uuid::Uuid;

pub(super) const HOP_HEADER: &str = "x-unrelated-gateway-hop";
pub(super) const MAX_HOPS: u32 = 8;

pub(super) struct UpstreamHandshake {
    pub session_id: Option<String>,
    pub protocol_version: String,
    pub capabilities: rmcp::model::ServerCapabilities,
}

pub(super) async fn upstream_initialize(
    http: &crate::outbound_safety::UpstreamHttpClients,
    mcp_url: &str,
    init_message: &ClientJsonRpcMessage,
    headers: &reqwest::header::HeaderMap,
    network_class: crate::store::UpstreamNetworkClass,
) -> anyhow::Result<UpstreamHandshake> {
    if let Err(err) =
        crate::outbound_safety::check_upstream_scheme_policy_for_class(network_class, mcp_url)
    {
        anyhow::bail!("upstream endpoint rejected by scheme policy: {err}");
    }

    // Outbound safety (SSRF hardening): validate the upstream endpoint before connecting.
    let safety = crate::outbound_safety::gateway_outbound_http_safety_for_class(network_class);
    if let Err(err) = crate::outbound_safety::check_url_allowed(&safety, mcp_url).await {
        anyhow::bail!("upstream endpoint blocked by outbound safety policy: {err}");
    }

    let http = http.for_class(network_class);
    let resp = streamable_http::post_message(
        http,
        mcp_url.to_string().into(),
        init_message.clone(),
        None,
        headers,
    )
    .await?;
    let (msg, session_id) = resp.expect_initialized::<reqwest::Error>().await?;
    let ServerJsonRpcMessage::Response(JsonRpcResponse {
        result: ServerResult::InitializeResult(result),
        ..
    }) = msg
    else {
        anyhow::bail!("upstream did not return an initialize result");
    };
    let protocol_version = result.protocol_version.to_string();
    let mut headers = headers.clone();
    headers.insert(
        HEADER_MCP_PROTOCOL_VERSION,
        HeaderValue::from_str(&protocol_version)?,
    );

    // MCP handshake: client must send `notifications/initialized` after `initialize`.
    // Some upstream servers (including our adapter) treat the session as invalid until this occurs.
    let initialized: ClientJsonRpcMessage = serde_json::from_value(serde_json::json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized"
    }))?;

    match streamable_http::post_message(
        http,
        mcp_url.to_string().into(),
        initialized,
        session_id.clone().map(Into::into),
        &headers,
    )
    .await?
    {
        StreamableHttpPostResponse::Accepted => {}
        other => {
            return Err(anyhow::anyhow!(
                "unexpected response to notifications/initialized: {other:?}"
            ));
        }
    }

    Ok(UpstreamHandshake {
        session_id,
        protocol_version,
        capabilities: result.capabilities,
    })
}

#[derive(Debug, thiserror::Error)]
#[error("The upstream did not confirm native MCP support")]
pub(super) struct NativeProtocolMismatch;

pub(super) async fn discover_server(
    http: &crate::outbound_safety::UpstreamHttpClients,
    url: &str,
    headers: &reqwest::header::HeaderMap,
    class: crate::store::UpstreamNetworkClass,
) -> anyhow::Result<rmcp::model::DiscoverResult> {
    use unrelated_mcp_support::headers::VERSION;
    crate::outbound_safety::check_upstream_scheme_policy_for_class(class, url)
        .map_err(anyhow::Error::msg)?;
    let safety = crate::outbound_safety::gateway_outbound_http_safety_for_class(class);
    crate::outbound_safety::check_url_allowed(&safety, url)
        .await
        .map_err(anyhow::Error::msg)?;
    let mut headers = headers.clone();
    headers.insert(
        HEADER_MCP_PROTOCOL_VERSION,
        HeaderValue::from_static(VERSION),
    );
    let response = streamable_http::post_value(
        http.for_class(class), url.to_owned().into(),
        serde_json::json!({"jsonrpc":"2.0","id":new_internal_request_id(),"method":"server/discover"}),
        None, &headers, None,
    ).await?;
    match read_first_response(response).await? {
        ServerResult::DiscoverResult(result)
            if result
                .supported_versions
                .iter()
                .any(|v| v.as_str() == VERSION) =>
        {
            Ok(result)
        }
        _ => Err(NativeProtocolMismatch.into()),
    }
}

/// Headers for a request after initialization, including the upstream's negotiated version.
pub(super) fn build_bound_upstream_headers(
    binding: &UpstreamSessionBinding,
    auth: Option<&unrelated_http_tools::config::AuthConfig>,
    hop: u32,
) -> reqwest::header::HeaderMap {
    let mut headers = build_upstream_headers(auth, hop);
    if let Some(version) = binding.protocol_version.as_deref()
        && let Ok(value) = HeaderValue::from_str(version)
    {
        headers.insert(HEADER_MCP_PROTOCOL_VERSION, value);
    }
    headers
}

pub(super) fn build_upstream_headers(
    auth: Option<&AuthConfig>,
    hop: u32,
) -> reqwest::header::HeaderMap {
    use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderName, HeaderValue};
    let mut headers = HeaderMap::new();

    // Loop guard (best-effort).
    if hop > 0
        && let Ok(v) = HeaderValue::from_str(&hop.to_string())
    {
        headers.insert(HOP_HEADER, v);
    }

    // Upstream auth (explicit; never forward caller Authorization).
    let Some(auth) = auth else {
        return headers;
    };
    match auth {
        AuthConfig::None | AuthConfig::Query { .. } => {}
        AuthConfig::Bearer { token } => {
            if let Ok(v) = HeaderValue::from_str(&format!("Bearer {token}")) {
                headers.insert(AUTHORIZATION, v);
            }
        }
        AuthConfig::Header { name, value } => {
            if let Ok(n) = HeaderName::from_bytes(name.as_bytes())
                && let Ok(v) = HeaderValue::from_str(value)
            {
                headers.insert(n, v);
            }
        }
        AuthConfig::Basic { username, password } => {
            let b64 =
                base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}"));
            if let Ok(v) = HeaderValue::from_str(&format!("Basic {b64}")) {
                headers.insert(AUTHORIZATION, v);
            }
        }
    }
    headers
}

pub(super) fn apply_query_auth(url: &str, auth: Option<&AuthConfig>) -> String {
    let Some(AuthConfig::Query { name, value }) = auth else {
        return url.to_string();
    };
    let Ok(mut u) = reqwest::Url::parse(url) else {
        return url.to_string();
    };
    u.query_pairs_mut()
        .append_pair(name.as_str(), value.as_str());
    u.to_string()
}

pub(super) fn random_start_index(len: usize) -> usize {
    if len == 0 {
        return 0;
    }
    let r = Uuid::new_v4().as_u128();
    (r % (len as u128)) as usize
}

pub(super) fn rewrite_upstream_initialize_message(
    init_message: &ClientJsonRpcMessage,
    policy: &UpstreamSecurityPolicy,
) -> ClientJsonRpcMessage {
    let mut msg = init_message.clone();
    let ClientJsonRpcMessage::Request(JsonRpcRequest { request, .. }) = &mut msg else {
        return msg;
    };
    let ClientRequest::InitializeRequest(init) = request else {
        return msg;
    };

    if policy.rewrite_client_info {
        init.params.client_info =
            rmcp::model::Implementation::new("unrelated-mcp-gateway", env!("CARGO_PKG_VERSION"));
    }

    match policy.client_capabilities_mode {
        UpstreamClientCapabilitiesMode::Passthrough => {}
        UpstreamClientCapabilitiesMode::Strip => {
            init.params.capabilities = rmcp::model::ClientCapabilities::default();
        }
        UpstreamClientCapabilitiesMode::Allowlist => {
            let allowed: HashSet<String> = policy
                .client_capabilities_allow
                .iter()
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(std::string::ToString::to_string)
                .collect();

            if allowed.is_empty() {
                init.params.capabilities = rmcp::model::ClientCapabilities::default();
            } else {
                let v = serde_json::to_value(&init.params.capabilities).unwrap_or_default();
                let serde_json::Value::Object(obj) = v else {
                    init.params.capabilities = rmcp::model::ClientCapabilities::default();
                    return msg;
                };
                let mut out: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();
                for (k, v) in obj {
                    if allowed.contains(&k) {
                        out.insert(k, v);
                    }
                }
                init.params.capabilities =
                    serde_json::from_value(serde_json::Value::Object(out)).unwrap_or_default();
            }
        }
    }

    msg
}

/// Apply the same upstream privacy policy to per-request metadata as initialization.
pub(super) fn rewrite_request_metadata(
    body: &mut serde_json::Value,
    policy: &UpstreamSecurityPolicy,
) {
    let meta = &body["params"]["_meta"];
    if meta
        .get(unrelated_mcp_support::headers::VERSION_META)
        .is_none()
    {
        return;
    }
    let initialize = serde_json::json!({"jsonrpc":"2.0","id":0,"method":"initialize","params":{
        "protocolVersion":rmcp::model::ProtocolVersion::V_2025_11_25,
        "clientInfo":meta[CLIENT_INFO_META],
        "capabilities":meta[CLIENT_CAPABILITIES_META]
    }});
    if let Ok(initialize) = serde_json::from_value(initialize) {
        let rewritten = rewrite_upstream_initialize_message(&initialize, policy);
        if let Ok(rewritten) = serde_json::to_value(rewritten) {
            body["params"]["_meta"][CLIENT_INFO_META] = rewritten["params"]["clientInfo"].clone();
            body["params"]["_meta"][CLIENT_CAPABILITIES_META] =
                rewritten["params"]["capabilities"].clone();
        }
    }
}

pub(super) async fn proxy_to_single_upstream(
    state: &McpState,
    profile_id: &str,
    payload: &TokenPayloadV1,
    upstream_id: &str,
    message: ClientJsonRpcMessage,
    hop: u32,
) -> Result<Response, Response> {
    if hop >= MAX_HOPS {
        return Err((
            StatusCode::BAD_GATEWAY,
            "proxy loop detected (max hops exceeded)",
        )
            .into_response());
    }
    let binding = payload
        .bindings
        .iter()
        .find(|b| b.upstream == upstream_id)
        .ok_or_else(|| {
            (StatusCode::BAD_GATEWAY, "upstream session not available").into_response()
        })?;

    let Some(endpoint) = resolve_endpoint(state, profile_id, binding).await? else {
        return Err((StatusCode::BAD_GATEWAY, "upstream endpoint not found").into_response());
    };

    let endpoint_url = apply_query_auth(&endpoint.url, endpoint.auth.as_ref());
    let headers = build_bound_upstream_headers(binding, endpoint.auth.as_ref(), hop + 1);

    let mut body = serde_json::to_value(message)
        .map_err(|e| super::internal_error_response("serialize request")(e.into()))?;
    if binding.protocol_version.as_deref() == Some(unrelated_mcp_support::headers::VERSION)
        && let Some(profile) = state
            .store
            .get_profile(profile_id)
            .await
            .map_err(super::internal_error_response("load profile policy"))?
    {
        rewrite_request_metadata(
            &mut body,
            &profile.mcp.security.effective_upstream_policy(upstream_id),
        );
    }
    let resp = streamable_http::post_value(
        state.http.for_class(endpoint.network_class),
        endpoint_url.into(),
        body,
        binding.session.clone().map(Into::into),
        &headers,
        None,
    )
    .await
    .map_err(|e| {
        (
            StatusCode::BAD_GATEWAY,
            format!("upstream request failed: {e}"),
        )
            .into_response()
    })?;

    Ok(match resp {
        StreamableHttpPostResponse::Accepted => StatusCode::ACCEPTED.into_response(),
        StreamableHttpPostResponse::Json(msg, ..) => Json(msg).into_response(),
        StreamableHttpPostResponse::Sse(stream, ..) => super::sse_from_upstream_stream(stream),
        _ => {
            return Err((
                StatusCode::BAD_GATEWAY,
                "unsupported upstream transport response",
            )
                .into_response());
        }
    })
}

pub(super) async fn resolve_endpoint(
    state: &McpState,
    _profile_id: &str,
    binding: &UpstreamSessionBinding,
) -> Result<Option<crate::endpoint_cache::UpstreamEndpoint>, Response> {
    if let Some(ep) = state
        .endpoint_cache
        .get(&binding.upstream, &binding.endpoint)
    {
        return Ok(Some(ep));
    }

    let upstream = state
        .store
        .get_upstream(&binding.upstream)
        .await
        .map_err(super::internal_error_response("load upstream"))?;
    let Some(upstream) = upstream else {
        return Ok(None);
    };

    let mut endpoints: HashMap<String, crate::endpoint_cache::UpstreamEndpoint> = HashMap::new();
    let safety =
        crate::outbound_safety::gateway_outbound_http_safety_for_class(upstream.network_class);
    for e in upstream.endpoints {
        if let Err(err) = crate::outbound_safety::check_upstream_scheme_policy_for_class(
            upstream.network_class,
            &e.url,
        ) {
            tracing::warn!(
                upstream_id = %binding.upstream,
                endpoint_id = %e.id,
                error = %err,
                "upstream endpoint rejected by scheme policy"
            );
            continue;
        }
        if let Err(err) = crate::outbound_safety::check_url_allowed(&safety, &e.url).await {
            // Block unsafe endpoints (SSRF hardening). Avoid logging full URLs (may contain
            // sensitive query auth in some deployments).
            tracing::warn!(
                upstream_id = %binding.upstream,
                endpoint_id = %e.id,
                error = %err,
                "upstream endpoint blocked by outbound safety policy"
            );
            continue;
        }
        endpoints.insert(
            e.id,
            crate::endpoint_cache::UpstreamEndpoint {
                url: e.url,
                auth: e.auth,
                network_class: upstream.network_class,
            },
        );
    }
    let endpoint = endpoints.get(&binding.endpoint).cloned();
    state
        .endpoint_cache
        .put(binding.upstream.clone(), endpoints);
    // The cache may expire or evict this entry immediately; return the loaded value directly.
    Ok(endpoint)
}

#[derive(Clone, Copy)]
struct ListAllUpstreamsCtx<'a> {
    state: &'a McpState,
    profile_id: &'a str,
    payload: &'a TokenPayloadV1,
    request_failed_message: &'static str,
    hop: u32,
}

async fn list_all_upstreams<T, FBuild, FExtract>(
    ctx: ListAllUpstreamsCtx<'_>,
    build_request: FBuild,
    extract: FExtract,
) -> Result<Vec<(String, Vec<T>)>, Response>
where
    T: Send,
    FBuild: Fn() -> ClientJsonRpcMessage + Sync,
    FExtract: Fn(ServerResult) -> Option<(Vec<T>, Option<String>)> + Sync,
{
    if ctx.hop >= MAX_HOPS {
        return Err((
            StatusCode::BAD_GATEWAY,
            "proxy loop detected (max hops exceeded)",
        )
            .into_response());
    }
    let profile = if ctx.payload.request_meta.is_some() {
        ctx.state.store.get_profile(ctx.profile_id).await.map_err(
            super::internal_error_response("load upstream privacy policy"),
        )?
    } else {
        None
    };
    let profile = &profile;
    let build_request = &build_request;
    let extract = &extract;
    let results = super::aggregation::AggregationPolicy::from_env().collect(
        ctx.payload.bindings.iter().map(|binding| async move {
            let Some(endpoint) = resolve_endpoint(ctx.state, ctx.profile_id, binding).await? else {
                return Ok(None);
            };
            let endpoint_url = apply_query_auth(&endpoint.url, endpoint.auth.as_ref());
            let headers = build_bound_upstream_headers(binding, endpoint.auth.as_ref(), ctx.hop + 1);
            let result = super::catalog_pages::collect(|cursor| {
                let mut request = serde_json::to_value(build_request()).expect("serializable request");
                if let Some(cursor) = cursor {
                    request["params"] = serde_json::json!({"cursor": cursor});
                }
                if let Some(meta) = &ctx.payload.request_meta {
                    request["params"]["_meta"] = meta.clone();
                    if let Some(profile) = &profile {
                        rewrite_request_metadata(&mut request, &profile.mcp.security.effective_upstream_policy(&binding.upstream));
                    }
                }
                let url = endpoint_url.clone();
                let headers = &headers;
                async move {
                    let response = streamable_http::post_value(
                        ctx.state.http.for_class(endpoint.network_class), url.into(), request,
                        binding.session.clone().map(Into::into), headers, None,
                    ).await?;
                    read_first_response(response).await
                }
            }, &extract).await;
            match result {
                Ok(items) => Ok(Some((binding.upstream.clone(), items))),
                Err(error) if error.is::<super::catalog_pages::CatalogLimit>() =>
                    Err((StatusCode::BAD_GATEWAY, error.to_string()).into_response()),
                Err(error) => {
                    tracing::warn!(upstream_id = %binding.upstream, %error, "{}", ctx.request_failed_message);
                    Ok(None)
                }
            }
        }.boxed()).collect(),
    ).await;
    let mut out = Vec::new();
    for (binding, result) in ctx.payload.bindings.iter().zip(results) {
        match result {
            Ok(Ok(Some(value))) => out.push(value),
            Ok(Ok(None)) => {}
            Ok(Err(response)) => return Err(response),
            Err(_) => {
                tracing::warn!(upstream_id = %binding.upstream, "upstream list request timed out");
            }
        }
    }
    Ok(out)
}

// Catalog reads also run while a notification stream opens. Each request needs
// its own ID on a shared upstream session, including across Gateway replicas.
fn new_internal_request_id() -> rmcp::model::RequestId {
    rmcp::model::RequestId::String(format!("gateway:{}", Uuid::new_v4()).into())
}

pub(super) async fn list_tools_all_upstreams(
    state: &McpState,
    profile_id: &str,
    payload: &TokenPayloadV1,
    hop: u32,
) -> Result<Vec<(String, Vec<rmcp::model::Tool>)>, Response> {
    list_all_upstreams(
        ListAllUpstreamsCtx {
            state,
            profile_id,
            payload,
            request_failed_message: "tools/list failed",
            hop,
        },
        || {
            ClientJsonRpcMessage::Request(JsonRpcRequest {
                jsonrpc: JsonRpcVersion2_0,
                id: new_internal_request_id(),
                request: ClientRequest::ListToolsRequest(rmcp::model::ListToolsRequest {
                    method: rmcp::model::ListToolsRequestMethod,
                    params: None,
                    extensions: rmcp::model::Extensions::default(),
                }),
            })
        },
        |result| match result {
            ServerResult::ListToolsResult(r) => Some((r.tools, r.next_cursor)),
            _ => None,
        },
    )
    .await
}

pub(super) async fn list_resources_all_upstreams(
    state: &McpState,
    profile_id: &str,
    payload: &TokenPayloadV1,
    hop: u32,
) -> Result<Vec<(String, Vec<rmcp::model::Resource>)>, Response> {
    list_all_upstreams(
        ListAllUpstreamsCtx {
            state,
            profile_id,
            payload,
            request_failed_message: "resources/list failed",
            hop,
        },
        || {
            ClientJsonRpcMessage::Request(JsonRpcRequest {
                jsonrpc: JsonRpcVersion2_0,
                id: new_internal_request_id(),
                request: ClientRequest::ListResourcesRequest(rmcp::model::ListResourcesRequest {
                    method: rmcp::model::ListResourcesRequestMethod,
                    params: None,
                    extensions: rmcp::model::Extensions::default(),
                }),
            })
        },
        |result| match result {
            ServerResult::ListResourcesResult(r) => Some((r.resources, r.next_cursor)),
            _ => None,
        },
    )
    .await
}

pub(super) async fn list_resource_templates_all_upstreams(
    state: &McpState,
    profile_id: &str,
    payload: &TokenPayloadV1,
    hop: u32,
) -> Result<Vec<(String, Vec<rmcp::model::ResourceTemplate>)>, Response> {
    list_all_upstreams(
        ListAllUpstreamsCtx {
            state,
            profile_id,
            payload,
            request_failed_message: "resources/templates/list failed",
            hop,
        },
        || {
            ClientJsonRpcMessage::Request(JsonRpcRequest {
                jsonrpc: JsonRpcVersion2_0,
                id: new_internal_request_id(),
                request: ClientRequest::ListResourceTemplatesRequest(
                    rmcp::model::ListResourceTemplatesRequest {
                        method: rmcp::model::ListResourceTemplatesRequestMethod,
                        params: None,
                        extensions: rmcp::model::Extensions::default(),
                    },
                ),
            })
        },
        |result| match result {
            ServerResult::ListResourceTemplatesResult(r) => {
                Some((r.resource_templates, r.next_cursor))
            }
            _ => None,
        },
    )
    .await
}

pub(super) async fn list_prompts_all_upstreams(
    state: &McpState,
    profile_id: &str,
    payload: &TokenPayloadV1,
    hop: u32,
) -> Result<Vec<(String, Vec<rmcp::model::Prompt>)>, Response> {
    list_all_upstreams(
        ListAllUpstreamsCtx {
            state,
            profile_id,
            payload,
            request_failed_message: "prompts/list failed",
            hop,
        },
        || {
            ClientJsonRpcMessage::Request(JsonRpcRequest {
                jsonrpc: JsonRpcVersion2_0,
                id: new_internal_request_id(),
                request: ClientRequest::ListPromptsRequest(rmcp::model::ListPromptsRequest {
                    method: rmcp::model::ListPromptsRequestMethod,
                    params: None,
                    extensions: rmcp::model::Extensions::default(),
                }),
            })
        },
        |result| match result {
            ServerResult::ListPromptsResult(r) => Some((r.prompts, r.next_cursor)),
            _ => None,
        },
    )
    .await
}

pub(super) async fn read_first_response(
    resp: StreamableHttpPostResponse,
) -> anyhow::Result<ServerResult> {
    match resp {
        StreamableHttpPostResponse::Json(msg, ..) => match msg {
            rmcp::model::ServerJsonRpcMessage::Response(r) => Ok(r.result),
            rmcp::model::ServerJsonRpcMessage::Error(e) => {
                Err(anyhow::anyhow!("upstream error: {}", e.error.message))
            }
            other => Err(anyhow::anyhow!("unexpected upstream message: {other:?}")),
        },
        StreamableHttpPostResponse::Sse(mut stream, ..) => {
            while let Some(evt) = stream.next().await {
                let evt = evt?;
                let payload = evt.data.unwrap_or_default();
                if payload.trim().is_empty() {
                    continue;
                }
                let msg: rmcp::model::ServerJsonRpcMessage = serde_json::from_str(&payload)?;
                if let rmcp::model::ServerJsonRpcMessage::Response(r) = msg {
                    return Ok(r.result);
                }
            }
            Err(anyhow::anyhow!("unexpected end of sse stream"))
        }
        StreamableHttpPostResponse::Accepted => Err(anyhow::anyhow!("unexpected accepted")),
        _ => Err(anyhow::anyhow!("unsupported upstream transport response")),
    }
}
