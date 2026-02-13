use super::{McpState, ProfileSurfaceSource, streamable_http, surface, upstream};
use crate::tools_cache::ToolRouteKind;
use rmcp::model::{
    ClientJsonRpcMessage, ClientRequest, JsonRpcRequest, JsonRpcVersion2_0, ServerResult,
};
use std::collections::HashMap;
use std::time::Duration;

const PROBE_TIMEOUT: Duration = Duration::from_secs(10);
const PROBE_HEADERS_HOP: u32 = 1;

#[derive(Debug, Clone)]
struct UpstreamCtx {
    upstream_id: String,
    endpoint_url: String,
    headers: reqwest::header::HeaderMap,
    session_id: String,
}

fn format_anyhow_chain(e: &anyhow::Error) -> String {
    e.chain()
        .map(std::string::ToString::to_string)
        .collect::<Vec<_>>()
        .join(": ")
}

fn minimal_initialize_message() -> ClientJsonRpcMessage {
    use rmcp::model::{
        ClientCapabilities, Implementation, InitializeRequest, InitializeRequestParams,
    };

    let init = InitializeRequest::new(InitializeRequestParams {
        meta: None,
        protocol_version: rmcp::model::ProtocolVersion::default(),
        capabilities: ClientCapabilities::default(),
        client_info: Implementation::from_build_env(),
    });
    ClientJsonRpcMessage::Request(JsonRpcRequest {
        jsonrpc: JsonRpcVersion2_0,
        id: rmcp::model::RequestId::Number(1),
        request: ClientRequest::InitializeRequest(init),
    })
}

fn make_source(
    kind: &str,
    source_id: &str,
    ok: bool,
    error: Option<String>,
) -> ProfileSurfaceSource {
    ProfileSurfaceSource {
        kind: kind.to_string(),
        source_id: source_id.to_string(),
        ok,
        error,
        tools_count: 0,
        resources_count: 0,
        prompts_count: 0,
    }
}

async fn initialize_upstream_probe_session(
    state: &McpState,
    upstream_id: &str,
    upstream: &crate::store::Upstream,
    init_msg: &ClientJsonRpcMessage,
) -> Result<UpstreamCtx, String> {
    let start = upstream::random_start_index(upstream.endpoints.len());

    let mut last_err: Option<String> = None;
    for i in 0..upstream.endpoints.len() {
        let ep = &upstream.endpoints[(start + i) % upstream.endpoints.len()];
        let endpoint_url = upstream::apply_query_auth(&ep.url, ep.auth.as_ref());
        let headers = upstream::build_upstream_headers(ep.auth.as_ref(), PROBE_HEADERS_HOP);
        let fut = upstream::upstream_initialize(&state.http, &endpoint_url, init_msg, &headers);
        match tokio::time::timeout(PROBE_TIMEOUT, fut).await {
            Ok(Ok(session_id)) => {
                return Ok(UpstreamCtx {
                    upstream_id: upstream_id.to_string(),
                    endpoint_url,
                    headers,
                    session_id,
                });
            }
            Ok(Err(e)) => last_err = Some(e.to_string()),
            Err(_) => last_err = Some("initialize timed out".to_string()),
        }
    }

    Err(last_err.unwrap_or_else(|| "initialize failed".to_string()))
}

#[allow(clippy::too_many_lines)] // TODO: refactor this to be more readable.
async fn classify_sources(
    state: &McpState,
    profile: &crate::store::Profile,
    init_msg: &ClientJsonRpcMessage,
) -> (
    Vec<surface::ToolSourceTools>,
    HashMap<String, ProfileSurfaceSource>,
    Vec<UpstreamCtx>,
) {
    let mut tool_sources: Vec<surface::ToolSourceTools> = Vec::new();
    let mut sources: HashMap<String, ProfileSurfaceSource> = HashMap::new();
    let mut upstreams: Vec<UpstreamCtx> = Vec::new();

    for source_id in &profile.source_ids {
        // Shared local sources.
        if state.catalog.is_local_tool_source(source_id) {
            let tools = state.catalog.list_tools(source_id).unwrap_or_default();
            tool_sources.push(surface::ToolSourceTools {
                kind: ToolRouteKind::SharedLocal,
                source_id: source_id.clone(),
                tools,
            });
            sources.insert(
                source_id.clone(),
                make_source("sharedLocal", source_id, true, None),
            );
            continue;
        }

        // Tenant-owned local sources.
        let is_tenant_local = state
            .tenant_catalog
            .has_tool_source(state.store.as_ref(), &profile.tenant_id, source_id)
            .await
            .unwrap_or(false);
        if is_tenant_local {
            match Box::pin(state.tenant_catalog.list_tools(
                state.store.as_ref(),
                &profile.tenant_id,
                source_id,
            ))
            .await
            {
                Ok(Some(tools)) => {
                    tool_sources.push(surface::ToolSourceTools {
                        kind: ToolRouteKind::TenantLocal,
                        source_id: source_id.clone(),
                        tools,
                    });
                    sources.insert(
                        source_id.clone(),
                        make_source("tenantLocal", source_id, true, None),
                    );
                }
                Ok(None) => {
                    sources.insert(
                        source_id.clone(),
                        make_source(
                            "tenantLocal",
                            source_id,
                            false,
                            Some("tenant tool source not found".to_string()),
                        ),
                    );
                }
                Err(e) => {
                    sources.insert(
                        source_id.clone(),
                        make_source(
                            "tenantLocal",
                            source_id,
                            false,
                            Some(format_anyhow_chain(&e)),
                        ),
                    );
                }
            }
            continue;
        }

        // Upstream MCP server.
        sources.insert(
            source_id.clone(),
            make_source("upstream", source_id, false, None),
        );

        let upstream = match state.store.get_upstream(source_id).await {
            Ok(Some(u)) => u,
            Ok(None) => {
                if let Some(s) = sources.get_mut(source_id) {
                    s.error = Some("unknown upstream".to_string());
                }
                continue;
            }
            Err(e) => {
                if let Some(s) = sources.get_mut(source_id) {
                    s.error = Some(e.to_string());
                }
                continue;
            }
        };

        if upstream.endpoints.is_empty() {
            if let Some(s) = sources.get_mut(source_id) {
                s.error = Some("upstream has no endpoints".to_string());
            }
            continue;
        }

        match initialize_upstream_probe_session(state, source_id, &upstream, init_msg).await {
            Ok(ctx) => {
                if let Some(s) = sources.get_mut(source_id) {
                    s.ok = true;
                }
                upstreams.push(ctx);
            }
            Err(err) => {
                if let Some(s) = sources.get_mut(source_id) {
                    s.error = Some(err);
                }
            }
        }
    }

    (tool_sources, sources, upstreams)
}

fn list_tools_request() -> ClientJsonRpcMessage {
    ClientJsonRpcMessage::Request(JsonRpcRequest {
        jsonrpc: JsonRpcVersion2_0,
        id: rmcp::model::RequestId::Number(1),
        request: ClientRequest::ListToolsRequest(rmcp::model::ListToolsRequest {
            method: rmcp::model::ListToolsRequestMethod,
            params: None,
            extensions: rmcp::model::Extensions::default(),
        }),
    })
}

fn list_resources_request() -> ClientJsonRpcMessage {
    ClientJsonRpcMessage::Request(JsonRpcRequest {
        jsonrpc: JsonRpcVersion2_0,
        id: rmcp::model::RequestId::Number(1),
        request: ClientRequest::ListResourcesRequest(rmcp::model::ListResourcesRequest {
            method: rmcp::model::ListResourcesRequestMethod,
            params: None,
            extensions: rmcp::model::Extensions::default(),
        }),
    })
}

fn list_prompts_request() -> ClientJsonRpcMessage {
    ClientJsonRpcMessage::Request(JsonRpcRequest {
        jsonrpc: JsonRpcVersion2_0,
        id: rmcp::model::RequestId::Number(1),
        request: ClientRequest::ListPromptsRequest(rmcp::model::ListPromptsRequest {
            method: rmcp::model::ListPromptsRequestMethod,
            params: None,
            extensions: rmcp::model::Extensions::default(),
        }),
    })
}

async fn post_and_read_first(
    state: &McpState,
    u: &UpstreamCtx,
    request: ClientJsonRpcMessage,
    timeout_message: &'static str,
    transport_failed_prefix: &'static str,
) -> Result<ServerResult, String> {
    let resp = tokio::time::timeout(
        PROBE_TIMEOUT,
        streamable_http::post_message(
            &state.http,
            u.endpoint_url.clone().into(),
            request,
            Some(u.session_id.clone().into()),
            &u.headers,
        ),
    )
    .await
    .map_err(|_| timeout_message.to_string())?
    .map_err(|e| format!("{transport_failed_prefix}: {e}"))?;

    upstream::read_first_response(resp)
        .await
        .map_err(|e| e.to_string())
}

async fn probe_upstreams_lists(
    state: &McpState,
    upstreams: &[UpstreamCtx],
    sources: &mut HashMap<String, ProfileSurfaceSource>,
    tool_sources: &mut Vec<surface::ToolSourceTools>,
) -> (
    Vec<(String, Vec<rmcp::model::Resource>)>,
    Vec<(String, Vec<rmcp::model::Prompt>)>,
) {
    let mut per_upstream_resources: Vec<(String, Vec<rmcp::model::Resource>)> = Vec::new();
    let mut per_upstream_prompts: Vec<(String, Vec<rmcp::model::Prompt>)> = Vec::new();

    for u in upstreams {
        let mut any_err: Option<String> = None;

        // tools/list
        match post_and_read_first(
            state,
            u,
            list_tools_request(),
            "tools/list timed out",
            "tools/list transport failed",
        )
        .await
        {
            Ok(ServerResult::ListToolsResult(r)) => {
                tool_sources.push(surface::ToolSourceTools {
                    kind: ToolRouteKind::Upstream,
                    source_id: u.upstream_id.clone(),
                    tools: r.tools,
                });
            }
            Ok(_) => any_err = Some("tools/list returned unexpected response".to_string()),
            Err(e) => any_err = Some(format!("tools/list failed: {e}")),
        }

        // resources/list
        match post_and_read_first(
            state,
            u,
            list_resources_request(),
            "resources/list timed out",
            "resources/list transport failed",
        )
        .await
        {
            Ok(ServerResult::ListResourcesResult(r)) => {
                per_upstream_resources.push((u.upstream_id.clone(), r.resources));
            }
            Ok(_) => {}
            Err(e) => {
                any_err.get_or_insert_with(|| format!("resources/list failed: {e}"));
            }
        }

        // prompts/list
        match post_and_read_first(
            state,
            u,
            list_prompts_request(),
            "prompts/list timed out",
            "prompts/list transport failed",
        )
        .await
        {
            Ok(ServerResult::ListPromptsResult(r)) => {
                per_upstream_prompts.push((u.upstream_id.clone(), r.prompts));
            }
            Ok(_) => {}
            Err(e) => {
                any_err.get_or_insert_with(|| format!("prompts/list failed: {e}"));
            }
        }

        if let Some(err) = any_err
            && let Some(s) = sources.get_mut(&u.upstream_id)
        {
            s.ok = false;
            s.error = Some(err);
        }
    }

    (per_upstream_resources, per_upstream_prompts)
}

async fn cleanup_upstream_sessions(state: &McpState, upstreams: &[UpstreamCtx]) {
    // Best-effort upstream session cleanup.
    for u in upstreams {
        let _ = streamable_http::delete_session(
            &state.http,
            u.endpoint_url.clone().into(),
            u.session_id.clone().into(),
            &u.headers,
        )
        .await;
    }
}

fn finalize_sources(
    profile: &crate::store::Profile,
    sources: &mut HashMap<String, ProfileSurfaceSource>,
    per_source_tool_counts: &HashMap<String, usize>,
    per_source_resource_counts: &HashMap<String, usize>,
    per_source_prompt_counts: &HashMap<String, usize>,
) -> Vec<ProfileSurfaceSource> {
    for s in sources.values_mut() {
        s.tools_count = per_source_tool_counts
            .get(&s.source_id)
            .copied()
            .unwrap_or(0);
        s.resources_count = per_source_resource_counts
            .get(&s.source_id)
            .copied()
            .unwrap_or(0);
        s.prompts_count = per_source_prompt_counts
            .get(&s.source_id)
            .copied()
            .unwrap_or(0);
    }

    // Preserve profile source order.
    let mut ordered_sources: Vec<ProfileSurfaceSource> = Vec::new();
    for id in &profile.source_ids {
        if let Some(s) = sources.get(id) {
            ordered_sources.push(s.clone());
        }
    }
    ordered_sources
}

/// Probe a profile's surface (tools/resources/prompts) without a browser MCP session.
///
/// Returns:
/// - per-source status + counts
/// - merged tools/resources/prompts lists (same collision semantics as the data plane)
pub(crate) async fn probe_profile_surface(
    state: &McpState,
    profile: &crate::store::Profile,
) -> Result<
    (
        Vec<ProfileSurfaceSource>,
        Vec<rmcp::model::Tool>,
        Vec<surface::ProbeTool>,
        Vec<rmcp::model::Resource>,
        Vec<rmcp::model::Prompt>,
    ),
    String,
> {
    let init_msg = minimal_initialize_message();
    let (mut tool_sources, mut sources, upstreams) =
        classify_sources(state, profile, &init_msg).await;

    // Probe upstream lists (tools/resources/prompts).
    let (per_upstream_resources, per_upstream_prompts) =
        probe_upstreams_lists(state, &upstreams, &mut sources, &mut tool_sources).await;

    cleanup_upstream_sessions(state, &upstreams).await;

    // Build merged tools list (apply transforms + allowlist + collision prefixing).
    let tool_surface = surface::merge_tools_surface(&profile.id, profile, tool_sources.clone());
    let merged_tools = tool_surface.tools;
    let per_source_tool_counts = tool_surface.per_source_tool_counts;

    // Build full tools list (including disabled) for UI toggles/editing.
    let all_tools = surface::merge_tools_for_probe(&profile.id, profile, tool_sources);

    let (merged_resources, per_source_resource_counts) =
        surface::merge_resources_with_collisions(per_upstream_resources);
    let (merged_prompts, per_source_prompt_counts) =
        surface::merge_prompts_with_collisions(per_upstream_prompts);

    let ordered_sources = finalize_sources(
        profile,
        &mut sources,
        &per_source_tool_counts,
        &per_source_resource_counts,
        &per_source_prompt_counts,
    );

    Ok((
        ordered_sources,
        merged_tools,
        all_tools,
        merged_resources,
        merged_prompts,
    ))
}
