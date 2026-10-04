//! Management discovery uses the same transport and bounded catalog pagination as MCP requests.
use super::{
    McpState, ProfileSurfaceSource, aggregation::AggregationPolicy, catalog_pages,
    catalog_transforms, streamable_http, surface, upstream,
};
use crate::{
    store::{Profile, Upstream, UpstreamEndpointLifecycle},
    tools_cache::ToolRouteKind,
};
use futures::FutureExt as _;
use rmcp::model::{
    ClientJsonRpcMessage, ClientRequest, JsonRpcRequest, JsonRpcVersion2_0, ServerCapabilities,
    ServerResult,
};
use rmcp::transport::common::http_header::HEADER_MCP_PROTOCOL_VERSION;
use std::time::Duration;
use unrelated_mcp_support::headers::VERSION;

const LOOKUP_TIMEOUT: Duration = Duration::from_secs(2);
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Clone, Copy)]
enum Protocol {
    Legacy,
    Native,
    Auto,
}

struct UpstreamCtx {
    network_class: crate::store::UpstreamNetworkClass,
    url: String,
    headers: reqwest::header::HeaderMap,
    session_id: Option<String>,
    capabilities: ServerCapabilities,
}

#[derive(Default)]
struct Catalogs {
    tools: Vec<rmcp::model::Tool>,
    resources: Vec<rmcp::model::Resource>,
    templates: Vec<rmcp::model::ResourceTemplate>,
    prompts: Vec<rmcp::model::Prompt>,
}

struct SourceOutcome {
    source: ProfileSurfaceSource,
    kind: ToolRouteKind,
    catalogs: Catalogs,
}

impl SourceOutcome {
    fn new(source_id: &str, kind: ToolRouteKind) -> Self {
        let label = match kind {
            ToolRouteKind::Upstream => "upstream",
            ToolRouteKind::TenantLocal => "tenantLocal",
            ToolRouteKind::SharedLocal => "sharedLocal",
        };
        Self {
            kind,
            catalogs: Catalogs::default(),
            source: ProfileSurfaceSource {
                source_id: source_id.into(),
                kind: label.into(),
                ok: true,
                error: None,
                tools_count: 0,
                resources_count: 0,
                resource_templates_count: 0,
                prompts_count: 0,
            },
        }
    }
    fn failed(mut self, message: String) -> Self {
        self.source.ok = false;
        self.source.error = Some(message);
        self
    }
}

pub(crate) struct ProbedProfileSurface {
    pub all_resources: Vec<catalog_transforms::CatalogEntry<rmcp::model::Resource>>,
    pub all_resource_templates:
        Vec<catalog_transforms::CatalogEntry<rmcp::model::ResourceTemplate>>,
    pub all_prompts: Vec<catalog_transforms::CatalogEntry<rmcp::model::Prompt>>,
    pub sources: Vec<ProfileSurfaceSource>,
    pub tools: Vec<rmcp::model::Tool>,
    pub all_tools: Vec<surface::ProbeTool>,
    pub resources: Vec<rmcp::model::Resource>,
    pub resource_templates: Vec<rmcp::model::ResourceTemplate>,
    pub prompts: Vec<rmcp::model::Prompt>,
}

pub(super) fn minimal_initialize_message() -> ClientJsonRpcMessage {
    use rmcp::model::{
        ClientCapabilities, Implementation, InitializeRequest, InitializeRequestParams,
    };
    ClientJsonRpcMessage::Request(JsonRpcRequest {
        jsonrpc: JsonRpcVersion2_0,
        id: rmcp::model::RequestId::String(uuid::Uuid::new_v4().to_string().into()),
        request: ClientRequest::InitializeRequest(InitializeRequest::new(
            InitializeRequestParams::new(
                ClientCapabilities::default(),
                Implementation::from_build_env(),
            ),
        )),
    })
}

async fn connect(
    state: &McpState,
    upstream: &Upstream,
    protocol: Protocol,
) -> anyhow::Result<UpstreamCtx> {
    let mut last_error = None;
    for ep in upstream
        .endpoints
        .iter()
        .filter(|ep| ep.enabled && ep.lifecycle == UpstreamEndpointLifecycle::Active)
    {
        let url = upstream::apply_query_auth(&ep.url, ep.auth.as_ref());
        let mut headers = upstream::build_upstream_headers(ep.auth.as_ref(), 1);
        if matches!(protocol, Protocol::Native | Protocol::Auto) {
            match upstream::discover_server(&state.http, &url, &headers, upstream.network_class)
                .await
            {
                Ok(result) => {
                    headers.insert(
                        HEADER_MCP_PROTOCOL_VERSION,
                        reqwest::header::HeaderValue::from_static(VERSION),
                    );
                    return Ok(UpstreamCtx {
                        network_class: upstream.network_class,
                        url,
                        headers,
                        session_id: None,
                        capabilities: result.capabilities,
                    });
                }
                Err(error) => {
                    last_error = Some(error);
                    if matches!(protocol, Protocol::Native) {
                        continue;
                    }
                }
            }
        }
        match upstream::upstream_initialize(
            &state.http,
            &url,
            &minimal_initialize_message(),
            &headers,
            upstream.network_class,
        )
        .await
        {
            Ok(result) => {
                headers.insert(
                    HEADER_MCP_PROTOCOL_VERSION,
                    reqwest::header::HeaderValue::from_str(&result.protocol_version)?,
                );
                return Ok(UpstreamCtx {
                    network_class: upstream.network_class,
                    url,
                    headers,
                    session_id: result.session_id,
                    capabilities: result.capabilities,
                });
            }
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("No active upstream endpoints")))
}

async fn read_catalog<T, E>(
    state: &McpState,
    ctx: &UpstreamCtx,
    deadline: tokio::time::Instant,
    method: &'static str,
    extract: E,
) -> anyhow::Result<Vec<T>>
where
    E: Fn(ServerResult) -> Option<(Vec<T>, Option<String>)>,
{
    let catalog = catalog_pages::collect(
        |cursor| async move {
            let mut params = serde_json::json!({});
            if let Some(cursor) = cursor {
                params["cursor"] = serde_json::Value::String(cursor);
            }
            let request = serde_json::json!({
                "jsonrpc": "2.0", "id": uuid::Uuid::new_v4().to_string(),
                "method": method, "params": params,
            });
            let response = streamable_http::post_value(
                state.http.for_class(ctx.network_class),
                ctx.url.clone().into(),
                request,
                ctx.session_id.clone().map(Into::into),
                &ctx.headers,
                None,
            )
            .await?;
            upstream::read_first_response(response).await
        },
        extract,
    );
    tokio::time::timeout_at(deadline, catalog).await?
}

async fn read_catalogs(
    state: &McpState,
    ctx: &UpstreamCtx,
    deadline: tokio::time::Instant,
) -> (Catalogs, Option<String>) {
    let tools = async {
        if ctx.capabilities.tools.is_none() {
            return Ok(Vec::new());
        }
        read_catalog(state, ctx, deadline, "tools/list", |r| match r {
            ServerResult::ListToolsResult(r) => Some((r.tools, r.next_cursor)),
            _ => None,
        })
        .await
    };
    let resources = async {
        if ctx.capabilities.resources.is_none() {
            return Ok(Vec::new());
        }
        read_catalog(state, ctx, deadline, "resources/list", |r| match r {
            ServerResult::ListResourcesResult(r) => Some((r.resources, r.next_cursor)),
            _ => None,
        })
        .await
    };
    let templates = async {
        if ctx.capabilities.resources.is_none() {
            return Ok(Vec::new());
        }
        read_catalog(
            state,
            ctx,
            deadline,
            "resources/templates/list",
            |r| match r {
                ServerResult::ListResourceTemplatesResult(r) => {
                    Some((r.resource_templates, r.next_cursor))
                }
                _ => None,
            },
        )
        .await
    };
    let prompts = async {
        if ctx.capabilities.prompts.is_none() {
            return Ok(Vec::new());
        }
        read_catalog(state, ctx, deadline, "prompts/list", |r| match r {
            ServerResult::ListPromptsResult(r) => Some((r.prompts, r.next_cursor)),
            _ => None,
        })
        .await
    };
    let (tools, resources, templates, prompts) = tokio::join!(tools, resources, templates, prompts);
    let failures: Vec<_> = [
        ("Tools", tools.as_ref().err()),
        ("Resources", resources.as_ref().err()),
        ("Resource templates", templates.as_ref().err()),
        ("Prompts", prompts.as_ref().err()),
    ]
    .into_iter()
    .filter_map(|(label, error)| error.map(|error| (label, error)))
    .map(|(label, error)| {
        let reason = if error.is::<catalog_pages::CatalogLimit>() {
            error.to_string()
        } else if error.is::<tokio::time::error::Elapsed>() {
            "Discovery timed out.".into()
        } else {
            "Catalog could not be read. Check upstream compatibility and permissions.".into()
        };
        format!("{label}: {reason}")
    })
    .collect();
    (
        Catalogs {
            tools: tools.unwrap_or_default(),
            resources: resources.unwrap_or_default(),
            templates: templates.unwrap_or_default(),
            prompts: prompts.unwrap_or_default(),
        },
        (!failures.is_empty()).then(|| failures.join(" ")),
    )
}

async fn probe_source(
    state: &McpState,
    profile: &Profile,
    id: &str,
    local: bool,
    protocol: Protocol,
    deadline: tokio::time::Instant,
) -> SourceOutcome {
    if state.catalog.is_local_tool_source(id) {
        let mut outcome = SourceOutcome::new(id, ToolRouteKind::SharedLocal);
        outcome.catalogs.tools = state.catalog.list_tools(id).unwrap_or_default();
        return outcome;
    }
    if local {
        let mut outcome = SourceOutcome::new(id, ToolRouteKind::TenantLocal);
        return match state
            .tenant_catalog
            .list_tools(state.store.as_ref(), &profile.tenant_id, id)
            .await
        {
            Ok(Some(tools)) => {
                outcome.catalogs.tools = tools;
                outcome
            }
            Ok(None) => outcome.failed("Tool source is missing or disabled.".into()),
            Err(_) => outcome.failed(
                "Tool source could not be loaded. Check its configuration and secret references."
                    .into(),
            ),
        };
    }
    let mut outcome = SourceOutcome::new(id, ToolRouteKind::Upstream);
    let upstream = match state.store.get_upstream(id).await {
        Ok(Some(value)) => value,
        Ok(None) => return outcome.failed("Upstream is missing or disabled.".into()),
        Err(_) => return outcome.failed("Upstream configuration could not be loaded.".into()),
    };
    let ctx = match tokio::time::timeout_at(deadline, connect(state, &upstream, protocol)).await {
        Ok(Ok(ctx)) => ctx,
        Ok(Err(error)) => return outcome.failed(super::connection_check::connection_error(&error)),
        Err(_) => return outcome.failed("Upstream connection timed out.".into()),
    };
    let (catalogs, error) = read_catalogs(state, &ctx, deadline).await;
    if let Some(session) = &ctx.session_id {
        let _ = tokio::time::timeout(
            CLEANUP_TIMEOUT,
            streamable_http::delete_session(
                state.http.for_class(ctx.network_class),
                ctx.url.into(),
                session.clone().into(),
                &ctx.headers,
            ),
        )
        .await;
    }
    outcome.catalogs = catalogs;
    if let Some(error) = error {
        return outcome.failed(error);
    }
    outcome
}

pub(crate) async fn probe_profile_surface(
    state: &McpState,
    profile: &Profile,
) -> Result<ProbedProfileSurface, String> {
    let protocol = if profile.mcp.modern_protocol {
        Protocol::Native
    } else {
        Protocol::Legacy
    };
    probe_surface(state, profile, protocol).await
}

pub(crate) async fn probe_upstream_surface(
    state: &McpState,
    profile: &Profile,
) -> Result<ProbedProfileSurface, String> {
    probe_surface(state, profile, Protocol::Auto).await
}

async fn probe_surface(
    state: &McpState,
    profile: &Profile,
    protocol: Protocol,
) -> Result<ProbedProfileSurface, String> {
    let local_ids = tokio::time::timeout(
        LOOKUP_TIMEOUT,
        state
            .store
            .tenant_tool_source_ids(&profile.tenant_id, &profile.source_ids),
    )
    .await
    .map_err(|_| "Source lookup timed out")?
    .map_err(|_| "Sources could not be loaded")?;
    // Reserve time to close legacy probe sessions even when a catalog stalls.
    let deadline = tokio::time::Instant::now() + PROBE_TIMEOUT - CLEANUP_TIMEOUT;
    let results = AggregationPolicy {
        concurrency: 8,
        timeout: PROBE_TIMEOUT,
    }
    .collect(
        profile
            .source_ids
            .iter()
            .map(|id| {
                probe_source(
                    state,
                    profile,
                    id,
                    local_ids.contains(id),
                    protocol,
                    deadline,
                )
                .boxed()
            })
            .collect(),
    )
    .await;
    let outcomes = profile
        .source_ids
        .iter()
        .zip(results)
        .map(|(id, result)| {
            result.unwrap_or_else(|_| {
                SourceOutcome::new(id, ToolRouteKind::Upstream)
                    .failed("Discovery timed out. Try again or check the upstream service.".into())
            })
        })
        .collect();
    Ok(merge_probe(profile, outcomes))
}

fn merge_probe(profile: &Profile, outcomes: Vec<SourceOutcome>) -> ProbedProfileSurface {
    let mut sources = Vec::new();
    let mut tools = Vec::new();
    let mut resources = Vec::new();
    let mut templates = Vec::new();
    let mut prompts = Vec::new();
    for result in outcomes {
        let id = result.source.source_id.clone();
        sources.push(result.source);
        tools.push(surface::ToolSourceTools {
            kind: result.kind,
            source_id: id.clone(),
            tools: result.catalogs.tools,
        });
        resources.push((id.clone(), result.catalogs.resources));
        templates.push((id.clone(), result.catalogs.templates));
        prompts.push((id.clone(), result.catalogs.prompts));
    }
    let merged = surface::merge_tools_surface(&profile.id, profile, tools.clone());
    for source in &mut sources {
        source.tools_count = merged
            .per_source_tool_counts
            .get(&source.source_id)
            .copied()
            .unwrap_or_default();
    }
    let all_resources = catalog_transforms::resources(&profile.transforms, resources);
    let all_resource_templates = catalog_transforms::templates(&profile.transforms, templates);
    let all_prompts = catalog_transforms::prompts(&profile.transforms, prompts);
    for source in &mut sources {
        source.resources_count = all_resources
            .iter()
            .filter(|entry| entry.enabled && entry.source_id == source.source_id)
            .count();
        source.resource_templates_count = all_resource_templates
            .iter()
            .filter(|entry| entry.enabled && entry.source_id == source.source_id)
            .count();
        source.prompts_count = all_prompts
            .iter()
            .filter(|entry| entry.enabled && entry.source_id == source.source_id)
            .count();
    }
    ProbedProfileSurface {
        sources,
        tools: merged.tools,
        all_tools: surface::merge_tools_for_probe(&profile.id, profile, tools),
        resources: all_resources
            .iter()
            .filter(|e| e.enabled)
            .map(|e| e.exposed.clone())
            .collect(),
        resource_templates: all_resource_templates
            .iter()
            .filter(|e| e.enabled)
            .map(|e| e.exposed.clone())
            .collect(),
        prompts: all_prompts
            .iter()
            .filter(|e| e.enabled)
            .map(|e| e.exposed.clone())
            .collect(),
        all_resources,
        all_resource_templates,
        all_prompts,
    }
}
