use super::McpState;
use crate::contracts::{ContractChange, ContractEvent};
use crate::session_token::TokenPayloadV1;
use crate::tools_cache::{CachedToolsSurface, ToolRoute, ToolRouteKind, profile_fingerprint};
use axum::response::Response;
use rmcp::model::{
    JsonRpcResponse, JsonRpcVersion2_0, ListPromptsResult, ListResourcesResult, ListToolsResult,
    ServerJsonRpcMessage, ServerResult,
};
use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    sync::Arc,
};

pub(crate) const UNRELATED_TOOL_REF_META_KEY: &str = "ai.unrelated/tool-ref";

fn set_stable_tool_ref(tool: &mut rmcp::model::Tool, source_id: &str, original_name: &str) {
    let meta = tool.meta.get_or_insert_with(rmcp::model::MetaObject::new);
    meta.0.insert(
        UNRELATED_TOOL_REF_META_KEY.to_string(),
        serde_json::Value::String(format!("{source_id}:{original_name}")),
    );
}

pub(super) fn merge_resources_with_collisions(
    per_upstream: Vec<(String, Vec<rmcp::model::Resource>)>,
) -> (Vec<rmcp::model::Resource>, HashMap<String, usize>) {
    let counts = count_resource_uris(&per_upstream);
    let mut merged = Vec::new();
    let mut per_source_counts: HashMap<String, usize> = HashMap::new();
    for (upstream_id, mut resources) in per_upstream {
        *per_source_counts.entry(upstream_id.clone()).or_default() += resources.len();
        for r in &mut resources {
            let uri = r.uri.clone();
            if counts.get(&uri).copied().unwrap_or(0) > 1 {
                r.uri = super::ids::resource_collision_urn(&upstream_id, &uri);
            }
        }
        merged.extend(resources);
    }
    (merged, per_source_counts)
}

pub(super) fn merge_prompts_with_collisions(
    per_upstream: Vec<(String, Vec<rmcp::model::Prompt>)>,
) -> (Vec<rmcp::model::Prompt>, HashMap<String, usize>) {
    let counts = count_prompt_names(&per_upstream);
    let mut merged = Vec::new();
    let mut per_source_counts: HashMap<String, usize> = HashMap::new();
    for (upstream_id, mut prompts) in per_upstream {
        *per_source_counts.entry(upstream_id.clone()).or_default() += prompts.len();
        for p in &mut prompts {
            let name = p.name.clone();
            if counts.get(&name).copied().unwrap_or(0) > 1 {
                p.name = format!("{upstream_id}:{name}");
            }
        }
        merged.extend(prompts);
    }
    (merged, per_source_counts)
}

pub(super) fn count_resource_uris(
    per_upstream: &[(String, Vec<rmcp::model::Resource>)],
) -> HashMap<String, usize> {
    let mut counts: HashMap<String, usize> = HashMap::new();
    for (_upstream_id, resources) in per_upstream {
        for r in resources {
            *counts.entry(r.uri.clone()).or_default() += 1;
        }
    }
    counts
}

fn count_prompt_names(
    per_upstream: &[(String, Vec<rmcp::model::Prompt>)],
) -> HashMap<String, usize> {
    let mut counts: HashMap<String, usize> = HashMap::new();
    for (_upstream_id, prompts) in per_upstream {
        for p in prompts {
            *counts.entry(p.name.clone()).or_default() += 1;
        }
    }
    counts
}

#[derive(Debug, Clone)]
pub(super) struct ToolSourceTools {
    pub(super) kind: ToolRouteKind,
    pub(super) source_id: String,
    pub(super) tools: Vec<rmcp::model::Tool>,
}

#[derive(Debug)]
pub(super) struct ToolSurfaceMerge {
    pub(super) tools: Vec<rmcp::model::Tool>,
    pub(super) routes: HashMap<String, ToolRoute>,
    pub(super) ambiguous_names: HashSet<String>,
    pub(super) per_source_tool_counts: HashMap<String, usize>,
}

#[derive(Debug, Clone)]
pub(crate) struct ProbeTool {
    pub(crate) source_id: String,
    /// Tool name as exposed to clients (post-transform; may be collision-prefixed).
    pub(crate) name: String,
    /// Tool base name (post-transform; without collision prefix).
    pub(crate) base_name: String,
    /// Tool name before profile transforms.
    pub(crate) original_name: String,
    pub(crate) enabled: bool,
    /// Tool description before profile overrides (as provided by the underlying source).
    pub(crate) original_description: Option<String>,
    /// Tool description exposed to clients (post overrides).
    pub(crate) description: Option<String>,
    /// Top-level argument keys from the original tool input schema (pre profile transforms).
    pub(crate) original_params: Vec<String>,
}

pub(super) fn merge_tools_surface(
    profile_id: &str,
    profile: &crate::store::Profile,
    sources: Vec<ToolSourceTools>,
) -> ToolSurfaceMerge {
    #[derive(Debug, Clone)]
    struct ToolRecord {
        kind: ToolRouteKind,
        source_id: String,
        original_name: String,
        tool: rmcp::model::Tool,
    }

    let mut records: Vec<ToolRecord> = Vec::new();
    let mut per_source_tool_counts: HashMap<String, usize> = HashMap::new();

    for source in sources {
        let mut seen: HashSet<String> = HashSet::new();
        for mut tool in source.tools {
            let original_name = tool.name.to_string();

            // Schema transforms (param renames + default surface).
            let mut schema = serde_json::Value::Object(tool.input_schema.as_ref().clone());
            profile
                .transforms
                .apply_schema_transforms(&original_name, &mut schema);
            if let serde_json::Value::Object(obj) = schema {
                tool.input_schema = Arc::new(obj);
            }

            // Apply optional per-profile allowlist (if configured).
            //
            // IMPORTANT: allowlisting is keyed by `<source_id>:<original_tool_name>` so tool renames
            // (transforms) do not change enablement.
            if !tool_is_enabled(profile, &source.source_id, &original_name) {
                continue;
            }

            // Tool name transforms.
            tool.name = Cow::Owned(
                profile
                    .transforms
                    .exposed_tool_name(&original_name)
                    .into_owned(),
            );

            // Tool description overrides.
            if let Some(desc) = profile
                .transforms
                .tool_overrides
                .get(&original_name)
                .and_then(|o| o.description.as_ref())
            {
                tool.description = Some(Cow::Owned(desc.clone()));
            }

            let exposed = tool.name.to_string();
            if !seen.insert(exposed.clone()) {
                tracing::warn!(
                    profile_id = %profile_id,
                    source_id = %source.source_id,
                    tool = %exposed,
                    "duplicate tool name after transforms; dropping"
                );
                continue;
            }

            *per_source_tool_counts
                .entry(source.source_id.clone())
                .or_default() += 1;
            records.push(ToolRecord {
                kind: source.kind,
                source_id: source.source_id.clone(),
                original_name,
                tool,
            });
        }
    }

    // Count tool name occurrences to detect collisions (names are post-transform and allowlist-filtered).
    let mut counts: HashMap<String, usize> = HashMap::new();
    for r in &records {
        *counts.entry(r.tool.name.to_string()).or_default() += 1;
    }
    let ambiguous_names: HashSet<String> = counts
        .iter()
        .filter(|(_, n)| **n > 1)
        .map(|(name, _)| name.clone())
        .collect();

    // Finalize names (prefix collisions), build routes, and assemble merged tool list.
    let mut routes: HashMap<String, ToolRoute> = HashMap::new();
    let mut merged: Vec<rmcp::model::Tool> = Vec::with_capacity(records.len());

    for mut r in records {
        let base_name = r.tool.name.to_string();
        let is_collision = counts.get(&base_name).copied().unwrap_or(0) > 1;
        let final_name = if is_collision {
            format!("{}:{}", r.source_id, base_name)
        } else {
            base_name.clone()
        };

        r.tool.name = Cow::Owned(final_name.clone());
        // This value is Gateway-owned. It is deliberately written after reading the
        // upstream definition so an upstream cannot spoof another source's stable ref.
        set_stable_tool_ref(&mut r.tool, &r.source_id, &r.original_name);
        merged.push(r.tool);

        let route = ToolRoute {
            kind: r.kind,
            source_id: r.source_id.clone(),
            original_name: r.original_name.clone(),
        };
        routes.insert(final_name.clone(), route.clone());

        // Allow optional prefix even when no collision.
        if !is_collision {
            let prefixed_alias = format!("{}:{}", r.source_id, base_name);
            routes.entry(prefixed_alias).or_insert(route);
        }
    }

    ToolSurfaceMerge {
        tools: merged,
        routes,
        ambiguous_names,
        per_source_tool_counts,
    }
}

pub(super) fn merge_tools_for_probe(
    profile_id: &str,
    profile: &crate::store::Profile,
    sources: Vec<ToolSourceTools>,
) -> Vec<ProbeTool> {
    #[derive(Debug, Clone)]
    struct ToolRecord {
        source_id: String,
        original_name: String,
        tool: rmcp::model::Tool,
        original_params: Vec<String>,
        enabled: bool,
        original_description: Option<String>,
    }

    let mut records: Vec<ToolRecord> = Vec::new();

    for source in sources {
        let mut seen: HashSet<String> = HashSet::new();
        for mut tool in source.tools {
            let original_name = tool.name.to_string();
            let original_description = tool.description.clone().map(Cow::into_owned);

            let original_params: Vec<String> = tool
                .input_schema
                .get("properties")
                .and_then(serde_json::Value::as_object)
                .map(|o| o.keys().cloned().collect())
                .unwrap_or_default();

            // Schema transforms (param renames + default surface).
            let mut schema = serde_json::Value::Object(tool.input_schema.as_ref().clone());
            profile
                .transforms
                .apply_schema_transforms(&original_name, &mut schema);
            if let serde_json::Value::Object(obj) = schema {
                tool.input_schema = Arc::new(obj);
            }

            // Tool name transforms.
            tool.name = Cow::Owned(
                profile
                    .transforms
                    .exposed_tool_name(&original_name)
                    .into_owned(),
            );
            let base_name = tool.name.to_string();

            // Tool description overrides.
            if let Some(desc) = profile
                .transforms
                .tool_overrides
                .get(&original_name)
                .and_then(|o| o.description.as_ref())
            {
                tool.description = Some(Cow::Owned(desc.clone()));
            }

            // Keep duplicates (post-transform) stable for UI; drop exact dupes per source.
            if !seen.insert(base_name.clone()) {
                tracing::warn!(
                    profile_id = %profile_id,
                    source_id = %source.source_id,
                    tool = %base_name,
                    "duplicate tool name after transforms; dropping"
                );
                continue;
            }

            let enabled = tool_is_enabled(profile, &source.source_id, &original_name);

            records.push(ToolRecord {
                source_id: source.source_id.clone(),
                original_name,
                tool,
                original_params,
                enabled,
                original_description,
            });
        }
    }

    // Count occurrences to detect collisions (names are post-transform, before prefixing).
    let mut counts: HashMap<String, usize> = HashMap::new();
    for r in &records {
        *counts.entry(r.tool.name.to_string()).or_default() += 1;
    }

    let mut out: Vec<ProbeTool> = Vec::with_capacity(records.len());
    for mut r in records {
        let base_name = r.tool.name.to_string();
        let is_collision = counts.get(&base_name).copied().unwrap_or(0) > 1;
        let final_name = if is_collision {
            format!("{}:{}", r.source_id, base_name)
        } else {
            base_name.clone()
        };
        r.tool.name = Cow::Owned(final_name.clone());

        out.push(ProbeTool {
            source_id: r.source_id,
            name: final_name,
            base_name,
            original_name: r.original_name,
            enabled: r.enabled,
            original_description: r.original_description,
            description: r.tool.description.clone().map(std::borrow::Cow::into_owned),
            original_params: r.original_params,
        });
    }

    out
}

pub(super) async fn build_tools_surface(
    state: &McpState,
    profile_id: &str,
    profile: &crate::store::Profile,
    payload: &TokenPayloadV1,
    hop: u32,
) -> Result<CachedToolsSurface, Response> {
    let per_upstream =
        super::upstream::list_tools_all_upstreams(state, profile_id, payload, hop).await?;
    let per_local = list_tools_local_sources(state, profile);
    let per_tenant_local = Box::pin(list_tools_tenant_sources(state, profile)).await;

    let mut sources: Vec<ToolSourceTools> = Vec::new();
    sources.extend(
        per_upstream
            .into_iter()
            .map(|(source_id, tools)| ToolSourceTools {
                kind: ToolRouteKind::Upstream,
                source_id,
                tools,
            }),
    );
    sources.extend(
        per_local
            .into_iter()
            .map(|(source_id, tools)| ToolSourceTools {
                kind: ToolRouteKind::SharedLocal,
                source_id,
                tools,
            }),
    );
    sources.extend(
        per_tenant_local
            .into_iter()
            .map(|(source_id, tools)| ToolSourceTools {
                kind: ToolRouteKind::TenantLocal,
                source_id,
                tools,
            }),
    );

    let merged = merge_tools_surface(profile_id, profile, sources);
    Ok(CachedToolsSurface {
        tools: Arc::new(merged.tools),
        routes: Arc::new(merged.routes),
        ambiguous_names: Arc::new(merged.ambiguous_names),
    })
}

pub(super) async fn aggregate_list_tools(
    state: &McpState,
    profile_id: &str,
    profile: &crate::store::Profile,
    payload: &TokenPayloadV1,
    token: &str,
    req_id: rmcp::model::RequestId,
    hop: u32,
) -> Result<Response, Response> {
    // NOTE: We intentionally rebuild the tools surface on every tools/list request.
    //
    // Rationale:
    // - In Mode 3, contract events (and replay/fanout tests) rely on `tools/list` observing upstream
    //   changes promptly.
    // - The session cache is still used to speed up `tools/call` routing (and to allow rebuild-on-miss).
    //
    // We can later reintroduce cached `tools/list` responses once we have robust invalidation signals
    // (e.g. upstream list_changed notifications) and/or a background refresh loop.
    let fp = profile_fingerprint(profile);
    let surface = Box::pin(build_tools_surface(
        state, profile_id, profile, payload, hop,
    ))
    .await?;
    state
        .tools_cache
        .put(profile_id, token.to_string(), fp, surface.clone());

    let tools = surface.tools.as_ref().clone();

    // Contract hashing: compute and broadcast list_changed (best-effort) if the exposed surface changed.
    publish_contract_event(
        state,
        state.contracts.update_tools_contract(profile_id, &tools),
    )
    .await;

    let result = ListToolsResult {
        tools,
        ..Default::default()
    };

    let msg = ServerJsonRpcMessage::Response(JsonRpcResponse {
        jsonrpc: JsonRpcVersion2_0,
        id: req_id,
        result: ServerResult::ListToolsResult(result),
    });
    Ok(super::sse_single_message(msg))
}

pub(super) async fn aggregate_list_resources(
    state: &McpState,
    profile_id: &str,
    payload: &TokenPayloadV1,
    req_id: rmcp::model::RequestId,
    hop: u32,
) -> Result<Response, Response> {
    let per_upstream =
        super::upstream::list_resources_all_upstreams(state, profile_id, payload, hop).await?;
    let (merged, _per_source_counts) = merge_resources_with_collisions(per_upstream);

    let result = ListResourcesResult {
        resources: merged,
        ..Default::default()
    };

    publish_contract_event(
        state,
        state
            .contracts
            .update_resources_contract(profile_id, &result.resources),
    )
    .await;

    let msg = ServerJsonRpcMessage::Response(JsonRpcResponse {
        jsonrpc: JsonRpcVersion2_0,
        id: req_id,
        result: ServerResult::ListResourcesResult(result),
    });
    Ok(super::sse_single_message(msg))
}

pub(super) async fn aggregate_list_prompts(
    state: &McpState,
    profile_id: &str,
    payload: &TokenPayloadV1,
    req_id: rmcp::model::RequestId,
    hop: u32,
) -> Result<Response, Response> {
    let per_upstream =
        super::upstream::list_prompts_all_upstreams(state, profile_id, payload, hop).await?;
    let (merged, _per_source_counts) = merge_prompts_with_collisions(per_upstream);

    let result = ListPromptsResult {
        prompts: merged,
        ..Default::default()
    };

    publish_contract_event(
        state,
        state
            .contracts
            .update_prompts_contract(profile_id, &result.prompts),
    )
    .await;

    let msg = ServerJsonRpcMessage::Response(JsonRpcResponse {
        jsonrpc: JsonRpcVersion2_0,
        id: req_id,
        result: ServerResult::ListPromptsResult(result),
    });
    Ok(super::sse_single_message(msg))
}

pub(super) async fn resolve_prompt_owner(
    state: &McpState,
    profile_id: &str,
    payload: &TokenPayloadV1,
    prompt_name: &str,
    hop: u32,
) -> anyhow::Result<(String, String)> {
    if let Some((upstream_id, rest)) = split_prefixed(prompt_name)
        && payload.bindings.iter().any(|b| b.upstream == upstream_id)
    {
        return Ok((upstream_id.to_string(), rest.to_string()));
    }

    let per_upstream = super::upstream::list_prompts_all_upstreams(state, profile_id, payload, hop)
        .await
        .map_err(|_| anyhow::anyhow!("failed to list prompts"))?;

    let mut owners = Vec::new();
    for (upstream_id, prompts) in per_upstream {
        if prompts.iter().any(|p| p.name == prompt_name) {
            owners.push(upstream_id);
        }
    }

    match owners.len() {
        0 => Err(anyhow::anyhow!("unknown prompt: {prompt_name}")),
        1 => Ok((owners.remove(0), prompt_name.to_string())),
        _ => Err(anyhow::anyhow!(
            "ambiguous prompt name '{prompt_name}'; use '<upstream_id>:{prompt_name}'"
        )),
    }
}

pub(super) async fn resolve_resource_owner(
    state: &McpState,
    profile_id: &str,
    payload: &TokenPayloadV1,
    uri: &str,
    hop: u32,
) -> anyhow::Result<(String, String)> {
    // If this is a gateway collision URN, parse the upstream id from it.
    if super::ids::parse_resource_collision_urn(uri).is_some() {
        // We need to map back to original uri; do that by listing resources and matching exposed uri.
        let mapping = build_resource_map(state, profile_id, payload, hop).await?;
        if let Some((u, original)) = mapping.get(uri) {
            return Ok((u.clone(), original.clone()));
        }
        return Err(anyhow::anyhow!("unknown resource uri: {uri}"));
    }

    // Otherwise, resolve by listing resources and finding unique owner.
    let mapping = build_resource_map(state, profile_id, payload, hop).await?;
    if let Some((u, original)) = mapping.get(uri) {
        return Ok((u.clone(), original.clone()));
    }
    Err(anyhow::anyhow!("unknown resource uri: {uri}"))
}

async fn build_resource_map(
    state: &McpState,
    profile_id: &str,
    payload: &TokenPayloadV1,
    hop: u32,
) -> anyhow::Result<HashMap<String, (String, String)>> {
    let per_upstream =
        super::upstream::list_resources_all_upstreams(state, profile_id, payload, hop)
            .await
            .map_err(|_| anyhow::anyhow!("failed to list resources"))?;
    let counts = count_resource_uris(&per_upstream);

    let mut map = HashMap::new();
    for (upstream_id, resources) in per_upstream {
        for r in resources {
            let original_uri = r.uri.clone();
            let exposed_uri = if counts.get(&original_uri).copied().unwrap_or(0) > 1 {
                super::ids::resource_collision_urn(&upstream_id, &original_uri)
            } else {
                original_uri.clone()
            };
            map.insert(exposed_uri, (upstream_id.clone(), original_uri));
        }
    }
    Ok(map)
}

fn split_prefixed(s: &str) -> Option<(&str, &str)> {
    let (prefix, rest) = s.split_once(':')?;
    if prefix.is_empty() || rest.is_empty() {
        return None;
    }
    Some((prefix, rest))
}

fn list_tools_local_sources(
    state: &McpState,
    profile: &crate::store::Profile,
) -> Vec<(String, Vec<rmcp::model::Tool>)> {
    let mut out = Vec::new();
    for source_id in &profile.source_ids {
        if let Some(tools) = state.catalog.list_tools(source_id) {
            out.push((source_id.clone(), tools));
        }
    }
    out
}

async fn list_tools_tenant_sources(
    state: &McpState,
    profile: &crate::store::Profile,
) -> Vec<(String, Vec<rmcp::model::Tool>)> {
    let mut out = Vec::new();
    for source_id in &profile.source_ids {
        // Skip shared local sources (handled separately).
        if state.catalog.is_local_tool_source(source_id) {
            continue;
        }

        match Box::pin(state.tenant_catalog.list_tools(
            state.store.as_ref(),
            &profile.tenant_id,
            source_id,
        ))
        .await
        {
            Ok(Some(tools)) => out.push((source_id.clone(), tools)),
            Ok(None) => {}
            Err(e) => {
                tracing::warn!(
                    tenant_id = %profile.tenant_id,
                    source_id = %source_id,
                    error = %e,
                    "tenant local source tools/list failed"
                );
            }
        }
    }
    out
}

fn tool_is_enabled(
    profile: &crate::store::Profile,
    source_id: &str,
    original_tool_name: &str,
) -> bool {
    // No allowlist configured => allow all tools.
    if profile.enabled_tools.is_empty() {
        return true;
    }

    profile.enabled_tools.iter().any(|entry| {
        let Some((src, name)) = entry.split_once(':') else {
            return false;
        };
        src == source_id && name == original_tool_name
    })
}

async fn publish_contract_event(state: &McpState, change: Option<ContractChange>) {
    let Some(change) = change else {
        return;
    };

    // Mode 3: persist + publish + broadcast.
    if let Some(fanout) = &state.contract_fanout {
        match fanout.persist(&change).await {
            Ok(event) => {
                // Broadcast locally.
                state.contracts.broadcast_event(event.clone());

                // Fanout to other nodes (best-effort).
                if let Err(e) = fanout.publish(&event).await {
                    tracing::warn!(
                        profile_id = %event.profile_id,
                        kind = ?event.kind,
                        error = %e,
                        "failed to publish contract event via Postgres fanout"
                    );
                }
            }
            Err(e) => {
                tracing::warn!(
                    profile_id = %change.profile_id,
                    kind = ?change.kind,
                    error = %e,
                    "failed to persist contract event"
                );
            }
        }
        return;
    }

    // Mode 1: in-memory only (non-durable).
    let event = ContractEvent {
        profile_id: change.profile_id,
        kind: change.kind,
        contract_hash: change.contract_hash,
        event_id: state.contracts.next_local_event_id(),
    };
    state.contracts.broadcast_event(event);
}
