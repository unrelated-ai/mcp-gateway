//! Request-scoped native streams. Dropping this stream drops every upstream body.
use super::super::{aggregation::AggregationPolicy, streamable_http, upstream};
use super::*;
use futures::{FutureExt as _, stream::BoxStream};
use rmcp::transport::streamable_http_client::StreamableHttpPostResponse;
use std::collections::BTreeMap;

const SUBSCRIPTION_ID: &str = "io.modelcontextprotocol/subscriptionId";
const CATEGORIES: [(&str, &str); 3] = [
    ("toolsListChanged", "notifications/tools/list_changed"),
    (
        "resourcesListChanged",
        "notifications/resources/list_changed",
    ),
    ("promptsListChanged", "notifications/prompts/list_changed"),
];
type Events = BoxStream<'static, Result<sse_stream::Sse, sse_stream::Error>>;

struct Target {
    binding: UpstreamSessionBinding,
    filter: Value,
    resources: BTreeMap<String, String>,
    tasks: BTreeMap<String, (String, RouteState)>,
}
impl Target {
    fn new(binding: UpstreamSessionBinding, filter: Value) -> Self {
        Self {
            binding,
            filter,
            resources: BTreeMap::new(),
            tasks: BTreeMap::new(),
        }
    }
}

fn bad(id: &Value, message: impl Into<String>) -> Response {
    error(StatusCode::BAD_REQUEST, id, -32602, message, Value::Null)
}
fn identifiers(filter: &Value, key: &str) -> anyhow::Result<Vec<String>> {
    let Some(value) = filter.get(key) else {
        return Ok(Vec::new());
    };
    let values = value
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("{key} must be an array"))?;
    anyhow::ensure!(values.len() <= 1024, "too many subscription identifiers");
    values
        .iter()
        .map(|value| {
            value
                .as_str()
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .ok_or_else(|| anyhow::anyhow!("{key} must contain nonempty strings"))
        })
        .collect()
}

pub(super) async fn listen(
    state: Arc<McpState>,
    request: RequestContext,
    payload: TokenPayloadV1,
    headers: HeaderMap,
    body: Value,
) -> Result<Response, Response> {
    let id = body["id"].clone();
    let mut changes = state.contracts.subscribe(&request.profile.id);
    let (mut accepted, targets) =
        prepare_targets(&state, &request, &payload, &headers, &body).await?;
    let limit = request.limits.max_sse_event_bytes;
    let hop = super::super::parse_hop(&headers);
    if hop >= upstream::MAX_HOPS {
        return Err(bad(&id, "Proxy hop limit exceeded"));
    }
    let futures = targets
        .into_values()
        .map(|target| {
            open_target(
                state.clone(),
                request.profile.clone(),
                target,
                body.clone(),
                hop,
                limit,
            )
            .boxed()
        })
        .collect();
    let results = AggregationPolicy::from_env().collect(futures).await;
    let mut streams = Vec::new();
    let mut resources = Vec::new();
    let mut tasks = Vec::new();
    for result in results {
        let (target, events) = match result {
            Ok(Ok(value)) => value,
            _ if request.profile.allow_partial_upstreams => continue,
            _ => {
                return Err(error(
                    StatusCode::BAD_GATEWAY,
                    &id,
                    -32603,
                    "Upstream subscription failed",
                    Value::Null,
                ));
            }
        };
        resources.extend(target.resources.values().cloned());
        tasks.extend(target.tasks.values().map(|(token, _)| token.clone()));
        streams.push(mapped_events(
            target,
            events,
            state.signer.clone(),
            request.profile.clone(),
            id.clone(),
            limit,
        ));
    }
    if !resources.is_empty() {
        accepted["resourceSubscriptions"] = json!(resources);
    }
    if !tasks.is_empty() {
        accepted["taskIds"] = json!(tasks);
    }
    let ack = notification(
        "notifications/subscriptions/acknowledged",
        json!({"notifications":accepted}),
        &id,
    );
    let mut events = futures::stream::select_all(streams);
    let mut revalidate = tokio::time::interval(std::time::Duration::from_secs(30));
    revalidate.tick().await;
    let profile_id = request.profile.id.clone();
    let initial_policy = serde_json::to_value(&request.profile.mcp).expect("profile settings");
    let stream = async_stream::stream! {
        yield Ok::<_, Infallible>(axum::response::sse::Event::default().data(ack.to_string()));
        loop {
            let message = tokio::select! {
                () = state.shutdown.cancelled() => break,
                event = events.next(), if !events.is_empty() => match event { Some(Some(message)) => message, _ => break },
                event = changes.recv() => {
                    let Ok(event) = event else { break; };
                    let method = event.kind.list_changed_method();
                    if !CATEGORIES.iter().any(|(key, category)| *category == method && accepted[*key] == true) { continue; }
                    notification(method, json!({}), &id)
                },
                _ = revalidate.tick() => {
                    let Ok(Some(profile)) = state.store.get_profile(&profile_id).await else { break; };
                    if serde_json::to_value(&profile.mcp).ok().as_ref() != Some(&initial_policy)
                        || profile.source_ids != request.profile.source_ids
                        || auth::enforce_data_plane_auth(&state, &profile, &headers, payload.auth.as_ref(), payload.oidc.as_ref()).await.is_err() { break; }
                    continue;
                }
            };
            yield Ok(axum::response::sse::Event::default().data(message.to_string()));
        }
    };
    Ok(finish_response(
        axum::response::Sse::new(stream)
            .keep_alive(axum::response::sse::KeepAlive::default())
            .into_response(),
    ))
}

fn finish_response(mut response: Response) -> Response {
    response.headers_mut().insert(
        "cache-control",
        axum::http::HeaderValue::from_static("no-store"),
    );
    response.headers_mut().insert(
        "x-accel-buffering",
        axum::http::HeaderValue::from_static("no"),
    );
    response
}

async fn next_message(events: &mut Events, limit: u64) -> anyhow::Result<Value> {
    loop {
        let event = events
            .next()
            .await
            .ok_or_else(|| anyhow::anyhow!("upstream subscription closed"))??;
        let Some(data) = event.data else {
            continue;
        };
        anyhow::ensure!(
            data.len() as u64 <= limit,
            "subscription event exceeds limit"
        );
        return Ok(serde_json::from_str(&data)?);
    }
}

fn notification(method: &str, mut params: Value, id: &Value) -> Value {
    params["_meta"]["io.modelcontextprotocol/serverInfo"] =
        json!({"name":"unrelated-mcp-gateway","version":env!("CARGO_PKG_VERSION")});
    params["_meta"][SUBSCRIPTION_ID] = id.clone();
    json!({"jsonrpc":"2.0","method":method,"params":params})
}
fn map_notification(
    mut message: Value,
    target: &Target,
    signer: &crate::session_token::SessionSigner,
    profile: &crate::store::Profile,
    id: &Value,
) -> anyhow::Result<Option<Value>> {
    anyhow::ensure!(
        message.get("id").is_none(),
        "unexpected response on subscription"
    );
    anyhow::ensure!(
        message["params"]["_meta"][SUBSCRIPTION_ID] == *id,
        "subscription correlation mismatch"
    );
    let method = message["method"].as_str().unwrap_or("");
    if !profile.mcp.notifications.allows(method) {
        return Ok(None);
    }
    if let Some((key, _)) = CATEGORIES.iter().find(|(_, category)| *category == method) {
        if target.filter[*key] != true {
            return Ok(None);
        }
    } else if method == "notifications/resources/updated" {
        let Some(exposed) = message["params"]["uri"]
            .as_str()
            .and_then(|uri| target.resources.get(uri))
        else {
            return Ok(None);
        };
        message["params"]["uri"] = json!(exposed);
    } else if method == "notifications/tasks" {
        let Some((token, route)) = message["params"]["taskId"]
            .as_str()
            .and_then(|id| target.tasks.get(id))
        else {
            return Ok(None);
        };
        route.wrap_result(signer, profile, &mut message["params"], Some(token))?;
    } else {
        return Ok(None);
    }
    Ok(Some(message))
}

async fn prepare_targets(
    state: &McpState,
    request: &RequestContext,
    payload: &TokenPayloadV1,
    headers: &HeaderMap,
    body: &Value,
) -> Result<(Value, BTreeMap<(String, String), Target>), Response> {
    let id = body["id"].clone();
    let requested = &body["params"]["notifications"];
    if !requested.is_object() {
        return Err(bad(&id, "notifications must be an object"));
    }
    for (key, _) in CATEGORIES {
        if requested.get(key).is_some_and(|v| !v.is_boolean()) {
            return Err(bad(&id, format!("{key} must be a boolean")));
        }
    }
    let resources =
        identifiers(requested, "resourceSubscriptions").map_err(|e| bad(&id, e.to_string()))?;
    let tasks = identifiers(requested, "taskIds").map_err(|e| bad(&id, e.to_string()))?;
    if !tasks.is_empty()
        && !body["params"]["_meta"][CLIENT_CAPABILITIES_META]["extensions"][TASKS_EXTENSION]
            .is_object()
    {
        return Err(error(
            StatusCode::BAD_REQUEST,
            &id,
            rmcp::model::ErrorCode::MISSING_REQUIRED_CLIENT_CAPABILITY.0,
            "Missing required client capability",
            json!({"requiredCapabilities":{"extensions":{(TASKS_EXTENSION):{}}}}),
        ));
    }
    let caps = request.profile.mcp.capabilities.effective();
    let mut accepted = json!({});
    for ((key, _), supported) in CATEGORIES.into_iter().zip([
        caps.tools_list_changed(),
        caps.resources_list_changed(),
        caps.prompts_list_changed(),
    ]) {
        if requested[key] == true && supported {
            accepted[key] = json!(true);
        }
    }
    // Subscribe before contacting upstreams so local edits during startup are observed.
    let mut targets = BTreeMap::new();
    for binding in &payload.bindings {
        targets.insert(
            (binding.upstream.clone(), binding.endpoint.clone()),
            Target::new(binding.clone(), accepted.clone()),
        );
    }
    if caps.resources_subscribe() {
        for exposed in resources {
            let (source, original) = super::super::surface::resolve_resource_owner(
                state,
                &request.profile.id,
                payload,
                &exposed,
                super::super::parse_hop(headers),
            )
            .await
            .map_err(|e| bad(&id, e.to_string()))?;
            let target = targets
                .values_mut()
                .find(|target| target.binding.upstream == source)
                .ok_or_else(|| bad(&id, "Resource source is unavailable"))?;
            target.resources.insert(original, exposed);
        }
    }
    for exposed in tasks {
        let route = RouteState::open(
            &state.signer,
            &exposed,
            true,
            &request.profile,
            payload,
            body,
        )
        .map_err(|e| bad(&id, e.to_string()))?;
        let binding = route.binding.clone();
        let target = targets
            .entry((binding.upstream.clone(), binding.endpoint.clone()))
            .or_insert_with(|| Target::new(binding, json!({})));
        target.tasks.insert(
            route
                .task_id
                .clone()
                .ok_or_else(|| bad(&id, "Invalid task state"))?,
            (exposed, route),
        );
    }
    Ok((accepted, targets))
}

async fn open_target(
    state: Arc<McpState>,
    profile: crate::store::Profile,
    mut target: Target,
    mut body: Value,
    hop: u32,
    limit: u64,
) -> anyhow::Result<(Target, Events)> {
    if !target.resources.is_empty() {
        target.filter["resourceSubscriptions"] = json!(target.resources.keys().collect::<Vec<_>>());
    }
    if !target.tasks.is_empty() {
        target.filter["taskIds"] = json!(target.tasks.keys().collect::<Vec<_>>());
    }
    body["params"]["notifications"] = target.filter.clone();
    let endpoint = upstream::resolve_endpoint(&state, &profile.id, &target.binding)
        .await
        .map_err(|_| anyhow::anyhow!("resolve subscription endpoint"))?
        .ok_or_else(|| anyhow::anyhow!("subscription endpoint unavailable"))?;
    upstream::rewrite_request_metadata(
        &mut body,
        &profile
            .mcp
            .security
            .effective_upstream_policy(&target.binding.upstream),
    );
    let headers =
        upstream::build_bound_upstream_headers(&target.binding, endpoint.auth.as_ref(), hop + 1);
    let response = streamable_http::post_value_limited(
        state.http.for_class(endpoint.network_class),
        upstream::apply_query_auth(&endpoint.url, endpoint.auth.as_ref()).into(),
        body.clone(),
        None,
        &headers,
        None,
        limit,
    )
    .await?;
    let StreamableHttpPostResponse::Sse(mut events, _) = response else {
        anyhow::bail!("subscription requires SSE");
    };
    let ack = next_message(&mut events, limit).await?;
    anyhow::ensure!(
        ack["method"] == "notifications/subscriptions/acknowledged"
            && ack["params"]["_meta"][SUBSCRIPTION_ID] == body["id"],
        "invalid subscription acknowledgement"
    );
    let accepted = &ack["params"]["notifications"];
    anyhow::ensure!(
        accepted.is_object(),
        "invalid subscription acknowledgement filter"
    );
    for (key, _) in CATEGORIES {
        anyhow::ensure!(
            accepted[key] != true || target.filter[key] == true,
            "upstream acknowledged unrequested category"
        );
    }
    let resources = identifiers(accepted, "resourceSubscriptions")?;
    let tasks = identifiers(accepted, "taskIds")?;
    anyhow::ensure!(
        resources.iter().all(|id| target.resources.contains_key(id))
            && tasks.iter().all(|id| target.tasks.contains_key(id)),
        "upstream acknowledged unrequested identifiers"
    );
    target.resources.retain(|id, _| resources.contains(id));
    target.tasks.retain(|id, _| tasks.contains(id));
    target.filter = accepted.clone();
    Ok::<_, anyhow::Error>((target, events))
}

fn mapped_events(
    target: Target,
    events: Events,
    signer: crate::session_token::SessionSigner,
    profile: crate::store::Profile,
    id: Value,
    limit: u64,
) -> BoxStream<'static, Option<Value>> {
    futures::stream::unfold((target, events), move |(target, mut events)| {
        let signer = signer.clone();
        let profile = profile.clone();
        let id = id.clone();
        async move {
            loop {
                let Ok(message) = next_message(&mut events, limit).await else {
                    return Some((None, (target, events)));
                };
                match map_notification(message, &target, &signer, &profile, &id) {
                    Ok(Some(message)) => return Some((Some(message), (target, events))),
                    Ok(None) => {}
                    Err(_) => return Some((None, (target, events))),
                }
            }
        }
    })
    .boxed()
}
