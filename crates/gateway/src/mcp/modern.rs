//! Native MCP lifecycle. Authentication and routing are evaluated on every POST.
mod continuation;
mod subscriptions;
use super::{McpState, RequestContext, auth, initialize, protocol};
use crate::session_token::{TokenPayloadV1, UpstreamSessionBinding};
use crate::store::{DataPlaneAuthMode, UpstreamEndpointLifecycle};
use axum::{
    Json,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use continuation::RouteState;
use futures::StreamExt as _;
use rmcp::model::{ClientJsonRpcMessage, DiscoverResult, ProtocolVersion, RequestMetaObject};
use rmcp::transport::common::http_header::HEADER_MCP_PROTOCOL_VERSION;
use serde_json::{Value, json};
use sha2::Digest as _;
use std::{convert::Infallible, sync::Arc};
use unrelated_mcp_support::headers::{CLIENT_CAPABILITIES_META, TASKS_EXTENSION};
use unrelated_mcp_support::headers::{VERSION, VERSION_META};

pub(super) fn is_modern_request(headers: &HeaderMap, body: &Value) -> bool {
    body["params"]["_meta"].get(VERSION_META).is_some()
        || (headers
            .get(HEADER_MCP_PROTOCOL_VERSION)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| {
                !initialize::LEGACY_VERSIONS
                    .iter()
                    .any(|version| version.as_str() == v)
            })
            && body["method"] != "initialize")
}

fn error(
    status: StatusCode,
    id: &Value,
    code: i32,
    message: impl Into<String>,
    data: Value,
) -> Response {
    let mut response =
        json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message.into()}});
    response["error"]["data"] = data;
    (status, Json(response)).into_response()
}

pub(super) fn validate_origin(headers: &HeaderMap) -> Result<(), Response> {
    let Some(origin) = headers.get("origin") else {
        return Ok(());
    };
    let origin = origin.to_str().unwrap_or("");
    let configured = std::env::var("UNRELATED_GATEWAY_ALLOWED_ORIGINS").unwrap_or_default();
    let allowed = configured
        .split(',')
        .map(str::trim)
        .any(|item| !item.is_empty() && item == origin);
    let local = reqwest::Url::parse(origin).is_ok_and(|url| {
        matches!(url.scheme(), "http" | "https")
            && matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"))
            && url.username().is_empty()
            && url.password().is_none()
            && url.path() == "/"
            && url.query().is_none()
            && url.fragment().is_none()
    });
    if allowed || local {
        Ok(())
    } else {
        Err((StatusCode::FORBIDDEN, "Origin is not allowed").into_response())
    }
}

fn validate_request(
    profile: &crate::store::Profile,
    headers: &HeaderMap,
    body: &Value,
) -> Result<(), Response> {
    validate_origin(headers)?;
    if body["jsonrpc"] != "2.0"
        || !(body["id"].is_string() || body["id"].is_i64())
        || !body["method"].is_string()
    {
        return Err(error(
            StatusCode::BAD_REQUEST,
            &body["id"],
            rmcp::model::ErrorCode::INVALID_REQUEST.0,
            "Invalid JSON-RPC request",
            Value::Null,
        ));
    }
    let version = body["params"]["_meta"][VERSION_META].as_str().unwrap_or("");
    if version != VERSION || !profile.mcp.modern_protocol {
        let mut supported: Vec<_> = initialize::LEGACY_VERSIONS
            .iter()
            .map(ProtocolVersion::as_str)
            .collect();
        if profile.mcp.modern_protocol {
            supported.insert(0, VERSION);
        }
        return Err(error(
            StatusCode::BAD_REQUEST,
            &body["id"],
            rmcp::model::ErrorCode::UNSUPPORTED_PROTOCOL_VERSION.0,
            "Unsupported protocol version",
            json!({"supported":supported,"requested":version}),
        ));
    }
    if headers
        .get(HEADER_MCP_PROTOCOL_VERSION)
        .and_then(|v| v.to_str().ok())
        != Some(version)
        || headers.get_all(HEADER_MCP_PROTOCOL_VERSION).iter().count() != 1
    {
        return Err(error(
            StatusCode::BAD_REQUEST,
            &body["id"],
            rmcp::model::ErrorCode::HEADER_MISMATCH.0,
            "MCP-Protocol-Version does not match request metadata",
            Value::Null,
        ));
    }
    let meta = serde_json::from_value::<RequestMetaObject>(body["params"]["_meta"].clone())
        .map_err(|_| {
            error(
                StatusCode::BAD_REQUEST,
                &body["id"],
                -32602,
                "Invalid request metadata",
                Value::Null,
            )
        })?;
    let missing = meta.missing_required_keys(&ProtocolVersion::V_2026_07_28);
    if !missing.is_empty() {
        return Err(error(
            StatusCode::BAD_REQUEST,
            &body["id"],
            -32602,
            "Missing request metadata",
            json!({"missing":missing}),
        ));
    }
    unrelated_mcp_support::headers::validate_request_headers(headers, body, None).map_err(
        |message| {
            error(
                StatusCode::BAD_REQUEST,
                &body["id"],
                rmcp::model::ErrorCode::HEADER_MISMATCH.0,
                message,
                Value::Null,
            )
        },
    )
}

async fn routing_payload(
    state: &McpState,
    profile: &crate::store::Profile,
    headers: &HeaderMap,
    tolerate_unavailable: bool,
) -> Result<TokenPayloadV1, Response> {
    let (auth, oidc) = match profile.data_plane_auth_mode {
        DataPlaneAuthMode::Disabled => (None, None),
        DataPlaneAuthMode::ApiKey => (
            Some(auth::authenticate_api_key_on_initialize(state, profile, headers).await?),
            None,
        ),
        DataPlaneAuthMode::OAuth => (
            None,
            Some(auth::authorize_oauth_request(state, profile, headers).await?),
        ),
    };
    let local_ids = state
        .store
        .tenant_tool_source_ids(&profile.tenant_id, &profile.source_ids)
        .await
        .map_err(protocol::internal_error_response(
            "classify tenant tool sources",
        ))?;
    let mut bindings = Vec::new();
    for source in &profile.source_ids {
        if state.catalog.is_local_tool_source(source) || local_ids.contains(source) {
            continue;
        }
        let upstream = state
            .store
            .get_upstream(source)
            .await
            .map_err(protocol::internal_error_response("load upstream"))?;
        let endpoint = upstream.as_ref().and_then(|upstream| {
            upstream.endpoints.iter().find(|endpoint| {
                endpoint.enabled && endpoint.lifecycle == UpstreamEndpointLifecycle::Active
            })
        });
        if let Some(endpoint) = endpoint {
            bindings.push(UpstreamSessionBinding {
                upstream: source.clone(),
                endpoint: endpoint.id.clone(),
                session: None,
                protocol_version: Some(VERSION.into()),
            });
        } else if !profile.allow_partial_upstreams && !tolerate_unavailable {
            return Err(error(
                StatusCode::BAD_GATEWAY,
                &Value::Null,
                -32603,
                "No active upstream endpoint",
                Value::Null,
            ));
        }
    }
    Ok(TokenPayloadV1 {
        request_meta: None,
        profile_id: profile.id.clone(),
        bindings,
        auth,
        oidc,
        iat: None,
        exp: None,
        proxy_key: None,
    })
}

#[derive(Clone)]
pub(super) struct VerifiedContinuation;

pub(super) fn is_verified_continuation(message: &ClientJsonRpcMessage) -> bool {
    matches!(message, ClientJsonRpcMessage::Request(rmcp::model::JsonRpcRequest {
        request: rmcp::model::ClientRequest::CallToolRequest(call), ..
    }) if call.extensions.get::<VerifiedContinuation>().is_some())
}

pub(super) async fn handle_post(
    state: Arc<McpState>,
    request: RequestContext,
    headers: HeaderMap,
    mut body: Value,
) -> Result<Response, Response> {
    validate_request(&request.profile, &headers, &body)?;
    let tolerate_unavailable = body["params"].get("requestState").is_some()
        || body["params"].get("taskId").is_some()
        || body["method"] == "server/discover"
        || body["params"]["notifications"].get("taskIds").is_some();
    let mut payload =
        routing_payload(&state, &request.profile, &headers, tolerate_unavailable).await?;
    payload.request_meta = Some(body["params"]["_meta"].clone());
    let method = body["method"].as_str().unwrap_or("").to_owned();
    let id = body["id"].clone();
    if method == "server/discover" {
        return Ok(discover(&request.profile, &id));
    }
    if method == "subscriptions/listen" {
        return subscriptions::listen(state, request, payload, headers, body).await;
    }
    let (task, tasks_allowed) = validate_method(&method, &body)?;
    let original = body.clone();
    let (sealed, restored) = restore(&state, &request.profile, &mut payload, &mut body, task)?;
    let identity = json!({"profile":request.profile.id,"auth":payload.auth,"oidc":payload.oidc,"meta":body["params"]["_meta"]});
    let cache_key = format!(
        "modern:{}",
        hex::encode(sha2::Sha256::digest(identity.to_string().as_bytes()))
    );
    let resolved_binding =
        resolve_request_binding(&state, &request, &payload, &headers, &original, &cache_key)
            .await?;
    let binding = if let Some(restored) = &restored {
        Some(restored.binding.clone())
    } else {
        resolved_binding
    };
    let route_state = restored.clone().or_else(|| {
        binding.map(|binding| RouteState::new(&request.profile, &payload, binding, &original))
    });
    let mut message: ClientJsonRpcMessage = serde_json::from_value(body).map_err(|e| {
        error(
            StatusCode::BAD_REQUEST,
            &id,
            -32602,
            e.to_string(),
            Value::Null,
        )
    })?;
    if restored.is_some()
        && !task
        && let ClientJsonRpcMessage::Request(rmcp::model::JsonRpcRequest {
            request: rmcp::model::ClientRequest::CallToolRequest(call),
            ..
        }) = &mut message
    {
        call.extensions.insert(VerifiedContinuation);
    }
    let result = if task {
        let source = &restored.as_ref().expect("verified task").binding.upstream;
        super::upstream::proxy_to_single_upstream(
            &state,
            &request.profile.id,
            &payload,
            source,
            message,
            super::parse_hop(&headers),
        )
        .await
    } else {
        super::handle_post_in_session_request(
            &state,
            &request,
            &payload,
            cache_key,
            &mut message,
            super::parse_hop(&headers),
        )
        .await
    };
    let context = Arc::new(ResponseContext {
        signer: state.signer.clone(),
        profile: request.profile,
        route: route_state,
        task_token: if task { sealed } else { None },
        tasks_allowed,
        id,
        method,
        limit: request.limits.max_sse_event_bytes,
    });
    modern_response(result.unwrap_or_else(|response| response), context).await
}

async fn resolve_request_binding(
    state: &McpState,
    request: &RequestContext,
    payload: &TokenPayloadV1,
    headers: &HeaderMap,
    body: &Value,
    cache_key: &str,
) -> Result<Option<UpstreamSessionBinding>, Response> {
    let method = body["method"].as_str().unwrap_or("");
    let hop = super::parse_hop(headers);
    let source = match method {
        "tools/call" => {
            let Some(source) =
                resolve_tool_source(state, request, payload, headers, body, cache_key).await?
            else {
                return Ok(None);
            };
            source
        }
        "resources/read" => {
            super::surface::resolve_resource_owner(
                state,
                &request.profile.id,
                payload,
                body["params"]["uri"].as_str().unwrap_or(""),
                hop,
            )
            .await
            .map_err(|e| {
                error(
                    StatusCode::BAD_REQUEST,
                    &body["id"],
                    -32602,
                    e.to_string(),
                    Value::Null,
                )
            })?
            .0
        }
        "prompts/get" => {
            super::surface::resolve_prompt_owner(
                state,
                &request.profile.id,
                payload,
                body["params"]["name"].as_str().unwrap_or(""),
                hop,
            )
            .await
            .map_err(|e| {
                error(
                    StatusCode::BAD_REQUEST,
                    &body["id"],
                    -32602,
                    e.to_string(),
                    Value::Null,
                )
            })?
            .0
        }
        _ => return Ok(None),
    };
    Ok(payload
        .bindings
        .iter()
        .find(|binding| binding.upstream == source)
        .cloned())
}

struct ResponseContext {
    signer: crate::session_token::SessionSigner,
    profile: crate::store::Profile,
    route: Option<RouteState>,
    task_token: Option<String>,
    tasks_allowed: bool,
    id: Value,
    method: String,
    limit: u64,
}

fn modern_message(mut message: Value, context: &ResponseContext) -> Value {
    let id = &context.id;
    if message.get("method").is_some() && message.get("id").is_some() {
        return json!({"jsonrpc":"2.0","id":id,"error":{"code":-32603,"message":"Upstream requires the legacy interactive lifecycle"}});
    }
    if let Some(result) = message.get_mut("result") {
        if !result.is_object() || result.get("_meta").is_some_and(|meta| !meta.is_object()) {
            return json!({"jsonrpc":"2.0","id":id,"error":{"code":-32603,"message":"Invalid upstream result"}});
        }
        if result["resultType"] == "task" && context.method != "tools/call" {
            return json!({"jsonrpc":"2.0","id":id,"error":{"code":-32603,"message":"Only tools/call can create tasks"}});
        }
        result["_meta"]["io.modelcontextprotocol/serverInfo"] =
            json!({"name":"unrelated-mcp-gateway","version":env!("CARGO_PKG_VERSION")});
        if result["resultType"] == "task" && !context.tasks_allowed {
            return json!({"jsonrpc":"2.0","id":id,"error":{"code":rmcp::model::ErrorCode::MISSING_REQUIRED_CLIENT_CAPABILITY.0,"message":"Missing required client capability","data":{"requiredCapabilities":{"extensions":{(TASKS_EXTENSION):{}}}}}});
        }
        if let Some(route) = &context.route
            && let Err(error) = route.wrap_result(
                &context.signer,
                &context.profile,
                result,
                context.task_token.as_deref(),
            )
        {
            return json!({"jsonrpc":"2.0","id":id,"error":{"code":-32603,"message":error.to_string()}});
        }
        if let Some(object) = result.as_object_mut() {
            object.entry("resultType").or_insert(json!("complete"));
            if matches!(
                context.method.as_str(),
                "tools/list"
                    | "resources/list"
                    | "resources/templates/list"
                    | "prompts/list"
                    | "resources/read"
            ) {
                object.insert("ttlMs".into(), json!(0));
                object.insert("cacheScope".into(), json!("private"));
            }
        }
    }
    message
}

async fn modern_response(
    response: Response,
    context: Arc<ResponseContext>,
) -> Result<Response, Response> {
    let id = &context.id;
    let limit = context.limit;
    let (mut parts, body) = response.into_parts();
    // Rewriting result metadata changes the body length.
    parts.headers.remove(axum::http::header::CONTENT_LENGTH);
    parts.headers.remove(super::HEADER_SESSION_ID);
    parts.headers.insert(
        "cache-control",
        axum::http::HeaderValue::from_static("no-store"),
    );
    let sse = parts
        .headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("text/event-stream"));
    if sse {
        let id = id.clone();
        let context = context.clone();
        let upstream = sse_stream::SseStream::from_bytes_stream(body.into_data_stream()).boxed();
        let stream = futures::stream::unfold((upstream, false), move |(mut upstream, done)| {
            let context = context.clone();
            let id = id.clone();
            async move {
                if done {
                    return None;
                }
                loop {
                    let event = upstream.next().await?;
                    if matches!(&event, Ok(event) if event.data.is_none()) {
                        continue;
                    }
                    let message = event.ok().and_then(|event| event.data).and_then(|data| {
                        (data.len() as u64 <= limit)
                            .then(|| serde_json::from_str::<Value>(&data).ok())
                            .flatten()
                    });
                    let data = message.map_or_else(|| json!({"jsonrpc":"2.0","id":id,"error":{"code":-32603,"message":"Invalid upstream event"}}), |message| modern_message(message, &context));
                    let done = data.get("id").is_some();
                    return Some((
                        Ok::<_, Infallible>(
                            axum::response::sse::Event::default().data(data.to_string()),
                        ),
                        (upstream, done),
                    ));
                }
            }
        });
        let mut response = axum::response::Sse::new(stream).into_response();
        response.headers_mut().insert(
            "cache-control",
            axum::http::HeaderValue::from_static("no-store"),
        );
        response.headers_mut().insert(
            "x-accel-buffering",
            axum::http::HeaderValue::from_static("no"),
        );
        return Ok(response);
    }
    let bytes = axum::body::to_bytes(body, usize::try_from(limit).unwrap_or(usize::MAX))
        .await
        .map_err(|_| {
            error(
                StatusCode::BAD_GATEWAY,
                id,
                -32603,
                "Response exceeds payload limit",
                Value::Null,
            )
        })?;
    if let Ok(message) = serde_json::from_slice::<Value>(&bytes) {
        return Ok(Response::from_parts(
            parts,
            axum::body::Body::from(modern_message(message, &context).to_string()),
        ));
    }
    Ok(Response::from_parts(parts, axum::body::Body::from(bytes)))
}

fn discover(profile: &crate::store::Profile, id: &Value) -> Response {
    let mut config =
        initialize::gateway_initialize_result(profile, ProtocolVersion::V_2026_07_28, &[]);
    config.capabilities.extensions =
        Some(serde_json::from_value(json!({(TASKS_EXTENSION):{}})).expect("extension map"));
    let result = DiscoverResult::from_server_info(
        vec![ProtocolVersion::V_2026_07_28, ProtocolVersion::V_2025_11_25],
        config,
    );
    (
        [("cache-control", "no-store")],
        Json(json!({"jsonrpc":"2.0","id":id,"result":result})),
    )
        .into_response()
}

fn validate_method(method: &str, body: &Value) -> Result<(bool, bool), Response> {
    let id = &body["id"];
    let task = matches!(method, "tasks/get" | "tasks/update" | "tasks/cancel");
    if !task
        && !matches!(
            method,
            "tools/list"
                | "tools/call"
                | "resources/list"
                | "resources/templates/list"
                | "resources/read"
                | "prompts/list"
                | "prompts/get"
                | "completion/complete"
                | "ping"
        )
    {
        return Err(error(
            StatusCode::NOT_FOUND,
            id,
            -32601,
            "Method not found",
            Value::Null,
        ));
    }
    let tasks_allowed = body["params"]["_meta"][CLIENT_CAPABILITIES_META]["extensions"]
        .get(TASKS_EXTENSION)
        .is_some_and(Value::is_object);
    if task && !tasks_allowed {
        return Err(error(
            StatusCode::BAD_REQUEST,
            id,
            rmcp::model::ErrorCode::MISSING_REQUIRED_CLIENT_CAPABILITY.0,
            "Missing required client capability",
            json!({"requiredCapabilities":{"extensions":{(TASKS_EXTENSION):{}}}}),
        ));
    }
    Ok((task, tasks_allowed))
}

fn restore(
    state: &McpState,
    profile: &crate::store::Profile,
    payload: &mut TokenPayloadV1,
    body: &mut Value,
    task: bool,
) -> Result<(Option<String>, Option<RouteState>), Response> {
    let id = body["id"].clone();
    let sealed = body["params"][if task { "taskId" } else { "requestState" }]
        .as_str()
        .map(str::to_owned);
    let restored = if let Some(token) = &sealed {
        Some(
            RouteState::open(&state.signer, token, task, profile, payload, body).map_err(|e| {
                error(
                    StatusCode::BAD_REQUEST,
                    &id,
                    -32602,
                    e.to_string(),
                    Value::Null,
                )
            })?,
        )
    } else {
        None
    };
    if (task || body["params"].get("inputResponses").is_some()) && restored.is_none() {
        return Err(error(
            StatusCode::BAD_REQUEST,
            &id,
            -32602,
            "A verified continuation or task identifier is required",
            Value::Null,
        ));
    }
    if let Some(restored) = &restored {
        if let Some(binding) = payload
            .bindings
            .iter_mut()
            .find(|binding| binding.upstream == restored.binding.upstream)
        {
            *binding = restored.binding.clone();
        } else {
            payload.bindings.push(restored.binding.clone());
        }
        if task {
            body["params"]["taskId"] = json!(restored.task_id);
        } else if let Some(value) = &restored.upstream_state {
            body["params"]["requestState"] = json!(value);
        } else {
            body["params"]
                .as_object_mut()
                .expect("params")
                .remove("requestState");
        }
    }
    Ok((sealed, restored))
}

async fn resolve_tool_source(
    state: &McpState,
    request: &RequestContext,
    payload: &TokenPayloadV1,
    headers: &HeaderMap,
    body: &Value,
    cache_key: &str,
) -> Result<Option<String>, Response> {
    let hop = super::parse_hop(headers);
    let fingerprint = crate::tools_cache::profile_fingerprint(&request.profile);
    let surface = if let Some(surface) = state.tools_cache.get(cache_key, &fingerprint) {
        surface
    } else {
        let surface = Box::pin(super::surface::build_tools_surface(
            state,
            &request.profile.id,
            &request.profile,
            payload,
            hop,
        ))
        .await?;
        state.tools_cache.put(
            &request.profile.id,
            cache_key.to_owned(),
            fingerprint,
            surface.clone(),
        );
        surface
    };
    let name = body["params"]["name"].as_str().unwrap_or("");
    let Some(route) = surface.routes.get(name) else {
        return Ok(None);
    };
    if let Some(tool) = surface.tools.iter().find(|tool| {
        surface
            .routes
            .get(tool.name.as_ref())
            .is_some_and(|candidate| {
                candidate.source_id == route.source_id
                    && candidate.original_name == route.original_name
            })
    }) {
        unrelated_mcp_support::headers::validate_request_headers(
            headers,
            body,
            Some(&json!(tool.input_schema)),
        )
        .map_err(|message| {
            error(
                StatusCode::BAD_REQUEST,
                &body["id"],
                rmcp::model::ErrorCode::HEADER_MISMATCH.0,
                message,
                Value::Null,
            )
        })?;
    }
    Ok(Some(route.source_id.clone()))
}

#[cfg(test)]
mod response_tests {
    use super::*;
    use crate::store::Store as _;

    #[tokio::test]
    async fn malformed_upstream_results_return_errors_without_panicking() -> anyhow::Result<()> {
        let config =
            serde_json::from_value(json!({"profiles":{"p":{"tenantId":"t","upstreams":[]}}}))?;
        let store = crate::store::ConfigStore::new(config);
        let context = ResponseContext {
            signer: crate::session_token::SessionSigner::new(
                vec![b"test key".to_vec()],
                std::time::Duration::from_secs(60),
            )?,
            profile: store.get_profile("p").await?.unwrap(),
            route: None,
            task_token: None,
            tasks_allowed: false,
            id: json!(1),
            method: "tools/list".into(),
            limit: 1024,
        };
        for result in [
            json!(42),
            json!([]),
            json!(null),
            json!({"_meta":"invalid"}),
        ] {
            let response =
                modern_message(json!({"jsonrpc":"2.0","id":1,"result":result}), &context);
            assert_eq!(response["error"]["code"], -32603);
            assert_eq!(response["id"], 1);
            assert!(response.get("result").is_none());
        }
        let response = modern_message(
            json!({"jsonrpc":"2.0","id":1,"result":{"tools":[]}}),
            &context,
        );
        assert!(response.get("error").is_none());
        assert!(response["result"]["_meta"]["io.modelcontextprotocol/serverInfo"].is_object());
        Ok(())
    }
}
