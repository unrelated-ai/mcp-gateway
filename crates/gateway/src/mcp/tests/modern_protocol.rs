use super::*;
use anyhow::Context as _;
use axum::Json;
use serde_json::{Value, json};
use std::sync::atomic::{AtomicUsize, Ordering};
static ACTIVE_SUBSCRIPTIONS: AtomicUsize = AtomicUsize::new(0);
struct SubscriptionGuard;
impl Drop for SubscriptionGuard {
    fn drop(&mut self) {
        ACTIVE_SUBSCRIPTIONS.fetch_sub(1, Ordering::SeqCst);
    }
}

fn routing_schema() -> Value {
    json!({"type":"object","properties":{"mode":{"type":"string","x-mcp-header":"mode"}}})
}

async fn native_upstream(headers: HeaderMap, Json(body): Json<Value>) -> Response {
    if let Err(error) = unrelated_mcp_support::headers::validate_request_headers(
        &headers,
        &body,
        Some(&routing_schema()),
    ) {
        return (StatusCode::BAD_REQUEST, error).into_response();
    }
    assert_eq!(
        body["params"]["_meta"][unrelated_mcp_support::headers::VERSION_META],
        "2026-07-28"
    );
    assert!(headers.get(HEADER_SESSION_ID).is_none());
    if body["method"] == "subscriptions/listen" {
        ACTIVE_SUBSCRIPTIONS.fetch_add(1, Ordering::SeqCst);
        let guard = SubscriptionGuard;
        let stream = async_stream::stream! {
            let _guard = guard;
            yield Ok::<_, Infallible>(axum::response::sse::Event::default().comment("heartbeat"));
            let meta = json!({"io.modelcontextprotocol/subscriptionId":body["id"]});
            let ack = json!({"jsonrpc":"2.0","method":"notifications/subscriptions/acknowledged","params":{"_meta":meta,"notifications":body["params"]["notifications"]}});
            yield Ok(axum::response::sse::Event::default().data(ack.to_string()));
            if let Some(resources) = body["params"]["notifications"]["resourceSubscriptions"].as_array() {
                for uri in resources {
                    let notification = json!({"jsonrpc":"2.0","method":"notifications/resources/updated","params":{"_meta":meta,"uri":uri}});
                    yield Ok(axum::response::sse::Event::default().data(notification.to_string()));
                }
            }
            if let Some(tasks) = body["params"]["notifications"]["taskIds"].as_array() {
                for task in tasks {
                    let timestamp = time::OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339).unwrap();
                    let notification = json!({"jsonrpc":"2.0","method":"notifications/tasks","params":{"_meta":meta,"taskId":task,"status":"working","createdAt":timestamp,"lastUpdatedAt":timestamp,"ttlMs":86_400_000}});
                    yield Ok(axum::response::sse::Event::default().data(notification.to_string()));
                }
            }
            std::future::pending::<()>().await;
        };
        return axum::response::Sse::new(stream).into_response();
    }
    let timestamp = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();
    let result = match body["method"].as_str().unwrap() {
        "tools/list" => {
            json!({"tools":[{"name":"echo","description":body["params"]["_meta"]["io.modelcontextprotocol/clientInfo"]["name"],"inputSchema":routing_schema()}]})
        }
        "tools/call"
            if body["params"]["arguments"]["mode"] == "mrtr"
                && body["params"]["requestState"].is_null() =>
        {
            json!({"resultType":"input_required","requestState":"private-upstream-state","inputRequests":{"roots":{"method":"roots/list"}}})
        }
        "tools/call" if body["params"]["arguments"]["mode"] == "mrtr" => {
            assert_eq!(body["params"]["requestState"], "private-upstream-state");
            assert_eq!(
                body["params"]["inputResponses"]["roots"]["roots"],
                json!([])
            );
            json!({"content":[{"type":"text","text":"continued"}]})
        }
        "tools/call" if body["params"]["arguments"]["mode"] == "task" => {
            json!({"resultType":"task","taskId":"upstream-task","status":"working","createdAt":timestamp,"lastUpdatedAt":timestamp,"ttlMs":86_400_000})
        }
        "tasks/get" => {
            assert_eq!(body["params"]["taskId"], "upstream-task");
            json!({"resultType":"complete","taskId":"upstream-task","status":"completed","createdAt":timestamp,"lastUpdatedAt":timestamp,"ttlMs":86_400_000,"result":{"content":[{"type":"text","text":"task completed"}]}})
        }
        "tasks/update" | "tasks/cancel" => {
            assert_eq!(body["params"]["taskId"], "upstream-task");
            json!({"resultType":"complete"})
        }
        "tools/call" => json!({"content":[{"type":"text","text":"native response"}]}),
        _ => json!({}),
    };
    Json(json!({"jsonrpc":"2.0","id":body["id"],"result":result})).into_response()
}

fn native_request(method: &str) -> Value {
    json!({"jsonrpc":"2.0","id":1,"method":method,"params":{"_meta":{
        "io.modelcontextprotocol/protocolVersion":"2026-07-28",
        "io.modelcontextprotocol/clientInfo":{"name":"native test","version":"1"},
        "io.modelcontextprotocol/clientCapabilities":{"roots":{},"extensions":{"io.modelcontextprotocol/tasks":{}}}
    }}})
}

#[tokio::test]
async fn discovery_and_native_calls_need_no_downstream_or_upstream_session() -> anyhow::Result<()> {
    let (upstream, upstream_server) =
        start_server(Router::new().route("/{source}", post(native_upstream))).await;
    let profile_id = Uuid::new_v4().to_string();
    let base = super::upstream_sessions::gateway_state(&upstream, &profile_id).await?;
    let mut profile = base.store.get_profile(&profile_id).await?.unwrap();
    profile.mcp.modern_protocol = true;
    let mut upstreams = HashMap::new();
    for source in &profile.source_ids {
        upstreams.insert(
            source.clone(),
            base.store.get_upstream(source).await?.unwrap(),
        );
    }
    let other_id = Uuid::new_v4().to_string();
    let mut other = profile.clone();
    other.id.clone_from(&other_id);
    let state = Arc::new(McpState {
        store: Arc::new(TestStore {
            profiles: HashMap::from([(profile_id.clone(), profile), (other_id.clone(), other)]),
            upstreams,
        }),
        ..Arc::try_unwrap(base).ok().unwrap()
    });
    let (gateway, gateway_server) = start_server(router(state)).await;
    let client = reqwest::Client::new();
    let url = format!("{gateway}/{profile_id}/mcp");
    let catalog = post_native(&client, &url, &native_request("tools/list")).await?;
    assert_eq!(catalog["result"]["tools"][0]["description"], "native test");
    for method in ["server/discover", "tools/list", "tools/call"] {
        let mut request = native_request(method);
        if method == "tools/call" {
            request["params"]["name"] = json!("stateful:echo");
            request["params"]["arguments"] = json!({});
        }
        let headers = unrelated_mcp_support::headers::request_headers(&request, None).unwrap();
        let response = client
            .post(&url)
            .headers(headers)
            .header("mcp-protocol-version", "2026-07-28")
            .header("accept", "application/json, text/event-stream")
            .json(&request)
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().get(HEADER_SESSION_ID).is_none());
        let body = response.text().await?;
        assert!(body.contains("\"resultType\":\"complete\""), "{body}");
        assert!(!body.contains("\"error\""), "{body}");
    }
    let response = client
        .post(&url)
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/call")
        .header("accept", "application/json, text/event-stream")
        .json(&native_request("server/discover"))
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body: Value = response.json().await?;
    assert_eq!(body["error"]["code"], -32020);
    let token = assert_continuations_and_tasks(&client, &url).await?;
    assert_subscriptions(&client, &url, &token).await?;
    let mut request = native_request("tasks/get");
    request["params"]["taskId"] = json!(token);
    let result = post_native(&client, &format!("{gateway}/{other_id}/mcp"), &request).await?;
    assert_eq!(result["error"]["code"], -32602);
    // The SDK's actual discovery lifecycle validates the Gateway's wire format.
    let transport = rmcp::transport::StreamableHttpClientTransport::from_uri(url.clone());
    let service = rmcp::service::ClientServiceExt::serve_with_lifecycle(
        (),
        transport,
        rmcp::service::ClientLifecycleMode::Discover {
            preferred_versions: vec![rmcp::model::ProtocolVersion::V_2026_07_28],
        },
    )
    .await?;
    assert_eq!(service.list_all_tools().await?.len(), 2);
    service.cancel().await?;
    assert_native_rejections(&client, &url).await?;
    assert_native_chain(&gateway, &profile_id).await?;
    gateway_server.abort();
    upstream_server.abort();
    Ok(())
}

async fn post_native(
    client: &reqwest::Client,
    url: &str,
    request: &Value,
) -> anyhow::Result<Value> {
    let headers =
        unrelated_mcp_support::headers::request_headers(request, Some(&routing_schema())).unwrap();
    let response = client
        .post(url)
        .headers(headers)
        .header("mcp-protocol-version", "2026-07-28")
        .header("accept", "application/json, text/event-stream")
        .json(request)
        .send()
        .await?;
    let body = response.text().await?;
    let json = body
        .strip_prefix("data: ")
        .or_else(|| body.strip_prefix("data:"))
        .unwrap_or(&body)
        .trim();
    serde_json::from_str(json).with_context(|| format!("parse response: {body}"))
}

async fn assert_continuations_and_tasks(
    client: &reqwest::Client,
    url: &str,
) -> anyhow::Result<String> {
    let mut request = native_request("tools/call");
    request["params"]["name"] = json!("stateful:echo");
    request["params"]["arguments"] = json!({"mode":"mrtr"});
    let first = post_native(client, url, &request).await?;
    assert_eq!(first["result"]["resultType"], "input_required", "{first}");
    let token = first["result"]["requestState"]
        .as_str()
        .context("sealed request state")?;
    assert!(token.starts_with("v4.local."));
    assert!(!token.contains("private-upstream-state"));
    request["params"]["requestState"] = json!(token);
    request["params"]["inputResponses"] = json!({"roots":{"roots":[]}});
    let result = post_native(client, url, &request).await?;
    assert_eq!(
        result["result"]["content"][0]["text"], "continued",
        "{result}"
    );
    request["params"]["arguments"] = json!({"mode":"different"});
    let rejected = post_native(client, url, &request).await?;
    assert!(rejected.get("error").is_some(), "{rejected}");

    let mut request = native_request("tools/call");
    request["params"]["name"] = json!("stateful:echo");
    request["params"]["arguments"] = json!({"mode":"task"});
    let created = post_native(client, url, &request).await?;
    assert_eq!(created["result"]["resultType"], "task", "{created}");
    let token = created["result"]["taskId"]
        .as_str()
        .context("sealed task id")?;
    assert!(token.starts_with("v4.local."));
    for method in ["tasks/get", "tasks/update", "tasks/cancel"] {
        let mut request = native_request(method);
        request["params"]["taskId"] = json!(token);
        if method == "tasks/update" {
            request["params"]["inputResponses"] = json!({});
        }
        let result = post_native(client, url, &request).await?;
        assert!(result.get("error").is_none(), "{method}: {result}");
        if method == "tasks/get" {
            assert_eq!(result["result"]["taskId"], token);
        }
    }
    Ok(token.to_owned())
}

async fn assert_subscriptions(
    client: &reqwest::Client,
    url: &str,
    task: &str,
) -> anyhow::Result<()> {
    let uri = unrelated_mcp_support::resource_template_uri("stateful", "note://expanded");
    let mut request = native_request("subscriptions/listen");
    request["params"]["notifications"] =
        json!({"toolsListChanged":true,"resourceSubscriptions":[uri],"taskIds":[task]});
    let headers = unrelated_mcp_support::headers::request_headers(&request, None).unwrap();
    let response = client
        .post(url)
        .headers(headers)
        .header("mcp-protocol-version", "2026-07-28")
        .header("accept", "application/json, text/event-stream")
        .json(&request)
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let mut events = sse_stream::SseStream::from_bytes_stream(response.bytes_stream());
    let mut messages = Vec::new();
    while messages.len() < 3 {
        let event = tokio::time::timeout(std::time::Duration::from_secs(3), events.next())
            .await?
            .context("subscription closed")??;
        if let Some(data) = event.data {
            messages.push(serde_json::from_str::<Value>(&data)?);
        }
    }
    assert_eq!(
        messages[0]["method"],
        "notifications/subscriptions/acknowledged"
    );
    assert_eq!(
        messages[0]["params"]["notifications"]["taskIds"],
        json!([task])
    );
    assert_eq!(
        messages[0]["params"]["notifications"]["resourceSubscriptions"],
        json!([uri])
    );
    assert!(
        messages
            .iter()
            .any(|m| m["method"] == "notifications/tasks" && m["params"]["taskId"] == task)
    );
    assert!(
        messages
            .iter()
            .any(|m| m["method"] == "notifications/resources/updated" && m["params"]["uri"] == uri)
    );
    drop(events);
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        while ACTIVE_SUBSCRIPTIONS.load(Ordering::SeqCst) != 0 {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await?;
    Ok(())
}

async fn assert_native_rejections(client: &reqwest::Client, url: &str) -> anyhow::Result<()> {
    let request = native_request("nonexistent/method");
    let result = post_native(client, url, &request).await?;
    assert_eq!(result["error"]["code"], -32601);
    let mut request = native_request("server/discover");
    request["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"] = json!("2099-01-01");
    let result = post_native(client, url, &request).await?;
    assert_eq!(result["error"]["code"], -32022);
    let response = client
        .get(url)
        .header("mcp-protocol-version", "2026-07-28")
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    let response = client
        .post(url)
        .header("origin", "https://untrusted.example")
        .header("accept", "application/json, text/event-stream")
        .json(&native_request("server/discover"))
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    Ok(())
}

async fn assert_native_chain(inner: &str, inner_profile: &str) -> anyhow::Result<()> {
    let id = Uuid::new_v4().to_string();
    let base = super::upstream_sessions::gateway_state(inner, &id).await?;
    let mut profile = base.store.get_profile(&id).await?.unwrap();
    profile.mcp.modern_protocol = true;
    profile.source_ids = vec!["stateful".into()];
    let mut upstream = base.store.get_upstream("stateful").await?.unwrap();
    for endpoint in &mut upstream.endpoints {
        endpoint.url = format!("{inner}/{inner_profile}/mcp");
    }
    let state = Arc::new(McpState {
        store: Arc::new(TestStore {
            profiles: HashMap::from([(id.clone(), profile)]),
            upstreams: HashMap::from([("stateful".into(), upstream)]),
        }),
        ..Arc::try_unwrap(base).ok().unwrap()
    });
    let (outer, server) = start_server(router(state)).await;
    let mut call = native_request("tools/call");
    call["params"]["name"] = json!("stateful:stateful:echo");
    call["params"]["arguments"] = json!({"mode":"mrtr"});
    let client = reqwest::Client::new();
    let url = format!("{outer}/{id}/mcp");
    let first = post_native(&client, &url, &call).await?;
    assert_eq!(first["result"]["resultType"], "input_required", "{first}");
    call["params"]["requestState"] = first["result"]["requestState"].clone();
    call["params"]["inputResponses"] = json!({"roots":{"roots":[]}});
    let result = post_native(&client, &url, &call).await?;
    assert_eq!(
        result["result"]["content"][0]["text"], "continued",
        "{result}"
    );
    server.abort();
    Ok(())
}
