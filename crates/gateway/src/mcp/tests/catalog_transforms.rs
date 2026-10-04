use super::*;
use axum::{
    Json,
    extract::{Path, State},
};
use serde_json::{Value, json};
use unrelated_mcp_support::headers::{
    CLIENT_CAPABILITIES_META, CLIENT_INFO_META, VERSION, VERSION_META,
};

type Requests = Arc<Mutex<Vec<(String, Value)>>>;

async fn fixture(
    Path(source): Path<String>,
    State(requests): State<Requests>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    requests
        .lock()
        .unwrap()
        .push((source.clone(), body.clone()));
    let method = body["method"].as_str().unwrap();
    if body["params"]["_meta"][VERSION_META] == VERSION {
        unrelated_mcp_support::headers::validate_request_headers(&headers, &body, None).unwrap();
    }
    if method.starts_with("notifications/") {
        return StatusCode::ACCEPTED.into_response();
    }
    let result = match method {
        "initialize" => {
            json!({"protocolVersion":"2025-11-25","capabilities":{"resources":{"subscribe":true},"prompts":{},"completions":{}},"serverInfo":{"name":"catalog","version":"1"}})
        }
        "server/discover" => serde_json::to_value(rmcp::model::DiscoverResult::new(
            vec![rmcp::model::ProtocolVersion::V_2026_07_28],
            rmcp::model::ServerCapabilities::builder()
                .enable_resources()
                .enable_resources_subscribe()
                .enable_prompts()
                .enable_completions()
                .build(),
        ))
        .unwrap(),
        "resources/list" => {
            json!({"resources":[{"uri":"test:///public","name":"public"},{"uri":"test:///private/single","name":"private"}]})
        }
        "resources/templates/list" => {
            json!({"resourceTemplates":[{"uriTemplate":"test:///private/{id}{?format}","name":"private"},{"uriTemplate":"test:///public/{id}","name":"public"}]})
        }
        "prompts/list" => {
            json!({"prompts":[{"name":"greet","arguments":[{"name":"topic","required":true},{"name":"audience","required":true}]},{"name":"secret"}]})
        }
        "resources/read" => {
            json!({"contents":[{"uri":body["params"]["uri"],"text":"unchanged payload"}]})
        }
        "prompts/get" => {
            json!({"messages":[{"role":"user","content":{"type":"text","text":body["params"].to_string()}}]})
        }
        "completion/complete" => {
            json!({"completion":{"values":["suggestion"],"total":1,"hasMore":false}})
        }
        "resources/subscribe" | "resources/unsubscribe" => json!({}),
        _ => panic!("unexpected {method}"),
    };
    Json(json!({"jsonrpc":"2.0","id":body["id"],"result":result})).into_response()
}

struct Client {
    http: reqwest::Client,
    url: String,
    token: Option<String>,
    native: bool,
}
impl Client {
    async fn send(&self, method: &str, mut params: Value) -> anyhow::Result<Value> {
        if self.native {
            params["_meta"] = json!({(VERSION_META):VERSION,(CLIENT_INFO_META):{"name":"test","version":"1"},(CLIENT_CAPABILITIES_META):{}});
        }
        let body = json!({"jsonrpc":"2.0","id":7,"method":method,"params":params});
        let mut request = self
            .http
            .post(&self.url)
            .header("accept", "application/json, text/event-stream")
            .json(&body);
        if let Some(token) = &self.token {
            request = request.header(HEADER_SESSION_ID, token);
        }
        if self.native {
            request = request.header("mcp-protocol-version", VERSION).headers(
                unrelated_mcp_support::headers::request_headers(&body, None)
                    .map_err(anyhow::Error::msg)?,
            );
        }
        let response = request.send().await?.text().await?;
        Ok(serde_json::from_str(
            response
                .trim()
                .strip_prefix("data:")
                .unwrap_or(&response)
                .trim(),
        )?)
    }
}

fn rules() -> unrelated_tool_transforms::TransformPipeline {
    serde_json::from_value(json!({
        "resourceOverrides":{"stateful":{"test:///public":{"name":"Policy guide","description":"Read the guide"}}},
        "resourceTemplateOverrides":{"stateful":{"test:///private/{id}{?format}":{"enabled":false},"test:///public/{id}":{"title":"Public documents"}}},
        "promptOverrides":{
            "stateful":{"greet":{"rename":"review","description":"Review a subject","params":{"topic":{"rename":"subject","default":"latest changes"},"audience":{"default":"engineering"}}},"secret":{"enabled":false}},
            "stateless":{"greet":{"rename":"review"}}
        }
    })).unwrap()
}

#[tokio::test]
async fn catalog_transforms_apply_to_both_protocols_and_block_direct_bypasses() -> anyhow::Result<()>
{
    let requests = Requests::default();
    let (upstream, server) = start_server(
        Router::new()
            .route("/{source}", post(fixture).get(fixture_stream))
            .with_state(requests.clone()),
    )
    .await;
    for native in [false, true] {
        let id = Uuid::new_v4().to_string();
        let base = upstream_sessions::gateway_state(&upstream, &id).await?;
        let mut profile = base.store.get_profile(&id).await?.unwrap();
        profile.mcp.modern_protocol = native;
        profile.transforms = rules();
        let mut upstreams = HashMap::new();
        for source in &profile.source_ids {
            upstreams.insert(
                source.clone(),
                base.store.get_upstream(source).await?.unwrap(),
            );
        }
        let state = Arc::new(McpState {
            store: Arc::new(TestStore {
                profiles: HashMap::from([(id.clone(), profile.clone())]),
                upstreams,
            }),
            ..Arc::try_unwrap(base).ok().unwrap()
        });
        let probe = probe_profile_surface(&state, &profile)
            .await
            .map_err(anyhow::Error::msg)?;
        assert_eq!(probe.all_resources.len(), 4);
        assert_eq!(probe.resources.len(), 3);
        assert_eq!(probe.all_prompts.len(), 4);
        assert_eq!(probe.prompts.len(), 3);
        let (gateway, gateway_server) = start_server(router(state)).await;
        let mut client = Client {
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .build()?,
            url: format!("{gateway}/{id}/mcp"),
            token: None,
            native,
        };
        if !native {
            let response = client.http.post(&client.url).header("accept","application/json, text/event-stream").json(&json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}})).send().await?;
            client.token = Some(response.headers()[HEADER_SESSION_ID].to_str()?.into());
        }
        assert_catalogs(&client).await?;
        assert_calls(&client, &requests).await?;
        assert_blocked(&client, &requests).await?;
        if !native {
            assert_stream_filters(&client).await?;
        }
        gateway_server.abort();
    }
    server.abort();
    Ok(())
}

async fn assert_catalogs(client: &Client) -> anyhow::Result<()> {
    let resources = client.send("resources/list", json!({})).await?;
    assert!(resources["error"].is_null(), "{resources}");
    assert_eq!(
        resources["result"]["resources"].as_array().unwrap().len(),
        3,
        "{resources}"
    );
    let policy = resources["result"]["resources"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"] == "Policy guide")
        .unwrap();
    assert_eq!(
        policy["uri"],
        resource_collision_urn("stateful", "test:///public")
    );
    let templates = client.send("resources/templates/list", json!({})).await?;
    assert_eq!(
        templates["result"]["resourceTemplates"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    let prompts = client.send("prompts/list", json!({})).await?;
    let prompt = prompts["result"]["prompts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["name"] == "stateful:review")
        .unwrap();
    assert_eq!(prompt["arguments"][0]["name"], "subject");
    assert_eq!(prompt["arguments"][0]["required"], false);
    Ok(())
}

async fn assert_calls(client: &Client, requests: &Requests) -> anyhow::Result<()> {
    let result = client
        .send(
            "prompts/get",
            json!({"name":"stateful:review","arguments":{"subject":"my changes"}}),
        )
        .await?;
    assert!(result.get("error").is_none(), "{result}");
    let forwarded = requests
        .lock()
        .unwrap()
        .iter()
        .rev()
        .find(|(_, r)| r["method"] == "prompts/get")
        .unwrap()
        .1
        .clone();
    assert_eq!(forwarded["params"]["name"], "greet");
    assert_eq!(
        forwarded["params"]["arguments"],
        json!({"topic":"my changes","audience":"engineering"})
    );
    let complete = client.send("completion/complete",json!({"ref":{"type":"ref/prompt","name":"stateful:review"},"argument":{"name":"subject","value":"my"},"context":{"arguments":{"audience":"writers"}}})).await?;
    assert!(complete.get("error").is_none(), "{complete}");
    let forwarded = requests
        .lock()
        .unwrap()
        .iter()
        .rev()
        .find(|(_, r)| r["method"] == "completion/complete")
        .unwrap()
        .1
        .clone();
    assert_eq!(forwarded["params"]["ref"]["name"], "greet");
    assert_eq!(forwarded["params"]["argument"]["name"], "topic");
    assert_eq!(
        forwarded["params"]["context"]["arguments"],
        json!({"audience":"writers"})
    );
    let uri = unrelated_mcp_support::resource_template_uri("stateful", "test:///public/document");
    let read = client.send("resources/read", json!({"uri":uri})).await?;
    assert_eq!(read["result"]["contents"][0]["text"], "unchanged payload");
    Ok(())
}

async fn assert_blocked(client: &Client, requests: &Requests) -> anyhow::Result<()> {
    let mut cases = vec![
        ("prompts/get", json!({"name":"stateful:secret"})),
        ("prompts/get", json!({"name":"stateful:greet"})),
        ("prompts/get", json!({"name":"review"})),
        (
            "completion/complete",
            json!({"ref":{"type":"ref/prompt","name":"stateful:secret"},"argument":{"name":"topic","value":"x"}}),
        ),
    ];
    let disabled = unrelated_mcp_support::resource_template_uri(
        "stateful",
        "test:///private/a%2Fb?format=text",
    );
    for uri in [
        disabled.clone(),
        resource_collision_urn("stateful", "test:///private/single"),
    ] {
        cases.push(("resources/read", json!({"uri":uri})));
        cases.push((
            "completion/complete",
            json!({"ref":{"type":"ref/resource","uri":uri},"argument":{"name":"id","value":"x"}}),
        ));
    }
    if client.native {
        cases.push((
            "subscriptions/listen",
            json!({"notifications":{"resourceSubscriptions":[disabled]}}),
        ));
    } else {
        cases.push(("resources/subscribe", json!({"uri":disabled})));
        cases.push(("resources/unsubscribe", json!({"uri":disabled})));
    }
    for (method, params) in cases {
        let count = requests
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, r)| r["method"] == method)
            .count();
        let response = client.send(method, params).await?;
        assert!(response.get("error").is_some(), "{method}: {response}");
        assert_eq!(
            requests
                .lock()
                .unwrap()
                .iter()
                .filter(|(_, r)| r["method"] == method)
                .count(),
            count,
            "blocked call reached upstream: {method}"
        );
    }
    Ok(())
}

async fn fixture_stream() -> Response {
    let events = ["test:///private/single", "test:///public"].map(|uri| {
        Ok::<_, Infallible>(axum::response::sse::Event::default().data(json!({"jsonrpc":"2.0","method":"notifications/resources/updated","params":{"uri":uri}}).to_string()))
    });
    Sse::new(futures::stream::iter(events)).into_response()
}

async fn assert_stream_filters(client: &Client) -> anyhow::Result<()> {
    let response = client
        .http
        .get(&client.url)
        .header("accept", "text/event-stream")
        .header(HEADER_SESSION_ID, client.token.as_ref().unwrap())
        .send()
        .await?;
    let mut stream = sse_stream::SseStream::from_bytes_stream(response.bytes_stream());
    let mut received = Vec::new();
    while received.len() < 3 {
        let event = tokio::time::timeout(Duration::from_secs(3), stream.next())
            .await?
            .ok_or_else(|| anyhow::anyhow!("stream ended"))??;
        if let Some(data) = event.data {
            let message: Value = serde_json::from_str(&data)?;
            if message["method"] == "notifications/resources/updated" {
                received.push(message["params"]["uri"].as_str().unwrap().to_owned());
            }
        }
    }
    assert!(!received.contains(&resource_collision_urn(
        "stateful",
        "test:///private/single"
    )));
    assert!(received.contains(&resource_collision_urn(
        "stateless",
        "test:///private/single"
    )));
    Ok(())
}
