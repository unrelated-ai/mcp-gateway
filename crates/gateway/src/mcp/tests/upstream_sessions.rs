use super::*;
use axum::Json;
use axum::extract::{Path, State};

#[derive(Clone, Debug)]
struct RecordedRequest {
    source: String,
    method: String,
    session: Option<String>,
    version: Option<String>,
}

type Requests = Arc<Mutex<Vec<RecordedRequest>>>;

fn record(requests: &Requests, source: &str, method: &str, headers: &HeaderMap) {
    requests.lock().unwrap().push(RecordedRequest {
        source: source.into(),
        method: method.into(),
        session: headers
            .get(HEADER_SESSION_ID)
            .map(|v| v.to_str().unwrap().to_owned()),
        version: headers
            .get("mcp-protocol-version")
            .map(|v| v.to_str().unwrap().to_owned()),
    });
}

async fn fixture_post(
    Path(source): Path<String>,
    State(requests): State<Requests>,
    headers: HeaderMap,
    Json(message): Json<serde_json::Value>,
) -> Response {
    let method = message["method"].as_str().unwrap();
    record(&requests, &source, method, &headers);
    let stateful = source == "stateful";
    if method != "initialize" {
        let session = headers.get(HEADER_SESSION_ID).and_then(|v| v.to_str().ok());
        if session != stateful.then_some("upstream-session")
            || headers
                .get("mcp-protocol-version")
                .and_then(|v| v.to_str().ok())
                != Some("2025-11-25")
        {
            return StatusCode::BAD_REQUEST.into_response();
        }
    }
    if method.starts_with("notifications/") {
        return StatusCode::ACCEPTED.into_response();
    }
    let result = match method {
        "initialize" => serde_json::json!({
            "protocolVersion":"2025-11-25", "capabilities":{"tools":{}},
            "serverInfo":{"name":source,"version":"1"}
        }),
        "tools/list" => serde_json::json!({"tools":[{
            "name":"echo", "description":"echo", "inputSchema":{"type":"object"}
        }]}),
        "tools/call" => serde_json::json!({"content":[{"type":"text","text":source}]}),
        "resources/list" => serde_json::json!({"resources":[]}),
        "prompts/list" => serde_json::json!({"prompts":[]}),
        _ => serde_json::json!({}),
    };
    let mut response =
        Json(serde_json::json!({"jsonrpc":"2.0", "id":message["id"], "result":result}))
            .into_response();
    if stateful && method == "initialize" {
        response.headers_mut().insert(
            HEADER_SESSION_ID,
            HeaderValue::from_static("upstream-session"),
        );
    }
    response
}

async fn fixture_get(
    Path(source): Path<String>,
    State(requests): State<Requests>,
    headers: HeaderMap,
) -> Response {
    record(&requests, &source, "GET", &headers);
    if source == "stateless" {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    Sse::new(futures::stream::empty::<
        Result<axum::response::sse::Event, Infallible>,
    >())
    .into_response()
}

async fn fixture_delete(
    Path(source): Path<String>,
    State(requests): State<Requests>,
    headers: HeaderMap,
) -> Response {
    record(&requests, &source, "DELETE", &headers);
    StatusCode::ACCEPTED.into_response()
}

async fn gateway_state(upstream_base: &str, profile_id: &str) -> anyhow::Result<Arc<McpState>> {
    let cfg: GatewayConfig = serde_json::from_value(serde_json::json!({
        "tenants":{"t":{"enabled":true}},
        "profiles":{profile_id:{"tenantId":"t", "upstreams":["stateful","stateless"], "allowPartialUpstreams":false}}
    }))?;
    let profile = crate::store::ConfigStore::new(cfg)
        .get_profile(profile_id)
        .await?
        .unwrap();
    let upstreams = ["stateful", "stateless"]
        .into_iter()
        .map(|name| {
            (
                name.to_owned(),
                crate::store::Upstream {
                    network_class: crate::store::UpstreamNetworkClass::ClusterInternalManaged,
                    endpoints: vec![crate::store::UpstreamEndpoint {
                        id: "one".into(),
                        url: format!("{upstream_base}/{name}"),
                        enabled: true,
                        lifecycle: crate::store::UpstreamEndpointLifecycle::Active,
                        auth: None,
                    }],
                },
            )
        })
        .collect();
    let state = Arc::new(McpState {
        store: Arc::new(TestStore {
            profiles: HashMap::from([(profile_id.to_owned(), profile)]),
            upstreams,
        }),
        signer: SessionSigner::new(vec![vec![0u8; 32]], Duration::from_secs(60))?,
        http: reqwest::Client::default(),
        oauth: None,
        shutdown: CancellationToken::new(),
        audit: Arc::new(crate::audit::NoopAuditSink),
        catalog: Arc::new(SharedCatalog::default()),
        tenant_catalog: Arc::new(TenantCatalog::new()),
        contracts: Arc::new(ContractTracker::new()),
        contract_fanout: None,
        tools_cache: Arc::new(crate::tools_cache::ToolSurfaceCache::new(
            Duration::from_secs(60),
        )),
        endpoint_cache: Arc::new(crate::endpoint_cache::UpstreamEndpointCache::new(
            Duration::from_secs(60),
        )),
    });
    Ok(state)
}

#[tokio::test]
async fn mixed_upstreams_support_discovery_calls_streams_and_session_cleanup() -> anyhow::Result<()>
{
    let requests = Requests::default();
    let (upstream_base, upstream_server) = start_server(
        Router::new()
            .route(
                "/{source}",
                post(fixture_post).get(fixture_get).delete(fixture_delete),
            )
            .with_state(requests.clone()),
    )
    .await;
    let profile_id = Uuid::new_v4().to_string();
    let state = gateway_state(&upstream_base, &profile_id).await?;
    let (base, gateway_server) = start_server(router(state.clone())).await;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;
    let url = format!("{base}/{profile_id}/mcp");
    let init = client.post(&url).header("accept", "application/json, text/event-stream")
        .json(&serde_json::json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
            "protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}
        }})).send().await?;
    assert_eq!(init.status(), StatusCode::OK);
    let token = init.headers()[HEADER_SESSION_ID].to_str()?.to_owned();
    let payload = state.signer.verify(&token)?;
    assert_eq!(payload.bindings.len(), 2);
    assert_eq!(
        payload.bindings[0].session.as_deref(),
        Some("upstream-session")
    );
    assert_eq!(payload.bindings[1].session, None);
    for method in ["tools/list", "resources/list", "prompts/list"] {
        let response = client
            .post(&url)
            .header("accept", "application/json, text/event-stream")
            .header(HEADER_SESSION_ID, &token)
            .json(&serde_json::json!({"jsonrpc":"2.0","id":2,"method":method}))
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(!response.text().await?.contains("\"error\""));
    }
    for source in ["stateful", "stateless"] {
        let response = client
            .post(&url)
            .header("accept", "application/json, text/event-stream")
            .header(HEADER_SESSION_ID, &token)
            .json(
                &serde_json::json!({"jsonrpc":"2.0","id":3,"method":"tools/call",
                "params":{"name":format!("{source}:echo"),"arguments":{}}}),
            )
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.text().await?.contains(source));
    }
    let stream = client
        .get(&url)
        .header("accept", "text/event-stream")
        .header(HEADER_SESSION_ID, &token)
        .send()
        .await?;
    assert_eq!(stream.status(), StatusCode::OK);
    drop(stream);
    let deleted = client
        .delete(&url)
        .header(HEADER_SESSION_ID, &token)
        .send()
        .await?;
    assert_eq!(deleted.status(), StatusCode::ACCEPTED);
    let profile = state.store.get_profile(&profile_id).await?.unwrap();
    let (sources, tools, _, _, _) = probe_profile_surface(&state, &profile)
        .await
        .map_err(anyhow::Error::msg)?;
    assert_eq!(sources.len(), 2);
    assert!(sources.iter().all(|source| source.ok), "{sources:?}");
    assert_eq!(tools.len(), 2);
    assert_recorded_sessions(&requests);
    gateway_server.abort();
    upstream_server.abort();
    Ok(())
}

fn assert_recorded_sessions(requests: &Requests) {
    let recorded = requests.lock().unwrap().clone();
    assert!(
        recorded
            .iter()
            .any(|r| r.source == "stateless" && r.method == "GET")
    );
    assert!(
        recorded
            .iter()
            .any(|r| r.source == "stateful" && r.method == "DELETE")
    );
    assert!(
        !recorded
            .iter()
            .any(|r| r.source == "stateless" && r.method == "DELETE")
    );
    for r in recorded.iter().filter(|r| r.method != "initialize") {
        assert_eq!(
            r.session.as_deref(),
            (r.source == "stateful").then_some("upstream-session")
        );
        assert_eq!(r.version.as_deref(), Some("2025-11-25"));
    }
}

#[test]
fn routing_binding_accepts_legacy_stateful_and_new_sessionless_tokens() {
    let old: UpstreamSessionBinding = serde_json::from_value(serde_json::json!({
        "upstream":"u","endpoint":"e","session":"existing-session"
    }))
    .unwrap();
    assert_eq!(old.session.as_deref(), Some("existing-session"));
    assert_eq!(old.protocol_version, None);
    let sessionless: UpstreamSessionBinding = serde_json::from_value(serde_json::json!({
        "upstream":"u","endpoint":"e","protocolVersion":"2025-11-25"
    }))
    .unwrap();
    assert_eq!(sessionless.session, None);
    let json = serde_json::to_value(sessionless).unwrap();
    assert!(json.get("session").is_none());
}
