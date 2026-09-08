use super::*;

#[tokio::test]
async fn post_loads_configuration_once_and_refreshes_it_for_the_next_request() -> anyhow::Result<()>
{
    let profile_id = Uuid::new_v4().to_string();
    let cfg: GatewayConfig = serde_json::from_value(serde_json::json!({
        "tenants": {"t": {"enabled": true}},
        "profiles": {&profile_id: {"tenantId": "t", "upstreams": ["local"]}},
        "sharedSources": {"local": {
            "type": "http", "baseUrl": "https://example.com",
            "tools": {"ping": {"method": "GET", "path": "/ping"}}
        }}
    }))?;
    let catalog = Arc::new(SharedCatalog::from_config(&cfg).await?);
    let profile = crate::store::ConfigStore::new(cfg)
        .get_profile(&profile_id)
        .await?
        .unwrap();
    let store = Arc::new(CountingStore::default());
    store
        .profiles
        .lock()
        .unwrap()
        .insert(profile_id.clone(), profile);
    let state = Arc::new(McpState {
        store: store.clone(),
        signer: SessionSigner::new(vec![vec![0u8; 32]], Duration::from_secs(60))?,
        http: reqwest::Client::default(),
        oauth: None,
        shutdown: CancellationToken::new(),
        audit: Arc::new(crate::audit::NoopAuditSink),
        catalog,
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
    let (base, server) = start_server(router(state)).await;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;
    let url = format!("{base}/{profile_id}/mcp");
    let init = client.post(&url).header("accept", "application/json, text/event-stream")
        .json(&serde_json::json!({"jsonrpc":"2.0", "id":1, "method":"initialize", "params":{
            "protocolVersion":"2025-11-25", "capabilities":{}, "clientInfo":{"name":"test", "version":"1"}
        }})).send().await?;
    assert_eq!(init.status(), StatusCode::OK);
    let token = init.headers()[HEADER_SESSION_ID].to_str()?.to_owned();
    assert_eq!(store.get_profile_calls.load(Ordering::SeqCst), 1);
    assert_eq!(store.get_limits_calls.load(Ordering::SeqCst), 1);
    for (i, method) in ["ping", "tools/list"].into_iter().enumerate() {
        let response = client
            .post(&url)
            .header("accept", "application/json, text/event-stream")
            .header(HEADER_SESSION_ID, &token)
            .json(&serde_json::json!({"jsonrpc":"2.0", "id":2, "method":method}))
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(store.get_profile_calls.load(Ordering::SeqCst), i + 2);
        assert_eq!(store.get_limits_calls.load(Ordering::SeqCst), i + 2);
    }
    store.profiles.lock().unwrap().remove(&profile_id);
    let removed = client
        .post(&url)
        .header("accept", "application/json, text/event-stream")
        .header(HEADER_SESSION_ID, &token)
        .json(&serde_json::json!({"jsonrpc":"2.0", "id":3, "method":"ping"}))
        .send()
        .await?;
    assert_eq!(removed.status(), StatusCode::NOT_FOUND);
    assert_eq!(store.get_profile_calls.load(Ordering::SeqCst), 4);
    assert_eq!(store.get_limits_calls.load(Ordering::SeqCst), 3);
    server.abort();
    Ok(())
}
