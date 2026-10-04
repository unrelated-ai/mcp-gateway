use super::*;
use axum::{
    Json,
    extract::{Path, State},
};
use serde_json::{Value, json};
use unrelated_mcp_support::headers::VERSION;

type Requests = Arc<Mutex<Vec<(String, String)>>>;

async fn post_catalog(
    Path(source): Path<String>,
    State(requests): State<Requests>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let method = body["method"].as_str().unwrap();
    requests
        .lock()
        .unwrap()
        .push((source.clone(), method.into()));
    let native = source == "stateless";
    if (method == "initialize" && native) || (method == "server/discover" && !native) {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    if method == "notifications/initialized" {
        return StatusCode::ACCEPTED.into_response();
    }
    let stall_tools = requests
        .lock()
        .unwrap()
        .iter()
        .any(|(s, m)| s == "fixture" && m == "stall-tools");
    if method == "tools/list" && stall_tools {
        return std::future::pending().await;
    }
    if native {
        assert_eq!(headers["mcp-protocol-version"], VERSION);
    }
    let next = if body["params"]["cursor"].is_null() {
        Some("second")
    } else {
        None
    };
    let suffix = if next.is_some() { "first" } else { "second" };
    let result = match method {
        "initialize" => {
            json!({"protocolVersion":"2025-11-25", "serverInfo":{"name":"fixture", "version":"1"}, "capabilities":{"tools":{},"resources":{},"prompts":{}}})
        }
        "server/discover" => serde_json::to_value(rmcp::model::DiscoverResult::new(
            vec![rmcp::model::ProtocolVersion::V_2026_07_28],
            rmcp::model::ServerCapabilities::builder()
                .enable_tools()
                .enable_resources()
                .enable_prompts()
                .build(),
        ))
        .unwrap(),
        "tools/list" => {
            json!({"tools":[{"name":suffix,"inputSchema":{"type":"object"}}],"nextCursor":next})
        }
        "resources/list" => {
            json!({"resources":[{"uri":format!("test:///{suffix}"),"name":suffix}],"nextCursor":next})
        }
        "resources/templates/list" => {
            json!({"resourceTemplates":[{"uriTemplate":format!("test:///{suffix}/{{id}}"),"name":suffix}],"nextCursor":next})
        }
        "prompts/list" => json!({"prompts":[{"name":suffix}],"nextCursor":next}),
        _ => panic!("Unexpected discovery method {method}"),
    };
    let mut response =
        Json(json!({"jsonrpc":"2.0","id":body["id"],"result":result})).into_response();
    if method == "initialize" {
        response
            .headers_mut()
            .insert(HEADER_SESSION_ID, HeaderValue::from_static("probe"));
    }
    response
}

async fn delete_catalog(
    Path(source): Path<String>,
    State(requests): State<Requests>,
) -> StatusCode {
    requests.lock().unwrap().push((source, "DELETE".into()));
    StatusCode::ACCEPTED
}

#[tokio::test]
async fn probes_native_and_legacy_catalog_pages_and_cleans_up_sessions() -> anyhow::Result<()> {
    let requests = Requests::default();
    let (base, server) = start_server(
        Router::new()
            .route("/{source}", post(post_catalog).delete(delete_catalog))
            .with_state(requests.clone()),
    )
    .await;
    let state = upstream_sessions::gateway_state(&base, "p").await?;
    let mut profile = state.store.get_profile("p").await?.unwrap();
    for (id, native) in [("stateful", false), ("stateless", true)] {
        profile.source_ids = vec![id.into()];
        profile.mcp.modern_protocol = native;
        let surface = probe_profile_surface(&state, &profile)
            .await
            .map_err(anyhow::Error::msg)?;
        assert!(surface.sources[0].ok, "{:?}", surface.sources);
        assert_eq!(surface.tools.len(), 2);
        assert_eq!(surface.resources.len(), 2);
        assert_eq!(surface.resource_templates.len(), 2);
        assert_eq!(surface.prompts.len(), 2);
        assert_eq!(surface.sources[0].resource_templates_count, 2);
        assert!(
            surface
                .resource_templates
                .iter()
                .all(|t| t.uri_template.contains("{id}"))
        );
    }
    // Source pages detect either protocol without a profile setting.
    profile.source_ids = vec!["stateful".into(), "stateless".into()];
    let surface = probe_upstream_surface(&state, &profile)
        .await
        .map_err(anyhow::Error::msg)?;
    assert!(
        surface.sources.iter().all(|s| s.ok),
        "{:?}",
        surface.sources
    );
    assert_eq!(surface.tools.len(), 4);
    let requests = requests.lock().unwrap();
    assert_eq!(
        requests
            .iter()
            .filter(|(source, method)| source == "stateful" && method == "DELETE")
            .count(),
        2
    );
    assert!(
        !requests
            .iter()
            .any(|(source, method)| source == "stateless" && method == "initialize")
    );
    server.abort();
    Ok(())
}

#[tokio::test]
async fn stalled_catalog_retains_other_results_and_closes_the_probe_session() -> anyhow::Result<()>
{
    let requests = Arc::new(Mutex::new(vec![("fixture".into(), "stall-tools".into())]));
    let (base, server) = start_server(
        Router::new()
            .route("/{source}", post(post_catalog).delete(delete_catalog))
            .with_state(requests.clone()),
    )
    .await;
    let state = upstream_sessions::gateway_state(&base, "p").await?;
    let mut profile = state.store.get_profile("p").await?.unwrap();
    profile.source_ids = vec!["stateful".into()];
    let surface = tokio::time::timeout(
        Duration::from_secs(11),
        probe_profile_surface(&state, &profile),
    )
    .await?
    .map_err(anyhow::Error::msg)?;
    assert!(!surface.sources[0].ok);
    assert!(surface.tools.is_empty());
    assert_eq!(surface.prompts.len(), 2);
    assert_eq!(surface.resources.len(), 2);
    assert_eq!(surface.resource_templates.len(), 2);
    assert!(
        requests
            .lock()
            .unwrap()
            .iter()
            .any(|(_, method)| method == "DELETE")
    );
    server.abort();
    Ok(())
}
