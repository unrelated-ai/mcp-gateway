use super::*;
use crate::store::{Upstream, UpstreamEndpoint, UpstreamEndpointLifecycle, UpstreamNetworkClass};
use axum::Json;
use axum::extract::{Path, State};
use unrelated_http_tools::config::AuthConfig;
use unrelated_mcp_support::headers::{CLIENT_INFO_META, VERSION, VERSION_META};

type Requests = Arc<Mutex<Vec<(String, String)>>>;

async fn fixture_post(
    Path(source): Path<String>,
    State(requests): State<Requests>,
    headers: HeaderMap,
    Json(message): Json<serde_json::Value>,
) -> Response {
    let method = message["method"].as_str().unwrap();
    requests
        .lock()
        .unwrap()
        .push((source.clone(), method.into()));
    if headers.get("authorization").and_then(|v| v.to_str().ok()) != Some("Bearer saved-secret") {
        return (
            StatusCode::UNAUTHORIZED,
            "private upstream error: saved-secret",
        )
            .into_response();
    }
    let result = match method {
        "initialize" => serde_json::json!({
            "protocolVersion": if source == "incompatible" { "2099-01-01" } else { "2025-11-25" },
            "capabilities":{}, "serverInfo":{"name":"fixture","version":"1"}
        }),
        "notifications/initialized" => return StatusCode::ACCEPTED.into_response(),
        "server/discover" => {
            assert_eq!(headers["mcp-protocol-version"], VERSION);
            assert_eq!(message["params"]["_meta"][VERSION_META], VERSION);
            assert!(message["params"]["_meta"][CLIENT_INFO_META].is_object());
            let version = if source == "incompatible" {
                rmcp::model::ProtocolVersion::V_2025_11_25
            } else {
                rmcp::model::ProtocolVersion::V_2026_07_28
            };
            serde_json::to_value(rmcp::model::DiscoverResult::new(
                vec![version],
                rmcp::model::ServerCapabilities::default(),
            ))
            .unwrap()
        }
        _ => panic!("Connection check must not call {method}"),
    };
    let mut response =
        Json(serde_json::json!({"jsonrpc":"2.0","id":message["id"],"result":result}))
            .into_response();
    if method == "initialize" && source != "stateless" {
        response
            .headers_mut()
            .insert(HEADER_SESSION_ID, HeaderValue::from_static("check-session"));
    }
    response
}

async fn fixture_delete(
    Path(source): Path<String>,
    State(requests): State<Requests>,
    headers: HeaderMap,
) -> StatusCode {
    assert_eq!(headers[HEADER_SESSION_ID], "check-session");
    assert_eq!(headers["authorization"], "Bearer saved-secret");
    assert!(headers.contains_key("mcp-protocol-version"));
    requests.lock().unwrap().push((source, "DELETE".into()));
    StatusCode::ACCEPTED
}

async fn fixture() -> (String, tokio::task::JoinHandle<()>, Requests) {
    let requests = Requests::default();
    let (base, handle) = start_server(
        Router::new()
            .route("/{source}", post(fixture_post).delete(fixture_delete))
            .with_state(requests.clone()),
    )
    .await;
    (base, handle, requests)
}

async fn check(base: &str, names: &[&str], modern: bool) -> serde_json::Value {
    let mut state = Arc::try_unwrap(upstream_sessions::gateway_state(base, "p").await.unwrap())
        .ok()
        .unwrap();
    let mut profile = state.store.get_profile("p").await.unwrap().unwrap();
    // Unit-test preflight permits loopback; the real connection must still respect
    // the external client policy while managed endpoints remain reachable.
    state.http = crate::outbound_safety::UpstreamHttpClients::with_safety(
        unrelated_http_tools::safety::OutboundHttpSafety::gateway_default(),
    )
    .unwrap();
    profile.source_ids = names.iter().map(|s| (*s).into()).collect();
    profile.mcp.modern_protocol = modern;
    let upstreams = names
        .iter()
        .filter(|name| **name != "missing")
        .map(|name| {
            (
                (*name).to_owned(),
                Upstream {
                    network_class: if *name == "blocked" {
                        UpstreamNetworkClass::External
                    } else {
                        UpstreamNetworkClass::ClusterInternalManaged
                    },
                    endpoints: vec![UpstreamEndpoint {
                        id: "one".into(),
                        // Use DNS so the external client's resolver checks the address
                        // despite the unit-test-only loopback preflight exception.
                        url: format!("{}/{name}", base.replace("127.0.0.1", "localhost")),
                        enabled: *name != "disabled",
                        lifecycle: if *name == "draining" {
                            UpstreamEndpointLifecycle::Draining
                        } else {
                            UpstreamEndpointLifecycle::Active
                        },
                        auth: (*name != "unauthorized").then(|| AuthConfig::Bearer {
                            token: "saved-secret".into(),
                        }),
                    }],
                },
            )
        })
        .collect();
    state.store = Arc::new(TestStore {
        profiles: HashMap::new(),
        upstreams,
    });
    serde_json::to_value(super::super::check_profile_connections(&state, &profile).await).unwrap()
}

#[tokio::test]
async fn legacy_checks_saved_auth_and_cleans_up_sessions_without_calling_tools() {
    let (base, server, requests) = fixture().await;
    let results = check(&base, &["stateful", "stateless"], false).await;
    for result in results.as_array().unwrap() {
        assert_eq!(result["status"], "passed", "{result}");
        assert_eq!(result["protocolVersion"], "2025-11-25");
    }
    let recorded = requests.lock().unwrap().clone();
    assert_eq!(recorded.len(), 5);
    assert!(recorded.contains(&("stateful".into(), "DELETE".into())));
    assert!(!recorded.contains(&("stateless".into(), "DELETE".into())));
    server.abort();
}

#[tokio::test]
async fn native_checks_discovery_and_reports_incompatible_protocols() {
    let (base, server, requests) = fixture().await;
    let results = check(&base, &["native", "incompatible"], true).await;
    assert_eq!(results[0]["status"], "passed", "{results}");
    assert_eq!(results[0]["protocolVersion"], VERSION);
    assert_eq!(results[1]["status"], "failed");
    assert!(
        results[1]["message"]
            .as_str()
            .unwrap()
            .contains("did not confirm support")
    );
    assert!(
        requests
            .lock()
            .unwrap()
            .iter()
            .all(|(_, method)| method == "server/discover")
    );
    server.abort();
}

#[tokio::test]
async fn failures_are_redacted_and_inactive_or_blocked_endpoints_are_not_contacted() {
    let (base, server, requests) = fixture().await;
    let results = check(
        &base,
        &[
            "unauthorized",
            "incompatible",
            "missing",
            "disabled",
            "draining",
            "blocked",
        ],
        false,
    )
    .await;
    assert_eq!(results.as_array().unwrap().len(), 6);
    for result in results.as_array().unwrap() {
        assert_eq!(result["status"], "failed", "{result}");
    }
    assert!(!results.to_string().contains("saved-secret"));
    let unauthorized = results
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["sourceId"] == "unauthorized")
        .unwrap();
    assert!(
        unauthorized["message"]
            .as_str()
            .unwrap()
            .contains("401/403")
    );
    let recorded = requests.lock().unwrap().clone();
    assert!(
        recorded
            .iter()
            .all(|(source, _)| source == "unauthorized" || source == "incompatible")
    );
    assert!(recorded.contains(&("incompatible".into(), "DELETE".into())));
    server.abort();
}
