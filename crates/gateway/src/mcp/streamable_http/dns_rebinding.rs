//! Real-client regression with DNS and HTTP fixtures confined to a container.
use super::*;
use crate::outbound_safety::UpstreamHttpClients;
use crate::store::UpstreamNetworkClass;
use std::collections::BTreeMap;
use std::io::Write as _;
use std::sync::{
    Mutex,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;
use unrelated_http_tools::{runtime::HttpToolSource, safety::OutboundHttpSafety};
use unrelated_openapi_tools::runtime::OpenApiToolSource;

type Queries = Arc<Mutex<BTreeMap<String, usize>>>;
const TEST_NAME: &str = "mcp::streamable_http::dns_rebinding::outbound_dns_rebinding";

#[tokio::test]
#[ignore = "requires Docker; run cargo test -p unrelated-mcp-gateway outbound_dns_rebinding -- --ignored --nocapture"]
async fn outbound_dns_rebinding() {
    if std::env::var_os("GATEWAY_DNS_TEST_CONTAINER").is_none() {
        run_in_container().await;
        return;
    }
    // Never change the host resolver, even if the test environment variable was set there.
    assert!(std::path::Path::new("/.dockerenv").exists());
    tokio::time::timeout(Duration::from_secs(15), check_rebinding())
        .await
        .unwrap();
}

async fn run_in_container() {
    let executable = std::env::current_exe().unwrap();
    for proxy in [false, true] {
        let mut command = tokio::process::Command::new("docker");
        command.args([
            "run",
            "--rm",
            "--network=none",
            "--env",
            "GATEWAY_DNS_TEST_CONTAINER=1",
            "--mount",
        ]);
        command.arg(format!(
            "type=bind,src={},dst=/dns-test,readonly",
            executable.display()
        ));
        // Mount the public CA bundle itself: on some hosts it is a symlink outside /etc/ssl.
        let certificates = std::fs::canonicalize("/etc/ssl/certs/ca-certificates.crt").unwrap();
        command.args(["--env", "SSL_CERT_FILE=/ca-certificates.crt", "--mount"]);
        command.arg(format!(
            "type=bind,src={},dst=/ca-certificates.crt,readonly",
            certificates.display()
        ));
        if proxy {
            for variable in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"] {
                command.args(["--env", &format!("{variable}=http://127.0.0.1:8081")]);
            }
        }
        command.args([
            "debian:trixie-slim",
            "/dns-test",
            TEST_NAME,
            "--exact",
            "--ignored",
            "--nocapture",
        ]);
        assert!(
            command.status().await.unwrap().success(),
            "rebinding regression failed (proxy={proxy})"
        );
    }
}

async fn serve_dns(dns: tokio::net::UdpSocket, queries: Queries) {
    let mut packet = [0; 4096];
    loop {
        let (_, peer) = dns.recv_from(&mut packet).await.unwrap();
        let mut pos = 12;
        let mut labels = Vec::new();
        while packet[pos] != 0 {
            let size = usize::from(packet[pos]);
            labels.push(std::str::from_utf8(&packet[pos + 1..pos + 1 + size]).unwrap());
            pos += size + 1;
        }
        pos += 1;
        let qtype = u16::from_be_bytes([packet[pos], packet[pos + 1]]);
        let mut response = packet[..2].to_vec();
        response.extend_from_slice(&[0x81, 0x80, 0, 1, 0, u8::from(qtype == 1), 0, 0, 0, 0]);
        response.extend_from_slice(&packet[12..pos + 4]);
        if qtype == 1 {
            let host = labels.join(".");
            let count = {
                let mut queries = queries.lock().unwrap();
                let count = queries.entry(host.clone()).or_default();
                *count += 1;
                *count
            };
            // TEST-NET-3 passes the existing policy; only the second answer is reachable.
            let ip = if count == 1 {
                [203, 0, 113, 10]
            } else {
                [127, 0, 0, 1]
            };
            eprintln!("DNS {host} #{count} -> {}", std::net::Ipv4Addr::from(ip));
            response.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4]);
            response.extend_from_slice(&ip);
        }
        dns.send_to(&response, peer).await.unwrap();
    }
}

async fn check_rebinding() {
    std::fs::write(
        "/etc/resolv.conf",
        "nameserver 127.0.0.1\noptions ndots:0 attempts:1 timeout:1\n",
    )
    .unwrap();
    let queries = Queries::default();
    let dns = tokio::net::UdpSocket::bind("127.0.0.1:53").await.unwrap();
    let dns_task = tokio::spawn(serve_dns(dns, queries.clone()));
    let hits = Arc::new(AtomicUsize::new(0));
    let requests = hits.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:8081")
        .await
        .unwrap();
    let server_task = tokio::spawn(async move {
        let app = axum::Router::new().fallback(move || {
            requests.fetch_add(1, Ordering::SeqCst);
            async { "INTERNAL-SECRET-MUST-NOT-LEAK" }
        });
        axum::serve(listener, app).await.unwrap();
    });
    check_http_tool().await;
    check_openapi().await;
    check_mcp().await;
    let expected: BTreeMap<_, _> = [
        "http-tool",
        "spec",
        "ref",
        "probe",
        "openapi-tool",
        "upstream-post",
        "upstream-get",
        "upstream-delete",
    ]
    .into_iter()
    .map(|host| (format!("{host}.rebind.test"), 2))
    .collect();
    assert_eq!(
        *queries.lock().unwrap(),
        expected,
        "each path must exercise both DNS lookups"
    );
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "internal service received a request"
    );
    eprintln!("All eight rebinding paths blocked; zero internal requests");
    dns_task.abort();
    server_task.abort();
}

async fn check_http_tool() {
    let config = serde_json::from_value(serde_json::json!({
        "baseUrl": "http://http-tool.rebind.test:8081",
        "tools": {"probe": {"method": "GET", "path": "/internal-secret"}}
    }))
    .unwrap();
    let source = HttpToolSource::new_with_safety(
        "rebind",
        config,
        Duration::from_secs(2),
        OutboundHttpSafety::gateway_default(),
    )
    .unwrap();
    let result = source.call_tool("probe", serde_json::json!({})).await;
    assert!(result.is_err(), "internal response escaped: {result:?}");
}

fn openapi_source(spec: &str, host: &str, probe: bool) -> OpenApiToolSource {
    let config = serde_json::from_value(serde_json::json!({
        "spec": spec, "baseUrl": format!("http://{host}.rebind.test:8081"), "autoDiscover": true
    }))
    .unwrap();
    OpenApiToolSource::new_with_safety(
        "rebind".into(),
        config,
        Duration::from_secs(2),
        Duration::from_secs(2),
        probe,
        Duration::from_secs(2),
        OutboundHttpSafety::gateway_default(),
    )
}

async fn check_openapi() {
    assert!(
        openapi_source(
            "http://spec.rebind.test:8081/internal-secret",
            "spec",
            false
        )
        .start()
        .await
        .is_err()
    );
    for case in ["ref", "probe", "openapi-tool"] {
        let mut spec = serde_json::json!({
            "openapi": "3.0.3", "info": {"title": "test", "version": "1"},
            "paths": {"/internal-secret": {"get": {"operationId": "probe", "responses": {"200": {"description": "OK"}}}}}
        });
        if case == "ref" {
            spec["paths"]["/internal-secret"]["get"]["parameters"] = serde_json::json!([{"$ref": "http://ref.rebind.test:8081/internal-secret#/parameter"}]);
        }
        let mut file = tempfile::NamedTempFile::new().unwrap();
        write!(file, "{spec}").unwrap();
        let source = openapi_source(file.path().to_str().unwrap(), case, case == "probe");
        if case == "probe" {
            assert!(source.start().await.is_err());
        } else {
            source.start().await.unwrap();
            if case == "ref" {
                // Discovery skips operations whose references fail to load.
                assert!(source.list_tools().is_empty());
            } else {
                let result = source.call_tool("probe", serde_json::json!({})).await;
                assert!(result.is_err(), "internal response escaped: {result:?}");
            }
        }
    }
}

async fn check_mcp() {
    // Explicit production policy: other gateway unit-test helpers allow local mock servers.
    let safety = OutboundHttpSafety::gateway_default();
    let clients = UpstreamHttpClients::with_safety(safety.clone()).unwrap();
    let http = clients.for_class(UpstreamNetworkClass::External);
    for method in ["post", "get", "delete"] {
        let url = format!("http://upstream-{method}.rebind.test:8081/internal-secret");
        safety.check_url(&url.parse().unwrap()).await.unwrap();
        let uri: Arc<str> = url.into();
        let headers = HeaderMap::new();
        let failed = match method {
            "post" => {
                let message = serde_json::from_value(
                    serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
                )
                .unwrap();
                post_message(http, uri, message, None, &headers)
                    .await
                    .is_err()
            }
            "get" => get_stream(http, uri, "session".into(), None, &headers)
                .await
                .is_err(),
            _ => delete_session(http, uri, "session".into(), &headers)
                .await
                .is_err(),
        };
        assert!(failed, "upstream {method} accepted a rebound address");
    }
}
