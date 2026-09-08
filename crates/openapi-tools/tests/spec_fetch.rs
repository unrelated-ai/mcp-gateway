use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use unrelated_http_tools::safety::{OutboundHttpSafety, RedirectPolicy};
use unrelated_openapi_tools::config::ApiServerConfig;
use unrelated_openapi_tools::runtime::OpenApiToolSource;

const SPEC: &str = r#"{"openapi":"3.0.3","info":{"title":"test","version":"1"},"paths":{"/ping":{"get":{"operationId":"ping","responses":{"200":{"description":"OK"}}}}}}"#;

struct Server {
    url: String,
    requests: Arc<Mutex<Vec<String>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Server {
    async fn start(handler: impl Fn(&str) -> String + Send + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let records = requests.clone();
        let task = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut bytes = Vec::new();
                let mut buf = [0; 1024];
                while !bytes.windows(4).any(|s| s == b"\r\n\r\n") {
                    let n = stream.read(&mut buf).await.unwrap();
                    if n == 0 {
                        break;
                    }
                    bytes.extend_from_slice(&buf[..n]);
                }
                let request = String::from_utf8(bytes).unwrap();
                records.lock().unwrap().push(request.clone());
                stream
                    .write_all(handler(&request).as_bytes())
                    .await
                    .unwrap();
            }
        });
        Self {
            url,
            requests,
            task,
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn response(status: &str, headers: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status}\r\nConnection: close\r\nContent-Length: {}\r\n{headers}\r\n{body}",
        body.len()
    )
}

async fn source(
    spec: &str,
    auth: serde_json::Value,
    safety: OutboundHttpSafety,
) -> unrelated_openapi_tools::error::Result<OpenApiToolSource> {
    let config: ApiServerConfig = serde_json::from_value(serde_json::json!({
        "spec": spec,
        "baseUrl": "http://localhost/api",
        "auth": auth,
        "autoDiscover": true
    }))
    .unwrap();
    OpenApiToolSource::build_with_safety(
        "test".into(),
        config,
        Duration::from_secs(2),
        Duration::from_secs(2),
        false,
        Duration::ZERO,
        safety,
    )
    .await
}

#[tokio::test]
async fn protected_spec_supports_every_auth_type() {
    for (auth, expected) in [
        (
            serde_json::json!({"type":"bearer","token":"test-token"}),
            "authorization: Bearer test-token",
        ),
        (
            serde_json::json!({"type":"basic","username":"user","password":"pass"}),
            "authorization: Basic dXNlcjpwYXNz",
        ),
        (
            serde_json::json!({"type":"header","name":"X-API-Key","value":"test-key"}),
            "x-api-key: test-key",
        ),
        (
            serde_json::json!({"type":"query","name":"api_key","value":"test & key"}),
            "GET /openapi.json?version=1&api_key=test+%26+key HTTP/1.1",
        ),
    ] {
        let server = Server::start(move |request| {
            if request.contains(expected) {
                response("200 OK", "", SPEC)
            } else {
                response("401 Unauthorized", "", r#"{"error":"unauthorized"}"#)
            }
        })
        .await;
        let loaded = source(
            &format!("{}/openapi.json?version=1", server.url),
            auth,
            OutboundHttpSafety::permissive(),
        )
        .await;
        assert!(loaded.is_ok(), "{expected}: {:?}", loaded.err());
        assert_eq!(loaded.unwrap().list_tools()[0].name, "ping");
    }
}

#[tokio::test]
async fn public_and_file_specs_still_load() {
    let server = Server::start(|_| response("200 OK", "", SPEC)).await;
    let loaded = source(
        &server.url,
        serde_json::Value::Null,
        OutboundHttpSafety::permissive(),
    )
    .await
    .unwrap();
    assert_eq!(loaded.list_tools()[0].name, "ping");
    assert!(!server.requests.lock().unwrap()[0].contains("authorization:"));

    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), SPEC).unwrap();
    let loaded = source(
        file.path().to_str().unwrap(),
        serde_json::Value::Null,
        OutboundHttpSafety::permissive(),
    )
    .await
    .unwrap();
    assert_eq!(loaded.list_tools()[0].name, "ping");
}

#[tokio::test]
async fn upstream_errors_report_status_without_credentials_or_response_body() {
    for status in [
        "401 Unauthorized",
        "403 Forbidden",
        "404 Not Found",
        "500 Internal Server Error",
    ] {
        let server =
            Server::start(move |_| response(status, "", "private upstream error body")).await;
        let error = source(
            &format!("{}?existing=private-query", server.url),
            serde_json::json!({"type":"query","name":"key","value":"private-auth-value"}),
            OutboundHttpSafety::permissive(),
        )
        .await
        .err()
        .unwrap()
        .to_string();
        assert!(error.contains(status), "{error}");
        assert!(!error.contains("private"), "{error}");
        assert!(!error.contains("parse spec"), "{error}");
    }
}

#[tokio::test]
async fn same_origin_redirect_keeps_auth_without_duplicate_query_keys() {
    for auth in [
        serde_json::json!({"type":"header","name":"X-API-Key","value":"test-key"}),
        serde_json::json!({"type":"query","name":"key","value":"test-key"}),
    ] {
        let server = Server::start(|request| {
            if request.starts_with("GET /start") {
                response("302 Found", "Location: /spec?key=old&version=2\r\n", "")
            } else {
                response("200 OK", "", SPEC)
            }
        })
        .await;
        source(
            &format!("{}/start", server.url),
            auth.clone(),
            OutboundHttpSafety::permissive(),
        )
        .await
        .unwrap();
        let records = server.requests.lock().unwrap();
        assert_eq!(records.len(), 2);
        if auth["type"] == "header" {
            assert!(
                records
                    .iter()
                    .all(|request| request.contains("x-api-key: test-key"))
            );
        } else {
            assert!(records[0].contains("/start?key=test-key "));
            assert!(records[1].contains("/spec?version=2&key=test-key "));
        }
    }
}

#[tokio::test]
async fn authenticated_redirects_never_reach_another_origin() {
    let destination = Server::start(|_| response("200 OK", "", SPEC)).await;
    for auth in [
        serde_json::json!({"type":"bearer","token":"test-token"}),
        serde_json::json!({"type":"basic","username":"user","password":"pass"}),
        serde_json::json!({"type":"header","name":"X-API-Key","value":"test-key"}),
        serde_json::json!({"type":"query","name":"key","value":"test-key"}),
    ] {
        let location = format!("Location: {}\r\n", destination.url);
        let server =
            Server::start(move |_| response("307 Temporary Redirect", &location, "")).await;
        let error = source(&server.url, auth, OutboundHttpSafety::permissive())
            .await
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("different origin"), "{error}");
        assert!(destination.requests.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn public_redirects_work_and_each_destination_is_checked() {
    let destination = Server::start(|_| response("200 OK", "", SPEC)).await;
    let location = format!(
        "Location: {}\r\n",
        destination.url.replace("127.0.0.1", "localhost")
    );
    let server = Server::start(move |_| response("302 Found", &location, "")).await;
    source(
        &server.url,
        serde_json::Value::Null,
        OutboundHttpSafety::permissive(),
    )
    .await
    .unwrap();
    assert_eq!(destination.requests.lock().unwrap().len(), 1);

    let mut safety = OutboundHttpSafety::permissive();
    safety.allowed_hosts = Some(std::collections::HashSet::from(["127.0.0.1".into()]));
    let error = source(&server.url, serde_json::Value::Null, safety)
        .await
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("not in allowlist"), "{error}");
    assert_eq!(destination.requests.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn redirect_policy_and_hop_limit_are_enforced() {
    let server = Server::start(|_| response("302 Found", "Location: /loop\r\n", "")).await;
    let mut safety = OutboundHttpSafety::permissive();
    safety.redirects = RedirectPolicy::None;
    let error = source(&server.url, serde_json::Value::Null, safety)
        .await
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("redirects are disabled"), "{error}");
    assert_eq!(server.requests.lock().unwrap().len(), 1);

    let error = source(
        &server.url,
        serde_json::Value::Null,
        OutboundHttpSafety::permissive(),
    )
    .await
    .err()
    .unwrap()
    .to_string();
    assert!(error.contains("too many redirects"), "{error}");
    assert_eq!(server.requests.lock().unwrap().len(), 12);
}

#[tokio::test]
async fn response_size_limit_still_applies() {
    let server = Server::start(|_| response("200 OK", "", SPEC)).await;
    let mut safety = OutboundHttpSafety::permissive();
    safety.max_response_bytes = Some(16);
    let error = source(&server.url, serde_json::Value::Null, safety)
        .await
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("Response too large"), "{error}");
}
