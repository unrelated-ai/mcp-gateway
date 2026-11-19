use anyhow::Context as _;
use axum::{
    Json, Router,
    extract::State,
    http::HeaderMap,
    response::{IntoResponse as _, Response},
    routing::post,
};
use serde_json::{Value, json};
use std::{
    convert::Infallible,
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader},
    process::{ChildStdin, ChildStdout, Command},
};

#[derive(Clone, Default)]
struct Fixture {
    active: Arc<AtomicUsize>,
}
struct Active(Arc<AtomicUsize>);
impl Drop for Active {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}
fn task() -> Value {
    json!({"taskId":"task-1","status":"working","createdAt":"2026-11-01T00:00:00Z","lastUpdatedAt":"2026-11-01T00:00:00Z","ttlMs":86_400_000})
}
async fn upstream(
    State(state): State<Fixture>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    assert!(headers.get("mcp-session-id").is_none());
    unrelated_mcp_support::headers::validate_request_headers(
        &headers,
        &body,
        Some(
            &json!({"type":"object","properties":{"mode":{"type":"string","x-mcp-header":"mode"}}}),
        ),
    )
    .expect("forwarded headers");
    assert_eq!(
        body["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"],
        "2026-07-28"
    );
    if body["method"] == "subscriptions/listen" {
        state.active.fetch_add(1, Ordering::SeqCst);
        let active = Active(state.active.clone());
        let stream = async_stream::stream! {
            let _active = active;
            if body["params"]["notifications"]["taskIds"] == json!(["pending-ack"]) {
                std::future::pending::<()>().await;
            }
            let meta = json!({"io.modelcontextprotocol/subscriptionId":body["id"]});
            let ack = json!({"jsonrpc":"2.0","method":"notifications/subscriptions/acknowledged","params":{"_meta":meta,"notifications":body["params"]["notifications"]}});
            yield Ok::<_, Infallible>(axum::response::sse::Event::default().data(ack.to_string()));
            // The stream must stay readable beyond the ordinary request deadline.
            tokio::time::sleep(Duration::from_millis(1500)).await;
            let mut params = task(); params["_meta"] = meta;
            let event = json!({"jsonrpc":"2.0","method":"notifications/tasks","params":params});
            yield Ok(axum::response::sse::Event::default().data(event.to_string()));
            std::future::pending::<()>().await;
        };
        return axum::response::Sse::new(stream).into_response();
    }
    let result = match body["method"].as_str().unwrap() {
        "server/discover" => {
            json!({"resultType":"complete","supportedVersions":["2026-07-28"],"capabilities":{"tools":{"listChanged":true},"extensions":{"io.modelcontextprotocol/tasks":{}}},"ttlMs":0,"cacheScope":"private"})
        }
        "tools/list" => {
            json!({"resultType":"complete","tools":[{"name":"echo","inputSchema":{"type":"object","properties":{"mode":{"type":"string","x-mcp-header":"mode"}}}}]})
        }
        "tools/call" => {
            assert_eq!(body["params"]["name"], "echo");
            assert_eq!(
                body["params"]["_meta"]["io.modelcontextprotocol/clientInfo"]["name"],
                "proxy-native-test"
            );
            match body["params"]["arguments"]["mode"].as_str().unwrap_or("") {
                "mrtr" if body["params"]["requestState"].is_null() => {
                    json!({"resultType":"input_required","requestState":"opaque","inputRequests":{"roots":{"method":"roots/list"}}})
                }
                "mrtr" => {
                    assert_eq!(body["params"]["requestState"], "opaque");
                    assert_eq!(
                        body["params"]["inputResponses"]["roots"],
                        json!({"roots":[]})
                    );
                    json!({"resultType":"complete","content":[{"type":"text","text":"resumed"}]})
                }
                "task" => {
                    let mut result = task();
                    result["resultType"] = json!("task");
                    result
                }
                _ => json!({"resultType":"complete","content":[]}),
            }
        }
        "tasks/get" => {
            assert_eq!(body["params"]["taskId"], "task-1");
            let mut result = task();
            result["resultType"] = json!("complete");
            result
        }
        "tasks/update" | "tasks/cancel" => {
            assert_eq!(body["params"]["taskId"], "task-1");
            json!({"resultType":"complete"})
        }
        _ => panic!("unexpected method: {body}"),
    };
    Json(json!({"jsonrpc":"2.0","id":body["id"],"result":result})).into_response()
}
fn request(id: u64, method: &str, mut params: Value) -> Value {
    params["_meta"] = json!({"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"proxy-native-test","version":"1"},"io.modelcontextprotocol/clientCapabilities":{"roots":{},"extensions":{"io.modelcontextprotocol/tasks":{}}}});
    json!({"jsonrpc":"2.0","id":id,"method":method,"params":params})
}
async fn send(input: &mut ChildStdin, value: &Value) -> anyhow::Result<()> {
    input.write_all(format!("{value}\n").as_bytes()).await?;
    input.flush().await?;
    Ok(())
}
async fn receive(output: &mut BufReader<ChildStdout>) -> anyhow::Result<Value> {
    let mut line = String::new();
    let count =
        tokio::time::timeout(Duration::from_secs(10), output.read_line(&mut line)).await??;
    anyhow::ensure!(count > 0, "proxy closed stdout");
    Ok(serde_json::from_str(&line)?)
}
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn proxy_native_round_trips_and_subscription_cancellation() -> anyhow::Result<()> {
    let fixture = Fixture::default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let router = Router::new()
        .route("/mcp", post(upstream))
        .with_state(fixture.clone());
    let server = tokio::spawn(async move { axum::serve(listener, router).await });
    let temp = tempfile::tempdir()?;
    let binary = env!("CARGO_BIN_EXE_unrelated");
    let status = Command::new(binary)
        .env("XDG_CONFIG_HOME", temp.path())
        .args([
            "context",
            "add",
            "test",
            "--url",
            &format!("http://{address}/mcp"),
            "--auth",
            "none",
        ])
        .stdout(Stdio::null())
        .status()
        .await?;
    assert!(status.success());
    let mut child = Command::new(binary)
        .env("XDG_CONFIG_HOME", temp.path())
        .env("XDG_CACHE_HOME", temp.path())
        .env("UNRELATED_MCP_PROTOCOL", "2026-07-28")
        .args(["proxy", "--context", "test", "--timeout", "1"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()?;
    let mut input = child.stdin.take().context("stdin")?;
    let mut output = BufReader::new(child.stdout.take().context("stdout")?);
    send(&mut input, &request(1, "server/discover", json!({}))).await?;
    let discovered = receive(&mut output).await?;
    assert!(
        discovered["result"]["supportedVersions"]
            .as_array()
            .context("versions")?
            .contains(&json!("2026-07-28")),
        "{discovered}"
    );
    send(&mut input, &request(2, "tools/list", json!({}))).await?;
    assert_eq!(
        receive(&mut output).await?["result"]["tools"]
            .as_array()
            .context("tools")?
            .len(),
        2
    );
    let mut call = request(
        3,
        "tools/call",
        json!({"name":"execute_tool","arguments":{"toolRef":"echo","arguments":{"mode":"mrtr"}}}),
    );
    send(&mut input, &call).await?;
    let response = receive(&mut output).await?;
    assert_eq!(
        response["result"]["resultType"], "input_required",
        "{response}"
    );
    call["params"]["requestState"] = response["result"]["requestState"].clone();
    call["params"]["inputResponses"] = json!({"roots":{"roots":[]}});
    send(&mut input, &call).await?;
    assert_eq!(
        receive(&mut output).await?["result"]["content"][0]["text"],
        "resumed"
    );
    send(&mut input, &request(4,"tools/call",json!({"name":"execute_tool","arguments":{"toolRef":"echo","arguments":{"mode":"task"}}}))).await?;
    assert_eq!(receive(&mut output).await?["result"]["taskId"], "task-1");
    for method in ["tasks/get", "tasks/update", "tasks/cancel"] {
        send(
            &mut input,
            &request(5, method, json!({"taskId":"task-1","inputResponses":{}})),
        )
        .await?;
        let result = receive(&mut output).await?;
        assert!(result.get("error").is_none(), "{result}");
    }
    send(
        &mut input,
        &request(
            6,
            "subscriptions/listen",
            json!({"notifications":{"taskIds":["task-1"]}}),
        ),
    )
    .await?;
    let ack = receive(&mut output).await?;
    assert_eq!(
        ack["method"], "notifications/subscriptions/acknowledged",
        "{ack}"
    );
    assert_eq!(ack["params"]["notifications"]["taskIds"], json!(["task-1"]));
    let task = receive(&mut output).await?;
    assert_eq!(task["method"], "notifications/tasks", "{task}");
    assert_eq!(
        task["params"]["_meta"]["io.modelcontextprotocol/subscriptionId"],
        6
    );
    send(
        &mut input,
        &json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":6}}),
    )
    .await?;
    tokio::time::timeout(Duration::from_secs(5), async {
        while fixture.active.load(Ordering::SeqCst) != 0 {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .context("upstream stream not closed")?;
    send(
        &mut input,
        &request(
            7,
            "subscriptions/listen",
            json!({"notifications":{"taskIds":["pending-ack"]}}),
        ),
    )
    .await?;
    tokio::time::timeout(Duration::from_secs(5), async {
        while fixture.active.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .context("pending subscription not started")?;
    send(
        &mut input,
        &json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":7}}),
    )
    .await?;
    tokio::time::timeout(Duration::from_secs(5), async {
        while fixture.active.load(Ordering::SeqCst) != 0 {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .context("unacknowledged upstream stream not closed")?;
    send(
        &mut input,
        &request(
            8,
            "subscriptions/listen",
            json!({"notifications":{"taskIds":["pending-ack"]}}),
        ),
    )
    .await?;
    // The SDK may finish the previously cancelled request before this response.
    let timeout_error = loop {
        let reply = receive(&mut output).await?;
        if reply["id"] == 8 {
            break reply;
        }
    };
    assert!(
        timeout_error["error"]["message"]
            .as_str()
            .is_some_and(|msg| msg.contains("acknowledgement timed out")),
        "{timeout_error}"
    );
    child.kill().await?;
    server.abort();
    Ok(())
}
