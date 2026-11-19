use super::journey::{self, Gateway, GatewayOptions, PROFILE_ID, Process};
use anyhow::Context as _;
use serde_json::{Value, json};
use std::{path::Path, process::Stdio, time::Duration};
use tokio::{
    io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader},
    process::{ChildStdin, ChildStdout},
};

fn message(id: u64, method: &str, mut params: Value) -> Value {
    params["_meta"] = json!({"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"native-journey","version":"1"},"io.modelcontextprotocol/clientCapabilities":{"roots":{},"extensions":{"io.modelcontextprotocol/tasks":{}}}});
    json!({"jsonrpc":"2.0","id":id,"method":method,"params":params})
}
async fn send(input: &mut ChildStdin, body: &Value) -> anyhow::Result<()> {
    input.write_all(format!("{body}\n").as_bytes()).await?;
    input.flush().await?;
    Ok(())
}
async fn receive(output: &mut BufReader<ChildStdout>) -> anyhow::Result<Value> {
    let mut line = String::new();
    tokio::time::timeout(Duration::from_secs(15), output.read_line(&mut line)).await??;
    let value: Value = serde_json::from_str(&line).context("native proxy output")?;
    anyhow::ensure!(value.get("error").is_none(), "{value}");
    Ok(value)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires sibling Adapter and unrelated binaries; make test-v1-journey"]
#[allow(clippy::too_many_lines)]
async fn native_proxy_gateway_adapter_stdio_round_trip() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let fixture =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../adapter/tests/fixtures/native_stdio.py");
    let port = crate::common::pick_unused_port()?;
    let adapter_config = dir.path().join("adapter.json");
    let log = dir.path().join("stdio.jsonl");
    std::fs::write(
        &adapter_config,
        serde_json::to_vec(
            &json!({"adapter":{"modernProtocol":true},"servers":{"native":{"type":"stdio","modernProtocol":true,"command":"python3","args":[fixture,"chain",log]}}}),
        )?,
    )?;
    let _adapter = Process::spawn(
        &journey::sibling_binary("unrelated-mcp-adapter")?,
        &[
            "--config",
            adapter_config.to_str().context("config")?,
            "--bind",
            &format!("127.0.0.1:{port}"),
            "--log-level",
            "warn",
        ],
        &[],
        dir.path().join("adapter.log"),
    )?;
    crate::common::wait_http_ok(
        &format!("http://127.0.0.1:{port}/ready"),
        Duration::from_secs(10),
    )
    .await?;
    let config = journey::mode1_config(
        dir.path(),
        &[("adapter", format!("http://127.0.0.1:{port}/mcp"))],
        false,
    )?;
    let mut value: Value = serde_json::from_slice(&std::fs::read(&config)?)?;
    value["profiles"][PROFILE_ID]["mcp"] = json!({"modernProtocol":true});
    std::fs::write(&config, serde_json::to_vec(&value)?)?;
    let gateway = Gateway::start(
        dir.path(),
        "native-gateway",
        GatewayOptions {
            config: Some(&config),
            ..GatewayOptions::default()
        },
    )
    .await?;
    journey::cli(
        dir.path(),
        &[
            "context",
            "add",
            "journey",
            "--url",
            &format!("{}/{PROFILE_ID}/mcp", gateway.data_base),
            "--auth",
            "none",
        ],
    )
    .await?;
    let mut child = tokio::process::Command::new(journey::sibling_binary("unrelated")?)
        .env_remove("UNRELATED_TOKEN")
        .env("UNRELATED_MCP_PROTOCOL", "2026-07-28")
        .env("XDG_CONFIG_HOME", dir.path().join("config"))
        .env("XDG_CACHE_HOME", dir.path().join("cache"))
        .args(["proxy", "--context", "journey"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(std::fs::File::create(dir.path().join("proxy.log"))?)
        .kill_on_drop(true)
        .spawn()?;
    let mut input = child.stdin.take().context("stdin")?;
    let mut output = BufReader::new(child.stdout.take().context("stdout")?);
    send(&mut input, &message(1, "server/discover", json!({}))).await?;
    assert!(
        receive(&mut output).await?["result"]["supportedVersions"]
            .as_array()
            .context("versions")?
            .contains(&json!("2026-07-28"))
    );
    let mut request = message(
        2,
        "tools/call",
        json!({"name":"execute_tool","arguments":{"toolRef":"adapter:echo","arguments":{"mode":"mrtr"}}}),
    );
    send(&mut input, &request).await?;
    let response = receive(&mut output).await?;
    assert_eq!(
        response["result"]["resultType"], "input_required",
        "{response}"
    );
    request["params"]["requestState"] = response["result"]["requestState"].clone();
    request["params"]["inputResponses"] = json!({"roots":{"roots":[]}});
    send(&mut input, &request).await?;
    assert_eq!(
        receive(&mut output).await?["result"]["content"][0]["text"],
        "chain"
    );
    send(&mut input,&message(3,"tools/call",json!({"name":"execute_tool","arguments":{"toolRef":"adapter:echo","arguments":{"mode":"task"}}}))).await?;
    let task = receive(&mut output).await?["result"]["taskId"]
        .as_str()
        .context("task")?
        .to_owned();
    for method in ["tasks/get", "tasks/update", "tasks/cancel"] {
        send(
            &mut input,
            &message(4, method, json!({"taskId":task,"inputResponses":{}})),
        )
        .await?;
        let response = receive(&mut output)
            .await
            .with_context(|| method.to_string())?;
        if method == "tasks/get" {
            assert_eq!(response["result"]["result"]["content"][0]["text"], "chain");
        }
    }
    send(
        &mut input,
        &message(
            5,
            "subscriptions/listen",
            json!({"notifications":{"taskIds":[task]}}),
        ),
    )
    .await?;
    let ack = receive(&mut output).await?;
    assert_eq!(ack["params"]["notifications"]["taskIds"], json!([task]));
    let notification = receive(&mut output).await?;
    assert_eq!(notification["params"]["taskId"], task);
    assert_eq!(
        notification["params"]["_meta"]["io.modelcontextprotocol/subscriptionId"],
        5
    );
    send(
        &mut input,
        &json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":5}}),
    )
    .await?;
    tokio::time::timeout(Duration::from_secs(5), async {
        while !std::fs::read_to_string(&log)
            .unwrap_or_default()
            .contains("notifications/cancelled")
        {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .context("stdio subscription was not cancelled")?;
    child.kill().await?;
    Ok(())
}
