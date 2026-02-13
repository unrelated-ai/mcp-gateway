#![allow(dead_code)]

use anyhow::Context as _;
use std::io::BufRead as _;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

pub mod mcp;
pub mod pg;
pub mod sse;

pub use unrelated_test_support::KillOnDrop;

pub fn pick_unused_port() -> anyhow::Result<u16> {
    unrelated_test_support::pick_unused_port()
}

pub async fn wait_http_ok(url: &str, timeout_dur: Duration) -> anyhow::Result<()> {
    unrelated_test_support::wait_http_ok(url, timeout_dur).await
}

pub struct SpawnedGateway {
    pub child: Child,
    pub data_base: String,
    pub admin_base: String,
}

fn parse_listen_addr(line: &str, marker: &str) -> Option<String> {
    let idx = line.find(marker)?;
    let rest = &line[idx + marker.len()..];
    // Most logs are JSON and the address ends before the next quote or brace.
    let end = rest
        .find('"')
        .or_else(|| rest.find('}'))
        .unwrap_or(rest.len());
    Some(rest[..end].trim().to_string())
}

pub fn wait_for_gateway_ports(
    mut child: Child,
    timeout: Duration,
) -> anyhow::Result<SpawnedGateway> {
    let stdout = child.stdout.take().context("missing child stdout")?;
    let stderr = child.stderr.take().context("missing child stderr")?;

    let (tx, rx) = mpsc::channel::<String>();
    let tx_out = tx.clone();
    std::thread::spawn(move || {
        let reader = std::io::BufReader::new(stdout);
        for line in reader.lines().map_while(Result::ok) {
            let _ = tx_out.send(line);
        }
    });
    std::thread::spawn(move || {
        let reader = std::io::BufReader::new(stderr);
        for line in reader.lines().map_while(Result::ok) {
            let _ = tx.send(line);
        }
    });

    let start = Instant::now();
    let mut data_addr: Option<String> = None;
    let mut admin_addr: Option<String> = None;
    let mut last_lines: Vec<String> = Vec::new();

    while start.elapsed() < timeout {
        if let Ok(Some(status)) = child.try_wait() {
            anyhow::bail!("gateway process exited early: {status}");
        }

        match rx.recv_timeout(Duration::from_millis(200)) {
            Ok(line) => {
                if last_lines.len() >= 50 {
                    last_lines.remove(0);
                }
                last_lines.push(line.clone());

                if data_addr.is_none() {
                    data_addr = parse_listen_addr(&line, "Starting data plane HTTP server on ");
                }
                if admin_addr.is_none() {
                    admin_addr =
                        parse_listen_addr(&line, "Starting admin/control plane HTTP server on ");
                }

                if let (Some(data_addr), Some(admin_addr)) = (data_addr.clone(), admin_addr.clone())
                {
                    return Ok(SpawnedGateway {
                        child,
                        data_base: format!("http://{data_addr}"),
                        admin_base: format!("http://{admin_addr}"),
                    });
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }

    anyhow::bail!(
        "timed out waiting for gateway ports; last output:\n{}",
        last_lines.join("\n")
    );
}

pub fn spawn_gateway(
    database_url: &str,
    admin_token: Option<&str>,
    session_secret: &str,
) -> anyhow::Result<SpawnedGateway> {
    let bin = env!("CARGO_BIN_EXE_unrelated-mcp-gateway");
    let mut cmd = Command::new(bin);
    cmd.arg("--bind")
        .arg("127.0.0.1:0")
        .arg("--admin-bind")
        .arg("127.0.0.1:0")
        .arg("--database-url")
        .arg(database_url)
        .arg("--log-level")
        .arg("info")
        .env("UNRELATED_GATEWAY_SESSION_SECRET", session_secret)
        // Integration tests run mock upstreams on loopback.
        .env("UNRELATED_GATEWAY_OUTBOUND_ALLOW_PRIVATE_NETWORKS", "1")
        // Integration tests run mock upstreams over plain HTTP on loopback.
        .env("UNRELATED_GATEWAY_UPSTREAM_ALLOW_HTTP", "1")
        // Mode 3 requires tenant secret encryption keys.
        .env(
            "UNRELATED_GATEWAY_SECRET_KEYS",
            "unrelated-mcp-gateway-test-secret-keys-v1",
        )
        // Enable bootstrap endpoint for relevant tests (still guarded by "no tenants exist").
        .env("UNRELATED_GATEWAY_BOOTSTRAP_ENABLED", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(admin_token) = admin_token {
        cmd.env("UNRELATED_GATEWAY_ADMIN_TOKEN", admin_token);
    }
    let child = cmd.spawn().context("spawn gateway")?;
    wait_for_gateway_ports(child, Duration::from_secs(10))
}

pub fn spawn_gateway_mode1(
    config_path: &std::path::Path,
    admin_token: Option<&str>,
    session_secret: &str,
) -> anyhow::Result<SpawnedGateway> {
    let bin = env!("CARGO_BIN_EXE_unrelated-mcp-gateway");
    let mut cmd = Command::new(bin);
    cmd.arg("--bind")
        .arg("127.0.0.1:0")
        .arg("--admin-bind")
        .arg("127.0.0.1:0")
        .arg("--config")
        .arg(config_path)
        .arg("--log-level")
        .arg("info")
        .env("UNRELATED_GATEWAY_SESSION_SECRET", session_secret)
        // Integration tests run mock upstreams on loopback.
        .env("UNRELATED_GATEWAY_OUTBOUND_ALLOW_PRIVATE_NETWORKS", "1")
        // Integration tests run mock upstreams over plain HTTP on loopback.
        .env("UNRELATED_GATEWAY_UPSTREAM_ALLOW_HTTP", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(admin_token) = admin_token {
        cmd.env("UNRELATED_GATEWAY_ADMIN_TOKEN", admin_token);
    }
    let child = cmd.spawn().context("spawn gateway (mode 1)")?;
    wait_for_gateway_ports(child, Duration::from_secs(10))
}
