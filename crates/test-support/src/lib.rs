pub mod images;

use anyhow::Context as _;
use std::net::TcpListener;
use std::process::Child;
use std::time::{Duration, Instant};

pub struct KillOnDrop(pub Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
    }
}

/// Pick an unused TCP port on localhost.
///
/// Note: this does not reserve the port; it's still possible for another process to bind it
/// before you do.
///
/// # Errors
///
/// Returns an error if binding an ephemeral localhost port fails or if the bound socket's
/// local address cannot be read.
pub fn pick_unused_port() -> anyhow::Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0").context("bind ephemeral port")?;
    Ok(listener.local_addr()?.port())
}

/// Poll an HTTP URL until it returns a success status (2xx/3xx).
///
/// # Errors
///
/// Returns an error if the timeout elapses before the endpoint returns a success status.
pub async fn wait_http_ok(url: &str, timeout_dur: Duration) -> anyhow::Result<()> {
    let client = reqwest::Client::new();
    let start = Instant::now();
    loop {
        if start.elapsed() > timeout_dur {
            anyhow::bail!("timed out waiting for {url}");
        }

        match client.get(url).send().await {
            Ok(resp) if resp.status().is_success() => return Ok(()),
            _ => tokio::time::sleep(Duration::from_millis(200)).await,
        }
    }
}
