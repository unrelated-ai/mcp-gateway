use anyhow::Context as _;
use futures::StreamExt as _;

pub async fn read_first_event_stream_json_message(
    resp: reqwest::Response,
) -> anyhow::Result<serde_json::Value> {
    let mut stream = sse_stream::SseStream::from_bytes_stream(resp.bytes_stream());
    while let Some(evt) = stream.next().await {
        let evt = evt.context("read SSE event")?;
        let payload = evt.data.unwrap_or_default();
        if payload.trim().is_empty() {
            continue;
        }
        return serde_json::from_str(&payload).context("parse SSE data as JSON");
    }
    anyhow::bail!("event-stream ended without a JSON message")
}
