use axum::http::{HeaderMap, HeaderValue};
use futures::{StreamExt as _, stream::BoxStream};
use rmcp::model::{ClientJsonRpcMessage, ServerJsonRpcMessage};
use rmcp::transport::common::http_header::HEADER_MCP_PROTOCOL_VERSION;
use rmcp::transport::common::http_header::{
    EVENT_STREAM_MIME_TYPE, HEADER_LAST_EVENT_ID, HEADER_SESSION_ID, JSON_MIME_TYPE,
};
use rmcp::transport::streamable_http_client::{StreamableHttpError, StreamableHttpPostResponse};
use std::sync::Arc;
use unrelated_mcp_support::headers::{CLIENT_CAPABILITIES_META, CLIENT_INFO_META};

fn header_to_string(h: &HeaderValue) -> Option<String> {
    h.to_str().ok().map(std::string::ToString::to_string)
}

fn content_type(headers: &reqwest::header::HeaderMap) -> Option<String> {
    headers
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(header_to_string)
        .map(|s| s.split(';').next().unwrap_or(&s).trim().to_string())
}

fn apply_headers(mut req: reqwest::RequestBuilder, headers: &HeaderMap) -> reqwest::RequestBuilder {
    for (k, v) in headers {
        req = req.header(k, v);
    }
    req
}

pub(crate) async fn post_message(
    http: &reqwest::Client,
    uri: Arc<str>,
    message: ClientJsonRpcMessage,
    session_id: Option<Arc<str>>,
    extra_headers: &HeaderMap,
) -> Result<StreamableHttpPostResponse, StreamableHttpError<reqwest::Error>> {
    post_message_with_schema(http, uri, message, session_id, extra_headers, None).await
}

pub(crate) async fn post_message_with_schema(
    http: &reqwest::Client,
    uri: Arc<str>,
    message: ClientJsonRpcMessage,
    session_id: Option<Arc<str>>,
    extra_headers: &HeaderMap,
    tool_schema: Option<&rmcp::model::JsonObject>,
) -> Result<StreamableHttpPostResponse, StreamableHttpError<reqwest::Error>> {
    post_value(
        http,
        uri,
        serde_json::to_value(&message)?,
        session_id,
        extra_headers,
        tool_schema,
    )
    .await
}

pub(crate) async fn post_value(
    http: &reqwest::Client,
    uri: Arc<str>,
    value: serde_json::Value,
    session_id: Option<Arc<str>>,
    extra_headers: &HeaderMap,
    tool_schema: Option<&rmcp::model::JsonObject>,
) -> Result<StreamableHttpPostResponse, StreamableHttpError<reqwest::Error>> {
    post_value_limited(
        http,
        uri,
        value,
        session_id,
        extra_headers,
        tool_schema,
        crate::transport_limits::HARD_MAX_SSE_EVENT_BYTES,
    )
    .await
}

pub(crate) async fn post_value_limited(
    http: &reqwest::Client,
    uri: Arc<str>,
    mut value: serde_json::Value,
    session_id: Option<Arc<str>>,
    extra_headers: &HeaderMap,
    tool_schema: Option<&rmcp::model::JsonObject>,
    limit: u64,
) -> Result<StreamableHttpPostResponse, StreamableHttpError<reqwest::Error>> {
    let mut headers = extra_headers.clone();
    if headers
        .get(HEADER_MCP_PROTOCOL_VERSION)
        .and_then(|v| v.to_str().ok())
        == Some(unrelated_mcp_support::headers::VERSION)
    {
        if value.get("params").is_none() {
            value["params"] = serde_json::json!({});
        }
        let meta = &mut value["params"]["_meta"];
        if meta.is_null() {
            *meta = serde_json::json!({});
        }
        meta[unrelated_mcp_support::headers::VERSION_META] =
            serde_json::json!(unrelated_mcp_support::headers::VERSION);
        if meta.get(CLIENT_INFO_META).is_none() {
            meta[CLIENT_INFO_META] = serde_json::json!({"name":"unrelated-mcp-gateway","version":env!("CARGO_PKG_VERSION")});
            meta[CLIENT_CAPABILITIES_META] = serde_json::json!({});
        }
        let schema = tool_schema.map(|schema| serde_json::json!(schema));
        let standard = unrelated_mcp_support::headers::request_headers(&value, schema.as_ref())
            .map_err(|e| StreamableHttpError::UnexpectedServerResponse(e.into()))?;
        let reserved: Vec<_> = headers
            .keys()
            .filter(|name| unrelated_mcp_support::headers::is_routing_header(name))
            .cloned()
            .collect();
        for name in reserved {
            headers.remove(name);
        }
        headers.extend(standard);
    }
    let body = serde_json::to_vec(&value)?;

    let mut req = http
        .post(uri.as_ref())
        .header(reqwest::header::CONTENT_TYPE, JSON_MIME_TYPE)
        .header(
            reqwest::header::ACCEPT,
            format!("{JSON_MIME_TYPE}, {EVENT_STREAM_MIME_TYPE}"),
        )
        .body(body);

    if let Some(sid) = session_id {
        req = req.header(HEADER_SESSION_ID, sid.as_ref());
    }
    req = apply_headers(req, &headers);

    let resp = req.send().await.map_err(StreamableHttpError::Client)?;
    let status = resp.status();

    if status == reqwest::StatusCode::ACCEPTED {
        return Ok(StreamableHttpPostResponse::Accepted);
    }
    if status.is_server_error() {
        return Err(StreamableHttpError::UnexpectedServerResponse(
            format!("upstream http {status}").into(),
        ));
    }
    if status.is_client_error() {
        return Err(StreamableHttpError::UnexpectedServerResponse(
            format!("upstream http {status}").into(),
        ));
    }

    let session_id = resp
        .headers()
        .get(HEADER_SESSION_ID)
        .and_then(header_to_string);

    match content_type(resp.headers()).as_deref() {
        Some(ct) if ct.eq_ignore_ascii_case(EVENT_STREAM_MIME_TYPE) => {
            let stream: BoxStream<'static, Result<sse_stream::Sse, sse_stream::Error>> =
                sse_stream::SseStream::from_bytes_stream(bounded_bytes(resp.bytes_stream(), limit))
                    .boxed();
            Ok(StreamableHttpPostResponse::Sse(stream, session_id))
        }
        Some(ct) if ct.eq_ignore_ascii_case(JSON_MIME_TYPE) => {
            let msg = read_json_response(resp, limit).await?;
            Ok(StreamableHttpPostResponse::Json(msg, session_id))
        }
        other => Err(StreamableHttpError::UnexpectedContentType(
            other.map(std::string::ToString::to_string),
        )),
    }
}

async fn read_json_response(
    response: reqwest::Response,
    limit: u64,
) -> Result<ServerJsonRpcMessage, StreamableHttpError<reqwest::Error>> {
    let too_large = || {
        StreamableHttpError::UnexpectedServerResponse(
            "JSON response exceeds transport limit".into(),
        )
    };
    if response
        .content_length()
        .is_some_and(|length| length > limit)
    {
        return Err(too_large());
    }
    let mut stream = response.bytes_stream();
    let mut body = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(StreamableHttpError::Client)?;
        if (body.len() as u64).saturating_add(chunk.len() as u64) > limit {
            return Err(too_large());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(serde_json::from_slice(&body)?)
}

pub(crate) async fn get_stream(
    http: &reqwest::Client,
    uri: Arc<str>,
    session_id: Option<Arc<str>>,
    last_event_id: Option<String>,
    extra_headers: &HeaderMap,
) -> Result<
    Option<BoxStream<'static, Result<sse_stream::Sse, sse_stream::Error>>>,
    StreamableHttpError<reqwest::Error>,
> {
    let mut req = http
        .get(uri.as_ref())
        .header(reqwest::header::ACCEPT, EVENT_STREAM_MIME_TYPE);
    if let Some(session_id) = session_id {
        req = req.header(HEADER_SESSION_ID, session_id.as_ref());
    }

    if let Some(id) = last_event_id {
        req = req.header(HEADER_LAST_EVENT_ID, id);
    }
    req = apply_headers(req, extra_headers);

    let resp = req.send().await.map_err(StreamableHttpError::Client)?;
    if resp.status() == reqwest::StatusCode::METHOD_NOT_ALLOWED {
        return Ok(None);
    }
    let resp = resp
        .error_for_status()
        .map_err(StreamableHttpError::Client)?;
    let ct = content_type(resp.headers());
    if !matches!(ct.as_deref(), Some(v) if v.eq_ignore_ascii_case(EVENT_STREAM_MIME_TYPE)) {
        return Err(StreamableHttpError::UnexpectedContentType(ct));
    }

    Ok(Some(
        sse_stream::SseStream::from_bytes_stream(resp.bytes_stream()).boxed(),
    ))
}

pub(crate) async fn delete_session(
    http: &reqwest::Client,
    uri: Arc<str>,
    session_id: Arc<str>,
    extra_headers: &HeaderMap,
) -> Result<(), StreamableHttpError<reqwest::Error>> {
    let mut req = http
        .delete(uri.as_ref())
        .header(HEADER_SESSION_ID, session_id.as_ref());
    req = apply_headers(req, extra_headers);
    req.send().await.map_err(StreamableHttpError::Client)?;
    Ok(())
}

#[cfg(test)]
mod dns_rebinding;

#[cfg(test)]
mod safety_tests {
    use crate::outbound_safety::UpstreamHttpClients;
    use crate::store::UpstreamNetworkClass;
    use unrelated_http_tools::safety::OutboundHttpSafety;

    #[tokio::test]
    async fn managed_pool_cannot_authorize_external_dns_connections() {
        use axum::{Router, routing::get};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new().route("/", get(|| async { "managed" })),
            )
            .await
            .unwrap();
        });
        let clients =
            UpstreamHttpClients::with_safety(OutboundHttpSafety::gateway_default()).unwrap();
        let url = format!("http://localhost:{port}/");
        let managed = clients.for_class(UpstreamNetworkClass::ClusterInternalManaged);
        assert_eq!(
            managed
                .get(&url)
                .send()
                .await
                .unwrap()
                .text()
                .await
                .unwrap(),
            "managed"
        );
        // Even after a successful managed request to the same origin, the external
        // client's pool/resolver cannot reuse that permitted private connection.
        let external = clients.for_class(UpstreamNetworkClass::External);
        assert!(external.get(&url).send().await.unwrap_err().is_connect());
        task.abort();
    }
}

/// Bound unterminated SSE events before the decoder accumulates their data.
#[derive(Default)]
struct EventBudget {
    bytes: u64,
    line_bytes: u64,
    cr: bool,
}
impl EventBudget {
    fn consume(&mut self, chunk: &[u8], limit: u64) -> bool {
        for &byte in chunk {
            if byte == b'\n' && self.cr {
                self.cr = false;
                continue;
            }
            self.bytes += 1;
            if self.bytes > limit {
                return false;
            }
            if matches!(byte, b'\r' | b'\n') {
                if self.line_bytes == 0 {
                    self.bytes = 0;
                }
                self.line_bytes = 0;
                self.cr = byte == b'\r';
            } else {
                self.line_bytes += 1;
                self.cr = false;
            }
        }
        true
    }
}
fn bounded_bytes<S>(
    stream: S,
    limit: u64,
) -> impl futures::Stream<Item = Result<axum::body::Bytes, std::io::Error>>
where
    S: futures::Stream<Item = Result<axum::body::Bytes, reqwest::Error>>,
{
    stream.scan(
        (EventBudget::default(), false),
        move |(budget, done), chunk| {
            let output = if *done {
                None
            } else {
                let result = chunk.map_err(std::io::Error::other).and_then(|chunk| {
                    if budget.consume(&chunk, limit) {
                        Ok(chunk)
                    } else {
                        Err(std::io::Error::other("SSE event exceeds transport limit"))
                    }
                });
                *done = result.is_err();
                Some(result)
            };
            futures::future::ready(output)
        },
    )
}
#[cfg(test)]
mod budget_tests {
    use super::*;

    #[tokio::test]
    async fn bounds_json_responses_with_or_without_content_length() {
        use axum::{Router, body::Body, response::IntoResponse as _, routing::get};
        const REPLY: &str = r#"{"jsonrpc":"2.0","id":1,"result":{}}"#;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new()
            .route(
                "/length",
                get(|| async { ([("content-type", "application/json")], REPLY) }),
            )
            .route(
                "/chunked",
                get(|| async {
                    let chunks = REPLY.as_bytes().chunks(7).map(|chunk| {
                        Ok::<_, std::io::Error>(axum::body::Bytes::copy_from_slice(chunk))
                    });
                    (
                        [("content-type", "application/json")],
                        Body::from_stream(futures::stream::iter(chunks)),
                    )
                        .into_response()
                }),
            );
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        for path in ["length", "chunked"] {
            for limit in [0, REPLY.len() as u64 - 1, REPLY.len() as u64] {
                let response = client
                    .get(format!("http://{address}/{path}"))
                    .send()
                    .await
                    .unwrap();
                assert_eq!(response.content_length().is_some(), path == "length");
                let result = read_json_response(response, limit).await;
                if limit < REPLY.len() as u64 {
                    assert!(result.unwrap_err().to_string().contains("transport limit"));
                } else {
                    assert!(matches!(result.unwrap(), ServerJsonRpcMessage::Response(_)));
                }
            }
        }
        server.abort();
    }

    #[test]
    fn limits_unterminated_events_across_chunks_and_accepts_all_line_endings() {
        for ending in ["\n", "\r\n", "\r"] {
            let mut budget = EventBudget::default();
            let event = format!("data:x{ending}{ending}");
            for _ in 0..10 {
                for byte in event.bytes() {
                    assert!(budget.consume(&[byte], 16));
                }
            }
            assert!(budget.consume(b"data:123456789", 16));
            assert!(!budget.consume(b"0123456789", 16));
        }
    }
}
