use axum::http::{HeaderMap, HeaderValue};
use futures::{StreamExt as _, stream::BoxStream};
use rmcp::model::{ClientJsonRpcMessage, ServerJsonRpcMessage};
use rmcp::transport::common::http_header::{
    EVENT_STREAM_MIME_TYPE, HEADER_LAST_EVENT_ID, HEADER_SESSION_ID, JSON_MIME_TYPE,
};
use rmcp::transport::streamable_http_client::{StreamableHttpError, StreamableHttpPostResponse};
use std::sync::Arc;

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
    let body = serde_json::to_vec(&message)?;

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
    req = apply_headers(req, extra_headers);

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
                sse_stream::SseStream::from_bytes_stream(resp.bytes_stream()).boxed();
            Ok(StreamableHttpPostResponse::Sse(stream, session_id))
        }
        Some(ct) if ct.eq_ignore_ascii_case(JSON_MIME_TYPE) => {
            let msg: ServerJsonRpcMessage =
                resp.json().await.map_err(StreamableHttpError::Client)?;
            Ok(StreamableHttpPostResponse::Json(msg, session_id))
        }
        other => Err(StreamableHttpError::UnexpectedContentType(
            other.map(std::string::ToString::to_string),
        )),
    }
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
