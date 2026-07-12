use super::*;

pub(super) fn extract_call_tool(
    message: &ClientJsonRpcMessage,
) -> Option<(String, rmcp::model::RequestId, serde_json::Value)> {
    let ClientJsonRpcMessage::Request(JsonRpcRequest { id, request, .. }) = message else {
        return None;
    };
    let ClientRequest::CallToolRequest(call) = request else {
        return None;
    };
    let args = call.params.arguments.clone().unwrap_or_default();
    Some((
        call.params.name.to_string(),
        id.clone(),
        serde_json::Value::Object(args),
    ))
}

pub(super) fn as_call_tool_mut(
    message: &mut ClientJsonRpcMessage,
) -> Option<&mut CallToolRequestParams> {
    let ClientJsonRpcMessage::Request(JsonRpcRequest { request, .. }) = message else {
        return None;
    };
    let ClientRequest::CallToolRequest(call) = request else {
        return None;
    };
    Some(&mut call.params)
}

pub(super) fn extract_read_resource(
    message: &ClientJsonRpcMessage,
) -> Option<(String, rmcp::model::RequestId)> {
    let ClientJsonRpcMessage::Request(JsonRpcRequest { id, request, .. }) = message else {
        return None;
    };
    let ClientRequest::ReadResourceRequest(req) = request else {
        return None;
    };
    Some((req.params.uri.clone(), id.clone()))
}

pub(super) fn extract_subscribe(
    message: &ClientJsonRpcMessage,
) -> Option<(String, rmcp::model::RequestId)> {
    let ClientJsonRpcMessage::Request(JsonRpcRequest { id, request, .. }) = message else {
        return None;
    };
    let ClientRequest::SubscribeRequest(req) = request else {
        return None;
    };
    Some((req.params.uri.clone(), id.clone()))
}

pub(super) fn as_subscribe_mut(
    message: &mut ClientJsonRpcMessage,
) -> Option<&mut SubscribeRequestParams> {
    let ClientJsonRpcMessage::Request(JsonRpcRequest { request, .. }) = message else {
        return None;
    };
    let ClientRequest::SubscribeRequest(req) = request else {
        return None;
    };
    Some(&mut req.params)
}

pub(super) fn extract_unsubscribe(
    message: &ClientJsonRpcMessage,
) -> Option<(String, rmcp::model::RequestId)> {
    let ClientJsonRpcMessage::Request(JsonRpcRequest { id, request, .. }) = message else {
        return None;
    };
    let ClientRequest::UnsubscribeRequest(req) = request else {
        return None;
    };
    Some((req.params.uri.clone(), id.clone()))
}

pub(super) fn as_unsubscribe_mut(
    message: &mut ClientJsonRpcMessage,
) -> Option<&mut UnsubscribeRequestParams> {
    let ClientJsonRpcMessage::Request(JsonRpcRequest { request, .. }) = message else {
        return None;
    };
    let ClientRequest::UnsubscribeRequest(req) = request else {
        return None;
    };
    Some(&mut req.params)
}

pub(super) fn as_read_resource_mut(
    message: &mut ClientJsonRpcMessage,
) -> Option<&mut ReadResourceRequestParams> {
    let ClientJsonRpcMessage::Request(JsonRpcRequest { request, .. }) = message else {
        return None;
    };
    let ClientRequest::ReadResourceRequest(req) = request else {
        return None;
    };
    Some(&mut req.params)
}

pub(super) fn extract_get_prompt(
    message: &ClientJsonRpcMessage,
) -> Option<(String, rmcp::model::RequestId)> {
    let ClientJsonRpcMessage::Request(JsonRpcRequest { id, request, .. }) = message else {
        return None;
    };
    let ClientRequest::GetPromptRequest(req) = request else {
        return None;
    };
    Some((req.params.name.clone(), id.clone()))
}

pub(super) fn as_get_prompt_mut(
    message: &mut ClientJsonRpcMessage,
) -> Option<&mut GetPromptRequestParams> {
    let ClientJsonRpcMessage::Request(JsonRpcRequest { request, .. }) = message else {
        return None;
    };
    let ClientRequest::GetPromptRequest(req) = request else {
        return None;
    };
    Some(&mut req.params)
}

pub(super) fn extract_complete(
    message: &ClientJsonRpcMessage,
) -> Option<(Reference, rmcp::model::RequestId)> {
    let ClientJsonRpcMessage::Request(JsonRpcRequest { id, request, .. }) = message else {
        return None;
    };
    let ClientRequest::CompleteRequest(req) = request else {
        return None;
    };
    Some((req.params.r#ref.clone(), id.clone()))
}

pub(super) fn as_complete_mut(
    message: &mut ClientJsonRpcMessage,
) -> Option<&mut rmcp::model::CompleteRequestParams> {
    let ClientJsonRpcMessage::Request(JsonRpcRequest { request, .. }) = message else {
        return None;
    };
    let ClientRequest::CompleteRequest(req) = request else {
        return None;
    };
    Some(&mut req.params)
}

pub(super) fn as_request_ref(
    message: &ClientJsonRpcMessage,
) -> Option<&JsonRpcRequest<ClientRequest>> {
    let ClientJsonRpcMessage::Request(req) = message else {
        return None;
    };
    Some(req)
}

pub(super) fn sse_single_message(msg: &ServerJsonRpcMessage) -> Response {
    let data = serde_json::to_string(&msg).expect("valid json");
    let stream = futures::stream::once(async move {
        Ok::<_, Infallible>(axum::response::sse::Event::default().data(data))
    });
    let mut resp = Sse::new(stream).into_response();
    resp.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static(EVENT_STREAM_MIME_TYPE),
    );
    resp
}

pub(super) fn sse_single_message_with_session_id(
    msg: &ServerJsonRpcMessage,
    session_id: &str,
) -> Response {
    let mut resp = sse_single_message(msg);
    resp.headers_mut().insert(
        HEADER_SESSION_ID,
        HeaderValue::from_str(session_id).expect("valid header"),
    );
    resp
}

pub(super) fn sse_from_upstream_stream<S>(stream: S) -> Response
where
    S: Stream<Item = Result<sse_stream::Sse, sse_stream::Error>> + Send + 'static,
{
    let mapped = stream.map(|evt| match evt {
        Ok(sse) => {
            let mut ev = axum::response::sse::Event::default();
            if let Some(id) = sse.id {
                ev = ev.id(id);
            }
            if let Some(data) = sse.data {
                ev = ev.data(data);
            }
            Ok::<_, Infallible>(ev)
        }
        Err(e) => {
            tracing::warn!(error = %e, "upstream sse error");
            Ok::<_, Infallible>(axum::response::sse::Event::default().comment("upstream error"))
        }
    });
    let mut resp = Sse::new(mapped).into_response();
    resp.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static(EVENT_STREAM_MIME_TYPE),
    );
    resp
}

pub(super) fn ensure_accepts_post(headers: &HeaderMap) -> Result<(), (StatusCode, &'static str)> {
    let accept = headers
        .get(axum::http::header::ACCEPT)
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default();
    if accept.contains(JSON_MIME_TYPE) && accept.contains(EVENT_STREAM_MIME_TYPE) {
        Ok(())
    } else {
        Err((
            StatusCode::NOT_ACCEPTABLE,
            "Not Acceptable: Client must accept both application/json and text/event-stream",
        ))
    }
}

pub(super) fn ensure_accepts_get(headers: &HeaderMap) -> Result<(), (StatusCode, &'static str)> {
    let accept = headers
        .get(axum::http::header::ACCEPT)
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default();
    if accept.contains(EVENT_STREAM_MIME_TYPE) {
        Ok(())
    } else {
        Err((
            StatusCode::NOT_ACCEPTABLE,
            "Not Acceptable: Client must accept text/event-stream",
        ))
    }
}

pub(super) fn ensure_json_content_type(
    headers: &HeaderMap,
) -> Result<(), (StatusCode, &'static str)> {
    let ct = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default();
    if ct.starts_with(JSON_MIME_TYPE) {
        Ok(())
    } else {
        Err((
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Unsupported Media Type: Content-Type must be application/json",
        ))
    }
}

pub(super) fn internal_error_response(
    context: &'static str,
) -> impl FnOnce(anyhow::Error) -> Response {
    move |e| {
        tracing::error!(error = %e, "internal error when {context}");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Internal error when {context}: {e}"),
        )
            .into_response()
    }
}

pub(super) fn jsonrpc_error_response(
    id: rmcp::model::RequestId,
    code: ErrorCode,
    message: String,
) -> Response {
    jsonrpc_error_response_with_data(id, code, message, None)
}

pub(super) fn jsonrpc_error_response_with_data(
    id: rmcp::model::RequestId,
    code: ErrorCode,
    message: String,
    data: Option<serde_json::Value>,
) -> Response {
    let error = ServerJsonRpcMessage::Error(JsonRpcError {
        jsonrpc: JsonRpcVersion2_0,
        id: Some(id),
        error: ErrorData::new(code, message, data),
    });
    sse_single_message(&error)
}
