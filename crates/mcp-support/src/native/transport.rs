use super::{NotificationHub, preserve_subscription};
use futures::StreamExt as _;
use http::{HeaderName, HeaderValue};
use rmcp::{
    model::ClientJsonRpcMessage,
    service::{RxJsonRpcMessage, ServiceRole, TxJsonRpcMessage},
    transport::{
        Transport,
        async_rw::AsyncRwTransport,
        streamable_http_client::{
            StreamableHttpClient, StreamableHttpError, StreamableHttpPostResponse,
        },
    },
};
use std::{collections::HashMap, io, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt as _, DuplexStream},
    process::Child,
    task::JoinHandle,
};
use tokio_util::codec::{FramedRead, LinesCodec};

const MAX_LINE: usize = 16 * 1024 * 1024;
type EventStream = futures::stream::BoxStream<'static, Result<sse_stream::Sse, sse_stream::Error>>;

/// Keep the SDK's message dispatch and bounded transport after preserving filters.
pub struct SubscriptionIo<R: ServiceRole, W: AsyncWrite> {
    inner: AsyncRwTransport<R, DuplexStream, W>,
    reader: JoinHandle<io::Result<()>>,
    child: Option<Child>,
}

impl<R: ServiceRole, W: AsyncWrite + Unpin + Send + 'static> SubscriptionIo<R, W> {
    pub fn new(read: impl AsyncRead + Unpin + Send + 'static, write: W) -> Self {
        Self::new_inner(read, write, None)
    }

    pub fn with_notifications(
        read: impl AsyncRead + Unpin + Send + 'static,
        write: W,
        hub: NotificationHub,
    ) -> Self {
        Self::new_inner(read, write, Some(hub))
    }

    fn new_inner(
        read: impl AsyncRead + Unpin + Send + 'static,
        write: W,
        hub: Option<NotificationHub>,
    ) -> Self {
        let (read_pipe, mut writer) = tokio::io::duplex(64 * 1024);
        let reader = tokio::spawn(async move {
            let mut lines = FramedRead::new(read, LinesCodec::new_with_max_length(MAX_LINE));
            while let Some(line) = lines.next().await {
                let line = line.map_err(io::Error::other)?;
                let output = match serde_json::from_str::<serde_json::Value>(&line) {
                    Ok(mut message) => {
                        preserve_subscription(&mut message);
                        if let Some(hub) = &hub {
                            hub.publish_message(&message);
                        }
                        message.to_string()
                    }
                    Err(_) => line,
                };
                writer.write_all(output.as_bytes()).await?;
                writer.write_all(b"\n").await?;
            }
            writer.shutdown().await
        });
        Self {
            inner: AsyncRwTransport::new(read_pipe, write),
            reader,
            child: None,
        }
    }

    #[must_use]
    pub fn with_child(mut self, child: Child) -> Self {
        self.child = Some(child);
        self
    }
}

impl<R: ServiceRole, W: AsyncWrite + Unpin + Send + 'static> Transport<R> for SubscriptionIo<R, W> {
    type Error = io::Error;

    fn send(
        &mut self,
        item: TxJsonRpcMessage<R>,
    ) -> impl Future<Output = Result<(), io::Error>> + Send + 'static {
        self.inner.send(item)
    }

    async fn receive(&mut self) -> Option<RxJsonRpcMessage<R>> {
        self.inner.receive().await
    }

    async fn close(&mut self) -> Result<(), io::Error> {
        let result = self.inner.close().await;
        if let Some(child) = self.child.as_mut()
            && tokio::time::timeout(Duration::from_secs(3), child.wait())
                .await
                .is_err()
        {
            child.kill().await?;
        }
        self.reader.abort();
        result
    }
}

impl<R: ServiceRole, W: AsyncWrite> Drop for SubscriptionIo<R, W> {
    fn drop(&mut self) {
        self.reader.abort();
        if let Some(child) = self.child.as_mut() {
            let _ = child.start_kill();
        }
    }
}

#[derive(Clone, Debug)]
pub struct SubscriptionHttpClient<C> {
    pub ordinary: C,
    pub subscriptions: C,
    pub notifications: NotificationHub,
}

fn preserve_response(
    response: StreamableHttpPostResponse,
    hub: NotificationHub,
) -> StreamableHttpPostResponse {
    match response {
        StreamableHttpPostResponse::Sse(stream, session) => {
            let stream = stream.map(move |event| {
                event.map(|mut event| {
                    if let Some(data) = event.data.as_mut()
                        && let Ok(mut message) = serde_json::from_str(data)
                    {
                        preserve_subscription(&mut message);
                        hub.publish_message(&message);
                        *data = message.to_string();
                    }
                    event
                })
            });
            StreamableHttpPostResponse::Sse(Box::pin(stream), session)
        }
        other => other,
    }
}

impl<C: StreamableHttpClient + Sync> StreamableHttpClient for SubscriptionHttpClient<C> {
    type Error = C::Error;

    async fn post_message(
        &self,
        uri: Arc<str>,
        message: ClientJsonRpcMessage,
        session_id: Option<Arc<str>>,
        auth_header: Option<String>,
        custom_headers: HashMap<HeaderName, HeaderValue>,
    ) -> Result<StreamableHttpPostResponse, StreamableHttpError<Self::Error>> {
        self.post_message_with_max_sse_event_size(
            uri,
            message,
            session_id,
            auth_header,
            custom_headers,
            MAX_LINE,
        )
        .await
    }

    async fn post_message_with_max_sse_event_size(
        &self,
        uri: Arc<str>,
        message: ClientJsonRpcMessage,
        session_id: Option<Arc<str>>,
        auth_header: Option<String>,
        custom_headers: HashMap<HeaderName, HeaderValue>,
        max_sse_event_size: usize,
    ) -> Result<StreamableHttpPostResponse, StreamableHttpError<Self::Error>> {
        let client = match &message {
            ClientJsonRpcMessage::Request(req)
                if req.request.method() == "subscriptions/listen" =>
            {
                &self.subscriptions
            }
            _ => &self.ordinary,
        };
        client
            .post_message_with_max_sse_event_size(
                uri,
                message,
                session_id,
                auth_header,
                custom_headers,
                max_sse_event_size,
            )
            .await
            .map(|response| preserve_response(response, self.notifications.clone()))
    }

    async fn delete_session(
        &self,
        uri: Arc<str>,
        session_id: Arc<str>,
        auth_header: Option<String>,
        custom_headers: HashMap<HeaderName, HeaderValue>,
    ) -> Result<(), StreamableHttpError<Self::Error>> {
        self.ordinary
            .delete_session(uri, session_id, auth_header, custom_headers)
            .await
    }

    async fn get_stream(
        &self,
        uri: Arc<str>,
        session_id: Option<Arc<str>>,
        last_event_id: Option<String>,
        auth_header: Option<String>,
        custom_headers: HashMap<HeaderName, HeaderValue>,
    ) -> Result<EventStream, StreamableHttpError<Self::Error>> {
        self.ordinary
            .get_stream(uri, session_id, last_event_id, auth_header, custom_headers)
            .await
    }

    async fn get_stream_with_max_sse_event_size(
        &self,
        uri: Arc<str>,
        session_id: Option<Arc<str>>,
        last_event_id: Option<String>,
        auth_header: Option<String>,
        custom_headers: HashMap<HeaderName, HeaderValue>,
        max_sse_event_size: usize,
    ) -> Result<EventStream, StreamableHttpError<Self::Error>> {
        self.ordinary
            .get_stream_with_max_sse_event_size(
                uri,
                session_id,
                last_event_id,
                auth_header,
                custom_headers,
                max_sse_event_size,
            )
            .await
    }
}
