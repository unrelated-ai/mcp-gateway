//! Session manager wrapper for rmcp's streamable HTTP transport.
//!
//! We delegate most behavior to rmcp's `LocalSessionManager`, but add adapter-specific
//! cleanup hooks on session close (e.g. per-session stdio processes).

use crate::contracts::ContractNotifier;
use crate::supervisor::BackendManager;
use futures::Stream;
use rmcp::model::{ClientJsonRpcMessage, ServerJsonRpcMessage};
use rmcp::transport::common::server_side_http::ServerSseMessage;
use rmcp::transport::streamable_http_server::session::SessionId;
use rmcp::transport::streamable_http_server::session::SessionManager;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use std::future::Future;
use std::sync::Arc;

#[derive(Default)]
pub struct AdapterSessionManager {
    inner: LocalSessionManager,
    backend_manager: Arc<BackendManager>,
    contracts: Arc<ContractNotifier>,
}

impl AdapterSessionManager {
    pub fn new(backend_manager: Arc<BackendManager>, contracts: Arc<ContractNotifier>) -> Self {
        let mut inner = LocalSessionManager::default();
        inner.session_config.sse_retry = None;

        Self {
            inner,
            backend_manager,
            contracts,
        }
    }

    async fn close_session_impl(
        &self,
        id: &SessionId,
    ) -> Result<(), <LocalSessionManager as SessionManager>::Error> {
        let result = self.inner.close_session(id).await;

        // Best-effort: remove peer reference and clean up any per-session backend state.
        self.contracts.forget_peer(id.as_ref());
        for backend in self.backend_manager.get_all_backends() {
            backend.shutdown_session(id.as_ref()).await;
        }

        result
    }
}

impl SessionManager for AdapterSessionManager {
    type Error = <LocalSessionManager as SessionManager>::Error;
    type Transport = <LocalSessionManager as SessionManager>::Transport;

    fn create_session(
        &self,
    ) -> impl Future<Output = Result<(SessionId, Self::Transport), Self::Error>> + Send {
        self.inner.create_session()
    }

    fn initialize_session(
        &self,
        id: &SessionId,
        message: ClientJsonRpcMessage,
    ) -> impl Future<Output = Result<ServerJsonRpcMessage, Self::Error>> + Send {
        self.inner.initialize_session(id, message)
    }

    fn has_session(
        &self,
        id: &SessionId,
    ) -> impl Future<Output = Result<bool, Self::Error>> + Send {
        self.inner.has_session(id)
    }

    fn close_session(
        &self,
        id: &SessionId,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        self.close_session_impl(id)
    }

    fn create_stream(
        &self,
        id: &SessionId,
        message: ClientJsonRpcMessage,
    ) -> impl Future<
        Output = Result<impl Stream<Item = ServerSseMessage> + Send + Sync + 'static, Self::Error>,
    > + Send {
        self.inner.create_stream(id, message)
    }

    fn accept_message(
        &self,
        id: &SessionId,
        message: ClientJsonRpcMessage,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        self.inner.accept_message(id, message)
    }

    fn create_standalone_stream(
        &self,
        id: &SessionId,
    ) -> impl Future<
        Output = Result<impl Stream<Item = ServerSseMessage> + Send + Sync + 'static, Self::Error>,
    > + Send {
        self.inner.create_standalone_stream(id)
    }

    fn resume(
        &self,
        id: &SessionId,
        last_event_id: String,
    ) -> impl Future<
        Output = Result<impl Stream<Item = ServerSseMessage> + Send + Sync + 'static, Self::Error>,
    > + Send {
        self.inner.resume(id, last_event_id)
    }
}
