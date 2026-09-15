use rmcp::{
    ErrorData, ServerHandler,
    model::{
        Implementation, ListToolsResult, PaginatedRequestParams, ServerCapabilities, ServerInfo,
        Tool,
    },
    service::{RequestContext, RoleServer},
    transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
    },
};
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use unrelated_cli::{
    client,
    config::{AuthMode, ContextConfig},
};

#[derive(Clone, Default)]
struct ChangingCatalog(Arc<AtomicUsize>);

impl ServerHandler for ChangingCatalog {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("changing-catalog", "1"))
    }

    fn list_tools(
        &self,
        _: Option<PaginatedRequestParams>,
        _: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ListToolsResult, ErrorData>> {
        let count = self.0.fetch_add(1, Ordering::SeqCst);
        std::future::ready(if count >= 2 {
            Err(ErrorData::internal_error("catalog unavailable", None))
        } else {
            Ok(ListToolsResult::with_all_items(vec![Tool::new(
                format!("generation-{count}"),
                "Current generation".to_string(),
                Arc::new(serde_json::Map::new()),
            )])
            .with_ttl_ms(60_000))
        })
    }
}

#[tokio::test]
async fn explicit_catalog_refresh_observes_changes_and_errors() -> anyhow::Result<()> {
    let catalog = ChangingCatalog::default();
    let service: StreamableHttpService<ChangingCatalog, LocalSessionManager> =
        StreamableHttpService::new(
            move || Ok(catalog.clone()),
            Arc::default(),
            StreamableHttpServerConfig::default(),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let server = tokio::spawn(async move {
        axum::serve(listener, axum::Router::new().nest_service("/mcp", service)).await
    });
    let context = ContextConfig {
        mcp_url: format!("http://{address}/mcp"),
        auth: AuthMode::None,
        oauth_client_id: None,
    };
    let connection = client::connect("catalog-refresh", &context, Duration::from_secs(5)).await?;
    assert_eq!(
        client::fetch_catalog(&connection).await?.tools[0].name,
        "generation-0"
    );
    assert_eq!(
        client::fetch_catalog(&connection).await?.tools[0].name,
        "generation-1"
    );
    let error = client::fetch_catalog(&connection)
        .await
        .expect_err("an upstream failure must not return stale tools");
    assert!(format!("{error:#}").contains("catalog unavailable"));
    connection.cancel().await?;
    server.abort();
    Ok(())
}
