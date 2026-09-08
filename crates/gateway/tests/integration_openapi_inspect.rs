mod common;

use anyhow::Context as _;
use axum::{Json, Router, http::HeaderMap, http::StatusCode, routing::get};
use common::pg::{apply_dbmate_migrations, wait_pg_ready};
use common::{KillOnDrop, spawn_gateway, wait_http_ok};
use serde_json::{Value, json};
use std::time::Duration;
use testcontainers::core::IntoContainerPort;
use testcontainers::runners::AsyncRunner;
use testcontainers::{GenericImage, ImageExt as _};

const TOKEN: &str = "inspect-fixture-token";
const ADMIN_TOKEN: &str = "inspect-admin-token";

async fn post(
    client: &reqwest::Client,
    url: &str,
    token: &str,
    body: Value,
) -> anyhow::Result<Value> {
    Ok(client
        .post(url)
        .bearer_auth(token)
        .json(&body)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?)
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
#[allow(clippy::too_many_lines)]
async fn openapi_inspect_authenticates_with_tenant_scoped_secrets() -> anyhow::Result<()> {
    let pg = GenericImage::new("postgres", "16-alpine")
        .with_exposed_port(5432.tcp())
        .with_env_var("POSTGRES_PASSWORD", "postgres")
        .with_env_var("POSTGRES_USER", "postgres")
        .with_env_var("POSTGRES_DB", "gateway")
        .start()
        .await?;
    let database_url = format!(
        "postgres://postgres:postgres@{}:{}/gateway?sslmode=disable",
        pg.get_host().await?,
        pg.get_host_port_ipv4(5432).await?
    );
    wait_pg_ready(&database_url, Duration::from_secs(30)).await?;
    apply_dbmate_migrations(&database_url).await?;
    let gateway = spawn_gateway(&database_url, Some(ADMIN_TOKEN), "inspect-session-secret")?;
    let _gateway = KillOnDrop(gateway.child);
    let base = gateway.admin_base;
    wait_http_ok(&format!("{base}/health"), Duration::from_secs(20)).await?;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let api_base = format!("http://{}", listener.local_addr()?);
    let spec = json!({
        "openapi": "3.0.3", "info": {"title":"Protected API", "version":"1"},
        "servers": [{"url": api_base}],
        "paths": {"/ping": {"get": {"operationId":"ping", "responses":{"200":{"description":"OK"}}}}}
    });
    let public_spec = spec.clone();
    let app = Router::new()
        .route(
            "/public.json",
            get(move || {
                let spec = public_spec.clone();
                async move { Json(spec) }
            }),
        )
        .route(
            "/protected.json",
            get(move |headers: HeaderMap| {
                let spec = spec.clone();
                async move {
                    if headers
                        .get("authorization")
                        .and_then(|value| value.to_str().ok())
                        != Some("Bearer inspect-fixture-token")
                    {
                        return Err(StatusCode::UNAUTHORIZED);
                    }
                    Ok(Json(spec))
                }
            }),
        );
    let cancel = tokio_util::sync::CancellationToken::new();
    let shutdown = cancel.clone().drop_guard();
    let server = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(cancel.cancelled_owned())
            .await
    });

    let client = reqwest::Client::new();
    let mut tokens = Vec::new();
    for tenant in ["owner", "other"] {
        post(
            &client,
            &format!("{base}/admin/v1/tenants"),
            ADMIN_TOKEN,
            json!({"id":tenant,"enabled":true}),
        )
        .await?;
        let token = post(
            &client,
            &format!("{base}/admin/v1/tenant-tokens"),
            ADMIN_TOKEN,
            json!({"tenantId":tenant,"ttlSeconds":3600}),
        )
        .await?;
        tokens.push(token["token"].as_str().context("tenant token")?.to_string());
    }
    post(
        &client,
        &format!("{base}/tenant/v1/secrets"),
        &tokens[0],
        json!({"name":"API_TOKEN","value":TOKEN}),
    )
    .await?;
    let endpoint = format!("{base}/tenant/v1/tool-sources/openapi/inspect");
    let protected = format!("{api_base}/protected.json");
    let secret_auth = json!({"type":"bearer","token":"${secret:API_TOKEN}"});

    for body in [
        json!({"specUrl":format!("{api_base}/public.json")}),
        json!({"specUrl":protected,"auth":{"type":"bearer","token":TOKEN}}),
        json!({"specUrl":protected,"auth":secret_auth}),
    ] {
        let result = post(&client, &endpoint, &tokens[0], body).await?;
        assert_eq!(result["tools"][0]["name"], "ping");
        assert_eq!(result["inferredBaseUrl"], api_base);
        assert!(!result.to_string().contains(TOKEN));
    }

    for auth in [
        Value::Null,
        json!({"type":"bearer","token":"invalid-fixture-token"}),
    ] {
        let response = client
            .post(&endpoint)
            .bearer_auth(&tokens[0])
            .json(&json!({"specUrl":protected,"auth":auth}))
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        let error = response.text().await?;
        assert!(error.contains("401 Unauthorized"), "{error}");
        assert!(!error.contains("invalid-fixture-token"));
    }

    // The second tenant cannot resolve a secret belonging to the first tenant.
    let response = client
        .post(&endpoint)
        .bearer_auth(&tokens[1])
        .json(&json!({"specUrl":protected,"auth":secret_auth}))
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(
        response
            .text()
            .await?
            .contains("missing secret 'API_TOKEN'")
    );

    // Previewing a source must not create or persist its resolved credentials.
    let sources: Value = client
        .get(format!("{base}/tenant/v1/tool-sources"))
        .bearer_auth(&tokens[0])
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert!(sources["sources"].as_array().context("sources")?.is_empty());
    drop(shutdown);
    server.await??;
    Ok(())
}
