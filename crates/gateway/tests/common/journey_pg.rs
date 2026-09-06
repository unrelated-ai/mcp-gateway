use anyhow::Context as _;
use serde_json::{Value, json};
use std::time::Duration;
use testcontainers::{
    ContainerAsync, GenericImage, ImageExt as _, core::IntoContainerPort, runners::AsyncRunner,
};

pub async fn start(statements: bool) -> anyhow::Result<(ContainerAsync<GenericImage>, String)> {
    let mut request = GenericImage::new("postgres", "16-alpine")
        .with_exposed_port(5432.tcp())
        .with_env_var("POSTGRES_PASSWORD", "postgres")
        .with_env_var("POSTGRES_USER", "postgres")
        .with_env_var("POSTGRES_DB", "gateway");
    if statements {
        request = request.with_cmd([
            "postgres",
            "-c",
            "shared_preload_libraries=pg_stat_statements",
        ]);
    }
    let container = request.start().await?;
    let url = format!(
        "postgres://postgres:postgres@{}:{}/gateway?sslmode=disable",
        container.get_host().await?,
        container.get_host_port_ipv4(5432).await?
    );
    crate::common::pg::wait_pg_ready(&url, Duration::from_secs(30)).await?;
    Ok((container, url))
}

pub async fn admin(base: &str, path: &str, body: Value) -> anyhow::Result<Value> {
    let response = reqwest::Client::new()
        .post(format!("{base}{path}"))
        .bearer_auth(crate::journey::ADMIN_TOKEN)
        .json(&body)
        .send()
        .await?;
    let status = response.status();
    let text = response.text().await?;
    anyhow::ensure!(status.is_success(), "{path}: {status}: {text}");
    serde_json::from_str(&text).context("admin response")
}

pub async fn seed_tenant(base: &str) -> anyhow::Result<String> {
    admin(
        base,
        "/admin/v1/tenants",
        json!({"id":"journey", "enabled":true}),
    )
    .await?;
    let token = admin(
        base,
        "/admin/v1/tenant-tokens",
        json!({"tenantId":"journey", "ttlSeconds":3600}),
    )
    .await?;
    Ok(token["token"].as_str().context("tenant token")?.to_string())
}

pub async fn seed_upstream(base: &str, id: &str, url: &str) -> anyhow::Result<()> {
    admin(
        base,
        "/admin/v1/upstreams",
        json!({"id":id, "enabled":true, "endpoints":[{"id":"one", "url":url}]}),
    )
    .await?;
    Ok(())
}

pub async fn seed_profile(base: &str, ids: &[String], auth: Value) -> anyhow::Result<()> {
    admin(
        base,
        "/admin/v1/profiles",
        json!({
            "id":crate::journey::PROFILE_ID, "tenantId":"journey", "name":"Upgrade rehearsal",
            "description":"Profile created by the release rehearsal", "toolCallTimeoutSecs":15,
            "enabled":true, "upstreams":ids, "allowPartialUpstreams":false, "dataPlaneAuth":auth
        }),
    )
    .await?;
    Ok(())
}
