mod common;
#[path = "common/journey.rs"]
#[allow(dead_code)]
mod journey;

use anyhow::Context as _;
use common::{KillOnDrop, spawn_gateway, wait_http_ok};
use reqwest::{Client, Method, StatusCode};
use serde_json::{Value, json};
use sqlx::{PgPool, Row as _};
use std::time::{Duration, Instant};
use testcontainers::{ImageExt as _, core::IntoContainerPort, runners::AsyncRunner};
use uuid::Uuid;

const ADMIN_TOKEN: &str = "profile-audit-admin";
const TENANT: &str = "audit-test";

struct Api {
    client: Client,
    base: String,
    token: String,
}

impl Api {
    async fn request(
        &self,
        method: Method,
        path: &str,
        body: Value,
    ) -> anyhow::Result<reqwest::Response> {
        Ok(self
            .client
            .request(method, format!("{}{path}", self.base))
            .bearer_auth(&self.token)
            .json(&body)
            .send()
            .await?)
    }

    async fn json(&self, method: Method, path: &str, body: Value) -> anyhow::Result<Value> {
        let response = self.request(method, path, body).await?;
        let status = response.status();
        let text = response.text().await?;
        anyhow::ensure!(status.is_success(), "{path}: {status}: {text}");
        Ok(serde_json::from_str(&text)?)
    }
}

async fn set_tenant(admin: &Api, enabled: bool, level: &str) -> anyhow::Result<()> {
    admin
        .json(
            Method::PUT,
            &format!("/admin/v1/tenants/{TENANT}/audit/settings"),
            json!({"enabled":enabled,"defaultLevel":level,"retentionDays":17}),
        )
        .await?;
    Ok(())
}

async fn set_profile(api: &Api, path: &str, settings: Value) -> anyhow::Result<Value> {
    let before = api.json(Method::GET, path, Value::Null).await?;
    api.json(
        Method::PUT,
        path,
        json!({"auditSettings":settings,"expectedRevision":before["revision"]}),
    )
    .await?;
    let after = api.json(Method::GET, path, Value::Null).await?;
    assert_eq!(
        after["revision"].as_i64(),
        before["revision"].as_i64().map(|r| r + 1)
    );
    assert_eq!(after["tenantSettings"]["retentionDays"], 17);
    Ok(after)
}

async fn latest_event(pool: &PgPool) -> anyhow::Result<i64> {
    Ok(
        sqlx::query_scalar("select coalesce(max(id),0) from audit_events")
            .fetch_one(pool)
            .await?,
    )
}

// A unique oversized request exercises sample capture and policy enforcement in the real data plane.
async fn probe_policy(
    pool: &PgPool,
    data_base: &str,
    profile: Uuid,
    expected: &str,
) -> anyhow::Result<()> {
    let before = latest_event(pool).await?;
    let response = Client::new()
        .post(format!("{data_base}/{profile}/mcp"))
        .header("Accept", "application/json, text/event-stream")
        .header("Content-Type", "application/json")
        .body("x".repeat(5000))
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let started = Instant::now();
    loop {
        let row = sqlx::query("select meta, error_message, error_kind from audit_events where id > $1 and profile_id = $2 and action = 'mcp.payload_limit_exceeded' order by id desc limit 1")
            .bind(before).bind(profile).fetch_optional(pool).await?;
        if let Some(row) = row {
            assert_ne!(expected, "off", "profile MCP activity must be suppressed");
            let meta: Value = row.try_get("meta")?;
            assert_eq!(
                row.try_get::<String, _>("error_kind")?,
                "payload_limit_exceeded"
            );
            if expected == "summary" {
                assert_eq!(meta, json!({}));
                assert!(row.try_get::<Option<String>, _>("error_message")?.is_none());
            } else {
                assert_eq!(meta["limit"], 128);
                if expected == "payload" {
                    assert_eq!(
                        meta["sample"].as_str().context("payload sample")?.len(),
                        4096
                    );
                    assert_eq!(meta["sampleTruncated"], true);
                } else {
                    assert!(meta.get("sample").is_none());
                    assert!(meta.get("sampleTruncated").is_none());
                }
            }
            return Ok(());
        }
        if expected == "off" && started.elapsed() > Duration::from_secs(1) {
            return Ok(());
        }
        anyhow::ensure!(
            started.elapsed() < Duration::from_secs(5),
            "missing {expected} audit event"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn profile_audit_policy_controls_logging_on_both_replicas() -> anyhow::Result<()> {
    let pg = common::pg::image()
        .with_exposed_port(5432.tcp())
        .with_env_var("POSTGRES_PASSWORD", "postgres")
        .with_env_var("POSTGRES_USER", "postgres")
        .with_env_var("POSTGRES_DB", "gateway")
        .start()
        .await?;
    let url = format!(
        "postgres://postgres:postgres@{}:{}/gateway?sslmode=disable",
        pg.get_host().await?,
        pg.get_host_port_ipv4(5432).await?
    );
    common::pg::wait_pg_ready(&url, Duration::from_secs(30)).await?;
    common::pg::apply_dbmate_migrations(&url).await?;
    let pool = PgPool::connect(&url).await?;
    let first = spawn_gateway(&url, Some(ADMIN_TOKEN), "profile-audit-session")?;
    let second = spawn_gateway(&url, Some(ADMIN_TOKEN), "profile-audit-session")?;
    let _children = [KillOnDrop(first.child), KillOnDrop(second.child)];
    for base in [&first.admin_base, &second.admin_base] {
        wait_http_ok(&format!("{base}/health"), Duration::from_secs(20)).await?;
    }
    let admin = Api {
        client: Client::new(),
        base: first.admin_base.clone(),
        token: ADMIN_TOKEN.into(),
    };
    admin
        .json(
            Method::POST,
            "/admin/v1/tenants",
            json!({"id":TENANT,"enabled":true}),
        )
        .await?;
    let token = admin
        .json(
            Method::POST,
            "/admin/v1/tenant-tokens",
            json!({"tenantId":TENANT,"ttlSeconds":3600}),
        )
        .await?;
    let tenant = Api {
        client: Client::new(),
        base: first.admin_base.clone(),
        token: token["token"].as_str().context("token")?.into(),
    };
    set_tenant(&admin, true, "metadata").await?;
    let profile = Uuid::new_v4();
    let config = json!({"id":profile,"tenantId":TENANT,"name":"Audit policy test","enabled":true,"upstreams":[],"dataPlaneAuth":{"mode":"disabled"},"mcp":{"security":{"transportLimits":{"maxPostBodyBytes":128}}}});
    admin
        .json(Method::POST, "/admin/v1/profiles", config)
        .await?;
    let path = format!("/tenant/v1/profiles/{profile}/audit/settings");
    let admin_path = format!("/admin/v1/profiles/{profile}/audit/settings");
    let initial = tenant.json(Method::GET, &path, Value::Null).await?;
    assert_eq!(initial["auditSettings"], json!({}));
    assert_eq!(initial["effectiveLevel"], "metadata");
    assert_eq!(initial["hasUnrecognizedSettings"], false);
    for data in [&first.data_base, &second.data_base] {
        probe_policy(&pool, data, profile, "metadata").await?;
    }

    // API writes invalidate local and already-warm peer caches without waiting for the 30s TTL.
    for level in ["payload", "summary", "off", "metadata"] {
        let after = set_profile(&tenant, &path, json!({"level":level})).await?;
        assert_eq!(after["effectiveLevel"], level);
        probe_policy(&pool, &first.data_base, profile, level).await?;
        // The local async audit flush also gives the PG notification time to reach the peer.
        probe_policy(&pool, &second.data_base, profile, level).await?;
    }
    let control_count: i64 = sqlx::query_scalar("select count(*) from audit_events where profile_id=$1 and action='tenant.profile_audit_settings_put' and meta->'audit_settings'->>'level'='off'").bind(profile).fetch_one(&pool).await?;
    assert_eq!(
        control_count, 1,
        "turning profile activity off must still record the settings change"
    );

    set_profile(&admin, &admin_path, json!({"level":"payload"})).await?;
    for (enabled, default) in [(false, "metadata"), (true, "off"), (true, "summary")] {
        set_tenant(&admin, enabled, default).await?;
        let expected = if !enabled || default == "off" {
            "off"
        } else {
            "payload"
        };
        let settings = tenant.json(Method::GET, &path, Value::Null).await?;
        assert_eq!(settings["effectiveLevel"], expected);
        for data in [&first.data_base, &second.data_base] {
            probe_policy(&pool, data, profile, expected).await?;
        }
    }
    assert_eq!(
        set_profile(&tenant, &path, json!({})).await?["effectiveLevel"],
        "summary"
    );
    for data in [&first.data_base, &second.data_base] {
        probe_policy(&pool, data, profile, "summary").await?;
    }
    set_tenant(&admin, true, "metadata").await?;
    for data in [&first.data_base, &second.data_base] {
        probe_policy(&pool, data, profile, "metadata").await?;
    }
    assert_tool_calls(&admin, &pool, &first.data_base, &second.data_base).await?;
    assert_api_guards(&admin, &tenant, &pool, profile, &path, &admin_path).await?;
    Ok(())
}

async fn assert_api_guards(
    admin: &Api,
    tenant: &Api,
    pool: &PgPool,
    profile: Uuid,
    path: &str,
    admin_path: &str,
) -> anyhow::Result<()> {
    for settings in [
        json!({"level":"verbose"}),
        json!({"retentionDays":1}),
        json!({"enabled":true}),
        json!({"level":"payload","other":true}),
        json!([]),
    ] {
        for (api, path) in [(tenant, path), (admin, admin_path)] {
            assert_eq!(
                api.request(Method::PUT, path, json!({"auditSettings":settings}))
                    .await?
                    .status(),
                StatusCode::BAD_REQUEST
            );
        }
    }
    let before = tenant.json(Method::GET, path, Value::Null).await?;
    let write = json!({"auditSettings":{"level":"summary"},"expectedRevision":before["revision"]});
    let (a, b) = tokio::try_join!(
        tenant.request(Method::PUT, path, write.clone()),
        admin.request(Method::PUT, admin_path, write)
    )?;
    let mut statuses = [a.status().as_u16(), b.status().as_u16()];
    statuses.sort_unstable();
    assert_eq!(statuses, [200, 409]);
    assert_eq!(
        tenant.json(Method::GET, path, Value::Null).await?["revision"].as_i64(),
        before["revision"].as_i64().map(|r| r + 1)
    );

    admin
        .json(
            Method::POST,
            "/admin/v1/tenants",
            json!({"id":"other","enabled":true}),
        )
        .await?;
    let token = admin
        .json(
            Method::POST,
            "/admin/v1/tenant-tokens",
            json!({"tenantId":"other","ttlSeconds":3600}),
        )
        .await?;
    let other = Api {
        client: Client::new(),
        base: tenant.base.clone(),
        token: token["token"].as_str().context("other token")?.into(),
    };
    for method in [Method::GET, Method::PUT] {
        assert_eq!(
            other
                .request(method, path, json!({"auditSettings":{}}))
                .await?
                .status(),
            StatusCode::NOT_FOUND
        );
    }
    // Existing arbitrary JSON remains inert, is reported clearly, and can be replaced explicitly.
    sqlx::query("update profiles set audit_settings=$2, enabled=false where id=$1")
        .bind(profile)
        .bind(json!({"level":"payload","legacy":true}))
        .execute(pool)
        .await?;
    let legacy = tenant.json(Method::GET, path, Value::Null).await?;
    assert_eq!(legacy["hasUnrecognizedSettings"], true);
    assert_eq!(legacy["auditSettings"], json!({}));
    assert_eq!(legacy["effectiveLevel"], "metadata");
    let saved = set_profile(tenant, path, json!({"level":null})).await?;
    assert_eq!(saved["hasUnrecognizedSettings"], false);
    assert_eq!(saved["effectiveLevel"], "metadata");
    sqlx::query("update tenants set enabled=false where id=$1")
        .bind(TENANT)
        .execute(pool)
        .await?;
    for method in [Method::GET, Method::PUT] {
        assert_eq!(
            tenant
                .request(method, path, json!({"auditSettings":{}}))
                .await?
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }
    Ok(())
}

async fn assert_tool_calls(
    admin: &Api,
    pool: &PgPool,
    native_base: &str,
    legacy_base: &str,
) -> anyhow::Result<()> {
    use unrelated_cli::client;
    let remote = journey::RemoteServer::start(None, "audit-tool-response").await?;
    admin.json(Method::POST, "/admin/v1/upstreams", json!({"id":"audit-remote","enabled":true,"endpoints":[{"id":"one","url":remote.url()}]})).await?;
    let profile = Uuid::new_v4();
    admin.json(Method::POST, "/admin/v1/profiles", json!({"id":profile,"tenantId":TENANT,"name":"Tool audit","enabled":true,"upstreams":["audit-remote"],"dataPlaneAuth":{"mode":"disabled"},"mcp":{"modernProtocol":true}})).await?;
    let path = format!("/admin/v1/profiles/{profile}/audit/settings");
    let native = journey::connect(&format!("{native_base}/{profile}/mcp")).await?;
    let catalog = client::fetch_catalog(&native).await?;
    let tool = catalog.find("audit-remote:echo").context("echo tool")?;
    let legacy =
        common::mcp::McpSession::connect(format!("{legacy_base}/{profile}/mcp"), None).await?;
    for level in ["payload", "off", "summary", "metadata"] {
        set_profile(admin, &path, json!({"level":level})).await?;
        for modern in [true, false] {
            let before = latest_event(pool).await?;
            let result = if modern {
                serde_json::to_value(
                    client::call_tool(
                        &native,
                        tool,
                        serde_json::Map::new(),
                        Duration::from_secs(5),
                    )
                    .await?,
                )?
            } else {
                legacy
                    .request_value(1, "tools/call", json!({"name":tool.name,"arguments":{}}))
                    .await?["result"]
                    .clone()
            };
            assert_eq!(result["content"][0]["text"], "audit-tool-response");
            let started = Instant::now();
            loop {
                let row = sqlx::query("select ok, meta, tool_ref from audit_events where id>$1 and profile_id=$2 and action='mcp.tools_call' order by id desc limit 1").bind(before).bind(profile).fetch_optional(pool).await?;
                if let Some(row) = row {
                    assert_ne!(level, "off");
                    assert!(row.try_get::<bool, _>("ok")?);
                    assert_eq!(row.try_get::<String, _>("tool_ref")?, "audit-remote:echo");
                    // Even payload detail does not persist full tool bodies.
                    assert_eq!(row.try_get::<Value, _>("meta")?, json!({}));
                    break;
                }
                if level == "off" && started.elapsed() > Duration::from_secs(1) {
                    break;
                }
                anyhow::ensure!(
                    started.elapsed() < Duration::from_secs(5),
                    "missing tool audit event ({level}, modern={modern})"
                );
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
    native.cancel().await?;
    // Buffered control-plane events must survive a deleted profile foreign key.
    let before = latest_event(pool).await?;
    admin
        .json(
            Method::DELETE,
            &format!("/admin/v1/profiles/{profile}"),
            Value::Null,
        )
        .await?;
    let started = Instant::now();
    loop {
        let row = sqlx::query("select profile_id from audit_events where id>$1 and action='admin.profile_delete' and meta->>'profile_id'=$2").bind(before).bind(profile.to_string()).fetch_optional(pool).await?;
        if let Some(row) = row {
            assert!(row.try_get::<Option<Uuid>, _>("profile_id")?.is_none());
            break;
        }
        anyhow::ensure!(
            started.elapsed() < Duration::from_secs(5),
            "missing profile deletion audit"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    remote.stop().await;
    Ok(())
}
