use unrelated_gateway_api::audit::{ProfileAuditSettings, ProfileAuditSettingsResponse};
mod audit;
mod deployments;
mod identity;
mod profiles;
mod tenants;
mod upstreams;

use crate::pg_invalidation;
use crate::store::{
    AdminProfile, AdminStore, AdminTenant, AdminUpstream, AdminUpstreamEndpoint, ApiKeyAuth,
    ApiKeyMetadata, AuditEventFilter, AuditEventRow, AuditStatsFilter, DataPlaneAuthMode,
    ManagedMcpBackendMode, ManagedMcpDeployable, ManagedMcpDeploymentRequest,
    ManagedMcpDeploymentStatus, OidcPrincipalBinding, Profile, SessionActivityBinding, Store,
    TenantAuditSettings, TenantSecretMetadata, TenantToolSource, ToolCallLimitRejection,
    ToolCallStatsByApiKey, ToolCallStatsByTool, ToolSourceKind, ToolSourceSpec, Upstream,
    UpstreamEndpoint, UpstreamEndpointActivity, UpstreamEndpointLifecycle, UpstreamNetworkClass,
};
use crate::tool_policy::ToolPolicy;
use async_trait::async_trait;
use getrandom::fill as fill_random_bytes;
use parking_lot::RwLock;
use serde_json::Value;
use sqlx::postgres::PgRow;
use sqlx::{PgPool, Postgres, QueryBuilder, Row as _, Transaction};
use std::{collections::HashSet, sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;
use unrelated_tool_transforms::TransformPipeline;
use uuid::Uuid;

use sha2::Digest as _;

const UPSTREAM_SESSION_ACTIVITY_TTL_ENV: &str =
    "UNRELATED_GATEWAY_UPSTREAM_SESSION_ACTIVITY_TTL_SECS";
const DEFAULT_UPSTREAM_SESSION_ACTIVITY_TTL_SECS: u64 = 300;
const UPSTREAM_SESSION_ACTIVITY_CLEANUP_INTERVAL_SECS: u64 = 30;

fn decode_json_opt<T: serde::de::DeserializeOwned>(
    v: Option<Value>,
) -> Result<Option<T>, sqlx::Error> {
    v.map(serde_json::from_value)
        .transpose()
        .map_err(|e| sqlx::Error::Decode(Box::new(e)))
}

#[derive(Clone)]
pub struct PostgresStore {
    pool: PgPool,
    secrets_cipher: std::sync::Arc<crate::secrets_crypto::SecretsCipher>,
    invalidation_publisher: Arc<RwLock<Option<InvalidationPublisher>>>,
}

type InvalidationPublisher =
    Arc<dyn Fn(pg_invalidation::InvalidationEvent) + Send + Sync + 'static>;

#[derive(Debug, Clone)]
struct ProfileAuthCore {
    accept_x_api_key: bool,
    oauth_required_scopes: Vec<String>,
}

#[derive(Debug, Clone)]
struct ProfileLimitsCore {
    rate_limit_enabled: bool,
    quota_enabled: bool,
}

#[derive(Debug, Clone)]
struct ProfileCore {
    id: String,
    tenant_id: String,
    allow_partial_upstreams: bool,
    enabled_tools: Vec<String>,
    transforms: TransformPipeline,
    mcp: crate::store::McpProfileSettings,
    data_plane_auth_mode: DataPlaneAuthMode,
    auth: ProfileAuthCore,
    limits: ProfileLimitsCore,
    rate_limit_tool_calls_per_minute: Option<i64>,
    quota_tool_calls: Option<i64>,
    tool_call_timeout_secs: Option<u64>,
    tool_policies: Vec<ToolPolicy>,
}

#[derive(Debug, Clone)]
struct AdminProfileFlags {
    enabled: bool,
    allow_partial_upstreams: bool,
}

#[derive(Debug, Clone)]
struct AdminProfileAuth {
    accept_x_api_key: bool,
    oauth_required_scopes: Vec<String>,
}

#[derive(Debug, Clone)]
struct AdminProfileLimits {
    rate_limit_enabled: bool,
    quota_enabled: bool,
}

#[derive(Debug, Clone)]
struct AdminProfileRow {
    revision: i64,
    upstream_ids: Vec<String>,
    source_ids: Vec<String>,
    id: String,
    name: String,
    description: Option<String>,
    tenant_id: String,
    flags: AdminProfileFlags,
    enabled_tools: Vec<String>,
    transforms: TransformPipeline,
    mcp: crate::store::McpProfileSettings,
    data_plane_auth_mode: DataPlaneAuthMode,
    auth: AdminProfileAuth,
    limits: AdminProfileLimits,
    rate_limit_tool_calls_per_minute: Option<i64>,
    quota_tool_calls: Option<i64>,
    tool_call_timeout_secs: Option<u64>,
    tool_policies: Vec<ToolPolicy>,
}

struct ProfileUpsertFlags {
    enabled: bool,
    allow_partial_upstreams: bool,
}

struct ProfileUpsertAuth {
    accept_x_api_key: bool,
    oauth_required_scopes: Vec<String>,
}

struct ProfileUpsertLimits {
    rate_limit_enabled: bool,
    quota_enabled: bool,
}

struct ProfileUpsertInput<'a> {
    tenant_id: &'a str,
    name: &'a str,
    description: Option<&'a str>,
    flags: ProfileUpsertFlags,
    enabled_tools: &'a [String],
    transforms: &'a TransformPipeline,
    mcp: &'a crate::store::McpProfileSettings,
    data_plane_auth_mode: DataPlaneAuthMode,
    auth: ProfileUpsertAuth,
    limits: ProfileUpsertLimits,
    rate_limit_tool_calls_per_minute: Option<i32>,
    quota_tool_calls: Option<i64>,
    tool_call_timeout_secs: Option<i32>,
    tool_policies: &'a [ToolPolicy],
}

impl PostgresStore {
    pub fn new(
        pool: PgPool,
        secrets_cipher: std::sync::Arc<crate::secrets_crypto::SecretsCipher>,
    ) -> Self {
        Self {
            pool,
            secrets_cipher,
            invalidation_publisher: Arc::new(RwLock::new(None)),
        }
    }

    pub(crate) fn set_invalidation_publisher(&self, publisher: InvalidationPublisher) {
        *self.invalidation_publisher.write() = Some(publisher);
    }

    fn emit_invalidation_events_best_effort(
        &self,
        events: Vec<pg_invalidation::InvalidationEvent>,
    ) {
        if events.is_empty() {
            return;
        }

        let Some(publish) = self.invalidation_publisher.read().clone() else {
            tracing::warn!(
                "invalidation publisher is not configured; skipping best-effort fanout events"
            );
            return;
        };
        for event in events {
            publish(event);
        }
    }

    async fn ensure_tenant_exists_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        tenant_id: &str,
    ) -> anyhow::Result<()> {
        sqlx::query(
            r"
insert into tenants (id, enabled)
values ($1, true)
on conflict (id) do nothing
",
        )
        .bind(tenant_id)
        .execute(&mut **tx)
        .await?;
        Ok(())
    }

    async fn ensure_api_key_profile_state_exists(
        &self,
        api_key_id: Uuid,
        profile_id: Uuid,
        quota_tool_calls: Option<i64>,
    ) -> anyhow::Result<()> {
        sqlx::query(
            r"
insert into api_key_profile_state (
  api_key_id,
  profile_id,
  rate_window_start,
  rate_window_count,
  quota_remaining
)
values ($1, $2, date_trunc('minute', now()), 0, $3)
on conflict (api_key_id, profile_id) do nothing
",
        )
        .bind(api_key_id)
        .bind(profile_id)
        .bind(quota_tool_calls)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn apply_quota_limit(
        &self,
        api_key_id: Uuid,
        profile_id: Uuid,
        quota_tool_calls: i64,
    ) -> anyhow::Result<Option<ToolCallLimitRejection>> {
        sqlx::query(
            r"
update api_key_profile_state
set quota_remaining = $3,
    updated_at = now()
where api_key_id = $1
  and profile_id = $2
  and quota_remaining is null
",
        )
        .bind(api_key_id)
        .bind(profile_id)
        .bind(quota_tool_calls)
        .execute(&self.pool)
        .await?;

        let ok = sqlx::query(
            r"
update api_key_profile_state
set quota_remaining = quota_remaining - 1,
    updated_at = now()
where api_key_id = $1
  and profile_id = $2
  and quota_remaining > 0
",
        )
        .bind(api_key_id)
        .bind(profile_id)
        .execute(&self.pool)
        .await?
        .rows_affected()
            > 0;

        Ok((!ok).then_some(ToolCallLimitRejection::QuotaExceeded))
    }

    async fn rate_limit_retry_after_secs(&self) -> anyhow::Result<Option<u64>> {
        let retry_after: i64 = sqlx::query_scalar(
            r"
select extract(epoch from (date_trunc('minute', now()) + interval '1 minute' - now()))::bigint
",
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(u64::try_from(retry_after.max(0)).ok())
    }

    async fn apply_rate_limit(
        &self,
        api_key_id: Uuid,
        profile_id: Uuid,
        rate_limit_tool_calls_per_minute: i64,
    ) -> anyhow::Result<Option<ToolCallLimitRejection>> {
        let ok = sqlx::query(
            r"
update api_key_profile_state
set
  rate_window_start = case
    when rate_window_start < date_trunc('minute', now()) then date_trunc('minute', now())
    else rate_window_start
  end,
  rate_window_count = case
    when rate_window_start < date_trunc('minute', now()) then 1
    else rate_window_count + 1
  end,
  updated_at = now()
where api_key_id = $1
  and profile_id = $2
  and (
    case
      when rate_window_start < date_trunc('minute', now()) then 1
      else rate_window_count + 1
    end
  ) <= $3
",
        )
        .bind(api_key_id)
        .bind(profile_id)
        .bind(rate_limit_tool_calls_per_minute)
        .execute(&self.pool)
        .await?
        .rows_affected()
            > 0;

        if ok {
            return Ok(None);
        }

        Ok(Some(ToolCallLimitRejection::RateLimited {
            retry_after_secs: self.rate_limit_retry_after_secs().await?,
        }))
    }

    pub async fn cleanup_expired_upstream_session_activity(
        &self,
        ttl_secs: u64,
    ) -> anyhow::Result<u64> {
        let ttl_secs = i64::try_from(ttl_secs).unwrap_or(i64::MAX);
        let res = sqlx::query(
            r"
delete from upstream_session_activity
where last_seen_at < now() - make_interval(secs => $1)
",
        )
        .bind(ttl_secs)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }
}

pub fn upstream_session_activity_ttl_secs_from_env() -> u64 {
    std::env::var(UPSTREAM_SESSION_ACTIVITY_TTL_ENV)
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(DEFAULT_UPSTREAM_SESSION_ACTIVITY_TTL_SECS)
        .max(1)
}

pub fn resolve_upstream_session_activity_ttl_secs(request_ttl: Option<u64>) -> u64 {
    request_ttl
        .unwrap_or_else(upstream_session_activity_ttl_secs_from_env)
        .max(1)
}

pub fn spawn_upstream_session_activity_cleanup_task(
    store: Arc<PostgresStore>,
    shutdown: CancellationToken,
    ttl_secs: u64,
) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(
            UPSTREAM_SESSION_ACTIVITY_CLEANUP_INTERVAL_SECS,
        ));
        loop {
            tokio::select! {
                () = shutdown.cancelled() => break,
                _ = interval.tick() => {
                    if let Err(err) = store.cleanup_expired_upstream_session_activity(ttl_secs).await {
                        tracing::warn!(error = %err, "upstream session activity cleanup failed");
                    }
                }
            }
        }
    });
}

#[async_trait]
impl Store for PostgresStore {
    async fn get_profile(&self, profile_id: &str) -> anyhow::Result<Option<Profile>> {
        self.data_get_profile(profile_id).await
    }

    async fn get_upstream(&self, upstream_id: &str) -> anyhow::Result<Option<Upstream>> {
        self.data_get_upstream(upstream_id).await
    }

    async fn record_session_activity(
        &self,
        tenant_id: &str,
        profile_id: &str,
        session_hash: &str,
        bindings: &[SessionActivityBinding],
    ) -> anyhow::Result<()> {
        self.data_record_session_activity(tenant_id, profile_id, session_hash, bindings)
            .await
    }

    async fn get_tenant_tool_source(
        &self,
        tenant_id: &str,
        source_id: &str,
    ) -> anyhow::Result<Option<TenantToolSource>> {
        self.data_get_tenant_tool_source(tenant_id, source_id).await
    }

    async fn tenant_tool_source_ids(
        &self,
        tenant_id: &str,
        ids: &[String],
    ) -> anyhow::Result<HashSet<String>> {
        self.data_tenant_tool_source_ids(tenant_id, ids).await
    }

    async fn get_tenant_secret_value(
        &self,
        tenant_id: &str,
        name: &str,
    ) -> anyhow::Result<Option<String>> {
        self.data_get_tenant_secret_value(tenant_id, name).await
    }

    async fn get_tenant_transport_limits(
        &self,
        tenant_id: &str,
    ) -> anyhow::Result<Option<crate::store::TransportLimitsSettings>> {
        self.data_get_tenant_transport_limits(tenant_id).await
    }

    async fn authenticate_api_key(
        &self,
        tenant_id: &str,
        profile_id: &str,
        secret: &str,
    ) -> anyhow::Result<Option<ApiKeyAuth>> {
        self.data_authenticate_api_key(tenant_id, profile_id, secret)
            .await
    }

    async fn is_api_key_active(&self, tenant_id: &str, api_key_id: &str) -> anyhow::Result<bool> {
        self.data_is_api_key_active(tenant_id, api_key_id).await
    }

    async fn touch_api_key(&self, tenant_id: &str, api_key_id: &str) -> anyhow::Result<()> {
        self.data_touch_api_key(tenant_id, api_key_id).await
    }

    async fn record_tool_call_attempt(
        &self,
        tenant_id: &str,
        api_key_id: &str,
    ) -> anyhow::Result<()> {
        self.data_record_tool_call_attempt(tenant_id, api_key_id)
            .await
    }

    async fn check_and_apply_tool_call_limits(
        &self,
        _tenant_id: &str,
        profile_id: &str,
        api_key_id: &str,
        rate_limit_tool_calls_per_minute: Option<i64>,
        quota_tool_calls: Option<i64>,
    ) -> anyhow::Result<Option<ToolCallLimitRejection>> {
        self.data_check_and_apply_tool_call_limits(
            _tenant_id,
            profile_id,
            api_key_id,
            rate_limit_tool_calls_per_minute,
            quota_tool_calls,
        )
        .await
    }

    async fn is_oidc_principal_allowed(
        &self,
        tenant_id: &str,
        profile_id: &str,
        issuer: &str,
        subject: &str,
    ) -> anyhow::Result<bool> {
        self.data_is_oidc_principal_allowed(tenant_id, profile_id, issuer, subject)
            .await
    }
}

#[async_trait]
impl AdminStore for PostgresStore {
    async fn list_tenants(&self) -> anyhow::Result<Vec<AdminTenant>> {
        self.admin_list_tenants().await
    }

    async fn get_tenant(&self, tenant_id: &str) -> anyhow::Result<Option<AdminTenant>> {
        self.admin_get_tenant(tenant_id).await
    }

    async fn delete_tenant(&self, tenant_id: &str) -> anyhow::Result<bool> {
        self.admin_delete_tenant(tenant_id).await
    }

    async fn put_tenant(&self, tenant_id: &str, enabled: bool) -> anyhow::Result<()> {
        self.admin_put_tenant(tenant_id, enabled).await
    }

    async fn list_upstreams(&self) -> anyhow::Result<Vec<AdminUpstream>> {
        self.admin_list_upstreams().await
    }

    async fn get_upstream(&self, upstream_id: &str) -> anyhow::Result<Option<AdminUpstream>> {
        self.admin_get_upstream(upstream_id).await
    }

    async fn delete_upstream(&self, upstream_id: &str) -> anyhow::Result<bool> {
        self.admin_delete_upstream(upstream_id).await
    }

    async fn put_upstream(
        &self,
        upstream_id: &str,
        enabled: bool,
        network_class: UpstreamNetworkClass,
        endpoints: &[UpstreamEndpoint],
    ) -> anyhow::Result<()> {
        self.admin_put_upstream(upstream_id, enabled, network_class, endpoints)
            .await
    }

    async fn patch_upstream_endpoint(
        &self,
        upstream_id: &str,
        endpoint_id: &str,
        enabled: Option<bool>,
        lifecycle: Option<UpstreamEndpointLifecycle>,
    ) -> anyhow::Result<bool> {
        self.admin_patch_upstream_endpoint(upstream_id, endpoint_id, enabled, lifecycle)
            .await
    }

    async fn delete_upstream_endpoint(
        &self,
        upstream_id: &str,
        endpoint_id: &str,
    ) -> anyhow::Result<bool> {
        self.admin_delete_upstream_endpoint(upstream_id, endpoint_id)
            .await
    }

    async fn list_upstream_endpoint_activity(
        &self,
        upstream_id: &str,
        ttl_secs: u64,
    ) -> anyhow::Result<Vec<UpstreamEndpointActivity>> {
        self.admin_list_upstream_endpoint_activity(upstream_id, ttl_secs)
            .await
    }

    async fn list_profiles(&self) -> anyhow::Result<Vec<AdminProfile>> {
        self.admin_list_profiles().await
    }

    async fn get_profile(&self, profile_id: &str) -> anyhow::Result<Option<AdminProfile>> {
        self.admin_get_profile(profile_id).await
    }

    async fn delete_profile(&self, profile_id: &str) -> anyhow::Result<bool> {
        self.admin_delete_profile(profile_id).await
    }

    async fn put_profile(&self, input: crate::store::PutProfileInput<'_>) -> anyhow::Result<()> {
        self.admin_put_profile(input).await
    }

    async fn list_tool_sources(&self, tenant_id: &str) -> anyhow::Result<Vec<TenantToolSource>> {
        self.admin_list_tool_sources(tenant_id).await
    }

    async fn get_tool_source(
        &self,
        tenant_id: &str,
        source_id: &str,
    ) -> anyhow::Result<Option<TenantToolSource>> {
        self.admin_get_tool_source(tenant_id, source_id).await
    }

    async fn put_tool_source(
        &self,
        tenant_id: &str,
        source_id: &str,
        enabled: bool,
        kind: ToolSourceKind,
        spec: Value,
        expected_revision: Option<i64>,
    ) -> anyhow::Result<()> {
        self.admin_put_tool_source(tenant_id, source_id, enabled, kind, spec, expected_revision)
            .await
    }

    async fn delete_tool_source(&self, tenant_id: &str, source_id: &str) -> anyhow::Result<bool> {
        self.admin_delete_tool_source(tenant_id, source_id).await
    }

    async fn list_secrets(&self, tenant_id: &str) -> anyhow::Result<Vec<TenantSecretMetadata>> {
        self.admin_list_secrets(tenant_id).await
    }

    async fn put_secret(&self, tenant_id: &str, name: &str, value: &str) -> anyhow::Result<()> {
        self.admin_put_secret(tenant_id, name, value).await
    }

    async fn delete_secret(&self, tenant_id: &str, name: &str) -> anyhow::Result<bool> {
        self.admin_delete_secret(tenant_id, name).await
    }

    async fn list_api_keys(&self, tenant_id: &str) -> anyhow::Result<Vec<ApiKeyMetadata>> {
        self.admin_list_api_keys(tenant_id).await
    }

    async fn put_api_key(
        &self,
        tenant_id: &str,
        api_key_id: &str,
        profile_id: Option<&str>,
        name: &str,
        prefix: &str,
        secret_hash: &str,
    ) -> anyhow::Result<()> {
        self.admin_put_api_key(tenant_id, api_key_id, profile_id, name, prefix, secret_hash)
            .await
    }

    async fn revoke_api_key(&self, tenant_id: &str, api_key_id: &str) -> anyhow::Result<bool> {
        self.admin_revoke_api_key(tenant_id, api_key_id).await
    }

    async fn list_oidc_principals(
        &self,
        tenant_id: &str,
        issuer: &str,
    ) -> anyhow::Result<Vec<OidcPrincipalBinding>> {
        self.admin_list_oidc_principals(tenant_id, issuer).await
    }

    async fn put_oidc_principal(
        &self,
        tenant_id: &str,
        issuer: &str,
        subject: &str,
        profile_id: Option<&str>,
        enabled: bool,
    ) -> anyhow::Result<()> {
        self.admin_put_oidc_principal(tenant_id, issuer, subject, profile_id, enabled)
            .await
    }

    async fn delete_oidc_principal(
        &self,
        tenant_id: &str,
        issuer: &str,
        subject: &str,
        profile_id: Option<&str>,
    ) -> anyhow::Result<u64> {
        self.admin_delete_oidc_principal(tenant_id, issuer, subject, profile_id)
            .await
    }

    async fn get_tenant_transport_limits(
        &self,
        tenant_id: &str,
    ) -> anyhow::Result<Option<crate::store::TransportLimitsSettings>> {
        self.admin_get_tenant_transport_limits(tenant_id).await
    }

    async fn put_tenant_transport_limits(
        &self,
        tenant_id: &str,
        limits: &crate::store::TransportLimitsSettings,
    ) -> anyhow::Result<()> {
        self.admin_put_tenant_transport_limits(tenant_id, limits)
            .await
    }

    async fn get_tenant_audit_settings(
        &self,
        tenant_id: &str,
    ) -> anyhow::Result<Option<TenantAuditSettings>> {
        self.admin_get_tenant_audit_settings(tenant_id).await
    }

    async fn put_tenant_audit_settings(
        &self,
        tenant_id: &str,
        settings: &TenantAuditSettings,
    ) -> anyhow::Result<()> {
        self.admin_put_tenant_audit_settings(tenant_id, settings)
            .await
    }

    async fn get_profile_audit_settings(
        &self,
        tenant_id: &str,
        profile_id: &str,
    ) -> anyhow::Result<Option<ProfileAuditSettingsResponse>> {
        self.admin_get_profile_audit_settings(tenant_id, profile_id)
            .await
    }

    async fn put_profile_audit_settings(
        &self,
        tenant_id: &str,
        profile_id: &str,
        audit_settings: ProfileAuditSettings,
        expected_revision: Option<i64>,
    ) -> anyhow::Result<()> {
        self.admin_put_profile_audit_settings(
            tenant_id,
            profile_id,
            audit_settings,
            expected_revision,
        )
        .await
    }

    async fn list_audit_events(
        &self,
        tenant_id: &str,
        filter: AuditEventFilter,
    ) -> anyhow::Result<Vec<AuditEventRow>> {
        self.admin_list_audit_events(tenant_id, filter).await
    }

    async fn tool_call_stats_by_tool(
        &self,
        tenant_id: &str,
        filter: AuditStatsFilter,
    ) -> anyhow::Result<Vec<ToolCallStatsByTool>> {
        self.admin_tool_call_stats_by_tool(tenant_id, filter).await
    }

    async fn tool_call_stats_by_api_key(
        &self,
        tenant_id: &str,
        filter: AuditStatsFilter,
    ) -> anyhow::Result<Vec<ToolCallStatsByApiKey>> {
        self.admin_tool_call_stats_by_api_key(tenant_id, filter)
            .await
    }

    async fn list_managed_mcp_deployables(&self) -> anyhow::Result<Vec<ManagedMcpDeployable>> {
        self.admin_list_managed_mcp_deployables().await
    }

    async fn upsert_managed_mcp_deployable(
        &self,
        deployable: &ManagedMcpDeployable,
    ) -> anyhow::Result<()> {
        self.admin_upsert_managed_mcp_deployable(deployable).await
    }

    async fn create_managed_mcp_deployment_request(
        &self,
        tenant_id: &str,
        deployable_id: &str,
    ) -> anyhow::Result<ManagedMcpDeploymentRequest> {
        self.admin_create_managed_mcp_deployment_request(tenant_id, deployable_id)
            .await
    }

    async fn get_managed_mcp_deployment_request(
        &self,
        request_id: &str,
    ) -> anyhow::Result<Option<ManagedMcpDeploymentRequest>> {
        self.admin_get_managed_mcp_deployment_request(request_id)
            .await
    }

    async fn get_managed_mcp_deployment_request_for_tenant(
        &self,
        tenant_id: &str,
        request_id: &str,
    ) -> anyhow::Result<Option<ManagedMcpDeploymentRequest>> {
        self.admin_get_managed_mcp_deployment_request_for_tenant(tenant_id, request_id)
            .await
    }

    async fn list_managed_mcp_deployment_requests(
        &self,
        statuses: &[ManagedMcpDeploymentStatus],
        limit: u32,
    ) -> anyhow::Result<Vec<ManagedMcpDeploymentRequest>> {
        self.admin_list_managed_mcp_deployment_requests(statuses, limit)
            .await
    }

    async fn list_managed_mcp_deployment_requests_for_tenant(
        &self,
        tenant_id: &str,
        limit: u32,
    ) -> anyhow::Result<Vec<ManagedMcpDeploymentRequest>> {
        self.admin_list_managed_mcp_deployment_requests_for_tenant(tenant_id, limit)
            .await
    }

    async fn update_managed_mcp_deployment_request_for_tenant(
        &self,
        tenant_id: &str,
        request_id: &str,
        desired_enabled: bool,
        desired_replicas: i32,
    ) -> anyhow::Result<Option<ManagedMcpDeploymentRequest>> {
        self.admin_update_managed_mcp_deployment_request_for_tenant(
            tenant_id,
            request_id,
            desired_enabled,
            desired_replicas,
        )
        .await
    }

    async fn mark_managed_mcp_deployment_status(
        &self,
        request_id: &str,
        status: ManagedMcpDeploymentStatus,
        upstream_id: Option<&str>,
        message: Option<&str>,
    ) -> anyhow::Result<bool> {
        self.admin_mark_managed_mcp_deployment_status(request_id, status, upstream_id, message)
            .await
    }

    async fn upsert_managed_mcp_reconciler_heartbeat(
        &self,
        backend_mode: ManagedMcpBackendMode,
        reconciler_id: &str,
    ) -> anyhow::Result<()> {
        self.admin_upsert_managed_mcp_reconciler_heartbeat(backend_mode, reconciler_id)
            .await
    }

    async fn latest_managed_mcp_reconciler_heartbeat_unix(
        &self,
        backend_mode: ManagedMcpBackendMode,
    ) -> anyhow::Result<Option<i64>> {
        self.admin_latest_managed_mcp_reconciler_heartbeat_unix(backend_mode)
            .await
    }

    async fn fail_stale_managed_mcp_deployment_requests(
        &self,
        statuses: &[ManagedMcpDeploymentStatus],
        stale_after_secs: u64,
        message: &str,
    ) -> anyhow::Result<u64> {
        self.admin_fail_stale_managed_mcp_deployment_requests(statuses, stale_after_secs, message)
            .await
    }

    async fn cleanup_audit_events_for_tenant(&self, tenant_id: &str) -> anyhow::Result<u64> {
        self.admin_cleanup_audit_events_for_tenant(tenant_id).await
    }
}

fn parse_data_plane_auth_mode(mode: &str) -> anyhow::Result<DataPlaneAuthMode> {
    match mode {
        "disabled" => Ok(DataPlaneAuthMode::Disabled),
        "api_key" => Ok(DataPlaneAuthMode::ApiKey),
        "oauth" => Ok(DataPlaneAuthMode::OAuth),
        other => Err(anyhow::anyhow!("unknown data_plane_auth_mode '{other}'")),
    }
}

const fn data_plane_auth_mode_to_db(mode: DataPlaneAuthMode) -> &'static str {
    match mode {
        DataPlaneAuthMode::Disabled => "disabled",
        DataPlaneAuthMode::ApiKey => "api_key",
        DataPlaneAuthMode::OAuth => "oauth",
    }
}

fn parse_upstream_endpoint_lifecycle(value: &str) -> anyhow::Result<UpstreamEndpointLifecycle> {
    match value {
        "active" => Ok(UpstreamEndpointLifecycle::Active),
        "draining" => Ok(UpstreamEndpointLifecycle::Draining),
        "disabled" => Ok(UpstreamEndpointLifecycle::Disabled),
        other => Err(anyhow::anyhow!(
            "unknown upstream endpoint lifecycle '{other}'"
        )),
    }
}

const fn upstream_endpoint_lifecycle_to_db(value: UpstreamEndpointLifecycle) -> &'static str {
    match value {
        UpstreamEndpointLifecycle::Active => "active",
        UpstreamEndpointLifecycle::Draining => "draining",
        UpstreamEndpointLifecycle::Disabled => "disabled",
    }
}

fn parse_upstream_network_class(value: &str) -> anyhow::Result<UpstreamNetworkClass> {
    match value {
        "external" => Ok(UpstreamNetworkClass::External),
        "cluster-internal-managed" => Ok(UpstreamNetworkClass::ClusterInternalManaged),
        other => Err(anyhow::anyhow!("unknown upstream network class '{other}'")),
    }
}

const fn upstream_network_class_to_db(value: UpstreamNetworkClass) -> &'static str {
    match value {
        UpstreamNetworkClass::External => "external",
        UpstreamNetworkClass::ClusterInternalManaged => "cluster-internal-managed",
    }
}

fn parse_managed_mcp_deployment_status(value: &str) -> anyhow::Result<ManagedMcpDeploymentStatus> {
    ManagedMcpDeploymentStatus::parse(value)
        .ok_or_else(|| anyhow::anyhow!("unknown managed MCP deployment status '{value}'"))
}

const fn managed_mcp_deployment_status_to_db(value: ManagedMcpDeploymentStatus) -> &'static str {
    value.as_str()
}

const fn managed_mcp_backend_mode_to_db(value: ManagedMcpBackendMode) -> &'static str {
    value.as_str()
}

fn parse_managed_mcp_deployment_request_row(
    row: &PgRow,
) -> anyhow::Result<ManagedMcpDeploymentRequest> {
    let status_raw: String = row.try_get("status")?;
    Ok(ManagedMcpDeploymentRequest {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        deployable_id: row.try_get("deployable_id")?,
        desired_enabled: row.try_get("desired_enabled")?,
        desired_replicas: row.try_get("desired_replicas")?,
        status: parse_managed_mcp_deployment_status(&status_raw)?,
        upstream_id: row.try_get("upstream_id")?,
        message: row.try_get("message")?,
        created_at_unix: row.try_get("created_at_unix")?,
        updated_at_unix: row.try_get("updated_at_unix")?,
    })
}

fn hash_api_key_secret(secret: &str) -> String {
    hex::encode(sha2::Sha256::digest(secret.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn managed_mcp_deployment_status_db_roundtrip_uses_canonical_strings() {
        let statuses = [
            ManagedMcpDeploymentStatus::Pending,
            ManagedMcpDeploymentStatus::Reconciling,
            ManagedMcpDeploymentStatus::Ready,
            ManagedMcpDeploymentStatus::Failed,
        ];
        for status in statuses {
            let db = managed_mcp_deployment_status_to_db(status);
            let parsed = parse_managed_mcp_deployment_status(db).expect("parse db status");
            assert_eq!(parsed, status);
            assert_eq!(db, status.as_str());
        }
    }

    #[test]
    fn managed_mcp_backend_mode_db_strings_match_store_enum() {
        assert_eq!(
            managed_mcp_backend_mode_to_db(ManagedMcpBackendMode::None),
            ManagedMcpBackendMode::None.as_str()
        );
        assert_eq!(
            managed_mcp_backend_mode_to_db(ManagedMcpBackendMode::K8s),
            ManagedMcpBackendMode::K8s.as_str()
        );
        assert_eq!(
            managed_mcp_backend_mode_to_db(ManagedMcpBackendMode::Docker),
            ManagedMcpBackendMode::Docker.as_str()
        );
    }
}
