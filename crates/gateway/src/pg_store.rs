use crate::pg_invalidation;
use crate::store::{
    AdminProfile, AdminStore, AdminTenant, AdminUpstream, AdminUpstreamEndpoint, ApiKeyAuth,
    ApiKeyMetadata, AuditEventFilter, AuditEventRow, AuditStatsFilter, DataPlaneAuthMode,
    OidcPrincipalBinding, Profile, Store, TenantAuditSettings, TenantSecretMetadata,
    TenantToolSource, ToolCallLimitRejection, ToolCallStatsByApiKey, ToolCallStatsByTool,
    ToolSourceKind, ToolSourceSpec, Upstream, UpstreamEndpoint,
};
use crate::tool_policy::ToolPolicy;
use async_trait::async_trait;
use rand_core::{OsRng, TryRngCore as _};
use serde_json::Value;
use sqlx::postgres::PgRow;
use sqlx::{PgPool, Postgres, Row as _, Transaction};
use unrelated_tool_transforms::TransformPipeline;
use uuid::Uuid;

use sha2::Digest as _;

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
}

#[derive(Debug, Clone)]
struct ProfileAuthCore {
    accept_x_api_key: bool,
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
}

#[derive(Debug, Clone)]
struct AdminProfileLimits {
    rate_limit_enabled: bool,
    quota_enabled: bool,
}

#[derive(Debug, Clone)]
struct AdminProfileRow {
    id_uuid: Uuid,
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
        }
    }

    async fn fetch_enabled_profile_row(&self, profile_id: Uuid) -> anyhow::Result<Option<PgRow>> {
        sqlx::query(
            r"
select
  p.id,
  p.name,
  p.description,
  p.tenant_id,
  p.allow_partial_upstreams,
  p.enabled_tools,
  p.transforms,
  p.mcp_settings,
  p.data_plane_auth_mode,
  p.accept_x_api_key,
  p.rate_limit_enabled,
  p.rate_limit_tool_calls_per_minute,
  p.quota_enabled,
  p.quota_tool_calls,
  p.tool_call_timeout_secs,
  p.tool_policies
from profiles p
join tenants t on t.id = p.tenant_id
where p.id = $1
  and p.enabled = true
  and t.enabled = true
",
        )
        .bind(profile_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(Into::into)
    }

    fn parse_profile_core(row: &PgRow) -> anyhow::Result<ProfileCore> {
        let id: Uuid = row.try_get("id")?;
        let tenant_id: String = row.try_get("tenant_id")?;
        let allow_partial_upstreams: bool = row.try_get("allow_partial_upstreams")?;
        let enabled_tools: Vec<String> = row.try_get("enabled_tools")?;

        let transforms: Value = row.try_get("transforms")?;
        let transforms: TransformPipeline = serde_json::from_value(transforms)?;

        let mcp_settings: Value = row.try_get("mcp_settings")?;
        let mcp: crate::store::McpProfileSettings = serde_json::from_value(mcp_settings)?;

        let data_plane_auth_mode: String = row.try_get("data_plane_auth_mode")?;
        let data_plane_auth_mode = parse_data_plane_auth_mode(&data_plane_auth_mode)?;

        let accept_x_api_key: bool = row.try_get("accept_x_api_key")?;
        let rate_limit_enabled: bool = row.try_get("rate_limit_enabled")?;
        let rate_limit_tool_calls_per_minute: Option<i32> =
            row.try_get("rate_limit_tool_calls_per_minute")?;
        let rate_limit_tool_calls_per_minute = rate_limit_tool_calls_per_minute.map(i64::from);
        let quota_enabled: bool = row.try_get("quota_enabled")?;
        let quota_tool_calls: Option<i64> = row.try_get("quota_tool_calls")?;

        let tool_call_timeout_secs: Option<i32> = row.try_get("tool_call_timeout_secs")?;
        let tool_call_timeout_secs: Option<u64> = tool_call_timeout_secs
            .and_then(|v| u64::try_from(v).ok())
            .filter(|v| *v > 0);

        let tool_policies: Value = row.try_get("tool_policies")?;
        let tool_policies: Vec<ToolPolicy> = serde_json::from_value(tool_policies)?;

        Ok(ProfileCore {
            id: id.to_string(),
            tenant_id,
            allow_partial_upstreams,
            enabled_tools,
            transforms,
            mcp,
            data_plane_auth_mode,
            auth: ProfileAuthCore { accept_x_api_key },
            limits: ProfileLimitsCore {
                rate_limit_enabled,
                quota_enabled,
            },
            rate_limit_tool_calls_per_minute,
            quota_tool_calls,
            tool_call_timeout_secs,
            tool_policies,
        })
    }

    async fn load_profile_source_ids(&self, profile_id: Uuid) -> anyhow::Result<Vec<String>> {
        let upstream_rows = sqlx::query(
            r"
select pu.upstream_id
from profile_upstreams pu
join upstreams u on u.id = pu.upstream_id
where pu.profile_id = $1
  and u.enabled = true
order by pu.ordinal asc, pu.upstream_id asc
",
        )
        .bind(profile_id)
        .fetch_all(&self.pool)
        .await?;

        let upstream_ids = upstream_rows
            .into_iter()
            .map(|r| r.try_get::<String, _>("upstream_id"))
            .collect::<Result<Vec<_>, _>>()?;

        let source_rows = sqlx::query(
            r"
select source_id
from profile_sources
where profile_id = $1
order by ordinal asc, source_id asc
",
        )
        .bind(profile_id)
        .fetch_all(&self.pool)
        .await?;

        let source_ids = source_rows
            .into_iter()
            .map(|r| r.try_get::<String, _>("source_id"))
            .collect::<Result<Vec<_>, _>>()?;

        let mut all_ids = upstream_ids;
        let mut seen: std::collections::HashSet<String> = all_ids.iter().cloned().collect();
        for sid in source_ids {
            if seen.insert(sid.clone()) {
                all_ids.push(sid);
            }
        }
        Ok(all_ids)
    }

    async fn fetch_admin_profile_row(&self, profile_id: Uuid) -> anyhow::Result<Option<PgRow>> {
        sqlx::query(
            r"
select
  id,
  tenant_id,
  name,
  description,
  enabled,
  allow_partial_upstreams,
  enabled_tools,
  transforms,
  mcp_settings,
  data_plane_auth_mode,
  accept_x_api_key,
  rate_limit_enabled,
  rate_limit_tool_calls_per_minute,
  quota_enabled,
  quota_tool_calls,
  tool_call_timeout_secs,
  tool_policies
from profiles
where id = $1
",
        )
        .bind(profile_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(Into::into)
    }

    fn parse_admin_profile_row(row: &PgRow) -> anyhow::Result<AdminProfileRow> {
        let id: Uuid = row.try_get("id")?;
        let name: String = row.try_get("name")?;
        let description: Option<String> = row.try_get("description")?;
        let tenant_id: String = row.try_get("tenant_id")?;
        let enabled: bool = row.try_get("enabled")?;
        let allow_partial_upstreams: bool = row.try_get("allow_partial_upstreams")?;
        let enabled_tools: Vec<String> = row.try_get("enabled_tools")?;

        let transforms: Value = row.try_get("transforms")?;
        let transforms: TransformPipeline = serde_json::from_value(transforms)?;

        let mcp_settings: Value = row.try_get("mcp_settings")?;
        let mcp: crate::store::McpProfileSettings = serde_json::from_value(mcp_settings)?;

        let data_plane_auth_mode: String = row.try_get("data_plane_auth_mode")?;
        let data_plane_auth_mode = parse_data_plane_auth_mode(&data_plane_auth_mode)?;

        let accept_x_api_key: bool = row.try_get("accept_x_api_key")?;
        let rate_limit_enabled: bool = row.try_get("rate_limit_enabled")?;
        let rate_limit_tool_calls_per_minute: Option<i32> =
            row.try_get("rate_limit_tool_calls_per_minute")?;
        let rate_limit_tool_calls_per_minute = rate_limit_tool_calls_per_minute.map(i64::from);
        let quota_enabled: bool = row.try_get("quota_enabled")?;
        let quota_tool_calls: Option<i64> = row.try_get("quota_tool_calls")?;

        let tool_call_timeout_secs: Option<i32> = row.try_get("tool_call_timeout_secs")?;
        let tool_call_timeout_secs: Option<u64> = tool_call_timeout_secs
            .and_then(|v| u64::try_from(v).ok())
            .filter(|v| *v > 0);

        let tool_policies: Value = row.try_get("tool_policies")?;
        let tool_policies: Vec<ToolPolicy> = serde_json::from_value(tool_policies)?;

        Ok(AdminProfileRow {
            id_uuid: id,
            id: id.to_string(),
            name,
            description,
            tenant_id,
            flags: AdminProfileFlags {
                enabled,
                allow_partial_upstreams,
            },
            enabled_tools,
            transforms,
            mcp,
            data_plane_auth_mode,
            auth: AdminProfileAuth { accept_x_api_key },
            limits: AdminProfileLimits {
                rate_limit_enabled,
                quota_enabled,
            },
            rate_limit_tool_calls_per_minute,
            quota_tool_calls,
            tool_call_timeout_secs,
            tool_policies,
        })
    }

    async fn load_admin_profile_upstream_ids(
        &self,
        profile_id: Uuid,
    ) -> anyhow::Result<Vec<String>> {
        let rows = sqlx::query(
            r"
select upstream_id
from profile_upstreams
where profile_id = $1
order by ordinal asc, upstream_id asc
",
        )
        .bind(profile_id)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|r| r.try_get::<String, _>("upstream_id"))
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    async fn load_admin_profile_source_ids(&self, profile_id: Uuid) -> anyhow::Result<Vec<String>> {
        let rows = sqlx::query(
            r"
select source_id
from profile_sources
where profile_id = $1
order by ordinal asc, source_id asc
",
        )
        .bind(profile_id)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|r| r.try_get::<String, _>("source_id"))
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
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

    async fn upsert_profile_row_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        profile_id: Uuid,
        input: ProfileUpsertInput<'_>,
    ) -> anyhow::Result<()> {
        sqlx::query(
            r"
insert into profiles (
  id,
  tenant_id,
  name,
  description,
  enabled,
  allow_partial_upstreams,
  enabled_tools,
  transforms,
  mcp_settings,
  data_plane_auth_mode,
  accept_x_api_key,
  rate_limit_enabled,
  rate_limit_tool_calls_per_minute,
  quota_enabled,
  quota_tool_calls,
  tool_call_timeout_secs,
  tool_policies
)
values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
on conflict (id) do update
set tenant_id = excluded.tenant_id,
    name = excluded.name,
    description = excluded.description,
    enabled = excluded.enabled,
    allow_partial_upstreams = excluded.allow_partial_upstreams,
    enabled_tools = excluded.enabled_tools,
    transforms = excluded.transforms,
    mcp_settings = excluded.mcp_settings,
    data_plane_auth_mode = excluded.data_plane_auth_mode,
    accept_x_api_key = excluded.accept_x_api_key,
    rate_limit_enabled = excluded.rate_limit_enabled,
    rate_limit_tool_calls_per_minute = excluded.rate_limit_tool_calls_per_minute,
    quota_enabled = excluded.quota_enabled,
    quota_tool_calls = excluded.quota_tool_calls,
    tool_call_timeout_secs = excluded.tool_call_timeout_secs,
    tool_policies = excluded.tool_policies,
    updated_at = now()
",
        )
        .bind(profile_id)
        .bind(input.tenant_id)
        .bind(input.name)
        .bind(input.description)
        .bind(input.flags.enabled)
        .bind(input.flags.allow_partial_upstreams)
        .bind(input.enabled_tools)
        .bind(serde_json::to_value(input.transforms)?)
        .bind(serde_json::to_value(input.mcp)?)
        .bind(data_plane_auth_mode_to_db(input.data_plane_auth_mode))
        .bind(input.auth.accept_x_api_key)
        .bind(input.limits.rate_limit_enabled)
        .bind(input.rate_limit_tool_calls_per_minute)
        .bind(input.limits.quota_enabled)
        .bind(input.quota_tool_calls)
        .bind(input.tool_call_timeout_secs)
        .bind(serde_json::to_value(input.tool_policies)?)
        .execute(&mut **tx)
        .await?;
        Ok(())
    }

    async fn replace_profile_upstreams_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        profile_id: Uuid,
        upstream_ids: &[String],
    ) -> anyhow::Result<()> {
        sqlx::query(r"delete from profile_upstreams where profile_id = $1")
            .bind(profile_id)
            .execute(&mut **tx)
            .await?;

        for (ordinal, upstream_id) in upstream_ids.iter().enumerate() {
            let ordinal: i32 = i32::try_from(ordinal)
                .map_err(|_| anyhow::anyhow!("too many upstreams in profile (ordinal overflow)"))?;

            // Ensure upstream exists (upsert disabled=false).
            sqlx::query(
                r"
insert into upstreams (id, enabled)
values ($1, true)
on conflict (id) do nothing
",
            )
            .bind(upstream_id)
            .execute(&mut **tx)
            .await?;

            sqlx::query(
                r"
insert into profile_upstreams (profile_id, upstream_id, ordinal)
values ($1, $2, $3)
on conflict (profile_id, upstream_id) do update
set ordinal = excluded.ordinal
",
            )
            .bind(profile_id)
            .bind(upstream_id)
            .bind(ordinal)
            .execute(&mut **tx)
            .await?;
        }

        Ok(())
    }

    async fn replace_profile_sources_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        profile_id: Uuid,
        source_ids: &[String],
    ) -> anyhow::Result<()> {
        sqlx::query(r"delete from profile_sources where profile_id = $1")
            .bind(profile_id)
            .execute(&mut **tx)
            .await?;

        for (ordinal, source_id) in source_ids.iter().enumerate() {
            let ordinal: i32 = i32::try_from(ordinal)
                .map_err(|_| anyhow::anyhow!("too many sources in profile (ordinal overflow)"))?;
            sqlx::query(
                r"
insert into profile_sources (profile_id, source_id, ordinal)
values ($1, $2, $3)
on conflict (profile_id, source_id) do update
set ordinal = excluded.ordinal
",
            )
            .bind(profile_id)
            .bind(source_id)
            .bind(ordinal)
            .execute(&mut **tx)
            .await?;
        }

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
}

#[async_trait]
impl Store for PostgresStore {
    async fn get_profile(&self, profile_id: &str) -> anyhow::Result<Option<Profile>> {
        let Ok(profile_id) = Uuid::parse_str(profile_id) else {
            return Ok(None);
        };

        let Some(row) = self.fetch_enabled_profile_row(profile_id).await? else {
            return Ok(None);
        };

        let core = Self::parse_profile_core(&row)?;
        let all_ids = self.load_profile_source_ids(profile_id).await?;

        Ok(Some(Profile {
            id: core.id,
            tenant_id: core.tenant_id,
            allow_partial_upstreams: core.allow_partial_upstreams,
            source_ids: all_ids,
            transforms: core.transforms,
            enabled_tools: core.enabled_tools,
            data_plane_auth_mode: core.data_plane_auth_mode,
            accept_x_api_key: core.auth.accept_x_api_key,
            rate_limit_enabled: core.limits.rate_limit_enabled,
            rate_limit_tool_calls_per_minute: core.rate_limit_tool_calls_per_minute,
            quota_enabled: core.limits.quota_enabled,
            quota_tool_calls: core.quota_tool_calls,
            tool_call_timeout_secs: core.tool_call_timeout_secs,
            tool_policies: core.tool_policies,
            mcp: core.mcp,
        }))
    }

    async fn get_upstream(&self, upstream_id: &str) -> anyhow::Result<Option<Upstream>> {
        let exists = sqlx::query(
            r"
select 1
from upstreams
where id = $1
  and enabled = true
",
        )
        .bind(upstream_id)
        .fetch_optional(&self.pool)
        .await?
        .is_some();

        if !exists {
            return Ok(None);
        }

        let rows = sqlx::query(
            r"
select id, url, auth
from upstream_endpoints
where upstream_id = $1
  and enabled = true
order by id asc
",
        )
        .bind(upstream_id)
        .fetch_all(&self.pool)
        .await?;

        let endpoints = rows
            .into_iter()
            .map(|r| {
                Ok(UpstreamEndpoint {
                    id: r.try_get("id")?,
                    url: r.try_get("url")?,
                    auth: decode_json_opt(r.try_get::<Option<Value>, _>("auth")?)?,
                })
            })
            .collect::<Result<Vec<_>, sqlx::Error>>()?;

        Ok(Some(Upstream { endpoints }))
    }

    async fn get_tenant_tool_source(
        &self,
        tenant_id: &str,
        source_id: &str,
    ) -> anyhow::Result<Option<TenantToolSource>> {
        let row = sqlx::query(
            r"
select tenant_id, id, kind, enabled, spec
from tool_sources
where tenant_id = $1
  and id = $2
",
        )
        .bind(tenant_id)
        .bind(source_id)
        .fetch_optional(&self.pool)
        .await?;

        let Some(row) = row else {
            return Ok(None);
        };

        let tenant_id: String = row.try_get("tenant_id")?;
        let id: String = row.try_get("id")?;
        let kind: String = row.try_get("kind")?;
        let enabled: bool = row.try_get("enabled")?;
        let spec: Value = row.try_get("spec")?;

        let (kind, spec) = match kind.as_str() {
            "http" => (
                ToolSourceKind::Http,
                ToolSourceSpec::Http(serde_json::from_value(spec)?),
            ),
            "openapi" => (
                ToolSourceKind::Openapi,
                ToolSourceSpec::Openapi(serde_json::from_value(spec)?),
            ),
            other => {
                return Err(anyhow::anyhow!(
                    "unknown tool source kind '{other}' for tenant '{tenant_id}' source '{id}'"
                ));
            }
        };

        Ok(Some(TenantToolSource {
            id,
            kind,
            enabled,
            spec,
        }))
    }

    async fn get_tenant_secret_value(
        &self,
        tenant_id: &str,
        name: &str,
    ) -> anyhow::Result<Option<String>> {
        let row = sqlx::query(
            r"
select value, kid, nonce, ciphertext, algo
from secrets
where tenant_id = $1
  and name = $2
",
        )
        .bind(tenant_id)
        .bind(name)
        .fetch_optional(&self.pool)
        .await?;

        let Some(row) = row else {
            return Ok(None);
        };
        let plaintext: Option<String> = row.try_get("value")?;
        let kid: Option<String> = row.try_get("kid")?;
        let nonce: Option<Vec<u8>> = row.try_get("nonce")?;
        let ciphertext: Option<Vec<u8>> = row.try_get("ciphertext")?;
        let algo: Option<String> = row.try_get("algo")?;

        if let (Some(nonce), Some(ciphertext)) = (nonce, ciphertext) {
            let cipher = &self.secrets_cipher;
            if let Some(algo) = algo.as_deref()
                && algo != "xchacha20poly1305"
            {
                anyhow::bail!("unsupported secret encryption algo '{algo}'");
            }
            let v = cipher.decrypt(tenant_id, name, kid.as_deref(), &nonce, &ciphertext)?;
            return Ok(Some(v));
        }

        // Legacy plaintext row: lazily migrate in-place.
        if let Some(value) = plaintext {
            let cipher = &self.secrets_cipher;
            let mut new_nonce = [0u8; 24];
            let mut rng = OsRng;
            rng.try_fill_bytes(&mut new_nonce)
                .map_err(|e| anyhow::anyhow!("generate secret nonce: {e:?}"))?;
            let new_ciphertext = cipher.encrypt(tenant_id, name, &value, new_nonce)?;
            let new_kid = cipher.active_kid().to_string();
            let new_algo = "xchacha20poly1305";

            // Best-effort: if this update fails, we still return the plaintext (since it was already in DB).
            let _ = sqlx::query(
                r"
update secrets
set kid = $3,
    nonce = $4,
    ciphertext = $5,
    algo = $6,
    value = null,
    updated_at = now()
where tenant_id = $1
  and name = $2
  and value is not null
",
            )
            .bind(tenant_id)
            .bind(name)
            .bind(new_kid)
            .bind(new_nonce.as_slice())
            .bind(new_ciphertext)
            .bind(new_algo)
            .execute(&self.pool)
            .await;

            // Best-effort HA invalidation.
            let _ = pg_invalidation::publish(
                &self.pool,
                &pg_invalidation::InvalidationEvent::TenantSecret {
                    tenant_id: tenant_id.to_string(),
                    name: Some(name.to_string()),
                },
            )
            .await;

            return Ok(Some(value));
        }

        Ok(None)
    }

    async fn get_tenant_transport_limits(
        &self,
        tenant_id: &str,
    ) -> anyhow::Result<Option<crate::store::TransportLimitsSettings>> {
        let row = sqlx::query(
            r"
select transport_limits
from tenants
where id = $1
  and enabled = true
",
        )
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?;

        let Some(row) = row else {
            return Ok(None);
        };

        let v: Value = row.try_get("transport_limits")?;
        Ok(Some(serde_json::from_value(v)?))
    }

    async fn authenticate_api_key(
        &self,
        tenant_id: &str,
        profile_id: &str,
        secret: &str,
    ) -> anyhow::Result<Option<ApiKeyAuth>> {
        let profile_id = Uuid::parse_str(profile_id)
            .map_err(|_| anyhow::anyhow!("invalid profile id (expected UUID)"))?;
        let secret_hash = hash_api_key_secret(secret);

        let row = sqlx::query(
            r"
select id, tenant_id
from api_keys
where tenant_id = $1
  and secret_hash = $2
  and revoked_at is null
  and (profile_id is null or profile_id = $3)
",
        )
        .bind(tenant_id)
        .bind(secret_hash)
        .bind(profile_id)
        .fetch_optional(&self.pool)
        .await?;

        let Some(row) = row else {
            return Ok(None);
        };

        let id: Uuid = row.try_get("id")?;
        let tenant_id: String = row.try_get("tenant_id")?;
        Ok(Some(ApiKeyAuth {
            api_key_id: id.to_string(),
            tenant_id,
        }))
    }

    async fn is_api_key_active(&self, tenant_id: &str, api_key_id: &str) -> anyhow::Result<bool> {
        let api_key_id = Uuid::parse_str(api_key_id)
            .map_err(|_| anyhow::anyhow!("invalid api key id (expected UUID)"))?;
        let exists = sqlx::query(
            r"
select 1
from api_keys
where tenant_id = $1
  and id = $2
  and revoked_at is null
",
        )
        .bind(tenant_id)
        .bind(api_key_id)
        .fetch_optional(&self.pool)
        .await?
        .is_some();
        Ok(exists)
    }

    async fn touch_api_key(&self, tenant_id: &str, api_key_id: &str) -> anyhow::Result<()> {
        let api_key_id = Uuid::parse_str(api_key_id)
            .map_err(|_| anyhow::anyhow!("invalid api key id (expected UUID)"))?;
        sqlx::query(
            r"
update api_keys
set last_used_at = now(),
    total_requests_attempted = total_requests_attempted + 1,
    updated_at = now()
where tenant_id = $1
  and id = $2
  and revoked_at is null
",
        )
        .bind(tenant_id)
        .bind(api_key_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn record_tool_call_attempt(
        &self,
        tenant_id: &str,
        api_key_id: &str,
    ) -> anyhow::Result<()> {
        let api_key_id = Uuid::parse_str(api_key_id)
            .map_err(|_| anyhow::anyhow!("invalid api key id (expected UUID)"))?;
        sqlx::query(
            r"
update api_keys
set total_tool_calls_attempted = total_tool_calls_attempted + 1,
    updated_at = now()
where tenant_id = $1
  and id = $2
  and revoked_at is null
",
        )
        .bind(tenant_id)
        .bind(api_key_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn check_and_apply_tool_call_limits(
        &self,
        _tenant_id: &str,
        profile_id: &str,
        api_key_id: &str,
        rate_limit_tool_calls_per_minute: Option<i64>,
        quota_tool_calls: Option<i64>,
    ) -> anyhow::Result<Option<ToolCallLimitRejection>> {
        if rate_limit_tool_calls_per_minute.is_none() && quota_tool_calls.is_none() {
            return Ok(None);
        }

        let api_key_id = Uuid::parse_str(api_key_id)
            .map_err(|_| anyhow::anyhow!("invalid api key id (expected UUID)"))?;
        let profile_id = Uuid::parse_str(profile_id)
            .map_err(|_| anyhow::anyhow!("invalid profile id (expected UUID)"))?;

        self.ensure_api_key_profile_state_exists(api_key_id, profile_id, quota_tool_calls)
            .await?;

        if let Some(quota) = quota_tool_calls
            && let Some(rej) = self
                .apply_quota_limit(api_key_id, profile_id, quota)
                .await?
        {
            return Ok(Some(rej));
        }

        if let Some(limit) = rate_limit_tool_calls_per_minute
            && let Some(rej) = self.apply_rate_limit(api_key_id, profile_id, limit).await?
        {
            return Ok(Some(rej));
        }

        Ok(None)
    }

    async fn is_oidc_principal_allowed(
        &self,
        tenant_id: &str,
        profile_id: &str,
        issuer: &str,
        subject: &str,
    ) -> anyhow::Result<bool> {
        let profile_id = Uuid::parse_str(profile_id)
            .map_err(|_| anyhow::anyhow!("invalid profile id (expected UUID)"))?;

        let exists = sqlx::query(
            r"
select 1
from oidc_principals
where tenant_id = $1
  and issuer = $2
  and subject = $3
  and enabled = true
  and (profile_id is null or profile_id = $4)
limit 1
",
        )
        .bind(tenant_id)
        .bind(issuer)
        .bind(subject)
        .bind(profile_id)
        .fetch_optional(&self.pool)
        .await?
        .is_some();

        Ok(exists)
    }
}

#[async_trait]
impl AdminStore for PostgresStore {
    async fn list_tenants(&self) -> anyhow::Result<Vec<AdminTenant>> {
        let rows = sqlx::query(
            r"
select id, enabled
from tenants
order by id asc
",
        )
        .fetch_all(&self.pool)
        .await?;

        let tenants = rows
            .into_iter()
            .map(|r| {
                Ok(AdminTenant {
                    id: r.try_get("id")?,
                    enabled: r.try_get("enabled")?,
                })
            })
            .collect::<Result<Vec<_>, sqlx::Error>>()?;

        Ok(tenants)
    }

    async fn get_tenant(&self, tenant_id: &str) -> anyhow::Result<Option<AdminTenant>> {
        let row = sqlx::query(
            r"
select id, enabled
from tenants
where id = $1
",
        )
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?;

        let Some(row) = row else {
            return Ok(None);
        };

        Ok(Some(AdminTenant {
            id: row.try_get("id")?,
            enabled: row.try_get("enabled")?,
        }))
    }

    async fn delete_tenant(&self, tenant_id: &str) -> anyhow::Result<bool> {
        let res = sqlx::query(
            r"
update tenants
set enabled = false,
    updated_at = now()
where id = $1
",
        )
        .bind(tenant_id)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() > 0)
    }

    async fn put_tenant(&self, tenant_id: &str, enabled: bool) -> anyhow::Result<()> {
        sqlx::query(
            r"
insert into tenants (id, enabled)
values ($1, $2)
on conflict (id) do update
set enabled = excluded.enabled,
    updated_at = now()
",
        )
        .bind(tenant_id)
        .bind(enabled)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn list_upstreams(&self) -> anyhow::Result<Vec<AdminUpstream>> {
        let rows = sqlx::query(
            r"
select id, enabled
from upstreams
order by id asc
",
        )
        .fetch_all(&self.pool)
        .await?;

        let mut out: Vec<AdminUpstream> = Vec::with_capacity(rows.len());
        for row in rows {
            let id: String = row.try_get("id")?;
            let enabled: bool = row.try_get("enabled")?;

            let endpoint_rows = sqlx::query(
                r"
select id, url, auth, enabled
from upstream_endpoints
where upstream_id = $1
order by id asc
",
            )
            .bind(&id)
            .fetch_all(&self.pool)
            .await?;

            let endpoints = endpoint_rows
                .into_iter()
                .map(|r| {
                    Ok(AdminUpstreamEndpoint {
                        id: r.try_get("id")?,
                        url: r.try_get("url")?,
                        enabled: r.try_get("enabled")?,
                        auth: decode_json_opt(r.try_get::<Option<Value>, _>("auth")?)?,
                    })
                })
                .collect::<Result<Vec<_>, sqlx::Error>>()?;

            out.push(AdminUpstream {
                id,
                enabled,
                endpoints,
            });
        }

        Ok(out)
    }

    async fn get_upstream(&self, upstream_id: &str) -> anyhow::Result<Option<AdminUpstream>> {
        let row = sqlx::query(
            r"
select id, enabled
from upstreams
where id = $1
",
        )
        .bind(upstream_id)
        .fetch_optional(&self.pool)
        .await?;

        let Some(row) = row else {
            return Ok(None);
        };

        let id: String = row.try_get("id")?;
        let enabled: bool = row.try_get("enabled")?;

        let endpoint_rows = sqlx::query(
            r"
select id, url, auth, enabled
from upstream_endpoints
where upstream_id = $1
order by id asc
",
        )
        .bind(&id)
        .fetch_all(&self.pool)
        .await?;

        let endpoints = endpoint_rows
            .into_iter()
            .map(|r| {
                Ok(AdminUpstreamEndpoint {
                    id: r.try_get("id")?,
                    url: r.try_get("url")?,
                    enabled: r.try_get("enabled")?,
                    auth: decode_json_opt(r.try_get::<Option<Value>, _>("auth")?)?,
                })
            })
            .collect::<Result<Vec<_>, sqlx::Error>>()?;

        Ok(Some(AdminUpstream {
            id,
            enabled,
            endpoints,
        }))
    }

    async fn delete_upstream(&self, upstream_id: &str) -> anyhow::Result<bool> {
        let mut tx: Transaction<'_, Postgres> = self.pool.begin().await?;

        let rows = sqlx::query(
            r"
select profile_id
from profile_upstreams
where upstream_id = $1
",
        )
        .bind(upstream_id)
        .fetch_all(&mut *tx)
        .await?;
        let affected_profile_ids: Vec<String> = rows
            .into_iter()
            .map(|r| {
                r.try_get::<uuid::Uuid, _>("profile_id")
                    .map(|id| id.to_string())
            })
            .collect::<Result<Vec<_>, sqlx::Error>>()?;

        let res = sqlx::query(
            r"
delete from upstreams
where id = $1
",
        )
        .bind(upstream_id)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        if res.rows_affected() > 0 {
            let _ = pg_invalidation::publish(
                &self.pool,
                &pg_invalidation::InvalidationEvent::Upstream {
                    upstream_id: upstream_id.to_string(),
                },
            )
            .await;

            for profile_id in affected_profile_ids {
                let _ = pg_invalidation::publish(
                    &self.pool,
                    &pg_invalidation::InvalidationEvent::Profile { profile_id },
                )
                .await;
            }
        }

        Ok(res.rows_affected() > 0)
    }

    async fn put_upstream(
        &self,
        upstream_id: &str,
        enabled: bool,
        endpoints: &[UpstreamEndpoint],
    ) -> anyhow::Result<()> {
        let mut tx: Transaction<'_, Postgres> = self.pool.begin().await?;

        sqlx::query(
            r"
insert into upstreams (id, enabled)
values ($1, $2)
on conflict (id) do update
set enabled = excluded.enabled,
    updated_at = now()
",
        )
        .bind(upstream_id)
        .bind(enabled)
        .execute(&mut *tx)
        .await?;

        // Replace endpoints (current semantics).
        sqlx::query(r"delete from upstream_endpoints where upstream_id = $1")
            .bind(upstream_id)
            .execute(&mut *tx)
            .await?;

        for ep in endpoints {
            sqlx::query(
                r"
insert into upstream_endpoints (upstream_id, id, url, auth, enabled)
values ($1, $2, $3, $4, true)
on conflict (upstream_id, id) do update
set url = excluded.url,
    auth = excluded.auth,
    enabled = excluded.enabled,
    updated_at = now()
",
            )
            .bind(upstream_id)
            .bind(&ep.id)
            .bind(&ep.url)
            .bind(ep.auth.as_ref().map(serde_json::to_value).transpose()?)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;

        // Best-effort HA invalidation.
        let _ = pg_invalidation::publish(
            &self.pool,
            &pg_invalidation::InvalidationEvent::Upstream {
                upstream_id: upstream_id.to_string(),
            },
        )
        .await;
        Ok(())
    }

    async fn list_profiles(&self) -> anyhow::Result<Vec<AdminProfile>> {
        let rows = sqlx::query(
            r"
select
  id,
  tenant_id,
  name,
  description,
  enabled,
  allow_partial_upstreams,
  enabled_tools,
  transforms,
  mcp_settings,
  data_plane_auth_mode,
  accept_x_api_key,
  rate_limit_enabled,
  rate_limit_tool_calls_per_minute,
  quota_enabled,
  quota_tool_calls,
  tool_call_timeout_secs,
  tool_policies
from profiles
order by created_at asc, id asc
",
        )
        .fetch_all(&self.pool)
        .await?;

        let mut out: Vec<AdminProfile> = Vec::with_capacity(rows.len());
        for row in rows {
            let row = Self::parse_admin_profile_row(&row)?;
            let upstream_ids = self.load_admin_profile_upstream_ids(row.id_uuid).await?;
            let source_ids = self.load_admin_profile_source_ids(row.id_uuid).await?;

            out.push(AdminProfile {
                id: row.id,
                name: row.name,
                description: row.description,
                tenant_id: row.tenant_id,
                enabled: row.flags.enabled,
                allow_partial_upstreams: row.flags.allow_partial_upstreams,
                upstream_ids,
                source_ids,
                transforms: row.transforms,
                enabled_tools: row.enabled_tools,
                data_plane_auth_mode: row.data_plane_auth_mode,
                accept_x_api_key: row.auth.accept_x_api_key,
                rate_limit_enabled: row.limits.rate_limit_enabled,
                rate_limit_tool_calls_per_minute: row.rate_limit_tool_calls_per_minute,
                quota_enabled: row.limits.quota_enabled,
                quota_tool_calls: row.quota_tool_calls,
                tool_call_timeout_secs: row.tool_call_timeout_secs,
                tool_policies: row.tool_policies,
                mcp: row.mcp,
            });
        }

        Ok(out)
    }

    async fn get_profile(&self, profile_id: &str) -> anyhow::Result<Option<AdminProfile>> {
        let profile_id = Uuid::parse_str(profile_id)
            .map_err(|_| anyhow::anyhow!("invalid profile id (expected UUID)"))?;

        let Some(row) = self.fetch_admin_profile_row(profile_id).await? else {
            return Ok(None);
        };
        let row = Self::parse_admin_profile_row(&row)?;
        let upstream_ids = self.load_admin_profile_upstream_ids(profile_id).await?;
        let source_ids = self.load_admin_profile_source_ids(profile_id).await?;

        Ok(Some(AdminProfile {
            id: row.id,
            name: row.name,
            description: row.description,
            tenant_id: row.tenant_id,
            enabled: row.flags.enabled,
            allow_partial_upstreams: row.flags.allow_partial_upstreams,
            upstream_ids,
            source_ids,
            transforms: row.transforms,
            enabled_tools: row.enabled_tools,
            data_plane_auth_mode: row.data_plane_auth_mode,
            accept_x_api_key: row.auth.accept_x_api_key,
            rate_limit_enabled: row.limits.rate_limit_enabled,
            rate_limit_tool_calls_per_minute: row.rate_limit_tool_calls_per_minute,
            quota_enabled: row.limits.quota_enabled,
            quota_tool_calls: row.quota_tool_calls,
            tool_call_timeout_secs: row.tool_call_timeout_secs,
            tool_policies: row.tool_policies,
            mcp: row.mcp,
        }))
    }

    async fn delete_profile(&self, profile_id: &str) -> anyhow::Result<bool> {
        let profile_id = Uuid::parse_str(profile_id)
            .map_err(|_| anyhow::anyhow!("invalid profile id (expected UUID)"))?;

        let mut tx: Transaction<'_, Postgres> = self.pool.begin().await?;

        let _ = sqlx::query(
            r"
delete from contract_events
where profile_id = $1
",
        )
        .bind(profile_id)
        .execute(&mut *tx)
        .await?;

        let res = sqlx::query(
            r"
delete from profiles
where id = $1
",
        )
        .bind(profile_id)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        if res.rows_affected() > 0 {
            let _ = pg_invalidation::publish(
                &self.pool,
                &pg_invalidation::InvalidationEvent::Profile {
                    profile_id: profile_id.to_string(),
                },
            )
            .await;
        }
        Ok(res.rows_affected() > 0)
    }

    async fn put_profile(&self, input: crate::store::PutProfileInput<'_>) -> anyhow::Result<()> {
        let profile_id = Uuid::parse_str(input.profile_id)
            .map_err(|_| anyhow::anyhow!("invalid profile id (expected UUID)"))?;

        let rate_limit_tool_calls_per_minute: Option<i32> = input
            .limits
            .rate_limit_tool_calls_per_minute
            .map(|v| {
                i32::try_from(v)
                    .map_err(|_| anyhow::anyhow!("rateLimitToolCallsPerMinute out of range"))
            })
            .transpose()?;

        let tool_call_timeout_secs: Option<i32> = input
            .tool_call_timeout_secs
            .map(|v| {
                i32::try_from(v).map_err(|_| anyhow::anyhow!("toolCallTimeoutSecs out of range"))
            })
            .transpose()?;

        let mut tx: Transaction<'_, Postgres> = self.pool.begin().await?;

        self.ensure_tenant_exists_tx(&mut tx, input.tenant_id)
            .await?;
        self.upsert_profile_row_tx(
            &mut tx,
            profile_id,
            ProfileUpsertInput {
                tenant_id: input.tenant_id,
                name: input.name,
                description: input.description,
                flags: ProfileUpsertFlags {
                    enabled: input.flags.enabled,
                    allow_partial_upstreams: input.flags.allow_partial_upstreams,
                },
                enabled_tools: input.enabled_tools,
                transforms: input.transforms,
                mcp: input.mcp,
                data_plane_auth_mode: input.data_plane_auth.mode,
                auth: ProfileUpsertAuth {
                    accept_x_api_key: input.data_plane_auth.accept_x_api_key,
                },
                limits: ProfileUpsertLimits {
                    rate_limit_enabled: input.limits.rate_limit_enabled,
                    quota_enabled: input.limits.quota_enabled,
                },
                rate_limit_tool_calls_per_minute,
                quota_tool_calls: input.limits.quota_tool_calls,
                tool_call_timeout_secs,
                tool_policies: input.tool_policies,
            },
        )
        .await?;
        self.replace_profile_upstreams_tx(&mut tx, profile_id, input.upstream_ids)
            .await?;
        self.replace_profile_sources_tx(&mut tx, profile_id, input.source_ids)
            .await?;

        tx.commit().await?;

        // Best-effort HA invalidation.
        let _ = pg_invalidation::publish(
            &self.pool,
            &pg_invalidation::InvalidationEvent::Profile {
                profile_id: profile_id.to_string(),
            },
        )
        .await;
        Ok(())
    }

    async fn list_tool_sources(&self, tenant_id: &str) -> anyhow::Result<Vec<TenantToolSource>> {
        let rows = sqlx::query(
            r"
select id, kind, enabled, spec
from tool_sources
where tenant_id = $1
order by created_at asc, id asc
",
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;

        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let id: String = row.try_get("id")?;
            let kind: String = row.try_get("kind")?;
            let enabled: bool = row.try_get("enabled")?;
            let spec: Value = row.try_get("spec")?;

            let (kind, spec) = match kind.as_str() {
                "http" => (
                    ToolSourceKind::Http,
                    ToolSourceSpec::Http(serde_json::from_value(spec)?),
                ),
                "openapi" => (
                    ToolSourceKind::Openapi,
                    ToolSourceSpec::Openapi(serde_json::from_value(spec)?),
                ),
                other => {
                    return Err(anyhow::anyhow!(
                        "unknown tool source kind '{other}' for tenant '{tenant_id}' source '{id}'"
                    ));
                }
            };

            out.push(TenantToolSource {
                id,
                kind,
                enabled,
                spec,
            });
        }

        Ok(out)
    }

    async fn get_tool_source(
        &self,
        tenant_id: &str,
        source_id: &str,
    ) -> anyhow::Result<Option<TenantToolSource>> {
        self.get_tenant_tool_source(tenant_id, source_id).await
    }

    async fn put_tool_source(
        &self,
        tenant_id: &str,
        source_id: &str,
        enabled: bool,
        kind: ToolSourceKind,
        spec: Value,
    ) -> anyhow::Result<()> {
        let kind = match kind {
            ToolSourceKind::Http => "http",
            ToolSourceKind::Openapi => "openapi",
        };

        sqlx::query(
            r"
insert into tool_sources (tenant_id, id, kind, enabled, spec)
values ($1, $2, $3, $4, $5)
on conflict (tenant_id, id) do update
set kind = excluded.kind,
    enabled = excluded.enabled,
    spec = excluded.spec,
    updated_at = now()
",
        )
        .bind(tenant_id)
        .bind(source_id)
        .bind(kind)
        .bind(enabled)
        .bind(spec)
        .execute(&self.pool)
        .await?;

        // Best-effort HA invalidation.
        let _ = pg_invalidation::publish(
            &self.pool,
            &pg_invalidation::InvalidationEvent::TenantToolSource {
                tenant_id: tenant_id.to_string(),
                source_id: source_id.to_string(),
            },
        )
        .await;

        Ok(())
    }

    async fn delete_tool_source(&self, tenant_id: &str, source_id: &str) -> anyhow::Result<bool> {
        let mut tx: Transaction<'_, Postgres> = self.pool.begin().await?;

        // Find affected profiles (including disabled profiles).
        let rows = sqlx::query(
            r"
select ps.profile_id
from profile_sources ps
join profiles p on p.id = ps.profile_id
where p.tenant_id = $1
  and ps.source_id = $2
",
        )
        .bind(tenant_id)
        .bind(source_id)
        .fetch_all(&mut *tx)
        .await?;
        let affected_profile_ids: Vec<String> = rows
            .into_iter()
            .map(|r| {
                r.try_get::<uuid::Uuid, _>("profile_id")
                    .map(|id| id.to_string())
            })
            .collect::<Result<Vec<_>, sqlx::Error>>()?;

        // Detach from tenant profiles. (We cannot use FK cascade because profile_sources can
        // reference shared sources too, so source_id is not a FK.)
        sqlx::query(
            r"
delete from profile_sources ps
using profiles p
where p.id = ps.profile_id
  and p.tenant_id = $1
  and ps.source_id = $2
",
        )
        .bind(tenant_id)
        .bind(source_id)
        .execute(&mut *tx)
        .await?;

        // Delete the tool source itself.
        let res = sqlx::query(
            r"
delete from tool_sources
where tenant_id = $1
  and id = $2
",
        )
        .bind(tenant_id)
        .bind(source_id)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        // Best-effort HA invalidation.
        if res.rows_affected() > 0 {
            let _ = pg_invalidation::publish(
                &self.pool,
                &pg_invalidation::InvalidationEvent::TenantToolSource {
                    tenant_id: tenant_id.to_string(),
                    source_id: source_id.to_string(),
                },
            )
            .await;

            for profile_id in affected_profile_ids {
                let _ = pg_invalidation::publish(
                    &self.pool,
                    &pg_invalidation::InvalidationEvent::Profile { profile_id },
                )
                .await;
            }
        }

        Ok(res.rows_affected() > 0)
    }

    async fn list_secrets(&self, tenant_id: &str) -> anyhow::Result<Vec<TenantSecretMetadata>> {
        let rows = sqlx::query(
            r"
select name
from secrets
where tenant_id = $1
order by name asc
",
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;

        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            out.push(TenantSecretMetadata {
                name: row.try_get("name")?,
            });
        }
        Ok(out)
    }

    async fn put_secret(&self, tenant_id: &str, name: &str, value: &str) -> anyhow::Result<()> {
        let cipher = &self.secrets_cipher;
        let mut nonce = [0u8; 24];
        let mut rng = OsRng;
        rng.try_fill_bytes(&mut nonce)
            .map_err(|e| anyhow::anyhow!("generate secret nonce: {e:?}"))?;
        let ciphertext = cipher.encrypt(tenant_id, name, value, nonce)?;
        let kid = cipher.active_kid().to_string();
        let algo = "xchacha20poly1305";

        sqlx::query(
            r"
insert into secrets (tenant_id, name, kid, nonce, ciphertext, algo, value)
values ($1, $2, $3, $4, $5, $6, null)
on conflict (tenant_id, name) do update
set kid = excluded.kid,
    nonce = excluded.nonce,
    ciphertext = excluded.ciphertext,
    algo = excluded.algo,
    value = null,
    updated_at = now()
",
        )
        .bind(tenant_id)
        .bind(name)
        .bind(kid)
        .bind(nonce.as_slice())
        .bind(ciphertext)
        .bind(algo)
        .execute(&self.pool)
        .await?;

        // Best-effort HA invalidation.
        let _ = pg_invalidation::publish(
            &self.pool,
            &pg_invalidation::InvalidationEvent::TenantSecret {
                tenant_id: tenant_id.to_string(),
                name: Some(name.to_string()),
            },
        )
        .await;
        Ok(())
    }

    async fn delete_secret(&self, tenant_id: &str, name: &str) -> anyhow::Result<bool> {
        let res = sqlx::query(
            r"
delete from secrets
where tenant_id = $1
  and name = $2
",
        )
        .bind(tenant_id)
        .bind(name)
        .execute(&self.pool)
        .await?;

        // Best-effort HA invalidation.
        if res.rows_affected() > 0 {
            let _ = pg_invalidation::publish(
                &self.pool,
                &pg_invalidation::InvalidationEvent::TenantSecret {
                    tenant_id: tenant_id.to_string(),
                    name: Some(name.to_string()),
                },
            )
            .await;
        }
        Ok(res.rows_affected() > 0)
    }

    async fn list_api_keys(&self, tenant_id: &str) -> anyhow::Result<Vec<ApiKeyMetadata>> {
        let rows = sqlx::query(
            r"
select
  id,
  name,
  prefix,
  profile_id,
  extract(epoch from created_at)::bigint as created_at_unix,
  extract(epoch from last_used_at)::bigint as last_used_at_unix,
  extract(epoch from revoked_at)::bigint as revoked_at_unix,
  total_tool_calls_attempted,
  total_requests_attempted
from api_keys
where tenant_id = $1
order by created_at asc, id asc
",
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;

        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let id: Uuid = row.try_get("id")?;
            let name: String = row.try_get("name")?;
            let prefix: String = row.try_get("prefix")?;
            let profile_id: Option<Uuid> = row.try_get("profile_id")?;
            let created_at_unix: i64 = row.try_get("created_at_unix")?;
            let last_used_at_unix: Option<i64> = row.try_get("last_used_at_unix")?;
            let revoked_at_unix: Option<i64> = row.try_get("revoked_at_unix")?;
            let total_tool_calls_attempted: i64 = row.try_get("total_tool_calls_attempted")?;
            let total_requests_attempted: i64 = row.try_get("total_requests_attempted")?;

            out.push(ApiKeyMetadata {
                id: id.to_string(),
                name,
                prefix,
                profile_id: profile_id.map(|u| u.to_string()),
                revoked_at_unix,
                last_used_at_unix,
                total_tool_calls_attempted,
                total_requests_attempted,
                created_at_unix,
            });
        }

        Ok(out)
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
        let api_key_id = Uuid::parse_str(api_key_id)
            .map_err(|_| anyhow::anyhow!("invalid api key id (expected UUID)"))?;
        let profile_id = match profile_id {
            Some(pid) => Some(
                Uuid::parse_str(pid)
                    .map_err(|_| anyhow::anyhow!("invalid profile id (expected UUID)"))?,
            ),
            None => None,
        };

        sqlx::query(
            r"
insert into api_keys (id, tenant_id, profile_id, name, prefix, secret_hash)
values ($1, $2, $3, $4, $5, $6)
",
        )
        .bind(api_key_id)
        .bind(tenant_id)
        .bind(profile_id)
        .bind(name)
        .bind(prefix)
        .bind(secret_hash)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn revoke_api_key(&self, tenant_id: &str, api_key_id: &str) -> anyhow::Result<bool> {
        let api_key_id = Uuid::parse_str(api_key_id)
            .map_err(|_| anyhow::anyhow!("invalid api key id (expected UUID)"))?;
        let res = sqlx::query(
            r"
update api_keys
set revoked_at = now(),
    updated_at = now()
where tenant_id = $1
  and id = $2
  and revoked_at is null
",
        )
        .bind(tenant_id)
        .bind(api_key_id)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() > 0)
    }

    async fn list_oidc_principals(
        &self,
        tenant_id: &str,
        issuer: &str,
    ) -> anyhow::Result<Vec<OidcPrincipalBinding>> {
        let rows = sqlx::query(
            r"
select
  subject,
  profile_id,
  enabled
from oidc_principals
where tenant_id = $1
  and issuer = $2
order by subject asc, profile_id asc nulls first
",
        )
        .bind(tenant_id)
        .bind(issuer)
        .fetch_all(&self.pool)
        .await?;

        let mut out: Vec<OidcPrincipalBinding> = Vec::with_capacity(rows.len());
        for r in rows {
            let subject: String = r.try_get("subject")?;
            let profile_id: Option<Uuid> = r.try_get("profile_id")?;
            let enabled: bool = r.try_get("enabled")?;
            out.push(OidcPrincipalBinding {
                issuer: issuer.to_string(),
                subject,
                profile_id: profile_id.map(|u| u.to_string()),
                enabled,
            });
        }
        Ok(out)
    }

    async fn put_oidc_principal(
        &self,
        tenant_id: &str,
        issuer: &str,
        subject: &str,
        profile_id: Option<&str>,
        enabled: bool,
    ) -> anyhow::Result<()> {
        let profile_id = match profile_id {
            Some(pid) => Some(
                Uuid::parse_str(pid)
                    .map_err(|_| anyhow::anyhow!("invalid profile id (expected UUID)"))?,
            ),
            None => None,
        };

        if let Some(pid) = profile_id {
            sqlx::query(
                r"
insert into oidc_principals (
  id,
  issuer,
  subject,
  tenant_id,
  profile_id,
  enabled
)
values ($1, $2, $3, $4, $5, $6)
on conflict (issuer, subject, tenant_id, profile_id) where profile_id is not null
do update
set enabled = excluded.enabled,
    updated_at = now()
",
            )
            .bind(Uuid::new_v4())
            .bind(issuer)
            .bind(subject)
            .bind(tenant_id)
            .bind(pid)
            .bind(enabled)
            .execute(&self.pool)
            .await?;
        } else {
            sqlx::query(
                r"
insert into oidc_principals (
  id,
  issuer,
  subject,
  tenant_id,
  profile_id,
  enabled
)
values ($1, $2, $3, $4, null, $5)
on conflict (issuer, subject, tenant_id) where profile_id is null
do update
set enabled = excluded.enabled,
    updated_at = now()
",
            )
            .bind(Uuid::new_v4())
            .bind(issuer)
            .bind(subject)
            .bind(tenant_id)
            .bind(enabled)
            .execute(&self.pool)
            .await?;
        }

        Ok(())
    }

    async fn delete_oidc_principal(
        &self,
        tenant_id: &str,
        issuer: &str,
        subject: &str,
        profile_id: Option<&str>,
    ) -> anyhow::Result<u64> {
        let profile_id = match profile_id {
            Some(pid) => Some(
                Uuid::parse_str(pid)
                    .map_err(|_| anyhow::anyhow!("invalid profile id (expected UUID)"))?,
            ),
            None => None,
        };

        let res = if let Some(pid) = profile_id {
            sqlx::query(
                r"
delete from oidc_principals
where tenant_id = $1
  and issuer = $2
  and subject = $3
  and profile_id = $4
",
            )
            .bind(tenant_id)
            .bind(issuer)
            .bind(subject)
            .bind(pid)
            .execute(&self.pool)
            .await?
        } else {
            sqlx::query(
                r"
delete from oidc_principals
where tenant_id = $1
  and issuer = $2
  and subject = $3
",
            )
            .bind(tenant_id)
            .bind(issuer)
            .bind(subject)
            .execute(&self.pool)
            .await?
        };

        Ok(res.rows_affected())
    }

    async fn get_tenant_transport_limits(
        &self,
        tenant_id: &str,
    ) -> anyhow::Result<Option<crate::store::TransportLimitsSettings>> {
        let row = sqlx::query(
            r"
select transport_limits
from tenants
where id = $1
",
        )
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?;

        let Some(row) = row else {
            return Ok(None);
        };

        let v: Value = row.try_get("transport_limits")?;
        Ok(Some(serde_json::from_value(v)?))
    }

    async fn put_tenant_transport_limits(
        &self,
        tenant_id: &str,
        limits: &crate::store::TransportLimitsSettings,
    ) -> anyhow::Result<()> {
        let res = sqlx::query(
            r"
update tenants
set transport_limits = $2
where id = $1
",
        )
        .bind(tenant_id)
        .bind(serde_json::to_value(limits)?)
        .execute(&self.pool)
        .await?;

        if res.rows_affected() == 0 {
            anyhow::bail!("tenant not found");
        }
        Ok(())
    }

    async fn get_tenant_audit_settings(
        &self,
        tenant_id: &str,
    ) -> anyhow::Result<Option<TenantAuditSettings>> {
        let row = sqlx::query(
            r"
select audit_enabled, audit_retention_days, audit_default_level
from tenants
where id = $1
",
        )
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?;

        let Some(row) = row else {
            return Ok(None);
        };

        Ok(Some(TenantAuditSettings {
            enabled: row.try_get("audit_enabled")?,
            retention_days: row.try_get("audit_retention_days")?,
            default_level: row.try_get("audit_default_level")?,
        }))
    }

    async fn put_tenant_audit_settings(
        &self,
        tenant_id: &str,
        settings: &TenantAuditSettings,
    ) -> anyhow::Result<()> {
        let res = sqlx::query(
            r"
update tenants
set audit_enabled = $2,
    audit_retention_days = $3,
    audit_default_level = $4
where id = $1
",
        )
        .bind(tenant_id)
        .bind(settings.enabled)
        .bind(settings.retention_days)
        .bind(&settings.default_level)
        .execute(&self.pool)
        .await?;

        if res.rows_affected() == 0 {
            anyhow::bail!("tenant not found");
        }
        Ok(())
    }

    async fn get_profile_audit_settings(&self, profile_id: &str) -> anyhow::Result<Option<Value>> {
        let profile_id = Uuid::parse_str(profile_id)
            .map_err(|_| anyhow::anyhow!("invalid profile id (expected UUID)"))?;

        let row = sqlx::query(
            r"
select audit_settings
from profiles
where id = $1
",
        )
        .bind(profile_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| r.try_get("audit_settings")).transpose()?)
    }

    async fn put_profile_audit_settings(
        &self,
        profile_id: &str,
        audit_settings: Value,
    ) -> anyhow::Result<()> {
        let profile_id = Uuid::parse_str(profile_id)
            .map_err(|_| anyhow::anyhow!("invalid profile id (expected UUID)"))?;

        let res = sqlx::query(
            r"
update profiles
set audit_settings = $2
where id = $1
",
        )
        .bind(profile_id)
        .bind(audit_settings)
        .execute(&self.pool)
        .await?;

        if res.rows_affected() == 0 {
            anyhow::bail!("profile not found");
        }
        Ok(())
    }

    async fn list_audit_events(
        &self,
        tenant_id: &str,
        filter: AuditEventFilter,
    ) -> anyhow::Result<Vec<AuditEventRow>> {
        let mut qb = sqlx::QueryBuilder::<Postgres>::new(
            r"
select
  id,
  extract(epoch from ts)::bigint as ts_unix_secs,
  tenant_id,
  profile_id::text as profile_id,
  api_key_id::text as api_key_id,
  oidc_issuer,
  oidc_subject,
  action,
  http_method,
  http_route,
  status_code,
  tool_ref,
  tool_name_at_time,
  ok,
  duration_ms,
  error_kind,
  error_message,
  meta
from audit_events
where tenant_id = 
",
        );
        qb.push_bind(tenant_id);

        if let Some(before_id) = filter.before_id {
            qb.push(" and id < ").push_bind(before_id);
        }
        if let Some(profile_id) = filter.profile_id.as_deref() {
            qb.push(" and profile_id = ").push_bind(
                Uuid::parse_str(profile_id)
                    .map_err(|_| anyhow::anyhow!("invalid profile id (expected UUID)"))?,
            );
        }
        if let Some(api_key_id) = filter.api_key_id.as_deref() {
            qb.push(" and api_key_id = ").push_bind(
                Uuid::parse_str(api_key_id)
                    .map_err(|_| anyhow::anyhow!("invalid api key id (expected UUID)"))?,
            );
        }
        if let Some(tool_ref) = filter.tool_ref.as_deref() {
            qb.push(" and tool_ref = ").push_bind(tool_ref);
        }
        if let Some(action) = filter.action.as_deref() {
            qb.push(" and action = ").push_bind(action);
        }
        if let Some(ok) = filter.ok {
            qb.push(" and ok = ").push_bind(ok);
        }
        if let Some(from) = filter.from_unix_secs {
            qb.push(" and ts >= to_timestamp(")
                .push_bind(from)
                .push("::double precision)");
        }
        if let Some(to) = filter.to_unix_secs {
            qb.push(" and ts < to_timestamp(")
                .push_bind(to)
                .push("::double precision)");
        }

        qb.push(" order by id desc limit ").push_bind(filter.limit);

        let rows = qb.build().fetch_all(&self.pool).await?;

        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            out.push(AuditEventRow {
                id: r.try_get("id")?,
                ts_unix_secs: r.try_get("ts_unix_secs")?,
                tenant_id: r.try_get("tenant_id")?,
                profile_id: r.try_get("profile_id")?,
                api_key_id: r.try_get("api_key_id")?,
                oidc_issuer: r.try_get("oidc_issuer")?,
                oidc_subject: r.try_get("oidc_subject")?,
                action: r.try_get("action")?,
                http_method: r.try_get("http_method")?,
                http_route: r.try_get("http_route")?,
                status_code: r.try_get("status_code")?,
                tool_ref: r.try_get("tool_ref")?,
                tool_name_at_time: r.try_get("tool_name_at_time")?,
                ok: r.try_get("ok")?,
                duration_ms: r.try_get("duration_ms")?,
                error_kind: r.try_get("error_kind")?,
                error_message: r.try_get("error_message")?,
                meta: r.try_get("meta")?,
            });
        }
        Ok(out)
    }

    async fn tool_call_stats_by_tool(
        &self,
        tenant_id: &str,
        filter: AuditStatsFilter,
    ) -> anyhow::Result<Vec<ToolCallStatsByTool>> {
        let mut qb = sqlx::QueryBuilder::<Postgres>::new(
            r"
select
  tool_ref,
  count(*)::bigint as total,
  count(*) filter (where ok)::bigint as ok,
  count(*) filter (where not ok)::bigint as err,
  round(avg(duration_ms) filter (where duration_ms is not null))::bigint as avg_duration_ms,
  round(percentile_cont(0.95) within group (order by duration_ms) filter (where duration_ms is not null))::bigint as p95_duration_ms,
  round(percentile_cont(0.99) within group (order by duration_ms) filter (where duration_ms is not null))::bigint as p99_duration_ms,
  max(duration_ms) as max_duration_ms
from audit_events
where tenant_id =
",
        );
        qb.push_bind(tenant_id);
        qb.push(" and action = 'mcp.tools_call' and tool_ref is not null");

        if let Some(profile_id) = filter.profile_id.as_deref() {
            qb.push(" and profile_id = ").push_bind(
                Uuid::parse_str(profile_id)
                    .map_err(|_| anyhow::anyhow!("invalid profile id (expected UUID)"))?,
            );
        }
        if let Some(api_key_id) = filter.api_key_id.as_deref() {
            qb.push(" and api_key_id = ").push_bind(
                Uuid::parse_str(api_key_id)
                    .map_err(|_| anyhow::anyhow!("invalid api key id (expected UUID)"))?,
            );
        }
        if let Some(tool_ref) = filter.tool_ref.as_deref() {
            qb.push(" and tool_ref = ").push_bind(tool_ref);
        }
        if let Some(from) = filter.from_unix_secs {
            qb.push(" and ts >= to_timestamp(")
                .push_bind(from)
                .push("::double precision)");
        }
        if let Some(to) = filter.to_unix_secs {
            qb.push(" and ts < to_timestamp(")
                .push_bind(to)
                .push("::double precision)");
        }

        qb.push(" group by tool_ref order by total desc limit ")
            .push_bind(filter.limit);

        let rows = qb.build().fetch_all(&self.pool).await?;
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            out.push(ToolCallStatsByTool {
                tool_ref: r
                    .try_get::<Option<String>, _>("tool_ref")?
                    .unwrap_or_else(|| "unknown".to_string()),
                total: r.try_get("total")?,
                ok: r.try_get("ok")?,
                err: r.try_get("err")?,
                avg_duration_ms: r.try_get("avg_duration_ms")?,
                p95_duration_ms: r.try_get("p95_duration_ms")?,
                p99_duration_ms: r.try_get("p99_duration_ms")?,
                max_duration_ms: r.try_get("max_duration_ms")?,
            });
        }
        Ok(out)
    }

    async fn tool_call_stats_by_api_key(
        &self,
        tenant_id: &str,
        filter: AuditStatsFilter,
    ) -> anyhow::Result<Vec<ToolCallStatsByApiKey>> {
        let mut qb = sqlx::QueryBuilder::<Postgres>::new(
            r"
select
  api_key_id::text as api_key_id,
  count(*)::bigint as total,
  count(*) filter (where ok)::bigint as ok,
  count(*) filter (where not ok)::bigint as err,
  round(avg(duration_ms) filter (where duration_ms is not null))::bigint as avg_duration_ms,
  round(percentile_cont(0.95) within group (order by duration_ms) filter (where duration_ms is not null))::bigint as p95_duration_ms,
  round(percentile_cont(0.99) within group (order by duration_ms) filter (where duration_ms is not null))::bigint as p99_duration_ms,
  max(duration_ms) as max_duration_ms
from audit_events
where tenant_id =
",
        );
        qb.push_bind(tenant_id);
        qb.push(" and action = 'mcp.tools_call' and api_key_id is not null");

        if let Some(profile_id) = filter.profile_id.as_deref() {
            qb.push(" and profile_id = ").push_bind(
                Uuid::parse_str(profile_id)
                    .map_err(|_| anyhow::anyhow!("invalid profile id (expected UUID)"))?,
            );
        }
        if let Some(api_key_id) = filter.api_key_id.as_deref() {
            qb.push(" and api_key_id = ").push_bind(
                Uuid::parse_str(api_key_id)
                    .map_err(|_| anyhow::anyhow!("invalid api key id (expected UUID)"))?,
            );
        }
        if let Some(tool_ref) = filter.tool_ref.as_deref() {
            qb.push(" and tool_ref = ").push_bind(tool_ref);
        }
        if let Some(from) = filter.from_unix_secs {
            qb.push(" and ts >= to_timestamp(")
                .push_bind(from)
                .push("::double precision)");
        }
        if let Some(to) = filter.to_unix_secs {
            qb.push(" and ts < to_timestamp(")
                .push_bind(to)
                .push("::double precision)");
        }

        qb.push(" group by api_key_id order by total desc limit ")
            .push_bind(filter.limit);

        let rows = qb.build().fetch_all(&self.pool).await?;
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            out.push(ToolCallStatsByApiKey {
                api_key_id: r.try_get("api_key_id")?,
                total: r.try_get("total")?,
                ok: r.try_get("ok")?,
                err: r.try_get("err")?,
                avg_duration_ms: r.try_get("avg_duration_ms")?,
                p95_duration_ms: r.try_get("p95_duration_ms")?,
                p99_duration_ms: r.try_get("p99_duration_ms")?,
                max_duration_ms: r.try_get("max_duration_ms")?,
            });
        }
        Ok(out)
    }

    async fn cleanup_audit_events_for_tenant(&self, tenant_id: &str) -> anyhow::Result<u64> {
        let row = sqlx::query(
            r"
select audit_retention_days
from tenants
where id = $1
",
        )
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?;

        let Some(row) = row else {
            anyhow::bail!("tenant not found");
        };
        let retention_days: i32 = row.try_get("audit_retention_days")?;

        let res = sqlx::query(
            r"
delete from audit_events
where tenant_id = $1
  and ts < now() - ($2::int * interval '1 day')
",
        )
        .bind(tenant_id)
        .bind(retention_days)
        .execute(&self.pool)
        .await?;

        Ok(res.rows_affected())
    }
}

fn parse_data_plane_auth_mode(mode: &str) -> anyhow::Result<DataPlaneAuthMode> {
    match mode {
        "disabled" => Ok(DataPlaneAuthMode::Disabled),
        "api_key_initialize_only" => Ok(DataPlaneAuthMode::ApiKeyInitializeOnly),
        "api_key_every_request" => Ok(DataPlaneAuthMode::ApiKeyEveryRequest),
        "jwt_every_request" => Ok(DataPlaneAuthMode::JwtEveryRequest),
        other => Err(anyhow::anyhow!("unknown data_plane_auth_mode '{other}'")),
    }
}

const fn data_plane_auth_mode_to_db(mode: DataPlaneAuthMode) -> &'static str {
    match mode {
        DataPlaneAuthMode::Disabled => "disabled",
        DataPlaneAuthMode::ApiKeyInitializeOnly => "api_key_initialize_only",
        DataPlaneAuthMode::ApiKeyEveryRequest => "api_key_every_request",
        DataPlaneAuthMode::JwtEveryRequest => "jwt_every_request",
    }
}

fn hash_api_key_secret(secret: &str) -> String {
    hex::encode(sha2::Sha256::digest(secret.as_bytes()))
}
