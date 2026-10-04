//! PostgreSQL identity operations.
use super::*;

impl PostgresStore {
    pub(super) async fn data_authenticate_api_key(
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

    pub(super) async fn data_is_api_key_active(
        &self,
        tenant_id: &str,
        api_key_id: &str,
    ) -> anyhow::Result<bool> {
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

    pub(super) async fn data_touch_api_key(
        &self,
        tenant_id: &str,
        api_key_id: &str,
    ) -> anyhow::Result<()> {
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

    pub(super) async fn data_record_tool_call_attempt(
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

    pub(super) async fn data_check_and_apply_tool_call_limits(
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

    pub(super) async fn data_is_oidc_principal_allowed(
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

    pub(super) async fn admin_list_api_keys(
        &self,
        tenant_id: &str,
    ) -> anyhow::Result<Vec<ApiKeyMetadata>> {
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

    pub(super) async fn admin_put_api_key(
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

    pub(super) async fn admin_revoke_api_key(
        &self,
        tenant_id: &str,
        api_key_id: &str,
    ) -> anyhow::Result<bool> {
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

    pub(super) async fn admin_list_oidc_principals(
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

    pub(super) async fn admin_put_oidc_principal(
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

    pub(super) async fn admin_delete_oidc_principal(
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

    pub(super) async fn admin_tool_call_stats_by_api_key(
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

        qb.push(" group by api_key_id order by total desc, api_key_id asc limit ")
            .push_bind(filter.limit)
            .push(" offset ")
            .push_bind(filter.offset);

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
}
