//! PostgreSQL audit operations.
use super::*;

impl PostgresStore {
    pub(super) async fn admin_get_tenant_audit_settings(
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

    pub(super) async fn admin_put_tenant_audit_settings(
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
        let events = vec![pg_invalidation::InvalidationEvent::TenantAuditSettings {
            tenant_id: tenant_id.to_string(),
        }];
        self.emit_invalidation_events_best_effort(events);
        Ok(())
    }

    pub(super) async fn admin_list_audit_events(
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

    pub(super) async fn admin_tool_call_stats_by_tool(
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

        qb.push(" group by tool_ref order by total desc, tool_ref asc limit ")
            .push_bind(filter.limit)
            .push(" offset ")
            .push_bind(filter.offset);

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

    pub(super) async fn admin_cleanup_audit_events_for_tenant(
        &self,
        tenant_id: &str,
    ) -> anyhow::Result<u64> {
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
