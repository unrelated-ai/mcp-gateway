//! PostgreSQL deployments operations.
use super::*;

// Keep the shared projection and queries static; request values remain bind parameters.
macro_rules! managed_mcp_deployment_request_sql {
    ($prefix:literal, $suffix:literal) => {
        concat!(
            $prefix,
            r"
  id,
  tenant_id,
  deployable_id,
  desired_enabled,
  desired_replicas,
  status,
  upstream_id,
  message,
  extract(epoch from created_at)::bigint as created_at_unix,
  extract(epoch from updated_at)::bigint as updated_at_unix
",
            $suffix
        )
    };
}

impl PostgresStore {
    pub(super) async fn admin_list_managed_mcp_deployables(
        &self,
    ) -> anyhow::Result<Vec<ManagedMcpDeployable>> {
        let rows = sqlx::query(
            r"
select id, display_name, description, image, default_upstream_url, enabled
from managed_mcp_deployables
order by id asc
",
        )
        .fetch_all(&self.pool)
        .await?;
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            out.push(ManagedMcpDeployable {
                id: row.try_get("id")?,
                display_name: row.try_get("display_name")?,
                description: row.try_get("description")?,
                image: row.try_get("image")?,
                default_upstream_url: row.try_get("default_upstream_url")?,
                enabled: row.try_get("enabled")?,
            });
        }
        Ok(out)
    }

    pub(super) async fn admin_upsert_managed_mcp_deployable(
        &self,
        deployable: &ManagedMcpDeployable,
    ) -> anyhow::Result<()> {
        sqlx::query(
            r"
insert into managed_mcp_deployables (
  id,
  display_name,
  description,
  image,
  default_upstream_url,
  enabled
)
values ($1, $2, $3, $4, $5, $6)
on conflict (id) do update set
  display_name = excluded.display_name,
  description = excluded.description,
  image = excluded.image,
  default_upstream_url = excluded.default_upstream_url,
  enabled = excluded.enabled,
  updated_at = now()
",
        )
        .bind(&deployable.id)
        .bind(&deployable.display_name)
        .bind(&deployable.description)
        .bind(&deployable.image)
        .bind(&deployable.default_upstream_url)
        .bind(deployable.enabled)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub(super) async fn admin_create_managed_mcp_deployment_request(
        &self,
        tenant_id: &str,
        deployable_id: &str,
    ) -> anyhow::Result<ManagedMcpDeploymentRequest> {
        let exists = sqlx::query(
            r"
select 1
from managed_mcp_deployables
where id = $1
  and enabled = true
",
        )
        .bind(deployable_id)
        .fetch_optional(&self.pool)
        .await?;
        if exists.is_none() {
            anyhow::bail!("deployable not found or disabled");
        }

        let existing = sqlx::query(managed_mcp_deployment_request_sql!(
            r"
select
",
            r"
from managed_mcp_deployment_requests
where tenant_id = $1
  and deployable_id = $2
  and status in ('pending', 'reconciling', 'ready')
order by created_at desc
limit 1
"
        ))
        .bind(tenant_id)
        .bind(deployable_id)
        .fetch_optional(&self.pool)
        .await?;
        if let Some(row) = existing {
            return parse_managed_mcp_deployment_request_row(&row);
        }

        let request_id = Uuid::new_v4().to_string();
        let row = sqlx::query(managed_mcp_deployment_request_sql!(
            r"
insert into managed_mcp_deployment_requests (
  id,
  tenant_id,
  deployable_id,
  desired_enabled,
  desired_replicas,
  status
)
values ($1, $2, $3, true, 1, 'pending')
returning
",
            r"
"
        ))
        .bind(&request_id)
        .bind(tenant_id)
        .bind(deployable_id)
        .fetch_one(&self.pool)
        .await?;
        parse_managed_mcp_deployment_request_row(&row)
    }

    pub(super) async fn admin_get_managed_mcp_deployment_request(
        &self,
        request_id: &str,
    ) -> anyhow::Result<Option<ManagedMcpDeploymentRequest>> {
        let row = sqlx::query(managed_mcp_deployment_request_sql!(
            r"
select
",
            r"
from managed_mcp_deployment_requests
where id = $1
"
        ))
        .bind(request_id)
        .fetch_optional(&self.pool)
        .await?;
        match row {
            Some(row) => Ok(Some(parse_managed_mcp_deployment_request_row(&row)?)),
            None => Ok(None),
        }
    }

    pub(super) async fn admin_get_managed_mcp_deployment_request_for_tenant(
        &self,
        tenant_id: &str,
        request_id: &str,
    ) -> anyhow::Result<Option<ManagedMcpDeploymentRequest>> {
        let row = sqlx::query(managed_mcp_deployment_request_sql!(
            r"
select
",
            r"
from managed_mcp_deployment_requests
where tenant_id = $1
  and id = $2
"
        ))
        .bind(tenant_id)
        .bind(request_id)
        .fetch_optional(&self.pool)
        .await?;
        match row {
            Some(row) => Ok(Some(parse_managed_mcp_deployment_request_row(&row)?)),
            None => Ok(None),
        }
    }

    pub(super) async fn admin_list_managed_mcp_deployment_requests(
        &self,
        statuses: &[ManagedMcpDeploymentStatus],
        limit: u32,
    ) -> anyhow::Result<Vec<ManagedMcpDeploymentRequest>> {
        let mut qb = QueryBuilder::<Postgres>::new(managed_mcp_deployment_request_sql!(
            r"
select
",
            r"
from managed_mcp_deployment_requests
"
        ));
        if !statuses.is_empty() {
            qb.push("where status in (");
            {
                let mut separated = qb.separated(", ");
                for status in statuses {
                    separated.push_bind(managed_mcp_deployment_status_to_db(*status));
                }
            }
            qb.push(") ");
        }
        qb.push("order by created_at asc limit ");
        qb.push_bind(i64::from(limit.max(1)));

        let rows = qb.build().fetch_all(&self.pool).await?;
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            out.push(parse_managed_mcp_deployment_request_row(&row)?);
        }
        Ok(out)
    }

    pub(super) async fn admin_list_managed_mcp_deployment_requests_for_tenant(
        &self,
        tenant_id: &str,
        limit: u32,
    ) -> anyhow::Result<Vec<ManagedMcpDeploymentRequest>> {
        let rows = sqlx::query(managed_mcp_deployment_request_sql!(
            r"
select
",
            r"
from managed_mcp_deployment_requests
where tenant_id = $1
order by created_at desc
limit $2
"
        ))
        .bind(tenant_id)
        .bind(i64::from(limit.max(1)))
        .fetch_all(&self.pool)
        .await?;
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            out.push(parse_managed_mcp_deployment_request_row(&row)?);
        }
        Ok(out)
    }

    pub(super) async fn admin_update_managed_mcp_deployment_request_for_tenant(
        &self,
        tenant_id: &str,
        request_id: &str,
        desired_enabled: bool,
        desired_replicas: i32,
    ) -> anyhow::Result<Option<ManagedMcpDeploymentRequest>> {
        let row = sqlx::query(managed_mcp_deployment_request_sql!(
            r"
update managed_mcp_deployment_requests
set desired_enabled = $3,
    desired_replicas = $4,
    status = 'pending',
    message = null,
    updated_at = now()
where tenant_id = $1
  and id = $2
returning
",
            r"
"
        ))
        .bind(tenant_id)
        .bind(request_id)
        .bind(desired_enabled)
        .bind(desired_replicas)
        .fetch_optional(&self.pool)
        .await?;
        match row {
            Some(row) => Ok(Some(parse_managed_mcp_deployment_request_row(&row)?)),
            None => Ok(None),
        }
    }

    pub(super) async fn admin_mark_managed_mcp_deployment_status(
        &self,
        request_id: &str,
        status: ManagedMcpDeploymentStatus,
        upstream_id: Option<&str>,
        message: Option<&str>,
    ) -> anyhow::Result<bool> {
        let res = sqlx::query(
            r"
update managed_mcp_deployment_requests
set status = $2,
    upstream_id = $3,
    message = $4,
    updated_at = now()
where id = $1
",
        )
        .bind(request_id)
        .bind(managed_mcp_deployment_status_to_db(status))
        .bind(upstream_id)
        .bind(message)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() > 0)
    }

    pub(super) async fn admin_upsert_managed_mcp_reconciler_heartbeat(
        &self,
        backend_mode: ManagedMcpBackendMode,
        reconciler_id: &str,
    ) -> anyhow::Result<()> {
        if matches!(backend_mode, ManagedMcpBackendMode::None) {
            anyhow::bail!("backend_mode=none is not valid for reconciler heartbeats");
        }
        if reconciler_id.trim().is_empty() {
            anyhow::bail!("reconciler_id is required");
        }
        sqlx::query(
            r"
insert into managed_mcp_reconciler_heartbeats (
  reconciler_id,
  backend_mode,
  last_heartbeat_at
)
values ($1, $2, now())
on conflict (reconciler_id) do update set
  backend_mode = excluded.backend_mode,
  last_heartbeat_at = excluded.last_heartbeat_at,
  updated_at = now()
",
        )
        .bind(reconciler_id)
        .bind(managed_mcp_backend_mode_to_db(backend_mode))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub(super) async fn admin_latest_managed_mcp_reconciler_heartbeat_unix(
        &self,
        backend_mode: ManagedMcpBackendMode,
    ) -> anyhow::Result<Option<i64>> {
        if matches!(backend_mode, ManagedMcpBackendMode::None) {
            return Ok(None);
        }
        let row = sqlx::query(
            r"
select extract(epoch from max(last_heartbeat_at))::bigint as last_heartbeat_unix
from managed_mcp_reconciler_heartbeats
where backend_mode = $1
",
        )
        .bind(managed_mcp_backend_mode_to_db(backend_mode))
        .fetch_one(&self.pool)
        .await?;
        Ok(row.try_get("last_heartbeat_unix")?)
    }

    pub(super) async fn admin_fail_stale_managed_mcp_deployment_requests(
        &self,
        statuses: &[ManagedMcpDeploymentStatus],
        stale_after_secs: u64,
        message: &str,
    ) -> anyhow::Result<u64> {
        if statuses.is_empty() {
            return Ok(0);
        }
        let stale_after_secs = i64::try_from(stale_after_secs).unwrap_or(i64::MAX);
        let mut qb = QueryBuilder::<Postgres>::new(
            r"
update managed_mcp_deployment_requests
set status = 'failed',
    message = ",
        );
        qb.push_bind(message);
        qb.push(
            r",
    updated_at = now()
where status in (",
        );
        {
            let mut separated = qb.separated(", ");
            for status in statuses {
                separated.push_bind(managed_mcp_deployment_status_to_db(*status));
            }
        }
        qb.push(") and updated_at < now() - make_interval(secs => ");
        qb.push_bind(stale_after_secs);
        qb.push(")");
        let res = qb.build().execute(&self.pool).await?;
        Ok(res.rows_affected())
    }
}
