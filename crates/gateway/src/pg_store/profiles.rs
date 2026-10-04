//! PostgreSQL profiles operations.
use super::*;

impl PostgresStore {
    pub(super) async fn data_get_profile(
        &self,
        profile_id: &str,
    ) -> anyhow::Result<Option<Profile>> {
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
            oauth_required_scopes: core.auth.oauth_required_scopes,
            rate_limit_enabled: core.limits.rate_limit_enabled,
            rate_limit_tool_calls_per_minute: core.rate_limit_tool_calls_per_minute,
            quota_enabled: core.limits.quota_enabled,
            quota_tool_calls: core.quota_tool_calls,
            tool_call_timeout_secs: core.tool_call_timeout_secs,
            tool_policies: core.tool_policies,
            mcp: core.mcp,
        }))
    }

    pub(super) async fn admin_list_profiles(&self) -> anyhow::Result<Vec<AdminProfile>> {
        let rows = sqlx::query(
            r"
select
  revision,
  array(select upstream_id from profile_upstreams where profile_id = profiles.id order by ordinal, upstream_id) as upstream_ids,
  array(select source_id from profile_sources where profile_id = profiles.id order by ordinal, source_id) as source_ids,
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
  oauth_required_scopes,
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
            let upstream_ids = row.upstream_ids;
            let source_ids = row.source_ids;

            out.push(AdminProfile {
                revision: row.revision,
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
                oauth_required_scopes: row.auth.oauth_required_scopes,
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

    pub(super) async fn admin_get_profile(
        &self,
        profile_id: &str,
    ) -> anyhow::Result<Option<AdminProfile>> {
        let profile_id = Uuid::parse_str(profile_id)
            .map_err(|_| anyhow::anyhow!("invalid profile id (expected UUID)"))?;

        let Some(row) = self.fetch_admin_profile_row(profile_id).await? else {
            return Ok(None);
        };
        let row = Self::parse_admin_profile_row(&row)?;
        let upstream_ids = row.upstream_ids;
        let source_ids = row.source_ids;

        Ok(Some(AdminProfile {
            revision: row.revision,
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
            oauth_required_scopes: row.auth.oauth_required_scopes,
            rate_limit_enabled: row.limits.rate_limit_enabled,
            rate_limit_tool_calls_per_minute: row.rate_limit_tool_calls_per_minute,
            quota_enabled: row.limits.quota_enabled,
            quota_tool_calls: row.quota_tool_calls,
            tool_call_timeout_secs: row.tool_call_timeout_secs,
            tool_policies: row.tool_policies,
            mcp: row.mcp,
        }))
    }

    pub(super) async fn admin_delete_profile(&self, profile_id: &str) -> anyhow::Result<bool> {
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
            let events = vec![pg_invalidation::InvalidationEvent::Profile {
                profile_id: profile_id.to_string(),
            }];
            self.emit_invalidation_events_best_effort(events);
        }
        Ok(res.rows_affected() > 0)
    }

    pub(super) async fn admin_put_profile(
        &self,
        input: crate::store::PutProfileInput<'_>,
    ) -> anyhow::Result<()> {
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

        if let Some(expected) = input.expected_revision {
            let current: Option<i64> = sqlx::query_scalar(
                "select revision from profiles where id = $1 and tenant_id = $2 for update",
            )
            .bind(profile_id)
            .bind(input.tenant_id)
            .fetch_optional(&mut *tx)
            .await?;
            if current != Some(expected) {
                return Err(crate::store::ProfileRevisionConflict.into());
            }
        }

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
                    oauth_required_scopes: input.data_plane_auth.oauth_required_scopes,
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

        let events = vec![pg_invalidation::InvalidationEvent::Profile {
            profile_id: profile_id.to_string(),
        }];
        self.emit_invalidation_events_best_effort(events);
        Ok(())
    }

    pub(super) async fn admin_get_profile_audit_settings(
        &self,
        tenant_id: &str,
        profile_id: &str,
    ) -> anyhow::Result<Option<ProfileAuditSettingsResponse>> {
        let profile_id = Uuid::parse_str(profile_id)?;
        let row = sqlx::query(
            r"
select p.audit_settings, p.revision, t.audit_enabled, t.audit_default_level, t.audit_retention_days
from profiles p
join tenants t on t.id = p.tenant_id
where p.id = $1 and p.tenant_id = $2
",
        )
        .bind(profile_id)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else { return Ok(None) };
        let parsed = serde_json::from_value::<ProfileAuditSettings>(row.try_get("audit_settings")?);
        let has_unrecognized_settings = parsed.is_err();
        let audit_settings = parsed.unwrap_or_default();
        let tenant_settings = unrelated_gateway_api::audit::TenantAuditDefaults {
            enabled: row.try_get("audit_enabled")?,
            default_level: row
                .try_get::<String, _>("audit_default_level")?
                .parse()
                .unwrap_or_default(),
            retention_days: row.try_get("audit_retention_days")?,
        };
        Ok(Some(ProfileAuditSettingsResponse {
            audit_settings,
            revision: row.try_get("revision")?,
            effective_level: audit_settings
                .effective_level(tenant_settings.enabled, tenant_settings.default_level),
            tenant_settings,
            has_unrecognized_settings,
        }))
    }

    pub(super) async fn admin_put_profile_audit_settings(
        &self,
        tenant_id: &str,
        profile_id: &str,
        audit_settings: ProfileAuditSettings,
        expected_revision: Option<i64>,
    ) -> anyhow::Result<()> {
        let profile_id = Uuid::parse_str(profile_id)?;
        let res = sqlx::query(
            r"
update profiles
set audit_settings = $3, updated_at = now()
where id = $1 and tenant_id = $2 and ($4::bigint is null or revision = $4)
",
        )
        .bind(profile_id)
        .bind(tenant_id)
        .bind(serde_json::to_value(audit_settings)?)
        .bind(expected_revision)
        .execute(&self.pool)
        .await?;
        if res.rows_affected() == 0 {
            return Err(crate::store::ProfileRevisionConflict.into());
        }
        self.emit_invalidation_events_best_effort(vec![
            pg_invalidation::InvalidationEvent::Profile {
                profile_id: profile_id.to_string(),
            },
        ]);
        Ok(())
    }
}

impl PostgresStore {
    pub(super) async fn fetch_enabled_profile_row(
        &self,
        profile_id: Uuid,
    ) -> anyhow::Result<Option<PgRow>> {
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
  p.oauth_required_scopes,
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

    pub(super) fn parse_profile_core(row: &PgRow) -> anyhow::Result<ProfileCore> {
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
        let oauth_required_scopes: Vec<String> = row.try_get("oauth_required_scopes")?;
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
            auth: ProfileAuthCore {
                accept_x_api_key,
                oauth_required_scopes,
            },
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

    pub(super) async fn load_profile_source_ids(
        &self,
        profile_id: Uuid,
    ) -> anyhow::Result<Vec<String>> {
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

    pub(super) async fn fetch_admin_profile_row(
        &self,
        profile_id: Uuid,
    ) -> anyhow::Result<Option<PgRow>> {
        sqlx::query(
            r"
select
  revision,
  array(select upstream_id from profile_upstreams where profile_id = profiles.id order by ordinal, upstream_id) as upstream_ids,
  array(select source_id from profile_sources where profile_id = profiles.id order by ordinal, source_id) as source_ids,
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
  oauth_required_scopes,
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

    pub(super) fn parse_admin_profile_row(row: &PgRow) -> anyhow::Result<AdminProfileRow> {
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
        let oauth_required_scopes: Vec<String> = row.try_get("oauth_required_scopes")?;
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
            revision: row.try_get("revision")?,
            upstream_ids: row.try_get("upstream_ids")?,
            source_ids: row.try_get("source_ids")?,
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
            auth: AdminProfileAuth {
                accept_x_api_key,
                oauth_required_scopes,
            },
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

    pub(super) async fn upsert_profile_row_tx(
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
  oauth_required_scopes,
  rate_limit_enabled,
  rate_limit_tool_calls_per_minute,
  quota_enabled,
  quota_tool_calls,
  tool_call_timeout_secs,
  tool_policies
)
values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
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
    oauth_required_scopes = excluded.oauth_required_scopes,
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
        .bind(input.auth.oauth_required_scopes)
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

    pub(super) async fn replace_profile_upstreams_tx(
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

    pub(super) async fn replace_profile_sources_tx(
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
}
