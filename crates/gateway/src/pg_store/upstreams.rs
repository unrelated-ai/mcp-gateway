//! PostgreSQL upstreams operations.
use super::*;

impl PostgresStore {
    pub(super) async fn data_get_upstream(
        &self,
        upstream_id: &str,
    ) -> anyhow::Result<Option<Upstream>> {
        let upstream_row = sqlx::query(
            r"
select network_class
from upstreams
where id = $1
  and enabled = true
",
        )
        .bind(upstream_id)
        .fetch_optional(&self.pool)
        .await?;

        let Some(upstream_row) = upstream_row else {
            return Ok(None);
        };
        let network_class: String = upstream_row.try_get("network_class")?;
        let network_class = parse_upstream_network_class(&network_class)?;

        let rows = sqlx::query(
            r"
select id, url, auth, enabled, lifecycle
from upstream_endpoints
where upstream_id = $1
  and enabled = true
  and lifecycle != 'disabled'
order by id asc
",
        )
        .bind(upstream_id)
        .fetch_all(&self.pool)
        .await?;

        let endpoints = rows
            .into_iter()
            .map(|r| {
                let lifecycle_raw: String = r.try_get("lifecycle")?;
                Ok(UpstreamEndpoint {
                    id: r.try_get("id")?,
                    url: r.try_get("url")?,
                    enabled: r.try_get("enabled")?,
                    lifecycle: parse_upstream_endpoint_lifecycle(&lifecycle_raw)
                        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?,
                    auth: decode_json_opt(r.try_get::<Option<Value>, _>("auth")?)?,
                })
            })
            .collect::<Result<Vec<_>, sqlx::Error>>()?;

        Ok(Some(Upstream {
            network_class,
            endpoints,
        }))
    }

    pub(super) async fn data_record_session_activity(
        &self,
        tenant_id: &str,
        profile_id: &str,
        session_hash: &str,
        bindings: &[SessionActivityBinding],
    ) -> anyhow::Result<()> {
        let profile_id = Uuid::parse_str(profile_id)
            .map_err(|_| anyhow::anyhow!("invalid profile id (expected UUID)"))?;
        if bindings.is_empty() {
            return Ok(());
        }
        let upstream_ids: Vec<&str> = bindings.iter().map(|b| b.upstream_id.as_str()).collect();
        let endpoint_ids: Vec<&str> = bindings.iter().map(|b| b.endpoint_id.as_str()).collect();
        // A single statement is atomic and avoids one database round trip per
        // upstream on every MCP request. Deduplicate pairs before ON CONFLICT:
        // one session can otherwise contain the same binding more than once.
        sqlx::query(
            r"
insert into upstream_session_activity (
  tenant_id, profile_id, upstream_id, endpoint_id, session_hash, last_seen_at
)
select $1, $2, binding.upstream_id, binding.endpoint_id, $5, now()
from (
  select distinct upstream_id, endpoint_id
  from unnest($3::text[], $4::text[]) as pairs(upstream_id, endpoint_id)
) as binding
on conflict (profile_id, upstream_id, endpoint_id, session_hash) do update
set last_seen_at = excluded.last_seen_at
",
        )
        .bind(tenant_id)
        .bind(profile_id)
        .bind(&upstream_ids)
        .bind(&endpoint_ids)
        .bind(session_hash)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub(super) async fn admin_list_upstreams(&self) -> anyhow::Result<Vec<AdminUpstream>> {
        let rows = sqlx::query(
            r"
select id, enabled, network_class
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
            let network_class_raw: String = row.try_get("network_class")?;
            let network_class = parse_upstream_network_class(&network_class_raw)?;

            let endpoint_rows = sqlx::query(
                r"
select id, url, auth, enabled, lifecycle
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
                    let lifecycle_raw: String = r.try_get("lifecycle")?;
                    Ok(AdminUpstreamEndpoint {
                        id: r.try_get("id")?,
                        url: r.try_get("url")?,
                        enabled: r.try_get("enabled")?,
                        lifecycle: parse_upstream_endpoint_lifecycle(&lifecycle_raw)
                            .map_err(|e| sqlx::Error::Protocol(e.to_string()))?,
                        auth: decode_json_opt(r.try_get::<Option<Value>, _>("auth")?)?,
                    })
                })
                .collect::<Result<Vec<_>, sqlx::Error>>()?;

            out.push(AdminUpstream {
                id,
                enabled,
                network_class,
                endpoints,
            });
        }

        Ok(out)
    }

    pub(super) async fn admin_get_upstream(
        &self,
        upstream_id: &str,
    ) -> anyhow::Result<Option<AdminUpstream>> {
        let row = sqlx::query(
            r"
select id, enabled, network_class
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
        let network_class_raw: String = row.try_get("network_class")?;
        let network_class = parse_upstream_network_class(&network_class_raw)?;

        let endpoint_rows = sqlx::query(
            r"
select id, url, auth, enabled, lifecycle
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
                let lifecycle_raw: String = r.try_get("lifecycle")?;
                Ok(AdminUpstreamEndpoint {
                    id: r.try_get("id")?,
                    url: r.try_get("url")?,
                    enabled: r.try_get("enabled")?,
                    lifecycle: parse_upstream_endpoint_lifecycle(&lifecycle_raw)
                        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?,
                    auth: decode_json_opt(r.try_get::<Option<Value>, _>("auth")?)?,
                })
            })
            .collect::<Result<Vec<_>, sqlx::Error>>()?;

        Ok(Some(AdminUpstream {
            id,
            enabled,
            network_class,
            endpoints,
        }))
    }

    pub(super) async fn admin_delete_upstream(&self, upstream_id: &str) -> anyhow::Result<bool> {
        let mut tx: Transaction<'_, Postgres> = self.pool.begin().await?;

        // Serialize detachment with conditional profile writes and advance revision.
        sqlx::query("update profiles set updated_at = now() where id in (select profile_id from profile_upstreams where upstream_id = $1)")
            .bind(upstream_id).execute(&mut *tx).await?;

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

        let mut events = Vec::new();
        if res.rows_affected() > 0 {
            events.push(pg_invalidation::InvalidationEvent::Upstream {
                upstream_id: upstream_id.to_string(),
            });
            for profile_id in affected_profile_ids {
                events.push(pg_invalidation::InvalidationEvent::Profile { profile_id });
            }
        }
        self.emit_invalidation_events_best_effort(events);

        Ok(res.rows_affected() > 0)
    }

    pub(super) async fn admin_put_upstream(
        &self,
        upstream_id: &str,
        enabled: bool,
        network_class: UpstreamNetworkClass,
        endpoints: &[UpstreamEndpoint],
    ) -> anyhow::Result<()> {
        let mut tx: Transaction<'_, Postgres> = self.pool.begin().await?;

        sqlx::query(
            r"
insert into upstreams (id, enabled, network_class)
values ($1, $2, $3)
on conflict (id) do update
set enabled = excluded.enabled,
    network_class = excluded.network_class,
    updated_at = now()
",
        )
        .bind(upstream_id)
        .bind(enabled)
        .bind(upstream_network_class_to_db(network_class))
        .execute(&mut *tx)
        .await?;

        for ep in endpoints {
            sqlx::query(
                r"
insert into upstream_endpoints (upstream_id, id, url, auth, enabled, lifecycle)
values ($1, $2, $3, $4, $5, $6)
on conflict (upstream_id, id) do update
set url = excluded.url,
    auth = excluded.auth,
    enabled = excluded.enabled,
    lifecycle = excluded.lifecycle,
    updated_at = now()
",
            )
            .bind(upstream_id)
            .bind(&ep.id)
            .bind(&ep.url)
            .bind(ep.auth.as_ref().map(serde_json::to_value).transpose()?)
            .bind(ep.enabled)
            .bind(upstream_endpoint_lifecycle_to_db(ep.lifecycle))
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;

        let events = vec![pg_invalidation::InvalidationEvent::Upstream {
            upstream_id: upstream_id.to_string(),
        }];
        self.emit_invalidation_events_best_effort(events);
        Ok(())
    }

    pub(super) async fn admin_patch_upstream_endpoint(
        &self,
        upstream_id: &str,
        endpoint_id: &str,
        enabled: Option<bool>,
        lifecycle: Option<UpstreamEndpointLifecycle>,
    ) -> anyhow::Result<bool> {
        let lifecycle = lifecycle.map(upstream_endpoint_lifecycle_to_db);
        let res = sqlx::query(
            r"
update upstream_endpoints
set
  enabled = coalesce($3, enabled),
  lifecycle = coalesce($4, lifecycle),
  updated_at = now()
where upstream_id = $1
  and id = $2
",
        )
        .bind(upstream_id)
        .bind(endpoint_id)
        .bind(enabled)
        .bind(lifecycle)
        .execute(&self.pool)
        .await?;

        if res.rows_affected() > 0 {
            let events = vec![pg_invalidation::InvalidationEvent::Upstream {
                upstream_id: upstream_id.to_string(),
            }];
            self.emit_invalidation_events_best_effort(events);
            return Ok(true);
        }
        Ok(false)
    }

    pub(super) async fn admin_delete_upstream_endpoint(
        &self,
        upstream_id: &str,
        endpoint_id: &str,
    ) -> anyhow::Result<bool> {
        let res = sqlx::query(
            r"
delete from upstream_endpoints
where upstream_id = $1
  and id = $2
",
        )
        .bind(upstream_id)
        .bind(endpoint_id)
        .execute(&self.pool)
        .await?;

        if res.rows_affected() > 0 {
            let events = vec![pg_invalidation::InvalidationEvent::Upstream {
                upstream_id: upstream_id.to_string(),
            }];
            self.emit_invalidation_events_best_effort(events);
            return Ok(true);
        }
        Ok(false)
    }

    pub(super) async fn admin_list_upstream_endpoint_activity(
        &self,
        upstream_id: &str,
        ttl_secs: u64,
    ) -> anyhow::Result<Vec<UpstreamEndpointActivity>> {
        let ttl_secs = i64::try_from(ttl_secs).unwrap_or(i64::MAX);
        let rows = sqlx::query(
            r"
select
  endpoint_id,
  count(distinct session_hash)::bigint as active_sessions,
  extract(epoch from max(last_seen_at))::bigint as last_seen_unix
from upstream_session_activity
where upstream_id = $1
  and last_seen_at >= now() - make_interval(secs => $2)
group by endpoint_id
order by endpoint_id asc
",
        )
        .bind(upstream_id)
        .bind(ttl_secs)
        .fetch_all(&self.pool)
        .await?;

        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            out.push(UpstreamEndpointActivity {
                endpoint_id: row.try_get("endpoint_id")?,
                active_sessions: row.try_get("active_sessions")?,
                last_seen_unix: row.try_get("last_seen_unix")?,
            });
        }
        Ok(out)
    }
}
