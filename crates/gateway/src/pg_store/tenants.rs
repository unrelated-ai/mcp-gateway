//! PostgreSQL tenants operations.
use super::*;

impl PostgresStore {
    pub(super) async fn data_tenant_tool_source_ids(
        &self,
        tenant_id: &str,
        ids: &[String],
    ) -> anyhow::Result<HashSet<String>> {
        if ids.is_empty() {
            return Ok(HashSet::new());
        }
        let ids = sqlx::query_scalar::<_, String>(
            "select id from tool_sources where tenant_id = $1 and enabled = true and id = any($2)",
        )
        .bind(tenant_id)
        .bind(ids)
        .fetch_all(&self.pool)
        .await?;
        Ok(ids.into_iter().collect())
    }

    pub(super) async fn data_get_tenant_tool_source(
        &self,
        tenant_id: &str,
        source_id: &str,
    ) -> anyhow::Result<Option<TenantToolSource>> {
        let row = sqlx::query(
            r"
select tenant_id, id, kind, enabled, spec, revision
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
            revision: row.try_get("revision")?,
            id,
            kind,
            enabled,
            spec,
        }))
    }

    pub(super) async fn data_get_tenant_secret_value(
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
            fill_random_bytes(&mut new_nonce)
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

            let events = vec![pg_invalidation::InvalidationEvent::TenantSecret {
                tenant_id: tenant_id.to_string(),
                name: Some(name.to_string()),
            }];
            self.emit_invalidation_events_best_effort(events);

            return Ok(Some(value));
        }

        Ok(None)
    }

    pub(super) async fn data_get_tenant_transport_limits(
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

    pub(super) async fn admin_list_tenants(&self) -> anyhow::Result<Vec<AdminTenant>> {
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

    pub(super) async fn admin_get_tenant(
        &self,
        tenant_id: &str,
    ) -> anyhow::Result<Option<AdminTenant>> {
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

    pub(super) async fn admin_delete_tenant(&self, tenant_id: &str) -> anyhow::Result<bool> {
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

    pub(super) async fn admin_put_tenant(
        &self,
        tenant_id: &str,
        enabled: bool,
    ) -> anyhow::Result<()> {
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

    pub(super) async fn admin_list_tool_sources(
        &self,
        tenant_id: &str,
    ) -> anyhow::Result<Vec<TenantToolSource>> {
        let rows = sqlx::query(
            r"
select id, kind, enabled, spec, revision
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
                revision: row.try_get("revision")?,
                id,
                kind,
                enabled,
                spec,
            });
        }

        Ok(out)
    }

    pub(super) async fn admin_get_tool_source(
        &self,
        tenant_id: &str,
        source_id: &str,
    ) -> anyhow::Result<Option<TenantToolSource>> {
        self.get_tenant_tool_source(tenant_id, source_id).await
    }

    pub(super) async fn admin_put_tool_source(
        &self,
        tenant_id: &str,
        source_id: &str,
        enabled: bool,
        kind: ToolSourceKind,
        spec: Value,
        expected_revision: Option<i64>,
    ) -> anyhow::Result<()> {
        let kind = match kind {
            ToolSourceKind::Http => "http",
            ToolSourceKind::Openapi => "openapi",
        };

        if expected_revision == Some(0) {
            // Revision zero means create only; a stale creation form must never upsert.
            let result = sqlx::query(
                "insert into tool_sources (tenant_id, id, kind, enabled, spec) \
                 values ($1, $2, $3, $4, $5) on conflict (tenant_id, id) do nothing",
            )
            .bind(tenant_id)
            .bind(source_id)
            .bind(kind)
            .bind(enabled)
            .bind(spec)
            .execute(&self.pool)
            .await?;
            if result.rows_affected() == 0 {
                return Err(crate::store::ToolSourceAlreadyExists.into());
            }
        } else if let Some(revision) = expected_revision {
            let result = sqlx::query(
                "update tool_sources set kind = $3, enabled = $4, spec = $5, updated_at = now() \
                 where tenant_id = $1 and id = $2 and revision = $6",
            )
            .bind(tenant_id)
            .bind(source_id)
            .bind(kind)
            .bind(enabled)
            .bind(spec)
            .bind(revision)
            .execute(&self.pool)
            .await?;
            if result.rows_affected() == 0 {
                return Err(crate::store::ToolSourceRevisionConflict.into());
            }
        } else {
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
        }

        let events = vec![pg_invalidation::InvalidationEvent::TenantToolSource {
            tenant_id: tenant_id.to_string(),
            source_id: source_id.to_string(),
        }];
        self.emit_invalidation_events_best_effort(events);

        Ok(())
    }

    pub(super) async fn admin_delete_tool_source(
        &self,
        tenant_id: &str,
        source_id: &str,
    ) -> anyhow::Result<bool> {
        let mut tx: Transaction<'_, Postgres> = self.pool.begin().await?;

        // Find affected profiles (including disabled profiles).
        // Serialize detachment with conditional profile writes and advance revision.
        sqlx::query("update profiles set updated_at = now() where tenant_id = $1 and id in (select profile_id from profile_sources where source_id = $2)")
            .bind(tenant_id).bind(source_id).execute(&mut *tx).await?;

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

        let mut events = Vec::new();
        if res.rows_affected() > 0 {
            events.push(pg_invalidation::InvalidationEvent::TenantToolSource {
                tenant_id: tenant_id.to_string(),
                source_id: source_id.to_string(),
            });
            for profile_id in affected_profile_ids {
                events.push(pg_invalidation::InvalidationEvent::Profile { profile_id });
            }
        }
        self.emit_invalidation_events_best_effort(events);

        Ok(res.rows_affected() > 0)
    }

    pub(super) async fn admin_list_secrets(
        &self,
        tenant_id: &str,
    ) -> anyhow::Result<Vec<TenantSecretMetadata>> {
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

    pub(super) async fn admin_put_secret(
        &self,
        tenant_id: &str,
        name: &str,
        value: &str,
    ) -> anyhow::Result<()> {
        let cipher = &self.secrets_cipher;
        let mut nonce = [0u8; 24];
        fill_random_bytes(&mut nonce)
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

        let events = vec![pg_invalidation::InvalidationEvent::TenantSecret {
            tenant_id: tenant_id.to_string(),
            name: Some(name.to_string()),
        }];
        self.emit_invalidation_events_best_effort(events);
        Ok(())
    }

    pub(super) async fn admin_delete_secret(
        &self,
        tenant_id: &str,
        name: &str,
    ) -> anyhow::Result<bool> {
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

        if res.rows_affected() > 0 {
            let events = vec![pg_invalidation::InvalidationEvent::TenantSecret {
                tenant_id: tenant_id.to_string(),
                name: Some(name.to_string()),
            }];
            self.emit_invalidation_events_best_effort(events);
        }
        Ok(res.rows_affected() > 0)
    }

    pub(super) async fn admin_get_tenant_transport_limits(
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

    pub(super) async fn admin_put_tenant_transport_limits(
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
}
