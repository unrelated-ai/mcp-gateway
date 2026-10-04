use crate::ttl_cache::{DEFAULT_CAPACITY, TtlCache};
use parking_lot::RwLock;
use serde_json::Value;
use sqlx::{PgPool, Row as _};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
pub use unrelated_gateway_api::audit::AuditLevel;
use unrelated_gateway_api::audit::ProfileAuditSettings;
use uuid::Uuid;

const SETTINGS_CACHE_TTL: Duration = Duration::from_secs(30);

#[derive(Debug, Clone)]
pub struct AuditEvent {
    pub tenant_id: String,
    pub profile_id: Option<Uuid>,

    pub api_key_id: Option<Uuid>,
    pub oidc_issuer: Option<String>,
    pub oidc_subject: Option<String>,

    pub action: String,

    pub http_method: Option<String>,
    pub http_route: Option<String>,
    pub status_code: Option<i32>,

    pub tool_ref: Option<String>,
    pub tool_name_at_time: Option<String>,

    pub ok: bool,
    pub duration_ms: Option<i64>,
    pub error_kind: Option<String>,
    pub error_message: Option<String>,

    pub meta: Value,
}

#[derive(Debug, Clone, Default)]
pub struct AuditActor {
    pub profile_id: Option<Uuid>,
    pub api_key_id: Option<Uuid>,
    pub oidc_issuer: Option<String>,
    pub oidc_subject: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AuditError {
    pub kind: &'static str,
    pub message: String,
}

impl AuditError {
    pub fn new(kind: &'static str, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
}

pub fn duration_ms(elapsed: Duration) -> Option<i64> {
    i64::try_from(elapsed.as_millis()).ok()
}

#[derive(Debug, Clone)]
pub struct HttpAuditEvent {
    pub tenant_id: String,
    pub actor: AuditActor,
    pub action: &'static str,
    pub http_method: &'static str,
    pub http_route: &'static str,
    pub status_code: i32,
    pub ok: bool,
    pub elapsed: Duration,
    pub meta: Value,
    pub error: Option<AuditError>,
}

pub fn http_event(input: HttpAuditEvent) -> AuditEvent {
    AuditEvent {
        tenant_id: input.tenant_id,
        profile_id: input.actor.profile_id,
        api_key_id: input.actor.api_key_id,
        oidc_issuer: input.actor.oidc_issuer,
        oidc_subject: input.actor.oidc_subject,
        action: input.action.to_string(),
        http_method: Some(input.http_method.to_string()),
        http_route: Some(input.http_route.to_string()),
        status_code: Some(input.status_code),
        tool_ref: None,
        tool_name_at_time: None,
        ok: input.ok,
        duration_ms: duration_ms(input.elapsed),
        error_kind: input.error.as_ref().map(|e| e.kind.to_string()),
        error_message: input.error.map(|e| e.message),
        meta: input.meta,
    }
}

#[derive(Debug, Clone)]
pub struct McpToolsCallAuditEvent {
    pub tenant_id: String,
    pub actor: AuditActor,
    pub tool_ref: Option<String>,
    pub tool_name_at_time: Option<String>,
    pub ok: bool,
    pub elapsed: Duration,
    pub meta: Value,
    pub error: Option<AuditError>,
}

pub fn mcp_tools_call_event(input: McpToolsCallAuditEvent) -> AuditEvent {
    AuditEvent {
        tenant_id: input.tenant_id,
        profile_id: input.actor.profile_id,
        api_key_id: input.actor.api_key_id,
        oidc_issuer: input.actor.oidc_issuer,
        oidc_subject: input.actor.oidc_subject,
        action: "mcp.tools_call".to_string(),
        http_method: None,
        http_route: None,
        status_code: None,
        tool_ref: input.tool_ref,
        tool_name_at_time: input.tool_name_at_time,
        ok: input.ok,
        duration_ms: duration_ms(input.elapsed),
        error_kind: input.error.as_ref().map(|e| e.kind.to_string()),
        error_message: input.error.map(|e| e.message),
        meta: input.meta,
    }
}

fn truncate_string(mut s: String, max_len: usize) -> String {
    if s.len() <= max_len {
        return s;
    }
    s.truncate(s.floor_char_boundary(max_len));
    s
}

fn normalize_meta(mut meta: Value) -> Value {
    if !meta.is_object() {
        meta = Value::Object(serde_json::Map::new());
    }
    meta
}

#[derive(Debug, Clone)]
struct ProfileAuditSettingsCached {
    tenant_id: String,
    settings: ProfileAuditSettings,
}

#[async_trait::async_trait]
pub trait AuditSink: Send + Sync {
    async fn record(&self, event: AuditEvent);

    /// Tenant-level default audit detail level (best-effort; cached when DB-backed).
    ///
    /// Returns `AuditLevel::Off` when audit is disabled for the tenant or when the setting cannot
    /// be loaded.
    async fn tenant_default_level(&self, tenant_id: &str) -> AuditLevel;

    /// Effective policy for profile MCP activity. Control-plane events use tenant defaults.
    async fn profile_level(&self, tenant_id: &str, _profile_id: Option<Uuid>) -> AuditLevel {
        self.tenant_default_level(tenant_id).await
    }

    fn invalidate_profile_settings_cache(&self, _profile_id: &str) {}

    /// Best-effort cache invalidation hook for tenant audit settings.
    ///
    /// Implementations without in-memory tenant-level caches can ignore this.
    fn invalidate_tenant_settings_cache(&self, _tenant_id: &str) {}
}

#[derive(Default)]
pub struct NoopAuditSink;

#[async_trait::async_trait]
impl AuditSink for NoopAuditSink {
    async fn record(&self, _event: AuditEvent) {}

    async fn tenant_default_level(&self, _tenant_id: &str) -> AuditLevel {
        AuditLevel::Off
    }
}

pub struct PostgresAuditSink {
    pool: PgPool,
    sender: mpsc::Sender<AuditEvent>,
    dropped: AtomicU64,
    tenant_cache: TtlCache<(bool, AuditLevel)>,
    profile_cache: TtlCache<ProfileAuditSettingsCached>,
    cache_generation: RwLock<u64>,
}

impl PostgresAuditSink {
    pub fn new(pool: PgPool, shutdown: CancellationToken) -> Arc<Self> {
        let (sender, receiver) = mpsc::channel::<AuditEvent>(10_000);
        let sink = Arc::new(Self {
            pool,
            sender,
            dropped: AtomicU64::new(0),
            tenant_cache: TtlCache::new(SETTINGS_CACHE_TTL, DEFAULT_CAPACITY),
            profile_cache: TtlCache::new(SETTINGS_CACHE_TTL, DEFAULT_CAPACITY),
            cache_generation: RwLock::new(0),
        });
        Self::spawn_worker(sink.clone(), receiver, shutdown);
        sink
    }

    fn spawn_worker(
        sink: Arc<Self>,
        mut rx: mpsc::Receiver<AuditEvent>,
        shutdown: CancellationToken,
    ) {
        tokio::spawn(async move {
            let mut buf: Vec<AuditEvent> = Vec::with_capacity(256);
            let mut tick = tokio::time::interval(Duration::from_millis(250));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                tokio::select! {
                    () = shutdown.cancelled() => {
                        // Best-effort flush then exit.
                        if !buf.is_empty() {
                            sink.flush_batch(&mut buf).await;
                        }
                        break;
                    }
                    maybe = rx.recv() => {
                        let Some(ev) = maybe else {
                            // Sender dropped: flush then exit.
                            if !buf.is_empty() {
                                sink.flush_batch(&mut buf).await;
                            }
                            break;
                        };
                        buf.push(ev);
                        if buf.len() >= 200 {
                            sink.flush_batch(&mut buf).await;
                        }
                    }
                    _ = tick.tick() => {
                        if !buf.is_empty() {
                            sink.flush_batch(&mut buf).await;
                        }
                    }
                }
            }
        });
    }

    async fn tenant_audit_settings(&self, tenant_id: &str) -> (bool, AuditLevel) {
        if let Some(cached) = self.tenant_cache.get(tenant_id) {
            return cached;
        }
        let generation = *self.cache_generation.read();

        // Refresh from DB (best-effort).
        let row = sqlx::query(
            r"
select audit_enabled, audit_default_level
from tenants
where id = $1
",
        )
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await;

        let (enabled, level) = match row {
            Ok(Some(r)) => {
                let enabled: bool = r.try_get("audit_enabled").unwrap_or(false);
                let lvl: String = r
                    .try_get("audit_default_level")
                    .unwrap_or_else(|_| "metadata".to_string());
                (enabled, lvl.parse().unwrap_or_default())
            }
            _ => (false, AuditLevel::Off),
        };

        let current = self.cache_generation.read();
        if generation == *current {
            self.tenant_cache
                .put(tenant_id.to_owned(), (enabled, level));
        }

        (enabled, level)
    }

    async fn profile_audit_settings(
        &self,
        tenant_id: &str,
        profile_id: Uuid,
    ) -> ProfileAuditSettings {
        let key = profile_id.to_string();
        if let Some(cached) = self
            .profile_cache
            .get(&key)
            .filter(|entry| entry.tenant_id == tenant_id)
        {
            return cached.settings;
        }
        let generation = *self.cache_generation.read();
        let value = sqlx::query_scalar::<_, Value>(
            "select audit_settings from profiles where id = $1 and tenant_id = $2",
        )
        .bind(profile_id)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await;
        let settings = match value {
            Ok(Some(value)) => serde_json::from_value(value).unwrap_or_default(),
            _ => ProfileAuditSettings {
                level: Some(AuditLevel::Off),
            },
        };
        let current = self.cache_generation.read();
        if generation == *current {
            self.profile_cache.put(
                key,
                ProfileAuditSettingsCached {
                    tenant_id: tenant_id.to_owned(),
                    settings,
                },
            );
        }
        settings
    }

    async fn flush_batch(&self, buf: &mut Vec<AuditEvent>) {
        // Apply current policy again at flush time, including stripping previously captured samples.
        let mut batch: Vec<AuditEvent> = Vec::with_capacity(buf.len());
        for mut ev in buf.drain(..) {
            let level = if ev.action.starts_with("mcp.") {
                self.profile_level(&ev.tenant_id, ev.profile_id).await
            } else {
                self.tenant_default_level(&ev.tenant_id).await
            };
            if apply_detail_level(&mut ev, level) {
                batch.push(ev);
            }
        }
        if batch.is_empty() {
            return;
        }

        // Insert row-by-row inside a transaction. This is simpler and safe for v1.
        // We can optimize to multi-row insert later if needed.
        let mut tx = match self.pool.begin().await {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!(error = %e, "audit insert: failed to begin transaction");
                return;
            }
        };

        for mut ev in batch {
            ev.meta = normalize_meta(ev.meta);
            ev.error_message = ev.error_message.map(|s| truncate_string(s, 1024));

            let _ = sqlx::query(
                r"
insert into audit_events (
  tenant_id,
  profile_id,
  api_key_id,
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
)
values ($1,
  (select id from profiles where id = $2 and tenant_id = $1),
  (select id from api_keys where id = $3 and tenant_id = $1),
  $4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
",
            )
            .bind(&ev.tenant_id)
            .bind(ev.profile_id)
            .bind(ev.api_key_id)
            .bind(ev.oidc_issuer)
            .bind(ev.oidc_subject)
            .bind(ev.action)
            .bind(ev.http_method)
            .bind(ev.http_route)
            .bind(ev.status_code)
            .bind(ev.tool_ref)
            .bind(ev.tool_name_at_time)
            .bind(ev.ok)
            .bind(ev.duration_ms)
            .bind(ev.error_kind)
            .bind(ev.error_message)
            .bind(ev.meta)
            .execute(&mut *tx)
            .await;
        }

        if let Err(e) = tx.commit().await {
            tracing::warn!(error = %e, "audit insert: commit failed");
        }
    }
}

#[async_trait::async_trait]
impl AuditSink for PostgresAuditSink {
    async fn record(&self, event: AuditEvent) {
        if self.sender.try_send(event).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    async fn tenant_default_level(&self, tenant_id: &str) -> AuditLevel {
        let (enabled, level) = self.tenant_audit_settings(tenant_id).await;
        if enabled { level } else { AuditLevel::Off }
    }

    async fn profile_level(&self, tenant_id: &str, profile_id: Option<Uuid>) -> AuditLevel {
        let (enabled, tenant_level) = self.tenant_audit_settings(tenant_id).await;
        if !enabled || tenant_level == AuditLevel::Off {
            return AuditLevel::Off;
        }
        let settings = match profile_id {
            Some(id) => self.profile_audit_settings(tenant_id, id).await,
            None => ProfileAuditSettings::default(),
        };
        settings.effective_level(enabled, tenant_level)
    }

    fn invalidate_tenant_settings_cache(&self, tenant_id: &str) {
        let mut generation = self.cache_generation.write();
        *generation = generation.wrapping_add(1);
        self.tenant_cache.remove(tenant_id);
    }

    fn invalidate_profile_settings_cache(&self, profile_id: &str) {
        let mut generation = self.cache_generation.write();
        *generation = generation.wrapping_add(1);
        self.profile_cache.remove(profile_id);
    }
}

fn apply_detail_level(event: &mut AuditEvent, level: AuditLevel) -> bool {
    match level {
        AuditLevel::Off => return false,
        AuditLevel::Summary => {
            event.meta = serde_json::json!({});
            event.error_message = None;
        }
        AuditLevel::Metadata => {
            if let Some(meta) = event.meta.as_object_mut() {
                meta.remove("sample");
                meta.remove("sampleTruncated");
            }
        }
        AuditLevel::Payload => {}
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn audit_level_from_db_maps_known_values() {
        assert_eq!("off".parse::<AuditLevel>().unwrap(), AuditLevel::Off);
        assert_eq!(
            "summary".parse::<AuditLevel>().unwrap(),
            AuditLevel::Summary
        );
        assert_eq!(
            "metadata".parse::<AuditLevel>().unwrap(),
            AuditLevel::Metadata
        );
        assert_eq!(
            "payload".parse::<AuditLevel>().unwrap(),
            AuditLevel::Payload
        );
    }

    #[test]
    fn audit_level_from_db_defaults_to_metadata() {
        assert_eq!(
            "nope".parse::<AuditLevel>().unwrap_or_default(),
            AuditLevel::Metadata
        );
        assert_eq!(
            "".parse::<AuditLevel>().unwrap_or_default(),
            AuditLevel::Metadata
        );
    }

    #[test]
    fn duration_ms_converts_small_durations() {
        assert_eq!(duration_ms(Duration::from_millis(0)), Some(0));
        assert_eq!(duration_ms(Duration::from_millis(12)), Some(12));
        assert_eq!(duration_ms(Duration::from_secs(2)), Some(2000));
    }

    #[test]
    fn normalize_meta_turns_non_object_into_empty_object() {
        let out = normalize_meta(Value::String("x".to_string()));
        assert!(out.is_object());
        assert_eq!(out, json!({}));
    }

    #[test]
    fn truncate_string_truncates_to_max_len() {
        let s = "abcdef".to_string();
        assert_eq!(truncate_string(s, 4), "abcd".to_string());
        assert_eq!(truncate_string("café ☕".to_string(), 4), "caf");
        assert_eq!(truncate_string("café ☕".to_string(), 8), "café ");
    }

    #[test]
    fn detail_policy_removes_metadata_and_samples_when_logging_is_reduced() {
        let event = http_event(HttpAuditEvent {
            tenant_id: "t1".into(),
            actor: AuditActor::default(),
            action: "mcp.payload_limit_exceeded",
            http_method: "POST",
            http_route: "/{profile_id}/mcp",
            status_code: 413,
            ok: false,
            elapsed: Duration::from_millis(3),
            meta: json!({"limit":128, "sample":"sensitive sample", "sampleTruncated":true}),
            error: Some(AuditError::new("payload_limit_exceeded", "details")),
        });
        let mut payload = event.clone();
        assert!(apply_detail_level(&mut payload, AuditLevel::Payload));
        assert_eq!(payload.meta, event.meta);
        // Recheck a previously collected payload against a stricter current policy.
        assert!(apply_detail_level(&mut payload, AuditLevel::Metadata));
        assert_eq!(payload.meta, json!({"limit":128}));
        assert_eq!(payload.error_message.as_deref(), Some("details"));
        assert!(apply_detail_level(&mut payload, AuditLevel::Summary));
        assert_eq!(payload.meta, json!({}));
        assert_eq!(payload.error_message, None);
        assert_eq!(
            payload.error_kind.as_deref(),
            Some("payload_limit_exceeded")
        );
        assert_eq!(payload.duration_ms, Some(3));
        assert!(!apply_detail_level(&mut payload, AuditLevel::Off));
    }

    #[test]
    fn http_event_populates_fields() {
        let profile_uuid = Uuid::new_v4();
        let api_key_uuid = Uuid::new_v4();

        let ev = http_event(HttpAuditEvent {
            tenant_id: "t1".to_string(),
            actor: AuditActor {
                profile_id: Some(profile_uuid),
                api_key_id: Some(api_key_uuid),
                oidc_issuer: Some("iss".to_string()),
                oidc_subject: Some("sub".to_string()),
            },
            action: "admin.secret_put",
            http_method: "PUT",
            http_route: "/admin/v1/tenants/{tenant_id}/secrets/{name}",
            status_code: 200,
            ok: true,
            elapsed: Duration::from_millis(7),
            meta: json!({"k":"v"}),
            error: None,
        });

        assert_eq!(ev.tenant_id, "t1");
        assert_eq!(ev.profile_id, Some(profile_uuid));
        assert_eq!(ev.api_key_id, Some(api_key_uuid));
        assert_eq!(ev.oidc_issuer.as_deref(), Some("iss"));
        assert_eq!(ev.oidc_subject.as_deref(), Some("sub"));
        assert_eq!(ev.action, "admin.secret_put");
        assert_eq!(ev.http_method.as_deref(), Some("PUT"));
        assert_eq!(
            ev.http_route.as_deref(),
            Some("/admin/v1/tenants/{tenant_id}/secrets/{name}")
        );
        assert_eq!(ev.status_code, Some(200));
        assert!(ev.ok);
        assert_eq!(ev.duration_ms, Some(7));
        assert_eq!(ev.error_kind, None);
        assert_eq!(ev.error_message, None);
        assert_eq!(ev.meta, json!({"k":"v"}));
    }

    #[test]
    fn mcp_tools_call_event_populates_fields() {
        let profile_uuid = Uuid::new_v4();
        let ev = mcp_tools_call_event(McpToolsCallAuditEvent {
            tenant_id: "t1".to_string(),
            actor: AuditActor {
                profile_id: Some(profile_uuid),
                ..AuditActor::default()
            },
            tool_ref: Some("s1:orig_tool".to_string()),
            tool_name_at_time: Some("tool".to_string()),
            ok: false,
            elapsed: Duration::from_millis(3),
            meta: json!({"reason":"nope"}),
            error: Some(AuditError::new("invalid_params", "bad args")),
        });

        assert_eq!(ev.tenant_id, "t1");
        assert_eq!(ev.action, "mcp.tools_call");
        assert_eq!(ev.profile_id, Some(profile_uuid));
        assert_eq!(ev.http_method, None);
        assert_eq!(ev.tool_ref.as_deref(), Some("s1:orig_tool"));
        assert_eq!(ev.tool_name_at_time.as_deref(), Some("tool"));
        assert!(!ev.ok);
        assert_eq!(ev.duration_ms, Some(3));
        assert_eq!(ev.error_kind.as_deref(), Some("invalid_params"));
        assert_eq!(ev.error_message.as_deref(), Some("bad args"));
        assert_eq!(ev.meta, json!({"reason":"nope"}));
    }
}
