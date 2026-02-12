use crate::store::TransportLimitsSettings;
use serde_json::Value;

// Process-safe defaults. These apply when neither the profile nor tenant configured a value.
pub const DEFAULT_MAX_POST_BODY_BYTES: u64 = 4 * 1024 * 1024; // 4 MiB
pub const DEFAULT_MAX_SSE_EVENT_BYTES: u64 = 8 * 1024 * 1024; // 8 MiB

// Absolute hard caps to prevent misconfiguration and protect the process.
pub const HARD_MAX_POST_BODY_BYTES: u64 = 32 * 1024 * 1024; // 32 MiB
pub const HARD_MAX_SSE_EVENT_BYTES: u64 = 32 * 1024 * 1024; // 32 MiB

pub const HARD_MAX_JSON_DEPTH: u32 = 512;
pub const HARD_MAX_JSON_ARRAY_LEN: u32 = 1_000_000;
pub const HARD_MAX_JSON_OBJECT_KEYS: u32 = 1_000_000;
pub const HARD_MAX_JSON_STRING_BYTES: u64 = 32 * 1024 * 1024; // 32 MiB

#[derive(Debug, Clone, Copy)]
#[allow(clippy::struct_field_names)]
pub struct EffectiveTransportLimits {
    pub max_post_body_bytes: u64,
    pub max_sse_event_bytes: u64,

    pub max_json_depth: Option<u32>,
    pub max_json_array_len: Option<u32>,
    pub max_json_object_keys: Option<u32>,
    pub max_json_string_bytes: Option<u64>,
}

impl EffectiveTransportLimits {
    pub fn from_profile_and_tenant(
        profile: &TransportLimitsSettings,
        tenant: Option<&TransportLimitsSettings>,
    ) -> Self {
        let max_post_body_bytes = pick_u64(
            profile.max_post_body_bytes,
            tenant.and_then(|t| t.max_post_body_bytes),
            DEFAULT_MAX_POST_BODY_BYTES,
            HARD_MAX_POST_BODY_BYTES,
        );
        let max_sse_event_bytes = pick_u64(
            profile.max_sse_event_bytes,
            tenant.and_then(|t| t.max_sse_event_bytes),
            DEFAULT_MAX_SSE_EVENT_BYTES,
            HARD_MAX_SSE_EVENT_BYTES,
        );

        Self {
            max_post_body_bytes,
            max_sse_event_bytes,
            max_json_depth: pick_u32_opt(
                profile.max_json_depth,
                tenant.and_then(|t| t.max_json_depth),
                HARD_MAX_JSON_DEPTH,
            ),
            max_json_array_len: pick_u32_opt(
                profile.max_json_array_len,
                tenant.and_then(|t| t.max_json_array_len),
                HARD_MAX_JSON_ARRAY_LEN,
            ),
            max_json_object_keys: pick_u32_opt(
                profile.max_json_object_keys,
                tenant.and_then(|t| t.max_json_object_keys),
                HARD_MAX_JSON_OBJECT_KEYS,
            ),
            max_json_string_bytes: pick_u64_opt(
                profile.max_json_string_bytes,
                tenant.and_then(|t| t.max_json_string_bytes),
                HARD_MAX_JSON_STRING_BYTES,
            ),
        }
    }

    #[must_use]
    pub fn has_json_complexity_limits(&self) -> bool {
        self.max_json_depth.is_some()
            || self.max_json_array_len.is_some()
            || self.max_json_object_keys.is_some()
            || self.max_json_string_bytes.is_some()
    }
}

fn pick_u64(profile: Option<u64>, tenant: Option<u64>, default: u64, hard_max: u64) -> u64 {
    profile.or(tenant).unwrap_or(default).clamp(1, hard_max)
}

fn pick_u64_opt(profile: Option<u64>, tenant: Option<u64>, hard_max: u64) -> Option<u64> {
    profile.or(tenant).map(|v| v.clamp(1, hard_max))
}

fn pick_u32_opt(profile: Option<u32>, tenant: Option<u32>, hard_max: u32) -> Option<u32> {
    profile.or(tenant).map(|v| v.clamp(1, hard_max))
}

pub fn validate_transport_limits_settings(
    limits: &TransportLimitsSettings,
) -> Result<(), &'static str> {
    if let Some(v) = limits.max_post_body_bytes
        && (v == 0 || v > HARD_MAX_POST_BODY_BYTES)
    {
        return Err("maxPostBodyBytes must be between 1 and 33554432");
    }
    if let Some(v) = limits.max_sse_event_bytes
        && (v == 0 || v > HARD_MAX_SSE_EVENT_BYTES)
    {
        return Err("maxSseEventBytes must be between 1 and 33554432");
    }

    if let Some(v) = limits.max_json_depth
        && (v == 0 || v > HARD_MAX_JSON_DEPTH)
    {
        return Err("maxJsonDepth must be between 1 and 512");
    }
    if let Some(v) = limits.max_json_array_len
        && (v == 0 || v > HARD_MAX_JSON_ARRAY_LEN)
    {
        return Err("maxJsonArrayLen must be between 1 and 1000000");
    }
    if let Some(v) = limits.max_json_object_keys
        && (v == 0 || v > HARD_MAX_JSON_OBJECT_KEYS)
    {
        return Err("maxJsonObjectKeys must be between 1 and 1000000");
    }
    if let Some(v) = limits.max_json_string_bytes
        && (v == 0 || v > HARD_MAX_JSON_STRING_BYTES)
    {
        return Err("maxJsonStringBytes must be between 1 and 33554432");
    }

    Ok(())
}

#[derive(Debug, Clone)]
pub struct JsonComplexityViolation {
    pub kind: &'static str,
    pub observed: u64,
    pub limit: u64,
}

pub fn check_json_complexity(
    v: &Value,
    limits: EffectiveTransportLimits,
) -> Option<JsonComplexityViolation> {
    if !limits.has_json_complexity_limits() {
        return None;
    }

    fn walk(
        v: &Value,
        depth: u32,
        max_depth: &mut u32,
        max_array_len: &mut u32,
        max_object_keys: &mut u32,
        max_string_bytes: &mut u64,
    ) {
        *max_depth = (*max_depth).max(depth);
        match v {
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
            Value::String(s) => {
                *max_string_bytes = (*max_string_bytes).max(s.len() as u64);
            }
            Value::Array(xs) => {
                *max_array_len = (*max_array_len).max(u32::try_from(xs.len()).unwrap_or(u32::MAX));
                for x in xs {
                    walk(
                        x,
                        depth.saturating_add(1),
                        max_depth,
                        max_array_len,
                        max_object_keys,
                        max_string_bytes,
                    );
                }
            }
            Value::Object(map) => {
                *max_object_keys =
                    (*max_object_keys).max(u32::try_from(map.len()).unwrap_or(u32::MAX));
                for (_k, x) in map {
                    walk(
                        x,
                        depth.saturating_add(1),
                        max_depth,
                        max_array_len,
                        max_object_keys,
                        max_string_bytes,
                    );
                }
            }
        }
    }

    let mut max_depth: u32 = 0;
    let mut max_array_len: u32 = 0;
    let mut max_object_keys: u32 = 0;
    let mut max_string_bytes: u64 = 0;

    walk(
        v,
        1,
        &mut max_depth,
        &mut max_array_len,
        &mut max_object_keys,
        &mut max_string_bytes,
    );

    if let Some(limit) = limits.max_json_depth
        && u64::from(max_depth) > u64::from(limit)
    {
        return Some(JsonComplexityViolation {
            kind: "maxJsonDepth",
            observed: u64::from(max_depth),
            limit: u64::from(limit),
        });
    }
    if let Some(limit) = limits.max_json_array_len
        && u64::from(max_array_len) > u64::from(limit)
    {
        return Some(JsonComplexityViolation {
            kind: "maxJsonArrayLen",
            observed: u64::from(max_array_len),
            limit: u64::from(limit),
        });
    }
    if let Some(limit) = limits.max_json_object_keys
        && u64::from(max_object_keys) > u64::from(limit)
    {
        return Some(JsonComplexityViolation {
            kind: "maxJsonObjectKeys",
            observed: u64::from(max_object_keys),
            limit: u64::from(limit),
        });
    }
    if let Some(limit) = limits.max_json_string_bytes
        && max_string_bytes > limit
    {
        return Some(JsonComplexityViolation {
            kind: "maxJsonStringBytes",
            observed: max_string_bytes,
            limit,
        });
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn base_effective_limits() -> EffectiveTransportLimits {
        EffectiveTransportLimits {
            max_post_body_bytes: DEFAULT_MAX_POST_BODY_BYTES,
            max_sse_event_bytes: DEFAULT_MAX_SSE_EVENT_BYTES,
            max_json_depth: None,
            max_json_array_len: None,
            max_json_object_keys: None,
            max_json_string_bytes: None,
        }
    }

    #[test]
    fn effective_limits_apply_profile_then_tenant_then_defaults() {
        let profile = TransportLimitsSettings {
            max_post_body_bytes: Some(128),
            max_sse_event_bytes: None,
            max_json_depth: None,
            max_json_array_len: Some(10),
            max_json_object_keys: None,
            max_json_string_bytes: None,
        };
        let tenant = TransportLimitsSettings {
            max_post_body_bytes: Some(256),
            max_sse_event_bytes: Some(512),
            max_json_depth: Some(6),
            max_json_array_len: Some(20),
            max_json_object_keys: Some(30),
            max_json_string_bytes: Some(64),
        };

        let limits = EffectiveTransportLimits::from_profile_and_tenant(&profile, Some(&tenant));
        assert_eq!(limits.max_post_body_bytes, 128);
        assert_eq!(limits.max_sse_event_bytes, 512);
        assert_eq!(limits.max_json_depth, Some(6));
        assert_eq!(limits.max_json_array_len, Some(10));
        assert_eq!(limits.max_json_object_keys, Some(30));
        assert_eq!(limits.max_json_string_bytes, Some(64));
    }

    #[test]
    fn effective_limits_clamp_to_hard_bounds() {
        let profile = TransportLimitsSettings {
            max_post_body_bytes: Some(0),
            max_sse_event_bytes: Some(HARD_MAX_SSE_EVENT_BYTES + 1),
            max_json_depth: Some(0),
            max_json_array_len: Some(HARD_MAX_JSON_ARRAY_LEN + 1),
            max_json_object_keys: Some(HARD_MAX_JSON_OBJECT_KEYS + 1),
            max_json_string_bytes: Some(HARD_MAX_JSON_STRING_BYTES + 1),
        };

        let limits = EffectiveTransportLimits::from_profile_and_tenant(&profile, None);
        assert_eq!(limits.max_post_body_bytes, 1);
        assert_eq!(limits.max_sse_event_bytes, HARD_MAX_SSE_EVENT_BYTES);
        assert_eq!(limits.max_json_depth, Some(1));
        assert_eq!(limits.max_json_array_len, Some(HARD_MAX_JSON_ARRAY_LEN));
        assert_eq!(limits.max_json_object_keys, Some(HARD_MAX_JSON_OBJECT_KEYS));
        assert_eq!(limits.max_json_string_bytes, Some(HARD_MAX_JSON_STRING_BYTES));
    }

    #[test]
    fn has_json_complexity_limits_detects_when_limits_are_set() {
        let none = base_effective_limits();
        assert!(!none.has_json_complexity_limits());

        let mut some = base_effective_limits();
        some.max_json_depth = Some(4);
        assert!(some.has_json_complexity_limits());
    }

    #[test]
    fn validate_transport_limits_settings_rejects_invalid_values() {
        let mut limits = TransportLimitsSettings::default();
        assert!(validate_transport_limits_settings(&limits).is_ok());

        limits.max_post_body_bytes = Some(0);
        assert_eq!(
            validate_transport_limits_settings(&limits),
            Err("maxPostBodyBytes must be between 1 and 33554432")
        );

        limits = TransportLimitsSettings::default();
        limits.max_json_depth = Some(HARD_MAX_JSON_DEPTH + 1);
        assert_eq!(
            validate_transport_limits_settings(&limits),
            Err("maxJsonDepth must be between 1 and 512")
        );
    }

    #[test]
    fn check_json_complexity_noop_when_no_complexity_limits_enabled() {
        let payload = json!({"k": [{"nested": "value"}]});
        assert!(check_json_complexity(&payload, base_effective_limits()).is_none());
    }

    #[test]
    fn check_json_complexity_reports_depth_violations() {
        let mut limits = base_effective_limits();
        limits.max_json_depth = Some(2);
        let payload = json!({"a": {"b": 1}});

        let vio = check_json_complexity(&payload, limits).expect("depth violation");
        assert_eq!(vio.kind, "maxJsonDepth");
        assert_eq!(vio.observed, 3);
        assert_eq!(vio.limit, 2);
    }

    #[test]
    fn check_json_complexity_reports_array_length_violations() {
        let mut limits = base_effective_limits();
        limits.max_json_array_len = Some(2);
        let payload = json!([1, 2, 3]);

        let vio = check_json_complexity(&payload, limits).expect("array len violation");
        assert_eq!(vio.kind, "maxJsonArrayLen");
        assert_eq!(vio.observed, 3);
        assert_eq!(vio.limit, 2);
    }

    #[test]
    fn check_json_complexity_reports_object_key_violations() {
        let mut limits = base_effective_limits();
        limits.max_json_object_keys = Some(2);
        let payload = json!({"a": 1, "b": 2, "c": 3});

        let vio = check_json_complexity(&payload, limits).expect("object keys violation");
        assert_eq!(vio.kind, "maxJsonObjectKeys");
        assert_eq!(vio.observed, 3);
        assert_eq!(vio.limit, 2);
    }

    #[test]
    fn check_json_complexity_reports_string_size_violations() {
        let mut limits = base_effective_limits();
        limits.max_json_string_bytes = Some(3);
        let payload = json!("abcd");

        let vio = check_json_complexity(&payload, limits).expect("string bytes violation");
        assert_eq!(vio.kind, "maxJsonStringBytes");
        assert_eq!(vio.observed, 4);
        assert_eq!(vio.limit, 3);
    }
}
