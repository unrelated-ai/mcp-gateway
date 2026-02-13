use crate::store::DataPlaneAuthMode;
use crate::timeouts::tool_call_timeout_max_secs;
use crate::tool_policy::ToolPolicy;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub(crate) enum NullableString {
    Null,
    Value(String),
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(untagged)]
pub(crate) enum NullableU64 {
    Null,
    Value(u64),
}

pub(crate) fn resolve_nullable_u64(req: Option<NullableU64>, existing: Option<u64>) -> Option<u64> {
    match req {
        None => existing,
        Some(NullableU64::Null) => None,
        Some(NullableU64::Value(v)) => Some(v),
    }
}

pub(crate) const fn default_data_plane_auth_mode() -> DataPlaneAuthMode {
    DataPlaneAuthMode::ApiKeyInitializeOnly
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DataPlaneAuthSettings {
    #[serde(default = "default_data_plane_auth_mode")]
    pub(crate) mode: DataPlaneAuthMode,
    #[serde(default)]
    pub(crate) accept_x_api_key: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DataPlaneLimitsSettings {
    #[serde(default)]
    pub(crate) rate_limit_enabled: bool,
    #[serde(default)]
    pub(crate) rate_limit_tool_calls_per_minute: Option<i64>,
    #[serde(default)]
    pub(crate) quota_enabled: bool,
    #[serde(default)]
    pub(crate) quota_tool_calls: Option<i64>,
}

impl DataPlaneLimitsSettings {
    pub(crate) fn validate(&self) -> Result<(), &'static str> {
        if self.rate_limit_enabled {
            let Some(v) = self.rate_limit_tool_calls_per_minute else {
                return Err(
                    "rateLimitToolCallsPerMinute is required when rateLimitEnabled is true",
                );
            };
            if v <= 0 {
                return Err("rateLimitToolCallsPerMinute must be > 0");
            }
        }
        if self.quota_enabled {
            let Some(v) = self.quota_tool_calls else {
                return Err("quotaToolCalls is required when quotaEnabled is true");
            };
            if v <= 0 {
                return Err("quotaToolCalls must be > 0");
            }
        }
        Ok(())
    }
}

pub(crate) fn validate_tool_timeout_and_policies(
    tool_call_timeout_secs: Option<u64>,
    tool_policies: &[ToolPolicy],
) -> Result<(), String> {
    let max = tool_call_timeout_max_secs();
    if let Some(secs) = tool_call_timeout_secs {
        if secs == 0 {
            return Err("toolCallTimeoutSecs must be > 0".to_string());
        }
        if secs > max {
            return Err(format!("toolCallTimeoutSecs must be <= {max}"));
        }
    }

    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for p in tool_policies {
        if p.tool.trim().is_empty() {
            return Err("toolPolicies[].tool is required".to_string());
        }
        if !seen.insert(p.tool.clone()) {
            return Err("toolPolicies contains duplicate tool entries".to_string());
        }
        if let Some(secs) = p.timeout_secs {
            if secs == 0 {
                return Err("toolPolicies[].timeoutSecs must be > 0".to_string());
            }
            if secs > max {
                return Err(format!("toolPolicies[].timeoutSecs must be <= {max}"));
            }
        }
        if let Some(r) = p.retry.as_ref() {
            if r.maximum_attempts == 0 {
                return Err("toolPolicies[].retry.maximumAttempts must be >= 1".to_string());
            }
            if r.initial_interval_ms == 0 {
                return Err("toolPolicies[].retry.initialIntervalMs must be > 0".to_string());
            }
            if !(r.backoff_coefficient.is_finite() && r.backoff_coefficient >= 1.0) {
                return Err("toolPolicies[].retry.backoffCoefficient must be >= 1.0".to_string());
            }
            if let Some(max_ms) = r.maximum_interval_ms
                && max_ms == 0
            {
                return Err(
                    "toolPolicies[].retry.maximumIntervalMs must be > 0 when set".to_string(),
                );
            }
        }
    }

    Ok(())
}

pub(crate) fn validate_tool_allowlist(tools: &[String]) -> Result<(), String> {
    if tools.is_empty() {
        // No allowlist configured.
        return Ok(());
    }

    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for raw in tools {
        let entry = raw.trim();
        if entry.is_empty() {
            return Err("tools entries must be non-empty".to_string());
        }
        if entry == "*" {
            return Err("tools: wildcard '*' is no longer supported; use explicit '<source_id>:<original_tool_name>' entries".to_string());
        }
        let Some((src, name)) = entry.split_once(':') else {
            return Err("tools entries must be '<source_id>:<original_tool_name>'".to_string());
        };
        if src.trim().is_empty() || name.trim().is_empty() {
            return Err("tools entries must be '<source_id>:<original_tool_name>'".to_string());
        }
        if !seen.insert(entry.to_string()) {
            return Err("tools contains duplicate entries".to_string());
        }
    }
    Ok(())
}
