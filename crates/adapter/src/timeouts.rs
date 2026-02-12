/// Default tool call timeout (seconds) when no env override is provided.
pub const DEFAULT_TOOL_CALL_TIMEOUT_SECS: u64 = 60;

fn read_positive_u64_env(var: &str) -> Option<u64> {
    unrelated_env::positive_u64(var)
}

/// Global maximum allowed timeout for `tools/call` (seconds).
///
/// Shared env vars (Gateway + Adapter):
/// - `UNRELATED_TOOL_CALL_TIMEOUT_MAX_SECS` (preferred)
/// - `UNRELATED_TOOL_CALL_TIMEOUT_SECS` (legacy fallback; sets both default+max)
#[must_use]
pub fn tool_call_timeout_max_secs() -> u64 {
    read_positive_u64_env("UNRELATED_TOOL_CALL_TIMEOUT_MAX_SECS")
        .or_else(|| read_positive_u64_env("UNRELATED_TOOL_CALL_TIMEOUT_SECS"))
        .unwrap_or(DEFAULT_TOOL_CALL_TIMEOUT_SECS)
}

/// Global default timeout for `tools/call` when no per-request budget is provided (seconds).
///
/// Shared env vars (Gateway + Adapter):
/// - `UNRELATED_TOOL_CALL_TIMEOUT_DEFAULT_SECS` (preferred)
/// - `UNRELATED_TOOL_CALL_TIMEOUT_SECS` (legacy fallback; sets both default+max)
///
/// The returned value is always clamped to `tool_call_timeout_max_secs()`.
#[must_use]
pub fn tool_call_timeout_default_secs() -> u64 {
    let max = tool_call_timeout_max_secs();
    let default = read_positive_u64_env("UNRELATED_TOOL_CALL_TIMEOUT_DEFAULT_SECS")
        .or_else(|| read_positive_u64_env("UNRELATED_TOOL_CALL_TIMEOUT_SECS"))
        .unwrap_or(DEFAULT_TOOL_CALL_TIMEOUT_SECS);
    default.min(max).max(1)
}

/// Backward-compatible alias for the maximum timeout cap.
///
/// Prefer `tool_call_timeout_max_secs()` for new code.
#[must_use]
pub fn tool_call_timeout_cap_secs() -> u64 {
    tool_call_timeout_max_secs()
}
