// UI fallbacks for the Gateway defaults in crates/gateway/src/transport_limits.rs.
// Tenant and profile values returned by the API take precedence.
export const BYTES_PER_MIB = 1024 * 1024;
export const DEFAULT_MAX_POST_BODY_BYTES = 4 * BYTES_PER_MIB;
export const DEFAULT_MAX_SSE_EVENT_BYTES = 8 * BYTES_PER_MIB;
export const TRANSPORT_LIMIT_PRESETS_MIB = [1, 4, 8, 16, 32] as const;
