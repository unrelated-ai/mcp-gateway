export type DataPlaneAuthMode =
  | "disabled"
  | "apiKeyInitializeOnly"
  | "apiKeyEveryRequest"
  | "jwtEveryRequest";

export type DataPlaneAuthSettings = {
  mode: DataPlaneAuthMode;
  acceptXApiKey: boolean;
};

export type DataPlaneLimitsSettings = {
  rateLimitEnabled: boolean;
  rateLimitToolCallsPerMinute?: number | null;
  quotaEnabled: boolean;
  quotaToolCalls?: number | null;
};

export type RetryPolicy = {
  /** Maximum number of attempts, including the initial attempt (1 => no retries). */
  maximumAttempts: number;
  /** Initial backoff interval in milliseconds (before the first retry). */
  initialIntervalMs: number;
  /** Backoff multiplier (typically >= 1.0). */
  backoffCoefficient: number;
  /** Optional maximum interval between retries in milliseconds. */
  maximumIntervalMs?: number | null;
  /** Optional list of error category strings that should not be retried. */
  nonRetryableErrorTypes?: string[];
};

export type ToolPolicy = {
  /** Stable tool reference in the form `"<source_id>:<original_tool_name>"`. */
  tool: string;
  /** Optional per-tool timeout override (seconds). */
  timeoutSecs?: number | null;
  /** Optional per-tool retry policy. */
  retry?: RetryPolicy | null;
};

export type McpCapability =
  | "logging"
  | "completions"
  | "resources-subscribe"
  | "tools-list-changed"
  | "resources-list-changed"
  | "prompts-list-changed";

export type McpCapabilitiesPolicy = {
  /** If non-empty, acts as an allowlist overriding defaults. */
  allow: McpCapability[];
  /** Denylist applied after defaults / allowlist. */
  deny: McpCapability[];
};

export type McpNotificationFilter = {
  /** If non-empty, only notifications with these methods are forwarded. */
  allow: string[];
  /** Notifications with these methods are dropped. */
  deny: string[];
};

export type RequestIdNamespacing = "opaque" | "readable";
export type SseEventIdNamespacing = "upstream-slash" | "none";

export type McpNamespacing = {
  requestId: RequestIdNamespacing;
  sseEventId: SseEventIdNamespacing;
};

export type UpstreamClientCapabilitiesMode = "passthrough" | "strip" | "allowlist";
export type McpPolicyAction = "allow" | "deny";

export type McpServerRequestFilter = {
  defaultAction: McpPolicyAction;
  allow: string[];
  deny: string[];
};

export type UpstreamSecurityPolicy = {
  clientCapabilitiesMode: UpstreamClientCapabilitiesMode;
  /**
   * For `clientCapabilitiesMode = "allowlist"`, only these top-level capability keys are forwarded
   * upstream (e.g. `sampling`, `roots`, `elicitation`).
   */
  clientCapabilitiesAllow: string[];
  /** Filter for upstream server→client JSON-RPC request methods forwarded downstream. */
  serverRequests: McpServerRequestFilter;
  /** If true, replace downstream `clientInfo` before sending `initialize` upstream (privacy). */
  rewriteClientInfo: boolean;
};

export type McpSecuritySettings = {
  signedProxiedRequestIds: boolean;
  upstreamDefault: UpstreamSecurityPolicy;
  upstreamOverrides: Record<string, UpstreamSecurityPolicy>;
};

export type McpProfileSettings = {
  capabilities: McpCapabilitiesPolicy;
  notifications: McpNotificationFilter;
  namespacing: McpNamespacing;
  security: McpSecuritySettings;
};

// NOTE: For v0 design work, we intentionally keep advanced fields loosely typed.
export type Profile = {
  id: string;
  name: string;
  description?: string | null;
  tenantId: string;
  enabled: boolean;
  allowPartialUpstreams: boolean;
  upstreams: string[];
  sources: string[];
  transforms: unknown;
  tools: string[];
  dataPlanePath: string;
  dataPlaneAuth: DataPlaneAuthSettings;
  dataPlaneLimits: DataPlaneLimitsSettings;
  toolCallTimeoutSecs?: number | null;
  toolPolicies: ToolPolicy[];
  mcp: McpProfileSettings;
};

export type ProfilesResponse = { profiles: Profile[] };

export type ToolSourceSummary = { id: string; type: "http" | "openapi" | string; enabled: boolean };
export type ToolSourcesResponse = { sources: ToolSourceSummary[] };

export type TenantSecretMetadata = { name: string };
export type SecretsResponse = { secrets: TenantSecretMetadata[] };

export type ApiKeyMetadata = {
  id: string;
  name: string;
  prefix: string;
  profileId: string | null;
  revokedAtUnix: number | null;
  lastUsedAtUnix: number | null;
  totalToolCallsAttempted: number;
  totalRequestsAttempted: number;
  createdAtUnix: number;
};

export type ApiKeysResponse = { apiKeys: ApiKeyMetadata[] };

export type CreateApiKeyRequest = {
  name?: string;
  profileId?: string;
};

export type CreateApiKeyResponse = {
  ok: boolean;
  id: string;
  secret: string;
  prefix: string;
  profileId: string | null;
};

export type TenantAuditSettings = {
  enabled: boolean;
  retentionDays: number;
  defaultLevel: "off" | "summary" | "metadata" | "payload" | string;
};

export type AuditEventRow = {
  id: number;
  tsUnixSecs: number;
  tenantId: string;
  profileId: string | null;
  apiKeyId: string | null;
  oidcIssuer: string | null;
  oidcSubject: string | null;
  action: string;
  httpMethod: string | null;
  httpRoute: string | null;
  statusCode: number | null;
  toolRef: string | null;
  toolNameAtTime: string | null;
  ok: boolean;
  durationMs: number | null;
  errorKind: string | null;
  errorMessage: string | null;
  meta: unknown;
};

export type AuditEventsResponse = { events: AuditEventRow[] };

export type ToolCallStatsByTool = {
  toolRef: string;
  total: number;
  ok: number;
  err: number;
  avgDurationMs: number | null;
  p95DurationMs: number | null;
  p99DurationMs: number | null;
  maxDurationMs: number | null;
};

export type ToolCallStatsByApiKey = {
  apiKeyId: string;
  total: number;
  ok: number;
  err: number;
  avgDurationMs: number | null;
  p95DurationMs: number | null;
  p99DurationMs: number | null;
  maxDurationMs: number | null;
};

export type ToolCallStatsByToolResponse = { items: ToolCallStatsByTool[] };
export type ToolCallStatsByApiKeyResponse = { items: ToolCallStatsByApiKey[] };
