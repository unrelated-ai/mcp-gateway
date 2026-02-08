import type {
  McpCapability,
  McpNotificationFilter,
  McpPolicyAction,
  McpProfileSettings,
  McpSecuritySettings,
  McpServerRequestFilter,
  McpNamespacing,
  UpstreamClientCapabilitiesMode,
  UpstreamSecurityPolicy,
} from "@/src/lib/types";

export const ALL_MCP_CAPABILITIES: McpCapability[] = [
  "logging",
  "completions",
  "resources-subscribe",
  "tools-list-changed",
  "resources-list-changed",
  "prompts-list-changed",
];

export const INTERACTIVE_REQUEST_METHODS = [
  "sampling/createMessage",
  "roots/list",
  "elicitation/create",
] as const;

export type InteractiveRequestMethod = (typeof INTERACTIVE_REQUEST_METHODS)[number];

function uniqStrings(xs: unknown[]): string[] {
  return [...new Set(xs.map((x) => String(x).trim()).filter(Boolean))].sort((a, b) =>
    a.localeCompare(b),
  );
}

function normalizeRequestFilter(f: McpServerRequestFilter): McpServerRequestFilter {
  return {
    defaultAction: f.defaultAction,
    allow: uniqStrings(f.allow),
    deny: uniqStrings(f.deny),
  };
}

export function trustedUpstreamPolicy(): UpstreamSecurityPolicy {
  return {
    clientCapabilitiesMode: "passthrough",
    clientCapabilitiesAllow: [],
    rewriteClientInfo: false,
    serverRequests: {
      defaultAction: "allow",
      allow: [],
      deny: [],
    },
  };
}

export function untrustedUpstreamPolicy(): UpstreamSecurityPolicy {
  return {
    clientCapabilitiesMode: "strip",
    clientCapabilitiesAllow: [],
    rewriteClientInfo: true,
    serverRequests: {
      defaultAction: "deny",
      allow: [],
      deny: [],
    },
  };
}

export function defaultSecuritySettings(): McpSecuritySettings {
  return {
    signedProxiedRequestIds: true,
    upstreamDefault: trustedUpstreamPolicy(),
    upstreamOverrides: {},
  };
}

export function defaultMcpSettings(): McpProfileSettings {
  return {
    capabilities: { allow: [], deny: [] },
    notifications: { allow: [], deny: [] },
    namespacing: { requestId: "opaque", sseEventId: "upstream-slash" },
    security: defaultSecuritySettings(),
  };
}

function asPolicyAction(v: unknown): McpPolicyAction | null {
  if (v === "allow" || v === "deny") return v;
  return null;
}

function asClientCapsMode(v: unknown): UpstreamClientCapabilitiesMode | null {
  if (v === "passthrough" || v === "strip" || v === "allowlist") return v;
  return null;
}

function asRequestFilter(input: unknown): McpServerRequestFilter {
  const d = defaultSecuritySettings().upstreamDefault.serverRequests;
  const obj = typeof input === "object" && input !== null ? (input as Record<string, unknown>) : {};
  const allow = Array.isArray(obj.allow) ? (obj.allow as unknown[]).map((x) => String(x)) : [];
  const deny = Array.isArray(obj.deny) ? (obj.deny as unknown[]).map((x) => String(x)) : [];
  return normalizeRequestFilter({
    defaultAction: asPolicyAction(obj.defaultAction) ?? d.defaultAction,
    allow,
    deny,
  });
}

function asUpstreamSecurityPolicy(input: unknown): UpstreamSecurityPolicy {
  const d = trustedUpstreamPolicy();
  const obj = typeof input === "object" && input !== null ? (input as Record<string, unknown>) : {};

  return {
    clientCapabilitiesMode:
      asClientCapsMode(obj.clientCapabilitiesMode) ?? d.clientCapabilitiesMode,
    clientCapabilitiesAllow: uniqStrings(
      Array.isArray(obj.clientCapabilitiesAllow) ? (obj.clientCapabilitiesAllow as unknown[]) : [],
    ),
    rewriteClientInfo:
      typeof obj.rewriteClientInfo === "boolean" ? obj.rewriteClientInfo : d.rewriteClientInfo,
    serverRequests: asRequestFilter(obj.serverRequests),
  };
}

function normalizeNotificationFilter(f: McpNotificationFilter): McpNotificationFilter {
  return {
    allow: uniqStrings(f.allow),
    deny: uniqStrings(f.deny),
  };
}

function normalizeNamespacing(n: McpNamespacing): McpNamespacing {
  return {
    requestId: n.requestId === "readable" || n.requestId === "opaque" ? n.requestId : "opaque",
    sseEventId:
      n.sseEventId === "none" || n.sseEventId === "upstream-slash"
        ? n.sseEventId
        : "upstream-slash",
  };
}

export function normalizeMcpSettings(s: McpProfileSettings): McpProfileSettings {
  const order = new Map<McpCapability, number>(ALL_MCP_CAPABILITIES.map((c, i) => [c, i]));
  const uniqSortedCaps = (xs: McpCapability[]): McpCapability[] =>
    [...new Set(xs)].sort((a, b) => (order.get(a) ?? 0) - (order.get(b) ?? 0));

  const upstreamOverrides: Record<string, UpstreamSecurityPolicy> = {};
  for (const [k, v] of Object.entries(s.security.upstreamOverrides ?? {})) {
    upstreamOverrides[String(k)] = asUpstreamSecurityPolicy(v);
  }

  return {
    capabilities: {
      allow: uniqSortedCaps(s.capabilities.allow),
      deny: uniqSortedCaps(s.capabilities.deny),
    },
    notifications: normalizeNotificationFilter(s.notifications),
    namespacing: normalizeNamespacing(s.namespacing),
    security: {
      signedProxiedRequestIds: !!s.security.signedProxiedRequestIds,
      upstreamDefault: asUpstreamSecurityPolicy(s.security.upstreamDefault),
      upstreamOverrides,
    },
  };
}

export function asMcpSettings(input: unknown): McpProfileSettings {
  const d = defaultMcpSettings();
  const obj = typeof input === "object" && input !== null ? (input as Record<string, unknown>) : {};

  // Capabilities.
  const capsObj =
    typeof obj.capabilities === "object" && obj.capabilities !== null
      ? (obj.capabilities as Record<string, unknown>)
      : {};
  const allowCaps = Array.isArray(capsObj.allow) ? (capsObj.allow as unknown[]) : [];
  const denyCaps = Array.isArray(capsObj.deny) ? (capsObj.deny as unknown[]) : [];
  const pickCap = (v: unknown): v is McpCapability =>
    typeof v === "string" && (ALL_MCP_CAPABILITIES.includes(v as McpCapability) as boolean);

  // Notifications.
  const notifsObj =
    typeof obj.notifications === "object" && obj.notifications !== null
      ? (obj.notifications as Record<string, unknown>)
      : {};
  const allowNotifs = Array.isArray(notifsObj.allow) ? (notifsObj.allow as unknown[]) : [];
  const denyNotifs = Array.isArray(notifsObj.deny) ? (notifsObj.deny as unknown[]) : [];

  // Namespacing.
  const nsObj =
    typeof obj.namespacing === "object" && obj.namespacing !== null
      ? (obj.namespacing as Record<string, unknown>)
      : {};
  const requestId = nsObj.requestId;
  const sseEventId = nsObj.sseEventId;

  // Security.
  const secObj =
    typeof obj.security === "object" && obj.security !== null
      ? (obj.security as Record<string, unknown>)
      : {};
  const upstreamOverridesObj =
    typeof secObj.upstreamOverrides === "object" && secObj.upstreamOverrides !== null
      ? (secObj.upstreamOverrides as Record<string, unknown>)
      : {};

  const upstreamOverrides: Record<string, UpstreamSecurityPolicy> = {};
  for (const [k, v] of Object.entries(upstreamOverridesObj)) {
    upstreamOverrides[String(k)] = asUpstreamSecurityPolicy(v);
  }

  return normalizeMcpSettings({
    capabilities: {
      allow: allowCaps.filter(pickCap),
      deny: denyCaps.filter(pickCap),
    },
    notifications: {
      allow: allowNotifs as unknown as string[],
      deny: denyNotifs as unknown as string[],
    },
    namespacing: {
      requestId:
        requestId === "readable" || requestId === "opaque" ? requestId : d.namespacing.requestId,
      sseEventId:
        sseEventId === "none" || sseEventId === "upstream-slash"
          ? sseEventId
          : d.namespacing.sseEventId,
    },
    security: {
      signedProxiedRequestIds:
        typeof secObj.signedProxiedRequestIds === "boolean"
          ? secObj.signedProxiedRequestIds
          : d.security.signedProxiedRequestIds,
      upstreamDefault: asUpstreamSecurityPolicy(secObj.upstreamDefault),
      upstreamOverrides,
    },
  });
}

export function allowsServerRequest(policy: UpstreamSecurityPolicy, method: string): boolean {
  const f = policy.serverRequests;
  if (f.deny.includes(method)) return false;
  if (f.allow.includes(method)) return true;
  return f.defaultAction === "allow";
}
