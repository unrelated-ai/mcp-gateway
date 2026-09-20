// Gateway and BFF paths share these builders. Identifiers are always one URL segment.
function segment(value: string): string {
  if (!value || value === "." || value === "..") throw new Error("Invalid route parameter");
  return encodeURIComponent(value);
}

export function bffRoute(path: string): string {
  const prefix = "/tenant/v1";
  if (!path.startsWith(prefix + "/")) throw new Error("Expected a tenant Gateway route");
  return "/api/tenant" + path.slice(prefix.length);
}

export const tenantRoutes = {
  UPSTREAMS: "/tenant/v1/upstreams",
  UPSTREAM: (upstream_id: string) => `/tenant/v1/upstreams/${segment(upstream_id)}`,
  ENDPOINT: (upstream_id: string, endpoint_id: string) =>
    `/tenant/v1/upstreams/${segment(upstream_id)}/endpoints/${segment(endpoint_id)}`,
  UPSTREAM_SURFACE: (upstream_id: string) => `/tenant/v1/upstreams/${segment(upstream_id)}/surface`,
  UPSTREAM_ACTIVITY: (upstream_id: string) =>
    `/tenant/v1/upstreams/${segment(upstream_id)}/session-activity`,
  TOOL_SOURCES: "/tenant/v1/tool-sources",
  TOOL_SOURCE: (source_id: string) => `/tenant/v1/tool-sources/${segment(source_id)}`,
  TOOL_SOURCE_TOOLS: (source_id: string) => `/tenant/v1/tool-sources/${segment(source_id)}/tools`,
  OPENAPI_INSPECT: "/tenant/v1/tool-sources/openapi/inspect",
  VALIDATE_SOURCE_ID: "/tenant/v1/tool-sources/validate-id",
  SECRETS: "/tenant/v1/secrets",
  SECRET: (name: string) => `/tenant/v1/secrets/${segment(name)}`,
  API_KEYS: "/tenant/v1/api-keys",
  API_KEY: (api_key_id: string) => `/tenant/v1/api-keys/${segment(api_key_id)}`,
  AUDIT_SETTINGS: "/tenant/v1/audit/settings",
  TRANSPORT_LIMITS: "/tenant/v1/transport/limits",
  AUDIT_EVENTS: "/tenant/v1/audit/events",
  AUDIT_BY_TOOL: "/tenant/v1/audit/analytics/tool-calls/by-tool",
  AUDIT_BY_API_KEY: "/tenant/v1/audit/analytics/tool-calls/by-api-key",
  PROFILES: "/tenant/v1/profiles",
  PROFILE: (profile_id: string) => `/tenant/v1/profiles/${segment(profile_id)}`,
  PROFILE_SURFACE: (profile_id: string) => `/tenant/v1/profiles/${segment(profile_id)}/surface`,
  DEPLOYABLES: "/tenant/v1/managed-mcp/deployables",
  DEPLOYMENTS: "/tenant/v1/managed-mcp/deployments",
  DEPLOYMENT: (request_id: string) => `/tenant/v1/managed-mcp/deployments/${segment(request_id)}`,
} as const;

export const bootstrapRoutes = {
  TENANT: "/bootstrap/v1/tenant",
  STATUS: "/bootstrap/v1/tenant/status",
} as const;
