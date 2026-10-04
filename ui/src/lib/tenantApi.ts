import { tenantRoutes, bffRoute } from "@/src/lib/gatewayRoutes";
import {
  createProfileUpdater,
  createProfileWriteQueue,
  type ProfileRevision,
} from "./profile-updates";
import type { ToolSourceDetail } from "./tool-source-updates";
import { tenantFetchJson } from "@/src/lib/tenantFetch";
import type {
  ApiKeyMetadata,
  CreateApiKeyResponse,
  TenantAuditSettings,
  TenantTransportLimitsSettings,
  AuditEventsResponse,
  ToolCallStatsByApiKeyResponse,
  ToolCallStatsByToolResponse,
  Profile,
  ProfileAuditSettings,
  ProfileAuditSettingsResponse,
  ToolSourceSummary,
} from "@/src/lib/types";

export type Upstream = {
  id: string;
  owner: "tenant" | "global" | string;
  enabled: boolean;
  networkClass: UpstreamNetworkClass;
  endpoints: {
    id: string;
    url: string;
    enabled: boolean;
    lifecycle: UpstreamEndpointLifecycle;
    auth?: AuthConfig | null;
  }[];
};

export type ListUpstreamsResponse = { upstreams: Upstream[] };

export type UpstreamEndpointLifecycle = "active" | "draining" | "disabled";
export type UpstreamNetworkClass = "external" | "cluster-internal-managed";

export type UpstreamEndpointActivity = {
  endpointId: string;
  activeSessions: number;
  lastSeenUnix: number | null;
};

export type UpstreamSessionActivity = {
  upstreamId: string;
  ttlSecs: number;
  generatedAtUnix: number;
  endpoints: UpstreamEndpointActivity[];
};

export type ManagedMcpDeployable = {
  id: string;
  displayName: string;
  description?: string | null;
  image: string;
  defaultUpstreamUrl: string;
  enabled: boolean;
};

export type ManagedMcpDeploymentStatus = "pending" | "reconciling" | "ready" | "failed";

export type ManagedMcpDeploymentRequest = {
  id: string;
  tenantId: string;
  deployableId: string;
  desiredEnabled: boolean;
  desiredReplicas: number;
  status: ManagedMcpDeploymentStatus;
  upstreamId?: string | null;
  message?: string | null;
  createdAtUnix: number;
  updatedAtUnix: number;
};

export type AuthConfig =
  | { type: "none" }
  | { type: "bearer"; token: string }
  | { type: "header"; name: string; value: string }
  | { type: "basic"; username: string; password: string }
  | { type: "query"; name: string; value: string };

export type CreateProfileResponse = {
  id: string;
  ok?: boolean;
  dataPlanePath?: string;
  data_plane_path?: string;
};

export type ProfileSurface = {
  profileId: string;
  generatedAtUnix: number;
  sources: {
    kind: string;
    sourceId: string;
    ok: boolean;
    error?: string | null;
    toolsCount: number;
    resourcesCount: number;
    promptsCount: number;
  }[];
  tools: { name: string; description?: string | null }[];
  allTools: {
    sourceId: string;
    name: string;
    baseName: string;
    originalName: string;
    enabled: boolean;
    originalParams: string[];
    originalDescription?: string | null;
    description?: string | null;
  }[];
  resources: { uri: string; name?: string | null }[];
  prompts: { name: string; description?: string | null }[];
};

export type OpenApiInspectResponse = {
  title?: string | null;
  inferredBaseUrl: string;
  suggestedId: string;
  tools: { name: string; description?: string | null }[];
};

export type ValidateSourceIdResponse = { ok: boolean; error?: string | null };

export async function listUpstreams(): Promise<ListUpstreamsResponse> {
  return await tenantFetchJson<ListUpstreamsResponse>(bffRoute(tenantRoutes.UPSTREAMS), {
    cache: "no-store",
  });
}

export async function getUpstream(id: string): Promise<Upstream> {
  return await tenantFetchJson<Upstream>(bffRoute(tenantRoutes.UPSTREAM(id)), {
    cache: "no-store",
  });
}

export async function putUpstream(
  id: string,
  body: {
    enabled: boolean;
    endpoints: {
      id: string;
      url: string;
      enabled?: boolean;
      lifecycle?: UpstreamEndpointLifecycle;
      auth?: AuthConfig;
    }[];
  },
): Promise<unknown> {
  return await tenantFetchJson(bffRoute(tenantRoutes.UPSTREAM(id)), {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

export async function patchUpstreamEndpoint(
  upstreamId: string,
  endpointId: string,
  body: { enabled?: boolean; lifecycle?: UpstreamEndpointLifecycle },
): Promise<unknown> {
  return await tenantFetchJson(bffRoute(tenantRoutes.ENDPOINT(upstreamId, endpointId)), {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

export async function deleteUpstreamEndpoint(
  upstreamId: string,
  endpointId: string,
): Promise<void> {
  await tenantFetchJson(bffRoute(tenantRoutes.ENDPOINT(upstreamId, endpointId)), {
    method: "DELETE",
  });
}

export async function getUpstreamSessionActivity(
  upstreamId: string,
  ttlSecs?: number,
): Promise<UpstreamSessionActivity> {
  const sp = new URLSearchParams();
  if (ttlSecs != null) sp.set("ttlSecs", String(ttlSecs));
  const qs = sp.toString();
  return await tenantFetchJson<UpstreamSessionActivity>(
    `${bffRoute(tenantRoutes.UPSTREAM_ACTIVITY(upstreamId))}${qs ? `?${qs}` : ""}`,
    {
      cache: "no-store",
    },
  );
}

export async function listManagedMcpDeployables(): Promise<{
  deployables: ManagedMcpDeployable[];
}> {
  return await tenantFetchJson<{ deployables: ManagedMcpDeployable[] }>(
    bffRoute(tenantRoutes.DEPLOYABLES),
    {
      cache: "no-store",
    },
  );
}

export async function createManagedMcpDeploymentRequest(
  deployableId: string,
): Promise<{ request: ManagedMcpDeploymentRequest }> {
  return await tenantFetchJson<{ request: ManagedMcpDeploymentRequest }>(
    bffRoute(tenantRoutes.DEPLOYMENTS),
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ deployableId }),
    },
  );
}

export async function listManagedMcpDeploymentRequests(): Promise<{
  requests: ManagedMcpDeploymentRequest[];
}> {
  return await tenantFetchJson<{ requests: ManagedMcpDeploymentRequest[] }>(
    bffRoute(tenantRoutes.DEPLOYMENTS),
    {
      cache: "no-store",
    },
  );
}

export async function getManagedMcpDeploymentRequest(
  requestId: string,
): Promise<{ request: ManagedMcpDeploymentRequest }> {
  return await tenantFetchJson<{ request: ManagedMcpDeploymentRequest }>(
    bffRoute(tenantRoutes.DEPLOYMENT(requestId)),
    {
      cache: "no-store",
    },
  );
}

export async function updateManagedMcpDeploymentRequest(
  requestId: string,
  body: { enabled?: boolean; replicas?: number },
): Promise<{ request: ManagedMcpDeploymentRequest }> {
  return await tenantFetchJson<{ request: ManagedMcpDeploymentRequest }>(
    bffRoute(tenantRoutes.DEPLOYMENT(requestId)),
    {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    },
  );
}

export async function deleteUpstream(id: string): Promise<void> {
  await tenantFetchJson(bffRoute(tenantRoutes.UPSTREAM(id)), { method: "DELETE" });
}

export type UpstreamSurface = {
  upstreamId: string;
  generatedAtUnix: number;
  sources: {
    kind: string;
    sourceId: string;
    ok: boolean;
    error?: string | null;
    toolsCount: number;
    resourcesCount: number;
    promptsCount: number;
  }[];
  tools: { name: string; description?: string | null }[];
  resources: { uri: string; name?: string | null }[];
  prompts: { name: string; description?: string | null }[];
};

export async function probeUpstreamSurface(id: string): Promise<UpstreamSurface> {
  return await tenantFetchJson<UpstreamSurface>(bffRoute(tenantRoutes.UPSTREAM_SURFACE(id)), {
    cache: "no-store",
  });
}

export async function listProfiles(): Promise<{ profiles: Profile[] }> {
  return await tenantFetchJson<{ profiles: Profile[] }>(bffRoute(tenantRoutes.PROFILES), {
    cache: "no-store",
  });
}

export async function getProfile(id: string): Promise<Profile> {
  return await tenantFetchJson<Profile>(bffRoute(tenantRoutes.PROFILE(id)), {
    cache: "no-store",
  });
}

export async function createProfile(body: unknown): Promise<CreateProfileResponse> {
  return await tenantFetchJson<CreateProfileResponse>(bffRoute(tenantRoutes.PROFILES), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

async function putProfile(id: string, body: unknown): Promise<unknown> {
  return await tenantFetchJson(bffRoute(tenantRoutes.PROFILE(id)), {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

const profileWriteQueue = createProfileWriteQueue({ read: getProfile });
export const updateProfile = createProfileUpdater({
  read: getProfile,
  write: putProfile,
  queue: profileWriteQueue,
});

export async function getProfileAuditSettings(id: string): Promise<ProfileAuditSettingsResponse> {
  return tenantFetchJson(bffRoute(tenantRoutes.PROFILE_AUDIT(id)), { cache: "no-store" });
}

export function updateProfileAuditSettings(
  profile: ProfileRevision,
  settings: ProfileAuditSettings,
): Promise<void> {
  const auditSettings = structuredClone(settings);
  return profileWriteQueue(profile, (current) =>
    tenantFetchJson(bffRoute(tenantRoutes.PROFILE_AUDIT(profile.id)), {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ auditSettings, expectedRevision: current.revision }),
    }),
  );
}

export async function deleteProfile(id: string): Promise<void> {
  await tenantFetchJson(bffRoute(tenantRoutes.PROFILE(id)), { method: "DELETE" });
}

export async function probeProfileSurface(id: string): Promise<ProfileSurface> {
  return await tenantFetchJson<ProfileSurface>(bffRoute(tenantRoutes.PROFILE_SURFACE(id)), {
    cache: "no-store",
  });
}

export type ConnectionCheck = {
  sourceId: string;
  endpointId?: string;
  status: "passed" | "failed" | "notChecked";
  message: string;
  protocolVersion?: string;
};

export async function checkProfileConnections(id: string): Promise<{ checks: ConnectionCheck[] }> {
  return tenantFetchJson(bffRoute(tenantRoutes.PROFILE_CONNECTIONS(id)), { method: "POST" });
}

export async function listToolSources(): Promise<{ sources: ToolSourceSummary[] }> {
  return await tenantFetchJson<{ sources: ToolSourceSummary[] }>(
    bffRoute(tenantRoutes.TOOL_SOURCES),
    {
      cache: "no-store",
    },
  );
}

export async function getToolSource(id: string): Promise<ToolSourceDetail> {
  return await tenantFetchJson<ToolSourceDetail>(bffRoute(tenantRoutes.TOOL_SOURCE(id)), {
    cache: "no-store",
  });
}

export async function listToolSourceTools(
  id: string,
): Promise<{ tools: { name: string; description?: string | null }[] }> {
  return await tenantFetchJson<{ tools: { name: string; description?: string | null }[] }>(
    bffRoute(tenantRoutes.TOOL_SOURCE_TOOLS(id)),
    { cache: "no-store" },
  );
}

export async function putToolSource(id: string, bodyJson: string): Promise<unknown> {
  return await tenantFetchJson(bffRoute(tenantRoutes.TOOL_SOURCE(id)), {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: bodyJson,
  });
}

export async function deleteToolSource(id: string): Promise<void> {
  await tenantFetchJson(bffRoute(tenantRoutes.TOOL_SOURCE(id)), { method: "DELETE" });
}

export async function openapiInspect(
  specUrl: string,
  auth?: AuthConfig,
): Promise<OpenApiInspectResponse> {
  return await tenantFetchJson<OpenApiInspectResponse>(bffRoute(tenantRoutes.OPENAPI_INSPECT), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ specUrl, auth }),
  });
}

export async function validateSourceId(id: string): Promise<ValidateSourceIdResponse> {
  return await tenantFetchJson<ValidateSourceIdResponse>(
    bffRoute(tenantRoutes.VALIDATE_SOURCE_ID),
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id }),
    },
  );
}

export async function listSecrets(): Promise<{ secrets: { name: string }[] }> {
  return await tenantFetchJson<{ secrets: { name: string }[] }>(bffRoute(tenantRoutes.SECRETS), {
    cache: "no-store",
  });
}

export async function createSecret(body: unknown): Promise<unknown> {
  return await tenantFetchJson(bffRoute(tenantRoutes.SECRETS), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

export async function deleteSecret(name: string): Promise<void> {
  await tenantFetchJson(bffRoute(tenantRoutes.SECRET(name)), { method: "DELETE" });
}

export async function listApiKeys(): Promise<ApiKeyMetadata[]> {
  const json = await tenantFetchJson<{ apiKeys?: ApiKeyMetadata[]; api_keys?: ApiKeyMetadata[] }>(
    bffRoute(tenantRoutes.API_KEYS),
    { cache: "no-store" },
  );
  return (json.apiKeys ?? json.api_keys ?? []) as ApiKeyMetadata[];
}

export async function createApiKey(body: unknown): Promise<CreateApiKeyResponse> {
  return await tenantFetchJson<CreateApiKeyResponse>(bffRoute(tenantRoutes.API_KEYS), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

export async function revokeApiKey(id: string): Promise<void> {
  await tenantFetchJson(bffRoute(tenantRoutes.API_KEY(id)), { method: "DELETE" });
}

export async function getTenantAuditSettings(): Promise<TenantAuditSettings> {
  return await tenantFetchJson<TenantAuditSettings>(bffRoute(tenantRoutes.AUDIT_SETTINGS), {
    cache: "no-store",
  });
}

export async function putTenantAuditSettings(body: TenantAuditSettings): Promise<{ ok: boolean }> {
  return await tenantFetchJson<{ ok: boolean }>(bffRoute(tenantRoutes.AUDIT_SETTINGS), {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

export async function getTenantTransportLimits(): Promise<TenantTransportLimitsSettings> {
  return await tenantFetchJson<TenantTransportLimitsSettings>(
    bffRoute(tenantRoutes.TRANSPORT_LIMITS),
    {
      cache: "no-store",
    },
  );
}

export async function putTenantTransportLimits(
  body: TenantTransportLimitsSettings,
): Promise<{ ok: boolean }> {
  return await tenantFetchJson<{ ok: boolean }>(bffRoute(tenantRoutes.TRANSPORT_LIMITS), {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

export async function listAuditEvents(params: {
  fromUnixSecs?: number;
  toUnixSecs?: number;
  beforeId?: number;
  profileId?: string;
  apiKeyId?: string;
  toolRef?: string;
  action?: string;
  ok?: boolean;
  limit?: number;
}): Promise<AuditEventsResponse> {
  const sp = new URLSearchParams();
  if (params.fromUnixSecs != null) sp.set("fromUnixSecs", String(params.fromUnixSecs));
  if (params.toUnixSecs != null) sp.set("toUnixSecs", String(params.toUnixSecs));
  if (params.beforeId != null) sp.set("beforeId", String(params.beforeId));
  if (params.profileId) sp.set("profileId", params.profileId);
  if (params.apiKeyId) sp.set("apiKeyId", params.apiKeyId);
  if (params.toolRef) sp.set("toolRef", params.toolRef);
  if (params.action) sp.set("action", params.action);
  if (params.ok != null) sp.set("ok", params.ok ? "true" : "false");
  if (params.limit != null) sp.set("limit", String(params.limit));
  const qs = sp.toString();
  return await tenantFetchJson<AuditEventsResponse>(
    `${bffRoute(tenantRoutes.AUDIT_EVENTS)}${qs ? `?${qs}` : ""}`,
    {
      cache: "no-store",
    },
  );
}

export async function toolCallStatsByTool(params: {
  fromUnixSecs?: number;
  toUnixSecs?: number;
  profileId?: string;
  apiKeyId?: string;
  toolRef?: string;
  limit?: number;
  offset?: number;
}): Promise<ToolCallStatsByToolResponse> {
  const sp = new URLSearchParams();
  if (params.offset != null) sp.set("offset", String(params.offset));
  if (params.fromUnixSecs != null) sp.set("fromUnixSecs", String(params.fromUnixSecs));
  if (params.toUnixSecs != null) sp.set("toUnixSecs", String(params.toUnixSecs));
  if (params.profileId) sp.set("profileId", params.profileId);
  if (params.apiKeyId) sp.set("apiKeyId", params.apiKeyId);
  if (params.toolRef) sp.set("toolRef", params.toolRef);
  if (params.limit != null) sp.set("limit", String(params.limit));
  const qs = sp.toString();
  return await tenantFetchJson<ToolCallStatsByToolResponse>(
    `${bffRoute(tenantRoutes.AUDIT_BY_TOOL)}${qs ? `?${qs}` : ""}`,
    { cache: "no-store" },
  );
}

export async function toolCallStatsByApiKey(params: {
  fromUnixSecs?: number;
  toUnixSecs?: number;
  profileId?: string;
  apiKeyId?: string;
  toolRef?: string;
  limit?: number;
  offset?: number;
}): Promise<ToolCallStatsByApiKeyResponse> {
  const sp = new URLSearchParams();
  if (params.offset != null) sp.set("offset", String(params.offset));
  if (params.fromUnixSecs != null) sp.set("fromUnixSecs", String(params.fromUnixSecs));
  if (params.toUnixSecs != null) sp.set("toUnixSecs", String(params.toUnixSecs));
  if (params.profileId) sp.set("profileId", params.profileId);
  if (params.apiKeyId) sp.set("apiKeyId", params.apiKeyId);
  if (params.toolRef) sp.set("toolRef", params.toolRef);
  if (params.limit != null) sp.set("limit", String(params.limit));
  const qs = sp.toString();
  return await tenantFetchJson<ToolCallStatsByApiKeyResponse>(
    `${bffRoute(tenantRoutes.AUDIT_BY_API_KEY)}${qs ? `?${qs}` : ""}`,
    { cache: "no-store" },
  );
}
