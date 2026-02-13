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
  ToolSourceSummary,
} from "@/src/lib/types";

export type Upstream = {
  id: string;
  owner: "tenant" | "global" | string;
  enabled: boolean;
  endpoints: { id: string; url: string; enabled: boolean; auth?: AuthConfig | null }[];
};

export type ListUpstreamsResponse = { upstreams: Upstream[] };

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
  return await tenantFetchJson<ListUpstreamsResponse>("/api/tenant/upstreams", {
    cache: "no-store",
  });
}

export async function getUpstream(id: string): Promise<Upstream> {
  return await tenantFetchJson<Upstream>(`/api/tenant/upstreams/${encodeURIComponent(id)}`, {
    cache: "no-store",
  });
}

export async function putUpstream(
  id: string,
  body: { enabled: boolean; endpoints: { id: string; url: string; auth?: AuthConfig }[] },
): Promise<unknown> {
  return await tenantFetchJson(`/api/tenant/upstreams/${encodeURIComponent(id)}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

export async function deleteUpstream(id: string): Promise<void> {
  await tenantFetchJson(`/api/tenant/upstreams/${encodeURIComponent(id)}`, { method: "DELETE" });
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
  return await tenantFetchJson<UpstreamSurface>(
    `/api/tenant/upstreams/${encodeURIComponent(id)}/surface`,
    {
      cache: "no-store",
    },
  );
}

export async function listProfiles(): Promise<{ profiles: Profile[] }> {
  return await tenantFetchJson<{ profiles: Profile[] }>("/api/tenant/profiles", {
    cache: "no-store",
  });
}

export async function getProfile(id: string): Promise<Profile> {
  return await tenantFetchJson<Profile>(`/api/tenant/profiles/${encodeURIComponent(id)}`, {
    cache: "no-store",
  });
}

export async function createProfile(body: unknown): Promise<CreateProfileResponse> {
  return await tenantFetchJson<CreateProfileResponse>("/api/tenant/profiles", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

export async function putProfile(id: string, body: unknown): Promise<unknown> {
  return await tenantFetchJson(`/api/tenant/profiles/${encodeURIComponent(id)}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

export async function deleteProfile(id: string): Promise<void> {
  await tenantFetchJson(`/api/tenant/profiles/${encodeURIComponent(id)}`, { method: "DELETE" });
}

export async function probeProfileSurface(id: string): Promise<ProfileSurface> {
  return await tenantFetchJson<ProfileSurface>(
    `/api/tenant/profiles/${encodeURIComponent(id)}/surface`,
    {
      cache: "no-store",
    },
  );
}

export async function listToolSources(): Promise<{ sources: ToolSourceSummary[] }> {
  return await tenantFetchJson<{ sources: ToolSourceSummary[] }>("/api/tenant/tool-sources", {
    cache: "no-store",
  });
}

export async function getToolSource(
  id: string,
): Promise<{ type: string; enabled: boolean; spec?: Record<string, unknown> }> {
  return await tenantFetchJson<{ type: string; enabled: boolean; spec?: Record<string, unknown> }>(
    `/api/tenant/tool-sources/${encodeURIComponent(id)}`,
    { cache: "no-store" },
  );
}

export async function listToolSourceTools(
  id: string,
): Promise<{ tools: { name: string; description?: string | null }[] }> {
  return await tenantFetchJson<{ tools: { name: string; description?: string | null }[] }>(
    `/api/tenant/tool-sources/${encodeURIComponent(id)}/tools`,
    { cache: "no-store" },
  );
}

export async function putToolSource(id: string, bodyJson: string): Promise<unknown> {
  return await tenantFetchJson(`/api/tenant/tool-sources/${encodeURIComponent(id)}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: bodyJson,
  });
}

export async function deleteToolSource(id: string): Promise<void> {
  await tenantFetchJson(`/api/tenant/tool-sources/${encodeURIComponent(id)}`, { method: "DELETE" });
}

export async function openapiInspect(specUrl: string): Promise<OpenApiInspectResponse> {
  return await tenantFetchJson<OpenApiInspectResponse>("/api/tenant/tool-sources/openapi/inspect", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ specUrl }),
  });
}

export async function validateSourceId(id: string): Promise<ValidateSourceIdResponse> {
  return await tenantFetchJson<ValidateSourceIdResponse>("/api/tenant/tool-sources/validate-id", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ id }),
  });
}

export async function listSecrets(): Promise<{ secrets: { name: string }[] }> {
  return await tenantFetchJson<{ secrets: { name: string }[] }>("/api/tenant/secrets", {
    cache: "no-store",
  });
}

export async function createSecret(body: unknown): Promise<unknown> {
  return await tenantFetchJson("/api/tenant/secrets", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

export async function deleteSecret(name: string): Promise<void> {
  await tenantFetchJson(`/api/tenant/secrets/${encodeURIComponent(name)}`, { method: "DELETE" });
}

export async function listApiKeys(): Promise<ApiKeyMetadata[]> {
  const json = await tenantFetchJson<{ apiKeys?: ApiKeyMetadata[]; api_keys?: ApiKeyMetadata[] }>(
    "/api/tenant/api-keys",
    { cache: "no-store" },
  );
  return (json.apiKeys ?? json.api_keys ?? []) as ApiKeyMetadata[];
}

export async function createApiKey(body: unknown): Promise<CreateApiKeyResponse> {
  return await tenantFetchJson<CreateApiKeyResponse>("/api/tenant/api-keys", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

export async function revokeApiKey(id: string): Promise<void> {
  await tenantFetchJson(`/api/tenant/api-keys/${encodeURIComponent(id)}`, { method: "DELETE" });
}

export async function getTenantAuditSettings(): Promise<TenantAuditSettings> {
  return await tenantFetchJson<TenantAuditSettings>("/api/tenant/audit/settings", {
    cache: "no-store",
  });
}

export async function putTenantAuditSettings(body: TenantAuditSettings): Promise<{ ok: boolean }> {
  return await tenantFetchJson<{ ok: boolean }>("/api/tenant/audit/settings", {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

export async function getTenantTransportLimits(): Promise<TenantTransportLimitsSettings> {
  return await tenantFetchJson<TenantTransportLimitsSettings>("/api/tenant/transport/limits", {
    cache: "no-store",
  });
}

export async function putTenantTransportLimits(
  body: TenantTransportLimitsSettings,
): Promise<{ ok: boolean }> {
  return await tenantFetchJson<{ ok: boolean }>("/api/tenant/transport/limits", {
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
    `/api/tenant/audit/events${qs ? `?${qs}` : ""}`,
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
}): Promise<ToolCallStatsByToolResponse> {
  const sp = new URLSearchParams();
  if (params.fromUnixSecs != null) sp.set("fromUnixSecs", String(params.fromUnixSecs));
  if (params.toUnixSecs != null) sp.set("toUnixSecs", String(params.toUnixSecs));
  if (params.profileId) sp.set("profileId", params.profileId);
  if (params.apiKeyId) sp.set("apiKeyId", params.apiKeyId);
  if (params.toolRef) sp.set("toolRef", params.toolRef);
  if (params.limit != null) sp.set("limit", String(params.limit));
  const qs = sp.toString();
  return await tenantFetchJson<ToolCallStatsByToolResponse>(
    `/api/tenant/audit/analytics/tool-calls/by-tool${qs ? `?${qs}` : ""}`,
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
}): Promise<ToolCallStatsByApiKeyResponse> {
  const sp = new URLSearchParams();
  if (params.fromUnixSecs != null) sp.set("fromUnixSecs", String(params.fromUnixSecs));
  if (params.toUnixSecs != null) sp.set("toUnixSecs", String(params.toUnixSecs));
  if (params.profileId) sp.set("profileId", params.profileId);
  if (params.apiKeyId) sp.set("apiKeyId", params.apiKeyId);
  if (params.toolRef) sp.set("toolRef", params.toolRef);
  if (params.limit != null) sp.set("limit", String(params.limit));
  const qs = sp.toString();
  return await tenantFetchJson<ToolCallStatsByApiKeyResponse>(
    `/api/tenant/audit/analytics/tool-calls/by-api-key${qs ? `?${qs}` : ""}`,
    { cache: "no-store" },
  );
}
