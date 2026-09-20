import type { Profile } from "@/src/lib/types";

export type PutProfileBody = {
  expectedRevision: number;
  name: string;
  description: string | null;
  enabled: boolean;
  allowPartialUpstreams: boolean;
  upstreams: string[];
  sources: string[];
  transforms: unknown;
  tools: string[];
  dataPlaneAuth: Profile["dataPlaneAuth"];
  dataPlaneLimits: Profile["dataPlaneLimits"];
  toolCallTimeoutSecs: number | null;
  toolPolicies: Profile["toolPolicies"];
  mcp: Profile["mcp"];
};

/**
 * Build a full PUT body for `/api/tenant/profiles/:id`.
 *
 * We intentionally send a complete shape to avoid accidental field resets when
 * multiple panels update different parts of the profile.
 */
export function buildPutProfileBody(
  profile: Profile,
  overrides: Partial<Omit<PutProfileBody, "expectedRevision">> = {},
): PutProfileBody {
  return {
    name: profile.name,
    description: profile.description ?? null,
    enabled: profile.enabled,
    allowPartialUpstreams: profile.allowPartialUpstreams,
    upstreams: profile.upstreams,
    sources: profile.sources,
    transforms: profile.transforms,
    tools: profile.tools,
    dataPlaneAuth: profile.dataPlaneAuth,
    dataPlaneLimits: profile.dataPlaneLimits,
    toolCallTimeoutSecs: profile.toolCallTimeoutSecs ?? null,
    toolPolicies: profile.toolPolicies ?? [],
    mcp: profile.mcp,
    ...overrides,
    expectedRevision: profile.revision,
  };
}
