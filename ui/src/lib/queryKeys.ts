export const qk = {
  gatewayStatus: () => ["gatewayStatus"] as const,
  tenantAuditSettings: () => ["tenantAuditSettings"] as const,

  profiles: () => ["profiles"] as const,
  profile: (id: string) => ["profiles", id] as const,
  profileSurface: (id: string) => ["profiles", id, "surface"] as const,

  upstreams: () => ["upstreams"] as const,
  upstream: (id: string) => ["upstreams", id] as const,
  upstreamSurface: (id: string) => ["upstreams", id, "surface"] as const,

  toolSources: () => ["toolSources"] as const,
  toolSource: (id: string) => ["toolSources", id] as const,
  toolSourceTools: (id: string) => ["toolSources", id, "tools"] as const,

  secrets: () => ["secrets"] as const,

  apiKeys: () => ["apiKeys"] as const,
} as const;
