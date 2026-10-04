# Gateway

The Gateway combines HTTP/OpenAPI tools and remote MCP servers behind a profile
endpoint: `/{profile_id}/mcp`. Each profile controls its sources, authentication,
and tool policies. The optional Adapter publishes stdio MCP servers over HTTP.

## Getting started

- [Docker quickstart](../../README.md#try-it-locally)
- [Kubernetes deployment](../deploy/HELM.md)
- [Upgrading to v1](V1_UPGRADE.md)
- [Web UI](../ui/INDEX.md)
- [Client CLI and compact MCP proxy](../unrelated-cli/README.md)

## Configuration and operation

- [Authentication](DATA_PLANE_AUTH.md): API keys and OAuth, with per-profile access rules.
- [MCP proxying](MCP_PROXYING.md): aggregation, routing, subscriptions, and protocol compatibility.
- [MCP settings](MCP_SETTINGS.md): capabilities, notifications, upstream trust, and transport limits.
- [Tenant sources and secrets](MODE3_TENANT_OVERLAY.md): isolated HTTP/OpenAPI sources and credentials.
- [Audit logging](AUDIT.md): event capture, retention, and tenant audit settings.
- [Outbound HTTP safety](OUTBOUND_HTTP_SAFETY.md): allowed destinations and SSRF protection.
- [Performance](PERFORMANCE.md): concurrency, workload measurement, and development benchmarks.
- [Admin CLI](../gateway-cli/INDEX.md): tenant, upstream, and profile administration.
- [Architecture](ARCHITECTURE.md): storage, session routing, and deployment behavior.

## Deployment modes

**File configuration (Mode 1)** serves profiles from a read-only configuration
file. **Shared configuration (Mode 3)** stores configuration in PostgreSQL and
provides admin and tenant APIs, the Web UI, and audit logging. Mode 3 can run on
Docker or Kubernetes and can use multiple Gateway replicas.

Replicas must share session keys and configuration. Routing tokens allow a client
request to reach the correct upstream through another Gateway replica; they do
not preserve a stateful upstream's sessions after that upstream restarts.

## Compatibility boundaries

- Native MCP `2026-07-28` is opt-in per profile and requires compatible remote
  upstreams. Adapter and compact stdio proxy connections use the legacy lifecycle.
- Tool allowlists do not restrict resources or prompts. Configure their availability
  separately with [resource and prompt overrides](MODE3_TENANT_OVERLAY.md#resource-and-prompt-overrides).
- Routing tokens have a lifetime but no individual revocation list. Authentication
  is still checked on each request.
