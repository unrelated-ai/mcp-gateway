# Documentation Index (workspace)

This repository ships **MCP infrastructure** for turning existing systems into MCP servers and serving them safely at scale:

- **Adapter**: expose HTTP/OpenAPI/stdio MCP as a single MCP server over streamable HTTP (`/mcp`)
- **Gateway**: expose tenant-owned “virtual MCP servers” (`/{profile_id}/mcp`) that proxy and aggregate upstream MCP sources (typically Adapters), with data-plane auth and policy
- **Admin tooling**: CLI (operator workflows) + Web UI (tenant workflows)

## Why use this

Common use cases:

- **Expose an existing HTTP API as MCP tools** without rewriting it as an MCP server.
- **Publish stdio MCP servers over streamable HTTP** (run the server as a child process; clients connect over HTTP).
- **Aggregate tool surfaces** from multiple upstreams into a single MCP endpoint (with collision handling).
- **Multi-tenant MCP gateway**: isolate tenants, issue API keys, configure per-profile tool allowlists/transforms, and enforce per-tool timeouts/retries.

## Components (start here)

- **Adapter (implemented)**: [`docs/adapter/INDEX.md`](adapter/INDEX.md)
  - Config reference: [`docs/adapter/CONFIG.md`](adapter/CONFIG.md)
  - Running & testing: [`docs/adapter/TESTING.md`](adapter/TESTING.md)
- **Gateway (beta)**: [`docs/gateway/INDEX.md`](gateway/INDEX.md)
  - MCP proxying & aggregation behavior: [`docs/gateway/MCP_PROXYING.md`](gateway/MCP_PROXYING.md)
  - Data-plane auth (API keys + OIDC/JWT): [`docs/gateway/DATA_PLANE_AUTH.md`](gateway/DATA_PLANE_AUTH.md)
  - Profile MCP settings (capabilities/notifications/namespacing, trust controls, transport limits): [`docs/gateway/MCP_SETTINGS.md`](gateway/MCP_SETTINGS.md)
  - Mode 3 tenant overlay (tool sources + secrets): [`docs/gateway/MODE3_TENANT_OVERLAY.md`](gateway/MODE3_TENANT_OVERLAY.md)
  - Audit logging (Mode 3 / Postgres): [`docs/gateway/AUDIT.md`](gateway/AUDIT.md)
- **Gateway admin CLI (implemented)**: [`docs/gateway-cli/INDEX.md`](gateway-cli/INDEX.md)
  - Commands: [`docs/gateway-cli/COMMANDS.md`](gateway-cli/COMMANDS.md)
  - Config/auth precedence: [`docs/gateway-cli/CONFIG.md`](gateway-cli/CONFIG.md)
  - `mcp.json` output: [`docs/gateway-cli/MCP_JSON.md`](gateway-cli/MCP_JSON.md)
- **Web UI (beta)**: [`docs/ui/INDEX.md`](ui/INDEX.md)
  - Build/versioning/releases: [`docs/CICD.md`](CICD.md)

## Notes on what exists today

- The Gateway implements **MCP proxying + upstream aggregation** and a **control-plane admin API** (Mode 3 / Postgres).
- Tenant-facing **data-plane authn/z is implemented** (API keys + OIDC/JWT).

## Workspace docs

- Workspace layout: [`docs/WORKSPACE.md`](WORKSPACE.md)
- CI/CD: [`docs/CICD.md`](CICD.md)
