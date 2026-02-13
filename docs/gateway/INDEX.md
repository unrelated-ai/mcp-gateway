# Gateway (beta)

The **Gateway** is the public-facing component of this workspace. It sits in front of one or more **Adapters** and provides:

- **MCP proxying** over streamable HTTP (`/{profile_id}/mcp`)
- **Upstream aggregation** (merge tools/resources/prompts across multiple upstream adapters per profile)
- **Tenancy (configuration scope)** via tenant-owned profiles
- **Control plane (admin API)** for managing tenants/upstreams/profiles (Mode 3 / Postgres)
- **HA-ready session routing** via stateless, signed Gateway session tokens (`Mcp-Session-Id`)

The Adapter stays “dumb plumbing” on purpose: it turns systems into MCP and exposes `/mcp` + operational endpoints (like `/map`) inside a trusted network.

## Current status

- **Data plane MCP proxy**: implemented (`POST`/`GET`/`DELETE` `/{profile_id}/mcp`)
  - Stateless Gateway session token returned as `Mcp-Session-Id` (**PASETO `v4.local`**, encrypted + authenticated)
    - TTL via `UNRELATED_GATEWAY_SESSION_TTL_SECS` (default: 1h)
    - Key rotation via `UNRELATED_GATEWAY_SESSION_SECRETS` (comma-separated; first is active for minting)
      - Fallback: `UNRELATED_GATEWAY_SESSION_SECRET` (single secret, no rotation)
      - If neither is set, the Gateway generates an ephemeral secret at startup (not HA-safe)
    - Legacy compatibility: still accepts the old sign-only `v1.<payload>.<hmac>` format for migration
  - `tools/list`, `resources/list`, `prompts/list`: fan-out to upstreams + merge
    - Name collisions: prefix with `<upstream_id>:` (same philosophy as the adapter)
    - Resource URI collisions: rewritten into stable gateway URNs (`urn:unrelated-mcp-gateway:resource:...`)
  - `tools/call`, `resources/read`, `prompts/get`: routed to the owning upstream session
    - `tools/call`: gateway-enforced timeout budgets (global default + per-profile/per-tool overrides) and optional per-tool retries
  - `GET` stream: opens one SSE stream per upstream and merges events (event ids are prefixed to reduce collisions)
  - Partial upstream availability is supported via per-profile `allow_partial_upstreams`
- **Control plane (admin API)**: implemented (Mode 3 only)
  - Requires `UNRELATED_GATEWAY_ADMIN_TOKEN` (static bearer token)
  - CRUD for tenants, upstreams (with endpoints), and profiles
- **Storage backends**:
  - Mode 1 (config file): implemented for the data plane (read-only); admin API is unavailable
  - Mode 3 (Postgres): implemented (shared state for HA deployments)
- **Audit logging** (Mode 3): implemented (optional per tenant; retention cleanup)

## Docs

- Architecture (incl. HA session routing “Model B”): [`docs/gateway/ARCHITECTURE.md`](ARCHITECTURE.md)
- Data-plane auth (Mode 1 API keys + Mode 3 API keys + OIDC/JWT, per-profile policy): [`docs/gateway/DATA_PLANE_AUTH.md`](DATA_PLANE_AUTH.md)
- MCP proxying & aggregation behavior: [`docs/gateway/MCP_PROXYING.md`](MCP_PROXYING.md)
- Profile MCP settings (capabilities, notifications, namespacing, upstream trust controls, transport limits): [`docs/gateway/MCP_SETTINGS.md`](MCP_SETTINGS.md)
- Outbound HTTP safety (SSRF hardening for tool sources + upstream MCP endpoints): [`docs/gateway/OUTBOUND_HTTP_SAFETY.md`](OUTBOUND_HTTP_SAFETY.md)
- Audit logging (Mode 3 / Postgres): [`docs/gateway/AUDIT.md`](AUDIT.md)
- CLI: [`docs/gateway-cli/INDEX.md`](../gateway-cli/INDEX.md)

## Current limitations

- No server-side session token revocation list (rely on TTL + re-initialize).
- Audit event detail levels are still evolving (the current implementation stores safe, structured metadata by default).
- Fine-grained allow/deny for **resources/prompts** is not implemented yet (tools have allowlisting + `tools/call` limits).
- Tasks (SEP-1686) are not proxied end-to-end yet (SDK support exists in `rmcp 0.15.x`; gateway/adapter task proxying remains pending).
- `notifications/roots/list_changed` is not forwarded yet (RMCP type exposure gap).

## What will NOT live here

- OpenAPI parsing, HTTP tool execution, spawning stdio servers — those stay in the Adapter.
