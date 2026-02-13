# Changelog

This repository is newly public. Earlier internal iteration notes are intentionally omitted.

## 2026-02-14

Release versions:

- Adapter: `0.10.0`
- Gateway: `0.10.0`
- Gateway admin CLI: `0.10.0`
- Tenant-level Web UI: `0.6.0`

### Gateway (0.10.0)

- Added per-profile MCP trust-policy controls under `mcp.security`:
  - signed proxied request IDs (`signedProxiedRequestIds`)
  - per-upstream client capability passthrough/strip/allowlist and optional client-info rewrite
  - per-upstream server->client request allow/deny filtering
- Added transport/payload hardening:
  - byte limits for downstream `POST /{profile_id}/mcp` and SSE `data:` payloads
  - optional JSON complexity caps (depth, array length, object keys, string bytes)
  - tenant-level defaults via `GET|PUT /tenant/v1/transport/limits` with per-profile overrides via `mcp.security.transportLimits`
  - payload-limit audit event `mcp.payload_limit_exceeded` in Mode 3
- Improved HA behavior in Mode 3:
  - Postgres `LISTEN/NOTIFY` invalidation fanout for per-node cache clearing on writes
  - local invalidation dispatcher for tool-routing cache updates
  - additional integration coverage for cross-node notification/replay paths
- Hardened upstream connectivity and auth:
  - upstream MCP endpoint URLs require `https://` by default
  - dev-only override for cleartext upstreams via `UNRELATED_GATEWAY_UPSTREAM_ALLOW_HTTP=1`
  - explicit outbound auth config for upstream MCP endpoints (`bearer`, `basic`, `header`, `query`) while still never forwarding downstream caller auth
- Refactored profile/upstream proxy internals and request-parameter handling; refreshed MCP/tooling dependencies.

### Adapter (0.10.0)

- Added optional static bearer-token protection for Adapter HTTP endpoints (including `/mcp`).
- Refactored adapter bearer-token auth handling across config/runtime HTTP paths.
- Integrated shared `unrelated-env` parsing helpers and refreshed dependency/runtime hardening.

### Web UI (0.6.0)

- Added Profile **Security** tab for MCP trust-policy controls.
- Added tenant transport-limits management in **Settings** plus per-profile transport-limits overrides.
- Expanded profile/upstream editing UX and normalized MCP settings handling for the new security model.
- Added a reusable callout UI primitive and improved profile connection/security flows.

### CI/CD and docs

- Replaced the legacy combined security workflow with dedicated RustSec + Trivy image workflows (adapter, gateway, migrator, UI).
- Expanded docs for bearer-token auth, MCP proxying/security settings, transport limits, and outbound safety behavior.
- Clarified release/versioning expectations for component-scoped tags and version guards.

### Migration notes

- Upstream MCP endpoint URLs now default to **`https://` required**.
- Existing `http://` upstream MCP endpoints may fail validation/connect after upgrade.
- Recommended migration path:
  - move upstream endpoints to `https://`, then deploy
  - for local/dev-only rollouts, set `UNRELATED_GATEWAY_UPSTREAM_ALLOW_HTTP=1` temporarily
  - remove that override once upstreams are migrated to HTTPS
- This HTTPS scheme policy is separate from private-network SSRF controls (`UNRELATED_GATEWAY_OUTBOUND_ALLOW_PRIVATE_NETWORKS`).

## 2026-02-02

- Gateway: `0.9.0`
- Gateway admin CLI: `0.9.0`
- Tenant-level Web UI: `0.5.0`

### Gateway (0.9.0)

- Add audit logging for tenant and profile management operations (create, update, delete).
- Add per-tenant audit settings (enable/disable, retention period).
- Add audit event query endpoint with filtering and pagination.
- Add audit analytics endpoints (tool calls by tool, tool calls by API key).
- Add audit retention cleanup endpoint and automatic purge of expired events.
- Add integration tests for audit events, audit retention, and tenant API audit trails.
- Dockerfile/Makefile: security enhancements and improved test coverage targets.

### Web UI (0.5.0)

- Add Audit page with event list, filtering, and detailed event view (summary, payload, metadata).
- Add audit settings management (enable/disable logging, set retention period) on the Settings page.

## 2026-01-26

- Gateway: `0.8.1`
- Gateway admin CLI: `0.8.1`
- Tenant-level Web UI: `0.4.2`

### Gateway (0.8.1)

- Fix profile deletion to be a hard delete in Postgres mode (including cleanup of durable contract events).
- Tenant API: `DELETE /profiles/:id` now returns a JSON `{ ok: true }` response on success.

### Web UI (0.4.2)

- Unlock page: replace the “Settings” link with an inline “I want to know how” reset guide modal (includes `make up-reset`).
- Fix modals being clipped/hidden by layout effects by rendering modals via a portal.
- Improve confirm/warning modal spacing and general toggle consistency across pages.
- Profile tools: fix the “Enabled only / All tools” switch layout and prevent tool allowlist resets when disabling the last tool.
- Reduce UI flicker by avoiding unnecessary automatic surface re-probes after small edits.

## 2026-01-24

- Tenant-level Web UI: `0.4.1`

### Web UI (0.4.1)

- Fix Profile auth editor to use a draft + explicit Apply (discard on Cancel/outside-click).
- Fix Profile metadata editor stacking/duplication by making it a modal (Cancel now closes + discards).
- OpenAPI source editor: standardize the Discovery enable/disable control to match the app’s toggle style.
- UI Docker image: remove bundled `npm`/`npx` from runtime to reduce vulnerability surface (Trivy tar CVEs).

## Initial public release

- Adapter: `0.9.0`
- Gateway: `0.8.0`
- Gateway admin CLI: `0.8.0`
- Tenant-level Web UI: `0.4.0`
