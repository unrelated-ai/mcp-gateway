# Changelog

## 2026-03-10

Release versions:

- Adapter: `0.12.0`
- Gateway: `0.12.0`
- Gateway admin CLI: `0.12.0`
- Gateway Operator: `0.12.0`
- Tenant-level Web UI: `0.8.0`
- Helm charts updated: `unrelated-mcp-gateway`, `unrelated-mcp-gateway-ui`, `unrelated-mcp-gateway-operator`, `unrelated-mcp-gateway-stack`, `unrelated-mcp-gateway-managed-fixtures`, `unrelated-mcp-postgres`

### Gateway + admin API + CLI (0.12.0)

- Fixed profile upstream binding in admin profile writes:
  - when a tenant-owned managed upstream exists, logical upstream IDs now resolve to the tenant-owned internal ID before persistence
  - avoids broken tool routing / empty `tools/list` results for managed profile bindings in Mode 3
- Hardened tenant API key behavior:
  - list/create/revoke API key operations now require the tenant to be enabled
- Hardened OpenAPI resolver outbound behavior:
  - external `$ref` URL fetches now pass outbound safety checks before network access
  - resolver network errors are normalized/sanitized for clearer operator-facing diagnostics
- Refreshed MCP protocol internals on `rmcp` `1.1.0` and updated request handling paths/tests to align with the newer constructor/parameter model.

### Adapter (0.12.0)

- Removed legacy MCP JSON import mode from runtime config:
  - `imports`-based `mcp-json` loading is no longer accepted
  - legacy `--mcp-config` input path support is removed
- `--print-effective-config` now redacts sensitive auth values (bearer/header/query/basic credentials) so output is safe to share in logs/tickets.
- Updated MCP request wiring to the `rmcp` `1.1.0` model with corresponding runtime/test coverage refresh.

### Gateway Operator (0.12.0)

- Operator ships on the `0.12.0` gateway release line for version alignment across gateway-managed runtime components.
- No operator-only behavior changes were introduced in this release.

### Web UI (0.8.0)

- Reworked tenant unlock/session handling:
  - added server-backed unlock endpoint (`/api/session/unlock`) that validates tenant tokens against Gateway before session establishment
  - tenant token cookie is now set as `httpOnly` by the server route
- Added dedicated logout/lock endpoint (`/api/session/logout`) with safe redirect handling for both sidebar and settings lock flows.
- Expanded UI session route tests and added UI test execution to release gate checks.

### Migration notes (0.12.0 line)

- Adapter configs using legacy `imports` (`type: mcp-json`) or `--mcp-config` must be migrated to the unified `servers` model before upgrade.
- Gateway now rejects legacy `v1.<payload>.<signature>` session token format; clients should establish fresh sessions after upgrade.
- OpenAPI external reference URLs are now enforced by outbound safety policy; blocked refs need policy-compliant targets.

## 2026-03-07

Release versions:

- Adapter: `0.11.0`
- Gateway: `0.11.0`
- Gateway admin CLI: `0.11.0`
- Gateway Operator: `0.11.0`
- Tenant-level Web UI: `0.7.0`
- Helm charts updated: `unrelated-mcp-gateway`, `unrelated-mcp-gateway-ui`, `unrelated-mcp-gateway-operator`, `unrelated-mcp-gateway-stack`, `unrelated-mcp-gateway-managed-fixtures`, `unrelated-mcp-postgres`

### Gateway + admin API + CLI (0.11.0)

- Added Managed MCP control-plane APIs and persistence for:
  - deployable catalog entries
  - deployment requests (`pending`/`reconciling`/`ready`/`failed`) with desired-state fields
  - reconciler heartbeat signaling
- Added backend readiness enforcement for managed deployments:
  - `UNRELATED_MANAGED_MCP_BACKEND_MODE` (`none|k8s|docker`)
  - reconciler heartbeat TTL checks and stale-request sweeper
  - fail-fast behavior when managed deployment backend is unavailable
- Added upstream network/lifecycle controls:
  - upstream `networkClass` (`external` / `cluster-internal-managed`)
  - endpoint lifecycle states (`active` / `draining`) and targeted endpoint update APIs
  - upstream session activity tracking APIs to support safe endpoint rollout/drain decisions
- Hardened managed/external boundary behavior:
  - tenant APIs cannot self-assign `cluster-internal-managed`
  - control-plane-authenticated callers can assign managed network class for operator-managed upstreams
- Extended CLI upstream UX to surface and set network class/lifecycle-aware endpoint data.

### Gateway Operator (0.11.0)

- Introduced OSS Gateway Operator runtime for `McpServer` reconciliation:
  - manages Kubernetes `Deployment` + `Service` resources
  - registers and updates Gateway upstream wiring
  - handles endpoint lifecycle transitions and cleanup (`disable-endpoint` or `delete-endpoint`)
- Added rollout behavior for endpoint replacement:
  - mark old endpoint `draining`
  - wait for in-flight session activity to clear (or timeout policy)
  - finalize by disable/delete and support explicit rollback trigger
- Added finalizer-based idempotent cleanup and optional leader election via Kubernetes Leases.
- Added managed deployment intake support for both `k8s` and `docker` backend modes plus reconciler heartbeat publishing.

### Web UI (0.7.0)

- Added Managed MCP tenant flows:
  - deployable catalog listing
  - managed deployment request/create/update flow
  - dedicated “Managed MCP” source onboarding page
- Added managed upstream visibility:
  - deployment metadata/status in sources list and upstream detail pages
  - lifecycle-oriented upstream endpoint presentation and session activity awareness
- Added/expanded tenant-facing API routes for managed deployables/deployments, endpoint lifecycle operations, and session activity queries.

### Helm and deployment packaging

- Expanded Helm packaging for operator, gateway, UI, stack umbrella chart, optional Postgres, and managed fixture seeding.
- Added dev/prod/kind-local value profiles and documented local image workflows for testing unmerged Gateway/UI/Operator changes.
- Synced Operator CRD into Helm packaging and added repo guardrails to prevent CRD drift.

### CI/CD and security (0.11.0 line)

- Gateway-tagged releases (`gateway-vX.Y.Z`) now publish the operator image with the same `X.Y.Z` version line as gateway/migrator.
- Added dedicated operator Trivy workflow and updated reusable Trivy image workflow wiring.
- Hardened Docker/CI release pipeline details and refreshed release documentation for the multi-component tag model.

### Migration notes (0.11.0 line)

- Run Gateway DB migrations before rolling out `0.11.0` components (new managed deployment + heartbeat tables/columns).
- Managed deployment requests now require an enabled backend mode and healthy reconciler heartbeat; misconfigured setups fail fast instead of remaining pending indefinitely.
- For operator-managed in-cluster upstreams, use `networkClass=cluster-internal-managed`; tenant-facing APIs remain restricted to `external`.

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
