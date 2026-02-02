# Changelog

This repository is newly public. Earlier internal iteration notes are intentionally omitted.

## 2026-02-02

- Gateway: `0.9.0`
- Gateway admin CLI: `0.9.0`
- Tenant-level Web UI: `0.5.0`

### Gateway

- Add audit logging for tenant and profile management operations (create, update, delete).
- Add per-tenant audit settings (enable/disable, retention period).
- Add audit event query endpoint with filtering and pagination.
- Add audit analytics endpoints (tool calls by tool, tool calls by API key).
- Add audit retention cleanup endpoint and automatic purge of expired events.
- Add integration tests for audit events, audit retention, and tenant API audit trails.
- Dockerfile/Makefile: security enhancements and improved test coverage targets.

### Web UI

- Add Audit page with event list, filtering, and detailed event view (summary, payload, metadata).
- Add audit settings management (enable/disable logging, set retention period) on the Settings page.

## 2026-01-26

- Gateway: `0.8.1`
- Gateway admin CLI: `0.8.1`
- Tenant-level Web UI: `0.4.2`

### Gateway

- Fix profile deletion to be a hard delete in Postgres mode (including cleanup of durable contract events).
- Tenant API: `DELETE /profiles/:id` now returns a JSON `{ ok: true }` response on success.

### Web UI

- Unlock page: replace the “Settings” link with an inline “I want to know how” reset guide modal (includes `make up-reset`).
- Fix modals being clipped/hidden by layout effects by rendering modals via a portal.
- Improve confirm/warning modal spacing and general toggle consistency across pages.
- Profile tools: fix the “Enabled only / All tools” switch layout and prevent tool allowlist resets when disabling the last tool.
- Reduce UI flicker by avoiding unnecessary automatic surface re-probes after small edits.

## 2026-01-24

- Tenant-level Web UI: `0.4.1`

### Web UI

- Fix Profile auth editor to use a draft + explicit Apply (discard on Cancel/outside-click).
- Fix Profile metadata editor stacking/duplication by making it a modal (Cancel now closes + discards).
- OpenAPI source editor: standardize the Discovery enable/disable control to match the app’s toggle style.
- UI Docker image: remove bundled `npm`/`npx` from runtime to reduce vulnerability surface (Trivy tar CVEs).

## Initial public release

- Adapter: `0.9.0`
- Gateway: `0.8.0`
- Gateway admin CLI: `0.8.0`
- Tenant-level Web UI: `0.4.0`
