# Audit logging (Mode 3 / Postgres)

> **Scope**: an internal, Postgres-backed audit trail (append-only) for tenant activity and basic tool-usage analytics.

---

## Start here

- Gateway overview: [`docs/gateway/INDEX.md`](INDEX.md)
- Mode 3 storage model (tenants/profiles/sources/secrets): [`docs/gateway/MODE3_TENANT_OVERLAY.md`](MODE3_TENANT_OVERLAY.md)
- Web UI overview: [`docs/ui/INDEX.md`](../ui/INDEX.md)

---

## What this is (and what it is not)

Audit logging is intended to answer questions like:

- “What changed in my tenant configuration?”
- “Which tools are being called, how often, and how slow are they?”
- “Which API key is generating errors?”

Non-goals (today):

- It is **not** a distributed tracing system (OTel comes later).
- It does **not** store full `tools/call` request/response payloads (it may store tool names and argument-validation error details).
- It is **not** a per-user “who did this” log yet (tenant auth is token-scoped today, not identity-scoped).

---

## Storage model

In Mode 3, audit events are stored in the `audit_events` table (see `crates/gateway/migrations/20260201145648_audit_mode3.sql`).

Each row includes:

- **Tenant linkage**: `tenant_id` (required)
- **Optional profile linkage**: `profile_id` (UUID, nullable)
- **Best-effort caller identity**:
  - `api_key_id` (UUID, nullable)
  - `oidc_issuer`, `oidc_subject` (nullable)
- **Action**: `action` (string)
- **Optional HTTP context** (control-plane requests): `http_method`, `http_route`, `status_code`
- **Optional tool context** (`tools/call`): `tool_ref`, `tool_name_at_time`
- **Outcome**: `ok` (boolean), `duration_ms` (nullable), `error_kind`/`error_message` (nullable)
- **Extra metadata**: `meta` (JSONB object; best-effort, action-specific; treat as potentially sensitive)

### Stable tool identity (`tool_ref`)

For tool calls, the Gateway uses a stable identifier:

- `tool_ref = "<source_id>:<original_tool_name>"`

This is designed to stay meaningful even if tools are renamed (via transforms) or if a source changes its exported surface over time.

---

## Enablement and settings

Audit storage is **Mode 3 only** (Postgres-backed). Mode 1 intentionally does not write audit events.

Tenant settings live on the `tenants` row:

- `audit_enabled` (boolean, default `false`)
- `audit_retention_days` (integer, default `30`, must be \(\ge 0\))
- `audit_default_level` (`off|summary|metadata|payload`, default `metadata`)

Today, `audit_default_level` is mainly a **detail-level placeholder**: the stored row shape is the same regardless of level. Audit writes are enabled when:

- `audit_enabled = true`, and
- `audit_default_level != 'off'`

> **Security note**: the Gateway intentionally avoids storing secrets and full `tools/call` payloads by default. The `meta` field is best-effort and not strictly enforced/redacted today; do not put secrets into arbitrary config blobs (for example, profile audit settings) and treat `meta` as potentially sensitive.

---

## Events emitted (high-level)

This is a **“what happened”** log (not a “who did it” log).

- **Data plane**
  - `mcp.tools_call`
- **Tenant control plane** (tenant token scoped)
  - examples: `tenant.profile_put`, `tenant.profile_delete`, `tenant.tool_source_put`, `tenant.secret_put`, `tenant.api_key_create`, …
- **Admin control plane** (admin token scoped; acts on a tenant)
  - examples: `admin.tenant_put`, `admin.profile_put`, `admin.tool_source_put`, `admin.secret_put`, …

Note: updating tenant audit settings via `/tenant/v1/audit/settings` is intentionally **not** recorded as an audit event.

---

## Retention and cleanup (including HA)

Audit events are deleted by a background retention task:

- Runs every **10 minutes**
- Deletes `audit_events` older than `now() - (audit_retention_days * 1 day)` per tenant

In HA deployments (multiple gateway replicas), the task uses a **Postgres advisory lock** to ensure only **one** replica performs cleanup on a given tick.

Manual cleanup can also be triggered via the admin API (see below).

---

## APIs (tenant + admin)

### Tenant-scoped

- **Tenant audit settings**
  - `GET /tenant/v1/audit/settings`
  - `PUT /tenant/v1/audit/settings`
- **Audit event listing**
  - `GET /tenant/v1/audit/events`
- **Tool-call analytics**
  - `GET /tenant/v1/audit/analytics/tool-calls/by-tool`
  - `GET /tenant/v1/audit/analytics/tool-calls/by-api-key`
- **Profile audit settings (raw JSONB)**
  - `GET /tenant/v1/profiles/{profile_id}/audit/settings`
  - `PUT /tenant/v1/profiles/{profile_id}/audit/settings`

These profile audit settings are stored as-is (JSONB) and are intended for future extensions. They are not currently used to change what gets recorded in the audit log.

### Admin (operator-scoped)

The admin API can read/write tenant audit settings and query tenant audit events/analytics:

- `GET|PUT /admin/v1/tenants/{tenant_id}/audit/settings`
- `GET /admin/v1/tenants/{tenant_id}/audit/events`
- `GET /admin/v1/tenants/{tenant_id}/audit/analytics/tool-calls/by-tool`
- `GET /admin/v1/tenants/{tenant_id}/audit/analytics/tool-calls/by-api-key`
- `POST /admin/v1/tenants/{tenant_id}/audit/cleanup`

---

## Web UI

The Web UI exposes:

- **Settings → Audit**: enable/disable + default level + retention (auto-saved)
- **Audit**: tenant-wide event listing + analytics with filters (including per-profile filtering and deep-links from profile pages)
- Clicking an event opens an **Event Details** view (raw fields + `meta` JSON with copy support).
