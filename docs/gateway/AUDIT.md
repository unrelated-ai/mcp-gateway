# Audit logging

Audit logging records configuration changes and MCP activity in Postgres (Mode 3).
The **Audit** page shows events and tool-call analytics, with filters for profiles,
API keys, tools, and outcomes. Opening an event shows its details and metadata.
File-based Mode 1 does not store audit events.

## Tenant defaults and profile overrides

**Settings → Audit** controls the tenant's logging switch, default detail level,
and retention. Logging starts disabled; the default level is Metadata and the
retention period is 30 days.

**Profile → Security → Profile audit** selects the detail level for that profile's
MCP activity. The card shows the tenant default, the currently effective level,
and tenant-wide retention. New profiles inherit the tenant default.

- **Inherit tenant default** follows later changes to the tenant's default level.
- An explicit profile level replaces the default for that profile, including
  choosing more detail or turning its activity logging off.
- Turning tenant logging off, or setting its default level to **Off**, stops
  logging for every profile. Saved overrides remain available when logging resumes.
- Configuration changes always follow tenant settings. Turning a profile's MCP
  activity off still allows its settings changes to be recorded.

| Level | Stored detail |
| --- | --- |
| Off | No new events in the applicable scope. |
| Summary | Event identity, profile, caller when available, tool, outcome, timing, and error kind. Additional metadata and error messages are omitted. |
| Metadata | Summary fields plus event metadata and error messages, without payload samples. |
| Payload samples | Metadata plus bounded samples from transport-limit failures. Full tool request and response bodies are not recorded. |

Settings affect new writes, including events waiting to be flushed. They do not
rewrite existing events. Metadata and payload samples can contain sensitive data;
access to the audit log should be restricted accordingly. Writes are buffered and
best-effort, so this is not a guaranteed delivery log.

## Recorded activity

The Gateway records tool calls (`mcp.tools_call`), transport-limit failures
(`mcp.payload_limit_exceeded`), and configuration changes such as profile updates,
source updates, secret changes, and API-key creation.

Tool calls use `toolRef` in the form `<source_id>:<original_tool_name>`, so their
identity remains useful after a display name changes. Caller information can
include an API-key ID or OAuth issuer and subject. Tenant-token configuration
changes do not identify an individual person.

At Metadata or Payload samples level, transport-limit failures include the
limit, observed size or complexity, direction, and action taken. Each payload sample
uses at most 4096 bytes of the original payload. Tool-call argument-validation details can appear in
metadata; Summary omits them.

Tenant-token updates to the tenant-wide audit settings are not themselves recorded.
Profile audit-setting changes are recorded while tenant logging is enabled.

## Retention

Retention applies to all profiles in a tenant. A background task removes expired
events every 10 minutes; multiple replicas coordinate cleanup through Postgres.
A value of zero makes existing events eligible for deletion at the next cleanup.
Turning logging off does not remove stored events immediately.

An operator can trigger cleanup with
`POST /admin/v1/tenants/{tenant_id}/audit/cleanup`.

## API

Tenant-token endpoints:

- `GET|PUT /tenant/v1/audit/settings`
- `GET|PUT /tenant/v1/profiles/{profile_id}/audit/settings`
- `GET /tenant/v1/audit/events`
- `GET /tenant/v1/audit/analytics/tool-calls/by-tool`
- `GET /tenant/v1/audit/analytics/tool-calls/by-api-key`

The admin equivalents use `/admin/v1/tenants/{tenant_id}/audit/...` for tenant
settings, events, and analytics, and
`/admin/v1/profiles/{profile_id}/audit/settings` for profile overrides.

A profile audit-setting update accepts one optional setting, `level`:

```json
{
  "auditSettings": { "level": "summary" },
  "expectedRevision": 4
}
```

Allowed values are `off`, `summary`, `metadata`, and `payload`. An empty object
or `"level": null` restores inheritance. Retention and the tenant master switch
cannot be set here; unsupported fields and values are rejected.

GET returns the saved `auditSettings`, the profile's `revision`, `tenantSettings`
(`enabled`, `defaultLevel`, `retentionDays`), and `effectiveLevel`. Send that
revision as `expectedRevision` to protect against concurrent changes; a stale
revision returns HTTP 409. Audit settings share the profile's revision counter
with other profile edits. Omitting the revision allows an unconditional update.

Earlier releases accepted arbitrary JSON without using it. Existing values that
do not match the supported format now inherit tenant defaults. GET flags them
with `hasUnrecognizedSettings: true`; saving a supported setting replaces them.

Event listing supports `limit` and `beforeId`: pass the last event's ID for the
next page of older events. Analytics support `limit` and a zero-based `offset`.
Keep `fromUnixSecs` and `toUnixSecs` fixed while paging for a consistent time window.

See also: [Gateway overview](INDEX.md), [Mode 3 configuration](MODE3_TENANT_OVERLAY.md),
and [Web UI](../ui/INDEX.md).
