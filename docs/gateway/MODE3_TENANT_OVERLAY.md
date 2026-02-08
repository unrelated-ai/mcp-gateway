# Mode 3 tenant overlay (Postgres): tool sources + secrets + profile composition

> **Scope**: Postgres-backed tenant-private tool sources + secrets + profile↔sources composition, wired into the data plane.

---

## 1) What “Mode 3 overlay” means

In Mode 3 (Postgres-backed), a profile’s effective tool surface can be composed from:

1. **Upstream MCP sources** (stored in Postgres): upstream clusters + endpoints, attached to profiles.
2. **Shared catalog local sources** (config-file): gateway-native HTTP DSL + OpenAPI sources available to all tenants.
3. **Tenant-owned local sources** (stored in Postgres): HTTP DSL + OpenAPI sources created by a tenant and attached to its profiles.

The Gateway aggregates tools across these sources and applies:

1. profile transforms (rename/defaults)
2. **optional allowlisting** (if configured)
3. collision prefixing (`<source_id>:<tool_name>` when needed; name is post-transform)
4. contract hashing + best-effort `notifications/*/list_changed`:
   - `notifications/tools/list_changed` (post-transform surface)
   - `notifications/resources/list_changed`
   - `notifications/prompts/list_changed`

---

## 2) Storage model (Postgres tables)

Mode 3 schema lives under `crates/gateway/migrations/`.

Key overlay tables:

- **`tool_sources`**: tenant-owned local tool sources (`http` / `openapi`)
- **`profile_sources`**: profile ↔ local-source attachments (shared + tenant-owned)
- **`secrets`**: tenant-owned secrets (write-only via APIs; never returned)

Notes:

- Upstream MCP attachments remain in `profile_upstreams`.
- Tool allowlisting is stored in `profiles.enabled_tools`.
- Profile transforms are stored in `profiles.transforms` (JSON).
- Tool timeout + retry policy is stored in:
  - `profiles.tool_call_timeout_secs`
  - `profiles.tool_policies` (JSON)

---

## 3) Control plane APIs (admin + tenant)

### 3.1 Admin (operator)

- **Tenant tokens**: `POST /admin/v1/tenant-tokens`
- **Profiles**: `POST /admin/v1/profiles` (supports:
  - `upstreams: [...]`
  - `sources: [...]` (local sources)
  - `transforms: {...}` (rename/default transforms)
  - `tools: [...]` (allowlist)
  - `toolCallTimeoutSecs?: <seconds>` (per-profile default `tools/call` timeout override)
  - `toolPolicies?: [...]` (per-tool overrides: `timeoutSecs` + `retry`))
  - `mcp?: {...}` (capabilities allow/deny, notification filters, ID namespacing)
- **Tenant tool sources**:
  - `GET /admin/v1/tenants/{tenant_id}/tool-sources`
  - `GET|PUT|DELETE /admin/v1/tenants/{tenant_id}/tool-sources/{source_id}`
- **Tenant secrets** (metadata-only listing; values are write-only):
  - `GET /admin/v1/tenants/{tenant_id}/secrets`
  - `PUT|DELETE /admin/v1/tenants/{tenant_id}/secrets/{name}`

### 3.2 Tenant (token-scoped)

- **Profiles**:
  - `GET|POST /tenant/v1/profiles`
  - `GET|PUT|DELETE /tenant/v1/profiles/{profile_id}`
  - Payload supports the same fields as admin profiles (including `toolCallTimeoutSecs` and `toolPolicies`).
- **Tool sources**:
  - `GET /tenant/v1/tool-sources`
  - `GET|PUT|DELETE /tenant/v1/tool-sources/{source_id}`
- **Secrets**:
  - `GET|POST /tenant/v1/secrets`
  - `DELETE /tenant/v1/secrets/{name}`

Isolation rule: all tenant endpoints derive `tenant_id` from the tenant token; cross-tenant ids return **404**.

---

## 4) Secret references in tool source configs

Tenant-owned tool source configs are stored as the same shapes used by the shared crates:

- `unrelated-http-tools` (`HttpServerConfig`)
- `unrelated-openapi-tools` (`ApiServerConfig`)

To reference a tenant secret from an auth field, use a **string placeholder**:

- `${secret:<name>}`

Example (conceptual):

```json
{
  "type": "http",
  "enabled": true,
  "baseUrl": "https://api.example.com",
  "auth": { "type": "bearer", "token": "${secret:api_token}" },
  "tools": {
    "get_user": { "method": "GET", "path": "/users/{id}", "params": { "id": { "in": "path", "required": true } } }
  }
}
```

The Gateway resolves these placeholders at runtime when building cached tool source runtimes.

---

## 5) Data plane wiring (how tools/list + tools/call work)

### 5.1 Local source runtimes

- **Shared sources**: built at startup in `SharedCatalog`.
- **Tenant sources**: built on demand (and cached) in `TenantCatalog`.

### 5.2 Outbound safety

Gateway-native execution and upstream MCP proxying use a restrictive outbound policy by default (SSRF protections, redirects disabled, response size capped for HTTP/OpenAPI tools). See [`docs/gateway/OUTBOUND_HTTP_SAFETY.md`](OUTBOUND_HTTP_SAFETY.md).

---

## 6) Current limitations

- **Secrets at rest**: Mode 3 tenant secrets are encrypted at rest by the Gateway (app-layer AEAD).
  - Configure the encryption keyring via `UNRELATED_GATEWAY_SECRET_KEYS` (comma-separated).
    - Keys can be any bytes; the Gateway derives a 32-byte key via SHA-256.
    - Multiple keys enable rotation: the first key is used for new writes; all keys are accepted for decryption.
  - Generate a key (example):

```bash
export UNRELATED_GATEWAY_SECRET_KEYS="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
```

  - If `openssl` is available, this also works:

```bash
# 32 random bytes → base64url (no padding)
export UNRELATED_GATEWAY_SECRET_KEYS="$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=')"
```

- Legacy plaintext rows (old schema) are migrated lazily: on read, the Gateway encrypts the row in-place and clears plaintext.
- HA cache invalidation is still **best-effort**:
  - Contract notifications are propagated cross-node in Mode 3 via Postgres `LISTEN/NOTIFY` (and can be replayed via SSE `Last-Event-ID`).
  - The Gateway also uses a lightweight Postgres `LISTEN/NOTIFY` invalidation channel to clear per-node caches on writes (secrets/tool-sources/profiles/upstreams).
  - In addition, tool routing caches are invalidated locally on `tools` contract changes (including remote changes delivered via fanout).
- Data-plane authn/z is implemented and configured per profile (API keys + OIDC/JWT). Claim-based RBAC is not implemented yet.
