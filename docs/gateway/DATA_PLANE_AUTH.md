# Gateway data-plane authentication (Mode 1 + Mode 3)

This document describes **how clients authenticate to the Gateway data plane** (`/{profile_id}/mcp`) and what is configurable per **profile**.

> This is **endpoint protection** only. The Gateway never forwards the caller’s credentials to any upstream.

---

## Non-negotiable security stance: no Authorization passthrough

- The caller’s `Authorization` header (used to authenticate to the Gateway) is **never forwarded** to:
  - upstream MCP servers (Adapters or any other upstream MCP server), or
  - any HTTP/OpenAPI backend (gateway-native tools or Adapter tools).

If an upstream MCP server or HTTP/OpenAPI backend needs auth, those credentials must be provided via **configuration + secrets** (Mode 3 secrets via `${secret:<name>}`), not by reusing caller credentials.

See also:

- `docs/gateway/ARCHITECTURE.md` (Authorization forwarding stance)
- `docs/adapter/config/AUTH.md` (Adapter outbound auth config; notes on no passthrough)
- `docs/gateway/MODE3_TENANT_OVERLAY.md` (Mode 3 tenant secrets)

---

## Data-plane client auth headers (client → gateway)

Supported header formats depend on the selected `dataPlaneAuth.mode`:

### API keys

- Primary: `Authorization: Bearer <api_key_secret>`
- Optional alias: `x-api-key: <api_key_secret>` (only if the profile enables it)

> The secret is accepted by the Gateway **only** to authenticate the caller. It is **never** forwarded upstream.

### OIDC/JWT (enterprise)

- `Authorization: Bearer <jwt>`

> The JWT is used only to authenticate the caller to the Gateway and is **never** forwarded upstream.

---

## Mode 3: per-profile policy (`dataPlaneAuth`)

Profiles control data-plane auth via:

- `mode`:
  - `disabled`
  - `apiKeyInitializeOnly` (default)
  - `apiKeyEveryRequest`
  - `jwtEveryRequest`
- `acceptXApiKey` (default: `false`): whether the `x-api-key` alias is accepted

Recommended for production / internet-exposed profiles:

- **`apiKeyEveryRequest`** or **`jwtEveryRequest`** (per-request authentication)

The `apiKeyInitializeOnly` mode exists for compatibility with some MCP clients, but it is less secure.

UI note:

- The Gateway UI creates new profiles with **`apiKeyEveryRequest`** by default and keeps `acceptXApiKey` **off** by default.

### `apiKeyInitializeOnly` (compatibility; not recommended)

- The client must provide an API key **only for `initialize`**.
- The resulting Gateway session token (`Mcp-Session-Id`) embeds `{tenant_id, api_key_id}`.
- Subsequent requests only need `Mcp-Session-Id`, but the Gateway still:
  - checks the key is not revoked, and
  - meters usage counters per key.

This mode is the most compatible with MCP clients that may not easily attach extra headers on the SSE `GET` stream, but it increases the impact of a leaked session token (session replay until expiry).

### `apiKeyEveryRequest`

- The client must provide an API key header on **every** data-plane request (`POST`/`GET`/`DELETE`), in addition to `Mcp-Session-Id`.
- The Gateway verifies that the API key matches the key used during `initialize`.

### `disabled`

- The data plane is public for that profile.
- Use only for local/dev or explicitly public endpoints.

### `jwtEveryRequest` (Mode 3 only; no other JWT modes)

- The client must send `Authorization: Bearer <jwt>` on **every** data-plane request (`POST`/`GET`/`DELETE`).
- The Gateway validates JWT signature via OIDC discovery + JWKS.
- There is no “JWT on initialize only” mode.
- The Gateway session token (`Mcp-Session-Id`) is **bound to the OIDC principal** (`issuer` + `subject`) from `initialize`; subsequent requests are rejected if the JWT principal does not match the session.

Authorization model (current):

- We do **not** use JWT claims for RBAC.
- After validating the token, the Gateway extracts a principal id (`sub`, or `oid` for Entra) and checks a DB-backed binding:
  - tenant-wide: principal can access **any** profile owned by the tenant
  - profile-scoped: principal can access **only** the bound profile

Configuration is global (gateway process):

- `UNRELATED_GATEWAY_OIDC_ISSUER` (enables OIDC when set)
- `UNRELATED_GATEWAY_OIDC_AUDIENCE` (comma-separated, optional)
- `UNRELATED_GATEWAY_OIDC_JWKS_URI` (optional override; otherwise uses `/.well-known/openid-configuration`)
- `UNRELATED_GATEWAY_OIDC_LEEWAY_SECS` (optional, default `60`)
- `UNRELATED_GATEWAY_OIDC_JWKS_REFRESH_SECS` (optional, default `600`)

Security notes:

- Discovery + JWKS fetches do **not** follow redirects (SSRF hardening).
- Discovered `jwks_uri` must be **HTTPS**. If you need HTTP for local development, set `UNRELATED_GATEWAY_OIDC_JWKS_URI` explicitly (the gateway will warn).
- JWTs with a JOSE `crit` header are rejected (we do not support critical JOSE extensions).

#### Managing OIDC principal bindings (Mode 3)

Bindings are managed by operators via the admin API and/or `unrelated-gateway-admin`:

- Admin API:
  - `GET /admin/v1/tenants/{tenant_id}/oidc-principals`
  - `PUT /admin/v1/tenants/{tenant_id}/oidc-principals` body: `{ "subject": "...", "profileId": "<uuid>|null", "enabled": true }`
  - `DELETE /admin/v1/tenants/{tenant_id}/oidc-principals/{subject}[?profileId=<uuid>]`
- CLI:
  - `tenants oidc-principals <tenant_id> list|put|delete`

---

## Mode 3 (Postgres): tenant-issued API keys

In Mode 3, API keys are stored in Postgres and managed via tenant control-plane APIs.

### Key lifecycle

- Create: returns the secret **once** (never retrievable again).
- List: returns **metadata only** (no secret).
- Revoke: sets `revoked_at` and future requests are rejected.

Secrets are not stored; the Gateway stores only:

- key id (`uuid`)
- secret hash (SHA-256 hex)
- metadata (name/label, prefix, profile scope, counters)

### Tenant control-plane endpoints (Mode 3)

- `POST /tenant/v1/api-keys`
  - body: `{ "name": "<label>", "profileId": "<uuid>" }`
    - `profileId` optional (if omitted, the key is tenant-wide)
  - response: `{ ..., "secret": "<api_key_secret>", "id": "<uuid>", "prefix": "..." }` (secret is returned once)
- `GET /tenant/v1/api-keys` → list metadata only
- `DELETE /tenant/v1/api-keys/{api_key_id}` → revoke

### Profile-scoped vs tenant-wide keys

- **Profile-scoped**: `profileId` is set on the key; the key only works for that profile.
- **Tenant-wide**: `profileId` is `null`; the key works for any profile owned by that tenant.

---

## Mode 1 (config file): optional static API keys

Mode 1 is intended for local/dev simplicity.

- If `dataPlaneAuth.mode: none`, the gateway starts unauthenticated and logs a **loud warning**.
- If `dataPlaneAuth.mode: static-api-keys`, the data plane requires one of the configured secrets.

Example:

```yaml
dataPlaneAuth:
  mode: static-api-keys
  apiKeys:
    - "ugw_sk_..."
  acceptXApiKey: false
  requireEveryRequest: false
```

> Mode 3 compatibility: when `--database-url` is provided, Mode 1 `dataPlaneAuth` config is rejected at startup to avoid ambiguity (Mode 3 uses DB-managed keys).

---

## Metering vs limits (today)

Today the Gateway records **best-effort counters** per API key:

- total requests attempted
- total `tools/call` attempts

## Per-profile limits (Mode 3): `dataPlaneLimits` (optional, disabled by default)

Profiles can optionally enable **rate limiting** and/or a **quota** for `tools/call`.

Semantics:

- Limits are **disabled by default**.
- Limits are configured **per profile**.
- Limits currently apply to `tools/call` only.
- Limits require API key authentication (so enforcement can be attributed per key).

### Fields

- `rateLimitEnabled` (default: `false`)
- `rateLimitToolCallsPerMinute` (required when enabled; must be > 0)
- `quotaEnabled` (default: `false`)
- `quotaToolCalls` (required when enabled; must be > 0)

### Behavior (current v1)

- **Rate limit**: fixed window per minute per `{api_key_id, profile_id}`.
- **Quota**: a per `{api_key_id, profile_id}` remaining counter, decremented on *attempted* `tools/call`.
  - If quotas are enabled after a key already exists, the key’s per-profile quota is initialized on its first `tools/call`.

### Responses

When blocked, the Gateway returns a JSON-RPC error:

- Rate limit exceeded: code `-32029`, message `"rate limit exceeded"`, optional `data.retryAfterSecs`
- Quota exceeded: code `-32030`, message `"quota exceeded"`
