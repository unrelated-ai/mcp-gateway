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

### OIDC/JWT

- `Authorization: Bearer <jwt>`

> The JWT is used only to authenticate the caller to the Gateway and is **never** forwarded upstream.

---

## Mode 3: per-profile policy (`dataPlaneAuth`)

The v1 profile policy has three modes:

| Mode               | Configuration                                           | Client behavior                                            |
| ------------------ | ------------------------------------------------------- | ---------------------------------------------------------- |
| `disabled`         | `{ "mode": "disabled" }`                                | No caller authentication for this profile.                 |
| `apiKey` (default) | `{ "mode": "apiKey", "acceptXApiKey": false }`          | Send the API key on every POST, GET, and DELETE.           |
| `oauth`            | `{ "mode": "oauth", "requiredScopes": ["mcp:access"] }` | Send an OAuth access token on every POST, GET, and DELETE. |

API-key sessions remain bound to the key used for initialization. `x-api-key` is
an optional alias; do not send both credential headers on the same request.
OAuth sessions remain bound to the issuer and subject used for initialization.

### OAuth resource-server configuration

The Gateway delegates login and token issuance to an external authorization server.
It publishes protected-resource metadata at
`/.well-known/oauth-protected-resource/{profile_id}/mcp` and supplies discovery
information through `WWW-Authenticate` challenges.

Configure these process-wide values before creating OAuth profiles:

- `UNRELATED_GATEWAY_PUBLIC_DATA_BASE_URL`: externally reachable Gateway base URL,
  including any reverse-proxy path prefix.
- `UNRELATED_GATEWAY_OAUTH_ISSUER`: the authorization server issuer.
- `UNRELATED_GATEWAY_OAUTH_JWKS_URI`: optional explicit JWKS endpoint; otherwise
  use authorization-server/OIDC discovery.
- `UNRELATED_GATEWAY_OAUTH_LEEWAY_SECS`: optional, default `60`.
- `UNRELATED_GATEWAY_OAUTH_JWKS_REFRESH_SECS`: optional, default `600`.

The runtime currently supports one data-plane issuer and RS256 access tokens.
The token audience must contain the exact profile resource URL:
`<PUBLIC_DATA_BASE_URL>/<profile_id>/mcp`. Required scopes default to `mcp:access`.
A matching tenant-wide or profile-specific issuer/subject binding is also required.

Control-plane OIDC continues to use the separate
`UNRELATED_GATEWAY_CONTROL_PLANE_OIDC_*` configuration. Tenant Web UI login still
uses tenant tokens; enabling data-plane OAuth does not change that login flow.

For migration from the old modes and environment variables, see [Upgrading to v1](V1_UPGRADE.md).

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

Mode 1 uses file-driven configuration. Static API keys are required on every request.
The old `requireEveryRequest` setting is removed and must be deleted from configuration.

- If `dataPlaneAuth.mode: none`, the gateway starts unauthenticated and logs a **loud warning**.
- If `dataPlaneAuth.mode: static-api-keys`, the data plane requires one of the configured secrets.

Example:

```yaml
dataPlaneAuth:
  mode: static-api-keys
  apiKeys:
    - "ugw_sk_..."
  acceptXApiKey: false
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
- **Quota**: a per `{api_key_id, profile_id}` remaining counter, decremented on _attempted_ `tools/call`.
  - If quotas are enabled after a key already exists, the key’s per-profile quota is initialized on its first `tools/call`.

### Responses

When blocked, the Gateway returns a JSON-RPC error:

- Rate limit exceeded: code `-32029`, message `"rate limit exceeded"`, optional `data.retryAfterSecs`
- Quota exceeded: code `-32030`, message `"quota exceeded"`
