# Gateway MCP settings (per-profile)

Profiles can tune how the Gateway behaves as an MCP server **to downstream clients**, especially for aggregated upstreams.

These settings are supported in:

- **Mode 1** (config file): under `profiles.<id>.mcp`
- **Mode 3** (Postgres): via Admin/Tenant profile APIs (`mcp` field), stored in `profiles.mcp_settings`
  - CLI: `unrelated-gateway-admin profiles create|put --mcp-json ...` (or `--mcp-file ...`)

## Native protocol

`mcp.modernProtocol` defaults to `false`. Enable it in the profile's MCP settings
or JSON/YAML configuration for native MCP **2026-07-28** clients. All attached
remote MCP sources must support that version. The Adapter's stdio lifecycle is
still legacy; use a separate profile for those sources. Older clients can still
initialize a native-enabled profile using a supported legacy revision.

Native requests authenticate on every POST and require the version, client info,
and capabilities in `params._meta` as defined by the
[Streamable HTTP specification](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http).
`MCP-Protocol-Version`, `Mcp-Method`, `Mcp-Name` and schema-promoted argument
headers are checked against the body, then regenerated for upstream names and
transformed arguments. Client-info rewriting and capability policies also apply
to native request metadata. Native GET/DELETE return 405 with `Allow: POST`.

`subscriptions/listen` supports catalog changes, resource subscriptions and task
IDs. Filters and ownership are validated before upstream access. At most 1,024
identifiers per filter are accepted. Stream disconnects release upstream
requests; upstream failure or profile/auth changes end the stream so the client
can reconnect. Authorization/profile settings are checked at least every 30
seconds. The existing notification filters and payload limits still apply.

MRTR continuations use encrypted state with a 15-minute lifetime, at most 10
rounds, and at most 16 KiB of sealed state. They are bound to the principal,
profile, arguments, original endpoint and policy. They do not trigger automatic
tool retries or consume a fresh tool quota for each continuation. Input requests
respect `mcp.security.*.serverRequests`.

The [Tasks Extension](https://tasks.extensions.modelcontextprotocol.io/specification/2026-07-28/tasks)
is supported for `tools/call`, `tasks/get`, `tasks/update`, `tasks/cancel`, and
status subscriptions. Clients must declare the extension. Public task IDs are
opaque encrypted routing state scoped to their owner; lifetime follows upstream
TTL with a maximum of 24 hours. Preserve the Gateway session keyring across
replicas/restarts. Removing a referenced key invalidates its outstanding state.

## Browser Origin policy

For all MCP lifecycle paths, requests with an `Origin` header accept loopback
origins by default. Add exact browser origins, separated by commas, using
`UNRELATED_GATEWAY_ALLOWED_ORIGINS`. Requests without Origin are unaffected.
This is transport Origin validation, not a replacement for authentication or
reverse-proxy CORS configuration.

## `mcp.capabilities` (allow/deny)

Controls which MCP **server** capabilities the Gateway advertises (and enforces for the corresponding methods/notifications).

Shape:

- `mcp.capabilities.allow`: list of capability keys (non-empty ⇒ acts as an allowlist overriding defaults)
- `mcp.capabilities.deny`: list of capability keys (applied after defaults/allowlist)

Supported keys:

- `logging`
- `completions`
- `resources-subscribe`
- `tools-list-changed`
- `resources-list-changed`
- `prompts-list-changed`

Defaults: all of the above are enabled.

## `mcp.notifications` (filtering)

Allows users to tune noisy upstream servers by filtering server→client notifications in the merged SSE stream.

Shape:

- `mcp.notifications.allow`: list of notification method strings (non-empty ⇒ allowlist)
- `mcp.notifications.deny`: list of notification method strings (denylist)

A nonempty allowlist takes precedence over the denylist. With an empty allowlist, all
methods except denied ones are permitted. The Web UI exposes both lists under
**Profile → MCP settings → Advanced MCP settings**.

Examples:

- `notifications/message`
- `notifications/progress`
- `notifications/resources/updated`
- `notifications/cancelled`
- `notifications/tools/list_changed`
- `notifications/resources/list_changed`
- `notifications/prompts/list_changed`

Defaults: allow everything.

Note: disabling the `logging` capability also suppresses `notifications/message` (even if not explicitly filtered).

## `mcp.namespacing` (IDs in the merged SSE stream)

Controls how the Gateway namespaces IDs so aggregated upstream streams don’t collide.

### `mcp.namespacing.requestId`

- `opaque` (default): `unrelated.proxy.<b64(upstream_id)>.<b64(json(request_id))>`
- `readable`: `unrelated.proxy.r.<upstream_id>.<b64(json(request_id))>`

### `mcp.namespacing.sseEventId`

- `upstream-slash` (default): `{upstream_id}/{upstream_event_id}`
- `none`: do not prefix upstream SSE event IDs (may break per-upstream resume via `Last-Event-ID`)

## `mcp.security` (upstream trust + proxy hardening)

These settings control how the Gateway behaves when interacting with **upstream MCP servers** and
how it hardens certain proxy mechanics against malicious clients.

Notes:

- This is **per-profile**, but supports **per-upstream overrides** (because not all upstreams are equally trusted).
- Defaults are intentionally **non-breaking** (preserve current behavior), but enable operators to tighten policy.

### `mcp.security.signedProxiedRequestIds`

If `true` (default), the Gateway will sign proxied upstream server→client request IDs with a
per-session key and reject downstream responses whose IDs do not verify (mitigates forged responses
from malicious downstream clients).

### `mcp.security.upstreamDefault` / `mcp.security.upstreamOverrides`

Shape:

- `mcp.security.upstreamDefault`: default policy applied to all upstreams unless overridden
- `mcp.security.upstreamOverrides`: object keyed by upstream id → policy override

Each upstream policy supports:

- `clientCapabilitiesMode`: how the Gateway advertises **client capabilities** upstream during `initialize`
  - `passthrough` (default): forward downstream client capabilities unchanged
  - `strip`: send empty client capabilities upstream
  - `allowlist`: forward only the keys in `clientCapabilitiesAllow`
- `clientCapabilitiesAllow`: list of top-level capability keys (e.g. `sampling`, `roots`, `elicitation`)
- `rewriteClientInfo`: if `true`, replace downstream `clientInfo` before sending `initialize` upstream (privacy)
- `serverRequests`: filter for upstream **server→client JSON-RPC requests** forwarded over SSE
  - `defaultAction`: `allow` (default) or `deny`
  - `allow`: allowlist of method strings
  - `deny`: denylist of method strings

Examples of request methods:

- `sampling/createMessage`
- `roots/list`
- `elicitation/create`

### `mcp.security.transportLimits` (DoS hardening)

The Gateway enforces **payload size** and optional **JSON complexity** limits to reduce DoS risk from oversized or adversarial messages.

Where limits apply:

- **Downstream POST bodies**: `POST /{profile_id}/mcp` (client → gateway)
- **SSE event payloads**: each SSE `data:` payload (upstream → gateway → downstream)

Shape (`camelCase`):

- `maxPostBodyBytes` (bytes; default: 4 MiB; hard max: 32 MiB)
- `maxSseEventBytes` (bytes; default: 8 MiB; hard max: 32 MiB)
- `maxJsonDepth` (optional; hard max: 512)
- `maxJsonArrayLen` (optional; hard max: 1_000_000)
- `maxJsonObjectKeys` (optional; hard max: 1_000_000)
- `maxJsonStringBytes` (optional; hard max: 32 MiB)

Precedence:

1. Per-profile `mcp.security.transportLimits`
2. Mode 3 tenant defaults (`GET|PUT /tenant/v1/transport/limits`, also exposed in the Web UI under **Settings**)
3. Process defaults (safe built-ins), bounded by hard caps

Mode 1 note: there are no tenant-level defaults; configure per profile.

When limits are exceeded:

- downstream requests are rejected, and
- upstream SSE streams are closed (dropping a single oversized event risks downstream desync)

In Mode 3, these incidents are also audit-logged as `mcp.payload_limit_exceeded` (see [`docs/gateway/AUDIT.md`](AUDIT.md)).

## Mode 1 example

```yaml
profiles:
  my-profile:
    tenantId: t1
    upstreams: ["u1", "u2"]
    mcp:
      capabilities:
        deny: ["logging"]
      notifications:
        deny: ["notifications/progress"]
      namespacing:
        requestId: opaque
        sseEventId: upstream-slash
      security:
        signedProxiedRequestIds: true
        upstreamDefault:
          clientCapabilitiesMode: passthrough
          rewriteClientInfo: false
          serverRequests:
            defaultAction: allow
            allow: []
            deny: []
        upstreamOverrides:
          untrusted-upstream-1:
            clientCapabilitiesMode: strip
            rewriteClientInfo: true
            serverRequests:
              defaultAction: deny
              allow: []
              deny: []
```
