# MCP proxying & aggregation (Gateway ⇄ Adapter)

This page describes how the Gateway behaves as an MCP server when it is aggregating multiple upstream MCP servers (typically Adapters).

## Start here

- Gateway overview: [`docs/gateway/INDEX.md`](INDEX.md)
- Adapter overview: [`docs/adapter/INDEX.md`](../adapter/INDEX.md)
- Profile MCP settings (capabilities, notifications, namespacing, security): [`docs/gateway/MCP_SETTINGS.md`](MCP_SETTINGS.md)

## What “aggregation” means for MCP

Aggregation means the Gateway exposes **one** MCP endpoint (`/{profile_id}/mcp`) that is backed by **many** upstream sessions.

This introduces three classes of collisions:

- **Name collisions** (tools/prompts): handled by prefixing with `<upstream_id>:` when needed.
- **Resource URI collisions**: handled by rewriting to stable Gateway URNs (`urn:unrelated-mcp-gateway:resource:...`) when needed.
- **ID collisions** (server→client requests, SSE event ids): handled by namespacing IDs so responses/resume work correctly.

## Supported MCP interactions (today)

### Server → client requests (interactive flows)

The Gateway can forward upstream server→client requests (JSON-RPC `request` messages) by rewriting
the JSON-RPC `id` in the merged SSE stream so the downstream client’s response can be routed back
to the correct upstream session.

Security / policy:

- Forwarding is gated by **per-upstream** policy under `mcp.security.*.serverRequests`.
- If a request method is blocked, the Gateway:
  - does **not** forward it to the downstream client
  - replies upstream with a JSON-RPC error (typically `-32601 Method not found`)

This applies to any upstream server→client request, for example:

- `sampling/createMessage`
- `roots/list`
- `elicitation/create`

### Response-forgery hardening (signed proxied request IDs)

When enabled (`mcp.security.signedProxiedRequestIds: true`), the Gateway emits **signed** proxied
request IDs (HMAC, per-session key stored inside the encrypted session token). Downstream responses
are only routed upstream if the proxied ID verifies. This mitigates malicious downstream clients
fabricating “valid-looking” proxied IDs.

### Client → server methods (routed / fanned out)

- `tools/list`, `resources/list`, `prompts/list` (fan-out + merge)
- `tools/call`, `resources/read`, `prompts/get` (route to owning upstream)
- `completion/complete` (route by prompt/resource owner)
- `resources/subscribe`, `resources/unsubscribe` (route by resource owner)
- `logging/setLevel` (best-effort fanout)

### Notifications (merged SSE)

Forwarded best-effort from upstreams (stdio backends via the Adapter):

- `notifications/cancelled`
- `notifications/progress`
- `notifications/message`
- `notifications/resources/updated` *(URI rewriting keeps subscriptions consistent under collision URNs)*
- `notifications/tools/list_changed`, `notifications/resources/list_changed`, `notifications/prompts/list_changed`

## Loop prevention (self-upstream protection)

It is possible to accidentally configure a profile to “point to itself” by creating an upstream MCP server that uses the profile’s own data-plane URL (`/{profile_id}/mcp`). If the Gateway then proxies `tools/list`, `tools/call`, etc. to that upstream, it can create a **proxy loop**.

### Config-time guard (implemented)

When creating/updating a profile, the Gateway rejects any upstream whose endpoint URL path matches:

- `/{profile_id}/mcp` (or `/{profile_id}/mcp/`)

This blocks the most obvious “self link” misconfiguration.

### Runtime loop guard header (implemented; also recommended for future)

To make loops **fail fast** even when config-time detection misses something (or in multi-hop topologies), the Gateway adds an internal hop counter header on outbound upstream requests:

- `x-unrelated-gateway-hop: <n>`

On each proxy hop, the Gateway increments the value and rejects forwarding once it exceeds a small maximum (currently 8 hops), returning `502 Bad Gateway` with a loop-detected message.

**Future improvement recommendation**: standardize this hop header across gateways/proxies so multi-gateway deployments can prevent loops deterministically, and consider making the max configurable per environment.

## Outbound safety for upstream MCP endpoints (implemented)

The Gateway applies its outbound HTTP safety policy (SSRF hardening) to **upstream MCP endpoint URLs**:

- non-`http(s)` schemes are rejected
- private/loopback/link-local/reserved destinations are blocked by default (unless explicitly allowed)
- redirects are not followed for upstream MCP proxying

See: [`docs/gateway/OUTBOUND_HTTP_SAFETY.md`](OUTBOUND_HTTP_SAFETY.md)

## Config knobs that improve UX

All of these are per-profile settings under `mcp:` (see [`docs/gateway/MCP_SETTINGS.md`](MCP_SETTINGS.md)):

- **`mcp.capabilities` allow/deny**: controls what the Gateway advertises in `initialize` and enforces at runtime.
- **`mcp.notifications` allow/deny**: filter noisy upstream notifications without changing defaults (defaults allow everything).
- **`mcp.namespacing`**: choose request-id and SSE-event-id namespacing formats (defaults are safe for aggregation).
- **`mcp.security`**: per-upstream trust controls (client capability forwarding, server→client request filtering, signed proxied IDs).

## Additional runtime behavior (implemented)

### `tools/call` argument validation

The Gateway validates `tools/call` arguments against the **advertised tool input schema** (the same schema returned by `tools/list`).

- Unknown parameters are rejected with `-32602 Invalid params` and include “did you mean …?” suggestions when likely.
- Validation errors include structured details under the JSON-RPC error `data` field.

### Binary + image tool results (HTTP/OpenAPI sources)

When the underlying HTTP API returns `Content-Type: image/*`, HTTP/OpenAPI tool execution returns MCP **image content** (`type: "image"`, base64 `data`, and `mimeType`).

For other non-UTF8 binary bodies, tool execution safely returns a base64-wrapped JSON value instead of failing UTF-8 decoding.

## Limitations

- Tasks (SEP-1686) are not proxied end-to-end yet (blocked on a newer published RMCP than crates.io `rmcp 0.12.0`).
- `notifications/roots/list_changed` is not forwarded yet (RMCP type exposure gap).
