# Outbound HTTP safety (SSRF hardening)

The Gateway can make outbound HTTP requests when it executes:

- gateway-native **HTTP tool sources**
- gateway-native **OpenAPI tool sources**
- `OpenAPI inspect` (wizard endpoint)
- proxying to **upstream MCP servers** (Streamable HTTP upstream endpoints)

Because the Gateway is intended to be deployed in **multi-tenant** environments, it applies a restrictive outbound policy by default to reduce SSRF risk.

## Why private networks are blocked by default

If a tenant can configure tool sources that cause the Gateway to fetch arbitrary URLs, they can attempt to access internal-only endpoints (SSRF), for example:

- services on the same private network (`http://db:5432`, `http://redis:6379`, `http://kube-dns...`)
- loopback endpoints on the Gateway host (`http://127.0.0.1:...`)
- link-local/metadata endpoints (`http://169.254.169.254`)

So the default Gateway policy blocks destinations that resolve to:

- loopback, private (RFC1918), link-local, CGNAT, reserved ranges, etc.

This is implemented by `OutboundHttpSafety::gateway_default()` in `crates/http-tools/src/safety.rs`.

## Opt-in override (explicit operator choice)

You can opt into allowing private network destinations by setting:

- `UNRELATED_GATEWAY_OUTBOUND_ALLOW_PRIVATE_NETWORKS=1`

This is intentionally an **explicit operator choice**. Turning it on means “I understand this increases SSRF blast radius”.

### When it makes sense

- local development / docker-compose demos (service DNS like `http://petstore:8080/...` resolves to a private IP)
- single-tenant gateways
- controlled deployments where tenants **cannot** set arbitrary tool source URLs (or where a strict egress allowlist exists)

### When it is dangerous

In a true multi-tenant environment where tenants can create/edit tool sources freely, enabling private-network outbound can allow tenants to probe internal services.

## Optional host allowlist

You can also restrict outbound destinations by hostname:

- `UNRELATED_GATEWAY_OUTBOUND_ALLOWED_HOSTS=host1,host2`

Notes:

- matching is **case-insensitive**
- hosts must match exactly (no wildcards today)

## Redirects and body limits

Gateway defaults are intentionally strict:

- redirects: **not followed** (gateway-native HTTP/OpenAPI tools and upstream MCP proxying)
- max response body: **1 MiB** (gateway-native HTTP/OpenAPI tool sources only)

## HTTPS requirement for upstream MCP endpoints (scheme policy)

For upstream MCP endpoint URLs (Streamable HTTP), the Gateway prefers **TLS by default**:

- upstream endpoint URLs must use **`https://`**
- `http://` is rejected unless an explicit dev override is set:
  - `UNRELATED_GATEWAY_UPSTREAM_ALLOW_HTTP=1`

This is enforced both:

- when upstream endpoints are created/updated (validation), and
- at connect-time (second line of defense).

Notes:

- This is **separate** from the private-network SSRF override. Even with HTTPS, private IP ranges are still blocked unless `UNRELATED_GATEWAY_OUTBOUND_ALLOW_PRIVATE_NETWORKS=1` is set.
- Today, this HTTPS scheme policy applies to **upstream MCP endpoints** only (not to gateway-native HTTP/OpenAPI tool sources).

## Scope / what this does *not* cover

This policy applies to:

- **gateway-native HTTP/OpenAPI tool sources** (and `openapi/inspect`), and
- **upstream MCP endpoint URLs** (when the Gateway connects to upstream MCP servers over Streamable HTTP).

It does not change the Gateway’s “no Authorization passthrough” stance.

