# OpenAPI backend (overview / historical notes)

This document used to be a long “feature spec”. The OpenAPI backend is now **implemented**, and the canonical docs are:

- Config reference: [`config/SERVERS_OPENAPI.md`](config/SERVERS_OPENAPI.md)
- Shared auth config: [`config/AUTH.md`](config/AUTH.md)
- Adapter architecture: [`ARCHITECTURE.md`](ARCHITECTURE.md)

This page stays intentionally short and captures the **non-obvious behavior** that is useful when operating the adapter.

## What it does

Given `servers.<name>.type: openapi`, the adapter:

- loads an OpenAPI spec (URL or file)
- generates MCP tools (auto-discovery and/or explicit mappings)
- forwards MCP tool calls as HTTP requests to the configured `baseUrl` (or spec server URL)

## Non-goals

- No tenancy or identity-based/per-tenant inbound policy and transforms (Gateway/reverse-proxy
  responsibility); the Adapter's optional static bearer guard can protect its HTTP surface
- No cross-cutting response masking/policy transformations (Gateway responsibility)

## Tool generation (high level)

- **Tool names**
  - If `endpoints` explicitly maps an operation: `tool: <name>` is used.
  - Else, `operationId` is used when present.
  - Else, a canonical name is derived from method+path.
  - Name collisions are resolved by suffixing (`_2`, `_3`, …) at generation time; collisions across servers are handled by the aggregator (prefix-on-collision).

- **Tool descriptions**
  - Prefer explicit config description, then OpenAPI `summary`, then OpenAPI `description`, else a fallback like `Calls {METHOD} {path}`.

- **Parameters**
  - Path/query/header params become tool arguments.
  - For `application/json` request bodies:
    - object bodies may be flattened into tool args
    - otherwise a single `body` argument may be used
  - Parameter collisions fail with a helpful error; explicit `endpoints.*.*.params.*.rename` can resolve.

## Auto-discovery filters

`autoDiscover` supports:

- `true` (discover all)
- `false` (explicit endpoints only)
- `{ include: [...], exclude: [...] }` where patterns are matched against strings like `"GET /pet/{petId}"`.

Exclude wins.

## Spec hash verification

If you set `specHash`, the adapter computes `sha256:<hex>` of the raw spec content.

- `specHashPolicy: warn` (default): log a warning and continue
- `specHashPolicy: fail`: exit on mismatch
- `specHashPolicy: ignore`: do nothing

See: [`config/SERVERS_OPENAPI.md`](config/SERVERS_OPENAPI.md)

## OpenAPI probing

By default `adapter.openapiProbe` is `true`, which probes the effective base URL on startup.

See: [`config/ADAPTER.md`](config/ADAPTER.md)

## Related docs

- [`config/SERVERS_OPENAPI.md`](config/SERVERS_OPENAPI.md)
- [`config/SERVERS_HTTP.md`](config/SERVERS_HTTP.md) (manual tool DSL used by OpenAPI overrides)
- [`ARCHITECTURE.md`](ARCHITECTURE.md)
