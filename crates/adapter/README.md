# unrelated-mcp-adapter

Expose MCP servers over streamable HTTP (`/mcp`).

Supports:

- Stdio-based MCP servers (child processes)
- HTTP APIs via OpenAPI (`type: openapi`)
- Manually defined HTTP tools (`type: http`)

> **IMPORTANT**
>
> The adapter intentionally does **not** implement authn/z or tenancy. Those controls are expected to be provided by the **Gateway** (or your reverse proxy).
>
> **Assumption**: the adapter runs only inside a **private network** (or behind your internal edge) and is **not** exposed directly to the public internet.

Guardrails:

- Default bind is loopback (`127.0.0.1:3000`). If you run it exposed (instead of behind the
  Gateway/reverse proxy), enable bearer-token protection below.
- Optional bearer-token protection for HTTP endpoints (including `/mcp`):
  - set `adapter.mcpBearerToken` or `UNRELATED_MCP_BEARER_TOKEN`
  - requests must include `Authorization: Bearer <token>` (health endpoints remain unauthenticated)

## Documentation

- Start here: [`docs/adapter/INDEX.md`](../../docs/adapter/INDEX.md)
- Configuration (field-by-field): [`docs/adapter/CONFIG.md`](../../docs/adapter/CONFIG.md)
- Local running & testing: [`docs/adapter/TESTING.md`](../../docs/adapter/TESTING.md)
- Architecture: [`docs/adapter/ARCHITECTURE.md`](../../docs/adapter/ARCHITECTURE.md)
