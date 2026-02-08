# Documentation Index

This documentation covers the **`unrelated-mcp-adapter`** binary in this repository ([`crates/adapter/`](../../crates/adapter/)).

## Start here

- **Quickstart & walkthrough**: root [`README.md`](../../README.md) (Docker + curl)
- **How to run locally**: [`TESTING.md`](TESTING.md)
- **Architecture overview**: [`ARCHITECTURE.md`](ARCHITECTURE.md)

## Configuration (field-by-field reference)

The adapter supports a **unified config file** (recommended) plus legacy MCP JSON imports.

- **Overview**: [`CONFIG.md`](CONFIG.md)
- **Adapter process settings** (`adapter:`): [`config/ADAPTER.md`](config/ADAPTER.md)
- **Imports** (`imports:`): [`config/IMPORTS.md`](config/IMPORTS.md)
- **Servers** (`servers:`):
  - **Stdio MCP servers** (`type: stdio`): [`config/SERVERS_STDIO.md`](config/SERVERS_STDIO.md)
  - **Manual HTTP tools** (`type: http`): [`config/SERVERS_HTTP.md`](config/SERVERS_HTTP.md)
  - **OpenAPI** (`type: openapi`): [`config/SERVERS_OPENAPI.md`](config/SERVERS_OPENAPI.md)
- **Authentication** (`auth:` blocks): [`config/AUTH.md`](config/AUTH.md)
- **Environment expansion & precedence**: [`config/ENV_AND_PRECEDENCE.md`](config/ENV_AND_PRECEDENCE.md)

## Protocol & endpoints

- **MCP endpoint**: `/mcp` (streamable HTTP) (see root [`README.md`](../../README.md))
- **Operational endpoints**: `/health`, `/health/any`, `/health/all`, `/ready`, `/status`, `/map` (see [`ARCHITECTURE.md`](ARCHITECTURE.md))

## Authentication (what “auth” means here)

The Adapter supports **outbound auth injection** for HTTP/OpenAPI backends via `auth:` blocks (e.g. bearer tokens, basic auth, custom headers, query parameters).

See: [`docs/adapter/config/AUTH.md`](config/AUTH.md).

Inbound note:

- The adapter can optionally require a **static bearer token** for HTTP endpoints (including `/mcp`)
  via `adapter.mcpBearerToken` (see [`config/ADAPTER.md`](config/ADAPTER.md)).

## CI/CD & releases

- **CI/CD overview**: [`docs/CICD.md`](../CICD.md)
- **How to cut a release**: [`docs/CICD.md`](../CICD.md)

## Design/spec docs (deep dive)

- **OpenAPI backend overview** (historical notes): [`OPENAPI_ADAPTER_SPEC.md`](OPENAPI_ADAPTER_SPEC.md)
