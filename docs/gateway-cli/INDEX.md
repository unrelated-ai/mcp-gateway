# Gateway CLI (`unrelated-gateway-admin`)

`unrelated-gateway-admin` is a small CLI tool for managing the **Gateway control plane** (Admin API).

Current focus:

- **Mode 3 only** (Postgres-backed Gateway)
- **Control-plane only** operations (no data-plane MCP calls)
- **Admin-operated**: the CLI authenticates with the **admin token** and is intended for cluster operators.
  - For tenant-scoped actions (like managing API keys), the CLI uses the admin token to **issue a tenant token** and then calls tenant APIs.
  - Tenants should not rely on this CLI directly; they should use tenant-facing APIs.
- Runtime/topology diagnostics are exposed by the Gateway `/status` endpoint (`runtimeMode`, `topology`, `nodeId`).

## Quickstart

1. Start the stack (example):

- `make up`

2. Configure the CLI (saves token + defaults to a local config file):

- `cargo run -p unrelated-gateway-admin -- config set --admin-base http://127.0.0.1:27101 --data-base http://127.0.0.1:27100 --token dev-admin-token`

3. List resources:

- `cargo run -p unrelated-gateway-admin -- tenants list`
- `cargo run -p unrelated-gateway-admin -- upstreams list`
- `cargo run -p unrelated-gateway-admin -- profiles list`

## Docs

- Commands: [`docs/gateway-cli/COMMANDS.md`](COMMANDS.md)
- Config/auth precedence: [`docs/gateway-cli/CONFIG.md`](CONFIG.md)
- `mcp.json` output: [`docs/gateway-cli/MCP_JSON.md`](MCP_JSON.md)
