# Unrelated MCP Adapter — Architecture

> **Repo**: `unrelated-ai/mcp-gateway` (Cargo workspace)  
> **Binary**: `unrelated-mcp-adapter` ([`crates/adapter/`](../../crates/adapter/))  
> **Status**: implemented

## What it does

The adapter exposes **one MCP server over streamable HTTP** (`/mcp`) while aggregating multiple backends:

- **stdio MCP servers** (spawned as child processes)
- **OpenAPI backends** (OpenAPI spec → tools → outgoing HTTP requests)
- **manual HTTP backends** (HTTP tool DSL, no OpenAPI)

It also exposes operational endpoints on the same port: `/health`, `/health/any`, `/health/all`, `/ready`, `/status`, `/map`.

Notes:

- `/map` is an operational “wiring/debug” view (server ownership + exposed names).
- `tools/list` is the protocol-level view (what an MCP client sees).

## High-level architecture

- **Config loader** ([`crates/adapter/src/config.rs`](../../crates/adapter/src/config.rs)): reads unified config (YAML/JSON) + legacy MCP JSON imports, expands `${ENV}` values, applies CLI/ENV overrides.
- **Backends** ([`crates/adapter/src/supervisor.rs`](../../crates/adapter/src/supervisor.rs), [`crates/adapter/src/openapi.rs`](../../crates/adapter/src/openapi.rs), [`crates/adapter/src/http_backend.rs`](../../crates/adapter/src/http_backend.rs)): implement a shared `Backend` trait.
- **Aggregator** ([`crates/adapter/src/aggregator.rs`](../../crates/adapter/src/aggregator.rs)): merges tools/resources/prompts across all backends, handles collisions, provides routing.
- **MCP server handler** ([`crates/adapter/src/mcp_server.rs`](../../crates/adapter/src/mcp_server.rs)): implements MCP methods (`tools/*`, `resources/*`, `prompts/*`) using the aggregator and backends.
- **HTTP server** ([`crates/adapter/src/http.rs`](../../crates/adapter/src/http.rs)): serves MCP over **streamable HTTP** (`/mcp`) and aux endpoints on a single `--bind`.

### Shared tooling crates (deduplication)

The HTTP DSL and OpenAPI tooling logic is implemented in shared crates and reused by both the Adapter and the Gateway:

- `crates/http-tools/` (`unrelated-http-tools`)
- `crates/openapi-tools/` (`unrelated-openapi-tools`)

The Adapter’s `http` and `openapi` backends are thin wrappers around these crates (the Adapter remains usable standalone).

## Workspace layout

```text
mcp-gateway/
├── Cargo.toml               # workspace config (edition/MSRV/repo)
├── Cargo.lock
├── crates/
│   ├── adapter/             # unrelated-mcp-adapter binary crate
│   ├── gateway/             # unrelated-mcp-gateway binary crate
│   ├── gateway-cli/         # unrelated-gateway-admin binary crate
│   ├── http-tools/          # shared HTTP tools runtime/config
│   ├── openapi-tools/       # shared OpenAPI parsing/runtime
│   └── tool-transforms/     # shared tool surface transforms
├── Dockerfile
├── docker-compose.yml
├── ui/                      # Web UI (Next.js)
├── .github/workflows/ci.yml
├── .github/workflows/release.yml
├── .github/workflows/docker-release.yml
└── tests/fixtures/
    ├── test-config.yaml
    └── test-config.json
```

## Configuration

### Unified config (recommended)

Top-level keys:

- **`adapter`**: process settings (bind/log/timeouts/restarts)
- **`imports`**: load-time includes (e.g. legacy MCP JSON files)
- **`servers`**: runtime backends (`stdio` / `openapi` / `http`)

Example:

```yaml
adapter:
  bind: 0.0.0.0:8080
  # Optional: protect HTTP endpoints (including /mcp) with a static bearer token.
  # mcpBearerToken: ${ADAPTER_BEARER_TOKEN}
  logLevel: info
  callTimeout: 30
  startupTimeout: 30
  openapiProbe: true
  openapiProbeTimeout: 5
  restartPolicy: on_demand
  restartBackoff:
    minMs: 250
    maxMs: 30000

imports:
  - type: mcp-json
    path: ~/.config/claude/claude_desktop_config.json
    prefix: legacy

servers:
  filesystem:
    type: stdio
    command: npx
    args: ["-y", "@modelcontextprotocol/server-filesystem", "/data"]

  petstore:
    type: openapi
    spec: https://petstore3.swagger.io/api/v3/openapi.json
    baseUrl: https://petstore3.swagger.io/api/v3
    autoDiscover: true

  internal:
    type: http
    baseUrl: https://internal.example/api
    tools:
      get_user:
        method: GET
        path: /users/{id}
        params:
          id: { in: path, required: true, schema: { type: string } }
```

### Precedence

Configuration precedence is:

```text
CLI > ENV (via clap) > config file > defaults
```

Note: log level has one extra fallback: if `--log-level` / `UNRELATED_LOG` is not set, `RUST_LOG` is used before the config file.

### Environment expansion

Strings can contain `${VAR}`; missing vars fail startup.

## Backends

### Stdio backends (`type: stdio`)

- Spawned as child processes via `rmcp` (`TokioChildProcess`).
- Lifecycle (`stdioLifecycle` / `servers.<name>.lifecycle`):
  - `persistent`: one shared process for all sessions/calls
  - `per_session`: one process per MCP session
  - `per_call`: one process per tool/resource/prompt call
- Restart policy (`restartPolicy`):
  - `never`: return errors if server is down
  - `on_demand`: restart only when a request arrives for that backend
  - `always`: attempt background restarts when the transport dies
- A successful restart triggers a **best-effort registry refresh** (only when the tool/resource/prompt surface actually changed), so `/map` and `tools/list` reflect the new tool surface.
  - If the refresh changes the exposed surface, the adapter also emits best-effort cache invalidation hints to connected clients:
    - `notifications/tools/list_changed`
    - `notifications/resources/list_changed`
    - `notifications/prompts/list_changed`

### OpenAPI backends (`type: openapi`)

- Spec source can be a **URL** or **file path**.
- Supports `$ref` across **local**, **file**, and **http(s)** documents (via `unrelated-openapi-tools`).
- `autoDiscover` supports include/exclude patterns like `"GET *"` or `"*/admin/*"`.
- Optional base URL probe on startup (`openapiProbe` + `openapiProbeTimeout`).
- Supports operation-level **manual overrides** (HTTP tool DSL) via `servers.<name>.overrides`.

### Manual HTTP backends (`type: http`)

- Tools are defined in config (`servers.<name>.tools`).
- Supports auth injection and query/body/header/path parameter mapping.

## Aggregation + routing

### Tool/prompt name collisions

The adapter uses **prefix-on-collision**:

- No collision: tool keeps its original name (`read_file`)
- Collision: tools become `server:tool` (e.g. `github:search`, `filesystem:search`)

### Resource URI collisions

If two servers expose the same resource URI, the adapter rewrites colliding URIs into a stable URN:

```text
urn:unrelated-mcp-adapter:resource:<server>:<sha256(original_uri)>
```

### Routing

The MCP handler uses the aggregator’s mapping to route calls/resources/prompts to the owning backend via `BackendManager::get_backend()`.

## HTTP surface

### MCP-over-streamable-HTTP (rmcp-native)

- `POST /mcp`: send JSON-RPC messages; the `initialize` request creates a session and returns `Mcp-Session-Id` (responses stream back as `text/event-stream` in the HTTP response body).
- `GET /mcp`: open a `text/event-stream` response stream for an existing session (requires `Mcp-Session-Id` header).
- `DELETE /mcp`: close a session (requires `Mcp-Session-Id` header).

### Operational endpoints

- `GET /health`: always 200 when the process is alive
- `GET /health/any`: 200 if any backend is running (or no backends configured), else 503
- `GET /health/all`: 200 if all backends are running (or no backends configured), else 503
- `GET /ready`: 200 if all backends are running (or no backends configured), else 503
- `GET /status`: version/uptime/backend states + request counters
- `GET /map`: tools/resources/prompts with server ownership metadata (for gateway routing/UI)

## Build, Docker, CI/CD

- **Rust**: edition 2024, MSRV 1.92.0 (see workspace [`Cargo.toml`](../../Cargo.toml)).
- **Release build**: `cargo build --release -p unrelated-mcp-adapter`
- **Docker image**: [`Dockerfile`](../../Dockerfile) builds an optimized release binary in a builder stage and copies it into a slim runtime image.
- **GitHub Actions**:
  - CI (PRs): [`.github/workflows/ci.yml`](../../.github/workflows/ci.yml)
  - Releases (tags): [`.github/workflows/release.yml`](../../.github/workflows/release.yml) → calls [`.github/workflows/docker-release.yml`](../../.github/workflows/docker-release.yml)

## Security model (current scope)

- No built-in **multi-tenant inbound** authn/z, TLS termination, or rate limiting.
- Safety guardrails are implemented:
  - optional static bearer-token protection for HTTP endpoints (including `/mcp`) via `adapter.mcpBearerToken`
- Outbound backend auth **is supported** for `type: http` and `type: openapi` via `auth:` blocks (see `docs/adapter/config/AUTH.md`).
- Assumes a trusted network / reverse proxy / Gateway provides inbound controls.

## Authorization forwarding stance (important)

This repository follows the MCP security guidance around the “confused deputy” problem:

- **Inbound client `Authorization` is not used for outbound calls.** The Adapter does not take an `Authorization` header from an MCP client request and “pass it through” to HTTP/OpenAPI backends.
- **Outbound auth is explicit and configuration-driven.** When an HTTP/OpenAPI backend needs credentials, they are provided via the backend’s `auth:` block (and/or explicit default headers), typically sourced from `${ENV}` (and later, tenant secrets via the Gateway).

See also:

- Adapter outbound auth config: `docs/adapter/config/AUTH.md`
- Gateway tenant secrets + `${secret:...}` placeholders: `docs/gateway/MODE3_TENANT_OVERLAY.md`
