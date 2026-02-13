# Testing & Running (local)

## Run the full demo stack (Docker Compose)

```bash
make up
```

Notes:

- The base adapter image is intentionally minimal (final target is `scratch`, no extra runtimes).
- The stdio aggregation aspect uses the `Dockerfile` target `stdio-node` (adds Node/npm for stdio MCP servers, without bloating the default image target).

Ports:

- `27100`: gateway (data plane)
- `27101`: gateway (admin/control plane)
- `27102`: gateway UI
- `5433`: Postgres (gateway Mode 3 DB)
- `8080`: adapter (HTTP tools aspect)
- `8081`: httpbin (direct)
- `8082`: petstore (direct)
- `8083`: adapter (OpenAPI aspect)
- `8084`: adapter (stdio aggregation aspect)

Config files used by the demo stack live under [`tests/fixtures/`](../../tests/fixtures/):

- [`tests/fixtures/http-tools-httpbin.yaml`](../../tests/fixtures/http-tools-httpbin.yaml) (used by `adapter_http_tools`)
- [`tests/fixtures/openapi-petstore3.yaml`](../../tests/fixtures/openapi-petstore3.yaml) (used by `adapter_openapi`)
- [`tests/fixtures/stdio-aggregation.yaml`](../../tests/fixtures/stdio-aggregation.yaml) (used by `adapter_stdio_aggregation`)

### Fixture configs as a playground (recommended)

Even though they live under `tests/`, the files in [`tests/fixtures/`](../../tests/fixtures/) are **small, commented example configs** and a great way to experiment:

- **Validate a config (no servers started)**:

```bash
cargo run -p unrelated-mcp-adapter --bin unrelated-mcp-adapter -- \
  --config tests/fixtures/minimal-no-servers.yaml \
  --print-effective-config
```

- **Start an adapter with an example config**:

```bash
cargo run -p unrelated-mcp-adapter --bin unrelated-mcp-adapter -- \
  --config tests/fixtures/minimal-no-servers.yaml
```

Notes:

- Some fixtures are meant to **fail** (to demonstrate validation), for example:
  - `adapter-invalid-restart-backoff.yaml`
  - `http-tools-auth-missing-env.yaml`
- Some fixtures assume the **docker-compose** network (e.g. `http://httpbin:80`, `http://petstore:8080`). If you’re not running the demo stack, prefer the `*-host.yaml` variants.
- The `stdio-*.yaml` fixtures require **Node/npm** (`npx`) for the example MCP servers; they’re easiest to run via the demo stack (`make up`) or with the adapter’s `stdio-node` image target.
- `openapi-mini-spec.yaml` is an OpenAPI **spec file** used by other fixtures (not an adapter config by itself).

Logs:

```bash
make logs
```

Stop everything:

```bash
make down
```

## Optional HTTP bearer-token guardrail

If you set `UNRELATED_MCP_BEARER_TOKEN` (or `adapter.mcpBearerToken`), the adapter will require
`Authorization: Bearer <token>` for all non-health endpoints (including `/mcp`).

Quick manual check:

```bash
# Start an adapter with bearer auth enabled
UNRELATED_MCP_BEARER_TOKEN=devtoken cargo run -p unrelated-mcp-adapter --bin unrelated-mcp-adapter -- \
  --config tests/fixtures/minimal-no-servers.yaml

# Health stays unauthenticated
curl -i http://127.0.0.1:3000/health

# Non-health endpoints require the token
curl -i http://127.0.0.1:3000/map
curl -i -H "Authorization: Bearer devtoken" http://127.0.0.1:3000/map
```

## Unit tests

```bash
make test-unit
```

## Integration tests (Testcontainers)

Integration tests are **ignored by default** (`#[ignore]`) so CI stays fast and doesn’t require Docker.

Run them locally (requires Docker daemon):

```bash
make test-integration
```

Current integration coverage:

- HTTP tools backend (`type: http`) end-to-end via MCP-over-streamable-HTTP (`/mcp`)
- OpenAPI backend (`type: openapi`) end-to-end via MCP-over-streamable-HTTP (`/mcp`) (Petstore addPet/getPetById roundtrip)
- OpenAPI config behaviors: auto-discover include/exclude, explicit endpoints, overrides, spec hash policy (fail)
- Mixed sources (`http` + `openapi`) collision prefixing + routing end-to-end
