# Commands

The CLI is a thin wrapper around the Gateway Admin API.

## Global flags

- `--admin-base <url>`: admin API base URL (default `http://127.0.0.1:27101`)
- `--data-base <url>`: data-plane base URL (default `http://127.0.0.1:27100`)
- `--token <value>` / `--token-file <path>` / `--token-stdin`
- `--json`: machine-readable output (where supported)

## `config`

- `config show`
- `config set [--admin-base ...] [--data-base ...] [--token ...|--token-file ...|--token-stdin]`

## `tenants`

- `tenants list`
- `tenants get <id>`
- `tenants put <id> [--enabled true|false]`
- `tenants delete <id>` *(soft-delete: sets enabled=false)*
- `tenants issue-token <id> [--ttl-seconds <seconds>]`

### Tenant tool sources (Mode 3)

These map to the Mode 3 tenant overlay and are managed via admin endpoints:

- `tenants tool-sources <tenant_id> list`
- `tenants tool-sources <tenant_id> get <source_id>`
- `tenants tool-sources <tenant_id> put <source_id> [--body-json <json> | --body-file <path>]`
- `tenants tool-sources <tenant_id> delete <source_id>` *(soft-delete: sets enabled=false)*

`put` payload must be a JSON object that includes `type` (`http` or `openapi`) and config fields, e.g.:

```json
{
  "type": "http",
  "enabled": true,
  "baseUrl": "http://example:8080"
}
```

### Tenant secrets (Mode 3)

- `tenants secrets <tenant_id> list`
- `tenants secrets <tenant_id> put <name> [--value <value> | --value-file <path> | --value-stdin]`
- `tenants secrets <tenant_id> delete <name>`

### Tenant API keys (Mode 3)

The gateway's API keys are managed via the tenant control-plane API. The CLI issues an ephemeral tenant token under the hood.
This still requires **admin credentials** (issuing tenant tokens is an admin operation).

- `tenants api-keys <tenant_id> [--ttl-seconds <seconds>] list`
- `tenants api-keys <tenant_id> [--ttl-seconds <seconds>] create [--name <label>] [--profile-id <uuid>]`
- `tenants api-keys <tenant_id> [--ttl-seconds <seconds>] revoke <api_key_id>`

### Tenant OIDC principals (Mode 3)

These configure **OIDC principal bindings** (issuer + subject) that authorize JWT callers to a tenant and optionally a single profile.

- `tenants oidc-principals <tenant_id> list`
- `tenants oidc-principals <tenant_id> put <subject> [--profile-id <uuid>] [--enabled true|false]`
- `tenants oidc-principals <tenant_id> delete <subject> [--profile-id <uuid>]`

## `upstreams`

- `upstreams list`
- `upstreams get <id>`
- `upstreams put <id> --endpoint <ep_id>=<url> [--endpoint ...] [--enabled true|false]`
- `upstreams delete <id>` *(hard-delete: removes the upstream)*

## `profiles`

- `profiles list`
- `profiles get <uuid>`
- `profiles create --tenant-id <tenant> --name <name> [--description <text>] --upstream <upstream> [--upstream ...] [--source <source_id> ...] [--enabled true|false] [--allow-partial-upstreams true|false] [--tool <source_id:tool_name> ...] [--transforms-json <json> | --transforms-file <path>] [--data-plane-auth-mode <...>] [--accept-x-api-key true|false] [--rate-limit-enabled true|false] [--rate-limit-tool-calls-per-minute <n>] [--quota-enabled true|false] [--quota-tool-calls <n>] [--tool-call-timeout-secs <secs>] [--tool-policies-json <json> | --tool-policies-file <path>] [--mcp-json <json> | --mcp-file <path>]`
- `profiles put --id <uuid> --tenant-id <tenant> --name <name> [--description <text>] --upstream <upstream> [--upstream ...] [--source <source_id> ...] [--enabled true|false] [--allow-partial-upstreams true|false] [--tool <source_id:tool_name> ...] [--transforms-json <json> | --transforms-file <path>] [--data-plane-auth-mode <...>] [--accept-x-api-key true|false] [--rate-limit-enabled true|false] [--rate-limit-tool-calls-per-minute <n>] [--quota-enabled true|false] [--quota-tool-calls <n>] [--tool-call-timeout-secs <secs>] [--tool-policies-json <json> | --tool-policies-file <path>] [--mcp-json <json> | --mcp-file <path>]`
- `profiles delete <uuid>` *(hard-delete: removes the profile)*
- `profiles url <uuid>` *(prints `/{profile_id}/mcp` URL using `--data-base`)*

### Profile `dataPlaneAuth` settings (Mode 3)

- `--data-plane-auth-mode`: `disabled` | `api-key-initialize-only` | `api-key-every-request` | `jwt-every-request`
- `--accept-x-api-key true|false`

On `profiles put`, these settings are merged with the existing profile when provided (so you can update just one field).

### Profile `dataPlaneLimits` settings (Mode 3)

Limits are optional and disabled by default. When enabled, they apply to `tools/call` per API key.

- `--rate-limit-enabled true|false`
- `--rate-limit-tool-calls-per-minute <n>` *(required when enabled)*
- `--quota-enabled true|false`
- `--quota-tool-calls <n>` *(required when enabled)*

On `profiles put`, these settings are merged with the existing profile when provided.

### Tool call timeouts + per-tool policy overrides

These apply to `tools/call` only.

- `--tool-call-timeout-secs <secs>`: per-profile default `tools/call` timeout override.
- `--tool-policies-json <json>` / `--tool-policies-file <path>`: set per-tool overrides as a JSON array.

Example:

```json
[
  {
    "tool": "u1:search",
    "timeoutSecs": 5
  },
  {
    "tool": "u1:fetch",
    "retry": {
      "maximumAttempts": 3,
      "initialIntervalMs": 250,
      "backoffCoefficient": 2.0,
      "maximumIntervalMs": 2000,
      "nonRetryableErrorTypes": ["timeout"]
    }
  }
]
```

`nonRetryableErrorTypes` categories currently recognized by the Gateway:
`timeout`, `transport`, `upstream_5xx`, `deserialize`.

### Tool allowlisting semantics

Tool allowlisting is **optional**:

- omitted / `null` / `[]` → no allowlist configured (allow all tools)
- otherwise entries are `"<source_id>:<original_tool_name>"` (stable across transforms/renames)

### Tool transforms

You can attach a transform pipeline to a profile (stored as `profiles.transforms` in Mode 3).

- `--transforms-json <json>`: inline JSON
- `--transforms-file <path>`: JSON file

The payload schema matches `TransformPipeline` (`camelCase` keys):

```json
{
  "toolOverrides": {
    "tool_a": {
      "rename": "renamed_tool_a",
      "params": {
        "oldParam": { "rename": "newParam" },
        "limit": { "default": 10 }
      }
    }
  }
}
```

### MCP settings (`mcp`)

You can override per-profile MCP proxy behavior (capabilities allow/deny, notification filters, ID namespacing) by passing a `mcp` settings object.

- `--mcp-json <json>`: inline JSON object
- `--mcp-file <path>`: JSON file containing the object

The schema matches `McpProfileSettings` (see [`docs/gateway/MCP_SETTINGS.md`](../gateway/MCP_SETTINGS.md)).

## `mcp-json`

- `mcp-json servers-file --profile-id <uuid> [--name <mcpServers_key>]`
- `mcp-json server-entry --profile-id <uuid>`

Both commands print JSON to stdout (no files are written).
