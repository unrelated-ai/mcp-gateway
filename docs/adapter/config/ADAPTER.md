# `adapter:` (process settings)

This section controls the adapter process itself (bind address, logging, timeouts, stdio restart policy), and (optionally) the **tool surface transforms** exposed by this adapter.

Source of truth: [`crates/adapter/src/config.rs`](../../../crates/adapter/src/config.rs) (`AdapterSection` + `TransformPipeline`).

## Example

```yaml
adapter:
  bind: 127.0.0.1:3000
  # Optional: protect HTTP endpoints (including /mcp) with a static bearer token.
  # mcpBearerToken: ${ADAPTER_BEARER_TOKEN}
  logLevel: info
  callTimeout: 60
  startupTimeout: 30
  openapiProbe: true
  openapiProbeTimeout: 5
  restartPolicy: on_demand
  stdioLifecycle: per_session
  restartBackoff:
    minMs: 250
    maxMs: 30000
  transforms:
    toolOverrides:
      tool_a:
        rename: renamed_tool_a
        params:
          oldParam:
            rename: newParam
          limit:
            default: 10
```

## Fields

### `bind`

- **Type**: string (`ip:port`)
- **Default**: `127.0.0.1:3000`
- **Notes**: can contain `${ENV}` (see [`ENV_AND_PRECEDENCE.md`](ENV_AND_PRECEDENCE.md)).

### `mcpBearerToken`

- **Type**: string (optional)
- **Default**: none
- **Meaning**: when set, the adapter requires:

  - `Authorization: Bearer <token>`

  for **all** HTTP endpoints except:

  - `/health*`
  - `/ready`

- **Overrides**:
  - CLI: `--mcp-bearer-token <token>`
  - Env: `UNRELATED_MCP_BEARER_TOKEN=<token>`

### `logLevel`

- **Type**: string
- **Default**: `info`
- **Notes**: uses `tracing` filter syntax.

### `callTimeout`

- **Type**: integer seconds (can be a string if using env expansion)
- **Default**: `UNRELATED_TOOL_CALL_TIMEOUT_DEFAULT_SECS` (defaults to `60`)
- **Meaning**: per tool-call timeout (applies to all backends).
- **Notes**:
  - This value is clamped to `UNRELATED_TOOL_CALL_TIMEOUT_MAX_SECS` (shared Gateway ↔ Adapter cap).
  - Legacy: `UNRELATED_TOOL_CALL_TIMEOUT_SECS` sets both default + max.
  - When running behind the Gateway, the adapter also honors `params._meta.unrelated.timeoutMs` as a per-request budget (clamped to `callTimeout` and the shared max cap).

### `startupTimeout`

- **Type**: integer seconds
- **Default**: `30`
- **Meaning**: max time to wait for servers to initialize on startup.

### `openapiProbe`

- **Type**: boolean (can be a string if using env expansion)
- **Default**: `true`
- **Meaning**: on startup, probe configured OpenAPI base URLs for reachability.
- **Notes**: if an OpenAPI spec (especially a local file) contains an unreachable placeholder server URL and you don't set `servers.<name>.baseUrl`, the probe can fail startup. Mitigate by setting `servers.<name>.baseUrl` to a reachable host or setting `adapter.openapiProbe: false`.

### `openapiProbeTimeout`

- **Type**: integer seconds
- **Default**: `5`
- **Meaning**: timeout for the OpenAPI base URL probe.

### `restartPolicy`

- **Type**: enum: `never` | `on_demand` | `always`
- **Default**: `on_demand`
- **Meaning**: stdio backend restart behavior (mainly relevant when `stdioLifecycle: persistent`).

### `stdioLifecycle`

- **Type**: enum: `persistent` | `per_session` | `per_call`
- **Default**: `per_session`
- **Meaning**: controls **how stdio MCP server child processes are reused**.
- **Notes**:
  - Can be overridden per server via `servers.<name>.lifecycle` (see [`SERVERS_STDIO.md`](SERVERS_STDIO.md)).
  - `per_session` requires clients to use MCP sessions (the adapter supports sessions on `/mcp` by default).

### `restartBackoff`

- **Type**: object
- **Fields**:
  - `minMs` (**default** `250`)
  - `maxMs` (**default** `30000`)
- **Validation**: `minMs <= maxMs` (otherwise startup fails).

### `transforms`

- **Type**: object (`TransformPipeline`)
- **Default**: empty (no transforms)
- **Meaning**: apply shared transforms to `tools/list` and `tools/call`:
  - **`toolOverrides`**: per tool overrides keyed by **original tool name**
    - `rename`: exposed tool name
    - `description`: exposed tool description
    - `params`: per-param overrides keyed by **original param name**
      - `rename`: exposed param name
      - `default`: JSON default value (injected on missing/`null`)

Semantics:

- **`tools/list`**:
  - tool names are rewritten using `toolOverrides.<tool>.rename`
  - tool descriptions can be overridden using `toolOverrides.<tool>.description`
  - top-level JSON schema `properties` keys and `required[]` entries are rewritten using `toolOverrides.<tool>.params.<param>.rename`
  - defaults are surfaced as `properties.<exposed_param>.default` (best-effort)
- **`tools/call`**:
  - incoming arguments are accepted using **exposed** param names and rewritten back to **original** param names
  - defaults are injected when an arg is missing or `null` (after arg rewrite to original names)
