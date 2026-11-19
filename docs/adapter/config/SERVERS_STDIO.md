# `servers.<name>: { type: stdio }`

A stdio server runs an external MCP server **as a child process** and re-exposes it through the adapter’s MCP endpoint (`/mcp`, streamable HTTP).

Source of truth: [`crates/adapter/src/config.rs`](../../../crates/adapter/src/config.rs) (`McpServerConfig`), [`crates/adapter/src/supervisor.rs`](../../../crates/adapter/src/supervisor.rs).

## Example

```yaml
servers:
  filesystem:
    type: stdio
    lifecycle: per_session  # optional override (defaults to adapter.stdioLifecycle)
    command: npx
    args: ["-y", "@modelcontextprotocol/server-filesystem", "/data"]
    env:
      NODE_ENV: production
```

## Fields

### `modernProtocol`

- **Type**: boolean
- **Default**: `false`
- Requires `adapter.modernProtocol: true` and a native MCP 2026-07-28 backend.
- Uses `persistent`; other explicit lifecycle values are rejected.

### `command`

- **Type**: string
- **Required**: yes
- **Meaning**: executable to spawn.

### `args`

- **Type**: list of strings
- **Default**: `[]`
- **Meaning**: argv passed to the command.

### `env`

- **Type**: map of string → string
- **Default**: `{}`
- **Meaning**: environment variables for the child process.

### `lifecycle`

- **Type**: enum: `persistent` | `per_session` | `per_call`
- **Default**: `adapter.stdioLifecycle`
- **Meaning**: override the stdio process reuse strategy for this server.

## Restart behavior (adapter-level)

Restart behavior for stdio servers is controlled by `adapter.restartPolicy` and `adapter.restartBackoff`.

> Note: `restartPolicy` is primarily meaningful when using `lifecycle: persistent` (one shared process).

See: [`ADAPTER.md`](ADAPTER.md)

## Lifecycle modes (pros/cons)

### `persistent`

One long-lived child process shared across all MCP sessions and calls.

- **Pros**:
  - **Fastest** per-call latency (no per-call spawn/connect).
  - **Supports stateful servers** that intentionally keep in-memory state/caches between calls.
  - Fewer processes overall (simpler ops, lower PID churn).
- **Cons**:
  - **Highest risk of cross-session / cross-tenant state leakage** if the server keeps state in memory (caches, auth tokens, “current workspace”, etc).
  - A single wedged/crashed process affects **all** clients.
  - Resource contention: one process serves all traffic (may become a bottleneck).
- **Good for**:
  - Single-tenant adapters, trusted callers, or servers that are proven stateless.
  - Very expensive startup servers where spawn/connect dominates latency.

### `per_session`

One child process per MCP session (`Mcp-Session-Id`), reused for all calls within that session.

- **Pros**:
  - **Strong isolation** between sessions (dramatically reduces “shared memory” leakage risk).
  - Still allows stateful servers *within* a single session (caches, conversational state, warm connections).
  - Naturally limits blast radius: one session’s process can crash without impacting others.
- **Cons**:
  - Higher memory/CPU footprint with many concurrent sessions (N sessions ⇒ N processes).
  - First call in a session pays a cold-start penalty (spawn + initialize).
  - If clients never close sessions, per-session processes can linger longer than intended.
- **Good for**:
  - Multi-tenant deployments.
  - Servers that are stateful or untrusted, where isolation matters more than pure throughput.

### `per_call`

One fresh child process per tool/resource/prompt call.

- **Pros**:
  - **Maximum isolation** (no state can persist between calls via process memory).
  - Simplifies correctness when servers are stateful but should *not* retain state between calls.
  - Minimizes “stuck process” impact (it dies with the call).
- **Cons**:
  - Highest latency and overhead (spawn + initialize every time).
  - Poor fit for servers that depend on maintaining long-lived state/caches.
  - Can generate significant process churn under load.
- **Good for**:
  - High-risk tools, untrusted servers, or very small/fast-starting servers.
  - Workloads where calls are infrequent and isolation is the top priority.

## Recommended default

The adapter defaults to `per_session` because it’s usually the best balance of isolation and performance for multi-tenant / shared deployments.
