# Legacy `imports` migration

`imports` is no longer supported by the adapter.

If your config still contains:

```yaml
imports:
  - type: mcp-json
    path: ...
```

the adapter now fails startup with a migration-focused error message.

## What to do instead

Move each imported server into `servers:` directly.

### Before (legacy)

```yaml
imports:
  - type: mcp-json
    path: /path/to/legacy-mcp.json
```

### After (supported)

```yaml
servers:
  filesystem:
    type: stdio
    command: npx
    args: ["-y", "@modelcontextprotocol/server-filesystem", "/data"]
```

## Quick conversion checklist

1. Open your old `mcpServers` JSON.
2. For each entry, copy command/args/env into a `servers.<name>` block with `type: stdio`.
3. Remove the `imports` section entirely (or keep it empty as `imports: []` during transition).
4. Start the adapter and confirm `tools/list` returns the expected tools.

## Source of truth

- [`crates/adapter/src/config.rs`](../../../crates/adapter/src/config.rs)
