# Configuration

The adapter uses a single configuration style: a **unified config file**.

- YAML is recommended.
- JSON also works when the file extension is `.json`.

This page is the entry point. For complete field-by-field docs, use the links below.

## Top-level structure

```yaml
adapter: {}   # process settings (bind/log/timeouts/restarts)
servers: {}   # runtime backends (stdio/openapi/http)
```

See:

- [`config/ADAPTER.md`](config/ADAPTER.md)
- [`config/SERVERS_STDIO.md`](config/SERVERS_STDIO.md)
- [`config/SERVERS_HTTP.md`](config/SERVERS_HTTP.md)
- [`config/SERVERS_OPENAPI.md`](config/SERVERS_OPENAPI.md)
- Legacy import migration notes: [`config/IMPORTS.md`](config/IMPORTS.md)

## CLI + environment variables

You can also set adapter options with CLI flags (and matching environment variables).

- Run `unrelated-mcp-adapter --help` for the full list.
- `--print-effective-config` prints the resolved config and exits.

See: [`config/ENV_AND_PRECEDENCE.md`](config/ENV_AND_PRECEDENCE.md)

## Common topics

- **Auth blocks**: the same `auth:` shape is used by `http` and `openapi` servers.
  - See: [`config/AUTH.md`](config/AUTH.md)
- **Environment expansion**: strings can use `${VAR}`. Missing variables fail startup.
  - See: [`config/ENV_AND_PRECEDENCE.md`](config/ENV_AND_PRECEDENCE.md)

## Source of truth

- [`crates/adapter/src/config.rs`](../../crates/adapter/src/config.rs) (schema, parsing, env expansion, precedence)
