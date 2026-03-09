# Environment expansion & precedence

Source of truth: [`crates/adapter/src/config.rs`](../../../crates/adapter/src/config.rs).

## Precedence (highest to lowest)

```text
CLI flags > environment variables (via clap) > config file > defaults
```

Notes:

- CLI flags are parsed by `clap`; many flags also have an `UNRELATED_*` env var.
- The unified config file can also contain env-expanded strings.
- Log level has one extra fallback: if `--log-level` / `UNRELATED_LOG` is not set, `RUST_LOG` is used before the config file.

## Environment expansion in config files

Strings can contain `${VAR}` and will be expanded at load time.

- If `${VAR}` is missing, startup fails (explicit is better than silent).
- Expansion applies to many string fields (e.g. URLs, tokens, bind).

## “Stringified” numbers and booleans

Some numeric/boolean fields accept either:

- a real number/bool, or
- a string that becomes a number/bool after env expansion.

Examples:

```yaml
adapter:
  callTimeout: "${CALL_TIMEOUT_SECS}"
  openapiProbe: "${OPENAPI_PROBE}"
```

## Useful CLI flags

- `--help`: list all flags and their env var bindings.
- `--print-effective-config`: prints the fully resolved config (after env expansion + overrides).
