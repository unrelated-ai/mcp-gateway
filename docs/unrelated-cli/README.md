# Client CLI and compact MCP proxy

`unrelated` is the user-facing client. `unrelated-gateway-admin` remains the operator
CLI for managing the Gateway. Both connect to an existing deployment.

Build the client from this branch:

```bash
cargo install --path crates/unrelated-cli
unrelated context add dev --url https://gateway.example.com/PROFILE_UUID/mcp --auth oauth
unrelated context use dev
unrelated auth login
unrelated tools search "list projects"
```

Replace the profile URL with your own. For API keys, use `--auth api-key` when adding
the context. `auth login` stores credentials in the native credential store. Headless
execution can supply a token with `UNRELATED_TOKEN`. OAuth providers that require a
registered client can use `context add --client-id CLIENT_ID`; authorization-server
configuration must permit the CLI's login flow.

Inspect a stable tool reference returned by search, then call it with its arguments:

```bash
unrelated tools describe SOURCE_ID:TOOL_NAME
unrelated --json tools call SOURCE_ID:TOOL_NAME --input '{"example":"value"}'
```

Potentially side-effecting CLI calls request confirmation; `--yes` supplies explicit
confirmation for automation. `--timeout` sets the client timeout. Search supports
`--detail brief|detailed|full`, `--limit`, and `--refresh`.

## Choosing a client connection

| Connection                                 | What the MCP host sees                      | Useful when                                                                                 |
| ------------------------------------------ | ------------------------------------------- | ------------------------------------------------------------------------------------------- |
| Direct profile URL                         | Individual tool definitions and annotations | The client manages the catalog itself or needs individual tool schemas.                     |
| `unrelated proxy --context dev` over stdio | `search_tools` and `execute_tool`           | The profile exposes a large catalog and the agent should discover relevant tools on demand. |

Configure the host to launch `unrelated proxy --context dev` as a stdio MCP server.
The proxy searches only the profile's authorized catalog and executes the stable
`toolRef` returned by search. It does not replace the Gateway's access checks.

The compact proxy downloads the full catalog locally and searches it using lexical
ranking. It reduces tool definitions sent to the model; it does not eliminate the
initial Gateway catalog request. A generic execution tool also gives the host less
per-tool schema/annotation detail than direct access. Both connection styles remain
supported; no switch to the compact proxy is required.
