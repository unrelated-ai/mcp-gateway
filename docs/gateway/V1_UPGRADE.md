# Upgrading to v1

This guide covers the upcoming v1 release on `feat/version_one_zero`.
v1 images and tags are not yet published. Build all components from the same
revision when rehearsing an upgrade.

## What changes

- MCP OAuth resource-server support: external login, protected-resource discovery,
  profile URL audiences, required scopes, and principal bindings.
- The `unrelated` client CLI: named contexts, login, tool discovery/execution, and an
  optional compact stdio MCP proxy. The admin CLI remains a separate tool.
- A simpler authentication configuration and a database migration that requires a
  maintenance window.
- Stateful and sessionless upstream interoperability, bounded parallel initialization
  and discovery, and bounded routing caches.

## Choose a deployment

| Recipe                       | Configuration and components                               | State to preserve                                                      |
| ---------------------------- | ---------------------------------------------------------- | ---------------------------------------------------------------------- |
| File-driven Gateway (Mode 1) | Gateway plus config file; optional Adapter for stdio tools | Config, configured credentials, and Gateway session keys.              |
| Shared Gateway (Mode 3)      | Gateway, PostgreSQL, optional UI and Adapters              | Database, secret-encryption keys, session keys, and upstream services. |
| Managed workloads            | Mode 3 plus the Docker or Kubernetes operator              | Shared deployment state plus operator/runtime configuration.           |

Runtime mode and deployment topology are separate. Mode 3 can run outside Kubernetes.
Adapters remain optional for remote MCP and Gateway-native HTTP/OpenAPI sources.
Use the existing [Docker quickstart](../../README.md#try-it-locally) or
[Helm deployment guide](../deploy/HELM.md) for the corresponding infrastructure.

## Breaking configuration changes

| Previous value                                 | v1 value or action                                                                  |
| ---------------------------------------------- | ----------------------------------------------------------------------------------- |
| `apiKeyInitializeOnly` / `apiKeyEveryRequest`  | `apiKey`; credentials are required on every request.                                |
| `jwtEveryRequest`                              | `oauth`; configure the OAuth issuer and public Gateway base URL.                    |
| Mode 1 `requireEveryRequest`                   | Remove the field, including an explicit `true`. Unknown fields are rejected.        |
| `UNRELATED_GATEWAY_OIDC_*` for data-plane auth | Configure `UNRELATED_GATEWAY_OAUTH_*` and `UNRELATED_GATEWAY_PUBLIC_DATA_BASE_URL`. |
| Generic configured JWT audiences               | Issue tokens for the exact profile MCP URL.                                         |

Existing `acceptXApiKey` database values are preserved. Newly created API-key profiles
default to `false`. Old JWT profiles acquire a required `mcp:access` scope during the
migration; configure your issuer accordingly or deliberately update the profile policy.
Control-plane OIDC variables remain separate and unchanged.

See [data-plane authentication](DATA_PLANE_AUTH.md) for the current API shapes and
OAuth environment variables. Update scripts and saved profile request bodies too.

## Rehearse and perform the upgrade

1. Back up the database, configuration, and the encryption/session keys needed to use it.
   Rehearse against a disposable copy of the current release database.
2. Update client headers, profile request bodies, issuer configuration, and deployment
   environment variables. Build matching Gateway, migrator, UI, and CLI artifacts.
3. Stop old Gateway replicas and pause control-plane writes before applying the v1
   migration. The migration changes stored authentication mode names; old replicas
   cannot interpret them. A normal mixed-version rolling upgrade is unsuitable.
4. Run the matching migrator (the Helm chart uses a migration Job), then start the v1
   Gateway replicas with shared configuration and keys.
5. Initialize profiles, list and call representative tools, check direct and compact
   clients, and verify OAuth login where enabled. Test both stateful and sessionless
   upstreams. Exercise a request through a different Gateway replica.
6. Resume normal traffic and control-plane operations after those checks pass.

Rollback must restore compatible application configuration and database state together.
The down migration maps API-key profiles to every-request authentication; it cannot
reconstruct which profiles previously used initialize-only authentication.

## What survives a restart

With shared session keys and configuration, another Gateway replica can read a routing
token. This does not preserve a stateful upstream's in-memory session if that upstream
restarts. Clients may need to initialize again. Cache loss is recoverable by rebuilding
catalogs and endpoint data. Database or key loss is not equivalent to cache loss.

Sessionless upstreams do not require an upstream session ID. Gateway routing tokens
still retain the chosen endpoint. Automatic endpoint reselection and replay of failed
tool calls are not part of this change. Update every Gateway replica before introducing
sessionless upstreams; older code cannot read their new routing-token bindings.

## Validation

```bash
cargo test --workspace --all-targets
make test-gateway-contracts
```

The second command requires Docker and runs PostgreSQL migration, profile isolation,
aggregation, cache invalidation, cross-replica notifications, and replay contracts.
The normal Rust test command skips tests marked `ignore`; CI runs these contracts
explicitly as an additional step.

For concurrency limits, deadlines, cache lifetime, and module responsibilities, see
[architecture](ARCHITECTURE.md#request-configuration-concurrency-and-cache-lifetime).
