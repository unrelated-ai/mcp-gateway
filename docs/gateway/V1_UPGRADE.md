# Upgrading to v1

v1 adds OAuth login, the `unrelated` client CLI, optional native MCP support, and
profile edit conflict detection. It also changes authentication settings and
requires database migrations. **Schedule a maintenance window:** old and v1
Gateway replicas cannot run together during this upgrade.

v1 release images are not yet published. For source builds, use the same revision
for the Gateway, migrator, UI, Adapter, operator, and CLIs.

## Deployment options

| Deployment | Components | State to preserve |
| --- | --- | --- |
| File configuration (Mode 1) | Gateway and a configuration file | Configuration, credentials, and session keys |
| Shared configuration (Mode 3) | Gateway and PostgreSQL; optional UI | Database, secret-encryption keys, and session keys |
| Managed MCP servers | Mode 3 plus the Docker or Kubernetes operator | Shared configuration plus operator and workload settings |

Adapters are optional for remote MCP and Gateway-native HTTP/OpenAPI sources.
They are required to publish stdio MCP servers. Mode 3 works with Docker or
Kubernetes; see the [Docker quickstart](../../README.md#try-it-locally) or
[Helm guide](../deploy/HELM.md).

## Configuration changes

| Previous setting | v1 setting or action |
| --- | --- |
| `apiKeyInitializeOnly` / `apiKeyEveryRequest` | Use `apiKey`. Send credentials on every request. |
| `jwtEveryRequest` | Use `oauth` and configure an OAuth issuer and the public Gateway base URL. |
| Mode 1 `requireEveryRequest` | Remove this field, even if its value is `true`. |
| Data-plane `UNRELATED_GATEWAY_OIDC_*` variables | Use `UNRELATED_GATEWAY_OAUTH_*` and `UNRELATED_GATEWAY_PUBLIC_DATA_BASE_URL`. |
| Generic JWT audiences | Issue tokens for the exact profile MCP URL. |

The migration preserves existing `acceptXApiKey` values. New API-key profiles
default to `false`, so clients should send `Authorization: Bearer <API_KEY_SECRET>`.
Migrated JWT profiles require the `mcp:access` scope; configure the issuer or
update the profile policy accordingly. Control-plane OIDC settings are unchanged.

Update saved API request bodies and automation as well as deployment settings.
See [authentication](DATA_PLANE_AUTH.md) for configuration examples.

YAML files must not contain duplicate mapping keys. Remove duplicates from
configuration and OpenAPI files before upgrading.

## Upgrade procedure

1. Back up the database, configuration, secret-encryption keys, and session keys.
   Test the upgrade and restore procedure against a disposable database copy.
2. Prepare matching v1 components and apply the configuration changes above.
3. Stop old Gateway replicas and pause operator and control-plane writes.
4. Run **all pending migrations** from the matching migrator, then start the v1
   components. Helm runs migrations through a Job.
5. Verify existing tenant tokens, API keys, encrypted secrets, profiles, and
   representative tool calls. Check OAuth login with the configured issuer and
   verify routing through more than one replica where applicable.
6. Resume traffic and configuration writes after verification succeeds.

Rollback must restore compatible application configuration and database state
together. The authentication down migration restores every-request API-key
authentication; it cannot recover which profiles previously used initialize-only
authentication. Preserve the backup until the upgrade is accepted.

## Client compatibility

- **Profile edits:** responses include `revision`. Tenant profile updates can
  send `expectedRevision`; a stale value returns HTTP 409. The UI handles this
  automatically and retains unsaved edits until the profile is reloaded.
  API clients that omit the value continue to use unconditional updates.
- **Native MCP:** `mcp.modernProtocol` is off by default. Enable it only for
  profiles whose remote sources support MCP `2026-07-28`. Adapter and compact
  stdio proxy connections continue to use the legacy lifecycle. See
  [MCP settings](MCP_SETTINGS.md#native-protocol).
- **Browser clients:** configure `UNRELATED_GATEWAY_ALLOWED_ORIGINS` for browser
  origins beyond loopback. This does not configure reverse-proxy CORS.
- **UI URLs:** set `GATEWAY_DATA_BASE` at startup to the public MCP base URL.
  `NEXT_PUBLIC_GATEWAY_DATA_BASE` remains a runtime alias.

## Sessions and restarts

Share the same session keys and configuration across Gateway replicas. This
allows a different replica to read existing routing tokens. Stateful upstreams
still own their sessions; an upstream restart may require client initialization
again. Sessionless upstreams do not have this requirement, but routing tokens
remain bound to the selected endpoint. Failed calls are not automatically
replayed on a different endpoint.

Update every Gateway replica before adding sessionless upstreams. Older Gateway
versions cannot read their routing-token bindings. Cache loss is recoverable;
database and encryption-key loss require restoration from backups.

## PostgreSQL 16 to 18

A PostgreSQL major upgrade is optional and separate from the Gateway upgrade.
Deployment defaults remain on PostgreSQL 16 to preserve existing volumes.

The recipes explicitly set `PGDATA=/var/lib/postgresql/data`, while the official
[PostgreSQL 18 image uses a different default layout](https://github.com/docker-library/docs/blob/master/postgres/content.md#pgdata).
Changing an image tag does not upgrade a database. Use a **new volume or PVC**:

1. Preserve the existing volume and back up configuration and encryption keys.
2. Stop Gateway and operator writers. Use PostgreSQL 18 `pg_dump -Fc` against
   the PostgreSQL 16 server; preserve custom roles separately.
3. Start an empty PostgreSQL 18 database on the new volume and restore with
   PostgreSQL 18 `pg_restore --exit-on-error`. Apply the matching app migrations.
4. Point all components at the restored database using the original keys. Check
   authentication, encrypted secrets, profile edits, and tool calls before
   resuming writes.

Select the image with Compose's `POSTGRES_IMAGE` or Helm's `postgres.image.tag`
(`image.tag` for the standalone PostgreSQL chart). The preserved old database
can support rollback before new writes are accepted. After writes resume,
rollback requires a data recovery plan.

See the [PostgreSQL upgrade guide](https://www.postgresql.org/docs/18/upgrading.html)
for database upgrade options.
