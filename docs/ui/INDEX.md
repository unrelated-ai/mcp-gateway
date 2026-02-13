# Web UI (beta)

The **Web UI** is a Next.js application used to manage Gateway tenants:

- profiles
- upstreams
- tool sources
- secrets
- API keys
- audit (events + tool-call analytics)
- profile MCP security controls
- tenant/profile transport limits

## Scope

- The Web UI is **tenant-scoped** (tenant self-service).
- **Gateway admin** provisioning and global configuration are intentionally out of scope for the UI today (use the Gateway admin CLI and deployment automation like `docker compose` / Helm).
- **Fresh install onboarding**: when the Gateway bootstrap endpoint is enabled and there are no tenants yet, the UI guides the user through creating the first tenant (via `/bootstrap/v1/tenant`) at `/onboarding`.

## Audit

- Audit settings live under **Settings → Audit** (enable/disable + retention + default detail level).
- Tenant audit events and analytics live under **Audit** (with profile filtering and deep-links from profile pages).

See also:

- Gateway audit logging: [`docs/gateway/AUDIT.md`](../gateway/AUDIT.md)

## Security and transport controls

- **Profile -> Security** includes MCP trust-policy controls (client capability shaping, proxied-request ID signing, and upstream server->client request filtering).
- **Settings -> Transport limits** configures tenant defaults for MCP payload/transport safety.
- Per-profile transport limits can override tenant defaults in profile MCP settings.

See also:

- Gateway MCP settings: [`docs/gateway/MCP_SETTINGS.md`](../gateway/MCP_SETTINGS.md)
- Gateway proxying/security behavior: [`docs/gateway/MCP_PROXYING.md`](../gateway/MCP_PROXYING.md)

## Docs

- Build, versioning, and releases: [`docs/CICD.md`](../CICD.md)

## Related docs

- Workspace docs index: [`docs/INDEX.md`](../INDEX.md)
- CI/CD: [`docs/CICD.md`](../CICD.md)
- Gateway docs: [`docs/gateway/INDEX.md`](../gateway/INDEX.md)
- Gateway admin CLI docs: [`docs/gateway-cli/INDEX.md`](../gateway-cli/INDEX.md)
