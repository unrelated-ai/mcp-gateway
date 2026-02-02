# Web UI (beta)

The **Web UI** is a Next.js application used to manage Gateway tenants:

- profiles
- upstreams
- tool sources
- secrets
- API keys
- audit (events + tool-call analytics)

## Scope

- The Web UI is **tenant-scoped** (tenant self-service).
- **Gateway admin** provisioning and global configuration are intentionally out of scope for the UI today (use the Gateway admin CLI and deployment automation like `docker compose` / Helm).
- **Fresh install onboarding**: when the Gateway bootstrap endpoint is enabled and there are no tenants yet, the UI guides the user through creating the first tenant (via `/bootstrap/v1/tenant`) at `/onboarding`.

## Audit

- Audit settings live under **Settings → Audit** (enable/disable + retention + default detail level).
- Tenant audit events and analytics live under **Audit** (with profile filtering and deep-links from profile pages).

See also:

- Gateway audit logging: [`docs/gateway/AUDIT.md`](../gateway/AUDIT.md)

## Docs

- Build, versioning, and releases: [`docs/CICD.md`](../CICD.md)

## Related docs

- Workspace docs index: [`docs/INDEX.md`](../INDEX.md)
- CI/CD: [`docs/CICD.md`](../CICD.md)
- Gateway docs: [`docs/gateway/INDEX.md`](../gateway/INDEX.md)
- Gateway admin CLI docs: [`docs/gateway-cli/INDEX.md`](../gateway-cli/INDEX.md)
