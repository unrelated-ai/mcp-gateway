## Unrelated MCP Gateway UI (beta)

This is the **Next.js** Web UI for managing an **Unrelated MCP Gateway** tenant:

- profiles
- upstreams (remote Streamable HTTP MCP servers)
- tool sources (OpenAPI + HTTP DSL)
- managed MCP deployments (beta; requires a configured reconciler)
- secrets
- API keys
- audit events and analytics
- tenant audit and transport settings

Docs live under `docs/ui/` (start at `docs/ui/INDEX.md`).

### Local development

```bash
cd ui
npm ci
cp env.example .env.local
npm run dev
```

### Environment variables

- **`GATEWAY_ADMIN_BASE`**: UI server → Gateway admin/control plane base URL (example: `http://gateway:4001` inside the repository's Compose network)
- **`GATEWAY_DATA_BASE`**: public Gateway URL used in copied MCP client configs (example: `http://localhost:27100`). Read by the UI server at request time, so one image can serve different deployments.
- **`NEXT_PUBLIC_GATEWAY_DATA_BASE`**: supported runtime alias for existing Compose/Helm deployments; `GATEWAY_DATA_BASE` takes precedence. Neither URL needs to be set while building the UI.

### Notes

- **Tenant access**: the UI is unlocked with a tenant token (stored in browser cookies).
- **Fresh install onboarding**: when the Gateway bootstrap endpoint is enabled and there are no tenants yet, the UI redirects to `/onboarding` automatically.
