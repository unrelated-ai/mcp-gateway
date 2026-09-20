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

Use the Node.js version pinned in the root `.node-version`.

```bash
cd ui
npm ci
cp env.example .env.local
npm run dev
```

### TypeScript tooling

`npm run typecheck` uses TypeScript 7. The `typescript` package name is an alias
for Microsoft's TypeScript 6 compatibility package because the current
`typescript-eslint` parser still requires that compiler API. The native TypeScript 7
compiler is installed as `@typescript/native`. `npm run build` runs the native
check before the Next.js build; Next.js also retains its own type check.

ESLint remains on 9.39.5 until the React, accessibility, and import plugins used
by `eslint-config-next` support ESLint 10 in their peer dependencies.

### Environment variables

- **`GATEWAY_ADMIN_BASE`**: UI server → Gateway admin/control plane base URL (example: `http://gateway:4001` inside the repository's Compose network)
- **`GATEWAY_DATA_BASE`**: public Gateway URL used in copied MCP client configs (example: `http://localhost:27100`). Read by the UI server at request time, so one image can serve different deployments.
- **`NEXT_PUBLIC_GATEWAY_DATA_BASE`**: supported runtime alias for existing Compose/Helm deployments; `GATEWAY_DATA_BASE` takes precedence. Neither URL needs to be set while building the UI.

### Browser acceptance tests

From the repository root, with Docker and the pinned Node.js version available:

```bash
cd ui && npm ci && npx playwright install chromium && cd ..
make test-ui-e2e
```

The suite builds the UI and starts its standalone artifact with `public` and
`.next/static`, as the Dockerfile does. It creates a disposable PostgreSQL database,
Gateway, sessionless rmcp server, and Adapter-backed stdio server. No existing
tenant or deployment is used. The fixture cleans up its services after the run.

Coverage includes onboarding and unlock, upstream/profile/key creation, calls from
the real `unrelated` CLI, delayed/failed saves, tab changes during saves, runtime
URLs on two instances of the same build, transform/MCP settings, and phone navigation. PR CI runs this
suite alongside UI unit tests and lint. Logs, traces and screenshots are under
`output/playwright/`; inspect the HTML report with
`cd ui && npx playwright show-report ../output/playwright/e2e-report`.

After the binaries and UI have been built, `cd ui && npm run test:e2e` reruns the
browser suite. This tests the standalone artifact locally, not Docker image
packaging, a Kubernetes ingress, or a live OAuth issuer.

Profile writes in one browser are serialized and merged with the latest saved
profile, so separate panels do not send stale copies of unrelated fields. Failed
autosaves retain the draft and offer an explicit retry. This does not implement
conflict detection between different browser tabs or users.

### Notes

- **Tenant access**: the UI is unlocked with a tenant token (stored in browser cookies).
- **Fresh install onboarding**: when the Gateway bootstrap endpoint is enabled and there are no tenants yet, the UI redirects to `/onboarding` automatically.
