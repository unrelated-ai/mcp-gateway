# Workspace crates

This repository is a Cargo workspace.

Optional (local only): you can enable repo githooks to run CI checks before `git push`:

```bash
make hooks-install
git config core.hooksPath .githooks
```

Workspace members live under [`crates/`](../crates/):

- [`crates/adapter/`](../crates/adapter/) (runtime adapter binary)
- [`crates/env/`](../crates/env/) (shared environment parsing helpers)
- [`crates/gateway/`](../crates/gateway/) (gateway binary; MCP proxy + upstream aggregation + admin API)
- [`crates/unrelated-cli/`](../crates/unrelated-cli/) (user CLI, OAuth login, catalog search, and compact stdio MCP proxy)
- [`crates/gateway-cli/`](../crates/gateway-cli/) (gateway admin CLI binary)
- [`crates/gateway-operator/`](../crates/gateway-operator/) (Kubernetes and Docker managed-deployment reconciler)
- [`crates/http-tools/`](../crates/http-tools/) (shared HTTP tool DSL and runtime)
- [`crates/openapi-tools/`](../crates/openapi-tools/) (shared OpenAPI-to-MCP tooling)
- [`crates/test-support/`](../crates/test-support/) (shared integration-test helpers)
- [`crates/tool-transforms/`](../crates/tool-transforms/) (shared tool surface transforms)

Other top-level components:

- [`ui/`](../ui/) (Web UI, Next.js)
