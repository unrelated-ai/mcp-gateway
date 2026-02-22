# Helm Deployment Guide (OSS)

This repository now ships Helm packaging for the OSS control/data plane stack.

## What Is Covered

- `deploy/helm/unrelated-mcp-gateway-operator/`
  - Kubernetes operator chart (+ CRD).
- `deploy/helm/unrelated-mcp-gateway/`
  - Gateway runtime/admin service chart.
  - Includes a migration Job (dbmate) that runs on install/upgrade.
  - Supports external DB by default, plus optional bundled Postgres subchart mode.
- `deploy/helm/unrelated-mcp-gateway-ui/`
  - Next.js tenant UI chart.
- `deploy/helm/unrelated-mcp-postgres/`
  - Optional bundled Postgres chart for quickstart/dev.
- `deploy/helm/unrelated-mcp-gateway-stack/`
  - Umbrella chart composing operator + gateway + UI + optional postgres.
  - Includes `values-dev.yaml` and `values-prod.yaml` profiles.

## What Is Not Covered

- Adapter Helm charting is intentionally out of scope.
  - Adapters are deployment payloads managed by the operator (often hybrid images with stdio MCP server + adapter).

## DB Decision Guidance

- Default recommendation: external Postgres (RDS/CloudSQL/etc).
  - Better for production operations and platform alignment.
- Bundled Postgres is available for quickstart/dev/test clusters.
  - Use profile `values-dev.yaml` in the stack chart.

## Install Flows

### 1) Production-like install (external Postgres default)

1. Create namespace:

```bash
kubectl create namespace mcp-gateway
```

1. Create DB URL Secret (expected by `values-prod.yaml`):

```bash
kubectl -n mcp-gateway create secret generic unrelated-mcp-gateway-db \
  --from-literal=UNRELATED_GATEWAY_DATABASE_URL='postgres://USER:PASS@HOST:5432/gateway?sslmode=require'
```

1. Create Gateway auth/session Secret (expected by `values-prod.yaml`):

```bash
kubectl -n mcp-gateway create secret generic unrelated-mcp-gateway-secrets \
  --from-literal=UNRELATED_GATEWAY_ADMIN_TOKEN='replace-me' \
  --from-literal=UNRELATED_GATEWAY_SESSION_SECRET='replace-me' \
  --from-literal=UNRELATED_GATEWAY_SECRET_KEYS='replace-me'
```

1. Build chart dependencies and install stack:

```bash
helm dependency build deploy/helm/unrelated-mcp-gateway
helm dependency build deploy/helm/unrelated-mcp-gateway-stack
helm upgrade --install unrelated-mcp-gateway deploy/helm/unrelated-mcp-gateway-stack \
  --namespace mcp-gateway \
  -f deploy/helm/unrelated-mcp-gateway-stack/values-prod.yaml
```

1. Set operator Gateway auth (if not provided in `values-prod.yaml`):

```bash
helm upgrade --install unrelated-mcp-gateway deploy/helm/unrelated-mcp-gateway-stack \
  --namespace mcp-gateway \
  -f deploy/helm/unrelated-mcp-gateway-stack/values-prod.yaml \
  --set operator.gateway.bearerToken='replace-me'
```

### 2) Quickstart/dev install (bundled Postgres)

```bash
kubectl create namespace mcp-gateway
helm dependency build deploy/helm/unrelated-mcp-gateway
helm dependency build deploy/helm/unrelated-mcp-gateway-stack
helm upgrade --install unrelated-mcp-gateway deploy/helm/unrelated-mcp-gateway-stack \
  --namespace mcp-gateway \
  -f deploy/helm/unrelated-mcp-gateway-stack/values-dev.yaml
```

This profile enables bundled Postgres and wires Gateway DB URL for local-style usage.

## Managed MCP requirement

Managed MCP deployment requests require the operator control loop to reconcile them.

- If Gateway runs in Mode 3 **without** the operator, managed deployment requests will not advance to ready.
- For operator-backed installs, set topology to `operator-oss` (chart value `gateway.topology` / env `UNRELATED_GATEWAY_TOPOLOGY`).

## Test unmerged changes on kind (local images)

To test branch-local UI/Gateway/Operator code before publishing GHCR tags:

```bash
# 1) Build local images from current workspace
make kind-local-build-images

# 2) Load images into kind
make kind-local-load-images

# 3) Deploy stack with local-image overrides
make kind-local-deploy
```

`kind-local-deploy` uses:

- `deploy/helm/unrelated-mcp-gateway-stack/values-dev.yaml`
- `deploy/helm/unrelated-mcp-gateway-stack/values-kind-local.yaml`

So chart behavior stays dev-like while image repositories/tags are local (`*:kind` by default).

For a full command reference (verification, troubleshooting, cleanup), see:

- [`docs/deploy/K8S_TESTING.md`](K8S_TESTING.md)

## Ingress/TLS/Policy/HPA/PDB Defaults

- Dev profile:
  - Ingress off, autoscaling off, PDB off, NetworkPolicy off.
- Prod profile:
  - Ingress on (data plane + UI), TLS expected via cert-manager annotations.
  - HPA and PDB enabled for Gateway and UI.
  - Baseline NetworkPolicy enabled (same-namespace ingress guardrails).

Adjust these values per platform and compliance requirements.
