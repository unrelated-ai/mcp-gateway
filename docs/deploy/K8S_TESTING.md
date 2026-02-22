# Kubernetes Testing Guide (kind + Helm)

This guide documents the day-to-day Kubernetes testing workflow for this repo, with a focus on testing **unmerged** Gateway/UI/Operator changes on a local `kind` cluster.

## Goals

- Test chart behavior (install/upgrade/migration jobs/RBAC) before merge.
- Test branch-local UI/Gateway/Operator code before publishing GHCR tags.
- Keep commands repeatable for local contributor workflows.

## Prerequisites

- `docker`
- `kind`
- `kubectl`
- `helm`

Optional but recommended:

- `go` (for installing `kind`)
- `make`

If `kind` is missing:

```bash
go install sigs.k8s.io/kind@v0.31.0
```

## Fast path (recommended)

Create cluster (once):

```bash
kind create cluster --name kind
kubectl config use-context kind-kind
```

Build local images, load into `kind`, and deploy stack:

```bash
make kind-local-refresh
```

The command above uses:

- `deploy/helm/unrelated-mcp-gateway-stack/values-dev.yaml`
- `deploy/helm/unrelated-mcp-gateway-stack/values-kind-local.yaml`

and deploys branch-local images tagged `:kind`.

## Verify deployment health

```bash
kubectl -n mcp-gateway get jobs,pods,deploy,sts,svc
```

Expected baseline:

- migration job `unrelated-mcp-gateway-migrate-r<revision>` is `Complete`
- deployments `unrelated-mcp-gateway`, `unrelated-mcp-gateway-ui`, `unrelated-mcp-gateway-operator` are `Available`
- bundled Postgres statefulset is `Ready` (dev profile)

Confirm deployed images are local branch builds:

```bash
kubectl -n mcp-gateway get deploy/unrelated-mcp-gateway-ui -o jsonpath='{.spec.template.spec.containers[0].image}{"\n"}'
kubectl -n mcp-gateway get deploy/unrelated-mcp-gateway -o jsonpath='{.spec.template.spec.containers[0].image}{"\n"}'
kubectl -n mcp-gateway get deploy/unrelated-mcp-gateway-operator -o jsonpath='{.spec.template.spec.containers[0].image}{"\n"}'
```

## Access UI + APIs locally

Run in separate terminals:

```bash
kubectl -n mcp-gateway port-forward svc/unrelated-mcp-gateway-ui 3000:3000
```

```bash
kubectl -n mcp-gateway port-forward svc/unrelated-mcp-gateway-admin 4001:4001
```

```bash
kubectl -n mcp-gateway port-forward svc/unrelated-mcp-gateway 27100:4000
```

Then open `http://localhost:3000`.

## Managed MCP testing

Managed MCP requires operator-backed topology (`operator-oss`).

Check Gateway topology:

```bash
kubectl -n mcp-gateway run status-check --image=curlimages/curl:8.12.1 --rm -i --restart=Never --command -- sh -c 'curl -sS http://unrelated-mcp-gateway-admin:4001/status'
```

You should see `"topology":"operator-oss"` in the JSON payload.

Seed one deployable in the catalog for end-to-end UI testing:

```bash
curl -sS -X PUT http://127.0.0.1:4001/admin/v1/managed-mcp/deployables \
  -H 'Authorization: Bearer dev-admin-token' \
  -H 'Content-Type: application/json' \
  -d '{
    "id":"demo-nginx",
    "displayName":"Demo Nginx",
    "description":"Managed deployment pipeline smoke test",
    "image":"nginx:1.27-alpine",
    "defaultUpstreamUrl":"http://demo/mcp",
    "enabled":true
  }'
```

Then test in UI:

- `Sources` -> `Add Source` -> `Managed MCP`
- Deploy catalog item
- watch request status transition (`pending`/`reconciling`/`ready`/`failed`)
- open generated upstream from the success link

## Command reference

Build local images only:

```bash
make kind-local-build-images
```

Load local images only:

```bash
make kind-local-load-images
```

Deploy/redeploy only:

```bash
make kind-local-deploy
```

Helm chart validation:

```bash
make helm-validate-optional
```

## Troubleshooting

- **UI appears old**
  - Confirm UI pod image is `unrelated-mcp-gateway-ui:kind`.
  - Re-run `make kind-local-refresh`.
- **Managed MCP option disabled in UI**
  - Gateway topology is not `operator-oss` or `/status` is unavailable.
  - Check `http://127.0.0.1:4001/status` and deployment health.
- **Migration job failed**
  - Inspect job/pod logs:

    ```bash
    kubectl -n mcp-gateway get jobs
    kubectl -n mcp-gateway logs job/<migration-job-name>
    ```

- **Operator not ready**
  - Check deployment/pod logs:

    ```bash
    kubectl -n mcp-gateway get deploy,pods -l app.kubernetes.io/name=unrelated-mcp-gateway-operator
    kubectl -n mcp-gateway logs deploy/unrelated-mcp-gateway-operator --tail=200
    ```

## Cleanup

Remove stack only:

```bash
helm uninstall unrelated-mcp-gateway -n mcp-gateway
kubectl delete namespace mcp-gateway
```

Delete cluster:

```bash
kind delete cluster --name kind
```
