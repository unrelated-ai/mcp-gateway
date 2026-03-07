# unrelated-mcp-gateway-operator

OSS Kubernetes operator for `McpServer` custom resources.

## Current scope

- Ensures CRD `mcpservers.gateway.unrelated.ai` is installed.
- Reconciles each `McpServer` into:
  - a Kubernetes `Deployment`
  - a Kubernetes `Service`
  - a Gateway upstream registration (source wiring only; never profile wiring)
- Supports endpoint lifecycle rollout behavior:
  - new endpoint becomes `active`
  - old endpoint moves to `draining`
  - old endpoint is disabled/deleted after drain success or timeout policy
- Supports explicit rollback trigger (`spec.rollout.forceRollback`) to return to last stable revision.
- Uses finalizers for idempotent cleanup of Kubernetes resources and Gateway endpoint wiring.
- Uses optional leader election via Kubernetes Leases.

## Environment variables

### Watch and leader election

- `OPERATOR_NAMESPACE` (optional): watch only this namespace; unset = all namespaces
- `OPERATOR_LABEL_SELECTOR` (optional): label selector for watched `McpServer` resources
- `OPERATOR_LEADER_ELECTION_ENABLED` (default: `true`)
- `OPERATOR_LEADER_ELECTION_LEASE_NAME` (default: `unrelated-mcp-gateway-operator`)
- `OPERATOR_LEADER_ELECTION_LEASE_NAMESPACE` (default: `OPERATOR_NAMESPACE` or `default`)
- `OPERATOR_LEADER_ELECTION_LEASE_DURATION_SECS` (default: `30`)
- `OPERATOR_LEADER_ELECTION_RENEW_INTERVAL_SECS` (default: `10`)
- `OPERATOR_LEADER_ELECTION_RETRY_INTERVAL_SECS` (default: `5`)

### Gateway registration and rollout

- `OPERATOR_GATEWAY_BASE_URL`: Gateway admin base URL (e.g. `http://gateway:8080`)
- `OPERATOR_GATEWAY_BEARER_TOKEN`: bearer token/JWT for Gateway admin API
- `OPERATOR_GATEWAY_TIMEOUT_SECS` (default: `15`)
- `OPERATOR_GATEWAY_RETRY_MAX_ATTEMPTS` (default: `5`)
- `OPERATOR_GATEWAY_RETRY_BASE_DELAY_MS` (default: `500`)
- `OPERATOR_GATEWAY_SESSION_ACTIVITY_TTL_SECS` (default: `300`)
- `OPERATOR_GATEWAY_UPSTREAM_NETWORK_CLASS` (default: `cluster-internal-managed`, alt: `external`)
- `OPERATOR_GATEWAY_CLEANUP_MODE` (default: `disable-endpoint`, alt: `delete-endpoint`)
- `OPERATOR_SERVICE_ENDPOINT_SCHEME` (default: `http`)
- `OPERATOR_SERVICE_DOMAIN_SUFFIX` (default: `svc.cluster.local`)
- `OPERATOR_REQUEST_NAMESPACE` (default: `OPERATOR_NAMESPACE`, otherwise `default`)
- `OPERATOR_DEPLOYMENT_REQUEST_POLL_SECS` (default: `5`)
- `OPERATOR_MANAGED_DEPLOYMENT_MODE` (default: `k8s`, alternatives: `docker`)
  - `k8s`: enables Managed MCP request intake + heartbeat publishing
  - `docker`: disables this operator's request intake/heartbeat loop (reserved for non-k8s reconcilers)
- `OPERATOR_MANAGED_DEPLOYMENT_HEARTBEAT_SECS` (default: `5`)
- `OPERATOR_MANAGED_DEPLOYMENT_RECONCILER_ID` (optional; defaults to `<hostname>-<pid>`)

## Build

```bash
cargo build -p unrelated-mcp-gateway-operator
```

## Test

```bash
cargo test -p unrelated-mcp-gateway-operator
```
