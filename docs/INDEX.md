# Documentation

MCP Gateway connects HTTP APIs and MCP servers to MCP clients through secured
profile endpoints. Start with the [Docker quickstart](../README.md#try-it-locally)
or the [Helm deployment guide](deploy/HELM.md).

## Components

| Component | Purpose | Guides |
| --- | --- | --- |
| Gateway | Profile endpoints, authentication, aggregation, and tool policies | [Overview](gateway/INDEX.md), [upgrading to v1](gateway/V1_UPGRADE.md) |
| Adapter | Publish HTTP/OpenAPI tools and stdio MCP servers over HTTP | [Overview](adapter/INDEX.md), [configuration](adapter/CONFIG.md), [testing](adapter/TESTING.md) |
| Web UI | Manage tenant sources, profiles, keys, secrets, and audit settings | [UI guide](ui/INDEX.md) |
| Client CLI | Connect to profiles, log in, discover tools, and run a compact stdio proxy | [`unrelated` guide](unrelated-cli/README.md) |
| Admin CLI | Administer tenants, upstreams, and profiles | [Overview](gateway-cli/INDEX.md), [commands](gateway-cli/COMMANDS.md) |
| Operator | Manage MCP workloads on Docker or Kubernetes | [Operator guide](../crates/gateway-operator/README.md) |

## Deployment and operation

- [Helm deployment](deploy/HELM.md)
- [Local Kubernetes testing](deploy/K8S_TESTING.md)
- [Authentication](gateway/DATA_PLANE_AUTH.md)
- [MCP compatibility and aggregation](gateway/MCP_PROXYING.md)
- [Profile MCP settings](gateway/MCP_SETTINGS.md)
- [Tenant sources and secrets](gateway/MODE3_TENANT_OVERLAY.md)
- [Audit logging](gateway/AUDIT.md)
- [Performance and tuning](gateway/PERFORMANCE.md)

## Development

- [Contributing](../CONTRIBUTING.md)
- [Workspace layout](WORKSPACE.md)
- [Version maintenance](development/VERSIONS.md)
- [Release checklist](development/RELEASING.md)
- [CI/CD](CICD.md)
