# Preparing a release

## Checks

Run the following from the repository root. Integration and browser checks use
disposable Docker services.

```bash
make ci
make test-gateway-contracts
make test-integration-gateway
make test-v1-journey
make test-ui-e2e
make helm-validate
cd ui && npm test && npm run lint && npm run build
```

Build and smoke-test the packaged Gateway, migrator, Adapter, operator, and UI
images. For managed deployments, verify scale-up, scale-down, endpoint draining,
and cleanup on the intended Docker or Kubernetes runtime. Check supported release
architectures and platform-specific credential stores on their corresponding runners.
See [CI/CD](../CICD.md) for artifact names, security checks, and publication workflows.

## Upgrade checks

The public-binary upgrade test creates data using Gateway 0.13.1, applies pending
migrations, and checks existing credentials and MCP routing. Supply an executable
from that release; the test does not download one automatically:

```bash
MCP_GATEWAY_0131_BIN=/path/to/gateway-0.13.1 make test-v1-upgrade
```

For deployments, also restore a representative database backup with its original
encryption keys. Test the actual ingress and OAuth issuer where configured. Use
the [v1 upgrade guide](../gateway/V1_UPGRADE.md) for the maintenance window,
authentication changes, rollback requirements, and optional PostgreSQL major upgrade.

## Publication

- Select component and chart versions and update release notes and quickstart
  image references. Point both quickstart downloads at the published release ref.
  Keep release versions separate from dependency pins; see
  [version maintenance](VERSIONS.md).
- Publish matching artifacts from the reviewed revision through the release
  workflows. Confirm workflow completion and smoke-test the published artifacts.
- Document supported protocol versions and deployment limitations in the user
  guides. Keep individual test-run logs in CI artifacts rather than these docs.
