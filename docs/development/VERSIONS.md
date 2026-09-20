# Version ownership

Edit versions in the files consumed by the relevant tool. There is no generator
or synchronization step.

## Shared deployment images

[`deploy/images.env`](../../deploy/images.env) is the single maintained definition
of PostgreSQL, curl, HTTPBin, and Petstore images. It contains plain `KEY=value`
entries, without quotes, interpolation, or secrets.

- Compose reads it with `docker compose --env-file deploy/images.env ...`.
  `make up`, `make down`, `make logs`, `make status`, and `make up-reset` supply it.
- The quickstart downloads Compose and this defaults file together. Use the
  `--env-file mcp-gateway-images.env` flag shown in the root README.
- The Helm `unrelated-mcp-images` library chart includes a symlink to the same
  file. Helm follows that link when packaging and bundles its contents, so the
  resulting charts install independently of the source checkout. PostgreSQL and
  managed-fixture charts inherit defaults through this library.
- Rust container tests include the same file through `unrelated-test-support`.

Shell variables still override Compose defaults. For a private local `.env`, use
`--env-file deploy/images.env --env-file .env`; later files take precedence.
Helm's existing `image.repository` and `image.tag` overrides remain supported;
empty values inherit the bundled defaults. A parent Gateway chart passes these
as `postgres.image.repository` and `postgres.image.tag`.

After editing image defaults, rebuild Helm dependencies before packaging:

```bash
helm dependency build deploy/helm/unrelated-mcp-postgres
helm dependency build deploy/helm/unrelated-mcp-gateway-managed-fixtures
helm dependency build deploy/helm/unrelated-mcp-gateway
helm dependency build deploy/helm/unrelated-mcp-gateway-stack
```

`make helm-validate` performs those builds and validates all deployment variants.
The HTTPBin and Petstore fixtures retain their existing `latest` selection.

## Toolchains and component versions

| Setting | Definition and reuse |
| --- | --- |
| Rust compiler | `rust-toolchain.toml`; CI lets rustup read it directly |
| Rust minimum version and dependencies | Workspace `Cargo.toml`; crates inherit workspace entries |
| Node for development and CI | `.node-version`; workflows use `node-version-file` |
| UI compatibility and dependencies | `ui/package.json` and npm's lockfile |
| Go compiler and dependencies | `deploy/migrator/go.mod` and `go.sum` |
| Docker build/runtime bases | Dockerfile arguments, shared stages, and build argument overrides |

Compiler minimums, development toolchains, Docker base images, and component/chart
release versions are separate compatibility decisions. Keep their native
manifests and package-manager lockfiles. GitHub Actions requires literal `uses`
references; Dependabot groups their updates.

Use constants near their owning modules and SDK constants for protocol values.
Tests may retain literal expected wire values so changing a constant cannot
silently change both implementation and assertion.

## Compatibility constraints

- Keep `sse-stream` compatible with RMCP's public transport types; upgrading it
  independently can produce incompatible Rust stream types.
- Upgrade ESLint's major version only when the React, import, and accessibility
  plugins used by Next support it.
- The UI uses the TypeScript 7 compiler alongside the TypeScript 6 API package
  required by ESLint. Both compiler and Next build checks must pass.
- The migrator keeps patched gRPC-Go 1.83.2; 1.84.0 is affected by
  [GO-2026-6443](https://pkg.go.dev/vuln/GO-2026-6443). Recheck the advisory before
  removing the corresponding Dependabot ignore rule.
- A PostgreSQL major version change requires a database migration. Follow the
  [upgrade procedure](../gateway/V1_UPGRADE.md#postgresql-16-to-18) instead of
  replacing the image tag on an existing volume.

References: [Compose interpolation and env files](https://docs.docker.com/compose/how-tos/environment-variables/variable-interpolation/),
[Helm library charts](https://helm.sh/docs/topics/library_charts/).
