# CI/CD

This repo is a monorepo. CI is generic; releases are tag-driven.

## Workflows

- **CI**: [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) (PRs only, no publishing)
  - Rust checks: `fmt`, `clippy`, `cargo test`
  - Helm checks: `helm dependency build`, `helm lint`, `helm template` (dev/prod/kind-local value combinations)
- **Release entrypoint**: [`.github/workflows/release.yml`](../.github/workflows/release.yml) (tag pushes only)
- **Reusable publisher**: [`.github/workflows/docker-release.yml`](../.github/workflows/docker-release.yml) (called from `release.yml`)
- **Reusable release assets**: [`.github/workflows/binary-release.yml`](../.github/workflows/binary-release.yml) (called from `release.yml`)
- **Reusable UI publisher**: [`.github/workflows/ui-docker-release.yml`](../.github/workflows/ui-docker-release.yml) (called from `release.yml`)

## Release tag convention

Use these release tags:

- **Adapter**: `adapter-vX.Y.Z` (or `adapter-vX.Y.Z-rc.N`)
- **Gateway line**: `gateway-vX.Y.Z` (or `gateway-vX.Y.Z-rc.N`) for gateway + migrator + operator + gateway CLI assets
- **Web UI**: `ui-vX.Y.Z` (or `ui-vX.Y.Z-rc.N`)

## Published image + tags

Published images:

- `ghcr.io/unrelated-ai/mcp-adapter`
- `ghcr.io/unrelated-ai/mcp-gateway`
- `ghcr.io/unrelated-ai/mcp-gateway-operator`
- `ghcr.io/unrelated-ai/mcp-gateway-migrator`
- `ghcr.io/unrelated-ai/mcp-gateway-ui`

All published runtime images are minimal and contain a **static** binary (or migrations for the migrator).

## Release guard (Cargo.toml is the source of truth)

On tag pushes (e.g. `adapter-v0.12.2`, `gateway-v0.12.2`, or `ui-v0.8.1`), the release workflow verifies that the tag version
matches the crate version resolved by `cargo metadata` for the target package. If it doesn’t
match, the release fails (no image is pushed).

## Adapter releases (`adapter-vX.Y.Z`)

On a **stable** tag `adapter-vX.Y.Z`, it publishes:

- `:X.Y.Z`
- `:latest` (points to the same digest as `:X.Y.Z`)
- `:sha-<short>`

On a **pre-release** tag `adapter-vX.Y.Z-rc.N`, it publishes:

- `:X.Y.Z-rc.N`
- `:sha-<short>`

## GitHub Release assets (binaries)

On `adapter-v*` tags, the release workflow also uploads a Linux **static** binary to the GitHub Release:

- `unrelated-mcp-adapter-vX.Y.Z-x86_64-unknown-linux-musl.tar.gz`
- `unrelated-mcp-adapter-vX.Y.Z-x86_64-unknown-linux-musl.tar.gz.sha256`

## Gateway releases (`gateway-vX.Y.Z`)

On `gateway-v*` tags, the release workflow publishes:

- Gateway runtime image: `ghcr.io/unrelated-ai/mcp-gateway`
- Gateway migrator image: `ghcr.io/unrelated-ai/mcp-gateway-migrator`
- Gateway operator image: `ghcr.io/unrelated-ai/mcp-gateway-operator` (same `X.Y.Z` as the gateway tag)
- Gateway admin CLI release assets:
  - `unrelated-gateway-admin-vX.Y.Z-x86_64-unknown-linux-musl.tar.gz`
  - `unrelated-gateway-admin-vX.Y.Z-x86_64-unknown-linux-musl.tar.gz.sha256`

This is a single operator image used for both runtime modes; behavior is selected at runtime via:

- `OPERATOR_MANAGED_DEPLOYMENT_MODE=k8s|docker`

## Web UI releases (`ui-vX.Y.Z`)

On `ui-v*` tags, the release workflow publishes:

- Web UI image: `ghcr.io/unrelated-ai/mcp-gateway-ui`

Tagging semantics match other components:

- Stable (`ui-vX.Y.Z`): `:X.Y.Z`, `:latest`, `:sha-<short>`
- Pre-release (`ui-vX.Y.Z-rc.N`): `:X.Y.Z-rc.N`, `:sha-<short>`

The UI version is **baked into the image** at build time via Docker build args:

- `ui/Dockerfile`: `ARG UI_VERSION` → `ENV NEXT_PUBLIC_UI_VERSION=$UI_VERSION`
- `Settings` page reads `NEXT_PUBLIC_UI_VERSION` to display the running UI version.

## How to cut a release

### Pre-flight (recommended)

Run CI checks locally before tagging:

```bash
make ci
```

If you have Docker available and want the full integration coverage:

```bash
make test-integration
```

### Adapter release (`adapter-vX.Y.Z`)

1) Bump versions / notes:

- Update `crates/adapter/Cargo.toml` `version = "X.Y.Z"`
- Update `CHANGELOG.md`

1) Tag and push:

```bash
git tag adapter-vX.Y.Z
git push origin adapter-vX.Y.Z
```

### Gateway release (`gateway-vX.Y.Z`)

1) Bump versions / notes:

- Update `crates/gateway/Cargo.toml` `version = "X.Y.Z"`
- Update `crates/gateway-cli/Cargo.toml` `version = "X.Y.Z"` (CLI is released with the Gateway tag)
- Update `crates/gateway-operator/Cargo.toml` `version = "X.Y.Z"` (Operator image is released with the Gateway tag)
- Update `CHANGELOG.md`

1) Tag and push:

```bash
git tag gateway-vX.Y.Z
git push origin gateway-vX.Y.Z
```

### Web UI release (`ui-vX.Y.Z`)

UI releases are tag-driven (similar to the Rust components):

- Stable: `ui-vX.Y.Z`
- Pre-release: `ui-vX.Y.Z-rc.N`

1) Bump versions / notes:

- Update `ui/package.json` to `"version": "X.Y.Z"`
- Update `ui/package-lock.json` to the same version
- Update `CHANGELOG.md`

1) Tag and push:

```bash
git tag ui-vX.Y.Z
git push origin ui-vX.Y.Z
```

### Notes

- Release workflows are tag-driven; see `.github/workflows/release.yml`.
- Rust release guards verify tag/version alignment via `cargo metadata`.
- UI release guard verifies the tag matches `ui/package.json` version.
