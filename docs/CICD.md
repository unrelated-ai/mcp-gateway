# CI/CD

This repo is a monorepo. CI is generic; releases are tag-driven.

## Workflows

- **CI**: [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) (PRs only, no publishing)
- **Release entrypoint**: [`.github/workflows/release.yml`](../.github/workflows/release.yml) (tag pushes only)
- **Reusable publisher**: [`.github/workflows/docker-release.yml`](../.github/workflows/docker-release.yml) (called from `release.yml`)
- **Reusable release assets**: [`.github/workflows/binary-release.yml`](../.github/workflows/binary-release.yml) (called from `release.yml`)
- **Reusable UI publisher**: [`.github/workflows/ui-docker-release.yml`](../.github/workflows/ui-docker-release.yml) (called from `release.yml`)

## Release tag convention

Use component-scoped tags:

- **Stable**: `<component>-vX.Y.Z` (example: `adapter-v3.5.2`)
- **Pre-release**: `<component>-vX.Y.Z-rc.N` (example: `adapter-v3.6.0-rc.1`)

## Published image + tags

Published images:

- `ghcr.io/unrelated-ai/mcp-adapter`
- `ghcr.io/unrelated-ai/mcp-gateway`
- `ghcr.io/unrelated-ai/mcp-gateway-migrator`
- `ghcr.io/unrelated-ai/mcp-gateway-ui`

All published runtime images are minimal and contain a **static** binary (or migrations for the migrator).

## Release guard (Cargo.toml is the source of truth)

On tag pushes (e.g. `adapter-v0.2.5` or `gateway-v0.8.0`), the release workflow verifies that the tag version
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
- Gateway admin CLI release assets:
  - `unrelated-gateway-admin-vX.Y.Z-x86_64-unknown-linux-musl.tar.gz`
  - `unrelated-gateway-admin-vX.Y.Z-x86_64-unknown-linux-musl.tar.gz.sha256`

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

2) Tag and push:

```bash
git tag adapter-vX.Y.Z
git push origin adapter-vX.Y.Z
```

### Gateway release (`gateway-vX.Y.Z`)

1) Bump versions / notes:

- Update `crates/gateway/Cargo.toml` `version = "X.Y.Z"`
- Update `crates/gateway-cli/Cargo.toml` `version = "X.Y.Z"` (CLI is released with the Gateway tag)
- Update `CHANGELOG.md`

2) Tag and push:

```bash
git tag gateway-vX.Y.Z
git push origin gateway-vX.Y.Z
```

### Web UI release (`ui-vX.Y.Z`)

UI releases are tag-driven (similar to the Rust components):

- Stable: `ui-vX.Y.Z`
- Pre-release: `ui-vX.Y.Z-rc.N`

Tag and push:

```bash
git tag ui-vX.Y.Z
git push origin ui-vX.Y.Z
```

### Notes

- Release workflows are tag-driven; see `.github/workflows/release.yml`.
- The release guard verifies the tag matches the package version (via `cargo metadata`).
