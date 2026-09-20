# Contributing

## Development setup

- Rust: the pinned compiler in `rust-toolchain.toml`
- Docker: required for integration tests (Testcontainers)

## Common commands

```bash
make ci
make test-integration
```

Optional local hooks:

```bash
make hooks-install
git config core.hooksPath .githooks
```

## PRs

- Keep PRs focused and small when possible
- Add tests for bug fixes and new behavior
- Run `make ci` before pushing

## Shared code and dependencies

Keep toolchain versions in native manifests and shared deployment images in
`deploy/images.env`. See [version maintenance](docs/development/VERSIONS.md)
for Compose usage, Helm packaging, and component-version boundaries.

Gateway routes and control-plane error contracts live in `crates/gateway-api`.
Routers use route templates; Rust clients bind identifiers through the shared
builders so reserved characters remain within their path segment. The UI uses
`gatewayRoutes.ts` and the shared `gateway-http.ts` response policies.

Shared Rust versions live in `[workspace.dependencies]`; member crates add only
their required features. Dependabot groups weekly Cargo/npm/Go/Actions updates
against `feat/version_one_zero`. Check the compatibility constraints in
[version maintenance](docs/development/VERSIONS.md#compatibility-constraints)
before changing dependency majors.

See [performance checks](docs/gateway/PERFORMANCE.md#development-checks) for load
and recovery tests, and the [release checklist](docs/development/RELEASING.md)
for packaging and upgrade validation.
