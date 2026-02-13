# Makefile for Unrelated MCP Workspace (Adapter + Gateway + CLI)
# ==============================================================

.PHONY: all \
        build build-release check \
        build-adapter build-gateway build-cli \
        build-release-adapter build-release-gateway build-release-cli \
        check-adapter check-gateway check-cli \
        test test-adapter test-gateway test-cli test-unit \
        test-integration test-integration-adapter test-integration-gateway \
        fmt fmt-check clippy lint \
        security security-audit security-trivy \
        doc doc-open \
        adapter-run adapter-run-release \
        adapter-run-with-test-config adapter-run-release-with-test-config \
        gateway \
        dev dev-adapter dev-gateway dev-cli \
        cli cli-dev cli-build cli-release cli-install \
        clean clean-all \
        docker-build-all docker-build-adapter docker-build-adapter-stdio-node \
        docker-run-adapter docker-build-gateway docker-build-gateway-migrator \
        up down logs status \
        inspector \
        ci ci-quick test-ci \
        hooks-install bench help

# Default target
all: build

# =============================================================================
# Build Targets
# =============================================================================

## Build all workspace binaries (debug)
build:
	cargo build --workspace

## Build all workspace binaries (release)
build-release:
	cargo build --release --workspace

## Type-check without building (faster feedback)
check:
	cargo check --workspace

## Build adapter only (debug)
build-adapter:
	cargo build -p unrelated-mcp-adapter

## Build gateway only (debug)
build-gateway:
	cargo build -p unrelated-mcp-gateway

## Build gateway CLI only (debug)
build-cli:
	cargo build -p unrelated-gateway-admin

## Build adapter only (release)
build-release-adapter:
	cargo build --release -p unrelated-mcp-adapter

## Build gateway only (release)
build-release-gateway:
	cargo build --release -p unrelated-mcp-gateway

## Build gateway CLI only (release)
build-release-cli:
	cargo build --release -p unrelated-gateway-admin

## Type-check adapter only
check-adapter:
	cargo check -p unrelated-mcp-adapter

## Type-check gateway only
check-gateway:
	cargo check -p unrelated-mcp-gateway

## Type-check gateway CLI only
check-cli:
	cargo check -p unrelated-gateway-admin

# =============================================================================
# Test Targets
# =============================================================================

## Run all tests (workspace)
test:
	cargo test --workspace --all-targets

## Run adapter tests only
test-adapter:
	cargo test -p unrelated-mcp-adapter

## Run gateway tests only
test-gateway:
	cargo test -p unrelated-mcp-gateway

## Run gateway CLI tests only
test-cli:
	cargo test -p unrelated-gateway-admin

## Run unit tests only (excludes integration tests)
test-unit:
	cargo test --workspace --lib --bins

## Run integration tests (requires Docker)
test-integration: test-integration-adapter test-integration-gateway

## Run adapter integration tests only (requires Docker)
test-integration-adapter:
	cargo test -p unrelated-mcp-adapter --tests -- --nocapture --test-threads=1 && \
	cargo test -p unrelated-mcp-adapter --tests -- --ignored --nocapture --test-threads=1

## Run gateway integration tests only (requires Docker)
test-integration-gateway:
	cargo test -p unrelated-mcp-gateway --tests -- --nocapture --test-threads=1 && \
	cargo test -p unrelated-mcp-gateway --tests -- --ignored --nocapture --test-threads=1

# =============================================================================
# Code Quality Targets
# =============================================================================

## Format code
fmt:
	cargo fmt
	cd ui && npm run -s format

## Check formatting without modifying files
fmt-check:
	cargo fmt --all -- --check
	cd ui && npm run -s format:check

## Run clippy linter
clippy:
	cargo clippy --workspace --all-targets -- -D warnings -W clippy::pedantic

## Run all lints (fmt + clippy)
lint: fmt-check clippy

# =============================================================================
# Security
# =============================================================================

## Run security checks (mirrors split security workflows in .github/workflows/security-*.yml)
security: security-audit security-trivy

## Rust dependency audit (RustSec)
security-audit:
	cargo audit

## Trivy scan local Docker images (requires docker + trivy)
security-trivy:
	docker build -t local/unrelated-mcp-adapter:pr .
	docker build --target gateway-runtime -t local/unrelated-mcp-gateway:pr .
	docker build --target gateway-migrator -t local/unrelated-mcp-gateway-migrator:pr .
	docker build -f ui/Dockerfile -t local/unrelated-mcp-gateway-ui:pr ui
	trivy image --format table --exit-code 1 --vuln-type os,library --severity CRITICAL,HIGH local/unrelated-mcp-adapter:pr
	trivy image --format table --exit-code 1 --vuln-type os,library --severity CRITICAL,HIGH local/unrelated-mcp-gateway:pr
	trivy image --format table --exit-code 1 --vuln-type os,library --severity CRITICAL,HIGH local/unrelated-mcp-gateway-migrator:pr
	trivy image --format table --exit-code 1 --vuln-type os,library --severity CRITICAL,HIGH local/unrelated-mcp-gateway-ui:pr

# =============================================================================
# Documentation
# =============================================================================

## Generate documentation
doc:
	cargo doc --no-deps

## Generate and open documentation in browser
doc-open:
	cargo doc --no-deps --open

# =============================================================================
# Development
# =============================================================================

# Common knobs for local runs.
ADAPTER_CONFIG ?= tests/fixtures/test-config.yaml
ADAPTER_BIND ?= 127.0.0.1:8080

## Run the adapter with example config (debug mode)
adapter-run:
	cargo run -p unrelated-mcp-adapter --bin unrelated-mcp-adapter -- --config $(ADAPTER_CONFIG) --bind $(ADAPTER_BIND)

## Run the adapter with example config (release mode)
adapter-run-release: build-release-adapter
	./target/release/unrelated-mcp-adapter \
		--config $(ADAPTER_CONFIG) \
		--bind $(ADAPTER_BIND)

## Run the adapter with test config (debug mode) (explicit name)
adapter-run-with-test-config: adapter-run

## Run the adapter with test config (release mode) (explicit name)
adapter-run-release-with-test-config: adapter-run-release

## Watch for changes and rebuild (requires cargo-watch)
dev:
	cargo watch -x 'check -p unrelated-mcp-adapter' -x 'test -p unrelated-mcp-adapter'

## Watch for changes (adapter only; explicit name)
dev-adapter: dev

## Watch for changes (gateway only; requires cargo-watch)
dev-gateway:
	cargo watch -x 'check -p unrelated-mcp-gateway' -x 'test -p unrelated-mcp-gateway'

## Watch for changes (CLI only; requires cargo-watch)
dev-cli:
	cargo watch -x 'check -p unrelated-gateway-admin' -x 'test -p unrelated-gateway-admin'

## Build gateway CLI (debug)
cli-build: build-cli

## Run gateway CLI (dev). Pass args via CLI_ARGS, e.g.:
##   make cli CLI_ARGS="config show"
##   make cli CLI_ARGS="tenants list"
CLI_ARGS ?= --help
cli:
	cargo run -p unrelated-gateway-admin -- $(CLI_ARGS)

## Run gateway CLI (dev) against docker-compose defaults (base URLs + token).
CLI_DEV_ADMIN_BASE ?= http://127.0.0.1:27101
CLI_DEV_DATA_BASE ?= http://127.0.0.1:27100
CLI_DEV_ADMIN_TOKEN ?= dev-admin-token
cli-dev:
	UNRELATED_GATEWAY_ADMIN_BASE=$(CLI_DEV_ADMIN_BASE) \
	UNRELATED_GATEWAY_DATA_BASE=$(CLI_DEV_DATA_BASE) \
	UNRELATED_GATEWAY_ADMIN_TOKEN=$(CLI_DEV_ADMIN_TOKEN) \
	cargo run -p unrelated-gateway-admin -- $(CLI_ARGS)

## Run gateway CLI (release). Pass args via CLI_ARGS.
cli-release: build-release-cli
	./target/release/unrelated-gateway-admin $(CLI_ARGS)

## Install gateway CLI into ~/.cargo/bin (useful for local iteration).
cli-install:
	cargo install --path crates/gateway-cli --locked --force

## Run the gateway (dev). Pass args via GATEWAY_ARGS, e.g.:
##   make gateway GATEWAY_ARGS="--help"
GATEWAY_ARGS ?= --help
gateway:
	cargo run -p unrelated-mcp-gateway -- $(GATEWAY_ARGS)

# =============================================================================
# Cleanup
# =============================================================================

## Clean build artifacts
clean:
	cargo clean

## Clean everything (build artifacts). Cargo.lock is tracked and won't be removed.
clean-all: clean
	@echo "Note: Cargo.lock is tracked. If you really want to remove it, run: rm -f Cargo.lock"

# =============================================================================
# Docker
# =============================================================================

## Build adapter runtime image (default target in Dockerfile)
docker-build-adapter:
	docker build -t unrelated-mcp-adapter:latest .

## Build adapter stdio-node image (for stdio aggregation examples)
docker-build-adapter-stdio-node:
	docker build --target stdio-node -t unrelated-mcp-adapter:stdio-node .

## Build all images used by the default docker-compose stack
docker-build-all: docker-build-adapter docker-build-adapter-stdio-node docker-build-gateway docker-build-gateway-migrator

## Run adapter in Docker container (standalone, without compose)
docker-run-adapter:
	docker run --rm -p 8080:8080 \
		-e UNRELATED_CONFIG=/config/config.yaml \
		-v $(PWD)/tests/fixtures/test-config.yaml:/config/config.yaml:ro \
		unrelated-mcp-adapter:latest

## Build Gateway image (runtime)
docker-build-gateway:
	docker build --target gateway-runtime -t unrelated-mcp-gateway:latest .

## Build Gateway migrator image (dbmate + baked migrations)
docker-build-gateway-migrator:
	docker build --target gateway-migrator -t unrelated-mcp-gateway-migrator:latest .

## Start services with docker-compose
up:
	docker compose up -d --build

## Reset the docker-compose Postgres DB (deletes all tenants/config; for onboarding testing)
up-reset:
	docker compose --profile manual run --rm gateway_db_reset

## Stop services with docker-compose
down:
	docker compose down

## View docker-compose logs
logs:
	docker compose logs -f

## Show docker-compose status
status:
	docker compose ps

# =============================================================================
# MCP Inspector
# =============================================================================

## Run the MCP Inspector (installs via npx if needed)
inspector:
	npx -y @modelcontextprotocol/inspector

# =============================================================================
# CI Targets
# =============================================================================

## Run all CI checks (lint + test)
ci: fmt-check clippy test-ci

## Fast CI for PRs (check + test-unit)
ci-quick: check fmt-check test-unit

## CI test command (mirrors .github/workflows/ci.yml)
test-ci:
	cargo test --workspace --all-targets

## Install repo githooks (pre-push)
hooks-install:
	chmod +x .githooks/pre-push
	@echo "Now run: git config core.hooksPath .githooks"

# =============================================================================
# Benchmarks (placeholder)
# =============================================================================

## Run benchmarks (requires bench setup)
bench:
	cargo bench

# =============================================================================
# Help
# =============================================================================

## Show this help message
help:
	@echo "Unrelated MCP Workspace - Available Make Targets"
	@echo "================================================"
	@echo ""
	@echo "Build:"
	@echo "  build                Build all workspace binaries (debug)"
	@echo "  build-release        Build all workspace binaries (release)"
	@echo "  check                Type-check workspace"
	@echo "  build-adapter        Build adapter only (debug)"
	@echo "  build-gateway        Build gateway only (debug)"
	@echo "  build-cli            Build gateway CLI only (debug)"
	@echo ""
	@echo "Test:"
	@echo "  test                 Run all tests (workspace)"
	@echo "  test-adapter         Run adapter tests"
	@echo "  test-gateway         Run gateway tests"
	@echo "  test-cli             Run gateway CLI tests"
	@echo "  test-integration     Run integration tests (requires Docker)"
	@echo ""
	@echo "Code Quality:"
	@echo "  fmt            Format code"
	@echo "  fmt-check      Check formatting"
	@echo "  clippy         Run clippy linter"
	@echo "  lint           Run all lints (fmt + clippy)"
	@echo ""
	@echo "Documentation:"
	@echo "  doc            Generate documentation"
	@echo "  doc-open       Generate and open docs in browser"
	@echo ""
	@echo "Development:"
	@echo "  adapter-run                     Run adapter with example config (debug)"
	@echo "  adapter-run-release             Run adapter with example config (release)"
	@echo "  gateway GATEWAY_ARGS=\"...\"       Run gateway (cargo run) with args"
	@echo "  cli CLI_ARGS=\"...\"              Run gateway CLI (cargo run) with args"
	@echo "  cli-dev CLI_ARGS=\"...\"          Run CLI with docker-compose defaults (base URLs + token)"
	@echo "  cli-release CLI_ARGS=\"...\"      Run CLI from ./target/release"
	@echo "  cli-install                     Install CLI into ~/.cargo/bin"
	@echo "  dev                             Watch mode (adapter; requires cargo-watch)"
	@echo "  dev-gateway                      Watch mode (gateway; requires cargo-watch)"
	@echo "  dev-cli                          Watch mode (cli; requires cargo-watch)"
	@echo ""
	@echo "Cleanup:"
	@echo "  clean          Clean build artifacts"
	@echo "  clean-all      Clean everything including Cargo.lock"
	@echo ""
	@echo "Docker:"
	@echo "  docker-build-adapter           Build adapter runtime image"
	@echo "  docker-build-adapter-stdio-node Build adapter stdio-node image"
	@echo "  docker-build-gateway           Build gateway Docker image"
	@echo "  docker-build-gateway-migrator  Build gateway migrator Docker image"
	@echo "  docker-build-all               Build all images used by docker-compose"
	@echo "  docker-run-adapter            Run adapter in Docker container (standalone)"
	@echo "  up                            Start docker-compose stack"
	@echo "  up-reset                      Reset compose DB (delete all tenants/config)"
	@echo "  down                          Stop docker-compose stack"
	@echo "  status                        Show docker-compose status"
	@echo "  logs                          View docker-compose logs"
	@echo ""
	@echo "Tools:"
	@echo "  inspector              Run MCP Inspector (npx)"
	@echo ""
	@echo "CI:"
	@echo "  ci             Run all CI checks"
	@echo "  ci-quick       Fast CI for PRs"
