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
        docker-build-gateway-operator docker-build-ui \
        kind-local-build-managed-mcp-images kind-local-build-images \
        kind-local-load-managed-mcp-images kind-local-load-images \
        kind-local-deploy kind-local-refresh kind-local-reset \
        up down logs status \
        inspector \
        ci ci-quick test-ci qa-release-gates \
        helm-validate helm-validate-optional \
        crd-sync crd-sync-check \
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

## Cross-milestone OSS release gates (gateway + operator + UI + compatibility)
qa-release-gates:
	cargo check -p unrelated-mcp-gateway
	cargo test -p unrelated-mcp-gateway --test integration_tenant_api -- --ignored --nocapture --test-threads=1
	cargo test -p unrelated-mcp-gateway --test integration_mode1_config -- --nocapture --test-threads=1
	cargo check -p unrelated-mcp-gateway-operator
	cargo test -p unrelated-mcp-gateway-operator
	cd ui && npm run lint && npm run build
	$(MAKE) helm-validate-optional

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
	docker build --target gateway-operator-runtime -t local/unrelated-mcp-gateway-operator:pr .
	docker build --target gateway-migrator -t local/unrelated-mcp-gateway-migrator:pr .
	docker build -f ui/Dockerfile -t local/unrelated-mcp-gateway-ui:pr ui
	trivy image --format table --exit-code 1 --pkg-types os,library --severity CRITICAL,HIGH local/unrelated-mcp-adapter:pr
	trivy image --format table --exit-code 1 --pkg-types os,library --severity CRITICAL,HIGH local/unrelated-mcp-gateway:pr
	trivy image --format table --exit-code 1 --pkg-types os,library --severity CRITICAL,HIGH local/unrelated-mcp-gateway-operator:pr
	trivy image --format table --exit-code 1 --pkg-types os,library --severity CRITICAL,HIGH local/unrelated-mcp-gateway-migrator:pr
	trivy image --format table --exit-code 1 --pkg-types os,library --severity CRITICAL,HIGH local/unrelated-mcp-gateway-ui:pr

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

KIND_CLUSTER_NAME ?= kind
KIND_IMAGE_TAG ?= kind
KIND_NAMESPACE ?= mcp-gateway
KIND_RELEASE_NAME ?= unrelated-mcp-gateway
KIND_NAMESPACE_DELETE_TIMEOUT_SECONDS ?= 120

CANONICAL_MCP_CRD ?= deploy/operator/crds/mcpservers.gateway.unrelated.ai.yaml
HELM_OPERATOR_MCP_CRD ?= deploy/helm/unrelated-mcp-gateway-operator/crds/mcpservers.gateway.unrelated.ai.yaml

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

## Build Gateway operator image (runtime)
docker-build-gateway-operator:
	docker build --target gateway-operator-runtime -t unrelated-mcp-gateway-operator:latest .

## Build Gateway UI image
docker-build-ui:
	docker build -t unrelated-mcp-gateway-ui:latest ui

## Build managed MCP fixture images for kind (stdio smoke + aggregation)
kind-local-build-managed-mcp-images:
	docker build --target stdio-node -t unrelated-mcp-adapter:stdio-node .
	docker build -f tests/fixtures/managed-images/stdio-aggregation.Dockerfile -t unrelated-mcp-managed-stdio-aggregation:$(KIND_IMAGE_TAG) .
	docker build -f tests/fixtures/managed-images/stdio-smoke.Dockerfile -t unrelated-mcp-managed-stdio-smoke:$(KIND_IMAGE_TAG) .

## Build local images for kind from current workspace
kind-local-build-images: kind-local-build-managed-mcp-images
	docker build --target gateway-runtime -t unrelated-mcp-gateway:$(KIND_IMAGE_TAG) .
	docker build --target gateway-migrator -t unrelated-mcp-gateway-migrator:$(KIND_IMAGE_TAG) .
	docker build --target gateway-operator-runtime -t unrelated-mcp-gateway-operator:$(KIND_IMAGE_TAG) .
	docker build -t unrelated-mcp-gateway-ui:$(KIND_IMAGE_TAG) ui

## Load managed MCP fixture images into kind
kind-local-load-managed-mcp-images:
	kind load docker-image unrelated-mcp-managed-stdio-aggregation:$(KIND_IMAGE_TAG) --name $(KIND_CLUSTER_NAME)
	kind load docker-image unrelated-mcp-managed-stdio-smoke:$(KIND_IMAGE_TAG) --name $(KIND_CLUSTER_NAME)

## Load locally built images into kind
kind-local-load-images: kind-local-load-managed-mcp-images
	kind load docker-image unrelated-mcp-gateway:$(KIND_IMAGE_TAG) --name $(KIND_CLUSTER_NAME)
	kind load docker-image unrelated-mcp-gateway-migrator:$(KIND_IMAGE_TAG) --name $(KIND_CLUSTER_NAME)
	kind load docker-image unrelated-mcp-gateway-operator:$(KIND_IMAGE_TAG) --name $(KIND_CLUSTER_NAME)
	kind load docker-image unrelated-mcp-gateway-ui:$(KIND_IMAGE_TAG) --name $(KIND_CLUSTER_NAME)

## Deploy Helm stack to kind with local images (dev profile)
kind-local-deploy:
	kubectl create namespace $(KIND_NAMESPACE) --dry-run=client -o yaml | kubectl apply -f -
	helm dependency build deploy/helm/unrelated-mcp-gateway
	helm dependency build deploy/helm/unrelated-mcp-gateway-stack
	helm upgrade --install $(KIND_RELEASE_NAME) deploy/helm/unrelated-mcp-gateway-stack \
		--namespace $(KIND_NAMESPACE) \
		-f deploy/helm/unrelated-mcp-gateway-stack/values-dev.yaml \
		-f deploy/helm/unrelated-mcp-gateway-stack/values-kind-local.yaml \
		--set gateway.image.tag=$(KIND_IMAGE_TAG) \
		--set gateway.migrations.image.tag=$(KIND_IMAGE_TAG) \
		--set gatewayui.image.tag=$(KIND_IMAGE_TAG) \
		--set operator.image.tag=$(KIND_IMAGE_TAG)

## Rebuild + load + deploy local images to kind
kind-local-refresh: kind-local-build-images kind-local-load-images kind-local-deploy

## Fully reset kind namespace/release and redeploy fresh (also restarts core deployments)
kind-local-reset:
	helm uninstall $(KIND_RELEASE_NAME) -n $(KIND_NAMESPACE) --ignore-not-found
	kubectl delete namespace $(KIND_NAMESPACE) --ignore-not-found --wait=false
	@echo "Waiting up to $(KIND_NAMESPACE_DELETE_TIMEOUT_SECONDS)s for namespace $(KIND_NAMESPACE) deletion..."
	@elapsed=0; \
	while kubectl get namespace $(KIND_NAMESPACE) >/dev/null 2>&1; do \
		kubectl -n $(KIND_NAMESPACE) get mcpservers.gateway.unrelated.ai -o name 2>/dev/null | while read -r name; do \
			[ -n "$$name" ] || continue; \
			kubectl -n $(KIND_NAMESPACE) patch "$$name" --type=merge -p '{"metadata":{"finalizers":[]}}' >/dev/null 2>&1 || true; \
		done; \
		if [ $$elapsed -ge $(KIND_NAMESPACE_DELETE_TIMEOUT_SECONDS) ]; then \
			echo "Namespace $(KIND_NAMESPACE) is still terminating after $(KIND_NAMESPACE_DELETE_TIMEOUT_SECONDS)s."; \
			echo "Check finalizers with: kubectl get namespace $(KIND_NAMESPACE) -o yaml"; \
			exit 1; \
		fi; \
		sleep 2; \
		elapsed=$$((elapsed + 2)); \
	done
	$(MAKE) kind-local-refresh
	kubectl -n $(KIND_NAMESPACE) rollout restart deploy/unrelated-mcp-gateway deploy/unrelated-mcp-gateway-ui deploy/unrelated-mcp-gateway-operator
	kubectl -n $(KIND_NAMESPACE) rollout status deploy/unrelated-mcp-gateway
	kubectl -n $(KIND_NAMESPACE) rollout status deploy/unrelated-mcp-gateway-ui
	kubectl -n $(KIND_NAMESPACE) rollout status deploy/unrelated-mcp-gateway-operator

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
ci: fmt-check clippy crd-sync-check test-ci

## Fast CI for PRs (check + test-unit)
ci-quick: check fmt-check test-unit

## CI test command (mirrors .github/workflows/ci.yml)
test-ci:
	cargo test --workspace --all-targets

## Sync canonical operator CRD into Helm chart copy
crd-sync:
	cp $(CANONICAL_MCP_CRD) $(HELM_OPERATOR_MCP_CRD)

## Fail if canonical and Helm CRD copies drift
crd-sync-check:
	@cmp -s $(CANONICAL_MCP_CRD) $(HELM_OPERATOR_MCP_CRD) || { \
		echo "ERROR: McpServer CRD copies are out of sync."; \
		echo "Run: make crd-sync"; \
		exit 1; \
	}

## Validate Helm charts (deps + lint + render smoke)
helm-validate:
	@command -v helm >/dev/null 2>&1 || { echo "ERROR: helm is not installed"; exit 1; }
	helm dependency build deploy/helm/unrelated-mcp-gateway
	helm dependency build deploy/helm/unrelated-mcp-gateway-stack
	helm lint deploy/helm/unrelated-mcp-postgres
	helm lint deploy/helm/unrelated-mcp-gateway-operator
	helm lint deploy/helm/unrelated-mcp-gateway --set database.url='postgres://postgres:postgres@db:5432/gateway?sslmode=disable' --set auth.adminToken.value=dev-admin-token --set session.secret.value=dev-session-secret --set session.secretKeys.value=dev-secret-keys
	helm lint deploy/helm/unrelated-mcp-gateway-ui --set gateway.dataBase=http://localhost:27100
	helm lint deploy/helm/unrelated-mcp-gateway-stack -f deploy/helm/unrelated-mcp-gateway-stack/values-dev.yaml
	helm lint deploy/helm/unrelated-mcp-gateway-stack -f deploy/helm/unrelated-mcp-gateway-stack/values-prod.yaml --set gatewayui.gateway.dataBase=https://gateway.example.com --set operator.gateway.bearerToken=lint-token
	helm template unrelated-mcp-gateway deploy/helm/unrelated-mcp-gateway --set database.url='postgres://postgres:postgres@db:5432/gateway?sslmode=disable' --set auth.adminToken.value=dev-admin-token --set session.secret.value=dev-session-secret --set session.secretKeys.value=dev-secret-keys >/dev/null
	helm template unrelated-mcp-gateway-ui deploy/helm/unrelated-mcp-gateway-ui --set gateway.dataBase=http://localhost:27100 >/dev/null
	helm template unrelated-mcp-gateway-stack deploy/helm/unrelated-mcp-gateway-stack -f deploy/helm/unrelated-mcp-gateway-stack/values-dev.yaml >/dev/null
	helm template unrelated-mcp-gateway-stack deploy/helm/unrelated-mcp-gateway-stack -f deploy/helm/unrelated-mcp-gateway-stack/values-prod.yaml --set gatewayui.gateway.dataBase=https://gateway.example.com --set operator.gateway.bearerToken=lint-token >/dev/null
	helm upgrade --install unrelated-mcp-gateway deploy/helm/unrelated-mcp-gateway-stack --namespace mcp-gateway --create-namespace --dry-run --debug -f deploy/helm/unrelated-mcp-gateway-stack/values-dev.yaml >/dev/null
	helm upgrade --install unrelated-mcp-gateway deploy/helm/unrelated-mcp-gateway-stack --namespace mcp-gateway --create-namespace --dry-run --debug -f deploy/helm/unrelated-mcp-gateway-stack/values-prod.yaml --set gatewayui.gateway.dataBase=https://gateway.example.com --set operator.gateway.bearerToken=lint-token >/dev/null

## Validate Helm charts if helm exists (skip otherwise)
helm-validate-optional:
	@if command -v helm >/dev/null 2>&1; then \
		$(MAKE) helm-validate; \
	else \
		echo "Skipping helm-validate (helm not installed)."; \
	fi

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
	@echo "  qa-release-gates     Run OSS release gate suite (gateway/operator/ui)"
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
	@echo "  docker-build-gateway-operator  Build gateway operator Docker image"
	@echo "  docker-build-ui                Build gateway UI Docker image"
	@echo "  docker-build-all               Build all images used by docker-compose"
	@echo "  kind-local-build-managed-mcp-images Build managed MCP fixture images for kind"
	@echo "  kind-local-build-images        Build gateway/ui/operator/migrator images for kind"
	@echo "  kind-local-load-managed-mcp-images Load managed MCP fixture images into kind"
	@echo "  kind-local-load-images         Load local kind images into kind cluster"
	@echo "  kind-local-deploy              Helm deploy to kind with local image overrides"
	@echo "  kind-local-refresh             Build + load + deploy local kind stack"
	@echo "  kind-local-reset               Full clean reset + refresh + rollout restart/status"
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
	@echo "  helm-validate  Run Helm deps/lint/template/dry-run checks"
	@echo "  crd-sync       Copy canonical McpServer CRD into Helm chart"
	@echo "  crd-sync-check Verify canonical/Helm McpServer CRDs are in sync"
