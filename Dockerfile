# syntax=docker/dockerfile:1.7-labs
#
# =============================================================================
# Unrelated MCP Workspace - Multi-stage Dockerfile
# =============================================================================
#
# This single Dockerfile builds both:
# - Adapter: `unrelated-mcp-adapter`
# - Gateway: `unrelated-mcp-gateway`
#
# Build examples:
# - Adapter (default final stage):
#   - docker build -t unrelated-mcp-adapter:latest .
# - Adapter (stdio helper image):
#   - docker build --target stdio-node -t unrelated-mcp-adapter:stdio-node .
# - Gateway:
#   - docker build --target gateway-runtime -t unrelated-mcp-gateway:latest .
# - Gateway migrator (dbmate + baked migrations):
#   - docker build --target gateway-migrator -t unrelated-mcp-gateway-migrator:latest .
#

# -----------------------------------------------------------------------------
# Stage 1: Build
# -----------------------------------------------------------------------------
FROM rust:1.92.0-slim AS builder

ARG TARGET=x86_64-unknown-linux-musl
ENV RUSTFLAGS="-C strip=symbols"

ENV CARGO_NET_RETRY=10
ENV CARGO_HTTP_TIMEOUT=120
ENV CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        musl-tools \
        && \
    rm -rf /var/lib/apt/lists/*

RUN rustup target add "${TARGET}"

WORKDIR /app

# Copy manifests first (for better layer caching)
COPY Cargo.toml Cargo.lock ./
COPY --parents crates/*/Cargo.toml ./

# Create common mount points (scratch can't mkdir)
RUN mkdir -p /config

# Create dummy source files to build dependencies (and satisfy workspace members).
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    mkdir -p crates/adapter/src crates/env/src crates/gateway/src crates/gateway-cli/src crates/http-tools/src crates/openapi-tools/src crates/test-support/src crates/tool-transforms/src && \
    echo "fn main() {}" > crates/adapter/src/main.rs && \
    echo "pub fn _dummy() {}" > crates/env/src/lib.rs && \
    echo "fn main() {}" > crates/gateway/src/main.rs && \
    echo "fn main() {}" > crates/gateway-cli/src/main.rs && \
    echo "pub fn _dummy() {}" > crates/http-tools/src/lib.rs && \
    echo "pub fn _dummy() {}" > crates/openapi-tools/src/lib.rs && \
    echo "pub fn _dummy() {}" > crates/test-support/src/lib.rs && \
    echo "pub fn _dummy() {}" > crates/tool-transforms/src/lib.rs && \
    cargo build --release --target "${TARGET}" -p unrelated-mcp-adapter --bin unrelated-mcp-adapter && \
    cargo build --release --target "${TARGET}" -p unrelated-mcp-gateway --bin unrelated-mcp-gateway && \
    rm -rf crates/adapter/src crates/env/src crates/gateway/src crates/gateway-cli/src crates/http-tools/src crates/openapi-tools/src crates/test-support/src crates/tool-transforms/src

# Copy actual source code
COPY crates/adapter/src ./crates/adapter/src
COPY crates/env/src ./crates/env/src
COPY crates/gateway/src ./crates/gateway/src
COPY crates/gateway-cli/src ./crates/gateway-cli/src
COPY crates/http-tools/src ./crates/http-tools/src
COPY crates/openapi-tools/src ./crates/openapi-tools/src
COPY crates/test-support/src ./crates/test-support/src
COPY crates/tool-transforms/src ./crates/tool-transforms/src

RUN touch crates/env/src/lib.rs crates/http-tools/src/lib.rs crates/openapi-tools/src/lib.rs crates/tool-transforms/src/lib.rs

# Build the actual binaries (touch to invalidate cache)
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    touch crates/adapter/src/main.rs && cargo build --release --target "${TARGET}" -p unrelated-mcp-adapter --bin unrelated-mcp-adapter
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    touch crates/gateway/src/main.rs && cargo build --release --target "${TARGET}" -p unrelated-mcp-gateway --bin unrelated-mcp-gateway

# -----------------------------------------------------------------------------
# Stage 2: Stdio integration image (adds extra runtimes; used for local testing)
# -----------------------------------------------------------------------------
FROM node:20-alpine AS stdio-node

ARG TARGET=x86_64-unknown-linux-musl

RUN apk add --no-cache ca-certificates
RUN mkdir -p /config

WORKDIR /app
COPY --from=builder /app/target/${TARGET}/release/unrelated-mcp-adapter /app/unrelated-mcp-adapter

ENV UNRELATED_BIND=0.0.0.0:8080
EXPOSE 8080
ENTRYPOINT ["/app/unrelated-mcp-adapter"]

# -----------------------------------------------------------------------------
# Stage 3: Gateway runtime
# -----------------------------------------------------------------------------
FROM alpine:3.20 AS gateway-runtime

ARG TARGET=x86_64-unknown-linux-musl

RUN apk add --no-cache ca-certificates

WORKDIR /app

COPY --from=builder /app/target/${TARGET}/release/unrelated-mcp-gateway /app/unrelated-mcp-gateway

ENV UNRELATED_GATEWAY_BIND=0.0.0.0:4000
ENV UNRELATED_GATEWAY_ADMIN_BIND=0.0.0.0:4001

EXPOSE 4000
EXPOSE 4001

ENTRYPOINT ["/app/unrelated-mcp-gateway"]

# -----------------------------------------------------------------------------
# Stage 4: Gateway migrator (dbmate + baked migrations)
# -----------------------------------------------------------------------------
FROM amacneil/dbmate:2.29.4 AS gateway-migrator

WORKDIR /db

COPY crates/gateway/migrations /db/migrations

ENV DBMATE_MIGRATIONS_DIR=/db/migrations

ENTRYPOINT ["/usr/local/bin/dbmate"]
CMD ["up"]

# -----------------------------------------------------------------------------
# Stage 5: Adapter runtime (final, minimal static; default)
# -----------------------------------------------------------------------------
FROM scratch AS runtime

ARG TARGET=x86_64-unknown-linux-musl

WORKDIR /app
COPY --from=builder /config /config
COPY --from=builder /app/target/${TARGET}/release/unrelated-mcp-adapter /app/unrelated-mcp-adapter

ENV UNRELATED_BIND=0.0.0.0:8080
EXPOSE 8080
ENTRYPOINT ["/app/unrelated-mcp-adapter"]
