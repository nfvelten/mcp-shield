# ── Build stage ───────────────────────────────────────────────────────────────
# Uses musl for a fully static binary — no glibc dependency in the runtime image.
FROM rust:alpine AS builder

RUN apk add --no-cache musl-dev perl make

WORKDIR /build

# Cache dependencies before copying source.
# Stub binaries allow `cargo build` to cache all crate downloads and compilation
# without re-running when only application source changes.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src/bin \
    && echo "fn main() {}" > src/bin/arbit.rs \
    && echo "fn main() {}" > src/bin/dummy_server.rs \
    && echo "" > src/lib.rs \
    && cargo build --release --bin arbit \
    && rm -rf src

# Build the real binary
COPY src ./src
RUN touch src/lib.rs \
    && cargo build --release --bin arbit

# ── Runtime stage ─────────────────────────────────────────────────────────────
# Static binary + ca-certificates in a minimal image.
# Uses debian:bookworm-slim (not scratch) to have /etc/passwd and CA certs
# available without manual setup — simplifies Kubernetes RunAsNonRoot.
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates wget \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 arbit \
    && useradd --uid 10001 --gid arbit --no-create-home --shell /sbin/nologin arbit

WORKDIR /app

COPY --from=builder /build/target/release/arbit /usr/local/bin/arbit

# Bundle the example config — override at runtime with -v or ConfigMap mount
COPY gateway.example.yml /app/gateway.yml

EXPOSE 4000

# Run as non-root by default
USER arbit

# LOG_FORMAT=json  → structured JSON logs (recommended for log aggregators)
# LOG_LEVEL=info   → log verbosity (debug | info | warn | error)
ENV LOG_FORMAT=json \
    LOG_LEVEL=info

ENTRYPOINT ["arbit"]
CMD ["start", "/app/gateway.yml"]
