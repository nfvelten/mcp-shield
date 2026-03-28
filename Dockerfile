# ── Build stage ───────────────────────────────────────────────────────────────
FROM rust:1.87-slim AS builder

WORKDIR /build

# Cache dependencies before copying source
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src/bin \
    && echo "fn main() {}" > src/bin/gateway.rs \
    && echo "fn main() {}" > src/bin/audit.rs \
    && echo "fn main() {}" > src/bin/dummy_server.rs \
    && echo "" > src/lib.rs \
    && cargo build --release --bin gateway --bin audit \
    && rm -rf src

# Build the real binaries
COPY src ./src
RUN touch src/main.rs \
    && cargo build --release --bin gateway --bin audit

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /build/target/release/gateway /usr/local/bin/gateway
COPY --from=builder /build/target/release/audit   /usr/local/bin/audit

# Default config location — mount your own with -v
COPY gateway.yml /app/gateway.yml

EXPOSE 4000

ENV LOG_FORMAT=json

ENTRYPOINT ["gateway"]
CMD ["/app/gateway.yml"]
