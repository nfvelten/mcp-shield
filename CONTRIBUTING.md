# Contributing to mcp-gateway

Contributions are welcome — bug fixes, new features, tests, and documentation.

## Before you start

For anything beyond a small fix, open an issue first to discuss the approach. This avoids wasted work if the direction doesn't fit the project.

## Setup

```bash
# Prerequisites: Rust stable, Node.js (for the filesystem MCP server used in tests)
git clone https://github.com/nfvelten/mcp-gateway
cd mcp-gateway
cargo build
```

## Running the tests

The integration tests spin up real processes — no mocking.

```bash
# HTTP transport (requires the dummy MCP server)
bash test-http.sh

# stdio transport (requires npx + @modelcontextprotocol/server-filesystem)
bash test-stdio.sh
```

Both scripts print `N passed | 0 failed` on success.

## Project structure

```
src/
  audit/          # AuditLog trait + backends (sqlite, stdout, webhook, fanout)
  middleware/     # Pipeline middleware (auth, rate_limit, payload_filter)
  transport/      # Transport trait + HTTP and stdio implementations
  upstream/       # McpUpstream trait + HTTP upstream with circuit breaker
  bin/
    gateway.rs    # Main binary — wires config, pipeline, transport
    audit.rs      # CLI for querying the SQLite audit log
    dummy_server.rs # Minimal MCP server used in HTTP integration tests
  config.rs       # YAML config parsing and validation
  gateway.rs      # Core McpGateway — intercept, handle, filter
  live_config.rs  # Hot-reloadable config shared via watch::channel
  metrics.rs      # Prometheus-compatible metrics
```

## Design principles

- **Traits over structs** — `Transport`, `McpUpstream`, `AuditLog` are all traits; adding a backend means implementing the trait, not touching the core.
- **No blocking in async context** — SQLite writes go through `spawn_blocking`; `record()` is fire-and-forget via an unbounded channel.
- **Hot-reload without restart** — `tokio::sync::watch` propagates a new `Arc<LiveConfig>` to all middleware on every reload. Middleware snapshots what it needs and drops the borrow before any `.await`.
- **Integration tests over unit tests** — the test scripts exercise real binaries and a real MCP server. Unit tests for logic that can be tested in isolation are welcome alongside them.

## Sending a PR

1. Fork the repo and create a branch from `master`.
2. Make your changes. Add or update tests if the change is observable behavior.
3. Run `cargo clippy` and `cargo fmt` before pushing.
4. Open a PR with a clear description of what and why.

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
