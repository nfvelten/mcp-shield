# Changelog

## [0.14.0] — 2026-03-31

### Added
- **Docker image published to GHCR**: `ghcr.io/nfvelten/arbit:<version>` built and pushed automatically on every `v*` tag via `.github/workflows/docker.yml`; multi-arch (`linux/amd64` + `linux/arm64`); layer cache backed by GitHub Actions cache
- **`docker-compose.yml`**: healthcheck via `wget /health`, `LOG_FORMAT`/`LOG_LEVEL` env vars documented, commented example for `ARBIT_ADMIN_TOKEN` secret injection

### Changed
- **Dockerfile**: fixed binary names (`gateway`/`audit` → `arbit`); added non-root user `arbit` (uid 10001); added `wget` for healthcheck; `ENTRYPOINT ["arbit"] CMD ["start", "/app/gateway.yml"]`
- **`.dockerignore`**: extended to exclude test fixtures, strategy docs, and extra config files
## [0.13.0] — 2026-03-31

### Changed
- **Graceful shutdown for stdio transport**: the main read loop now uses `tokio::select!` to race `stdin.next_line()` against SIGTERM/CTRL-C; on signal the loop breaks cleanly, the child process is drained, and the audit log is flushed before exit — previously SIGTERM killed the process immediately without flushing
- **Shutdown log sequence**: `shutdown_signal()` (HTTP) now logs "draining active connections"; `arbit.rs` logs "flushing audit backends" and "shutdown complete" after transport exits — the audit flush is no longer misleadingly attributed to the signal handler

---

## [0.12.0] — 2026-03-31

### Added
- **Env var interpolation in config** (`${VAR}` syntax): any value in `gateway.yml` can reference an environment variable; missing variables abort startup with a descriptive error identifying the missing name — enables Kubernetes Secret injection without embedding credentials in config files
- **`ARBIT_*` env var overrides**: three top-level overrides applied after YAML parsing; precedence: env var > YAML value:
  - `ARBIT_ADMIN_TOKEN` — overrides `admin_token`
  - `ARBIT_UPSTREAM_URL` — overrides `transport.upstream`
  - `ARBIT_LISTEN_ADDR` — overrides `transport.addr`
- `Config::set_upstream_url()` and `Config::set_listen_addr()` helper methods

### Changed
- `Config::from_file()` now runs interpolation and env overrides before `validate()` — fully backward compatible

---

## [0.11.0] — 2026-03-31

### Added
- **OpenLineage Integration**: new `openlineage` audit backend emits OpenLineage `RunEvent` (spec 2-0-2) on every `tools/call`:
  - `eventType` maps to `COMPLETE` (allowed/forwarded/shadowed) or `FAIL` (blocked)
  - `job.namespace` / `job.name` encode `<namespace>/<agent_id>/<tool_name>` for lineage graph navigation
  - `run.runId` is the existing `X-Request-Id` UUID — correlates lineage events with audit log entries
  - `run.facets` includes `arbit:execution` (outcome, agent, input_tokens) and `arbit:arguments` (captured tool arguments)
  - `inputs[]` dataset entry identifies the tool and agent as the lineage source
  - Configurable `namespace`, optional Bearer token auth; non-tools/call events skipped automatically
  - Enables LGPD/GDPR compliance tracing: "AI generated response X based on tool Y which queried Z"
- **`AuditConfig::OpenLineage`** variant: `url`, `token` (optional), `namespace` (default: `"arbit"`) — fully backward compatible

---

## [0.10.0] — 2026-03-31

### Added
- **Cost Observability**: per-agent token estimation and chargeback tracking using the 4-chars-per-token heuristic:
  - `arbit_tokens_total` Prometheus counter with `agent` and `direction` (`input`/`output`) labels — queryable via `/metrics` for cumulative per-agent spend
  - `input_tokens` column added to the SQLite audit log — per-request token estimate stored alongside every `tools/call` entry; existing databases are migrated automatically
  - `cost.rs` module with `estimate_tokens()` and `estimate_tokens_str()` utilities
  - `GatewayMetrics::record_tokens()` method called on every forwarded `tools/call` (both regular and federated paths)

---

## [0.9.0] — 2026-03-31

### Added
- **Tool Federation**: agents with `federate: true` query all named upstreams in parallel on `tools/list` and receive a single merged tool view; colliding tool names are prefixed with `<upstream>__name` (e.g. `filesystem__read_file`); `tools/call` transparently strips the prefix and routes to the correct upstream
- **OpenAI Tools Bridge**: two new endpoints translate between OpenAI function-calling format and MCP, allowing legacy OpenAI SDK clients to use arbit's security infrastructure without refactoring:
  - `GET /openai/v1/tools` — returns available tools in OpenAI function format (`parameters` / `type: function`)
  - `POST /openai/v1/execute` — accepts `tool_calls` array, executes each via the MCP gateway, returns `tool_results`; all requests pass through the full middleware pipeline

### Changed
- `AgentPolicy` gains `federate: bool` field (default: `false`) — fully backward compatible

---

## [0.8.0] — 2026-03-31

### Added
- **Human-in-the-Loop (HITL)**: `HitlMiddleware` suspends `tools/call` requests matching `approval_required` patterns and waits for an operator decision via REST API (`GET /approvals`, `POST /approvals/{id}/approve`, `POST /approvals/{id}/reject`); auto-rejects after `hitl_timeout_secs` (default: 60)
- **Shadow mode**: tools matching `shadow_tools` are intercepted after the middleware pipeline passes — logged as `Outcome::Shadowed`, a mock success response is returned, and the call is never forwarded to the upstream; supports glob wildcards
- **Supply-chain security**: binary verification for the stdio transport before spawn; two independent checks: SHA-256 hash pinning (`verify.sha256`) and Sigstore cosign bundle (`verify.cosign_bundle` via `cosign verify-blob`); startup aborted on failure
- **CloudEvents 1.0**: webhook audit backend gains `cloudevents: true` option; emits CNCF CloudEvents 1.0 envelopes (`application/cloudevents+json`) with event type `dev.arbit.audit.<outcome>`; configurable `source` attribute (default: `/arbit`)
- **Unified CLI**: `arbit start`, `arbit validate`, and `arbit audit` subcommands replace the separate `arbit` and `arbit-audit` binaries; legacy `arbit gateway.yml` invocation still works
- **`Outcome::Shadowed`** audit variant: all backends (SQLite, stdout, webhook) handle the new outcome

### Changed
- `AuditConfig::Webhook` gains `cloudevents: bool` (default: `false`) and `source: String` (default: `"/arbit"`) fields — fully backward compatible
- `TransportConfig::Stdio` gains optional `verify: BinaryVerifyConfig` field

---

## [0.7.0] — 2026-03-30

### Added
- **Schema validation middleware**: `SchemaValidationMiddleware` validates `tools/call` arguments against the `inputSchema` from `tools/list`; invalid args are blocked before reaching the upstream
- **Encoding-aware filtering**: `decode.rs` decodes Base64 (standard and URL-safe), percent-encoding, double-encoding, and Unicode (NFC + Bidi-control stripping) variants of every argument before applying block patterns — catches obfuscated bypass attempts
- **Schema cache**: `schema_cache.rs` caches per-agent `inputSchema` entries populated from `tools/list` responses; used by the validation middleware
- **Expanded `AuthMiddleware`**: full allowlist/denylist enforcement and API key / JWT validation moved into the middleware pipeline
- **Security test suite**: `attack_scenarios.rs` (SSRF, path traversal, credential leaks, SQL injection, prompt injection variants) and `security_coverage.rs` (payload filter and injection detection coverage)
- **`gateway-test.yml`** fixture for the integration test environment

### Changed
- Integration tests migrated from shell scripts (`test-http.sh`, `test-stdio.sh`) to Rust (`tests/http_gateway.rs`, `tests/stdio_gateway.rs`)
- Stdio tests marked `#[ignore]` — require `npx` at runtime, excluded from CI

---

## [0.6.0] — 2026-03-29

### Added
- **Wildcard tool matching**: glob patterns (`read_*`, `*_file`, `fs/*`) in `allowed_tools` / `denied_tools`
- **`/health` endpoint v2**: reports per-upstream circuit state (`{"status":"ok","upstreams":{"default":true,"filesystem":false}}`)
- **Per-agent upstream timeout**: `timeout_secs` field overrides the global 30s default
- **`default_policy`**: top-level fallback for agents not listed in config (rate limit, denied tools, timeout)
- **`X-Request-Id`** header on every response for end-to-end tracing
- **OAuth 2.1 / multi-provider auth**: list form of `auth:` accepts multiple providers; first valid token wins
- **OpenTelemetry tracing**: `telemetry.otlp_endpoint` exports spans per `tools/call`
- **Prompt injection detection**: `block_prompt_injection: true` in `rules` enables 7 built-in patterns
- **`filter_mode: redact`**: scrubs matching values to `[REDACTED]` and forwards the sanitised request instead of blocking
- **Rate-limit response headers**: `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`, and `Retry-After`
- **`/dashboard`** endpoint — HTML audit log viewer with per-agent filtering

---

## [0.5.0] — 2026-03-28

### Added
- **Response filtering** in stdio transport: block patterns now applied to all upstream responses, not just HTTP
- **Configurable circuit breaker**: `circuit_breaker.threshold` and `circuit_breaker.recovery_secs` in `gateway.yml`
- **Key-based agent identity**: `X-Api-Key` header maps directly to an agent (via reverse lookup in `LiveConfig`), overriding `clientInfo.name`
- **Audit log rotation**: `max_entries` and `max_age_days` options for `sqlite` audit backend
- **`/health` endpoint**: returns `{"status":"ok","version":"0.5.0"}`
- **Config validation at startup**: validates regexes, upstream references, TLS file existence, circuit breaker threshold
- **SIGUSR1 hot-reload**: immediate config reload on `SIGUSR1`; 30-second polling as fallback
- **Test coverage**: 42 HTTP integration tests, 16 stdio integration tests

### Changed
- `LiveConfig::new()` now precomputes the `api_key → agent_name` reverse map for O(1) key lookup
- `do_reload()` extracted as a helper to avoid duplication between signal and timer paths

---

## [0.4.0] — 2026-03-27

### Added
- **API key authentication**: `api_key` field per agent in config; middleware returns 401 on mismatch
- **Response filtering**: HTTP responses checked against `block_patterns`; replaced with error on match
- **Config hot-reload**: config file polled every 30 seconds; changes applied without restart via `watch::channel`
- **`FanoutAudit`**: fan-out audit backend that writes to multiple backends simultaneously
- **Circuit breaker** in `HttpUpstream`: opens after N consecutive failures, recovers after timeout
- **Per-tool rate limits**: `tool_rate_limits` map per agent (e.g., `echo: 2` — max 2 calls/min to that tool)
- **SSE proxy**: `GET /mcp` proxies upstream SSE stream with per-event response filtering
- **`DELETE /mcp`**: session invalidation endpoint; returns 204 on success, 404 if not found
- **Prometheus metrics endpoint** (`/metrics`): request counts, blocked counts, latency histograms
- **Named upstreams**: `upstreams:` map in config; agents can route to different upstream servers
- **TLS support**: optional `tls.cert` / `tls.key` in HTTP transport config

---

## [0.3.0] — 2026-03-26

### Added
- **`DELETE /mcp`** session invalidation
- **Webhook audit backend**: POSTs JSON audit entries to a configurable URL with optional Bearer token
- **`FanoutAudit` skeleton**: multiple audit backends wired together
- **Session TTL**: configurable `session_ttl_secs` in HTTP transport

---

## [0.2.0] — 2026-03-25

### Added
- **HTTP transport** (`axum`) with MCP session management (`Mcp-Session-Id` header)
- **SQLite audit log** with async worker task
- **Middleware pipeline**: auth, rate limit, payload filter — composable and ordered
- **`tools/list` filtering**: per-agent `allowed_tools` / `denied_tools` applied to upstream responses
- **Stdio transport**: wraps any MCP server process, intercepts JSON-RPC on stdin/stdout
- **`x-agent-id` fallback** for clients that skip session management

---

## [0.1.0] — 2026-03-24

### Added
- Initial implementation: JSON-RPC 2.0 proxy with basic allow/deny tool filtering
- YAML config (`gateway.yml`) with agents, rules, and transport sections
- Stdout audit backend
- HTTP upstream with `reqwest`
