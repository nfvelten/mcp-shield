# arbit

[![crates.io](https://img.shields.io/crates/v/arbit.svg)](https://crates.io/crates/arbit)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/nfvelten/arbit/actions/workflows/ci.yml/badge.svg)](https://github.com/nfvelten/arbit/actions/workflows/ci.yml)

A security proxy that sits between AI agents and MCP servers. It enforces per-agent policies before any tool call reaches the upstream server.

```
Agent (Cursor, Claude, etc.)
        │  JSON-RPC
        ▼
      arbit       ← auth, rate limit, HITL, payload filter, audit
        │
        ▼
  MCP Server (filesystem, database, APIs...)
```

## What it does

- **Auth** — each agent gets an explicit allowlist or denylist of tools; glob wildcards supported (`read_*`, `fs/*`); optional pre-shared API key or JWT/OIDC
- **tools/list filtering** — agents only see the tools they are allowed to call (wildcards respected)
- **Rate limiting** — per-agent sliding window (calls/min) + per-tool limits + per-IP limit; standard `X-RateLimit-*` headers on every response
- **Human-in-the-Loop (HITL)** — tools in `approval_required` suspend execution until an operator approves or rejects via REST API; configurable timeout with auto-rejection
- **Shadow mode** — tools in `shadow_tools` are intercepted and logged, but a mock success response is returned without forwarding to the upstream; useful for dry-running risky operations
- **Payload filtering** — block requests whose arguments match sensitive patterns (passwords, API keys, tokens); encoding-aware: catches Base64, percent-encoded, double-encoded, and Unicode (Bidi/NFC) bypass attempts
- **Response filtering** — block upstream responses that contain sensitive patterns before they reach the agent
- **Schema validation** — `tools/call` arguments validated against the `inputSchema` from `tools/list`; invalid or unexpected fields are rejected before reaching the upstream
- **Supply-chain security** — verify the MCP server binary before spawning it (stdio mode): SHA-256 hash pinning and/or `cosign verify-blob` (Sigstore transparency log); startup aborted on mismatch
- **Audit log** — every request recorded with a unique `X-Request-Id`; fan-out to multiple backends simultaneously (SQLite, webhook, stdout)
- **CloudEvents** — webhook audit backend can emit CNCF CloudEvents 1.0 envelopes (`application/cloudevents+json`), enabling direct ingestion by SIEMs (Splunk, Elastic, Datadog) without custom parsers
- **Tool Federation** — agents with `federate: true` aggregate tools from all named upstreams into a single merged view; colliding names are prefixed with `<upstream>__`; `tools/call` is transparently routed to the correct upstream
- **OpenAI Tools Bridge** — `GET /openai/v1/tools` and `POST /openai/v1/execute` let OpenAI function-calling clients use arbit without refactoring; all requests still pass through the full security pipeline
- **Multiple upstreams** — route different agents to different MCP servers
- **Circuit breaker** — upstream failures open the circuit; automatic half-open probe after recovery timeout
- **Health check** — `GET /health` returns upstream status; `503` when any upstream is degraded
- **Config hot-reload** — reload on `SIGUSR1` or automatically every 30 seconds without restart
- **Helm chart** — production-ready chart at `charts/arbit/`; sidecar pattern via `extraContainers`; optional HPA, PDB, NetworkPolicy, PVC; `gateway.yml` rendered from `values.yaml`; secrets injected via `existingSecret` or `env`
- **Container-ready** — multi-arch Docker image (`linux/amd64` + `linux/arm64`) published to `ghcr.io/nfvelten/arbit` on every release; runs as non-root (uid 10001); `LOG_FORMAT=json` structured logs; `docker-compose.yml` with healthcheck included
- **Graceful shutdown** — SIGTERM and CTRL-C handled in both HTTP and stdio transports; active connections drained, child process closed, all audit backends flushed before exit — safe for Kubernetes `terminationGracePeriodSeconds`
- **Secrets-safe config** — `${VAR}` interpolation in `gateway.yml` resolves env vars at startup; `ARBIT_ADMIN_TOKEN`, `ARBIT_UPSTREAM_URL`, `ARBIT_LISTEN_ADDR` override YAML values directly — compatible with Kubernetes Secrets, Vault Agent, External Secrets Operator, and any secret manager that injects env vars
- **Cost Observability** — per-agent token estimation (4-chars-per-token heuristic); `arbit_tokens_total` Prometheus counter with `agent`/`direction` labels for chargeback dashboards; `input_tokens` stored in the SQLite audit log per request
- **OpenLineage** — `openlineage` audit backend emits `RunEvent` (spec 2-0-2) per `tools/call`; `run.runId` correlates with `X-Request-Id`; enables LGPD/GDPR data lineage tracing ("agent X called tool Y which accessed Z")
- **Metrics** — Prometheus-compatible `/metrics` endpoint
- **Dashboard** — `/dashboard` audit viewer with per-agent filtering
- **TLS** — optional HTTPS with certificate and key files
- **SSE streaming** — `GET /mcp` proxies the upstream SSE stream with response filtering
- **Transport agnostic** — works over HTTP+SSE or stdio; same config, same policies
- **Default policy** — fallback policy for agents not listed in config; avoids hard-blocking unknown agents
- **Per-agent timeout** — configurable upstream timeout per agent overrides the global 30s default

## Installation

Download a pre-built binary for your platform from the [releases page](https://github.com/nfvelten/arbit/releases):

| Platform | Archive |
|---|---|
| Linux x64 (static) | `arbit-vX.Y.Z-x86_64-unknown-linux-musl.tar.gz` |
| Linux ARM64 (static) | `arbit-vX.Y.Z-aarch64-unknown-linux-musl.tar.gz` |
| macOS x64 | `arbit-vX.Y.Z-x86_64-apple-darwin.tar.gz` |
| macOS Apple Silicon | `arbit-vX.Y.Z-aarch64-apple-darwin.tar.gz` |
| Windows x64 | `arbit-vX.Y.Z-x86_64-pc-windows-msvc.zip` |

Or install from crates.io (requires Rust 1.85+):

```sh
cargo install arbit
```

Or build from source:

```sh
git clone https://github.com/nfvelten/arbit
cd arbit
cargo build --release
# binary: target/release/arbit
```

### Docker

```sh
docker-compose up
```

## Configuration

The gateway is configured via a YAML file. Pass the path as the first argument, or let it default to `gateway.yml`.

```yaml
transport:
  type: http
  addr: "0.0.0.0:4000"
  upstream: "http://localhost:3000/mcp"
  session_ttl_secs: 3600   # optional, default: 3600
  # tls:                   # optional — enables HTTPS
  #   cert: "cert.pem"
  #   key:  "key.pem"

admin_token: "admin-secret"   # optional — protects /metrics and /dashboard

audit:
  type: sqlite
  path: "gateway-audit.db"

# Named upstreams — agents can reference these via `upstream:` in their policy.
# upstreams:
#   filesystem: "http://localhost:3001/mcp"
#   database:   "http://localhost:3002/mcp"

agents:
  cursor:
    allowed_tools:
      - read_file
      - list_directory
    rate_limit: 30

  claude-code:
    denied_tools:
      - write_file
      - delete_file
    rate_limit: 60
    # upstream: filesystem   # route this agent to a named upstream

rules:
  block_patterns:
    - "password"
    - "api_key"
    - "secret"
    - "Bearer "
    - "private_key"
  # ip_rate_limit: 100      # optional — max calls/min per client IP
```

### `transport`

| Field | Description |
|---|---|
| `type` | `http` or `stdio` |
| `addr` | (HTTP only) address to listen on |
| `upstream` | (HTTP only) default upstream MCP server URL, including path (e.g. `/mcp`) |
| `session_ttl_secs` | (HTTP only) session lifetime in seconds. Default: `3600` |
| `tls.cert` | (HTTP only) path to PEM certificate file. Enables HTTPS when set. |
| `tls.key` | (HTTP only) path to PEM private key file |
| `server` | (stdio only) command to spawn the MCP server, as a list |
| `verify` | (stdio only) optional binary verification before spawn — see [Supply-chain security](#supply-chain-security) |

### Secrets in config

Credentials should never be stored in plaintext. Two mechanisms are available:

#### `${VAR}` interpolation

Reference any environment variable inside `gateway.yml`:

```yaml
admin_token: "${ARBIT_ADMIN_TOKEN}"

agents:
  cursor:
    api_key: "${CURSOR_API_KEY}"

auth:
  - type: jwt
    secret: "${JWT_SECRET}"
```

If the variable is not set, arbit aborts at startup:

```
config error: env var 'ARBIT_ADMIN_TOKEN' is not set (referenced in gateway.yml)
```

#### `ARBIT_*` env var overrides

Override specific fields without modifying the YAML file — useful when deploying a shared base config with environment-specific secrets:

| Env var | Overrides |
|---------|-----------|
| `ARBIT_ADMIN_TOKEN` | `admin_token` |
| `ARBIT_UPSTREAM_URL` | `transport.upstream` |
| `ARBIT_LISTEN_ADDR` | `transport.addr` |

These work with any secret manager that exposes secrets as env vars: Kubernetes Secrets (`envFrom`), Vault Agent, External Secrets Operator, OpenBao, Infisical, etc.

### `admin_token`

Optional top-level field. When set, `/metrics` and `/dashboard` require an `Authorization: Bearer <token>` header. Without the header the endpoints return `403`.

```yaml
admin_token: "${ARBIT_ADMIN_TOKEN}"   # recommended: inject via env var
```

### `auth` (JWT / OIDC / OAuth 2.1)

Optional. When set, every `initialize` request must carry a valid JWT in the `Authorization: Bearer` header. The gateway rejects tokens without an `exp` claim.

Accepts a single provider or a list — the first to successfully validate the token wins:

```yaml
# HMAC (HS256) — shared secret
auth:
  secret: "your-signing-secret"
  issuer: "https://auth.example.com"   # optional — validated if set
  audience: "arbit"               # optional — validated if set

# JWKS (RS256 / OIDC) — explicit endpoint
auth:
  jwks_url: "https://auth.example.com/.well-known/jwks.json"
  issuer: "https://auth.example.com"
  audience: "arbit"

# Provider presets — OIDC discovery URL resolved automatically
auth:
  provider: google
  audience: "my-oauth-client-id"

# Multiple providers — any valid token is accepted
auth:
  - provider: google
    audience: "my-client-id"
  - provider: github-actions
    audience: "https://github.com/myorg"
  - provider: okta
    issuer: "https://dev-123.okta.com"
    audience: "api://default"
```

| Provider | Issuer (auto-set) | Notes |
|---|---|---|
| `google` | `https://accounts.google.com` | Google Cloud / Firebase ID tokens |
| `github-actions` | `https://token.actions.githubusercontent.com` | GitHub Actions OIDC tokens |
| `auth0` | user-specified `issuer` required | Auth0 tenants |
| `okta` | user-specified `issuer` required | Okta orgs |

JWKS keys are fetched lazily, cached for 5 minutes, and refreshed on expiry. OIDC discovery documents are cached for the process lifetime.

### `upstreams`

Named upstream servers. Agents can route to a specific upstream by setting `upstream: <name>` in their policy. Agents without a named upstream use the default `transport.upstream`.

```yaml
upstreams:
  filesystem: "http://localhost:3001/mcp"
  database:   "http://localhost:3002/mcp"

agents:
  cursor:
    upstream: filesystem
    allowed_tools: [read_file]
  claude-code:
    upstream: database
    denied_tools: [drop_table]
```

### `agents`

Each key is an agent name matched against the `clientInfo.name` field in the MCP `initialize` message.

| Field | Description |
|---|---|
| `allowed_tools` | Allowlist — only these tools are reachable. Omit to allow all. Supports glob wildcards (`read_*`, `*_file`, `fs/*`). |
| `denied_tools` | Denylist — these tools are always blocked, even if in the allowlist. Supports glob wildcards. |
| `rate_limit` | Max `tools/call` requests per minute. Default: 60. |
| `tool_rate_limits` | Per-tool rate limits (calls/min). Checked in addition to `rate_limit`. |
| `upstream` | Named upstream to use for this agent. Falls back to the default. |
| `api_key` | Pre-shared API key. Agent must send `X-Api-Key: <key>` on `initialize`. Optional. |
| `timeout_secs` | Upstream timeout in seconds for this agent. Overrides the default 30s. Optional. |
| `approval_required` | List of tool patterns that require human approval before being forwarded. Supports glob wildcards. |
| `hitl_timeout_secs` | Seconds to wait for a human decision before auto-rejecting. Default: 60. |
| `shadow_tools` | List of tool patterns to intercept in shadow mode — logged but not forwarded to upstream. Supports glob wildcards. |

Agents not listed in the config are blocked entirely unless `default_policy` is set.

### `default_policy`

Optional top-level fallback applied to any agent not listed in `agents`. Useful when you want to allow unknown agents with baseline restrictions rather than hard-blocking them.

```yaml
default_policy:
  denied_tools: [delete_file, drop_table]
  rate_limit: 10
  timeout_secs: 5
```

Example with `api_key`, `tool_rate_limits`, HITL, and shadow mode:

```yaml
agents:
  cursor:
    allowed_tools: [read_file, write_file, list_directory, delete_file]
    rate_limit: 60
    tool_rate_limits:
      write_file: 5       # max 5 write_file calls/min, within the global 60/min
    api_key: "sk-cursor-secret"
    approval_required:
      - delete_file       # human must approve every delete
    shadow_tools:
      - "exec_*"          # intercept all exec_* tools silently
```

### `rules`

| Field | Description |
|---|---|
| `block_patterns` | List of regex patterns applied to `tools/call` arguments and upstream responses. Applied after decoding Base64, percent-encoding, double-encoding, and Unicode normalization — obfuscated payloads are not bypassed. |
| `filter_mode` | `block` (default) or `redact`. In `redact` mode, matching values in arguments are scrubbed to `[REDACTED]` and the sanitised request is forwarded instead of being rejected. Responses are always scrubbed regardless of this setting. |
| `block_prompt_injection` | `true` to enable built-in prompt injection detection (7 patterns). Matched requests are always blocked, even in `redact` mode. Default: `false`. |
| `ip_rate_limit` | Max `tools/call` requests per minute per client IP. Applied before per-agent limits. Optional. |
| `validate_schema` | `true` to enable JSON schema validation of `tools/call` arguments against the `inputSchema` from `tools/list`. Requests with invalid or unexpected fields are blocked. Default: `false`. |

```yaml
rules:
  block_patterns:
    - "password"
    - "api_key"
  filter_mode: redact          # scrub instead of block
  block_prompt_injection: true # detect "ignore previous instructions" etc.
  ip_rate_limit: 100
```

Config changes to `agents` and `rules` are picked up automatically — no restart required.

### `audit` / `audits`

Use `audit:` for a single backend or `audits:` to fan-out to multiple backends simultaneously:

```yaml
# Single backend (backward compatible)
audit:
  type: sqlite
  path: "gateway-audit.db"

# Multiple backends — all receive every event
audits:
  - type: sqlite
    path: "gateway-audit.db"
  - type: webhook
    url: "https://hooks.example.com/mcp"
    token: "secret"
```

| Value | Description |
|---|---|
| `type: stdout` | Print entries to stdout (default) |
| `type: sqlite` | Persist to a SQLite database at `path` |
| `type: webhook` | POST each entry as JSON to `url` |
| `type: openlineage` | POST OpenLineage `RunEvent` to `url` |

#### Webhook — plain JSON

```yaml
audit:
  type: webhook
  url: "https://hooks.example.com/mcp-audit"
  token: "secret"   # optional — sent as Bearer token in Authorization header
```

Payload sent on each request:

```json
{
  "ts": 1711584000,
  "agent_id": "cursor",
  "method": "tools/call",
  "tool": "write_file",
  "outcome": "blocked",
  "reason": "tool 'write_file' not in allowlist"
}
```

#### Webhook — CloudEvents 1.0

Set `cloudevents: true` to emit [CNCF CloudEvents 1.0](https://cloudevents.io/) envelopes. The `Content-Type` header becomes `application/cloudevents+json`, enabling direct ingestion by SIEMs and event brokers without custom parsers.

```yaml
audit:
  type: webhook
  url: "https://hooks.splunk.example.com/mcp"
  token: "splunk-hec-token"
  cloudevents: true
  source: "https://gateway.prod.example.com"  # optional, default: /arbit
```

CloudEvents envelope:

```json
{
  "specversion": "1.0",
  "type": "dev.arbit.audit.blocked",
  "source": "https://gateway.prod.example.com",
  "id": "req-abc-123",
  "time": "2026-03-31T00:54:00Z",
  "datacontenttype": "application/json",
  "data": {
    "agent_id": "cursor",
    "method": "tools/call",
    "tool": "write_file",
    "outcome": "blocked",
    "reason": "tool 'write_file' not in allowlist"
  }
}
```

Event types follow the reverse-DNS convention: `dev.arbit.audit.<outcome>` where outcome is `allowed`, `blocked`, `forwarded`, or `shadowed`.

#### OpenLineage

Emits an OpenLineage `RunEvent` (spec 2-0-2) for every `tools/call`. Enables data lineage tracing for LGPD/GDPR compliance: "agent X called tool Y which accessed Z".

```yaml
audit:
  type: openlineage
  url: "https://api.openlineage.io/api/v1/lineage"
  token: "my-api-key"   # optional — sent as Bearer token
  namespace: "arbit"    # optional — OpenLineage job.namespace, default: "arbit"
```

Or fan-out alongside other backends:

```yaml
audits:
  - type: sqlite
    path: "gateway-audit.db"
  - type: openlineage
    url: "https://marquez.internal/api/v1/lineage"
    namespace: "prod-gateway"
```

Payload sent per `tools/call`:

```json
{
  "eventType": "COMPLETE",
  "eventTime": "2026-03-31T00:54:00Z",
  "run": {
    "runId": "550e8400-e29b-41d4-a716-446655440000",
    "facets": {
      "arbit:execution": { "outcome": "allowed", "agent": "cursor", "input_tokens": 12 },
      "arbit:arguments": { "arguments": { "path": "/etc/hosts" } }
    }
  },
  "job": { "namespace": "arbit", "name": "cursor/read_file", "facets": {} },
  "inputs": [{ "namespace": "cursor", "name": "read_file" }],
  "outputs": [],
  "producer": "https://github.com/nfvelten/arbit",
  "schemaURL": "https://openlineage.io/spec/2-0-2/OpenLineage.json#/definitions/RunEvent"
}
```

`eventType` is `COMPLETE` for allowed/forwarded/shadowed and `FAIL` for blocked. The `run.runId` matches the `X-Request-Id` header so lineage events can be correlated with audit log entries.

## Helm

```sh
# Add the Helm repository
helm repo add arbit https://nfvelten.github.io/arbit
helm repo update

# Install from the repo
helm install arbit arbit/arbit \
  --set env[0].name=ARBIT_UPSTREAM_URL \
  --set env[0].value=http://mcp-server:3000/mcp
```

```sh
# Install with defaults (points upstream to $ARBIT_UPSTREAM_URL) — local chart
helm install arbit ./charts/arbit \
  --set env[0].name=ARBIT_UPSTREAM_URL \
  --set env[0].value=http://mcp-server:3000/mcp

# Install with an existing Kubernetes Secret
helm install arbit ./charts/arbit --set existingSecret=arbit-secrets

# Upgrade
helm upgrade arbit ./charts/arbit -f my-values.yaml
```

```yaml
# my-values.yaml — sidecar example
config:
  gateway: |
    transport:
      type: http
      addr: "0.0.0.0:4000"
      upstream: "${ARBIT_UPSTREAM_URL}"
    agents:
      my-agent:
        allowed_tools: [read_file, list_dir]
        rate_limit: 60
    rules:
      block_prompt_injection: true

existingSecret: arbit-secrets   # must contain ARBIT_UPSTREAM_URL

extraContainers:
  - name: my-agent
    image: my-org/my-agent:latest
    env:
      - name: MCP_GATEWAY_URL
        value: http://localhost:4000/mcp
```

```
┌─────────────────────────────────┐
│  Pod                            │
│  ┌──────────┐  ┌─────────────┐ │
│  │  agent   │→ │    arbit    │ │
│  │(sidecar) │  │  :4000/mcp  │ │
│  └──────────┘  └──────┬──────┘ │
└─────────────────────────│───────┘
                          ↓
                   MCP Server
```

| Key | Default | Description |
|-----|---------|-------------|
| `image.tag` | `""` (appVersion) | Override image tag |
| `existingSecret` | `""` | K8s Secret loaded via `envFrom` |
| `env` | `[]` | Extra env vars injected into arbit |
| `autoscaling.enabled` | `false` | Enable HPA |
| `podDisruptionBudget.enabled` | `false` | Enable PDB |
| `networkPolicy.enabled` | `false` | Restrict ingress to `arbit-client: "true"` pods |
| `persistence.enabled` | `false` | PVC for SQLite audit log |
| `extraContainers` | `[]` | Sidecar containers sharing Pod network |

## Docker

```sh
# Pull the latest image
docker pull ghcr.io/nfvelten/arbit:latest

# Run with your config file
docker run --rm \
  -p 4000:4000 \
  -v $(pwd)/gateway.yml:/app/gateway.yml:ro \
  -e ARBIT_ADMIN_TOKEN=your-secret \
  ghcr.io/nfvelten/arbit:latest

# Or with docker-compose (includes healthcheck and audit log persistence)
docker compose up
```

Available tags: `latest`, `0.14`, `0.14.0`. Multi-arch: `linux/amd64` and `linux/arm64`.

## Usage

### HTTP mode

Start the gateway:

```sh
./arbit gateway.yml
# or explicitly:
./arbit start gateway.yml
```

Agents connect to `http://localhost:4000/mcp`. The gateway forwards allowed requests to the upstream MCP server.

Session management follows the MCP spec: the gateway assigns a `Mcp-Session-Id` on `initialize` and uses it to identify the agent on subsequent requests. Requests with a missing or expired session ID receive `404`.

To explicitly end a session, send `DELETE /mcp` with the session header:

```sh
curl -X DELETE http://localhost:4000/mcp -H "Mcp-Session-Id: <id>"
# 204 No Content on success, 404 if the session is already gone
```

### Rate-limit headers

Every `tools/call` response includes standard rate-limit headers:

```
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 57
X-RateLimit-Reset: 42
```

When the limit is exceeded, the response also includes `Retry-After`:

```
HTTP/1.1 200 OK
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 38
Retry-After: 38
```

`X-RateLimit-Reset` and `Retry-After` are in seconds until the oldest request in the window ages out (≤ 60).

### Human-in-the-Loop (HITL)

Tools listed in `approval_required` are suspended until an operator takes action. The gateway holds the request open and waits up to `hitl_timeout_secs` (default: 60) before auto-rejecting.

List pending approvals:

```sh
curl http://localhost:4000/approvals \
  -H "Authorization: Bearer admin-secret"
```

```json
[
  {
    "id": "appr-abc-123",
    "agent_id": "cursor",
    "tool_name": "delete_file",
    "arguments": {"path": "/data/important.db"},
    "created_at": 1743375600
  }
]
```

Approve or reject:

```sh
# Approve
curl -X POST http://localhost:4000/approvals/appr-abc-123/approve \
  -H "Authorization: Bearer admin-secret"

# Reject with reason
curl -X POST http://localhost:4000/approvals/appr-abc-123/reject \
  -H "Authorization: Bearer admin-secret" \
  -H "Content-Type: application/json" \
  -d '{"reason": "not authorized during off-hours"}'
```

Both endpoints return `204 No Content` on success, `404` if the approval ID is unknown or already resolved.

### Shadow mode

Tools listed in `shadow_tools` are intercepted after all middleware passes. The gateway logs them as `shadowed`, returns a mock success response to the agent, and does **not** forward the call to the upstream server.

This is useful for observing what a new agent would do with dangerous tools before granting real access.

```yaml
agents:
  new-agent:
    shadow_tools:
      - delete_file
      - "exec_*"
```

The agent receives:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "content": [{"type": "text", "text": "[shadow] call intercepted — not forwarded to upstream"}]
  }
}
```

Shadowed calls appear in the audit log with `outcome: shadowed`.

### Supply-chain security

When using stdio transport, verify the MCP server binary before spawning it:

```yaml
transport:
  type: stdio
  server: ["/usr/local/bin/mcp-server", "--data-dir", "/data"]
  verify:
    sha256: "e3b0c44298fc1c149afbf4c8996fb924..."  # hex SHA-256 of the binary
    cosign_bundle: "/etc/mcp/server.bundle"         # cosign bundle produced by `cosign sign-blob`
    cosign_identity: "ci@example.com"               # expected signer identity (keyless)
    cosign_issuer: "https://token.actions.githubusercontent.com"
```

Both `sha256` and `cosign_bundle` are optional and independent — configure one or both. If either check fails, the gateway aborts at startup before spawning the process.

To generate a `sha256` for your binary:

```sh
sha256sum /usr/local/bin/mcp-server
```

To sign a binary with cosign (keyless, via GitHub Actions OIDC):

```sh
cosign sign-blob --bundle server.bundle /usr/local/bin/mcp-server
```

### SSE streaming

Once a session is established, open a server-sent event stream to receive server-pushed notifications:

```sh
curl -N http://localhost:4000/mcp \
  -H "Accept: text/event-stream" \
  -H "Mcp-Session-Id: <id>"
```

The gateway proxies the upstream SSE stream and applies `block_patterns` to each event before forwarding it to the client.

Without a session, `GET /mcp` returns an `endpoint` event (legacy HTTP+SSE transport):

```
event: endpoint
data: /mcp
```

### HTTPS mode

Add `tls` to the transport config:

```yaml
transport:
  type: http
  addr: "0.0.0.0:4443"
  upstream: "http://localhost:3000/mcp"
  tls:
    cert: "cert.pem"
    key:  "key.pem"
```

### stdio mode

The gateway spawns the MCP server as a child process and mediates the stdio pipe:

```yaml
transport:
  type: stdio
  server: ["npx", "-y", "@modelcontextprotocol/server-filesystem", "/data"]
```

```sh
./arbit gateway-stdio.yml
```

This is the mode used when configuring the gateway inside tools like Cursor or Claude Code — the editor talks to the gateway via stdio, and the gateway talks to the real server the same way.

## Config validation

Validate a config file without starting the gateway:

```sh
./arbit validate gateway.yml
```

Checks performed: regex syntax in `block_patterns`, upstream name references, TLS file paths, circuit breaker threshold, and tool name format.

## Metrics

The HTTP gateway exposes a Prometheus-compatible metrics endpoint:

```sh
curl http://localhost:4000/metrics
# With admin_token:
curl http://localhost:4000/metrics -H "Authorization: Bearer admin-secret"
```

```
# HELP arbit_requests_total Total requests processed by the gateway
# TYPE arbit_requests_total counter
arbit_requests_total{agent="cursor",outcome="allowed"} 12
arbit_requests_total{agent="cursor",outcome="blocked"} 3
arbit_requests_total{agent="cursor",outcome="shadowed"} 2
arbit_requests_total{agent="claude-code",outcome="forwarded"} 8

# HELP arbit_tokens_total Estimated token count processed by arbit (4-chars-per-token heuristic)
# TYPE arbit_tokens_total counter
arbit_tokens_total{agent="cursor",direction="input"} 1420
arbit_tokens_total{agent="cursor",direction="output"} 3870
arbit_tokens_total{agent="claude-code",direction="input"} 520
arbit_tokens_total{agent="claude-code",direction="output"} 1340
```

Use `arbit_tokens_total` for per-agent chargeback dashboards in Grafana or Datadog. The `input` direction tracks tokens sent to upstream MCP servers; `output` tracks tokens returned in responses. Both use the 4-chars-per-token heuristic — actual billing by model providers may differ.

## Health check

```sh
curl http://localhost:4000/health
```

```json
{
  "status": "ok",
  "version": "0.7.0",
  "upstreams": {
    "default": true,
    "filesystem": true,
    "database": false
  }
}
```

Returns `200 OK` when all upstreams are healthy, `503 Service Unavailable` when any are degraded (circuit open). The status reflects the circuit breaker state — no extra probing requests are made.

## Dashboard

The HTTP gateway exposes an audit dashboard at `/dashboard`:

```sh
open http://localhost:4000/dashboard
# With admin_token:
curl http://localhost:4000/dashboard -H "Authorization: Bearer admin-secret"
```

Supports filtering by agent via query parameter:

```sh
curl "http://localhost:4000/dashboard?agent=cursor"
```

## Config hot-reload

Agent policies and block patterns reload from disk every 30 seconds automatically, or immediately on `SIGUSR1`:

```sh
kill -USR1 $(pidof arbit)
```

No restart required. In-flight requests are not affected.

## OpenTelemetry

Export traces to any OTLP-compatible backend (Jaeger, Grafana Tempo, Honeycomb, Datadog, etc.):

```yaml
telemetry:
  otlp_endpoint: "http://localhost:4317"   # gRPC OTLP
  service_name: "arbit"               # optional, default: "arbit"
```

Every `tools/call` creates a span with `agent_id`, `method`, and `tool` attributes. Spans are exported in batches; any buffered spans are flushed on shutdown.

```sh
# Quick local test with Jaeger all-in-one
docker run -p 4317:4317 -p 16686:16686 jaegertracing/all-in-one
LOG_LEVEL=debug ./arbit gateway.yml
open http://localhost:16686
```

## Logging

Control log format and level via environment variables:

```sh
# Structured JSON (production / log aggregators)
LOG_FORMAT=json ./arbit gateway.yml

# Adjust log level (default: info)
LOG_LEVEL=debug ./arbit gateway.yml
```

## Audit CLI

Query the audit log without opening SQLite directly:

```sh
# Last 50 entries
./arbit audit gateway-audit.db

# Only blocked requests in the last hour
./arbit audit gateway-audit.db --outcome blocked --since 1h

# All activity from a specific agent
./arbit audit gateway-audit.db --agent cursor

# Increase the row limit
./arbit audit gateway-audit.db --limit 200
```

Output:

```
AGE            AGENT            METHOD             TOOL                   OUTCOME    REASON
──────────────────────────────────────────────────────────────────────────────────────────────
3s ago         cursor           tools/call         write_file             blocked    tool 'write_file' not in allowlist
5s ago         cursor           tools/call         read_file              allowed
7s ago         cursor           tools/call         delete_file            shadowed
9s ago         claude-code      tools/call         write_file             blocked    tool 'write_file' explicitly denied
──────────────────────────────────────────────────────────────────────────────────────────────
Showing 4 of 4 total record(s) — since=1m
```

Flags:

| Flag | Description |
|---|---|
| `--agent NAME` | Filter by agent name |
| `--since DURATION` | Relative time window: `30s`, `5m`, `2h`, `7d` |
| `--outcome VALUE` | `allowed`, `blocked`, `forwarded`, or `shadowed` |
| `--limit N` | Max rows (default: 50) |

## Architecture

```
            ┌──────────────────────────────────────────┐
            │                  Arbit                   │
            │                                          │
  request ──► Pipeline                                 │
            │   1. RateLimitMiddleware                 │
            │   2. AuthMiddleware                      │
            │   3. HitlMiddleware    ← suspend & wait  │
            │   4. SchemaValidationMiddleware          │
            │   5. PayloadFilterMiddleware             │
            │         │                                │
            │    Allow / Block                         │
            │         │                                │
            │   Shadow mode check  ← mock if matched   │
            │         │                                │
            │   AuditLog + Metrics                     │
            │         │                                │
            │    McpUpstream (per-agent)               │
            └──────────────────────────────────────────┘
```

Each middleware is a trait object — new checks can be added without touching the gateway core. Transport, upstream, and audit backend are also trait objects, swappable via config.

Payload filtering is encoding-aware: before applying `block_patterns`, the gateway decodes Base64 (standard and URL-safe), percent-encoding, double-encoding, and Unicode variants (NFC normalization, Bidi-control stripping). This prevents bypass attempts using encoded payloads.

## Tests

```sh
# All tests
cargo test --all-features

# Skip stdio tests (require npx)
cargo test --lib

# Single test file
cargo test --test http_gateway
```

Integration tests are written in Rust under `tests/`. They spin up a real gateway binary and an in-process dummy MCP server on free ports. Stdio tests are marked `#[ignore]` since they require `npx` at runtime.
