# mcp-gateway

A security proxy that sits between AI agents and MCP servers. It enforces per-agent policies before any tool call reaches the upstream server.

```
Agent (Cursor, Claude, etc.)
        │  JSON-RPC
        ▼
  mcp-gateway          ← auth, rate limit, payload filter, audit
        │
        ▼
  MCP Server (filesystem, database, APIs...)
```

## What it does

- **Auth** — each agent gets an explicit allowlist or denylist of tools; optional pre-shared API key or JWT/OIDC
- **tools/list filtering** — agents only see the tools they are allowed to call
- **Rate limiting** — per-agent sliding window (calls/min) + per-tool limits + per-IP limit; standard `X-RateLimit-*` headers on every response
- **Payload filtering** — block requests whose arguments match sensitive patterns (passwords, API keys, tokens)
- **Response filtering** — block upstream responses that contain sensitive patterns before they reach the agent
- **Audit log** — every request recorded; fan-out to multiple backends simultaneously (SQLite, webhook, stdout)
- **Multiple upstreams** — route different agents to different MCP servers
- **Circuit breaker** — upstream failures open the circuit; automatic half-open probe after recovery timeout
- **Config hot-reload** — reload on `SIGUSR1` or automatically every 30 seconds without restart
- **Metrics** — Prometheus-compatible `/metrics` endpoint
- **Dashboard** — `/dashboard` audit viewer with per-agent filtering
- **TLS** — optional HTTPS with certificate and key files
- **SSE streaming** — `GET /mcp` proxies the upstream SSE stream with response filtering
- **Transport agnostic** — works over HTTP+SSE or stdio; same config, same policies

## Installation

```sh
cargo install mcp-gateway
```

Or build from source (requires Rust 1.85+):

```sh
git clone https://github.com/nfvelten/mcp-gateway
cd mcp-gateway
cargo build --release
```

Binaries will be at `target/release/gateway` and `target/release/audit`.

Or download a pre-built binary from the [releases page](https://github.com/nfvelten/mcp-gateway/releases).

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

### `admin_token`

Optional top-level field. When set, `/metrics` and `/dashboard` require an `Authorization: Bearer <token>` header. Without the header the endpoints return `403`.

```yaml
admin_token: "your-admin-secret"
```

### `auth` (JWT / OIDC)

Optional. When set, every `initialize` request must carry a valid JWT in the `Authorization: Bearer` header. The gateway rejects tokens without an `exp` claim.

```yaml
# HMAC (HS256) — shared secret
auth:
  hmac_secret: "your-signing-secret"
  issuer: "https://auth.example.com"      # optional — validated if set
  audience: "mcp-gateway"                 # optional — validated if set

# JWKS (RS256 / OIDC) — public key endpoint
auth:
  jwks_url: "https://auth.example.com/.well-known/jwks.json"
  issuer: "https://auth.example.com"
  audience: "mcp-gateway"
```

`hmac_secret` and `jwks_url` are mutually exclusive. JWKS keys are fetched on startup and cached; the fetch has a 5-second timeout.

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
| `allowed_tools` | Allowlist — only these tools are reachable. Omit to allow all. |
| `denied_tools` | Denylist — these tools are always blocked, even if in the allowlist. |
| `rate_limit` | Max `tools/call` requests per minute. Default: 60. |
| `tool_rate_limits` | Per-tool rate limits (calls/min). Checked in addition to `rate_limit`. |
| `upstream` | Named upstream to use for this agent. Falls back to the default. |
| `api_key` | Pre-shared API key. Agent must send `X-Api-Key: <key>` on `initialize`. Optional. |

Agents not listed in the config are blocked entirely.

Example with api_key and tool_rate_limits:

```yaml
agents:
  cursor:
    allowed_tools: [read_file, write_file, list_directory]
    rate_limit: 60
    tool_rate_limits:
      write_file: 5       # max 5 write_file calls/min, within the global 60/min
      delete_file: 2
    api_key: "sk-cursor-secret"
```

### `rules`

| Field | Description |
|---|---|
| `block_patterns` | List of regex patterns. Any `tools/call` whose arguments **or upstream response** matches is blocked. |
| `ip_rate_limit` | Max `tools/call` requests per minute per client IP. Applied before per-agent limits. Optional. |

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

Webhook config:

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

## Usage

### HTTP mode

Start the gateway:

```sh
./gateway gateway.yml
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
./gateway gateway-stdio.yml
```

This is the mode used when configuring the gateway inside tools like Cursor or Claude Code — the editor talks to the gateway via stdio, and the gateway talks to the real server the same way.

## Metrics

The HTTP gateway exposes a Prometheus-compatible metrics endpoint:

```sh
curl http://localhost:4000/metrics
# With admin_token:
curl http://localhost:4000/metrics -H "Authorization: Bearer admin-secret"
```

```
# HELP mcp_gateway_requests_total Total requests processed by the gateway
# TYPE mcp_gateway_requests_total counter
mcp_gateway_requests_total{agent="cursor",outcome="allowed"} 12
mcp_gateway_requests_total{agent="cursor",outcome="blocked"} 3
mcp_gateway_requests_total{agent="claude-code",outcome="forwarded"} 8
```

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
kill -USR1 $(pidof gateway)
```

No restart required. In-flight requests are not affected.

## Logging

Control log format and level via environment variables:

```sh
# Structured JSON (production / log aggregators)
LOG_FORMAT=json ./gateway gateway.yml

# Adjust log level (default: info)
LOG_LEVEL=debug ./gateway gateway.yml
```

## Audit CLI

Query the audit log without opening SQLite directly:

```sh
# Last 50 entries
./audit gateway-audit.db

# Only blocked requests in the last hour
./audit gateway-audit.db --outcome blocked --since 1h

# All activity from a specific agent
./audit gateway-audit.db --agent cursor

# Increase the row limit
./audit gateway-audit.db --limit 200
```

Output:

```
AGE            AGENT            METHOD             TOOL                   OUTCOME    REASON
──────────────────────────────────────────────────────────────────────────────────────────────
3s ago         cursor           tools/call         write_file             blocked    tool 'write_file' not in allowlist
5s ago         cursor           tools/call         read_file              allowed
7s ago         claude-code      tools/call         write_file             blocked    tool 'write_file' explicitly denied
──────────────────────────────────────────────────────────────────────────────────────────────
Showing 3 of 3 total record(s) — since=1m, outcome=blocked
```

Flags:

| Flag | Description |
|---|---|
| `--agent NAME` | Filter by agent name |
| `--since DURATION` | Relative time window: `30s`, `5m`, `2h`, `7d` |
| `--outcome VALUE` | `allowed`, `blocked`, or `forwarded` |
| `--limit N` | Max rows (default: 50) |

## Architecture

```
            ┌─────────────────────────────────┐
            │           McpGateway            │
            │                                 │
  request ──► Pipeline                        │
            │   1. RateLimitMiddleware        │
            │   2. AuthMiddleware             │
            │   3. PayloadFilterMiddleware    │
            │         │                       │
            │    Allow/Block                  │
            │         │                       │
            │   AuditLog + Metrics            │
            │         │                       │
            │    McpUpstream (per-agent)      │
            └─────────────────────────────────┘
```

Each middleware is a trait object — new checks can be added without touching the gateway core. Transport, upstream, and audit backend are also trait objects, swappable via config.

## Tests

```sh
# Unit tests (85 tests)
cargo test

# HTTP integration tests (35 checks)
bash test-http.sh

# stdio integration tests — requires Node.js
mkdir -p /tmp/mcp-test && echo "hello" > /tmp/mcp-test/hello.txt
cargo build
bash test-stdio.sh
```
