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

- **Auth** — each agent gets an explicit allowlist or denylist of tools
- **tools/list filtering** — agents only see the tools they are allowed to call
- **Rate limiting** — per-agent sliding window (calls/min)
- **Payload filtering** — block requests whose arguments match sensitive patterns (passwords, API keys, tokens)
- **Audit log** — every request recorded to SQLite with agent, method, tool, outcome, and reason
- **Multiple upstreams** — route different agents to different MCP servers
- **Metrics** — Prometheus-compatible `/metrics` endpoint
- **TLS** — optional HTTPS with certificate and key files
- **Transport agnostic** — works over HTTP+SSE or stdio; same config, same policies

## Installation

Requires Rust 1.85+.

```sh
git clone https://github.com/nfvelten/mcp-gateway
cd mcp-gateway
cargo build --release
```

Binaries will be at `target/release/gateway` and `target/release/audit`.

Or download a pre-built binary from the [releases page](https://github.com/nfvelten/mcp-gateway/releases).

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
| `upstream` | Named upstream to use for this agent. Falls back to the default. |

Agents not listed in the config are blocked entirely.

### `rules`

| Field | Description |
|---|---|
| `block_patterns` | List of regex patterns. Any `tools/call` whose arguments match is blocked. |

### `audit`

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
```

```
# HELP mcp_gateway_requests_total Total requests processed by the gateway
# TYPE mcp_gateway_requests_total counter
mcp_gateway_requests_total{agent="cursor",outcome="allowed"} 12
mcp_gateway_requests_total{agent="cursor",outcome="blocked"} 3
mcp_gateway_requests_total{agent="claude-code",outcome="forwarded"} 8
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

## Integration tests

Requires Node.js (for `@modelcontextprotocol/server-filesystem`):

```sh
# stdio mode — tests against real filesystem MCP server
mkdir -p /tmp/mcp-test && echo "hello" > /tmp/mcp-test/hello.txt
cargo build
bash test-stdio.sh

# HTTP mode — tests against the built-in dummy server
bash test-http.sh
```

Expected: 10/10 stdio, 13/13 HTTP.
