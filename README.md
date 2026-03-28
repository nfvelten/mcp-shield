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
- **Transport agnostic** — works over HTTP+SSE or stdio; same config, same policies

## Installation

Requires Rust 1.85+.

```sh
git clone https://github.com/youruser/mcp-gateway
cd mcp-gateway
cargo build --release
```

Binaries will be at `target/release/gateway` and `target/release/audit`.

## Configuration

The gateway is configured via a YAML file. Pass the path as the first argument, or let it default to `gateway.yml`.

```yaml
transport:
  type: http
  addr: "0.0.0.0:4000"
  upstream: "http://localhost:3000"

audit:
  type: sqlite
  path: "gateway-audit.db"

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
| `upstream` | (HTTP only) upstream MCP server URL |
| `server` | (stdio only) command to spawn the MCP server, as a list |

### `agents`

Each key is an agent name matched against the `clientInfo.name` field in the MCP `initialize` message.

| Field | Description |
|---|---|
| `allowed_tools` | Whitelist — only these tools are reachable. Omit to allow all. |
| `denied_tools` | Blacklist — these tools are always blocked. Applied even when `allowed_tools` is set. |
| `rate_limit` | Max `tools/call` requests per minute. Default: 60. |

Agents not listed in the config are blocked entirely.

### `rules`

| Field | Description |
|---|---|
| `block_patterns` | List of regex patterns. Any `tools/call` whose arguments match one of these is blocked. |

### `audit`

| Value | Description |
|---|---|
| `type: stdout` | Print entries to stdout (default) |
| `type: sqlite` | Persist to a SQLite database at `path` |

## Usage

### HTTP mode

Start the gateway:

```sh
./gateway gateway.yml
```

Agents connect to `http://localhost:4000/mcp`. The gateway forwards allowed requests to the upstream MCP server.

Session management follows the MCP spec: the gateway assigns a `Mcp-Session-Id` on `initialize` and uses it to identify the agent on subsequent requests.

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

This is the mode used when configuring the gateway as an MCP server inside tools like Cursor or Claude Code — the editor talks to the gateway via stdio, and the gateway talks to the real server the same way.

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
            │   AuditLog (SQLite/stdout)      │
            │         │                       │
            │    McpUpstream (HTTP/stdio)     │
            └─────────────────────────────────┘
```

Each middleware is a trait object — new checks can be added without touching the gateway core. Transport and audit backend are also trait objects, swappable via config.

## Integration test

Requires Node.js (for `@modelcontextprotocol/server-filesystem`):

```sh
mkdir -p /tmp/mcp-test && echo "hello" > /tmp/mcp-test/hello.txt
cargo build
bash test-stdio.sh
```

Expected: 10 passed, 0 failed.
