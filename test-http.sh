#!/usr/bin/env bash
# Integration test: HTTP gateway + dummy MCP server
# Starts both processes, runs curl-based scenarios, then cleans up.

set -euo pipefail

GATEWAY="./target/debug/gateway"
DUMMY="./target/debug/dummy-server"
CONFIG="gateway.yml"
GATEWAY_PORT=4000
DUMMY_PORT=3000
PASS=0
FAIL=0
DUMMY_PID=""
GATEWAY_PID=""

# ── Helpers ───────────────────────────────────────────────────────────────────

cleanup() {
    [ -n "$GATEWAY_PID" ] && kill "$GATEWAY_PID" 2>/dev/null || true
    [ -n "$DUMMY_PID"   ] && kill "$DUMMY_PID"   2>/dev/null || true
}
trap cleanup EXIT

wait_for_port() {
    local port=$1 retries=30
    while ! (echo > /dev/tcp/localhost/"$port") 2>/dev/null; do
        retries=$((retries - 1))
        [ $retries -eq 0 ] && { echo "  ABORT  port $port never opened"; exit 1; }
        sleep 0.2
    done
}

mcp_post() {
    local session="$1"
    local body="$2"
    if [ -n "$session" ]; then
        curl -s -D /tmp/mcp-headers.txt \
            -H "Content-Type: application/json" \
            -H "Mcp-Session-Id: $session" \
            -d "$body" \
            "http://localhost:${GATEWAY_PORT}/mcp"
    else
        curl -s -D /tmp/mcp-headers.txt \
            -H "Content-Type: application/json" \
            -d "$body" \
            "http://localhost:${GATEWAY_PORT}/mcp"
    fi
}

mcp_post_status() {
    local session="$1"
    local body="$2"
    if [ -n "$session" ]; then
        curl -s -o /dev/null -w "%{http_code}" \
            -H "Content-Type: application/json" \
            -H "Mcp-Session-Id: $session" \
            -d "$body" \
            "http://localhost:${GATEWAY_PORT}/mcp"
    else
        curl -s -o /dev/null -w "%{http_code}" \
            -H "Content-Type: application/json" \
            -d "$body" \
            "http://localhost:${GATEWAY_PORT}/mcp"
    fi
}

init_agent() {
    local agent="$1"
    local extra_header="${2:-}"
    local body="{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-03-26\",\"capabilities\":{},\"clientInfo\":{\"name\":\"${agent}\",\"version\":\"1.0.0\"}}}"
    if [ -n "$extra_header" ]; then
        curl -s -D /tmp/mcp-headers.txt \
            -H "Content-Type: application/json" \
            -H "$extra_header" \
            -d "$body" \
            "http://localhost:${GATEWAY_PORT}/mcp"
    else
        curl -s -D /tmp/mcp-headers.txt \
            -H "Content-Type: application/json" \
            -d "$body" \
            "http://localhost:${GATEWAY_PORT}/mcp"
    fi
}

init_agent_status() {
    local agent="$1"
    local extra_header="${2:-}"
    local body="{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-03-26\",\"capabilities\":{},\"clientInfo\":{\"name\":\"${agent}\",\"version\":\"1.0.0\"}}}"
    if [ -n "$extra_header" ]; then
        curl -s -o /dev/null -w "%{http_code}" \
            -H "Content-Type: application/json" \
            -H "$extra_header" \
            -d "$body" \
            "http://localhost:${GATEWAY_PORT}/mcp"
    else
        curl -s -o /dev/null -w "%{http_code}" \
            -H "Content-Type: application/json" \
            -d "$body" \
            "http://localhost:${GATEWAY_PORT}/mcp"
    fi
}

check() {
    local label="$1" output="$2" expect="$3"
    if echo "$output" | grep -q "$expect"; then
        echo "  PASS  $label"
        PASS=$((PASS + 1))
    else
        echo "  FAIL  $label"
        echo "        expected: $expect"
        echo "        got:      $(echo "$output" | tr '\n' ' ' | cut -c1-120)"
        FAIL=$((FAIL + 1))
    fi
}

check_absent() {
    local label="$1" output="$2" pattern="$3"
    if echo "$output" | grep -q "$pattern"; then
        echo "  FAIL  $label (pattern found: $pattern)"
        FAIL=$((FAIL + 1))
    else
        echo "  PASS  $label"
        PASS=$((PASS + 1))
    fi
}

check_status() {
    local label="$1" got="$2" expect="$3"
    if [ "$got" = "$expect" ]; then
        echo "  PASS  $label"
        PASS=$((PASS + 1))
    else
        echo "  FAIL  $label (expected HTTP $expect, got $got)"
        FAIL=$((FAIL + 1))
    fi
}

check_status_any() {
    local label="$1" got="$2"
    shift 2
    for expect in "$@"; do
        if [ "$got" = "$expect" ]; then
            echo "  PASS  $label"
            PASS=$((PASS + 1))
            return
        fi
    done
    echo "  FAIL  $label (expected one of [$*], got $got)"
    FAIL=$((FAIL + 1))
}

# ── Start servers ─────────────────────────────────────────────────────────────

"$DUMMY" > /dev/null 2>&1 &
DUMMY_PID=$!
wait_for_port $DUMMY_PORT

"$GATEWAY" "$CONFIG" > /dev/null 2>&1 &
GATEWAY_PID=$!
wait_for_port $GATEWAY_PORT

# ══ EXISTING SCENARIOS ════════════════════════════════════════════════════════

echo ""
echo "━━━ 1. initialize as cursor → get session ━━━"
OUT=$(mcp_post "" '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"cursor","version":"1.0.0"}}}')
SESSION=$(grep -i "mcp-session-id:" /tmp/mcp-headers.txt | awk '{print $2}' | tr -d '\r\n')
check "initialize returns serverInfo" "$OUT" "serverInfo"
check "session ID assigned"           "$SESSION" "."

echo ""
echo "━━━ 2. notifications/initialized ━━━"
STATUS=$(mcp_post_status "$SESSION" '{"jsonrpc":"2.0","method":"notifications/initialized"}')
check_status "notifications/initialized returns 202" "$STATUS" "202"

echo ""
echo "━━━ 3. tools/list — cursor sees only echo ━━━"
OUT=$(mcp_post "$SESSION" '{"jsonrpc":"2.0","id":2,"method":"tools/list"}')
check        "tools/list contains echo"              "$OUT" '"echo"'
check_absent "tools/list does not expose secret_dump" "$OUT" '"secret_dump"'

echo ""
echo "━━━ 4. echo tool call — allowed ━━━"
OUT=$(mcp_post "$SESSION" '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hello"}}}')
check "echo returns result" "$OUT" "echo: hello"

echo ""
echo "━━━ 5. unknown tool — blocked ━━━"
OUT=$(mcp_post "$SESSION" '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"delete_database","arguments":{}}}')
check "unknown tool blocked" "$OUT" "blocked"

echo ""
echo "━━━ 6. sensitive payload — blocked ━━━"
OUT=$(mcp_post "$SESSION" '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"echo","arguments":{"text":"my secret=abc"}}}')
check "sensitive payload blocked" "$OUT" "blocked"

echo ""
echo "━━━ 7. expired/invalid session → 404 ━━━"
STATUS=$(mcp_post_status "invalid-session-id" '{"jsonrpc":"2.0","id":6,"method":"tools/list"}')
check_status "invalid session returns 404" "$STATUS" "404"

echo ""
echo "━━━ 8. unknown agent — blocked ━━━"
OUT=$(mcp_post "" '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"malicious-agent","version":"1.0.0"}}}')
EVIL_SESSION=$(grep -i "mcp-session-id:" /tmp/mcp-headers.txt | awk '{print $2}' | tr -d '\r\n')
OUT=$(mcp_post "$EVIL_SESSION" '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hello"}}}')
check "unknown agent blocked" "$OUT" "unknown"

echo ""
echo "━━━ 9. /metrics endpoint ━━━"
METRICS=$(curl -s "http://localhost:${GATEWAY_PORT}/metrics")
check "metrics endpoint responds"              "$METRICS" "mcp_gateway_requests_total"
check "metrics tracks allowed requests"        "$METRICS" 'outcome="allowed"'
check "metrics tracks blocked requests"        "$METRICS" 'outcome="blocked"'

# ══ NEW: claude-code denylist ══════════════════════════════════════════════════

echo ""
echo "━━━ 10. claude-code — denylist ━━━"
OUT=$(mcp_post "" '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"claude-code","version":"1.0.0"}}}')
CC_SESSION=$(grep -i "mcp-session-id:" /tmp/mcp-headers.txt | awk '{print $2}' | tr -d '\r\n')
LIST=$(mcp_post "$CC_SESSION" '{"jsonrpc":"2.0","id":2,"method":"tools/list"}')
check_absent "tools/list hides delete_database"   "$LIST" '"delete_database"'
OUT=$(mcp_post "$CC_SESSION" '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"delete_database","arguments":{}}}')
check        "delete_database call blocked"        "$OUT" "blocked"

# ══ NEW: metrics forwarded ════════════════════════════════════════════════════

echo ""
echo "━━━ 11. metrics forwarded counter ━━━"
METRICS=$(curl -s "http://localhost:${GATEWAY_PORT}/metrics")
check "metrics tracks forwarded requests" "$METRICS" 'outcome="forwarded"'

# ══ NEW: api_key auth ════════════════════════════════════════════════════════

echo ""
echo "━━━ 12. api_key auth ━━━"
STATUS=$(init_agent_status "secured-agent")
check_status "initialize without key → 401"       "$STATUS" "401"

STATUS=$(init_agent_status "secured-agent" "X-Api-Key: wrong-key")
check_status "initialize with wrong key → 401"    "$STATUS" "401"

OUT=$(init_agent "secured-agent" "X-Api-Key: test-key-123")
SECURED_SESSION=$(grep -i "mcp-session-id:" /tmp/mcp-headers.txt | awk '{print $2}' | tr -d '\r\n')
check        "initialize with correct key → session" "$OUT" "serverInfo"
check        "secured session assigned"               "$SECURED_SESSION" "."

# ══ NEW: DELETE /mcp session invalidation ════════════════════════════════════

echo ""
echo "━━━ 13. DELETE /mcp — session invalidation ━━━"
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE \
    -H "Mcp-Session-Id: $SECURED_SESSION" \
    "http://localhost:${GATEWAY_PORT}/mcp")
check_status "DELETE valid session → 204"             "$STATUS" "204"

STATUS=$(mcp_post_status "$SECURED_SESSION" '{"jsonrpc":"2.0","id":1,"method":"tools/list"}')
check_status "POST to deleted session → 404"          "$STATUS" "404"

STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE \
    -H "Mcp-Session-Id: $SECURED_SESSION" \
    "http://localhost:${GATEWAY_PORT}/mcp")
check_status "duplicate DELETE → 404"                 "$STATUS" "404"

STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE \
    "http://localhost:${GATEWAY_PORT}/mcp")
check_status "DELETE without session header → 400"    "$STATUS" "400"

# ══ NEW: global rate limit ════════════════════════════════════════════════════

echo ""
echo "━━━ 14. global rate limit (rate-test: 3/min) ━━━"
OUT=$(mcp_post "" '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"rate-test","version":"1.0.0"}}}')
RT_SESSION=$(grep -i "mcp-session-id:" /tmp/mcp-headers.txt | awk '{print $2}' | tr -d '\r\n')
CALL='{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"text":"x"}}}'
mcp_post "$RT_SESSION" "$CALL" > /dev/null  # call 1
mcp_post "$RT_SESSION" "$CALL" > /dev/null  # call 2
mcp_post "$RT_SESSION" "$CALL" > /dev/null  # call 3 — limit reached
OUT=$(mcp_post "$RT_SESSION" "$CALL")        # call 4 — should be blocked
check "4th call blocked by rate limit" "$OUT" "rate limit"

# ══ NEW: per-tool rate limit ══════════════════════════════════════════════════

echo ""
echo "━━━ 15. per-tool rate limit (tool-rate-test: echo 2/min) ━━━"
OUT=$(mcp_post "" '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"tool-rate-test","version":"1.0.0"}}}')
TRT_SESSION=$(grep -i "mcp-session-id:" /tmp/mcp-headers.txt | awk '{print $2}' | tr -d '\r\n')
CALL='{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"text":"x"}}}'
mcp_post "$TRT_SESSION" "$CALL" > /dev/null  # echo call 1
mcp_post "$TRT_SESSION" "$CALL" > /dev/null  # echo call 2 — per-tool limit reached
OUT=$(mcp_post "$TRT_SESSION" "$CALL")        # echo call 3 — should be blocked by tool limit
check "3rd echo blocked by tool rate limit" "$OUT" "rate limit"

# ══ NEW: response filtering ═══════════════════════════════════════════════════

echo ""
echo "━━━ 16. response filtering — upstream leaks private_key ━━━"
OUT=$(mcp_post "" '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"secret-dumper","version":"1.0.0"}}}')
SD_SESSION=$(grep -i "mcp-session-id:" /tmp/mcp-headers.txt | awk '{print $2}' | tr -d '\r\n')
OUT=$(mcp_post "$SD_SESSION" '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"secret_dump","arguments":{}}}')
check        "response redacts private_key"             "$OUT" "REDACTED"
check_absent "raw private_key not forwarded to client"  "$OUT" "AAABBBCCC123"

# ══ NEW: SSE endpoint ═════════════════════════════════════════════════════════

echo ""
echo "━━━ 17. GET /mcp — SSE transport ━━━"
# Without session: should return text/event-stream with endpoint event
SSE_HEADERS=$(curl -s -D - -o /tmp/sse-body.txt --max-time 2 \
    -H "Accept: text/event-stream" \
    "http://localhost:${GATEWAY_PORT}/mcp" 2>/dev/null || true)
SSE_BODY=$(cat /tmp/sse-body.txt 2>/dev/null || true)
check "SSE no-session content-type"  "$SSE_HEADERS" "text/event-stream"
check "SSE no-session endpoint event" "$SSE_BODY"   "endpoint"

# With session: should also return text/event-stream (proxies upstream)
OUT=$(mcp_post "" '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"cursor","version":"1.0.0"}}}')
CURSOR2_SESSION=$(grep -i "mcp-session-id:" /tmp/mcp-headers.txt | awk '{print $2}' | tr -d '\r\n')
SSE_HEADERS=$(curl -s -D - -o /dev/null --max-time 2 \
    -H "Accept: text/event-stream" \
    -H "Mcp-Session-Id: $CURSOR2_SESSION" \
    "http://localhost:${GATEWAY_PORT}/mcp" 2>/dev/null || true)
check "SSE with-session content-type" "$SSE_HEADERS" "text/event-stream"

# ══ NEW: edge cases ════════════════════════════════════════════════════════════

echo ""
echo "━━━ 18. edge cases ━━━"

# Agent name > 128 chars → 400
LONG_NAME=$(printf '%0.s-' {1..130})
STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Content-Type: application/json" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-03-26\",\"capabilities\":{},\"clientInfo\":{\"name\":\"${LONG_NAME}\",\"version\":\"1.0.0\"}}}" \
    "http://localhost:${GATEWAY_PORT}/mcp")
check_status "agent name > 128 chars → 400" "$STATUS" "400"

# Malformed JSON → 4xx (axum rejects before handler)
STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Content-Type: application/json" \
    -d "{not valid json" \
    "http://localhost:${GATEWAY_PORT}/mcp")
check_status_any "malformed JSON → 4xx" "$STATUS" "400" "422"

# ══ NEW: /health endpoint ════════════════════════════════════════════════════

echo ""
echo "━━━ 19. /health endpoint ━━━"
HEALTH=$(curl -s "http://localhost:${GATEWAY_PORT}/health")
HEALTH_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:${GATEWAY_PORT}/health")
check_status "health returns 200"     "$HEALTH_STATUS" "200"
check        "health body status ok"  "$HEALTH" '"ok"'
check        "health body has version" "$HEALTH" "version"

# ══ NEW: key-based identity (key IS the identity, clientInfo.name ignored) ════

echo ""
echo "━━━ 20. key-based identity ━━━"
# Sending correct key with a DIFFERENT claimed name → still resolves to secured-agent
OUT=$(curl -s -D /tmp/mcp-headers.txt \
    -H "Content-Type: application/json" \
    -H "X-Api-Key: test-key-123" \
    -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"i-am-lying","version":"1.0.0"}}}' \
    "http://localhost:${GATEWAY_PORT}/mcp")
KB_SESSION=$(grep -i "mcp-session-id:" /tmp/mcp-headers.txt | awk '{print $2}' | tr -d '\r\n')
check "key overrides claimed name → session created" "$OUT" "serverInfo"
# The identity should be secured-agent (allowed: echo), not "i-am-lying" (unknown → blocked)
OUT=$(mcp_post "$KB_SESSION" '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hi"}}}')
check "session acts as secured-agent (echo allowed)" "$OUT" "echo: hi"

# ══ NEW: hot-reload via SIGUSR1 ════════════════════════════════════════════════

echo ""
echo "━━━ 21. config hot-reload via SIGUSR1 ━━━"
RELOAD_CONFIG=$(mktemp --suffix=.yml)
RELOAD_PORT=4001

# Write initial config with "reload-blocker" as a block pattern
cat > "$RELOAD_CONFIG" <<'YMLEOF'
transport:
  type: http
  addr: "0.0.0.0:4001"
  upstream: "http://localhost:3000/mcp"
audit:
  type: stdout
agents:
  cursor:
    allowed_tools: [echo]
    rate_limit: 100
rules:
  block_patterns:
    - "reload-blocker"
YMLEOF

./target/debug/gateway "$RELOAD_CONFIG" > /dev/null 2>&1 &
RELOAD_PID=$!
wait_for_port $RELOAD_PORT

# Initialize cursor on the reload gateway
curl -s -D /tmp/reload-headers.txt \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"cursor","version":"1.0.0"}}}' \
    "http://localhost:${RELOAD_PORT}/mcp" > /dev/null
RELOAD_SESSION=$(grep -i "mcp-session-id:" /tmp/reload-headers.txt | awk '{print $2}' | tr -d '\r\n')

# Verify the block pattern is active
OUT=$(curl -s -H "Content-Type: application/json" -H "Mcp-Session-Id: $RELOAD_SESSION" \
    -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"text":"reload-blocker"}}}' \
    "http://localhost:${RELOAD_PORT}/mcp")
check "block pattern active before reload" "$OUT" "blocked"

# Remove the block pattern from config
cat > "$RELOAD_CONFIG" <<'YMLEOF'
transport:
  type: http
  addr: "0.0.0.0:4001"
  upstream: "http://localhost:3000/mcp"
audit:
  type: stdout
agents:
  cursor:
    allowed_tools: [echo]
    rate_limit: 100
rules:
  block_patterns: []
YMLEOF

# Re-initialize to get a fresh session (hot-reload keeps existing sessions)
kill -USR1 "$RELOAD_PID"
sleep 0.5  # give reload task time to process the signal

curl -s -D /tmp/reload-headers.txt \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"cursor","version":"1.0.0"}}}' \
    "http://localhost:${RELOAD_PORT}/mcp" > /dev/null
RELOAD_SESSION2=$(grep -i "mcp-session-id:" /tmp/reload-headers.txt | awk '{print $2}' | tr -d '\r\n')

# Verify the block pattern is gone
OUT=$(curl -s -H "Content-Type: application/json" -H "Mcp-Session-Id: $RELOAD_SESSION2" \
    -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"text":"reload-blocker"}}}' \
    "http://localhost:${RELOAD_PORT}/mcp")
check "block pattern removed after reload" "$OUT" "reload-blocker"

kill "$RELOAD_PID" 2>/dev/null || true
RELOAD_PID=""
rm -f "$RELOAD_CONFIG"

# ══ NEW: JWT auth ═════════════════════════════════════════════════════════════

echo ""
echo "━━━ 22. JWT auth ━━━"
# Pre-computed HS256 token: {"sub":"jwt-agent","exp":9999999999}
# Secret: "test-jwt-secret" — matches auth.secret in gateway.yml
JWT_TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJqd3QtYWdlbnQiLCJleHAiOjk5OTk5OTk5OTl9.2BhA_cFyVkszZaPrzdXbUlLRs5tNMXhzyFLA03g5tsE"

JWT_OUT=$(curl -s -D /tmp/jwt-headers.txt -X POST \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $JWT_TOKEN" \
    -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"ignored","version":"1.0.0"}}}' \
    "http://localhost:${GATEWAY_PORT}/mcp")
JWT_SID=$(grep -i "mcp-session-id:" /tmp/jwt-headers.txt | awk '{print $2}' | tr -d '\r\n')

check "JWT initialize → session created"  "$JWT_OUT" "serverInfo"
check_absent "JWT session header present" "$JWT_SID" "^$"

ECHO_OUT=$(curl -s -X POST -H "Content-Type: application/json" -H "Mcp-Session-Id: $JWT_SID" \
    -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"text":"jwt-works"}}}' \
    "http://localhost:${GATEWAY_PORT}/mcp")
check "JWT session can call echo (jwt-agent policy)" "$ECHO_OUT" "jwt-works"

INVALID_OUT=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer invalid.token.here" \
    -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"x","version":"1.0.0"}}}' \
    "http://localhost:${GATEWAY_PORT}/mcp")
check "invalid JWT → 401" "$INVALID_OUT" "401"

# ══ NEW: IP rate limit ════════════════════════════════════════════════════════

echo ""
echo "━━━ 22. IP rate limit ━━━"
# Start a fresh gateway on port 4001 with ip_rate_limit: 3
IP_PORT=4001
IP_CONFIG=$(mktemp /tmp/gateway-ip-XXXXXX.yml)
cat > "$IP_CONFIG" <<'YMLEOF'
transport:
  type: http
  addr: "0.0.0.0:4001"
  upstream: "http://localhost:3000/mcp"
  session_ttl_secs: 3600
agents:
  cursor:
    allowed_tools: [echo]
    rate_limit: 100
rules:
  ip_rate_limit: 3
YMLEOF
./target/debug/gateway "$IP_CONFIG" 2>/dev/null &
IP_GW_PID=$!
wait_for_port $IP_PORT

IP_INIT=$(curl -s -D /tmp/ip-headers.txt -X POST \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"cursor","version":"1.0.0"}}}' \
    "http://localhost:${IP_PORT}/mcp" 2>/dev/null)
IP_SID=$(grep -i "mcp-session-id:" /tmp/ip-headers.txt | awk '{print $2}' | tr -d '\r\n')
CALL='{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hi"}}}'
R1=$(curl -s -X POST -H "Content-Type: application/json" -H "Mcp-Session-Id: $IP_SID" -d "$CALL" "http://localhost:${IP_PORT}/mcp")
R2=$(curl -s -X POST -H "Content-Type: application/json" -H "Mcp-Session-Id: $IP_SID" -d "$CALL" "http://localhost:${IP_PORT}/mcp")
R3=$(curl -s -X POST -H "Content-Type: application/json" -H "Mcp-Session-Id: $IP_SID" -d "$CALL" "http://localhost:${IP_PORT}/mcp")
R4=$(curl -s -X POST -H "Content-Type: application/json" -H "Mcp-Session-Id: $IP_SID" -d "$CALL" "http://localhost:${IP_PORT}/mcp")
check "first 3 calls within IP limit" "$R1$R2$R3" "hi"
check "4th call exceeds IP rate limit" "$R4" "IP rate limit"

kill "$IP_GW_PID" 2>/dev/null || true
rm -f "$IP_CONFIG"

# ══ NEW: circuit breaker (last — kills dummy server) ══════════════════════════

echo ""
echo "━━━ 19. circuit breaker — upstream failure ━━━"
OUT=$(mcp_post "" '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"claude-code","version":"1.0.0"}}}')
CB_SESSION=$(grep -i "mcp-session-id:" /tmp/mcp-headers.txt | awk '{print $2}' | tr -d '\r\n')

# Kill the dummy server
kill "$DUMMY_PID" 2>/dev/null || true
DUMMY_PID=""
sleep 0.3  # let the OS clean up the port

CALL='{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"text":"x"}}}'
OUT1=$(mcp_post "$CB_SESSION" "$CALL")
OUT2=$(mcp_post "$CB_SESSION" "$CALL")
OUT3=$(mcp_post "$CB_SESSION" "$CALL")
OUT4=$(mcp_post "$CB_SESSION" "$CALL")
OUT5=$(mcp_post "$CB_SESSION" "$CALL")
OUT6=$(mcp_post "$CB_SESSION" "$CALL")  # circuit should be open now

check "failure before circuit open returns service unavailable" "$OUT1" "unavailable"
check "circuit opens after threshold — returns circuit open"    "$OUT6" "circuit open"

# ═════════════════════════════════════════════════════════════════════════════

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Result: $PASS passed | $FAIL failed"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
[ $FAIL -eq 0 ] && exit 0 || exit 1
