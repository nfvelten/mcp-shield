#!/usr/bin/env bash
# Integration test: stdio gateway + @modelcontextprotocol/server-filesystem
# Each block sends messages via stdin and captures responses via stdout.

set -euo pipefail
BINARY="./target/debug/mcp-shield"
CONFIG="gateway-stdio.yml"
PASS=0
FAIL=0

run_session() {
  local input="$1"
  "$BINARY" "$CONFIG" <<< "$input" 2>/dev/null
}

check() {
  local label="$1"
  local output="$2"
  local expect="$3"
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
  local label="$1"
  local output="$2"
  local pattern="$3"
  if echo "$output" | grep -q "$pattern"; then
    echo "  FAIL  $label"
    echo "        pattern found (should not be present): $pattern"
    FAIL=$((FAIL + 1))
  else
    echo "  PASS  $label"
    PASS=$((PASS + 1))
  fi
}

# ══ EXISTING SCENARIOS ════════════════════════════════════════════════════════

echo ""
echo "━━━ 1. Handshake + tools/list (cursor sees only read_file and list_directory) ━━━"
OUT=$(run_session "$(printf '%s\n%s\n%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"cursor","version":"1.0.0"}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}')")

check "initialize returns serverInfo"           "$OUT" "serverInfo"
check "tools/list contains read_file"           "$OUT" "read_file"
check_absent "tools/list does not contain write_file" "$OUT" '"write_file"'

echo ""
echo "━━━ 2. read_file allowed (cursor reads hello.txt) ━━━"
OUT=$(run_session "$(printf '%s\n%s\n%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"cursor","version":"1.0.0"}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/mcp-test/hello.txt"}}}')")
check "read_file returns file contents" "$OUT" "conteudo do arquivo"

echo ""
echo "━━━ 3. write_file blocked (cursor does not have it in allowlist) ━━━"
OUT=$(run_session "$(printf '%s\n%s\n%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"cursor","version":"1.0.0"}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"/tmp/mcp-test/pwned.txt","content":"hacked"}}}')")
check "write_file returns block error" "$OUT" "blocked"
check "file was NOT created" "$([ ! -f /tmp/mcp-test/pwned.txt ] && echo 'does not exist')" "does not exist"

echo ""
echo "━━━ 4. Sensitive payload blocked ━━━"
OUT=$(run_session "$(printf '%s\n%s\n%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"cursor","version":"1.0.0"}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/mcp-test/secret=abc"}}}')")
check "sensitive payload blocked" "$OUT" "blocked"

echo ""
echo "━━━ 5. Unknown agent blocked ━━━"
OUT=$(run_session "$(printf '%s\n%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"malicious-agent","version":"1.0.0"}}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/mcp-test/hello.txt"}}}')")
check "unknown agent blocked" "$OUT" "unknown"

echo ""
echo "━━━ 6. claude-code reads file (allowed) ━━━"
OUT=$(run_session "$(printf '%s\n%s\n%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"claude-code","version":"1.0.0"}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/mcp-test/hello.txt"}}}')")
check "claude-code reads file" "$OUT" "conteudo do arquivo"

echo ""
echo "━━━ 7. claude-code tries write_file (explicitly denied) ━━━"
OUT=$(run_session "$(printf '%s\n%s\n%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"claude-code","version":"1.0.0"}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"/tmp/mcp-test/pwned.txt","content":"hacked"}}}')")
check "claude-code write blocked" "$OUT" "blocked"

# ══ NEW SCENARIOS ══════════════════════════════════════════════════════════════

echo ""
echo "━━━ 8. claude-code tools/list — denylist hides write_file and delete_file ━━━"
OUT=$(run_session "$(printf '%s\n%s\n%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"claude-code","version":"1.0.0"}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}')")
check_absent "write_file absent in claude-code tools/list"  "$OUT" '"write_file"'
check_absent "delete_file absent in claude-code tools/list" "$OUT" '"delete_file"'
check        "read_file visible to claude-code"             "$OUT" '"read_file"'

echo ""
echo "━━━ 9. rate limit exhaustion (rate-test: 2/min, 3 calls in same session) ━━━"
# All 3 calls sent in a single session — the gateway process is shared,
# so the sliding-window counter accumulates across all three calls.
OUT=$(run_session "$(printf '%s\n%s\n%s\n%s\n%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"rate-test","version":"1.0.0"}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/mcp-test/hello.txt"}}}' \
  '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/mcp-test/hello.txt"}}}' \
  '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/mcp-test/hello.txt"}}}')")
check        "calls within limit succeed"    "$OUT" "conteudo do arquivo"
check        "third call blocked (rate limit)" "$OUT" "rate limit"

echo ""
echo "━━━ 10. list_directory allowed for claude-code (not in denylist) ━━━"
# Use a subdirectory within the allowed root that has no "secret"-matching filenames.
# (A listing of /tmp/mcp-test contains secrets.txt, which the block_pattern "secret"
#  would filter — that's correct behaviour, not a denylist failure.)
mkdir -p /tmp/mcp-test/safe && echo "hello world" > /tmp/mcp-test/safe/readme.txt
OUT=$(run_session "$(printf '%s\n%s\n%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"claude-code","version":"1.0.0"}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_directory","arguments":{"path":"/tmp/mcp-test/safe"}}}')")
check "list_directory allowed for claude-code" "$OUT" "readme.txt"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Result: $PASS passed | $FAIL failed"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
[ $FAIL -eq 0 ] && exit 0 || exit 1
