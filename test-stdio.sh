#!/usr/bin/env bash
# Integration test: stdio gateway + @modelcontextprotocol/server-filesystem
# Each block sends messages via stdin and captures responses via stdout.

set -euo pipefail
BINARY="./target/debug/gateway"
CONFIG="gateway-stdio.yml"
PASS=0
FAIL=0

run_session() {
  local label="$1"
  local input="$2"
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

echo ""
echo "━━━ 1. Handshake + tools/list (cursor sees only read_file and list_directory) ━━━"
OUT=$(run_session "tools/list" "$(printf '%s\n%s\n%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"cursor","version":"1.0.0"}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}')")

check "initialize returns serverInfo"           "$OUT" "serverInfo"
check "tools/list contains read_file"           "$OUT" "read_file"
check_absent "tools/list does not contain write_file" "$OUT" '"write_file"'

echo ""
echo "━━━ 2. read_file allowed (cursor reads hello.txt) ━━━"
OUT=$(run_session "read_file" "$(printf '%s\n%s\n%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"cursor","version":"1.0.0"}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/mcp-test/hello.txt"}}}')")
check "read_file returns file contents" "$OUT" "conteudo do arquivo"

echo ""
echo "━━━ 3. write_file blocked (cursor does not have it in allowlist) ━━━"
OUT=$(run_session "write_file blocked" "$(printf '%s\n%s\n%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"cursor","version":"1.0.0"}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"/tmp/mcp-test/pwned.txt","content":"hacked"}}}')")
check "write_file returns block error" "$OUT" "blocked"
check "file was NOT created" "$([ ! -f /tmp/mcp-test/pwned.txt ] && echo 'does not exist')" "does not exist"

echo ""
echo "━━━ 4. Sensitive payload blocked ━━━"
OUT=$(run_session "sensitive payload" "$(printf '%s\n%s\n%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"cursor","version":"1.0.0"}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/mcp-test/secret=abc"}}}')")
check "sensitive payload blocked" "$OUT" "blocked"

echo ""
echo "━━━ 5. Unknown agent blocked ━━━"
OUT=$(run_session "unknown agent" "$(printf '%s\n%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"malicious-agent","version":"1.0.0"}}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/mcp-test/hello.txt"}}}')")
check "unknown agent blocked" "$OUT" "unknown"

echo ""
echo "━━━ 6. claude-code reads file (allowed) ━━━"
OUT=$(run_session "claude-code read" "$(printf '%s\n%s\n%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"claude-code","version":"1.0.0"}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/mcp-test/hello.txt"}}}')")
check "claude-code reads file" "$OUT" "conteudo do arquivo"

echo ""
echo "━━━ 7. claude-code tries write_file (explicitly denied) ━━━"
OUT=$(run_session "claude-code write blocked" "$(printf '%s\n%s\n%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"claude-code","version":"1.0.0"}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"/tmp/mcp-test/pwned.txt","content":"hacked"}}}')")
check "claude-code write blocked" "$OUT" "blocked"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Result: $PASS passed | $FAIL failed"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
[ $FAIL -eq 0 ] && exit 0 || exit 1
