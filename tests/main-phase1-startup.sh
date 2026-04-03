#!/usr/bin/env bash
# Phase 1 startup verification tests for JudgeClaw
# Assumes: docker compose up -d has been run and containers are ready
set -uo pipefail

PASS=0
FAIL=0

check_output() {
  local desc="$1"
  local expected="$2"
  shift 2
  local output
  output=$("$@" 2>&1) || true
  if echo "$output" | grep -q "$expected"; then
    echo "PASS: $desc"
    ((PASS++))
  else
    echo "FAIL: $desc (expected '$expected', got '$output')"
    ((FAIL++))
  fi
}

echo "=== JudgeClaw Phase 1 Startup Tests ==="
echo ""

# Normal: LiteLLM container is healthy
check_output "LiteLLM container is running" \
  "openclaw-litellm" \
  docker ps --filter "name=openclaw-litellm" --filter "status=running" --format "{{.Names}}"

check_output "LiteLLM health endpoint responds healthy" \
  '"status":"healthy"' \
  curl.exe -s http://127.0.0.1:4100/health/readiness

# Normal: Agent container is running
check_output "Agent container is running" \
  "openclaw-agent" \
  docker ps --filter "name=openclaw-agent" --filter "status=running" --format "{{.Names}}"

# Normal: Gateway health
check_output "Gateway health endpoint responds ok" \
  '"ok":true' \
  curl.exe -s http://localhost:18789/health

# Edge: Agent runs as uid 1000
check_output "Agent runs as uid 1000 (node)" \
  "uid=1000(node)" \
  docker exec openclaw-agent id

# Normal: Agent model is litellm/agent-reasoner (not default Claude)
check_output "Agent model set to litellm/agent-reasoner" \
  "agent model: litellm/agent-reasoner" \
  docker logs openclaw-agent --tail 20

# Normal: Gateway binds to 0.0.0.0 (not loopback)
check_output "Gateway binds to 0.0.0.0 (LAN mode)" \
  "listening on ws://0.0.0.0:18789" \
  docker logs openclaw-agent --tail 20

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ] || exit 1
