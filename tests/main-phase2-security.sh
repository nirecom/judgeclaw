#!/usr/bin/env bash
# Phase 2 security verification tests for JudgeClaw
# Assumes: docker compose up -d has been run and all containers are ready
# Matches ops.md checklist items 1-12
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

check_exit_nonzero() {
  local desc="$1"
  shift
  if "$@" >/dev/null 2>&1; then
    echo "FAIL: $desc (command succeeded, expected failure)"
    ((FAIL++))
  else
    echo "PASS: $desc"
    ((PASS++))
  fi
}

echo "=== JudgeClaw Phase 2 Security Tests ==="
echo ""

echo "--- Network Isolation ---"

# 1. Agent cannot reach external IP
check_exit_nonzero "Agent cannot reach 8.8.8.8" \
  docker exec openclaw-agent curl -s --max-time 5 http://8.8.8.8

# 2. Agent cannot reach LiteLLM directly
check_exit_nonzero "Agent cannot reach LiteLLM directly" \
  docker exec openclaw-agent curl -s --max-time 5 http://openclaw-litellm:4000/health/readiness

# 3. Agent can reach Bridge
check_output "Agent can reach Bridge" \
  '"status":"ok"' \
  docker exec openclaw-agent curl -s --max-time 5 http://openclaw-bridge:8080/health

echo ""
echo "--- Containers ---"

# 4. All Phase 2 containers are running
for name in openclaw-ingress openclaw-agent openclaw-bridge openclaw-litellm openclaw-squid openclaw-sandbox; do
  check_output "$name is running" \
    "$name" \
    docker ps --filter "name=$name" --filter "status=running" --format "{{.Names}}"
done

# 5. Agent runs as uid 1000
check_output "Agent runs as uid 1000" \
  "uid=1000(node)" \
  docker exec openclaw-agent id

# 6. Sandbox: read-only rootfs
export MSYS_NO_PATHCONV=1
check_output "Sandbox rootfs is read-only" \
  "Read-only file system" \
  docker exec openclaw-sandbox touch /test.txt

# 7. Sandbox: all capabilities dropped
check_output "Sandbox capabilities are empty" \
  "0000000000000000" \
  docker exec openclaw-sandbox cat /proc/1/status

unset MSYS_NO_PATHCONV

echo ""
echo "--- Services ---"

# 8. Bridge health
check_output "Bridge health responds ok" \
  '"status":"ok"' \
  docker exec openclaw-agent curl -s http://openclaw-bridge:8080/health

# 9. LiteLLM health
check_output "LiteLLM health responds healthy" \
  '"status":"healthy"' \
  curl.exe -s http://127.0.0.1:4100/health/readiness

# 10. LiteLLM has both model routes
check_output "LiteLLM has agent-reasoner model" \
  "agent-reasoner" \
  curl.exe -s http://127.0.0.1:4100/v1/models

check_output "LiteLLM has judge model" \
  '"id":"judge"' \
  curl.exe -s http://127.0.0.1:4100/v1/models

# 11. Gateway accessible via ingress
check_output "Gateway accessible via ingress (nginx)" \
  "200" \
  curl.exe -s -o /dev/null -w "%{http_code}" http://localhost:18789/health

# 12. Squid blocks all outbound (whitelist empty)
check_output "Squid blocks outbound (403)" \
  "HTTP Error 403" \
  docker exec openclaw-bridge python -c "import urllib.request;h=urllib.request.ProxyHandler({'http':'http://openclaw-squid:3128'});o=urllib.request.build_opener(h);o.open('http://example.com',timeout=5)"

echo ""
echo "--- Network Membership ---"

check_output "Internal network: agent + bridge + ingress" \
  "openclaw-agent" \
  docker network inspect judgeclaw_openclaw-internal --format '{{range .Containers}}{{.Name}} {{end}}'

check_output "External network: bridge + litellm + squid + ingress (no agent)" \
  "openclaw-litellm" \
  docker network inspect judgeclaw_openclaw-external --format '{{range .Containers}}{{.Name}} {{end}}'

# Verify agent is NOT on external
external_members=$(docker network inspect judgeclaw_openclaw-external --format '{{range .Containers}}{{.Name}} {{end}}' 2>&1)
if echo "$external_members" | grep -q "openclaw-agent"; then
  echo "FAIL: Agent must NOT be on external network"
  ((FAIL++))
else
  echo "PASS: Agent is not on external network"
  ((PASS++))
fi

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ] || exit 1
