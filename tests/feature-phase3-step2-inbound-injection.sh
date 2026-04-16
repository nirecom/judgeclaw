#!/usr/bin/env bash
# Broad integration test: inbound injection filter (Phase 3 Step 2)
#
# Requires: docker compose up -d openclaw-bridge (with INBOUND_JUDGE_MODE=signal-only)
# No live Judge LLM needed — signal-hit fixtures are blocked by regex alone.
#
# Usage: bash tests/feature-phase3-step2-inbound-injection.sh

set -euo pipefail

BRIDGE_URL="${BRIDGE_URL:-http://localhost:8080}"
LOG_FILE="${LOG_DIR:-./logs}/judge.log"
FIXTURES_DIR="$(dirname "$0")/fixtures/inbound"
PASS=0
FAIL=0

run_with_timeout() {
    if command -v timeout >/dev/null 2>&1; then
        timeout 180 "$@"
    else
        perl -e 'alarm 180; exec @ARGV' -- "$@"
    fi
}

pass() { echo "PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "FAIL: $1"; FAIL=$((FAIL+1)); }

# ---------------------------------------------------------------------------
# Pre-flight: set signal-only mode and restart bridge
# ---------------------------------------------------------------------------
echo "=== Setting INBOUND_JUDGE_MODE=signal-only and restarting bridge ==="
if command -v docker >/dev/null 2>&1; then
    INBOUND_JUDGE_MODE=signal-only docker compose up -d openclaw-bridge 2>/dev/null || true
    sleep 3
fi

# Wait for bridge health
for i in $(seq 1 10); do
    if curl -sf "${BRIDGE_URL}/health" >/dev/null 2>&1; then
        break
    fi
    sleep 2
done

# ---------------------------------------------------------------------------
# Assertion 1: injection fixture → 403 BLOCK (signal scan)
# ---------------------------------------------------------------------------
echo "=== Test 1: injection_direct_override_en → 403 ==="
INJECTION_BODY=$(python3 -c "
import json, sys
with open('${FIXTURES_DIR}/injection_direct_override_en.json') as f:
    print(json.dumps(json.load(f)))
")

STATUS=$(run_with_timeout curl -s -o /dev/null -w "%{http_code}" \
    -X POST "${BRIDGE_URL}/v1/responses" \
    -H "Content-Type: application/json" \
    -d "${INJECTION_BODY}")

if [ "${STATUS}" = "403" ]; then
    pass "injection fixture returns 403"
else
    fail "injection fixture expected 403, got ${STATUS}"
fi

# ---------------------------------------------------------------------------
# Assertion 2: benign fixture → 200 (forwarded or bridge error, not 403)
# ---------------------------------------------------------------------------
echo "=== Test 2: benign_weather → not 403 ==="
BENIGN_BODY=$(python3 -c "
import json
with open('${FIXTURES_DIR}/benign_weather.json') as f:
    print(json.dumps(json.load(f)))
")

STATUS=$(run_with_timeout curl -s -o /dev/null -w "%{http_code}" \
    -X POST "${BRIDGE_URL}/v1/responses" \
    -H "Content-Type: application/json" \
    -d "${BENIGN_BODY}")

if [ "${STATUS}" != "403" ]; then
    pass "benign fixture not blocked (status=${STATUS})"
else
    fail "benign fixture unexpectedly blocked with 403"
fi

# ---------------------------------------------------------------------------
# Assertion 3: dedup — same benign twice, second entry in log has via=dedup
# ---------------------------------------------------------------------------
echo "=== Test 3: dedup — second identical benign request logs via=dedup ==="
LOG_LINE_BEFORE=$(wc -l < "${LOG_FILE}" 2>/dev/null || echo 0)

run_with_timeout curl -s -o /dev/null \
    -X POST "${BRIDGE_URL}/v1/responses" \
    -H "Content-Type: application/json" \
    -d "${BENIGN_BODY}" || true

run_with_timeout curl -s -o /dev/null \
    -X POST "${BRIDGE_URL}/v1/responses" \
    -H "Content-Type: application/json" \
    -d "${BENIGN_BODY}" || true

sleep 1

if [ -f "${LOG_FILE}" ]; then
    DEDUP_COUNT=$(tail -n +$((LOG_LINE_BEFORE+1)) "${LOG_FILE}" | \
        python3 -c "
import sys, json
count = 0
for line in sys.stdin:
    try:
        e = json.loads(line.strip())
        if e.get('via') == 'dedup' and e.get('direction') == 'inbound':
            count += 1
    except Exception:
        pass
print(count)
")
    if [ "${DEDUP_COUNT}" -ge 1 ]; then
        pass "dedup log entry found (count=${DEDUP_COUNT})"
    else
        fail "no dedup log entry found in judge.log"
    fi
else
    fail "judge.log not found at ${LOG_FILE}"
fi

# ---------------------------------------------------------------------------
# Assertion 4: inbound BLOCK entry in log for injection fixture
# ---------------------------------------------------------------------------
echo "=== Test 4: judge.log contains inbound BLOCK entry ==="
if [ -f "${LOG_FILE}" ]; then
    BLOCK_COUNT=$(python3 -c "
import sys, json
count = 0
with open('${LOG_FILE}') as f:
    for line in f:
        try:
            e = json.loads(line.strip())
            if e.get('direction') == 'inbound' and e.get('action') == 'BLOCK':
                count += 1
        except Exception:
            pass
print(count)
")
    if [ "${BLOCK_COUNT}" -ge 1 ]; then
        pass "inbound BLOCK entry found in judge.log (count=${BLOCK_COUNT})"
    else
        fail "no inbound BLOCK entry found in judge.log"
    fi
else
    fail "judge.log not found at ${LOG_FILE}"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "${FAIL}" -gt 0 ]; then
    exit 1
fi
exit 0
