#!/usr/bin/env bash
# =============================================================================
# Phase 3 Step 1.6 — OpenClaw SSRF hostname allowlist patch tests
# -----------------------------------------------------------------------------
# Purpose:
#   Validate that apply-ssrf-patch.sh correctly patches pi-embedded-*.js inside
#   the openclaw-agent container to enforce a hostnameAllowlist policy for
#   fetchWithWebToolsNetworkGuard. Tests cover the patch marker, domain list,
#   structural pattern, idempotency across restarts, error handling when the
#   anchor is missing, missing whitelist file, and negative functional testing
#   with a narrow allowlist override.
#
# Branch:
#   feature/phase3-step1_6-openclaw-ssrf-patch
#
# Related plan:
#   ../ai-specs/projects/engineering/judgeclaw/architecture.md (Phase 3 Step 1.6)
#
# NOTE:
#   The implementation for Step 1.6 does NOT yet exist at the time this test
#   file is authored. This file is written test-first and is only required to
#   pass `bash -n` syntax-check for now. It will be executed end-to-end after
#   the implementation lands.
# =============================================================================

set -euo pipefail

# Prevent MSYS/Git-Bash from translating container paths in docker commands
export MSYS_NO_PATHCONV=1

# ---------------------------------------------------------------------------
# Working directory
# ---------------------------------------------------------------------------
if [[ -d "/c/LLM/judgeclaw" ]]; then
    cd /c/LLM/judgeclaw
elif [[ -d "c:/LLM/judgeclaw" ]]; then
    cd "c:/LLM/judgeclaw"
else
    echo "[ERROR] judgeclaw repo not found at expected path" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Counters / state
# ---------------------------------------------------------------------------
PASS=0
FAIL=0
FAILED_TESTS=()
WHITELIST_BACKUP=""

# ---------------------------------------------------------------------------
# Cleanup — restore whitelist and restart openclaw-agent to normal state
# ---------------------------------------------------------------------------
cleanup() {
    local ec=$?
    if [[ -n "${WHITELIST_BACKUP}" && -f "${WHITELIST_BACKUP}" ]]; then
        cp -f "${WHITELIST_BACKUP}" config/whitelist.txt 2>/dev/null || true
        rm -f "${WHITELIST_BACKUP}" 2>/dev/null || true
    fi
    # Restore normal openclaw-agent (in case override or narrow whitelist was active)
    MSYS_NO_PATHCONV=1 docker compose up -d openclaw-agent >/dev/null 2>&1 || true
    exit "${ec}"
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Convert a Git-Bash / MSYS path to a form Docker Desktop can resolve as a
# file bind mount source.
to_docker_path() {
    local p="$1"
    if command -v cygpath >/dev/null 2>&1; then
        cygpath -m "$p"
    else
        printf '%s' "$p"
    fi
}

run_test() {
    local name="$1"
    local fn="$2"
    local out
    if out=$(set +e; "$fn" 2>&1); then
        echo "[OK]   ${name}"
        PASS=$((PASS + 1))
    else
        echo "[FAIL] ${name}"
        if [[ -n "${out}" ]]; then
            while IFS= read -r line; do
                echo "       ${line}"
            done <<< "${out}"
        fi
        FAIL=$((FAIL + 1))
        FAILED_TESTS+=("${name}")
    fi
}

assert_contains() {
    # Usage: assert_contains <haystack> <needle> [label]
    local haystack="$1"
    local needle="$2"
    local label="${3:-content}"
    if ! grep -qF -- "${needle}" <<< "${haystack}"; then
        echo "assertion failed: ${label} does not contain: ${needle}"
        return 1
    fi
    return 0
}

assert_not_contains() {
    # Usage: assert_not_contains <haystack> <needle> [label]
    local haystack="$1"
    local needle="$2"
    local label="${3:-content}"
    if grep -qF -- "${needle}" <<< "${haystack}"; then
        echo "assertion failed: ${label} unexpectedly contains: ${needle}"
        return 1
    fi
    return 0
}

docker_exec_cat() {
    # Usage: docker_exec_cat <service> <path>
    local svc="$1"
    local path="$2"
    MSYS_NO_PATHCONV=1 docker compose exec -T "${svc}" cat "${path}"
}

# Ensure openclaw-egress is attached to the current agent network namespace.
# When openclaw-agent is recreated, egress loses its network_mode link and must
# also be recreated (not just restarted).
ensure_egress() {
    MSYS_NO_PATHCONV=1 docker compose up -d openclaw-egress >/dev/null 2>&1 || true
}

# Wait for openclaw-agent to become responsive (up to 30s)
wait_for_agent() {
    ensure_egress
    local i=0
    while [[ $i -lt 30 ]]; do
        if MSYS_NO_PATHCONV=1 docker compose exec -T openclaw-agent true >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
        i=$((i + 1))
    done
    echo "openclaw-agent did not become ready within 30s"
    return 1
}

# Read the patched pi-embedded JS content from the container
get_patched_js() {
    MSYS_NO_PATHCONV=1 docker compose exec -T openclaw-agent sh -c 'cat /app/dist/pi-embedded-*.js'
}

# ---------------------------------------------------------------------------
# Test functions
# ---------------------------------------------------------------------------

# T1: docker compose build openclaw-agent exits 0
test_T1() {
    MSYS_NO_PATHCONV=1 docker compose build openclaw-agent >/dev/null 2>&1 || {
        echo "docker compose build openclaw-agent failed"
        return 1
    }
    return 0
}

# T2: Patched file contains exactly 1 SSRF patch marker
test_T2() {
    local count
    # grep -c with glob outputs "filename:N" per file; sum all counts
    count=$(MSYS_NO_PATHCONV=1 docker compose exec -T openclaw-agent sh -c \
        'grep -c OPENCLAW_WEB_FETCH_SSRF_PATCHED /app/dist/pi-embedded-*.js 2>/dev/null | awk -F: "{s+=\$NF} END{print s}"' 2>&1) || true
    count="${count//[$'\t\r\n ']/}"
    if [[ "${count}" != "1" ]]; then
        echo "expected marker count 1, got: ${count}"
        return 1
    fi
    return 0
}

# T3: Patched file contains all 4 domains as JSON strings
test_T3() {
    local js
    js=$(get_patched_js) || {
        echo "failed to read patched JS"
        return 1
    }
    for domain in api.search.brave.com ja.wikipedia.org en.wikipedia.org wttr.in; do
        assert_contains "${js}" "\"${domain}\"" "patched JS domain ${domain}" || return 1
    done
    return 0
}

# T4: Patched file contains the structural pattern policy:{hostnameAllowlist:[
test_T4() {
    local js
    js=$(get_patched_js) || {
        echo "failed to read patched JS"
        return 1
    }
    assert_contains "${js}" "policy:{hostnameAllowlist:[" "structural pattern" || return 1
    return 0
}

# T5: Positive functional — HTTPS GET to wttr.in succeeds (200-399)
test_T5() {
    local node_js='const https=require("https");https.get("https://wttr.in/?format=3",r=>{console.log(r.statusCode);process.exit(r.statusCode>=200&&r.statusCode<400?0:1);}).on("error",e=>{console.error(e.message);process.exit(2);});'
    local out rc=0
    out=$(MSYS_NO_PATHCONV=1 docker compose exec -T openclaw-agent node -e "${node_js}" 2>&1) || rc=$?
    if [[ ${rc} -ne 0 ]]; then
        echo "HTTPS to wttr.in failed (rc=${rc}): ${out}"
        return 1
    fi
    return 0
}

# T6: Idempotency — restart twice, marker count still 1 and all 4 domains present
test_T6() {
    MSYS_NO_PATHCONV=1 docker compose restart openclaw-agent >/dev/null 2>&1 || {
        echo "first restart failed"
        return 1
    }
    wait_for_agent || return 1

    MSYS_NO_PATHCONV=1 docker compose restart openclaw-agent >/dev/null 2>&1 || {
        echo "second restart failed"
        return 1
    }
    wait_for_agent || return 1

    # Check marker count is still 1
    local count
    count=$(MSYS_NO_PATHCONV=1 docker compose exec -T openclaw-agent sh -c \
        'grep -c OPENCLAW_WEB_FETCH_SSRF_PATCHED /app/dist/pi-embedded-*.js 2>/dev/null | awk -F: "{s+=\$NF} END{print s}"' 2>&1) || true
    count="${count//[$'\t\r\n ']/}"
    if [[ "${count}" != "1" ]]; then
        echo "expected marker count 1 after restarts, got: ${count}"
        return 1
    fi

    # Check all 4 domains still present
    local js
    js=$(get_patched_js) || {
        echo "failed to read patched JS after restarts"
        return 1
    }
    for domain in api.search.brave.com ja.wikipedia.org en.wikipedia.org wttr.in; do
        assert_contains "${js}" "\"${domain}\"" "post-restart domain ${domain}" || return 1
    done
    return 0
}

# T7: Narrow whitelist swap — only wttr.in + en.wikipedia.org, then restore
test_T7() {
    if [[ ! -f config/whitelist.txt ]]; then
        echo "config/whitelist.txt missing — cannot run T7"
        return 1
    fi

    # Backup original whitelist
    WHITELIST_BACKUP="$(mktemp)"
    cp -f config/whitelist.txt "${WHITELIST_BACKUP}"

    # Write narrow whitelist (2 domains only)
    cat > config/whitelist.txt <<'NARROW'
# Narrow test whitelist for T7
wttr.in
en.wikipedia.org
NARROW

    MSYS_NO_PATHCONV=1 docker compose restart openclaw-agent >/dev/null 2>&1 || {
        echo "restart with narrow whitelist failed"
        return 1
    }
    wait_for_agent || return 1

    local js
    js=$(get_patched_js) || {
        echo "failed to read patched JS with narrow whitelist"
        return 1
    }
    assert_contains "${js}" "\"wttr.in\"" "narrow: wttr.in" || return 1
    assert_contains "${js}" "\"en.wikipedia.org\"" "narrow: en.wikipedia.org" || return 1
    assert_not_contains "${js}" "\"api.search.brave.com\"" "narrow: api.search.brave.com should be absent" || return 1

    # Restore original whitelist
    cp -f "${WHITELIST_BACKUP}" config/whitelist.txt
    rm -f "${WHITELIST_BACKUP}"
    WHITELIST_BACKUP=""

    MSYS_NO_PATHCONV=1 docker compose restart openclaw-agent >/dev/null 2>&1 || {
        echo "restart after restoring whitelist failed"
        return 1
    }
    wait_for_agent || return 1

    # Verify all 4 domains are back
    js=$(get_patched_js) || {
        echo "failed to read patched JS after whitelist restore"
        return 1
    }
    for domain in api.search.brave.com ja.wikipedia.org en.wikipedia.org wttr.in; do
        assert_contains "${js}" "\"${domain}\"" "restored domain ${domain}" || return 1
    done
    return 0
}

# T8: apply-ssrf-patch.sh against a dummy file with no anchor → non-zero exit
test_T8() {
    local rc=0 out
    out=$(MSYS_NO_PATHCONV=1 docker compose exec -T openclaw-agent sh -c \
        'echo "no anchor" > /tmp/dummy.js && /opt/judgeclaw/apply-ssrf-patch.sh /etc/whitelist.txt /tmp' 2>&1) || rc=$?
    if [[ ${rc} -eq 0 ]]; then
        echo "expected non-zero exit when anchor is missing, but got 0: ${out}"
        return 1
    fi
    return 0
}

# T9: Run image without whitelist mount → non-zero exit
test_T9() {
    local rc=0 out
    out=$(MSYS_NO_PATHCONV=1 docker run --rm --network none \
        --entrypoint /opt/judgeclaw/entrypoint.sh \
        judgeclaw-openclaw-agent:latest \
        node -e "console.log('hi')" 2>&1) || rc=$?
    if [[ ${rc} -eq 0 ]]; then
        echo "expected non-zero exit without whitelist, but got 0: ${out}"
        return 1
    fi
    return 0
}

# T10: Negative functional — override with narrow allowlist via docker-compose override
# Uses its own wait loop to avoid ensure_egress reverting the override via depends_on.
test_T10() {
    # Start with narrow allowlist override (include egress to avoid depends_on revert)
    MSYS_NO_PATHCONV=1 docker compose -f docker-compose.yml -f tests/docker-compose.override.yml \
        up -d openclaw-agent openclaw-egress >/dev/null 2>&1 || {
        echo "failed to start with override"
        return 1
    }
    # Wait for agent without calling ensure_egress (already included above)
    local i=0
    while [[ $i -lt 30 ]]; do
        if MSYS_NO_PATHCONV=1 docker compose exec -T openclaw-agent true >/dev/null 2>&1; then
            break
        fi
        sleep 1
        i=$((i + 1))
    done

    local js
    js=$(get_patched_js) || {
        echo "failed to read patched JS with override"
        return 1
    }
    assert_contains "${js}" "\"wttr.in\"" "override: wttr.in" || return 1
    assert_not_contains "${js}" "\"api.search.brave.com\"" "override: api.search.brave.com should be absent" || return 1

    # Restore normal configuration
    MSYS_NO_PATHCONV=1 docker compose up -d openclaw-agent openclaw-egress >/dev/null 2>&1 || {
        echo "failed to restore normal config"
        return 1
    }
    wait_for_agent || return 1

    # Verify all 4 domains are back
    js=$(get_patched_js) || {
        echo "failed to read patched JS after restoring normal config"
        return 1
    }
    for domain in api.search.brave.com ja.wikipedia.org en.wikipedia.org wttr.in; do
        assert_contains "${js}" "\"${domain}\"" "restored domain ${domain}" || return 1
    done
    return 0
}

# ---------------------------------------------------------------------------
# Run tests
# ---------------------------------------------------------------------------
echo "=== Phase 3 Step 1.6 — OpenClaw SSRF hostname allowlist patch tests ==="
echo "=== 10 tests: 5 normal, 2 edge (idempotency), 2 error, 1 negative ==="
if [[ ! -f config/whitelist.txt ]]; then
    echo "[WARN] config/whitelist.txt not present — Step 1.6 implementation likely missing."
    echo "[WARN] T1 will fail as the canary; docker-dependent tests may error out."
fi
echo ""

run_test "T1  build openclaw-agent exits 0"                              test_T1

# After build, ensure agent is running with the new image + egress is attached
MSYS_NO_PATHCONV=1 docker compose up -d openclaw-agent >/dev/null 2>&1 || true
wait_for_agent || echo "[WARN] agent not ready after T1 build+up"

run_test "T2  patched file has exactly 1 SSRF marker"                    test_T2
run_test "T3  patched file contains all 4 domains as JSON strings"       test_T3
run_test "T4  patched file has policy:{hostnameAllowlist:[ pattern"       test_T4
run_test "T5  HTTPS GET to wttr.in succeeds (positive functional)"       test_T5
run_test "T6  idempotency: restart twice, marker=1, all domains present" test_T6
run_test "T7  narrow whitelist swap: 2 domains only, then restore"       test_T7
run_test "T8  apply-ssrf-patch.sh no anchor → non-zero exit"             test_T8
run_test "T9  run without whitelist mount → non-zero exit"               test_T9
run_test "T10 negative functional: override narrow allowlist (D-1b)"     test_T10

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "=== Summary ==="
echo "Passed: ${PASS}  Failed: ${FAIL}"
if [[ ${FAIL} -gt 0 ]]; then
    echo "Failed tests:"
    for t in "${FAILED_TESTS[@]}"; do
        echo "  - ${t}"
    done
    exit 1
fi
exit 0
