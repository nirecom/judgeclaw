#!/usr/bin/env bash
# =============================================================================
# Phase 3 Step 1.55 — SSOT whitelist unification tests
# -----------------------------------------------------------------------------
# Purpose:
#   Validate that config/whitelist.txt is the Single Source Of Truth for both
#   openclaw-dns (dnsmasq) and openclaw-sniproxy (nginx stream), and that both
#   entrypoints generate consistent, safe, idempotent runtime configuration
#   from that file.
#
# Branch:
#   feature/phase3-step1_55-shared-whitelist
#
# Related plan:
#   ../ai-specs/projects/engineering/judgeclaw/architecture.md (Phase 3 Step 1.55)
#
# NOTE:
#   The implementation for Step 1.55 does NOT yet exist at the time this test
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
TMP_ROOT="$(mktemp -d)"
WHITELIST_BACKUP=""

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------
cleanup() {
    local ec=$?
    if [[ -n "${WHITELIST_BACKUP}" && -f "${WHITELIST_BACKUP}" ]]; then
        cp -f "${WHITELIST_BACKUP}" config/whitelist.txt 2>/dev/null || true
        rm -f "${WHITELIST_BACKUP}" 2>/dev/null || true
    fi
    if [[ -n "${TMP_ROOT}" && -d "${TMP_ROOT}" ]]; then
        rm -rf "${TMP_ROOT}" 2>/dev/null || true
    fi
    exit "${ec}"
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
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

docker_exec_cat() {
    # Usage: docker_exec_cat <service> <path>
    local svc="$1"
    local path="$2"
    docker compose exec -T "${svc}" cat "${path}"
}

# Convert a Git-Bash / MSYS path to a form Docker Desktop can resolve as a
# file bind mount source. On Git Bash, /tmp/... is a pseudo path that Docker
# Desktop cannot find, causing bind mounts to silently create empty dirs.
# `cygpath -m` maps to a mixed Windows path (forward slashes).
to_docker_path() {
    local p="$1"
    if command -v cygpath >/dev/null 2>&1; then
        cygpath -m "$p"
    else
        printf '%s' "$p"
    fi
}

# Run an image's entrypoint.sh --print-only against a fixture whitelist, using
# `docker run` directly (bypassing docker-compose to avoid the static ipv4
# address conflict when the production container is already running).
run_print_only() {
    # Usage: run_print_only <image> [fixture_path|""]
    local image="$1"
    local fx="${2:-}"
    if [[ -n "${fx}" ]]; then
        local fx_host
        fx_host="$(to_docker_path "$fx")"
        docker run --rm --network none \
            -v "${fx_host}:/etc/whitelist.txt:ro" \
            --entrypoint /entrypoint.sh \
            "${image}" --print-only
    else
        docker run --rm --network none \
            --entrypoint /entrypoint.sh \
            "${image}" --print-only
    fi
}

DNS_IMAGE="judgeclaw-openclaw-dns:latest"
SNI_IMAGE="judgeclaw-openclaw-sniproxy:latest"

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

# ---------------------------------------------------------------------------
# Test functions
# ---------------------------------------------------------------------------

# T1: whitelist.txt exists with all 4 initial domains
test_T1() {
    if [[ ! -f config/whitelist.txt ]]; then
        echo "config/whitelist.txt does not exist"
        return 1
    fi
    for d in api.search.brave.com ja.wikipedia.org en.wikipedia.org wttr.in; do
        if ! grep -qE "^[[:space:]]*${d}[[:space:]]*$" config/whitelist.txt; then
            echo "domain missing from whitelist.txt: ${d}"
            return 1
        fi
    done
    return 0
}

# T2: dnsmasq.conf contains forwarders for each whitelisted domain
test_T2() {
    local conf
    conf="$(docker_exec_cat openclaw-dns /etc/dnsmasq.conf)" || {
        echo "failed to read /etc/dnsmasq.conf from openclaw-dns"
        return 1
    }
    for d in api.search.brave.com ja.wikipedia.org en.wikipedia.org wttr.in; do
        assert_contains "${conf}" "server=/${d}/8.8.8.8" "dnsmasq.conf" || return 1
    done
    return 0
}

# T3: nginx.conf in sniproxy has map entries for each domain
test_T3() {
    local conf
    conf="$(docker_exec_cat openclaw-sniproxy /etc/nginx/nginx.conf)" || {
        echo "failed to read /etc/nginx/nginx.conf from openclaw-sniproxy"
        return 1
    }
    for d in api.search.brave.com ja.wikipedia.org en.wikipedia.org wttr.in; do
        assert_contains "${conf}" "${d} ${d}:443;" "nginx.conf" || return 1
    done
    return 0
}

# T4: dns static guards present
test_T4() {
    local conf
    conf="$(docker_exec_cat openclaw-dns /etc/dnsmasq.conf)" || {
        echo "failed to read dnsmasq.conf"
        return 1
    }
    for g in "address=/#/" "server=/openclaw-bridge/127.0.0.11" "no-resolv" "log-queries" "listen-address=172.24.0.253"; do
        assert_contains "${conf}" "${g}" "dnsmasq static guard" || return 1
    done
    return 0
}

# T5: sniproxy static guards present
test_T5() {
    local conf
    conf="$(docker_exec_cat openclaw-sniproxy /etc/nginx/nginx.conf)" || {
        echo "failed to read nginx.conf"
        return 1
    }
    # 'default 127.0.0.1:1;' may have variable whitespace — match with regex
    if ! grep -qE '^[[:space:]]*default[[:space:]]+127\.0\.0\.1:1;[[:space:]]*$' <<< "${conf}"; then
        echo "nginx static guard missing: default 127.0.0.1:1;"
        return 1
    fi
    for g in "listen 443" "ssl_preread on" "proxy_pass \$upstream" "resolver 127.0.0.11"; do
        assert_contains "${conf}" "${g}" "nginx static guard" || return 1
    done
    return 0
}

# T6: nslookup a whitelisted domain returns an answer
test_T6() {
    local out
    if ! out=$(docker compose exec -T openclaw-dns nslookup api.search.brave.com 172.24.0.253 2>&1); then
        echo "nslookup exited non-zero: ${out}"
        return 1
    fi
    if ! grep -q "Address" <<< "${out}"; then
        echo "no Address in nslookup output: ${out}"
        return 1
    fi
    return 0
}

# T7: nslookup a non-whitelisted/nonexistent domain returns NXDOMAIN
test_T7() {
    local bogus="nonexistent-$(date +%s).test"
    local out rc=0
    out=$(docker compose exec -T openclaw-dns nslookup "${bogus}" 172.24.0.253 2>&1) || rc=$?
    if [[ ${rc} -ne 0 ]]; then
        return 0
    fi
    if grep -qiE "NXDOMAIN|can't find|can not find" <<< "${out}"; then
        return 0
    fi
    echo "expected NXDOMAIN for ${bogus}, got: ${out}"
    return 1
}

# T8: HTTPS to a whitelisted domain from openclaw-agent succeeds
test_T8() {
    # wttr.in serves plain-text weather; unlike Wikipedia it does not block the
    # default Node.js User-Agent. ?format=3 returns a one-line response.
    local js='const https=require("https");https.get("https://wttr.in/?format=3",r=>{console.log(r.statusCode);process.exit(r.statusCode>=200&&r.statusCode<400?0:1);}).on("error",e=>{console.error(e.message);process.exit(2);});'
    local out rc=0
    out=$(docker compose exec -T openclaw-agent node -e "${js}" 2>&1) || rc=$?
    if [[ ${rc} -ne 0 ]]; then
        echo "node https to wttr.in failed (rc=${rc}): ${out}"
        return 1
    fi
    return 0
}

# T9: HTTPS to a non-whitelisted domain is blocked
test_T9() {
    local js='const https=require("https");const req=https.get("https://example.com/",r=>{console.log(r.statusCode);process.exit(0);});req.on("error",e=>{console.error(e.message);process.exit(2);});req.setTimeout(5000,()=>{req.destroy(new Error("timeout"));});'
    local out rc=0
    out=$(docker compose exec -T openclaw-agent node -e "${js}" 2>&1) || rc=$?
    if [[ ${rc} -eq 0 ]]; then
        echo "expected failure for example.com (not whitelisted), but succeeded: ${out}"
        return 1
    fi
    return 0
}

# T10: Fixture with mixed comments/blank/trailing-ws/CRLF — 2 real domains
test_T10() {
    local fx="${TMP_ROOT}/t10-whitelist.txt"
    {
        printf '# leading comment\r\n'
        printf '\r\n'
        printf 'example.org   \r\n'
        printf '# another comment\r\n'
        printf '   \r\n'
        printf 'example.net\r\n'
    } > "${fx}"

    local dns_out sni_out
    if ! dns_out=$(run_print_only "${DNS_IMAGE}" "${fx}" 2>&1); then
        echo "dns --print-only failed: ${dns_out}"
        return 1
    fi
    local count
    count=$(grep -cE '^server=/(example\.org|example\.net)/8\.8\.8\.8$' <<< "${dns_out}" || true)
    if [[ "${count}" != "2" ]]; then
        echo "expected 2 external server= lines, got ${count}"
        return 1
    fi
    if grep -q 'leading comment\|another comment' <<< "${dns_out}"; then
        echo "whitelist comment text leaked into dns output"
        return 1
    fi
    if [[ $(grep -Pc '\r' <<< "${dns_out}" || true) -ne 0 ]]; then
        echo "CRLF leaked into dns output"
        return 1
    fi

    if ! sni_out=$(run_print_only "${SNI_IMAGE}" "${fx}" 2>&1); then
        echo "sniproxy --print-only failed: ${sni_out}"
        return 1
    fi
    local scount
    scount=$(grep -cE '^[[:space:]]*(example\.org|example\.net) (example\.org|example\.net):443;$' <<< "${sni_out}" || true)
    if [[ "${scount}" != "2" ]]; then
        echo "expected 2 sniproxy map entries, got ${scount}"
        return 1
    fi
    if grep -q 'leading comment\|another comment' <<< "${sni_out}"; then
        echo "comment text leaked into sniproxy output"
        return 1
    fi
    if [[ $(grep -Pc '\r' <<< "${sni_out}" || true) -ne 0 ]]; then
        echo "CRLF leaked into sniproxy output"
        return 1
    fi
    return 0
}

# T11: Fixture with only comments/blanks — zero effective entries
test_T11() {
    local fx="${TMP_ROOT}/t11-whitelist.txt"
    {
        echo "# only comments"
        echo ""
        echo "   "
        echo "# more"
    } > "${fx}"

    local dns_out sni_out
    if ! dns_out=$(run_print_only "${DNS_IMAGE}" "${fx}" 2>&1); then
        echo "dns --print-only failed: ${dns_out}"
        return 1
    fi
    # Count ONLY external forwarders (8.8.8.8), not internal openclaw-* (127.0.0.11)
    local ecount
    ecount=$(grep -cE '^server=/[^/]+/8\.8\.8\.8$' <<< "${dns_out}" || true)
    if [[ "${ecount}" != "0" ]]; then
        echo "expected 0 external dns entries, got ${ecount}"
        return 1
    fi

    if ! sni_out=$(run_print_only "${SNI_IMAGE}" "${fx}" 2>&1); then
        echo "sniproxy --print-only failed: ${sni_out}"
        return 1
    fi
    local mcount
    mcount=$(grep -cE '^[[:space:]]*[a-zA-Z0-9.-]+ [a-zA-Z0-9.-]+:443;$' <<< "${sni_out}" || true)
    if [[ "${mcount}" != "0" ]]; then
        echo "expected 0 sniproxy map entries, got ${mcount}"
        return 1
    fi
    if ! grep -qE '^[[:space:]]*default[[:space:]]+127\.0\.0\.1:1;[[:space:]]*$' <<< "${sni_out}"; then
        echo "missing black hole default in sniproxy output"
        return 1
    fi
    return 0
}

# T12: Fixture with single domain
test_T12() {
    local fx="${TMP_ROOT}/t12-whitelist.txt"
    echo "example.org" > "${fx}"

    local dns_out sni_out
    if ! dns_out=$(run_print_only "${DNS_IMAGE}" "${fx}" 2>&1); then
        echo "dns --print-only failed: ${dns_out}"
        return 1
    fi
    local ec
    ec=$(grep -cE '^server=/example\.org/8\.8\.8\.8$' <<< "${dns_out}" || true)
    if [[ "${ec}" != "1" ]]; then
        echo "expected exactly 1 dns entry for example.org, got ${ec}"
        return 1
    fi

    if ! sni_out=$(run_print_only "${SNI_IMAGE}" "${fx}" 2>&1); then
        echo "sniproxy --print-only failed: ${sni_out}"
        return 1
    fi
    local sc
    sc=$(grep -cE '^[[:space:]]*example\.org example\.org:443;$' <<< "${sni_out}" || true)
    if [[ "${sc}" != "1" ]]; then
        echo "expected exactly 1 sniproxy map entry, got ${sc}"
        return 1
    fi
    return 0
}

# T13: Missing whitelist file → non-zero exit for both services
test_T13() {
    local rc=0
    run_print_only "${DNS_IMAGE}" "" >/dev/null 2>&1 || rc=$?
    if [[ ${rc} -eq 0 ]]; then
        echo "dns --print-only unexpectedly succeeded without whitelist"
        return 1
    fi
    rc=0
    run_print_only "${SNI_IMAGE}" "" >/dev/null 2>&1 || rc=$?
    if [[ ${rc} -eq 0 ]]; then
        echo "sniproxy --print-only unexpectedly succeeded without whitelist"
        return 1
    fi
    return 0
}

# T14: Binary/NULL byte fixture → safe handling
test_T14() {
    local fx="${TMP_ROOT}/t14-whitelist.txt"
    printf 'example.org\x00\x01\x02binary\xffdata\n' > "${fx}"

    local rc=0 out
    out=$(run_print_only "${DNS_IMAGE}" "${fx}" 2>&1) || rc=$?
    if [[ ${rc} -ne 0 ]]; then
        return 0
    fi
    local bad
    bad=$(grep -cE '^server=/[^/]*[^a-zA-Z0-9.-][^/]*/8\.8\.8\.8$' <<< "${out}" || true)
    if [[ "${bad}" != "0" ]]; then
        echo "binary bytes leaked into dns output"
        return 1
    fi
    return 0
}

# T15: Restart preserves generated config md5
test_T15() {
    local md5_dns_before md5_sni_before md5_dns_after md5_sni_after
    md5_dns_before=$(docker compose exec -T openclaw-dns md5sum /etc/dnsmasq.conf 2>&1) || {
        echo "failed to md5sum dnsmasq.conf: ${md5_dns_before}"
        return 1
    }
    md5_sni_before=$(docker compose exec -T openclaw-sniproxy md5sum /etc/nginx/nginx.conf 2>&1) || {
        echo "failed to md5sum nginx.conf: ${md5_sni_before}"
        return 1
    }

    docker compose restart openclaw-dns openclaw-sniproxy >/dev/null 2>&1 || {
        echo "restart failed"
        return 1
    }

    local i=0
    while [[ $i -lt 10 ]]; do
        if docker compose exec -T openclaw-dns true >/dev/null 2>&1 && \
           docker compose exec -T openclaw-sniproxy true >/dev/null 2>&1; then
            break
        fi
        sleep 1
        i=$((i + 1))
    done

    md5_dns_after=$(docker compose exec -T openclaw-dns md5sum /etc/dnsmasq.conf 2>&1) || {
        echo "failed to md5sum dnsmasq.conf after restart"
        return 1
    }
    md5_sni_after=$(docker compose exec -T openclaw-sniproxy md5sum /etc/nginx/nginx.conf 2>&1) || {
        echo "failed to md5sum nginx.conf after restart"
        return 1
    }

    if [[ "${md5_dns_before%% *}" != "${md5_dns_after%% *}" ]]; then
        echo "dnsmasq.conf md5 changed across restart"
        return 1
    fi
    if [[ "${md5_sni_before%% *}" != "${md5_sni_after%% *}" ]]; then
        echo "nginx.conf md5 changed across restart"
        return 1
    fi
    return 0
}

# T16: Rebuild idempotency
test_T16() {
    local md5_dns_before md5_sni_before
    md5_dns_before=$(docker compose exec -T openclaw-dns md5sum /etc/dnsmasq.conf 2>&1 | awk '{print $1}') || {
        echo "failed baseline md5"
        return 1
    }
    md5_sni_before=$(docker compose exec -T openclaw-sniproxy md5sum /etc/nginx/nginx.conf 2>&1 | awk '{print $1}') || {
        echo "failed baseline md5"
        return 1
    }

    docker compose up -d --build openclaw-dns openclaw-sniproxy >/dev/null 2>&1 || {
        echo "first build failed"
        return 1
    }
    docker compose up -d --build openclaw-dns openclaw-sniproxy >/dev/null 2>&1 || {
        echo "second build failed"
        return 1
    }

    local i=0
    while [[ $i -lt 10 ]]; do
        if docker compose exec -T openclaw-dns true >/dev/null 2>&1 && \
           docker compose exec -T openclaw-sniproxy true >/dev/null 2>&1; then
            break
        fi
        sleep 1
        i=$((i + 1))
    done

    local md5_dns_after md5_sni_after
    md5_dns_after=$(docker compose exec -T openclaw-dns md5sum /etc/dnsmasq.conf 2>&1 | awk '{print $1}')
    md5_sni_after=$(docker compose exec -T openclaw-sniproxy md5sum /etc/nginx/nginx.conf 2>&1 | awk '{print $1}')

    if [[ "${md5_dns_before}" != "${md5_dns_after}" ]]; then
        echo "dns md5 differs after rebuild: ${md5_dns_before} vs ${md5_dns_after}"
        return 1
    fi
    if [[ "${md5_sni_before}" != "${md5_sni_after}" ]]; then
        echo "sni md5 differs after rebuild"
        return 1
    fi
    return 0
}

# T17: Trailing blank line in whitelist.txt doesn't affect output md5
test_T17() {
    if [[ ! -f config/whitelist.txt ]]; then
        echo "config/whitelist.txt missing — cannot run T17"
        return 1
    fi

    local md5_dns_before md5_sni_before
    md5_dns_before=$(docker compose exec -T openclaw-dns md5sum /etc/dnsmasq.conf 2>&1 | awk '{print $1}')
    md5_sni_before=$(docker compose exec -T openclaw-sniproxy md5sum /etc/nginx/nginx.conf 2>&1 | awk '{print $1}')

    WHITELIST_BACKUP="${TMP_ROOT}/whitelist.bak"
    cp -f config/whitelist.txt "${WHITELIST_BACKUP}"

    printf '\n' >> config/whitelist.txt

    docker compose restart openclaw-dns openclaw-sniproxy >/dev/null 2>&1 || {
        echo "restart failed"
        cp -f "${WHITELIST_BACKUP}" config/whitelist.txt
        return 1
    }

    local i=0
    while [[ $i -lt 10 ]]; do
        if docker compose exec -T openclaw-dns true >/dev/null 2>&1 && \
           docker compose exec -T openclaw-sniproxy true >/dev/null 2>&1; then
            break
        fi
        sleep 1
        i=$((i + 1))
    done

    local md5_dns_after md5_sni_after
    md5_dns_after=$(docker compose exec -T openclaw-dns md5sum /etc/dnsmasq.conf 2>&1 | awk '{print $1}')
    md5_sni_after=$(docker compose exec -T openclaw-sniproxy md5sum /etc/nginx/nginx.conf 2>&1 | awk '{print $1}')

    cp -f "${WHITELIST_BACKUP}" config/whitelist.txt
    rm -f "${WHITELIST_BACKUP}"
    WHITELIST_BACKUP=""

    if [[ "${md5_dns_before}" != "${md5_dns_after}" ]]; then
        echo "dns md5 changed due to trailing blank line"
        return 1
    fi
    if [[ "${md5_sni_before}" != "${md5_sni_after}" ]]; then
        echo "sni md5 changed due to trailing blank line"
        return 1
    fi
    return 0
}

# ---------------------------------------------------------------------------
# Run tests
# ---------------------------------------------------------------------------
echo "=== Phase 3 Step 1.55 — SSOT whitelist unification tests ==="
if [[ ! -f config/whitelist.txt ]]; then
    echo "[WARN] config/whitelist.txt not present — Step 1.55 implementation likely missing."
    echo "[WARN] T1 will fail as the canary; docker-dependent tests may error out."
fi

run_test "T1  whitelist.txt exists with 4 initial domains"           test_T1
run_test "T2  dnsmasq.conf has server= entries for each domain"      test_T2
run_test "T3  nginx.conf has map entries for each domain"            test_T3
run_test "T4  dns static guards present"                             test_T4
run_test "T5  sniproxy static guards present"                        test_T5
run_test "T6  nslookup whitelisted domain returns answer"            test_T6
run_test "T7  nslookup nonexistent domain returns NXDOMAIN"          test_T7
run_test "T8  agent HTTPS to en.wikipedia.org succeeds"              test_T8
run_test "T9  agent HTTPS to example.com is blocked"                 test_T9
run_test "T10 fixture with comments/blanks/CRLF — 2 effective"       test_T10
run_test "T11 fixture empty (comments only) — 0 effective"           test_T11
run_test "T12 fixture single domain — exactly 1 effective"           test_T12
run_test "T13 missing whitelist → non-zero exit"                     test_T13
run_test "T14 binary/NULL bytes → safe handling"                     test_T14
run_test "T15 restart preserves config md5 (idempotent)"             test_T15
run_test "T16 rebuild twice preserves config md5 (idempotent)"       test_T16
run_test "T17 trailing blank line in whitelist does not affect md5"  test_T17

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
