#!/usr/bin/env bash
# =============================================================================
# main — generate-web-access-section.sh tests
# -----------------------------------------------------------------------------
# Purpose:
#   Validate that generate-web-access-section.sh correctly generates the
#   ## Web Access section of TOOLS.md from whitelist.txt.
#
# Runs entirely on the host (no Docker required).
# Uses OPENCLAW_SSRF_ALLOWLIST_FILE and OPENCLAW_TOOLS_MD env overrides.
# =============================================================================

set -euo pipefail
export MSYS_NO_PATHCONV=1

SCRIPT="$(cd "$(dirname "$0")/.." && pwd)/openclaw-agent/generate-web-access-section.sh"

if [[ ! -x "${SCRIPT}" ]]; then
    echo "[ERROR] script not found or not executable: ${SCRIPT}" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Counters
# ---------------------------------------------------------------------------
PASS=0
FAIL=0
FAILED_TESTS=()
TMP_ROOT="$(mktemp -d)"

cleanup() {
    local ec=$?
    rm -rf "${TMP_ROOT}" 2>/dev/null || true
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

make_whitelist() {
    local path="$1"
    cat > "${path}" <<'EOF'
# judgeclaw whitelist
api.search.brave.com
en.wikipedia.org

# Academic
arxiv.org
EOF
}

make_tools_md() {
    local path="$1"
    cat > "${path}" <<'EOF'
# TOOLS.md

Some existing content.

---
<!-- BEGIN auto-generated: web-access -->
<!-- END auto-generated: web-access -->
---

Add whatever helps you do your job.
EOF
}

run_generate() {
    local whitelist="$1"
    local tools_md="$2"
    OPENCLAW_SSRF_ALLOWLIST_FILE="${whitelist}" \
    OPENCLAW_TOOLS_MD="${tools_md}" \
        sh "${SCRIPT}"
}

# ---------------------------------------------------------------------------
# Normal cases
# ---------------------------------------------------------------------------
test_domains_appear() {
    local wl="${TMP_ROOT}/wl_domains.txt"
    local md="${TMP_ROOT}/tools_domains.md"
    make_whitelist "${wl}"
    make_tools_md "${md}"
    run_generate "${wl}" "${md}"
    local content
    content="$(cat "${md}")"
    grep -qF -- "- api.search.brave.com" <<< "${content}" || { echo "missing api.search.brave.com"; return 1; }
    grep -qF -- "- en.wikipedia.org"     <<< "${content}" || { echo "missing en.wikipedia.org"; return 1; }
    grep -qF -- "- arxiv.org"            <<< "${content}" || { echo "missing arxiv.org"; return 1; }
}

test_comments_excluded() {
    local wl="${TMP_ROOT}/wl_comments.txt"
    local md="${TMP_ROOT}/tools_comments.md"
    make_whitelist "${wl}"
    make_tools_md "${md}"
    run_generate "${wl}" "${md}"
    local content
    content="$(cat "${md}")"
    if grep -qF "# judgeclaw whitelist" <<< "${content}"; then
        echo "comment line leaked into output"; return 1
    fi
    if grep -qF "# Academic" <<< "${content}"; then
        echo "section comment leaked into output"; return 1
    fi
}

test_blank_lines_excluded() {
    local wl="${TMP_ROOT}/wl_blank.txt"
    local md="${TMP_ROOT}/tools_blank.md"
    make_whitelist "${wl}"
    make_tools_md "${md}"
    run_generate "${wl}" "${md}"
    # List items must each start with "- "; no bare blank list item
    if grep -E "^- $" "${md}" > /dev/null 2>&1; then
        echo "blank domain list item found"; return 1
    fi
}

test_markers_present_in_output() {
    local wl="${TMP_ROOT}/wl_markers.txt"
    local md="${TMP_ROOT}/tools_markers.md"
    make_whitelist "${wl}"
    make_tools_md "${md}"
    run_generate "${wl}" "${md}"
    grep -qF "<!-- BEGIN auto-generated: web-access -->" "${md}" || { echo "BEGIN marker missing"; return 1; }
    grep -qF "<!-- END auto-generated: web-access -->"   "${md}" || { echo "END marker missing"; return 1; }
}

test_surrounding_content_preserved() {
    local wl="${TMP_ROOT}/wl_surround.txt"
    local md="${TMP_ROOT}/tools_surround.md"
    make_whitelist "${wl}"
    make_tools_md "${md}"
    run_generate "${wl}" "${md}"
    grep -qF "Some existing content." "${md}" || { echo "existing content lost"; return 1; }
    grep -qF "Add whatever helps you do your job." "${md}" || { echo "trailing content lost"; return 1; }
}

test_crlf_stripped() {
    local wl="${TMP_ROOT}/wl_crlf.txt"
    local md="${TMP_ROOT}/tools_crlf.md"
    printf "api.search.brave.com\r\nen.wikipedia.org\r\n" > "${wl}"
    make_tools_md "${md}"
    run_generate "${wl}" "${md}"
    # Domains should appear without \r
    grep -qF -- "- api.search.brave.com" "${md}" || { echo "CRLF domain not found"; return 1; }
    if grep -P "\r" "${md}" > /dev/null 2>&1; then
        echo "carriage return found in output"; return 1
    fi
}

# ---------------------------------------------------------------------------
# Error cases
# ---------------------------------------------------------------------------
test_unreadable_whitelist_exits_1() {
    local wl="${TMP_ROOT}/wl_missing.txt"
    local md="${TMP_ROOT}/tools_err.md"
    make_tools_md "${md}"
    # wl_missing.txt does not exist → should exit 1
    local rc=0
    OPENCLAW_SSRF_ALLOWLIST_FILE="${wl}" OPENCLAW_TOOLS_MD="${md}" sh "${SCRIPT}" 2>/dev/null || rc=$?
    if [[ "${rc}" -ne 1 ]]; then
        echo "expected exit 1, got ${rc}"; return 1
    fi
}

test_missing_tools_md_exits_0() {
    local wl="${TMP_ROOT}/wl_ok_nomd.txt"
    local md="${TMP_ROOT}/nonexistent_tools.md"
    make_whitelist "${wl}"
    # TOOLS.md does not exist → should exit 0 (warning only, not fatal)
    local rc=0
    OPENCLAW_SSRF_ALLOWLIST_FILE="${wl}" OPENCLAW_TOOLS_MD="${md}" sh "${SCRIPT}" 2>/dev/null || rc=$?
    if [[ "${rc}" -ne 0 ]]; then
        echo "expected exit 0, got ${rc}"; return 1
    fi
}

# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------
test_empty_whitelist_generates_section() {
    local wl="${TMP_ROOT}/wl_empty.txt"
    local md="${TMP_ROOT}/tools_empty.md"
    printf "# only comments\n\n" > "${wl}"
    make_tools_md "${md}"
    run_generate "${wl}" "${md}"
    grep -qF "<!-- BEGIN auto-generated: web-access -->" "${md}" || { echo "BEGIN marker missing"; return 1; }
    grep -qF "<!-- END auto-generated: web-access -->"   "${md}" || { echo "END marker missing"; return 1; }
}

test_append_when_no_markers() {
    local wl="${TMP_ROOT}/wl_append.txt"
    local md="${TMP_ROOT}/tools_nomarkers.md"
    make_whitelist "${wl}"
    printf "# TOOLS.md\n\nExisting content.\n" > "${md}"
    run_generate "${wl}" "${md}"
    grep -qF "<!-- BEGIN auto-generated: web-access -->" "${md}" || { echo "BEGIN marker not appended"; return 1; }
    grep -qF -- "- api.search.brave.com" "${md}" || { echo "domain not appended"; return 1; }
    grep -qF "Existing content." "${md}" || { echo "existing content lost on append"; return 1; }
}

# ---------------------------------------------------------------------------
# Idempotency cases
# ---------------------------------------------------------------------------
test_idempotent_same_result() {
    local wl="${TMP_ROOT}/wl_idempotent.txt"
    local md="${TMP_ROOT}/tools_idempotent.md"
    make_whitelist "${wl}"
    make_tools_md "${md}"
    run_generate "${wl}" "${md}"
    local first
    first="$(cat "${md}")"
    run_generate "${wl}" "${md}"
    local second
    second="$(cat "${md}")"
    if [[ "${first}" != "${second}" ]]; then
        echo "second run produced different output"; return 1
    fi
}

test_idempotent_no_marker_duplication() {
    local wl="${TMP_ROOT}/wl_nodup.txt"
    local md="${TMP_ROOT}/tools_nodup.md"
    make_whitelist "${wl}"
    make_tools_md "${md}"
    run_generate "${wl}" "${md}"
    run_generate "${wl}" "${md}"
    local count
    count="$(grep -c "BEGIN auto-generated: web-access" "${md}")"
    if [[ "${count}" -ne 1 ]]; then
        echo "BEGIN marker duplicated (found ${count} times)"; return 1
    fi
}

# ---------------------------------------------------------------------------
# Normal cases (additional)
# ---------------------------------------------------------------------------
test_header_and_description_present() {
    local wl="${TMP_ROOT}/wl_hdr.txt"
    local md="${TMP_ROOT}/tools_hdr.md"
    make_whitelist "${wl}"
    make_tools_md "${md}"
    run_generate "${wl}" "${md}"
    grep -qF "## Web Access" "${md}" || { echo "## Web Access header missing"; return 1; }
    grep -qF "Only these external domains are reachable" "${md}" || { echo "description text missing"; return 1; }
}

test_single_domain() {
    local wl="${TMP_ROOT}/wl_one.txt"
    local md="${TMP_ROOT}/tools_one.md"
    printf "example.com\n" > "${wl}"
    make_tools_md "${md}"
    run_generate "${wl}" "${md}"
    grep -qF -- "- example.com" "${md}" || { echo "single domain not found"; return 1; }
    local count
    count="$(grep -c "^- " "${md}")"
    if [[ "${count}" -ne 1 ]]; then
        echo "expected 1 domain item, got ${count}"; return 1
    fi
}

test_whitespace_stripped() {
    local wl="${TMP_ROOT}/wl_ws.txt"
    local md="${TMP_ROOT}/tools_ws.md"
    printf "  leading.com  \n\tindented.com\t\n" > "${wl}"
    make_tools_md "${md}"
    run_generate "${wl}" "${md}"
    grep -qF -- "- leading.com" "${md}"   || { echo "leading space not stripped"; return 1; }
    grep -qF -- "- indented.com" "${md}"  || { echo "tab not stripped"; return 1; }
    if grep -E "^- .+ $" "${md}" > /dev/null 2>&1; then
        echo "trailing whitespace found in domain list item"; return 1
    fi
}

# ---------------------------------------------------------------------------
# Error cases (additional)
# ---------------------------------------------------------------------------
test_readonly_tools_md_exits_nonzero() {
    local wl="${TMP_ROOT}/wl_ro.txt"
    local md="${TMP_ROOT}/tools_ro.md"
    make_whitelist "${wl}"
    # No markers → triggers append path (>> md); read-only file blocks write
    printf "# TOOLS.md\n\nSome content.\n" > "${md}"
    chmod 444 "${md}"
    local rc=0
    OPENCLAW_SSRF_ALLOWLIST_FILE="${wl}" OPENCLAW_TOOLS_MD="${md}" sh "${SCRIPT}" 2>/dev/null || rc=$?
    chmod 644 "${md}"
    if [[ "${rc}" -eq 0 ]]; then
        echo "expected non-zero exit for read-only TOOLS.md, got 0"; return 1
    fi
}

# ---------------------------------------------------------------------------
# Idempotency cases (additional)
# ---------------------------------------------------------------------------
test_idempotent_domain_change() {
    local wl="${TMP_ROOT}/wl_chg.txt"
    local md="${TMP_ROOT}/tools_chg.md"
    make_whitelist "${wl}"
    make_tools_md "${md}"
    run_generate "${wl}" "${md}"
    grep -qF -- "- api.search.brave.com" "${md}" || { echo "initial domain missing"; return 1; }
    printf "newdomain.example.com\n" > "${wl}"
    run_generate "${wl}" "${md}"
    grep -qF -- "- newdomain.example.com" "${md}" || { echo "new domain not found after update"; return 1; }
    if grep -qF -- "- api.search.brave.com" "${md}"; then
        echo "old domain still present after whitelist change"; return 1
    fi
}

test_append_to_replace_transition() {
    local wl="${TMP_ROOT}/wl_tr.txt"
    local md="${TMP_ROOT}/tools_tr.md"
    make_whitelist "${wl}"
    printf "# TOOLS.md\n\nExisting content.\n" > "${md}"
    run_generate "${wl}" "${md}"
    grep -qF "<!-- BEGIN auto-generated: web-access -->" "${md}" || { echo "BEGIN not appended on first run"; return 1; }
    run_generate "${wl}" "${md}"
    local count
    count="$(grep -c "BEGIN auto-generated: web-access" "${md}")"
    if [[ "${count}" -ne 1 ]]; then
        echo "markers duplicated on append→replace transition (found ${count})"; return 1
    fi
    grep -qF "Existing content." "${md}" || { echo "existing content lost on replace"; return 1; }
}

# ---------------------------------------------------------------------------
# Run all tests
# ---------------------------------------------------------------------------
run_test "normal: whitelisted domains appear as list items"       test_domains_appear
run_test "normal: comment lines excluded from domain list"        test_comments_excluded
run_test "normal: blank lines excluded from domain list"          test_blank_lines_excluded
run_test "normal: BEGIN/END markers present in output"            test_markers_present_in_output
run_test "normal: content outside markers is preserved"           test_surrounding_content_preserved
run_test "normal: CRLF line endings stripped from domains"        test_crlf_stripped
run_test "error:  unreadable whitelist exits 1"                   test_unreadable_whitelist_exits_1
run_test "error:  missing TOOLS.md exits 0 (non-fatal)"          test_missing_tools_md_exits_0
run_test "edge:   empty whitelist still generates section"        test_empty_whitelist_generates_section
run_test "edge:   appends markers when not yet present"           test_append_when_no_markers
run_test "idempotency: running twice produces identical output"   test_idempotent_same_result
run_test "idempotency: markers not duplicated on second run"      test_idempotent_no_marker_duplication
run_test "normal: ## Web Access header and description present"   test_header_and_description_present
run_test "normal: single domain renders correctly"                test_single_domain
run_test "normal: leading/trailing whitespace stripped"           test_whitespace_stripped
run_test "error:  read-only TOOLS.md exits non-zero"             test_readonly_tools_md_exits_nonzero
run_test "idempotency: domain change removes old, adds new"       test_idempotent_domain_change
run_test "idempotency: append→replace transition no duplication"  test_append_to_replace_transition

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
if [[ "${FAIL}" -gt 0 ]]; then
    echo "Failed:"
    for t in "${FAILED_TESTS[@]}"; do
        echo "  - ${t}"
    done
    exit 1
fi
