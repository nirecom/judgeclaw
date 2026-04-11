#!/usr/bin/env bash
# =============================================================================
# Test: whitelist.txt includes www.alphaxiv.org for HEARTBEAT fetch
# =============================================================================
# Purpose:
#   Verify that www.alphaxiv.org is in the whitelist to enable heartbeat
#   to fetch alphaxiv.org trending papers without SSRF blocking.
#
# Related fix:
#   judgeclaw issue: HEARTBEAT.md periodic alphaxiv.org fetch was blocked
#
# =============================================================================

set -euo pipefail

# Test directory
TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WHITELIST_FILE="$TEST_DIR/config/whitelist.txt"

echo "Testing whitelist.txt for alphaxiv domains..."

# Test 1: alphaxiv.org is present
if grep -q "^alphaxiv.org$" "$WHITELIST_FILE"; then
    echo "✓ alphaxiv.org is in whitelist"
else
    echo "✗ FAILED: alphaxiv.org not in whitelist"
    exit 1
fi

# Test 2: www.alphaxiv.org is present (added for heartbeat)
if grep -q "^www.alphaxiv.org$" "$WHITELIST_FILE"; then
    echo "✓ www.alphaxiv.org is in whitelist"
else
    echo "✗ FAILED: www.alphaxiv.org not in whitelist"
    exit 1
fi

# Test 3: No wildcards (*.alphaxiv.org should NOT be in whitelist)
if grep -q "\*\.alphaxiv\.org" "$WHITELIST_FILE"; then
    echo "✗ FAILED: Wildcard *.alphaxiv.org found (should be explicit domains only)"
    exit 1
else
    echo "✓ No wildcard entries for alphaxiv (as expected)"
fi

# Test 4: File exists and is readable
if [[ ! -f "$WHITELIST_FILE" ]]; then
    echo "✗ FAILED: Whitelist file not found at $WHITELIST_FILE"
    exit 1
fi
if [[ ! -r "$WHITELIST_FILE" ]]; then
    echo "✗ FAILED: Whitelist file is not readable"
    exit 1
fi
echo "✓ Whitelist file exists and is readable"

# Test 5: Validate whitelist format (each entry must be valid hostname)
while IFS= read -r line; do
    line="${line%% *}"  # Remove comments
    [ -z "$line" ] && continue  # Skip empty lines
    [[ "$line" =~ ^# ]] && continue  # Skip comment lines

    # Basic hostname validation: alphanumeric, dots, hyphens only
    if ! [[ "$line" =~ ^[a-zA-Z0-9.-]+$ ]]; then
        echo "✗ FAILED: Invalid hostname in whitelist: $line"
        exit 1
    fi
done < "$WHITELIST_FILE"
echo "✓ All whitelist entries are valid hostnames"

# Test 6: Validate DNS label length (RFC 1035: max 63 chars per label)
while IFS= read -r line; do
    line="${line%% *}"  # Remove comments
    [ -z "$line" ] && continue  # Skip empty lines
    [[ "$line" =~ ^# ]] && continue  # Skip comment lines

    IFS='.' read -ra labels <<< "$line"
    for label in "${labels[@]}"; do
        if (( ${#label} > 63 )); then
            echo "✗ FAILED: DNS label exceeds 63 chars: $label (in $line)"
            exit 1
        fi
    done
done < "$WHITELIST_FILE"
echo "✓ All DNS labels within 63-character limit (RFC 1035 compliant)"

# Test 7: Validate total domain length (RFC 1035: max 253 chars)
while IFS= read -r line; do
    line="${line%% *}"  # Remove comments
    [ -z "$line" ] && continue  # Skip empty lines
    [[ "$line" =~ ^# ]] && continue  # Skip comment lines

    if (( ${#line} > 253 )); then
        echo "✗ FAILED: Domain exceeds 253 chars: $line"
        exit 1
    fi
done < "$WHITELIST_FILE"
echo "✓ All domains within 253-character limit (RFC 1035 compliant)"

# Test 8: Verify alphaxiv domains are not commented out
if grep -q "^[[:space:]]*#.*alphaxiv\.org" "$WHITELIST_FILE"; then
    echo "✗ FAILED: alphaxiv.org is commented out in whitelist"
    exit 1
fi
if grep -q "^[[:space:]]*#.*www\.alphaxiv\.org" "$WHITELIST_FILE"; then
    echo "✗ FAILED: www.alphaxiv.org is commented out in whitelist"
    exit 1
fi
echo "✓ alphaxiv domains are not commented out"

# Test 9: Detect duplicate entries
duplicates=$(awk '!/^#/{print $1}' "$WHITELIST_FILE" | grep -v '^[[:space:]]*$' | sort | uniq -d)
if [[ -z "$duplicates" ]]; then
    echo "✓ No duplicate entries in whitelist"
else
    echo "✗ FAILED: Duplicate entries found: $duplicates"
    exit 1
fi

echo ""
echo "All tests passed!"
exit 0
