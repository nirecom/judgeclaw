#!/bin/sh
# apply-ssrf-patch.sh — Patch OpenClaw's web_fetch to enforce hostnameAllowlist
#
# Usage: apply-ssrf-patch.sh <whitelist_file> <dist_dir>
#   whitelist_file: path to whitelist.txt (1 domain/line, # comments, blank lines)
#   dist_dir:       path containing pi-embedded-*.js (typically /app/dist)
#
# The script is idempotent: .orig backup is created on first run; subsequent
# runs restore from .orig before re-patching (handles whitelist changes).
# Exits non-zero if the anchor string is not found (upstream change detection).
set -eu

WHITELIST_FILE="$1"
DIST_DIR="$2"
ANCHOR='await fetchWithWebToolsNetworkGuard({'
MARKER='OPENCLAW_WEB_FETCH_SSRF_PATCHED'

# --- 1. Build JSON array from whitelist ---
ALLOWLIST_JSON=$(
    tr -d '\r' < "$WHITELIST_FILE" \
        | sed -e 's/#.*$//' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' \
        | awk 'NF > 0 && /^[a-zA-Z0-9.-]+$/ { printf "%s\"%s\"", (c++?",":""), $1 }' \
        | sed 's/^/[/' | sed 's/$/]/'
)

if [ "$ALLOWLIST_JSON" = "[]" ]; then
    echo "[apply-ssrf-patch] WARNING: whitelist produced empty allowlist" >&2
fi

# --- 2. Find target file ---
TARGET=""
for f in "$DIST_DIR"/pi-embedded-*.js; do
    if [ -f "$f" ] && grep -q "$ANCHOR" "$f"; then
        TARGET="$f"
        break
    fi
done

if [ -z "$TARGET" ]; then
    echo "[apply-ssrf-patch] ERROR: no file in $DIST_DIR/pi-embedded-*.js contains anchor" >&2
    echo "[apply-ssrf-patch] Anchor: $ANCHOR" >&2
    exit 1
fi

# --- 3. Verify anchor uniqueness ---
ANCHOR_COUNT=$(grep -c "$ANCHOR" "$TARGET")
if [ "$ANCHOR_COUNT" -ne 1 ]; then
    echo "[apply-ssrf-patch] ERROR: anchor found $ANCHOR_COUNT times (expected 1)" >&2
    exit 1
fi

# --- 4. .orig backup management ---
ORIG="${TARGET}.orig"
if [ ! -f "$ORIG" ]; then
    cp "$TARGET" "$ORIG"
else
    cp "$ORIG" "$TARGET"
fi

# --- 5. Apply patch ---
REPLACEMENT="/*${MARKER}*/ await fetchWithWebToolsNetworkGuard({policy:{hostnameAllowlist:${ALLOWLIST_JSON}},"
sed -i "s|${ANCHOR}|${REPLACEMENT}|" "$TARGET"

# --- 6. Verify ---
PATCHED_COUNT=$(grep -c "$MARKER" "$TARGET")
if [ "$PATCHED_COUNT" -ne 1 ]; then
    echo "[apply-ssrf-patch] ERROR: post-patch marker count is $PATCHED_COUNT (expected 1)" >&2
    exit 1
fi

echo "[apply-ssrf-patch] OK: patched $TARGET with allowlist $ALLOWLIST_JSON"
