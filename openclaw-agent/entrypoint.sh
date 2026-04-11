#!/bin/sh
# openclaw-agent entrypoint: apply SSRF allowlist patch, then exec original entrypoint.
# Supports OPENCLAW_SSRF_ALLOWLIST_FILE env override for testing (D-1b).
set -eu

ALLOWLIST_FILE="${OPENCLAW_SSRF_ALLOWLIST_FILE:-/etc/whitelist.txt}"

if [ ! -r "$ALLOWLIST_FILE" ]; then
    echo "[openclaw-agent] ERROR: allowlist file not readable: $ALLOWLIST_FILE" >&2
    exit 1
fi

/opt/judgeclaw/apply-ssrf-patch.sh "$ALLOWLIST_FILE" /app/dist
/opt/judgeclaw/generate-web-access-section.sh "$ALLOWLIST_FILE"

exec docker-entrypoint.sh "$@"
