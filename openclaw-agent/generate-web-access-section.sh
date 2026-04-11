#!/bin/sh
# Generate the "## Web Access" section of TOOLS.md from whitelist.txt.
# Replaces content between BEGIN/END markers in TOOLS.md.
# If markers are absent, appends them at the end of the file.
#
# Usage: generate-web-access-section.sh [allowlist-file]
# Args:
#   $1  Path to whitelist file (default: $OPENCLAW_SSRF_ALLOWLIST_FILE or /etc/whitelist.txt)
set -eu

ALLOWLIST_FILE="${1:-${OPENCLAW_SSRF_ALLOWLIST_FILE:-/etc/whitelist.txt}}"
TOOLS_MD="${OPENCLAW_TOOLS_MD:-/home/node/.openclaw/workspace/TOOLS.md}"

BEGIN_MARKER="<!-- BEGIN auto-generated: web-access -->"
END_MARKER="<!-- END auto-generated: web-access -->"

if [ ! -r "$ALLOWLIST_FILE" ]; then
    echo "[generate-web-access] ERROR: whitelist not readable: $ALLOWLIST_FILE" >&2
    exit 1
fi

if [ ! -f "$TOOLS_MD" ]; then
    echo "[generate-web-access] WARNING: TOOLS.md not found, skipping" >&2
    exit 0
fi

# Build the replacement section in a temp file
TMPFILE=$(mktemp)
trap 'rm -f "$TMPFILE"' EXIT

{
    printf '%s\n' "$BEGIN_MARKER"
    printf '## Web Access\n\n'
    printf 'This environment enforces DNS and HTTPS restrictions at the network level.\n'
    printf 'Only these external domains are reachable:\n\n'
    while IFS= read -r line; do
        line=$(printf '%s' "$line" | tr -d '\r' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        case "$line" in ''|\#*) continue ;; esac
        printf -- '- %s\n' "$line"
    done < "$ALLOWLIST_FILE"
    printf '\nAll other domains will fail. Do not retry failed domains.\n'
    printf '%s\n' "$END_MARKER"
} > "$TMPFILE"

if grep -qF "$BEGIN_MARKER" "$TOOLS_MD"; then
    # Replace content between markers (inclusive)
    awk -v begin="$BEGIN_MARKER" -v end="$END_MARKER" -v tmpfile="$TMPFILE" '
        $0 == begin { while ((getline line < tmpfile) > 0) print line; skip=1; next }
        $0 == end   { skip=0; next }
        !skip       { print }
    ' "$TOOLS_MD" > "$TOOLS_MD.tmp"
    mv "$TOOLS_MD.tmp" "$TOOLS_MD"
else
    # Append markers + content if not yet present
    { printf '\n'; cat "$TMPFILE"; } >> "$TOOLS_MD"
fi

echo "[openclaw-agent] TOOLS.md web-access section generated from $(basename "$ALLOWLIST_FILE")"
