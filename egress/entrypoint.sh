#!/bin/sh
# openclaw-egress: transparent DNAT rules for outbound HTTPS
# Runs in agent's network namespace (network_mode: service:openclaw-agent)
# Redirects outbound :443 to sniproxy for SNI-based domain whitelisting
# Port 80 (HTTP) is intentionally not redirected — blocked by default

set -e

SNIPROXY_IP="${SNIPROXY_IP:-172.24.0.251}"
SNIPROXY_PORT="${SNIPROXY_PORT:-443}"

echo "Setting up egress rules: HTTPS→${SNIPROXY_IP}:${SNIPROXY_PORT}"

# Add default route via sniproxy so the kernel creates packets for external IPs.
# Without this, connect() to non-local IPs fails with ENETUNREACH before iptables
# can intercept. Only 172.24.0.0/16 (internal) has a direct route by default.
ip route add default via "${SNIPROXY_IP}" 2>/dev/null || true

# Remove any existing DNAT rules for :443 (idempotent on container restart)
# Cannot flush entire OUTPUT chain — Docker's DOCKER_OUTPUT rule must be preserved
while iptables -t nat -D OUTPUT -p tcp --dport 443 -j DNAT --to-destination "${SNIPROXY_IP}:${SNIPROXY_PORT}" 2>/dev/null; do :; done

# Redirect outbound HTTPS (port 443) to sniproxy
iptables -t nat -A OUTPUT -p tcp --dport 443 -j DNAT --to-destination "${SNIPROXY_IP}:${SNIPROXY_PORT}"

echo "Egress rules applied:"
iptables -t nat -L OUTPUT -n -v
echo "Routes:"
ip route

# Keep container alive
exec tail -f /dev/null
