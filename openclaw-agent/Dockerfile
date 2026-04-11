FROM ghcr.io/openclaw/openclaw@sha256:0b2170d5ec3a487a6313ed0556d377c5c5c80a0f806043daa2e685a4bedd45e3

# Default CMD for this image is: node openclaw.mjs gateway --allow-unconfigured
# Since overriding ENTRYPOINT resets CMD, we re-specify it in docker-compose.yml.

USER root
COPY entrypoint.sh /opt/judgeclaw/entrypoint.sh
COPY apply-ssrf-patch.sh /opt/judgeclaw/apply-ssrf-patch.sh
COPY generate-web-access-section.sh /opt/judgeclaw/generate-web-access-section.sh
RUN chmod +x /opt/judgeclaw/entrypoint.sh /opt/judgeclaw/apply-ssrf-patch.sh /opt/judgeclaw/generate-web-access-section.sh
USER node

ENTRYPOINT ["/bin/sh", "/opt/judgeclaw/entrypoint.sh"]
