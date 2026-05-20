# The sandboxed browser environment.
#
# When the agent calls `sandbox_fetch`, we'll spin up a fresh container from
# this image, render the URL inside it, capture results, and tear it down.
#
# The real Dockerfile lands in the next pass. For now, this is a placeholder
# so the repo structure shows where the sandbox lives.
#
# Plan:
#   - Base image: mcr.microsoft.com/playwright/python (chromium pre-installed)
#   - Non-root user, no host bind mounts
#   - Egress restricted via iptables (only the target host on 80/443)
#   - Output written to a stdout JSON blob, picked up by the host

FROM python:3.12-slim

LABEL purpose="URL triage sandbox (placeholder)"
LABEL status="not-yet-implemented"

CMD ["echo", "Sandbox not implemented yet. Real Dockerfile lands in the next pass."]
