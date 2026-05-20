# The sandboxed browser environment.
#
# When the agent calls `sandbox_fetch`, the host runner spins up a fresh
# container from this image, renders the URL inside it, and tears it down.
# Nothing the page does can touch the host filesystem or any other host.
#
# Base image:
#   mcr.microsoft.com/playwright/python — Microsoft's official Playwright
#   image. It ships with Python 3 plus a clean Chromium build that's been
#   tested against the playwright Python bindings of the same version. Saves
#   us a couple of GB of "compile chromium from scratch" pain.
#
# On top we add:
#   - iptables: so the entrypoint can lock down outbound traffic.
#   - gosu:     a tiny, well-audited setuid helper. Lets root set the
#               iptables rules and then cleanly drop to a non-root user
#               before running the actual browser.
#   - dnsutils: gives us `getent ahosts` for resolving the target.
#
# Runtime hardening (applied by the host's `docker run` flags, not here):
#   --cap-drop=ALL --cap-add=NET_ADMIN  : only iptables capability granted
#   --security-opt=no-new-privileges    : no setuid escalation paths
#   --read-only --tmpfs /tmp            : root fs immutable, only /tmp is writable
#   --memory=512m --cpus=1              : a runaway script can't eat the laptop
#   no bind mounts                      : the container can't see host files

FROM mcr.microsoft.com/playwright/python:v1.50.0-noble

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        iptables \
        gosu \
        dnsutils \
    && rm -rf /var/lib/apt/lists/*

# The playwright image ships the browser binaries (under /ms-playwright) but
# not the Python bindings. Install them system-wide. --break-system-packages
# is needed on Ubuntu Noble because of PEP 668, and is the right call inside
# a single-purpose container.
RUN pip install --no-cache-dir --break-system-packages playwright==1.50.0

# /app is owned by pwuser (the non-root user shipped by the playwright image).
# Everything the runner needs to read lives here.
RUN mkdir -p /app && chown -R pwuser:pwuser /app

COPY runner.py /app/runner.py
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh /app/runner.py

ENTRYPOINT ["/entrypoint.sh"]
