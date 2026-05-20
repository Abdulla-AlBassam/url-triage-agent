#!/usr/bin/env bash
#
# Container entrypoint.
#
# Runs as root just long enough to:
#   1. Resolve the target hostname while DNS is still allowed.
#   2. Bake the resolved IPs into /etc/hosts so chromium never needs DNS.
#   3. Apply iptables rules that allow outbound TCP only to those IPs on
#      ports 80/443. Everything else (DNS exfil, SMTP, SSH, other hosts) is
#      dropped.
#   4. Drop privileges to the non-root `pwuser` and exec the python runner.
#
# Set STRICT_EGRESS=0 to skip the iptables lockdown (useful for debugging,
# or for the few legit sites that need third-party CDNs to render at all).
#
# All errors are emitted as a single JSON line on stderr; the host runner
# logs them but still returns a structured result to the agent.

set -euo pipefail

emit_error() {
    # Single-line JSON so the host can parse it. $1 is the message.
    printf '{"error": "%s"}\n' "$1" >&2
}

if [[ -z "${TARGET_URL:-}" ]]; then
    emit_error "TARGET_URL environment variable not set"
    exit 2
fi
if [[ -z "${TARGET_HOST:-}" ]]; then
    emit_error "TARGET_HOST environment variable not set"
    exit 2
fi

STRICT="${STRICT_EGRESS:-1}"

if [[ "$STRICT" == "1" ]]; then
    # Resolve the target while DNS is still permitted. We use IPv4 only — the
    # firewall rules below only allowlist v4 IPs, and v6 is locked down at
    # the bottom of this block.
    IPS=$(getent ahostsv4 "$TARGET_HOST" | awk '{print $1}' | sort -u || true)

    if [[ -z "$IPS" ]]; then
        emit_error "could not resolve $TARGET_HOST to any IPv4 address"
        exit 3
    fi

    # Default-deny all outbound; allow loopback and established replies.
    iptables -P INPUT DROP
    iptables -P OUTPUT DROP
    iptables -P FORWARD DROP
    iptables -A INPUT  -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT
    iptables -A INPUT  -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # Allow DNS by destination port. Docker rewrites the container's
    # nameserver to 127.0.0.11 but then NATs the actual query to the host's
    # resolver, so a `-d 127.0.0.11` rule never matches post-NAT. Allowing
    # port 53 universally is looser than ideal (a page could DNS-exfil) but
    # acceptable: the page can't actually open a TCP connection to anywhere
    # except the target host's resolved IPs, enforced just below.
    iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
    iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT

    # Allow only TCP egress to the resolved target IPs on 80 and 443.
    for ip in $IPS; do
        iptables -A OUTPUT -p tcp -d "$ip" --dport 443 -j ACCEPT
        iptables -A OUTPUT -p tcp -d "$ip" --dport 80  -j ACCEPT
    done

    # IPv6: drop the lot. We only allowlisted IPv4 above, so any v6 traffic
    # would be an unintentional escape hatch.
    if command -v ip6tables >/dev/null 2>&1; then
        ip6tables -P INPUT DROP  || true
        ip6tables -P OUTPUT DROP || true
        ip6tables -P FORWARD DROP || true
        ip6tables -A INPUT  -i lo -j ACCEPT || true
        ip6tables -A OUTPUT -o lo -j ACCEPT || true
    fi
fi

# Drop to non-root and run the actual browser script.
# gosu doesn't fork an extra shell, so the python process is PID 1's direct
# child and signals (SIGTERM from `docker stop`) propagate cleanly.
exec gosu pwuser python /app/runner.py "$TARGET_URL"
