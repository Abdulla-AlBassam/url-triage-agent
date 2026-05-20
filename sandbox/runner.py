"""
The sandboxed browser script.

Runs inside the Docker container. By the time this starts:
  - The container has dropped to a non-root user.
  - Outbound traffic is locked down to the target host on 80/443 only.
  - The target hostname is hard-coded in /etc/hosts (DNS is blocked).

What this script does:
  1. Launches Chromium via Playwright.
  2. Navigates to the URL.
  3. Listens for network requests, console logs, redirects, and form data
     while the page renders.
  4. Captures a screenshot to /tmp (which the host extracts via `docker cp`).
  5. Prints a single JSON blob to stdout summarising what it saw.

The host runner reads that JSON, attaches the screenshot path, and returns
the result to the agent.

Defensive choices:
  - `wait_until="domcontentloaded"` first, then a short settle delay, rather
    than `networkidle` — many phishing pages load tracking pixels forever
    and networkidle would time out on them.
  - Visible text is truncated to keep the JSON small.
  - Forms and inputs are summarised, not echoed verbatim (we redact input
    values; the agent doesn't need to know what was pre-filled).
"""
from __future__ import annotations

import json
import os
import sys
import traceback
from urllib.parse import urlparse

from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout


VISIBLE_TEXT_MAX = 8000
NETWORK_REQUEST_CAP = 200
CONSOLE_LOG_CAP = 100
LINK_SAMPLE_CAP = 50
FORM_CAP = 10


def main() -> int:
    if len(sys.argv) < 2:
        print(json.dumps({"error": "usage: runner.py <url>"}))
        return 2

    url = sys.argv[1]
    timeout_ms = int(os.getenv("TIMEOUT_MS", "20000"))

    network_requests: list[dict] = []
    blocked_requests: list[dict] = []
    console_logs: list[dict] = []

    try:
        with sync_playwright() as p:
            # --no-sandbox: chromium's own user-namespace sandbox needs caps
            # we deliberately dropped. The outer Docker container is still
            # our security boundary.
            browser = p.chromium.launch(
                args=[
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                ],
            )
            context = browser.new_context(
                viewport={"width": 1280, "height": 800},
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                ),
                ignore_https_errors=True,
            )
            page = context.new_page()

            def on_request(req):
                if len(network_requests) >= NETWORK_REQUEST_CAP:
                    return
                network_requests.append({
                    "url": req.url,
                    "method": req.method,
                    "resource_type": req.resource_type,
                })

            def on_request_failed(req):
                if len(blocked_requests) >= NETWORK_REQUEST_CAP:
                    return
                blocked_requests.append({
                    "url": req.url,
                    "failure": (req.failure or "unknown") if isinstance(req.failure, str) else "blocked",
                    "resource_type": req.resource_type,
                })

            def on_console(msg):
                if len(console_logs) >= CONSOLE_LOG_CAP:
                    return
                try:
                    console_logs.append({
                        "type": msg.type,
                        "text": (msg.text or "")[:500],
                    })
                except Exception:
                    pass

            page.on("request", on_request)
            page.on("requestfailed", on_request_failed)
            page.on("console", on_console)

            navigation_error: str | None = None
            response = None
            try:
                response = page.goto(url, timeout=timeout_ms, wait_until="domcontentloaded")
            except PWTimeout:
                navigation_error = f"navigation timeout after {timeout_ms} ms"
            except Exception as exc:
                navigation_error = f"{type(exc).__name__}: {exc}"

            # Let any post-DOM JavaScript settle. Capped so phishing pages
            # that endlessly poll don't keep us forever.
            try:
                page.wait_for_timeout(2500)
            except Exception:
                pass

            final_url = page.url
            try:
                title = page.title()
            except Exception:
                title = ""

            try:
                visible_text = page.evaluate(
                    "() => document.body ? document.body.innerText : ''"
                ) or ""
            except Exception:
                visible_text = ""
            visible_text = visible_text[:VISIBLE_TEXT_MAX]

            try:
                html_size = len(page.content())
            except Exception:
                html_size = 0

            # Form analysis. We surface the form action URL, the method,
            # and a redacted summary of each input (type only — never values).
            try:
                forms = page.evaluate(
                    """
                    () => Array.from(document.querySelectorAll('form')).map(f => ({
                        action: f.action || '',
                        method: (f.method || 'get').toLowerCase(),
                        input_types: Array.from(f.querySelectorAll('input'))
                            .map(i => i.type || 'text'),
                        has_password: !!f.querySelector('input[type="password"]'),
                    }))
                    """
                ) or []
            except Exception:
                forms = []

            try:
                links = page.evaluate(
                    """
                    () => Array.from(document.querySelectorAll('a[href]'))
                            .slice(0, 50)
                            .map(a => a.href)
                    """
                ) or []
            except Exception:
                links = []

            # Capture the screenshot as bytes and base64-encode it into the
            # JSON output. We can't write to a tmpfs file and `docker cp`
            # it out, because the tmpfs is gone the moment the container
            # exits. Inlining the bytes is ugly but cheap and works under
            # the `--read-only` constraint.
            screenshot_b64 = None
            try:
                import base64
                png_bytes = page.screenshot(full_page=False)
                screenshot_b64 = base64.b64encode(png_bytes).decode("ascii")
            except Exception:
                pass

            try:
                browser.close()
            except Exception:
                pass

        # Derive a couple of analyst-friendly summaries from the raw data.
        page_host = urlparse(final_url).hostname or ""
        password_input_present = any(f.get("has_password") for f in forms)

        form_action_hosts: list[str] = []
        cross_domain_form_post = False
        for f in forms:
            action = f.get("action") or ""
            if not action:
                continue
            ah = urlparse(action).hostname
            if ah and ah not in form_action_hosts:
                form_action_hosts.append(ah)
            if ah and page_host and ah != page_host:
                # Strict same-host comparison. The agent can decide if a
                # subdomain difference matters by looking at the hosts.
                cross_domain_form_post = True

        result = {
            "url": url,
            "final_url": final_url,
            "title": title,
            "html_size_bytes": html_size,
            "visible_text_excerpt": visible_text,
            "network_request_count": len(network_requests),
            "network_requests_sample": network_requests[:50],
            "blocked_request_count": len(blocked_requests),
            "blocked_requests_sample": blocked_requests[:30],
            "console_logs": console_logs[:30],
            "forms": forms[:FORM_CAP],
            "password_input_present": password_input_present,
            "form_action_hosts": form_action_hosts,
            "cross_domain_form_post": cross_domain_form_post,
            "outbound_links_sample": links[:LINK_SAMPLE_CAP],
            "screenshot_b64": screenshot_b64,
            "screenshot_captured": screenshot_b64 is not None,
            "navigation_error": navigation_error,
            "strict_egress": os.getenv("STRICT_EGRESS", "1") == "1",
        }
        print(json.dumps(result))
        return 0

    except Exception as exc:
        print(json.dumps({
            "url": url,
            "error": f"{type(exc).__name__}: {exc}",
            "traceback_tail": traceback.format_exc().splitlines()[-5:],
        }))
        return 1


if __name__ == "__main__":
    sys.exit(main())
