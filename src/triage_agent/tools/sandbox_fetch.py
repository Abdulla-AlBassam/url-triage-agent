"""
sandbox_fetch — open a URL in a sealed-off browser and report what it shows.

This is the heavyweight tool. It launches a real Chromium browser inside a
Docker container that has:
  - no access to the host filesystem,
  - no network egress except to the target host,
  - and a fresh, throwaway profile.

The browser navigates to the URL, lets JavaScript run, then we collect:
  - the final URL after redirects,
  - the page title,
  - a screenshot,
  - the visible text,
  - the network requests the page tried to make,
  - any console logs.

Why we can't just `curl` the URL: many phishing pages show different content
to scrapers than to real browsers ("cloaking"), and many pages only assemble
the malicious payload after JavaScript runs.

This is a STUB for now. The Docker sandbox setup lands in the next pass.
"""
from ..tool_registry import register_tool


@register_tool(
    name="sandbox_fetch",
    description=(
        "Render a URL in a sandboxed Chromium browser inside Docker. Returns "
        "the final URL after redirects, page title, visible text, network "
        "requests the page made, console logs, and a screenshot path. "
        "Expensive; only use after cheaper tools haven't given you a verdict."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "url": {
                "type": "string",
                "description": "The URL to render.",
            },
            "timeout_seconds": {
                "type": "integer",
                "description": "How long to wait for the page to load. Default 15.",
                "default": 15,
            },
        },
        "required": ["url"],
    },
)
def sandbox_fetch(url: str, timeout_seconds: int = 15) -> dict:
    return {
        "_stub": True,
        "url": url,
        "final_url": url,
        "title": "Example Domain",
        "visible_text_excerpt": (
            "This domain is for use in illustrative examples in documents."
        ),
        "network_requests": [],
        "console_logs": [],
        "blocked_egress": [],
        "screenshot_path": None,
        "note": "Stub data. Real Docker sandbox lands in the next pass.",
    }
