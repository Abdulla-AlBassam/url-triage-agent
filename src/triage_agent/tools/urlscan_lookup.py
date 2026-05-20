"""
urlscan_lookup — has urlscan.io seen this URL before?

urlscan.io runs its own sandbox infrastructure. Anyone can submit a URL and
urlscan will render it in a real browser, capture a screenshot, log the
network traffic, and archive the lot. The archive is publicly searchable.

So before we render a page ourselves, we ask urlscan: have you seen this
exact URL, or anything on this domain, recently? If yes, we get free
historical evidence: rendered screenshots, redirect chains, network calls
the page made.

This is a STUB for now.
"""
from ..tool_registry import register_tool


@register_tool(
    name="urlscan_lookup",
    description=(
        "Search urlscan.io's archive for previous scans of a URL or domain. "
        "Returns recent scan IDs, verdicts, and screenshot URLs. Useful as a "
        "first look before doing your own sandbox fetch."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "description": (
                    "A URL or bare domain to search the urlscan archive for."
                ),
            }
        },
        "required": ["query"],
    },
)
def urlscan_lookup(query: str) -> dict:
    return {
        "_stub": True,
        "query": query,
        "result_count": 0,
        "recent_scans": [],
        "note": "Stub data. Real urlscan API call lands in the next pass.",
    }
