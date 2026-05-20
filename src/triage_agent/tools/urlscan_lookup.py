"""
urlscan_lookup — has urlscan.io seen this domain before?

urlscan.io runs its own sandbox infrastructure. Anyone can submit a URL,
urlscan renders it in a real browser, captures a screenshot, logs the
network traffic, and archives the lot. The archive is publicly searchable.

So before we render a page ourselves (which is expensive), we ask urlscan:
have you seen this URL or anything on this domain recently? If yes, we get
free historical evidence — rendered screenshots, redirect chains, network
calls the page made.

We search by domain rather than full URL, because:
  1. Phishing campaigns rotate URLs but reuse infrastructure.
  2. A urlscan-by-domain search returns sibling URLs from the same operator,
     which is gold for spotting a campaign.
"""
from __future__ import annotations

import os

import httpx

from ..tool_registry import register_tool
from ._helpers import to_hostname


URLSCAN_SEARCH = "https://urlscan.io/api/v1/search/"


@register_tool(
    name="urlscan_lookup",
    description=(
        "Search urlscan.io's archive for previous scans of a domain. Returns "
        "recent scan IDs, page URLs, verdicts, and screenshot links. Useful "
        "as a first look before doing your own sandbox fetch."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "description": (
                    "A URL or bare domain to search the urlscan archive for. "
                    "We extract the hostname and search by domain."
                ),
            }
        },
        "required": ["query"],
    },
)
def urlscan_lookup(query: str) -> dict:
    key = os.getenv("URLSCAN_API_KEY")
    if not key:
        return {
            "available": False,
            "reason": "URLSCAN_API_KEY not set in .env.",
        }

    hostname = to_hostname(query)

    try:
        response = httpx.get(
            URLSCAN_SEARCH,
            params={"q": f"domain:{hostname}", "size": 10},
            headers={"API-Key": key},
            timeout=15.0,
        )
    except Exception as exc:
        return {"query": query, "error": str(exc)}

    if response.status_code != 200:
        return {
            "query": query,
            "error": f"HTTP {response.status_code}: {response.text[:200]}",
        }

    data = response.json()
    results = data.get("results", [])

    summary = []
    for r in results:
        verdicts = r.get("verdicts") or {}
        overall = verdicts.get("overall") or {}
        summary.append(
            {
                "scan_id": r.get("_id"),
                "url": (r.get("page") or {}).get("url"),
                "scanned_at": (r.get("task") or {}).get("time"),
                "malicious_verdict": overall.get("malicious", False),
                "score": overall.get("score"),
                "screenshot": r.get("screenshot"),
                "result_url": r.get("result"),
            }
        )

    return {
        "query": query,
        "hostname_searched": hostname,
        "total_matches": data.get("total", 0),
        "recent_scans": summary,
    }
