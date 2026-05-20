"""
virustotal_lookup — ask 70+ antivirus engines what they think.

VirusTotal (owned by Google) is an aggregator: submit a URL, file, or hash,
and it runs the input past every major AV engine, returning each verdict.

The API needs a free key. We treat the key as optional — if missing, the
tool reports itself unavailable and the agent works around it.

How VT identifies a URL: not by raw URL, but by a deterministic ID:

    url_id = base64.urlsafe_b64encode(url).rstrip("=")

We hit `/api/v3/urls/{url_id}`. If VT has seen this URL before, we get
historical scan data. If not, we submit it and report that the data isn't
available yet.
"""
from __future__ import annotations

import base64
import os

import httpx

from ..tool_registry import register_tool


VT_BASE = "https://www.virustotal.com/api/v3"


@register_tool(
    name="virustotal_lookup",
    description=(
        "Query VirusTotal for a URL. Returns how many of 70+ AV engines "
        "flagged it as malicious, plus the engines' individual verdicts and "
        "VT's reputation score. Treat 5+ malicious votes as strong evidence."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "url": {
                "type": "string",
                "description": "The full URL to look up.",
            }
        },
        "required": ["url"],
    },
)
def virustotal_lookup(url: str) -> dict:
    key = os.getenv("VIRUSTOTAL_API_KEY")
    if not key:
        return {
            "available": False,
            "reason": "VIRUSTOTAL_API_KEY not set in .env.",
        }

    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

    try:
        response = httpx.get(
            f"{VT_BASE}/urls/{url_id}",
            headers={"x-apikey": key, "accept": "application/json"},
            timeout=20.0,
        )
    except Exception as exc:
        return {"url": url, "error": str(exc)}

    if response.status_code == 404:
        # Not seen by VT yet. Submit it so future runs have data.
        try:
            httpx.post(
                f"{VT_BASE}/urls",
                headers={"x-apikey": key},
                data={"url": url},
                timeout=20.0,
            )
        except Exception:
            pass
        return {
            "url": url,
            "found": False,
            "note": "URL not previously seen by VirusTotal. Submitted for analysis.",
        }

    if response.status_code != 200:
        return {
            "url": url,
            "error": f"HTTP {response.status_code}: {response.text[:200]}",
        }

    attrs = response.json().get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})

    flagging: list[str] = []
    for engine, result in (attrs.get("last_analysis_results") or {}).items():
        if result.get("category") == "malicious":
            flagging.append(f"{engine}: {result.get('result', 'malicious')}")

    return {
        "url": url,
        "found": True,
        "malicious_count": stats.get("malicious", 0),
        "suspicious_count": stats.get("suspicious", 0),
        "harmless_count": stats.get("harmless", 0),
        "undetected_count": stats.get("undetected", 0),
        "engines_flagged": flagging[:20],
        "reputation": attrs.get("reputation"),
        "first_submission_date": attrs.get("first_submission_date"),
        "last_analysis_date": attrs.get("last_analysis_date"),
        "categories": list((attrs.get("categories") or {}).values())[:10],
    }
