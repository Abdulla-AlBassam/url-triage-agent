"""
urlhaus_lookup — ask abuse.ch whether this URL is on their malicious list.

abuse.ch is a Swiss non-profit that runs a community-fed feed of known
malicious URLs (it's the open-source backbone of a lot of commercial threat
intel). URLhaus is their database.

The API requires a free Auth-Key (registered at https://auth.abuse.ch/) as
of 2024. If the key is missing from the environment, this tool reports
itself as unavailable rather than crashing the run.

A hit on URLhaus is strong evidence the URL is malicious. The agent should
weight it heavily and not need much more to verdict.
"""
from __future__ import annotations

import os

import httpx

from ..tool_registry import register_tool


URLHAUS_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/url/"


@register_tool(
    name="urlhaus_lookup",
    description=(
        "Check abuse.ch's URLhaus database for the given URL. A hit is strong "
        "evidence the URL is malicious. Returns threat type, tags, and the "
        "associated payload hashes if any."
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
def urlhaus_lookup(url: str) -> dict:
    auth_key = os.getenv("URLHAUS_AUTH_KEY")
    if not auth_key:
        return {
            "available": False,
            "reason": (
                "URLHAUS_AUTH_KEY not set. Get a free key at https://auth.abuse.ch/ "
                "and add it to .env."
            ),
        }

    try:
        response = httpx.post(
            URLHAUS_ENDPOINT,
            data={"url": url},
            headers={"Auth-Key": auth_key},
            timeout=15.0,
        )
    except Exception as exc:
        return {"url": url, "error": str(exc)}

    if response.status_code == 401:
        return {"url": url, "error": "URLhaus rejected the Auth-Key (HTTP 401)."}
    if response.status_code != 200:
        return {"url": url, "error": f"HTTP {response.status_code}"}

    body = response.json()
    status = body.get("query_status")

    if status == "no_results":
        return {"url": url, "found": False}

    if status == "ok":
        payloads = body.get("payloads") or []
        return {
            "url": url,
            "found": True,
            "threat": body.get("threat"),
            "tags": body.get("tags") or [],
            "url_status": body.get("url_status"),
            "date_added": body.get("date_added"),
            "reporter": body.get("reporter"),
            "payload_count": len(payloads),
            "payload_hashes": [p.get("response_sha256") for p in payloads[:5]],
        }

    return {"url": url, "query_status": status, "raw": body}
