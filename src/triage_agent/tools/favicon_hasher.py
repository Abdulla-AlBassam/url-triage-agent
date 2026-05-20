"""
favicon_hasher — fingerprint a site's tiny tab icon.

Phishing kits are recycled across hundreds of fake sites. The operators
almost never change the favicon between deployments. So the favicon hash
becomes a fingerprint: two domains with the same hash often belong to the
same operator.

The Shodan and urlscan databases publish lists of favicon hashes seen on
phishing kits, C2 panels, and leaked admin interfaces. Matching against
those lists gives strong evidence.

Hash function: MurmurHash3 (mmh3). Not cryptographic; chosen because Shodan
picked it as the canonical favicon hash. The exact recipe matters:

    1. Fetch /favicon.ico.
    2. Base64-encode the raw bytes with `base64.encodebytes` (which inserts a
       newline every 76 characters — this quirk is part of the spec).
    3. mmh3.hash on the resulting bytes.

If you skip the newline insertion (e.g. by using b64encode) you get a
different number that won't match Shodan's database. The convention is the
convention.
"""
from __future__ import annotations

import base64
from urllib.parse import urlparse, urlunparse

import httpx
import mmh3

from ..tool_registry import register_tool


@register_tool(
    name="favicon_hasher",
    description=(
        "Download a site's favicon and compute its Shodan-style MurmurHash3 "
        "hash. The hash is a fingerprint of the phishing kit (or legitimate "
        "template) the site uses. You can search Shodan with "
        "`http.favicon.hash:<value>` to find other sites with the same icon."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "url": {
                "type": "string",
                "description": (
                    "The site URL or hostname. We append /favicon.ico ourselves."
                ),
            }
        },
        "required": ["url"],
    },
)
def favicon_hasher(url: str) -> dict:
    if "://" not in url:
        url = f"https://{url}"

    parsed = urlparse(url)
    if not parsed.hostname:
        return {"url": url, "error": "Could not parse hostname from URL"}

    favicon_url = urlunparse((parsed.scheme, parsed.netloc, "/favicon.ico", "", "", ""))

    try:
        response = httpx.get(favicon_url, follow_redirects=True, timeout=10.0)
    except Exception as exc:
        return {"url": url, "favicon_url": favicon_url, "error": str(exc)}

    if response.status_code != 200:
        return {
            "url": url,
            "favicon_url": favicon_url,
            "error": f"HTTP {response.status_code} fetching favicon",
        }

    # The Shodan-compatible recipe: base64.encodebytes inserts newlines every
    # 76 chars. b64encode would not, and would produce a different hash.
    encoded = base64.encodebytes(response.content)
    hash_value = mmh3.hash(encoded)

    return {
        "url": url,
        "favicon_url": favicon_url,
        "favicon_size_bytes": len(response.content),
        "mmh3_hash": hash_value,
        "shodan_query": f"http.favicon.hash:{hash_value}",
    }
