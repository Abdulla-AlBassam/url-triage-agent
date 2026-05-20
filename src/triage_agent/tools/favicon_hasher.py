"""
favicon_hasher — fingerprint a site's tiny tab icon.

A favicon is the small image a website shows in the browser tab. Phishing
kits are recycled across hundreds of fake sites, and the operators almost
never bother changing the favicon. So the favicon's hash is a fingerprint:
two unrelated-looking domains with the same favicon hash often belong to the
same operator.

The Shodan and urlscan databases publish lists of "favicon hashes that have
been seen on phishing kits / C2 panels / leaked admin interfaces". If our
hash matches one, that's strong evidence.

Hash function: MurmurHash3 (mmh3). Not because it's cryptographic, but
because Shodan picked it as the canonical favicon hash. To match against
their database, we use the same function.

This is a STUB for now.
"""
from ..tool_registry import register_tool


@register_tool(
    name="favicon_hasher",
    description=(
        "Download a site's favicon and compute its MurmurHash3 (the Shodan "
        "favicon hash). Useful for fingerprinting phishing kits and matching "
        "against published lists of known-bad favicon hashes."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "url": {
                "type": "string",
                "description": "The site URL. We'll append /favicon.ico ourselves.",
            }
        },
        "required": ["url"],
    },
)
def favicon_hasher(url: str) -> dict:
    return {
        "_stub": True,
        "url": url,
        "favicon_url": f"{url.rstrip('/')}/favicon.ico",
        "mmh3_hash": None,
        "known_bad_match": False,
        "note": "Stub data. Real favicon fetch + hash lands in the next pass.",
    }
