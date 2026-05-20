"""
urlhaus_lookup — ask abuse.ch whether this URL is already on the naughty list.

abuse.ch is a Swiss non-profit that runs a community-fed feed of known
malicious URLs (it's the open-source backbone of a lot of commercial threat
intel). URLhaus is their database.

The API is free, has no key, and is one of the most useful single sources of
"is this thing definitely bad?" data on the internet.

This is a STUB for now.
"""
from ..tool_registry import register_tool


@register_tool(
    name="urlhaus_lookup",
    description=(
        "Check abuse.ch's URLhaus database for the given URL. If URLhaus has "
        "the URL flagged, that's strong evidence the URL is malicious. Returns "
        "the threat type (malware_download / phishing / etc.) and the tags."
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
    return {
        "_stub": True,
        "url": url,
        "found": False,
        "threat": None,
        "tags": [],
        "note": "Stub data. Real URLhaus API call lands in the next pass.",
    }
