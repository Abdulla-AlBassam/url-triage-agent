"""
virustotal_lookup — ask 70+ antivirus engines what they think.

VirusTotal is owned by Google. It's an aggregator: submit a URL, file, or
hash, and it runs the input past every major AV vendor's engine, returning
each verdict.

We use the URL endpoint. A useful summary number is "how many of 70+ engines
flagged this URL?". Anything north of 5-10 is essentially settled, but even a
handful of detections matters when combined with other signals.

This is a STUB for now.
"""
from ..tool_registry import register_tool


@register_tool(
    name="virustotal_lookup",
    description=(
        "Query VirusTotal for a URL or domain. Returns how many AV engines "
        "flagged it as malicious, plus the engines' individual verdicts. "
        "Treat 5+ malicious votes from major engines as strong evidence."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "url": {
                "type": "string",
                "description": "The URL to look up (or a bare domain).",
            }
        },
        "required": ["url"],
    },
)
def virustotal_lookup(url: str) -> dict:
    return {
        "_stub": True,
        "url": url,
        "malicious_count": 0,
        "suspicious_count": 0,
        "harmless_count": 65,
        "undetected_count": 5,
        "engines_flagged": [],
        "note": "Stub data. Real VirusTotal API call lands in the next pass.",
    }
