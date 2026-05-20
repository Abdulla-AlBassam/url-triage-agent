"""
whois_lookup — when was this domain registered, and by whom?

WHOIS is an old internet protocol for asking the registries who owns a domain
and when it was first registered. Modern privacy rules mean the "by whom" is
often hidden, but the registration date is almost always public, and that's
the high-signal piece for us.

Domain age is one of the most predictive features in phishing detection. Most
phishing domains are registered hours to days before they're used. Legitimate
sites tend to be years old.

This is a STUB for now.
"""
from ..tool_registry import register_tool


@register_tool(
    name="whois_lookup",
    description=(
        "Look up WHOIS information for a domain: registrar, creation date, "
        "expiry. The creation date is the highest-signal field. Domains "
        "registered within the last 30 days serving anything brand-adjacent "
        "should be treated with suspicion."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "domain": {
                "type": "string",
                "description": "The bare domain to look up, e.g. 'example.com'.",
            }
        },
        "required": ["domain"],
    },
)
def whois_lookup(domain: str) -> dict:
    return {
        "_stub": True,
        "domain": domain,
        "registrar": "Example Registrar Inc.",
        "creation_date": "1995-08-14",
        "expiry_date": "2030-08-13",
        "age_days": 11000,
        "note": "Stub data. Real WHOIS lookup lands in the next pass.",
    }
