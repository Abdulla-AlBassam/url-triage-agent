"""
whois_lookup — when was this domain registered, and by whom?

WHOIS is an old protocol for asking the registries who owns a domain. Modern
privacy rules hide the "who", but the registration date is almost always
public, and that's the high-signal piece for triage.

Domain age is one of the most predictive features in phishing detection.
Most phishing domains are registered hours to days before they are used.
Legitimate domains tend to be years old.
"""
from __future__ import annotations

from datetime import date, datetime

import whois  # python-whois package

from ..tool_registry import register_tool
from ._helpers import to_hostname


@register_tool(
    name="whois_lookup",
    description=(
        "Look up WHOIS information for a domain: registrar, creation date, "
        "expiry, age in days. Domains under 30 days old serving brand-adjacent "
        "content should be treated with suspicion."
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
    domain = to_hostname(domain)

    try:
        record = whois.whois(domain)
    except Exception as exc:
        return {"domain": domain, "error": f"WHOIS lookup failed: {exc}"}

    creation = _first(record.creation_date)
    expiry = _first(record.expiration_date)

    creation_iso = _to_iso(creation)
    expiry_iso = _to_iso(expiry)

    age_days = None
    if isinstance(creation, datetime):
        age_days = (date.today() - creation.date()).days
    elif isinstance(creation, date):
        age_days = (date.today() - creation).days

    name_servers = record.name_servers
    if isinstance(name_servers, str):
        name_servers = [name_servers]
    elif name_servers is None:
        name_servers = []
    else:
        # python-whois sometimes returns duplicates with different cases.
        name_servers = sorted({ns.lower() for ns in name_servers if ns})

    return {
        "domain": domain,
        "registrar": record.registrar,
        "creation_date": creation_iso,
        "expiry_date": expiry_iso,
        "age_days": age_days,
        "name_servers": name_servers,
        "status": record.status if not isinstance(record.status, str) else [record.status],
    }


def _first(value):
    """python-whois sometimes returns a list of dates (when registry data differs)."""
    if isinstance(value, list):
        return value[0] if value else None
    return value


def _to_iso(value):
    if isinstance(value, datetime):
        return value.date().isoformat()
    if isinstance(value, date):
        return value.isoformat()
    return None
