"""
dns_lookup — ask the internet's address book about a domain.

DNS is how human-readable names (`example.com`) get turned into the numeric
addresses (`93.184.216.34`) that computers actually use to talk to each other.
This tool queries that system and returns the records.

What we look at:
  - A / AAAA records: the IPv4 and IPv6 addresses behind the domain.
  - MX records:       the mail servers, if any.
  - NS records:       the nameservers (who is *authoritative* for this domain).
  - TXT records:      free-form text records, often used for SPF/DKIM/DMARC and
                      ownership verification (e.g. Google site verification).

This is a STUB for now. The real implementation lands on day 1 part 2.
"""
from ..tool_registry import register_tool


@register_tool(
    name="dns_lookup",
    description=(
        "Look up DNS records (A, AAAA, MX, NS, TXT) for a hostname. "
        "A fresh domain with a single A record, no MX, and short TTLs is "
        "suspicious. Legitimate sites tend to have CDN-backed records and "
        "proper mail infrastructure."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "hostname": {
                "type": "string",
                "description": "The hostname to look up, e.g. 'example.com'.",
            }
        },
        "required": ["hostname"],
    },
)
def dns_lookup(hostname: str) -> dict:
    return {
        "_stub": True,
        "hostname": hostname,
        "a_records": ["93.184.216.34"],
        "aaaa_records": [],
        "mx_records": [],
        "ns_records": ["a.iana-servers.net", "b.iana-servers.net"],
        "txt_records": [],
        "note": "Stub data. Real DNS lookup lands in the next pass.",
    }
