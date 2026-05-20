"""
dns_lookup — ask the internet's address book about a domain.

DNS turns names (`example.com`) into numbers (`93.184.216.34`). This tool
asks DNS for the records that matter for triage:

  - A / AAAA: the IPv4 / IPv6 addresses behind the domain.
  - MX:       the mail servers, if any. No MX often means "no real business".
  - NS:       the nameservers (who is authoritative for this domain).
  - TXT:      free-form records, often used for SPF / DKIM / DMARC and
              ownership verification.

We also note the TTL on the A record. Very short TTLs (under a minute) are
a soft signal — they mean the operator wants to move the IP quickly, which
matters more for phishing than for legitimate sites.
"""
from __future__ import annotations

import dns.resolver
import dns.exception

from ..tool_registry import register_tool
from ._helpers import to_hostname


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
    hostname = to_hostname(hostname)

    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 10

    out: dict = {"hostname": hostname}

    for record_type in ("A", "AAAA", "MX", "NS", "TXT"):
        field = f"{record_type.lower()}_records"
        try:
            answers = resolver.resolve(hostname, record_type)
        except dns.resolver.NXDOMAIN:
            return {"hostname": hostname, "error": "NXDOMAIN — domain does not exist"}
        except dns.resolver.NoAnswer:
            out[field] = []
            continue
        except dns.exception.Timeout:
            out[field] = []
            out.setdefault("timeouts", []).append(record_type)
            continue
        except Exception as exc:
            out[field] = []
            out.setdefault("errors", {})[record_type] = str(exc)
            continue

        if record_type == "MX":
            formatted = []
            for a in answers:
                exchange = a.exchange.to_text().rstrip(".")
                # RFC 7505 "null MX": preference 0 pointing at the root, meaning
                # "this domain explicitly does not receive email".
                if exchange == "":
                    formatted.append("0 . (null MX, no email)")
                else:
                    formatted.append(f"{a.preference} {exchange}")
            out[field] = formatted
        elif record_type == "TXT":
            out[field] = [
                b"".join(a.strings).decode("utf-8", errors="replace") for a in answers
            ]
        elif record_type in ("NS",):
            out[field] = [a.target.to_text().rstrip(".") for a in answers]
        else:
            out[field] = [a.to_text() for a in answers]

        if record_type == "A" and answers.rrset is not None:
            out["a_record_ttl"] = answers.rrset.ttl

    return out
