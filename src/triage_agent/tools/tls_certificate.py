"""
tls_certificate — inspect the site's HTTPS certificate.

When a browser connects to an HTTPS site, the site presents a digital
certificate proving "I am who I say I am." That certificate contains useful
metadata for triage:

  - Who issued it (Let's Encrypt, DigiCert, Sectigo, etc.).
  - When it was issued and when it expires.
  - Which hostnames it's valid for (the SAN list, often a clue to other
    domains the same operator runs).

Signals we care about:
  - A self-signed cert on a public site is a red flag.
  - A brand-new Let's Encrypt cert on a brand-new domain claiming to be a bank
    is a very common phishing pattern.
  - A SAN list containing many unrelated brand-impersonation names is a
    huge red flag (the operator is running multiple kits off one cert).

This is a STUB for now.
"""
from ..tool_registry import register_tool


@register_tool(
    name="tls_certificate",
    description=(
        "Fetch and parse the TLS certificate served by a hostname. Returns the "
        "issuer, validity window, age, and the SAN list (other hostnames the "
        "cert is valid for). Fresh Let's Encrypt certs on fresh domains are a "
        "common phishing signature."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "hostname": {
                "type": "string",
                "description": "The hostname to connect to over HTTPS.",
            }
        },
        "required": ["hostname"],
    },
)
def tls_certificate(hostname: str) -> dict:
    return {
        "_stub": True,
        "hostname": hostname,
        "issuer": "DigiCert Global G2",
        "valid_from": "2024-01-01",
        "valid_until": "2025-01-01",
        "age_days": 200,
        "san_list": [hostname, f"www.{hostname}"],
        "self_signed": False,
        "note": "Stub data. Real TLS inspection lands in the next pass.",
    }
