"""
tls_certificate — inspect the site's HTTPS certificate.

Every HTTPS site presents a digital certificate during the handshake. The
certificate has useful metadata for triage:

  - Who issued it (Let's Encrypt, DigiCert, Sectigo, etc.).
  - When it was issued and when it expires.
  - Which hostnames it's valid for (the SAN list).

Signals worth weighing:
  - A self-signed cert on a public site is a red flag.
  - A brand-new Let's Encrypt cert on a brand-new domain claiming to be a
    bank or a software vendor is a very common phishing pattern.
  - A SAN list containing many unrelated brand-imitation names suggests one
    operator running many kits behind the same cert.
"""
from __future__ import annotations

import socket
import ssl
from datetime import date, datetime, timezone

from cryptography import x509
from cryptography.hazmat.backends import default_backend

from ..tool_registry import register_tool
from ._helpers import to_hostname


@register_tool(
    name="tls_certificate",
    description=(
        "Fetch and parse the TLS certificate served by a hostname. Returns "
        "issuer, validity window, age, self-signed flag, and the SAN list "
        "(other hostnames the cert is valid for). Fresh Let's Encrypt certs "
        "on fresh domains are a common phishing pattern."
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
    hostname = to_hostname(hostname)

    try:
        context = ssl.create_default_context()
        # We want to inspect the cert even if it would normally fail validation
        # (self-signed, expired, hostname mismatch are interesting signals).
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                der = ssock.getpeercert(binary_form=True)
    except Exception as exc:
        return {"hostname": hostname, "error": f"TLS handshake failed: {exc}"}

    cert = x509.load_der_x509_certificate(der, default_backend())

    issuer = cert.issuer.rfc4514_string()
    subject = cert.subject.rfc4514_string()

    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san_list = san_ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        san_list = []

    # cryptography 42+ has *_utc variants for timezone-aware datetimes.
    valid_from_dt = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before
    valid_until_dt = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after

    if isinstance(valid_from_dt, datetime) and valid_from_dt.tzinfo is None:
        valid_from_dt = valid_from_dt.replace(tzinfo=timezone.utc)
    if isinstance(valid_until_dt, datetime) and valid_until_dt.tzinfo is None:
        valid_until_dt = valid_until_dt.replace(tzinfo=timezone.utc)

    today = datetime.now(timezone.utc).date()
    age_days = (today - valid_from_dt.date()).days
    expires_in_days = (valid_until_dt.date() - today).days

    return {
        "hostname": hostname,
        "issuer": issuer,
        "subject": subject,
        "valid_from": valid_from_dt.date().isoformat(),
        "valid_until": valid_until_dt.date().isoformat(),
        "age_days": age_days,
        "expires_in_days": expires_in_days,
        "san_list": san_list[:20],
        "san_count": len(san_list),
        "self_signed": cert.issuer == cert.subject,
    }
