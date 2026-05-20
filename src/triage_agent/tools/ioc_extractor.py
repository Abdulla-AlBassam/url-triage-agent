"""
ioc_extractor — pull suspicious patterns out of a blob of text.

"IOC" is Indicator of Compromise: any atomic piece of evidence used in
threat intel. A single phishing page often references other malicious
infrastructure (it posts credentials to a different domain, loads a script
from yet another, asks for payment to a wallet).

This tool uses regular expressions on raw text. Regex is the right tool here:
fast, deterministic, never invents an IOC, and free to run.

We extract:
  - URLs (http/https/www).
  - IPv4 addresses (loose validation, false positives are easy to filter).
  - Emails.
  - MD5 (32-hex), SHA1 (40-hex), SHA256 (64-hex) hashes.
  - Bitcoin addresses (legacy 1*/3* and bech32 bc1*).
"""
from __future__ import annotations

import re

from ..tool_registry import register_tool


# A URL must start with http(s)://, then have at least one dot in the hostname.
_URL_PATTERN = re.compile(
    r"https?://[a-zA-Z0-9.\-]+(?:\.[a-zA-Z]{2,})+(?:[/?#][^\s\"'<>]*)?",
    re.IGNORECASE,
)

# IPv4: four 1-3 digit octets. Loose: doesn't enforce <=255 per octet.
_IPV4_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

_EMAIL_PATTERN = re.compile(
    r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"
)

# Word-boundary anchored. \b{N}\b will not match a substring inside a longer
# hex run, so MD5 (32), SHA1 (40), SHA256 (64) don't collide.
_MD5_PATTERN = re.compile(r"\b[a-fA-F0-9]{32}\b")
_SHA1_PATTERN = re.compile(r"\b[a-fA-F0-9]{40}\b")
_SHA256_PATTERN = re.compile(r"\b[a-fA-F0-9]{64}\b")

# Bitcoin: legacy P2PKH/P2SH (1.../3...) or bech32 (bc1...).
_BTC_PATTERN = re.compile(
    r"\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[ac-hj-np-z02-9]{6,87})\b"
)

# Cap how many of each kind we return so a giant page doesn't drown the agent.
_MAX_PER_KIND = 50


@register_tool(
    name="ioc_extractor",
    description=(
        "Extract indicators of compromise (URLs, IPs, emails, MD5/SHA1/SHA256 "
        "hashes, Bitcoin wallets) from a chunk of text. Useful for finding "
        "secondary infrastructure that a phishing page references."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "text": {
                "type": "string",
                "description": (
                    "The text to scan, usually the DOM or visible text from a "
                    "sandbox_fetch result."
                ),
            }
        },
        "required": ["text"],
    },
)
def ioc_extractor(text: str) -> dict:
    if not text:
        return {"input_length": 0}

    def _grab(pattern: re.Pattern) -> list[str]:
        return sorted({m for m in pattern.findall(text)})[:_MAX_PER_KIND]

    return {
        "input_length": len(text),
        "urls": _grab(_URL_PATTERN),
        "ipv4_addresses": _grab(_IPV4_PATTERN),
        "emails": _grab(_EMAIL_PATTERN),
        "md5_hashes": _grab(_MD5_PATTERN),
        "sha1_hashes": _grab(_SHA1_PATTERN),
        "sha256_hashes": _grab(_SHA256_PATTERN),
        "bitcoin_addresses": _grab(_BTC_PATTERN),
    }
