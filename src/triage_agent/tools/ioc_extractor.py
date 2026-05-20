"""
ioc_extractor — pull suspicious patterns out of a blob of text.

"IOC" stands for Indicator of Compromise. In security, it's any atomic piece
of evidence: an IP address, a domain, a URL, a file hash, an email address, a
Bitcoin wallet. A single phishing page often contains references to *other*
malicious infrastructure (the page posts credentials to a different domain,
loads a script from yet another, asks for payment to a wallet, etc.).

This tool uses regular expressions to scan a chunk of text and pull every IOC
it finds. The agent then decides which ones are worth investigating further.

Regex (not an LLM) is the right tool here: it's fast, deterministic, never
hallucinates an IOC that wasn't there, and is free to run.

This is a STUB for now.
"""
from ..tool_registry import register_tool


@register_tool(
    name="ioc_extractor",
    description=(
        "Extract indicators of compromise (URLs, IPs, hashes, emails, "
        "Bitcoin wallets) from a chunk of text. Useful for finding the "
        "secondary infrastructure that a phishing page references."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "text": {
                "type": "string",
                "description": (
                    "The text to scan, usually the DOM or visible text from "
                    "a sandbox_fetch result."
                ),
            }
        },
        "required": ["text"],
    },
)
def ioc_extractor(text: str) -> dict:
    return {
        "_stub": True,
        "input_length": len(text),
        "urls": [],
        "ipv4_addresses": [],
        "emails": [],
        "md5_hashes": [],
        "sha256_hashes": [],
        "bitcoin_addresses": [],
        "note": "Stub data. Real regex extractor lands in the next pass.",
    }
