"""
Small helpers shared between tool files.

The leading underscore tells the rest of the codebase "this is internal,
don't register it as a tool".
"""
from __future__ import annotations

from urllib.parse import urlparse


def to_hostname(value: str) -> str:
    """
    Turn either a full URL or a bare hostname into just the hostname.

        to_hostname("https://example.com/login?x=1")  -> "example.com"
        to_hostname("example.com")                    -> "example.com"
        to_hostname("example.com/path")               -> "example.com"

    The agent sometimes passes a URL where we asked for a hostname (or vice
    versa). This lets every tool defensively normalise.
    """
    if "://" in value:
        parsed = urlparse(value)
        return parsed.hostname or value
    return value.split("/")[0].split("?")[0]
