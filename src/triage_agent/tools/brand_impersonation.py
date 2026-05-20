"""
brand_impersonation — is this page pretending to be a known brand?

Most phishing pages impersonate someone: Microsoft, your bank, the post
office, a tax agency. The kit reproduces the look and feel and asks the
victim to "sign in" or "verify". The credentials go to the attacker.

This tool scores the impersonation likelihood from 0 to 10 using four
signals on the rendered page (which `sandbox_fetch` produces):

  1. Brand names mentioned in the visible text that don't match the page's
     own registered domain. "Microsoft" on `microsoftonline.com` is fine.
     "Microsoft" on `verify-account-update.help` is not.

  2. A password input field on the page. By itself this is benign (every
     login page has one) but combined with off-brand mentions it's a strong
     phishing tell.

  3. A form whose `action` attribute posts to a different host than the
     page itself. Legitimate login pages post back to the same domain.
     Cross-domain form posts are a classic credential-exfil pattern.

  4. Login / verification phrases in the page text. Phishing kits lean
     heavily on a small set of phrases ("verify your identity", "your
     account has been suspended", etc.).

The brand list is curated, not exhaustive. We catch the long tail by
relying on the agent to read the page text and the impersonation findings
together. The score is a hint, not a verdict.

eTLD+1 note: we use a small allowlist of multi-label public suffixes
(`co.uk`, `gov.uk`, ...) rather than the full Public Suffix List. For a
2-day portfolio project this is precise enough; for production we'd swap
in `tldextract`.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

from ..tool_registry import register_tool
from ._helpers import to_hostname


# Brands phishing kits target most often. Format:
#   { brand_label: {"domains": [...legitimate eTLD+1s...], "aliases": [...]} }
KNOWN_BRANDS: dict[str, dict] = {
    "Microsoft":         {"domains": ["microsoft.com", "office.com", "microsoftonline.com", "live.com", "outlook.com"], "aliases": ["office 365", "office365", "outlook", "onedrive", "sharepoint"]},
    "Apple":             {"domains": ["apple.com", "icloud.com"],                                                    "aliases": ["apple id", "icloud"]},
    "Google":            {"domains": ["google.com", "gmail.com", "googlemail.com"],                                  "aliases": ["gmail", "google drive", "google account"]},
    "Amazon":            {"domains": ["amazon.com", "amazon.co.uk", "amazonaws.com"],                                "aliases": []},
    "PayPal":            {"domains": ["paypal.com"],                                                                 "aliases": []},
    "Netflix":           {"domains": ["netflix.com"],                                                                "aliases": []},
    "DHL":               {"domains": ["dhl.com"],                                                                    "aliases": []},
    "FedEx":             {"domains": ["fedex.com"],                                                                  "aliases": []},
    "UPS":               {"domains": ["ups.com"],                                                                    "aliases": ["united parcel service"]},
    "USPS":              {"domains": ["usps.com"],                                                                   "aliases": ["united states postal"]},
    "Royal Mail":        {"domains": ["royalmail.com"],                                                              "aliases": ["royal mail"]},
    "HMRC":              {"domains": ["hmrc.gov.uk", "gov.uk"],                                                      "aliases": ["her majesty's revenue", "his majesty's revenue"]},
    "IRS":               {"domains": ["irs.gov"],                                                                    "aliases": ["internal revenue service"]},
    "Lloyds":            {"domains": ["lloydsbank.com"],                                                             "aliases": ["lloyds bank"]},
    "Barclays":          {"domains": ["barclays.co.uk", "barclays.com"],                                             "aliases": []},
    "HSBC":              {"domains": ["hsbc.com", "hsbc.co.uk"],                                                     "aliases": []},
    "NatWest":           {"domains": ["natwest.com"],                                                                "aliases": []},
    "Chase":             {"domains": ["chase.com"],                                                                  "aliases": ["chase bank"]},
    "Bank of America":   {"domains": ["bankofamerica.com"],                                                          "aliases": ["bofa"]},
    "Wells Fargo":       {"domains": ["wellsfargo.com"],                                                             "aliases": []},
    "Coinbase":          {"domains": ["coinbase.com"],                                                                "aliases": []},
    "Binance":           {"domains": ["binance.com"],                                                                "aliases": []},
    "Spotify":           {"domains": ["spotify.com"],                                                                "aliases": []},
    "Facebook":          {"domains": ["facebook.com"],                                                                "aliases": []},
    "Instagram":         {"domains": ["instagram.com"],                                                              "aliases": []},
    "WhatsApp":          {"domains": ["whatsapp.com"],                                                               "aliases": []},
    "LinkedIn":          {"domains": ["linkedin.com"],                                                               "aliases": []},
    "GitHub":            {"domains": ["github.com"],                                                                 "aliases": []},
    "Dropbox":           {"domains": ["dropbox.com"],                                                                "aliases": []},
    "Adobe":             {"domains": ["adobe.com"],                                                                  "aliases": []},
    "DocuSign":          {"domains": ["docusign.com"],                                                               "aliases": []},
    "Steam":             {"domains": ["steampowered.com", "steamcommunity.com"],                                     "aliases": ["steam community"]},
    "TikTok":            {"domains": ["tiktok.com"],                                                                 "aliases": ["tiktok shop"]},
    "eBay":              {"domains": ["ebay.com", "ebay.co.uk"],                                                     "aliases": []},
    "Walmart":           {"domains": ["walmart.com"],                                                                "aliases": []},
    "Shopify":           {"domains": ["shopify.com"],                                                                "aliases": []},
    "Disney+":           {"domains": ["disneyplus.com"],                                                             "aliases": ["disney plus", "disneyplus"]},
    "Roblox":            {"domains": ["roblox.com"],                                                                 "aliases": []},
}


MULTI_LABEL_SUFFIXES = {
    "co.uk", "co.jp", "com.au", "com.br", "co.in",
    "gov.uk", "ac.uk", "org.uk", "net.uk", "nhs.uk",
}


# Phrases that appear on login / "verify your identity" pages. Individually
# weak; collectively (and combined with off-brand mentions) they're a tell.
LOGIN_PHRASES = [
    "sign in", "log in", "login", "signin",
    "verify your account", "verify your identity",
    "confirm your identity", "confirm your account",
    "update your password", "reset your password",
    "your account has been suspended", "account has been locked",
    "two-factor", "two factor", "2fa",
    "verification code", "one-time code", "one time code",
    "secure your account",
]


def _etld_plus_one(host: str) -> str:
    """Pull the registered name (eTLD+1) out of a hostname.

    `mail.example.co.uk` -> `example.co.uk`
    `verify.microsoft.fake.help` -> `fake.help`
    """
    if not host:
        return ""
    host = host.lower().rstrip(".")
    parts = host.split(".")
    if len(parts) >= 3:
        last_two = ".".join(parts[-2:])
        if last_two in MULTI_LABEL_SUFFIXES:
            return ".".join(parts[-3:])
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


def _brand_text_hits(text: str, brand: str, aliases: list[str]) -> list[str]:
    """Word-boundary, case-insensitive matches for the brand label and its aliases."""
    if not text:
        return []
    hits: list[str] = []
    for candidate in (brand, *aliases):
        if not candidate:
            continue
        pattern = r"\b" + re.escape(candidate) + r"\b"
        if re.search(pattern, text, flags=re.IGNORECASE):
            hits.append(candidate)
    return hits


@register_tool(
    name="brand_impersonation",
    description=(
        "Analyse a rendered page for brand-impersonation tells. Scores 0-10 "
        "based on: brand names on unrelated domains, password input fields, "
        "cross-domain form submissions, and login/verification phrases. Feed "
        "it the relevant fields from sandbox_fetch's output."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "hostname": {
                "type": "string",
                "description": "The final hostname (after any redirects) the page is served from.",
            },
            "visible_text": {
                "type": "string",
                "description": "Visible text extracted from the rendered page (truncated is fine).",
            },
            "form_actions": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "List of form action URLs (or bare hostnames). Pass the "
                    "'form_action_hosts' field from sandbox_fetch, or extract "
                    "from 'forms'."
                ),
                "default": [],
            },
            "password_input_present": {
                "type": "boolean",
                "description": "True if the page has at least one <input type=password>.",
                "default": False,
            },
        },
        "required": ["hostname", "visible_text"],
    },
)
def brand_impersonation(
    hostname: str,
    visible_text: str,
    form_actions: list[str] | None = None,
    password_input_present: bool = False,
) -> dict:
    hostname = to_hostname(hostname)
    page_etld = _etld_plus_one(hostname)

    brands_mentioned: list[dict] = []
    findings: list[str] = []
    off_brand_count = 0

    for brand, info in KNOWN_BRANDS.items():
        hits = _brand_text_hits(visible_text or "", brand, info.get("aliases", []))
        if not hits:
            continue
        canonical_etlds = {_etld_plus_one(d) for d in info.get("domains", [])}
        on_brand_domain = page_etld in canonical_etlds and bool(page_etld)
        brands_mentioned.append({
            "brand": brand,
            "hits": hits[:5],
            "on_brand_domain": on_brand_domain,
        })
        if not on_brand_domain:
            off_brand_count += 1
            findings.append(
                f"'{brand}' mentioned on unrelated domain "
                f"(page eTLD+1: {page_etld or 'unknown'})"
            )

    # Form-action cross-domain analysis.
    distinct_action_hosts: list[str] = []
    cross_domain = False
    for raw in form_actions or []:
        if not raw:
            continue
        action_host = raw if "://" not in raw else (urlparse(raw).hostname or "")
        action_host = (action_host or "").lower()
        if not action_host:
            continue
        if action_host not in distinct_action_hosts:
            distinct_action_hosts.append(action_host)
        if _etld_plus_one(action_host) and _etld_plus_one(action_host) != page_etld:
            cross_domain = True

    if cross_domain:
        findings.append(
            f"Form posts cross-domain (page on {page_etld or 'unknown'}, "
            f"actions on {distinct_action_hosts})"
        )

    # Login-phrase tells.
    text_lower = (visible_text or "").lower()
    login_phrase_hits = [p for p in LOGIN_PHRASES if p in text_lower]

    if password_input_present:
        findings.append("Page contains a password input field")
    if login_phrase_hits:
        findings.append(
            f"Login/verification phrases on page: {login_phrase_hits[:4]}"
        )

    # Score (0-10). The weights are deliberately conservative; the agent
    # cross-references with WHOIS age, threat-intel, etc.
    score = 0
    if off_brand_count >= 1:
        score += 4
    if off_brand_count >= 2:
        score += 1
    if password_input_present:
        score += 2
    if cross_domain:
        score += 3
    if login_phrase_hits and off_brand_count >= 1:
        score += 1
    score = min(score, 10)

    return {
        "hostname": hostname,
        "page_etld_plus_one": page_etld,
        "brands_mentioned": brands_mentioned,
        "off_brand_mentions": off_brand_count,
        "password_input_present": password_input_present,
        "cross_domain_form_post": cross_domain,
        "form_action_hosts": distinct_action_hosts,
        "login_phrase_hits": login_phrase_hits,
        "impersonation_score": score,
        "findings": findings,
    }
