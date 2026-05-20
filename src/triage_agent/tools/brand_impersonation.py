"""
brand_impersonation — is this page pretending to be a known brand?

Most phishing pages impersonate something: Microsoft, your bank, DHL, the
post office, a tax agency. They reproduce the look and feel and ask you to
"log in" or "verify" your details. The credentials then go to the attacker.

Detecting impersonation is mostly about heuristics on the rendered page:

  - Brand strings ("Microsoft", "Lloyds", "DHL") appearing prominently on a
    domain whose registered name has nothing to do with that brand.
  - A login form (password input) on a freshly-registered domain.
  - A form whose action URL posts credentials to a different domain than
    the one the user is on.
  - Pixel-similarity between the page's logo and a known brand's logo.

This tool consumes the output of `sandbox_fetch` (the rendered DOM and
screenshot) and runs the heuristics over it.

This is a STUB for now.
"""
from ..tool_registry import register_tool


@register_tool(
    name="brand_impersonation",
    description=(
        "Analyse a rendered page for signs of brand impersonation: brand "
        "strings on unrelated domains, credential forms posting cross-domain, "
        "login UI on freshly-registered domains. Use after sandbox_fetch."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "hostname": {
                "type": "string",
                "description": "The hostname the page is served from.",
            },
            "visible_text": {
                "type": "string",
                "description": "Visible text from the rendered page.",
            },
            "form_actions": {
                "type": "array",
                "items": {"type": "string"},
                "description": "List of URLs that forms on the page submit to.",
            },
        },
        "required": ["hostname", "visible_text"],
    },
)
def brand_impersonation(
    hostname: str, visible_text: str, form_actions: list[str] | None = None
) -> dict:
    return {
        "_stub": True,
        "hostname": hostname,
        "brands_mentioned": [],
        "credential_form_present": False,
        "cross_domain_form_post": False,
        "impersonation_score": 0,
        "note": "Stub data. Real heuristics land in the next pass.",
    }
