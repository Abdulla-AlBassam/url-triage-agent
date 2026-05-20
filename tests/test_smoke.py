"""
Smoke tests — quick checks that the scaffolding is sound.

These don't hit the Anthropic API. They just verify the project's plumbing
is wired up correctly: every tool registers itself, every tool's schema is
JSON-serialisable, dispatch works, and the system prompt loads.
"""
import json

import pytest


EXPECTED_TOOLS = {
    "brand_impersonation",
    "dns_lookup",
    "favicon_hasher",
    "ioc_extractor",
    "sandbox_fetch",
    "tls_certificate",
    "urlhaus_lookup",
    "urlscan_lookup",
    "virustotal_lookup",
    "whois_lookup",
    "write_report",
}


def test_all_eleven_tools_register():
    import triage_agent.tools  # noqa: F401 - registers tools
    from triage_agent.tool_registry import list_tool_names

    names = set(list_tool_names())
    assert names == EXPECTED_TOOLS, (
        f"Missing: {EXPECTED_TOOLS - names}; Extra: {names - EXPECTED_TOOLS}"
    )


def test_schemas_are_valid_json():
    import triage_agent.tools  # noqa: F401
    from triage_agent.tool_registry import get_tool_schemas

    # If any schema has a non-JSON-serialisable value, this will raise.
    json.dumps(get_tool_schemas())


def test_dispatch_unknown_tool_returns_error():
    import triage_agent.tools  # noqa: F401
    from triage_agent.tool_registry import dispatch_tool

    result = dispatch_tool("not_a_real_tool", {})
    assert "error" in result


def test_dispatch_real_tool_runs_handler():
    import triage_agent.tools  # noqa: F401
    from triage_agent.tool_registry import dispatch_tool

    result = dispatch_tool("dns_lookup", {"hostname": "example.com"})
    assert "hostname" in result
    assert result["hostname"] == "example.com"


def test_system_prompt_loads():
    from triage_agent.agent_loop import _load_system_prompt

    text = _load_system_prompt()
    assert "SOC" in text
    assert "write_report" in text


def test_write_report_schema_has_all_required_fields():
    import triage_agent.tools  # noqa: F401
    from triage_agent.tool_registry import get_tool_schemas

    schema = next(s for s in get_tool_schemas() if s["name"] == "write_report")
    required = set(schema["input_schema"]["required"])
    assert required == {"verdict", "confidence", "explanation", "evidence"}
