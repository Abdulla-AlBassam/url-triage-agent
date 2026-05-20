"""
The tool registry.

Think of this as a phone book of tools. Each tool file (in `tools/`) registers
itself here by name, description, and input shape. The agent loop asks the
registry for the list of tools (to show Claude what's available) and asks the
registry to run a tool when Claude calls one.

Why have a registry instead of just a big if/elif?
- New tools plug themselves in just by adding a file and importing it.
- The agent loop never has to be edited to support a new tool.
- Schemas and handlers live next to each other, in one file per tool.
"""
from __future__ import annotations

from typing import Any, Callable


# The phone book. Keys are tool names, values are dicts with the schema + handler.
_TOOLS: dict[str, dict[str, Any]] = {}


def register_tool(
    *, name: str, description: str, input_schema: dict[str, Any]
) -> Callable[[Callable], Callable]:
    """
    Decorator that registers a tool with the registry.

    Each tool file uses this near the top, like:

        @register_tool(
            name="dns_lookup",
            description="Look up DNS records for a hostname.",
            input_schema={...},
        )
        def dns_lookup(hostname: str) -> dict:
            ...
    """

    def decorator(handler: Callable) -> Callable:
        _TOOLS[name] = {
            "name": name,
            "description": description,
            "input_schema": input_schema,
            "handler": handler,
        }
        return handler

    return decorator


def get_tool_schemas() -> list[dict[str, Any]]:
    """
    Return the list of tools in the exact shape the Anthropic API expects.

    This is what we send to Claude so it knows what tools exist and how to call
    each one.
    """
    return [
        {
            "name": t["name"],
            "description": t["description"],
            "input_schema": t["input_schema"],
        }
        for t in _TOOLS.values()
    ]


def dispatch_tool(name: str, tool_input: dict[str, Any]) -> dict[str, Any]:
    """
    Run the named tool with the given input and return its result.

    If the tool name is unknown, or the tool blows up, we return an error dict
    instead of raising. That keeps the agent loop simple: every tool call
    produces *some* result Claude can read.
    """
    if name not in _TOOLS:
        return {"error": f"Unknown tool: {name}"}

    handler = _TOOLS[name]["handler"]
    try:
        return handler(**tool_input)
    except Exception as exc:
        return {"error": f"{type(exc).__name__}: {exc}"}


def list_tool_names() -> list[str]:
    """Used by tests and for debugging."""
    return list(_TOOLS.keys())
