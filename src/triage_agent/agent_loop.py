"""
The agent loop. This is the heart of the project.

What the loop does, in plain language:

    1. We give Claude (the AI brain) a URL and a list of tools it can use.
    2. Claude picks a tool and says "call dns_lookup on this hostname".
    3. We run that tool. We hand the result back to Claude.
    4. Claude looks at the result and either picks another tool, or
       calls the special `write_report` tool to end the investigation.
    5. We repeat steps 2-4 until Claude is done, or until we've hit the
       tool-call budget (a safety cap).

That's it. The whole thing is a `while` loop wrapping calls to Claude. No magic.

Why this matters:
- Claude can't run code itself; it can only *ask* us to run code by emitting
  a structured request (a "tool use" block). We do the running and feed the
  result back.
- The loop yields events as it goes (a tool was called, a result came back, a
  verdict was reached). The CLI and the future web UI both consume the same
  event stream.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

from anthropic import Anthropic
from anthropic.types import Message

# Importing the tools package triggers each tool file's @register_tool
# decorator, populating the tool registry. Without this import, the registry
# is empty.
from . import tools  # noqa: F401
from .tool_registry import dispatch_tool, get_tool_schemas


# --- Configuration -----------------------------------------------------------

# Hard cap on tool calls per run. Without this, a confused agent could spin
# forever and burn API credits.
MAX_TOOL_CALLS = 12

# Default model. Sonnet is the workhorse: fast, cheap, very reliable at tool
# use. Override by setting MODEL in your .env file.
DEFAULT_MODEL = os.getenv("MODEL", "claude-sonnet-4-6")

# The system prompt lives in a separate markdown file so it's easy to edit.
SYSTEM_PROMPT_PATH = Path(__file__).parent / "prompts" / "system_prompt.md"


# --- Event type --------------------------------------------------------------


@dataclass
class AgentEvent:
    """
    One thing that happened during a triage run.

    The loop yields these as it works, so the CLI (or web UI) can show
    progress in real time instead of waiting silently.

    `kind` is one of:
      - "start"        — investigation begins
      - "thought"      — Claude said something between tool calls
      - "tool_call"    — Claude asked for a tool to be run
      - "tool_result"  — we ran the tool and got a result back
      - "verdict"      — Claude called write_report; this is the final answer
      - "error"        — something went wrong, or the budget ran out
    """

    kind: str
    data: dict[str, Any]


# --- Internals ---------------------------------------------------------------


def _load_system_prompt() -> str:
    return SYSTEM_PROMPT_PATH.read_text()


def _add_cache_marker(schemas: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Mark the last tool with `cache_control: ephemeral` so Anthropic caches the
    whole tool list (and the system prompt above it) for 5 minutes.

    Why we care:
      Every call inside a single run re-sends the same system prompt and the
      same 11 tool definitions. That's thousands of tokens, every call.
      Without caching, we pay full price for them every time. With caching,
      we pay 10% on cache hits. Across a 10-tool-call run, that's a 70-80%
      saving on input tokens.

    The trick:
      Anthropic's cache marker says "cache everything from the start of the
      request up to and including this block". So we only need to mark the
      *last* tool. Everything before it (system prompt, all earlier tools)
      gets cached too.
    """
    if not schemas:
        return schemas
    out = [dict(s) for s in schemas]  # shallow copy so we don't mutate the registry
    out[-1]["cache_control"] = {"type": "ephemeral"}
    return out


# --- The loop itself ---------------------------------------------------------


def run_triage(url: str, *, model: str | None = None) -> Iterator[AgentEvent]:
    """
    Triage a single URL and yield events as the investigation progresses.

    Usage:

        for event in run_triage("https://example.com"):
            print(event.kind, event.data)

    The function returns when Claude calls `write_report`, when the tool-call
    budget runs out, or when something goes wrong.
    """
    client = Anthropic()  # picks up ANTHROPIC_API_KEY from env automatically
    model = model or DEFAULT_MODEL

    yield AgentEvent("start", {"url": url, "model": model})

    system_prompt = _load_system_prompt()
    tool_schemas = _add_cache_marker(get_tool_schemas())

    # The conversation we're building up with Claude. Each turn appends to it.
    messages: list[dict[str, Any]] = [
        {"role": "user", "content": f"Please triage this URL: {url}"}
    ]

    tool_calls_made = 0

    while tool_calls_made < MAX_TOOL_CALLS:
        # 1. Ask Claude what to do next.
        response: Message = client.messages.create(
            model=model,
            max_tokens=4096,
            system=[
                {
                    "type": "text",
                    "text": system_prompt,
                    "cache_control": {"type": "ephemeral"},
                }
            ],
            tools=tool_schemas,
            messages=messages,
        )

        # 2. Walk through Claude's response. It can mix free-form text
        #    (its reasoning) and tool-use requests in any order.
        assistant_blocks: list[dict[str, Any]] = []
        tool_uses: list[Any] = []

        for block in response.content:
            if block.type == "text":
                if block.text.strip():
                    yield AgentEvent("thought", {"text": block.text})
                assistant_blocks.append({"type": "text", "text": block.text})
            elif block.type == "tool_use":
                tool_uses.append(block)
                assistant_blocks.append(
                    {
                        "type": "tool_use",
                        "id": block.id,
                        "name": block.name,
                        "input": block.input,
                    }
                )

        # The Anthropic API requires us to echo back exactly what Claude said
        # in the assistant turn, before we add tool results in the next user turn.
        messages.append({"role": "assistant", "content": assistant_blocks})

        # 3. Did Claude actually want to use tools?
        if response.stop_reason != "tool_use":
            yield AgentEvent(
                "error",
                {
                    "message": "Agent stopped without producing a verdict.",
                    "stop_reason": response.stop_reason,
                },
            )
            return

        # 4. Run each requested tool and collect the results.
        tool_results: list[dict[str, Any]] = []

        for tu in tool_uses:
            yield AgentEvent(
                "tool_call",
                {"name": tu.name, "input": dict(tu.input), "id": tu.id},
            )

            # write_report is special: it signals the end of the investigation.
            # We never run a handler for it. Its input *is* the final verdict.
            if tu.name == "write_report":
                yield AgentEvent("verdict", dict(tu.input))
                return

            result = dispatch_tool(tu.name, dict(tu.input))
            tool_calls_made += 1

            tool_results.append(
                {
                    "type": "tool_result",
                    "tool_use_id": tu.id,
                    "content": json.dumps(result),
                }
            )
            yield AgentEvent(
                "tool_result",
                {"name": tu.name, "output": result, "id": tu.id},
            )

        # 5. Send all the tool results back to Claude as a single user turn,
        #    then loop and ask Claude what to do next.
        messages.append({"role": "user", "content": tool_results})

    # We exhausted the tool budget. Tell Claude it must verdict from what it has.
    yield AgentEvent(
        "error",
        {
            "message": (
                f"Tool-call budget ({MAX_TOOL_CALLS}) exhausted. "
                "Forcing a verdict from the evidence so far."
            )
        },
    )

    messages.append(
        {
            "role": "user",
            "content": (
                "You have used your tool budget. Call `write_report` now with "
                "the best verdict you can from the evidence gathered so far."
            ),
        }
    )

    final = client.messages.create(
        model=model,
        max_tokens=4096,
        system=[
            {
                "type": "text",
                "text": system_prompt,
                "cache_control": {"type": "ephemeral"},
            }
        ],
        tools=tool_schemas,
        # tool_choice forces Claude to call write_report instead of free-form text.
        tool_choice={"type": "tool", "name": "write_report"},
        messages=messages,
    )

    for block in final.content:
        if block.type == "tool_use" and block.name == "write_report":
            yield AgentEvent("verdict", dict(block.input))
            return

    yield AgentEvent("error", {"message": "Failed to force a final verdict."})
