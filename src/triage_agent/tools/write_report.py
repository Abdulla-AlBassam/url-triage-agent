"""
write_report — the agent's "I am done" tool.

This is special. The agent loop watches for this tool by name and uses its
arguments as the final verdict. The handler below is never actually called;
it's registered only so the schema exists for Claude to fill in.
"""
from ..tool_registry import register_tool


@register_tool(
    name="write_report",
    description=(
        "Call this once when you have reached a verdict on the URL. "
        "This ends the investigation. Do not call any other tools after this."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "verdict": {
                "type": "string",
                "enum": ["BENIGN", "SUSPICIOUS", "MALICIOUS"],
                "description": "Your final classification of the URL.",
            },
            "confidence": {
                "type": "integer",
                "minimum": 1,
                "maximum": 10,
                "description": (
                    "How confident you are, 1 (a guess) to 10 (near-certain)."
                ),
            },
            "explanation": {
                "type": "string",
                "description": (
                    "Two to four sentences explaining the verdict in plain "
                    "language, for a human reader who hasn't seen the tool calls."
                ),
            },
            "evidence": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "A list of concrete facts you discovered that support the "
                    "verdict. One short item per entry."
                ),
            },
        },
        "required": ["verdict", "confidence", "explanation", "evidence"],
    },
)
def write_report(**kwargs):
    """Never called — the agent loop intercepts this tool to end the run."""
    return kwargs
