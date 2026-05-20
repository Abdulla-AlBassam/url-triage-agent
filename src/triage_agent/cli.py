"""
The command-line interface.

After running `uv sync`, you can use this from the terminal:

    uv run triage https://example.com

It loads your keys from .env, runs the agent loop, prints each step to the
terminal with nice colours, and saves the final verdict to `reports/`.
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

import typer
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule

from .agent_loop import run_triage


# Load .env so ANTHROPIC_API_KEY (and friends) are available to the SDK.
load_dotenv()

app = typer.Typer(
    help="URL Triage Agent — investigate web links automatically.",
    no_args_is_help=True,
)
console = Console()


# Colours for verdict labels. Green / yellow / red, the universal traffic light.
VERDICT_COLOURS = {
    "BENIGN": "green",
    "SUSPICIOUS": "yellow",
    "MALICIOUS": "red",
}


@app.command()
def run(
    url: str = typer.Argument(..., help="The URL to triage."),
    model: str = typer.Option(
        None,
        "--model",
        "-m",
        help="Override the Claude model (e.g. claude-opus-4-7).",
    ),
) -> None:
    """Triage a single URL."""
    console.print(Panel.fit(f"[bold]Triaging[/bold] {url}", title="URL Triage Agent"))

    verdict: dict[str, Any] | None = None

    for event in run_triage(url, model=model):
        if event.kind == "start":
            console.print(f"[dim]Using model: {event.data['model']}[/dim]\n")

        elif event.kind == "thought":
            console.print(f"[italic cyan]{event.data['text']}[/italic cyan]\n")

        elif event.kind == "tool_call":
            console.print(
                f"[yellow]→[/yellow] [bold]{event.data['name']}[/bold] "
                f"[dim]{event.data['input']}[/dim]"
            )

        elif event.kind == "tool_result":
            output = event.data["output"]
            # Truncate huge outputs so the terminal stays readable.
            preview = json.dumps(output, indent=2, default=str)
            if len(preview) > 500:
                preview = preview[:500] + "\n[truncated]"
            console.print(f"[green]✓[/green] [dim]{preview}[/dim]\n")

        elif event.kind == "verdict":
            verdict = event.data

        elif event.kind == "error":
            console.print(f"[red]![/red] {event.data['message']}")

    console.print(Rule())

    if verdict is None:
        console.print("[red]No verdict produced.[/red]")
        raise typer.Exit(code=1)

    _print_verdict(verdict)
    saved = _save_report(url, verdict)
    console.print(f"\n[dim]Saved to {saved}[/dim]")


def _print_verdict(v: dict[str, Any]) -> None:
    label = v.get("verdict", "UNKNOWN")
    colour = VERDICT_COLOURS.get(label, "white")
    body_lines = [
        f"[bold {colour}]{label}[/bold {colour}]",
        f"[dim]Confidence:[/dim] {v.get('confidence', '?')}/10",
        "",
        v.get("explanation", ""),
    ]
    evidence = v.get("evidence") or []
    if evidence:
        body_lines.append("")
        body_lines.append("[bold]Evidence[/bold]")
        for item in evidence:
            body_lines.append(f"  • {item}")
    console.print(Panel("\n".join(body_lines), title="Verdict", border_style=colour))


def _save_report(url: str, verdict: dict[str, Any]) -> Path:
    """Persist the verdict to reports/ as JSON. Markdown export comes in day 2."""
    reports_dir = Path("reports")
    reports_dir.mkdir(exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    safe = (
        url.replace("https://", "")
        .replace("http://", "")
        .replace("/", "_")
        .replace(":", "_")[:60]
    )
    path = reports_dir / f"{timestamp}_{safe}.json"
    path.write_text(json.dumps({"url": url, **verdict}, indent=2))
    return path


if __name__ == "__main__":
    app()
