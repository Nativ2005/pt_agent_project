from __future__ import annotations

import asyncio
from enum import Enum
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.style import Style

from core.analyzer import AuraAnalyzer
from core.ollama_client import OllamaClient, OllamaConnectionError
from parsers.burp_parser import parse_burp_xml
from parsers.swagger_parser import parse_swagger_file

app = typer.Typer(
    name="aurapt",
    help="AuraPT — air-gapped Web PT CLI powered by local Ollama.",
    rich_markup_mode="rich",
)
console = Console()


class Env(str, Enum):
    dev = "dev"
    prod = "prod"


# ---------------------------------------------------------------------------
# scan command
# ---------------------------------------------------------------------------

@app.command()
def scan(
    env: Env = typer.Option(..., "--env", help="Runtime environment (dev | prod)."),
    burp: Optional[Path] = typer.Option(
        None, "--burp", exists=True, readable=True,
        help="Path to a Burp Suite XML export.",
    ),
    swagger: Optional[Path] = typer.Option(
        None, "--swagger", exists=True, readable=True,
        help="Path to a Swagger / OpenAPI JSON or YAML file.",
    ),
) -> None:
    """Parse Burp XML and/or Swagger input and print a summary."""
    console.print(f"[bold cyan][AuraPT][/bold cyan] env=[yellow]{env.value}[/yellow]")

    if burp is None and swagger is None:
        console.print("[bold red]No input files provided — nothing to do.[/bold red]")
        raise typer.Exit(code=1)

    if burp:
        requests = parse_burp_xml(burp)
        console.print(f"[green]✓[/green] Burp: parsed [bold]{len(requests)}[/bold] request(s) from {burp}")

    if swagger:
        endpoints = parse_swagger_file(swagger)
        console.print(f"[green]✓[/green] Swagger: parsed [bold]{len(endpoints)}[/bold] endpoint(s) from {swagger}")


# ---------------------------------------------------------------------------
# analyze command
# ---------------------------------------------------------------------------

@app.command()
def analyze(
    env: Env = typer.Option(..., "--env", help="Runtime environment (dev | prod)."),
    burp: Optional[Path] = typer.Option(
        None, "--burp", exists=True, readable=True,
        help="Path to a Burp Suite XML export.",
    ),
    swagger: Optional[Path] = typer.Option(
        None, "--swagger", exists=True, readable=True,
        help="Path to a Swagger / OpenAPI JSON or YAML file.",
    ),
    model: str = typer.Option(
        "llama3:latest", "--model",
        help="Local Ollama model to use for analysis.",
    ),
    host: str = typer.Option(
        "http://localhost:11434", "--host",
        help="Ollama base URL (must be localhost for air-gapped operation).",
    ),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o",
        help="Save the Markdown report to this file path.",
    ),
) -> None:
    """Run a full PT analysis via local Ollama and print a Markdown report.

    Parses --burp and/or --swagger inputs, builds a structured context, sends
    it to the local model, and renders the resulting report with rich.
    """
    if burp is None and swagger is None:
        console.print("[bold red]Provide at least one of --burp or --swagger.[/bold red]")
        raise typer.Exit(code=1)

    # Environment banner
    env_style = Style(color="red", bold=True) if env == Env.prod else Style(color="green", bold=True)
    env_label = "PRODUCTION — non-destructive payloads only" if env == Env.prod else "DEVELOPMENT — full scope"
    console.print(Panel(env_label, style=env_style, title="[bold]Environment[/bold]"))

    async def _run() -> str:
        burp_requests = parse_burp_xml(burp) if burp else []
        swagger_endpoints = parse_swagger_file(swagger) if swagger else []

        if burp:
            console.print(
                f"[green]✓[/green] Burp: [bold]{len(burp_requests)}[/bold] request(s) parsed "
                f"([dim]{burp}[/dim])"
            )
        if swagger:
            console.print(
                f"[green]✓[/green] Swagger: [bold]{len(swagger_endpoints)}[/bold] endpoint(s) parsed "
                f"([dim]{swagger}[/dim])"
            )

        analyzer = AuraAnalyzer(env=env.value, model=model, ollama_base_url=host)

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True,
        ) as progress:
            progress.add_task(
                description=f"[cyan]Analysing with [bold]{model}[/bold] — this may take a minute...",
                total=None,
            )
            try:
                report = await analyzer.analyze(
                    burp_requests=burp_requests,
                    swagger_endpoints=swagger_endpoints,
                )
            except OllamaConnectionError as exc:
                console.print(f"\n[bold red]Ollama unreachable:[/bold red] {exc}")
                raise typer.Exit(code=1)

        return report

    report_md = asyncio.run(_run())

    # Render to console
    console.print("\n")
    console.print(Panel("[bold white]AuraPT Analysis Report[/bold white]", style="cyan"))
    console.print(Markdown(report_md))

    # Optionally save to file
    if output:
        output.write_text(report_md, encoding="utf-8")
        console.print(f"\n[green]✓[/green] Report saved to [bold]{output}[/bold]")


# ---------------------------------------------------------------------------
# test-connection command
# ---------------------------------------------------------------------------

@app.command("test-connection")
def test_connection(
    model: str = typer.Option("llama3", "--model", help="Ollama model name to verify."),
    host: str = typer.Option("http://localhost:11434", "--host", help="Ollama base URL."),
) -> None:
    """Verify that the local Ollama daemon is reachable and list available models."""

    async def _run() -> None:
        client = OllamaClient(model=model, base_url=host)

        console.print(f"[cyan][AuraPT][/cyan] Pinging Ollama at [bold]{host}[/bold] ...")
        try:
            info = await client.ping()
            console.print(
                f"[bold green]  ✓ Ollama is UP[/bold green]  "
                f"(version: [yellow]{info.get('version', 'unknown')}[/yellow])"
            )
        except OllamaConnectionError as exc:
            console.print(f"[bold red]  ✗ Ollama is DOWN[/bold red] — {exc}")
            raise typer.Exit(code=1)

        console.print("[cyan][AuraPT][/cyan] Fetching locally available models ...")
        try:
            models = await client.list_models()
        except OllamaConnectionError as exc:
            console.print(f"[yellow]  Could not list models: {exc}[/yellow]")
            return

        if not models:
            console.print("[yellow]  No models found. Run: ollama pull llama3[/yellow]")
        else:
            console.print(f"[cyan]  {len(models)} model(s) available:[/cyan]")
            for m in models:
                marker = "[bold green]*[/bold green]" if m.startswith(model) else " "
                console.print(f"    {marker} {m}")

    asyncio.run(_run())


if __name__ == "__main__":
    app()
