from __future__ import annotations

import asyncio
from enum import Enum
from pathlib import Path
from typing import Optional

import typer

from core.ollama_client import OllamaClient, OllamaConnectionError
from parsers.burp_parser import parse_burp_xml
from parsers.swagger_parser import parse_swagger_file

app = typer.Typer(name="aurapt", help="AuraPT – air-gapped Web PT CLI powered by local Ollama.")


class Env(str, Enum):
    dev = "dev"
    prod = "prod"


@app.command()
def scan(
    env: Env = typer.Option(..., "--env", help="Runtime environment (dev | prod)."),
    burp: Optional[Path] = typer.Option(
        None,
        "--burp",
        exists=True,
        readable=True,
        help="Path to a Burp Suite XML export.",
    ),
    swagger: Optional[Path] = typer.Option(
        None,
        "--swagger",
        exists=True,
        readable=True,
        help="Path to a Swagger / OpenAPI JSON or YAML file.",
    ),
) -> None:
    """Parse Burp XML and/or Swagger input then run PT analysis via Ollama."""
    typer.echo(f"[AuraPT] env={env.value}")

    if burp is None and swagger is None:
        typer.echo("No input files provided — nothing to do.", err=True)
        raise typer.Exit(code=1)

    if burp:
        requests = parse_burp_xml(burp)
        typer.echo(f"[burp] parsed {len(requests)} request(s) from {burp}")

    if swagger:
        endpoints = parse_swagger_file(swagger)
        typer.echo(f"[swagger] parsed {len(endpoints)} endpoint(s) from {swagger}")


@app.command("test-connection")
def test_connection(
    model: str = typer.Option("llama3", "--model", help="Ollama model name to verify."),
    host: str = typer.Option("http://localhost:11434", "--host", help="Ollama base URL."),
) -> None:
    """Verify that the local Ollama daemon is reachable and list available models."""

    async def _run() -> None:
        client = OllamaClient(model=model, base_url=host)

        typer.echo(f"[AuraPT] Pinging Ollama at {host} ...")
        try:
            info = await client.ping()
            typer.echo(
                typer.style(
                    f"  Ollama is UP  (version: {info.get('version', 'unknown')})",
                    fg=typer.colors.GREEN,
                    bold=True,
                )
            )
        except OllamaConnectionError as exc:
            typer.echo(
                typer.style(f"  Ollama is DOWN — {exc}", fg=typer.colors.RED, bold=True),
                err=True,
            )
            raise typer.Exit(code=1)

        typer.echo("[AuraPT] Fetching locally available models ...")
        try:
            models = await client.list_models()
        except OllamaConnectionError as exc:
            typer.echo(typer.style(f"  Could not list models: {exc}", fg=typer.colors.YELLOW))
            return

        if not models:
            typer.echo(
                typer.style(
                    "  No models found. Run: ollama pull llama3",
                    fg=typer.colors.YELLOW,
                )
            )
        else:
            typer.echo(typer.style(f"  {len(models)} model(s) available:", fg=typer.colors.CYAN))
            for m in models:
                marker = " *" if m.startswith(model) else "  "
                typer.echo(f"   {marker} {m}")

    asyncio.run(_run())


if __name__ == "__main__":
    app()
