from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Optional

import typer

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


if __name__ == "__main__":
    app()
