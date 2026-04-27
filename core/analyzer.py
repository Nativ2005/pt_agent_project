from __future__ import annotations

import json
from typing import Sequence

from core.models import BurpRequest, SwaggerEndpoint
from core.ollama_client import OllamaClient
from prompts.system_prompts import get_system_prompt

_DEFAULT_MODEL = "llama3:latest"


class AuraAnalyzer:
    """Orchestrates the full analysis pipeline.

    Takes parsed Pydantic objects, serialises them into a structured context
    string, and sends everything to the local Ollama model via OllamaClient.
    """

    def __init__(
        self,
        env: str = "dev",
        model: str = _DEFAULT_MODEL,
        ollama_base_url: str = "http://localhost:11434",
    ) -> None:
        self.env = env
        self._client = OllamaClient(model=model, base_url=ollama_base_url)
        self._system_prompt = get_system_prompt(env)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def analyze(
        self,
        burp_requests: Sequence[BurpRequest] | None = None,
        swagger_endpoints: Sequence[SwaggerEndpoint] | None = None,
    ) -> str:
        """Run the full PT analysis and return a Markdown report.

        Args:
            burp_requests:     Parsed Burp Suite requests.
            swagger_endpoints: Parsed Swagger / OpenAPI endpoints.

        Returns:
            Markdown-formatted penetration testing report.
        """
        context = self._build_context(burp_requests or [], swagger_endpoints or [])
        return await self._client.generate_analysis(
            system_prompt=self._system_prompt,
            context_data=context,
        )

    # ------------------------------------------------------------------
    # Context serialisation
    # ------------------------------------------------------------------

    def _build_context(
        self,
        burp_requests: Sequence[BurpRequest],
        swagger_endpoints: Sequence[SwaggerEndpoint],
    ) -> str:
        sections: list[str] = []

        sections.append(f"# AuraPT Analysis Context\n\nEnvironment: **{self.env.upper()}**")

        if burp_requests:
            sections.append(self._format_burp_section(burp_requests))

        if swagger_endpoints:
            sections.append(self._format_swagger_section(swagger_endpoints))

        if not burp_requests and not swagger_endpoints:
            sections.append("_No input data provided._")

        return "\n\n---\n\n".join(sections)

    @staticmethod
    def _format_burp_section(requests: Sequence[BurpRequest]) -> str:
        lines: list[str] = [
            f"## Captured HTTP Requests (Burp Suite) — {len(requests)} request(s)\n"
        ]
        for i, req in enumerate(requests, start=1):
            lines.append(f"### Request {i}: {req.method} {req.host}{req.path}")
            lines.append(f"- **Host:** `{req.host}`")
            lines.append(f"- **Method:** `{req.method}`")
            lines.append(f"- **Path:** `{req.path}`")

            if req.headers:
                lines.append("- **Headers:**")
                for k, v in req.headers.items():
                    lines.append(f"  - `{k}: {v}`")

            if req.body:
                # Try to pretty-print JSON bodies for readability.
                try:
                    pretty = json.dumps(json.loads(req.body), indent=2)
                    lines.append(f"- **Body (JSON):**\n```json\n{pretty}\n```")
                except (json.JSONDecodeError, ValueError):
                    lines.append(f"- **Body:**\n```\n{req.body}\n```")
            else:
                lines.append("- **Body:** _(empty)_")

            lines.append("")  # blank line between requests

        return "\n".join(lines)

    @staticmethod
    def _format_swagger_section(endpoints: Sequence[SwaggerEndpoint]) -> str:
        lines: list[str] = [
            f"## API Surface (Swagger / OpenAPI) — {len(endpoints)} endpoint(s)\n",
            "| Method | Full URL | Parameters | Operation ID | Summary |",
            "|--------|----------|------------|--------------|---------|",
        ]
        for ep in endpoints:
            params = ", ".join(f"`{p}`" for p in ep.parameters) if ep.parameters else "—"
            op_id = ep.operation_id or "—"
            summary = (ep.summary or "—").replace("|", "\\|")
            lines.append(
                f"| `{ep.method}` | `{ep.full_url}` | {params} | {op_id} | {summary} |"
            )
        return "\n".join(lines)
