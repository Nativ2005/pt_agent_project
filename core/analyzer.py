from __future__ import annotations

import json
from typing import AsyncIterator, Sequence

from core.knowledge import VULN_KNOWLEDGE_BASE
from core.models import BurpRequest, SwaggerEndpoint
from core.ollama_client import OllamaClient
from prompts.system_prompts import RED_TEAMER_PROMPT

_DEFAULT_MODEL = "llama3:latest"


# ---------------------------------------------------------------------------
# Knowledge router
# ---------------------------------------------------------------------------

def _get_knowledge_context(signal: str) -> str:
    """Scan *signal* for trigger keywords and return matched heuristics.

    Each matched entry contributes one block:
        [VulnName]: <heuristic text>

    If nothing matches, returns an empty string so the prompt placeholder
    is left blank rather than filled with noise.
    """
    matched: list[str] = []
    signal_lower = signal.lower()

    for vuln_name, entry in VULN_KNOWLEDGE_BASE.items():
        for keyword in entry["trigger_keywords"]:
            if keyword.lower() in signal_lower:
                matched.append(f"[{vuln_name}]: {entry['heuristic']}")
                break  # one match per vuln is enough

    return "\n\n".join(matched)


# ---------------------------------------------------------------------------
# Traffic serialiser (shared between analyze / analyze_stream)
# ---------------------------------------------------------------------------

def _build_traffic_context(
    burp_requests: Sequence[BurpRequest],
    swagger_endpoints: Sequence[SwaggerEndpoint],
) -> str:
    """Serialise all parsed input into a compact, readable traffic string."""
    sections: list[str] = []

    for i, req in enumerate(burp_requests, start=1):
        lines = [f"### Request {i}: {req.method} {req.host}{req.path}"]
        lines.append(f"Host: {req.host}")
        lines.append(f"Method: {req.method}  Path: {req.path}")

        if req.headers:
            lines.append("Headers:")
            for k, v in req.headers.items():
                lines.append(f"  {k}: {v}")

        if req.body:
            try:
                pretty = json.dumps(json.loads(req.body), indent=2)
                lines.append(f"Body (JSON):\n{pretty}")
            except (json.JSONDecodeError, ValueError):
                lines.append(f"Body:\n{req.body}")
        else:
            lines.append("Body: (empty)")

        sections.append("\n".join(lines))

    if swagger_endpoints:
        ep_lines = [f"### API Surface ({len(swagger_endpoints)} endpoint(s))"]
        for ep in swagger_endpoints:
            params = ", ".join(ep.parameters) if ep.parameters else "none"
            ep_lines.append(
                f"  {ep.method} {ep.full_url}  params=[{params}]"
                + (f"  # {ep.summary}" if ep.summary else "")
            )
        sections.append("\n".join(ep_lines))

    return "\n\n---\n\n".join(sections) if sections else "(no traffic data provided)"


def _build_signal(
    burp_requests: Sequence[BurpRequest],
    swagger_endpoints: Sequence[SwaggerEndpoint],
) -> str:
    """Flatten all observable surfaces into one string for keyword scanning."""
    parts: list[str] = []
    for req in burp_requests:
        parts.append(f"{req.method} {req.path}")
        parts.extend(f"{k}: {v}" for k, v in req.headers.items())
        if req.body:
            parts.append(req.body)
    for ep in swagger_endpoints:
        parts.append(f"{ep.method} {ep.full_url}")
        parts.extend(ep.parameters)
    return "\n".join(parts)


def _build_prompt(
    burp_requests: Sequence[BurpRequest],
    swagger_endpoints: Sequence[SwaggerEndpoint],
) -> str:
    """Return the fully-formatted RED_TEAMER_PROMPT ready for Ollama."""
    signal = _build_signal(burp_requests, swagger_endpoints)
    knowledge_context = _get_knowledge_context(signal)
    traffic_context = _build_traffic_context(burp_requests, swagger_endpoints)
    return RED_TEAMER_PROMPT.format(
        knowledge_context=knowledge_context,
        traffic_context=traffic_context,
    )


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------

class AuraAnalyzer:
    """Orchestrates the full analysis pipeline.

    1. Routes the parsed input through VULN_KNOWLEDGE_BASE to select relevant heuristics.
    2. Formats the RED_TEAMER_PROMPT with {knowledge_context} and {traffic_context}.
    3. Sends the complete prompt to OllamaClient (temperature=0.1 is set in the client).
    """

    def __init__(
        self,
        env: str = "dev",
        model: str = _DEFAULT_MODEL,
        ollama_base_url: str = "http://localhost:11434",
        read_timeout: float = 600.0,
    ) -> None:
        self.env = env
        self._client = OllamaClient(
            model=model,
            base_url=ollama_base_url,
            read_timeout=read_timeout,
        )

    async def analyze(
        self,
        burp_requests: Sequence[BurpRequest] | None = None,
        swagger_endpoints: Sequence[SwaggerEndpoint] | None = None,
    ) -> str:
        """Run the full PT analysis and return a Markdown report string."""
        prompt = _build_prompt(burp_requests or [], swagger_endpoints or [])
        return await self._client.generate_analysis(
            system_prompt="",
            context_data=prompt,
        )

    async def analyze_stream(
        self,
        burp_requests: Sequence[BurpRequest] | None = None,
        swagger_endpoints: Sequence[SwaggerEndpoint] | None = None,
    ) -> AsyncIterator[str]:
        """Stream the PT analysis token-by-token."""
        prompt = _build_prompt(burp_requests or [], swagger_endpoints or [])
        async for token in self._client.generate_analysis_stream(
            system_prompt="",
            context_data=prompt,
        ):
            yield token
