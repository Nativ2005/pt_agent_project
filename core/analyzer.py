from __future__ import annotations

import json
import re
from typing import AsyncIterator, Sequence

from core.knowledge import VULN_KNOWLEDGE_BASE, VulnEntry, format_for_prompt
from core.models import BurpRequest, SwaggerEndpoint
from core.ollama_client import OllamaClient
from prompts.system_prompts import get_system_prompt

_DEFAULT_MODEL = "llama3:latest"

# ---------------------------------------------------------------------------
# Signal map — maps vuln IDs to compiled regex patterns.
#
# The router runs every pattern against the combined signal string built from
# a request's path + query + headers + body.  A match triggers injection of
# that vuln's knowledge entry.
#
# To add routing for a new vuln: add its ID here with one or more patterns.
# The ID must match a key in VULN_KNOWLEDGE_BASE.
# ---------------------------------------------------------------------------

_RAW_SIGNALS: dict[str, list[str]] = {
    "sqli": [
        r"id=\d+",                          # numeric ID param
        r"(search|query|q|filter|where|order|sort|limit|offset)=",
        r"(username|user|login|email|pass)",
        r"(SELECT|INSERT|UPDATE|DELETE|UNION|WHERE|ORDER BY)",
    ],
    "ssrf": [
        r"https?://",                        # URL value in any param/body
        r"(url|uri|dest|destination|redirect|next|continue|src|href|"
        r"image|load|fetch|webhook|callback|feed|endpoint)=",
        r"(url|uri|dest|redirect|src|href|image|load|fetch|webhook|"
        r"callback|feed|endpoint)[\"']?\s*:",  # JSON key
    ],
    "xxe": [
        r"<\?xml",
        r"<!DOCTYPE",
        r"<!ENTITY",
        r"application/xml",
        r"text/xml",
        r"application/soap\+xml",
        r"\.xml(\?|$)",
        r"(soap|wsdl|xml|rss|atom|svg)",
    ],
    "cmdi": [
        r"(cmd|exec|command|run|shell|ping|nslookup|host|dig|query|"
        r"ip|domain|filename|file|path|report|convert|process)=",
        r"(cmd|exec|command|shell|ping|nslookup|process)[\"']?\s*:",  # JSON key
        r"(\||;|&&|\$\(|`)",                 # shell metacharacters in values
    ],
    "jwt": [
        r"[Bb]earer\s+[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]*",
        r"[Aa]uthorization\s*:",
        r"(token|access_token|id_token|refresh_token)[\"']?\s*:",
        r"eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+",  # raw JWT prefix
    ],
    "idor": [
        r"/\d{1,10}(/|$|\?)",               # numeric ID in path
        r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}",  # UUID
        r"(user_id|account_id|order_id|invoice_id|document_id|"
        r"resource_id|profile_id|record_id)=",
        r"(user_id|account_id|order_id|invoice_id)[\"']?\s*:",  # JSON key
    ],
    "mass_assignment": [
        r"(POST|PUT|PATCH)\s",
        r"application/json",
        r"application/x-www-form-urlencoded",
        r"(role|is_admin|admin|verified|balance|credit|"
        r"permissions|account_type|status)[\"']?\s*[=:]",
    ],
    "ssti": [
        r"(template|render|view|page|name|greeting|subject|message|"
        r"body|content|output|preview|report)=",
        r"\{\{.*\}\}",                       # already-injected template syntax
        r"\$\{.*\}",
        r"(jinja|twig|freemarker|smarty|velocity|thymeleaf)",
    ],
    "deserial": [
        r"rO0AB",                            # Java serialised object (base64)
        r"O:\d+:",                           # PHP serialised object
        r"__VIEWSTATE",
        r"application/x-java-serialized-object",
        r"(session|state|data|payload|object|token)=[A-Za-z0-9+/]{20,}={0,2}",
    ],
    "graphql": [
        r"graphql",
        r"/gql(\?|$|/)",
        r"(query|mutation|subscription)\s*[\({]",
        r"application/graphql",
        r"__schema|__typename|__type",
    ],
}

# Compile once at import time.
_SIGNAL_MAP: dict[str, list[re.Pattern[str]]] = {
    vuln_id: [re.compile(p, re.IGNORECASE) for p in patterns]
    for vuln_id, patterns in _RAW_SIGNALS.items()
}


# ---------------------------------------------------------------------------
# Knowledge router
# ---------------------------------------------------------------------------

def get_relevant_knowledge(
    requests: Sequence[BurpRequest],
    endpoints: Sequence[SwaggerEndpoint],
) -> dict[str, VulnEntry]:
    """Analyse requests and endpoints and return the matching KB entries.

    Builds a single signal string from all observable surfaces
    (path, query, headers, body, method, content-type) and runs every
    compiled pattern against it.  Only entries with at least one match
    are returned, keeping the injected context minimal.
    """
    signal_parts: list[str] = []

    for req in requests:
        signal_parts.append(f"{req.method} {req.path}")
        for k, v in req.headers.items():
            signal_parts.append(f"{k}: {v}")
        if req.body:
            signal_parts.append(req.body)

    for ep in endpoints:
        signal_parts.append(f"{ep.method} {ep.full_url}")
        signal_parts.extend(ep.parameters)
        if ep.summary:
            signal_parts.append(ep.summary)

    signal = "\n".join(signal_parts)

    matched: dict[str, VulnEntry] = {}
    for vuln_id, patterns in _SIGNAL_MAP.items():
        if vuln_id not in VULN_KNOWLEDGE_BASE:
            continue
        if any(p.search(signal) for p in patterns):
            matched[vuln_id] = VULN_KNOWLEDGE_BASE[vuln_id]

    return matched


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------

class AuraAnalyzer:
    """Orchestrates the full analysis pipeline.

    Takes parsed Pydantic objects, routes to the relevant knowledge entries,
    injects that knowledge into the LLM context, and streams/returns the report.
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
        self._system_prompt = get_system_prompt(env)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def analyze(
        self,
        burp_requests: Sequence[BurpRequest] | None = None,
        swagger_endpoints: Sequence[SwaggerEndpoint] | None = None,
    ) -> str:
        """Run the full PT analysis and return a Markdown report."""
        context = self._build_context(burp_requests or [], swagger_endpoints or [])
        return await self._client.generate_analysis(
            system_prompt=self._system_prompt,
            context_data=context,
        )

    async def analyze_stream(
        self,
        burp_requests: Sequence[BurpRequest] | None = None,
        swagger_endpoints: Sequence[SwaggerEndpoint] | None = None,
    ) -> AsyncIterator[str]:
        """Stream the PT analysis token-by-token as it is generated."""
        context = self._build_context(burp_requests or [], swagger_endpoints or [])
        async for token in self._client.generate_analysis_stream(
            system_prompt=self._system_prompt,
            context_data=context,
        ):
            yield token

    # ------------------------------------------------------------------
    # Context construction
    # ------------------------------------------------------------------

    def _build_context(
        self,
        burp_requests: Sequence[BurpRequest],
        swagger_endpoints: Sequence[SwaggerEndpoint],
    ) -> str:
        sections: list[str] = []

        sections.append(
            f"# AuraPT Analysis Context\n\nEnvironment: **{self.env.upper()}**"
        )

        # Dynamic knowledge injection — only relevant entries are included.
        matched_knowledge = get_relevant_knowledge(burp_requests, swagger_endpoints)
        if matched_knowledge:
            knowledge_block = format_for_prompt(matched_knowledge)
            sections.append(knowledge_block)

        if burp_requests:
            sections.append(self._format_burp_section(burp_requests))

        if swagger_endpoints:
            sections.append(self._format_swagger_section(swagger_endpoints))

        if not burp_requests and not swagger_endpoints:
            sections.append("_No input data provided._")

        return "\n\n---\n\n".join(sections)

    # ------------------------------------------------------------------
    # Section formatters
    # ------------------------------------------------------------------

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
                try:
                    pretty = json.dumps(json.loads(req.body), indent=2)
                    lines.append(f"- **Body (JSON):**\n```json\n{pretty}\n```")
                except (json.JSONDecodeError, ValueError):
                    lines.append(f"- **Body:**\n```\n{req.body}\n```")
            else:
                lines.append("- **Body:** _(empty)_")

            lines.append("")

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
