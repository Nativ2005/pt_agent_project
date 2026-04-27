from __future__ import annotations

import json
import re
from urllib.parse import parse_qs, unquote_plus, urlparse
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
# Python Pre-Processor — exact substring search, Python-side
# ---------------------------------------------------------------------------

_SNIPPET_RADIUS = 75  # characters before/after match to extract


def _extract_params(req: BurpRequest) -> dict[str, str]:
    """Return {param_name: decoded_value} from query string and request body."""
    params: dict[str, str] = {}

    # Query-string parameters from the path.
    parsed = urlparse(req.path)
    for name, values in parse_qs(parsed.query, keep_blank_values=True).items():
        params[name] = unquote_plus(values[0])

    # Form-encoded body parameters.
    if req.body:
        content_type = req.headers.get("Content-Type", "")
        if "application/x-www-form-urlencoded" in content_type:
            for name, values in parse_qs(req.body, keep_blank_values=True).items():
                params[name] = unquote_plus(values[0])
        else:
            # Try JSON body — extract string leaf values.
            try:
                parsed_json = json.loads(req.body)
                if isinstance(parsed_json, dict):
                    for k, v in parsed_json.items():
                        if isinstance(v, str):
                            params[k] = v
            except (json.JSONDecodeError, ValueError):
                pass

    return params


def _make_snippet(haystack: str, match_start: int, match_len: int) -> str:
    start = max(0, match_start - _SNIPPET_RADIUS)
    end = min(len(haystack), match_start + match_len + _SNIPPET_RADIUS)
    prefix = "..." if start > 0 else ""
    suffix = "..." if end < len(haystack) else ""
    return f"{prefix}{haystack[start:end]}{suffix}"


def _python_pre_processor(requests: Sequence[BurpRequest]) -> str:
    """Search every decoded parameter value inside the captured response body.

    Returns a formatted <system_hints> content string describing every match
    found, or a single 'no matches' line if nothing was found.
    Python does the exact string search so the LLM never has to.
    """
    hints: list[str] = []

    for req in requests:
        if not req.response_body:
            continue

        params = _extract_params(req)
        endpoint = f"{req.method} {req.path}"

        for param, decoded_val in params.items():
            if len(decoded_val) < 2:  # skip trivially short values (e.g., "1")
                continue

            idx = req.response_body.find(decoded_val)
            if idx == -1:
                continue

            snippet = _make_snippet(req.response_body, idx, len(decoded_val))
            hints.append(
                f"PYTHON PRE-PROCESSOR ALERT [{endpoint}]\n"
                f"  Parameter : '{param}'\n"
                f"  Decoded value : '{decoded_val}'\n"
                f"  Status : FOUND IN RESPONSE BODY\n"
                f"  Context Snippet : `{snippet}`"
            )

    if not hints:
        return "No parameter reflections detected by Python pre-processor."

    return "\n\n".join(hints)


# ---------------------------------------------------------------------------
# <analysis> block stripper
# ---------------------------------------------------------------------------

_ANALYSIS_RE = re.compile(
    r"<analysis>.*?(</analysis>|$)",
    re.DOTALL | re.IGNORECASE,
)


def _strip_analysis_block(text: str) -> str:
    """Remove the LLM's internal <analysis>…</analysis> chain-of-thought block.

    Uses |$ so an unclosed tag doesn't swallow the entire response.
    """
    print(f"[DEBUG] Raw LLM Response length: {len(text)} characters")
    cleaned = _ANALYSIS_RE.sub("", text)
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
    cleaned = cleaned.lstrip("\n")
    if not cleaned.strip():
        print("[!] Analysis completed, but no Markdown report was generated outside the analysis block.")
    return cleaned


# ---------------------------------------------------------------------------
# Traffic serialiser (shared between analyze / analyze_stream)
# ---------------------------------------------------------------------------

def _build_traffic_context(
    burp_requests: Sequence[BurpRequest],
    swagger_endpoints: Sequence[SwaggerEndpoint],
) -> str:
    """Serialise all parsed input into a compact, readable traffic string."""
    sections: list[str] = []

    for req in burp_requests:
        # Label by Verb + Path so the LLM never needs to use generic numbers.
        label = f"{req.method} {req.path}"
        lines = [f"### {label}"]
        lines.append(f"Host: {req.host}")

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

        sections.append("\n".join(lines))  # label already set above

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
    system_hints = _python_pre_processor(burp_requests)
    return RED_TEAMER_PROMPT.format(
        knowledge_context=knowledge_context,
        system_hints=system_hints,
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
        """Run the full PT analysis and return a cleaned Markdown report."""
        prompt = _build_prompt(burp_requests or [], swagger_endpoints or [])
        raw = await self._client.generate_analysis(
            system_prompt="",
            context_data=prompt,
        )
        return _strip_analysis_block(raw)

    async def analyze_stream(
        self,
        burp_requests: Sequence[BurpRequest] | None = None,
        swagger_endpoints: Sequence[SwaggerEndpoint] | None = None,
    ) -> AsyncIterator[str]:
        """Stream the PT analysis, suppressing the <analysis> block entirely.

        Tokens are buffered until the closing </analysis> tag is confirmed,
        then the Markdown report is streamed token-by-token from that point on.
        """
        prompt = _build_prompt(burp_requests or [], swagger_endpoints or [])

        buffer = ""
        past_analysis = False
        all_tokens: list[str] = []

        async for token in self._client.generate_analysis_stream(
            system_prompt="",
            context_data=prompt,
        ):
            all_tokens.append(token)

            if past_analysis:
                yield token
                continue

            buffer += token

            # Transition: closing tag found OR LLM wrote ## (report started without closing tag).
            closing_found = "</analysis>" in buffer.lower()
            report_started = not closing_found and "##" in buffer and "<analysis>" in buffer.lower()

            if closing_found or report_started:
                past_analysis = True
                after = _ANALYSIS_RE.sub("", buffer).lstrip("\n")
                if not after.strip():
                    print("[!] Analysis completed, but no Markdown report was generated outside the analysis block.")
                if after:
                    yield after
                buffer = ""

        # If the LLM never opened an <analysis> block at all, emit everything.
        if not past_analysis:
            full = "".join(all_tokens)
            print(f"[DEBUG] Raw LLM Response length: {len(full)} characters")
            result = _strip_analysis_block(full)
            if result:
                yield result
