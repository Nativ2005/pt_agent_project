from __future__ import annotations

import json
import re
from urllib.parse import parse_qs, unquote_plus, urlparse
from typing import AsyncIterator, Sequence

from core.knowledge import VULN_KNOWLEDGE_BASE
from core.models import BurpRequest, SwaggerEndpoint
from core.ollama_client import OllamaClient
from prompts.system_prompts import RED_TEAMER_PROMPT

_DEFAULT_MODEL = "qwen2.5-coder:7b"


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


def _extract_anchor(decoded_val: str) -> str:
    """Extract only the alphanumeric characters from a decoded value.

    This 'canary' survives mutations the payload itself may not:
    case changes, HTML/JSON encoding, and partial reflection all leave
    the alphabetic core intact. Searching for it is far more robust
    than searching for the full payload.

    Returns an empty string if fewer than 3 alphanumeric chars exist
    (too short to be a meaningful anchor — would cause false positives).
    """
    anchor = re.sub(r"[^a-zA-Z0-9]", "", decoded_val)
    return anchor if len(anchor) >= 3 else ""


_SSRF_BODY_EXCERPT_LEN = 1000


def _python_pre_processor(requests: Sequence[BurpRequest]) -> str:
    """Vulnerability-Aware Pre-Processor.

    Routes each matched parameter to the correct analysis strategy based on
    which vulnerability class triggered it:

      Reflected_XSS  → Canary Anchoring: find the alphanumeric anchor in the
                        response body and extract a 75-char context snippet.
                        Skipped entirely for application/json responses.

      SSRF           → Response Inspection: extract the first 1000 chars of
                        the response body and ask the LLM to judge whether it
                        looks like internal network data, metadata, or an error.
    """
    hints: list[str] = []

    for req in requests:
        if not req.response_body:
            continue

        params = _extract_params(req)
        endpoint = f"{req.method} {req.path}"
        content_type = req.headers.get("Content-Type", "")
        param_names_lower = {p.lower() for p in params}

        # ── Determine which vuln classes are triggered by this request's params ──
        triggered_vulns: set[str] = set()
        for vuln_name, entry in VULN_KNOWLEDGE_BASE.items():
            for keyword in entry["trigger_keywords"]:
                if keyword.lower() in param_names_lower:
                    triggered_vulns.add(vuln_name)
                    break

        # ── ROUTE A: Reflected XSS — Canary Anchoring ───────────────────────────
        if "Reflected_XSS" in triggered_vulns:
            if "application/json" in content_type:
                print(f"[DEBUG] Skipping XSS check: application/json response ({endpoint})")
            else:
                response_lower = req.response_body.lower()
                for param, decoded_val in params.items():
                    anchor = _extract_anchor(decoded_val)
                    if not anchor:
                        continue
                    idx = response_lower.find(anchor.lower())
                    if idx == -1:
                        continue
                    snippet = _make_snippet(req.response_body, idx, len(anchor))

                    # Python determines the encoding verdict — do not leave this to the LLM.
                    special_chars = [c for c in decoded_val if not c.isalnum() and not c.isspace()]
                    html_entity_map = {
                        '"': "&quot;", "'": "&#x27;", "<": "&lt;", ">": "&gt;", "&": "&amp;",
                    }
                    raw_chars = []
                    encoded_chars = []
                    for ch in special_chars:
                        entity = html_entity_map.get(ch)
                        if entity and entity in snippet:
                            encoded_chars.append(f"{ch!r} → {entity}")
                        else:
                            raw_chars.append(repr(ch))

                    if raw_chars:
                        verdict = (
                            f"⚠️  PYTHON VERDICT: RAW — {', '.join(raw_chars)} appear UNENCODED in the snippet. "
                            f"The server did NOT sanitize these characters. "
                            f"This is a 🔴 VERIFIED HIGH XSS. Do NOT say the characters were encoded."
                        )
                    elif encoded_chars:
                        verdict = (
                            f"✅ PYTHON VERDICT: ENCODED — {', '.join(encoded_chars)}. "
                            f"The server sanitized the input. Classify as 🟡 Investigation Lead."
                        )
                    else:
                        verdict = "ℹ️  PYTHON VERDICT: Special characters absent from snippet — likely stripped."

                    hints.append(
                        f"XSS PRE-PROCESSOR ALERT [{endpoint}]\n"
                        f"  Parameter          : '{param}'\n"
                        f"  Full decoded input : '{decoded_val}'\n"
                        f"  Anchor term        : '{anchor}'\n"
                        f"  Snippet            : `{snippet}`\n"
                        f"  {verdict}"
                    )

        # ── ROUTE B: SSRF — Response Body Inspection ────────────────────────────
        if "SSRF" in triggered_vulns:
            body_excerpt = req.response_body[:_SSRF_BODY_EXCERPT_LEN]
            for param, decoded_val in params.items():
                # Only emit for params whose names match SSRF keywords.
                ssrf_keywords = {k.lower() for k in VULN_KNOWLEDGE_BASE["SSRF"]["trigger_keywords"]}
                if param.lower() not in ssrf_keywords:
                    continue
                hints.append(
                    f"SSRF PRE-PROCESSOR ALERT [{endpoint}]\n"
                    f"  Parameter   : '{param}'\n"
                    f"  Value       : '{decoded_val}'\n"
                    f"  YOUR TASK   : DO NOT look for input reflections.\n"
                    f"                Analyze the server response excerpt below.\n"
                    f"                Does it resemble internal network data, an admin panel,\n"
                    f"                cloud metadata (AWS/GCP/Azure), or a specific backend error?\n"
                    f"  Response excerpt:\n{body_excerpt}"
                )

    if not hints:
        return "No pre-processor alerts triggered."

    return "\n\n".join(hints)


# ---------------------------------------------------------------------------
# Report extractor
# ---------------------------------------------------------------------------

_REPORT_DELIMITER = "===REPORT==="


def _extract_report(text: str) -> str:
    """Return everything after the ===REPORT=== delimiter.

    Split on the plain-text delimiter — no XML parsing, no regex.
    Takes parts[1] (the first occurrence) so any accidental repetition
    of the delimiter inside the report itself is preserved.
    """
    print(f"[DEBUG] Raw LLM Response length: {len(text)} characters")
    parts = text.split(_REPORT_DELIMITER)
    if len(parts) > 1:
        report = parts[1].strip()
        if not report:
            print("[!] Delimiter found but no Markdown report followed it.")
        return report
    # Delimiter absent — return full text so nothing is silently lost.
    print("[!] ===REPORT=== delimiter not found — returning full LLM output.")
    return text.strip()


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
        return _extract_report(raw)

    async def analyze_stream(
        self,
        burp_requests: Sequence[BurpRequest] | None = None,
        swagger_endpoints: Sequence[SwaggerEndpoint] | None = None,
    ) -> AsyncIterator[str]:
        """Stream the PT analysis. Collects all tokens, then splits on </analysis> to yield only the Markdown report."""
        prompt = _build_prompt(burp_requests or [], swagger_endpoints or [])

        all_tokens: list[str] = []

        async for token in self._client.generate_analysis_stream(
            system_prompt="",
            context_data=prompt,
        ):
            all_tokens.append(token)

        full = "".join(all_tokens)
        report = _extract_report(full)
        if report:
            yield report
