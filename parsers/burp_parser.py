from __future__ import annotations

import base64
from pathlib import Path
from xml.etree import ElementTree as ET

from core.models import BurpRequest

# Extensions that are almost certainly not interesting for a PT engagement.
_STATIC_NOISE: set[str] = {
    ".css", ".js", ".map", ".png", ".jpg", ".jpeg", ".gif",
    ".ico", ".svg", ".woff", ".woff2", ".ttf", ".eot",
    ".webp", ".avif", ".mp4", ".webm", ".pdf",
}


def _is_static(path: str) -> bool:
    suffix = Path(path.split("?")[0]).suffix.lower()
    return suffix in _STATIC_NOISE


def _decode(text: str | None, is_base64: bool) -> str:
    if not text:
        return ""
    if is_base64:
        try:
            return base64.b64decode(text).decode("utf-8", errors="replace")
        except Exception:
            return text
    return text


def parse_burp_xml(xml_path: Path) -> list[BurpRequest]:
    """Parse a Burp Suite XML export and return typed request objects.

    Filters out static assets (images, fonts, stylesheets, etc.) so that
    only potentially interesting endpoints reach the analysis pipeline.
    """
    tree = ET.parse(xml_path)
    root = tree.getroot()

    results: list[BurpRequest] = []

    for item in root.findall("item"):
        host_el = item.find("host")
        path_el = item.find("path")
        method_el = item.find("method")
        request_el = item.find("request")

        host = host_el.text or "" if host_el is not None else ""
        path = path_el.text or "/" if path_el is not None else "/"
        method = method_el.text or "GET" if method_el is not None else "GET"

        if _is_static(path):
            continue

        # Burp can base64-encode the raw request blob.
        is_b64 = request_el is not None and request_el.attrib.get("base64") == "true"
        raw_request = _decode(
            request_el.text if request_el is not None else None, is_b64
        )

        # Split raw HTTP request into headers / body sections.
        headers: dict[str, str] = {}
        body = ""
        if raw_request:
            parts = raw_request.split("\r\n\r\n", 1)
            header_section = parts[0]
            body = parts[1] if len(parts) > 1 else ""
            for line in header_section.splitlines()[1:]:  # skip request-line
                if ": " in line:
                    k, _, v = line.partition(": ")
                    headers[k] = v

        results.append(
            BurpRequest(
                host=host,
                path=path,
                method=method.upper(),
                headers=headers,
                body=body,
            )
        )

    return results
