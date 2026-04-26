from __future__ import annotations

import json
from pathlib import Path

from core.models import SwaggerEndpoint

try:
    import yaml  # optional – only needed for YAML Swagger files
    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False


def _load_spec(swagger_path: Path) -> dict:
    raw = swagger_path.read_text(encoding="utf-8")
    if swagger_path.suffix.lower() in {".yaml", ".yml"}:
        if not _YAML_AVAILABLE:
            raise RuntimeError(
                "PyYAML is required to parse YAML Swagger files: pip install pyyaml"
            )
        return yaml.safe_load(raw)
    return json.loads(raw)


def parse_swagger_file(swagger_path: Path) -> list[SwaggerEndpoint]:
    """Extract every path+method pair from a Swagger / OpenAPI 2 or 3 spec."""
    spec = _load_spec(swagger_path)

    # OpenAPI 3 uses `servers[0].url`; Swagger 2 uses `host` + `basePath`.
    if "servers" in spec:
        base = (spec["servers"][0].get("url") or "").rstrip("/")
    else:
        scheme = (spec.get("schemes") or ["https"])[0]
        host = spec.get("host", "")
        base_path = spec.get("basePath", "")
        base = f"{scheme}://{host}{base_path}".rstrip("/")

    http_methods = {"get", "post", "put", "patch", "delete", "head", "options"}

    results: list[SwaggerEndpoint] = []
    for path, path_item in (spec.get("paths") or {}).items():
        for method, operation in path_item.items():
            if method.lower() not in http_methods:
                continue
            if not isinstance(operation, dict):
                continue

            params = [
                p.get("name", "")
                for p in (operation.get("parameters") or [])
                if isinstance(p, dict)
            ]

            results.append(
                SwaggerEndpoint(
                    base_url=base,
                    path=path,
                    method=method.upper(),
                    operation_id=operation.get("operationId"),
                    parameters=params,
                    summary=operation.get("summary"),
                )
            )

    return results
