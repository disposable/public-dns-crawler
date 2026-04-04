"""JSON exporter for validated resolver data."""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path
from typing import Any

from resolver_inventory.models import ValidationResult


def _to_dict(result: ValidationResult) -> dict[str, Any]:
    c = result.candidate
    return {
        "status": result.status,
        "score": result.score,
        "accepted": result.accepted,
        "reasons": result.reasons,
        "candidate": {
            "provider": c.provider,
            "source": c.source,
            "transport": c.transport,
            "endpoint_url": c.endpoint_url,
            "host": c.host,
            "port": c.port,
            "path": c.path,
            "bootstrap_ipv4": c.bootstrap_ipv4,
            "bootstrap_ipv6": c.bootstrap_ipv6,
            "tls_server_name": c.tls_server_name,
            "metadata": c.metadata,
        },
        "probes": [dataclasses.asdict(p) for p in result.probes],
        "median_latency_ms": result.median_latency_ms(),
    }


def export_json(
    results: list[ValidationResult],
    *,
    accepted_only: bool = True,
    path: str | Path | None = None,
    indent: int = 2,
) -> str:
    """Serialize validation results to JSON.

    Returns the JSON string. If *path* is given, also writes it to disk.
    """
    records = [r for r in results if r.accepted] if accepted_only else results
    payload = [_to_dict(r) for r in records]
    text = json.dumps(payload, indent=indent, ensure_ascii=False)
    if path is not None:
        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
    return text
