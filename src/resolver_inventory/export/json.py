"""JSON exporter for validated resolver data."""

from __future__ import annotations

import json
from pathlib import Path

from resolver_inventory.models import FilteredCandidate, ValidationResult
from resolver_inventory.serialization import filtered_candidate_to_dict, validation_result_to_dict


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
    payload = [validation_result_to_dict(r) for r in records]
    text = json.dumps(payload, indent=indent, ensure_ascii=False)
    if path is not None:
        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
    return text


def export_filtered_json(
    records: list[FilteredCandidate],
    *,
    path: str | Path | None = None,
    indent: int = 2,
) -> str:
    """Serialize filtered candidates to JSON."""
    payload = [filtered_candidate_to_dict(record) for record in records]
    text = json.dumps(payload, indent=indent, ensure_ascii=False)
    if path is not None:
        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
    return text
