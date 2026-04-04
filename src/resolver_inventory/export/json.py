"""JSON exporter for validated resolver data."""

from __future__ import annotations

import json
from pathlib import Path

from resolver_inventory.models import FilteredCandidate, Status, ValidationResult
from resolver_inventory.serialization import (
    filtered_candidate_to_dict,
    validation_result_to_dict_export,
)


def _candidate_sort_key(result: ValidationResult) -> tuple[str, str, str, int, str]:
    candidate = result.candidate
    return (
        candidate.transport,
        candidate.endpoint_url or "",
        candidate.host,
        candidate.port,
        candidate.path or "",
    )


def _filtered_sort_key(record: FilteredCandidate) -> tuple[str, str, str, str, int, str]:
    candidate = record.candidate
    return (
        record.stage,
        record.reason,
        candidate.transport,
        candidate.host,
        candidate.port,
        candidate.endpoint_url or "",
    )


def _base_and_suffix(path: Path) -> tuple[str, str]:
    suffix = path.suffix or ".json"
    base = path.name[: -len(path.suffix)] if path.suffix else path.name
    return base, suffix


def _split_output_path(path: Path, index: int) -> Path:
    base, suffix = _base_and_suffix(path)
    return path.with_name(f"{base}.part-{index:04d}{suffix}")


def _write_chunked_json(path: Path, payload: list[dict], max_file_bytes: int) -> None:
    if max_file_bytes < 3:
        raise ValueError("max_file_bytes must be at least 3")

    encoded_items = [
        json.dumps(record, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        for record in payload
    ]
    chunks: list[list[bytes]] = []
    current: list[bytes] = []
    current_size = 2  # []

    for item in encoded_items:
        item_size = len(item)
        delimiter = 0 if not current else 1
        if current and (current_size + delimiter + item_size) > max_file_bytes:
            chunks.append(current)
            current = [item]
            current_size = 2 + item_size
            continue
        if not current and (2 + item_size) > max_file_bytes:
            chunks.append([item])
            current = []
            current_size = 2
            continue
        current.append(item)
        current_size += delimiter + item_size

    if current:
        chunks.append(current)

    # keep empty payload behavior as a single JSON file.
    if not chunks:
        path.write_text("[]", encoding="utf-8")
        return

    if len(chunks) == 1:
        path.write_text(f"[{b','.join(chunks[0]).decode('utf-8')}]", encoding="utf-8")
        return

    for index, chunk in enumerate(chunks, start=1):
        split_path = _split_output_path(path, index)
        split_path.write_text(f"[{b','.join(chunk).decode('utf-8')}]", encoding="utf-8")


def export_json(
    results: list[ValidationResult],
    *,
    accepted_only: bool = True,
    statuses: set[Status] | None = None,
    rejected_failed_only: bool = False,
    sort_records: bool = True,
    max_file_bytes: int | None = None,
    path: str | Path | None = None,
    indent: int | None = None,
) -> str:
    """Serialize validation results to JSON.

    Returns the JSON string. If *path* is given, also writes it to disk.
    """
    if statuses is not None:
        records = [r for r in results if r.status in statuses]
    else:
        records = [r for r in results if r.accepted] if accepted_only else results
    if sort_records:
        records = sorted(records, key=_candidate_sort_key)
    payload = [
        validation_result_to_dict_export(r, rejected_failed_only=rejected_failed_only)
        for r in records
    ]
    if indent is None:
        text = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    else:
        text = json.dumps(payload, indent=indent, ensure_ascii=False)
    if path is not None:
        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        if max_file_bytes is None:
            out.write_text(text, encoding="utf-8")
        else:
            _write_chunked_json(out, payload, max_file_bytes)
    return text


def export_filtered_json(
    records: list[FilteredCandidate],
    *,
    sort_records: bool = True,
    max_file_bytes: int | None = None,
    path: str | Path | None = None,
    indent: int | None = None,
) -> str:
    """Serialize filtered candidates to JSON."""
    if sort_records:
        records = sorted(records, key=_filtered_sort_key)
    payload = [filtered_candidate_to_dict(record) for record in records]
    if indent is None:
        text = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    else:
        text = json.dumps(payload, indent=indent, ensure_ascii=False)
    if path is not None:
        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        if max_file_bytes is None:
            out.write_text(text, encoding="utf-8")
        else:
            _write_chunked_json(out, payload, max_file_bytes)
    return text
