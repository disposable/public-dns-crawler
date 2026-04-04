"""Schema validation for imported probe corpus files."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


class CorpusSchemaError(ValueError):
    """Raised when an external probe corpus fails schema validation."""


@dataclass(slots=True)
class ProbeDefinition:
    id: str
    kind: str
    qtype: str
    expected_mode: str
    qname: str | None = None
    qname_template: str | None = None
    expected_answers: list[str] = field(default_factory=list)
    parent_zone: str | None = None
    notes: str | None = None


@dataclass(slots=True)
class ProbeCorpus:
    schema_version: int
    corpus_version: str
    generated_at: str
    probes: list[ProbeDefinition]


_TOP_LEVEL_FIELDS = {
    "schema_version",
    "corpus_version",
    "generated_at",
    "probes",
}
_PROBE_FIELDS = {
    "id",
    "kind",
    "qtype",
    "expected_mode",
    "qname",
    "qname_template",
    "expected_answers",
    "parent_zone",
    "notes",
}


def parse_probe_corpus(
    raw: object,
    *,
    required_schema_version: int | None = None,
    strict: bool = True,
) -> ProbeCorpus:
    """Validate a raw JSON-decoded probe corpus and return typed models."""
    if not isinstance(raw, dict):
        raise CorpusSchemaError("probe corpus must be a JSON object")
    if strict:
        _reject_unknown_fields(raw, _TOP_LEVEL_FIELDS, context="probe corpus")

    schema_version = _require_int(raw, "schema_version")
    if required_schema_version is not None and schema_version != required_schema_version:
        raise CorpusSchemaError(
            f"unsupported schema_version {schema_version}; expected {required_schema_version}"
        )

    corpus_version = _require_str(raw, "corpus_version")
    generated_at = _require_str(raw, "generated_at")

    probes_raw = raw.get("probes")
    if not isinstance(probes_raw, list):
        raise CorpusSchemaError("probe corpus field 'probes' must be a list")
    probes = [parse_probe_definition(item, strict=strict) for item in probes_raw]

    return ProbeCorpus(
        schema_version=schema_version,
        corpus_version=corpus_version,
        generated_at=generated_at,
        probes=probes,
    )


def parse_probe_definition(raw: object, *, strict: bool = True) -> ProbeDefinition:
    if not isinstance(raw, dict):
        raise CorpusSchemaError("each probe entry must be a JSON object")
    if strict:
        _reject_unknown_fields(raw, _PROBE_FIELDS, context="probe entry")

    qname = _optional_str(raw, "qname")
    qname_template = _optional_str(raw, "qname_template")
    if not qname and not qname_template:
        raise CorpusSchemaError("probe entry must include either 'qname' or 'qname_template'")

    expected_answers_raw = raw.get("expected_answers", [])
    if not isinstance(expected_answers_raw, list) or not all(
        isinstance(item, str) for item in expected_answers_raw
    ):
        raise CorpusSchemaError("probe entry field 'expected_answers' must be a list of strings")

    return ProbeDefinition(
        id=_require_str(raw, "id"),
        kind=_require_str(raw, "kind"),
        qtype=_require_str(raw, "qtype"),
        expected_mode=_require_str(raw, "expected_mode"),
        qname=qname,
        qname_template=qname_template,
        expected_answers=list(expected_answers_raw),
        parent_zone=_optional_str(raw, "parent_zone"),
        notes=_optional_str(raw, "notes"),
    )


def _reject_unknown_fields(raw: dict[str, Any], allowed: set[str], *, context: str) -> None:
    extra = sorted(set(raw) - allowed)
    if extra:
        raise CorpusSchemaError(f"{context} includes unsupported fields: {', '.join(extra)}")


def _require_str(raw: dict[str, Any], key: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value:
        raise CorpusSchemaError(f"missing or invalid string field '{key}'")
    return value


def _optional_str(raw: dict[str, Any], key: str) -> str | None:
    value = raw.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise CorpusSchemaError(f"invalid string field '{key}'")
    return value


def _require_int(raw: dict[str, Any], key: str) -> int:
    value = raw.get(key)
    if not isinstance(value, int):
        raise CorpusSchemaError(f"missing or invalid integer field '{key}'")
    return value
