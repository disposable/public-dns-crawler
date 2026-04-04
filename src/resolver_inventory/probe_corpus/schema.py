"""Schema validation and serialization for probe corpus files."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


class ProbeSchemaError(ValueError):
    """Raised when a probe corpus fails schema validation."""


@dataclass(slots=True)
class ProbeDefinition:
    id: str
    kind: str
    qtype: str
    expected_mode: str
    qname: str | None = None
    qname_template: str | None = None
    expected_answers: list[str] = field(default_factory=list)
    expected_nameservers: list[str] = field(default_factory=list)
    parent_zone: str | None = None
    source: str | None = None
    stability_score: float | None = None
    notes: str | None = None


@dataclass(slots=True)
class ProbeCorpus:
    schema_version: int
    corpus_version: str
    generated_at: str
    probes: list[ProbeDefinition]
    generator_version: str | None = None
    sources_used: list[str] = field(default_factory=list)
    probe_counts: dict[str, int] = field(default_factory=dict)


_TOP_LEVEL_FIELDS = {
    "schema_version",
    "corpus_version",
    "generated_at",
    "generator_version",
    "sources_used",
    "probe_counts",
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
    "expected_nameservers",
    "parent_zone",
    "source",
    "stability_score",
    "notes",
}
_ALLOWED_KINDS = {"positive_exact", "positive_consensus", "negative_generated"}
_ALLOWED_EXPECTED_MODES = {"exact_rrset", "consensus_match", "nxdomain"}
_EXPECTED_MODE_ALIASES = {"baseline_match": "consensus_match"}


def parse_probe_corpus(
    raw: object,
    *,
    required_schema_version: int | None = None,
    strict: bool = True,
) -> ProbeCorpus:
    """Validate a raw JSON-decoded probe corpus and return typed models."""
    if not isinstance(raw, dict):
        raise ProbeSchemaError("probe corpus must be a JSON object")
    if strict:
        _reject_unknown_fields(raw, _TOP_LEVEL_FIELDS, context="probe corpus")

    schema_version = _require_int(raw, "schema_version")
    if required_schema_version is not None and schema_version != required_schema_version:
        raise ProbeSchemaError(
            f"unsupported schema_version {schema_version}; expected {required_schema_version}"
        )

    corpus_version = _require_str(raw, "corpus_version")
    generated_at = _require_str(raw, "generated_at")
    generator_version = _optional_str(raw, "generator_version")

    if schema_version >= 2:
        if generator_version is None:
            raise ProbeSchemaError("missing or invalid string field 'generator_version'")
        sources_used = _require_str_list(raw, "sources_used")
        probe_counts = _require_int_map(raw, "probe_counts")
    else:
        sources_used = _optional_str_list(raw, "sources_used")
        probe_counts = _optional_int_map(raw, "probe_counts")

    probes_raw = raw.get("probes")
    if not isinstance(probes_raw, list):
        raise ProbeSchemaError("probe corpus field 'probes' must be a list")
    probes = [parse_probe_definition(item, strict=strict) for item in probes_raw]

    corpus = ProbeCorpus(
        schema_version=schema_version,
        corpus_version=corpus_version,
        generated_at=generated_at,
        generator_version=generator_version,
        sources_used=sources_used,
        probe_counts=probe_counts or _count_probes(probes),
        probes=probes,
    )
    return corpus


def parse_probe_definition(raw: object, *, strict: bool = True) -> ProbeDefinition:
    if not isinstance(raw, dict):
        raise ProbeSchemaError("each probe entry must be a JSON object")
    if strict:
        _reject_unknown_fields(raw, _PROBE_FIELDS, context="probe entry")

    qname = _optional_str(raw, "qname")
    qname_template = _optional_str(raw, "qname_template")
    if not qname and not qname_template:
        raise ProbeSchemaError("probe entry must include either 'qname' or 'qname_template'")

    kind = _require_str(raw, "kind")
    if kind not in _ALLOWED_KINDS:
        raise ProbeSchemaError(f"unsupported probe kind '{kind}'")

    expected_mode = _EXPECTED_MODE_ALIASES.get(
        _require_str(raw, "expected_mode"),
        raw["expected_mode"],
    )
    if expected_mode not in _ALLOWED_EXPECTED_MODES:
        raise ProbeSchemaError(f"unsupported expected_mode '{expected_mode}'")

    expected_answers = _optional_str_list(raw, "expected_answers")
    expected_nameservers = _optional_str_list(raw, "expected_nameservers")

    if kind == "negative_generated" and not qname_template:
        raise ProbeSchemaError("negative_generated probes require 'qname_template'")
    if expected_mode == "exact_rrset" and not expected_answers:
        raise ProbeSchemaError("exact_rrset probes require 'expected_answers'")
    if expected_mode == "nxdomain" and not (qname_template or qname):
        raise ProbeSchemaError("nxdomain probes require 'qname' or 'qname_template'")

    stability_score = raw.get("stability_score")
    if stability_score is not None and not isinstance(stability_score, (int, float)):
        raise ProbeSchemaError("probe entry field 'stability_score' must be numeric")

    return ProbeDefinition(
        id=_require_str(raw, "id"),
        kind=kind,
        qtype=_require_str(raw, "qtype"),
        expected_mode=expected_mode,
        qname=qname,
        qname_template=qname_template,
        expected_answers=expected_answers,
        expected_nameservers=expected_nameservers,
        parent_zone=_optional_str(raw, "parent_zone"),
        source=_optional_str(raw, "source"),
        stability_score=float(stability_score) if stability_score is not None else None,
        notes=_optional_str(raw, "notes"),
    )


def probe_corpus_to_dict(corpus: ProbeCorpus) -> dict[str, Any]:
    payload = asdict(corpus)
    payload["probe_counts"] = corpus.probe_counts or _count_probes(corpus.probes)
    return payload


def _count_probes(probes: list[ProbeDefinition]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for probe in probes:
        counts[probe.kind] = counts.get(probe.kind, 0) + 1
    return counts


def _reject_unknown_fields(raw: dict[str, Any], allowed: set[str], *, context: str) -> None:
    extra = sorted(set(raw) - allowed)
    if extra:
        raise ProbeSchemaError(f"{context} includes unsupported fields: {', '.join(extra)}")


def _require_str(raw: dict[str, Any], key: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value:
        raise ProbeSchemaError(f"missing or invalid string field '{key}'")
    return value


def _optional_str(raw: dict[str, Any], key: str) -> str | None:
    value = raw.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise ProbeSchemaError(f"invalid string field '{key}'")
    return value


def _require_int(raw: dict[str, Any], key: str) -> int:
    value = raw.get(key)
    if not isinstance(value, int):
        raise ProbeSchemaError(f"missing or invalid integer field '{key}'")
    return value


def _optional_str_list(raw: dict[str, Any], key: str) -> list[str]:
    value = raw.get(key, [])
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ProbeSchemaError(f"probe corpus field '{key}' must be a list of strings")
    return list(value)


def _require_str_list(raw: dict[str, Any], key: str) -> list[str]:
    value = raw.get(key)
    if not isinstance(value, list) or not value or not all(isinstance(item, str) for item in value):
        raise ProbeSchemaError(f"missing or invalid list field '{key}'")
    return list(value)


def _optional_int_map(raw: dict[str, Any], key: str) -> dict[str, int]:
    value = raw.get(key, {})
    if not isinstance(value, dict) or not all(
        isinstance(k, str) and isinstance(v, int) for k, v in value.items()
    ):
        raise ProbeSchemaError(f"probe corpus field '{key}' must be a string->int map")
    return dict(value)


def _require_int_map(raw: dict[str, Any], key: str) -> dict[str, int]:
    value = raw.get(key)
    if (
        not isinstance(value, dict)
        or not value
        or not all(isinstance(k, str) and isinstance(v, int) for k, v in value.items())
    ):
        raise ProbeSchemaError(f"missing or invalid map field '{key}'")
    return dict(value)
