"""Helpers for serializing discovery, validation, and shard metadata."""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path
from typing import Any

from resolver_inventory.models import (
    Candidate,
    FilteredCandidate,
    ProbeResult,
    ValidationResult,
)


def candidate_to_dict(candidate: Candidate) -> dict[str, Any]:
    return {
        "provider": candidate.provider,
        "source": candidate.source,
        "transport": candidate.transport,
        "endpoint_url": candidate.endpoint_url,
        "host": candidate.host,
        "port": candidate.port,
        "path": candidate.path,
        "bootstrap_ipv4": candidate.bootstrap_ipv4,
        "bootstrap_ipv6": candidate.bootstrap_ipv6,
        "tls_server_name": candidate.tls_server_name,
        "metadata": candidate.metadata,
    }


def candidate_from_dict(data: dict[str, Any]) -> Candidate:
    return Candidate(
        provider=data.get("provider"),
        source=data.get("source", "loaded"),
        transport=data["transport"],
        endpoint_url=data.get("endpoint_url"),
        host=data["host"],
        port=data["port"],
        path=data.get("path"),
        bootstrap_ipv4=data.get("bootstrap_ipv4", []),
        bootstrap_ipv6=data.get("bootstrap_ipv6", []),
        tls_server_name=data.get("tls_server_name"),
        metadata=data.get("metadata", {}),
    )


def filtered_candidate_to_dict(record: FilteredCandidate) -> dict[str, Any]:
    return {
        "reason": record.reason,
        "detail": record.detail,
        "stage": record.stage,
        "candidate": candidate_to_dict(record.candidate),
    }


def filtered_candidate_from_dict(data: dict[str, Any]) -> FilteredCandidate:
    return FilteredCandidate(
        candidate=candidate_from_dict(data["candidate"]),
        reason=data["reason"],
        detail=data["detail"],
        stage=data["stage"],
    )


def validation_result_to_dict(result: ValidationResult) -> dict[str, Any]:
    return {
        "status": result.status,
        "score": result.score,
        "accepted": result.accepted,
        "reasons": result.reasons,
        "candidate": candidate_to_dict(result.candidate),
        "probes": [dataclasses.asdict(probe) for probe in result.probes],
        "median_latency_ms": result.median_latency_ms(),
    }


def validation_result_from_dict(data: dict[str, Any]) -> ValidationResult:
    probes = [
        ProbeResult(
            ok=probe["ok"],
            probe=probe["probe"],
            latency_ms=probe.get("latency_ms"),
            error=probe.get("error"),
            details=probe.get("details", {}),
        )
        for probe in data.get("probes", [])
    ]
    return ValidationResult(
        candidate=candidate_from_dict(data["candidate"]),
        accepted=data["accepted"],
        score=data["score"],
        status=data["status"],
        reasons=data["reasons"],
        probes=probes,
    )


def load_json_list(path: str | Path) -> list[dict[str, Any]]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_json(path: str | Path, payload: Any, *, indent: int = 2) -> None:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=indent, ensure_ascii=False), encoding="utf-8")
