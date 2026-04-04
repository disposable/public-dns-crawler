"""Seed input loading for probe corpus generation."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from resolver_inventory.probe_corpus.models import (
    DelegationSeed,
    ExactHostSeed,
    RootServerSeed,
    SeedSnapshot,
)

DEFAULT_SEED_SNAPSHOT = Path("configs/probe-corpus-seeds.json")


def load_seed_snapshot(path: str | Path | None = None) -> SeedSnapshot:
    snapshot_path = Path(path) if path is not None else DEFAULT_SEED_SNAPSHOT
    raw = json.loads(snapshot_path.read_text(encoding="utf-8"))
    return parse_seed_snapshot(raw)


def parse_seed_snapshot(raw: object) -> SeedSnapshot:
    if not isinstance(raw, dict):
        raise ValueError("seed snapshot must be a JSON object")

    return SeedSnapshot(
        snapshot_version=_require_int(raw, "snapshot_version"),
        generated_at=_require_str(raw, "generated_at"),
        sources_used=_require_str_list(raw, "sources_used"),
        root_servers=[
            RootServerSeed(
                hostname=_require_str(item, "hostname"),
                ipv4=_optional_str_list(item, "ipv4"),
                ipv6=_optional_str_list(item, "ipv6"),
                source=_require_str(item, "source"),
                operator_family=_optional_str(item, "operator_family"),
                notes=_optional_str(item, "notes"),
            )
            for item in _require_list(raw, "root_servers")
        ],
        delegations=[
            DelegationSeed(
                zone=_require_str(item, "zone"),
                nameservers=_require_str_list(item, "nameservers"),
                exact_hosts=[
                    ExactHostSeed(
                        hostname=_require_str(host, "hostname"),
                        ipv4=_optional_str_list(host, "ipv4"),
                        ipv6=_optional_str_list(host, "ipv6"),
                        source=_require_str(host, "source"),
                        operator_family=_optional_str(host, "operator_family"),
                        notes=_optional_str(host, "notes"),
                    )
                    for host in _require_list(item, "exact_hosts")
                ],
                source=_require_str(item, "source"),
                notes=_optional_str(item, "notes"),
            )
            for item in _require_list(raw, "delegations")
        ],
    )


def _require_list(raw: dict[str, Any], key: str) -> list[dict[str, Any]]:
    value = raw.get(key)
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise ValueError(f"missing or invalid list field '{key}'")
    return list(value)


def _require_str(raw: dict[str, Any], key: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"missing or invalid string field '{key}'")
    return value


def _optional_str(raw: dict[str, Any], key: str) -> str | None:
    value = raw.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise ValueError(f"invalid string field '{key}'")
    return value


def _require_int(raw: dict[str, Any], key: str) -> int:
    value = raw.get(key)
    if not isinstance(value, int):
        raise ValueError(f"missing or invalid integer field '{key}'")
    return value


def _require_str_list(raw: dict[str, Any], key: str) -> list[str]:
    value = raw.get(key)
    if not isinstance(value, list) or not value or not all(isinstance(item, str) for item in value):
        raise ValueError(f"missing or invalid list field '{key}'")
    return list(value)


def _optional_str_list(raw: dict[str, Any], key: str) -> list[str]:
    value = raw.get(key, [])
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"invalid list field '{key}'")
    return list(value)
