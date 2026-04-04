"""Configuration loading and defaults for resolver-inventory."""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class CorpusConfig:
    mode: str = "fallback"
    zone: str = ""


@dataclass
class ValidationConfig:
    rounds: int = 3
    timeout_ms: int = 2000
    parallelism: int = 50
    require_tcp_for_dns: bool = False
    require_tls_valid_for_doh: bool = True
    corpus: CorpusConfig = field(default_factory=CorpusConfig)


@dataclass
class ScoringConfig:
    accept_min_score: int = 80
    candidate_min_score: int = 60


@dataclass
class ExportConfig:
    formats: list[str] = field(default_factory=lambda: ["json", "text"])
    output_dir: str = "outputs"


@dataclass
class SourceEntry:
    type: str
    path: str | None = None
    url: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class SourcesConfig:
    dns: list[SourceEntry] = field(default_factory=list)
    doh: list[SourceEntry] = field(default_factory=list)


@dataclass
class Settings:
    sources: SourcesConfig = field(default_factory=SourcesConfig)
    validation: ValidationConfig = field(default_factory=ValidationConfig)
    scoring: ScoringConfig = field(default_factory=ScoringConfig)
    export: ExportConfig = field(default_factory=ExportConfig)


def _parse_source_list(raw: list[dict[str, Any]]) -> list[SourceEntry]:
    result: list[SourceEntry] = []
    for item in raw:
        entry = SourceEntry(type=item.pop("type"))
        entry.path = item.pop("path", None)
        entry.url = item.pop("url", None)
        entry.extra = item
        result.append(entry)
    return result


def load_settings(path: str | Path | None = None) -> Settings:
    """Load settings from a TOML file, falling back to defaults."""
    if path is None:
        env_path = os.environ.get("RESOLVER_INVENTORY_CONFIG")
        if env_path:
            path = Path(env_path)

    if path is None or not Path(path).exists():
        return Settings()

    with open(path, "rb") as fh:
        raw: dict[str, Any] = tomllib.load(fh)

    settings = Settings()

    if "sources" in raw:
        src = raw["sources"]
        settings.sources.dns = _parse_source_list(list(src.get("dns", [])))
        settings.sources.doh = _parse_source_list(list(src.get("doh", [])))

    if "validation" in raw:
        v = raw["validation"]
        vc = settings.validation
        vc.rounds = int(v.get("rounds", vc.rounds))
        vc.timeout_ms = int(v.get("timeout_ms", vc.timeout_ms))
        vc.parallelism = int(v.get("parallelism", vc.parallelism))
        vc.require_tcp_for_dns = bool(v.get("require_tcp_for_dns", vc.require_tcp_for_dns))
        vc.require_tls_valid_for_doh = bool(
            v.get("require_tls_valid_for_doh", vc.require_tls_valid_for_doh)
        )
        if "corpus" in v:
            c = v["corpus"]
            vc.corpus.mode = str(c.get("mode", vc.corpus.mode))
            vc.corpus.zone = str(c.get("zone", vc.corpus.zone))

    if "scoring" in raw:
        s = raw["scoring"]
        settings.scoring.accept_min_score = int(
            s.get("accept_min_score", settings.scoring.accept_min_score)
        )
        settings.scoring.candidate_min_score = int(
            s.get("candidate_min_score", settings.scoring.candidate_min_score)
        )

    if "export" in raw:
        e = raw["export"]
        settings.export.formats = list(e.get("formats", settings.export.formats))
        settings.export.output_dir = str(e.get("output_dir", settings.export.output_dir))

    return settings
