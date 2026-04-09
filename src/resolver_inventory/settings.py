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
    zone: str | None = None
    path: str | None = None
    schema_version: int | None = None
    allow_builtin_fallback: bool = False
    strict: bool = True


@dataclass
class ValidationConfig:
    rounds: int = 3
    timeout_ms: int = 2000
    parallelism: int = 50
    doh_parallelism: int = 20
    require_tcp_for_dns: bool = False
    require_tls_valid_for_doh: bool = True
    baseline_resolvers: list[str] = field(default_factory=lambda: ["1.1.1.1", "9.9.9.9", "8.8.8.8"])
    corpus: CorpusConfig = field(default_factory=CorpusConfig)
    dns_backend: DnsBackendConfig = field(default_factory=lambda: DnsBackendConfig())


@dataclass
class DnsBackendConfig:
    kind: str = "python"
    massdns_bin: str = "massdns"
    extra_args: list[str] = field(default_factory=list)
    hashmap_size: int = 2000
    processes: int = 1
    socket_count: int = 1
    interval_ms: int = 0
    predictable: bool = True
    flush: bool = True
    batch_max_queries: int = 50000
    stderr_log_level: str = "debug"
    fallback_to_python_on_error: bool = True


@dataclass
class ScoringConfig:
    accept_min_score: int = 80
    candidate_min_score: int = 60


@dataclass
class ExportConfig:
    formats: list[str] = field(default_factory=lambda: ["json", "text"])
    output_dir: str = "outputs"


@dataclass
class BaselineConfig:
    resolvers: list[str] = field(default_factory=lambda: ["1.1.1.1", "9.9.9.9", "8.8.8.8"])


@dataclass
class ProbeCorpusNegativeConfig:
    parent_zones: list[str] = field(default_factory=lambda: ["com.", "net.", "de.", "jp."])
    label_length: int = 40
    validation_rounds: int = 3


@dataclass
class ProbeCorpusSelectionConfig:
    max_per_operator_family: int = 3
    max_per_tld: int = 3


@dataclass
class ProbeCorpusExactValidationConfig:
    rounds: int = 2
    required_quorum: int = 2


@dataclass
class ProbeCorpusConsensusValidationConfig:
    rounds: int = 2
    required_quorum: int = 2


@dataclass
class ProbeCorpusNegativeValidationConfig:
    rounds: int = 3
    labels_per_parent: int = 3
    required_quorum: int = 2
    label_length: int = 40


@dataclass
class ProbeCorpusValidationConfig:
    exact: ProbeCorpusExactValidationConfig = field(
        default_factory=ProbeCorpusExactValidationConfig
    )
    consensus: ProbeCorpusConsensusValidationConfig = field(
        default_factory=ProbeCorpusConsensusValidationConfig
    )
    negative: ProbeCorpusNegativeValidationConfig = field(
        default_factory=ProbeCorpusNegativeValidationConfig
    )


@dataclass
class ProbeCorpusThresholdsConfig:
    min_positive_exact: int = 6
    min_positive_consensus: int = 3
    min_negative_generated: int = 3


@dataclass
class ProbeCorpusConfig:
    schema_version: int = 2
    corpus_version: str = "dev"
    seed_path: str | None = None
    baseline: BaselineConfig = field(default_factory=BaselineConfig)
    negative: ProbeCorpusNegativeConfig = field(default_factory=ProbeCorpusNegativeConfig)
    selection: ProbeCorpusSelectionConfig = field(default_factory=ProbeCorpusSelectionConfig)
    validation: ProbeCorpusValidationConfig = field(default_factory=ProbeCorpusValidationConfig)
    thresholds: ProbeCorpusThresholdsConfig = field(default_factory=ProbeCorpusThresholdsConfig)


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
    probe_corpus: ProbeCorpusConfig = field(default_factory=ProbeCorpusConfig)


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
        vc.doh_parallelism = int(v.get("doh_parallelism", vc.doh_parallelism))
        vc.require_tcp_for_dns = bool(v.get("require_tcp_for_dns", vc.require_tcp_for_dns))
        vc.require_tls_valid_for_doh = bool(
            v.get("require_tls_valid_for_doh", vc.require_tls_valid_for_doh)
        )
        if "baseline" in v:
            vc.baseline_resolvers = list(v["baseline"].get("resolvers", vc.baseline_resolvers))
        if "corpus" in v:
            c = v["corpus"]
            vc.corpus.mode = str(c.get("mode", vc.corpus.mode))
            zone = c.get("zone", vc.corpus.zone)
            vc.corpus.zone = None if zone is None else str(zone)
            path = c.get("path", vc.corpus.path)
            vc.corpus.path = None if path is None else str(path)
            schema_version = c.get("schema_version", vc.corpus.schema_version)
            vc.corpus.schema_version = None if schema_version is None else int(schema_version)
            vc.corpus.allow_builtin_fallback = bool(
                c.get("allow_builtin_fallback", vc.corpus.allow_builtin_fallback)
            )
            vc.corpus.strict = bool(c.get("strict", vc.corpus.strict))
        if "dns_backend" in v:
            dns_backend = v["dns_backend"]
            vc.dns_backend.kind = str(dns_backend.get("kind", vc.dns_backend.kind))
            vc.dns_backend.massdns_bin = str(
                dns_backend.get("massdns_bin", vc.dns_backend.massdns_bin)
            )
            vc.dns_backend.extra_args = [
                str(arg) for arg in dns_backend.get("extra_args", vc.dns_backend.extra_args)
            ]
            vc.dns_backend.hashmap_size = int(
                dns_backend.get("hashmap_size", vc.dns_backend.hashmap_size)
            )
            vc.dns_backend.processes = int(dns_backend.get("processes", vc.dns_backend.processes))
            vc.dns_backend.socket_count = int(
                dns_backend.get("socket_count", vc.dns_backend.socket_count)
            )
            vc.dns_backend.interval_ms = int(
                dns_backend.get("interval_ms", vc.dns_backend.interval_ms)
            )
            vc.dns_backend.predictable = bool(
                dns_backend.get("predictable", vc.dns_backend.predictable)
            )
            vc.dns_backend.flush = bool(dns_backend.get("flush", vc.dns_backend.flush))
            vc.dns_backend.batch_max_queries = int(
                dns_backend.get("batch_max_queries", vc.dns_backend.batch_max_queries)
            )
            vc.dns_backend.stderr_log_level = str(
                dns_backend.get("stderr_log_level", vc.dns_backend.stderr_log_level)
            )
            vc.dns_backend.fallback_to_python_on_error = bool(
                dns_backend.get(
                    "fallback_to_python_on_error",
                    vc.dns_backend.fallback_to_python_on_error,
                )
            )

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

    if "probe_corpus" in raw:
        p = raw["probe_corpus"]
        pc = settings.probe_corpus
        pc.schema_version = int(p.get("schema_version", pc.schema_version))
        pc.corpus_version = str(p.get("corpus_version", pc.corpus_version))
        seed_path = p.get("seed_path", pc.seed_path)
        pc.seed_path = None if seed_path is None else str(seed_path)
        if "baseline" in p:
            pc.baseline.resolvers = list(p["baseline"].get("resolvers", pc.baseline.resolvers))
        if "negative" in p:
            neg = p["negative"]
            pc.negative.parent_zones = list(neg.get("parent_zones", pc.negative.parent_zones))
            pc.negative.label_length = int(neg.get("label_length", pc.negative.label_length))
            pc.negative.validation_rounds = int(
                neg.get("validation_rounds", pc.negative.validation_rounds)
            )
        if "selection" in p:
            sel = p["selection"]
            pc.selection.max_per_operator_family = int(
                sel.get("max_per_operator_family", pc.selection.max_per_operator_family)
            )
            pc.selection.max_per_tld = int(sel.get("max_per_tld", pc.selection.max_per_tld))
        if "validation" in p:
            validation = p["validation"]
            if "exact" in validation:
                exact = validation["exact"]
                pc.validation.exact.rounds = int(exact.get("rounds", pc.validation.exact.rounds))
                pc.validation.exact.required_quorum = int(
                    exact.get("required_quorum", pc.validation.exact.required_quorum)
                )
            if "consensus" in validation:
                consensus = validation["consensus"]
                pc.validation.consensus.rounds = int(
                    consensus.get("rounds", pc.validation.consensus.rounds)
                )
                pc.validation.consensus.required_quorum = int(
                    consensus.get("required_quorum", pc.validation.consensus.required_quorum)
                )
            if "negative" in validation:
                negative = validation["negative"]
                pc.validation.negative.rounds = int(
                    negative.get("rounds", pc.validation.negative.rounds)
                )
                pc.validation.negative.labels_per_parent = int(
                    negative.get(
                        "labels_per_parent",
                        pc.validation.negative.labels_per_parent,
                    )
                )
                pc.validation.negative.required_quorum = int(
                    negative.get(
                        "required_quorum",
                        pc.validation.negative.required_quorum,
                    )
                )
                pc.validation.negative.label_length = int(
                    negative.get("label_length", pc.validation.negative.label_length)
                )
        if "thresholds" in p:
            thresholds = p["thresholds"]
            pc.thresholds.min_positive_exact = int(
                thresholds.get("min_positive_exact", pc.thresholds.min_positive_exact)
            )
            pc.thresholds.min_positive_consensus = int(
                thresholds.get(
                    "min_positive_consensus",
                    pc.thresholds.min_positive_consensus,
                )
            )
            pc.thresholds.min_negative_generated = int(
                thresholds.get(
                    "min_negative_generated",
                    pc.thresholds.min_negative_generated,
                )
            )
        # Backward-compatible aliases from the previous phase.
        if "min_exact_probes" in p:
            pc.thresholds.min_positive_exact = int(p["min_exact_probes"])
        if "min_consensus_probes" in p:
            pc.thresholds.min_positive_consensus = int(p["min_consensus_probes"])
        if "min_negative_parents" in p:
            pc.thresholds.min_negative_generated = int(p["min_negative_parents"])

    return settings
